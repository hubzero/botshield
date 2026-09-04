"""HTTP client wrapper for the dev vhost.

Wraps httpx with the defaults every test wants:
  - trust the self-signed dev cert (verify=False)
  - short timeout so a blocked test doesn't hang CI for the full
    pytest-timeout window
  - easy `X-Forwarded-For` injection (every test either needs a fresh
    IP or a sticky one; passing it as a first-class kwarg is cleaner
    than building the header dict inline every time)
  - return the response object, not a body — tests inspect status,
    headers, and body separately

httpx over requests for forward compatibility (async pathways in
M11.7 when the soak driver folds in) and because its `follow_redirects`
default matches test intent more closely (we assert on the first
response, not the final one).
"""

from __future__ import annotations

import httpx

from .config import BASE_URL, DEFAULT_TIMEOUT


def _headers(
    *,
    ua: str | None,
    accept_language: str | None,
    xff: str | None,
    cookies: dict | None,
    extra: dict | None,
) -> dict:
    h: dict[str, str] = {}
    if ua is not None:
        h["User-Agent"] = ua
    if accept_language is not None:
        h["Accept-Language"] = accept_language
    if xff is not None:
        h["X-Forwarded-For"] = xff
    if cookies:
        # Build the Cookie header directly instead of using httpx's
        # per-request `cookies=` kwarg — httpx deprecated that because
        # jar-persistence semantics are ambiguous. We never want
        # persistence; each call is one ephemeral request.
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if extra:
        h.update(extra)
    return h


def request(
    method: str,
    path: str,
    *,
    ua: str | None = None,
    # Omitted by default, and that default is load-bearing in both
    # directions, which is why it is left alone.
    #
    # Without the header, a request from this client scores 10 for a
    # scraper-classified agent, 5 for the missing header and 5 for a
    # Bloom-fresh address: 20, against a dev-vhost threshold of 20.
    # Tests asserting a path is NOT blocked want to be under that line;
    # tests asserting the safeguard trips need to be over it. Sending
    # the header by default was tried and moved the failures from one
    # group to the other without reducing them.
    #
    # So each test states the client shape it needs rather than
    # inheriting one. The real fix is that the dev vhost leaves no
    # headroom either side of the line, which is a scoring decision
    # rather than a harness one.
    accept_language: str | None = None,
    xff: str | None = None,
    cookies: dict | None = None,
    data: dict | str | None = None,
    headers: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = False,
    base_url: str = BASE_URL,
) -> httpx.Response:
    """Issue one request against the dev vhost.

    `path` is a URL-path (starts with `/`). The caller never passes a
    full URL — `base_url` defaults to the dev vhost and tests rarely
    need to override it.

    Every keyword argument reflects a real need that showed up
    repeatedly in the bash suite. Tests that don't need a given
    header leave that kwarg at its default (`None`) and the header is
    simply not sent. `cookies` goes out as a single Cookie header —
    httpx's jar is explicitly bypassed.
    """
    url = base_url.rstrip("/") + path
    # Security review LOW #16 — verify=False is correct for the dev
    # vhost (self-signed cert) but actively dangerous if applied to
    # a non-loopback host. Use verify=True (system trust store) for
    # any non-loopback target so a misconfigured BS_BASE pointing
    # at a public host doesn't silently accept any cert. Loopback
    # targets keep verify=False since the dev cert is self-signed.
    # Tests that probe a public provider URL (reachability checks)
    # naturally land on the verify=True path.
    from urllib.parse import urlparse as _urlparse
    _host = (_urlparse(base_url).hostname or "").lower()
    _is_loopback = (
        _host in ("localhost", "127.0.0.1", "::1")
        or _host.endswith(".localhost")
    )
    h = _headers(
        ua=ua, accept_language=accept_language, xff=xff,
        cookies=cookies, extra=headers,
    )
    _verify = not _is_loopback   # False on loopback, True elsewhere
    with httpx.Client(verify=_verify, timeout=timeout) as client:
        return client.request(
            method, url,
            data=data,
            headers=h,
            follow_redirects=follow_redirects,
        )


def get(path: str, **kwargs) -> httpx.Response:
    return request("GET", path, **kwargs)


def post(path: str, **kwargs) -> httpx.Response:
    return request("POST", path, **kwargs)
