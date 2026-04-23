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
    h = _headers(
        ua=ua, accept_language=accept_language, xff=xff,
        cookies=cookies, extra=headers,
    )
    with httpx.Client(verify=False, timeout=timeout) as client:
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
