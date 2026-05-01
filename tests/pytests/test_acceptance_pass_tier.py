"""Acceptance: the happy path. A plausible-looking browser with a
plausible header set arrives at /, gets no interstitial, and receives
origin content.

If this test fails, every regular user is seeing a challenge — the
module is no longer usable as a drop-in.

Port of tests/acceptance/pass_tier.sh. M11.6 will replace this with a
Playwright-driven browser test; the assertion shape stays the same.
"""

from __future__ import annotations

import pytest

from botshield_test import client


pytestmark = pytest.mark.acceptance


CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)
CHROME_HEADERS = {
    "Accept":
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
}


def test_normal_user_passes_through(fresh_ip, log_slice):
    with log_slice as slc:
        resp = client.get(
            "/", xff=fresh_ip,
            ua=CHROME_UA, accept_language="en-US,en;q=0.9",
            headers=CHROME_HEADERS,
        )
        lines = slc.decision_lines(ip=fresh_ip)

    assert resp.headers.get("X-Botshield") != "challenge", (
        f"browser-like request got a challenge; headers={dict(resp.headers)}"
    )
    assert resp.status_code == 200

    assert any(
        d["tier"] == "pass" and d["outcome"] == "allow"
        for d in lines
    ), (
        f"expected tier=pass outcome=allow for ip={fresh_ip}; "
        f"got: {lines}"
    )

    # Always-mint: a fresh cookieless visitor's pass-through still
    # gets a __Host-bs_session minted on the response (most carry
    # trust=0 and are session markers; any solve evidence rides in
    # later issuances). The decision log records cookie=minted to
    # distinguish "no cookie at all" (cookie=absent) from "no cookie
    # in, fresh one going out".
    assert any(
        d["tier"] == "pass" and d["cookie"] == "minted"
        for d in lines
    ), (
        f"expected cookie=minted on a fresh visitor's pass through; "
        f"got: {[(d['tier'], d['cookie']) for d in lines]}"
    )
    assert "__Host-bs_session" in resp.cookies, (
        f"always-mint should issue __Host-bs_session on pass; "
        f"got cookies={dict(resp.cookies)}"
    )

    # Session-cookie semantics: the Set-Cookie line for
    # __Host-bs_session must NOT carry Expires= or Max-Age= so the
    # browser discards on session end. The server-side expires_at
    # field inside the envelope is the hard cap. Inspect the raw
    # Set-Cookie header rather than the parsed cookie since httpx
    # collapses some attributes during parse.
    set_cookies = resp.headers.get_list("set-cookie") \
        if hasattr(resp.headers, "get_list") \
        else [resp.headers.get("set-cookie", "")]
    bs_lines = [c for c in set_cookies if "__Host-bs_session" in c]
    assert bs_lines, "no Set-Cookie line for __Host-bs_session"
    for line in bs_lines:
        assert "Expires=" not in line, (
            f"__Host-bs_session is a session cookie; Expires= would "
            f"keep it past browser-session end. Set-Cookie: {line!r}"
        )
        assert "Max-Age=" not in line, (
            f"__Host-bs_session is a session cookie; Max-Age= would "
            f"keep it past browser-session end. Set-Cookie: {line!r}"
        )
