"""Acceptance: cookieless-but-recoverable journey.

1. Suspicious UA + no cookie → silent/form tier interstitial.
2. Solve PoW locally, assemble the 15-field signed cookie.
3. Replay with the cookie → tier drops to pass, origin served.

If this regresses, suspicious visitors have no graceful recovery
short of a captcha.

Port of tests/acceptance/form_tier.sh. M11.6 replaces the local PoW
solve with Chromium's own JS worker; assertion shape stays the same.
"""

from __future__ import annotations

import pytest

from botshield_test import client, cookies


pytestmark = pytest.mark.acceptance


SUSPICIOUS_UA = "Mozilla/5.0 (X11) Chrome/145"
BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


def test_cookieless_recoverable_journey(fresh_ip, log_slice):
    # 1. Initial probe: interstitial with a challenge. Form-tier
    #    interstitial is 403 + X-Robots-Tag noindex,nofollow so
    #    search engines don't index the placeholder.
    resp = client.get("/", xff=fresh_ip, ua=SUSPICIOUS_UA)
    assert resp.status_code == 403, (
        f"form-tier interstitial should return 403; got {resp.status_code}"
    )
    robots_tag = resp.headers.get("X-Robots-Tag", "")
    assert "noindex" in robots_tag and "nofollow" in robots_tag, (
        f"form-tier interstitial missing X-Robots-Tag noindex,nofollow; "
        f"got {robots_tag!r}"
    )
    challenge = cookies.extract_challenge(resp.text)

    # 2. Solve + build cookie.
    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    # 3. Replay with browser-like headers + the signed cookie.
    with log_slice as slc:
        resp = client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_verified": cookie},
        )
        lines = slc.decision_lines(ip=fresh_ip)

    assert resp.headers.get("X-Botshield") != "challenge", (
        f"cookied replay still challenged; headers={dict(resp.headers)}"
    )
    assert resp.status_code == 200

    assert any(
        d["tier"] == "pass" and d["cookie"] == "ok"
        for d in lines
    ), f"expected tier=pass cookie=ok for ip={fresh_ip}; got: {lines}"
