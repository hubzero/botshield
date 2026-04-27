"""M7: silent-tier auto-submit interstitial end-to-end.

1. Cookieless silent-band request → interstitial JS with auto=1
2. Locally solve the PoW, build the 15-field cookie
3. Replay with the cookie → pass tier (no challenge)

This is the Python-PoW-hand-roll version. The Playwright version
lands in M11.6 and exercises the real browser's JS worker.

Port of tests/integration/m7_silent_tier.sh.
"""

from __future__ import annotations

import pytest

from botshield_test import client, cookies


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


def test_silent_tier_round_trip(fresh_ip):
    # 1. Cookieless silent-band probe: Mozilla UA + missing Accept-
    #    Language + first-sight-ip = score 20 → silent tier.
    resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)

    # auto=1 indicates silent tier. If it's 0 we got form tier —
    # means the IP was already in Bloom, first-sight-ip didn't fire.
    assert challenge["auto"] == 1, (
        f"expected auto=1 (silent tier), got auto={challenge['auto']} — "
        f"is the IP already in Bloom? ip={fresh_ip}"
    )

    # 2. Solve PoW + build cookie.
    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    # 3. Replay with browser-like headers + the signed cookie.
    resp = client.get(
        "/", xff=fresh_ip,
        ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_verified": cookie},
    )
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"cookied replay still challenged; headers={dict(resp.headers)}"
    )
