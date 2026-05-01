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
