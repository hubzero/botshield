"""M11.6 browser acceptance: pass tier in a real Chromium.

A browser-shaped visitor (real Chromium UA, Accept-Language set,
fresh IP) arrives at / and should see the origin page directly — no
interstitial, no challenge header, but a fresh trust=0
__Host-bs_session is minted (always-mint: every pass through the
handler emits a session cookie so the next request from the same
browser carries an identifier).

This catches regressions that the httpx-based test_acceptance_pass_
tier can't see: changes in the module's UA heuristics that would
accidentally penalize real Chromium, or interstitial-leakage where
a pass-tier decision still sets the X-Botshield: challenge header.
"""

from __future__ import annotations

import pytest


pytestmark = [pytest.mark.acceptance, pytest.mark.browser]


def test_pass_tier_no_challenge(bs_browser_context_pass):
    page = bs_browser_context_pass.new_page()
    resp = page.goto("https://localhost/")

    assert resp.status == 200
    assert resp.headers.get("x-botshield") != "challenge", (
        f"browser-shaped visitor got a challenge header; "
        f"headers={dict(resp.headers)}"
    )

    # The interstitial template is titled "Verify you are human".
    # A pass-tier response is the real origin page.
    title = page.title()
    assert "Verify you are human" not in title, (
        f"pass-tier response rendered the interstitial; title={title!r}"
    )

    # Always-mint: pass-tier issues a fresh __Host-bs_session
    # (typically trust=0, a per-browser-session marker). Chromium
    # parses the Set-Cookie and stores it; we verify it landed and
    # is a session cookie (Playwright surfaces `expires` == -1 for
    # cookies with no Expires/Max-Age).
    bs_cookies = [c for c in bs_browser_context_pass.cookies()
                  if c["name"] == "__Host-bs_session"]
    assert len(bs_cookies) == 1, (
        f"pass tier should mint exactly one __Host-bs_session; "
        f"got {len(bs_cookies)} (cookies="
        f"{[c['name'] for c in bs_browser_context_pass.cookies()]})"
    )
    c = bs_cookies[0]
    assert c["expires"] in (-1, None), (
        f"__Host-bs_session is a session cookie; Playwright reports "
        f"expires={c['expires']!r} (expected -1 / None for no "
        f"Expires=). The Set-Cookie line should not carry Expires= "
        f"or Max-Age=."
    )
    assert c["secure"] is True
    assert c["httpOnly"] is True
