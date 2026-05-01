"""M11.6 browser acceptance: pass tier in a real Chromium.

A browser-shaped visitor (real Chromium UA, Accept-Language set,
fresh IP) arrives at / and should see the origin page directly — no
interstitial, no challenge header, no verified cookie minted.

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

    # No verified cookie on a straight pass — the module doesn't
    # mint one until the visitor clears a challenge. (Legitimate
    # users never receive a cookie; that's the design.)
    cookies = {c["name"] for c in bs_browser_context_pass.cookies()}
    assert "__Host-bs_session" not in cookies, (
        f"pass tier shouldn't mint __Host-bs_session; cookies={cookies}"
    )
