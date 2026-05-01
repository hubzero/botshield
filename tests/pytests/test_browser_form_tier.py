"""M11.6 browser acceptance: silent/form tier in a real Chromium.

This is the test that cannot be done with httpx: a cookieless
suspicious-shaped request receives the interstitial, the interstitial's
JS PoW worker runs to completion inside a real browser, the
auto-submit fires, and the real origin page appears.

Catches regressions the httpx-based test_acceptance_form_tier can't
see:
  - PoW worker path or MIME type wrong (browser can't fetch/execute
    the script).
  - Auto-submit form is broken (wrong method, wrong action, JS
    handler renamed).
  - Cookie attributes prevent the browser from echoing __Host-bs_session
    on the reload (Secure on http, SameSite wrong, Path wrong).
"""

from __future__ import annotations

import pytest


pytestmark = [pytest.mark.acceptance, pytest.mark.browser]


def _has_verified_cookie(ctx) -> bool:
    return any(c["name"] == "__Host-bs_session" for c in ctx.cookies())


def test_silent_tier_js_pow_round_trip(bs_browser_context):
    """Silent tier: Mozilla UA + missing Accept-Language + first-sight-ip
    = score 20 → silent. Interstitial auto-submits on load."""
    ctx = bs_browser_context
    page = ctx.new_page()

    # 1. Cookieless request. Module returns the interstitial.
    resp = page.goto("https://localhost/")
    assert resp.headers.get("x-botshield") == "challenge", (
        f"expected silent-tier challenge, got "
        f"X-Botshield={resp.headers.get('x-botshield')!r} "
        f"status={resp.status}"
    )
    assert "Verify you are human" in page.title(), (
        f"expected interstitial, got title={page.title()!r}"
    )

    # 2. The interstitial JS sets __Host-bs_session then
    #    `setTimeout(location.reload, 250)`. Wait for the reload to
    #    finish, not just the cookie-set: the title only changes on
    #    the follow-up navigation when the real origin page renders.
    page.wait_for_function(
        "() => document.title !== 'Verify you are human'",
        timeout=20_000,
    )

    # 3. Cookie present in browser context, real page rendered.
    assert _has_verified_cookie(ctx), (
        f"__Host-bs_session never landed in the browser cookie jar; "
        f"cookies={[c['name'] for c in ctx.cookies()]}"
    )


def test_verified_cookie_clears_subsequent_challenge(bs_browser_context):
    """After the silent-tier round-trip, the same context navigating
    back to / should get a pass — no re-challenge."""
    ctx = bs_browser_context
    page = ctx.new_page()

    # Trigger + complete the silent-tier flow first.
    page.goto("https://localhost/")
    page.wait_for_function(
        "() => document.title !== 'Verify you are human'",
        timeout=20_000,
    )
    assert _has_verified_cookie(ctx), "setup: cookie didn't land"

    # Fresh navigation with the cookie already in the jar.
    resp = page.goto("https://localhost/")
    assert resp.status == 200
    assert resp.headers.get("x-botshield") != "challenge", (
        f"verified visitor got re-challenged; "
        f"X-Botshield={resp.headers.get('x-botshield')!r}"
    )
    assert "Verify you are human" not in page.title()
