"""Acceptance: high-confidence-friction journey.

/captcha-demo is pinned to captcha tier via BotShieldScoreCaptcha 3.
The user:
  1. hits /captcha-demo → interstitial with a Turnstile widget,
  2. solves → 303 + __Host-bs_verified cookie,
  3. continues browsing /  → no challenge on normal paths.

Requires Cloudflare reachability. M11.6 replaces step 2 with an
actual browser-driven Turnstile solve.

Port of tests/acceptance/captcha_tier.sh.
"""

from __future__ import annotations

import pytest

from botshield_test import client


pytestmark = [pytest.mark.acceptance, pytest.mark.live_network]


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


def _turnstile_reachable() -> bool:
    try:
        r = client.get(
            "/turnstile/v0/siteverify",
            base_url="https://challenges.cloudflare.com",
            timeout=5,
        )
        return r.status_code in (200, 404, 405)
    except Exception:
        return False


def test_captcha_journey_end_to_end(pending_cookie, log_slice):
    if not _turnstile_reachable():
        pytest.skip("challenges.cloudflare.com unreachable")

    # 1. Interstitial (pending cookie minted).
    pending = pending_cookie("captcha-demo")
    interstitial = client.get("/captcha-demo")
    assert "cf-turnstile" in interstitial.text, (
        "interstitial didn't render the Turnstile widget"
    )

    # 2. Solve: always-pass sitekey returns success for any token.
    #    return_to=/ because /captcha-demo is permanently at captcha
    #    tier; the real user's next stop is the normal site.
    with log_slice as slc:
        resp = client.post(
            "/botshield/captcha-verify/turnstile",
            cookies={"_bs_captcha_pending": pending},
            data={"cf-turnstile-response": "x", "return_to": "/"},
        )
        lines = slc.decision_lines(outcome="verified", provider="turnstile")

    assert resp.status_code == 303
    assert resp.headers.get("X-Botshield") == "captcha-ok"
    verified = resp.cookies.get("__Host-bs_verified")
    assert verified, "verify response didn't set __Host-bs_verified"
    assert lines, (
        "no 'outcome=verified provider=turnstile' decision line emitted"
    )

    # 3. Replay / with verified cookie + browser headers → no challenge.
    resp2 = client.get(
        "/",
        ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_verified": verified},
    )
    assert resp2.status_code == 200
    assert resp2.headers.get("X-Botshield") != "challenge", (
        f"verified cookie didn't lift challenge on normal path; "
        f"headers={dict(resp2.headers)}"
    )
