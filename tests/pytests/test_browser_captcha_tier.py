"""M11.6 browser acceptance: captcha tier in a real Chromium.

/captcha-demo is pinned to the captcha tier (BotShieldScoreCaptcha 3),
so a fresh-IP + missing-AL request is guaranteed to land there. A real
Chromium loads the interstitial, the module's form markup is well-
formed enough that a submit with an injected Turnstile-always-pass
token does a round-trip → 303 → __Host-bs_session cookie → redirect to
return_to → challenge cleared on subsequent navigation.

We inject the token rather than wait for Turnstile to auto-solve:
the always-pass sitekey accepts any token, and Turnstile's JS widget
doesn't reliably auto-complete in headless Chromium. The assertion
we care about is "module's verify handler accepts the POST, sets
the cookie, and redirects" — which this exercises fully.

Requires live Turnstile siteverify (Cloudflare reachability).
"""

from __future__ import annotations

import pytest

from botshield_test import config


# live_network picks up rerun-on-flake via the conftest hook (M11.7):
# Turnstile's always-pass sitekey occasionally flakes under parallel
# siteverify pressure, and a single retry absorbs that without
# turning the test serial.
pytestmark = [
    pytest.mark.acceptance, pytest.mark.browser, pytest.mark.live_network,
]


def _turnstile_reachable(context) -> bool:
    try:
        r = context.request.get(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            timeout=5_000,
        )
        return r.status in (200, 404, 405)
    except Exception:
        return False


def test_captcha_tier_end_to_end(bs_browser_context):
    if not _turnstile_reachable(bs_browser_context):
        pytest.skip("challenges.cloudflare.com unreachable")

    ctx = bs_browser_context
    page = ctx.new_page()

    # 1. Cookieless hit on /captcha-demo → interstitial with Turnstile widget
    resp = page.goto(config.BASE_URL + "/captcha-demo",
                     wait_until="domcontentloaded", timeout=15_000)
    assert resp.headers.get("x-botshield") == "challenge"
    assert "Verify you are human" in page.title()
    assert page.query_selector(".cf-turnstile") is not None, (
        "interstitial didn't render the Turnstile widget"
    )
    assert page.query_selector("#bscf") is not None, (
        "interstitial is missing the captcha form"
    )

    # 2. Inject an always-pass token, rewrite return_to=/ so post-solve
    #    we land on the real site (not the permanently-captcha demo
    #    page), then submit the form.
    page.evaluate("""() => {
        const f = document.getElementById('bscf');
        f.querySelector('input[name=return_to]').value = '/';
        const i = document.createElement('input');
        i.type = 'hidden';
        i.name = 'cf-turnstile-response';
        i.value = 'x';
        f.appendChild(i);
        f.submit();
    }""")
    page.wait_for_load_state("load", timeout=15_000)

    # 3. After the solve: __Host-bs_session in the jar, we're on the real site.
    cookies = {c["name"] for c in ctx.cookies()}
    assert "__Host-bs_session" in cookies, (
        f"captcha solve didn't set __Host-bs_session; cookies={cookies}"
    )
    assert "Verify you are human" not in page.title(), (
        f"still on interstitial post-submit; title={page.title()!r}"
    )


def test_captcha_cookie_clears_subsequent_challenge(bs_browser_context):
    """After the captcha solve, browsing normally shouldn't re-challenge.

    Uses a browser-shaped header envelope on the replay (AL set) so
    the only tier-deciding signal is the verified cookie's rep.
    """
    if not _turnstile_reachable(bs_browser_context):
        pytest.skip("challenges.cloudflare.com unreachable")

    ctx = bs_browser_context
    page = ctx.new_page()

    # Complete the captcha flow (setup).
    page.goto(config.BASE_URL + "/captcha-demo", wait_until="domcontentloaded")
    page.evaluate("""() => {
        const f = document.getElementById('bscf');
        f.querySelector('input[name=return_to]').value = '/';
        const i = document.createElement('input');
        i.type='hidden'; i.name='cf-turnstile-response'; i.value='x';
        f.appendChild(i); f.submit();
    }""")
    page.wait_for_load_state("load", timeout=15_000)
    assert "__Host-bs_session" in {c["name"] for c in ctx.cookies()}, \
        "setup: verified cookie didn't land"

    # Replay /: layer a browser-shaped Accept-Language on top of the
    # existing XFF so the only remaining tier-deciding signal is the
    # verified cookie.
    ctx.set_extra_http_headers({"Accept-Language": "en-US"})
    resp = page.goto(config.BASE_URL + "/")
    assert resp.status == 200
    assert resp.headers.get("x-botshield") != "challenge", (
        f"verified visitor got re-challenged on /; "
        f"X-Botshield={resp.headers.get('x-botshield')!r}"
    )
