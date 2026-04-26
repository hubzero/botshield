"""E17 PoC — embedded silent verification round-trip in a real browser.

The PoC's job is to prove the timing model works: page renders
immediately (no interstitial), wrapper runs in background, Worker
solves PoW, POSTs result, _bs_verified cookie is set, next page-load
in the session rides through without re-challenge.

These tests use a Bloom-fresh IP shaped to land at silent tier (no
Accept-Language, no Mozilla UA boost) and visit /embedded-test.html
(a tiny static page that includes the wrapper). With
BotShieldSilentMode embedded scoped to that path, the response is
DECLINED (real page) instead of the M7 splash; the wrapper does the
verification work in the background.

The "kicks in eventually" guarantee:
  - first request may not have the cookie yet (wrapper hasn't
    finished posting)
  - within ~2-3 seconds the cookie should be set
  - subsequent requests in the same browser context ride through
"""

from __future__ import annotations

import time

import pytest


pytestmark = [pytest.mark.acceptance, pytest.mark.browser,
              pytest.mark.serial]


EMBEDDED_PATH = "/embedded-test.html"


def test_embedded_serves_real_page_immediately(
    config_override, bs_browser_context,
):
    """First page-load under embedded mode: real page renders, no
    interstitial. The page title is 'BotShield embedded-mode test
    page', not 'Verify you are human'."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldSilentMode embedded\n'
        '    </Location>',
        count=1,
    ):
        page = bs_browser_context.new_page()
        resp = page.goto(f"https://localhost{EMBEDDED_PATH}")
        assert resp.status == 200, (
            f"embedded mode should serve the real page; "
            f"status={resp.status}"
        )
        title = page.title()
        assert "Verify you are human" not in title, (
            f"embedded mode leaked the M7 interstitial; title={title!r}"
        )
        assert "embedded-mode test page" in title, (
            f"unexpected page title: {title!r}"
        )


def test_embedded_wrapper_mints_verified_cookie(
    config_override, bs_browser_context,
):
    """The headline timing test: load the page (wrapper fires in
    background), wait a few seconds for the Worker + POST to
    complete, observe _bs_verified in the cookie jar."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldSilentMode embedded\n'
        '    </Location>',
        count=1,
    ):
        page = bs_browser_context.new_page()
        page.goto(f"https://localhost{EMBEDDED_PATH}")

        # Poll for the cookie up to 8s. PoW at default difficulty=4
        # is a few thousand hashes — Worker should finish in well
        # under 2s on any modern machine, but CI variance + Worker
        # spin-up justifies a generous deadline.
        deadline = time.monotonic() + 8.0
        cookie_present = False
        while time.monotonic() < deadline:
            cookies = {c["name"] for c in bs_browser_context.cookies()}
            if "_bs_verified" in cookies:
                cookie_present = True
                break
            time.sleep(0.25)

        assert cookie_present, (
            f"wrapper failed to mint _bs_verified within deadline; "
            f"cookies={[c['name'] for c in bs_browser_context.cookies()]}"
        )


def test_embedded_turnstile_mints_verified_cookie(
    config_override, bs_browser_context,
):
    """E17.2 — invisible Turnstile adapter. Scope is configured for
    Turnstile (not native PoW); the wrapper loads Cloudflare's
    api.js, renders an invisible widget with the always-pass test
    sitekey 2x00000000000000000000AB, gets a token from
    Cloudflare, POSTs to /embedded-verify, server siteverifies
    against Cloudflare's real endpoint with the always-pass secret,
    and mints _bs_verified.

    Hits the real challenges.cloudflare.com infrastructure — slower
    + flakier than the PoW path, but proves the provider-dispatch
    mechanism works end-to-end."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldSilentMode embedded\n'
        '        BotShieldCaptchaProvider turnstile\n'
        '        BotShieldCaptchaSiteKey 2x00000000000000000000AB\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/turnstile-secret\n'
        '    </Location>',
        count=1,
    ):
        page = bs_browser_context.new_page()
        page.goto(f"https://localhost{EMBEDDED_PATH}")

        # Real Cloudflare round trip — give it more time than PoW.
        # Local network + CF latency + invisible-widget readiness
        # typically lands within 5s but we allow 15.
        deadline = time.monotonic() + 15.0
        cookie_present = False
        while time.monotonic() < deadline:
            cookies = {c["name"] for c in bs_browser_context.cookies()}
            if "_bs_verified" in cookies:
                cookie_present = True
                break
            time.sleep(0.5)

        assert cookie_present, (
            f"turnstile wrapper failed to mint _bs_verified within "
            f"deadline; cookies="
            f"{[c['name'] for c in bs_browser_context.cookies()]}"
        )


def test_embedded_hcaptcha_mints_verified_cookie(
    config_override, bs_browser_context,
):
    """E17.4a — hCaptcha invisible adapter. Same architectural shape
    as Turnstile (token-based, real round-trip against the provider's
    siteverify), but materially different client API: hcaptcha.render
    returns a widget ID, then hcaptcha.execute(widgetId) triggers
    the invisible challenge. Validates that the wrapper's per-
    provider dispatch actually handles the API differences cleanly,
    not just the abstraction over them.

    Uses hCaptcha's published always-pass test keys:
      sitekey: 10000000-ffff-ffff-ffff-000000000001
      secret:  0x0000000000000000000000000000000000000000
    """
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldSilentMode embedded\n'
        '        BotShieldCaptchaProvider hcaptcha\n'
        '        BotShieldCaptchaSiteKey '
            '10000000-ffff-ffff-ffff-000000000001\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/hcaptcha-secret\n'
        '        BotShieldCaptchaExpectedHostname dummy-key-pass\n'
        '    </Location>',
        count=1,
    ):
        page = bs_browser_context.new_page()
        page.goto(f"https://localhost{EMBEDDED_PATH}")

        # Real hCaptcha round trip — comparable latency to Turnstile.
        deadline = time.monotonic() + 15.0
        cookie_present = False
        while time.monotonic() < deadline:
            cookies = {c["name"] for c in bs_browser_context.cookies()}
            if "_bs_verified" in cookies:
                cookie_present = True
                break
            time.sleep(0.5)

        assert cookie_present, (
            f"hcaptcha wrapper failed to mint _bs_verified within "
            f"deadline; cookies="
            f"{[c['name'] for c in bs_browser_context.cookies()]}"
        )


def test_embedded_falls_back_to_m7_when_wrapper_blocked(
    config_override, bs_browser_context,
):
    """E17 spec gate: 'With E17 enabled but the wrapper missing,
    blocked by CSP, or not yet supported, the site still works and
    M7 remains the fallback path for future silent-tier requests.'

    Simulate a CSP-blocked wrapper by intercepting the
    /botshield/embedded.js URL with Playwright's route() and
    aborting the request. The page loads, wrapper never runs,
    no _bs_verified arrives. After 3 silent-tier dispatches without
    verify (default fallback threshold), the server switches to
    issuing the M7 form-PoW interstitial.

    Test pins silent tier explicitly via tight ScoreSilent + relaxed
    ScoreHard so successive requests don't drop to pass tier after
    the Bloom first-sight bonus stops applying. Without that, only
    the first request would be silent-tier and the count couldn't
    accumulate."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldSilentMode embedded\n'
        '        BotShieldScoreSilent 1\n'
        '        BotShieldScoreHard 1000\n'
        '        BotShieldScoreCaptcha 2000\n'
        '    </Location>',
        count=1,
    ):
        page = bs_browser_context.new_page()
        # Block the wrapper script — simulates strict CSP / ad-blocker
        # killing /botshield/embedded.js.
        page.route("**/botshield/embedded.js", lambda r: r.abort())

        # Three attempts that should land at silent-tier-embedded
        # (the embedded short-circuit fires; real page served; no
        # cookie because wrapper is blocked).
        for _ in range(3):
            resp = page.goto(f"https://localhost{EMBEDDED_PATH}")
            assert resp.status == 200, (
                f"unexpected status during embedded attempt; "
                f"status={resp.status}"
            )

        # 4th request — embedded fallback threshold (3) crossed; M7
        # interstitial should now be served instead. The interstitial
        # template title is "Verify you are human".
        resp = page.goto(f"https://localhost{EMBEDDED_PATH}")
        title = page.title()
        assert "Verify you are human" in title, (
            f"after 3 embedded attempts without verify, M7 fallback "
            f"should fire; got title={title!r} (status={resp.status})"
        )


def test_embedded_worker_endpoint_serves_pow_solver():
    """E17 worker-src 'self' alternative: the wrapper loads its
    Web Worker from /botshield/embedded-worker.js (a real same-
    origin URL) instead of a blob: URL, so strict CSP scopes
    (worker-src 'self') accept it.

    Sanity check that the endpoint actually serves the worker
    source — content-type is JS, body has the SubtleCrypto digest
    call that the PoW solver uses."""
    from botshield_test import client as _client

    r = _client.get("/botshield/embedded-worker.js")
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "javascript" in ct, (
        f"worker endpoint should serve JS; content-type={ct!r}"
    )
    body = r.text
    assert "self.onmessage" in body, "worker missing message handler"
    assert "crypto.subtle.digest" in body, (
        "worker missing SHA-256 digest call"
    )


def test_embedded_wrapper_uses_real_url_worker():
    """E17 worker-src 'self' alternative: the wrapper JS
    /botshield/embedded.js must construct its Worker from
    '/botshield/embedded-worker.js' (a real URL), NOT from a blob:
    URL. Catches a regression where someone reverts the worker-src
    hardening."""
    from botshield_test import client as _client

    r = _client.get("/botshield/embedded.js")
    assert r.status_code == 200
    body = r.text
    assert "/botshield/embedded-worker.js" in body, (
        "wrapper missing real-URL Worker reference"
    )
    # blob: URL should NOT be how the worker is created anymore.
    # (The file may still mention 'blob' in comments or ancillary
    # code, but the Worker constructor should NOT be passed a blob
    # object URL.)
    assert "URL.createObjectURL" not in body, (
        "wrapper still uses blob: URL Worker — strict CSP scopes "
        "will reject this"
    )


def test_embedded_subsequent_request_declined_through(
    config_override, bs_browser_context,
):
    """Once the cookie has landed, the next page-load within the same
    browser context should ride through with the cookie attached. No
    challenge, no re-issue. Verifies the round-trip closes the loop:
    cookie minted → cookie sent → cookie verified server-side → real
    content."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldSilentMode embedded\n'
        '    </Location>',
        count=1,
    ):
        page = bs_browser_context.new_page()
        # First visit — wait for the wrapper to mint the cookie.
        page.goto(f"https://localhost{EMBEDDED_PATH}")
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            if "_bs_verified" in {c["name"] for c in bs_browser_context.cookies()}:
                break
            time.sleep(0.25)

        # Second visit on the same context — cookie should ride along
        # and the response should be the real page with no challenge
        # marker.
        resp = page.goto(f"https://localhost{EMBEDDED_PATH}")
        assert resp.status == 200
        assert resp.headers.get("x-botshield") != "challenge", (
            f"second request to embedded scope got a challenge "
            f"despite cookie present; headers={dict(resp.headers)}"
        )
