"""E17.3-4 — recaptcha-v3 / recaptcha-v2 / friendly dispatch coverage.

reCAPTCHA v3 is materially different from Turnstile in client API:
no widget element, always invisible, uses grecaptcha.execute() with
action binding, and the server-side decision depends on a numeric
score rather than just success/fail. E17.3 validates that the
wrapper-and-verify abstraction is real — both shapes route through
the same /botshield/embedded-bootstrap and /botshield/embedded-verify
without provider-specific handler code.

Coverage scope: dispatch only. End-to-end against Google's
siteverify isn't tested because reCAPTCHA v3 has no published
always-pass test keys (Google deliberately doesn't ship them — v3's
whole point is "all real traffic" and you self-test against your
own production keys). The dev-config comments (apache/botshield-
dev.conf) call this out explicitly.

These tests verify:
  - bootstrap returns provider=recaptcha-v3 + sitekey + action when
    the scope is configured for recaptcha-v3
  - the embedded.js wrapper carries the recaptcha-v3 dispatch case
  - the verify endpoint cleanly rejects malformed POSTs that claim
    provider=recaptcha-v3 (stops at parse before any siteverify
    call to Google goes out)
"""

from __future__ import annotations

import json

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


def test_bootstrap_returns_recaptcha_v3_provider(config_override):
    """With the scope configured for recaptcha-v3, /embedded-bootstrap
    surfaces provider=recaptcha-v3 + sitekey + action so the wrapper
    can dispatch to grecaptcha.execute(). Action defaults to
    'botshield' if BotShieldCaptchaExpectedAction isn't set."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location /botshield/embedded-bootstrap>\n'
        '        BotShieldCaptchaProvider recaptcha-v3\n'
        '        BotShieldCaptchaSiteKey 6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v3-secret\n'
        '    </Location>',
        count=1,
    ):
        r = client.get("/botshield/embedded-bootstrap")
        assert r.status_code == 200
        j = json.loads(r.text)
        assert j.get("mode") == "silent", f"mode={j.get('mode')!r}"
        assert j.get("provider") == "recaptcha-v3", (
            f"provider={j.get('provider')!r}"
        )
        assert "sitekey" in j and j["sitekey"], (
            f"sitekey missing/empty: {j!r}"
        )
        assert j.get("action") == "botshield", (
            f"default action expected 'botshield'; got {j.get('action')!r}"
        )


def test_bootstrap_action_overrideable(config_override):
    """BotShieldCaptchaExpectedAction overrides the default action so
    operators can have different action strings on different scopes
    without cross-contamination of v3 score semantics."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location /botshield/embedded-bootstrap>\n'
        '        BotShieldCaptchaProvider recaptcha-v3\n'
        '        BotShieldCaptchaSiteKey 6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v3-secret\n'
        '        BotShieldCaptchaExpectedAction my_login_form\n'
        '    </Location>',
        count=1,
    ):
        r = client.get("/botshield/embedded-bootstrap")
        j = json.loads(r.text)
        assert j.get("action") == "my_login_form", (
            f"expected operator-set action; got {j.get('action')!r}"
        )


def test_wrapper_js_carries_recaptcha_dispatch():
    """The wrapper served from /botshield/embedded.js must contain
    both the recaptcha-v3 dispatch case AND the runRecaptchaV3
    function definition. Catches a future regression where someone
    drops the recaptcha-v3 path during wrapper refactor without
    updating the dispatch."""
    r = client.get("/botshield/embedded.js")
    assert r.status_code == 200
    body = r.text
    assert "recaptcha-v3" in body, (
        "wrapper missing recaptcha-v3 dispatch case"
    )
    assert "runRecaptchaV3" in body, (
        "wrapper missing runRecaptchaV3 function"
    )
    assert "grecaptcha" in body, (
        "wrapper missing grecaptcha invocation"
    )
    assert "google.com/recaptcha/api.js" in body, (
        "wrapper missing recaptcha api.js loader"
    )


def test_verify_rejects_recaptcha_v3_missing_token(config_override):
    """A POST claiming provider=recaptcha-v3 but with no token field
    must be rejected at parse time, before any HTTP call to Google.
    Verifies the bs_embedded_verify_provider input-validation runs."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location /botshield/embedded-verify>\n'
        '        BotShieldCaptchaProvider recaptcha-v3\n'
        '        BotShieldCaptchaSiteKey 6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v3-secret\n'
        '    </Location>',
        count=1,
    ):
        r = client.post(
            "/botshield/embedded-verify",
            data=json.dumps({"provider": "recaptcha-v3"}),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code in (400, 403), (
            f"missing-token POST should be rejected; got {r.status_code}"
        )


def test_wrapper_js_carries_recaptcha_v2_dispatch():
    """E17.4b — recaptcha-v2 invisible mode."""
    r = client.get("/botshield/embedded.js")
    assert r.status_code == 200
    body = r.text
    assert "recaptcha-v2" in body, "wrapper missing recaptcha-v2 dispatch"
    assert "runRecaptchaV2" in body, "wrapper missing runRecaptchaV2"
    # v2 invisible uses grecaptcha.render + execute (NOT execute(sitekey))
    # — the API differs from v3.
    assert "grecaptcha.render" in body, (
        "wrapper missing grecaptcha.render call (v2 invisible needs it)"
    )


def test_wrapper_js_carries_friendly_dispatch():
    """E17.4c — Friendly Captcha auto-start mode."""
    r = client.get("/botshield/embedded.js")
    assert r.status_code == 200
    body = r.text
    assert "friendly" in body, "wrapper missing friendly dispatch case"
    assert "runFriendly" in body, "wrapper missing runFriendly function"
    assert "friendlyChallenge.WidgetInstance" in body, (
        "wrapper missing friendlyChallenge.WidgetInstance constructor"
    )
    assert "doneCallback" in body, (
        "wrapper missing doneCallback (Friendly's solution callback)"
    )
    assert "startMode" in body and "auto" in body, (
        "wrapper missing startMode:'auto' for invisible behavior"
    )
    assert "cdn.jsdelivr.net/npm/friendly-challenge" in body, (
        "wrapper missing Friendly Captcha CDN loader"
    )


def test_bootstrap_returns_recaptcha_v2_provider(config_override):
    """Sanity check: bootstrap surfaces provider=recaptcha-v2 when
    configured. Sitekey is the v2 always-pass test pair (Google's
    only published v2 test keys; not invisible-specific but the
    bootstrap doesn't care about the sitekey type, just transports
    it to the wrapper)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location /botshield/embedded-bootstrap>\n'
        '        BotShieldCaptchaProvider recaptcha-v2\n'
        '        BotShieldCaptchaSiteKey 6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v2-secret\n'
        '    </Location>',
        count=1,
    ):
        r = client.get("/botshield/embedded-bootstrap")
        j = json.loads(r.text)
        assert j.get("provider") == "recaptcha-v2"


def test_bootstrap_returns_friendly_provider(config_override):
    """Same check for Friendly. The placeholder sitekey from the dev
    config is fine — bootstrap just round-trips it."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location /botshield/embedded-bootstrap>\n'
        '        BotShieldCaptchaProvider friendly\n'
        '        BotShieldCaptchaSiteKey FRIENDLY_CAPTCHA_SITEKEY_PLACEHOLDER\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/friendly-secret\n'
        '    </Location>',
        count=1,
    ):
        r = client.get("/botshield/embedded-bootstrap")
        j = json.loads(r.text)
        assert j.get("provider") == "friendly"


def test_verify_rejects_provider_mismatch(config_override):
    """Wrapper claims provider=recaptcha-v3 but scope is configured
    for turnstile: must 400 fail-loud, not silently coerce. The
    bs_embedded_verify_provider mismatch check fires."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location /botshield/embedded-verify>\n'
        '        BotShieldCaptchaProvider turnstile\n'
        '        BotShieldCaptchaSiteKey 1x00000000000000000000AA\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/turnstile-secret\n'
        '    </Location>',
        count=1,
    ):
        r = client.post(
            "/botshield/embedded-verify",
            data=json.dumps({
                "provider": "recaptcha-v3",
                "token": "fake-token-shouldnt-reach-google",
            }),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400, (
            f"provider mismatch should be 400; got {r.status_code}"
        )
