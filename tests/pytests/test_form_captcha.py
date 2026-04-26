"""E18 — inline form captcha (verify-on-submit).

When `BotShieldFormCaptcha on` is set on a scope, BotShield's fixup
hook intercepts POSTs, reads the application/x-www-form-urlencoded
body, looks for the configured captcha provider's response field,
calls siteverify, and either:
  - mints _bs_verified, replays the body via input filter, lets the
    downstream app handler run normally
  - 403s the request before the app handler ever sees it

These tests exercise the decision boundary using Cloudflare's
published always-pass Turnstile keys so siteverify doesn't need real
operator credentials. End-to-end body-replay correctness shows up in
the BotShield decision log ("form-captcha verified (body_len=N)")
when the request reaches the downstream handler — visible in the
error log if a test ever needs to drill into it.
"""

from __future__ import annotations

import re

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


# Cloudflare always-pass Turnstile pair.
SITEKEY = "1x00000000000000000000AA"
SECRET_PATH = "/etc/botshield/turnstile-secret"


def _override_form_captcha(provider: str = "turnstile",
                           sitekey: str = SITEKEY,
                           secret_path: str = SECRET_PATH,
                           expected_hostname: str = "example.com") -> str:
    """Build the override block enabling BotShieldFormCaptcha on a
    test scope. Returns the replacement string for config_override.

    expected_hostname defaults to "example.com" because Cloudflare's
    always-pass Turnstile siteverify response carries hostname=
    example.com — without the override, the M8 hostname binding
    fires (got=example.com expected=localhost) and rejects."""
    return (
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        f'        BotShieldCaptchaProvider {provider}\n'
        f'        BotShieldCaptchaSiteKey {sitekey}\n'
        f'        BotShieldCaptchaSecretFile {secret_path}\n'
        f'        BotShieldCaptchaExpectedHostname {expected_hostname}\n'
        '        BotShieldFormCaptcha on\n'
        '    </Location>'
    )


def test_form_captcha_rejects_missing_token(config_override):
    """POST without a captcha-response field must 403 — fixup hook
    short-circuits before any app handler sees the body."""
    with config_override(
        r"BotShieldAllow\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data="email=foo@example.com&message=hi",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert r.status_code == 403, (
        f"missing token should be 403; got {r.status_code}"
    )


def test_form_captcha_rejects_empty_token(config_override):
    """Empty token field is the same as missing — 403."""
    with config_override(
        r"BotShieldAllow\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data="email=foo@example.com&cf-turnstile-response=",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert r.status_code == 403


def test_form_captcha_rejects_wrong_content_type(config_override):
    """v1 supports only application/x-www-form-urlencoded; multipart
    or JSON POSTs get a 415 with diagnostic so operators notice the
    gap immediately."""
    with config_override(
        r"BotShieldAllow\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data='{"cf-turnstile-response":"x"}',
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 415, (
        f"unsupported content-type should be 415; got {r.status_code}"
    )


def test_form_captcha_passes_valid_token(config_override, log_slice):
    """Valid Turnstile token (from Cloudflare's always-pass test
    sitekey) → BotShield mints _bs_verified, body replay filter is
    installed, downstream handler runs.

    /embedded-test.html is a static file that doesn't accept POST,
    so Apache returns 405. That 405 means BotShield got out of the
    way (DECLINED) — exactly what we want. The interesting signal
    is the log line."""
    # Cloudflare's always-pass response token. Their test secret
    # accepts any non-empty token for the always-pass sitekey, so
    # this is fine. Real production tokens are JWT-shaped.
    valid_token = "any-token-the-always-pass-secret-accepts"
    with config_override(
        r"BotShieldAllow\s+on", _override_form_captcha(), count=1,
    ):
        with log_slice as slc:
            r = client.post(
                "/embedded-test.html",
                data=(f"email=foo@example.com&"
                      f"cf-turnstile-response={valid_token}"),
                headers={
                    "Content-Type":
                    "application/x-www-form-urlencoded",
                },
            )
            log_text = slc.text()

    # Not 403 means BotShield didn't reject the captcha.
    # Apache then returned 405 (POST not allowed on a static file).
    assert r.status_code != 403, (
        f"valid captcha should NOT be rejected; got 403 — "
        f"check siteverify reachability and always-pass secret"
    )
    # The log line proves the fixup ran the verify path and replay
    # was installed. Body-len should match what we sent.
    assert "form-captcha verified" in log_text, (
        f"missing form-captcha-verified log line; "
        f"log tail:\n{log_text[-2000:]}"
    )
    # Verify _bs_verified was set on the response.
    set_cookies = r.headers.get_list("set-cookie") \
        if hasattr(r.headers, "get_list") \
        else [r.headers.get("set-cookie", "")]
    bs_cookie_set = any(
        "_bs_verified=" in (c or "") for c in set_cookies
    )
    assert bs_cookie_set, (
        f"valid form-captcha should mint _bs_verified; "
        f"set-cookies={set_cookies}"
    )


def test_form_captcha_misconfigured_scope_503(config_override):
    """BotShieldFormCaptcha on without a configured provider on the
    scope is misconfiguration — 503 rather than silent allow."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldFormCaptcha on\n'
        '    </Location>',
        count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data="cf-turnstile-response=x",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
    assert r.status_code == 503
