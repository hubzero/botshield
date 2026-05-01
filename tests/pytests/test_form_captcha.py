"""E18 — inline form captcha (verify-on-submit).

When `BotShieldFormCaptcha on` is set on a scope, BotShield's fixup
hook intercepts POSTs, reads the application/x-www-form-urlencoded
body, looks for the configured captcha provider's response field,
calls siteverify, and either:
  - mints __Host-bs_verified, replays the body via input filter, lets the
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
        'BotShieldAllowVerifiedBots on\n'
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
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
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
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data="email=foo@example.com&cf-turnstile-response=",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert r.status_code == 403


def test_form_captcha_rejects_wrong_content_type(config_override):
    """E18 supports url-encoded + JSON. Multipart and other shapes
    get 415 with diagnostic so operators notice the gap."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data="--b\r\nContent-Disposition: form-data\r\n\r\nfoo",
            headers={"Content-Type": "multipart/form-data; boundary=b"},
        )
    assert r.status_code == 415, (
        f"unsupported content-type should be 415; got {r.status_code}"
    )


def test_form_captcha_json_rejects_missing_token(config_override):
    """E18.3 — JSON body without the captcha-response field is
    rejected the same way url-encoded missing-token is."""
    import json as _json
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data=_json.dumps({"email": "foo@example.com"}),
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 403


def test_form_captcha_json_rejects_malformed(config_override):
    """E18.3 — non-JSON body claiming JSON content-type is a 400."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data="this is not json",
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 400


def test_form_captcha_json_passes_valid_token(config_override, log_slice):
    """E18.3 — JSON body with a valid Turnstile token round-trips
    through siteverify the same way url-encoded does. Cookie minted,
    body replay installed, downstream handler runs (Apache returns
    405 because /embedded-test.html is static)."""
    import json as _json
    valid_token = "any-token-the-always-pass-secret-accepts"
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
    ):
        with log_slice as slc:
            r = client.post(
                "/embedded-test.html",
                data=_json.dumps({
                    "email": "foo@example.com",
                    "cf-turnstile-response": valid_token,
                }),
                headers={"Content-Type": "application/json"},
            )
            log_text = slc.text()

    assert r.status_code != 403, (
        f"valid JSON form-captcha should not be rejected; "
        f"got 403"
    )
    assert "form-captcha verified" in log_text, (
        f"missing form-captcha-verified log line for JSON path"
    )


def test_form_captcha_passes_valid_token(config_override, log_slice):
    """Valid Turnstile token (from Cloudflare's always-pass test
    sitekey) → BotShield mints __Host-bs_verified, body replay filter is
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
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
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
    # Verify __Host-bs_verified was set on the response.
    set_cookies = r.headers.get_list("set-cookie") \
        if hasattr(r.headers, "get_list") \
        else [r.headers.get("set-cookie", "")]
    bs_cookie_set = any(
        "__Host-bs_verified=" in (c or "") for c in set_cookies
    )
    assert bs_cookie_set, (
        f"valid form-captcha should mint __Host-bs_verified; "
        f"set-cookies={set_cookies}"
    )


def test_form_widget_endpoint_serves_provider_dispatch():
    """E18.4 — /botshield/form-widget.js serves a JS shell that
    detects [data-bs-form-captcha] slots and injects per-provider
    markup. Sanity-check that the served body has the dispatch
    table and the right CDN URLs."""
    r = client.get("/botshield/form-widget.js")
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "javascript" in ct, f"expected JS content-type; got {ct!r}"
    body = r.text
    # Provider dispatch table
    for name in ("turnstile", "hcaptcha", "recaptcha-v2",
                 "recaptcha-v3", "friendly"):
        assert name in body, f"widget missing dispatch case: {name!r}"
    # Per-provider widget classes
    for cls in ("cf-turnstile", "h-captcha", "g-recaptcha",
                "frc-captcha"):
        assert cls in body, f"widget missing markup class: {cls!r}"
    # CDN loaders
    assert "challenges.cloudflare.com/turnstile" in body
    assert "js.hcaptcha.com" in body
    assert "google.com/recaptcha/api.js" in body
    assert "cdn.jsdelivr.net/npm/friendly-challenge" in body
    # Slot detection + run-once guard
    assert "_bsFormWidgetRan" in body
    assert "data-bs-form-captcha" in body


def test_form_captcha_honors_log_only(config_override):
    """E12 review fix — `BotShieldEnabled LogOnly` must suppress
    E18's policy-level 403s. A POST with a missing or bad captcha
    token under LogOnly should pass through (DECLINED; Apache
    static handler returns 405 because the test path doesn't
    accept POST). Without the fix, E18 hard-403's regardless of
    log-only and breaks the dry-run mental model."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldEnabled LogOnly\n'
        '    <Location /embedded-test.html>\n'
        '        BotShieldCaptchaProvider turnstile\n'
        '        BotShieldCaptchaSiteKey 1x00000000000000000000AA\n'
        '        BotShieldCaptchaSecretFile /etc/botshield/turnstile-secret\n'
        '        BotShieldFormCaptcha on\n'
        '    </Location>',
        count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data="email=foo@example.com&message=hi",  # missing token
            headers={"Content-Type":
                     "application/x-www-form-urlencoded"},
        )
    # Without LogOnly this would have been 403. Under LogOnly it
    # passes through to Apache, which 405s the static-file POST.
    assert r.status_code != 403, (
        f"LogOnly should suppress E18's 403; got {r.status_code}"
    )


def test_form_captcha_misconfigured_scope_503(config_override):
    """BotShieldFormCaptcha on without a configured provider on the
    scope is misconfiguration — 503 rather than silent allow."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
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


# --- HIGH #1: embedded-NUL parser-confusion smuggling ----------

def test_form_captcha_rejects_embedded_nul_byte(config_override, log_slice):
    """Security review HIGH #1. The form-captcha body is read as raw
    bytes but downstream validators treat it as a C string (bs_form_get
    uses strchr; json_tokener stops at '\\0'). The full byte buffer
    (including post-NUL bytes) is then replayed to the app handler. An
    attacker can hide a separate request shape past a NUL — BotShield
    validates the prefix, the app handler sees the full body. Fix:
    bodies containing any embedded NUL are rejected with 400 before
    any validator runs."""
    body = b"cf-turnstile-response=x\x00&hidden=evil"
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
    ):
        with log_slice as slc:
            r = client.post(
                "/embedded-test.html",
                data=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            matches = slc.grep(
                r"form-captcha body contains embedded NUL byte"
            )

    assert r.status_code == 400, (
        f"embedded-NUL body should be 400; got {r.status_code}"
    )
    assert matches, (
        "expected 'embedded NUL byte' rejection in log slice; "
        f"tail: {slc.text().splitlines()[-5:]}"
    )


def test_form_captcha_accepts_clean_body_with_high_bytes(
    config_override,
):
    """Counterpart to the NUL-rejection test: a body with high-bit
    bytes (>= 0x80) that is otherwise clean must NOT trigger the
    NUL guard. Confirms the rejection is scoped to 0x00, not to
    'any non-ASCII byte', so the guard doesn't break legitimate
    clients sending UTF-8 in form fields."""
    # The captcha is "x" (a non-empty token) so siteverify will run;
    # we don't care about the verify outcome here — just that the
    # body wasn't pre-rejected by the NUL guard.
    body = (
        b"cf-turnstile-response=x&"
        b"name=" + "café".encode("utf-8")
    )
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on", _override_form_captcha(), count=1,
    ):
        r = client.post(
            "/embedded-test.html",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
    # Either the captcha verifies (200/302/etc.) or fails (403). Both
    # are fine; what matters is we got past the NUL pre-check.
    assert r.status_code != 400, (
        f"clean high-bit body was rejected with 400 — NUL guard is "
        f"too aggressive. status={r.status_code}"
    )
