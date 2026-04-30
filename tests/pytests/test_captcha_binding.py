"""Security review #1: captcha siteverify response must be bound to
THIS origin and THIS BotShield flow, not just "provider said success".

Before this fix, a valid reCAPTCHA v3 token minted for the same
sitekey but a different action (or any Google-family token minted
for a different hostname) would be accepted as long as success:true
came back. The fix adds:
  - Hostname check against r->server->server_hostname (default) or
    BotShieldCaptchaExpectedHostname.
  - Action check (reCAPTCHA v3 + Turnstile) against "botshield" or
    BotShieldCaptchaExpectedAction.

Mismatch flips OK → REJECTED with outcome=rejected and a reason
string like "hostname-mismatch:got=example.com,expected=attacker.tld".
"""

from __future__ import annotations

import pytest

from botshield_test import client, cookies


pytestmark = [pytest.mark.serial, pytest.mark.live_network]


def test_hostname_mismatch_rejects_valid_token(config_override, log_slice):
    """Turnstile's always-pass returns hostname=example.com. If we
    configure the verify endpoint to expect a DIFFERENT hostname,
    the otherwise-valid token must be rejected."""
    # Swap the expected hostname to something the response will never
    # match. config_override reverts on exit.
    with config_override(
        r"BotShieldCaptchaExpectedHostname\s+example\.com",
        "BotShieldCaptchaExpectedHostname wrong.attacker.tld",
        count=1,
    ):
        pending = cookies.fetch_pending_cookie("captcha-demo")

        with log_slice as slc:
            resp = client.post(
                "/botshield/captcha-verify/turnstile",
                cookies={"_bs_captcha_pending": pending},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"cf-turnstile-response": "x", "return_to": "/"},
            )
            rejected = slc.decision_lines(
                outcome="block", provider="turnstile",
            )

    assert resp.status_code == 403, (
        f"hostname mismatch should 403 a valid token; got {resp.status_code}"
    )
    assert resp.headers.get("X-Botshield") == "captcha-rejected"
    assert rejected, "no outcome=rejected decision line for hostname mismatch"
    # Reason carries the mismatch detail so operators can diagnose.
    reasons = {line.get("reason") for line in rejected}
    assert any("hostname-mismatch" in r for r in reasons), (
        f"expected 'hostname-mismatch' in reason; got {reasons}"
    )


def test_hostname_match_accepts_valid_token(pending_cookie):
    """Sanity: with the default dev-vhost config (expected hostname =
    example.com, matching what Turnstile's always-pass echoes), a
    valid token succeeds. This guards against the fix accidentally
    rejecting legitimate tokens."""
    pending = pending_cookie("captcha-demo")
    resp = client.post(
        "/botshield/captcha-verify/turnstile",
        cookies={"_bs_captcha_pending": pending},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )
    assert resp.status_code == 303, (
        f"default (matching) hostname should accept; got {resp.status_code}"
    )
    assert resp.headers.get("X-Botshield") == "captcha-ok"


def test_off_expected_hostname_disables_check(config_override, pending_cookie):
    """Setting BotShieldCaptchaExpectedHostname to the literal value
    `off` is the documented escape hatch for multi-origin
    deployments. It must bypass the hostname check so a valid token
    is accepted even if the echoed hostname differs from anything
    we'd compare to. (`off` rather than "" because Apache's
    directive parser rejects bare "" as zero args.)"""
    with config_override(
        r"BotShieldCaptchaExpectedHostname\s+example\.com",
        "BotShieldCaptchaExpectedHostname off",
        count=1,
    ):
        pending = pending_cookie("captcha-demo")
        resp = client.post(
            "/botshield/captcha-verify/turnstile",
            cookies={"_bs_captcha_pending": pending},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"cf-turnstile-response": "x", "return_to": "/"},
        )
    assert resp.status_code == 303, (
        f"`off` expected-hostname should disable the check; "
        f"got {resp.status_code}"
    )
    assert resp.headers.get("X-Botshield") == "captcha-ok"
