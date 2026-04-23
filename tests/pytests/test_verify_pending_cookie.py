"""M8.1: pending-cookie guardrail on the verify endpoint.

Without a valid `_bs_captcha_pending` cookie the module must
short-circuit to 403 + X-Botshield: captcha-pending-missing,
before constructing any libcurl handle. Catches regressions in the
cheap-check-first ordering.

Port of tests/integration/m8_1_pending_cookie.sh.
"""

from __future__ import annotations

from botshield_test import client


def test_no_cookie_returns_403():
    resp = client.post(
        "/botshield/captcha-verify/turnstile",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )
    assert resp.status_code == 403
    assert resp.headers.get("X-Botshield") == "captcha-pending-missing"


def test_tampered_cookie_returns_403():
    # Right shape, wrong HMAC — hex garbage in the signature slot.
    tampered = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "|9999999999|"
        + "de" * 32
    )
    resp = client.post(
        "/botshield/captcha-verify/turnstile",
        cookies={"_bs_captcha_pending": tampered},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )
    assert resp.status_code == 403
    assert resp.headers.get("X-Botshield") == "captcha-pending-missing"


def test_valid_cookie_passes_guard(pending_cookie):
    pending = pending_cookie("captcha-demo")
    resp = client.post(
        "/botshield/captcha-verify/turnstile",
        cookies={"_bs_captcha_pending": pending},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )
    # Assert only that we got past the pending check. Final outcome
    # (303/403/failopen) depends on Turnstile and is tested elsewhere.
    xbs = resp.headers.get("X-Botshield", "")
    assert xbs != "captcha-pending-missing", (
        f"valid pending cookie still tripped the guard: X-Botshield={xbs}"
    )
