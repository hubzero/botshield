"""M8.1: Content-Type prefilter on /botshield/captcha-verify/*.

The verify endpoint must return 415 before libcurl is constructed
for any Content-Type other than application/x-www-form-urlencoded.
A form-urlencoded body gets past the prefilter; whether the final
outcome is OK/REJECTED/failopen is not this test's concern.

Port of tests/integration/m8_1_content_type.sh.
"""

from __future__ import annotations

from botshield_test import client


def test_json_content_type_rejected(pending_cookie):
    pending = pending_cookie("captcha-demo")
    resp = client.post(
        "/botshield/captcha-verify/turnstile",
        cookies={"_bs_captcha_pending": pending},
        headers={"Content-Type": "application/json"},
        data='{"cf-turnstile-response":"x"}',
    )
    assert resp.status_code == 415
    assert resp.headers.get("X-Botshield") == "captchabadcontenttype"


def test_missing_content_type_rejected(pending_cookie):
    pending = pending_cookie("captcha-demo")
    # Deliberately send no Content-Type header. httpx's `data=str`
    # bypasses the form-urlencoded auto-header; `content=` would
    # similarly skip it, but we need a tiny raw body regardless.
    resp = client.post(
        "/botshield/captcha-verify/turnstile",
        cookies={"_bs_captcha_pending": pending},
        headers={"Content-Type": ""},
        data="cf-turnstile-response=x",
    )
    assert resp.status_code == 415


def test_form_urlencoded_passes_prefilter(pending_cookie):
    pending = pending_cookie("captcha-demo")
    resp = client.post(
        "/botshield/captcha-verify/turnstile",
        cookies={"_bs_captcha_pending": pending},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )
    # Final status can be 303/403/failopen depending on siteverify —
    # the prefilter just has to not reject as 415.
    assert resp.status_code != 415, (
        f"form-urlencoded body wrongly rejected as 415; "
        f"headers={dict(resp.headers)}"
    )
