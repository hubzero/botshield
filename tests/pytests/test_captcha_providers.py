"""Parametrized captcha-provider tests.

Replaces six bash scripts (m8_captcha_{turnstile,hcaptcha,recaptcha_v2,
recaptcha_v3,friendly,geetest}.sh) with four parametrized tests that
drive the per-provider spec in `botshield_test.providers`.

Coverage:
  - test_captcha_ok: providers that ship with an always-pass test
    keypair (Turnstile, hCaptcha, reCAPTCHA v2). Asserts 303 +
    X-Botshield: captcha-ok + __Host-bs_session cookie issued.
  - test_captcha_plumbing_smoke: all six providers. Fire a bogus
    token through the verify endpoint and assert the decision log
    carries `provider=<name>`. Regression gate for body-field
    extraction, siteverify routing, and decision-log dispatch —
    works without real keys.
  - test_captcha_rejected_via_bad_secret: Turnstile + v2 only. Uses
    config_override to swap in a known-bad secret, asserts 403 +
    captcha-rejected. Serial (mutates vhost).
  - test_captcha_body_field_regression: Friendly + GeeTest. Posts
    the wrong field name, asserts 400 + 'missing token field' log.
    Catches any rename of the frc-captcha-solution / geetest-token
    fields.
"""

from __future__ import annotations

import pytest

from botshield_test import client
from botshield_test.providers import (
    ALL, FRIENDLY, GEETEST,
    WITH_OK_TOKEN, WITH_SECRET_SWAP,
)


pytestmark = pytest.mark.live_network


def _reachable(spec) -> bool:
    try:
        r = client.get(
            "/", base_url=spec.siteverify_probe, timeout=5,
        )
        return r.status_code < 500
    except Exception:
        return False


# --- OK branch ---------------------------------------------------------------

@pytest.mark.parametrize(
    "spec", WITH_OK_TOKEN, ids=lambda s: s.name,
)
def test_captcha_ok(spec, pending_cookie):
    if not _reachable(spec):
        pytest.skip(f"{spec.siteverify_probe} unreachable")

    pending = pending_cookie(spec.demo_path)
    resp = client.post(
        spec.verify_path,
        cookies={"_bs_captcha_pending": pending},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={spec.body_field: spec.ok_token, "return_to": "/"},
    )
    assert resp.status_code == 303, (
        f"{spec.name}: expected 303, got {resp.status_code}; "
        f"headers={dict(resp.headers)}"
    )
    assert resp.headers.get("X-Botshield") == "captcha-ok"
    assert resp.cookies.get("__Host-bs_session"), (
        f"{spec.name}: no __Host-bs_session cookie issued"
    )


# --- Plumbing smoke (all six providers) --------------------------------------

@pytest.mark.parametrize("spec", ALL, ids=lambda s: s.name)
def test_captcha_plumbing_smoke(spec, pending_cookie, log_slice):
    """Module must route any POST to the right provider's code path.

    Even with placeholder secrets + a bogus token, the decision log
    should show `provider=<name>` (either from an OK, REJECTED, or
    failopen outcome — all three go through the provider's module).
    """
    if not _reachable(spec):
        pytest.skip(f"{spec.siteverify_probe} unreachable")

    pending = pending_cookie(spec.demo_path)

    # GeeTest's "token" is a JSON-packed bundle; the frontend packs
    # four fields into one body-field value. Send something JSON-
    # shaped so the parser doesn't reject before siteverify.
    if spec.name == "geetest":
        bogus = (
            '{"lot_number":"l","captcha_output":"o",'
            '"pass_token":"p","gen_time":"1"}'
        )
    else:
        bogus = "garbage-token"

    with log_slice as slc:
        client.post(
            spec.verify_path,
            cookies={"_bs_captcha_pending": pending},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={spec.body_field: bogus, "return_to": "/"},
        )
        matched = slc.decision_lines(provider=spec.log_name)

    assert matched, (
        f"{spec.name}: no decision line with provider={spec.log_name}; "
        f"all lines in slice: {slc.decision_lines()}"
    )


# --- REJECTED via bad-secret swap (Turnstile + v2) ---------------------------

@pytest.mark.serial
@pytest.mark.parametrize(
    "spec", WITH_SECRET_SWAP, ids=lambda s: s.name,
)
def test_captcha_rejected_via_bad_secret(
    spec, pending_cookie, config_override, log_slice,
):
    if not _reachable(spec):
        pytest.skip(f"{spec.siteverify_probe} unreachable")

    # Swap the Location's secret file path. The regex matches the
    # full line including whitespace; replacement uses the bad file.
    good = spec.good_secret_file
    bad = spec.bad_secret_file
    # Match 1+ whitespace characters between directive + path so the
    # test survives aligned-column formatting in the vhost file.
    pattern = rf"BotShieldCaptchaSecretFile\s+{good}"
    replacement = f"BotShieldCaptchaSecretFile {bad}"

    pending = pending_cookie(spec.demo_path)
    with config_override(pattern, replacement):
        with log_slice as slc:
            resp = client.post(
                spec.verify_path,
                cookies={"_bs_captcha_pending": pending},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={spec.body_field: spec.ok_token, "return_to": "/"},
            )
            # Assert on decision line (never throttled) rather than
            # the prose "captcha REJECTED" line (log-throttled 1/60s
            # per IP — flaky under rapid re-runs).
            matched = slc.decision_lines(
                outcome="block", provider=spec.log_name,
            )

    assert resp.status_code == 403, (
        f"{spec.name}: expected 403 with bad secret, got {resp.status_code}"
    )
    assert resp.headers.get("X-Botshield") == "captcha-rejected"
    assert matched, (
        f"{spec.name}: no 'outcome=block provider={spec.log_name}' line"
    )


# --- Body-field-name regression (Friendly + GeeTest) -------------------------

@pytest.mark.parametrize(
    "spec", [FRIENDLY, GEETEST], ids=lambda s: s.name,
)
def test_captcha_body_field_name_stable(spec, pending_cookie, log_slice):
    """A wrong body field name must produce 400 + 'missing token
    field' rather than silently hitting siteverify with an empty
    value. If this fails, a rename of the field has gone undetected.
    """
    if not _reachable(spec):
        pytest.skip(f"{spec.siteverify_probe} unreachable")

    pending = pending_cookie(spec.demo_path)
    with log_slice as slc:
        resp = client.post(
            spec.verify_path,
            cookies={"_bs_captcha_pending": pending},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            # Deliberately wrong field name (the generic "token" is
            # not what the module reads for either of these).
            data={"token": "x", "return_to": "/"},
        )
        hits = slc.grep(f"missing token field '{spec.body_field}'")

    assert resp.status_code == 400
    assert hits, (
        f"{spec.name}: expected 'missing token field {spec.body_field!r}' "
        f"log line; none found"
    )
