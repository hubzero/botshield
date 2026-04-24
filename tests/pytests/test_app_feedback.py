"""E5 — app-to-module reputation feedback.

App sets `X-BotShield-Feedback: flag=<name>;ttl=<sec>;sig=<hmac>`
on its response. Module validates the HMAC, strips the header, and
applies the flag to the flagged-IP table so future requests from
that IP carry the bit's score contribution.

Tests use the `Header always set` directive from mod_headers to
plant the feedback header on responses to specific locations.
We cover both the normal content chain (existing files in the
dev vhost's DocumentRoot) and Apache's separate error-response
chain (404 for a missing path) — the module registers the strip
filter on both chains so the "header never reaches client"
promise holds regardless of response status.

Secret is fixed in `tests/setup/provision.sh`
(/etc/botshield/app-feedback-secret) so the test can recompute
HMACs with the same bytes.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from botshield_test import client, ips as _ips


pytestmark = pytest.mark.serial


SECRET_PATH = "/etc/botshield/app-feedback-secret"
SECRET = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"

FEEDBACK_PATH_1 = "/about.html"
FEEDBACK_PATH_2 = "/login.html"
FEEDBACK_LOC_1  = '<Location "/about.html">'
FEEDBACK_LOC_2  = '<Location "/login.html">'


def _g(path, xff, **kw):
    return client.get(path, xff=xff, ua=PASS_UA,
                      accept_language=PASS_AL, **kw)


def _sign(flag: str, ttl: int, extra: str = "") -> str:
    body = f"flag={flag};ttl={ttl}"
    if extra:
        body += ";" + extra
    sig = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"{body};sig={sig}"


def _cfg(body_inserts: str) -> str:
    return (
        'BotShieldAllow on\n'
        '    BotShieldAppFeedback on\n'
        f'    BotShieldAppFeedbackSecretFile {SECRET_PATH}\n'
        + body_inserts
    )


# --- Happy paths: penalty bit + credit bit --------------------------


def test_app_feedback_penalty_flag_applies_to_next_request(
    config_override, log_slice,
):
    val = _sign("honeypot_hit", 3600)
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        _cfg(
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r1 = _g(FEEDBACK_PATH_1, xff=ip)
        assert "X-BotShield-Feedback" not in r1.headers, (
            "feedback header leaked to client; strip-before-send "
            "rule broken"
        )
        with log_slice as slc:
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)
    assert lines, "no follow-up decision line"
    assert "flagged-ip" in lines[-1]["reason"], (
        f"follow-up request didn't pick up the flagged bit; "
        f"reason={lines[-1]['reason']}"
    )


def test_app_feedback_credit_flag_lowers_score(
    config_override, log_slice,
):
    val = _sign("app_verified_human", 3600)
    ip_base = _ips.fresh_ip()
    ip_cred = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        _cfg(
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        _g(FEEDBACK_PATH_1, xff=ip_cred)
        with log_slice as slc:
            _g("/index.html", xff=ip_base)
            _g("/index.html", xff=ip_cred)
            base_lines = slc.decision_lines(ip=ip_base)
            cred_lines = slc.decision_lines(ip=ip_cred)

    assert base_lines and cred_lines
    base_score = int(base_lines[-1]["score"])
    cred_score = int(cred_lines[-1]["score"])
    assert cred_score == base_score - 80, (
        f"app_verified_human credit of -80 didn't land; "
        f"baseline={base_score} credited={cred_score}"
    )


# --- Strip rules ----------------------------------------------------


def test_app_feedback_strips_from_404_error_response(
    config_override,
):
    """Regression: Apache's 404 (missing-file) response travels a
    separate filter chain than normal content. Without the
    `ap_hook_insert_error_filter` registration, mod_headers' `Header
    always set` leaks the feedback header to the client on 404s.
    Confirm it's stripped."""
    val = _sign("honeypot_hit", 3600)
    missing_path = "/this-file-does-not-exist-404.html"
    with config_override(
        r"BotShieldAllow\s+on",
        _cfg(
            f'    <Location "{missing_path}">\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r = _g(missing_path, xff=_ips.fresh_ip())
    assert r.status_code == 404, (
        f"expected 404 (missing file); got {r.status_code}"
    )
    assert "X-BotShield-Feedback" not in r.headers, (
        "feedback header leaked to client on 404 error response; "
        "the error-filter chain registration is missing"
    )


def test_app_feedback_strips_when_feature_off(config_override):
    val = _sign("honeypot_hit", 3600)
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldAppFeedback off\n'
        f'    BotShieldAppFeedbackSecretFile {SECRET_PATH}\n'
        f'    {FEEDBACK_LOC_1}\n'
        f'        Header always set X-BotShield-Feedback "{val}"\n'
        f'    </Location>',
        count=1,
    ):
        r = _g(FEEDBACK_PATH_1, xff=_ips.fresh_ip())
    assert r.status_code == 200
    assert "X-BotShield-Feedback" not in r.headers, (
        "feature=off must still strip the header on output"
    )


def test_app_feedback_tampered_sig_rejected_and_stripped(
    config_override, log_slice,
):
    val = _sign("honeypot_hit", 3600)
    tampered = val[:-1] + ("0" if val[-1] != "0" else "1")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        _cfg(
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{tampered}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r1 = _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)

    assert "X-BotShield-Feedback" not in r1.headers, (
        "tampered header must still be stripped"
    )
    assert lines and "flagged-ip" not in lines[-1]["reason"], (
        f"tampered feedback shouldn't have flagged the IP; "
        f"reason={lines[-1]['reason']}"
    )


# --- TTL clamp + unknown flag ---------------------------------------


def test_app_feedback_rejects_out_of_range_ttl(
    config_override, log_slice,
):
    val = _sign("honeypot_hit", 10)
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        _cfg(
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r1 = _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)

    assert "X-BotShield-Feedback" not in r1.headers
    assert lines and "flagged-ip" not in lines[-1]["reason"]


def test_app_feedback_rejects_unknown_flag(config_override, log_slice):
    val = _sign("definitely_not_a_real_flag", 3600)
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        _cfg(
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r1 = _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)

    assert "X-BotShield-Feedback" not in r1.headers
    assert lines and "flagged-ip" not in lines[-1]["reason"]


# --- Credit + penalty compose --------------------------------------


def test_app_feedback_credit_and_penalty_compose(
    config_override, log_slice,
):
    """An IP that trips a honeypot AND later gets app_verified_human
    should carry the composite flag penalty +60 + (-80) = -20 on
    future requests. We assert on the flag contribution directly
    rather than on the composed score (first-sight and other
    heuristics can shift the absolute number but the `flagged-ip`
    reason token is where the flag-penalty math surfaces)."""
    penalty_val = _sign("honeypot_hit", 3600)
    credit_val  = _sign("app_verified_human", 3600)
    ip_both = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        _cfg(
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{penalty_val}"\n'
            f'    </Location>\n'
            f'    {FEEDBACK_LOC_2}\n'
            f'        Header always set X-BotShield-Feedback "{credit_val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        _g(FEEDBACK_PATH_1, xff=ip_both)   # earn honeypot_hit  (+60)
        _g(FEEDBACK_PATH_2, xff=ip_both)   # earn app_verified_human (-80)
        # A few subsequent requests so Bloom eats first-sight-ip and
        # the follow-up's reason trace doesn't include it, leaving
        # just flagged-ip as the visible flag contribution.
        _g("/index.html", xff=ip_both)
        _g("/index.html", xff=ip_both)
        _g("/index.html", xff=ip_both)
        with log_slice as slc:
            _g("/index.html", xff=ip_both)
            lines = slc.decision_lines(ip=ip_both)

    assert lines
    # Score is dominated by flag-penalty now. Composite should be
    # -20 (60 + -80); other heuristics pile ≤0 for a clean UA.
    score = int(lines[-1]["score"])
    assert score == -20, (
        f"penalty+credit compose didn't yield net -20; "
        f"reason={lines[-1]['reason']} score={score}"
    )
    assert "flagged-ip" in lines[-1]["reason"]
