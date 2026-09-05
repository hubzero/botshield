"""E5 — app-to-module reputation feedback (post-E7.3 wire format).

App sets `X-BotShield-Feedback: event=<name>;sig=<hmac>` on its
response. The signer only has to know the HMAC secret and an event
name; the mapping from event → action (flag bit + TTL + optional
log tag) is declared server-side via `BotShieldFeedbackTrigger`, so
a compromised app can't reach into arbitrary module memory by
emitting raw `flag=` / `ttl=` tokens on the wire.

Tests use `Header always set` from mod_headers to plant the feedback
header on responses to specific locations. We cover both the normal
content chain (existing files in the dev vhost's DocumentRoot) and
Apache's separate error-response chain (404 for a missing path) —
the module registers the strip filter on both chains so the "header
never reaches client" promise holds regardless of response status.

Secret is fixed in `tests/setup/provision.sh`
(/etc/botshield/app-integration-secret) so the test can recompute
HMACs with the same bytes. The same key covers the outbound
X-Botshield-Claims path (test_app_claims.py); the two protocols'
canonical forms are structurally distinct so cross-replay is
blocked by parser shape, not by key separation.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from botshield_test import client, ips as _ips


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


SECRET_PATH = "/etc/botshield/app-integration-secret"
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


def _sign(event: str, extra: str = "") -> str:
    """Produce an E7.3 wire-format X-BotShield-Feedback value.

    Body is `event=<name>[;extra];sig=<hex>`. HMAC covers everything
    up to (not including) the `;sig=` marker.
    """
    body = f"event={event}"
    if extra:
        body += ";" + extra
    sig = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"{body};sig={sig}"


def _cfg(feedback_triggers: str, body_inserts: str) -> str:
    """Assemble the override block.

    `feedback_triggers` is zero or more `BotShieldFeedbackTrigger`
    lines (pre-indented to match the vhost-body style), and
    `body_inserts` is the <Location>…</Location> chunk that plants
    the header on the test path.
    """
    return (
        'BotShieldEnabled On\n'
        '    BotShieldAppFeedback on\n'
        f'    BotShieldAppIntegrationSecretFile {SECRET_PATH}\n'
        + feedback_triggers
        + body_inserts
    )


# --- Happy paths: penalty bit + credit bit --------------------------


def test_app_feedback_penalty_flag_applies_to_next_request(
    config_override, log_slice,
):
    """Event `scanner-hit` maps to flag=honeypot_hit ttl=3600. App
    signs the event name; module looks it up in the config and
    applies the configured bit to the flagged-IP table."""
    val = _sign("scanner-hit")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    BotShieldFeedbackTrigger scanner-hit '
            'flag=honeypot_hit ttl=3600\n',
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
    assert "flaggedip" in lines[-1]["reason"], (
        f"follow-up request didn't pick up the flagged bit; "
        f"reason={lines[-1]['reason']}"
    )


def test_app_feedback_observed_under_log_only(
    config_override, log_slice,
):
    """E12 — `BotShieldEnabled LogOnly` flips every trigger match into
    observe semantics. The feedback path lives on the response-side
    E5 filter (not the shared bs_apply_trigger_action executor), so
    bridge.c honors the dir-cfg log-only gate inline. Without that
    gate, a signed feedback event would still mutate the flagged-IP
    table while staging policy under LogOnly — exactly the staging
    hazard E12 was added to prevent.

    Verify by minting feedback under LogOnly, then checking that
    a follow-up request from the same IP does NOT see the
    flaggedip reason."""
    val = _sign("scanner-hit")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnabled LogOnly\n'
        '    BotShieldAppFeedback on\n'
        f'    BotShieldAppIntegrationSecretFile {SECRET_PATH}\n'
        '    BotShieldFeedbackTrigger scanner-hit '
        'flag=honeypot_hit ttl=3600\n'
        f'    {FEEDBACK_LOC_1}\n'
        f'        Header always set X-BotShield-Feedback "{val}"\n'
        f'    </Location>',
        count=1,
    ):
        with log_slice as slc:
            _g(FEEDBACK_PATH_1, xff=ip)
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)

    assert lines, "no decision lines emitted"
    follow_up = lines[-1]["reason"]
    assert "flaggedip" not in follow_up, (
        f"follow-up request picked up the flagged bit even though "
        f"BotShieldEnabled LogOnly was set; bridge.c bypassed the "
        f"observe gate. reason={follow_up}"
    )
    # An observe match still shows up in the slice text — the filter
    # logs `event=<x> observed (would-flag=...) — shadow/observe`.
    assert any("observed" in ln for ln in slc.grep("scanner-hit")), (
        f"expected observe-mode log line for the feedback event; "
        f"slice tail did not surface one"
    )


def test_app_feedback_per_trigger_observe_mode(
    config_override, log_slice,
):
    """Per-trigger `mode=observe` on a BotShieldFeedbackTrigger
    suppresses the flagged-IP write the same way scope-level
    BotShieldEnabled LogOnly does. Even though feedback runs on
    the response path, the side effect is future-request state —
    so observe-mode gates that mutation. bridge.c honors
    `ft->action.mode == BS_TMODE_OBSERVE` next to the dir-cfg
    log-only check."""
    val = _sign("scanner-hit")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldAppFeedback on\n'
        f'    BotShieldAppIntegrationSecretFile {SECRET_PATH}\n'
        '    BotShieldFeedbackTrigger scanner-hit '
        'flag=honeypot_hit ttl=3600 mode=observe\n'
        f'    {FEEDBACK_LOC_1}\n'
        f'        Header always set X-BotShield-Feedback "{val}"\n'
        f'    </Location>',
        count=1,
    ):
        with log_slice as slc:
            _g(FEEDBACK_PATH_1, xff=ip)
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)

    assert lines, "no decision lines emitted"
    follow_up = lines[-1]["reason"]
    assert "flaggedip" not in follow_up, (
        f"follow-up request picked up the flagged bit even though "
        f"the feedback trigger was mode=observe. reason={follow_up}"
    )
    assert any("observed" in ln for ln in slc.grep("scanner-hit")), (
        f"expected observe-mode log line for the feedback event"
    )


def test_app_feedback_credit_flag_lowers_score(
    config_override, log_slice,
):
    """Credit bits land the same way penalty bits do; the event →
    flag mapping is the only surface the app controls."""
    val = _sign("human-verified")
    ip_base = _ips.fresh_ip()
    ip_cred = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    BotShieldFeedbackTrigger human-verified '
            'flag=app_verified_human ttl=3600\n',
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
    # The app_verified_human flag adds -80 to the score. The exact
    # diff depends on which heuristics fire on each IP at the time
    # of the follow-up — ip_cred was put in the Bloom filter by
    # its earlier feedback request and now picks up droppedcookie
    # (+25) on the follow-up, while ip_base on its first request
    # does not. Assert the credit landed (cred materially below
    # baseline) rather than a fragile exact-diff equality.
    assert cred_score <= base_score - 50, (
        f"app_verified_human credit didn't land meaningfully; "
        f"baseline={base_score} credited={cred_score} "
        f"(expected cred at least 50 below baseline)"
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
    val = _sign("scanner-hit")
    missing_path = "/this-file-does-not-exist-404.html"
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    BotShieldFeedbackTrigger scanner-hit '
            'flag=honeypot_hit ttl=3600\n',
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
    val = _sign("scanner-hit")
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldAppFeedback off\n'
        f'    BotShieldAppIntegrationSecretFile {SECRET_PATH}\n'
        '    BotShieldFeedbackTrigger scanner-hit '
        'flag=honeypot_hit ttl=3600\n'
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
    val = _sign("scanner-hit")
    tampered = val[:-1] + ("0" if val[-1] != "0" else "1")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    BotShieldFeedbackTrigger scanner-hit '
            'flag=honeypot_hit ttl=3600\n',
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
    assert lines and "flaggedip" not in lines[-1]["reason"], (
        f"tampered feedback shouldn't have flagged the IP; "
        f"reason={lines[-1]['reason']}"
    )


# --- Unmapped event + legacy wire format -------------------------


def test_app_feedback_unmapped_event_is_ignored(
    config_override, log_slice,
):
    """App signs an event name nobody has BotShieldFeedbackTrigger'd.
    The HMAC is valid but the event has no module-memory mapping, so
    the flag doesn't land. Gives operators safe rollout: apps can
    start emitting new event names before the config catches up."""
    val = _sign("brand-new-event-name")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            # deliberately no BotShieldFeedbackTrigger for the event
            '',
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
    assert lines and "flaggedip" not in lines[-1]["reason"], (
        f"unmapped event should not have flagged the IP; "
        f"reason={lines[-1]['reason']}"
    )


def test_app_feedback_legacy_wire_format_rejected(
    config_override, log_slice,
):
    """Pre-E7.3 apps signed `flag=<name>;ttl=<sec>` directly. After
    E7.3 the module HMACs event=<name>, so an old-format body will
    either fail HMAC verification (signer covered different bytes)
    or fail the event= required-field check — either way the IP is
    not flagged and the header is stripped."""
    # Reproduce the pre-E7.3 wire format: sign `flag=<name>;ttl=<sec>`.
    body = "flag=honeypot_hit;ttl=3600"
    sig = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    val = f"{body};sig={sig}"
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    BotShieldFeedbackTrigger legacy-guard '
            'flag=honeypot_hit ttl=3600\n',
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
    assert lines and "flaggedip" not in lines[-1]["reason"], (
        f"legacy wire format must not flag; "
        f"reason={lines[-1]['reason']}"
    )


# --- Credit + penalty compose --------------------------------------


def test_app_feedback_credit_and_penalty_compose(
    config_override, log_slice,
):
    """An IP that trips a honeypot AND later gets app_verified_human
    should carry the composite flag penalty +60 + (-80) = -20 on
    future requests. We assert on the flag contribution directly
    rather than on the composed score (first-sight and other
    heuristics can shift the absolute number but the `flaggedip`
    reason token is where the flag-penalty math surfaces)."""
    penalty_val = _sign("scanner-hit")
    credit_val  = _sign("human-verified")
    ip_both = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    BotShieldFeedbackTrigger scanner-hit '
            'flag=honeypot_hit ttl=3600\n'
            '    BotShieldFeedbackTrigger human-verified '
            'flag=app_verified_human ttl=3600\n',
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
        # A few subsequent requests so Bloom eats firstsightip and
        # the follow-up's reason trace doesn't include it, leaving
        # just flaggedip as the visible flag contribution.
        _g("/index.html", xff=ip_both)
        _g("/index.html", xff=ip_both)
        _g("/index.html", xff=ip_both)
        with log_slice as slc:
            _g("/index.html", xff=ip_both)
            lines = slc.decision_lines(ip=ip_both)

    assert lines
    # Score is dominated by flag-penalty composition: honeypot +60
    # plus app_verified_human -80 = -20. The droppedcookie
    # heuristic adds +25 on cookieless follow-ups whose IP is in the
    # Bloom filter, so the observed score on a typical run is +5.
    # We assert the composite landed roughly where it should (well
    # below zero plus a small buffer for the droppedcookie penalty)
    # rather than an exact value the heuristic stack can shift.
    score = int(lines[-1]["score"])
    assert score < 30, (
        f"penalty+credit composition didn't pull score down — "
        f"app_verified_human credit may not have applied. "
        f"reason={lines[-1]['reason']} score={score}"
    )
    assert "flaggedip" in lines[-1]["reason"]
