"""E5 — app-to-module reputation feedback (post-E7.3 wire format).

App sets `X-BotShield-Feedback: event=<name>;sig=<hmac>` on its
response. The signer only has to know the HMAC secret and an event
name; the mapping from event → action (flag bit + TTL + optional
log tag) is declared server-side via `BotShieldFeedback`, so
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


COOKIE_NAME = "__Host-bs_session"


def _g(path, xff, **kw):
    return client.get(path, xff=xff, ua=PASS_UA,
                      accept_language=PASS_AL, **kw)


def _carry(resp):
    """Hand the session cookie from `resp` to the next request.

    Feedback marks the session rather than the address, so a follow-up
    that does not carry the cookie cannot see the mark. That matters
    most for the negative assertions below: "flaggedsession not in
    reason" passes trivially on a request that was never able to see
    it, which would make them pass no matter what bridge.c did.
    """
    c = resp.cookies.get(COOKIE_NAME)
    return {COOKIE_NAME: c} if c else {}


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

    `feedback_triggers` is zero or more `BotShieldFeedback`
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
    """Event `scanner-hit` maps to flagsession=honeypot_hit. App
    signs the event name; the module looks it up in the config and
    applies the configured bit to the cookie session."""
    val = _sign("scanner-hit")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    <BotShieldFeedback scanner-hit>\n'
            '        BotShieldEvent        scanner-hit\n'
            '        BotShieldFlagsession  honeypot_hit\n'
            '    </BotShieldFeedback>\n',
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
        assert r1.cookies.get(COOKIE_NAME), (
            f"the feedback response should carry the resealed cookie "
            f"holding the mark; got {dict(r1.cookies)}"
        )
        with log_slice as slc:
            _g("/index.html", xff=ip, cookies=_carry(r1))
            lines = slc.decision_lines(ip=ip)
    assert lines, "no follow-up decision line"
    assert "flaggedsession" in lines[-1]["reason"], (
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
    flaggedsession reason."""
    val = _sign("scanner-hit")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnabled LogOnly\n'
        '    BotShieldAppFeedback on\n'
        f'    BotShieldAppIntegrationSecretFile {SECRET_PATH}\n'
        '    <BotShieldFeedback scanner-hit>\n'
        '        BotShieldEvent        scanner-hit\n'
        '        BotShieldFlagsession  honeypot_hit\n'
        '    </BotShieldFeedback>\n'
        f'    {FEEDBACK_LOC_1}\n'
        f'        Header always set X-BotShield-Feedback "{val}"\n'
        f'    </Location>',
        count=1,
    ):
        with log_slice as slc:
            first = _g(FEEDBACK_PATH_1, xff=ip)
            _g("/index.html", xff=ip, cookies=_carry(first))
            lines = slc.decision_lines(ip=ip)

    assert lines, "no decision lines emitted"
    follow_up = lines[-1]["reason"]
    assert "flaggedsession" not in follow_up, (
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
    """Per-trigger `mode=observe` on a BotShieldFeedback
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
        '    <BotShieldFeedback scanner-hit>\n'
        '        BotShieldEvent        scanner-hit\n'
        '        BotShieldFlagsession  honeypot_hit\n'
        '        BotShieldMode         observe\n'
        '    </BotShieldFeedback>\n'
        f'    {FEEDBACK_LOC_1}\n'
        f'        Header always set X-BotShield-Feedback "{val}"\n'
        f'    </Location>',
        count=1,
    ):
        with log_slice as slc:
            first = _g(FEEDBACK_PATH_1, xff=ip)
            _g("/index.html", xff=ip, cookies=_carry(first))
            lines = slc.decision_lines(ip=ip)

    assert lines, "no decision lines emitted"
    follow_up = lines[-1]["reason"]
    assert "flaggedsession" not in follow_up, (
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
    flag mapping is the only surface the app controls.

    Asserted as a challenge that does not happen rather than as a
    number in the log. The dev vhost's app_verified_human trigger
    scores -80 onto botsignals, and a scraper UA without it reaches the
    noninteractive row at 20 -- so the credit is visible as the
    difference between two tiers, which is the thing an operator
    actually cares about and does not depend on how the number is
    carried."""
    val = _sign("human-verified")
    ip_base = _ips.fresh_ip()
    ip_cred = _ips.fresh_ip()
    scraper = "python-requests/2.31"
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    <BotShieldFeedback human-verified>\n'
            '        BotShieldEvent        human-verified\n'
            '        BotShieldFlagsession  app_verified_human\n'
            '    </BotShieldFeedback>\n',
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        credited = _g(FEEDBACK_PATH_1, xff=ip_cred)
        with log_slice as slc:
            client.get("/index.html", xff=ip_base, ua=scraper)
            client.get("/index.html", xff=ip_cred, ua=scraper,
                       cookies=_carry(credited))
            base_lines = slc.decision_lines(ip=ip_base)
            cred_lines = slc.decision_lines(ip=ip_cred)

    assert base_lines and cred_lines
    base_tier = base_lines[-1]["tier"]
    cred = cred_lines[-1]
    assert base_tier != "nochallenge", (
        f"the control needs to be challenged for this test to mean "
        f"anything; tier={base_tier} reason={base_lines[-1]['reason']!r}"
    )
    assert "rule:flag-app-verified-human" in cred["reason"], (
        f"the credit flag never fired; reason={cred['reason']!r}"
    )
    assert cred["tier"] == "nochallenge", (
        f"app_verified_human should have kept this under the "
        f"noninteractive row; tier={cred['tier']} "
        f"reason={cred['reason']!r}"
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
            '    <BotShieldFeedback scanner-hit>\n'
            '        BotShieldEvent        scanner-hit\n'
            '        BotShieldFlagsession  honeypot_hit\n'
            '    </BotShieldFeedback>\n',
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
        '    <BotShieldFeedback scanner-hit>\n'
        '        BotShieldEvent        scanner-hit\n'
        '        BotShieldFlagsession  honeypot_hit\n'
        '    </BotShieldFeedback>\n'
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
            '    <BotShieldFeedback scanner-hit>\n'
            '        BotShieldEvent        scanner-hit\n'
            '        BotShieldFlagsession  honeypot_hit\n'
            '    </BotShieldFeedback>\n',
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{tampered}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r1 = _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip, cookies=_carry(r1))
            lines = slc.decision_lines(ip=ip)

    assert "X-BotShield-Feedback" not in r1.headers, (
        "tampered header must still be stripped"
    )
    assert lines and "flaggedsession" not in lines[-1]["reason"], (
        f"tampered feedback shouldn't have marked the session; "
        f"reason={lines[-1]['reason']}"
    )


# --- Unmapped event + legacy wire format -------------------------


def test_app_feedback_unmapped_event_is_ignored(
    config_override, log_slice,
):
    """App signs an event name nobody has BotShieldFeedback'd.
    The HMAC is valid but the event has no module-memory mapping, so
    the flag doesn't land. Gives operators safe rollout: apps can
    start emitting new event names before the config catches up."""
    val = _sign("brand-new-event-name")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            # deliberately no BotShieldFeedback for event=for the event
            '',
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r1 = _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip, cookies=_carry(r1))
            lines = slc.decision_lines(ip=ip)

    assert "X-BotShield-Feedback" not in r1.headers
    assert lines and "flaggedsession" not in lines[-1]["reason"], (
        f"unmapped event should not have marked the session; "
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
            '    <BotShieldFeedback legacy-guard>\n'
            '        BotShieldEvent        legacy-guard\n'
            '        BotShieldFlagsession  honeypot_hit\n'
            '    </BotShieldFeedback>\n',
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        r1 = _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip, cookies=_carry(r1))
            lines = slc.decision_lines(ip=ip)

    assert "X-BotShield-Feedback" not in r1.headers
    assert lines and "flaggedsession" not in lines[-1]["reason"], (
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
            '    <BotShieldFeedback scanner-hit>\n'
            '        BotShieldEvent        scanner-hit\n'
            '        BotShieldFlagsession  honeypot_hit\n'
            '    </BotShieldFeedback>\n'
            '    <BotShieldFeedback human-verified>\n'
            '        BotShieldEvent        human-verified\n'
            '        BotShieldFlagsession  app_verified_human\n'
            '    </BotShieldFeedback>\n',
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{penalty_val}"\n'
            f'    </Location>\n'
            f'    {FEEDBACK_LOC_2}\n'
            f'        Header always set X-BotShield-Feedback "{credit_val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        # Both marks land on one session, so the cookie has to be
        # chained through: the second event reseals the cookie the
        # first one produced.
        r1 = _g(FEEDBACK_PATH_1, xff=ip_both)   # honeypot_hit  (+60)
        r2 = _g(FEEDBACK_PATH_2, xff=ip_both,   # app_verified_human (-80)
                cookies=_carry(r1))
        ck = _carry(r2)
        # A few subsequent requests so Bloom eats firstsightip and the
        # follow-up's reason trace doesn't include it, leaving just
        # flaggedsession as the visible flag contribution.
        for _ in range(3):
            _g("/index.html", xff=ip_both, cookies=ck)
        with log_slice as slc:
            _g("/index.html", xff=ip_both, cookies=ck)
            lines = slc.decision_lines(ip=ip_both)

    assert lines
    # Score is dominated by flag composition: honeypot +60 plus
    # app_verified_human -80 = -20. The follow-ups carry the cookie
    # now, so droppedcookie no longer adds its +25 -- the bound stays
    # loose anyway, because asserting an exact value would make this
    # test a tripwire for every heuristic weight.
    score = int(lines[-1]["score"])
    assert score < 30, (
        f"penalty+credit composition didn't pull score down — "
        f"app_verified_human credit may not have applied. "
        f"reason={lines[-1]['reason']} score={score}"
    )
    assert "flaggedsession" in lines[-1]["reason"]


def test_app_feedback_can_mark_the_address(config_override, log_slice):
    """BotShieldFlagIP on a feedback trigger flags the address.

    The subject is the operator's choice and the two say different
    things. A session mark is right for what the app knows about a
    person it authenticated. An abuse report usually has no session to
    point at -- a scripted client never takes a cookie, and a session
    write no-ops without one -- so the address is the only place that
    report can land.

    Sent deliberately without a cookie, which is both the case that
    needs the address and the case that proves the session path is not
    quietly doing the work.
    """
    val = _sign("scanner-hit")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    <BotShieldFeedback scanner-hit>\n'
            '        BotShieldEvent        scanner-hit\n'
            '        BotShieldFlagip       honeypot_hit\n'
            '    </BotShieldFeedback>\n',
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)
    assert lines, "no follow-up decision line"
    assert "flaggedip" in lines[-1]["reason"], (
        f"the address should carry the mark; "
        f"reason={lines[-1]['reason']}"
    )


# --- the container shape --------------------------------------------


def test_the_retired_tag_is_refused(config_override):
    """<BotShieldFeedbackTrigger> is gone.

    It held a migration stub naming the replacement until 2026-09-07,
    when the slot was dropped; the failure is now Apache's generic
    "Invalid command, perhaps misspelled or defined by a module not
    included". What this asserts either way is that the old spelling
    does not quietly work -- the message is a courtesy, the refusal is
    the contract.
    """
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldFeedbackTrigger scanner-hit>\n"
            "        BotShieldFlagIP   honeypot_hit\n"
            "    </BotShieldFeedbackTrigger>",
            count=1,
        ):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


def test_a_block_without_an_event_is_refused(config_override):
    """The name is a label now, so it no longer says what the block
    is about. While event= is the only condition, a block without one
    would match every signed event -- which is never what someone
    writing one of these means."""
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldFeedback nameless>\n"
            "        BotShieldFlagSession  honeypot_hit\n"
            "    </BotShieldFeedback>",
            count=1,
        ):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


def test_label_and_event_are_separate(config_override, log_slice):
    """The point of the reshape: the block is named one thing and
    matches another, which is what leaves room for a second
    condition."""
    val = _sign("scanner-hit")
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg(
            '    <BotShieldFeedback watch-for-probes>\n'
            '        BotShieldEvent    scanner-hit\n'
            '        BotShieldFlagIP   honeypot_hit\n'
            '    </BotShieldFeedback>\n',
            f'    {FEEDBACK_LOC_1}\n'
            f'        Header always set X-BotShield-Feedback "{val}"\n'
            f'    </Location>'
        ),
        count=1,
    ):
        _g(FEEDBACK_PATH_1, xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)
    assert lines and "flaggedip" in lines[-1]["reason"], (
        f"the event should have matched despite the differing label; "
        f"reason={lines[-1]['reason'] if lines else None}"
    )
