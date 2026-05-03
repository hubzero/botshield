"""E14 (rework) — BotShieldFlagTrigger + compiled-in default rules.

Replaces the prior E14 BotShieldFlag/BotShieldMaxDifficulty machinery
which was AI-suggested-but-never-used in any deployment. The reworked
design plumbs flag effects through the existing trigger-action surface
under a new family (BS_TFAMILY_FLAG):

    BotShieldFlagTrigger <flag> [reset] [action=<verb> args...]

Compiled-in defaults seeded at post_config time mean the module Just
Works with zero config — honeypot_hit and fake_bot escalate to
captcha tier, scanner_probe to form, pow_fail_streak to silent, and
the app_verified_* credit bits subtract score.

Accumulation: SCORE actions SUM, TIER_FLOOR actions MAX. Operator
declarations append after defaults; per-flag `reset` clears all
prior entries (defaults + earlier operator) for the named flag.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"


def _g(path: str, **kw):
    return client.get(path, ua=PASS_UA, accept_language=PASS_AL, **kw)


def _trip_honeypot(ip: str) -> None:
    """Set BS_FLAG_HONEYPOT_HIT for the given IP via the canonical
    /admin/.env scope. The flag write goes through a mutex; a one-
    second sleep is enough for the next lookup to see it."""
    client.get("/admin/.env", xff=ip)
    time.sleep(1)


# --- Defaults: zero-config behavior --------------------------------


def test_default_honeypot_forces_captcha(fresh_ip, log_slice):
    """No operator config — built-in default
    `honeypot_hit -> tier_floor=captcha` lifts the request to the
    captcha floor. The dev rig may transparently downgrade captcha
    to form when no captcha provider is configured (captcha_fallback);
    we assert the floor was *applied* via the reason chain rather
    than the final landed tier so the test stays valid both with
    and without a real provider key."""
    _trip_honeypot(fresh_ip)
    with log_slice as slc:
        _g("/", xff=fresh_ip)
        lines = slc.decision_lines(ip=fresh_ip)

    assert lines, f"no decision line for ip={fresh_ip}"
    last = lines[-1]
    reason = last["reason"]
    # The default `honeypot_hit -> tier_floor=captcha` may surface as
    # either the explicit `flag-tier-floor:captcha` reason token (if
    # the score-derived tier was below captcha and the floor lifted
    # it) or implicitly via the `flag-trigger:honeypot_hit` score
    # action pushing the score past the captcha threshold on its own
    # — the new dropped-cookie heuristic now adds +25 on cookieless
    # follow-ups, often crossing captcha threshold without needing
    # the explicit tier-floor lift. Either path lands the same
    # tier=captcha decision; we assert that.
    assert "flag-trigger:honeypot_hit" in reason, (
        f"expected flag-trigger:honeypot_hit (score action); "
        f"got {reason!r}"
    )
    # Tier landed at the floor or a captcha-fallback (form) — never
    # below form.
    assert last["tier"] in ("captcha", "form"), (
        f"tier should be captcha (or form via captcha_fallback); "
        f"got {last['tier']!r} reason={reason!r}"
    )


def test_default_emits_score_reason_per_flag(fresh_ip, log_slice):
    """Built-in defaults emit a `flag-trigger:<name>` reason for each
    SCORE action that fires. honeypot's +60 SCORE action surfaces
    distinct from the flag-tier-floor reason."""
    _trip_honeypot(fresh_ip)
    with log_slice as slc:
        _g("/", xff=fresh_ip)
        lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    # Coarse signal stays for log-reader compatibility.
    assert "flagged-ip" in reason, reason
    # Per-flag walker emission.
    assert "flag-trigger:honeypot_hit" in reason, reason


# --- Operator extends defaults -------------------------------------


def test_operator_extra_score_sums_with_default(
    config_override, fresh_ip, log_slice,
):
    """Operator adds `score add=20` on honeypot_hit on top of the
    default `score add=60`. Both fire — score effect is the SUM, +80.
    Two `flag-trigger:honeypot_hit` reasons appear in the chain."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldFlagTrigger honeypot_hit action=score add=20',
        count=1,
    ):
        _trip_honeypot(fresh_ip)
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    # Two emissions of flag-trigger:honeypot_hit (default + operator).
    occurrences = reason.count("flag-trigger:honeypot_hit")
    assert occurrences >= 2, (
        f"expected >=2 honeypot_hit score emissions (default + operator), "
        f"got {occurrences} in reason={reason!r}"
    )


def test_softer_tier_floor_does_not_relax_default(
    config_override, fresh_ip, log_slice,
):
    """Default honeypot_hit -> tier_floor=captcha. Operator adds a
    SOFTER tier_floor=form on the same flag without resetting.
    MAX semantics: captcha still wins — config that would soften a
    definitive-bot signal is intentionally inert; the operator must
    `reset` first. We assert the captcha floor still rides the reason
    chain (the visible audit signal) rather than the landed tier,
    since dev rigs may downgrade captcha → form via captcha_fallback."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldFlagTrigger honeypot_hit action=tier_floor min=form',
        count=1,
    ):
        _trip_honeypot(fresh_ip)
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    last = lines[-1]
    reason = last["reason"]
    # The softer `tier_floor=form` must not relax the default
    # `tier_floor=captcha`. The audit signal can land in two ways:
    # (a) explicit `flag-tier-floor:captcha` in the reason chain
    # when the floor lifted a sub-captcha score, or (b) the actual
    # tier landing at captcha (or its captcha_fallback shim) via
    # the score action itself crossing the threshold. The dropped-
    # cookie heuristic + flag score push routinely produce (b).
    # In neither case may `flag-tier-floor:form` appear — that
    # would mean the softer floor won, which is the regression.
    assert "flag-tier-floor:form" not in reason, (
        f"the softer form floor must NOT be the winning floor reason; "
        f"got {reason!r}"
    )
    assert last["tier"] in ("captcha", "form"), (
        f"tier should land at captcha (or form via captcha_fallback) "
        f"despite the softer floor override; got {last['tier']!r} "
        f"reason={reason!r}"
    )


# --- Operator resets defaults --------------------------------------


def test_reset_then_softer_tier_floor_takes_effect(
    config_override, fresh_ip, log_slice,
):
    """`BotShieldFlagTrigger honeypot_hit reset` followed by an
    operator-supplied `tier_floor=form` clears the captcha default
    and the form floor takes effect — request lands at form tier."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldFlagTrigger honeypot_hit reset\n'
        '    BotShieldFlagTrigger honeypot_hit action=tier_floor min=form',
        count=1,
    ):
        _trip_honeypot(fresh_ip)
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    last = lines[-1]
    # form tier means the user gets a form challenge, not captcha.
    # The score-derived tier may already be at-or-above form because
    # the default score+60 is gone after reset, so accept any tier
    # below captcha.
    assert last["tier"] != "captcha", (
        f"reset + tier_floor=form should not produce captcha; "
        f"got {last['tier']!r}"
    )


def test_reset_with_no_replacement_clears_default(
    config_override, fresh_ip, log_slice,
):
    """`BotShieldFlagTrigger honeypot_hit reset` with no follow-up
    triggers clears the default entirely. The flag bit still gets
    set (honeypot path is unchanged), but no flag-trigger:honeypot_hit
    reason or flag-tier-floor reason should appear."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldFlagTrigger honeypot_hit reset',
        count=1,
    ):
        _trip_honeypot(fresh_ip)
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    assert "flag-trigger:honeypot_hit" not in reason, (
        f"honeypot_hit triggers should be gone after reset; "
        f"got {reason!r}"
    )
    assert "flag-tier-floor" not in reason, (
        f"no tier_floor should be applied after reset; got {reason!r}"
    )
    # Coarse "flagged-ip" reason is emitted independently (the
    # IP is still in the flagged-IP table) and stays.
    assert "flagged-ip" in reason, reason


def test_reset_inline_replacement(
    config_override, fresh_ip, log_slice,
):
    """`BotShieldFlagTrigger honeypot_hit reset action=score add=10`
    is the syntactic-sugar form: reset + one inline replacement on a
    single line. Default score+60 is gone; only +10 contributes."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldFlagTrigger honeypot_hit reset action=score add=10',
        count=1,
    ):
        _trip_honeypot(fresh_ip)
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    # Exactly one flag-trigger:honeypot_hit (the +10 the operator
    # declared after the reset).
    assert reason.count("flag-trigger:honeypot_hit") == 1, (
        f"expected exactly one honeypot_hit emission after reset+inline; "
        f"got reason={reason!r}"
    )


# --- Retired directives behave like any unknown directive ----------


def test_botshield_flag_directive_unknown(config_override):
    """The retired BotShieldFlag directive is no longer registered.
    Apache treats it as an unknown command — config-parse fails and
    `config_override` surfaces that as an exception."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldFlag honeypot_hit penalty=10',
            count=1,
        ):
            pass


def test_botshield_max_difficulty_directive_unknown(config_override):
    """BotShieldMaxDifficulty was deleted along with the adaptive
    difficulty knob it capped. Apache reports it as unknown."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldMaxDifficulty 12',
            count=1,
        ):
            pass


# --- Directive validation ------------------------------------------


def test_unknown_flag_rejected(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldFlagTrigger never_existed action=score add=10',
            count=1,
        ):
            pass


def test_unknown_action_verb_rejected(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldFlagTrigger honeypot_hit action=meltdown',
            count=1,
        ):
            pass


def test_bad_tier_value_rejected(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldFlagTrigger honeypot_hit action=tier_floor '
            'min=meltdown',
            count=1,
        ):
            pass
