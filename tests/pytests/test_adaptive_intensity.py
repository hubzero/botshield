"""E14 — adaptive challenge intensity via flag-registry metadata.

`BotShieldFlag <name> [penalty=N] [next_difficulty=±N]
[next_tier=pass|silent|form|captcha]` overrides registered flag-bit
metadata. Any writer that sets the bit (BotShieldFlagIP, feedback
events, env-trigger flag actions) automatically picks up the
operator-declared adaptive consequences.

Request-time semantics:
  - flagged-IP and cookie flags both contribute to adaptive deltas
  - next_difficulty SUMS across all set bits, then clamps against
    BotShieldMaxDifficulty (default 8)
  - next_tier_floor takes MAX (never silently downgrades)
  - the score-derived tier wins if it's already higher than the floor
  - reasons surface via score reasons: adaptive-tier:<tier>,
    adaptive-difficulty:+N (effective applied delta after clamp)
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


# --- Directive validation ------------------------------------------


def test_directive_rejects_unknown_flag(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldFlag never_existed penalty=10',
            count=1,
        ):
            pass


def test_directive_rejects_bad_tier_value(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldFlag honeypot_hit next_tier=meltdown',
            count=1,
        ):
            pass


def test_directive_rejects_difficulty_out_of_range(config_override):
    """+/-16 is the hard cap; +20 must be rejected at parse time."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldFlag honeypot_hit next_difficulty=+20',
            count=1,
        ):
            pass


def test_directive_requires_at_least_one_kv(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldFlag honeypot_hit',
            count=1,
        ):
            pass


def test_max_difficulty_directive_rejects_out_of_range(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldMaxDifficulty 99',
            count=1,
        ):
            pass


# --- next_tier floor: BotShieldFlag bumps tier on flagged IP -------


def test_flag_next_tier_forces_captcha(config_override, fresh_ip,
                                       log_slice):
    """Honeypot's default +60 penalty puts score at the hard-form
    threshold; on its own it would land at tier=form. Bumping the
    floor to captcha via BotShieldFlag forces the request up to
    captcha tier — score-derived tier is form, adaptive floor is
    captcha, so adaptive wins. adaptive-tier:captcha rides the
    reason chain."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldFlag honeypot_hit next_tier=captcha',
        count=1,
    ):
        # Trip the honeypot — sets BS_FLAG_HONEYPOT_HIT for fresh_ip.
        client.get("/admin/.env", xff=fresh_ip)
        time.sleep(1)  # mutex write -> seqlock visible
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert lines, f"no decision line for ip={fresh_ip}"
    last = lines[-1]
    reason = last["reason"]
    assert "adaptive-tier:captcha" in reason, (
        f"expected adaptive-tier:captcha in reason; got {reason!r}"
    )


def test_flag_next_tier_does_not_downgrade(config_override, fresh_ip,
                                           log_slice):
    """Score-derived tier already form (honeypot's +60 penalty under
    default thresholds). Setting next_tier=silent (lower than form)
    must NOT downgrade — score wins. No adaptive-tier reason should
    be emitted because the floor doesn't push higher."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldFlag honeypot_hit next_tier=silent',
        count=1,
    ):
        client.get("/admin/.env", xff=fresh_ip)
        time.sleep(1)
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    assert "adaptive-tier" not in reason, (
        f"adaptive-tier should not appear when floor is below "
        f"score-derived tier; got {reason!r}"
    )


# --- next_difficulty: cumulative bump fires + clamps ---------------


def test_flag_next_difficulty_appears_in_reasons(
    config_override, fresh_ip, log_slice,
):
    """Honeypot hit + next_difficulty=+3 means next_difficulty applies
    when the same IP is challenged. Reason chain must include
    adaptive-difficulty:+N (after clamp). Default base is 4 and
    BotShieldMaxDifficulty default is 8, so +3 lands fully (final
    issue_difficulty=7)."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldFlag honeypot_hit next_difficulty=+3',
        count=1,
    ):
        client.get("/admin/.env", xff=fresh_ip)
        time.sleep(1)
        # Force a challenge with a scraper UA so the request actually
        # hits the issue path (not just a pass-through).
        with log_slice as slc:
            client.get("/", xff=fresh_ip, ua="python-httpx/0.27")
            lines = slc.decision_lines(ip=fresh_ip)

    assert lines, "no decision line"
    reason = lines[-1]["reason"]
    assert "adaptive-difficulty:+3" in reason, (
        f"expected adaptive-difficulty:+3 in reason; got {reason!r}"
    )


def test_flag_next_difficulty_clamps_to_max(
    config_override, fresh_ip, log_slice,
):
    """Default BotShieldMaxDifficulty is 8, base difficulty 4. A flag
    requesting +10 should clamp to +4 (8 - 4) at apply time, NOT +10.
    Verifies the ceiling is honored."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldFlag honeypot_hit next_difficulty=+10',
        count=1,
    ):
        client.get("/admin/.env", xff=fresh_ip)
        time.sleep(1)
        with log_slice as slc:
            client.get("/", xff=fresh_ip, ua="python-httpx/0.27")
            lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    # Effective applied delta is +4, not the requested +10.
    assert "adaptive-difficulty:+4" in reason, (
        f"expected adaptive-difficulty:+4 (clamped from +10); "
        f"got {reason!r}"
    )
    assert "adaptive-difficulty:+10" not in reason, (
        f"unclamped raw delta leaked into reason chain: {reason!r}"
    )


# --- Compose: max_difficulty raises the ceiling --------------------


def test_max_difficulty_raises_ceiling(config_override, fresh_ip,
                                       log_slice):
    """BotShieldMaxDifficulty 12 lifts the ceiling. With base 4 + flag
    +10, the effective delta should now be +8 (12 - 4) — the request
    delta clamps higher than under default 8."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldMaxDifficulty 12\n'
        '    BotShieldFlag honeypot_hit next_difficulty=+10',
        count=1,
    ):
        client.get("/admin/.env", xff=fresh_ip)
        time.sleep(1)
        with log_slice as slc:
            client.get("/", xff=fresh_ip, ua="python-httpx/0.27")
            lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    assert "adaptive-difficulty:+8" in reason, (
        f"expected +8 after raising max-difficulty to 12; got {reason!r}"
    )


# --- Default config: no adaptive bump = no reason emitted ----------


def test_no_adaptive_when_no_flag_metadata(fresh_ip, log_slice):
    """Default built-in flag metadata has next_difficulty=0 and
    next_tier=pass for all flags. A flagged IP picks up score penalty
    but no adaptive- reason should appear in the chain."""
    client.get("/admin/.env", xff=fresh_ip)
    time.sleep(1)
    with log_slice as slc:
        _g("/", xff=fresh_ip)
        lines = slc.decision_lines(ip=fresh_ip)

    reason = lines[-1]["reason"]
    assert "adaptive-tier" not in reason, (
        f"adaptive-tier reason emitted under default config: {reason!r}"
    )
    assert "adaptive-difficulty" not in reason, (
        f"adaptive-difficulty reason emitted under default config: "
        f"{reason!r}"
    )
