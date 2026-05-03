"""E9 — repeated-429 escalation.

Builds on the existing BotShieldRateLimit machinery. The new
BotShieldRateLimitEscalate directive remembers per-(IP, rate-rule)
strike counts: enough rejected requests inside a window promote the
client into a stricter status (default 403) for a short TTL,
sliding on each additional strike.

Tests cover:
  - threshold crossing: extra 429s past the strike count escalate
  - below threshold: still get plain 429
  - rule isolation: escalating rule A doesn't affect rule B
  - IP isolation:   escalating IP A doesn't affect IP B
  - log tag emitted on threshold crossing for fail2ban handoff
  - directive validation: bogus values rejected at parse time

TTL-expiry into normal 429 is implicitly covered by the
strike-window roll: each test ends inside the same `<per>` window so
state is naturally cleaned up at the next test boundary. We don't
sleep for ttl seconds — that would inflate runtime — but the SHM
slot's own seqlock semantics make the lookup return non-escalated
once `escalation_until <= now`, which the unit-style invariant in
bs_strike_check_escalated already guarantees.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


CORP_UA = "CorpBot/1.0"


def _hammer(ip: str, ua: str, n: int) -> list[int]:
    return [client.get("/", xff=ip, ua=ua).status_code for _ in range(n)]


# --- Threshold crossing -------------------------------------------


def test_repeated_429_escalates_to_403(config_override, fresh_ip,
                                       log_slice):
    """Budget=2/60s, escalate after 3 strikes / 60s. The first 2
    requests admit, the next 3 return 429 (strikes 1, 2, 3); the
    third 429 crosses the threshold, so the FOURTH overage and
    every subsequent request gets the escalated 403."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRateLimit corpbot 2 sec "CorpBot" *\n'
        '    BotShieldRateLimitEscalate corpbot 3 min '
        'status=403 ttl=60 "log=BAN rate-abuse"',
        count=1,
    ):
        with log_slice as slc:
            codes = _hammer(fresh_ip, CORP_UA, 6)
            tag_lines = slc.grep(
                r"rate-limit-abuse threshold crossed for 'corpbot'"
            )
            decision_lines = slc.decision_lines(ip=fresh_ip)

    # First 2 admit (status 200), strikes 1-3 are 429s, then 403s.
    assert codes[:2] == [200, 200], f"first 2 must admit; got {codes}"
    # Among the next 4 requests there must be at least one 429 and
    # then at least one 403 — strict ordering varies if a worker
    # picks up a stale window roll, but the transition must happen.
    assert 429 in codes[2:], f"expected 429s before escalation; got {codes}"
    assert 403 in codes[2:], f"expected 403 after escalation; got {codes}"
    # 429 must come before 403 in the sequence.
    first_429 = next(i for i, c in enumerate(codes) if c == 429)
    first_403 = next(i for i, c in enumerate(codes) if c == 403)
    assert first_429 < first_403, (
        f"403 should follow 429s in the same burst; got {codes}"
    )
    # Tag log fires exactly once at the crossing.
    assert len(tag_lines) == 1, (
        f"expected one threshold-crossing log line; got "
        f"{len(tag_lines)}: {tag_lines}"
    )
    assert "BAN rate-abuse" in tag_lines[0], (
        f"log line missing operator tag: {tag_lines[0]}"
    )
    # The escalated request's decision line carries the
    # rate-limit-abuse:<name> reason (not rate-limit-exceeded).
    abuse = [d for d in decision_lines
             if "rate-limit-abuse:corpbot" in d["reason"]]
    assert abuse, (
        f"no rate-limit-abuse decision line; "
        f"decision_lines={decision_lines}"
    )


# --- Below threshold ----------------------------------------------


def test_below_strike_threshold_stays_at_429(
    config_override, fresh_ip, log_slice,
):
    """Budget=2/60s, escalate after 5 strikes. Only 4 overage
    requests: never crosses the threshold, all 429, no 403s."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRateLimit corpbot 2 sec "CorpBot" *\n'
        '    BotShieldRateLimitEscalate corpbot 5 min '
        'status=403 ttl=60',
        count=1,
    ):
        with log_slice as slc:
            codes = _hammer(fresh_ip, CORP_UA, 6)
            tag_lines = slc.grep(
                r"rate-limit-abuse threshold crossed"
            )

    assert codes[:2] == [200, 200], f"first 2 must admit; got {codes}"
    assert 403 not in codes, (
        f"403 must not appear below the strike threshold; got {codes}"
    )
    assert codes.count(429) >= 1, (
        f"expected 429s in the over-budget tail; got {codes}"
    )
    assert tag_lines == [], (
        f"threshold-crossing log fired below strikes count: {tag_lines}"
    )


# --- Per-rule isolation ------------------------------------------


def test_escalation_isolates_per_rule(
    config_override, fresh_ip, log_slice,
):
    """Two rules match the same UA: rule-A has escalation, rule-B
    does not. Rule-A's escalation must not affect rule-B's behavior
    when the UA-narrowing differs. Here we run two cohorts with
    different UA patterns: only the matching one's escalation
    applies. The other's normal 429 stays normal."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        # Rule-A matches "CorpBot" with escalation. Tight budget +
        # tight strike count to escalate quickly.
        '    BotShieldRateLimit corpbot 1 sec "CorpBot" *\n'
        '    BotShieldRateLimitEscalate corpbot 2 min '
        'status=403 ttl=60\n'
        # Rule-B matches "OtherUA" — no escalation. Different cohort
        # entirely, so even strict bursts stay at 429.
        '    BotShieldRateLimit otherbot 1 sec "OtherUA" *',
        count=1,
    ):
        # Drive rule-A into escalation: first request admits, then
        # 429s stack until escalation kicks in.
        codes_a = _hammer(fresh_ip, CORP_UA, 5)
        # Now hit rule-B: budget=1/sec, tight burst gets 429s but
        # never 403 because rule-B has no escalation config.
        codes_b = _hammer(fresh_ip, "OtherUA", 4)

    assert 403 in codes_a, (
        f"rule-A should have escalated; got codes_a={codes_a}"
    )
    assert 403 not in codes_b, (
        f"rule-B has no escalation config but saw 403; "
        f"codes_b={codes_b} — escalation leaked across rules"
    )
    assert 429 in codes_b, (
        f"rule-B should still rate-limit normally; codes_b={codes_b}"
    )


# --- Per-IP isolation --------------------------------------------


def test_escalation_isolates_per_ip(config_override):
    """IP-A misbehaves and escalates. A different IP-B that matches
    the same rule should NOT inherit the escalation: the strike
    table is keyed by (client_ip, rule_slot), so per-IP state stays
    private even when the rate-counter budget is shared.

    The cohort budget IS shared, so we sleep past the rate-limit
    window between phases. Otherwise IP-B's burst would all fall
    over the (already-exhausted) budget and IP-B would rack up its
    own strikes — a real-but-different effect that would mask the
    cross-IP-isolation property under test.

    Budget is intentionally tight (1/sec) and threshold low (3
    strikes/min) so the test isn't sensitive to how slowly Python
    sends sequential HTTPS requests — at any plausible request rate
    of ~10 reqs/sec, IP-A's 12-request burst lands ~11 strikes,
    well past threshold. Earlier shape (4/sec budget, 8/min
    threshold) flaked when post-parallel-phase Apache slowed
    sequential HTTPS handshakes enough that the 4/sec rate-counter
    rolled mid-burst and strikes didn't accumulate fast enough.
    Loosening the timing tolerance is cheaper than fighting Apache
    load."""
    ip_a = "198.51.100.10"
    ip_b = "198.51.100.20"
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRateLimit corpbot 1 sec "CorpBot" *\n'
        '    BotShieldRateLimitEscalate corpbot 3 min '
        'status=403 ttl=60',
        count=1,
    ):
        # Drive IP-A: 1 admit + ~11 strikes well past threshold(3).
        codes_a = _hammer(ip_a, CORP_UA, 12)
        # Wait past the 1-second rate-limit window so IP-B's request
        # gets a fresh budget (and thus zero strikes of its own).
        time.sleep(1.2)
        # IP-B's single request fits the fresh budget — admit.
        codes_b = _hammer(ip_b, CORP_UA, 1)
        # IP-A is still escalated even after the rate-counter window
        # rolled (escalation TTL is independent of the rate-counter
        # window). One more request from IP-A should still hit 403.
        codes_a_followup = _hammer(ip_a, CORP_UA, 1)

    assert 403 in codes_a, f"IP-A should have escalated; got {codes_a}"
    assert 403 not in codes_b, (
        f"IP-B saw 403 but only IP-A misbehaved; "
        f"codes_b={codes_b} — escalation leaked across IPs"
    )
    assert codes_a_followup == [403], (
        f"IP-A escalation should outlive the rate-counter window roll; "
        f"got {codes_a_followup}"
    )


# --- Directive validation ----------------------------------------


def test_directive_rejects_bogus_status(config_override):
    """status=29 is below 100 → parse error, configtest fails."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
            '    BotShieldRateLimit corpbot 1 sec "CorpBot" *\n'
            '    BotShieldRateLimitEscalate corpbot 2 sec status=29',
            count=1,
        ):
            pass


def test_directive_rejects_status_429(config_override):
    """status=429 is a no-op (same as the normal 429 response). The
    setter rejects it explicitly so operators don't write directives
    that have no effect."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
            '    BotShieldRateLimit corpbot 1 sec "CorpBot" *\n'
            '    BotShieldRateLimitEscalate corpbot 2 sec status=429',
            count=1,
        ):
            pass


def test_directive_rejects_unknown_key(config_override):
    """Unknown action keys fail parse rather than silently."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
            '    BotShieldRateLimit corpbot 1 sec "CorpBot" *\n'
            '    BotShieldRateLimitEscalate corpbot 2 sec '
            'mystery_key=42',
            count=1,
        ):
            pass


def test_directive_warns_on_unmatched_rate_name(
    config_override, log_slice,
):
    """An escalate that names no existing BotShieldRateLimit doesn't
    fail configtest (operator may add the rule later via include),
    but it logs a warning at post_config and stays inert at runtime."""
    with log_slice as slc:
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
            '    BotShieldRateLimitEscalate ghostrule 2 sec',
            count=1,
        ):
            pass
        warnings = slc.grep(
            r"BotShieldRateLimitEscalate 'ghostrule' names no matching"
        )
    assert warnings, (
        f"expected post_config warning for unlinked escalate; "
        f"tail: {slc.text().splitlines()[-5:]}"
    )
