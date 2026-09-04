"""Resolver idempotence: compiled-in defaults must be seeded exactly once.

`bs_resolve_flag_triggers` and `bs_resolve_heuristic_triggers`
(src/config.c) each read and write the SAME `bs_server_cfg` field: it
carries operator declarations on input and the fully resolved list on
output. That is only safe if the post_config walk visits every
`bs_server_cfg` exactly once. Nothing guaranteed it did -- these configs
are shared between `server_rec`s, because `bs_merge_rule_array` returns
the caller's array object unchanged when one side is empty
(`if (nadd == 0) return base;`). A second visit then treats the first
visit's output -- compiled-in defaults included -- as operator input and
seeds the defaults again.

Found in production 2026-08-08 on a HubZero hub with 102 namevhosts and
the policy at main server scope. Every heuristic fired 107 times:

    first-sight-ip           20  ->  score 2140      (2140 / 20 == 107)
    dropped-cookie           25  ->  score 2675      (2675 / 25 == 107)
    missing-al                5  ->  score  535      ( 535 /  5 == 107)

Ordinary Chrome and Firefox requests were scored into the captcha tier,
and the 2048-slot rate-counter pool exhausted on startup, silently
dropping *all* bot rate limiting -- the exact opposite of the configured
policy. Fixed by giving each resolver an idempotence guard
(`heuristic_triggers_resolved` / `flag_triggers_resolved`).

`test_no_heuristic_fires_more_than_once` encodes the invariant directly
and is the durable regression guard: it fails for any recurrence,
whatever the mechanism.

`test_vhost_count_does_not_change_scoring` pins the environmental factor.
Note it is NOT a confirmed reproduction of the original failure: the dev
vhost keeps its BotShield config at vhost scope, whereas the production
trigger was main scope, and the precise aliasing path was never pinned
down. It is a cheap guard on the property we actually care about --
scoring must not depend on how many vhosts the server happens to have.
"""

from __future__ import annotations

import pytest

from botshield_test import client, ips


# Every compiled-in heuristic, from bs_heuristic_defs (src/heuristics.c).
HEURISTICS = (
    "missing-ua",
    "missing-al",
    "scraper-ua",
    "first-sight-ip",
    "dropped-cookie",
)

# BS_PENALTY_* (src/score.h). Their sum is the most any single request can
# collect from heuristics when each fires exactly once.
PENALTY_SUM = 40 + 5 + 10 + 20 + 25  # == 100

# Classification can add on top of heuristics (fake-bot is +100), so this
# is a deliberately loose sanity bound rather than an exact expectation.
# It only has to sit far below the failure it guards: the bug produced
# 2140 from a single heuristic.
SCORE_CEILING = PENALTY_SUM + 150

# Trips scraper-ua; sending no Accept-Language trips missing-al; a
# Bloom-fresh IP with no cookie trips first-sight-ip.
SCRAPER_UA = "python-requests/2.31"

EXTRA_VHOSTS = 30


def _reason_tokens(decision: dict) -> list[str]:
    return [t.strip() for t in decision["reason"].split(",") if t.strip()]


def _assert_each_heuristic_at_most_once(decision: dict) -> None:
    tokens = _reason_tokens(decision)
    for name in HEURISTICS:
        seen = tokens.count(name)
        assert seen <= 1, (
            f"heuristic {name!r} appears {seen}x in one decision -- the "
            f"compiled-in defaults were seeded more than once. "
            f"score={decision.get('score')!r} reason={decision['reason']!r}"
        )


def _decision_for(ip: str, log_slice) -> dict:
    with log_slice as slc:
        client.get("/", xff=ip, ua=SCRAPER_UA, accept_language=None)
        lines = slc.decision_lines(ip=ip)
    assert lines, f"no decision line logged for ip={ip}"
    return lines[0]


def test_no_heuristic_fires_more_than_once(fresh_ip, log_slice):
    """No heuristic may contribute to one request more than once."""
    decision = _decision_for(fresh_ip, log_slice)

    _assert_each_heuristic_at_most_once(decision)

    score = int(decision["score"])
    assert score <= SCORE_CEILING, (
        f"score {score} exceeds the sanity ceiling {SCORE_CEILING}; a "
        f"heuristic is very likely being applied repeatedly. "
        f"reason={decision['reason']!r}"
    )


@pytest.mark.serial
def test_vhost_count_does_not_change_scoring(fresh_ip, log_slice, config_override):
    """Adding redirect-only vhosts must not change how a request scores.

    Mirrors the production shape: 101 of qubeshub.org's 102 namevhosts are
    TLS-termination shells with a dummy DocumentRoot and a single
    RedirectMatch, declaring no BotShield directives of their own.
    """
    baseline = _decision_for(fresh_ip, log_slice)
    baseline_score = int(baseline["score"])
    _assert_each_heuristic_at_most_once(baseline)

    extra = "\n" + "\n".join(
        "<VirtualHost *:80>\n"
        f"    ServerName dummy{i}.botshield.test\n"
        "    RedirectMatch (/.*|$) https://localhost$1\n"
        "</VirtualHost>"
        for i in range(EXTRA_VHOSTS)
    ) + "\n"

    # r"\Z" matches exactly once, at end of file, so this appends the
    # blocks without needing an anchor inside the dev config.
    with config_override(r"\Z", extra):
        after = _decision_for(ips.fresh_ip(), log_slice)

    _assert_each_heuristic_at_most_once(after)

    after_score = int(after["score"])
    assert after_score == baseline_score, (
        f"score changed from {baseline_score} to {after_score} after adding "
        f"{EXTRA_VHOSTS} redirect-only vhosts. Scoring must not depend on "
        f"vhost count.\n  baseline reason={baseline['reason']!r}\n"
        f"  after    reason={after['reason']!r}"
    )
