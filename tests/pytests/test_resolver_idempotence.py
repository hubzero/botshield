"""Resolver idempotence: nothing may be seeded or applied twice.

`bs_resolve_flag_triggers` (src/config.c) reads and writes the SAME
`bs_server_cfg` field: it carries operator declarations on input and
the fully resolved list on output. That is only safe if the post_config
walk visits every `bs_server_cfg` exactly once. Nothing guaranteed it
did -- these configs are shared between `server_rec`s, because
`bs_merge_rule_array` returns the caller's array object unchanged when
one side is empty (`if (nadd == 0) return base;`). A second visit then
treats the first visit's output as operator input and applies it again.

Found in production 2026-08-08 on a HubZero hub with 102 namevhosts and
the policy at main server scope. Every heuristic fired 107 times:

    firstsightip           20  ->  score 2140      (2140 / 20 == 107)
    droppedcookie           25  ->  score 2675      (2675 / 25 == 107)
    missingal                5  ->  score  535      ( 535 /  5 == 107)

Ordinary Chrome and Firefox requests were scored into the captcha tier,
and the 2048-slot rate-counter pool exhausted on startup, silently
dropping *all* bot rate limiting -- the exact opposite of the
configured policy. Fixed by giving the resolver an idempotence guard
(`flag_triggers_resolved`).

The heuristic family that produced those numbers is gone, and its
resolver with it. The hazard belongs to the resolve-in-place shape
rather than to what was being resolved, so this still has a subject and
the flag resolver is it.

What is asserted moved too. Heuristic names no longer appear in a
reason and the cumulative score is 0 for every request, so counting
those tokens or comparing those scores would pass without testing
anything. A double seed today fires a trigger twice and moves its
accumulator twice -- a repeated reason token, and a different tier if
the doubling crosses a `BotShieldChallengeAtLeast` row. Comparing the
whole decision catches that without depending on how the number is
carried.

`test_no_token_repeats` encodes the invariant directly.
`test_vhost_count_does_not_change_the_decision` pins the environmental
factor. Note the second is NOT a confirmed reproduction: the dev vhost
keeps its BotShield config at vhost scope, whereas the production
trigger was main scope, and the precise aliasing path was never pinned
down. It is a cheap guard on the property actually cared about -- the
decision must not depend on how many vhosts the server happens to have.
"""

from __future__ import annotations

import collections

import pytest

from botshield_test import client, ips


# Trips the scraper-UA rule; sending no Accept-Language trips the
# missing-AL rule; a Bloom-fresh address with no cookie trips
# first-sight.
SCRAPER_UA = "python-requests/2.31"

EXTRA_VHOSTS = 30


def _tokens(decision: dict) -> list[str]:
    return [t.strip() for t in decision["reason"].split(",") if t.strip()]


def _assert_no_token_repeats(decision: dict) -> None:
    counts = collections.Counter(_tokens(decision))
    repeated = {t: n for t, n in counts.items() if n > 1}
    assert not repeated, (
        f"reason tokens appear more than once: {repeated}. A rule or "
        f"trigger was applied twice, which is what a resolver seeding "
        f"its own output looks like. "
        f"tier={decision.get('tier')!r} reason={decision['reason']!r}"
    )


def _decision_for(ip: str, log_slice) -> dict:
    with log_slice as slc:
        client.get("/", xff=ip, ua=SCRAPER_UA, accept_language=None)
        lines = slc.decision_lines(ip=ip)
    assert lines, f"no decision line logged for ip={ip}"
    return lines[0]


def test_no_token_repeats(fresh_ip, log_slice):
    """Nothing may contribute to one request more than once."""
    _assert_no_token_repeats(_decision_for(fresh_ip, log_slice))


@pytest.mark.serial
def test_vhost_count_does_not_change_the_decision(
    fresh_ip, log_slice, config_override,
):
    """Adding redirect-only vhosts must not change the decision.

    Mirrors the production shape: 101 of qubeshub.org's 102 namevhosts
    are TLS-termination shells with a dummy DocumentRoot and a single
    RedirectMatch, declaring no BotShield directives of their own.
    """
    baseline = _decision_for(fresh_ip, log_slice)
    _assert_no_token_repeats(baseline)

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

    _assert_no_token_repeats(after)

    assert after["tier"] == baseline["tier"], (
        f"tier changed from {baseline['tier']!r} to {after['tier']!r} "
        f"after adding {EXTRA_VHOSTS} redirect-only vhosts. The "
        f"decision must not depend on vhost count.\n"
        f"  baseline reason={baseline['reason']!r}\n"
        f"  after    reason={after['reason']!r}"
    )
    assert collections.Counter(_tokens(after)) ==            collections.Counter(_tokens(baseline)), (
        f"reason tokens changed after adding vhosts.\n"
        f"  baseline reason={baseline['reason']!r}\n"
        f"  after    reason={after['reason']!r}"
    )
