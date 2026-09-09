"""A rule can carry a window.

A rate limit is a rule with a counter. `bs_rate_limit_entry` holds
name, cohort, budget, window and slot; a rule already had the first two
and the mode, so the counter was the only thing missing. Putting it on
the rule is what makes the predicate set available to it -- and the
predicate a rate limit has never had is the path. `bs_cohort` is
ua + ipspec and nothing else, so "thirty requests a minute to /search/"
has not been sayable in either family.

`BotShieldRate <n> <seconds>` is the shared form: everyone the rule
matches spends from one window. `BotShieldDelay <seconds>` is the
per-crawler form; test_rate_vocabulary.py owns the difference. This
file is about what a windowed rule does once it has one.

BotShieldRateLimit, the directive this family replaced, was retired on
2026-09-09; BotShieldBotRateLimit is untouched.
"""

from __future__ import annotations

import pytest

from botshield_test import apache, client

UA = "budget-probe/1.0"


def _rule(body: str, name: str = "budgeted") -> str:
    return (
        "BotShieldEnabled On\n"
        f"    <BotShieldRule {name}>\n"
        f"{body}\n"
        "    </BotShieldRule>"
    )


def test_a_path_scoped_rate_limit(config_override, fresh_ip):
    """The thing neither directive family can express.

    The retired BotShieldRateLimit matched on ua= and ipspec= only, so
    it could not be told to apply to one path. This asserts the exact-index shape --
    third request refused. The window is anchored to the first request
    rather than to a wall-clock tick, so the burst needs no alignment.
    """
    conf = _rule(
        "        BotShieldPath      /budget-probe\n"
        "        BotShieldRate      2 1"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        codes = [client.get("/budget-probe", xff=fresh_ip, ua=UA).status_code
                 for _ in range(3)]
        # Same rule, different path: must be untouched by the window.
        other = client.get("/elsewhere-probe", xff=fresh_ip, ua=UA)

    # Assert on 429 specifically, not on 200. The harness client sends
    # no Accept-Language, so an admitted request is still challenged to
    # 403 by the baseline signature rules -- comparing to 200 tests the
    # whole vhost rather than this window.
    assert 429 not in codes[:2], f"a budget of 2 refused early; got {codes}"
    assert codes[2] == 429, f"third request should exceed; got {codes}"
    assert other.status_code != 429, (
        f"a path outside the rule was rate-limited ({other.status_code}) -- "
        f"the counter is not scoped to the path condition"
    )


def test_under_budget_does_not_run_the_action(config_override, fresh_ip):
    """On a rule with a window, the action is what exceeding it means.

    This test used to assert the opposite -- that the action ran
    while under budget, on the reasoning that the counter was "a
    gate on the way to the action". That makes the window
    decorative: a budget of 5 with BotShieldRespond 403 would answer
    403 to the first request and to every request, and the window
    would change nothing at all.

    It was caught by writing test_over_budget_runs_the_rule_action,
    where the first request came back 451 before any budget had
    been spent.

    Under budget the request has spent from the window and the rule
    is done with it; the walk continues to the rules below.
    """
    conf = _rule(
        "        BotShieldPath      /budget-and-act\n"
        "        BotShieldRate      5 60\n"
        "        BotShieldRespond   403"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        r = client.get("/budget-and-act", xff=fresh_ip, ua=UA)
    assert r.status_code != 403, (
        f"the action ran on an admitted request, so the window is "
        f"decorative; got {r.status_code}"
    )


def test_the_window_appears_in_the_policy_dump(config_override):
    conf = _rule(
        "        BotShieldPath      /budget-dump\n"
        "        BotShieldRate      30 3600",
        name="dumped-budget",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith("dumped-budget")]
    assert line, f"rule missing from dump; body={body[:600]}"
    assert "rate=30/3600" in line[0], line[0]


def test_two_windows_on_one_rule_are_refused(config_override):
    """A rule has one counter. delay= and rate= both claim it, and the
    last one written silently winning is how a config says one thing
    and does another."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath  /x\n"
                  "        BotShieldDelay 1\n"
                  "        BotShieldRate  5 60"),
            render=False, count=1,
        ):
            pass


# --- escalation on a rule window -------------------------------------


def test_escalation_can_name_a_rule(config_override, fresh_ip):
    """BotShieldRateLimitEscalate binds by name, and a rule carrying a
    window is a rate limit by another spelling.

    The strike table is keyed on (address, slot) rather than on which
    directive family owns the slot, so nothing beneath the linkage had
    to change to make this work.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule esc-rule>\n"
        "        BotShieldPath      /esc-probe\n"
        "        BotShieldRate      1 1\n"
        "    </BotShieldRule>\n"
        "    BotShieldRateLimitEscalate esc-rule 2 min respond=403 ttl=60"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        codes = [client.get("/esc-probe", xff=fresh_ip, ua=UA).status_code
                 for _ in range(6)]
    assert 429 in codes, f"the window never refused; got {codes}"
    assert 403 in codes, (
        f"strikes never escalated to the operator status; got {codes}"
    )


def test_an_escalate_naming_nothing_warns(config_override, log_slice):
    """Inert rather than fatal, but it has to say so. An escalate that
    binds to nothing looks armed and is not."""
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldRateLimitEscalate no-such-thing 2 min respond=403"
    )
    with log_slice as slc:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            pass
        warned = slc.grep(r"names no rule carrying rate= or delay=")
    assert warned, "an unlinked escalate warned about nothing"


def test_over_budget_runs_the_rule_action(config_override, fresh_ip):
    """A spent window applies whatever the rule says. 429 is only the
    default, for a rule that declares a window and nothing else."""
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule budget-451>\n"
        "        BotShieldPath      /budget-action\n"
        "        BotShieldRate      1 1\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        codes = [client.get("/budget-action", xff=fresh_ip, ua=UA).status_code
                 for _ in range(2)]
    assert codes[1] == 451, (
        f"over budget returned the default instead of the rule action; "
        f"got {codes}"
    )


def test_a_window_can_mark_without_refusing(config_override, fresh_ip):
    """The shape the separate family could not offer.

    Rate limits ran at step 7 of the walk, after every rule, so a mark
    one of them wrote could not be a condition in the same request --
    only in the next one. In the ladder a window can score the client
    and a rule below can read it, which is the same property that makes
    trap-then-act work in one request rather than two.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule mark-flood>\n"
        "        BotShieldPath   /mark-probe\n"
        "        BotShieldRate   1 1\n"
        "        BotShieldScore  flood +50\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule act-on-mark>\n"
        "        BotShieldPath          /mark-probe\n"
        "        BotShieldScoreAtLeast  flood 50\n"
        "        BotShieldRespond       451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        first = client.get("/mark-probe", xff=fresh_ip, ua=UA)
        second = client.get("/mark-probe", xff=fresh_ip, ua=UA)
    assert first.status_code != 451, (
        f"the first request was under budget and should not have been "
        f"marked; got {first.status_code}"
    )
    assert second.status_code == 451, (
        f"the second was over budget, so the rule below should have read "
        f"the score it wrote; got {second.status_code}"
    )
