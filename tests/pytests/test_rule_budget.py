"""A rule can carry a budget.

A rate limit is a rule with a counter. `bs_rate_limit_entry` holds
name, cohort, budget, window and slot; a rule already had the first two
and the mode, so the counter was the only thing missing. Putting it on
the rule is what makes the predicate set available to it -- and the
predicate a rate limit has never had is the path. `bs_cohort` is
ua + ipspec and nothing else, so "five requests a minute to /search/"
has not been sayable in either family.

countper= is the counter key rather than a predicate: it says which
bucket the count lands in, not whether the rule matched. Only `total`
is wired -- one bucket per rule, everyone matching sharing one budget.
That is what BotShieldRateLimit has always done without naming it, and
naming it is half the point: `client` and `session` are the ones an
operator probably means, and they are refused with a message rather
than silently approximated.

Nothing migrates here. BotShieldRateLimit and BotShieldBotRateLimit are
untouched and still the only spelling with escalation behind it.
"""

from __future__ import annotations

import pytest

from botshield_test import apache, client, ratelimit

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

    A BotShieldRateLimit matches on ua= and ipspec= only, so it cannot
    be told to apply to one path. This asserts the exact-index shape --
    third request refused -- which needs the burst inside one window,
    hence the alignment.
    """
    conf = _rule(
        "        BotShieldPath      /budget-probe\n"
        "        BotShieldBudget    2\n"
        "        BotShieldPer       sec"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        ratelimit.align_to_window()
        codes = [client.get("/budget-probe", xff=fresh_ip, ua=UA).status_code
                 for _ in range(3)]
        # Same rule, different path: must be untouched by the budget.
        other = client.get("/elsewhere-probe", xff=fresh_ip, ua=UA)

    # Assert on 429 specifically, not on 200. The harness client sends
    # no Accept-Language, so an admitted request is still challenged to
    # 403 by the baseline signature rules -- comparing to 200 tests the
    # whole vhost rather than this budget.
    assert 429 not in codes[:2], f"budget of 2 refused early; got {codes}"
    assert codes[2] == 429, f"third request should exceed; got {codes}"
    assert other.status_code != 429, (
        f"a path outside the rule was rate-limited ({other.status_code}) -- "
        f"the counter is not scoped to the path condition"
    )


def test_under_budget_the_rule_carries_on(config_override, fresh_ip):
    """Spending from the window is not the same as matching-and-stopping.

    A rule that rate-limits and also responds should still respond
    while it is under budget; the counter is a gate on the way to the
    action, not a replacement for it.
    """
    conf = _rule(
        "        BotShieldPath      /budget-and-act\n"
        "        BotShieldBudget    5\n"
        "        BotShieldPer       min\n"
        "        BotShieldRespond   403"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        r = client.get("/budget-and-act", xff=fresh_ip, ua=UA)
    assert r.status_code == 403, (
        f"the rule's own action was skipped while under budget; got "
        f"{r.status_code}"
    )


def test_the_budget_appears_in_the_policy_dump(config_override):
    conf = _rule(
        "        BotShieldPath      /budget-dump\n"
        "        BotShieldBudget    30\n"
        "        BotShieldPer       hour",
        name="dumped-budget",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith("dumped-budget")]
    assert line, f"rule missing from dump; body={body[:600]}"
    assert "budget=30/hour" in line[0], line[0]
    assert "countper=total" in line[0], line[0]


@pytest.mark.parametrize("body, why", [
    ("        BotShieldBudget    5", "per= missing"),
    ("        BotShieldPer       sec", "budget= missing"),
])
def test_half_a_rate_limit_is_refused(config_override, body, why):
    """Half of one is not a smaller one -- it is a rule that silently
    has none."""
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On",
                             _rule("        BotShieldPath /x\n" + body),
                             render=False, count=1):
            pass


@pytest.mark.parametrize("bad", ["0", "-1", "1000001", "lots"])
def test_bad_budgets_are_refused(config_override, bad):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  f"        BotShieldBudget {bad}\n"
                  "        BotShieldPer sec"),
            render=False, count=1,
        ):
            pass


@pytest.mark.parametrize("bad", ["week", "5", "secs"])
def test_bad_windows_are_refused(config_override, bad):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  "        BotShieldBudget 5\n"
                  f"        BotShieldPer {bad}"),
            render=False, count=1,
        ):
            pass


@pytest.mark.parametrize("key", ["client", "session"])
def test_unimplemented_count_keys_say_so(config_override, key):
    """Refused with a reason, not accepted and quietly treated as
    total. An operator writing countper=client means "one budget each"
    and would get "one budget between them" -- the opposite of the
    request, and invisible until someone counts 429s.
    """
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  "        BotShieldBudget 5\n"
                  "        BotShieldPer sec\n"
                  f"        BotShieldCountPer {key}"),
            render=False, count=1,
        ):
            pass


def test_countper_total_is_accepted(config_override, fresh_ip):
    """The one that works, spelled out rather than defaulted."""
    conf = _rule(
        "        BotShieldPath      /budget-total\n"
        "        BotShieldBudget    2\n"
        "        BotShieldPer       min\n"
        "        BotShieldCountPer  total"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        r = client.get("/budget-total", xff=fresh_ip, ua=UA)
    assert r.status_code != 429, f"first request refused; got {r.status_code}"
