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


def test_under_budget_does_not_run_the_action(config_override, fresh_ip):
    """On a rule with a budget, the action is what exceeding it means.

    This test used to assert the opposite -- that the action ran
    while under budget, on the reasoning that the counter was "a
    gate on the way to the action". That makes the budget
    decorative: BotShieldBudget 5 with BotShieldRespond 403 would
    answer 403 to the first request and to every request, and the
    budget would change nothing at all.

    It was caught by writing test_over_budget_runs_the_rule_action,
    where the first request came back 451 before any budget had
    been spent.

    Under budget the request has spent from the window and the rule
    is done with it; the walk continues to the rules below.
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
    assert r.status_code != 403, (
        f"the action ran on an admitted request, so the budget is "
        f"decorative; got {r.status_code}"
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


# "5" was here until 2026-09-07, when per= learned to take a
# count and a bare number came to mean seconds.
@pytest.mark.parametrize("bad", ["week", "secs", "5weeks"])
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


# --- escalation on a rule budget -------------------------------------


def test_escalation_can_name_a_rule(config_override, fresh_ip):
    """BotShieldRateLimitEscalate binds by name, and a rule carrying a
    budget is a rate limit by another spelling.

    The strike table is keyed on (address, slot) rather than on which
    directive family owns the slot, so nothing beneath the linkage had
    to change to make this work.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule esc-rule>\n"
        "        BotShieldPath      /esc-probe\n"
        "        BotShieldBudget    1\n"
        "        BotShieldPer       sec\n"
        "    </BotShieldRule>\n"
        "    BotShieldRateLimitEscalate esc-rule 2 min respond=403 ttl=60"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        codes = [client.get("/esc-probe", xff=fresh_ip, ua=UA).status_code
                 for _ in range(6)]
    assert 429 in codes, f"the budget never refused; got {codes}"
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
        warned = slc.grep(r"names no matching BotShieldRateLimit and no rule")
    assert warned, "an unlinked escalate warned about nothing"


def test_over_budget_runs_the_rule_action(config_override, fresh_ip):
    """A spent budget applies whatever the rule says. 429 is only the
    default, for a rule that declares a budget and nothing else."""
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule budget-451>\n"
        "        BotShieldPath      /budget-action\n"
        "        BotShieldBudget    1\n"
        "        BotShieldPer       sec\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        ratelimit.align_to_window()
        codes = [client.get("/budget-action", xff=fresh_ip, ua=UA).status_code
                 for _ in range(2)]
    assert codes[1] == 451, (
        f"over budget returned the default instead of the rule action; "
        f"got {codes}"
    )


def test_a_budget_can_mark_without_refusing(config_override, fresh_ip):
    """The shape the separate family could not offer.

    Rate limits ran at step 7 of the walk, after every rule, so a mark
    one of them wrote could not be a condition in the same request --
    only in the next one. In the ladder a budget can score the client
    and a rule below can read it, which is the same property that makes
    trap-then-act work in one request rather than two.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule mark-flood>\n"
        "        BotShieldPath   /mark-probe\n"
        "        BotShieldBudget 1\n"
        "        BotShieldPer    sec\n"
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
        ratelimit.align_to_window()
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
