"""BotShieldRule inside an Apache container.

The scope-trigger family existed for one reason: a rule could not be
written in a <Location>. Its predicate was the container match and it
had no conditions of its own, which is exactly a rule whose condition
Apache has already evaluated.

So the container is the condition. A rule declared in one needs no
match key -- and at server scope still does, because there the same
rule would swallow the site.

Two ladders now, and the order between them is the thing to pin: the
scoped one runs first, because Apache's own match is the more specific
statement and first-match-wins would otherwise let a broad vhost rule
answer for a path someone wrote a <Location> about.
"""

from __future__ import annotations

import pytest

from botshield_test import client


SCOPED = "/scoped-rule-probe"
OTHER = "/unscoped-probe"


def _conf(body: str) -> str:
    return "BotShieldEnabled On\n    BotShieldChallengeAtLeast none\n" + body


def test_a_rule_in_a_location_needs_no_condition(config_override, fresh_ip):
    """The scope trigger's whole job, written as a rule."""
    conf = _conf(
        f'    <Location "{SCOPED}">\n'
        "        <BotShieldRule scope-only>\n"
        "            BotShieldRespond   451\n"
        "        </BotShieldRule>\n"
        "    </Location>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        inside = client.get(SCOPED, xff=fresh_ip).status_code
        outside = client.get(OTHER, xff=fresh_ip).status_code
    assert inside == 451, "the container match is the condition"
    assert outside != 451, "and it does not reach outside the container"


def test_the_same_rule_at_server_scope_is_refused(config_override):
    """Unchanged where it matters. A condition-less rule at server
    scope matches every request, which is never deliberate."""
    conf = _conf(
        "    <BotShieldRule swallows-everything>\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


def test_conditions_still_apply_inside_a_container(config_override,
                                                   fresh_ip):
    """The container ANDs with the rule's own keys rather than
    replacing them."""
    conf = _conf(
        f'    <Location "{SCOPED}">\n'
        "        <BotShieldRule scoped-bots>\n"
        "            BotShieldUserAgent @scraper\n"
        "            BotShieldRespond   451\n"
        "        </BotShieldRule>\n"
        "    </Location>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        bot = client.get(SCOPED, xff=fresh_ip,
                         ua="python-requests/2.31").status_code
        human = client.get(
            SCOPED, xff=fresh_ip,
            ua="Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0",
            accept_language="en-US,en;q=0.9").status_code
    assert bot == 451
    assert human != 451, "the UA condition still has to hold"


def test_scoped_rules_are_walked_before_server_rules(config_override,
                                                     fresh_ip):
    """The ordering decision, pinned.

    A server-scope rule matching the same path with a different answer
    is declared FIRST here. If the ladders were concatenated the
    obvious way it would win, and the <Location> someone wrote about
    exactly this path would never be reached.
    """
    conf = _conf(
        "    <BotShieldRule broad>\n"
        f"        BotShieldPath      {SCOPED}\n"
        "        BotShieldRespond   403\n"
        "    </BotShieldRule>\n"
        f'    <Location "{SCOPED}">\n'
        "        <BotShieldRule specific>\n"
        "            BotShieldRespond   451\n"
        "        </BotShieldRule>\n"
        "    </Location>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        got = client.get(SCOPED, xff=fresh_ip).status_code
    assert got == 451, (
        f"the scoped rule should answer for its own path; got {got}"
    )


def test_a_scoped_rule_can_use_ipspec(config_override, fresh_ip):
    """ipspec= needs ranges loaded at post_config, which walks server
    configs. A rule in a dir config is unreachable from there, so it
    is pushed onto a server-side resolution list holding the same
    pointer. Without that this rule would parse and never match."""
    conf = _conf(
        f'    <Location "{SCOPED}">\n'
        "        <BotShieldRule scoped-ip>\n"
        "            BotShieldIPSpec    100.64.0.0/10\n"
        "            BotShieldRespond   451\n"
        "        </BotShieldRule>\n"
        "    </Location>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        got = client.get(SCOPED, xff=fresh_ip).status_code
    assert got == 451, (
        f"the cohort never resolved its ranges; got {got}"
    )
