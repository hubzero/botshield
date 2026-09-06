"""BotShieldScore / BotShieldScoreAtLeast — named, per-request, ordered.

The ambient score these replace was fragile for two reasons, neither of
which was arithmetic. It persisted into the cookie, so a request refused
for someone else's rate spike billed the client toward a future
challenge. And its contributors were spread across compiled-in defaults,
heuristic config and a -985 credit, so nobody could read a config and
predict a score.

These are written and read in one file, in order, and die with the
request. A rule at position k sees what rules above it accumulated --
a fold over the ladder, which is what makes a score safe to read as a
predicate. Against an ambient total it never could have been: the value
would depend on rules that had not run yet.
"""

from __future__ import annotations

import pytest

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"

REACHES = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule s1>\n"
    "        BotShieldPath   /score-probe\n"
    "        BotShieldScore  suspicion +10\n"
    "    </BotShieldRule>\n"
    "    <BotShieldRule s2>\n"
    "        BotShieldPath   /score-probe\n"
    "        BotShieldScore  suspicion +5\n"
    "    </BotShieldRule>\n"
    "    <BotShieldRule act>\n"
    "        BotShieldPath          /score-probe\n"
    "        BotShieldScoreAtLeast  suspicion 15\n"
    "        BotShieldRespond       403\n"
    "        BotShieldLogAs         acted\n"
    "    </BotShieldRule>\n"
)

FALLS_SHORT = REACHES.replace("suspicion 15", "suspicion 16")

SEPARATE = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule s1>\n"
    "        BotShieldPath   /score-probe\n"
    "        BotShieldScore  suspicion +10\n"
    "    </BotShieldRule>\n"
    "    <BotShieldRule act>\n"
    "        BotShieldPath          /score-probe\n"
    "        BotShieldScoreAtLeast  otherthing 5\n"
    "        BotShieldRespond       403\n"
    "    </BotShieldRule>\n"
)


def _get(ip, path="/score-probe"):
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG)


def test_contributions_sum_and_the_threshold_fires(config_override,
                                                   fresh_ip):
    """10 + 5 reaches 15."""
    with config_override(r"BotShieldEnabled\s+On", REACHES,
                         render=False, count=1):
        assert _get(fresh_ip).status_code == 403


def test_one_short_does_not_fire(config_override, fresh_ip):
    """The control. Same rules, threshold at 16, so 15 must not act.

    Without this the test above passes on any 403 the vhost produces.
    """
    with config_override(r"BotShieldEnabled\s+On", FALLS_SHORT,
                         render=False, count=1):
        assert _get(fresh_ip).status_code != 403


def test_accumulators_are_separate(config_override, fresh_ip):
    """A name scopes the coupling; that is the point of naming them."""
    with config_override(r"BotShieldEnabled\s+On", SEPARATE,
                         render=False, count=1):
        assert _get(fresh_ip).status_code != 403, (
            "moving 'suspicion' must not satisfy a test of 'otherthing'"
        )


def test_a_score_does_not_survive_the_request(config_override, fresh_ip,
                                              log_slice):
    """Per-request is the property that makes this safe.

    Two requests from one address: if the accumulator persisted, the
    second would start at 10 and a threshold of 15 would be reached by
    a single +10.

    Asserted on the decision reason, not the status. This vhost scores
    a returning address 25 for droppedcookie and serves the resulting
    challenge as 403, so a status check here reads that challenge as
    the rule firing -- which is exactly the false positive this test
    first produced.
    """
    once = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule s1>\n"
        "        BotShieldPath   /score-probe\n"
        "        BotShieldScore  suspicion +10\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule carried>\n"
        "        BotShieldPath          /score-probe\n"
        "        BotShieldScoreAtLeast  suspicion 15\n"
        "        BotShieldRespond       403\n"
        "        BotShieldLogAs         carried\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", once,
                         render=False, count=1):
        for attempt in (1, 2):
            with log_slice as slc:
                _get(fresh_ip)
            fired = [d for d in slc.decision_lines(ip=fresh_ip)
                     if "requesttrigger:carried" in (d.get("reason") or "")]
            assert not fired, (
                f"request {attempt}: the accumulator reached 15, so it "
                f"carried across requests; lines={fired}"
            )


def test_order_decides_what_a_reader_sees(config_override, fresh_ip):
    """A reader above the contributor sees nothing.

    This is the fold: position k reads rules 1..k-1. It is also the
    property that makes score-as-predicate well-defined.
    """
    reader_first = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule act>\n"
        "        BotShieldPath          /score-probe\n"
        "        BotShieldScoreAtLeast  suspicion 10\n"
        "        BotShieldRespond       403\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule s1>\n"
        "        BotShieldPath   /score-probe\n"
        "        BotShieldScore  suspicion +10\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", reader_first,
                         render=False, count=1):
        assert _get(fresh_ip).status_code != 403, (
            "a rule above the contributor must see 0"
        )


def test_a_scoring_rule_does_not_refuse_by_default(config_override,
                                                   fresh_ip):
    """BotShieldScore alone implies a pass, like BotShieldChallenge.

    Without that a score-only rule would refuse with the family default
    of 403, which is not what "score this" means -- and every later
    rule would be unreachable.
    """
    scoring_only = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule s1>\n"
        "        BotShieldPath   /score-probe\n"
        "        BotShieldScore  suspicion +1\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", scoring_only,
                         render=False, count=1):
        assert _get(fresh_ip).status_code != 403


def test_minus_and_assign(config_override, fresh_ip):
    """- subtracts and = assigns, both against what came before."""
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule s1>\n"
        "        BotShieldPath   /score-probe\n"
        "        BotShieldScore  suspicion +20\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule s2>\n"
        "        BotShieldPath   /score-probe\n"
        "        BotShieldScore  suspicion -12\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule act>\n"
        "        BotShieldPath          /score-probe\n"
        "        BotShieldScoreAtLeast  suspicion 10\n"
        "        BotShieldRespond       403\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        assert _get(fresh_ip).status_code != 403, "20 - 12 = 8, under 10"


def test_a_malformed_movement_is_refused(config_override):
    """No operator, no rule. Silently ignoring it would score nothing."""
    with pytest.raises(Exception) as exc:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldRule bad>\n"
            "        BotShieldPath   /score-probe\n"
            "        BotShieldScore  suspicion 10\n"
            "    </BotShieldRule>\n",
            render=False, count=1,
        ):
            pass
    assert "non-zero exit status" in str(exc.value)
