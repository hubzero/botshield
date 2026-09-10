"""`minload=` is gone as a rule condition.

It matched on the three-state load machine -- normal/warm/hot, driven
mostly by the busy-worker ratio. The shed ladder was its only real
consumer, and on 2026-09-07 that moved to `latencyatleast=`, on the
evidence that the state machine and the load average disagree sharply
about what "busy" means: the machine reached warm 172 times on
2026-09-01 while 98.3% of the shedding it drove happened at a per-CPU
load average between 0.07 and 0.24.

Nobody could say what actually moved the ratio -- a keepalive
explanation was proposed and does not survive KeepAliveTimeout 1 -- and
a condition whose firing nobody can account for is worse than no
condition. So the predicate went and the measurement stayed: the state
is still sampled every tick and still reported as the `load_state`
gauge and `load_state_changes_total`, where being unexplained is a
research problem rather than a policy one.

The 220 lines of behavioural tests that used to live here went with the
predicate. What remains is the guard that it stays gone, because the
key is short, plausible, and would otherwise be easy to reintroduce by
habit.
"""

from __future__ import annotations

import pytest


def test_minload_is_refused_in_a_rule(config_override):
    """A rule naming it fails config parse rather than ignoring it.

    Ignoring an unknown key is how a shed rung ends up looking armed
    while matching every request instead of the loaded ones -- the
    unknown key would simply drop out and leave the rest of the rule
    firing unconditionally.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule minload-gone>\n"
        "        BotShieldPath      /minload-probe\n"
        "        BotShieldMinLoad   warm\n"
        "        BotShieldRespond   503\n"
        "    </BotShieldRule>"
    )
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            pass


def test_a_rule_with_only_minload_is_refused(config_override):
    """It also stops counting as "this rule has a condition".

    Left in the empty-rule guard, a rule whose only predicate was
    minload= would parse as unconditional and match every request --
    the loudest possible version of the previous failure.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule minload-only>\n"
        "        BotShieldMinLoad   hot\n"
        "        BotShieldRespond   503\n"
        "    </BotShieldRule>"
    )
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            pass
