"""BotShieldLatencyAtLeast: the shed signal loadavg cannot see.

An Apache worker blocked on a database socket sits in interruptible
sleep, which Linux does not count toward the load average. A server
with every worker waiting on the database therefore reads as idle to
loadavgatleast=, which is the shape of this deployment's outages: four
of them ran at 25-30 busy workers with requests taking thirty seconds.
Mean request duration does see it -- a blocked worker accumulates
duration for the whole time it waits.

What is asserted here is parse behaviour, the dump, and that a
threshold far above any real reading declines. What is deliberately
not asserted is the firing path: mean latency is a server-wide number
over a tick window that a test cannot set, so "assert it fires at 1ms"
would pass or fail on how busy the box happened to be. That is the
kind of test this suite has been removing, not adding.

Also not covered: the unavailable-metric branch. The metric only reads
unavailable when ExtendedStatus is off, which is server config rather
than vhost config, and config_override reaches only the vhost. The
branch matters -- the sentinel is 0xFFFFFFFF, so comparing it as a
number would clear every threshold and shed traffic precisely when the
server stopped being able to measure itself -- so it is written as an
explicit equality check against the sentinel before any comparison,
and test_a_threshold_no_traffic_reaches_declines would catch the
inverted-comparison half of that mistake. Closing the rest of the gap
needs a server-config override fixture the harness does not have.
"""

from __future__ import annotations

import pytest

from botshield_test import apache, client

# src/shm.h: BS_M_AP_MAX_MS
MAX_MS = 65534


def _rule(body: str) -> str:
    return (
        "BotShieldEnabled On\n"
        "    <BotShieldRule latency-probe>\n"
        f"{body}\n"
        "    </BotShieldRule>"
    )


def test_latency_is_a_condition_on_its_own(config_override):
    """It has to count toward "this rule has a condition".

    Left out of that guard, a rule whose only predicate is latency
    reads as unconditional and is refused at parse time -- which is
    how a condition ships looking supported and is unusable.
    """
    conf = _rule(
        "        BotShieldLatencyAtLeast  500\n"
        "        BotShieldRespond         503"
    )
    # Entering the override is the assertion: config_override runs
    # a configtest and raises if the rule is refused. The request
    # that follows only confirms the rule declines rather than
    # sheds -- on a path the baseline vhost does not gate, because
    # a 403 from gated-content would say nothing about this
    # condition.
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        r = client.get("/latency-cond-probe", ua="probe/1.0")
    assert r.status_code != 503, (
        f"a 500ms floor shed a request on an idle server; "
        f"got {r.status_code}"
    )


def test_the_policy_dump_shows_the_threshold(config_override):
    """A shed rung that cannot be read back before arming is the
    reason the dump grew a rules section in the first place."""
    conf = _rule(
        "        BotShieldPath            /latency-dump-probe\n"
        "        BotShieldLatencyAtLeast  1200\n"
        "        BotShieldRespond         503"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith("latency-probe")]
    assert line, f"rule missing from dump; body={body[:600]}"
    assert "latencyatleast=1200ms" in line[0], line[0]


def test_a_threshold_no_traffic_reaches_declines(config_override):
    """65 seconds of mean request latency is not a number this server
    produces, so the rule must decline and the request must be served.

    This is the half of the gate that can be asserted without knowing
    what the box is doing: if the condition were ignored, or compared
    the wrong way round, the 503 would arrive here.
    """
    conf = _rule(
        "        BotShieldPath            /latency-gate-probe\n"
        "        BotShieldLatencyAtLeast  65000\n"
        "        BotShieldRespond         503\n"
        "        BotShieldLogAs           latency-gate"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        r = client.get("/latency-gate-probe", ua="probe/1.0")
    assert r.status_code != 503, (
        "a 65-second latency floor fired on a healthy server -- the "
        "condition is inverted, ignored, or reading the unavailable "
        "sentinel as a high value"
    )


@pytest.mark.parametrize(
    "value, why",
    [
        ("0", "a 0ms floor matches everything and is always a mistake"),
        (str(MAX_MS + 1), "above the ring's ceiling"),
        ("-5", "negative"),
        ("fast", "not a number"),
        ("250ms", "unit suffix, not the bare integer the setter takes"),
    ],
)
def test_bad_thresholds_are_refused(config_override, value, why):
    """Parse-time refusal, not a silently ignored rung. A shed rule
    that quietly does nothing is worse than one that fails loudly:
    the operator believes the ladder is armed."""
    conf = _rule(
        f"        BotShieldLatencyAtLeast  {value}\n"
        "        BotShieldRespond         503"
    )
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            pass


def test_negation_is_refused(config_override):
    """"Below this" is not expressible, and pretending otherwise
    would invert a shed rule -- shedding exactly when the server is
    healthy. The error says to order the rules instead."""
    conf = _rule(
        "        BotShieldLatencyAtLeast  !500\n"
        "        BotShieldRespond         503"
    )
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            pass
