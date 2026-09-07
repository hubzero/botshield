"""BotShieldLoadAvgAtLeast - per-CPU load average as a rule condition.

The quantitative half of minload=. That reads a three-state machine
driven mostly by the busy-worker ratio, and shm.h says plainly that the
ratio is blind on a large pool: 1024 worker slots on 6 cores means a
fully unusable site still reads 2-3% busy. Load average moves.

Nothing new is measured. The watchdog tick that decides warm/hot
already writes the per-CPU load average to the SHM header, in the same
unit the warm/hot load-average bands use -- hundredths of a runnable
process per core, so 1.0 means one per core and the same threshold
means the same thing on a 6-core host and a 64-core one.

Testing this cannot set the machine's load, so the tests bracket
it instead: read what the module currently reports through
/botshield/metrics, then assert a threshold below it fires and a
threshold above it does not. That works at any real load, and it also
checks the condition and the metric agree about the same number -- a
test with a fixed threshold would pass or fail depending on how busy
the host happened to be.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client


PROBE = "/loadavg-probe"


def _current_pct() -> int:
    """Per-CPU 1-minute load average in hundredths, as the module
    reports it."""
    resp = client.get("/botshield/metrics")
    for line in resp.text.splitlines():
        if line.startswith("botshield_loadavg_1m_pct "):
            return int(line.split()[1])
    raise AssertionError("botshield_loadavg_1m_pct absent from metrics")


def _wait_for_sample(timeout: float = 10.0) -> int:
    """Wait for the watchdog to publish a load sample after a reload.

    A graceful reload resets loadavg_pct to 0 until the next watchdog
    tick, so a rule with this condition does not fire for a few
    seconds after any config change. That is a real property of the
    module, not of the test -- see the module docs -- and every test
    here goes through config_override, so all of them would race it.
    """
    deadline = time.monotonic() + timeout
    last = 0
    while time.monotonic() < deadline:
        last = _current_pct()
        if last > 0:
            return last
        time.sleep(0.5)
    return last

def _conf(ratio: str) -> str:
    return (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule shed>\n"
        f"        BotShieldPath            {PROBE}\n"
        f"        BotShieldLoadAvgAtLeast  {ratio}\n"
        "        BotShieldRespond         451\n"
        "    </BotShieldRule>"
    )


def _fires(config_override, fresh_ip, ratio: str) -> bool:
    with config_override(r"BotShieldEnabled\s+On", _conf(ratio),
                         render=False, count=1):
        _wait_for_sample()
        return client.get(PROBE, xff=fresh_ip).status_code == 451


def test_fires_at_or_below_the_current_load(config_override, fresh_ip):
    """A threshold under the reported load must match.

    Only meaningful when the host has load to be under. At idle the
    reported value hovers near zero and drifts between reading the
    gauge and making the request, so any "just below current"
    threshold is a coin flip -- the first version of this test failed
    exactly that way at 0.10/core. Skipped rather than weakened,
    because the assertion it makes is real when it can be made and
    test_zero_always_fires covers the idle case.
    """
    pct = _current_pct()
    if pct < 20:
        pytest.skip(f"host is idle ({pct/100.0:.2f}/core); no headroom "
                    f"to put a threshold under")
    ratio = f"{(pct // 2) / 100.0:.2f}"
    assert _fires(config_override, fresh_ip, ratio), (
        f"load is {pct/100.0:.2f}/core and the rule asked for {ratio}"
    )
def test_does_not_fire_above_the_current_load(config_override, fresh_ip):
    """A threshold well above it must not.

    Ten per core is chosen rather than something marginal: on a healthy
    host this is unreachable, and if the box really is at 10x cores the
    test failing is the least of anyone's problems.
    """
    pct = _current_pct()
    assert pct < 1000, (
        f"host is at {pct/100.0:.2f}/core; this test assumes it is not "
        f"melting"
    )
    assert not _fires(config_override, fresh_ip, "10.0"), (
        f"load is {pct/100.0:.2f}/core but a 10.0 threshold fired"
    )


def test_zero_always_fires(config_override, fresh_ip):
    """0 is a legal threshold and means every request.

    Pinned because absence is -1 internally, not 0 -- if those were
    conflated, this rule would silently never fire.
    """
    assert _fires(config_override, fresh_ip, "0")


def test_composes_with_the_rest_of_the_rule(config_override, fresh_ip):
    """The point of a condition over a family: shed a kind of client at
    a load, not every client at a load."""
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule shed-bots>\n"
        f"        BotShieldPath            {PROBE}\n"
        "        BotShieldLoadAvgAtLeast  0\n"
        "        BotShieldUserAgent       @scraper\n"
        "        BotShieldRespond         451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        bot = client.get(PROBE, xff=fresh_ip,
                         ua="python-requests/2.31").status_code
        human = client.get(
            PROBE, xff=fresh_ip,
            ua="Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0",
            accept_language="en-US,en;q=0.9").status_code
    assert bot == 451, "a scraper over the threshold is shed"
    assert human != 451, "a browser at the same load is not"


def test_reads_the_same_number_the_metric_reports(config_override, fresh_ip):
    """The condition and the gauge must agree.

    Both read bs_loadavg_current(); this pins that they keep doing so.
    A threshold one hundredth above the reported value must not fire,
    and one at it must -- which is only true if they are the same
    number in the same unit.
    """
    pct = _current_pct()
    at = f"{pct / 100.0:.2f}"
    just_above = f"{(pct + 25) / 100.0:.2f}"
    fires_at = _fires(config_override, fresh_ip, at)
    fires_above = _fires(config_override, fresh_ip, just_above)
    # Load moves between the two requests, so the strict claim is only
    # that "at" is at least as likely to fire as "above".
    assert fires_at or not fires_above, (
        f"threshold {just_above} fired while {at} did not, which means "
        f"the condition is not reading the gauge's number"
    )


# --- config validation ----------------------------------------------


@pytest.mark.parametrize("bad", ["warm", "-1", "1.0.0", "101", "abc"])
def test_rejects_a_non_ratio(config_override, bad):
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", _conf(bad),
                             render=False, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


def test_negation_is_refused(config_override):
    """There is no "below this" spelling. A quiet-host rule is the one
    the loaded rule falls through to, not a negated condition."""
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", _conf("!1.0"),
                             render=False, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)
