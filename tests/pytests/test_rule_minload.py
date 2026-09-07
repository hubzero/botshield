"""E11.2 load state as a rule condition: BotShieldMinLoad.

`minload=normal|warm|hot` fires at that load state **or above**, which
is what a load-shed ladder wants: the strict rung first, the looser one
under it.

    <BotShieldRule shed-hard>
        BotShieldMinLoad   hot
        BotShieldUserAgent @bot
        BotShieldRespond   503
    </BotShieldRule>
    <BotShieldRule shed-soft>
        BotShieldMinLoad   warm
        BotShieldUserAgent @ai-train
        BotShieldChallenge noninteractive
    </BotShieldRule>

This file used to test BotShieldLoadTrigger, a family of its own, and
BotShieldMinLoad had no test at all -- while production used minload=
four times and the family zero. The tests moved to the thing that runs.

The family also offered exact `state=<level>` alongside `state>=`. It
is not carried over and nothing needed it: the only exact form ever
written was `state=hot`, which means the same as `state>=hot` because
hot is the top of the scale. "warm but not hot" has never been asked
for.

Load state is read from BotShieldLoadStateFile, which the tests write
directly and then wait for the module to pick up via its metrics.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client, config


pytestmark = pytest.mark.serial


# Per-worker: BotShieldLoadStateFile is server scope and each
# xdist worker runs its own httpd, so a shared path would let
# one worker's "hot" satisfy or break another's expectations.
LOAD_FILE_PATH = config.LOAD_STATE_FILE
PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"

PROBE = "/minload-probe"


def _g(path: str, **kw):
    return client.get(path, ua=PASS_UA, accept_language=PASS_AL, **kw)


def _set_load_file(value: str) -> None:
    with open(LOAD_FILE_PATH, "w") as f:
        f.write(value + "\n")


def _wait_for_metric_load_state(target: int, timeout: float = 12.0) -> int:
    """Poll metrics until load_state reaches target."""
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        resp = client.get("/botshield/metrics")
        for line in resp.text.splitlines():
            if line.startswith("botshield_load_state "):
                last = int(line.split()[1])
                if last == target:
                    return last
        time.sleep(0.5)
    raise AssertionError(
        f"load_state did not reach {target} within {timeout}s; "
        f"last observed {last}"
    )


def _rule(level, extra=""):
    return (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule shed>\n"
        f"        BotShieldPath      {PROBE}\n"
        f"        BotShieldMinLoad   {level}\n"
        f"{extra}"
        "        BotShieldRespond   503\n"
        "    </BotShieldRule>"
    )


# --- Directive validation ------------------------------------------


def test_rejects_bad_state_name(config_override):
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", _rule("melting"),
                             render=False, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


# --- Behaviour ------------------------------------------------------


def test_inert_under_normal(config_override, fresh_ip):
    """minload=warm with the server at normal: must not fire."""
    _set_load_file("normal")
    try:
        with config_override(r"BotShieldEnabled\s+On", _rule("warm"),
                             render=False, count=1):
            _wait_for_metric_load_state(target=0, timeout=12.0)
            assert _g(PROBE, xff=fresh_ip).status_code != 503
    finally:
        _set_load_file("normal")


def test_fires_at_or_above(config_override, fresh_ip):
    """minload=warm fires once the state has escalated to hot.

    This is the whole point of the "or above" reading: a rule written
    for warm keeps applying as things get worse, rather than being
    stepped over by the escalation it was written for.
    """
    _set_load_file("hot")
    try:
        with config_override(r"BotShieldEnabled\s+On", _rule("warm"),
                             render=False, count=1):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            assert _g(PROBE, xff=fresh_ip).status_code == 503
    finally:
        _set_load_file("normal")


def test_hot_rule_does_not_fire_at_warm(config_override, fresh_ip):
    """The other half of the ladder: a hot rung stays quiet at warm."""
    _set_load_file("warm")
    try:
        with config_override(r"BotShieldEnabled\s+On", _rule("hot"),
                             render=False, count=1):
            _wait_for_metric_load_state(target=1, timeout=12.0)
            assert _g(PROBE, xff=fresh_ip).status_code != 503
    finally:
        _set_load_file("normal")


def test_ladder_takes_the_first_matching_rung(config_override, fresh_ip):
    """Two rungs, strict one first. At hot the strict rung answers.

    Rules are declaration-ordered, so a shed ladder reads top-down with
    the harshest response first -- the same shape the load family's
    first-match-wins gave, without a second walk to explain it.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule shed-hot>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldMinLoad   hot\n"
        "        BotShieldRespond   503\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule shed-warm>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldMinLoad   warm\n"
        "        BotShieldRespond   429\n"
        "    </BotShieldRule>"
    )
    _set_load_file("hot")
    try:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            assert _g(PROBE, xff=fresh_ip).status_code == 503
    finally:
        _set_load_file("normal")

    _set_load_file("warm")
    try:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            _wait_for_metric_load_state(target=1, timeout=12.0)
            assert _g(PROBE, xff=fresh_ip).status_code == 429, (
                "at warm the hot rung must not match and the warm one "
                "must answer"
            )
    finally:
        _set_load_file("normal")


def test_composes_with_the_rest_of_the_rule(config_override, fresh_ip):
    """The reason it is a condition and not a family.

    A load trigger matched load and nothing else. A rule sheds a
    specific kind of client at a specific load, which is what shedding
    actually means.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule shed-bots>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldMinLoad   warm\n"
        "        BotShieldUserAgent @scraper\n"
        "        BotShieldRespond   503\n"
        "    </BotShieldRule>"
    )
    _set_load_file("hot")
    try:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            bot = client.get(PROBE, xff=fresh_ip,
                             ua="python-requests/2.31").status_code
            human = _g(PROBE, xff=fresh_ip).status_code
    finally:
        _set_load_file("normal")
    assert bot == 503, "a scraper under load is shed"
    assert human != 503, "a browser under the same load is not"
