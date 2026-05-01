"""E11.2 — BotShieldLoadTrigger.

Plugs into the E7.2 trigger family. Predicate matches on the global
cached load_state (from E11.1's sampler + external file). Action
keys reuse the shared bs_trigger_action surface: penalty, credit,
status, log. flag/ttl/redirect rejected at parse time because load
is global state, not per-IP behavior.

Tests use the external load-state file from E11.1 to drive the
state deterministically. With the file containing `hot`, after the
hysteresis settles (3+2 ticks), state becomes hot — and any
configured `state>=warm` or `state=hot` trigger fires on the next
request.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


LOAD_FILE_PATH = "/etc/botshield/load.state.test"
PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"


def _g(path: str, **kw):
    return client.get(path, ua=PASS_UA, accept_language=PASS_AL, **kw)


def _set_load_file(value: str) -> None:
    with open(LOAD_FILE_PATH, "w") as f:
        f.write(value + "\n")


def _wait_for_metric_load_state(target: int, timeout: float = 12.0) -> int:
    """Poll metrics until load_state reaches target. Reuse of the
    helper from test_load_state.py would be DRY-er but pulling it
    in across files isn't worth the conftest.py churn for two
    tests."""
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


# --- Directive validation ----------------------------------------


def test_directive_rejects_unrecognized_load_match(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllowVerifiedBots\s+on",
            'BotShieldAllowVerifiedBots on\n'
            '    BotShieldLoadTrigger bad cpu>=80 penalty=10',
            count=1,
        ):
            pass


def test_directive_rejects_bad_state_name(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllowVerifiedBots\s+on",
            'BotShieldAllowVerifiedBots on\n'
            '    BotShieldLoadTrigger bad state=meltdown penalty=10',
            count=1,
        ):
            pass


def test_directive_rejects_flag_key(config_override):
    """Load triggers can't write per-IP flags — load is global state.
    The shared parser rejects flag= for this family."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllowVerifiedBots\s+on",
            'BotShieldAllowVerifiedBots on\n'
            '    BotShieldLoadTrigger bad state=hot '
            'flag=honeypot_hit ttl=3600',
            count=1,
        ):
            pass


# --- Trigger doesn't fire under normal state --------------------


def test_load_trigger_inert_under_normal(config_override, fresh_ip,
                                         log_slice):
    """state>=warm trigger configured but state is normal: must NOT
    fire. The reason trace should not contain load-trigger:..."""
    _set_load_file("normal")
    try:
        with config_override(
            r"BotShieldAllowVerifiedBots\s+on",
            'BotShieldAllowVerifiedBots on\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}\n'
            '    BotShieldLoadTrigger be-strict state>=warm '
            'penalty=20',
            count=1,
        ):
            with log_slice as slc:
                _g("/", xff=fresh_ip)
                lines = slc.decision_lines(ip=fresh_ip)
    finally:
        _set_load_file("normal")
    assert lines, "no decision line"
    assert "load-trigger:be-strict" not in lines[-1]["reason"], (
        f"load trigger fired under normal state; reason="
        f"{lines[-1]['reason']}"
    )


# --- Trigger fires under hot ------------------------------------


def test_load_trigger_fires_under_hot(config_override, fresh_ip,
                                      log_slice):
    """state>=warm trigger fires when state has escalated to hot.
    Wait for the state to reach hot via the watchdog hysteresis,
    then issue a request and observe the load-trigger reason."""
    _set_load_file("hot")
    try:
        with config_override(
            r"BotShieldAllowVerifiedBots\s+on",
            'BotShieldAllowVerifiedBots on\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}\n'
            '    BotShieldLoadTrigger be-strict state>=warm '
            'penalty=20 log=brownout',
            count=1,
        ):
            # Wait for state machine to settle on hot (~5s).
            _wait_for_metric_load_state(target=2, timeout=12.0)
            with log_slice as slc:
                _g("/", xff=fresh_ip)
                lines = slc.decision_lines(ip=fresh_ip)
    finally:
        _set_load_file("normal")
    assert lines, "no decision line for the hot-state request"
    reason = lines[-1]["reason"]
    assert "load-trigger:be-strict" in reason, (
        f"load trigger should have fired; reason={reason}"
    )
    # log= tag rides the decision line.
    assert lines[-1].get("tag") == "brownout", (
        f"expected tag=brownout; got {lines[-1].get('tag')!r}"
    )


# --- status=403 short-circuits the request ----------------------


def test_load_trigger_status_blocks_under_hot(
    config_override, fresh_ip,
):
    """state=hot with status=503 short-circuits the request. CHANGELOG's
    'optional short-circuiting of expensive anonymous paths' shape:
    operators can hard-stop traffic when the host is hot."""
    _set_load_file("hot")
    try:
        with config_override(
            r"BotShieldAllowVerifiedBots\s+on",
            'BotShieldAllowVerifiedBots on\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}\n'
            '    BotShieldLoadTrigger drop-noise state=hot '
            'status=503',
            count=1,
        ):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            r = _g("/", xff=fresh_ip)
    finally:
        _set_load_file("normal")
    assert r.status_code == 503, (
        f"hot-state load trigger should have returned 503; "
        f"got {r.status_code}"
    )


# --- Specificity: state=hot fires before state>=warm if listed first


def test_load_trigger_first_match_wins_specific_first(
    config_override, fresh_ip, log_slice,
):
    """Two load triggers — declaration order is operator's lever.
    With `state=hot` declared first, hot requests get its action;
    warm requests fall through to the second `state>=warm`.
    Verifies the first-match-wins semantic the executor enforces."""
    _set_load_file("hot")
    try:
        with config_override(
            r"BotShieldAllowVerifiedBots\s+on",
            'BotShieldAllowVerifiedBots on\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}\n'
            '    BotShieldLoadTrigger only-hot state=hot penalty=80\n'
            '    BotShieldLoadTrigger any-warm state>=warm penalty=20',
            count=1,
        ):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            with log_slice as slc:
                _g("/", xff=fresh_ip)
                lines = slc.decision_lines(ip=fresh_ip)
    finally:
        _set_load_file("normal")
    reason = lines[-1]["reason"]
    assert "load-trigger:only-hot" in reason, (
        f"specific-first declaration should win under hot; "
        f"reason={reason}"
    )
    assert "load-trigger:any-warm" not in reason, (
        f"second load trigger should not have fired (first-match-wins); "
        f"reason={reason}"
    )
