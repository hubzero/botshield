"""Order between trigger families in the bs_check_policy walk.

    1. load triggers   (E11.2 - global load_state)
    2. rules           (one-off per-request intent)
    3. feedback        (response-path; separate hook)

This file used to pin five families in a row: cookie, then env, then
load, then path, then feedback. The cookie and env families are gone --
their predicates are BotShieldCookie and BotShieldEnv inside a rule
now -- so four of the six tests here lost their subject rather than
their answer. What is left is load before rule, which is still an
order and can still be got wrong.

One of the deleted tests is worth remembering. An env trigger applied
an action, so it ran on both legs of an internal redirect and applied
twice; the walk carried an ap_is_initial_req gate to stop that. A rule
condition only reads a variable. The gate had nothing to guard once the
action went, and the whole bug class went with the family.

Gate from CHANGELOG.md E7.3:
  - ordering is deterministic
  - later families do not run after an earlier short-circuit
  - decision logs show which family fired
"""

from __future__ import annotations

import time

import pytest


from botshield_test import client, ips as _ips


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"

from botshield_test.config import LOAD_STATE_FILE as LOAD_FILE_PATH


def _g(path, xff, **kw):
    return client.get(path, xff=xff, ua=PASS_UA,
                      accept_language=PASS_AL, **kw)


def _set_load_file(value: str) -> None:
    with open(LOAD_FILE_PATH, "w") as f:
        f.write(value + "\n")


def _wait_for_metric_load_state(target: int, timeout: float = 12.0) -> int:
    """Poll metrics until load_state reaches target. Mirror of the
    helper in test_load_trigger.py — the dispatch-order tests need
    the same state-machine settle to fire load triggers."""
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


# --- Short-circuit blocks later families ---------------------------


def test_load_short_circuit_blocks_path(
    config_override, log_slice, fresh_ip,
):
    """E11.2 load trigger sits between env and path in the runtime
    walk (policy.c:268). When load=hot fires respond=503, the path
    trigger that would also match must not run."""
    _set_load_file("hot")
    try:
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldLoadTrigger l-block state=hot respond=503\n'
            '    BotShieldRule p-block path="/*" respond=451',
            count=1,
        ):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            with log_slice as slc:
                r = _g("/whatever", xff=fresh_ip)
                lines = slc.decision_lines(ip=fresh_ip)
    finally:
        _set_load_file("normal")

    assert r.status_code == 503, (
        f"load short-circuit should return its 503, not defer to path "
        f"(451); got {r.status_code}"
    )
    assert lines
    reason = lines[-1]["reason"]
    assert "loadtrigger:l-block" in reason, reason
    assert "rule:p-block" not in reason, (
        f"path trigger must not have run after load short-circuit; "
        f"reason={reason}"
    )
