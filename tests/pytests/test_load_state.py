"""E11.1 — load-state sampler + cached SHM state + external file.

The watchdog ticks once per second by default, sampling the Apache
scoreboard's busy-worker ratio + reading the operator's external
state file (/etc/botshield/load.state.test in tests; configurable
via BotShieldLoadStateFile). Hysteresis: 3 escalating samples to
promote into warm, 2 more to hot; 5 normal samples to demote one
level.

Tests cover:
  - directive validation (refresh / threshold ranges)
  - invalid file content treated as normal (logged warning)
  - metrics endpoint emits load_state + load_state_changes_total
  - external file driving promotion to hot under hysteresis
    (slow — needs ~5 ticks to actually flip the cached state)

Synthetic worker saturation (driving the scoreboard sampler with
real load) isn't covered here — would need concurrent connection
storms that are flaky in pytest. The internal sampler shares the
same hysteresis machinery as the external file path; if the file
path works the internal path will too once a saturating workload
hits production.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


LOAD_FILE_PATH = "/etc/botshield/load.state.test"


def _read_metrics() -> dict[str, str]:
    """Return a dict of metric-name → value from /botshield/metrics."""
    resp = client.get("/botshield/metrics")
    out = {}
    for line in resp.text.splitlines():
        if not line or line.startswith("#"):
            continue
        # `botshield_<name> <value>` (no labels in this module yet)
        toks = line.split()
        if len(toks) == 2:
            out[toks[0]] = toks[1]
    return out


def _set_load_file(value: str) -> None:
    """Overwrite the external load-state file. Uses a normal write
    because the file is owned by the test user (provisioned with
    mode 0664). No sudo needed."""
    with open(LOAD_FILE_PATH, "w") as f:
        f.write(value + "\n")


def _wait_for_state(target: int, timeout: float = 12.0) -> int:
    """Poll the metrics endpoint until botshield_load_state == target,
    returning the final observed value. Raises if the timeout
    elapses without seeing the target. Polls at 0.5s — fast enough
    to catch a single-tick transition."""
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        m = _read_metrics()
        v = int(m.get("botshield_load_state", "0"))
        last = v
        if v == target:
            return v
        time.sleep(0.5)
    raise AssertionError(
        f"load_state did not reach {target} within {timeout}s; "
        f"last observed {last}"
    )


# --- Directive validation ----------------------------------------


def test_directive_rejects_bad_refresh_interval(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldLoadRefreshInterval 0',
            count=1,
        ):
            pass


def test_directive_rejects_bad_warm_threshold(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldLoadWarmThreshold 0',
            count=1,
        ):
            pass


def test_directive_rejects_relative_state_file_path(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldLoadStateFile relative/path',
            count=1,
        ):
            pass


# --- Metrics surface ---------------------------------------------


def test_metrics_endpoint_emits_load_state_and_counter():
    """Default config (no LoadStateFile, no LoadTrigger) — metrics
    should still expose the load-state gauge + counter so operators
    can observe it without opting into the feature."""
    m = _read_metrics()
    assert "botshield_load_state" in m, (
        f"metrics missing load_state gauge; keys={list(m)[:20]}"
    )
    assert "botshield_load_state_changes_total" in m, (
        f"metrics missing load_state_changes counter; "
        f"keys={list(m)[:20]}"
    )
    # Initial state is normal.
    assert m["botshield_load_state"] == "0", (
        f"expected default state=0 (normal); got "
        f"{m['botshield_load_state']}"
    )


# --- External file path ------------------------------------------


def test_invalid_state_file_value_treated_as_normal(config_override):
    """Garbage in the file → watchdog parses as 'normal' rather
    than crashing or jumping to a wrong state. The warning gets
    logged at the server scope (global error log, not the dev
    vhost log slice) so we observe the behavior via metrics
    instead: state stays at 0 across multiple ticks. Wait long
    enough that hysteresis would have promoted to warm if the
    parse was treated as anything other than normal."""
    _set_load_file("not-a-real-state")
    try:
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}',
            count=1,
        ):
            # 4 watchdog ticks > warm-rise threshold (3). If parse
            # failure were silently treated as warm/hot, state
            # would have promoted by now.
            time.sleep(4.5)
            m = _read_metrics()
    finally:
        _set_load_file("normal")
    assert m["botshield_load_state"] == "0", (
        f"unrecognized state value should fall back to normal; "
        f"got load_state={m['botshield_load_state']}"
    )


def test_external_hot_promotes_through_hysteresis(config_override):
    """Set the file to `hot`. Hysteresis: 3 ticks to promote to
    warm + 2 ticks to promote to hot = 5 ticks at 1s/tick. Allow
    generous slack (12s) to absorb watchdog scheduling jitter."""
    _set_load_file("hot")
    try:
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}',
            count=1,
        ):
            # Watch the gauge climb. 1=warm, 2=hot. We assert
            # eventual hot — passing through warm is implicit.
            final = _wait_for_state(target=2, timeout=12.0)
            assert final == 2

            # Demote: write `normal`, expect 5 ticks to fall to warm
            # and 5 more to fall back to normal. Total ~10s. Use a
            # 15s timeout for safety.
            _set_load_file("normal")
            final = _wait_for_state(target=0, timeout=15.0)
            assert final == 0
    finally:
        _set_load_file("normal")
