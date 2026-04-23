"""M6.1: mod_watchdog periodic state save fires on its configured
interval. Also asserts the save-duration log line is non-negative
(catches the apr_time_now clock-rollback bug fixed in M10.1).

Slow (waits > 30s for the watchdog tick). Serial because a
config-override reload from a neighbouring test resets the SHM
state_saves_total counter — asserting the delta in an otherwise
parallel run is a race. This test reads the log for ground truth,
which survives reloads.

Port of tests/integration/m6_1_periodic_save.sh.
"""

from __future__ import annotations

import re
import subprocess
import time
from datetime import datetime

import pytest

from botshield_test import client
from botshield_test.config import APACHE_ERROR_LOG, DEV_VHOST_CONF


pytestmark = [pytest.mark.slow, pytest.mark.serial]

_INTERVAL_RX = re.compile(r"^\s*BotShieldStateSaveInterval\s+(\d+)",
                          re.MULTILINE)

# Apache ErrorLog line prefix: "[Thu Apr 23 00:01:27.663998 2026] ..."
# Followed by the state-save payload. We capture the timestamp and
# the duration separately.
_SAVE_LINE_RX = re.compile(
    r"\[(?P<ts>[A-Za-z]{3} [A-Za-z]{3} [ \d]{1,2} \d{2}:\d{2}:\d{2})"
    r"[^\]]*\] "
    r".*state saved to [^\s]+ \([^)]*?(?P<us>-?\d+) us\)"
)


def _read_configured_interval() -> int | None:
    text = subprocess.run(
        ["sudo", "cat", DEV_VHOST_CONF],
        check=True, capture_output=True, text=True,
    ).stdout
    m = _INTERVAL_RX.search(text)
    return int(m.group(1)) if m else None


def _save_lines_after(start: datetime) -> list[tuple[datetime, int]]:
    """Return (timestamp, duration_us) for every 'state saved' log
    line newer than `start`. Reads the main apache error log — the
    watchdog callback emits against the main server_rec, so saves
    land there rather than in the dev-vhost log."""
    tail = subprocess.run(
        ["sudo", "tail", "-n", "500", APACHE_ERROR_LOG],
        check=True, capture_output=True, text=True,
    ).stdout
    out: list[tuple[datetime, int]] = []
    for line in tail.splitlines():
        m = _SAVE_LINE_RX.search(line)
        if not m:
            continue
        # Apache's timestamp drops the year here; we synthesize one
        # from the current year and accept the year-boundary false
        # negative around midnight Dec 31 — not a real risk in CI.
        ts_raw = f"{m.group('ts')} {start.year}"
        try:
            ts = datetime.strptime(ts_raw, "%a %b %d %H:%M:%S %Y")
        except ValueError:
            continue
        if ts >= start:
            out.append((ts, int(m.group("us"))))
    return out


def test_periodic_save_fires_and_duration_non_negative(rate_slot_ip):
    interval = _read_configured_interval()
    if interval is None or interval > 60:
        pytest.skip(
            f"BotShieldStateSaveInterval={interval}; test needs <=60s"
        )

    # Drive one write so there's something dirty worth saving.
    client.get("/admin/.env", xff=rate_slot_ip)

    start = datetime.now()

    # Wait one full cycle plus 15s slack. Watchdog ticks can drift
    # a couple of seconds if the apache was just reloaded by another
    # test — 15s covers that.
    time.sleep(interval + 15)

    saves = _save_lines_after(start)
    assert saves, (
        f"no 'state saved' log lines after {start.isoformat()} "
        f"(waited {interval + 15}s)"
    )

    # Duration of the most recent save must be ≥ 0. A negative
    # value means apr_time_now rolled backwards and the clamp broke.
    last_ts, last_us = saves[-1]
    assert last_us >= 0, (
        f"state-save duration {last_us} us at {last_ts.isoformat()} "
        f"is negative — clock rollback clamp regressed"
    )
