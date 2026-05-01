"""E13.1 — capacity headroom gauges.

The metrics endpoint surfaces population + capacity for each of the
three open-addressing reputation tables (flagged-IP, strike,
safeguard). Operators chart used / capacity to see load factor; the
periodic headroom watchdog warns at 50% / 70% before probe-saturation
forces overwrites.

These tests cover the metrics-export surface; the warning emission
itself is best validated by inspecting the error log under load,
which is impractical in a pytest. The headroom watchdog ticks every
60s and walks at most 3 × 50k slots (default), so the cost is
negligible and the absence of a regression there is easy to confirm
by the suite running normally.
"""

from __future__ import annotations

import re
import time

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


METRIC_RE = re.compile(r"^botshield_(\S+)\s+(\d+)\s*$")


def _scrape_metrics() -> dict[str, int]:
    resp = client.get("/botshield/metrics")
    out: dict[str, int] = {}
    for line in resp.text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = METRIC_RE.match(line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def test_metrics_exposes_all_three_table_gauges():
    """flagged-IP, strike, and safeguard each get a used + capacity
    gauge, with capacities defaulting to 50k slots in the dev config."""
    m = _scrape_metrics()
    for table in ("flagged", "strike", "safeguard"):
        used = f"shm_{table}_used"
        cap  = f"shm_{table}_capacity"
        assert used in m, f"missing gauge: {used}"
        assert cap in m, f"missing gauge: {cap}"
        assert m[cap] >= 1024, (
            f"{cap}={m[cap]} unexpectedly small; default config "
            f"should size each table at >=1024 slots"
        )
        assert m[used] <= m[cap], (
            f"{used}={m[used]} exceeds {cap}={m[cap]} — load factor "
            f">100% violates physical capacity"
        )


def test_strike_used_grows_when_429_burst_recorded(
    config_override, fresh_ip,
):
    """Tight rate limit + escalate. Burst past the limit and observe
    the strike table's used-count climb. Verifies the new gauge isn't
    a static zero and tracks bs_strike_record_429 writes.

    Uses a 2/min budget (not /sec) so a sequential 8-request burst
    actually exhausts the bucket inside one window — /sec rolls
    every wall-clock second and Python HTTPS requests are slow
    enough that some hit fresh windows.

    Sleeps >1s before scraping so the thread-local gauge cache
    expires and the scrape sees fresh values."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldRateLimit corpbot 2 min "CorpBot" *\n'
        '    BotShieldRateLimitEscalate corpbot 3 min status=403 ttl=60',
        count=1,
    ):
        for _ in range(8):
            client.get("/", xff=fresh_ip, ua="CorpBot/1.0")
        time.sleep(1.1)   # gauge cache TTL is 1s
        used = _scrape_metrics().get("shm_strike_used", 0)
    assert used >= 1, (
        f"strike_used should reflect at least one 429 strike after "
        f"a 2/min budget burst of 8 requests; got {used}"
    )
