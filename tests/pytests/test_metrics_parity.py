"""M9.3: for every enum value across tier / outcome / cookie / provider,
delta(/metrics) == count(decision-log lines carrying that enum).

The core contract: counters and the structured log never drift from
each other. A wrong entry somewhere on the emission path will show
up here as exactly one non-matching dimension.

Port of tests/integration/m9_3_metrics_parity.sh.
"""

from __future__ import annotations

import pytest

from botshield_test import client, enums, metrics


# Serial: the parity check compares metrics deltas to counts of decision
# lines. Any other test generating traffic between the before/after
# snapshots (but outside our log_slice window) causes spurious drift —
# the metric bumps, the log line doesn't land in the slice.
pytestmark = [pytest.mark.live_network, pytest.mark.serial]


def _drive_mix():
    """Tap a range of enum values: allow + challenged + pending_missing
    + a captcha interstitial render. Doesn't cover every enum but
    covers enough that drift on any dimension is caught."""
    for i in range(1, 6):
        client.get("/", ua="Mozilla/5.0 (X11) Chrome/145",
                   accept_language="en-US",
                   xff=f"203.0.113.{160 + i}")
    for i in range(1, 4):
        client.get("/", ua="python-requests/2.31",
                   xff=f"203.0.113.{170 + i}")
    for _ in range(2):
        client.get("/captcha-demo")

    client.post(
        "/botshield/captcha-verify/turnstile",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"cf-turnstile-response": "x"},
    )


def test_counter_log_parity(log_slice):
    before = metrics.snapshot()
    with log_slice as slc:
        _drive_mix()
        lines = slc.decision_lines()
    after = metrics.snapshot()

    deltas = metrics.delta(before, after)

    drift: list[str] = []

    # tier / outcome / cookie: log spelling matches metric suffix.
    for prefix, values in (("tier", enums.TIERS),
                            ("outcome", enums.OUTCOMES),
                            ("cookie", enums.COOKIES)):
        for v in values:
            metric = f"botshield_{prefix}_{v}_total"
            d = deltas.get(metric, 0.0)
            log_count = sum(1 for ln in lines if ln.get(prefix) == v)
            if int(d) != log_count:
                drift.append(f"{metric}: metric Δ={d}, log={log_count}")

    # Provider: metric uses underscores, log uses hyphens.
    for p in enums.PROVIDERS:
        metric = f"botshield_provider_{p}_total"
        log_form = enums.provider_log(p)
        d = deltas.get(metric, 0.0)
        log_count = sum(1 for ln in lines if ln.get("provider") == log_form)
        if int(d) != log_count:
            drift.append(f"{metric}: metric Δ={d}, log={log_count}")

    assert not drift, (
        f"counter/log drift on {len(drift)} dimension(s):\n"
        + "\n".join(drift)
    )
