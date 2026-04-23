"""M11.8: soak test as a pytest invocation.

Replaces the bash soak.sh + soak-analyze.sh pair with a single test
that drives load via `botshield_test.load.LoadGenerator`, samples
metrics/RSS/log-size in-process, and asserts analyzer-level
invariants directly.

Knobs (all env vars):

  BS_SOAK_DURATION_SEC                 duration (default 60)
  BS_SOAK_RPS                          target rps (default 25)
  BS_SOAK_MAX_RSS_GROWTH_KB            (default 200 MB in kB)
  BS_SOAK_MAX_LOG_GROWTH_PER_HOUR_MB   (default 100)
  BS_SOAK_REPORT                       optional path to write the
                                       sample series (mainly for
                                       overnight runs; short runs
                                       don't need it)

Running:

  short (PR gate):    tests/run --slow --match soak
  overnight (manual): BS_SOAK_DURATION_SEC=28800 BS_SOAK_RPS=50 \\
                      tests/run --slow --match soak

Marked @slow (the default 60s wait is beyond the fast-lane budget)
and @serial (the load hits the whole module; parallel tests would
have their counters drowned).
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from botshield_test import client, metrics
from botshield_test.config import APACHE_ERROR_LOG, ERROR_LOG
from botshield_test.load import LoadGenerator


pytestmark = [pytest.mark.slow, pytest.mark.serial]


# Counters the analyzer watches for strict non-decreasing behavior.
# A decrease means the SHM segment reset mid-run (crash, graceful
# reload).
_MONOTONIC_COUNTERS = (
    "botshield_tier_pass_total",
    "botshield_tier_form_total",
    "botshield_tier_captcha_total",
    "botshield_outcome_declined_total",
    "botshield_outcome_challenged_total",
)

# These decision-log keys shouldn't appear during a soak. Anything
# here is a real signal that the module is misbehaving.
_FORBIDDEN_PATTERNS = (
    r"metrics: unknown",
)

# Crash signatures scanned from journalctl.
_CRASH_PATTERNS = (
    r"SIGSEGV",
    r"segfault",
    r"core dumped",
    r"AddressSanitizer",
    r"UndefinedBehavior",
)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _apache_rss_kb() -> int:
    """Total RSS across all apache2 workers, in kB."""
    out = subprocess.run(
        ["ps", "-C", "apache2", "-o", "rss="],
        capture_output=True, text=True, check=False,
    ).stdout
    return sum(int(x) for x in out.split() if x.strip())


def _file_size(path: str) -> int:
    """Size of a root-owned file via sudo stat."""
    result = subprocess.run(
        ["sudo", "stat", "-c", "%s", path],
        check=False, capture_output=True, text=True,
    )
    try:
        return int(result.stdout.strip())
    except ValueError:
        return 0


def _sampling_interval(duration_sec: int) -> int:
    """Scale sampling frequency to the soak length.

    Short smoke runs sample often for resolution; overnight runs
    sample every 30 min to keep the series manageable.
    """
    if duration_sec <= 300:
        return 15          # ≤5m: every 15s
    if duration_sec <= 3600:
        return 300         # ≤1h: every 5m
    return 1800            # >1h: every 30m


def _count_forbidden_since(start_unix: int) -> dict[str, int]:
    """Count FORBIDDEN_PATTERNS in both apache logs written after
    start_unix. Cheap: one sudo grep per pattern per log.
    """
    out: dict[str, int] = {}
    # Use awk to filter by [ApacheTimestamp] >= start. Apache's
    # error-log prefix is [Thu Apr 23 12:34:56.xxx 2026].
    for pat in _FORBIDDEN_PATTERNS:
        total = 0
        for log in (ERROR_LOG, APACHE_ERROR_LOG):
            # sudo grep | wc -l, bounded by start_unix heuristically
            # via `awk`. Approximate match is fine; any non-zero is
            # a red flag.
            result = subprocess.run(
                ["sudo", "grep", "-c", pat, log],
                capture_output=True, text=True, check=False,
            )
            try:
                n = int(result.stdout.strip())
            except ValueError:
                n = 0
            total += n
        out[pat] = total
    return out


def _crash_signatures_since(start_iso: str) -> list[str]:
    """Scan journalctl for apache crash/sanitizer signatures since
    start_iso. Returns matching lines (head 5)."""
    result = subprocess.run(
        ["sudo", "journalctl", "-u", "apache2",
         "--since", start_iso, "--no-pager"],
        capture_output=True, text=True, check=False,
    )
    rx = re.compile("|".join(_CRASH_PATTERNS))
    return [ln for ln in result.stdout.splitlines() if rx.search(ln)][:5]


def test_soak(request):
    duration_sec = _env_int("BS_SOAK_DURATION_SEC", 60)
    rps = _env_int("BS_SOAK_RPS", 25)
    max_rss_growth_kb = _env_int("BS_SOAK_MAX_RSS_GROWTH_KB", 200 * 1024)
    max_log_per_hour_mb = _env_int("BS_SOAK_MAX_LOG_GROWTH_PER_HOUR_MB", 100)
    report_path = os.environ.get("BS_SOAK_REPORT", "")

    sampling_interval = _sampling_interval(duration_sec)

    # --- Baseline ---
    start_unix = int(time.time())
    start_iso = datetime.fromtimestamp(start_unix, tz=timezone.utc).isoformat()
    baseline_rss_kb = _apache_rss_kb()
    baseline_log_bytes = _file_size(ERROR_LOG)

    print(
        f"\nsoak starting: duration={duration_sec}s rps={rps} "
        f"sampling_interval={sampling_interval}s"
    )
    print(
        f"baseline: rss={baseline_rss_kb} kB, "
        f"log={baseline_log_bytes} B"
    )

    # Sample series: list of dicts, one per sample.
    samples: list[dict] = []

    def sample():
        samples.append({
            "t": time.time(),
            "rss_kb": _apache_rss_kb(),
            "log_bytes": _file_size(ERROR_LOG),
            "metrics": metrics.snapshot(),
        })

    # --- Start load + sample loop in foreground ---
    gen = LoadGenerator(rps=rps, duration_sec=duration_sec)
    gen.start()
    sample()  # t0 sample so first-vs-last comparison is clean.

    # Fire one sample per interval tick. Counting explicitly instead
    # of checking time.time() against a deadline dodges a class of
    # "last sample stolen by rounding" bugs; we know duration_sec /
    # interval and just loop that many times.
    n_ticks = max(1, duration_sec // sampling_interval)
    for _ in range(n_ticks):
        time.sleep(sampling_interval)
        sample()

    gen.stop()
    sample()  # final sample after drain.

    s = gen.stats
    print(
        f"load generator: sent={s.sent} errors={s.errors} "
        f"duration={s.duration_sec:.1f}s actual_rps={s.rps:.1f}"
    )

    # Optionally write the full series out for post-mortem.
    if report_path:
        _write_report(report_path, samples, start_unix, duration_sec, rps, s)

    # --- Assertions ---

    # 1. Sample floor — we control sampling here, so <4 means the
    #    loop aborted. Would have caught the M11.5 bash-archive
    #    breakage instantly.
    assert len(samples) >= 4, (
        f"only {len(samples)} samples collected; sampling loop broke"
    )

    # 2. RSS growth bounded.
    rss_delta = samples[-1]["rss_kb"] - samples[0]["rss_kb"]
    assert rss_delta <= max_rss_growth_kb, (
        f"RSS grew by {rss_delta} kB > {max_rss_growth_kb} kB threshold "
        f"over {duration_sec}s"
    )
    print(f"RSS delta: {rss_delta} kB (bound {max_rss_growth_kb} kB)")

    # 3. Log growth bounded, scaled to wall-clock hours (floor 50 MB).
    hours = duration_sec / 3600
    log_delta_bytes = samples[-1]["log_bytes"] - samples[0]["log_bytes"]
    threshold_mb = max(50, int(max_log_per_hour_mb * hours))
    threshold_bytes = threshold_mb * 1024 * 1024
    assert log_delta_bytes <= threshold_bytes, (
        f"log grew by {log_delta_bytes} B > {threshold_bytes} B "
        f"({threshold_mb} MB budget at {max_log_per_hour_mb} MB/hr × {hours:.3f}h)"
    )
    print(f"log delta: {log_delta_bytes} B (bound {threshold_bytes} B)")

    # 4. Critical counters monotonic AND non-negative AND actually moved.
    for counter in _MONOTONIC_COUNTERS:
        values = [
            sample["metrics"].get(counter, 0.0) for sample in samples
        ]
        # No negatives. A metric that reads -1 is a scrape error.
        negatives = [v for v in values if v < 0]
        assert not negatives, (
            f"{counter}: negative values in series: {values}"
        )
        # Monotonic non-decreasing.
        for i in range(1, len(values)):
            assert values[i] >= values[i - 1], (
                f"{counter} decreased at sample {i}: "
                f"{values[i-1]} → {values[i]} (SHM reset? crash?)"
            )
        # Final > 0 for counters that should have moved. Given the
        # default mix is 70% pass-tier traffic, the pass / declined
        # counters must have grown; form / challenged likewise from
        # the scraper-UA slice; captcha-tier from /captcha-demo.
        # Any zero here means the driver wasn't actually reaching
        # the module.
        assert values[-1] > values[0], (
            f"{counter}: no growth across soak "
            f"(start={values[0]}, end={values[-1]}). Driver not landing traffic?"
        )

    # 5. No 'metrics: unknown' lines anywhere (M9.2 vocabulary drift).
    #    We can't cleanly filter by start_unix across both logs with
    #    a single grep, so a non-zero count is an unconditional red
    #    flag — the test suite should never leave these in the logs,
    #    and if M9.2 drift appeared mid-soak, a rotated log is still
    #    better than a silent pass.
    forbidden = _count_forbidden_since(start_unix)
    for pat, count in forbidden.items():
        assert count == 0, (
            f"soak tripped forbidden log pattern {pat!r}: {count} line(s) "
            f"in apache error logs"
        )

    # 6. No crash signatures in journalctl since soak start.
    crashes = _crash_signatures_since(start_iso)
    assert not crashes, (
        "crash signatures in journalctl since soak start:\n"
        + "\n".join(crashes)
    )

    print(
        f"soak: PASS — {len(samples)} samples, "
        f"RSS+{rss_delta} kB, log+{log_delta_bytes} B over {duration_sec}s"
    )


def _write_report(path, samples, start_unix, duration_sec, rps, stats):
    """Emit a human-readable sample series for overnight
    post-mortems. Not machine-consumed — pytest fails tests itself
    if any invariant breaks — so plain text is fine."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        f.write(
            f"# soak pytest report  duration={duration_sec}s rps={rps}\n"
            f"# start_unix={start_unix}  baseline_rss={samples[0]['rss_kb']} kB  "
            f"baseline_log={samples[0]['log_bytes']} B\n"
        )
        for s in samples:
            m = s["metrics"]
            f.write(
                f"t={int(s['t'])} rss_kb={s['rss_kb']} "
                f"log_bytes={s['log_bytes']} "
                f"tier_pass={int(m.get('botshield_tier_pass_total', 0))} "
                f"tier_form={int(m.get('botshield_tier_form_total', 0))} "
                f"tier_captcha={int(m.get('botshield_tier_captcha_total', 0))} "
                f"state_saves={int(m.get('botshield_state_saves_total', 0))}\n"
            )
        f.write(
            f"# load: sent={stats.sent} errors={stats.errors} "
            f"actual_rps={stats.rps:.1f}\n"
        )
