"""Prometheus /metrics scraper + delta helpers.

A snapshot is a dict[str, float] keyed by the full Prometheus metric
name including labels. `delta(before, after)` returns another dict
with the per-metric difference. That's enough structure for every
assertion the bash suite needed.
"""

from __future__ import annotations

from . import client

METRICS_PATH = "/botshield/metrics"


def snapshot() -> dict[str, float]:
    """Scrape /metrics and return {metric_name: value}.

    HELP/TYPE lines are skipped. Metrics with labels appear once per
    label-set, keyed by the full expansion including braces. A metric
    without labels lands under its bare name.
    """
    resp = client.get(METRICS_PATH)
    resp.raise_for_status()
    out: dict[str, float] = {}
    for raw_line in resp.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # `name{labels} value [timestamp]` or `name value`.
        # The splitting strategy handles both: rpartition on the first
        # whitespace that separates value from name+labels.
        parts = line.rsplit(maxsplit=1)
        if len(parts) != 2:
            continue
        name, value = parts
        try:
            out[name] = float(value)
        except ValueError:
            continue
    return out


def delta(before: dict[str, float], after: dict[str, float]) -> dict[str, float]:
    """Return {metric: after - before} for every metric that exists in
    either snapshot. Missing metrics on either side default to 0."""
    keys = set(before) | set(after)
    return {k: after.get(k, 0.0) - before.get(k, 0.0) for k in keys}


def value(snap: dict[str, float], name: str) -> float:
    """Convenience: `snap.get(name, 0.0)` but returns 0 on missing so
    a metric that didn't exist at baseline doesn't KeyError later."""
    return snap.get(name, 0.0)
