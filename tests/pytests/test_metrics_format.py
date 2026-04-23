"""M11.8: /metrics conforms to the Prometheus exposition format.

Uses prometheus_client's ground-truth parser. Regression gate for:
  - typos / malformed lines that the human eye skips
  - metric names that don't match the [a-zA-Z_:][a-zA-Z0-9_:]*
    regex Prometheus requires
  - missing HELP / TYPE declarations (downstream scrapers tolerate
    but get sloppy display without them)
  - label-name collisions (same metric exposed with mismatched
    label sets)

This catches drift of a different flavor than M9.2/M9.3: those
verify the enum vocabulary is consistent between the log and the
counters; this verifies the counters are *syntactically* valid
Prometheus output.
"""

from __future__ import annotations

import re

import pytest
from prometheus_client.parser import text_string_to_metric_families

from botshield_test import client


# Prometheus 0.0.4: metric names match this regex, label names match
# the same but excluding the colon.
_METRIC_NAME_RX = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_NAME_RX = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def test_metrics_parses_cleanly():
    """prometheus_client's parser accepts /metrics without raising.

    Any malformed line (bad escape, unquoted label value, trailing
    junk) would make the parser raise — we let that propagate so
    pytest's traceback points at the offending text.
    """
    resp = client.get("/botshield/metrics")
    assert resp.status_code == 200

    families = list(text_string_to_metric_families(resp.text))
    assert families, "prometheus parser returned zero metric families"

    # Every family has at least one sample. An empty family is the
    # usual symptom of a misregistered collector.
    for fam in families:
        assert fam.samples, f"metric family {fam.name!r} has no samples"


def test_metric_names_valid():
    """Every metric name conforms to the Prometheus name regex."""
    resp = client.get("/botshield/metrics")
    families = list(text_string_to_metric_families(resp.text))

    bad = [f.name for f in families if not _METRIC_NAME_RX.match(f.name)]
    assert not bad, f"metric names fail Prometheus name regex: {bad}"

    # Samples can carry suffixes (_total on a Counter, _bucket on a
    # Histogram); the parser flattens those into sample.name, which
    # must also be valid.
    bad_samples = []
    for fam in families:
        for s in fam.samples:
            if not _METRIC_NAME_RX.match(s.name):
                bad_samples.append(s.name)
    assert not bad_samples, (
        f"sample names fail Prometheus regex: {bad_samples[:5]}"
    )


def test_label_names_valid():
    """If any metric ever grows labels, their names must match the
    label-name regex. (As of M11.8 the module emits only unlabeled
    metrics; this test guards the day that changes.)"""
    resp = client.get("/botshield/metrics")
    families = list(text_string_to_metric_families(resp.text))

    bad = []
    for fam in families:
        for s in fam.samples:
            for label_name in s.labels:
                if not _LABEL_NAME_RX.match(label_name):
                    bad.append((fam.name, label_name))
    assert not bad, f"label names fail Prometheus regex: {bad[:5]}"


def test_every_metric_has_help_and_type():
    """HELP + TYPE are technically optional per the Prometheus spec,
    but downstream scrapers + alertmanager UIs lean on them heavily.
    Catch the day someone adds a counter without registering the
    metadata."""
    resp = client.get("/botshield/metrics")
    families = list(text_string_to_metric_families(resp.text))

    missing_help = [f.name for f in families if not f.documentation]
    assert not missing_help, (
        f"metrics without HELP text: {missing_help}"
    )
    # Parser normalizes type to a few strings; empty is the failure.
    missing_type = [f.name for f in families if not f.type]
    assert not missing_type, (
        f"metrics without TYPE declaration: {missing_type}"
    )


def test_no_duplicate_family_registration():
    """The parser will happily emit the same family twice if the
    source text declares HELP/TYPE + samples twice. That's a real
    regression risk in a hand-written exposition writer."""
    resp = client.get("/botshield/metrics")
    families = list(text_string_to_metric_families(resp.text))
    seen: dict[str, int] = {}
    for f in families:
        seen[f.name] = seen.get(f.name, 0) + 1
    dupes = {k: v for k, v in seen.items() if v > 1}
    assert not dupes, f"metric families appear more than once: {dupes}"
