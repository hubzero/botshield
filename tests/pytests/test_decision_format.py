"""M9.1 decision-log vocabulary contract.

Drive a diverse traffic mix, then assert every emitted decision
line is well-formed: all required keys present, enum values from
their documented sets. Replaces tests/unit/decision_format.sh +
tests/lib/decision_gate.awk with a Python validator.
"""

from __future__ import annotations

import pytest

from botshield_test import client, cookies, logs


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"
SCRAPER_UA = "python-requests/2.31"


def test_decision_format_across_outcomes(log_slice):
    with log_slice as slc:
        # pass tier — browser headers, no cookie
        client.get("/", ua=BROWSER_UA, accept_language="en-US",
                   xff="203.0.113.150")

        # asset pass-through — no tier assignment either way
        client.get("/favicon.ico")

        # form tier (scraper UA bumps score into form band)
        client.get("/", ua=SCRAPER_UA, xff="203.0.113.151")

        # captcha-challenged (interstitial served)
        client.get("/captcha-demo")

        # pending_missing — verify POST with no pending cookie
        client.post(
            "/botshield/captcha-verify/turnstile",
            data={"cf-turnstile-response": "x"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        # bad content-type
        client.post(
            "/botshield/captcha-verify/turnstile",
            headers={"Content-Type": "application/json"},
            data="{}",
        )

        # unknown endpoint (tier=none, outcome=rejected)
        client.get("/botshield/nonexistent-path")

        lines = slc.decision_lines()

    assert len(lines) > 0, "no decision lines captured — module silent?"

    all_problems: list[str] = []
    for d in lines:
        issues = logs.validate_decision(d)
        if issues:
            all_problems.append(f"{d!r}: {issues}")

    assert not all_problems, (
        f"decision-log format violations ({len(all_problems)} lines bad):\n"
        + "\n".join(all_problems[:5])
    )
