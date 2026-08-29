"""E15 — per-cookie forgiveness cap per rolling hour.

A patient bot solving challenges repeatedly used to earn unbounded
forgiveness against accumulated rep score. The cap bounds the
points-per-hour any one cookie can earn so a bot pinned at borderline
score can't farm forgiveness indefinitely. State rides in the cookie
envelope (`forgive_window_start`, `forgive_consumed`) so the cap
survives cookie re-issues but not deliberate cookie drops — by
design, since dropping the cookie also drops the score-debt the
forgiveness was meant to offset.

The cap defaults to BS_DEFAULT_FORGIVE_CAP_PER_HOUR (200) and is
configurable via BotShieldForgivenessCapPerHour at server scope.
0 disables the cap (legacy behavior).
"""

from __future__ import annotations

import pytest

from botshield_test import client


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


# --- Directive validation ------------------------------------------


def test_directive_rejects_negative(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldForgivenessCapPerHour -1',
            count=1,
        ):
            pass


def test_directive_rejects_out_of_range(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldForgivenessCapPerHour 9999',
            count=1,
        ):
            pass


def test_directive_accepts_zero_to_disable(config_override, fresh_ip):
    """0 disables the cap (legacy uncapped behavior). Reload should
    succeed and the server should still respond. Smoke test on the
    directive parser; not load-bearing on tier behavior, so we
    accept the new 403 interstitial as a healthy response too —
    the only way this should fail is a 5xx from a misconfig."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldForgivenessCapPerHour 0',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip,
                       ua="Mozilla/5.0 Firefox/125.0",
                       accept_language="en-US,en;q=0.9")
        assert r.status_code < 500, (
            f"server unhealthy after cap-disable reload; "
            f"status={r.status_code}"
        )


def test_directive_accepts_normal_value(config_override, fresh_ip):
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldForgivenessCapPerHour 50',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip,
                       ua="Mozilla/5.0 Firefox/125.0",
                       accept_language="en-US,en;q=0.9")
        assert r.status_code < 500
