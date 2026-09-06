"""M5.2: rotating Bloom filter's firstsightip penalty.

A fresh IP should pick up `firstsightip` in the reason list; a
repeat hit from the same IP should not.

Port of tests/integration/m5_2_bloom_first_sight.sh.
"""

from __future__ import annotations

from botshield_test import client


SCRAPER_UA = "python-requests/2.31"


def test_first_sight_fires_once(fresh_ip, log_slice):
    with log_slice as slc:
        # First hit from the fresh IP.
        client.get("/", xff=fresh_ip, ua=SCRAPER_UA)

        # Second hit from the SAME IP.
        client.get("/", xff=fresh_ip, ua=SCRAPER_UA)

        lines = slc.decision_lines(ip=fresh_ip)

    assert len(lines) == 2, (
        f"expected two decision lines for ip={fresh_ip}, got {len(lines)}: {lines}"
    )

    first, second = lines[0], lines[1]

    assert "sig-firstsight" in first["reason"], (
        f"first hit should carry firstsightip; reason={first['reason']!r}"
    )

    assert "sig-firstsight" not in second["reason"], (
        f"second hit should NOT carry firstsightip (Bloom already has it); "
        f"reason={second['reason']!r}"
    )
