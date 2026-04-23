"""M5.1: honeypot hit writes the client IP into the SHM flagged-IP
table; next request from the same IP picks up reason=flagged-ip.

Port of tests/integration/m5_1_flagged_ip.sh.
"""

from __future__ import annotations

import time

from botshield_test import client


def test_flagged_ip_propagates(rate_slot_ip, log_slice):
    # rate_slot_ip gives us an address in 198.51.100.0/24 — a range
    # the bash suite also uses for flagging, but the honeypot table
    # has plenty of slots so cross-test collisions are fine.
    with log_slice as slc:
        # Trip the honeypot scope.
        client.get("/admin/.env", xff=rate_slot_ip)

        # Flag writes through a mutex; the next lookup is lockless
        # but the seqlock write may not be visible instantly. One
        # second is plenty.
        time.sleep(1)

        # Hit the normal path from the same IP.
        client.get("/", xff=rate_slot_ip)

        lines = slc.decision_lines(ip=rate_slot_ip)

    flagged = [d for d in lines if "flagged-ip" in d.get("reason", "")]
    assert flagged, (
        f"no decision for ip={rate_slot_ip} carried reason=flagged-ip; "
        f"all lines for this IP: {lines}"
    )
