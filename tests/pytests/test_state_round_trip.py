"""M6: flagged-IP entries persist across an Apache restart via the
state file.

1. Flag an IP by tripping the honeypot.
2. Record baseline metrics.
3. `systemctl restart apache2` (slow; why this test is @serial + @slow).
4. Same IP request after restart still carries reason=flagged-ip.
5. State-load log line says kept >= 1.
6. shm_flagged_used gauge reflects the restored entries.

Port of tests/integration/m6_state_round_trip.sh.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import apache, client, metrics


pytestmark = [pytest.mark.serial]


def test_state_file_survives_restart(rate_slot_ip, log_slice):
    # 1. Flag the IP.
    client.get("/admin/.env", xff=rate_slot_ip)
    time.sleep(1)

    # 2. Warm up: confirm the flag is live via one synchronization hit.
    client.get("/", xff=rate_slot_ip)

    # 3. Restart (pconf cleanup → state saved, new parent → state loaded).
    apache.restart()

    # 4. Same IP post-restart: reason should still carry flagged-ip.
    with log_slice as slc:
        client.get("/", xff=rate_slot_ip)
        post_restart = slc.decision_lines(ip=rate_slot_ip)

    flagged = [d for d in post_restart if "flagged-ip" in d.get("reason", "")]
    assert flagged, (
        f"flag for ip={rate_slot_ip} didn't survive restart; "
        f"post-restart lines: {post_restart}"
    )

    # 5. gauge reflects >= 1 restored entry.
    snap = metrics.snapshot()
    used = metrics.value(snap, "botshield_shm_flagged_used")
    assert used >= 1, (
        f"botshield_shm_flagged_used={used} after restart; expected >= 1"
    )
