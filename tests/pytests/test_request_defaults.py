"""A rule remembers nothing unless it says so.

This family used to flag the matching address with scanner_probe for an
hour by default. The rule that wanted a quiet 404 on /wp-admin got an
hour of per-address state nobody asked for, and wherever an operator
had given scanner_probe a tier floor, every client behind that NAT
started meeting interstitials -- with nothing in the config saying so.

Kept as its own test because a default that writes state is invisible
in the configuration that caused it. Only a test keeps it honest, and
this one outlived the burn= mechanism it was originally written
alongside.
"""

from __future__ import annotations

import time

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"


def test_request_trigger_does_not_flag_the_address_by_default(
    config_override, fresh_ip, log_slice,
):
    """No flag directive, no flag.

    The visible symptom of the old default was the next request from
    that address arriving with `flaggedip` in its reason and a challenge
    it never asked for -- for every client sharing the address, not just
    the one that probed.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        '    BotShieldRule wp-probe path="/wp-admin/*" respond=404 '
        "logas=wp-probe\n",
        count=1,
    ):
        client.get("/wp-admin/setup-config.php", xff=fresh_ip,
                   ua=BROWSER_UA, accept_language=ACCEPT_LANG)
        # Flag writes go through a mutex; a second is enough for the
        # next lookup to see one if it were being written.
        time.sleep(1)

        with log_slice as slc:
            client.get("/", xff=fresh_ip, ua=BROWSER_UA,
                       accept_language=ACCEPT_LANG)

        lines = slc.decision_lines(ip=fresh_ip)
        assert not any("flaggedip" in (d.get("reason") or "")
                       for d in lines), (
            "a rule must not flag the address unless it says "
            f"BotShieldFlagIP; lines={lines}"
        )
