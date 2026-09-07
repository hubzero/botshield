"""A flag-driven challenge fires even where scoring can never reach.

This is the question an operator actually has when their thresholds
are unset -- as qubeshub's are, which means cumulative score
challenges nobody there. If BotShieldChallenge on a flagged= rule
needed a score threshold to be crossed, flagging an address would be
inert on exactly the deployment most likely to reach for it, and the
docs' claim that it bypasses the score thresholds would be false where
it matters most.

Thresholds are parked absurdly high rather than left unset, because
config_override appends and cannot unset. Same effect: no score this
suite generates approaches 9000.

This was a BotShieldFlagTrigger with action=tier_floor until that
family was retired. Same mechanism underneath -- the rule sets a
request tier floor, which MAXes into the decision without consulting a
threshold.
"""

from __future__ import annotations

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"

LADDER_OFF = (
    "BotShieldEnabled On\n"
    # Off, not parked at 9000. The second request in each test is
    # cookieless at an address the first one minted for, which is
    # droppedcookie: 25, past the vhost's 20, and the control would
    # fail on a challenge that has nothing to do with tier floors.
    # This file declares no rows of its own, so the scope switch is
    # exactly the right shape.
    "    BotShieldChallengeAtLeast none\n"
    "    <BotShieldRule tf-probe>\n"
    "        BotShieldPath      /tier-floor-probe\n"
    "        BotShieldRespond   404\n"
    "        BotShieldFlagIP    scanner_probe\n"
    "        BotShieldLogAs     tf-probe\n"
    "    </BotShieldRule>\n"
)

WITH_FLOOR = LADDER_OFF + (
    "    <BotShieldRule flag-floor>\n"
    "        BotShieldFlagged   scanner_probe\n"
    "        BotShieldChallenge noninteractive\n"
    "    </BotShieldRule>\n"
)


def _get(path, ip):
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG)


def _challenged(slc, ip):
    return any(d.get("outcome") == "challenged"
               for d in slc.decision_lines(ip=ip))


def test_tier_floor_fires_with_the_ladder_off(config_override, fresh_ip,
                                              log_slice):
    """Flag the address, then watch an ordinary path get challenged."""
    with config_override(r"BotShieldEnabled\s+On", WITH_FLOOR,
                         render=False, count=1):
        assert _get("/tier-floor-probe", fresh_ip).status_code == 404

        with log_slice as slc:
            _get("/", fresh_ip)
        assert _challenged(slc, fresh_ip), (
            "a declared tier_floor should challenge regardless of the "
            f"score thresholds; lines={slc.decision_lines(ip=fresh_ip)}"
        )


def test_without_the_floor_the_same_flag_does_nothing(config_override,
                                                      fresh_ip, log_slice):
    """The control, so the test above cannot pass for another reason.

    Same rule, same flag, no BotShieldFlagTrigger. Nothing is seeded in,
    so the flag is recorded and acts on nothing.
    """
    with config_override(r"BotShieldEnabled\s+On", LADDER_OFF,
                         render=False, count=1):
        assert _get("/tier-floor-probe", fresh_ip).status_code == 404

        with log_slice as slc:
            _get("/", fresh_ip)
        assert not _challenged(slc, fresh_ip), (
            "with no flag trigger declared the flag should act on "
            f"nothing; lines={slc.decision_lines(ip=fresh_ip)}"
        )
