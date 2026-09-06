"""BotShieldChallengeAtLeast — decide on an accumulator, after policy.

BotShieldScore accumulates in the rule ladder, which runs before
robots.txt and rate limiting. Accumulating there is harmless; nothing
between those stages reads an accumulator. Deciding there is not: a
request both over the threshold and over a rate ceiling would be
challenged instead of refused, because the ladder short-circuits before
the limiter runs.

So the decision lives beside bs_decide_tier, after all of policy, which
is where the score thresholds always chose a tier.

The accumulator here is deliberately not called `suspicion`: names are a
per-request global namespace, and test_named_scores already uses that
one. Two configs picking the same name share the accumulator, silently.
"""

from __future__ import annotations

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"

# No parking. This used to raise the ambient cut-points to 9000 so
# the vhost's ladder could not reach anything; the vhost has no ambient
# ladder now, and unset has always meant never, so 9000 said nothing
# that silence does not say.
#
# The vhost's botsignals rows are what could still interfere, and this
# probe stays clear of them by being uninteresting: one request from a
# fresh address, a browser UA, an Accept-Language. firstsight is the
# only signal that fires and 5 does not reach 20.
REACHES = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule cal-a>\n"
      "        BotShieldPath   /cal-probe\n"
      "        BotShieldScore  calsig +12\n"
      "    </BotShieldRule>\n"
      "    <BotShieldRule cal-b>\n"
      "        BotShieldPath   /cal-probe\n"
      "        BotShieldScore  calsig +8\n"
      "    </BotShieldRule>\n"
      "    BotShieldChallengeAtLeast calsig 20 noninteractive\n"
)

SHORT = REACHES.replace("calsig 20 noninteractive",
                        "calsig 21 noninteractive")


def _get(ip, path="/cal-probe"):
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG)


def _challenged(slc, ip):
    return any(d.get("outcome") in ("challenged", "~challenge")
               for d in slc.decision_lines(ip=ip))


def test_reaching_the_threshold_challenges(config_override, fresh_ip,
                                           log_slice):
    """12 + 8 reaches 20, and the tier decision acts on it."""
    with config_override(r"BotShieldEnabled\s+On", REACHES,
                         render=False, count=1):
        with log_slice as slc:
            _get(fresh_ip)
        assert _challenged(slc, fresh_ip), (
            f"calsig reached 20; lines={slc.decision_lines(ip=fresh_ip)}"
        )


def test_one_short_does_not_challenge(config_override, fresh_ip,
                                      log_slice):
    """The control: same rules, threshold 21, so 20 must not act."""
    with config_override(r"BotShieldEnabled\s+On", SHORT,
                         render=False, count=1):
        with log_slice as slc:
            _get(fresh_ip)
        assert not _challenged(slc, fresh_ip), (
            f"20 is under 21; lines={slc.decision_lines(ip=fresh_ip)}"
        )


def test_none_drops_inherited_rows(config_override, fresh_ip, log_slice):
    """'none' is the off switch a list needs.

    Rows accumulate on merge, so without this a scope could add a row
    and never silence one. The thresholds this replaces were
    single-valued, so overriding one was enough; a list is not.
    """
    with_reset = REACHES + "    BotShieldChallengeAtLeast none\n"
    with config_override(r"BotShieldEnabled\s+On", with_reset,
                         render=False, count=1):
        with log_slice as slc:
            _get(fresh_ip)
        assert not _challenged(slc, fresh_ip), (
            "'none' should have dropped the row above it; "
            f"lines={slc.decision_lines(ip=fresh_ip)}"
        )


def test_rows_max_rather_than_first_match(config_override, fresh_ip,
                                          log_slice):
    """Several rows may match; the highest tier wins, order irrelevant.

    Written lowest-first so a first-match implementation would settle
    on noninteractive and be caught.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule cal-a>\n"
        "        BotShieldPath   /cal-probe\n"
        "        BotShieldScore  calsig +60\n"
        "    </BotShieldRule>\n"
        "    BotShieldChallengeAtLeast calsig 20 noninteractive\n"
        "    BotShieldChallengeAtLeast calsig 50 interactive\n"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        with log_slice as slc:
            _get(fresh_ip)
        tiers = [d.get("tier") for d in slc.decision_lines(ip=fresh_ip)]
        assert "interactive" in tiers, (
            f"60 crosses both rows; the higher tier should win, got {tiers}"
        )


def test_a_nested_row_lifts_an_inherited_none(config_override, fresh_ip,
                                              log_slice):
    """'none' is inherited, and declaring a row is what lifts it.

    Off has to inherit or a vhost cannot silence everything under it in
    one line. It also has to be liftable, or a <Location> can never say
    "not the vhost's rows, mine" -- an off switch with no way back on.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule cal-nest>\n"
        "        BotShieldPath   /cal-nested\n"
        "        BotShieldScore  calsig +25\n"
        "    </BotShieldRule>\n"
        "    <Location /cal-nested>\n"
        "        BotShieldChallengeAtLeast calsig 20 noninteractive\n"
        "    </Location>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        with log_slice as slc:
            _get(fresh_ip, path="/cal-nested")
        assert _challenged(slc, fresh_ip), (
            "a row declared in a nested scope should lift the "
            "inherited none; "
            f"lines={slc.decision_lines(ip=fresh_ip)}"
        )


def test_none_still_inherits_where_nothing_is_declared(
    config_override, fresh_ip, log_slice,
):
    """The control for the test above, and the property it must not
    cost: a scope that declares no row of its own stays silenced."""
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule cal-nest>\n"
        "        BotShieldPath   /cal-nested\n"
        "        BotShieldScore  calsig +25\n"
        "    </BotShieldRule>\n"
        "    BotShieldChallengeAtLeast calsig 20 noninteractive\n"
        "    <Location /cal-nested>\n"
        "        BotShieldNonInteractiveMode interstitial\n"
        "    </Location>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        with log_slice as slc:
            _get(fresh_ip, path="/cal-nested")
        assert not _challenged(slc, fresh_ip), (
            "the Location declares no row, so the vhost's none should "
            "still reach it; "
            f"lines={slc.decision_lines(ip=fresh_ip)}"
        )
