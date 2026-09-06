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

# Parks the vhost's own ladder so only this accumulator can act.
PARK = (
    "    BotShieldScoreNonInteractive 9000\n"
    "    BotShieldScoreInteractive    9500\n"
    "    BotShieldScoreCaptcha        9900\n"
)

REACHES = (
    "BotShieldEnabled On\n"
    + PARK
    + "    <BotShieldRule cal-a>\n"
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
        + PARK
        + "    <BotShieldRule cal-a>\n"
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
