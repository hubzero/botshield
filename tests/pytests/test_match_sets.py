"""<BotShieldMatch> — name a set of conditions, use it in several rules.

The case this exists for is in the production config: `crawler-pass` and
`content-gate` carry the same eighteen BotShieldPath lines, verbatim.
They are a matched pair — one exempts declared crawlers from the gate,
the other gates everyone else — and nothing in the config says so. Edit
one list and forget the other and verified crawlers start being
challenged on the diverged path.

Expansion is textual and happens at parse time, so a rule naming a set
is exactly the rule someone would have typed by hand. That is why these
tests assert on behaviour rather than on parsing: if expansion produced
anything other than the hand-written block, the rules would stop
matching.
"""

from __future__ import annotations

import pytest

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"

SHARED = (
    "BotShieldEnabled On\n"
    "    <BotShieldMatch gated>\n"
    "        BotShieldPath  /set-alpha\n"
    "        BotShieldPath  /set-beta\n"
    "    </BotShieldMatch>\n"
    "    <BotShieldRule set-rule>\n"
    "        BotShieldMatches  gated\n"
    "        BotShieldRespond  403\n"
    "        BotShieldLogAs    set-rule\n"
    "    </BotShieldRule>\n"
)

NESTED = (
    "BotShieldEnabled On\n"
    "    <BotShieldMatch inner>\n"
    "        BotShieldPath  /set-alpha\n"
    "    </BotShieldMatch>\n"
    "    <BotShieldMatch outer>\n"
    "        BotShieldMatches  inner\n"
    "        BotShieldPath     /set-beta\n"
    "    </BotShieldMatch>\n"
    "    <BotShieldRule set-rule>\n"
    "        BotShieldMatches  outer\n"
    "        BotShieldRespond  403\n"
    "        BotShieldLogAs    set-rule\n"
    "    </BotShieldRule>\n"
)


def _get(path, ip):
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG)


def _refused(config_override, conf, ip, path):
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        return _get(path, ip).status_code


def test_a_named_set_supplies_every_condition_in_it(config_override,
                                                    fresh_ip):
    """Both paths in the set reach the rule that names it."""
    with config_override(r"BotShieldEnabled\s+On", SHARED,
                         render=False, count=1):
        for path in ("/set-alpha", "/set-beta"):
            assert _get(path, fresh_ip).status_code == 403, (
                f"{path} is in the set, so the rule should refuse it"
            )


def test_paths_outside_the_set_are_untouched(config_override, fresh_ip):
    """The control: expansion must not widen the rule."""
    with config_override(r"BotShieldEnabled\s+On", SHARED,
                         render=False, count=1):
        assert _get("/set-gamma", fresh_ip).status_code != 403, (
            "a path the set does not list must not match"
        )


def test_two_rules_can_share_one_set(config_override, fresh_ip):
    """The production case: a gate and its crawler carve-out.

    Both rules name one set, so the two cannot drift apart -- which is
    the whole reason to have this.
    """
    pair = (
        "BotShieldEnabled On\n"
        "    <BotShieldMatch gated>\n"
        "        BotShieldPath  /set-alpha\n"
        "        BotShieldPath  /set-beta\n"
        "    </BotShieldMatch>\n"
        "    <BotShieldRule pass-crawlers>\n"
        "        BotShieldMatches  gated\n"
        "        BotShieldCrawler  yes\n"
        "        BotShieldNoChallenge\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule gate-everyone>\n"
        "        BotShieldMatches  gated\n"
        "        BotShieldRespond  403\n"
        "        BotShieldLogAs    gate-everyone\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", pair,
                         render=False, count=1):
        # Not a declared crawler, so the second rule refuses -- proving
        # the set reached both rules rather than only the first.
        assert _get("/set-beta", fresh_ip).status_code == 403


def test_a_set_can_name_a_set_defined_above_it(config_override, fresh_ip):
    """Nesting works because expansion is in definition order.

    A cycle cannot be built for the same reason: a name that is not yet
    defined does not resolve.
    """
    with config_override(r"BotShieldEnabled\s+On", NESTED,
                         render=False, count=1):
        for path in ("/set-alpha", "/set-beta"):
            assert _get(path, fresh_ip).status_code == 403, (
                f"{path} should arrive through the nested set"
            )


def test_an_undefined_set_is_refused_at_config_time(config_override):
    """A typo must not silently produce a rule matching nothing."""
    with pytest.raises(Exception) as exc:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldRule r>\n"
            "        BotShieldMatches  nosuchset\n"
            "        BotShieldRespond  403\n"
            "    </BotShieldRule>\n",
            render=False, count=1,
        ):
            pass
    assert "non-zero exit status" in str(exc.value)


def test_a_set_refuses_an_action(config_override):
    """Conditions only: a set names what it matches, not what happens."""
    with pytest.raises(Exception) as exc:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldMatch s>\n"
            "        BotShieldPath     /set-alpha\n"
            "        BotShieldRespond  403\n"
            "    </BotShieldMatch>\n",
            render=False, count=1,
        ):
            pass
    assert "non-zero exit status" in str(exc.value)


def test_a_set_defined_twice_is_refused(config_override):
    """Last-one-wins is how a shared set quietly stops being shared."""
    with pytest.raises(Exception) as exc:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldMatch s>\n"
            "        BotShieldPath /set-alpha\n"
            "    </BotShieldMatch>\n"
            "    <BotShieldMatch s>\n"
            "        BotShieldPath /set-beta\n"
            "    </BotShieldMatch>\n",
            render=False, count=1,
        ):
            pass
    assert "non-zero exit status" in str(exc.value)
