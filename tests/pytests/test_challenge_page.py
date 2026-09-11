"""<BotShieldChallengePage> — how the interstitial looks.

These nine settings were flat directives until 2026-09-11 and had no
config-level coverage at all: nothing in the suite set a prompt, a
logo or a help mode, so the setters, their defaults and their merge
had never run under test. The block is the occasion to fix that.

The page is not the captcha tier's. bs_render_challenge_page draws
every tier and the captcha widget is one branch inside it, so these
tests force the interactive tier — the cheapest way to get an
interstitial — and what they assert holds for all three.
"""

from __future__ import annotations

import re

import pytest

from botshield_test import apache, client


PROBE = "/challenge-page-probe"
OTHER = "/challenge-page-other"

MARK_PROMPT = "Prove you are not a machine"
MARK_LABEL = "Example University Library"

# The rendered help element. The stylesheet carries .bs-help rules
# whatever the mode, so the class name alone proves nothing -- the
# id only appears on the element itself.
HELP_EL = 'id="bs-help"'


def _conf(page_body: str, path: str = PROBE, extra: str = "") -> str:
    """A scope that renders an interstitial on `path` and nothing else,
    so a body assertion is about the page and not about scoring."""
    return (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldChallengePage>\n"
        f"{page_body}"
        "    </BotShieldChallengePage>\n"
        "    <BotShieldRule page-probe>\n"
        f"        BotShieldPath      {path}\n"
        "        BotShieldChallenge interactive\n"
        "    </BotShieldRule>\n"
        + extra
    )


# --- the settings reach the page -------------------------------------


def test_the_block_sets_the_prompt(config_override, fresh_ip):
    conf = _conf(f'        BotShieldPrompt "{MARK_PROMPT}"\n')
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        body = client.get(PROBE, xff=fresh_ip).text
    assert MARK_PROMPT in body, (
        f"BotShieldPrompt did not reach the page; body={body[:600]}"
    )
    assert "I'm not a robot" not in body, (
        "the default prompt is still there, so the setting was parsed "
        "but not applied"
    )


def test_the_block_sets_the_logo_label(config_override, fresh_ip):
    conf = _conf(f'        BotShieldLogoLabel "{MARK_LABEL}"\n')
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        body = client.get(PROBE, xff=fresh_ip).text
    assert MARK_LABEL in body, f"body={body[:600]}"


def test_show_logo_off_removes_the_brand_column(config_override,
                                                fresh_ip):
    """Asserted through a label of our own rather than the default
    "botshield", which appears in class names and endpoint paths all
    over the page and would make the absence assertion meaningless."""
    conf = _conf(
        f'        BotShieldLogoLabel "{MARK_LABEL}"\n'
        "        BotShieldShowLogo  Off\n"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        body = client.get(PROBE, xff=fresh_ip).text
    assert MARK_LABEL not in body, (
        "BotShieldShowLogo Off should take the caption with the "
        f"column; body={body[:600]}"
    )


def test_help_off_drops_the_help_panel(config_override, fresh_ip):
    with config_override(
        r"BotShieldEnabled\s+On",
        _conf("        BotShieldHelp Off\n"), count=1,
    ):
        off = client.get(PROBE, xff=fresh_ip).text
    with config_override(
        r"BotShieldEnabled\s+On",
        _conf("        BotShieldHelp On\n"), count=1,
    ):
        on = client.get(PROBE, xff=fresh_ip).text
    assert HELP_EL in on, f"help on rendered no panel; body={on[:600]}"
    assert HELP_EL not in off, (
        f"help off still rendered the panel; body={off[:600]}"
    )


# --- scope ------------------------------------------------------------


def test_a_location_can_dress_its_own_page(config_override, fresh_ip):
    """Per-directory like <BotShieldCaptcha>, so one path can look
    different from the rest of the vhost."""
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule page-probe>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldChallenge interactive\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule page-other>\n"
        f"        BotShieldPath      {OTHER}\n"
        "        BotShieldChallenge interactive\n"
        "    </BotShieldRule>\n"
        f"    <Location {PROBE}>\n"
        "        <BotShieldChallengePage>\n"
        f'            BotShieldPrompt "{MARK_PROMPT}"\n'
        "        </BotShieldChallengePage>\n"
        "    </Location>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        inside = client.get(PROBE, xff=fresh_ip).text
        outside = client.get(OTHER, xff=fresh_ip).text
    assert MARK_PROMPT in inside, f"body={inside[:600]}"
    assert MARK_PROMPT not in outside, (
        "a Location's page block leaked to a path outside it; "
        f"body={outside[:600]}"
    )


# --- refusals ---------------------------------------------------------


@pytest.mark.parametrize("body, why", [
    ('        BotShieldPromptText "x"\n', "the retired flat spelling"),
    ('        BotShieldChallengeFile /tmp/x.html\n', "the old file name"),
    ('        BotShieldNonsense on\n', "not a page setting"),
    ('        BotShieldShowBox Maybe\n', "a flag that is neither On nor Off"),
    ('        BotShieldHelp On\n        BotShieldHelp Off\n',
     "the same setting twice"),
])
def test_the_block_refuses_bad_settings(config_override, body, why):
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On", _conf(body), count=1):
            pass


def test_the_block_takes_no_argument(config_override):
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldChallengePage dark>\n"
        '        BotShieldPrompt "x"\n'
        "    </BotShieldChallengePage>\n"
    )
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            pass


def test_one_block_per_scope(config_override):
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldChallengePage>\n"
        '        BotShieldPrompt "one"\n'
        "    </BotShieldChallengePage>\n"
        "    <BotShieldChallengePage>\n"
        '        BotShieldPrompt "two"\n'
        "    </BotShieldChallengePage>\n"
    )
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            pass


# --- the flat spellings say where they went --------------------------


@pytest.mark.parametrize("line, expect", [
    ('BotShieldPromptText "x"',        "BotShieldPrompt"),
    ("BotShieldChallengeFile /tmp/x",  "BotShieldTemplate"),
    ("BotShieldShowLogo On",           "BotShieldShowLogo"),
    ("BotShieldHelpFile /tmp/x",       "BotShieldHelpFile"),
])
def test_a_flat_spelling_names_its_new_home(line, expect):
    """Registered rather than dropped, so the failure is a migration
    sentence instead of Apache's "Invalid command", which reads like a
    typo or a missing LoadModule.

    configtest rather than config_override: a failed reload raises a
    CalledProcessError carrying no httpd stderr, so the message -- the
    whole point of the stub -- would be invisible to the assertion.
    """
    rc, err = apache.configtest(line)
    assert rc != 0, f"{line!r} was accepted after the move"
    assert "BotShieldChallengePage" in err, err[-500:]
    assert expect in err, err[-500:]



def _label(body: str) -> str:
    """The widget's rendered label text.

    Whole-body matching is wrong here: the challenge JS carries its own
    hardcoded 'Verifying you are human\\u2026' for the interactive
    tier's post-click moment, which is a different string doing a
    different job. Only the span (or the aria-label that replaces it
    when BotShieldShowLabel is off) is the directive's output.
    """
    m = re.search(r'<span class="bs-label">(.*?)</span>', body, re.S)
    if m:
        return m.group(1)
    m = re.search(r'aria-label="([^"]*)"', body)
    return m.group(1) if m else ""


# --- BotShieldPrompt vs BotShieldNotice ------------------------------

# Substrings of the two built-ins, chosen to avoid the curly ellipsis
# and apostrophe the defaults actually carry.
DEFAULT_NOTICE = "Verifying you are human"
DEFAULT_PROMPT = "not a robot"
MARK_NOTICE = "Checking your browser now"


def _tier_conf(page_body: str, tier: str) -> str:
    """Force one tier on the probe path so the assertion is about the
    string that tier picks, not about scoring."""
    return (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldChallengePage>\n"
        f"{page_body}"
        "    </BotShieldChallengePage>\n"
        "    <BotShieldRule page-probe>\n"
        f"        BotShieldPath      {PROBE}\n"
        f"        BotShieldChallenge {tier}\n"
        "    </BotShieldRule>\n"
    )


def test_the_two_tiers_differ_by_default(config_override, fresh_ip):
    """The module already split these before either directive existed:
    a status where there is nothing to click, an invitation where there
    is. This is the behaviour the two names protect."""
    with config_override(r"BotShieldEnabled\s+On",
                         _tier_conf("", "noninteractive"), count=1):
        silent = client.get(PROBE, xff=fresh_ip).text
    with config_override(r"BotShieldEnabled\s+On",
                         _tier_conf("", "interactive"), count=1):
        clickable = client.get(PROBE, xff=fresh_ip).text
    assert DEFAULT_NOTICE in _label(silent), f"label={_label(silent)!r}"
    assert DEFAULT_PROMPT in _label(clickable), f"label={_label(clickable)!r}"


def test_notice_reaches_the_silent_tier(config_override, fresh_ip):
    body_cfg = f'        BotShieldNotice "{MARK_NOTICE}"\n'
    with config_override(r"BotShieldEnabled\s+On",
                         _tier_conf(body_cfg, "noninteractive"), count=1):
        body = client.get(PROBE, xff=fresh_ip).text
    assert MARK_NOTICE in _label(body), f"label={_label(body)!r}"
    assert DEFAULT_NOTICE not in _label(body), (
        "the built-in notice is still the label"
    )


def test_prompt_no_longer_overrides_the_silent_tier(config_override,
                                                    fresh_ip):
    """The regression this pair exists to fix.

    Before 2026-09-11 a single BotShieldPrompt won on every tier, so
    setting the invitation replaced the status too and the self-solving
    page asked a question it gave the client no way to answer.
    """
    body_cfg = f'        BotShieldPrompt "{MARK_PROMPT}"\n'
    with config_override(r"BotShieldEnabled\s+On",
                         _tier_conf(body_cfg, "noninteractive"), count=1):
        body = client.get(PROBE, xff=fresh_ip).text
    assert MARK_PROMPT not in _label(body), (
        "BotShieldPrompt leaked onto the tier with nothing to click; "
        f"label={_label(body)!r}"
    )
    assert DEFAULT_NOTICE in _label(body), (
        "the silent tier should have fallen back to its own built-in; "
        f"label={_label(body)!r}"
    )


def test_notice_does_not_reach_the_clickable_tier(config_override,
                                                  fresh_ip):
    """The other direction, so neither name quietly covers both."""
    body_cfg = f'        BotShieldNotice "{MARK_NOTICE}"\n'
    with config_override(r"BotShieldEnabled\s+On",
                         _tier_conf(body_cfg, "interactive"), count=1):
        body = client.get(PROBE, xff=fresh_ip).text
    assert MARK_NOTICE not in _label(body), f"label={_label(body)!r}"
    assert DEFAULT_PROMPT in _label(body), f"label={_label(body)!r}"


def test_both_set_at_once(config_override, fresh_ip):
    body_cfg = (f'        BotShieldPrompt "{MARK_PROMPT}"\n'
                f'        BotShieldNotice "{MARK_NOTICE}"\n')
    with config_override(r"BotShieldEnabled\s+On",
                         _tier_conf(body_cfg, "noninteractive"), count=1):
        silent = client.get(PROBE, xff=fresh_ip).text
    with config_override(r"BotShieldEnabled\s+On",
                         _tier_conf(body_cfg, "interactive"), count=1):
        clickable = client.get(PROBE, xff=fresh_ip).text
    assert MARK_NOTICE in _label(silent) and \
           MARK_PROMPT not in _label(silent), (
        f"label={_label(silent)!r}"
    )
    assert MARK_PROMPT in _label(clickable) and \
           MARK_NOTICE not in _label(clickable), (
        f"label={_label(clickable)!r}"
    )


def test_notice_needs_text(config_override):
    with pytest.raises(Exception):
        with config_override(r"BotShieldEnabled\s+On",
                             _conf('        BotShieldNotice\n'), count=1):
            pass
