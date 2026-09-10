"""Refusals leave a mark the next request can read.

Four paths refuse a request from inside bs_check_policy and return
where they stand: robots.txt Disallow, the rate-limit cohorts, their
E9 escalation, and the slug-keyed bot limits. Nothing downstream runs
after them, and the rule walk runs *before* all four -- so until these
bits existed, a client refused a hundred times in a row was still a
stranger to every rule on request 101.

The score bump each site carries is not that memory and has not been
since B5: the total is computed, logged, and mapped to nothing. What
the score used to buy across requests is what these flags buy now.

They carry no built-in effect. Nothing seeds a flag trigger for them,
so writing one changes no decision until an operator asks for it --
the module keeps the memory, the operator keeps the policy. Every test
here therefore supplies its own rule to observe the flag at all, which
is the intended shape rather than an inconvenience.
"""

from __future__ import annotations

import os
import textwrap
import uuid

import pytest

from botshield_test import client


PROBE = "/enforcement-flag-probe"
LIMITED = "/enforcement-flag-limited"
GPTBOT_UA = ("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); "
             "compatible; GPTBot/1.0; +https://openai.com/gptbot")
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")
TEST_ROBOTS_DIR = "/etc/botshield/test-robots"


@pytest.fixture
def robots_path():
    p = f"{TEST_ROBOTS_DIR}/robots-{uuid.uuid4().hex}.txt"
    yield p
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass


def _write_robots(path: str, body: str) -> str:
    with open(path, "w") as f:
        f.write(textwrap.dedent(body).lstrip() + "\n")
    os.chmod(path, 0o644)
    return path


def _reader(flag: str) -> str:
    """A rule that does nothing but make `flag` visible as a 451.

    Declared for PROBE only, and PROBE is outside every cohort and
    Disallow below, so reaching it does not itself write the flag it
    reports.
    """
    return (
        "    <BotShieldRule read-flag>\n"
        f"        BotShieldPath      {PROBE}\n"
        f"        BotShieldFlagged   {flag}\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>\n"
    )


def _conf(body: str) -> str:
    return "BotShieldEnabled On\n    BotShieldChallengeAtLeast none\n" + body


def _flagged(fresh_ip, flag: str) -> bool:
    return client.get(PROBE, xff=fresh_ip,
                      ua=BROWSER_UA).status_code == 451


# --- rate-limit cohorts ---------------------------------------------


def test_a_cohort_429_flags_the_address(config_override, fresh_ip):
    """The regression this file exists for.

    The cohort keys on UA, so the probe -- sent as a browser -- is
    never in it. What carries between the two requests is the flag on
    the address, which is the only thing that can: the rule walk runs
    before the rate limiter, so on the probe request the limiter has
    not spoken yet.
    """
    conf = _conf(
        '    <BotShieldRule rl>\n'
        '        BotShieldUserAgent RateBot\n'
        '        BotShieldRate      1 60\n'
        '    </BotShieldRule>\n'
        + _reader("rate_abuse")
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        before = _flagged(fresh_ip, "rate_abuse")
        first = client.get(LIMITED, xff=fresh_ip, ua="RateBot/1.0")
        second = client.get(LIMITED, xff=fresh_ip, ua="RateBot/1.0")
        after = _flagged(fresh_ip, "rate_abuse")
    assert not before, "nothing has been refused yet"
    assert first.status_code != 429, "the first request is under budget"
    assert second.status_code == 429, "the second is over it"
    assert after, "a 429 must leave the address flagged"


def test_staying_under_budget_flags_nothing(config_override, fresh_ip):
    """The control. Being in a rate-limited cohort is not the event;
    exceeding the budget is."""
    conf = _conf(
        '    <BotShieldRule rl>\n'
        '        BotShieldUserAgent RateBot\n'
        '        BotShieldRate      5 60\n'
        '    </BotShieldRule>\n'
        + _reader("rate_abuse")
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        r = client.get(LIMITED, xff=fresh_ip, ua="RateBot/1.0")
        after = _flagged(fresh_ip, "rate_abuse")
    assert r.status_code != 429
    assert not after, "an under-budget request must not flag"


def test_observe_mode_does_not_flag(config_override, fresh_ip):
    """Observe must not enforce, and a flag is enforcement deferred.

    A bit written under observe would follow the client into later
    requests and change what rules match -- which is the whole point
    of the bit, and exactly what an operator asking what a rule would
    fire has said they do not want yet.
    """
    conf = _conf(
        '    <BotShieldRule rl>\n'
        '        BotShieldUserAgent RateBot\n'
        '        BotShieldRate      1 60\n'
        '        BotShieldMode      observe\n'
        '    </BotShieldRule>\n'
        + _reader("rate_abuse")
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        client.get(LIMITED, xff=fresh_ip, ua="RateBot/1.0")
        second = client.get(LIMITED, xff=fresh_ip, ua="RateBot/1.0")
        after = _flagged(fresh_ip, "rate_abuse")
    assert second.status_code != 429, "observe must not refuse"
    assert not after, "observe must not flag either"


# --- robots.txt ------------------------------------------------------


def test_a_robots_block_flags_the_address(
    robots_path, config_override, fresh_ip,
):
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /admin
    """)
    conf = _conf(
        "    <BotShieldRobots>\n"
        f"        BotShieldRobotsTxt {robots_path}\n"
        "    </BotShieldRobots>\n"
        + _reader("robots_ignored")
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        before = _flagged(fresh_ip, "robots_ignored")
        blocked = client.get("/admin", xff=fresh_ip, ua=GPTBOT_UA)
        after = _flagged(fresh_ip, "robots_ignored")
    assert not before
    assert blocked.status_code == 403
    assert after, "a robots 403 must leave the address flagged"


def test_robots_observe_does_not_flag(
    robots_path, config_override, fresh_ip,
):
    """BotShieldMode observe on <BotShieldRobots> exists so an operator can find out
    who ignores a robots.txt they have published but never enforced.
    A flag written under it would be the enforcement they deferred."""
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /admin
    """)
    conf = _conf(
        "    <BotShieldRobots>\n"
        f"        BotShieldRobotsTxt {robots_path}\n"
        "        BotShieldMode      observe\n"
        "    </BotShieldRobots>\n"
        + _reader("robots_ignored")
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        blocked = client.get("/admin", xff=fresh_ip, ua=GPTBOT_UA)
        after = _flagged(fresh_ip, "robots_ignored")
    assert blocked.status_code != 403, "observe must not refuse"
    assert not after, "observe must not flag either"


def test_an_allowed_path_flags_nothing(
    robots_path, config_override, fresh_ip,
):
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /admin
    """)
    conf = _conf(
        "    <BotShieldRobots>\n"
        f"        BotShieldRobotsTxt {robots_path}\n"
        "    </BotShieldRobots>\n"
        + _reader("robots_ignored")
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        ok = client.get("/public", xff=fresh_ip, ua=GPTBOT_UA)
        after = _flagged(fresh_ip, "robots_ignored")
    assert ok.status_code != 403
    assert not after


# --- the two are not the same accusation -----------------------------


def test_a_rate_trip_does_not_set_the_robots_bit(
    config_override, fresh_ip,
):
    """Separate bits, separately written. Conflating them would tell
    an operator watching for robots violations that every client who
    ever exceeded a budget had ignored their robots.txt."""
    conf = _conf(
        '    <BotShieldRule rl>\n'
        '        BotShieldUserAgent RateBot\n'
        '        BotShieldRate      1 60\n'
        '    </BotShieldRule>\n'
        + _reader("robots_ignored")
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        client.get(LIMITED, xff=fresh_ip, ua="RateBot/1.0")
        second = client.get(LIMITED, xff=fresh_ip, ua="RateBot/1.0")
        after = _flagged(fresh_ip, "robots_ignored")
    assert second.status_code == 429
    assert not after, "a rate trip is not a robots violation"


# --- config surface --------------------------------------------------


@pytest.mark.parametrize("flag", ["rate_abuse", "robots_ignored"])
def test_the_new_flags_are_nameable(config_override, flag):
    """Both spellings parse wherever a flag name is taken."""
    conf = _conf(
        "    <BotShieldRule r>\n"
        f"        BotShieldPath      {PROBE}\n"
        f"        BotShieldFlagged   {flag}\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>\n"
        f"    <BotShieldRule score-{flag.replace(chr(95), chr(45))}>\n"
        f"        BotShieldFlagged   {flag}\n"
        "        BotShieldScore     botsignals +10\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        pass


def test_an_unknown_flag_lists_the_known_ones(config_override):
    """The two hand-written lists this message replaced had both
    stopped naming `blocked`. Built from the registry now, so a new
    bit cannot be added without the message learning it."""
    conf = _conf(
        "    <BotShieldRule r>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldFlagged   rate-abuse\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)
