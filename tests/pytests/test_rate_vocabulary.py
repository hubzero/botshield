"""per=<n>unit and countper=slug -- the two things robots.txt could say
and the rule vocabulary could not.

`Crawl-delay: 10` is one request per ten seconds. per= took sec, min
and hour and nothing between them, so that window had no spelling even
though window_sec has always been an int.

`Crawl-delay` also gives *each* crawler the budget. countper=total
gives all of them one between them, which looks the same in the config
and is drastically different in effect -- with @bot and 1/sec, total
means the whole crawler population shares one request a second.
"""

from __future__ import annotations

import pytest

from botshield_test import apache, client, ratelimit

# Two UAs the classifier gives distinct known slugs, and neither needs
# IP verification to land in @bot -- a spoofed Googlebot from a test
# address classifies FAKE_BOT and would not match @bot at all.
UA_A = "curl/8.0.1"
UA_B = "Go-http-client/2.0"


def _rule(body: str, name: str = "vocab") -> str:
    return (
        "BotShieldEnabled On\n"
        f"    <BotShieldRule {name}>\n"
        f"{body}\n"
        "    </BotShieldRule>"
    )


# --- per=<n>unit ------------------------------------------------------


@pytest.mark.parametrize("spelling, shown", [
    ("10sec", "10sec"),
    ("30", "30sec"),        # bare number means seconds
    ("2min", "120sec"),
    ("sec", "sec"),         # the old spellings still work
    ("min", "min"),
    ("hour", "hour"),
])
def test_per_accepts_a_count(config_override, spelling, shown):
    conf = _rule(
        "        BotShieldPath   /per-probe\n"
        "        BotShieldBudget 5\n"
        f"        BotShieldPer    {spelling}",
        name="per-dump",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith("per-dump")]
    assert line, f"rule missing from dump; body={body[:400]}"
    assert f"budget=5/{shown}" in line[0], line[0]


@pytest.mark.parametrize("bad", ["0sec", "weeks", "10weeks", "0", "-5"])
def test_bad_windows_are_refused(config_override, bad):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  "        BotShieldBudget 5\n"
                  f"        BotShieldPer {bad}"),
            render=False, count=1,
        ):
            pass


def test_a_window_over_a_day_is_refused(config_override):
    """86400 is the ceiling. A window longer than the counter's own
    reset cadence is a budget nobody can reason about."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  "        BotShieldBudget 5\n"
                  "        BotShieldPer 25hour"),
            render=False, count=1,
        ):
            pass


# --- countper=slug ----------------------------------------------------


def test_each_crawler_gets_its_own_budget(config_override, fresh_ip):
    """The whole point of slug.

    Under countper=total these three requests share one bucket and the
    second UA is refused. Under slug each crawler has its own, so only
    a repeat from the *same* crawler is.
    """
    conf = _rule(
        "        BotShieldPath      /slug-probe\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldBudget    1\n"
        "        BotShieldPer       sec\n"
        "        BotShieldCountPer  slug",
        name="per-slug",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        ratelimit.align_to_window()
        first_a = client.get("/slug-probe", xff=fresh_ip, ua=UA_A)
        first_b = client.get("/slug-probe", xff=fresh_ip, ua=UA_B)
        again_a = client.get("/slug-probe", xff=fresh_ip, ua=UA_A)

    assert first_a.status_code != 429, (
        f"first request from crawler A was refused; got {first_a.status_code}"
    )
    assert first_b.status_code != 429, (
        f"crawler B was refused on its first request, so it is sharing "
        f"A's bucket -- that is countper=total behaviour; got "
        f"{first_b.status_code}"
    )
    assert again_a.status_code == 429, (
        f"crawler A repeated inside its own window and was admitted; got "
        f"{again_a.status_code}"
    )


def test_total_makes_them_share(config_override, fresh_ip):
    """The contrast, so the test above is not passing by accident."""
    conf = _rule(
        "        BotShieldPath      /total-probe\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldBudget    1\n"
        "        BotShieldPer       sec\n"
        "        BotShieldCountPer  total",
        name="per-total",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        ratelimit.align_to_window()
        client.get("/total-probe", xff=fresh_ip, ua=UA_A)
        second = client.get("/total-probe", xff=fresh_ip, ua=UA_B)

    assert second.status_code == 429, (
        f"a different crawler was admitted under countper=total, so the "
        f"bucket is not shared; got {second.status_code}"
    )


def test_countper_slug_shows_in_the_dump(config_override):
    conf = _rule(
        "        BotShieldPath      /slug-dump\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldBudget    1\n"
        "        BotShieldPer       10sec\n"
        "        BotShieldCountPer  slug",
        name="slug-dumped",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith("slug-dumped")]
    assert line, f"rule missing from dump; body={body[:400]}"
    assert "budget=1/10sec" in line[0], line[0]
    assert "countper=slug" in line[0], line[0]
