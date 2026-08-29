"""Multi-tier bot rate limiting: scope=each | group | total.

A per-slug budget cannot see aggregate volume. With ~700 directory
slugs at 1 req/sec, a thousand individually compliant bots add up to a
thousand requests a second and no counter ever trips. These tiers close
that, and the tests below are written to fail if a tier silently
degrades into per-slug behaviour -- which is why every aggregate case
drives *different* bots rather than repeating one.

Status codes are part of the contract, not an implementation detail:

  slug trip   429  the client exceeded its own quota
  group trip  503  the client behaved; the site is out of what it gives
  total trip  503  same, at the ceiling

A 429 for a group or total trip would blame a well-behaved crawler for
a capacity decision, and search engines treat the two differently.
"""

from __future__ import annotations

import subprocess

import pytest

from botshield_test import client, config


# Three ai-train slugs with distinct UA patterns. Distinct slugs is the
# whole point: if the group counter were per-slug these would never
# interfere with each other and the test would pass for the wrong
# reason.
AI_TRAIN_UAS = [
    "netEstate NE Crawler (+http://www.netestate.de/)",
    "Seamus the Search Engine",
    "CloudflareBrowserRenderingCrawler/1.0",
]

# Unrelated bots spanning different botgroups, for the total ceiling.
MIXED_BOT_UAS = [
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
    "netEstate NE Crawler (+http://www.netestate.de/)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
]

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)


def test_group_scope_aggregates_across_distinct_bots(
    config_override, log_slice, fresh_ip,
):
    """One shared counter for a whole botgroup.

    Per-slug budget is set generously (100/sec) so that any refusal
    here can only have come from the group counter. Three different
    ai-train bots consume the group's budget of 3; the next request
    from any of them is refused even though that bot has spent 1 of
    its own 100.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 100 sec\n'
        '    BotShieldBotRateLimit @ai-train 3 sec scope=group',
        count=1,
    ):
        with log_slice as slc:
            got = [
                client.get("/", xff=fresh_ip, ua=ua)
                for ua in AI_TRAIN_UAS + AI_TRAIN_UAS[:1]
            ]
            lines = slc.decision_lines(ip=fresh_ip)

    admitted = [r.status_code for r in got[:3]]
    assert all(s != 503 for s in admitted), (
        f"first three (one per bot) must fit the group budget of 3; "
        f"got {admitted}"
    )
    assert got[3].status_code == 503, (
        f"4th request must exhaust the ai-train group budget with 503, "
        f"got {got[3].status_code}. A 429 here would mean the slug tier "
        f"refused it, i.e. the group counter is not shared."
    )
    assert got[3].headers.get("Retry-After"), (
        "a group trip must carry Retry-After"
    )
    assert any("bot-rate:@ai-train" in d["reason"] for d in lines), (
        f"the refusal must name the group, not a slug -- an operator "
        f"reading a slug name would go tune the wrong budget; "
        f"lines={lines}"
    )


def test_group_trip_does_not_penalise_the_client(
    config_override, log_slice, fresh_ip,
):
    """A bot refused at the group ceiling did nothing wrong.

    The score penalty is the client's record of misbehaviour. Charging
    it for being present during someone else's spike would accumulate
    score toward a challenge it never earned.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 100 sec\n'
        '    BotShieldBotRateLimit @ai-train 1 sec scope=group',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=fresh_ip, ua=AI_TRAIN_UAS[0])
            r2 = client.get("/", xff=fresh_ip, ua=AI_TRAIN_UAS[1])
            lines = slc.decision_lines(ip=fresh_ip)

    assert r2.status_code == 503
    tripped = [d for d in lines if "bot-rate:@ai-train" in d["reason"]]
    assert tripped, f"no group trip logged; lines={lines}"
    assert all(int(d["score"]) == 0 for d in tripped), (
        f"a group trip must not add score; got "
        f"{[d['score'] for d in tripped]}"
    )


def test_total_scope_is_a_ceiling_over_every_bot(
    config_override, log_slice, fresh_ip,
):
    """The circuit breaker: unrelated bots in unrelated groups share it."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 100 sec\n'
        '    BotShieldBotRateLimit * 3 sec scope=total',
        count=1,
    ):
        with log_slice as slc:
            got = [
                client.get("/", xff=fresh_ip, ua=ua)
                for ua in MIXED_BOT_UAS
            ]
            lines = slc.decision_lines(ip=fresh_ip)

    assert got[3].status_code == 503, (
        f"the 4th bot must hit the total ceiling of 3 even though it "
        f"is a different bot in a different group; got "
        f"{[r.status_code for r in got]}"
    )
    assert any("bot-rate:*" in d["reason"] for d in lines), (
        f"the refusal must name the total ceiling; lines={lines}"
    )


def test_total_ceiling_does_not_apply_to_browsers(
    config_override, fresh_ip,
):
    """It is a *bot* ceiling. Real users are shed by load, not by this."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 1 sec scope=total',
        count=1,
    ):
        codes = [
            client.get("/", xff=fresh_ip, ua=BROWSER_UA).status_code
            for _ in range(4)
        ]
    assert all(c != 503 for c in codes), (
        f"browsers must never be refused by a bot ceiling; got {codes}"
    )


def test_slug_tier_still_returns_429_alongside_the_new_tiers(
    config_override, log_slice, fresh_ip,
):
    """Adding tiers must not change what a per-slug trip looks like."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 1 sec\n'
        '    BotShieldBotRateLimit * 10000 sec scope=total',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=fresh_ip, ua=AI_TRAIN_UAS[0])
            r2 = client.get("/", xff=fresh_ip, ua=AI_TRAIN_UAS[0])
            lines = slc.decision_lines(ip=fresh_ip)

    assert r2.status_code == 429, (
        f"a slug trip is the client's own fault and stays 429; got "
        f"{r2.status_code}"
    )
    assert any("bot-rate:datenbank" in d["reason"] for d in lines), (
        f"slug trips still name the slug; lines={lines}"
    )


def _configtest(directive: str) -> tuple[int, str]:
    """Run configtest against THIS worker's instance with one extra
    directive. Deliberately not the production config: that loads the
    deployed module, so a check for a directive the working tree just
    added would silently assert against the old build.
    """
    result = subprocess.run(
        ["sudo", "httpd", "-f", config.HTTPD_CONF, "-C", directive, "-t"],
        capture_output=True, text=True, check=False,
    )
    return result.returncode, result.stderr


@pytest.mark.parametrize(
    "rule,expect",
    [
        ("@ai-train 3 sec scope=total", "requires the '*' selector"),
        ("* 5 sec scope=group", "requires an @botgroup selector"),
        ("googlebot 5 sec scope=group", "requires an @botgroup selector"),
        ("@ai-train 3 sec scope=bogus", "must be each, group or total"),
    ],
)
def test_scope_and_selector_must_agree(rule, expect):
    """A shared budget over a population of one is scope=each in a
    costume. Accepting it would leave an operator one typo away from
    believing a group cap exists when it does not, which is exactly the
    silent-misconfiguration class this project keeps getting bitten by.
    """
    rc, err = _configtest("BotShieldBotRateLimit " + rule)
    assert rc != 0, f"configtest accepted 'BotShieldBotRateLimit {rule}'"
    assert expect in err, f"expected {expect!r} in configtest output: {err}"


def test_scope_and_selector_agreeing_is_accepted():
    """Guard against the validation above false-rejecting valid rules."""
    for rule in ("@ai-train 3 sec scope=group", "* 300 sec scope=total",
                 "googlebot 2 min"):
        rc, err = _configtest("BotShieldBotRateLimit " + rule)
        assert rc == 0, f"valid rule {rule!r} rejected: {err[-400:]}"
