"""BotShieldBotRateLimit — slug-keyed bot rate limit.

Each test injects a directive via config_override + reload. Cohorts:

  specific:   `BotShieldBotRateLimit googlebot 2 min` resolves to the
              googlebot slug; first 2 requests pass, the 3rd hits 429.
  pattern:    `BotShieldBotRateLimit Google 5 min` resolves to all
              Google-family slugs (googlebot, google-other, ...) which
              SHARE one budget — sum across the family caps at 5/min.
  wildcard:   `BotShieldBotRateLimit * 1 min` pre-allocates one slot
              PER directory slug not covered by a specific rule. Each
              unmatched bot has its own counter capped at 1/min.
  unknown:    With wildcard configured, requests classified as
              unknownbot or fake-bot share aggregate slots (one each)
              capped at the wildcard budget.
  no-match:   Browser UAs and unclassified UAs are not rate-limited.
  bad args:   Validation errors at config time.
"""

from __future__ import annotations

import pytest

from botshield_test import apache, client


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GOOGLEOTHER_UA = "Mozilla/5.0 (compatible) AppleWebKit/537.36 (KHTML, like Gecko; compatible; GoogleOther/2.0)"
BINGBOT_UA = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"

# Real Googlebot range so the request is verified, not faked. This
# isolates the rate-limit behaviour from the fake-bot penalty path.
REAL_GOOGLEBOT_IP = "66.249.66.1"
# Bingbot must arrive from a real Bing range too. Sending BINGBOT_UA
# from an arbitrary fresh_ip makes it class=fake-bot -- a UA claiming a
# crawler whose IP fails the cross-check -- which is challenged, not
# rate-limited, so every assertion about bot-rate budgets failed on the
# challenge instead. The tests predate IP verification covering Bing.
REAL_BINGBOT_IP = "157.55.39.1"


def test_bot_rate_specific_slug_trips(config_override, log_slice, fresh_ip):
    """A rule against a specific slug fires after `budget` requests
    in the window. Use Googlebot from a real Googlebot IP so the
    request is verified-bot (otherwise the fake-bot penalty would
    push tier away from pass and complicate the assertion)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit googlebot 2 min',
        count=1,
    ):
        with log_slice as slc:
            r1 = client.get("/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA)
            r2 = client.get("/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA)
            r3 = client.get("/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA)
            lines = slc.decision_lines(ip=REAL_GOOGLEBOT_IP)

    # First two should be admitted (verified-bot credit drives them
    # to pass tier); third should be 429.
    assert r1.status_code == 200, f"req1 status={r1.status_code}"
    assert r2.status_code == 200, f"req2 status={r2.status_code}"
    assert r3.status_code == 429, (
        f"req3 expected 429, got {r3.status_code}; "
        f"Retry-After={r3.headers.get('Retry-After')!r}"
    )
    assert r3.headers.get("Retry-After"), (
        "429 must include Retry-After header"
    )
    # The reason names the DIRECTORY SLUG, not the string the operator
    # typed: "Googlebot/" resolves to slug "google" (see
    # generated_bot_directory.c), and the slug is the rate counter's
    # key. Reporting the key is what lets an operator find the counter
    # they need to tune -- test_bot_rate_tiers pins the same convention
    # for the per-slug and @botgroup cases.
    tripped = [d for d in lines if "botrate:google" in d["reason"]]
    assert tripped, (
        f"no decision line carried botrate:googlebot; lines={lines}"
    )


def test_bot_rate_pattern_shares_budget(
    config_override, log_slice, fresh_ip,
):
    """`BotShieldBotRateLimit Google 2 min` resolves to all Google-
    family slugs sharing ONE counter. Two requests across the family
    (Googlebot + GoogleOther) consume the budget; the third trips."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit Google 2 min',
        count=1,
    ):
        with log_slice as slc:
            r1 = client.get(
                "/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA,
            )
            r2 = client.get(
                "/", xff=fresh_ip, ua=GOOGLEOTHER_UA,
            )
            r3 = client.get(
                "/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA,
            )

    # Either of the first two might 200 or 200; third must be 429
    # because both google-family slugs feed the same counter.
    assert r3.status_code == 429, (
        f"req3 (Googlebot, after 2 family requests) expected 429, "
        f"got {r3.status_code}; r1={r1.status_code} r2={r2.status_code}"
    )


def test_bot_rate_wildcard_per_slug(config_override, fresh_ip):
    """`BotShieldBotRateLimit * 1 min` allocates one counter per
    directory slug NOT covered by a specific rule. So Bingbot and
    Googlebot each cap at 1/min INDEPENDENTLY — not shared."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 1 min',
        count=1,
    ):
        # First Bingbot request: admitted. Second: 429.
        b1 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
        b2 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
        # Googlebot's counter is independent — first request still admits.
        g1 = client.get(
            "/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA,
        )

    assert b1.status_code in (200, 302), f"b1 status={b1.status_code}"
    assert b2.status_code == 429, f"b2 expected 429, got {b2.status_code}"
    assert g1.status_code in (200, 302), (
        f"Googlebot first hit should be independent of Bingbot's counter; "
        f"got {g1.status_code}"
    )


def test_bot_rate_browser_unaffected(config_override, fresh_ip):
    """Browser-classified UAs bypass the bot rate limit entirely —
    even with a wildcard configured. The wildcard's `*` only catches
    classified-as-bot UAs (verified/known/unknown/fake bot), not
    browsers, unknownua, or emptyua."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 1 min',
        count=1,
    ):
        # 5 browser requests — none should hit 429 from bot-rate.
        for _ in range(5):
            resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
            assert resp.status_code != 429, (
                f"browser hit 429 unexpectedly; "
                f"reason={resp.headers.get('X-Botshield-Reason')!r}"
            )


def test_bot_rate_specific_overrides_wildcard(
    config_override, log_slice, fresh_ip,
):
    """When both a specific slug rule and a wildcard exist, the
    specific rule wins for that slug — the wildcard doesn't
    additionally constrain it."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit googlebot 5 min\n'
        '    BotShieldBotRateLimit * 1 min',
        count=1,
    ):
        with log_slice as slc:
            # Googlebot: 5/min budget → first 5 admit, 6th 429.
            results = [
                client.get(
                    "/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA,
                )
                for _ in range(6)
            ]
            lines = slc.decision_lines(ip=REAL_GOOGLEBOT_IP)

    # First 5 admitted, 6th 429.
    assert all(r.status_code in (200, 302) for r in results[:5]), (
        f"expected first 5 to admit; got "
        f"{[r.status_code for r in results]}"
    )
    assert results[5].status_code == 429, (
        f"6th Googlebot hit expected 429 (budget=5); "
        f"got {results[5].status_code}"
    )


def test_bot_rate_two_arg_delay_form(config_override, fresh_ip):
    """2-arg shorthand: <slug> <delay-sec> = 1 req per delay seconds.
    Crawl-delay-style. Expressed as `bingbot 5` instead of
    `bingbot 1 5sec`."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit bingbot 5',  # 1 req per 5 sec
        count=1,
    ):
        b1 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
        b2 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)

    assert b1.status_code in (200, 302), f"b1 status={b1.status_code}"
    assert b2.status_code == 429, (
        f"b2 expected 429 within 5sec window; got {b2.status_code}"
    )


def test_bot_rate_zero_delay_admits_all(config_override, fresh_ip):
    """Delay value of 0 admits all requests — the per-slug opt-out
    sentinel. Useful for excepting one slug from a stricter wildcard."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 1\n'             # everyone 1/sec
        '    BotShieldBotRateLimit bingbot 0',        # except bingbot
        count=1,
    ):
        # 5 rapid bingbot requests — none should 429 because slug=0.
        results = [
            client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
            for _ in range(5)
        ]
    assert all(r.status_code != 429 for r in results), (
        f"bingbot at delay=0 should never 429; got "
        f"{[r.status_code for r in results]}"
    )


def test_nothing_is_rate_limited_without_a_rule(config_override, fresh_ip):
    """No rule, no rate limiting.

    This used to be the opposite: enabling the module synthesised a
    wildcard of 1 req/sec per slug, so a bot hitting the site twice in
    a second got a 429 nobody had configured. The synthesis is gone,
    and this pins that -- rapid repeated requests from a known bot all
    admit when no rule mentions it."""
    results = [
        client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
        for _ in range(5)
    ]
    assert all(r.status_code != 429 for r in results), (
        f"nothing should be rate limited without a rule; "
        f"got {[r.status_code for r in results]}"
    )


def test_bot_rate_botgroup_selector(config_override, fresh_ip):
    """`@search` selector resolves to all directory slugs with the
    `search` botgroup. Each matched slug gets its own counter
    at the entry's budget (per-slug, not aggregate)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit @search 1 hour',
        count=1,
    ):
        # Bingbot is in SEARCH_ENGINE_CRAWLER → botgroup=search.
        # First request admits (counter starts at 0 in 1-hour window).
        b1 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
        b2 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
    assert b1.status_code in (200, 302), f"b1={b1.status_code}"
    assert b2.status_code == 429, (
        f"b2 should hit @search 1/hour cap; got {b2.status_code}"
    )


def test_bot_rate_botgroup_specific_overrides(config_override, fresh_ip):
    """Specific slug rule wins over @botgroup rule. With both
    `@search 1 hour` (strict) and `googlebot 100 min` (looser),
    Googlebot uses the specific budget — many requests admit."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit googlebot 100 min\n'
        '    BotShieldBotRateLimit @search 1 hour',
        count=1,
    ):
        # 5 Googlebot requests should all admit (specific 100/min
        # wins over @search 1/hour).
        results = [
            client.get("/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA)
            for _ in range(5)
        ]
    assert all(r.status_code in (200, 302) for r in results), (
        f"specific googlebot rule should override @search; got "
        f"{[r.status_code for r in results]}"
    )


def test_bot_rate_botgroup_unknown_rejected():
    """An @botgroup selector that doesn't match any directory entry is
    a config-time error. Checked with configtest rather than a reload:
    a reload with a config the module rejects would take this worker's
    instance down for the rest of the session."""
    rc, err = apache.configtest("BotShieldBotRateLimit @nosuchgroup 60")
    assert rc != 0, (
        "an unresolvable @botgroup selector was accepted; the operator "
        "gets a rule that silently matches nothing"
    )
    assert "nosuchgroup" in err or "BotShieldBotRateLimit" in err, (
        f"rejection doesn't name the selector or the directive, so an "
        f"operator can't tell what to fix. stderr:\n{err[-500:]}"
    )


def test_bot_rate_off_with_specific_entry(config_override, fresh_ip):
    """`Off` + a specific entry: the specific entry still applies, but
    no wildcard fallback for unmatched slugs."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit Off\n'
        '    BotShieldBotRateLimit bingbot 60',  # only bingbot rate-limited
        count=1,
    ):
        # bingbot trips the specific rule
        b1 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
        b2 = client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
        # Other bots are unprotected (Gatus has no specific entry, no
        # wildcard since Off)
        gatus_ua = "Gatus/1.0"
        g1 = client.get("/", xff=fresh_ip, ua=gatus_ua)
        g2 = client.get("/", xff=fresh_ip, ua=gatus_ua)

    assert b1.status_code in (200, 302), f"b1 status={b1.status_code}"
    assert b2.status_code == 429, f"b2 expected 429 (bingbot specific rule)"
    assert g1.status_code != 429 and g2.status_code != 429, (
        f"gatus should not be rate-limited under Off + bingbot-only; "
        f"got g1={g1.status_code} g2={g2.status_code}"
    )


BAD_BOT_RATE_ARGS = [
    ("BotShieldBotRateLimit gptbot notanumber", "budget"),
    ("BotShieldBotRateLimit gptbot 60 fortnight", "period"),
    ("BotShieldBotRateLimit gptbot -5", "negative budget"),
    ("BotShieldBotRateLimit", "no args at all"),
]


@pytest.mark.parametrize("snippet,what", BAD_BOT_RATE_ARGS,
                         ids=[w.replace(" ", "_") for _, w in
                              BAD_BOT_RATE_ARGS])
def test_bot_rate_bad_directive_args(snippet, what):
    """Malformed BotShieldBotRateLimit args are a config-time error.
    Silent acceptance is the failure that matters here: a budget that
    parses as 0 or INT_MAX is a rate limit the operator believes is in
    force and isn't."""
    rc, err = apache.configtest(snippet)
    assert rc != 0, f"configtest accepted {what}: {snippet!r}"
    assert "BotShieldBotRateLimit" in err, (
        f"error for {snippet!r} doesn't name the directive. "
        f"stderr:\n{err[-500:]}"
    )


def test_challenge_pass_waives_the_challenge_not_the_rate_limit(
    config_override, fresh_ip,
):
    """`status=nochallenge` means "do not challenge", not "do not
    enforce".

    A bare pass used to return out of the policy walk immediately,
    which skipped robots.txt and both rate limiters along with the
    challenge. A rule written to let declared crawlers read content
    without an interstitial was therefore also making them
    unratelimitable. The pass still shadows later rules on the same
    path; the walk just continues into the enforcement stages.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldBotRateLimit * 1 sec\n'
        '    BotShieldRequestTrigger cp path="/*" status=nochallenge log=cp',
        count=1,
    ):
        results = [
            client.get("/", xff=REAL_BINGBOT_IP, ua=BINGBOT_UA)
            for _ in range(4)
        ]

    codes = [r.status_code for r in results]
    assert codes[0] in (200, 302), f"first request should admit; got {codes}"
    assert 429 in codes, (
        f"a nochallenge must not exempt the request from the rate "
        f"limit; got {codes}"
    )
