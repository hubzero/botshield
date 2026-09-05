"""E2.2 — server-side robots.txt enforcement.

Exercises BotShieldRobotsTxt + BotShieldRobotsWildcardScope:

  Disallow      → 403, reason robotsblock:<group-name>
  Crawl-delay   → 429 + Retry-After, reason robots-rate:<group>
  Allow/Disallow longest-match-wins within a group
  User-agent: * gated by wildcard scope (heuristic / strict / off)
  Directive rules layer over robots.txt (operator wins in each family)

Each test writes a tiny robots.txt under /tmp and injects a
BotShieldRobotsTxt directive via config_override to point at it. The
file is cleaned up by pytest tmp_path_factory.
"""

from __future__ import annotations

import os
import re
import textwrap
import uuid

import pytest

from botshield_test import client


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


GPTBOT_UA  = "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"
# A real Firefox string. The previous value here omitted the rv:
# and Gecko/ tokens, which no Firefox actually does -- so it
# matched no browser template, classified as `unclassified`, and
# the robots heuristic correctly declined to treat it as a
# browser. The test then read that as the module failing to skip
# real browsers. A UA literal in a test has to be a string some
# browser really emits, or it tests the wrong thing.
REAL_UA    = ("Mozilla/5.0 (X11; Linux x86_64; rv:130.0) "
              "Gecko/20100101 Firefox/130.0")
CURL_UA    = "curl/8.6.0"


TEST_ROBOTS_DIR = "/etc/botshield/test-robots"


@pytest.fixture
def robots_path(request):
    """Allocate a fresh path for a test's robots.txt file under
    /etc/botshield/test-robots (provisioned by tests/setup/provision.sh).

    Can't use pytest's tmp_path or /tmp — Apache's systemd unit has
    PrivateTmp=true, which gives the apache2 process its own private
    /tmp namespace. Files under the host /tmp are invisible to Apache,
    so the module fails to open them and we get silent "enforcement
    disabled" from post_config. /etc/ sidesteps the namespace.
    """
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


# --- Disallow / Allow -------------------------------------------------


def test_robots_disallow_blocks_bot(
    robots_path, config_override, log_slice, fresh_ip,
):
    """Bot UA that robots.txt Disallows a path for → 403."""
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /admin
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n    BotShieldScoreNonInteractive 500\n    BotShieldScoreInteractive 600\n    BotShieldScoreCaptcha 700\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        with log_slice as slc:
            r_blocked = client.get("/admin", xff=fresh_ip, ua=GPTBOT_UA)
            r_ok      = client.get("/public", xff=fresh_ip, ua=GPTBOT_UA)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r_blocked.status_code == 403
    assert r_ok.status_code != 403
    hits = [d for d in lines if "robotsblock:gptbot" in d["reason"]]
    assert hits, f"no robotsblock:gptbot line; lines={lines}"


def test_robots_allow_longest_match_wins(
    robots_path, config_override, log_slice, fresh_ip,
):
    """Allow overrides Disallow when its path pattern is longer
    (RFC 9309 longest-match-wins)."""
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /admin
        Allow: /admin/public
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n    BotShieldScoreNonInteractive 500\n    BotShieldScoreInteractive 600\n    BotShieldScoreCaptcha 700\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        r_admin  = client.get("/admin",        xff=fresh_ip, ua=GPTBOT_UA)
        r_public = client.get("/admin/public", xff=fresh_ip, ua=GPTBOT_UA)

    assert r_admin.status_code  == 403, "plain /admin still Disallowed"
    assert r_public.status_code != 403, (
        "Allow: /admin/public is longer → overrides Disallow: /admin"
    )


# --- Crawl-delay ------------------------------------------------------


def test_robots_crawl_delay_rate_limits(
    robots_path, config_override, log_slice, fresh_ip,
):
    """Crawl-delay N translates to 1 request per N sec per group.
    Second request in the window returns 429 + Retry-After + the
    robots-rate:<group> reason."""
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Crawl-delay: 60
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n    BotShieldScoreNonInteractive 500\n    BotShieldScoreInteractive 600\n    BotShieldScoreCaptcha 700\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        with log_slice as slc:
            r1 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
            r2 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r1.status_code != 403
    assert r2.status_code == 429
    ra = r2.headers.get("Retry-After")
    assert ra and ra.isdigit() and int(ra) > 0, (
        f"Retry-After missing or not a positive integer: {ra!r}"
    )
    # Reason name changed when robots.txt Crawl-delay was rekeyed onto
    # the slug-keyed bot_rate machinery (formerly "robots-rate:<group>").
    assert [d for d in lines if "botrate:gptbot" in d["reason"]], (
        f"no botrate:gptbot decision line; lines={lines}"
    )


# --- Wildcard scope ---------------------------------------------------


@pytest.fixture
def wildcard_robots(robots_path):
    return _write_robots(robots_path, """
        User-agent: *
        Disallow: /admin
    """)


def test_robots_wildcard_heuristic_skips_real_browser(
    wildcard_robots, config_override, fresh_ip,
):
    """Default heuristic: Firefox UA NOT blocked (real browsers don't
    read robots.txt; we don't apply * rules to them). curl UA IS
    blocked (scripting tool, crawler-candidate)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n    BotShieldScoreNonInteractive 500\n    BotShieldScoreInteractive 600\n    BotShieldScoreCaptcha 700\n    BotShieldRobotsTxt {wildcard_robots}',
        count=1,
    ):
        r_firefox = client.get("/admin", xff=fresh_ip, ua=REAL_UA)
        r_curl    = client.get("/admin", xff=fresh_ip, ua=CURL_UA)

    assert r_firefox.status_code != 403, (
        "real browser must not be blocked by a * rule in heuristic mode"
    )
    assert r_curl.status_code == 403, (
        "curl (non-browser prefix) is a crawler candidate and should "
        "be blocked by a * rule"
    )


def test_robots_wildcard_strict_applies_to_everyone(
    wildcard_robots, config_override, fresh_ip,
):
    """strict: * rules apply to every UA, including real browsers."""
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        f'    BotShieldRobotsTxt {wildcard_robots}\n'
        f'    BotShieldRobotsWildcardScope strict',
        count=1,
    ):
        r_firefox = client.get("/admin", xff=fresh_ip, ua=REAL_UA)

    assert r_firefox.status_code == 403, (
        "strict mode should apply * rules even to real-browser UAs"
    )


def test_robots_wildcard_off_skips_wildcard_entirely(
    wildcard_robots, config_override, fresh_ip,
):
    """off: * rules are not enforced for any UA."""
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        f'    BotShieldRobotsTxt {wildcard_robots}\n'
        f'    BotShieldRobotsWildcardScope off',
        count=1,
    ):
        r_firefox = client.get("/admin", xff=fresh_ip, ua=REAL_UA)
        r_curl    = client.get("/admin", xff=fresh_ip, ua=CURL_UA)

    assert r_firefox.status_code != 403
    assert r_curl.status_code != 403, (
        "off mode: * group should never fire"
    )


# --- Segment-based UA match semantics -------------------------------


def test_robots_ua_match_is_segment_based(
    robots_path, config_override, log_slice, fresh_ip,
):
    """The robots.txt UA matcher splits the UA on `;` and checks each
    segment for a prefix match with the token — not a blanket
    substring of the whole UA.

    Under the earlier strcasestr semantics, a `User-agent: Bot` rule
    would match any UA that contained 'bot' anywhere, including
    something like `Mozilla/5.0 (+https://example.com/robot-info)`
    (because it contains 'bot' in the URL). Under segment semantics
    it only matches when a `;`-separated segment starts with 'Bot'.

    The specific 'GPTBot' case still matches its Mozilla-style UA
    because the GPTBot segment is a `;`-separated piece that starts
    with 'GPTBot'."""
    robots_path = _write_robots(robots_path, """
        User-agent: Bot
        Disallow: /admin
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n    BotShieldScoreNonInteractive 500\n    BotShieldScoreInteractive 600\n    BotShieldScoreCaptcha 700\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        # A UA that mentions 'bot' only inside a URL in a slug —
        # the slug starts with '+https://', not 'Bot'. Must NOT match.
        r_substring_only = client.get(
            "/admin", xff=fresh_ip,
            ua="Mozilla/5.0 (+https://example.com/robot-info)",
        )
        # A UA whose product-token slug starts with 'Bot'. MUST match.
        r_real_bot = client.get(
            "/admin", xff=fresh_ip,
            ua="Mozilla/5.0 (compatible; BotMom/1.0; +https://example.com)",
        )

    assert r_substring_only.status_code != 403, (
        "strcasestr-era semantics would have blocked this; slug-based "
        "matching must not — 'bot' only appears inside a URL"
    )
    assert r_real_bot.status_code == 403, (
        "the slug 'BotMom/1.0' starts with 'Bot' — this should match"
    )


# --- Duplicate-UA groups (RFC 9309 §2.2.1) ---------------------------


def test_robots_duplicate_ua_groups_are_unioned(
    robots_path, config_override, fresh_ip,
):
    """Per RFC 9309 §2.2.1, when the same User-agent token appears in
    multiple group stanzas, the crawler MUST obey the rules from all
    of them. Earlier implementations only consulted the first (or
    longest) matching group, under-enforcing files like this one."""
    _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /a

        User-agent: GPTBot
        Disallow: /b
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n    BotShieldScoreNonInteractive 500\n    BotShieldScoreInteractive 600\n    BotShieldScoreCaptcha 700\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        r_a = client.get("/a", xff=fresh_ip, ua=GPTBOT_UA)
        r_b = client.get("/b", xff=fresh_ip, ua=GPTBOT_UA)
        r_c = client.get("/c", xff=fresh_ip, ua=GPTBOT_UA)

    assert r_a.status_code == 403, "Disallow /a from first stanza must fire"
    assert r_b.status_code == 403, (
        "Disallow /b from second stanza must fire too — duplicate "
        "User-agent groups are accumulative per RFC 9309"
    )
    assert r_c.status_code != 403, "/c not mentioned; should pass"


def test_robots_duplicate_crawl_delay_takes_max(
    robots_path, config_override, fresh_ip,
):
    """When duplicate UA stanzas carry different Crawl-delay values,
    the max (most restrictive) wins. Two stanzas with Crawl-delay: 30
    and Crawl-delay: 60 → effective budget is 1 per 60 sec."""
    _write_robots(robots_path, """
        User-agent: GPTBot
        Crawl-delay: 30

        User-agent: GPTBot
        Crawl-delay: 60
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n    BotShieldScoreNonInteractive 500\n    BotShieldScoreInteractive 600\n    BotShieldScoreCaptcha 700\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        r1 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
        r2 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
        ra = r2.headers.get("Retry-After")

    assert r1.status_code != 403
    assert r2.status_code == 429
    assert ra and ra.isdigit() and int(ra) > 30, (
        f"Retry-After should reflect the 60s window (max across "
        f"stanzas); got {ra!r}"
    )


# --- Main-scope server-config inheritance ----------------------------


def test_robots_main_scope_path_inherits_into_vhost(
    robots_path, config_override, fresh_ip,
):
    """BotShieldRobotsTxt declared at the main server (outside
    <VirtualHost>) must flow into the vhost's effective scfg via the
    server-config merge hook — same guarantee E1/E2.1 already
    provide. Anchor off the main-scope BotShieldStateSaveInterval line."""
    _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /admin
    """)
    with config_override(
        r"BotShieldStateSaveInterval\s+\d+",
        f'BotShieldRobotsTxt {robots_path}\n'
        r'BotShieldStateSaveInterval 30',
        count=1,
    ):
        r = client.get("/admin", xff=fresh_ip, ua=GPTBOT_UA)

    assert r.status_code == 403, (
        "main-scope BotShieldRobotsTxt didn't inherit into the vhost; "
        "bs_merge_server_cfg needs to carry robots_* fields"
    )


# --- Layering directive rules over robots.txt ------------------------


def test_robots_live_refresh_picks_up_changes(
    robots_path, config_override, fresh_ip,
):
    """E2.2.2 — with BotShieldRobotsRefreshInterval set, the module
    should pick up on-disk changes to robots.txt via mod_watchdog
    without an Apache reload.

    Strategy: initial file Disallows /admin for GPTBot. Verify the
    block is active. Rewrite the file with the Disallow removed and
    bump mtime. Wait ~2 refresh intervals. Confirm /admin is no
    longer blocked, purely from the watchdog tick (no apachectl
    reload between requests).

    Uses the shortest-safe refresh interval (1s) so the test cost
    stays under 5s. The sleep after the file rewrite is
    interval * 3 to account for scheduling jitter and the initial
    stat check having happened immediately after reload."""
    import time

    # Initial file: block /admin for GPTBot.
    _write_robots(robots_path, """
        User-agent: GPTBot
        Disallow: /admin
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        f'    BotShieldRobotsTxt {robots_path}\n'
        f'    BotShieldRobotsRefreshInterval 1',
        count=1,
    ):
        r_before = client.get("/admin", xff=fresh_ip, ua=GPTBOT_UA)
        assert r_before.status_code == 403, (
            "initial robots.txt must block before refresh test begins"
        )

        # Rewrite the file with an empty Disallow (explicitly allow)
        # and bump mtime one second forward so the stat() definitely
        # detects the change (some filesystems have 1s mtime
        # granularity).
        _write_robots(robots_path, """
            User-agent: GPTBot
            Allow: /
        """)
        future = time.time() + 2
        os.utime(robots_path, (future, future))

        # Wait for the watchdog to tick and the refresh to run. Poll
        # until the deadline — under load, watchdog scheduling jitters
        # far past what the 1s interval would suggest.
        #
        # Widened from 20s on 2026-09-05 after this failed two of about
        # five CI runs in a day while passing 3/3 locally. CI runs the
        # 60-second soak concurrently with this suite, so mod_watchdog
        # competes for a thread in a way it never does on a developer
        # box -- twenty missed 1s intervals is starvation, not a slow
        # filesystem.
        #
        # The loop exits the moment the refresh lands, so a healthy run
        # pays nothing for the larger number; only a genuine watchdog
        # regression waits it out. That is the trade: slower to report
        # a scheduling bug, incapable of hiding a wrong answer, which
        # is the right way round for an async timing check.
        started = time.time()
        deadline = started + 45
        r_after = None
        while time.time() < deadline:
            r_after = client.get("/admin", xff=fresh_ip, ua=GPTBOT_UA)
            if r_after.status_code != 403:
                break
            time.sleep(0.5)

    assert r_after is not None and r_after.status_code != 403, (
        "robots.txt was rewritten to allow /admin, but the refresh "
        f"watchdog didn't swap in the new rules within "
        f"{time.time() - started:.0f}s — request "
        "is still blocked. Check BotShieldRobotsRefreshInterval wiring "
        f"(last status={r_after.status_code if r_after else 'n/a'})."
    )


def test_directive_rate_limit_overrides_robots_crawl_delay(
    robots_path, config_override, fresh_ip,
):
    """Operator directive takes precedence over robots.txt in the
    slug-keyed rate-limit family. robots.txt says 1/60s; directive
    says 10/sec for the same slug; directive's looser bucket wins —
    all three requests admit. After the robots.txt rekey, both
    sources feed the same slug→counter map, and bot_rate_init
    processes directives second so they overwrite robots.txt-
    derived entries on slug conflict (with a config-time NOTICE)."""
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Crawl-delay: 60
    """)
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        f'    BotShieldRobotsTxt {robots_path}\n'
        f'    BotShieldBotRateLimit gptbot 10 sec',
        count=1,
    ):
        r1 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
        r2 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
        r3 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)

    # Directive budget is 10/sec; all three should admit. If robots.txt's
    # 1/60s were being consulted (i.e., directive didn't win), r2 = 429.
    assert [r1.status_code, r2.status_code, r3.status_code] == [200, 200, 200]
