"""E2.2 — server-side robots.txt enforcement.

Exercises BotShieldRobotsTxt + BotShieldRobotsWildcardScope:

  Disallow      → 403, reason robots-block:<group-name>
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


pytestmark = pytest.mark.serial


GPTBOT_UA  = "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"
REAL_UA    = "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"
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
        r"BotShieldAllow\s+on",
        f'BotShieldAllow on\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        with log_slice as slc:
            r_blocked = client.get("/admin", xff=fresh_ip, ua=GPTBOT_UA)
            r_ok      = client.get("/public", xff=fresh_ip, ua=GPTBOT_UA)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r_blocked.status_code == 403
    assert r_ok.status_code      == 200
    hits = [d for d in lines if "robots-block:gptbot" in d["reason"]]
    assert hits, f"no robots-block:gptbot line; lines={lines}"


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
        r"BotShieldAllow\s+on",
        f'BotShieldAllow on\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        r_admin  = client.get("/admin",        xff=fresh_ip, ua=GPTBOT_UA)
        r_public = client.get("/admin/public", xff=fresh_ip, ua=GPTBOT_UA)

    assert r_admin.status_code  == 403, "plain /admin still Disallowed"
    assert r_public.status_code == 200, (
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
        r"BotShieldAllow\s+on",
        f'BotShieldAllow on\n    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        with log_slice as slc:
            r1 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
            r2 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r1.status_code == 200
    assert r2.status_code == 429
    ra = r2.headers.get("Retry-After")
    assert ra and ra.isdigit() and int(ra) > 0, (
        f"Retry-After missing or not a positive integer: {ra!r}"
    )
    assert [d for d in lines if "robots-rate:gptbot" in d["reason"]], (
        f"no robots-rate:gptbot decision line; lines={lines}"
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
        r"BotShieldAllow\s+on",
        f'BotShieldAllow on\n    BotShieldRobotsTxt {wildcard_robots}',
        count=1,
    ):
        r_firefox = client.get("/admin", xff=fresh_ip, ua=REAL_UA)
        r_curl    = client.get("/admin", xff=fresh_ip, ua=CURL_UA)

    assert r_firefox.status_code == 200, (
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
        r"BotShieldAllow\s+on",
        f'BotShieldAllow on\n'
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
        r"BotShieldAllow\s+on",
        f'BotShieldAllow on\n'
        f'    BotShieldRobotsTxt {wildcard_robots}\n'
        f'    BotShieldRobotsWildcardScope off',
        count=1,
    ):
        r_firefox = client.get("/admin", xff=fresh_ip, ua=REAL_UA)
        r_curl    = client.get("/admin", xff=fresh_ip, ua=CURL_UA)

    assert r_firefox.status_code == 200
    assert r_curl.status_code    == 200, (
        "off mode: * group should never fire"
    )


# --- Layering directive rules over robots.txt ------------------------


def test_directive_rate_limit_overrides_robots_crawl_delay(
    robots_path, config_override, fresh_ip,
):
    """Operator directive takes precedence over robots.txt in the same
    feature family. robots.txt says 1/60s; directive says 10/sec. The
    directive's looser bucket is checked first; request admits."""
    robots_path = _write_robots(robots_path, """
        User-agent: GPTBot
        Crawl-delay: 60
    """)
    with config_override(
        r"BotShieldAllow\s+on",
        f'BotShieldAllow on\n'
        f'    BotShieldRobotsTxt {robots_path}\n'
        f'    BotShieldRateLimit gptbot 10 sec "GPTBot" *',
        count=1,
    ):
        r1 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
        r2 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)
        r3 = client.get("/", xff=fresh_ip, ua=GPTBOT_UA)

    # Directive budget is 10/sec; all three should admit. If robots.txt's
    # 1/60s were being consulted, r2 would be 429.
    assert [r1.status_code, r2.status_code, r3.status_code] == [200, 200, 200]
