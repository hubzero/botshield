"""E2.2.3 — /botshield/policy-status page.

Operator-visibility surface. Not authenticated / not rate limited —
operators protect the endpoint via <Location> the same way they
protect /server-status. These tests only confirm that the page
surfaces the configured rules with their source tags and a couple
of recognizable bits of state; format drift that preserves the
substrings here is fine.
"""

from __future__ import annotations

import os
import uuid

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


TEST_ROBOTS_DIR = "/etc/botshield/test-robots"


@pytest.fixture
def robots_path():
    p = f"{TEST_ROBOTS_DIR}/robots-{uuid.uuid4().hex}.txt"
    yield p
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass


def test_policy_status_without_config_shows_none(config_override):
    """With a vanilla vhost (no rate limits, block paths, or robots.txt
    configured) the page loads and marks each section as empty / not
    configured — the handler doesn't crash on a scfg with nothing in it."""
    resp = client.get("/botshield/policy-status")
    assert resp.status_code == 200
    body = resp.text
    assert "# mod_botshield policy status" in body
    assert "## BotShieldRateLimit" in body
    assert "## BotShieldBlockPath" in body
    assert "## robots.txt" in body
    # Dev vhost doesn't declare any of these by default.
    assert "# (none)" in body
    assert "# (not configured)" in body


def test_policy_status_surfaces_rate_limit(config_override):
    """A BotShieldRateLimit directive appears in the directive
    section with its cohort + live counter state."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldRateLimit gptbot 60 min "GPTBot" *',
        count=1,
    ):
        resp = client.get("/botshield/policy-status")

    assert resp.status_code == 200
    body = resp.text
    assert "BotShieldRateLimit" in body
    assert "gptbot" in body
    assert '"GPTBot"' in body
    # The counter column — format is "count/budget"; we don't care
    # about the count but the /60 is the budget we configured.
    assert "/60" in body


def test_policy_status_surfaces_block_path(config_override):
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldBlockPath admin-block "/admin/*" "Scraper/" *',
        count=1,
    ):
        resp = client.get("/botshield/policy-status")

    assert resp.status_code == 200
    body = resp.text
    assert "admin-block" in body
    assert "/admin/*" in body
    assert '"Scraper/"' in body


def test_policy_status_surfaces_robots(robots_path, config_override):
    """Robots.txt section shows the path, mtime line, each group, its
    UA tokens, and its rules."""
    with open(robots_path, "w") as f:
        f.write("User-agent: GPTBot\n"
                "Disallow: /admin\n"
                "Allow: /admin/public\n"
                "Crawl-delay: 30\n"
                "\n"
                "User-agent: *\n"
                "Disallow: /private\n")
    os.chmod(robots_path, 0o644)

    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        f'BotShieldAllowVerifiedBots on\n'
        f'    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        resp = client.get("/botshield/policy-status")

    assert resp.status_code == 200
    body = resp.text
    assert f"# path:                {robots_path}" in body
    # At least one of the RFC822 date tokens — exact value varies.
    assert "# mtime:" in body

    # GPTBot group (with rules + Crawl-delay).
    assert 'group[0] "gptbot"' in body
    assert "user-agent: gptbot" in body
    assert "Disallow: /admin" in body
    assert "Allow:    /admin/public" in body
    assert "Crawl-delay: 30s" in body

    # Wildcard group.
    assert 'group[1] "wildcard"' in body
    assert "wildcard=yes" in body
    assert "user-agent: *" in body
    assert "Disallow: /private" in body
