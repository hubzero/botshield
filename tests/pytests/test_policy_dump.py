"""`httpd -t -D DUMP_BOTSHIELD_POLICY` policy dump.

Operator-visibility surface. This was an HTTP endpoint; it is now a
config-test dump, which needs no access control and answers the
question operators actually asked ("what will this config do?")
before the config is live rather than after. These tests only
confirm the dump surfaces the configured rules with their source
tags and a couple of recognizable bits of state; format drift that
preserves the substrings here is fine.
"""

from __future__ import annotations

import os
import uuid

import pytest

from botshield_test import apache


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


TEST_ROBOTS_DIR = "/etc/botshield/test-robots"


@pytest.fixture
def robots_path():
    p = f"{TEST_ROBOTS_DIR}/robots-{uuid.uuid4().hex}.txt"
    yield p
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass


def test_policy_dump_without_config_shows_none(config_override):
    """With a vanilla vhost (no rate limits or robots.txt configured)
    the page loads and marks each section as empty / not configured
    — the handler doesn't crash on a scfg with nothing in it."""
    body = apache.policy_dump()
    assert "# mod_botshield policy dump" in body
    assert "## BotShieldRateLimit" in body
    assert "## robots.txt" in body
    # Dev vhost doesn't declare any of these by default.
    assert "# (none)" in body
    assert "# (not configured)" in body


def test_policy_dump_surfaces_rate_limit(config_override):
    """A BotShieldRateLimit directive appears in the directive
    section with its cohort + live counter state."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRateLimit gptbot 60 min "GPTBot" *',
        count=1,
    ):
        body = apache.policy_dump()

    assert "BotShieldRateLimit" in body
    assert "gptbot" in body
    assert '"GPTBot"' in body
    # Budget and window as configured. There is deliberately no live
    # counter column: a configtest process has no SHM to read.
    assert "60" in body
    assert "60s" in body
    assert "count/budget" not in body


def test_policy_dump_surfaces_robots(robots_path, config_override):
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
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n'
        f'    BotShieldRobotsTxt {robots_path}',
        count=1,
    ):
        body = apache.policy_dump()

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
