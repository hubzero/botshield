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
    assert "## BotShieldBotRateLimit" in body
    assert "## robots.txt" in body
    # Dev vhost doesn't declare any of these by default.
    assert "# (no directives)" in body
    assert "# (not configured)" in body


def test_policy_dump_surfaces_rate_limit(config_override):
    """A rule carrying rate= appears in the rules section with its
    conditions and its window, and no live counter column."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRule gptbot ua="GPTBot" rate=60/60',
        count=1,
    ):
        body = apache.policy_dump()

    line = [ln for ln in body.splitlines() if ln.startswith("gptbot")]
    assert line, f"rule missing from dump; body={body[:600]}"
    assert "GPTBot" in line[0], line[0]
    # Budget and window as configured. There is deliberately no live
    # counter column: a configtest process has no SHM to read.
    assert "rate=60/60" in line[0], line[0]
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


def test_policy_dump_surfaces_rules(config_override):
    """Rules are in the dump.

    They were absent entirely until 2026-09-07, which is how a shed
    ladder sat in a production config for months unable to fire with
    nothing saying so: the one tool that answers "what is in effect"
    covered every subsystem except the one operators write.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule dumped>\n"
        "        BotShieldPath          /dump-probe\n"
        "        BotShieldUserAgent     @bot\n"
        "        BotShieldRespond       403\n"
        "        BotShieldLogAs         dump-probe\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    assert "## BotShieldRule" in body, body[:400]
    line = [ln for ln in body.splitlines() if ln.startswith("dumped")]
    assert line, f"the rule is missing from the dump; body={body[:600]}"
    assert "path=/dump-probe" in line[0], line[0]
    assert "ua=@bot" in line[0], line[0]
    assert "respond=403" in line[0], line[0]
    assert "logas=dump-probe" in line[0], line[0]


def test_policy_dump_names_flags_rather_than_bits(config_override):
    """A bitmask is true and useless.

    The dump exists so a rule reads back the way it was written, so
    flagged= and flagip= print the names the operator typed rather
    than the bits they resolve to.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule flagnames>\n"
        "        BotShieldPath      /flagname-probe\n"
        "        BotShieldFlagged   scanner_probe\n"
        "        BotShieldFlagIP    honeypot_hit\n"
        "        BotShieldRespond   403\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith("flagnames")]
    assert line, f"rule missing; body={body[:600]}"
    assert "flagged=scanner_probe" in line[0], line[0]
    assert "flagip=honeypot_hit" in line[0], line[0]
    assert "0x" not in line[0], f"raw bits leaked into the dump: {line[0]}"


def test_policy_dump_marks_observe_rules(config_override):
    """An observe rule that reads like an enforcing one is the whole
    reason to check a dump before arming a ladder."""
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule staged>\n"
        "        BotShieldPath      /observe-probe\n"
        "        BotShieldRespond   503\n"
        "        BotShieldMode      observe\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith("staged")]
    assert line and "[observe]" in line[0], (
        f"an observe rule must say so; line={line}"
    )


def test_policy_dump_counts_container_rules(config_override):
    """Rules in a <Location> cannot be attributed back to it here --
    this walk reads server config. Saying how many are missing beats
    an empty section that reads as none."""
    conf = (
        "BotShieldEnabled On\n"
        '    <Location "/dump-scoped">\n'
        "        <BotShieldRule scoped>\n"
        "            BotShieldRespond   403\n"
        "        </BotShieldRule>\n"
        "    </Location>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        body = apache.policy_dump()
    assert "in containers" in body, body[:600]
    assert "not listed" in body, body[:600]
