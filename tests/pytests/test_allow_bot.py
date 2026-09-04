"""E1 — Allow family (verified-bot policy).

Exercises the Allow paths in mod_botshield:

  verified:   Googlebot UA from an IP in Googlebot's CIDR list
              → tier=pass, reason carries verified-bot:googlebot.
  fake:       Googlebot UA from an IP NOT in the list
              → fake-bot:googlebot penalty routes the request to captcha/form.
  non-bot:    Regular browser UA never touches the Allow path.
  UA-only:    BotShieldAllowBot with '*' as the 3rd arg opts out of IP
              verification. Without an IP check the bot doesn't qualify
              for verified-bot credit; the UA pattern just contributes to
              the known-bot pool (logged as known-bot:<name>, score 0).
  inline CIDR: BotShieldAllowBot with a comma-separated CIDR list inline
              → in-range matches verified, out-of-range matches are fake.

The first three tests use the dev vhost's bundled config (Googlebot /
Bingbot / Applebot seeded by provision.sh from data/bots/*.txt). The
UA-only and inline-CIDR tests inject their own directives via
config_override.
"""

from __future__ import annotations

import pytest

from botshield_test import client


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
# From the bundled Googlebot IPv4 ranges; stable enough for CI.
REAL_GOOGLEBOT_IP = "66.249.66.1"


def test_allow_bot_cidr_verified(log_slice):
    """Real Googlebot UA + real Googlebot IP must produce tier=pass
    with the verified-bot:googlebot reason. The large negative credit
    from the Allow check dominates any other penalty (missing
    Accept-Language, first-sight-ip, etc.) so the score stays well
    below even the silent threshold."""
    with log_slice as slc:
        resp = client.get(
            "/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA,
        )
        lines = slc.decision_lines(ip=REAL_GOOGLEBOT_IP)

    assert resp.status_code == 200
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"verified Googlebot got challenged; headers={dict(resp.headers)}"
    )
    assert lines, "no decision line for verified-bot request"
    verified = [d for d in lines if "verified-bot:googlebot" in d["reason"]]
    assert verified, (
        f"no decision line carried verified-bot:googlebot — "
        f"E1 not wired correctly? lines={lines}"
    )
    assert verified[0]["tier"] == "pass", (
        f"verified bot ended up at tier={verified[0]['tier']}"
    )


def test_allow_bot_fake_routed_to_captcha(log_slice, fresh_ip):
    """UA claims Googlebot, IP is nowhere near a real Googlebot range.
    fake-bot:googlebot penalty should fire and drive tier into captcha
    (or form-PoW fallback if no provider is configured at /)."""
    with log_slice as slc:
        client.get("/", xff=fresh_ip, ua=GOOGLEBOT_UA)
        lines = slc.decision_lines(ip=fresh_ip)

    fake = [d for d in lines if "fake-bot:googlebot" in d["reason"]]
    assert fake, (
        f"no decision line for fake-bot:googlebot on ip={fresh_ip}; "
        f"lines={lines}"
    )
    assert fake[0]["tier"] in ("interactive", "captcha"), (
        f"fake bot didn't reach form/captcha tier: "
        f"tier={fake[0]['tier']}"
    )


def test_non_bot_ua_unaffected(log_slice, fresh_ip):
    """Regression guard: regular browser traffic shouldn't touch the
    Allow path at all. No verified-bot / fake-bot reason should appear."""
    with log_slice as slc:
        client.get(
            "/", xff=fresh_ip,
            ua="Mozilla/5.0 (X11; Linux x86_64) Chrome/145.0",
            accept_language="en-US,en;q=0.9",
        )
        lines = slc.decision_lines(ip=fresh_ip)

    assert lines, "no decision line at all — unexpected"
    for d in lines:
        assert "verified-bot:" not in d["reason"], (
            f"non-bot UA tagged with verified-bot reason: {d['reason']!r}"
        )
        assert "fake-bot:" not in d["reason"], (
            f"non-bot UA tagged with fake-bot reason: {d['reason']!r}"
        )


def test_allow_bot_ua_only_mode(config_override, log_slice, fresh_ip):
    """`BotShieldAllowBot <name> <ua-substr> *` opts out of IP
    verification — the operator's `*` target. Without an IP check
    the bot doesn't qualify for verified-bot credit; the UA pattern
    just contributes to the known-bot pool. The decision log should
    carry known-bot:<name> with score 0, and the request should pass
    through without a challenge.

    Pick a UA and pattern that contain NONE of bot/crawl/spider/
    fetch/slurp — doubles as the regression test for the earlier
    prefilter bug where operator-defined patterns were silently
    unreachable unless the UA happened to match a hardcoded token."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldAllowBot xenophon "Xenophon/" *',
        count=1,
    ):
        with log_slice as slc:
            resp = client.get(
                "/", xff=fresh_ip,
                ua="Xenophon/9.9 (internal scraper)",
            )
            lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 200
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"UA-only-allowed bot got challenged; headers={dict(resp.headers)}"
    )
    ua_only = [d for d in lines if "known-bot:xenophon" in d["reason"]]
    assert ua_only, (
        f"no decision line carried known-bot:xenophon; "
        f"lines={lines}"
    )


def test_allow_bot_inline_cidr(config_override, log_slice, fresh_ip):
    """`BotShieldAllowBot <name> <ua-substr> <cidr,cidr,...>` accepts a
    comma-separated CIDR list inline (no file). In-range IPs allow,
    out-of-range IPs fake."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldAllowBot corpbot "CorpBot/" '
        '"198.51.100.0/24,203.0.113.0/24"',
        count=1,
    ):
        in_range_ip = "198.51.100.42"
        ua = "CorpBot/2.0 (+https://corp.example/bot)"
        # Fire both requests inside a single log slice (the fixture is
        # a one-shot CM) and filter the lines by IP for each assertion.
        with log_slice as slc:
            client.get("/", xff=in_range_ip, ua=ua)
            client.get("/", xff=fresh_ip, ua=ua)
            in_lines = slc.decision_lines(ip=in_range_ip)
            out_lines = slc.decision_lines(ip=fresh_ip)

    allowed = [d for d in in_lines if "verified-bot:corpbot" in d["reason"]]
    assert allowed, f"in-range CorpBot not allowed; lines={in_lines}"
    assert allowed[0]["tier"] == "pass"

    fake = [d for d in out_lines if "fake-bot:corpbot" in d["reason"]]
    assert fake, f"out-of-range CorpBot not faked; lines={out_lines}"
    assert fake[0]["tier"] in ("interactive", "captcha")


def test_allow_bot_main_scope_inherits_to_vhost(
    config_override, log_slice, fresh_ip,
):
    """Regression test for the server-config merge hook.

    Declaring `BotShieldAllowBot` at MAIN scope (outside `<VirtualHost>`)
    must flow into the vhost where `BotShieldEnabled On` lives. Without
    the merge hook, main-scope entries were invisible to per-request
    matching — a structural mismatch for the common "declare globally,
    enable per-vhost" shape.

    Anchor off the main-scope BotShieldStateSaveInterval line (outside any
    vhost block) to inject the main-scope directive."""
    with config_override(
        r"BotShieldStateSaveInterval\s+\d+",
        'BotShieldAllowBot globalbot "GlobalBot/" *\n'
        r'BotShieldStateSaveInterval 30',
        count=1,
    ):
        with log_slice as slc:
            resp = client.get(
                "/", xff=fresh_ip,
                ua="GlobalBot/1.0 (internal)",
            )
            lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 200
    inherited = [d for d in lines if "known-bot:globalbot" in d["reason"]]
    assert inherited, (
        f"main-scope BotShieldAllowBot did not inherit into vhost; "
        f"lines={lines}"
    )


def test_allow_bot_longest_match_wins(
    config_override, log_slice, fresh_ip,
):
    """Overlapping UA patterns must resolve to the longer/more specific
    match. A UA matching both `CorpBot` and `CorpBot/Admin` should
    classify as corpbot-admin, not corpbot — otherwise specific
    overrides are shadowed by the generic pattern registered first."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldAllowBot corpbot       "CorpBot" *\n'
        '    BotShieldAllowBot corpbot-admin "CorpBot/Admin" *',
        count=1,
    ):
        with log_slice as slc:
            resp = client.get(
                "/", xff=fresh_ip,
                ua="CorpBot/Admin 1.0 (internal)",
            )
            lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 200
    admin_lines = [
        d for d in lines if "known-bot:corpbot-admin" in d["reason"]
    ]
    assert admin_lines, (
        f"CorpBot/Admin UA was not classified as the longer-match "
        f"corpbot-admin; lines={lines}"
    )
    # Defensive: make sure the generic corpbot didn't also win a line
    # (shouldn't — classify returns a single name per request).
    assert not [
        d for d in lines if "known-bot:corpbot," in d["reason"]
        or d["reason"].endswith("known-bot:corpbot")
    ], f"generic corpbot shadowed the specific override; lines={lines}"


def test_metrics_counters_present():
    """After the tests above, the /metrics endpoint should expose
    the three new bot counters. M11.8's prometheus format test
    validates the shape; this test just confirms the names ARE
    exposed so we notice if someone drops the registration."""
    resp = client.get("/botshield/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert "botshield_bot_allow_total" in body
    assert "botshield_bot_fake_total" in body
    assert "botshield_bot_unverified_total" in body
