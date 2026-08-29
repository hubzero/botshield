"""E6 — env-var triggers.

BotShieldEnvTrigger reads a per-request env var from
r->subprocess_env and applies action (credit/penalty/flag/
log/status). Producers include SetEnvIf / SetEnvIfNoCase /
SetEnvIfExpr / BrowserMatch / RewriteRule [E=VAR:VAL] /
ModSecurity v2 `setenv`.

Tests exercise the common Apache-config-driven producers
(SetEnvIfNoCase, SetEnvIfExpr) since ModSecurity v2 isn't
always installed in the test environment. Behavior is
indistinguishable from BotShield's perspective — all producers
write to the same apr_table_t.
"""

from __future__ import annotations

import pytest

from botshield_test import client, ips as _ips


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"


def _g(path, xff, **kw):
    return client.get(path, xff=xff, ua=PASS_UA,
                      accept_language=PASS_AL, **kw)


# --- env=<var> presence predicates ----------------------------------


def test_env_trigger_penalty_on_presence(config_override, log_slice):
    """SetEnvIfNoCase sets BS_SUSPECT_UA=1 for curl-like UAs;
    BotShieldEnvTrigger matches env=BS_SUSPECT_UA and applies a
    penalty. Baseline request without the matching UA unaffected."""
    ip_base = _ips.fresh_ip()
    ip_trig = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    SetEnvIfNoCase User-Agent "curl" BS_SUSPECT_UA=1\n'
        '    BotShieldEnvTrigger suspect-ua env=BS_SUSPECT_UA '
        'penalty=25 log=env-suspect',
        count=1,
    ):
        with log_slice as slc:
            # Non-curl UA: no match.
            _g("/", xff=ip_base)
            # curl-flavored UA explicitly: overrides our default pass
            # UA by passing a different one.
            client.get("/", xff=ip_trig, ua="curl/8.6.0",
                       accept_language="en")
            base_lines = slc.decision_lines(ip=ip_base)
            trig_lines = slc.decision_lines(ip=ip_trig)

    assert base_lines and trig_lines
    base_reason = base_lines[-1]["reason"]
    trig_reason = trig_lines[-1]["reason"]
    assert "env-trigger:suspect-ua" not in base_reason, (
        f"non-curl UA should not trigger; reason={base_reason}"
    )
    assert "env-trigger:suspect-ua" in trig_reason, (
        f"curl UA should trigger; reason={trig_reason}"
    )
    # Tag rides the decision line.
    assert trig_lines[-1].get("tag") == "env-suspect"


def test_env_trigger_absent(config_override, log_slice, fresh_ip):
    """!env=<var> matches when the var is not set; use it to
    penalize requests that don't carry an upstream-set signal."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnvTrigger no-marker !env=BS_MARKER '
        'penalty=30',
        count=1,
    ):
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert lines
    assert "env-trigger:no-marker" in lines[-1]["reason"], (
        f"!env=BS_MARKER should fire when no one sets BS_MARKER; "
        f"reason={lines[-1]['reason']}"
    )


# --- env=<var>=<value> exact match -----------------------------------


def test_env_trigger_value_exact_match(config_override, log_slice):
    """env=VAR=value fires only when the env var has exactly that
    value; case-sensitive."""
    ip_hi = _ips.fresh_ip()
    ip_med = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    SetEnvIf Request_URI "/hi$" BS_LEVEL=high\n'
        '    SetEnvIf Request_URI "/med$" BS_LEVEL=medium\n'
        '    BotShieldEnvTrigger hi-match env=BS_LEVEL=high penalty=80\n'
        '    BotShieldEnvTrigger med-match env=BS_LEVEL=medium penalty=20',
        count=1,
    ):
        with log_slice as slc:
            _g("/hi", xff=ip_hi)
            _g("/med", xff=ip_med)
            hi_lines  = slc.decision_lines(ip=ip_hi)
            med_lines = slc.decision_lines(ip=ip_med)

    assert hi_lines and med_lines
    assert "env-trigger:hi-match" in hi_lines[-1]["reason"]
    assert "env-trigger:med-match" in med_lines[-1]["reason"]


# --- status=<code> short-circuit ------------------------------------


def test_env_trigger_status_code_blocks(config_override, fresh_ip):
    """status=<code> short-circuits the response with that code."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    SetEnvIfExpr "%{REQUEST_URI} =~ /hostile/" BS_HOSTILE=1\n'
        '    BotShieldEnvTrigger hostile env=BS_HOSTILE status=403',
        count=1,
    ):
        r_hit = _g("/hostile/path", xff=fresh_ip)
        r_ok  = _g("/other",        xff=fresh_ip)

    assert r_hit.status_code == 403
    assert r_ok.status_code  != 403


# --- RewriteRule [E=...] producer ------------------------------------


def test_env_trigger_from_rewrite_producer(config_override, log_slice,
                                            fresh_ip):
    """Producer variation: RewriteRule [E=VAR:VAL] sets the env at
    fixups phase. Handler reads it fine."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    RewriteEngine On\n'
        '    RewriteRule ^/rw-flag /index.html [E=BS_FROM_RW:1,L]\n'
        '    BotShieldEnvTrigger rw-origin env=BS_FROM_RW penalty=15',
        count=1,
    ):
        with log_slice as slc:
            _g("/rw-flag", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert lines
    assert "env-trigger:rw-origin" in lines[-1]["reason"], (
        f"RewriteRule [E=...] producer didn't light up the trigger; "
        f"reason={lines[-1]['reason']}"
    )


# --- Flag + ttl persist to next request -----------------------------


def test_env_trigger_flag_persists(config_override, log_slice):
    """Flag+ttl adds the IP to flagged-IP table; next request from
    the same IP carries the bit's contribution as flagged-ip in the
    reason trace."""
    ip = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    SetEnvIf Request_URI "/flag-me" BS_FLAG_ME=1\n'
        '    BotShieldEnvTrigger flagger env=BS_FLAG_ME '
        'flag=scanner_probe ttl=3600',
        count=1,
    ):
        _g("/flag-me", xff=ip)
        with log_slice as slc:
            _g("/index.html", xff=ip)
            lines = slc.decision_lines(ip=ip)
    assert lines
    assert "flagged-ip" in lines[-1]["reason"]


# --- Precedence: first match wins (no accumulation) -----------------


def test_env_trigger_first_match_wins(config_override, log_slice,
                                       fresh_ip):
    """Two env triggers matching the same request: only the first
    declared fires (strict first-match-wins, unlike E4's cookies
    which accumulate pass matches)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    SetEnvIf Request_URI ".*" BS_PING=1\n'
        '    BotShieldEnvTrigger first  env=BS_PING penalty=5\n'
        '    BotShieldEnvTrigger second env=BS_PING penalty=50',
        count=1,
    ):
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)
    assert lines
    reason = lines[-1]["reason"]
    assert "env-trigger:first" in reason, reason
    assert "env-trigger:second" not in reason, (
        f"second trigger must NOT fire after first match wins; "
        f"reason={reason}"
    )


# --- Main-scope inheritance + no redirect= -------------------------


def test_env_trigger_main_scope_inherits(config_override, fresh_ip):
    """BotShieldEnvTrigger at main scope flows into the vhost via
    the server-config merge (same guarantee E3/E4 get)."""
    with config_override(
        r"BotShieldStateFile\s+\S+",
        'BotShieldEnvTrigger ms-env !env=BS_NEVER_SET status=403\n'
        'BotShieldStateFile /var/lib/botshield/state.bin',
        count=1,
    ):
        r = _g("/", xff=fresh_ip)
    assert r.status_code == 403


def test_env_trigger_redirect_rejected_at_config_time(
    config_override, fresh_ip,
):
    """redirect= is intentionally not supported on env triggers;
    config parse must reject it."""
    import pytest as _p
    with _p.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldEnvTrigger r-test env=X redirect=https://x',
            count=1,
        ):
            pass
