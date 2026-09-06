"""BotShieldTrigger — per-Apache-scope trigger declaration.

Verifies that a BotShieldTrigger directive placed inside a
<Location> takes effect only for requests under that scope, that
the action keys mirror the cookie-family surface (status / flag /
ttl / penalty / log / mode), and that the `reset` keyword clears
inherited triggers from outer scopes.

Replaces the legacy BotShieldFlagIP coverage — the equivalent today
is `BotShieldTrigger flag=<name> ttl=<sec>`.
"""

from __future__ import annotations

import pytest

from botshield_test import client


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


# --- BotShieldTrigger fires only inside its scope -------------------


def test_scope_trigger_status_blocks_inside_location_only(
    config_override, log_slice, fresh_ip,
):
    """A BotShieldTrigger inside <Location /trap> returns 403 for
    requests to /trap, and DOES NOT fire for requests to other
    paths in the same vhost."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location "/trap">\n'
        '        BotShieldTrigger respond=403 logas=trap-block\n'
        '    </Location>',
        count=1,
    ):
        with log_slice as slc:
            inside = _g("/trap", xff=fresh_ip)
            outside = _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert inside.status_code == 403, (
        f"BotShieldTrigger in <Location /trap> should 403; got {inside.status_code}"
    )
    assert outside.status_code == 200, (
        f"requests outside the trap scope must not be affected; "
        f"got {outside.status_code}"
    )
    assert any(
        "scopetrigger" in l["reason"] and l.get("path", "").startswith("/trap")
        for l in lines
    ), f"expected scopetrigger reason on /trap; got {[l.get('reason') for l in lines]}"


# --- flag= action replaces BotShieldFlagIP -------------------------


def test_scope_trigger_flag_persists_to_next_request(
    config_override, log_slice, fresh_ip,
):
    """A BotShieldTrigger flag=honeypot_hit in <Location> writes
    the flag into the SHM flagged-IP table; the next request from
    the same IP hits the default flagtrigger reaction
    (tier_floor=captcha + +60 score) — same behavior the legacy
    BotShieldFlagIP directive provided."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location "/admin/.env">\n'
        '        BotShieldTrigger flag=honeypot_hit ttl=3600\n'
        '    </Location>',
        count=1,
    ):
        # Hit the honeypot first.
        _g("/admin/.env", xff=fresh_ip)

        # Subsequent request from the same IP should pick up the flag.
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert lines, "no decision line for the follow-up request"
    reason = lines[-1]["reason"]
    assert "flaggedip" in reason, (
        f"follow-up request didn't pick up the honeypot flag; "
        f"reason={reason}"
    )


# --- reset drops inherited triggers --------------------------------


def test_scope_trigger_reset_drops_inherited(
    config_override, log_slice, fresh_ip,
):
    """A BotShieldTrigger reset in a deeper scope drops triggers
    that would otherwise be inherited from the parent scope."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location "/api">\n'
        '        BotShieldTrigger score=\"probe +15\" logas=api-tax\n'
        '    </Location>\n'
        '    <Location "/api/health">\n'
        '        BotShieldTrigger reset\n'
        '    </Location>',
        count=1,
    ):
        with log_slice as slc:
            _g("/api/users", xff=fresh_ip)
            _g("/api/health", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    by_path = {l.get("path", ""): l for l in lines}
    assert "/api/users" in by_path, f"missing /api/users line; got paths={list(by_path)}"
    assert "/api/health" in by_path, f"missing /api/health line; got paths={list(by_path)}"

    assert "scopetrigger:api-tax" in by_path["/api/users"]["reason"], (
        f"taxed request should carry the inherited tax reason; "
        f"reason={by_path['/api/users']['reason']}"
    )
    assert "scopetrigger" not in by_path["/api/health"]["reason"], (
        f"reset scope should drop the inherited tax; "
        f"reason={by_path['/api/health']['reason']}"
    )


# --- mode=observe gates the side effect ----------------------------


def test_scope_trigger_observe_mode_does_not_enforce(
    config_override, log_slice, fresh_ip,
):
    """A BotShieldTrigger with mode=observe logs `:observe` but
    does not return the configured status."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    <Location "/staging">\n'
        '        BotShieldTrigger respond=403 logas=staging-trial mode=observe\n'
        '    </Location>',
        count=1,
    ):
        with log_slice as slc:
            r = _g("/staging", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r.status_code != 403, (
        f"observe-mode trigger must not enforce respond=403; got {r.status_code}"
    )
    assert lines
    reason = lines[-1]["reason"]
    assert "scopetrigger:staging-trial:observe" in reason, (
        f"observe match should appear in reason with :observe suffix; "
        f"reason={reason}"
    )
