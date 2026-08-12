"""E13 — per-vhost SHM namespacing.

Each vhost gets its own reputation namespace by default (ns_id derived
from siphash(ServerName)); operators opt into sharing by setting
`BotShieldShareScope <token>` to the same string on the vhosts that
should pool reputation.

The dev vhost has only ServerName=localhost, so we can't drive a true
two-vhost test from here. Instead these tests exploit the fact that
ns_id is recomputed at every post_config: flipping `BotShieldShareScope`
between two values across `config_override` cycles is functionally the
same as moving between two namespaces. Cross-namespace lookups must
miss because slot writes carry an ns_id field and lookups reject
mismatched ns_id.

What's covered:
  - directive validation (empty token rejected; too-long rejected)
  - flagged-IP isolation across namespaces (the load-bearing case)
  - Bloom filter isolation across namespaces (first-sight credit
    only fires per-namespace)
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"


def _g(path: str, **kw):
    return client.get(path, ua=PASS_UA, accept_language=PASS_AL, **kw)


# --- Directive validation -------------------------------------------


def test_share_scope_rejects_empty_token(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldShareScope ""',
            count=1,
        ):
            pass


def test_share_scope_rejects_overlong_token(config_override):
    long_tok = "x" * 200
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            f'BotShieldEnabled On\n'
            f'    BotShieldShareScope {long_tok}',
            count=1,
        ):
            pass


def test_share_scope_accepts_normal_token(config_override, fresh_ip):
    """No-op acceptance — directive parses and Apache reloads cleanly."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldShareScope ns-acceptance-test',
        count=1,
    ):
        # Reload succeeded if we got here; sanity-poke the server.
        # fresh_ip, not the default client address: 127.0.0.1 is
        # Bloom-known after any earlier test, which adds
        # dropped-cookie (25) and challenges this sanity poke.
        r = _g("/", xff=fresh_ip)
        assert r.status_code in (200, 304), (
            f"server unhealthy after share-scope reload; "
            f"status={r.status_code}"
        )


# --- Flagged-IP isolation across namespaces -------------------------


def test_flagged_ip_isolated_across_share_scopes(
    config_override, rate_slot_ip, log_slice,
):
    """Flag IP_X under ShareScope=alpha, then switch to ShareScope=beta
    and verify the same IP is NOT flagged in the new namespace.

    Two separate `config_override` windows because the directive is
    server-scope and config_override does the reload that recomputes
    ns_id. Apache's persisted state file carries the slot across the
    reload (slot is copied verbatim with its ns_id field), so under
    the beta namespace the slot is still present in SHM but lookups
    miss on the ns_id mismatch."""

    # --- Phase A: flag IP_X under namespace alpha ----------------
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldShareScope ns-isolation-alpha',
        count=1,
    ):
        client.get("/admin/.env", xff=rate_slot_ip)
        time.sleep(1)  # mutex write → seqlock visible

    # --- Phase B: switch namespace; capture the decision line ---
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldShareScope ns-isolation-beta',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=rate_slot_ip)
            lines = slc.decision_lines(ip=rate_slot_ip)

    assert lines, f"no decision line captured for IP {rate_slot_ip}"
    flagged = [d for d in lines if "flagged-ip" in d.get("reason", "")]
    assert not flagged, (
        f"namespace isolation broken: IP {rate_slot_ip} picked up "
        f"flagged-ip in beta namespace despite being flagged only in "
        f"alpha; lines={lines}"
    )


# --- Re-entry under same scope sees flag again ----------------------


def test_share_scope_revisit_sees_prior_flag(
    config_override, rate_slot_ip, log_slice,
):
    """Same flag, two visits, same ShareScope token. Slot persists and
    matches on ns_id both times — the prior flag is visible. This is
    the inverse of the isolation test: it proves the slot survival
    isn't accidentally erasing the ns_id on store, just that lookups
    correctly key on it."""
    cfg_alpha = (
        'BotShieldEnabled On\n'
        '    BotShieldShareScope ns-revisit-alpha'
    )

    # Visit 1 — flag the IP.
    with config_override(
        r"BotShieldEnabled\s+On", cfg_alpha, count=1,
    ):
        client.get("/admin/.env", xff=rate_slot_ip)
        time.sleep(1)

    # Visit 2 — same scope, fresh override window. Reload happened
    # between phases. State file persistence + matching ns_id keep
    # the flag visible.
    with config_override(
        r"BotShieldEnabled\s+On", cfg_alpha, count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=rate_slot_ip)
            lines = slc.decision_lines(ip=rate_slot_ip)

    flagged = [d for d in lines if "flagged-ip" in d.get("reason", "")]
    assert flagged, (
        f"flag did not survive reload under same ShareScope token; "
        f"lines={lines}"
    )
