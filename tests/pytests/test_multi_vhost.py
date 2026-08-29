"""Multi-vhost reputation isolation — operator-facing scenarios.

mod_botshield gives every vhost its own reputation namespace by
default (ns_id derived from `siphash(ServerName)`); operators opt
into sharing across sibling vhosts by setting
`BotShieldShareScope <token>` to the same string on each.

The dev test rig has a single ServerName, so these tests can't
spin up a second real vhost — they use `BotShieldShareScope` token
swaps as a faithful proxy for two-vhost behavior. The token feeds
the same `siphash → ns_id` pipeline as ServerName, so swapping the
token between phases is identical at the namespace level to
swapping which vhost serves the request.

This file is the operator-pattern view; the mechanism-level tests
(directive validation, slot-survival across reloads, Bloom-filter
isolation) live in `test_namespace.py`.

What's covered here:
  - Default behavior: a flag set in one namespace does NOT carry to
    a sibling namespace (operator's "vhost A vs vhost B" scenario).
  - Opt-in sharing: when two namespaces use the same scope token
    (operator's "www and api in one cluster" scenario), a flag set
    in one IS visible in the other.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"


def _g(path: str, **kw):
    return client.get(path, ua=PASS_UA, accept_language=PASS_AL, **kw)


@pytest.mark.heavy
def test_isolation_default_per_vhost(
    config_override, rate_slot_ip, log_slice,
):
    """Operator scenario: site-a.example.com and site-b.example.com on
    one Apache instance.

    A bot trips a honeypot on site-a → gets flagged on site-a only.
    Visiting site-b from the same IP, the bot appears clean — no
    flag carries across vhosts. This is the default behavior;
    operators get per-site reputation without configuring anything.

    Test simulates two vhosts via two BotShieldShareScope token
    values. Each token hashes to a distinct ns_id; lookups under
    one token miss on entries written under the other.
    """
    # Phase A: simulate vhost site-a.example.com via scope token.
    # IP trips a honeypot path; mod_botshield sets honeypot_hit on
    # the (ip, ns_id_a) row in the flagged-IP table.
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldShareScope vhost-site-a',
        count=1,
    ):
        client.get("/admin/.env", xff=rate_slot_ip)
        time.sleep(1)  # mutex write → seqlock visible

    # Phase B: same IP visits "site-b" — different scope token,
    # different ns_id. The flagged-IP slot from phase A is still in
    # SHM (state file persists across the reload) but lookups under
    # ns_id_b miss on the ns_id mismatch.
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldShareScope vhost-site-b',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=rate_slot_ip)
            lines = slc.decision_lines(ip=rate_slot_ip)

    assert lines, f"no decision line for ip={rate_slot_ip}"
    flagged_lines = [d for d in lines
                     if "flagged-ip" in d.get("reason", "")]
    assert not flagged_lines, (
        f"per-vhost isolation broken: IP {rate_slot_ip} carried a "
        f"flagged-ip reason into the second vhost. Operator-facing "
        f"docs claim this doesn't happen; lines={lines}"
    )


@pytest.mark.heavy
def test_sharing_via_share_scope(
    config_override, rate_slot_ip, log_slice,
):
    """Operator scenario: www.example.com and api.example.com both
    set `BotShieldShareScope example-cluster` to pool reputation.

    A bot flagged on www should also appear flagged on api — the
    operator opted into one shared namespace by giving both vhosts
    the same scope token.

    Test simulates two vhosts under one shared scope by leaving the
    scope token constant across two reload cycles. Both phases
    compute the same ns_id from the same token, so the flag set in
    phase A is visible in phase B.
    """
    cfg = (
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldShareScope example-cluster'
    )

    # Phase A: simulate www.example.com under the shared scope.
    # Trip the honeypot; flag is written under ns_id(example-cluster).
    with config_override(r"BotShieldEnabled\s+On", cfg, count=1):
        client.get("/admin/.env", xff=rate_slot_ip)
        time.sleep(1)

    # Phase B: simulate api.example.com under the same shared scope.
    # Reload between phases recomputes ns_id from the unchanged token,
    # giving the same ns_id; the flagged-IP entry from phase A is
    # found and re-applied.
    with config_override(r"BotShieldEnabled\s+On", cfg, count=1):
        with log_slice as slc:
            client.get("/", xff=rate_slot_ip)
            lines = slc.decision_lines(ip=rate_slot_ip)

    flagged_lines = [d for d in lines
                     if "flagged-ip" in d.get("reason", "")]
    assert flagged_lines, (
        f"opt-in sharing broken: IP {rate_slot_ip} flagged on the "
        f"first vhost did NOT carry to the second under the same "
        f"BotShieldShareScope. Operator-facing docs claim this DOES "
        f"happen; lines={lines}"
    )
