"""E3 — path-based triggers.

Exercises BotShieldPathTrigger directives:

  status=<code>       → Apache returns that code; ErrorDocument
                        compatible (we don't write a body).
  status=pass         → request passes through to the real handler;
                        no BotShield interstitial; flag-IP / log
                        effects still apply for future requests.
  redirect=<url>      → 302 (or operator-chosen 3xx) + Location.
  log=<tag>           → embedded on the existing decision log line
                        as tag="<string>" (no second emission).
  flag=<bit> ttl=<n>  → IP registered in the M5.1 flagged-IP table
                        so future requests inherit the bit's penalty.

Precedence: declaration order, first match wins. Main-scope
BotShieldPathTrigger inherits into vhosts.
"""

from __future__ import annotations

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


# --- status=<code> ---------------------------------------------------


def test_trigger_status_code_blocks_and_tags_log(
    config_override, log_slice, fresh_ip,
):
    """status=403 short-circuits with that code. log=<tag> rides the
    existing decision log line as tag="<string>" — no second log line."""
    # Apache's config parser splits on whitespace; a log= value with
    # a space must have the WHOLE key=value quoted (not just the
    # value), otherwise the splitter hands us two separate argv
    # tokens.
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger env-probe "/.env" '
        'status=403 "log=BAN 2h" ttl=3600',
        count=1,
    ):
        with log_slice as slc:
            resp = client.get("/.env", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 403
    hits = [d for d in lines if "path-trigger:env-probe" in d["reason"]]
    assert hits, f"no path-trigger:env-probe decision line; lines={lines}"
    # The tag rides the existing decision log line — decision_lines
    # should pick it up as the "tag" field.
    assert any(d.get("tag") == "BAN 2h" for d in hits), (
        f"no tag=\"BAN 2h\" on decision line; hits={hits}"
    )


# --- status=pass -----------------------------------------------------


def test_trigger_status_pass_lets_request_through(
    config_override, log_slice, fresh_ip,
):
    """status=pass returns DECLINED from the handler — the real
    Apache server serves the response (probably a 404 for a non-
    existent path). No BotShield 403/captcha/etc."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger pass-probe "/definitely-nonexistent" '
        'status=pass',
        count=1,
    ):
        resp = client.get("/definitely-nonexistent", xff=fresh_ip)
    # Real handler's response — not 403. Typically 404 (Apache's
    # default) or whatever the dev vhost serves.
    assert resp.status_code != 403, (
        f"status=pass must not 403; got {resp.status_code}"
    )


# --- redirect= -------------------------------------------------------


def test_trigger_redirect_sets_location(
    config_override, log_slice, fresh_ip,
):
    """redirect=<url> implies 302 and sets the Location header.
    Request must return 302 (httpx sees allow_redirects=False by
    default on our client, or we check status + header)."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger env-redirect "/.env.redir" '
        'redirect=https://example.org/gone',
        count=1,
    ):
        resp = client.get("/.env.redir", xff=fresh_ip,
                          follow_redirects=False)

    assert resp.status_code == 302
    assert resp.headers.get("Location") == "https://example.org/gone"


def test_trigger_redirect_honors_explicit_status(
    config_override, log_slice, fresh_ip,
):
    """Explicit status=301 sets a permanent redirect."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger env-redirect "/.env.perm" '
        'redirect=https://example.org/gone status=301',
        count=1,
    ):
        resp = client.get("/.env.perm", xff=fresh_ip,
                          follow_redirects=False)
    assert resp.status_code == 301


# --- Precedence -------------------------------------------------------


def test_trigger_declaration_order_wins_on_overlap(
    config_override, log_slice, fresh_ip,
):
    """Specific rule declared BEFORE generic must win on paths
    matched by both. /wp-admin/admin-ajax.php matches both the
    specific pass rule and the generic 403 rule — specific wins."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger wp-ajax "/wp-admin/admin-ajax.php" status=pass\n'
        '    BotShieldPathTrigger wp-all  "/wp-admin*"               status=403',
        count=1,
    ):
        r_ajax  = client.get("/wp-admin/admin-ajax.php", xff=fresh_ip)
        r_other = client.get("/wp-admin/login.php",      xff=fresh_ip)

    assert r_ajax.status_code != 403, (
        "specific-first wp-ajax pass rule must shadow the generic 403"
    )
    assert r_other.status_code == 403, (
        "non-ajax paths should fall through to the generic 403 rule"
    )


# --- Main-scope inheritance ------------------------------------------


def test_trigger_main_scope_inherits_into_vhost(
    config_override, log_slice, fresh_ip,
):
    """BotShieldPathTrigger declared outside <VirtualHost> must flow
    into the vhost via bs_merge_server_cfg — same guarantee the
    other E2.x directives got."""
    with config_override(
        r"BotShieldStateFile\s+\S+",
        'BotShieldPathTrigger main-scope-trap "/main-scope-env" '
        'status=403 log="MAIN"\n'
        'BotShieldStateFile /var/lib/botshield/state.bin',
        count=1,
    ):
        resp = client.get("/main-scope-env", xff=fresh_ip)
    assert resp.status_code == 403, (
        "main-scope BotShieldPathTrigger did not inherit into the vhost"
    )


# --- flag + ttl across requests --------------------------------------


def test_trigger_flag_ip_carries_to_next_request(
    config_override, log_slice, fresh_ip,
):
    """First request to the trap flags the IP. A subsequent request
    from the same IP to an innocent path should carry the extra
    score from the flagged-IP table, even though the second request
    doesn't hit any trigger.

    We use honeypot_hit (+60 on future requests) so the subsequent
    request's decision line carries flagged_bits=0x1 (honeypot_hit).
    """
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger bait "/honey-bait" '
        'status=pass flag=honeypot_hit ttl=3600',
        count=1,
    ):
        # First request primes the flagged-IP table.
        client.get("/honey-bait", xff=fresh_ip)
        # Second request from same IP to an innocent path.
        with log_slice as slc:
            client.get("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    # The flag-IP contribution shows up on the follow-up request as
    # a `flagged-ip` reason token. honeypot_hit contributes +60 to
    # bs_flag_penalty, which surfaces in the request's reason trace.
    follow_up = [d for d in lines if d.get("path") == "/"]
    assert follow_up, f"no decision line for follow-up request; lines={lines}"
    assert any("flagged-ip" in d["reason"] for d in follow_up), (
        f"follow-up request didn't show flagged-ip in reason; "
        f"follow_up={follow_up}"
    )
