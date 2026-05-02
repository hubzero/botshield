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
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
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
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
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


def test_trigger_status_pass_does_not_apply_current_request_penalty(
    config_override, log_slice, fresh_ip,
):
    """Path-family divergence from cookie/env: status=pass means
    'don't enforce anything on this request.' Even if the operator
    wrote penalty=N, that penalty must NOT bump the current
    request's score — it's purely future-request bookkeeping
    via flag=/ttl=. Pinned here so E7.2's shared action engine
    can't silently homogenize this with cookie/env semantics."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger passpen "/honey-pass" '
        'status=pass penalty=90 flag=honeypot_hit ttl=3600',
        count=1,
    ):
        with log_slice as slc:
            client.get("/honey-pass", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)
    assert lines, f"no decision line for the passpen match; lines={lines}"
    d = lines[-1]
    # Reason trace records the match with the :pass suffix so
    # operators can correlate, but the score delta is 0 — not 90.
    assert "path-trigger:passpen:pass" in d["reason"], (
        f"path-trigger:passpen:pass missing from reason; d={d}"
    )
    # Score the decision logs should only carry first-sight-ip (+5)
    # and whatever clean-UA signals pile up — NEVER the +90 penalty.
    score = int(d["score"])
    assert score < 60, (
        f"path-trigger status=pass leaked the penalty=90 bump into "
        f"the current request's score; reason={d['reason']} score={score}"
    )


# --- redirect= -------------------------------------------------------


def test_trigger_redirect_sets_location(
    config_override, log_slice, fresh_ip,
):
    """redirect=<url> implies 302 and sets the Location header.
    Request must return 302 (httpx sees allow_redirects=False by
    default on our client, or we check status + header)."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
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
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
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
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
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
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
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


# --- RFC 9309 path matching: middle-`*` patterns -------------------
#
# After consolidating onto the RFC 9309 matcher (was: a v1 placeholder
# in botshield.c that treated middle '*' as a literal byte), '*'
# in non-trailing position is a proper wildcard.

def test_path_trigger_middle_star_matches_segment(
    config_override, log_slice, fresh_ip,
):
    """`/api/*/admin` matches `/api/v1/admin` and `/api/internal/admin`
    via the RFC 9309 matcher's middle-wildcard semantics."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger api-admin "/api/*/admin" status=403',
        count=1,
    ):
        with log_slice as slc:
            r1 = client.get("/api/v1/admin", xff=fresh_ip)
            r2 = client.get("/api/internal/admin", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r1.status_code == 403, (
        f"middle-* didn't match /api/v1/admin; got {r1.status_code}"
    )
    assert r2.status_code == 403, (
        f"middle-* didn't match /api/internal/admin; got {r2.status_code}"
    )
    assert sum(1 for d in lines
               if "path-trigger:api-admin" in d["reason"]) >= 2, (
        f"expected two path-trigger:api-admin decisions; lines={lines}"
    )


def test_path_trigger_middle_star_anchored_excludes_suffix(
    config_override, log_slice,
):
    """`/api/*/admin$` matches `/api/v1/admin` but NOT
    `/api/v1/admin/foo` — the trailing $ anchors to end-of-path
    even when '*' appears mid-pattern. Uses two different fresh
    IPs so any reputation-side-effect on the matched request
    doesn't carry forward into the suffix-beyond-anchor request."""
    from botshield_test import ips as _ips
    ip_match = _ips.fresh_ip()
    ip_after = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger api-admin-end "/api/*/admin$" status=403',
        count=1,
    ):
        with log_slice as slc:
            r_match  = client.get("/api/v1/admin",     xff=ip_match)
            r_after  = client.get("/api/v1/admin/foo", xff=ip_after)
            lines = slc.decision_lines()

    assert r_match.status_code == 403, (
        f"middle-*-with-$ anchor didn't match /api/v1/admin; "
        f"got {r_match.status_code}"
    )
    assert r_after.status_code != 403, (
        f"middle-*-with-$ anchor must NOT match /api/v1/admin/foo "
        f"(suffix beyond anchor); got {r_after.status_code}"
    )
    triggered = [d for d in lines
                 if "path-trigger:api-admin-end" in d["reason"]]
    assert len(triggered) == 1, (
        f"expected exactly one trigger fire (the /admin path); "
        f"lines={lines}"
    )


def test_path_trigger_middle_star_emits_notice_on_config_load(
    config_override,
):
    """Operators who write a non-trailing '*' get a NOTICE on config
    load explaining that the matcher interprets it per RFC 9309. The
    placeholder matcher used to treat middle '*' as a literal byte;
    this warning surfaces the behavior change so a typo doesn't
    silently start matching paths the operator didn't intend.

    During directive parsing the vhost's ErrorLog isn't applied
    yet, so the NOTICE lands in the main Apache error log rather
    than the vhost-specific log_slice surface. Read the main log
    directly via sudo tail."""
    import subprocess
    from botshield_test.config import APACHE_ERROR_LOG

    # Snapshot the main log size before, then look at everything
    # after this offset for our NOTICE.
    before = int(subprocess.run(
        ["sudo", "stat", "-c", "%s", APACHE_ERROR_LOG],
        capture_output=True, text=True, check=True,
    ).stdout.strip())

    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger middle-warn "/foo*bar" status=403',
        count=1,
    ):
        pass

    tail = subprocess.run(
        ["sudo", "tail", "-c", f"+{before + 1}", APACHE_ERROR_LOG],
        capture_output=True, text=True, check=True,
    ).stdout

    assert "BotShieldPathTrigger 'middle-warn'" in tail and \
           "non-trailing '*'" in tail, (
        "expected a NOTICE about non-trailing '*' on config load; "
        f"main-log tail: {tail!r}"
    )
