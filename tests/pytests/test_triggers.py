"""E3 — path-based triggers.

Exercises BotShieldRule directives:

  status=<code>       → Apache returns that code; ErrorDocument
                        compatible (we don't write a body).
  respond=nochallenge         → request passes through to the real handler;
                        no BotShield interstitial; flag-IP / log
                        effects still apply for future requests.
  redirect=<url>      → 302 (or operator-chosen 3xx) + Location.
  logas=<tag>           → embedded on the existing decision log line
                        as tag="<string>" (no second emission).
  flag=<bit> ttl=<n>  → IP registered in the M5.1 flagged-IP table
                        so future requests inherit the bit's penalty.

Precedence: declaration order, first match wins. Main-scope
BotShieldRule inherits into vhosts.
"""

from __future__ import annotations

import pytest

from botshield_test import client, ips


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


# --- status=<code> ---------------------------------------------------


def test_trigger_status_code_blocks_and_tags_log(
    config_override, log_slice, fresh_ip,
):
    """respond=403 short-circuits with that code. logas=<tag> rides the
    existing decision log line as tag="<string>" — no second log line."""
    # Apache's config parser splits on whitespace; a logas= value with
    # a space must have the WHOLE key=value quoted (not just the
    # value), otherwise the splitter hands us two separate argv
    # tokens.
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule env-probe path="/.env" '
        'respond=403 "logas=BAN 2h" ttl=3600',
        count=1,
    ):
        with log_slice as slc:
            resp = client.get("/.env", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 403
    hits = [d for d in lines if "requesttrigger:env-probe" in d["reason"]]
    assert hits, f"no requesttrigger:env-probe decision line; lines={lines}"
    # The tag rides the existing decision log line — decision_lines
    # should pick it up as the "tag" field.
    assert any(d.get("tag") == "BAN 2h" for d in hits), (
        f"no tag=\"BAN 2h\" on decision line; hits={hits}"
    )


# --- respond=nochallenge -----------------------------------------------------


def test_trigger_status_pass_lets_request_through(
    config_override, log_slice, fresh_ip,
):
    """respond=nochallenge returns DECLINED from the handler — the real
    Apache server serves the response (probably a 404 for a non-
    existent path). No BotShield 403/captcha/etc."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule pass-probe path="/definitely-nonexistent" '
        'respond=nochallenge',
        count=1,
    ):
        resp = client.get("/definitely-nonexistent", xff=fresh_ip)
    # Real handler's response — not 403. Typically 404 (Apache's
    # default) or whatever the dev vhost serves.
    assert resp.status_code != 403, (
        f"respond=nochallenge must not 403; got {resp.status_code}"
    )


def test_trigger_status_pass_penalty_scores_the_current_request(
    config_override, log_slice, fresh_ip,
):
    """`respond=nochallenge penalty=N` adds N to THIS request's score.

    This test used to pin the opposite -- that the penalty was purely
    future-request bookkeeping via flag=/ttl= and must never touch the
    current score. That contract was deliberately revised in 14ec15a
    ("Let request triggers challenge"), which routes respond=nochallenge with
    score-shaping through the scoring pipeline rather than declining
    out of the handler, and directives.md documents the current
    behaviour: "Score only | respond=nochallenge penalty=<n> | Adds to the
    score and lets normal thresholds decide."

    The old assertion outlived the change and sat in the failing set
    long enough to be treated as background noise, which is the real
    hazard: a stale pin and a genuine regression look identical from
    the summary line.

    Measured as a difference between two penalties rather than
    against an absolute, because the ambient dev config contributes
    its own signals and a fixed number would be brittle.

    Both arms carry a penalty on purpose. Comparing "penalty" against
    "no penalty" measures the wrong thing entirely: a bare respond=nochallenge
    declines out of the handler before the scoring pipeline runs, so
    its reason chain comes back bracketed and zeroed
    ([knownbot:...:0,requesttrigger:passpen:pass:0]) while the
    penalty arm additionally picks up missingacceptlanguage,
    scraperua-python, firstsightip and any flag triggers. The
    difference there is the whole pipeline, not the penalty.
    """
    RULE = ('    BotShieldRule passpen path="/honey-pass" '
            'respond=nochallenge %s ttl=3600')

    def score_for(extra, ip):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldScoreNonInteractive 500\n'
            '    BotShieldScoreInteractive 600\n'
            '    BotShieldScoreCaptcha 700\n'
            + (RULE % extra),
            count=1,
        ):
            with log_slice as slc:
                client.get("/honey-pass", xff=ip)
                lines = slc.decision_lines(ip=ip)
        assert lines, f"no decision line for the passpen match; extra={extra!r}"
        return lines[-1]

    low  = score_for("penalty=10", fresh_ip)
    high = score_for("penalty=90", ips.fresh_ip())

    assert "requesttrigger:passpen" in high["reason"], (
        f"the match must be traceable in the reason chain; d={high}"
    )
    delta = int(high["score"]) - int(low["score"])
    assert delta == 80, (
        f"raising penalty 10 -> 90 must move the current request's "
        f"score by exactly 80; got {delta} "
        f"({low['score']} -> {high['score']})\n"
        f"  low:  {low['reason']!r}\n"
        f"  high: {high['reason']!r}"
    )


# --- redirect= -------------------------------------------------------


def test_trigger_redirect_sets_location(
    config_override, log_slice, fresh_ip,
):
    """redirect=<url> implies 302 and sets the Location header.
    Request must return 302 (httpx sees allow_redirects=False by
    default on our client, or we check status + header)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule env-redirect path="/.env.redir" '
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
    """Explicit respond=301 sets a permanent redirect."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule env-redirect path="/.env.perm" '
        'redirect=https://example.org/gone respond=301',
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule wp-ajax path="/wp-admin/admin-ajax.php" respond=nochallenge\n'
        '    BotShieldRule wp-all  path="/wp-admin*"               respond=403',
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
    """BotShieldRule declared outside <VirtualHost> must flow
    into the vhost via bs_merge_server_cfg — same guarantee the
    other E2.x directives got."""
    with config_override(
        r"BotShieldStateSaveInterval\s+\d+",
        'BotShieldRule main-scope-trap path="/main-scope-env" '
        'respond=403 logas="MAIN"\n'
        'BotShieldStateSaveInterval 30',
        count=1,
    ):
        resp = client.get("/main-scope-env", xff=fresh_ip)
    assert resp.status_code == 403, (
        "main-scope BotShieldRule did not inherit into the vhost"
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule bait path="/honey-bait" '
        'respond=nochallenge flag=honeypot_hit ttl=3600',
        count=1,
    ):
        # First request primes the flagged-IP table.
        client.get("/honey-bait", xff=fresh_ip)
        # Second request from same IP to an innocent path.
        with log_slice as slc:
            client.get("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    # The flag-IP contribution shows up on the follow-up request as
    # a `flaggedip` reason token. honeypot_hit contributes +60 to
    # bs_flag_penalty, which surfaces in the request's reason trace.
    follow_up = [d for d in lines if d.get("path") == "/"]
    assert follow_up, f"no decision line for follow-up request; lines={lines}"
    assert any("flaggedip" in d["reason"] for d in follow_up), (
        f"follow-up request didn't show flaggedip in reason; "
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule api-admin path="/api/*/admin" respond=403',
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
               if "requesttrigger:api-admin" in d["reason"]) >= 2, (
        f"expected two requesttrigger:api-admin decisions; lines={lines}"
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule api-admin-end path="/api/*/admin$" respond=403',
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
                 if "requesttrigger:api-admin-end" in d["reason"]]
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreNonInteractive 500\n'
        '    BotShieldScoreInteractive 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRule middle-warn path="/foo*bar" respond=403',
        count=1,
    ):
        pass

    tail = subprocess.run(
        ["sudo", "tail", "-c", f"+{before + 1}", APACHE_ERROR_LOG],
        capture_output=True, text=True, check=True,
    ).stdout

    assert "BotShieldRule 'middle-warn'" in tail and \
           "non-trailing '*'" in tail, (
        "expected a NOTICE about non-trailing '*' on config load; "
        f"main-log tail: {tail!r}"
    )


# --- Retired one-line form ------------------------------------------

def test_flat_trigger_form_is_rejected(config_override):
    """The `key=value` one-liner is retired; only blocks parse.

    Worth its own test because the rest of the suite cannot notice.
    Tests still *write* the compact spelling and the harness renders
    it to a block before Apache sees it, so every other case here
    would keep passing if the flat form quietly came back.

    render=False is load-bearing: without it the harness would
    convert this test's input to a block and the test would pass
    whether or not the module still accepted the retired spelling.
    """
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            '    BotShieldRule oldform path="/retired" respond=403',
            render=False,
        ):
            pass
    msg = str(exc_info.value)
    assert "returned non-zero exit status" in msg or "retired" in msg, (
        f"expected the flat trigger form to be refused; got: {msg!r}"
    )


def test_deprecated_requesttrigger_spelling_still_parses(
    config_override, fresh_ip,
):
    """<BotShieldRequestTrigger> is the old spelling of <BotShieldRule>.

    It warns at config time and keeps working. A config error is fatal
    to httpd and the name is still in live configs, so removing it
    outright would take a site down at its next restart rather than
    announce a rename. BotShieldPathTrigger was retired the same way --
    renamed first, removed nine days later.

    render=False is load-bearing for the same reason it is on the flat
    -form test: the block is written out here exactly as an operator
    would write it, so the module is what gets tested rather than the
    harness renderer.

    When the name is finally removed, this becomes its rejection test:
    flip it to expect a failure naming BotShieldRule.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRequestTrigger legacy-spelling>\n"
        "        BotShieldPath      /legacy-spelling-probe\n"
        "        BotShieldRespond    404\n"
        "    </BotShieldRequestTrigger>",
        render=False,
        count=1,
    ):
        resp = client.get("/legacy-spelling-probe", xff=fresh_ip)
        assert resp.status_code == 404, (
            "the deprecated spelling must keep working until it is "
            f"removed; got {resp.status_code}"
        )


def test_deprecated_status_spelling_still_parses(config_override, fresh_ip):
    """BotShieldStatus is the old spelling of BotShieldRespond.

    Warns at config time and keeps working, on the same
    deprecate-then-remove schedule as the directive rename: the name is
    in live configs -- twenty-four times in the one on qubeshub.org --
    and a config error is fatal to httpd.

    render=False so the block reaches Apache exactly as written, which
    is the only way the module rather than the harness is under test.
    When the spelling is removed this inverts into its rejection test.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule legacy-status>\n"
        "        BotShieldPath      /legacy-status-probe\n"
        "        BotShieldStatus    404\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = client.get("/legacy-status-probe", xff=fresh_ip)
        assert resp.status_code == 404, (
            "the deprecated spelling must keep working until it is "
            f"removed; got {resp.status_code}"
        )


def test_respond_is_the_canonical_spelling(config_override, fresh_ip):
    """BotShieldRespond does what BotShieldStatus did.

    Written as a block rather than the compact form so this test proves
    the directive name resolves through bs_section_key, which is the
    part a rename can break.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule respond-spelling>\n"
        "        BotShieldPath      /respond-spelling-probe\n"
        "        BotShieldRespond   404\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = client.get("/respond-spelling-probe", xff=fresh_ip)
        assert resp.status_code == 404, (
            f"BotShieldRespond should return the rule status; got "
            f"{resp.status_code}"
        )
