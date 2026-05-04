"""E2.1 — policy enforcement (rate limit + path block).

Exercises the two cohort-conditional surfaces:

  BotShieldRateLimit <name> <budget> <per> <ua> <ipspec>
  BotShieldPathTrigger <name> <path-glob> [ua=...] [ipspec=...] status=403

The legacy `BotShieldBlockPath` directive was retired in favor of a
PathTrigger with `status=403` plus optional `ua=`/`ipspec=` match
keys. Cohort shape still reuses E1 (UA substring + polymorphic
ipspec). '*' means "any" on either axis; both-'*' is rejected at
config time. On trip, rate-limit → 429 + Retry-After +
rate-limit-exceeded:<name>; path-trigger → status + path-trigger:<name>.
"""

from __future__ import annotations

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


CORP_UA = "CorpBot/2.0 (+https://corp.example/bot)"


# --- Rate limit ------------------------------------------------------


def test_rate_limit_ua_narrowing(config_override, log_slice, fresh_ip):
    """UA-matched cohort with '*' ipspec. Budget=3 / 60sec. The 4th
    request of the window should fire 429 + Retry-After + the
    rate-limit-exceeded reason."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRateLimit corpbot 3 sec "CorpBot" *',
        count=1,
    ):
        with log_slice as slc:
            responses = [
                client.get("/", xff=fresh_ip, ua=CORP_UA)
                for _ in range(5)
            ]
            lines = slc.decision_lines(ip=fresh_ip)

    codes = [r.status_code for r in responses]
    assert codes[:3] == [200, 200, 200], f"budget admits first 3; got {codes}"
    assert 429 in codes[3:], f"expected 429 after budget; got {codes}"
    # Retry-After must be set on at least one 429 response.
    ras = [r.headers.get("Retry-After") for r in responses if r.status_code == 429]
    assert ras and all(ra and ra.isdigit() for ra in ras), (
        f"Retry-After missing or non-numeric: {ras}"
    )

    tripped = [d for d in lines if "rate-limit-exceeded:corpbot" in d["reason"]]
    assert tripped, f"no rate-limit-exceeded line; lines={lines}"


def test_rate_limit_inline_cidr_narrowing(config_override, log_slice, fresh_ip):
    """Cohort restricts on IP only: UA='*' + inline CIDR containing the
    test IP. Out-of-range IPs must NOT consume the budget."""
    in_range_ip = "198.51.100.99"
    ua = "AnyBrowser/1.0"

    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRateLimit dcblock 2 sec * "198.51.100.0/24"',
        count=1,
    ):
        # Hit from an out-of-range IP — should not trip no matter how many.
        for _ in range(5):
            r = client.get("/", xff=fresh_ip, ua=ua)
            assert r.status_code == 200, (
                "out-of-range IP shouldn't trip IP-narrowed cohort"
            )

        with log_slice as slc:
            responses = [
                client.get("/", xff=in_range_ip, ua=ua)
                for _ in range(4)
            ]
            lines = slc.decision_lines(ip=in_range_ip)

    codes = [r.status_code for r in responses]
    assert codes[:2] == [200, 200], f"budget admits first 2; got {codes}"
    assert 429 in codes[2:], f"expected 429 after budget; got {codes}"
    assert [d for d in lines
            if "rate-limit-exceeded:dcblock" in d["reason"]], (
        f"no rate-limit-exceeded line for dcblock; lines={lines}"
    )


def test_rate_limit_ua_and_ip_and_ed(config_override, log_slice, fresh_ip):
    """Cohort restricts on BOTH UA and IP. A request matching only one
    axis must not consume the budget."""
    matched_ip = "203.0.113.77"
    ua_match = "Scraper/1.0"
    ua_miss  = "OtherClient/1.0"

    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRateLimit pair 1 sec "Scraper/" "203.0.113.0/24"',
        count=1,
    ):
        # UA miss from matching IP → must not trip.
        for _ in range(3):
            r = client.get("/", xff=matched_ip, ua=ua_miss)
            assert r.status_code == 200
        # IP miss with matching UA → must not trip.
        for _ in range(3):
            r = client.get("/", xff=fresh_ip, ua=ua_match)
            assert r.status_code == 200

        with log_slice as slc:
            r1 = client.get("/", xff=matched_ip, ua=ua_match)
            r2 = client.get("/", xff=matched_ip, ua=ua_match)
            lines = slc.decision_lines(ip=matched_ip)

    assert r1.status_code != 403, "first matching request admitted"
    assert r2.status_code == 429, "second matching request rate-limited"
    assert [d for d in lines
            if "rate-limit-exceeded:pair" in d["reason"]]


# --- PathTrigger as path-block (BlockPath replacement) --------------


def test_path_trigger_block_prefix_match(config_override, log_slice, fresh_ip):
    """Plain prefix: `/admin` matches `/admin/foo` as well as `/admin`."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger lockdown "/admin" ua="Scraper/" status=403',
        count=1,
    ):
        with log_slice as slc:
            r_root = client.get("/admin",     xff=fresh_ip, ua="Scraper/1.0")
            r_sub  = client.get("/admin/foo", xff=fresh_ip, ua="Scraper/1.0")
            r_safe = client.get("/public",    xff=fresh_ip, ua="Scraper/1.0")
            lines = slc.decision_lines(ip=fresh_ip)

    assert r_root.status_code == 403
    assert r_sub.status_code  == 403
    assert r_safe.status_code != 403, "non-matching path should not 403"
    hits = [d for d in lines if "path-trigger:lockdown" in d["reason"]]
    assert len(hits) == 2, f"expected 2 path-trigger hits; got {hits}"


def test_path_trigger_block_end_anchor(config_override, log_slice, fresh_ip):
    """Trailing `$` anchors to exact equality: `/exact$` matches only
    `/exact`, not `/exact/sub`."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger exact "/exact$" ua="Scraper/" status=403',
        count=1,
    ):
        r_exact = client.get("/exact",     xff=fresh_ip, ua="Scraper/1.0")
        r_sub   = client.get("/exact/sub", xff=fresh_ip, ua="Scraper/1.0")

    assert r_exact.status_code == 403, "exact-anchored match should 403"
    assert r_sub.status_code != 403, "anchored pattern shouldn't cover subpath"


def test_path_trigger_cohort_narrowing(config_override, log_slice, fresh_ip):
    """A path-trigger with a `ua=` predicate must NOT fire when the UA
    doesn't match — cohort narrowing applies to path triggers too."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger scrapersonly "/wp-admin" ua="Scraper/" status=403',
        count=1,
    ):
        r_scrap = client.get("/wp-admin", xff=fresh_ip, ua="Scraper/1.0")
        r_real  = client.get("/wp-admin", xff=fresh_ip,
                             ua="Mozilla/5.0 Firefox/130.0")

    assert r_scrap.status_code == 403
    assert r_real.status_code != 403, (
        "real-browser UA should pass narrower cohort"
    )


# --- Regression tests for review findings ---------------------------


def test_rate_limit_ua_match_is_case_insensitive(
    config_override, log_slice, fresh_ip,
):
    """Directive contract documents UA matching as case-insensitive.
    Configure a lowercase pattern, send a mixed-case UA, expect the
    cohort to match and trip the rate limit."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldRateLimit gptbot 1 sec "gptbot" *',
        count=1,
    ):
        with log_slice as slc:
            r1 = client.get("/", xff=fresh_ip, ua="GPTBot/1.0")
            r2 = client.get("/", xff=fresh_ip, ua="GPTBot/1.0")
            lines = slc.decision_lines(ip=fresh_ip)

    assert r1.status_code != 403, "first request admitted"
    assert r2.status_code == 429, (
        "mixed-case UA should match lowercase pattern; "
        "regression indicates strstr vs strcasestr bug"
    )
    assert [d for d in lines
            if "rate-limit-exceeded:gptbot" in d["reason"]], (
        f"no rate-limit-exceeded line; lines={lines}"
    )


def test_path_trigger_precedence_is_declaration_order(
    config_override, log_slice, fresh_ip,
):
    """Overlapping BotShieldPathTrigger rules must resolve by declaration
    order, not by hash-iteration chance. A specific `/admin/secret`
    rule declared FIRST should win when both it and a generic
    `/admin*` rule match."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldScoreSilent 500\n'
        '    BotShieldScoreHard 600\n'
        '    BotShieldScoreCaptcha 700\n'
        '    BotShieldPathTrigger specific "/admin/secret" ua="Scraper/" status=403\n'
        '    BotShieldPathTrigger generic  "/admin*"       ua="Scraper/" status=403',
        count=1,
    ):
        with log_slice as slc:
            r_secret = client.get("/admin/secret", xff=fresh_ip,
                                  ua="Scraper/1.0")
            r_other  = client.get("/admin/other",  xff=fresh_ip,
                                  ua="Scraper/1.0")
            lines = slc.decision_lines(ip=fresh_ip)

    assert r_secret.status_code == 403
    assert r_other.status_code  == 403

    specific_hits = [d for d in lines
                     if "path-trigger:specific" in d["reason"]]
    generic_hits  = [d for d in lines
                     if "path-trigger:generic"  in d["reason"]]
    assert len(specific_hits) == 1, (
        f"/admin/secret should hit the specific rule (declared first); "
        f"specific_hits={specific_hits}"
    )
    assert len(generic_hits) == 1, (
        f"/admin/other should fall through to generic; "
        f"generic_hits={generic_hits}"
    )


# --- Metrics ---------------------------------------------------------


def test_policy_metrics_present():
    """Sanity: /metrics exposes the rate-limit counter."""
    resp = client.get("/botshield/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert "botshield_rate_limit_exceeded_total" in body
