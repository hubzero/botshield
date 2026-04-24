"""E4 — cookie triggers.

Parallel family to E3 path triggers, matched on cookies instead of
paths. Tests cover the predicate surface (named presence / value /
absence / bulk state / bs-cookie state) and the action surface
(credit / penalty / status / log / flag / ttl).

Key semantic divergence from E3 that MUST be asserted explicitly:
cookie triggers apply credit/penalty under `status=pass`, because
cookies are ongoing-state signals the client carries on THIS
request. Path triggers leave the score alone under pass.
"""

from __future__ import annotations

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


# --- Named-cookie predicates -----------------------------------------


def test_cookie_trigger_named_present_applies_credit(
    config_override, log_slice, request,
):
    """cookie=<name> fires on presence; credit reduces this request's
    score even though status=pass (divergence from E3).

    log_slice is a one-shot context manager so we issue both
    requests inside a single slice and distinguish them by the
    separate IPs we use — one baseline, one with the cookie."""
    # Allocate two distinct IPs up front (fresh_ip is a fixture
    # that mints one; we need two.)
    from botshield_test import ips as _ips
    ip_base = _ips.fresh_ip()
    ip_with = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger app-session cookie=PHPSESSID credit=15',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=ip_base)
            client.get("/", xff=ip_with,
                       cookies={"PHPSESSID": "deadbeef"})
            baseline   = slc.decision_lines(ip=ip_base)
            withcookie = slc.decision_lines(ip=ip_with)

    assert baseline, "no baseline decision line"
    assert withcookie, "no with-cookie decision line"
    base_score = int(baseline[-1]["score"])
    cookie_score = int(withcookie[-1]["score"])
    assert cookie_score == base_score - 15, (
        f"credit=15 should reduce score by 15 under status=pass; "
        f"baseline={base_score} cookie={cookie_score}"
    )
    # Reason string should tag the cookie trigger.
    assert any("cookie-trigger:app-session" in d["reason"]
               for d in withcookie), f"lines={withcookie}"


def test_cookie_trigger_named_eq_value_blocks(
    config_override, log_slice, fresh_ip,
):
    """cookie=<name>=<value> fires on exact value — simulate a
    known-bad token that should immediately 403."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger stale-token '
        'cookie=api_token=LEAKED_HEX '
        'status=403 flag=honeypot_hit ttl=3600',
        count=1,
    ):
        r_hit  = client.get("/", xff=fresh_ip,
                            cookies={"api_token": "LEAKED_HEX"})
        r_ok   = client.get("/", xff=fresh_ip,
                            cookies={"api_token": "legit-value"})

    assert r_hit.status_code == 403
    assert r_ok.status_code  != 403


def test_cookie_trigger_named_contains_substring(
    config_override, log_slice, fresh_ip,
):
    """cookie=<name>~<substr> fires when the value contains the
    substring anywhere."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger bait-signup '
        'cookie=signup_tmp~BAIT-HEX status=403',
        count=1,
    ):
        r_hit = client.get("/", xff=fresh_ip,
                           cookies={"signup_tmp": "xyz-BAIT-HEX-abc"})
        r_ok  = client.get("/", xff=fresh_ip,
                           cookies={"signup_tmp": "legit"})

    assert r_hit.status_code == 403
    assert r_ok.status_code != 403


def test_cookie_trigger_named_absent_fires(
    config_override, log_slice, fresh_ip,
):
    """!cookie=<name> fires when the cookie is missing."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger missing-csrf '
        '!cookie=csrf_token status=403',
        count=1,
    ):
        r_missing = client.get("/", xff=fresh_ip)  # no cookies
        r_present = client.get("/", xff=fresh_ip,
                               cookies={"csrf_token": "abc"})

    assert r_missing.status_code == 403
    assert r_present.status_code != 403


# --- Bulk-state predicates -------------------------------------------


def test_cookie_trigger_cookies_none(
    config_override, log_slice, fresh_ip,
):
    """cookies=none fires when the request carries zero cookies."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger no-cookies cookies=none status=403',
        count=1,
    ):
        r_none = client.get("/", xff=fresh_ip)
        r_any  = client.get("/", xff=fresh_ip, cookies={"foo": "bar"})

    assert r_none.status_code == 403
    assert r_any.status_code  != 403


def test_cookie_trigger_cookies_session_matches_curated_name(
    config_override, log_slice, fresh_ip,
):
    """cookies=session matches any cookie whose name is on the
    curated list (PHPSESSID, JSESSIONID, etc.). Unknown cookie
    names don't match."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger any-session cookies=session status=403',
        count=1,
    ):
        r_php  = client.get("/", xff=fresh_ip,
                            cookies={"PHPSESSID": "x"})
        r_jv   = client.get("/", xff=fresh_ip,
                            cookies={"JSESSIONID": "x"})
        r_other = client.get("/", xff=fresh_ip,
                             cookies={"my_token": "x"})

    assert r_php.status_code == 403
    assert r_jv.status_code  == 403
    assert r_other.status_code != 403


def test_cookie_trigger_session_name_directive_extends_list(
    config_override, log_slice, fresh_ip,
):
    """BotShieldSessionCookieName adds to the session list so
    cookies=session fires on the operator's custom name."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldSessionCookieName my_custom_session\n'
        '    BotShieldCookieTrigger any-session '
        'cookies=session status=403',
        count=1,
    ):
        r_match = client.get("/", xff=fresh_ip,
                             cookies={"my_custom_session": "x"})
    assert r_match.status_code == 403


# --- bs-cookie state -------------------------------------------------


def test_cookie_trigger_bs_cookie_missing(
    config_override, log_slice, fresh_ip,
):
    """bs-cookie=missing fires when no _bs_verified cookie present —
    the most common case (first-sight visitor)."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger fresh bs-cookie=missing status=403',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip)
    assert r.status_code == 403


def test_cookie_trigger_bs_cookie_invalid(
    config_override, log_slice, fresh_ip,
):
    """bs-cookie=invalid fires when _bs_verified is present but
    fails verification (tampered HMAC, wrong format, etc.)."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger bad-bs bs-cookie=invalid status=403',
        count=1,
    ):
        # Send a garbage _bs_verified cookie — fails signature check.
        r = client.get("/", xff=fresh_ip,
                       cookies={"_bs_verified": "obviously-bogus"})
    assert r.status_code == 403


# --- status=pass divergence from E3 ----------------------------------


def test_cookie_trigger_status_pass_still_applies_credit(
    config_override, log_slice,
):
    """DIVERGENCE FROM E3: cookie triggers under status=pass still
    apply credit/penalty to THIS request (E3 path triggers ignore
    penalty under pass). This test guards that behavior — changing
    it silently would break the E4 reputation model.

    Strategy: compare two requests (distinct IPs, same everything
    else) with and without the cookie. Score must differ by the
    credit amount regardless of baseline heuristics."""
    from botshield_test import ips as _ips
    ip_base = _ips.fresh_ip()
    ip_with = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger ghost cookie=PHPSESSID '
        'status=pass credit=20',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=ip_base)
            client.get("/", xff=ip_with, cookies={"PHPSESSID": "x"})
            base_lines = slc.decision_lines(ip=ip_base)
            with_lines = slc.decision_lines(ip=ip_with)

    assert base_lines and with_lines
    hits = [d for d in with_lines if "cookie-trigger:ghost" in d["reason"]]
    assert hits, f"no cookie-trigger:ghost decision line; lines={with_lines}"
    base_score = int(base_lines[-1]["score"])
    with_score = int(with_lines[-1]["score"])
    assert with_score == base_score - 20, (
        f"credit=20 must shift the score by exactly -20 under "
        f"status=pass; baseline={base_score} with-cookie={with_score}"
    )


# --- Precedence: pass accumulates, non-pass short-circuits -----------


def test_cookie_trigger_pass_triggers_stack_credits(
    config_override, log_slice,
):
    """When two status=pass triggers both match (e.g. a client
    carries both a session cookie and an auth cookie), their
    credits MUST stack — that's the whole point of the layered-
    reputation pattern. A "first match wins" reading would lose
    the second credit."""
    from botshield_test import ips as _ips
    ip_base = _ips.fresh_ip()
    ip_both = _ips.fresh_ip()
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger app-session cookie=PHPSESSID credit=15\n'
        '    BotShieldCookieTrigger app-auth    cookie=auth_token credit=40',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=ip_base)
            client.get("/", xff=ip_both,
                       cookies={"PHPSESSID": "x", "auth_token": "y"})
            baseline  = slc.decision_lines(ip=ip_base)
            both      = slc.decision_lines(ip=ip_both)

    assert baseline and both
    base_score = int(baseline[-1]["score"])
    both_score = int(both[-1]["score"])
    assert both_score == base_score - 55, (
        f"two pass-triggers with credit=15 + credit=40 must stack "
        f"to -55; baseline={base_score} both={both_score}"
    )
    # Both reasons should appear in the decision line.
    reason = both[-1]["reason"]
    assert "cookie-trigger:app-session" in reason, reason
    assert "cookie-trigger:app-auth"    in reason, reason


def test_cookie_trigger_non_pass_shortcircuits_after_pass(
    config_override, log_slice, fresh_ip,
):
    """A pass trigger before a non-pass trigger must let the
    non-pass trigger short-circuit (the response status comes
    from the non-pass rule, not the pass one). The pass trigger's
    credit still contributes to the decision-log score."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger app-session cookie=PHPSESSID credit=15\n'
        '    BotShieldCookieTrigger kill       cookie=api_token=BAD status=403',
        count=1,
    ):
        with log_slice as slc:
            r = client.get("/", xff=fresh_ip,
                           cookies={"PHPSESSID": "x", "api_token": "BAD"})
            lines = slc.decision_lines(ip=fresh_ip)

    assert r.status_code == 403, (
        "non-pass trigger declared after a matching pass trigger "
        "must still short-circuit the response"
    )
    # The pass trigger's reason should be on the log line too.
    reason = lines[-1]["reason"] if lines else ""
    assert "cookie-trigger:app-session" in reason, (
        f"pass trigger's reason missing from decision log even "
        f"though non-pass short-circuited; reason={reason}"
    )
    assert "cookie-trigger:kill" in reason, (
        f"non-pass trigger's reason missing; reason={reason}"
    )


def test_cookie_trigger_first_non_pass_wins_over_second(
    config_override, log_slice, fresh_ip,
):
    """Two non-pass triggers in declaration order: the first to
    match wins. Second never runs."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieTrigger first  cookie=foo status=403\n'
        '    BotShieldCookieTrigger second cookie=foo status=451',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip, cookies={"foo": "x"})
    assert r.status_code == 403, (
        f"first declared non-pass trigger must win; got {r.status_code}"
    )


# --- Main-scope inheritance + _bs_verified rejection ------------------


def test_cookie_trigger_main_scope_inherits_into_vhost(
    config_override, log_slice, fresh_ip,
):
    """Directive at main scope must flow into the vhost via the
    merge hook (same guarantee E2.1, E3 get)."""
    with config_override(
        r"BotShieldStateFile\s+\S+",
        'BotShieldCookieTrigger ms-scope '
        'cookies=none status=403\n'
        'BotShieldStateFile /var/lib/botshield/state.bin',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip)
    assert r.status_code == 403, (
        "main-scope BotShieldCookieTrigger did not inherit into vhost"
    )


def test_cookie_trigger_bs_verified_raw_name_rejected(
    config_override,
):
    """Declaring a cookie=_bs_verified predicate must fail at config
    parse time — operators are redirected to bs-cookie=<state>."""
    import pytest as _pytest
    with _pytest.raises(Exception) as ei:
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldCookieTrigger bad cookie=_bs_verified=foo',
            count=1,
        ):
            pass
    # The apache2 reload failure bubbles as CalledProcessError — we
    # just want to confirm the config was rejected, not silently
    # accepted.
    assert "bs-cookie" in str(ei.value) or "exit status 1" in str(ei.value)
