"""E4 — cookie triggers.

Parallel family to E3 path triggers, matched on cookies instead of
paths. Tests cover the predicate surface (named presence / value /
absence / bulk state / bs-cookie state) and the action surface
(credit / penalty / status / log / flag / ttl).

Key semantic divergence from E3 that MUST be asserted explicitly:
cookie triggers apply credit/penalty under `respond=nochallenge`, because
cookies are ongoing-state signals the client carries on THIS
request. Path triggers leave the score alone under pass.
"""

from __future__ import annotations

import pytest

from botshield_test import client


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


# --- Named-cookie predicates -----------------------------------------


def test_cookie_trigger_named_present_applies_credit(
    config_override, log_slice, request,
):
    """cookie=<name> fires on presence; credit reduces this request's
    score even though respond=nochallenge (divergence from E3).

    log_slice is a one-shot context manager so we issue both
    requests inside a single slice and distinguish them by the
    separate IPs we use — one baseline, one with the cookie."""
    # Allocate two distinct IPs up front (fresh_ip is a fixture
    # that mints one; we need two.)
    from botshield_test import ips as _ips
    ip_base = _ips.fresh_ip()
    ip_with = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    <BotShieldRule probe-base>\n'
        '        BotShieldPath   /*\n'
        '        BotShieldScore  probe +20\n'
        '    </BotShieldRule>\n'
        '    BotShieldCookieTrigger app-session cookie=PHPSESSID score=\"probe -15\"\n'
        '    <Location />\n'
        '        BotShieldChallengeAtLeast probe 20 noninteractive\n'
        '    </Location>',
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
    # 20 reaches the row; 20 - 15 does not. The credit is visible as
    # the difference between being challenged and not.
    assert baseline[-1]["tier"] != "nochallenge", (
        f"the control must cross the row or this proves nothing; "
        f"tier={baseline[-1]['tier']} reason={baseline[-1]['reason']!r}"
    )
    assert withcookie[-1]["tier"] == "nochallenge", (
        f"the cookie's -15 should have kept this under the row; "
        f"tier={withcookie[-1]['tier']} "
        f"reason={withcookie[-1]['reason']!r}"
    )
    # Reason string should tag the cookie trigger.
    assert any("cookietrigger:app-session" in d["reason"]
               for d in withcookie), f"lines={withcookie}"


def test_cookie_trigger_named_eq_value_blocks(
    config_override, log_slice,
):
    """cookie=<name>=<value> fires on exact value — simulate a
    known-bad token that should immediately 403. Uses two different
    fresh IPs so the trigger's `flag=honeypot_hit` side-effect on
    r_hit's IP doesn't carry forward and tier_floor r_ok into
    captcha enforcement."""
    from botshield_test import ips as _ips
    ip_hit = _ips.fresh_ip()
    ip_ok  = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger stale-token '
        'cookie=api_token=LEAKED_HEX '
        'respond=403 flag=honeypot_hit ttl=3600',
        count=1,
    ):
        r_hit  = client.get("/", xff=ip_hit,
                            cookies={"api_token": "LEAKED_HEX"})
        r_ok   = client.get("/", xff=ip_ok,
                            cookies={"api_token": "legit-value"})

    assert r_hit.status_code == 403
    assert r_ok.status_code  != 403


def test_cookie_trigger_named_contains_substring(
    config_override, log_slice, fresh_ip,
):
    """cookie=<name>~<substr> fires when the value contains the
    substring anywhere."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger bait-signup '
        'cookie=signup_tmp~BAIT-HEX respond=403',
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger missing-csrf '
        '!cookie=csrf_token respond=403',
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger no-cookies cookies=none respond=403',
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger any-session cookies=session respond=403',
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldSessionCookieName my_custom_session\n'
        '    BotShieldCookieTrigger any-session '
        'cookies=session respond=403',
        count=1,
    ):
        r_match = client.get("/", xff=fresh_ip,
                             cookies={"my_custom_session": "x"})
    assert r_match.status_code == 403


# --- bs-cookie state -------------------------------------------------


def test_cookie_trigger_bs_cookie_missing(
    config_override, log_slice, fresh_ip,
):
    """bs-cookie=missing fires when no __Host-bs_session cookie present —
    the most common case (first-sight visitor)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger fresh bs-cookie=missing respond=403',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip)
    assert r.status_code == 403


def test_cookie_trigger_bs_cookie_invalid(
    config_override, log_slice, fresh_ip,
):
    """bs-cookie=invalid fires when __Host-bs_session is present but
    fails verification (tampered HMAC, wrong format, etc.)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger bad-bs bs-cookie=invalid respond=403',
        count=1,
    ):
        # Send a garbage __Host-bs_session cookie — fails signature check.
        r = client.get("/", xff=fresh_ip,
                       cookies={"__Host-bs_session": "obviously-bogus"})
    assert r.status_code == 403


# --- respond=nochallenge divergence from E3 ----------------------------------


def test_cookie_trigger_status_pass_still_applies_credit(
    config_override, log_slice,
):
    """DIVERGENCE FROM E3: cookie triggers under respond=nochallenge still
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
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    <BotShieldRule probe-base>\n'
        '        BotShieldPath   /*\n'
        '        BotShieldScore  probe +20\n'
        '    </BotShieldRule>\n'
        '    BotShieldCookieTrigger ghost cookie=PHPSESSID '
        'respond=nochallenge score=\"probe -20\"\n'
        '    <Location />\n'
        '        BotShieldChallengeAtLeast probe 20 noninteractive\n'
        '    </Location>',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=ip_base)
            client.get("/", xff=ip_with, cookies={"PHPSESSID": "x"})
            base_lines = slc.decision_lines(ip=ip_base)
            with_lines = slc.decision_lines(ip=ip_with)

    assert base_lines and with_lines
    hits = [d for d in with_lines if "cookietrigger:ghost" in d["reason"]]
    assert hits, f"no cookietrigger:ghost decision line; lines={with_lines}"
    # respond=nochallenge decides the trigger's own outcome; it does
    # not stop the score it carries from reaching the decision.
    assert base_lines[-1]["tier"] != "nochallenge", (
        f"the control must cross the row; "
        f"tier={base_lines[-1]['tier']} "
        f"reason={base_lines[-1]['reason']!r}"
    )
    assert with_lines[-1]["tier"] == "nochallenge", (
        f"a respond=nochallenge trigger's -20 should still have kept "
        f"this under the row; tier={with_lines[-1]['tier']} "
        f"reason={with_lines[-1]['reason']!r}"
    )


# --- Precedence: pass accumulates, non-pass short-circuits -----------


def test_cookie_trigger_pass_triggers_stack_credits(
    config_override, log_slice,
):
    """When two respond=nochallenge triggers both match (e.g. a client
    carries both a session cookie and an auth cookie), their
    credits MUST stack — that's the whole point of the layered-
    reputation pattern. A "first match wins" reading would lose
    the second credit."""
    from botshield_test import ips as _ips
    ip_base = _ips.fresh_ip()
    ip_one  = _ips.fresh_ip()
    ip_both = _ips.fresh_ip()
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    <BotShieldRule probe-base>\n'
        '        BotShieldPath   /*\n'
        '        BotShieldScore  probe +60\n'
        '    </BotShieldRule>\n'
        '    BotShieldCookieTrigger app-session cookie=PHPSESSID score=\"probe -15\"\n'
        '    BotShieldCookieTrigger app-auth    cookie=auth_token score=\"probe -40\"\n'
        '    <Location />\n'
        '        BotShieldChallengeAtLeast probe 20 noninteractive\n'
        '    </Location>',
        count=1,
    ):
        with log_slice as slc:
            client.get("/", xff=ip_base)
            client.get("/", xff=ip_one, cookies={"PHPSESSID": "x"})
            client.get("/", xff=ip_both,
                       cookies={"PHPSESSID": "x", "auth_token": "y"})
            baseline  = slc.decision_lines(ip=ip_base)
            one       = slc.decision_lines(ip=ip_one)
            both      = slc.decision_lines(ip=ip_both)

    assert baseline and one and both
    # 60 crosses the row at 20. One credit leaves 45, still over. Both
    # leave 5, under -- which only happens if they combined rather than
    # the first match winning.
    assert baseline[-1]["tier"] != "nochallenge", (
        f"the control must cross the row; "
        f"reason={baseline[-1]['reason']!r}"
    )
    assert one[-1]["tier"] != "nochallenge", (
        f"one credit leaves 45, still over the row -- if this passes, "
        f"the credits are not what moved it; "
        f"reason={one[-1]['reason']!r}"
    )
    assert both[-1]["tier"] == "nochallenge", (
        f"-15 and -40 must both land: 60 - 55 is under the row. "
        f"tier={both[-1]['tier']} reason={both[-1]['reason']!r}"
    )
    # Both reasons should appear in the decision line.
    reason = both[-1]["reason"]
    assert "cookietrigger:app-session" in reason, reason
    assert "cookietrigger:app-auth"    in reason, reason


def test_cookie_trigger_non_pass_shortcircuits_after_pass(
    config_override, log_slice, fresh_ip,
):
    """A pass trigger before a non-pass trigger must let the
    non-pass trigger short-circuit (the response status comes
    from the non-pass rule, not the pass one). The pass trigger's
    credit still contributes to the decision-log score."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger app-session cookie=PHPSESSID score=\"probe -15\"\n'
        '    BotShieldCookieTrigger kill       cookie=api_token=BAD respond=403',
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
    assert "cookietrigger:app-session" in reason, (
        f"pass trigger's reason missing from decision log even "
        f"though non-pass short-circuited; reason={reason}"
    )
    assert "cookietrigger:kill" in reason, (
        f"non-pass trigger's reason missing; reason={reason}"
    )


def test_cookie_trigger_first_non_pass_wins_over_second(
    config_override, log_slice, fresh_ip,
):
    """Two non-pass triggers in declaration order: the first to
    match wins. Second never runs."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
        '    BotShieldCookieTrigger first  cookie=foo respond=403\n'
        '    BotShieldCookieTrigger second cookie=foo respond=451',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip, cookies={"foo": "x"})
    assert r.status_code == 403, (
        f"first declared non-pass trigger must win; got {r.status_code}"
    )


# --- Main-scope inheritance + __Host-bs_session rejection ------------------


def test_cookie_trigger_main_scope_inherits_into_vhost(
    config_override, log_slice, fresh_ip,
):
    """Directive at main scope must flow into the vhost via the
    merge hook (same guarantee E2.1, E3 get)."""
    with config_override(
        r"BotShieldStateSaveInterval\s+\d+",
        'BotShieldCookieTrigger ms-scope '
        'cookies=none respond=403\n'
        'BotShieldStateSaveInterval 30',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip)
    assert r.status_code == 403, (
        "main-scope BotShieldCookieTrigger did not inherit into vhost"
    )


def test_cookie_trigger_bs_session_raw_name_rejected(
    config_override,
):
    """Declaring a cookie=__Host-bs_session predicate must fail at config
    parse time — operators are redirected to bs-cookie=<state>."""
    import pytest as _pytest
    with _pytest.raises(Exception) as ei:
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
        '    BotShieldChallengeAtLeast none\n'
            '    BotShieldCookieTrigger bad cookie=__Host-bs_session=foo',
            count=1,
        ):
            pass
    # The apache2 reload failure bubbles as CalledProcessError — we
    # just want to confirm the config was rejected, not silently
    # accepted.
    assert "bs-cookie" in str(ei.value) or "exit status 1" in str(ei.value)
