"""E12 — shadow mode / dry-run enforcement.

Two layers, with the scope-level one winning when set:
  - per-rule  `mode=observe` action key (path/cookie/env/load
                triggers via shared engine; mode=observe trailing
                token on the rate-limit setter)
  - scope     BotShieldEnabled LogOnly (vhost / Location / Directory
                tri-state on bs_dir_cfg.enabled — flip-all within
                the scope)

Observe-mode invariants:
  - rule matches as normal
  - decision-log reason gets a `:observe` suffix
  - no flag-IP write, no score bump, no status/redirect, no
    persistent memory
  - subsequent rules in the same family still get a chance
    (observed rules don't shadow enforced ones)
  - `_observed_total` metrics counter increments separately from
    the real enforcement counter
"""

from __future__ import annotations

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"
SCRAPER_UA = "python-httpx/0.27"


def _g(path: str, **kw):
    return client.get(path, ua=PASS_UA, accept_language=PASS_AL, **kw)


def _read_metric(name: str) -> int:
    """Pull a single counter value out of /botshield/metrics. Returns
    0 if the metric is absent."""
    resp = client.get("/botshield/metrics")
    needle = f"{name} "
    for line in resp.text.splitlines():
        if line.startswith(needle):
            return int(line.split()[1])
    return 0


# --- Per-rule observe: path trigger ---------------------------------


def test_path_trigger_observe_does_not_enforce(
    config_override, fresh_ip, log_slice,
):
    """status=403 mode=observe: rule matches the URL, the decision
    line shows :observe, but the response is NOT 403 (Apache's
    static handler serves the path's normal response — 404 here
    since the path doesn't exist)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRequestTrigger trap path="/.envprobe" '
        'status=403 mode=observe',
        count=1,
    ):
        with log_slice as slc:
            r = _g("/.envprobe", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)
    # No 403; observed rule didn't enforce.
    assert r.status_code != 403, (
        f"observe-mode path trigger enforced; status={r.status_code}"
    )
    # Decision log shows the :observe suffix.
    reason = lines[-1]["reason"]
    assert "request-trigger:trap:observe" in reason, (
        f"expected observe suffix in reason; got {reason!r}"
    )


def test_path_trigger_observe_does_not_flag_ip(
    config_override, fresh_ip, log_slice,
):
    """The point of observe is no persistent memory. Match a path
    trigger with flag=fake_bot ttl=3600 in observe mode; the IP
    must not pick up the flag bit on the next request."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRequestTrigger trap path="/.envprobe" '
        'status=pass flag=fake_bot ttl=3600 mode=observe',
        count=1,
    ):
        # Match in observe mode.
        _g("/.envprobe", xff=fresh_ip)
        # Subsequent request from same IP — should not see flagged-ip.
        with log_slice as slc:
            _g("/", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)
    reason = lines[-1]["reason"]
    assert "flagged-ip" not in reason, (
        f"observe must not flag the IP; reason={reason!r}"
    )


# --- Per-rule observe: rate limit -----------------------------------


def test_rate_limit_observe_does_not_429(config_override, fresh_ip):
    """Tight budget (1/sec) with mode=observe: 5 requests in a tight
    burst would normally hit 429 on requests 2-5. Under observe,
    none return 429 — the over-budget hits log :observe and
    continue."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRateLimit corpbot 1 sec "CorpBot" * '
        'mode=observe',
        count=1,
    ):
        codes = [
            client.get("/", xff=fresh_ip, ua="CorpBot/1.0").status_code
            for _ in range(5)
        ]
    assert 429 not in codes, (
        f"observe-mode rate limit returned 429; got {codes}"
    )


def test_rate_limit_observe_increments_metric(
    config_override, fresh_ip,
):
    """Over-budget hits in observe mode bump the
    rate_limit_observed_total counter, NOT the
    rate_limit_exceeded_total counter."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRateLimit corpbot 1 sec "CorpBot" * '
        'mode=observe',
        count=1,
    ):
        before_obs = _read_metric("botshield_rate_limit_observed_total")
        before_enf = _read_metric("botshield_rate_limit_exceeded_total")
        # 5 requests → 1 admit + 4 observe-only over-budget hits.
        for _ in range(5):
            client.get("/", xff=fresh_ip, ua="CorpBot/1.0")
        after_obs = _read_metric("botshield_rate_limit_observed_total")
        after_enf = _read_metric("botshield_rate_limit_exceeded_total")

    assert after_obs - before_obs >= 1, (
        f"observed counter didn't increment; before={before_obs} "
        f"after={after_obs}"
    )
    assert after_enf == before_enf, (
        f"enforcement counter incremented under observe mode; "
        f"before={before_enf} after={after_enf}"
    )


# --- Per-rule observe: path trigger as a path-block ----------------


def test_path_trigger_observe_does_not_403(config_override, fresh_ip):
    """A scraper-UA hit on /admin/* under observe-mode PathTrigger
    (status=403 mode=observe) must not 403 from request-trigger
    enforcement. The challenge tier may still serve a 403
    interstitial (signaled by `X-Botshield: challenge`) — the test
    distinguishes the two by that header rather than status code
    alone, since interstitials moved from 200 to 403 in 2026."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRequestTrigger admin-block path="/admin/*" '
        'ua="httpx" status=403 mode=observe',
        count=1,
    ):
        r = client.get("/admin/login.php", xff=fresh_ip,
                       ua=SCRAPER_UA)
    if r.status_code == 403:
        assert r.headers.get("X-Botshield") == "challenge", (
            f"observe-mode path trigger enforced (403 without "
            f"challenge interstitial); headers={dict(r.headers)}"
        )


# --- Scope BotShieldEnabled LogOnly overrides per-rule -------------


def test_scope_log_only_overrides_per_rule_enforce(
    config_override, fresh_ip,
):
    """Per-rule mode is enforce (default) but BotShieldEnabled LogOnly
    flips everything within scope to observe. The 403 path trigger
    must NOT enforce."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnabled LogOnly\n'
        '    BotShieldRequestTrigger trap path="/.envprobe" status=403',
        count=1,
    ):
        r = _g("/.envprobe", xff=fresh_ip)
    assert r.status_code != 403, (
        f"scope LogOnly failed to suppress enforcement; "
        f"status={r.status_code}"
    )


def test_scope_log_only_default_lets_per_rule_enforce(
    config_override, fresh_ip,
):
    """Sanity: without BotShieldEnabled LogOnly (default On), a rule
    in default-enforce mode actually enforces. Catches accidental
    inversion of the tri-state check."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRequestTrigger trap path="/.envprobe2" status=403',
        count=1,
    ):
        r = _g("/.envprobe2", xff=fresh_ip)
    assert r.status_code == 403, (
        f"default-enforce path trigger didn't enforce; "
        f"status={r.status_code}"
    )


# --- Observe doesn't shadow downstream enforce rules ---------------


def test_observe_does_not_shadow_subsequent_enforce_rule(
    config_override, fresh_ip,
):
    """Two request-trigger rules match the same URL. First is observe-
    only; second is enforce. Without proper handling, the first
    match would either wrongly enforce or wrongly skip the second.
    With correct semantics: first observes (logs :observe), second
    enforces — request returns 403."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRequestTrigger staged path="/admin/*" ua="httpx" '
        'status=403 mode=observe\n'
        '    BotShieldRequestTrigger active path="/admin/*" ua="httpx" '
        'status=403',
        count=1,
    ):
        r = client.get("/admin/login.php", xff=fresh_ip,
                       ua=SCRAPER_UA)
    assert r.status_code == 403, (
        f"observed rule shadowed the subsequent enforce rule; "
        f"status={r.status_code}"
    )


# --- Directive validation ------------------------------------------


def test_directive_rejects_bad_mode_value(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldRequestTrigger trap path="/foo" '
            'status=403 mode=monitor',
            count=1,
        ):
            pass


def test_directive_accepts_mode_on_feedback(config_override):
    """Feedback runs response-path but its side effect is the
    flagged-IP write — observe-mode means "log :observe but skip
    the SHM mutation", which is the same staging gate operators
    get for the other trigger families. The parser must accept
    `mode=observe` on a feedback trigger; bridge.c honors it.
    Per-trigger functional verification lives in
    test_app_feedback.py::test_app_feedback_per_trigger_observe_mode."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldFeedbackTrigger event-x '
        'flag=honeypot_hit ttl=3600 mode=observe',
        count=1,
    ):
        pass


# --- Counterfactual outcomes under BotShieldEnabled LogOnly --------
#
# A LogOnly-suppressed enforce site emits a tilde-prefixed outcome in
# the decision log to signal the suppressed-counterfactual: real
# action was `allow`, this is what would have happened. The outcome
# counter still bumps the `allow` slot (since allow is what actually
# happened); per-family `*_observed_total` counters carry the
# staging-volume signal.


def test_log_only_emits_tilde_block_for_path_trigger(
    config_override, fresh_ip, log_slice,
):
    """Scope-level BotShieldEnabled LogOnly + a PathTrigger rule
    that would otherwise 403 must emit `outcome=~block` and serve
    the real content (no 403)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnabled LogOnly\n'
        '    BotShieldRequestTrigger admin-block path="/admin/*" ua="httpx" status=403',
        count=1,
    ):
        with log_slice as slc:
            r = client.get("/admin/login.php", xff=fresh_ip,
                           ua=SCRAPER_UA)
            lines = slc.decision_lines(ip=fresh_ip)
    assert r.status_code != 403, (
        f"LogOnly should suppress PathTrigger enforcement; "
        f"status={r.status_code}"
    )
    outcomes = [d["outcome"] for d in lines]
    assert "~block" in outcomes, (
        f"expected outcome=~block in decision log under LogOnly; "
        f"got outcomes={outcomes}"
    )


def test_log_only_emits_tilde_rate_limited_for_ratelimit(
    config_override, fresh_ip, log_slice,
):
    """Scope-level BotShieldEnabled LogOnly + a RateLimit rule with a
    tight budget. Over-budget hits would normally 429; under LogOnly
    every hit lands `outcome=~rate_limited` instead."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnabled LogOnly\n'
        '    BotShieldRateLimit corpbot 1 sec "CorpBot" *',
        count=1,
    ):
        with log_slice as slc:
            codes = [
                client.get("/", xff=fresh_ip,
                           ua="CorpBot/1.0").status_code
                for _ in range(5)
            ]
            lines = slc.decision_lines(ip=fresh_ip)
    assert 429 not in codes, (
        f"LogOnly should suppress RateLimit 429s; got {codes}"
    )
    outcomes = [d["outcome"] for d in lines]
    assert "~rate_limited" in outcomes, (
        f"expected outcome=~rate_limited under LogOnly; "
        f"got outcomes={outcomes}"
    )


def test_log_only_emits_tilde_challenge_for_tier_dispatch(
    config_override, fresh_ip, log_slice,
):
    """Scope-level BotShieldEnabled LogOnly + a request whose score
    crosses BotShieldScoreSilent. Without LogOnly the response would
    be a tier=silent interstitial; under LogOnly the module logs
    `outcome=~challenge` and declines so the real handler runs."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnabled LogOnly',
        count=1,
    ):
        with log_slice as slc:
            r = client.get("/", xff=fresh_ip, ua=SCRAPER_UA)
            lines = slc.decision_lines(ip=fresh_ip)
    # Real handler ran; not the interstitial 403.
    assert r.status_code != 403, (
        f"LogOnly should suppress tier dispatch; status={r.status_code}"
    )
    outcomes = [d["outcome"] for d in lines]
    assert "~challenge" in outcomes, (
        f"expected outcome=~challenge for suppressed tier dispatch "
        f"under LogOnly; got outcomes={outcomes}"
    )


def test_path_trigger_observe_increments_observed_total(
    config_override, fresh_ip,
):
    """Per-rule mode=observe on a PathTrigger bumps the shared
    `trigger_observed_total` counter on match. Mirrors the
    rate-limit observed-counter check earlier in this file."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldRequestTrigger admin-block path="/admin/*" ua="httpx" '
        'status=403 mode=observe',
        count=1,
    ):
        before_obs = _read_metric("botshield_trigger_observed_total")
        client.get("/admin/login.php", xff=fresh_ip, ua=SCRAPER_UA)
        after_obs = _read_metric("botshield_trigger_observed_total")

    assert after_obs - before_obs >= 1, (
        f"trigger_observed_total didn't increment; before={before_obs} "
        f"after={after_obs}"
    )


# --- Per-Location BotShieldEnabled override ------------------------


def test_per_location_log_only_with_inner_enforce(
    config_override, fresh_ip,
):
    """BotShieldEnabled is a tri-state at RSRC_CONF | ACCESS_CONF
    scope. Setting it to LogOnly at vhost scope and overriding to
    On inside a <Location> must enforce within the location and
    only-log outside it. Tests the merge in bs_dir_cfg.enabled."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldEnabled LogOnly\n'
        '    BotShieldRequestTrigger everywhere path="/*" ua="httpx" status=403\n'
        '    <Location "/enforce-here">\n'
        '        BotShieldEnabled On\n'
        '    </Location>',
        count=1,
    ):
        outside = client.get("/", xff=fresh_ip, ua=SCRAPER_UA)
        inside = client.get("/enforce-here", xff=fresh_ip,
                            ua=SCRAPER_UA)
    assert outside.status_code != 403, (
        f"vhost-scope LogOnly should suppress request-trigger outside the "
        f"override Location; got {outside.status_code}"
    )
    assert inside.status_code == 403, (
        f"<Location> override to BotShieldEnabled On should re-enable "
        f"enforcement inside that location; got {inside.status_code}"
    )
