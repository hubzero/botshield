"""E12 — shadow mode / dry-run enforcement.

Two layers, with the global one winning when set:
  - per-rule  `mode=observe` action key (path/cookie/env/load
                triggers via shared engine; mode=observe trailing
                token on rate-limit + block-path setters)
  - global    BotShieldShadowMode on (server-scope flip-all)

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
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger trap "/.envprobe" '
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
    assert "path-trigger:trap:observe" in reason, (
        f"expected observe suffix in reason; got {reason!r}"
    )


def test_path_trigger_observe_does_not_flag_ip(
    config_override, fresh_ip, log_slice,
):
    """The point of observe is no persistent memory. Match a path
    trigger with flag=fake_bot ttl=3600 in observe mode; the IP
    must not pick up the flag bit on the next request."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger trap "/.envprobe" '
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
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
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
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
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


# --- Per-rule observe: block path -----------------------------------


def test_block_path_observe_does_not_403(config_override, fresh_ip):
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldBlockPath admin-block "/admin/*" '
        '"httpx" * mode=observe',
        count=1,
    ):
        r = client.get("/admin/login.php", xff=fresh_ip,
                       ua=SCRAPER_UA)
    assert r.status_code != 403, (
        f"observe-mode block path enforced; status={r.status_code}"
    )


# --- Global BotShieldShadowMode overrides per-rule ------------------


def test_global_shadow_mode_overrides_per_rule_enforce(
    config_override, fresh_ip,
):
    """Per-rule mode is enforce (default) but BotShieldShadowMode on
    flips everything to observe. The 403 path trigger must NOT
    enforce."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldShadowMode on\n'
        '    BotShieldPathTrigger trap "/.envprobe" status=403',
        count=1,
    ):
        r = _g("/.envprobe", xff=fresh_ip)
    assert r.status_code != 403, (
        f"global shadow mode failed to suppress enforcement; "
        f"status={r.status_code}"
    )


def test_global_shadow_mode_off_lets_per_rule_enforce(
    config_override, fresh_ip,
):
    """Sanity: with BotShieldShadowMode off (the default), a rule
    in default-enforce mode actually enforces. Catches accidental
    inversion of the global flag's check."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldPathTrigger trap "/.envprobe2" status=403',
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
    """Two block-path rules match the same URL. First is observe-
    only; second is enforce. Without proper handling, the first
    match would either wrongly enforce or wrongly skip the second.
    With correct semantics: first observes (logs :observe), second
    enforces — request returns 403."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldBlockPath staged "/admin/*" "httpx" * '
        'mode=observe\n'
        '    BotShieldBlockPath active "/admin/*" "httpx" *',
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
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldPathTrigger trap "/foo" '
            'status=403 mode=monitor',
            count=1,
        ):
            pass


def test_directive_rejects_mode_on_feedback(config_override):
    """Feedback runs response-path; observe is meaningless there."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldFeedbackTrigger event-x '
            'flag=honeypot_hit ttl=3600 mode=observe',
            count=1,
        ):
            pass
