"""E7.3 — cross-family trigger dispatch order.

Per-family precedence (declaration order) is covered by the family-
specific test files. This file pins the ORDER between families:

    1. cookie triggers       (persistent state; accumulates on pass)
    2. env triggers          (upstream-module / Apache-config state;
                              ap_is_initial_req-gated to avoid double-
                              application on internal-redirect legs)
    3. load triggers         (E11.2 — global load_state; inserted into
                              the shared family between env and path)
    4. path triggers         (one-off per-path intent)
    5. feedback triggers     (response-path; separate hook)

Gate from CHANGELOG.md E7.3:
  - ordering is deterministic
  - later trigger families do not run after an earlier short-circuit
  - decision logs show which family fired (already covered by reason-
    prefix normalization in E7.1, so we assert the right prefix here)

Feedback triggers are validated by `test_app_feedback.py` since they
run on a separate hook and don't participate in the bs_check_policy
walk.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client, ips as _ips


pytestmark = pytest.mark.serial


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"

LOAD_FILE_PATH = "/etc/botshield/load.state.test"


def _g(path, xff, **kw):
    return client.get(path, xff=xff, ua=PASS_UA,
                      accept_language=PASS_AL, **kw)


def _set_load_file(value: str) -> None:
    with open(LOAD_FILE_PATH, "w") as f:
        f.write(value + "\n")


def _wait_for_metric_load_state(target: int, timeout: float = 12.0) -> int:
    """Poll metrics until load_state reaches target. Mirror of the
    helper in test_load_trigger.py — the dispatch-order tests need
    the same state-machine settle to fire load triggers."""
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        resp = client.get("/botshield/metrics")
        for line in resp.text.splitlines():
            if line.startswith("botshield_load_state "):
                last = int(line.split()[1])
                if last == target:
                    return last
        time.sleep(0.5)
    raise AssertionError(
        f"load_state did not reach {target} within {timeout}s; "
        f"last observed {last}"
    )


# --- Short-circuit blocks later families ---------------------------


def test_cookie_short_circuit_blocks_env_and_path(
    config_override, log_slice, fresh_ip,
):
    """Cookie trigger with status=403 fires first. The env trigger
    and path trigger that would also match must not run — no env/
    path reason-tokens on the decision line, and the status is the
    cookie's 403 (not the path trigger's 451 or env's 429)."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldCookieTrigger c-block cookies=none status=403\n'
        '    SetEnvIfExpr "true" BS_CROSS=1\n'
        '    BotShieldEnvTrigger e-block env=BS_CROSS status=429\n'
        '    BotShieldPathTrigger p-block "/*" status=451',
        count=1,
    ):
        with log_slice as slc:
            r = _g("/no-cookie-path", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r.status_code == 403, (
        f"cookie short-circuit should return its 403, not defer to "
        f"env (429) or path (451); got {r.status_code}"
    )
    assert lines
    reason = lines[-1]["reason"]
    assert "cookie-trigger:c-block" in reason, (
        f"cookie match missing from decision reason; reason={reason}"
    )
    assert "env-trigger:e-block" not in reason, (
        f"env trigger must not have run after cookie short-circuit; "
        f"reason={reason}"
    )
    assert "path-trigger:p-block" not in reason, (
        f"path trigger must not have run after cookie short-circuit; "
        f"reason={reason}"
    )


def test_env_short_circuit_blocks_path(
    config_override, log_slice, fresh_ip,
):
    """Env trigger with status=403 fires (cookie family has no
    matching trigger). The path trigger that would also match must
    not run."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    SetEnvIfExpr "true" BS_CROSS=1\n'
        '    BotShieldEnvTrigger e-block env=BS_CROSS status=403\n'
        '    BotShieldPathTrigger p-block "/*" status=451',
        count=1,
    ):
        with log_slice as slc:
            r = _g("/whatever", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r.status_code == 403, (
        f"env short-circuit should return its 403, not defer to path "
        f"(451); got {r.status_code}"
    )
    assert lines
    reason = lines[-1]["reason"]
    assert "env-trigger:e-block" in reason
    assert "path-trigger:p-block" not in reason, (
        f"path trigger must not have run after env short-circuit; "
        f"reason={reason}"
    )


# --- Pass matches let later families run ---------------------------


def test_cookie_and_env_pass_then_path_runs(
    config_override, log_slice, fresh_ip,
):
    """Cookie pass accumulates a penalty; env pass accumulates
    another; the path trigger then fires with its own status. All
    three families should appear in the reason trace."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    BotShieldCookieTrigger c-pass cookies=none '
        'status=pass penalty=3\n'
        '    SetEnvIfExpr "true" BS_CROSS=1\n'
        '    BotShieldEnvTrigger e-pass env=BS_CROSS '
        'status=pass penalty=7\n'
        '    BotShieldPathTrigger p-block "/*" status=403',
        count=1,
    ):
        with log_slice as slc:
            r = _g("/whatever", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r.status_code == 403, (
        f"path trigger should win after cookie/env pass; "
        f"got {r.status_code}"
    )
    assert lines
    reason = lines[-1]["reason"]
    assert "cookie-trigger:c-pass" in reason, reason
    assert "env-trigger:e-pass"    in reason, reason
    assert "path-trigger:p-block"  in reason, reason


# --- Load triggers in the shared family ----------------------------


def test_load_short_circuit_blocks_path(
    config_override, log_slice, fresh_ip,
):
    """E11.2 load trigger sits between env and path in the runtime
    walk (policy.c:268). When load=hot fires status=503, the path
    trigger that would also match must not run."""
    _set_load_file("hot")
    try:
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}\n'
            '    BotShieldLoadTrigger l-block state=hot status=503\n'
            '    BotShieldPathTrigger p-block "/*" status=451',
            count=1,
        ):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            with log_slice as slc:
                r = _g("/whatever", xff=fresh_ip)
                lines = slc.decision_lines(ip=fresh_ip)
    finally:
        _set_load_file("normal")

    assert r.status_code == 503, (
        f"load short-circuit should return its 503, not defer to path "
        f"(451); got {r.status_code}"
    )
    assert lines
    reason = lines[-1]["reason"]
    assert "load-trigger:l-block" in reason, reason
    assert "path-trigger:p-block" not in reason, (
        f"path trigger must not have run after load short-circuit; "
        f"reason={reason}"
    )


def test_env_pass_then_load_blocks_path(
    config_override, log_slice, fresh_ip,
):
    """Env pass accumulates a penalty; load=hot then short-circuits
    with status=503. The path trigger must not run. Both env-pass
    and load-block reasons should appear; path-block must not."""
    _set_load_file("hot")
    try:
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            f'    BotShieldLoadStateFile {LOAD_FILE_PATH}\n'
            '    SetEnvIfExpr "true" BS_CROSS=1\n'
            '    BotShieldEnvTrigger e-pass env=BS_CROSS '
            'status=pass penalty=4\n'
            '    BotShieldLoadTrigger l-block state=hot status=503\n'
            '    BotShieldPathTrigger p-block "/*" status=451',
            count=1,
        ):
            _wait_for_metric_load_state(target=2, timeout=12.0)
            with log_slice as slc:
                r = _g("/whatever", xff=fresh_ip)
                lines = slc.decision_lines(ip=fresh_ip)
    finally:
        _set_load_file("normal")

    assert r.status_code == 503, (
        f"load should win after env pass; got {r.status_code}"
    )
    assert lines
    reason = lines[-1]["reason"]
    assert "env-trigger:e-pass" in reason, reason
    assert "load-trigger:l-block" in reason, reason
    assert "path-trigger:p-block" not in reason, (
        f"path trigger must not have run after load short-circuit; "
        f"reason={reason}"
    )


# --- Env trigger initial-req gate (regression) ---------------------


def test_env_trigger_no_double_apply_on_internal_redirect(
    config_override, log_slice, fresh_ip,
):
    """policy.c:223 — env triggers are gated on `ap_is_initial_req`
    so a 403 → ErrorDocument internal-redirect leg doesn't re-apply
    the env-trigger side effect. Without the gate, a SetEnvIf-style
    env that's set on both legs would have its penalty / flag-IP
    side effect applied twice — once on the original request, once
    on the ErrorDocument leg.

    Setup: env=BS_CROSS on every request (status=pass + penalty so
    we can see whether it fired in the reason trace), path-trigger
    on /start, ErrorDocument 403 → /error. Hit /start. The original
    leg's decision line should carry env-trigger; the /error leg's
    decision line must NOT."""
    with config_override(
        r"BotShieldEnabled\s+On",
        'BotShieldEnabled On\n'
        '    SetEnvIfExpr "true" BS_CROSS=1\n'
        '    BotShieldEnvTrigger e-pass env=BS_CROSS '
        'status=pass penalty=5\n'
        '    BotShieldPathTrigger p-block "/start" status=403\n'
        '    ErrorDocument 403 /error',
        count=1,
    ):
        with log_slice as slc:
            r = _g("/start", xff=fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r.status_code == 403, (
        f"path trigger on /start should yield 403; got {r.status_code}"
    )
    assert lines, "no decision lines emitted"

    initial = [l for l in lines if l.get("path", "").startswith("/start")]
    redirect = [l for l in lines if l.get("path", "").startswith("/error")]

    assert initial, (
        f"expected a decision line for /start; got paths={[l.get('path') for l in lines]}"
    )
    assert "env-trigger:e-pass" in initial[-1]["reason"], (
        f"env-trigger should fire on the initial /start leg; "
        f"reason={initial[-1]['reason']}"
    )

    if redirect:
        assert "env-trigger:e-pass" not in redirect[-1]["reason"], (
            f"env-trigger must NOT re-fire on the ErrorDocument /error "
            f"internal-redirect leg (ap_is_initial_req gate); "
            f"reason={redirect[-1]['reason']}"
        )
