"""E7.3 — cross-family trigger dispatch order.

Per-family precedence (declaration order) is covered by the family-
specific test files. This file pins the ORDER between families:

    1. cookie triggers       (persistent state; accumulates on pass)
    2. env triggers          (upstream-module / Apache-config state)
    3. path triggers         (one-off per-path intent)
    4. feedback triggers     (response-path; separate hook)

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

import pytest

from botshield_test import client, ips as _ips


pytestmark = pytest.mark.serial


PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"


def _g(path, xff, **kw):
    return client.get(path, xff=xff, ua=PASS_UA,
                      accept_language=PASS_AL, **kw)


# --- Short-circuit blocks later families ---------------------------


def test_cookie_short_circuit_blocks_env_and_path(
    config_override, log_slice, fresh_ip,
):
    """Cookie trigger with status=403 fires first. The env trigger
    and path trigger that would also match must not run — no env/
    path reason-tokens on the decision line, and the status is the
    cookie's 403 (not the path trigger's 451 or env's 429)."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
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
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
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
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
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
