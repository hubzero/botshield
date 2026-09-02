"""The interactive tier's server-side solve-time floor, and the
attestation probes that ride back with the solve.

Why a floor exists at all: the interactive tier's only distinguishing
feature used to be a client-side `if (!e.isTrusted) return`, checked in
the client's own browser on a page the client controls. It stops
JS-injected clicks and nothing above that -- Selenium and Puppeteer
both dispatch genuinely trusted events, and `window.__bsChallenge` is a
global, so anything already running our JS can solve and submit without
touching the button.

The floor is the first check on this tier the client cannot answer for
itself. issued_ms is covered by the bootstrap HMAC, so the clock is
entirely the server's; a submit arriving faster than a person can react
did not come from a person reacting.

It does not stop a bot that sleeps. It makes sleeping mandatory, and
because the delay is real server-observed wall time it costs throughput
per request rather than one line of script. That is a smaller claim
than "detects automation" and these tests are written to that claim.
"""

from __future__ import annotations

import json
import time

import pytest

from botshield_test import client, cookies


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"
# Same forced-tier path test_acceptance_form_tier uses: ambient score
# never reaches the interactive threshold, so relying on it would make
# this test depend on scoring config it is not about.
INTERACTIVE_PATH = "/form-demo"

FLOOR_MS = 400   # BS_DEFAULT_INTERACTIVE_MIN_MS


def _interactive_challenge(ip):
    """Fetch a real interactive-tier interstitial and return its
    challenge. auto_tier lives inside the encrypted cookie_prefix, so
    the tier cannot be forged from the client side -- this has to come
    from a genuine interstitial."""
    resp = client.get(INTERACTIVE_PATH, xff=ip, ua=BROWSER_UA)
    assert resp.status_code == 403, (
        f"expected an interactive interstitial; got {resp.status_code}"
    )
    ch = cookies.extract_challenge(resp.text)
    assert ch.get("auto") == 0, (
        f"this path must issue an interactive (auto=0) challenge, "
        f"otherwise the floor under test does not apply; got {ch.get('auto')}"
    )
    return ch


def _submit(ch, counter, ip, *, att=None, issued_ms=None):
    body = {
        "provider": "pow-gcm",
        "cookie_prefix": ch["cookie_prefix"],
        "bound_ip": ch["bound_ip"],
        "bootstrap_sig": ch["bootstrap_sig"],
        "issued_ms": ch["issued_ms"] if issued_ms is None else issued_ms,
        "counter": counter,
    }
    if att is not None:
        body["att"] = att
    return client.post(
        "/botshield/embedded-verify",
        data=json.dumps(body),
        headers={"Content-Type": "application/json"},
        ua=BROWSER_UA,
        xff=ip,
    )


def test_instant_solve_is_refused(fresh_ip, log_slice, config_override):
    """A solve submitted with no human delay is refused on the
    interactive tier.

    Difficulty is pinned to 1 here. The floor measures issue ->
    submit, and at the default difficulty a Python solve on a loaded
    box can itself outlast 150ms -- the submit then clears the floor
    on compute time and the test fails for a reason unrelated to what
    it asserts. The browser had the same property, which is why the
    real client now solves at load and the click only releases the
    answer. Difficulty 1 makes the solve free, so the only thing
    between issue and submit is this test.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n    BotShieldDifficulty 1",
        count=1,
    ):
        ch = _interactive_challenge(fresh_ip)
        counter = cookies.solve_pow(ch)
        with log_slice as slc:
            resp = _submit(ch, counter, fresh_ip)
            lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 403, (
        f"a solve returned instantly must be refused on the interactive "
        f"tier; got {resp.status_code}"
    )
    assert any("solve_too_fast" in d["reason"] for d in lines), (
        f"the refusal must be attributable in the log, or an operator "
        f"cannot tell this floor from a bad signature; lines={lines}"
    )


def test_solve_after_human_delay_is_accepted(fresh_ip):
    """The mirror image, so the refusal above cannot be some unrelated
    breakage in the interactive verify path."""
    ch = _interactive_challenge(fresh_ip)
    counter = cookies.solve_pow(ch)
    time.sleep((FLOOR_MS + 120) / 1000.0)
    resp = _submit(ch, counter, fresh_ip)
    assert resp.status_code == 204, (
        f"a solve after a plausible click delay must be accepted; got "
        f"{resp.status_code}"
    )


def test_non_interactive_tier_has_no_floor(fresh_ip):
    """The floor is about a human click. The non-interactive tier
    starts solving at DOMContentLoaded with nobody in the loop, so
    applying a delay requirement there would refuse every real
    browser that happens to be fast."""
    raw = client.get("/botshield/embedded-bootstrap", xff=fresh_ip,
                     ua=BROWSER_UA)
    ch = json.loads(raw.text)["challenge"]
    assert ch["auto"] == 1
    counter = cookies.solve_pow(ch)
    resp = _submit(ch, counter, fresh_ip)
    assert resp.status_code == 204, (
        f"non-interactive solves must not be subject to the click "
        f"floor; got {resp.status_code}"
    )


def test_issued_ms_is_signed(fresh_ip):
    """The whole floor rests on issued_ms being the server's value.
    If it were merely echoed, backdating it would buy an instant
    solve -- which is exactly the bypass this asserts is closed."""
    ch = _interactive_challenge(fresh_ip)
    counter = cookies.solve_pow(ch)
    backdated = ch["issued_ms"] - 5000
    resp = _submit(ch, counter, fresh_ip, issued_ms=backdated)
    assert resp.status_code == 403, (
        f"a backdated issued_ms must fail the bootstrap signature, not "
        f"buy a pass through the floor; got {resp.status_code}"
    )


def test_attestation_failures_are_logged(fresh_ip, log_slice):
    """Attestation is reported, not enforced: the solve still succeeds
    and the probe names land in the reason chain. If this ever starts
    blocking, a privacy browser or a native-patching extension becomes
    an outage."""
    ch = _interactive_challenge(fresh_ip)
    counter = cookies.solve_pow(ch)
    time.sleep((FLOOR_MS + 120) / 1000.0)
    with log_slice as slc:
        resp = _submit(ch, counter, fresh_ip, att=["webdriver", "no-screen"])
        lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 204, (
        f"attestation failures must not block a valid solve; got "
        f"{resp.status_code}"
    )
    assert any("attest:webdriver+no-screen" in d["reason"] for d in lines), (
        f"probe names must reach the decision log; lines={lines}"
    )


@pytest.mark.parametrize("bad", [
    ["../etc", "ok"],
    ["has space"],
    ["UPPER"],
    ["x" * 40],
    ["a"] * 40,
])
def test_attestation_input_is_sanitised(fresh_ip, log_slice, bad):
    """The array is attacker-controlled and lands in a log parsed by
    tooling. Anything outside the probe-name alphabet is dropped
    rather than escaped, so a comma or quote can never reach a
    decision line."""
    ch = _interactive_challenge(fresh_ip)
    counter = cookies.solve_pow(ch)
    time.sleep((FLOOR_MS + 120) / 1000.0)
    with log_slice as slc:
        resp = _submit(ch, counter, fresh_ip, att=bad)
        lines = slc.decision_lines(ip=fresh_ip)

    assert resp.status_code == 204
    for d in lines:
        assert "../etc" not in d["reason"]
        assert "UPPER" not in d["reason"]
        assert "has space" not in d["reason"]
        assert len(d["reason"]) < 400, (
            f"unbounded attestation input reached the log: {d['reason'][:120]}"
        )


def _configtest(directive: str) -> tuple[int, str]:
    """Same pattern as test_bot_rate_tiers: check against THIS worker's
    instance so a directive the working tree just added is not tested
    against the deployed module."""
    import subprocess
    from botshield_test import config as _cfg
    r = subprocess.run(
        ["sudo", "httpd", "-f", _cfg.HTTPD_CONF, "-C", directive, "-t"],
        capture_output=True, text=True, check=False,
    )
    return r.returncode, r.stderr


@pytest.mark.parametrize("directive", [
    "BotShieldInteractiveMinSolveMs 400",
    "BotShieldInteractiveMinSolveMs 0",
    "BotShieldInteractiveMinSolveMs 5000",
    "BotShieldInteractiveArmMs 300",
    "BotShieldInteractiveArmMs 100",
    "BotShieldInteractiveArmMs 0",
    "BotShieldInteractiveArmMs 2000",
])
def test_timing_directives_accept_valid_values(directive):
    """These exist because both directives shipped rejecting every
    value: the bounded-int parser's fourth argument is a cap on the
    digit-string length, not a default, and passing 0 there refuses
    any input at all. Nothing caught it, because every other test in
    this file exercises the defaults and never sets the directive.
    A parse test is cheap; a knob that silently cannot be set is not.
    """
    rc, err = _configtest(directive)
    assert rc == 0, f"valid directive {directive!r} rejected: {err[-300:]}"


@pytest.mark.parametrize("directive,expect", [
    ("BotShieldInteractiveMinSolveMs 5001", "0..5000"),
    ("BotShieldInteractiveMinSolveMs -1", "0..5000"),
    ("BotShieldInteractiveMinSolveMs abc", "0..5000"),
    ("BotShieldInteractiveArmMs 2001", "0..2000"),
    ("BotShieldInteractiveArmMs xyz", "0..2000"),
])
def test_timing_directives_reject_bad_values(directive, expect):
    rc, err = _configtest(directive)
    assert rc != 0, f"configtest accepted {directive!r}"
    assert expect in err, f"expected {expect!r} in: {err[-300:]}"


def test_arm_window_reaches_the_client(fresh_ip):
    """arm_ms has to be in the challenge JSON or the widget arms
    instantly and the whole mechanism is inert with no visible sign."""
    ch = _interactive_challenge(fresh_ip)
    assert ch.get("arm_ms", 0) > 0, (
        f"interactive challenge must carry a non-zero arm_ms; got "
        f"{ch.get('arm_ms')!r}"
    )


def test_non_interactive_does_not_arm(fresh_ip):
    """Arming is a property of waiting on a human. The
    non-interactive tier has nobody to wait for, and a window there
    would be pure added latency for every visitor."""
    raw = client.get("/botshield/embedded-bootstrap", xff=fresh_ip,
                     ua=BROWSER_UA)
    ch = json.loads(raw.text)["challenge"]
    assert ch.get("arm_ms", 0) == 0, (
        f"non-interactive challenge must not arm; got {ch.get('arm_ms')!r}"
    )
