"""Pytest fixtures shared across the botshield test suite.

Any test under `tests/pytests/` picks these up automatically — no
import, just request the fixture by parameter name.
"""

from __future__ import annotations

import pytest

from botshield_test import apache as _apache
from botshield_test import ips as _ips
from botshield_test import logs as _logs
from botshield_test import cookies as _cookies


# ---------------------------------------------------------------------------
# Flake control (M11.7)
#
# pytest-rerunfailures' `flaky` marker retries a failed test N times
# before reporting failure. We apply it narrowly — only to tests tagged
# @pytest.mark.live_network — because:
#   1. Retrying unit logic that fails is harmful (masks real bugs).
#   2. Third-party captcha siteverify endpoints genuinely flake: rate
#      limits, maintenance windows, network blips. A single retry
#      absorbs those without cost to signal quality.
#
# Implementing this via a collection hook rather than decorating each
# test keeps the test bodies clean and guarantees every live_network
# test inherits the policy automatically.
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.get_closest_marker("live_network") is not None:
            # 2 retries = up to 3 total attempts per failing test. Only
            # kicks in when the initial run failed; passes are not
            # re-run.
            item.add_marker(pytest.mark.flaky(reruns=2, reruns_delay=1))


@pytest.fixture(scope="session")
def apache():
    """Session-level sanity: Apache is running and the dev vhost
    responds. Tests don't need this directly unless they're about to
    reset state; most use Apache implicitly via the HTTP client."""
    from botshield_test import client

    resp = client.get("/botshield/metrics", timeout=5)
    assert resp.status_code in (200, 401, 403), (
        f"/botshield/metrics returned {resp.status_code}; is Apache up?"
    )
    return True


@pytest.fixture
def fresh_ip():
    """Return a Bloom-fresh client IP. Each call returns a distinct
    address; safe to call multiple times in one test."""
    return _ips.fresh_ip()


@pytest.fixture
def rate_slot_ip():
    """IP from 198.51.100.0/24 picked for rate-limit-slot uniqueness."""
    return _ips.fresh_ip(rate_slot=True)


@pytest.fixture
def log_slice():
    """Yield a LogSlice bound to the current error-log offset.

    Usage:
        def test_something(log_slice):
            with log_slice as slc:
                # drive traffic
                lines = slc.decision_lines(outcome="rejected")
                assert lines
    """
    return _logs.log_slice()


@pytest.fixture
def config_override():
    """Hand the caller the `apache.config_override` context manager.

    Not called directly as a fixture — the test uses it as a
    `with` block:

        def test_foo(config_override):
            with config_override(
                r"BotShieldCaptchaTimeout\\s+\\d+",
                "BotShieldCaptchaTimeout 100",
            ):
                ...
    """
    return _apache.config_override


@pytest.fixture
def pending_cookie():
    """Factory fixture: `pending_cookie("hcaptcha-demo")` → string
    cookie value. Calling it multiple times mints distinct cookies."""
    return _cookies.fetch_pending_cookie


@pytest.fixture
def clean_state():
    """Wipe state file + restart Apache. Only use when the test
    genuinely needs empty Bloom + empty flagged-IP table.

    Expensive (restart ~2s). Prefer a fresh IP when that admits the
    same assertion.
    """
    _apache.reset_state()
    yield
    # No teardown: state accumulates naturally, and the next clean_state
    # caller will wipe again if they need to.


# ---------------------------------------------------------------------------
# Playwright / browser fixtures (M11.6)
#
# pytest-playwright ships `page` / `context` / `browser` fixtures by
# default. We layer our own on top so every browser test gets:
#   - self-signed cert trusted
#   - XFF header injected (so tests can pick fresh Bloom-clean IPs the
#     same way httpx tests do)
#   - Accept-Language *omitted* by default, because Chromium's locale
#     default would keep scores below the silent-tier threshold and
#     make the form-tier journey untestable. Tests that need to look
#     like a well-behaved browser add it back explicitly.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Override the stock pytest-playwright fixture so every context
    trusts the dev cert."""
    return {**browser_context_args, "ignore_https_errors": True}


@pytest.fixture
def bs_browser_context(browser, fresh_ip):
    """A Chromium context pinned to one Bloom-fresh IP via
    X-Forwarded-For and with Accept-Language blank — the shape that
    lands a cookieless request in silent / form tier.

    Test that wants to look like a well-behaved browser (to exercise
    the pass path) should override the headers via
    `ctx.set_extra_http_headers(...)` or use `bs_browser_context_pass`.
    """
    ctx = browser.new_context(
        ignore_https_errors=True,
        extra_http_headers={
            "X-Forwarded-For": fresh_ip,
            "Accept-Language": "",
        },
    )
    yield ctx
    ctx.close()


@pytest.fixture
def bs_browser_context_pass(browser, fresh_ip):
    """A Chromium context shaped like a real human visitor: fresh IP,
    Accept-Language set, no scraper heuristics tripped. Should land
    at pass tier with no challenge."""
    ctx = browser.new_context(
        ignore_https_errors=True,
        locale="en-US",
        extra_http_headers={"X-Forwarded-For": fresh_ip},
    )
    yield ctx
    ctx.close()


@pytest.fixture
def bs_browser_context_form(browser, fresh_ip):
    """A Chromium context shaped to land at form tier (the click-to-
    verify variant), as opposed to silent tier's auto-submit.

    Form tier requires score in [50, 80): strong enough to trip a
    challenge but under the captcha threshold. Scraper UA
    ("python-requests") contributes +50 via scraper-ua-python;
    missing Accept-Language contributes +15; first-sight-ip +5 —
    around 70, comfortably in the form band. Matches what the
    bash-era m8_1 tests used to provoke form tier.

    Tests use this when they need a user-interactive interstitial
    (keyboard reachability, click-through a11y, visible labels).
    """
    ctx = browser.new_context(
        ignore_https_errors=True,
        user_agent="python-requests/2.31",
        extra_http_headers={
            "X-Forwarded-For": fresh_ip,
            "Accept-Language": "",
        },
    )
    yield ctx
    ctx.close()
