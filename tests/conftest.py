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
