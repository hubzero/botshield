"""M11.8: MPM-matrix tests.

A small set of assertions re-run against each Apache MPM
(event / worker / prefork). Catches regressions that only show up
under one serving model — prefork has no thread contention at all,
event/worker do. The module's SHM seqlocks, rate-limit ring, and
captcha-verify inflight semaphore all behave measurably differently
across MPMs.

Session-scoped switch + restart cost is ~5s per MPM, so this test
file is @slow and @serial. The graceful-restart counter reset
property means we cannot share this fixture with non-MPM tests in
the same pytest run without giving up counter continuity.

Opt in with:
  tests/run --slow --match mpm_matrix
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from botshield_test import apache, client, cookies, ips


pytestmark = [pytest.mark.slow, pytest.mark.serial]


@pytest.fixture(scope="module", params=apache._MPMS)
def mpm(request):
    """Switch Apache to the parametrized MPM for the duration of
    this module, restore to 'event' on teardown.

    Parametrized at session scope so the 5-second restart happens
    once per MPM, not once per test. All tests requesting `mpm`
    group by parametrize value — pytest runs all tests at event,
    then all at worker, then all at prefork.
    """
    name = request.param
    apache.switch_mpm(name)
    # Give workers a moment to fully ramp; under prefork a startup
    # burst can race the first request.
    time.sleep(1)
    yield name
    # Teardown: restore the default MPM so subsequent pytest
    # invocations (or CI's soak step) don't run under a surprise
    # serving model.
    apache.switch_mpm("event")


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


# --- Assertion 1: cookie HMAC round-trip works on every MPM ------------------

def test_cookie_hmac_roundtrip(mpm):
    """Silent-tier PoW solve → cookie replay accepts under every MPM."""
    ip = ips.fresh_ip()
    resp = client.get("/", xff=ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)
    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    resp = client.get(
        "/", xff=ip, ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_verified": cookie},
    )
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"cookie replay challenged on MPM={mpm}"
    )


# --- Assertion 2: flagged-IP SHM visible after honeypot hit ------------------

def test_flagged_ip_visible(mpm):
    """Honeypot trip on one request must be visible to the next.

    Interesting on prefork: multiple worker processes don't share
    thread state, so the SHM read path is exercised. On event /
    worker the same process might handle both requests and see the
    write via in-thread state, so this probes a different code path
    per MPM.
    """
    ip = ips.fresh_ip(rate_slot=True)

    client.get("/admin/.env", xff=ip)
    # Flag write goes through the mutex; pessimistic wait.
    time.sleep(1)

    resp = client.get("/", xff=ip)
    # We're reading the outcome via the decision log rather than
    # response headers so the assertion shape is MPM-agnostic.
    # Simpler check: the header carries "challenge" (form tier from
    # the flag penalty) rather than "" (pass).
    xbs = resp.headers.get("X-Botshield", "")
    assert xbs == "challenge", (
        f"flagged IP didn't re-challenge on MPM={mpm}: "
        f"X-Botshield={xbs!r}"
    )


# --- Assertion 3: per-IP rate limit fires on every MPM -----------------------

def _fire_verify(pending: str, ip: str):
    return client.post(
        "/botshield/captcha-verify/turnstile",
        xff=ip,
        cookies={"_bs_captcha_pending": pending},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )


def test_rate_limit_fires(mpm):
    """40 parallel POSTs from one IP must produce at least one 429
    on every MPM. prefork has per-process workers; the rate-limit
    ring is process-shared via SHM, so the serialization behaves
    differently but the outcome must be the same."""
    pending = cookies.fetch_pending_cookie("captcha-demo")
    ip = ips.fresh_ip(rate_slot=True)

    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = [pool.submit(_fire_verify, pending, ip) for _ in range(40)]
        responses = [f.result() for f in futures]

    n_429 = sum(1 for r in responses if r.status_code == 429)
    assert n_429 >= 1, (
        f"no 429 across 40 parallel POSTs on MPM={mpm}; "
        f"status distribution: "
        f"{dict((r.status_code, sum(1 for x in responses if x.status_code == r.status_code)) for r in responses)}"
    )
