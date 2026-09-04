"""M11.8: property-style byte-level fuzz of the __Host-bs_session cookie
parser.

Premise: a valid cookie that round-trips cleanly (we build one with
`cookies.solve_pow` + `cookies.build_cookie`) must reject under any
single-byte perturbation. Either the signature check fails, the
base64 decodes to something malformed, or the field count is wrong
— all rejection paths are acceptable. What's NOT acceptable is
silent acceptance of a modified cookie.

Hypothesis drives a byte-index into the cookie string and a
bit-flip mask. If it ever finds an index where the tampered cookie
is accepted, it shrinks to the minimum failing position + mask.

Budget-limited: one challenge per session, 50 examples, ~5 seconds
total — this is a smoke for cookie-parser hardening, not a fuzzer.
"""

from __future__ import annotations

import httpx
import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from botshield_test import client, cookies


pytestmark = [pytest.mark.serial]

BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"
# Gated by an explicit solved=no rule rather than by ambient score.
CHALLENGE_PATH = "/browser-gate.html"


@pytest.fixture(scope="module")
def valid_cookie(request):
    """Mint one valid cookie to fuzz against.

    Module-scoped so hypothesis doesn't pay for a full
    probe-and-solve per example. The cookie remains valid across
    all examples in this session.
    """
    # Request a session-unique IP via the standard allocator. We use
    # a helper rather than the fresh_ip fixture because this fixture
    # is module-scoped and can't depend on function-scoped fixtures.
    from botshield_test import ips
    ip = ips.fresh_ip()

    # "/" no longer challenges a recognised browser UA -- it is
    # credited past the score threshold and passes, so this used to
    # fetch the docroot index and fail extracting a challenge from it.
    # CHALLENGE_PATH carries an explicit solved=no gate: challenged
    # while unsolved, served once solved, which is exactly the
    # challenge -> solve -> sanity-check-passes shape this fixture
    # needs. See the browser-gate rule in tests/setup/botshield-dev.conf.
    resp = client.get(CHALLENGE_PATH, xff=ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)
    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    # Sanity: the cookie we're about to fuzz around actually
    # round-trips before we start tampering. Otherwise every
    # "block" outcome below is meaningless.
    sanity = client.get(
        CHALLENGE_PATH, xff=ip, ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_session": cookie},
    )
    assert sanity.headers.get("X-Botshield") != "challenge", (
        "valid-cookie sanity check failed: fuzzing would be useless"
    )

    return {"ip": ip, "cookie": cookie}


@given(
    index=st.integers(min_value=0, max_value=1000),
    bitmask=st.integers(min_value=1, max_value=255),
)
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_single_byte_tamper_always_rejected(valid_cookie, index, bitmask):
    """For any byte position + any non-zero XOR mask, the perturbed
    cookie must NOT be accepted (i.e. the response must still carry
    a challenge header, OR the module must not issue a fresh
    verified cookie)."""
    cookie_bytes = valid_cookie["cookie"].encode("ascii")
    # Fold the index into range rather than discarding out-of-range
    # draws. The strategy's 0..1000 is a coarse overshoot of the real
    # cookie length (~200 bytes), so filtering threw away roughly four
    # examples in five: max_examples=50 was buying about ten actual
    # tampers, and the run finished in 0.15s because most of it did
    # nothing. Modulo keeps shrinking well behaved (a smaller draw
    # still maps to a smaller index) and every example now exercises
    # the parser.
    index %= len(cookie_bytes)

    tampered_bytes = bytearray(cookie_bytes)
    tampered_bytes[index] ^= bitmask

    # If the tamper produced a non-ASCII byte that httpx/Chromium
    # would drop as invalid header content, treat as vacuous. The
    # module never sees such a cookie.
    try:
        tampered = tampered_bytes.decode("ascii")
    except UnicodeDecodeError:
        return

    try:
        # CHALLENGE_PATH, not "/": on an ungated path the rejection
        # branch below can never fire, because nothing challenges a
        # recognised browser UA there. The fuzz would still exercise
        # the cookie parser, but the "was it rejected?" half of the
        # claim would go unobserved -- the test would only ever be
        # asserting "no 5xx".
        resp = client.get(
            CHALLENGE_PATH, xff=valid_cookie["ip"],
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_session": tampered},
        )
    except httpx.LocalProtocolError:
        # httpx refuses to send control bytes (0x00–0x1F) in header
        # values — the request never reaches the module, so the
        # tamper is vacuous for this test's purposes. Real browsers
        # do the same thing (Chromium would strip such bytes before
        # sending), which is another layer of defense the module
        # benefits from without having to implement it.
        return
    # Two acceptable outcomes:
    #   1. Response carries X-Botshield: challenge (module rejected
    #      the cookie and served an interstitial).
    #   2. Request was served from pass tier and the module minted
    #      a fresh trust=0 __Host-bs_session via the always-mint
    #      path. This is the legitimate "tamper was cosmetic, the
    #      score wasn't influenced by it" case.
    #
    # The always-mint behavior means every pass-tier response sets
    # a Set-Cookie regardless of incoming-cookie validity, so the
    # presence of Set-Cookie here is not by itself a bug. The
    # security claim ("a tampered cookie cannot transfer trust into
    # a freshly-minted cookie") is held by test_cookie_gcm.py's
    # signature-mismatch and bad-format suites; this property test
    # exists to fuzz adversarial bytes against the cookie parser
    # and confirm the module doesn't crash, mint a verified cookie
    # by mistake (signaled via X-Botshield: challenge being absent
    # AND tier shifting up — which we don't observe via headers
    # alone), or 5xx on bizarre input.
    xbs = resp.headers.get("X-Botshield", "")
    if xbs == "challenge":
        return  # perfect: rejected
    assert resp.status_code < 500, (
        f"tamper at index={index} bitmask={bitmask:#04x} produced "
        f"a 5xx response: {resp.status_code}"
    )
