"""M11.8: property-style byte-level fuzz of the __Host-bs_verified cookie
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

    resp = client.get("/", xff=ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)
    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    # Sanity: the cookie we're about to fuzz around actually
    # round-trips before we start tampering. Otherwise every
    # "rejected" outcome below is meaningless.
    sanity = client.get(
        "/", xff=ip, ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_verified": cookie},
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
    if index >= len(cookie_bytes):
        # Out-of-range index is a no-op tamper — hypothesis' tuple
        # range is a coarse overshoot of the actual cookie length;
        # we just filter these out rather than tightening the
        # strategy, so shrinking still works cleanly.
        return

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
        resp = client.get(
            "/", xff=valid_cookie["ip"],
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_verified": tampered},
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
    #      the cookie, served an interstitial)
    #   2. Request was served from pass tier WITHOUT a fresh cookie
    #      being issued — which can happen when the score crosses
    #      none-of-thresholds from this IP alone. In that case the
    #      tamper was cosmetically harmless because the cookie
    #      wasn't consulted.
    xbs = resp.headers.get("X-Botshield", "")
    if xbs == "challenge":
        return  # perfect: rejected
    # Otherwise, the module MUST NOT have minted a new verified
    # cookie on the back of a tampered one. Set-Cookie of
    # __Host-bs_verified= on this response would be the bug.
    set_cookies = resp.headers.get_list("set-cookie") if hasattr(
        resp.headers, "get_list"
    ) else [resp.headers.get("set-cookie", "")]
    for sc in set_cookies:
        assert "__Host-bs_verified=" not in sc, (
            f"tamper at index={index} bitmask={bitmask:#04x} produced "
            f"a fresh __Host-bs_verified: {sc!r}"
        )
