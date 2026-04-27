"""M2: tampered `__Host-bs_verified` cookie must be rejected with
reason="signature mismatch".

Port of tests/integration/m2_cookie_hmac.sh. Builds a valid cookie
by solving the silent-tier PoW locally, flips one hex character of
the HMAC signature, and replays. The log slice should carry a
`__Host-bs_verified rejected: signature mismatch` line.
"""

from __future__ import annotations

from botshield_test import client, cookies


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


def test_tampered_cookie_rejected(fresh_ip, log_slice):
    # 1. Silent-tier probe: Mozilla UA + missing Accept-Language +
    #    first-sight-ip = score 20 → silent tier with a challenge.
    resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)

    # 2. Solve the PoW, assemble the 15-field cookie.
    counter = cookies.solve_pow(challenge)
    valid = cookies.build_cookie(challenge, counter)

    # 3. Sanity: the valid cookie round-trips cleanly (no challenge
    #    on replay). If this fails the tampered test is untrustworthy.
    resp = client.get(
        "/", xff=fresh_ip,
        ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_verified": valid},
    )
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"sanity check failed: valid cookie was challenged. "
        f"Headers: {dict(resp.headers)}"
    )

    # 4. Flip one byte in the HMAC signature and replay.
    tampered = cookies.tamper_signature(valid)

    with log_slice as slc:
        client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_verified": tampered},
        )
        matches = slc.grep(r"__Host-bs_verified rejected: signature mismatch")

    assert matches, (
        "expected '__Host-bs_verified rejected: signature mismatch' in log slice; "
        f"tail: {slc.text().splitlines()[-5:]}"
    )
