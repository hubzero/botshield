"""AES-256-GCM cookie confidentiality.

The `__Host-bs_session` cookie is an AES-256-GCM envelope wrapping the
canonical pipe-delimited form. Wire format:

    base64( alg_id(1) || nonce(12) || ct || tag(16) ) "." counter

Cookie format consolidation (this commit) removed the legacy
HMAC-SHA-256 cleartext envelope and the `BotShieldCookieFormat`
selector — GCM is now the only on-the-wire format.

These tests confirm: (1) GCM cookies round-trip end-to-end, (2) the
JSON the JS sees omits the rep block (cookie_prefix is opaque),
(3) tampering with the envelope fails the GCM tag check, (4) the old
HMAC-shape cookie (no '.' separator) is rejected, (5) the retired
`BotShieldCookieFormat` directive name is unknown.
"""

from __future__ import annotations

import base64

import pytest

from botshield_test import client, cookies


pytestmark = [pytest.mark.serial]

BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


# --- Retired directive --------------------------------------------

def test_cookie_format_directive_unknown(config_override):
    """`BotShieldCookieFormat` was removed when the wire format
    consolidated to GCM-only. Inserting it into the dev vhost should
    make Apache refuse to reload."""
    # Splice the retired directive in next to BotShieldAlgorithm,
    # which exists in the dev vhost. Apache's reload() in the
    # config_override fixture raises CalledProcessError when the
    # syntax check fails.
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldAlgorithm\s+sha256-zeros",
            "BotShieldAlgorithm sha256-zeros\n"
            "    BotShieldCookieFormat gcm",
        ):
            pass
    msg = str(exc_info.value)
    assert "BotShieldCookieFormat" in msg or "Invalid command" in msg or \
           "returned non-zero exit status" in msg, (
        f"expected reload failure for retired BotShieldCookieFormat "
        f"directive; got: {msg!r}"
    )


# --- GCM roundtrip + JSON shape -----------------------------------

def test_gcm_mode_roundtrip(fresh_ip):
    """End-to-end: the silent-tier interstitial JSON carries
    `cookie_prefix` (no rep fields). Solving the PoW and replaying
    the assembled cookie passes verify."""
    resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)

    # GCM JSON deliberately omits the rep block — the whole point
    # of the encrypted envelope is to hide rep state from the
    # client. Only `cookie_prefix` rides in the JSON.
    assert "cookie_prefix" in challenge, (
        f"GCM JSON missing cookie_prefix; keys={sorted(challenge)}"
    )
    for leak in ("score", "flags", "passes_silent",
                 "passes_form", "passes_captcha", "signature"):
        assert leak not in challenge, (
            f"GCM JSON should not expose '{leak}'; "
            f"keys={sorted(challenge)}"
        )

    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    # GCM cookie shape: '<base64-prefix>.<counter>'.
    assert "." in cookie, (
        f"GCM cookie should carry the dot separator; got {cookie[:60]}…"
    )

    resp = client.get(
        "/", xff=fresh_ip,
        ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_session": cookie},
    )
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"valid GCM cookie was challenged; "
        f"headers={dict(resp.headers)}"
    )


def test_gcm_cookie_envelope_is_random_bytes(fresh_ip):
    """Decoding the base64 envelope from `cookie_prefix` should give
    high-entropy bytes. The first byte is alg_id (currently 0x01),
    then 12-byte nonce, ciphertext, 16-byte tag — none of which
    should look like the legacy '|'-delimited canonical form."""
    resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)

    prefix = challenge["cookie_prefix"]
    decoded = base64.b64decode(prefix)
    assert decoded[0] == 0x01, (
        f"GCM envelope alg_id byte should be 0x01; got 0x{decoded[0]:02x}"
    )
    # Pipe count in plaintext canonical is 14 (15 fields). Encrypted
    # ciphertext should be effectively random — a few '|' bytes by
    # coincidence is fine, but not 14+.
    pipe_count = decoded.count(b"|")
    assert pipe_count < 5, (
        f"GCM envelope has {pipe_count} '|' bytes; cleartext canonical "
        f"would have ~14. Encryption looks broken."
    )


# --- Tampering -----------------------------------------------------

def test_gcm_tampered_envelope_rejected(fresh_ip, log_slice):
    """Flipping a base64 character in the envelope head changes one
    ciphertext (or tag, or nonce) byte after decode, breaking GCM
    auth. The module rejects with `signature mismatch` (same string
    the legacy HMAC tamper produced — callers don't carry rep
    forward in either case)."""
    resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
    challenge = cookies.extract_challenge(resp.text)
    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    tampered = cookies.tamper_envelope(cookie)
    with log_slice as slc:
        client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_session": tampered},
        )
        matches = slc.grep(
            r"__Host-bs_session rejected: signature mismatch"
        )

    assert matches, (
        "expected 'signature mismatch' in log slice for tampered GCM "
        f"cookie; tail: {slc.text().splitlines()[-5:]}"
    )


# --- Legacy HMAC-shape cookie is rejected -------------------------

def test_legacy_hmac_shape_cookie_rejected(fresh_ip, log_slice):
    """A leftover HMAC-format cookie from before consolidation has
    no '.' separator. The verifier rejects with
    'unsupported cookie format'."""
    # Synthesize a legacy HMAC-shape blob: arbitrary base64 with no
    # '.' inside. We don't need it to be a valid signature — the
    # verifier short-circuits on the missing separator before any
    # crypto runs.
    fake_legacy = base64.b64encode(b"|" * 40 + b"deadbeef" * 4).decode()
    assert "." not in fake_legacy

    with log_slice as slc:
        client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_session": fake_legacy},
        )
        matches = slc.grep(
            r"__Host-bs_session rejected: unsupported cookie format"
        )

    assert matches, (
        "expected 'unsupported cookie format' rejection for HMAC-shape "
        f"cookie; tail: {slc.text().splitlines()[-5:]}"
    )
