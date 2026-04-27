"""E8.1 — AES-256-GCM cookie confidentiality + BotShieldCookieFormat
compat switch.

Pre-E8.1 the `__Host-bs_verified` cookie was an HMAC-SHA-256 envelope:
fields cleartext, integrity tag at the end. Anyone base64-decoding
read the rep block (score, flag bitmap, pass counters) in the clear.
E8.1 adds an AES-256-GCM wire format that wraps the same canonical
form but the rep block stays confidential.

Wire format under GCM:
    base64(alg_id(0x01) || nonce(12) || ciphertext || tag(16)) + "." + counter

`BotShieldCookieFormat` controls the issue-side preference and the
verify-side allow list:
    hmac        legacy only (default until operator opts in)
    gcm         issue + verify GCM only; legacy cookies rejected
    gcm,hmac    issue GCM, accept either on verify (migration mode)

These tests confirm: (1) GCM cookies round-trip end-to-end, (2) the
JSON the JS sees omits the rep block under GCM, (3) tampering with
the envelope fails the GCM tag check, (4) compat mode accepts a
legacy HMAC cookie issued before the upgrade, (5) `gcm`-only mode
rejects legacy HMAC cookies, (6) the directive itself rejects bogus
values.
"""

from __future__ import annotations

import base64

import pytest

from botshield_test import client, cookies


pytestmark = pytest.mark.serial


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


# --- Directive validation ------------------------------------------


def test_cookie_format_rejects_unknown_value(config_override):
    """A bogus format token fails configtest at parse time; Apache
    refuses to reload, the context manager surfaces it as an
    exception."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldAllow\s+on",
            'BotShieldAllow on\n'
            '    BotShieldCookieFormat foobar',
            count=1,
        ):
            pass


# --- GCM mode roundtrip + JSON shape -------------------------------


def test_gcm_mode_roundtrip(config_override, fresh_ip):
    """End-to-end: under cookie_format=gcm the JS sees a minimal JSON
    (no rep block), solves the PoW, assembles `<cookie_prefix>.<counter>`,
    and the module accepts the cookie on the next request."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieFormat gcm',
        count=1,
    ):
        # Silent-tier probe gets us a challenge page.
        resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
        challenge = cookies.extract_challenge(resp.text)

        # GCM JSON deliberately omits the rep block — the whole point
        # of encryption is that score / flags / passes_* / signature
        # don't reach the client. Salt / nonce / difficulty are still
        # present so the JS can compute the PoW.
        assert "cookie_prefix" in challenge, (
            f"GCM JSON missing cookie_prefix; keys={sorted(challenge)}"
        )
        for leak in ("score", "flags", "signature",
                     "passes_silent", "passes_form", "passes_captcha"):
            assert leak not in challenge, (
                f"GCM JSON should not expose '{leak}'; "
                f"keys={sorted(challenge)}"
            )

        # The shipped cookies.build_cookie helper dispatches on shape:
        # GCM JSON → '<prefix>.<counter>'.
        counter = cookies.solve_pow(challenge)
        cookie = cookies.build_cookie(challenge, counter)
        assert "." in cookie, (
            f"GCM cookie should carry the dot separator; got {cookie[:60]}…"
        )

        # Replay the cookie on a normal request — should NOT be
        # re-challenged.
        resp = client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_verified": cookie},
        )
        assert resp.headers.get("X-Botshield") != "challenge", (
            f"valid GCM cookie was challenged; "
            f"X-Botshield={resp.headers.get('X-Botshield')}"
        )


# --- Confidentiality: rep block must not appear in cleartext --------


def test_gcm_cookie_envelope_is_random_bytes(config_override, fresh_ip):
    """Decoding the GCM envelope from the cookie_prefix should give
    high-entropy bytes — none of the canonical-form ASCII separators
    (`|`) should be visible. A failure here would mean the encryption
    isn't actually happening."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieFormat gcm',
        count=1,
    ):
        resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
        challenge = cookies.extract_challenge(resp.text)

    prefix_b64 = challenge["cookie_prefix"]
    decoded = base64.b64decode(prefix_b64)
    # First byte is alg_id = 0x01, the rest is nonce/ct/tag — all
    # high-entropy. The HMAC canonical form has lots of '|' bytes;
    # GCM ciphertext should have effectively zero ASCII '|'.
    assert decoded[0] == 0x01, (
        f"GCM envelope alg_id byte should be 0x01; got 0x{decoded[0]:02x}"
    )
    pipe_count = decoded.count(b"|")
    # 1/256 odds per byte, 13 fields fit in ~140 bytes — expect 0
    # most of the time, well under 5 with comfortable margin.
    assert pipe_count < 5, (
        f"GCM envelope has {pipe_count} '|' bytes; cleartext canonical "
        f"would have ~12 — encryption may not be running"
    )


# --- Tamper detection ----------------------------------------------


def test_gcm_tampered_envelope_rejected(config_override, fresh_ip,
                                        log_slice):
    """Flipping one base64 char of the envelope changes a byte after
    base64-decode and breaks GCM tag verification. The module rejects
    the cookie with the same `signature mismatch` reason it uses for
    HMAC failures (callers don't carry rep forward in either case)."""
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieFormat gcm',
        count=1,
    ):
        resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
        challenge = cookies.extract_challenge(resp.text)
        counter = cookies.solve_pow(challenge)
        cookie = cookies.build_cookie(challenge, counter)

        tampered = cookies.tamper_envelope(cookie)
        with log_slice as slc:
            client.get(
                "/", xff=fresh_ip,
                ua=BROWSER_UA, accept_language="en-US",
                cookies={"__Host-bs_verified": tampered},
            )
            matches = slc.grep(
                r"__Host-bs_verified rejected: signature mismatch"
            )

    assert matches, (
        "expected 'signature mismatch' in log slice for tampered GCM "
        f"envelope; tail: {slc.text().splitlines()[-5:]}"
    )


# --- Compat mode (gcm,hmac): legacy HMAC cookie still verifies ------


def test_compat_mode_accepts_legacy_hmac_cookie(
    config_override, fresh_ip,
):
    """Operator's migration path: `BotShieldCookieFormat hmac`
    (default) → `gcm,hmac` (issue GCM, accept either) → `gcm`.
    The middle step must accept any HMAC cookies issued under the
    previous step. Issue here, replay there."""
    # Step 1: legacy HMAC mode. Earn a cookie.
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieFormat hmac',
        count=1,
    ):
        resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
        challenge = cookies.extract_challenge(resp.text)
        # HMAC mode → JSON has the legacy fields including signature.
        assert "signature" in challenge, (
            f"HMAC JSON should expose signature; keys={sorted(challenge)}"
        )
        counter = cookies.solve_pow(challenge)
        hmac_cookie = cookies.build_cookie(challenge, counter)

    # Step 2: compat mode. Replay the HMAC cookie — should verify.
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieFormat gcm,hmac',
        count=1,
    ):
        resp = client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"__Host-bs_verified": hmac_cookie},
        )

    assert resp.headers.get("X-Botshield") != "challenge", (
        "compat mode (gcm,hmac) should accept a legacy HMAC cookie; "
        f"got X-Botshield={resp.headers.get('X-Botshield')}"
    )


# --- Strict GCM-only mode rejects legacy HMAC cookies --------------


def test_gcm_only_mode_rejects_hmac_cookie(
    config_override, fresh_ip, log_slice,
):
    """End of the migration: operator flips to `BotShieldCookieFormat
    gcm`. Any leftover HMAC cookies that haven't aged out yet hit the
    'HMAC cookies not accepted' rejection — log shows it; client gets
    re-challenged."""
    # Step 1: HMAC mode. Earn a cookie.
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieFormat hmac',
        count=1,
    ):
        resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
        challenge = cookies.extract_challenge(resp.text)
        counter = cookies.solve_pow(challenge)
        hmac_cookie = cookies.build_cookie(challenge, counter)

    # Step 2: GCM-only. Legacy HMAC cookie must be refused.
    with config_override(
        r"BotShieldAllow\s+on",
        'BotShieldAllow on\n'
        '    BotShieldCookieFormat gcm',
        count=1,
    ):
        with log_slice as slc:
            client.get(
                "/", xff=fresh_ip,
                ua=BROWSER_UA, accept_language="en-US",
                cookies={"__Host-bs_verified": hmac_cookie},
            )
            matches = slc.grep(
                r"__Host-bs_verified rejected: HMAC cookies not accepted"
            )

    assert matches, (
        "expected 'HMAC cookies not accepted' rejection under "
        "BotShieldCookieFormat gcm; "
        f"tail: {slc.text().splitlines()[-5:]}"
    )
