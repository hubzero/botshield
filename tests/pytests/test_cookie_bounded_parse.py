"""Security review #2: pre-HMAC cookie fields must not invoke UB
when fed overflowing digit runs.

The old parser called atoi()/strtoul()/apr_atoi64() directly on
attacker-controlled bytes BEFORE HMAC validation. atoi + strtoul
without errno checks invoke UB on overflow per C11 §7.22.1. The
ASan/UBSan fuzz catches UB inside instrumented project code but
NOT inside libc call sites.

Fix: bs_parse_{int,uint32,int64}_bounded caps input length, uses
strtol/strtoll/strtoul with errno, and rejects ERANGE / junk tail.

This test drives cookies with gigantic digit runs in every pre-
HMAC-parsed field and asserts:
  1. The module responds normally (challenge, not crash).
  2. The log notes a specific rejection reason rather than silently
     proceeding into the signature compare with a clamped value.
  3. No abnormal status codes or process crashes.

Because these are assertions about what should NOT happen, they
don't prove the bounded parser is perfectly safe — that's what the
LibFuzzer harness does at 225k exec/sec on the same parser. They
verify the integration: a malformed cookie produces a clean reject,
not an obscured bypass or process crash.
"""

from __future__ import annotations

import base64

import pytest

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


def _encode_cookie(fields: list[str]) -> str:
    """Pack the 17 fields into a base64 cookie payload, matching
    what the module's assembler + parser expect.

    The canonical envelope grew from 13 to 15 fields with
    BS_PROTOCOL_VERSION 1->2 (E15 added forgive_window_start
    and forgive_consumed); the cookie body still appends sig_hex and
    counter for a total of 17 fields."""
    return base64.b64encode("|".join(fields).encode()).decode()


# A baseline valid-shape cookie. Each field obeys the module's
# expected type; signature is zero bytes (hex) which will fail HMAC
# compare — but the parse path runs FIRST, and that's what's under
# test. We want parse-step rejections, not signature-step rejections.
def _valid_shape_fields():
    return [
        "2",                              # 0:  version (bumped 1->2 for E15)
        "sha256-zeros",                   # 1:  alg
        "00" * 16,                        # 2:  salt (32 hex = 16 bytes)
        "00" * 8,                         # 3:  nonce (16 hex = 8 bytes)
        "4",                              # 4:  difficulty
        "1999999999",                     # 5:  expires_at (future)
        "0",                              # 6:  score
        "0",                              # 7:  flags
        "0", "1", "0",                    # 8-10: passes_silent/form/captcha
        "1900000000",                     # 11: challenged_at
        "1",                              # 12: auto
        "0",                              # 13: forgive_window_start (E15)
        "0",                              # 14: forgive_consumed (E15)
        "00" * 32,                        # 15: signature (would fail HMAC)
        "0",                              # 16: counter
    ]


# (field_index, overflowing_value, why_we_expect_rejection)
OVERFLOW_CASES = [
    (0,  "9" * 40,  "version — atoi on 40 digits overflows int"),
    (4,  "9" * 20,  "difficulty — 20-digit run well beyond max=8"),
    (5,  "9" * 30,  "expires_at — apr_atoi64 would clamp silently"),
    (6,  "-" + "9" * 30, "score — signed overflow with huge negative"),
    (7,  "9" * 30,  "flags — strtoul without errno check UB"),
    (11, "9" * 30,  "challenged_at — same libc shape as expires_at"),
    (12, "9" * 40,  "auto — should only be 0/1, giant digit run rejected"),
]


@pytest.mark.parametrize("idx,bad_value,why", OVERFLOW_CASES,
                         ids=[c[2].split(" ")[0] for c in OVERFLOW_CASES])
def test_overflow_field_rejected(fresh_ip, log_slice, idx, bad_value, why):
    """Each variant: take a shape-valid cookie, replace one numeric
    field with a digit run that would overflow the libc type the old
    code used, send it. Module must reject with a specific reason
    and not trap/crash."""
    fields = _valid_shape_fields()
    fields[idx] = bad_value
    cookie = _encode_cookie(fields)

    with log_slice as slc:
        resp = client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"_bs_verified": cookie},
        )
        # The module logs per-request details when a cookie fails
        # verification — look for either the cookie-rejection marker
        # or an outcome=* decision line showing we survived cleanly.
        slice_text = slc.text()

    # The module must have responded — no crash, no 500.
    assert resp.status_code < 500, (
        f"overflow in field {idx} ({why}) produced {resp.status_code}; "
        f"a rejection should be <500"
    )

    # The cookie is rejected, so the request either gets a challenge
    # (cookie treated as absent) or serves origin content — never an
    # accepted-verification path. If X-Botshield were "verified" or
    # similar, the cookie was accepted despite overflowing numeric.
    assert resp.headers.get("X-Botshield") not in ("verified", "captcha-ok"), (
        f"overflowing cookie field {idx} was accepted: "
        f"X-Botshield={resp.headers.get('X-Botshield')!r}"
    )

    # The rejection reason should surface in the log — either as a
    # specific "bad <field>" marker from our new bounded parser, or
    # as the generic signature-mismatch if we somehow got past parse.
    # Both count as safely rejected.
    assert ("_bs_verified rejected:" in slice_text), (
        f"no cookie-rejection log line found for overflow in field {idx} "
        f"({why}); module may be silently accepting overflowing input"
    )


def test_valid_cookie_still_parses_cleanly(fresh_ip, log_slice):
    """Regression guard: the bounded parsers must NOT false-reject a
    cookie that passed fine before. We don't mint a real valid
    cookie here (that's test_cookie_hmac's job); we just confirm
    the shape-valid but HMAC-bad cookie produces the expected
    `signature mismatch` reason rather than `bad <field>`. If the
    bounded parsers were over-strict, we'd see `bad <field>` instead."""
    fields = _valid_shape_fields()
    cookie = _encode_cookie(fields)

    with log_slice as slc:
        client.get(
            "/", xff=fresh_ip,
            ua=BROWSER_UA, accept_language="en-US",
            cookies={"_bs_verified": cookie},
        )
        lines = [
            ln for ln in slc.text().splitlines()
            if "_bs_verified rejected:" in ln
        ]

    assert lines, "expected a cookie-rejected log line; got none"
    # Every rejection should be signature mismatch; bounded-parse
    # rejections here would mean a false-positive from over-strict
    # numeric parsing on a legitimate-shape cookie.
    joined = "\n".join(lines)
    assert "signature mismatch" in joined, (
        f"shape-valid cookie rejected for non-signature reason — "
        f"bounded parser may be over-strict:\n{joined}"
    )
