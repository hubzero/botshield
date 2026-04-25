"""Cookie helpers: pending cookie fetch + HMAC cookie assembly.

The PoW solver moves here from `tests/tools/solve_pow.py` so every
cookie operation lives in one module.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

from . import client


def fetch_pending_cookie(demo_path: str = "captcha-demo") -> str:
    """Visit a demo path cookieless and return the raw value of the
    `_bs_captcha_pending` cookie that the module mints.

    `demo_path` is the route *without* leading slash (e.g.
    `captcha-demo`, `hcaptcha-demo`). The caller never adds the slash
    — that's the job of this function so it reads cleanly at call
    sites.
    """
    resp = client.get(f"/{demo_path}")
    cookie = resp.cookies.get("_bs_captcha_pending")
    if cookie is None:
        raise AssertionError(
            f"no _bs_captcha_pending minted from /{demo_path}; "
            f"module may not be serving the captcha interstitial"
        )
    return cookie


# window.__bsChallenge = { ... };  — captured from the interstitial HTML
_CHALLENGE_RX = re.compile(r"window\.__bsChallenge=(\{[^;]+);?")


def extract_challenge(html: str) -> dict:
    """Pull the JSON payload of `window.__bsChallenge = {...};` out of
    an interstitial page.

    Raises AssertionError if not found — a missing challenge means the
    request didn't land in silent/form/captcha tier.
    """
    m = _CHALLENGE_RX.search(html)
    if not m:
        raise AssertionError("no window.__bsChallenge JSON in response body")
    return json.loads(m.group(1))


# ---------------------------------------------------------------------------
# SHA-256 leading-zero-hex PoW solver (from tests/tools/solve_pow.py).
# The module expects a 15-field `_bs_verified` cookie; solve_pow() returns
# the counter, cookie_payload() assembles the full envelope.
# ---------------------------------------------------------------------------

def solve_pow(challenge: dict, *, limit: int = 10_000_000) -> int:
    """Solve the SHA-256 leading-zero-hex-digits PoW; return the
    counter that produced a matching hash."""
    salt = bytes.fromhex(challenge["salt"])
    nonce = bytes.fromhex(challenge["nonce"])
    d = challenge["difficulty"]
    full = d // 2
    half = d & 1
    for counter in range(limit):
        h = hashlib.sha256(salt + nonce + str(counter).encode()).digest()
        if any(h[i] for i in range(full)):
            continue
        if half and (h[full] >> 4):
            continue
        return counter
    raise AssertionError(f"PoW not solved in {limit} attempts")


def build_cookie(challenge: dict, counter: int) -> str:
    """Assemble the cookie payload from a parsed challenge JSON.

    Dispatches on the JSON shape:
      - GCM mode (E8.1): challenge carries an opaque `cookie_prefix`
        base64 envelope from the module. Cookie = `<prefix>.<counter>`.
      - Legacy HMAC mode: challenge carries cleartext canonical
        fields + signature. Cookie = base64 of the 15-field
        pipe-delimited payload.
    """
    if "cookie_prefix" in challenge:
        return f"{challenge['cookie_prefix']}.{counter}"
    fields = [
        challenge["v"], challenge["alg"],
        challenge["salt"], challenge["nonce"], challenge["difficulty"],
        challenge["expires_at"],
        challenge["score"], challenge["flags"],
        challenge["passes_silent"], challenge["passes_form"],
        challenge["passes_captcha"],
        challenge["challenged_at"], challenge["auto"],
        challenge["signature"], counter,
    ]
    joined = "|".join(str(f) for f in fields).encode()
    return base64.b64encode(joined).decode()


def tamper_signature(cookie: str) -> str:
    """Flip one hex character of the HMAC signature (field 13) in an
    assembled legacy `_bs_verified` cookie. Used to prove the module
    rejects a forged signature."""
    raw = base64.b64decode(cookie).decode()
    fields = raw.split("|")
    sig = list(fields[13])
    # Deterministic flip: a↔b. Any in-place change invalidates the HMAC.
    sig[0] = "b" if sig[0] == "a" else "a"
    fields[13] = "".join(sig)
    return base64.b64encode("|".join(fields).encode()).decode()


def tamper_envelope(cookie: str) -> str:
    """Flip one base64 character of the GCM envelope (everything
    before the last '.'). Mutating any byte in alg_id/nonce/ct/tag
    causes GCM tag verification to fail. Counterpart of
    tamper_signature for E8.1 GCM-format cookies."""
    head, sep, counter = cookie.rpartition(".")
    if not sep:
        raise AssertionError("not a GCM-format cookie (no '.' separator)")
    # Flip the leading char of the base64 envelope. Any single-char
    # change inside the envelope changes one ciphertext (or tag, or
    # nonce) byte after base64-decode, which breaks GCM auth.
    flipped = ("b" if head[0] == "a" else "a") + head[1:]
    return f"{flipped}.{counter}"
