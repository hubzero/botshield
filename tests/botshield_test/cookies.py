"""Cookie helpers: pending cookie fetch + GCM cookie assembly.

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
# Cookie wire form is base64(GCM envelope) "." counter; build_cookie()
# composes the value the JS would assemble in production.
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

    The challenge carries an opaque `cookie_prefix` (base64-encoded
    AES-256-GCM envelope of the canonical form). Cookie value =
    `<prefix>.<counter>`.
    """
    return f"{challenge['cookie_prefix']}.{counter}"


def tamper_envelope(cookie: str) -> str:
    """Flip one base64 character of the GCM envelope (everything
    before the last '.'). Mutating any byte in alg_id/nonce/ct/tag
    causes GCM tag verification to fail."""
    head, sep, counter = cookie.rpartition(".")
    if not sep:
        raise AssertionError("not a GCM-format cookie (no '.' separator)")
    # Flip the leading char of the base64 envelope. Any single-char
    # change inside the envelope changes one ciphertext (or tag, or
    # nonce) byte after base64-decode, which breaks GCM auth.
    flipped = ("b" if head[0] == "a" else "a") + head[1:]
    return f"{flipped}.{counter}"
