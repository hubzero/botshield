#!/usr/bin/env python3
"""Solve a SHA-256 leading-zero-hex-digits PoW and print a
base64-encoded bs_verified cookie payload.

Used by tests/integration/m7_silent_tier.sh to replay a solve without
actually loading the JS worker in a browser.

Input: a JSON challenge (window.__bsChallenge from the interstitial)
on stdin. Output: the base64 cookie value on stdout, ready to hand to
curl -b "_bs_verified=<value>".
"""
import base64
import hashlib
import json
import sys


def solve(ch):
    salt = bytes.fromhex(ch["salt"])
    nonce = bytes.fromhex(ch["nonce"])
    d = ch["difficulty"]
    full = d // 2
    half = d & 1
    for counter in range(10_000_000):
        h = hashlib.sha256(salt + nonce + str(counter).encode()).digest()
        if any(h[i] for i in range(full)):
            continue
        if half and (h[full] >> 4):
            continue
        return counter
    raise SystemExit("PoW not found under 10M attempts")


def cookie_payload(ch, counter):
    """Mirror bs_challenge_canonical + the cookie tail (sig, counter)."""
    fields = [
        ch["v"], ch["alg"], ch["salt"], ch["nonce"], ch["difficulty"],
        ch["expires_at"],
        ch["score"], ch["flags"],
        ch["passes_silent"], ch["passes_form"], ch["passes_captcha"],
        ch["challenged_at"], ch["auto"],
        ch["signature"], counter,
    ]
    joined = "|".join(str(f) for f in fields).encode()
    return base64.b64encode(joined).decode()


if __name__ == "__main__":
    ch = json.load(sys.stdin)
    counter = solve(ch)
    print(cookie_payload(ch, counter))
