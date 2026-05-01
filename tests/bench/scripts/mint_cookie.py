#!/usr/bin/env python3
"""Mint a valid `_bs_session` cookie for the bench vhost.

Hits the bench endpoint with a scraper UA to force the silent
challenge tier, parses the challenge JSON out of the interstitial,
solves the SHA-256 leading-zero PoW locally, and writes the
resulting cookie value to stdout.

The cookie value is `<base64-GCM-envelope>.<solved-counter>`.
The envelope is server-signed (server produced it during challenge
issuance); the counter satisfies the PoW difficulty embedded in
the envelope's plaintext fields. Subsequent requests presenting
this cookie hit the happy-cached-pass path: GCM-decrypt, verify
PoW counter against the envelope's salt+nonce+difficulty, accept,
DECLINED to the static handler.

Used by tests/bench/run-bench.sh for the cookied scenario; the
output is exported to BENCH_COOKIE which wrk-cookie.lua attaches
as the Cookie header on every request.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request

URL = "http://127.0.0.1:8080/bench.html"
SCRAPER_UA = "python-requests/2.31"
PNG_LIMIT = 10_000_000

CHALLENGE_RX = re.compile(r"window\.__bsChallenge\s*=\s*(\{[^;]+);?")


def fetch_challenge() -> dict:
    req = urllib.request.Request(URL, headers={"User-Agent": SCRAPER_UA})
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    m = CHALLENGE_RX.search(body)
    if not m:
        sys.exit(
            "mint_cookie: no window.__bsChallenge JSON in response. "
            "The bench scope did not issue a silent challenge — "
            "check that BotShieldEnabled is on and that the heuristic "
            "score for a scraper UA crosses the silent threshold."
        )
    return json.loads(m.group(1))


def solve_pow(ch: dict) -> int:
    salt = bytes.fromhex(ch["salt"])
    nonce = bytes.fromhex(ch["nonce"])
    d = int(ch["difficulty"])
    full = d // 2
    half = d & 1
    for counter in range(PNG_LIMIT):
        h = hashlib.sha256(salt + nonce + str(counter).encode()).digest()
        if any(h[i] for i in range(full)):
            continue
        if half and (h[full] >> 4):
            continue
        return counter
    sys.exit(f"mint_cookie: PoW not solved in {PNG_LIMIT} attempts "
             f"(difficulty={d} unusually high?)")


def main() -> int:
    ch = fetch_challenge()
    counter = solve_pow(ch)
    sys.stdout.write(f"{ch['cookie_prefix']}.{counter}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
