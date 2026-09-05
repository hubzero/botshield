#!/usr/bin/env python3
"""Seed tests/fuzz/corpus/ with real _bs_verified cookies + a few
hand-rolled malformed ones. LibFuzzer mutates from these as starting
points — far more effective than random-from-zero for finding
parser edge cases in a format-heavy input like the pipe-delimited
base64 cookie.

Run once after `make fuzz`:
    tests/.venv/bin/python tests/fuzz/seed_corpus.py
"""

from pathlib import Path

# Import the framework. Assumes tests/.venv has the framework
# installed (provision.sh takes care of that).
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from botshield_test import client, cookies, ips

CORPUS = Path(__file__).resolve().parent / "corpus"
CORPUS.mkdir(exist_ok=True)

BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"


def mint_real_cookie(i: int) -> bytes:
    """Solve a real silent-tier PoW and return the assembled cookie."""
    ip = ips.fresh_ip()
    resp = client.get("/", xff=ip, ua=BROWSER_UA)
    ch = cookies.extract_challenge(resp.text)
    counter = cookies.solve_pow(ch)
    return cookies.build_cookie(ch, counter).encode("ascii")


# Real valid cookies — the fuzzer's best mutation fodder.
for i in range(5):
    (CORPUS / f"real_{i:02d}").write_bytes(mint_real_cookie(i))

# Malformed-but-structurally-cookie-ish inputs. Nudges the fuzzer
# toward field-boundary edge cases (too-few fields, too-many, empty
# fields, truncated hex, oversized base64) from the start instead
# of waiting for random mutation to produce them.
malformed = {
    "empty":           b"",
    "one_byte":        b"A",
    "one_pipe":        b"|",
    "many_pipes":      b"|" * 100,
    "b64_bad_padding": b"====",
    "valid_b64_short": b"MXwxfDF8MXwxfDF8MXwxfDF8MXwxfDF8MXwxfDE=",  # 15 ones
    "overlong":        b"A" * 1024,
    "nul_embedded":    b"1|sha256zeros|" + b"\x00" * 32,
    "just_sig_bytes":  b"de" * 32,
}
for name, data in malformed.items():
    (CORPUS / f"seed_{name}").write_bytes(data)

print(f"seeded {len(list(CORPUS.iterdir()))} inputs in {CORPUS}")
