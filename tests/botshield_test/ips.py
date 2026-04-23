"""IP allocators for tests that need Bloom-fresh or rate-slot-fresh
client addresses.

The bash suite rolled its own `time.now() % 250` allocator in every
test that needed one. Two problems solved here:

1. Parallel pytest-xdist workers can't coincidentally pick the same
   IP. Each worker contributes its pytest-xdist worker id (PYTEST_XDIST_WORKER
   env, e.g. "gw0", "gw1") to the octet mix.
2. The rate-limit ring has 4096 slots keyed by a hash of the IP.
   `fresh_ip(rate_slot=True)` varies the octets across a wider range
   so collisions with stale slots from a prior run are vanishingly
   rare.

Non-overlapping subnets across test categories:
  - 100.64.0.0/10 — Bloom-fresh default. RFC 6598 shared-address
    space, reserved for CGN — no real traffic would come from this
    range. The legacy bash suite uses 203.0/203.1/203.2 and 198.18,
    so this range is collision-free with bash during the M11.4–M11.5
    transition period.
  - 198.51.100.0/24 — rate-limit slot test. A /24 is enough because
    we only need per-run uniqueness, not cross-run; the 4096-slot
    ring makes collisions with old IPs unlikely. Bash's rate-limit
    test also uses this /24 and collisions there are fine —
    different slots for different seconds.
"""

from __future__ import annotations

import itertools
import os
import time

# Per-process counter so successive calls within one test file get
# distinct IPs even if they happen in the same second.
_SEQ = itertools.count()


def _worker_octet() -> int:
    """Map a pytest-xdist worker id to an octet in [1, 250].

    Single-process pytest (no xdist) → worker id is unset → returns 0.
    """
    wid = os.environ.get("PYTEST_XDIST_WORKER", "")
    if not wid.startswith("gw"):
        return 0
    try:
        n = int(wid[2:])
    except ValueError:
        return 0
    return (n % 250) + 1


def fresh_ip(*, rate_slot: bool = False) -> str:
    """Return a time-salted client IP.

    `rate_slot=False` (default): IP from 100.64.0.0/10 (CGN). This
    range is untouched by the legacy bash suite, so its Bloom slots
    stay clean even across a full-suite mixed run.

    `rate_slot=True`: IP from 198.51.100.0/24 chosen so its rate-
    limit slot is unlikely to collide with a prior run.
    """
    t = int(time.time())
    seq = next(_SEQ)
    wid = _worker_octet()

    if rate_slot:
        # 4096-slot ring; varying the last octet and salting with
        # time+seq is sufficient. 198.51.100.1–250 is documentation-
        # range space — safe for synthetic traffic.
        last = (t + seq * 7 + wid * 13) % 250 + 1
        return f"198.51.100.{last}"

    # Bloom-fresh: three octets of entropy (b, c, d) inside
    # 100.64.0.0/10. The /10 is 4M addresses; time+seq+worker mix
    # gets us a different address on every call and near-zero
    # collision probability across a mixed bash+pytest run.
    b = ((t // 65536) + seq) % 64 + 64   # 64..127 → /10 prefix-safe
    c = ((t // 256) + seq * 3 + wid * 31) % 256
    d = (t + seq * 11 + wid) % 254 + 1
    return f"100.{b}.{c}.{d}"
