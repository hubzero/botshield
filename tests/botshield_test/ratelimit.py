"""Timing help for rate-limit tests.

The rate counter is a fixed window keyed on wall-clock seconds, not a
sliding one: bs_rate_counter_admit compares against window_start_sec
and resets the count when the second rolls. A burst that straddles a
boundary therefore gets a fresh budget half way through, and the
request a test expects to be refused is admitted instead.

That is the whole of the flake in this family. It is invisible when
the suite runs alone, because sequential HTTPS requests land a few
milliseconds apart and rarely straddle. It shows up under a full
parallel lane, where the gap between requests widens and the odds of
crossing a tick go up with it -- which is why these read as "only
fails under load" rather than as a timing bug.

Widening the window is not the fix. The counter is indexed by rule
slot alone, not by client address, so a rule's budget is one global
counter: with a minute-long window one test's consumption leaks into
the next test that names the same rule. The one-second window is what
keeps these tests independent of each other.

So align instead. Start the burst just after a tick and the whole
burst lands in one window, which lets a test keep asserting the exact
budget -- "the fourth request is refused", not the weaker "one of them
was" -- and that exactness is the contract worth having.
"""

from __future__ import annotations

import time


def align_to_window(headroom: float = 0.05) -> None:
    """Block until just after the next wall-clock second boundary.

    Costs under a second and buys ~950ms of window for a burst that
    takes tens of milliseconds. Call it immediately before a burst
    whose assertion depends on which request is refused.
    """
    now = time.time()
    time.sleep(1.0 - (now % 1.0) + headroom)
