"""Timing help for rate-limit tests. Currently empty.

align_to_window() lived here until 2026-09-08. The rate counter stored
its window start in whole seconds, which aligned every window to the
wall-clock tick, so a burst that straddled a tick got a fresh budget
half way through and the request a test expected refused was admitted.
Sleeping to just after a tick was the fix.

The counter keeps milliseconds now and a window is anchored to the
first request that opens it, so there is no tick to straddle and the
helper was retired. The nine callers were run repeatedly without it
before it went.
"""
