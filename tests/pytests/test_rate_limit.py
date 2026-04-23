"""M8.1: per-IP rate limit on the verify endpoint.

Default budget is 30/min; 40 parallel POSTs should yield a mix of
303s and 429s, and the 'captcha-verify rate limit' log line must be
throttled to at most ~2 emissions per IP per 60-second window.

Port of tests/integration/m8_1_rate_limit.sh — the parallel firing
pattern is the same (concurrent.futures instead of bash backgrounding)
because serial Cloudflare POSTs span 20+ seconds and can cross the
rate-limit window boundary.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from botshield_test import client, cookies, metrics


def _fire(pending: str, ip: str):
    return client.post(
        "/botshield/captcha-verify/turnstile",
        xff=ip,
        cookies={"_bs_captcha_pending": pending},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )


def test_rate_limit_fires(rate_slot_ip, log_slice):
    pending = cookies.fetch_pending_cookie("captcha-demo")
    assert pending, "could not mint pending cookie"

    before = metrics.snapshot()
    rl_before = metrics.value(before, "botshield_outcome_rate_limited_total")

    with log_slice as slc:
        with ThreadPoolExecutor(max_workers=40) as pool:
            futures = [
                pool.submit(_fire, pending, rate_slot_ip) for _ in range(40)
            ]
            responses = [f.result() for f in futures]

        after = metrics.snapshot()
        rl_after = metrics.value(after, "botshield_outcome_rate_limited_total")

        codes = Counter(r.status_code for r in responses)

        # Rate limit must fire at least once against 40 parallel POSTs
        # from one IP.
        assert codes.get(429, 0) >= 1, (
            f"expected ≥1 429 from 40 parallel POSTs from {rate_slot_ip}; "
            f"got codes={dict(codes)}, "
            f"rate_limited counter delta={rl_after - rl_before}"
        )

        # Log throttle: the 'captcha-verify rate limit' line fires at
        # most ~once per IP per 60s window. Tolerate up to 2 in case a
        # second window rolled over during the burst.
        rate_lines = slc.grep(
            fr"captcha-verify rate limit.*ip={rate_slot_ip}"
        )
        assert len(rate_lines) <= 2, (
            f"log throttle broke: {len(rate_lines)} rate-limit lines "
            f"for {rate_slot_ip} (expected ≤2)"
        )
