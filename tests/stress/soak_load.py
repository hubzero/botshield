#!/usr/bin/env python3
"""Steady rate-limited load generator for tests/stress/soak.sh.

Dispatches HTTPS requests at an exact target RPS (a request every
1/RPS seconds, launched on its own short-lived thread so latency
doesn't slow the sender). Mix is 70/20/10 pass/form/captcha-render
against the local dev vhost, all internal (no third-party egress).

Stdlib only — no aiohttp / requests / etc. — so provision.sh's
python3 install is enough.

Usage:
    soak_load.py <rps> <duration_sec> [base_url]
"""
import random
import ssl
import sys
import threading
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: soak_load.py <rps> <duration_sec> [base_url]")
    rps = int(sys.argv[1])
    duration_sec = int(sys.argv[2])
    base = sys.argv[3] if len(sys.argv) > 3 else "https://localhost"

    ctx = ssl._create_unverified_context()

    mix = [
        (70, "/",             {"User-Agent": "Mozilla/5.0 (X11) Chrome/145",
                               "Accept-Language": "en-US"}),
        (20, "/",             {"User-Agent": "python-requests/2.31"}),
        (10, "/captcha-demo", {}),
    ]
    weighted = []
    for weight, path, headers in mix:
        weighted.extend([(path, headers)] * weight)

    interval = 1.0 / rps
    end = time.time() + duration_sec
    sent = 0
    errs = 0
    err_lock = threading.Lock()

    def do_one():
        nonlocal errs
        path, headers = random.choice(weighted)
        try:
            req = Request(base + path, headers=headers)
            urlopen(req, context=ctx, timeout=5).read()
        except (URLError, Exception):
            with err_lock:
                errs += 1

    next_fire = time.time()
    while time.time() < end:
        next_fire += interval
        t = threading.Thread(target=do_one, daemon=True)
        t.start()
        sent += 1
        # If we're behind schedule (slow server), skip the sleep —
        # otherwise rate would drift below target over time.
        sleep_for = next_fire - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)

    # Let in-flight requests finish before reporting.
    time.sleep(5)
    print(f"sent={sent} errors={errs} duration={duration_sec}s "
          f"target_rps={rps} actual_rps={sent/duration_sec:.1f}")


if __name__ == "__main__":
    main()
