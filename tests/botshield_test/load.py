"""Rate-limited load generator for the soak driver and any pytest
fixture that wants to run traffic in the background.

Port of the legacy tests/stress/soak_load.py. Deliberately stdlib-
only — urllib.request rather than the framework's httpx-based
`client`, and no IP allocator dependency — so the load driver works
as a one-file CLI entry (`python -m botshield_test.load`) without
pulling in pytest-scoped primitives. The tradeoff is that tests
that want structured assertions about requests the load driver
made should use the test-side helpers (botshield_test.client, logs,
metrics) separately.

The traffic mix is 70/20/10 pass/form/captcha-render and
internal-only (never hits a third-party siteverify) because that
keeps log growth predictable and doesn't burn rate-limit budgets
upstream.

`LoadGenerator` can be used as a context manager so pytest fixtures
can start traffic on entry and stop it on teardown:

    with LoadGenerator(rps=50, base_url=BASE_URL):
        # do something while traffic is running
        ...
    # __exit__ calls stop(): firing stops immediately; drain waits
    # up to drain_timeout for in-flight requests to finish.
"""

from __future__ import annotations

import random
import ssl
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from urllib.error import URLError

from .config import BASE_URL


# Traffic-class mix. Each entry: (weight, path, headers).
# Browser-ish pass, scraper-ish form challenge, captcha render.
_DEFAULT_MIX = (
    (70, "/", {
        "User-Agent": "Mozilla/5.0 (X11) Chrome/145",
        "Accept-Language": "en-US",
    }),
    # /form-demo, not "/": this slice exists to drive FORM tier, and a
    # scraper UA on / scores 20 (first-sight 5 + missing-AL 5 +
    # scraperua 10), which is silent tier. Form needs 50, so the
    # botshield_tier_interactive_total assertion in test_soak could never
    # grow. /form-demo pins the tier instead of hoping the score
    # lands there.
    (20, "/form-demo", {
        "User-Agent": "python-requests/2.31",
    }),
    (10, "/captcha-demo", {}),
)


@dataclass
class LoadStats:
    sent: int = 0
    errors: int = 0
    duration_sec: float = 0.0

    @property
    def rps(self) -> float:
        if self.duration_sec <= 0:
            return 0.0
        return self.sent / self.duration_sec


@dataclass
class LoadGenerator:
    """Rate-limited in-process load driver.

    `rps` is exact: a request is launched every 1/rps seconds on a
    short-lived thread so slow responses don't slow the sender.
    `duration_sec` is a hard upper bound; `stop()` / `__exit__` will
    signal an early shutdown and block until in-flight requests
    drain (up to `drain_timeout`).
    """
    rps: float
    duration_sec: float = 0.0  # 0 = run until stop() called
    base_url: str = BASE_URL
    mix: tuple = field(default_factory=lambda: _DEFAULT_MIX)
    drain_timeout: float = 5.0

    def __post_init__(self):
        weighted = []
        for weight, path, headers in self.mix:
            weighted.extend([(path, headers)] * weight)
        self._weighted = weighted
        self._ssl = ssl._create_unverified_context()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Track outstanding request threads explicitly: counting
        # `threading.active_count()` from inside _run() is always ≥2
        # (main + _run), so a naive drain loop would run until it
        # hit drain_timeout every time and inflate duration_sec.
        self._inflight = 0
        self._inflight_lock = threading.Lock()
        self.stats = LoadStats()

    # --- Context manager API --------------------------------------------

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False  # don't swallow exceptions

    # --- Lifecycle ------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("LoadGenerator already started")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.duration_sec + self.drain_timeout + 5)
            self._thread = None

    # --- Core loop ------------------------------------------------------

    def _fire_one(self) -> None:
        path, headers = random.choice(self._weighted)
        # Distinct client IP per request. Without this every request
        # arrives as 127.0.0.1, which is Bloom-known the moment the
        # soak starts, so each one collects droppedcookie (25) and is
        # challenged -- outcome_allow_total never grows and the soak
        # reports "driver not landing traffic" while landing plenty.
        # 198.18.0.0/15 is the RFC 2544 benchmarking range, reserved
        # for exactly this and never routable.
        headers = dict(headers)
        headers["X-Forwarded-For"] = "198.18.%d.%d" % (
            random.randint(0, 255), random.randint(1, 254))
        try:
            req = urllib.request.Request(self.base_url + path, headers=headers)
            urllib.request.urlopen(req, context=self._ssl, timeout=5).read()
        except (URLError, Exception):
            with self._inflight_lock:
                self.stats.errors += 1
        finally:
            with self._inflight_lock:
                self._inflight -= 1

    def _run(self) -> None:
        interval = 1.0 / self.rps
        start = time.time()
        end = start + self.duration_sec if self.duration_sec > 0 else float("inf")
        next_fire = start

        while time.time() < end and not self._stop.is_set():
            next_fire += interval
            with self._inflight_lock:
                self._inflight += 1
            threading.Thread(target=self._fire_one, daemon=True).start()
            self.stats.sent += 1

            # If the server slows us down, skip the sleep so actual
            # rps stays on target over the window.
            sleep_for = next_fire - time.time()
            if sleep_for > 0:
                # Shorter waits keep stop() responsive.
                self._stop.wait(timeout=sleep_for)

        # duration_sec is the FIRING window only — not the drain
        # tail. Actual rps should compare against the interval we
        # actually sent on, so the caller's sanity-check works.
        self.stats.duration_sec = time.time() - start

        # Drain: wait for fired-off request threads to finish. Uses
        # our tracked counter, not threading.active_count(), because
        # active_count includes main + _run itself and would never
        # drop to 0 from inside this thread.
        drain_deadline = time.time() + self.drain_timeout
        while time.time() < drain_deadline:
            with self._inflight_lock:
                if self._inflight <= 0:
                    break
            time.sleep(0.05)


def main_cli() -> None:
    """CLI entry for tests/stress/soak.sh back-compat:

        python -m botshield_test.load <rps> <duration_sec> [base]
    """
    import sys

    if len(sys.argv) < 3:
        sys.exit("usage: python -m botshield_test.load "
                 "<rps> <duration_sec> [base_url]")
    rps = float(sys.argv[1])
    duration_sec = float(sys.argv[2])
    base = sys.argv[3] if len(sys.argv) > 3 else BASE_URL

    gen = LoadGenerator(rps=rps, duration_sec=duration_sec, base_url=base)
    gen.start()
    gen._thread.join()
    s = gen.stats
    print(
        f"sent={s.sent} errors={s.errors} "
        f"duration={int(s.duration_sec)}s "
        f"target_rps={rps:.0f} actual_rps={s.rps:.1f}"
    )


if __name__ == "__main__":
    main_cli()
