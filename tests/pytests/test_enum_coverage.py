"""M9.1: every reachable outcome enum must appear in the decision log
under an ordinary test run.

`misconfigured` and `debug` require intentional config breaks (debug=On,
or removing secrets) and aren't counted here. The tilde-prefixed
counterfactuals (`~challenge`, `~block`, `~rate_limited`) require
`BotShieldEnabled LogOnly` and are exercised from test_shadow_mode.py.
The remainder — allow, challenged, verified, block, failopen,
rate_limited, pending_missing — should all fire from routine traffic.

Uses config_override to force a fail-open via a 100ms timeout. Serial
because the override mutates the live vhost.

Port of tests/integration/m9_1_enum_coverage.sh.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from botshield_test import client, cookies


pytestmark = [pytest.mark.serial, pytest.mark.live_network]


REACHABLE = {
    "allow", "challenged", "verified", "block",
    "failopen", "rate_limited", "pending_missing",
}


def _fire_verify(pending: str, ip: str):
    return client.post(
        "/botshield/captcha-verify/turnstile",
        xff=ip,
        cookies={"_bs_captcha_pending": pending},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )


@pytest.mark.heavy
def test_all_reachable_outcomes_emitted(config_override, rate_slot_ip, log_slice):
    with log_slice as slc:
        # allow: browser-like request
        client.get("/", ua="Mozilla/5.0 (X11) Chrome/145",
                   accept_language="en-US", xff="203.0.113.210")

        # challenged: scraper UA
        client.get("/", ua="python-requests/2.31", xff="203.0.113.211")

        # verified: pending cookie + always-pass Turnstile
        pending = cookies.fetch_pending_cookie("captcha-demo")
        client.post(
            "/botshield/captcha-verify/turnstile",
            cookies={"_bs_captcha_pending": pending},
            data={"cf-turnstile-response": "x", "return_to": "/"},
        )

        # block: POST missing token field → 400
        pending = cookies.fetch_pending_cookie("captcha-demo")
        client.post(
            "/botshield/captcha-verify/turnstile",
            cookies={"_bs_captcha_pending": pending},
            data={"return_to": "/"},
        )

        # failopen: 100ms timeout forces the next verify to fail-open.
        with config_override(
            r"BotShieldCaptchaTimeout\s+1500",
            "BotShieldCaptchaTimeout    100",
        ):
            pending = cookies.fetch_pending_cookie("captcha-demo")
            client.post(
                "/botshield/captcha-verify/turnstile",
                cookies={"_bs_captcha_pending": pending},
                data={"cf-turnstile-response": "x", "return_to": "/"},
            )

        # rate_limited: 45 parallel POSTs from one IP → exceed 30/min.
        pending = cookies.fetch_pending_cookie("captcha-demo")
        with ThreadPoolExecutor(max_workers=45) as pool:
            futures = [
                pool.submit(_fire_verify, pending, rate_slot_ip)
                for _ in range(45)
            ]
            for f in futures:
                f.result()

        # pending_missing: POST without the pending cookie.
        client.post(
            "/botshield/captcha-verify/turnstile",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"cf-turnstile-response": "x"},
        )

        lines = slc.decision_lines()

    seen = {d["outcome"] for d in lines}
    missing = REACHABLE - seen
    assert not missing, (
        f"outcomes never emitted during this run: {sorted(missing)} "
        f"(seen: {sorted(seen)})"
    )
