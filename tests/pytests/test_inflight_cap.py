"""M8.1: global in-flight captcha semaphore.

The captcha-verify handler caps concurrent outbound siteverify
calls at `BotShieldCaptchaMaxInFlight` (default 64). Beyond that,
requests short-circuit to 503 + `X-Botshield: captcha-saturated`
and log outcome=inflight_capped without touching libcurl.

This is the last reachable outcome that had no assertion in the
suite (see test_enum_coverage's REACHABLE set). Audit surfaced
during the through-M11.8 review.

Strategy: config_override the cap down to 2, fire 20 parallel
verify POSTs against Turnstile (each holds a slot for the
~100-300ms libcurl round trip), assert at least one 503.

Marked @serial because config_override mutates the vhost and
@live_network because the verify path still reaches Cloudflare
— without that upstream latency the cap isn't observable. The
@live_network marker also gives us the 2-retry flake absorption
from conftest's collection hook.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import pytest

from botshield_test import client, cookies


pytestmark = [pytest.mark.serial, pytest.mark.live_network]


def _fire(pending: str):
    return client.post(
        "/botshield/captcha-verify/turnstile",
        cookies={"_bs_captcha_pending": pending},
        data={"cf-turnstile-response": "x", "return_to": "/"},
    )


def test_inflight_cap_fires(config_override, log_slice):
    # Cap = 2 so 20 concurrent POSTs reliably saturate. The directive
    # appears once at server scope in the dev vhost; be strict about
    # the count so a config layout change surfaces here instead of
    # silently matching multiple lines.
    with config_override(
        r"BotShieldCaptchaMaxInFlight\s+\d+",
        "BotShieldCaptchaMaxInFlight 2",
        count=1,
    ):
        pending = cookies.fetch_pending_cookie("captcha-demo")

        with log_slice as slc:
            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = [pool.submit(_fire, pending) for _ in range(20)]
                responses = [f.result() for f in futures]
            inflight_lines = slc.decision_lines(outcome="inflight_capped")

    codes = Counter(r.status_code for r in responses)
    n_503 = codes.get(503, 0)

    assert n_503 >= 1, (
        f"expected ≥1 503 with cap=2 + 20 parallel POSTs; "
        f"got status distribution {dict(codes)}"
    )

    # Spot-check one of the 503 responses carries the saturation marker.
    saturated = [r for r in responses if r.status_code == 503]
    assert saturated, "no 503 responses captured (impossible — just asserted ≥1)"
    assert saturated[0].headers.get("X-Botshield") == "captcha-saturated", (
        f"503 without captcha-saturated marker: "
        f"X-Botshield={saturated[0].headers.get('X-Botshield')!r}"
    )

    assert inflight_lines, (
        f"no outcome=inflight_capped decision line emitted; "
        f"response distribution {dict(codes)}"
    )
