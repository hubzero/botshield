"""M9.2: zero 'metrics: unknown' WARNING lines must appear during a
typical request mix. Any such line means an enum string emitted by
the decision-log path has no counter registered for it — vocabulary
drift between M9.1 and M9.2.

Port of tests/integration/m9_2_vocab_sync.sh.
"""

from __future__ import annotations

from botshield_test import client, cookies


def test_no_vocabulary_drift(log_slice):
    with log_slice as slc:
        # Browser-headers — pass
        client.get("/", ua="Mozilla/5.0 (X11) Chrome/145",
                   accept_language="en-US", xff="203.0.113.220")

        # Scraper UA — form/challenged
        client.get("/", ua="python-requests/2.31", xff="203.0.113.221")

        # Captcha interstitial render
        client.get("/captcha-demo")

        # Verify OK via always-pass Turnstile
        pending = cookies.fetch_pending_cookie("captcha-demo")
        client.post(
            "/botshield/captcha-verify/turnstile",
            cookies={"_bs_captcha_pending": pending},
            data={"cf-turnstile-response": "x", "return_to": "/"},
        )

        # pending_missing
        client.post(
            "/botshield/captcha-verify/turnstile",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"cf-turnstile-response": "x"},
        )

        drift = slc.grep(r"metrics: unknown")

    assert not drift, (
        f"M9.2 vocabulary drift — {len(drift)} 'metrics: unknown' "
        f"WARNINGs:\n" + "\n".join(drift[:5])
    )
