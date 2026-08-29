"""M7: silent-tier auto-submit interstitial end-to-end.

1. Cookieless silent-band request → interstitial JS with auto=1
2. Locally solve the PoW, build the 15-field cookie
3. Replay with the cookie → pass tier (no challenge)

This is the Python-PoW-hand-roll version. The Playwright version
lands in M11.6 and exercises the real browser's JS worker.

Port of tests/integration/m7_silent_tier.sh.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client, cookies, ips as _ips


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


BROWSER_UA = "Mozilla/5.0 (X11) Chrome/145"

# Forced silent tier rather than relying on the ambient first-sight-ip
# default -- see the note in test_cookie_gcm.py.
SILENT_PATH = "/silent-demo"


def test_silent_tier_round_trip(fresh_ip):
    # 1. Cookieless silent-band probe: Mozilla UA + missing Accept-
    #    Language + first-sight-ip = score 20 → silent tier.
    resp = client.get(SILENT_PATH, xff=fresh_ip, ua=BROWSER_UA)
    # Interstitial responses are 403 + X-Robots-Tag noindex,nofollow
    # so search engines don't index the placeholder body. Browsers
    # still execute inline JS / captcha widgets on 4xx, so the
    # auto-solve in step 2 still works.
    assert resp.status_code == 403, (
        f"silent interstitial should return 403; got {resp.status_code}"
    )
    robots_tag = resp.headers.get("X-Robots-Tag", "")
    assert "noindex" in robots_tag and "nofollow" in robots_tag, (
        f"silent interstitial missing X-Robots-Tag noindex,nofollow; "
        f"got {robots_tag!r}"
    )
    challenge = cookies.extract_challenge(resp.text)

    # auto=1 indicates silent tier. If it's 0 we got form tier —
    # means the IP was already in Bloom, first-sight-ip didn't fire.
    assert challenge["auto"] == 1, (
        f"expected auto=1 (silent tier), got auto={challenge['auto']} — "
        f"is the IP already in Bloom? ip={fresh_ip}"
    )

    # 2. Solve PoW + build cookie.
    counter = cookies.solve_pow(challenge)
    cookie = cookies.build_cookie(challenge, counter)

    # 3. Replay with browser-like headers + the signed cookie.
    resp = client.get(
        "/", xff=fresh_ip,
        ua=BROWSER_UA, accept_language="en-US",
        cookies={"__Host-bs_session": cookie},
    )
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"cookied replay still challenged; headers={dict(resp.headers)}"
    )


# --- MEDIUM #1: render-side carry-forward refuses expired cookies --

@pytest.mark.heavy
def test_expired_cookie_does_not_carry_rep_to_render_path(
    config_override, log_slice,
):
    """Security review MEDIUM #1, render-side. The four issuance
    sites correctly reject an expired prior cookie via
    bs_carry_forward_eligible. But bs_handler's render-side
    predicate used to accept "expired" — only "signature mismatch"
    was rejected — so an expired cookie's rep was carried into
    next_rep, baked into the next challenge's GCM envelope, and
    round-tripped through the JS to /embedded-verify. The TTL
    guarantee leaked through that path.

    Fix routes both sides through bs_should_carry_prior_rep so an
    expired cookie is rejected at the render step too.
    Verifiable signal: bs_handler's "challenging" log line emits
        cookie_score=%d  with  have_prior_rep ? cookie_score : -1
    so cookie_score=-1 means have_prior_rep is 0 — i.e. the expired
    cookie did not contribute. Pre-fix, the same line would have
    shown cookie_score=0 (the prior cookie's score for a fresh
    bootstrap-issued envelope).

    Setup uses a 2-second BotShieldCookieTTL so a sleep(3) reliably
    expires the cookie without slowing the suite materially. The
    second request comes from a different IP so first-sight-ip +
    missing Accept-Language reliably push the score back into
    silent tier and cause bs_handler to emit the challenge log
    line we're asserting on."""
    ip_issue = _ips.fresh_ip()

    with config_override(
        r"BotShieldAlgorithm\s+sha256-zeros",
        "BotShieldAlgorithm sha256-zeros\n"
        "    BotShieldCookieTTL 2",
    ):
        resp = client.get(SILENT_PATH, xff=ip_issue, ua=BROWSER_UA)
        challenge = cookies.extract_challenge(resp.text)
        counter   = cookies.solve_pow(challenge)
        cookie    = cookies.build_cookie(challenge, counter)

        # Cookie's expires_at is "now + 2s" at issue time. Wait past
        # that point so bs_verify_cookie returns "expired" on the
        # next use.
        time.sleep(3)

        ip_replay = _ips.fresh_ip()
        with log_slice as slc:
            # SILENT_PATH, not "/": this asserts on the log line the
            # RENDER path emits, so a challenge has to actually be
            # rendered for there to be anything to match.
            client.get(
                SILENT_PATH, xff=ip_replay, ua=BROWSER_UA,
                cookies={"__Host-bs_session": cookie},
            )
            matches = slc.grep(r"challenging.*cookie_score=-1")

    assert matches, (
        "bs_handler emitted a 'challenging' log line for an expired "
        "cookie but cookie_score is not -1 — the render-side "
        "carry-forward predicate is letting the expired cookie's "
        "rep through. tail:\n"
        + "\n".join(slc.text().splitlines()[-8:])
    )
