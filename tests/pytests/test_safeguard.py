"""E10 — challenge safeguard / anti-loop hysteresis.

Track presentations without a solve per IP. After N presentations
inside window W, flip to a short-lived pass-through for the
safeguard TTL so a client broken on challenge-solving (JS disabled,
CSP strips the interstitial, privacy extensions mangle cookies)
stops being looped on the same challenge forever.

Safeguard is opt-in (BotShieldSafeguard off by default). These
tests enable it explicitly and check:
  - threshold crossing promotes the request to safeguard pass-through
  - below threshold still issues a challenge
  - per-IP isolation (IP-A safeguarded doesn't carry to IP-B)
  - safeguard doesn't mint `__Host-bs_verified` (no cookie issued)
  - safeguard doesn't override a 403 block decision
  - successful cookie verify resets the per-IP counter

The test IP classification (Mozilla UA + no Accept-Language +
cookieless) lands in silent tier reliably — enough to be offered a
challenge every time without solving. That's the shape a broken
browser looks like to BotShield, minus the "I can't solve it"
property we simulate by just not submitting the PoW counter.
"""

from __future__ import annotations

import pytest

from botshield_test import client, cookies


pytestmark = pytest.mark.serial


# Suspicious-looking UA that consistently scores into challenge
# tier (50 = scraper-ua-httpx) plus missing Accept-Language (+15).
# Total stays >=50 across requests even after first-sight bloom
# fades, so every cookieless request gets the form-PoW
# interstitial. That's the steady-state "broken client" shape we
# need safeguard to detect.
SCRAPER_UA = "python-httpx/0.27"


def _hammer(ip: str, n: int) -> list:
    """Fire N cookieless GETs from the same IP so BotShield presents
    a challenge each time. Returns the responses."""
    return [client.get("/", xff=ip, ua=SCRAPER_UA) for _ in range(n)]


def _safeguard_cfg(threshold: int, ttl: int = 900, window: int = 600) -> str:
    return (
        'BotShieldAllowVerifiedBots on\n'
        '    BotShieldSafeguard on\n'
        f'    BotShieldSafeguardThreshold {threshold}\n'
        f'    BotShieldSafeguardWindow {window}\n'
        f'    BotShieldSafeguardTTL {ttl}\n'
    )


# --- Threshold crossing → pass-through ------------------------------


def test_safeguard_trips_after_threshold(config_override, fresh_ip,
                                         log_slice):
    """Threshold=3: first 3 cookieless requests get challenged
    (interstitial HTML + _bs_pending cookie). The 4th is passed
    through with reason=challenge-safeguard — no interstitial, no
    __Host-bs_verified, backend handler serves real content."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=3),
        count=1,
    ):
        with log_slice as slc:
            responses = _hammer(fresh_ip, 5)
            lines = slc.decision_lines(ip=fresh_ip)

    # Interstitial HTML has the window.__bsChallenge marker; real
    # content (index.html in the testsite) does not. Use that to
    # distinguish challenged vs passed-through responses.
    challenged = ["__bsChallenge" in r.text for r in responses]

    # First threshold presentations get the interstitial.
    assert all(challenged[:3]), (
        f"first 3 should have been challenged; got {challenged}"
    )
    # Next requests get passed through — no interstitial.
    assert not any(challenged[3:]), (
        f"requests after threshold should be safeguard pass-through "
        f"(no interstitial); got {challenged}"
    )

    # Decision log: at least one challenge-safeguard reason after
    # threshold crossing. Outcome is "allow" (module got out of
    # the way) and tier is "safeguard" (distinct from "pass").
    safeguard_lines = [d for d in lines
                       if "challenge-safeguard" in d["reason"]]
    assert safeguard_lines, (
        f"no challenge-safeguard decision line; lines={lines}"
    )
    assert safeguard_lines[0]["tier"] == "safeguard", (
        f"expected tier=safeguard; got {safeguard_lines[0]}"
    )

    # Sanity: no __Host-bs_verified cookie ever set by safeguard (the
    # point is to NOT grant trust). The pending cookie from the
    # pre-threshold challenges may exist; the verified one must not.
    for r in responses:
        assert "__Host-bs_verified" not in r.cookies, (
            f"safeguard must not mint __Host-bs_verified; got "
            f"cookies={dict(r.cookies)}"
        )


# --- Below threshold: still challenges -----------------------------


def test_below_threshold_still_challenges(config_override, fresh_ip):
    """Threshold=10: 5 requests don't cross. Every one gets the
    interstitial, no safeguard pass-through."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=10),
        count=1,
    ):
        responses = _hammer(fresh_ip, 5)
    challenged = ["__bsChallenge" in r.text for r in responses]
    assert all(challenged), (
        f"all 5 should have been challenged below threshold=10; "
        f"got {challenged}"
    )


# --- Per-IP isolation ----------------------------------------------


def test_safeguard_isolates_per_ip(config_override):
    """IP-A trips safeguard. IP-B, on its first visit, should still
    be challenged — safeguard state is per-IP and doesn't leak."""
    ip_a = "198.51.100.30"
    ip_b = "198.51.100.40"
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=2),
        count=1,
    ):
        # Trip IP-A: 2 challenges, then pass-through.
        _hammer(ip_a, 3)
        # IP-B's first visit — must be challenged (fresh slate).
        r_b = client.get("/", xff=ip_b, ua=SCRAPER_UA)

    assert "__bsChallenge" in r_b.text, (
        f"IP-B got safeguard pass-through but IP-A is the broken one; "
        f"safeguard leaked across IPs"
    )


# --- Doesn't override 403 blocks -----------------------------------


def test_safeguard_does_not_override_block_path(
    config_override, fresh_ip,
):
    """CHANGELOG: 'safeguard should never override a clear hard block /
    deny decision.' Configure a BotShieldBlockPath on /blocked and
    trip safeguard on /. Then hit /blocked — must still return 403,
    not safeguard pass-through."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=2)
        # UA-narrowed cohort: 'httpx' substring keeps the cohort
        # legal (BotShield rejects both-'*'). Our SCRAPER_UA
        # contains 'httpx' so the test request matches.
        + '    BotShieldBlockPath badpath "/blocked" "httpx" *',
        count=1,
    ):
        # Trip safeguard on /.
        _hammer(fresh_ip, 3)
        # Now a blocked path must still return 403, not a soft pass.
        r = client.get("/blocked", xff=fresh_ip, ua=SCRAPER_UA)

    assert r.status_code == 403, (
        f"safeguard must not override BotShieldBlockPath 403; "
        f"got {r.status_code}"
    )


# --- Clear on solve -------------------------------------------------


def test_solved_cookie_clears_safeguard_counter(
    config_override, fresh_ip, log_slice,
):
    """Threshold=4. Phase 1: 2 cookieless failures (counter=2).
    Phase 2 prep: 1 cookieless request to obtain the JSON for PoW
    (counter=3, still under threshold).  Phase 2 solve: replay the
    solved cookie. The verify path calls bs_safeguard_clear (counter
    → 0). The same request still scores into challenge tier (UA is
    httpx + missing AL = 65), so a new challenge is issued and a
    presentation gets recorded (counter → 1).

    Without clear-on-solve, the request would be the 4th
    presentation — exactly threshold — and safeguard would fire on
    THIS request (decision-log reason=challenge-safeguard). With
    clear-on-solve, counter is at 1; safeguard does not fire.

    The decision log of the post-solve request is what
    distinguishes the two behaviors."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=4),
        count=1,
    ):
        # Phase 1: 2 cookieless presentations.
        _hammer(fresh_ip, 2)
        # Phase 2 prep: get JSON to solve. 3rd presentation.
        resp = client.get("/", xff=fresh_ip, ua=SCRAPER_UA)
        ch = cookies.extract_challenge(resp.text)
        counter = cookies.solve_pow(ch)
        solved = cookies.build_cookie(ch, counter)
        # Phase 3: replay solved cookie. Without clear-on-solve this
        # is presentation #4 → safeguard trips. With clear-on-solve,
        # counter resets to 0 on cookie-verify and the re-challenge
        # bumps it back to 1 — still well under threshold.
        with log_slice as slc:
            r_solved = client.get(
                "/", xff=fresh_ip, ua=SCRAPER_UA,
                cookies={"__Host-bs_verified": solved},
            )
            lines = slc.decision_lines(ip=fresh_ip)
    # The post-solve request's decision line must NOT carry the
    # safeguard reason. (The body still has an interstitial because
    # the score still sends them to challenge tier — that's
    # expected for SCRAPER_UA. Safeguard's job here is just to NOT
    # have tripped due to the solve clearing the counter.)
    assert lines, "no decision line for the post-solve request"
    safeguard_lines = [d for d in lines
                       if "challenge-safeguard" in d["reason"]]
    assert not safeguard_lines, (
        f"clear-on-solve broken: safeguard fired on the post-solve "
        f"request even though the cookie verified. "
        f"lines={lines[-3:]}"
    )


# --- Default off ---------------------------------------------------


def test_safeguard_off_by_default(config_override, fresh_ip):
    """Without BotShieldSafeguard on, the challenge-issue path
    runs every time regardless of N. Tight-loop hammering never
    promotes to safeguard — pre-E10 behavior preserved."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        # Deliberately no BotShieldSafeguard directive.
        'BotShieldAllowVerifiedBots on\n',
        count=1,
    ):
        responses = _hammer(fresh_ip, 10)
    challenged = ["__bsChallenge" in r.text for r in responses]
    assert all(challenged), (
        f"safeguard should be off by default; got {challenged} "
        f"(expected all True)"
    )
