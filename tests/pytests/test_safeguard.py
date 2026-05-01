"""E10 — challenge safeguard / anti-loop hysteresis.

Track presentations without a solve per IP. After N presentations
inside window W, the next presentation gets a 302 redirect to a
configured URL (BotShieldSafeguardRedirectURL) or to the built-in
explainer at <BotShieldEndpointPrefix>/safeguard-info. The original
URI is appended as ?return=<urlencoded path>. The per-IP counter
clears on redirect so a fresh failure cycle starts after the
client engages with the redirect target.

The redirect-with-explainer behavior replaced the pre-2026 silent
pass-through. Silent pass-through gave determined bots free access
for the TTL window without informing real-but-broken users about
what was happening. The redirect makes the failure mode visible to
legitimate clients and gives bots nothing useful (the explainer has
no scrapable content; redirect followers land on it but never
reach the protected URL).

Safeguard is opt-in (BotShieldSafeguard off by default). These
tests enable it explicitly and check:
  - threshold crossing promotes the request to a 302 redirect
  - decision log carries tier=safeguard outcome=redirect
  - the Location header points at the explainer (or operator URL)
    with a same-origin ?return= parameter
  - below threshold still issues a challenge
  - per-IP isolation (IP-A safeguarded doesn't carry to IP-B)
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
    (interstitial 403 + _bs_pending cookie). The 4th is a 302
    redirect to the explainer page, with the original URI appended
    as ?return=/. The per-IP counter clears on redirect, so the 5th
    gets a fresh challenge again rather than a second redirect."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=3),
        count=1,
    ):
        with log_slice as slc:
            responses = _hammer(fresh_ip, 5)
            lines = slc.decision_lines(ip=fresh_ip)

    # First threshold presentations get the 403 interstitial.
    for i, r in enumerate(responses[:3]):
        assert r.status_code == 403 and "__bsChallenge" in r.text, (
            f"request {i} should have been challenged "
            f"(403 + __bsChallenge); got status={r.status_code}, "
            f"body-marker={'__bsChallenge' in r.text}"
        )

    # 4th presentation: 302 redirect to the safeguard explainer.
    sg = responses[3]
    assert sg.status_code == 302, (
        f"4th request should be 302 (safeguard redirect); "
        f"got {sg.status_code}"
    )
    assert sg.headers.get("X-Botshield") == "safeguard-redirect", (
        f"missing X-Botshield: safeguard-redirect; "
        f"headers={dict(sg.headers)}"
    )
    location = sg.headers.get("Location", "")
    assert "/safeguard-info" in location, (
        f"Location should point at the built-in explainer when no "
        f"BotShieldSafeguardRedirectURL is set; got {location!r}"
    )
    assert "return=" in location, (
        f"Location must carry the original URI as ?return=; "
        f"got {location!r}"
    )
    # No-store on a redirect prevents broken intermediaries from
    # caching the safeguard response and serving it to a healthy
    # client later.
    assert sg.headers.get("Cache-Control") == "no-store"

    # Decision log: tier=safeguard outcome=redirect with the
    # challenge-safeguard reason.
    sg_lines = [d for d in lines if d["tier"] == "safeguard"]
    assert sg_lines, f"no tier=safeguard decision line; lines={lines}"
    assert sg_lines[0]["outcome"] == "redirect", (
        f"safeguard decision should have outcome=redirect; "
        f"got {sg_lines[0]}"
    )
    assert "challenge-safeguard" in sg_lines[0]["reason"], (
        f"safeguard line should carry reason=challenge-safeguard; "
        f"got {sg_lines[0]}"
    )

    # Note: under always-mint, the 302 response *does* carry a
    # trust=0 __Host-bs_session — installed by the always-mint hook
    # before bs_apply_safeguard returns. That cookie does not grant
    # trust on its own (passes_silent / passes_form / passes_captcha
    # are zero) and does not reset the safeguard counter
    # (bs_safeguard_clear is gated on solve evidence). The
    # security-relevant property is tested separately by
    # test_unverified_session_cookie_does_not_clear_safeguard.


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
        # Trip IP-A: 2 challenges, then a redirect.
        _hammer(ip_a, 3)
        # IP-B's first visit — must be challenged (fresh slate),
        # not redirected.
        r_b = client.get("/", xff=ip_b, ua=SCRAPER_UA)

    assert r_b.status_code != 302, (
        f"IP-B got safeguard redirect but IP-A is the broken one; "
        f"safeguard leaked across IPs (status={r_b.status_code})"
    )
    assert "__bsChallenge" in r_b.text, (
        f"IP-B should have been challenged; got body without "
        f"interstitial marker"
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
                cookies={"__Host-bs_session": solved},
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
    redirected = [r.status_code == 302 for r in responses]
    assert all(challenged) and not any(redirected), (
        f"safeguard should be off by default; got "
        f"challenged={challenged}, redirected={redirected}"
    )


# --- BotShieldSafeguardRedirectURL override ------------------------


def test_safeguard_redirect_url_override(config_override, fresh_ip):
    """`BotShieldSafeguardRedirectURL` lets the operator point the
    redirect at their own page (a status page, a help article, a
    login flow). When set, the Location should target that URL with
    the original URI appended as ?return=<urlencoded path>."""
    custom_url = "/help/please-enable-javascript"
    cfg = (
        _safeguard_cfg(threshold=2)
        + f'    BotShieldSafeguardRedirectURL {custom_url}\n'
    )
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on", cfg, count=1,
    ):
        # Trip threshold + 1 redirect.
        responses = _hammer(fresh_ip, 3)

    sg = responses[2]
    assert sg.status_code == 302, (
        f"3rd request should redirect; got {sg.status_code}"
    )
    location = sg.headers.get("Location", "")
    assert location.startswith(custom_url), (
        f"Location should target the configured override URL; "
        f"got {location!r}"
    )
    assert "return=" in location, (
        f"Location must carry ?return=; got {location!r}"
    )


# --- Built-in explainer page ---------------------------------------


def test_safeguard_info_endpoint_serves_explainer():
    """`<BotShieldEndpointPrefix>/safeguard-info` is auto-routed by
    the module — no <Location> carve-out needed. It serves a small
    HTML body explaining why the auto-check failed and offering a
    Continue link."""
    r = client.get("/botshield/safeguard-info")
    assert r.status_code == 200, (
        f"safeguard-info endpoint should serve 200; got {r.status_code}"
    )
    body = r.text.lower()
    # Body should mention the troubleshooting context — a few common
    # phrases the explainer references.
    assert any(s in body for s in (
        "javascript", "js", "browser", "extension",
    )), (
        f"explainer body missing expected troubleshooting hints; "
        f"first 300 chars: {r.text[:300]!r}"
    )


def test_safeguard_info_passes_return_param_through(fresh_ip,
                                                    config_override):
    """When the explainer is hit with ?return=<path>, the rendered
    Continue link should carry the same return value through to the
    user (so they can resume their original journey after fixing
    their browser)."""
    target = "/some/protected/path"
    r = client.get(
        f"/botshield/safeguard-info?return={target}",
    )
    assert r.status_code == 200
    # The Continue link / form should reference the return target so
    # the user can navigate back. Be loose about the exact markup —
    # the page may use a Link, a form action, or a header link.
    assert target in r.text, (
        f"explainer should propagate the return param to the page; "
        f"target={target!r} not found in body"
    )


# --- Open-redirect prevention --------------------------------------


@pytest.mark.parametrize("malicious", [
    "//evil.example.com/path",        # protocol-relative
    "/\\evil.example.com",            # backslash trick
    "https://evil.example.com",       # absolute URL
    "javascript:alert(1)",            # javascript: scheme
])
def test_safeguard_info_rejects_off_origin_return(malicious):
    """The ?return= parser validates same-origin shape: must start
    with a single '/', no scheme, no '//', no backslash trick. On
    failure the rendered Continue link falls back to '/'. Without
    this gate, a bot could craft a return= that turns the explainer
    into an open-redirect amplifier (?return=//evil → Continue to
    https://evil)."""
    r = client.get(f"/botshield/safeguard-info?return={malicious}")
    assert r.status_code == 200
    # The malicious string must not survive into the rendered body
    # as a usable Continue link. The body falls back to /.
    assert malicious not in r.text, (
        f"open-redirect candidate {malicious!r} survived into the "
        f"explainer body; ?return validator is leaking"
    )


# --- bs_safeguard_clear gating on solve evidence -------------------


def test_unverified_session_cookie_does_not_clear_safeguard(
    config_override, fresh_ip,
):
    """`bs_safeguard_clear` is gated on actual solve evidence
    (passes_silent / passes_form / passes_captcha > 0) at its single
    call site in cookie verify. Without that gate, a bot could
    harvest a fresh trust=0 cookie on its first request and bypass
    safeguard on every subsequent failed challenge.

    Functional shape: drive 3 cookieless presentations with the
    *same* bogus session cookie attached each time. Cookie verify
    fails on every request (signature mismatch), so each falls
    through to challenge tier and increments the safeguard
    presentation count. Threshold=2 means the 3rd presentation
    should trip safeguard (302 redirect).

    If the clear-gate were missing — i.e. cookie-verify-failure
    paths still called bs_safeguard_clear — the counter would reset
    on every request and the 3rd would still be a 403 challenge
    rather than a 302 redirect."""
    bogus_cookie = "AUcZ.bogus"  # GCM-shape but doesn't verify
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=2),
        count=1,
    ):
        responses = [
            client.get(
                "/", xff=fresh_ip, ua=SCRAPER_UA,
                cookies={"__Host-bs_session": bogus_cookie},
            )
            for _ in range(3)
        ]

    # First two presentations: 403 challenge (cookie rejected,
    # below safeguard threshold).
    for i, r in enumerate(responses[:2]):
        assert r.status_code == 403, (
            f"request {i} with bogus cookie should be 403 challenge "
            f"(cookie verify fails, score sends to challenge tier); "
            f"got {r.status_code}"
        )
    # Third presentation: safeguard 302. If the clear-gate were
    # missing, the bogus cookie would have reset the counter on each
    # request and we'd see a 3rd 403 instead.
    assert responses[2].status_code == 302, (
        f"safeguard didn't fire on the 3rd presentation — "
        f"bs_safeguard_clear is running on cookie-verify-failure "
        f"paths and erasing the counter. Got status="
        f"{responses[2].status_code}."
    )


# --- outcome_redirect_total counter parity -------------------------


def test_safeguard_redirect_increments_outcome_counter(
    config_override, fresh_ip,
):
    """Each safeguard 302 should bump `botshield_outcome_redirect_total`.
    Mirrors the existing `_observed_total` counter checks elsewhere
    in this suite — counter parity is the loud-not-silent gate that
    catches enum drift between source and metrics export."""
    with config_override(
        r"BotShieldAllowVerifiedBots\s+on",
        _safeguard_cfg(threshold=2),
        count=1,
    ):
        # Hit the threshold + 1 redirect.
        before = _read_metric("botshield_outcome_redirect_total")
        _hammer(fresh_ip, 3)
        after = _read_metric("botshield_outcome_redirect_total")

    assert after - before >= 1, (
        f"safeguard 302 didn't bump outcome_redirect_total; "
        f"before={before} after={after}"
    )


# Helper used by the counter test above. Pulled from the same
# pattern test_shadow_mode.py uses; keeping it local so the file is
# self-contained.
def _read_metric(name: str) -> int:
    resp = client.get("/botshield/metrics")
    needle = f"{name} "
    for line in resp.text.splitlines():
        if line.startswith(needle):
            return int(line.split()[1])
    return 0
