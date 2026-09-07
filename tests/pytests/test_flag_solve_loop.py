"""Regression: a flagged client must be able to solve its way out.

Solving a challenge does not clear a flag, and flag scores re-apply on
every request. Any flag scoring at or above the noninteractive row is
therefore a loop unless something breaks it: challenge, solve, get
re-scored by the same flag, challenge again, forever. It reached
production twice -- once via a compiled-in tier_floor, once via the
score that the documented fix for the first one recommends.

Two things break it now, and both live at the tier decision rather
than at the flag.

A client is not challenged at a tier it already passed. Re-asking a
question the cookie already answers gets the same answer and costs a
page; only a demand HIGHER than what was passed is a new question. So
a flag keeps scoring, keeps appearing in the reason trace, and stops
producing challenges once the client has cleared its level.

And a captcha this scope cannot serve is clamped to what it can. The
render path falls back to the interactive PoW page when no provider is
configured, but the demand used to survive the fallback -- and the
envelope that page mints carries passes_interactive, never
passes_captcha. The client was asked for a proof it was never offered.
That is the loop these tests actually caught when `flags_excused` was
removed and the clamp was not yet there.

The shape of the bug is why it survived a test suite that already
covered flags and already covered solving. A test that solves once and
asserts the next request passes is not enough, because the first
post-solve request is not where this fails -- the cookie is fresh and
carries proof of the solve. The loop shows up on the request AFTER
that, when the flag has been re-applied. Every test here therefore
makes at least two post-solve requests.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import client, cookies


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"

# Comfortably above the dev vhost's botsignals row at 20, which is
# what makes the flag alone sufficient to challenge on every request.
LOOPING_SCORE = 60


def _trip_honeypot(ip: str) -> None:
    """Set BS_FLAG_HONEYPOT_HIT for this IP via the honeypot scope.
    The flag write goes through a mutex; one second is enough for the
    next lookup to see it."""
    client.get("/admin/.env", xff=ip)
    time.sleep(1)


# Thin UA with no Accept-Language: enough to land in a challenge tier
# on its own, so a test can obtain a solve without needing a flag to
# provoke one.
SUSPICIOUS_UA = "Mozilla/5.0 (X11) Chrome/145"


def _solve(path: str, ip: str, ua: str = BROWSER_UA):
    """Take a challenge and return the solved cookie."""
    resp = client.get(path, xff=ip, ua=ua,
                      accept_language=ACCEPT_LANG)
    challenge = cookies.extract_challenge(resp.text)
    counter = cookies.solve_pow(challenge)
    return cookies.build_cookie(challenge, counter)


def _get(path: str, ip: str, cookie: str):
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG,
                      cookies={"__Host-bs_session": cookie})


def test_flagged_client_escapes_loop_after_solving(
    config_override, fresh_ip, log_slice,
):
    """The whole incident, reproduced: flag worth more than the silent
    threshold, one solve, then repeated requests that must not be
    re-challenged."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        f"    BotShieldFlagTrigger honeypot_hit reset "
        f"action=score accumulator=botsignals add={LOOPING_SCORE}",
        count=1,
    ):
        _trip_honeypot(fresh_ip)
        cookie = _solve("/", fresh_ip)

        # Five consecutive requests. In the bug every one of these was a
        # fresh challenge; the reporter's browser did this about once a
        # second for four minutes.
        for i in range(5):
            resp = _get("/", fresh_ip, cookie)
            assert resp.headers.get("X-Botshield") != "challenge", (
                f"request {i + 1} after solving was re-challenged; the "
                f"flag is being re-applied despite valid solve proof"
            )


def test_flag_acquired_after_solving_still_fires(
    config_override, fresh_ip, log_slice,
):
    """Solving must not switch the flag system off.

    A client that solves and then earns a DIFFERENT flag has produced
    new evidence. The flag still fires: it scores, and it appears in
    the reason trace, which is what this asserts. Whether it also
    produces a challenge is the separate question the tier decision
    answers -- new evidence that pushes the demand above what the
    client passed does challenge, and evidence that lands at or below
    it does not, because that question is already answered.

    Two distinct flags rather than one, because a mechanism keyed on
    "this client has solved something" rather than on what it proved
    would let the second flag through unnoticed."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule flagger>\n"
        "        BotShieldPath    /flag-me\n"
        "        BotShieldFlagIP  scanner_probe\n"
        "    </BotShieldRule>\n"
        f"    BotShieldFlagTrigger honeypot_hit reset "
        f"action=score accumulator=botsignals add={LOOPING_SCORE}\n"
        f"    BotShieldFlagTrigger scanner_probe reset "
        f"action=score accumulator=botsignals add={LOOPING_SCORE}",
        count=1,
    ):
        # Solve carrying honeypot_hit, which excuses exactly that bit.
        _trip_honeypot(fresh_ip)
        cookie = _solve("/", fresh_ip)
        resp = _get("/", fresh_ip, cookie)
        assert resp.headers.get("X-Botshield") != "challenge", (
            "solved client should not be re-challenged for the flag it "
            "just answered for"
        )

        # Now earn a different flag.
        client.get("/flag-me", xff=fresh_ip, ua=BROWSER_UA,
                   accept_language=ACCEPT_LANG)
        time.sleep(1)

        with log_slice as slc:
            _get("/", fresh_ip, cookie)
        lines = slc.decision_lines(ip=fresh_ip)
        assert any("flagtrigger:scanner_probe" in d["reason"] for d in lines), (
            f"a flag earned after the solve must still fire; lines={lines}"
        )


def test_a_presence_cookie_settles_nothing(
    config_override, fresh_ip, log_slice,
):
    """A presence cookie is not solve proof.

    Under always-mint every returning client holds a valid cookie,
    which is exactly what a cookie-harvesting bot has. It carries no
    passes_* bit, so it proves nothing and answers no demand."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        f"    BotShieldFlagTrigger honeypot_hit reset "
        f"action=score accumulator=botsignals add={LOOPING_SCORE}",
        count=1,
    ):
        _trip_honeypot(fresh_ip)

        # Take the presence cookie handed out with the challenge, but
        # never solve: no counter appended, so no proof of work.
        resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA,
                          accept_language=ACCEPT_LANG)
        presence = resp.cookies.get("__Host-bs_session")
        if not presence:
            pytest.skip("no presence cookie issued in this configuration")

        with log_slice as slc:
            _get("/", fresh_ip, presence)
        lines = slc.decision_lines()
        assert any("flagtrigger:honeypot_hit" in d["reason"] for d in lines), (
            f"an unsolved presence cookie must not excuse a flag; "
            f"lines={lines}"
        )


def test_an_unservable_captcha_demand_is_clamped(
    config_override, fresh_ip, log_slice,
):
    """A captcha nobody can serve must not be demanded.

    The dev vhost configures no captcha provider, so the render path
    falls back to the interactive PoW page. The demand used to survive
    that fallback: the envelope minted for a PoW page carries
    passes_interactive and never passes_captcha, so the next request
    met the same captcha demand, the same missing provider, and the
    same PoW page. The client was asked for a proof it was never
    offered, and no amount of solving could end it.

    Scored straight past the captcha row rather than through a flag,
    because the flag route is the one that was already covered -- this
    pins the clamp itself, which any route to a captcha demand needs.

    The reason trace naming captcha_unavailable is the assertion that
    the clamp is what did it. A challenge served at interactive proves
    nothing on its own: that is exactly what the broken version did
    too, one loop iteration at a time.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule demand-captcha>\n"
        "        BotShieldPath      /captcha-clamp-probe\n"
        "        BotShieldChallenge captcha\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        with log_slice as slc:
            first = client.get("/captcha-clamp-probe", xff=fresh_ip,
                               ua=BROWSER_UA, accept_language=ACCEPT_LANG)
            lines = slc.decision_lines(ip=fresh_ip)

        assert first.headers.get("X-Botshield") == "challenge", (
            "the rule asked for a challenge; something else refused the "
            "request and this test is not exercising the clamp"
        )
        assert any("captcha_unavailable" in (d.get("reason") or "")
                   for d in lines), (
            f"the demand should have been clamped to what this scope "
            f"can serve; lines={lines}"
        )
        assert all(d["tier"] != "captcha" for d in lines), (
            f"a captcha tier survived into the decision log with no "
            f"provider to serve it; lines={lines}"
        )

        # And it ends: solve the page actually served, then two more
        # requests. The second is where the loop showed up.
        cookie = _solve("/captcha-clamp-probe", fresh_ip)
        _get("/captcha-clamp-probe", fresh_ip, cookie)
        again = _get("/captcha-clamp-probe", fresh_ip, cookie)
        assert again.headers.get("X-Botshield") != "challenge", (
            "a client that solved what it was offered is still being "
            "challenged -- the demand outlived the fallback again"
        )
