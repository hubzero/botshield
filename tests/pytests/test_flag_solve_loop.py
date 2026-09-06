"""Regression: a flagged client must be able to solve its way out.

Solving a challenge does not clear a flag, and flag scores re-apply on
every request. Before `flags_excused`, any flag scoring at or above
the noninteractive row was therefore an unbreakable loop: challenge,
solve, get re-scored by the same flag, challenge again, forever. It
reached production twice -- once via a compiled-in tier_floor, once via
the score that the documented fix for the first one recommends.

The shape of the bug is why it survived a test suite that already
covered flags and already covered solving. A test that solves once and
asserts the next request passes is not enough, because the first
post-solve request is not where this fails -- the cookie is fresh and
carries a just-forgiven score. The loop shows up on the request AFTER
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
    """The excusal must not become blanket immunity.

    Only the flags live at solve time are settled. A client that solves
    and then earns a DIFFERENT flag has produced new evidence, and that
    must still challenge -- otherwise one solve buys permanent immunity
    and the flag system stops meaning anything.

    Two distinct flags rather than one, because that is precisely the
    distinction being tested: excusal is per-flag-bit, not a blanket
    "this client has solved" exemption."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        '    SetEnvIf Request_URI "/flag-me" BS_FLAG_ME=1\n'
        "    BotShieldEnvTrigger flagger env=BS_FLAG_ME "
        "flag=scanner_probe ttl=3600\n"
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


def test_excusal_requires_real_solve_proof(
    config_override, fresh_ip, log_slice,
):
    """A presence cookie is not solve proof.

    Under always-mint every returning client holds a valid cookie, which
    is exactly what a cookie-harvesting bot has. Only `solved` -- a
    cookie carrying a passes_* bit -- may excuse anything."""
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
