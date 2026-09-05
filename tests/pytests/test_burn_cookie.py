"""A trigger's `burn=` ends the session of the browser that tripped it.

Two kinds of memory, and this file covers the one that travels in the
cookie. `flag=`/`ttl=` marks an address, which marks every client behind
the same NAT; `burn=` marks the cookie session, so it catches the one
browser that actually probed and nobody else sharing the address.

Both are opt-in as of 2026-09-05. The request family used to flag
`scanner_probe` for an hour on its own, and because that flag carries a
compiled-in tier floor, a rule written to return a quiet 404 quietly
started rendering interstitials to whoever shared the address next --
with nothing in the config saying so. The default-off half is tested
here too, and it is the regression that matters more: a rule that
remembers people is invisible in the config that caused it, so only a
test keeps the default honest.
"""

from __future__ import annotations

import time

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"
COOKIE_NAME = "__Host-bs_session"

PROBE_PATH = "/wp-admin/setup-config.php"

_RULE = (
    "BotShieldEnabled On\n"
    '    BotShieldRule wp-probe path="/wp-admin/*" '
    "respond=404 {actions}log=wp-probe"
)
BURN_RULE = _RULE.format(actions="burn=3600 ")
PLAIN_RULE = _RULE.format(actions="")


def _probe(ip: str):
    return client.get(PROBE_PATH, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG)


def _return(ip: str, cookie: str):
    return client.get("/", xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG,
                      cookies={COOKIE_NAME: cookie})


def test_burn_refuses_the_session_that_probed(
    config_override, fresh_ip, log_slice,
):
    """The probe gets its status, and the cookie it is handed ends it.

    Two assertions rather than one, because the interesting failure sits
    between them: the rule can fire correctly and the burn still not
    take, if the ordinary session mint runs later in the same response
    and its Set-Cookie wins. That looks exactly like the rule not firing
    at all, so the cookie coming back refused is the only proof."""
    with config_override(r"BotShieldEnabled\s+On", BURN_RULE, count=1):
        probe = _probe(fresh_ip)
        assert probe.status_code == 404, (
            f"the rule's own status should apply; got {probe.status_code}"
        )
        cookie = probe.cookies.get(COOKIE_NAME)
        assert cookie, (
            "the burn must hand the client a cookie carrying the mark; "
            f"got cookies={dict(probe.cookies)}"
        )

        with log_slice as slc:
            back = _return(fresh_ip, cookie)

        assert back.status_code == 403, (
            "a burned session must be refused on its next request; got "
            f"{back.status_code}"
        )
        lines = slc.decision_lines(ip=fresh_ip)
        assert any(d.get("cookie") == "burned" for d in lines), (
            f"decision log should record cookie=burned; lines={lines}"
        )
        assert any("burnedcookie" in (d.get("reason") or "") for d in lines), (
            f"decision log should give burnedcookie as the reason; "
            f"lines={lines}"
        )


def test_no_burn_leaves_the_session_live(config_override, fresh_ip):
    """Without `burn=` the same rule forgets the client entirely.

    The rule still returns its 404 -- what must not happen is the
    client's next request being refused."""
    with config_override(r"BotShieldEnabled\s+On", PLAIN_RULE, count=1):
        probe = _probe(fresh_ip)
        assert probe.status_code == 404

        cookie = probe.cookies.get(COOKIE_NAME)
        if cookie:
            back = _return(fresh_ip, cookie)
            assert back.status_code != 403, (
                "a rule with no burn= must not end the client's session"
            )


def test_request_trigger_does_not_flag_the_address_by_default(
    config_override, fresh_ip, log_slice,
):
    """The removed default, pinned.

    This family flagged `scanner_probe` for 3600 s unless the rule said
    otherwise, and `scanner_probe` carries a compiled-in tier floor. The
    visible symptom was the next request from that address arriving with
    `flaggedip` in its reason and a challenge it never asked for -- for
    every client behind the NAT, not just the prober."""
    with config_override(r"BotShieldEnabled\s+On", PLAIN_RULE, count=1):
        _probe(fresh_ip)
        # Flag writes go through a mutex; a second is enough for the
        # next lookup to see one if it were being written.
        time.sleep(1)

        with log_slice as slc:
            client.get("/", xff=fresh_ip, ua=BROWSER_UA,
                       accept_language=ACCEPT_LANG)

        lines = slc.decision_lines(ip=fresh_ip)
        assert not any("flaggedip" in (d.get("reason") or "") for d in lines), (
            "the request family must not flag the address unless the rule "
            f"says flag= and ttl=; lines={lines}"
        )
