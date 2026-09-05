"""App feedback can mark the cookie session, not just the address.

Trust is the reason this exists. `app_verified_human` says something
about one person who authenticated; written to an address it credits
everyone sharing that connection, and the sliding window means
unrelated traffic keeps renewing the discount. So trust belongs on the
cookie.

Getting it there is the awkward part. The handler decides what the
cookie says while the request is still being processed; feedback
arrives afterwards, in an output filter, as a signed header on the
application's own response. By then the cookie exists. Adding a second
Set-Cookie for the same name leaves the browser to choose, which is the
coin toss burn= used to take -- so the filter reseals the one already
queued instead. It has not reached the wire yet.
"""

from __future__ import annotations

import hashlib
import hmac

from botshield_test import client


SECRET_PATH = "/etc/botshield/app-integration-secret"
SECRET = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

PASS_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
PASS_AL = "en-US,en;q=0.9"
COOKIE_NAME = "__Host-bs_session"

FEEDBACK_PATH = "/about.html"
FEEDBACK_LOC = '<Location "/about.html">'


def _g(path, xff, **kw):
    return client.get(path, xff=xff, ua=PASS_UA,
                      accept_language=PASS_AL, **kw)


def _sign(event: str) -> str:
    body = f"event={event}"
    sig = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"{body};sig={sig}"


def _cfg(triggers: str) -> str:
    val = _sign("login-success")
    return (
        "BotShieldEnabled On\n"
        "    BotShieldAppFeedback on\n"
        f"    BotShieldAppIntegrationSecretFile {SECRET_PATH}\n"
        + triggers
        + f"    {FEEDBACK_LOC}\n"
        f'        Header always set X-BotShield-Feedback "{val}"\n'
        "    </Location>\n"
    )


def _bs_cookies(resp):
    if hasattr(resp.headers, "get_list"):
        lines = resp.headers.get_list("set-cookie")
    else:
        raw = resp.headers.get("set-cookie", "")
        lines = [raw] if raw else []
    return [c for c in lines if "bs_session" in c]


def test_session_mark_does_not_add_a_second_cookie(config_override,
                                                   fresh_ip):
    """Resealed, not duplicated.

    One Set-Cookie for our name. Two would mean the mark applies only
    if the browser happens to keep the right one.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg("    BotShieldFeedbackTrigger login-success "
             "flagsession=app_verified_human\n"),
        count=1,
    ):
        resp = _g(FEEDBACK_PATH, fresh_ip)
        ours = _bs_cookies(resp)
        assert len(ours) == 1, (
            f"expected exactly one bs cookie on the response; got {ours}"
        )


def test_session_mark_comes_back_on_the_next_request(config_override,
                                                     fresh_ip, log_slice):
    """The mark has to survive the round trip to be worth anything.

    The cookie handed back carries the flag, so the flag trigger fires
    on the next request -- which is the whole point: the client carries
    the evidence about itself, and its NAT neighbours do not.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        _cfg("    BotShieldFeedbackTrigger login-success "
             "flagsession=app_verified_human\n"
             "    BotShieldFlagTrigger app_verified_human "
             "action=score add=-40\n"),
        count=1,
    ):
        first = _g(FEEDBACK_PATH, fresh_ip)
        cookie = first.cookies.get(COOKIE_NAME)
        assert cookie, (
            f"feedback response should carry a cookie; got "
            f"{dict(first.cookies)}"
        )

        with log_slice as slc:
            _g("/", fresh_ip, cookies={COOKIE_NAME: cookie})
        lines = slc.decision_lines(ip=fresh_ip)
        assert any("app_verified_human" in (d.get("reason") or "")
                   for d in lines), (
            "the session flag should fire its trigger on the next "
            f"request; lines={lines}"
        )
