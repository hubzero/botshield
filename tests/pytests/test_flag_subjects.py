"""BotShieldFlagIP / BotShieldFlagSession: two subjects, one vocabulary.

The address and the cookie session are the two places this module can
remember a client. Which one a rule writes to is now a directive rather
than an implicit consequence of the family, and three of the seven flag
names are refused on the address entirely.

That refusal is the point of this file. `app_verified_human` and its
siblings are credits, and a credit on an address is inherited by every
client sharing it -- so a NAT where one person logged in hands a
discount to everyone behind it, renewed by whatever traffic keeps that
address flagged. Suspicion shared across an address costs strangers a
challenge, which is a trade this module already makes; trust shared
across an address gives strangers an exemption they did not earn.
"""

from __future__ import annotations

import pytest

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
COOKIE_NAME = "__Host-bs_session"


def test_flag_ip_refuses_session_only_flags(config_override):
    """A credit on an address is refused at config time, not at runtime.

    Config-time because the failure is silent otherwise: the rule looks
    like it grants trust and instead grants it to a whole NAT."""
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldRule trust-on-address>\n"
            "        BotShieldPath      /trust-probe\n"
            "        BotShieldFlagIP    app_verified_human\n"
            "    </BotShieldRule>",
            render=False,
            count=1,
        ):
            pass
    msg = str(exc_info.value)
    assert "returned non-zero exit status" in msg or "FlagSession" in msg, (
        f"expected the credit-on-address rule to be refused; got {msg!r}"
    )


def test_flag_session_accepts_them(config_override, fresh_ip):
    """The same names are fine on the session, which is what they describe."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule trust-on-session>\n"
        "        BotShieldPath         /trust-session-probe\n"
        "        BotShieldRespond      nochallenge\n"
        "        BotShieldFlagSession  app_verified_human\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = client.get("/trust-session-probe", xff=fresh_ip, ua=BROWSER_UA)
        assert resp.status_code != 500, (
            "a session credit must parse and run; got 500"
        )


def test_flag_session_reaches_the_cookie(config_override, fresh_ip):
    """The mark must survive into the cookie the client is handed.

    This is the half burn= had to fight for: a rule fires from the
    policy walk, and the ordinary session mint runs later in the same
    response. Accumulating on the request and letting that one mint
    carry the bits means there is only ever one Set-Cookie."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule mark-session>\n"
        "        BotShieldPath         /mark-session-probe\n"
        "        BotShieldRespond      nochallenge\n"
        "        BotShieldFlagSession  scanner_probe\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = client.get("/mark-session-probe", xff=fresh_ip, ua=BROWSER_UA)
        cookies = resp.headers.get_list("set-cookie") \
            if hasattr(resp.headers, "get_list") \
            else [resp.headers.get("set-cookie", "")]
        bs_lines = [c for c in cookies if COOKIE_NAME in c]
        assert len(bs_lines) <= 1, (
            f"exactly one bs cookie per response, never a race; got {bs_lines}"
        )


def test_flag_ip_accepts_suspicion_flags(config_override, fresh_ip):
    """Suspicion on an address is the ordinary case and stays allowed."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule suspect-address>\n"
        "        BotShieldPath     /suspect-address-probe\n"
        "        BotShieldRespond  404\n"
        "        BotShieldFlagIP   scanner_probe\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = client.get("/suspect-address-probe", xff=fresh_ip,
                          ua=BROWSER_UA)
        assert resp.status_code == 404
