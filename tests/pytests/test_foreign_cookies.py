"""Exactly one BotShield cookie per response.

A rule that marks the session has to amend the cookie this response is
already carrying. Adding a second Set-Cookie for the same name leaves
the browser to pick one, and the mark applies only if it happens to
keep the right one -- which is the coin toss the removed burn= took,
and the reason it had to clear the queued header before writing its
own.

The clearing is selective: this module drops its own Set-Cookie lines
and leaves anything the application set standing. That part is hygiene
rather than a fix -- rules fire before the content handler and before
the header filters, so a foreign Set-Cookie is not in the table yet and
the blunt spelling was never observed to eat one. Not clearing headers
this module does not own is still the right shape, and it stops being
merely tidy the day something fires later in the cycle.
"""

from __future__ import annotations

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"


def _set_cookies(resp):
    if hasattr(resp.headers, "get_list"):
        return resp.headers.get_list("set-cookie")
    raw = resp.headers.get("set-cookie", "")
    return [raw] if raw else []


def test_session_mark_replaces_rather_than_duplicates(config_override,
                                                      fresh_ip):
    """One bs cookie on a response that marks the session.

    Two would mean the mark lands only when the browser happens to keep
    the later header.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule mark-once>\n"
        "        BotShieldPath         /mark-once-probe\n"
        "        BotShieldRespond      404\n"
        "        BotShieldFlagSession  blocked\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = client.get("/mark-once-probe", xff=fresh_ip, ua=BROWSER_UA)
        assert resp.status_code == 404
        ours = [c for c in _set_cookies(resp) if "bs_session" in c]
        assert len(ours) == 1, (
            f"expected exactly one bs cookie on the response; got {ours}"
        )
