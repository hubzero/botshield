"""Exactly one BotShield cookie per response.

burn= mints its own cookie, so it has to clear whatever this module
already queued -- two Set-Cookie lines for one name means the browser
keeps whichever arrived last, and the burn becomes a coin toss.

It clears selectively rather than calling apr_table_unset on
Set-Cookie outright. That is hygiene rather than a fix: triggers fire
before the content handler and before the header filters, so a
foreign Set-Cookie is not in the table yet and the blunt spelling was
never observed to eat one. Not clearing headers this module does not
own is still the right shape, and it stops being merely tidy the day a
trigger fires later in the cycle.
"""

from __future__ import annotations

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
APP_COOKIE = "app_session=keepme"


def _set_cookies(resp):
    if hasattr(resp.headers, "get_list"):
        return resp.headers.get_list("set-cookie")
    raw = resp.headers.get("set-cookie", "")
    return [raw] if raw else []


def test_burn_still_replaces_our_own_cookie(config_override, fresh_ip):
    """The selective drop must not stop the burn working.

    Exactly one bs cookie on the response: the burned one. If the
    filter kept ours as well as adding the burn, the browser would keep
    whichever arrived last and the burn would be a coin toss.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule burn-only-ours>\n"
        "        BotShieldPath     /burn-only-ours\n"
        "        BotShieldRespond  404\n"
        "        BotShieldBurn     60\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = client.get("/burn-only-ours", xff=fresh_ip, ua=BROWSER_UA)
        ours = [c for c in _set_cookies(resp) if "bs_session" in c]
        assert len(ours) == 1, (
            f"expected exactly one bs cookie on the response; got {ours}"
        )
