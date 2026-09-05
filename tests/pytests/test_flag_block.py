"""`action=block` — the flag action that ends a request.

score SUMs, tier_floor MAXes, and block sits above both: it is not a
harder challenge, it is a refusal. That is what makes it safe to leave
outside excusal.

Excusal exists because a flag that forces a challenge and cannot be
excused is an unbreakable loop -- solve, get re-flagged, get
re-challenged -- which reached production twice. A block cannot loop,
because it never asks the client for anything. So `block` reads the
un-excused flag set while score and tier_floor read the excused one,
and that asymmetry is deliberate rather than an oversight.
"""

from __future__ import annotations

import pytest

from botshield_test import client, cookies


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"
COOKIE_NAME = "__Host-bs_session"

RULE = (
    "BotShieldEnabled On\n"
    '    BotShieldRule wp-probe path="/wp-admin/*" respond=404 '
    "flagsession=blocked logas=wp-probe\n"
    "    BotShieldFlagTrigger blocked action=block status=404\n"
)


def _get(path, ip, cookie=None):
    kw = {"cookies": {COOKIE_NAME: cookie}} if cookie else {}
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG, **kw)


def test_blocked_session_is_refused_on_its_next_request(
    config_override, fresh_ip, log_slice,
):
    """The probe gets its own status; the session gets the block.

    Two different refusals: 404 because the rule said respond=404, then
    404 again because the flag the rule set means block. They coincide
    here deliberately -- a probe should not learn anything from the
    difference.
    """
    with config_override(r"BotShieldEnabled\s+On", RULE, count=1):
        probe = _get("/wp-admin/setup-config.php", fresh_ip)
        assert probe.status_code == 404
        cookie = probe.cookies.get(COOKIE_NAME)
        assert cookie, (
            f"the rule should hand back a marked cookie; got "
            f"{dict(probe.cookies)}"
        )

        with log_slice as slc:
            back = _get("/", fresh_ip, cookie)

        assert back.status_code == 404, (
            f"a blocked session must be refused; got {back.status_code}"
        )
        lines = slc.decision_lines(ip=fresh_ip)
        assert any("flagblock:blocked" in (d.get("reason") or "")
                   for d in lines), (
            f"decision log should name the blocking flag; lines={lines}"
        )


def test_block_is_not_excused_by_solving(config_override, fresh_ip):
    """A refusal is not a debt the client can work off.

    Solving pays off the flags live at solve time. If block were
    excusable, "blocked" would mean "solve a challenge to continue" --
    which is what a challenge tier already says, and not what an
    operator writing block asked for.
    """
    with config_override(r"BotShieldEnabled\s+On", RULE, count=1):
        probe = _get("/wp-admin/setup-config.php", fresh_ip)
        cookie = probe.cookies.get(COOKIE_NAME)
        assert cookie

        # Whatever the client does next, it stays refused. Repeat to
        # rule out a one-request fluke.
        for i in range(3):
            back = _get("/", fresh_ip, cookie)
            assert back.status_code == 404, (
                f"request {i + 1} after the block was allowed through "
                f"({back.status_code}); block must not be excusable"
            )


def test_block_rejects_a_non_refusal_status(config_override):
    """status=200 on a block has no meaning; refused at config time."""
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    BotShieldFlagTrigger blocked action=block status=200\n",
            count=1,
        ):
            pass
    msg = str(exc_info.value)
    assert "returned non-zero exit status" in msg or "400..599" in msg, (
        f"expected a non-refusal status to be refused; got {msg!r}"
    )
