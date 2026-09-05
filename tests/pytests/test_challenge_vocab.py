"""BotShieldNoChallenge and BotShieldChallenge.

Two directives replacing a pair that only worked together.

`BotShieldTier noninteractive` needed `status=nochallenge` beside it,
because a concrete status short-circuits before any tier is chosen --
so you wrote a line with no meaning of its own in order to be allowed
to write the line you wanted. Issuing a challenge already implies
producing no other response, so BotShieldChallenge sets both.

And a rule that decides nothing was spelled by *omission*: a bare
`status=nochallenge` with no tier and no penalty. BotShieldNoChallenge
says it. It is named for what it waives, not what it grants -- the
request still meets rate limiting and robots.txt, and the rule's flag
writes still happen. `pass` was retired for claiming more than that.
"""

from __future__ import annotations

import pytest

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"
# Enough on its own to land in a challenge tier, which is what makes
# the no-challenge test meaningful rather than vacuous.
SCRAPER_UA = "python-requests/2.31"


def _get(path, ip, ua, accept_language=ACCEPT_LANG):
    return client.get(path, xff=ip, ua=ua, accept_language=accept_language)


def _scraper(path, ip):
    """A request that is challenged on its own merits.

    No Accept-Language: the scraper UA alone is not enough in this
    vhost, and a control that is not actually challenged would make the
    test it guards prove nothing."""
    return client.get(path, xff=ip, ua=SCRAPER_UA)


def test_scraper_is_challenged_without_the_rule(config_override, fresh_ip):
    """Control. If this ever stops being true the next test proves nothing."""
    with config_override(
        r"BotShieldEnabled\s+On", "BotShieldEnabled On\n", count=1,
    ):
        resp = _scraper("/?nochal=1", fresh_ip)
        assert resp.headers.get("X-Botshield") == "challenge", (
            "the scraper UA should be challenged with no rule in play; "
            f"headers={dict(resp.headers)}"
        )


def test_nochallenge_declines_the_decision(config_override, fresh_ip):
    """The same request, with a rule that decides nothing, is served."""
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule quiet>\n"
        '        BotShieldQuery        *nochal=1*\n'
        "        BotShieldNoChallenge\n"
        "        BotShieldLog          quiet\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = _scraper("/?nochal=1", fresh_ip)
        assert resp.headers.get("X-Botshield") != "challenge", (
            "BotShieldNoChallenge should stop the challenge decision; "
            f"got headers={dict(resp.headers)}"
        )


def test_challenge_needs_no_companion(config_override, fresh_ip):
    """BotShieldChallenge alone challenges a client that would pass.

    No BotShieldRespond line: that is the point. Under the old spelling
    this rule needed `status=nochallenge` as well or the tier was never
    reached.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule gate>\n"
        '        BotShieldQuery      *chal=1*\n'
        "        BotShieldChallenge  noninteractive\n"
        "        BotShieldLog        gate\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        resp = _get("/?chal=1", fresh_ip, BROWSER_UA)
        assert resp.headers.get("X-Botshield") == "challenge", (
            "BotShieldChallenge should raise a challenge on its own; "
            f"got headers={dict(resp.headers)}"
        )


def test_challenge_rejects_nochallenge_as_a_tier(config_override):
    """`nochallenge` is not a tier; the error names the directive to use."""
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldRule bad>\n"
            '        BotShieldQuery      *x=1*\n'
            "        BotShieldChallenge  nochallenge\n"
            "    </BotShieldRule>",
            render=False,
            count=1,
        ):
            pass
    msg = str(exc_info.value)
    assert "returned non-zero exit status" in msg or "NoChallenge" in msg, (
        f"expected nochallenge to be refused as a tier; got {msg!r}"
    )
