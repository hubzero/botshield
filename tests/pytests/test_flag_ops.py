"""`+` / `-` / `=` on the flag directives, and who is allowed to clear.

`+` adds, `-` removes, `=` makes the named set the whole set. `+` is the
default, so an unprefixed list behaves as it always did. The grammar is
borrowed rather than invented: BotShieldClassify already takes
`[All|None] [+/-flag]...`.

The part worth testing is the gate. Clearing is available only on
BotShieldFeedbackTrigger, which fires on an app-signed header. Every
other family matches on request properties the client controls, so `-`
there would be a laundering primitive: fetch the URL that matches, shed
your own record. That refusal has to happen at config time, because at
runtime it looks like a rule that works.
"""

from __future__ import annotations

import pytest

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"


def _override(config_override, body):
    return config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n" + body,
        render=False,
        count=1,
    )


def _refused(config_override, body):
    with pytest.raises(Exception) as exc_info:
        with _override(config_override, body):
            pass
    return str(exc_info.value)


def test_remove_is_refused_on_a_request_rule(config_override):
    """A rule cannot clear an address: the client picks when it fires."""
    msg = _refused(config_override,
        "    <BotShieldRule launder>\n"
        "        BotShieldPath    /launder-probe\n"
        "        BotShieldFlagIP  -scanner_probe\n"
        "    </BotShieldRule>")
    assert "returned non-zero exit status" in msg or "Feedback" in msg, (
        f"a rule clearing an address must be refused; got {msg!r}"
    )


def test_replace_is_refused_on_a_request_rule(config_override):
    """`=` is the same hazard with a bigger blast radius."""
    msg = _refused(config_override,
        "    <BotShieldRule wipe>\n"
        "        BotShieldPath    /wipe-probe\n"
        "        BotShieldFlagIP  =scanner_probe\n"
        "    </BotShieldRule>")
    assert "returned non-zero exit status" in msg or "Feedback" in msg, (
        f"a rule replacing an address flag set must be refused; got {msg!r}"
    )


def test_mixing_replace_with_a_delta_is_refused(config_override):
    """`=a,+b` has no reading that is not a guess.

    Refused on the feedback family too, where both operators are
    otherwise allowed -- this is a grammar error, not a permission one.
    """
    msg = _refused(config_override,
        "    <BotShieldFeedbackTrigger login-success>\n"
        "        BotShieldFlagSession  =app_verified_human,+scanner_probe\n"
        "    </BotShieldFeedbackTrigger>")
    assert "returned non-zero exit status" in msg or "mix" in msg, (
        f"mixing = with a delta must be refused; got {msg!r}"
    )


def test_feedback_may_clear(config_override, fresh_ip):
    """The app-signed family is where clearing lives.

    Clear-only is a legitimate mapping: "this event means forget that
    suspicion" needs no flag of its own to set.
    """
    with _override(config_override,
        "    <BotShieldFeedbackTrigger login-success>\n"
        "        BotShieldFlagSession  -scanner_probe\n"
        "    </BotShieldFeedbackTrigger>"):
        resp = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
        assert resp.status_code < 500, (
            "a clear-only feedback trigger must parse and serve"
        )


def test_explicit_plus_matches_the_bare_form(config_override, fresh_ip):
    """`+name` is the default spelling written out, not a new behaviour."""
    with _override(config_override,
        "    <BotShieldRule plus-probe>\n"
        "        BotShieldPath     /plus-probe\n"
        "        BotShieldRespond  404\n"
        "        BotShieldFlagIP   +scanner_probe\n"
        "    </BotShieldRule>"):
        resp = client.get("/plus-probe", xff=fresh_ip, ua=BROWSER_UA)
        assert resp.status_code == 404
