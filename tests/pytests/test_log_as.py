"""BotShieldLogAs labels a decision line; it does not cause one.

The decision entry is emitted whether or not a rule sets a tag, and the
tag is embedded on that same line rather than producing a second one.
BotShieldLog read as the thing that made the log happen -- and as
something you could remove to stop it -- which is the opposite of what
it does. "As" says the value is a name.

The old spelling still parses and warns, so a config that has not
migrated keeps working.
"""

from __future__ import annotations

import pytest

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"


def _rule(directive, tag, path):
    return (
        "BotShieldEnabled On\n"
        f"    <BotShieldRule tagged>\n"
        f"        BotShieldPath     {path}\n"
        f"        BotShieldRespond  403\n"
        f"        {directive}       {tag}\n"
        f"    </BotShieldRule>"
    )


def test_log_as_tags_the_decision_line(config_override, fresh_ip, log_slice):
    with config_override(
        r"BotShieldEnabled\s+On",
        _rule("BotShieldLogAs", "newspelling", "/logas-probe"),
        render=False,
        count=1,
    ):
        with log_slice as slc:
            resp = client.get("/logas-probe", xff=fresh_ip, ua=BROWSER_UA)
        assert resp.status_code == 403
        lines = slc.decision_lines(ip=fresh_ip)
        assert any(d.get("tag") == "newspelling" for d in lines), (
            f"BotShieldLogAs should set the decision tag; lines={lines}"
        )


def test_removed_log_spelling_is_refused(config_override):
    """BotShieldLog is gone; BotShieldLogAs is the name.

    The old one read as the thing that produces the log entry, and
    removing it as a way to stop one. It does neither -- the line was
    going to be emitted anyway, and this only labels it.

    Removed 2026-09-06 with the other four deprecated spellings rather
    than carried: this is the only site running the module, so there
    was nobody to hold a window open for.
    """
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("BotShieldLog", "oldspelling", "/log-probe"),
            render=False,
            count=1,
        ):
            pass
    assert "returned non-zero exit status" in str(exc_info.value), (
        f"the removed spelling must be refused by httpd; "
        f"got: {str(exc_info.value)!r}"
    )
