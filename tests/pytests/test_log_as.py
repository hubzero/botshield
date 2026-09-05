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


def test_deprecated_log_still_tags(config_override, fresh_ip, log_slice):
    """The old spelling keeps working while it is being migrated."""
    with config_override(
        r"BotShieldEnabled\s+On",
        _rule("BotShieldLog", "oldspelling", "/log-probe"),
        render=False,
        count=1,
    ):
        with log_slice as slc:
            resp = client.get("/log-probe", xff=fresh_ip, ua=BROWSER_UA)
        assert resp.status_code == 403
        lines = slc.decision_lines(ip=fresh_ip)
        assert any(d.get("tag") == "oldspelling" for d in lines), (
            f"the deprecated spelling must still tag; lines={lines}"
        )
