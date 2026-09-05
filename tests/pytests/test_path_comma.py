"""A path containing a comma is one path.

Comma is a legal path character (RFC 3986 sub-delims), and it was also
the separator for a path list -- so `BotShieldPath /a,/b` became two
patterns and matched two prefixes instead of the one literal path
asked for. Silent, and broader than intended, which is the bad
direction for a rule that blocks.

Repeated BotShieldPath lines are the list now, which is how the block
form reads anyway. Nothing can separate a path list inside one value,
because every candidate delimiter is either legal in a path or eaten by
Apache's argv split before the module sees it.
"""

from __future__ import annotations

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"


def _get(path, ip):
    return client.get(path, xff=ip, ua=BROWSER_UA)


def test_comma_in_a_path_is_not_a_separator(config_override, fresh_ip):
    """The literal path matches; the halves either side of the comma do not.

    Before the fix this rule produced patterns `/comma-a` and `/comma-b`
    and blocked both, while the path actually written was never matched
    at all.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule comma-path>\n"
        "        BotShieldPath     /comma-a,/comma-b\n"
        "        BotShieldRespond  403\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        literal = _get("/comma-a,/comma-b", fresh_ip)
        assert literal.status_code == 403, (
            "the path as written should match; got "
            f"{literal.status_code}"
        )

        half = _get("/comma-a", fresh_ip)
        assert half.status_code != 403, (
            "the text before the comma is not a path of its own; "
            f"got {half.status_code}"
        )


def test_repeated_path_lines_still_or_together(config_override, fresh_ip):
    """The list form the block spelling actually uses.

    Repeated lines are how you write several paths, and they still OR:
    the walker hands the setter one token per line instead of joining
    them, and the setter accumulates.
    """
    with config_override(
        r"BotShieldEnabled\s+On",
        "BotShieldEnabled On\n"
        "    <BotShieldRule multi-path>\n"
        "        BotShieldPath     /multi-one\n"
        "        BotShieldPath     /multi-two\n"
        "        BotShieldRespond  403\n"
        "    </BotShieldRule>",
        render=False,
        count=1,
    ):
        for p in ("/multi-one", "/multi-two"):
            resp = _get(p, fresh_ip)
            assert resp.status_code == 403, (
                f"{p} should match the rule (403 from the rule, 404 means it did not); got {resp.status_code}"
            )

        other = _get("/multi-three", fresh_ip)
        assert other.status_code != 403, (
            "an unlisted path must not match; got "
            f"{other.status_code}"
        )
