"""Repeating BotShieldUserAgent ORs the alternatives.

BotShieldPath has always done this. UserAgent looked like it did --
the key is in the repeatable set, so a second line is accepted without
complaint -- but the block walker comma-joined the values and the
setter could only split them back apart when every element began with
'@'. Two plain lines became the single literal substring
"CorpBot,OtherBot", which matches no User-Agent ever sent, and nothing
said so.

The fix gives ua the branch path already took: one token per line, no
separator to be ambiguous about. These tests pin both halves -- the
case that was silently broken, and the spellings that already worked
and had to keep working.
"""

from __future__ import annotations

from botshield_test import client

UA_A = "CorpBot/1.0"
UA_B = "OtherBot/2.0"
UA_C = "Unrelated/3.0"


def _rule(ua_lines: str) -> str:
    return (
        "BotShieldEnabled On\n"
        "    <BotShieldRule ua-alts>\n"
        "        BotShieldPath         /ua-alt-probe\n"
        f"{ua_lines}\n"
        "        BotShieldRespond      403\n"
        "        BotShieldLogAs        ua-alts\n"
        "    </BotShieldRule>"
    )


def test_two_plain_user_agents_are_ored(config_override, fresh_ip):
    """The case that was silently broken.

    Neither line contains an '@', so the old join produced one literal
    substring with a comma in it and the rule matched nothing.
    """
    conf = _rule(
        f'        BotShieldUserAgent    "{UA_A}"\n'
        f'        BotShieldUserAgent    "{UA_B}"'
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        a = client.get("/ua-alt-probe", xff=fresh_ip, ua=UA_A)
        b = client.get("/ua-alt-probe", xff=fresh_ip, ua=UA_B)
        c = client.get("/ua-alt-probe", xff=fresh_ip, ua=UA_C)

    assert a.status_code == 403, f"first alternative missed; got {a.status_code}"
    assert b.status_code == 403, f"second alternative missed; got {b.status_code}"
    assert c.status_code != 403, (
        f"an unrelated UA was refused; got {c.status_code} -- the rule is "
        f"matching more than its alternatives"
    )


def test_a_selector_and_a_plain_ua_are_ored(config_override, fresh_ip):
    """Mixed lines. The old guard required *every* element to start
    with '@', so reading the code says one plain line poisoned the
    whole list.

    Unlike the two-plain case below, this one passed against the
    pre-fix build as well, and I could not account for that from the
    source before the old build was gone. So treat it as a
    forward-looking guard on the mixed spelling rather than as a test
    known to have caught the bug -- test_two_plain_user_agents_are_ored
    is the one verified to fail without the fix.
    """
    conf = _rule(
        "        BotShieldUserAgent    @bot\n"
        f'        BotShieldUserAgent    "{UA_C}"'
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        bot = client.get("/ua-alt-probe", xff=fresh_ip, ua="curl/8.0.1")
        plain = client.get("/ua-alt-probe", xff=fresh_ip, ua=UA_C)

    assert bot.status_code == 403, f"@bot alternative missed; got {bot.status_code}"
    assert plain.status_code == 403, (
        f"plain alternative missed alongside a selector; got {plain.status_code}"
    )
    control = client.get("/ua-alt-probe", xff=fresh_ip, ua="Mozilla/5.0 (X11)")
    assert control.status_code != 403, (
        f"a UA matching neither alternative was refused ({control.status_code})"
    )


def test_one_line_of_comma_separated_selectors_still_ors(
    config_override, fresh_ip,
):
    """The spelling that already worked. It is the reason the join
    existed, so it is the one most at risk from removing it."""
    conf = _rule("        BotShieldUserAgent    @bot,@ai-train")
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        r = client.get("/ua-alt-probe", xff=fresh_ip, ua="curl/8.0.1")
    assert r.status_code == 403, f"@bot,@ai-train on one line broke; got {r.status_code}"


def test_a_single_user_agent_is_unchanged(config_override, fresh_ip):
    """One line, no commas, no '@' -- the ordinary case, which must
    not have acquired list semantics."""
    conf = _rule(f'        BotShieldUserAgent    "{UA_A}"')
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        hit = client.get("/ua-alt-probe", xff=fresh_ip, ua=UA_A)
        miss = client.get("/ua-alt-probe", xff=fresh_ip, ua=UA_B)
    assert hit.status_code == 403, f"single UA missed; got {hit.status_code}"
    assert miss.status_code != 403, f"single UA over-matched; got {miss.status_code}"


def test_a_user_agent_containing_a_comma_is_one_value(
    config_override, fresh_ip,
):
    """The reason a comma cannot be the separator.

    Real User-Agents contain commas, so a value with one must stay a
    single substring rather than becoming two alternatives -- if it
    split, this rule would match on "Gecko" alone and refuse most
    browsers.
    """
    ua = "Mozilla/5.0 (X11; Linux x86_64, like Gecko) Probe/1.0"
    conf = _rule(f'        BotShieldUserAgent    "{ua}"')
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        exact = client.get("/ua-alt-probe", xff=fresh_ip, ua=ua)
        half = client.get("/ua-alt-probe", xff=fresh_ip,
                          ua="Mozilla/5.0 (Windows NT 10.0) Gecko/20100101")
    assert exact.status_code == 403, f"exact UA missed; got {exact.status_code}"
    assert half.status_code != 403, (
        f"a UA matching only part of the comma-containing value was refused "
        f"({half.status_code}) -- the value was split on its comma"
    )


def test_two_ipspec_lines_are_ored(config_override):
    """ipspec repeats the same way, for consistency rather than repair.

    A comma cannot appear in a CIDR, so the old comma-joining was never
    ambiguous here the way it was for a User-Agent -- this spelling
    already worked. What it was not was consistent: three repeatable
    keys, two taking a token per line and one joined behind the
    reader's back.

    Every address here is inside 192.0.2.0/24, which no other
    test or config touches. The first draft used 203.0.113.x and
    198.51.100.x -- four and five other files use those -- and the
    control address arrived carrying flag state from an earlier
    test, refused for a reason unrelated to this rule. It passed
    alone and failed in the full lane.
    """
    conf = (
        'BotShieldEnabled On\n'
        '    <BotShieldRule ip-alts>\n'
        '        BotShieldPath      /ip-alt-probe\n'
        '        BotShieldIPSpec    192.0.2.0/28\n'
        '        BotShieldIPSpec    192.0.2.128/28\n'
        '        BotShieldRespond   403\n'
        '    </BotShieldRule>'
    )
    with config_override(r'BotShieldEnabled\s+On', conf,
                         render=False, count=1):
        a = client.get('/ip-alt-probe', xff='192.0.2.3', ua='probe/1.0')
        b = client.get('/ip-alt-probe', xff='192.0.2.130', ua='probe/1.0')
        c = client.get('/ip-alt-probe', xff='192.0.2.200', ua='probe/1.0')
    assert a.status_code == 403, f'first CIDR missed; got {a.status_code}'
    assert b.status_code == 403, f'second CIDR missed; got {b.status_code}'
    assert c.status_code != 403, f'an unlisted IP was refused; got {c.status_code}'
