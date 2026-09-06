"""T3 - BotShieldFlagged as a rule condition.

The FlagTrigger predicate, moved into the rule so it can be ANDed with
the path, the UA and the rest. FlagTrigger's action half stays: a
flag->tier mapping applied at the tier decision is a different thing
from a request match.

Two decisions this file pins.

Reads are live. A rule sees flags written by rules above it in the same
walk, which is the contract BotShieldScoreAtLeast already has for
accumulators -- a rule reads what rules above it have done. That is
what makes trap-then-act possible in one request instead of two.

Matching a flag and writing the same flag is refused at config time. In
one request there is no loop, because a rule is evaluated once. The
hazard is across requests: such a rule refreshes the flag's expiry on
every request it matches, so the address never ages out of it. Expiry
is the only recovery for a client that CANNOT solve a challenge --
flags_excused only helps one that can -- and this module has twice
shipped a state a client could not get out of.
"""

from __future__ import annotations

import pytest

from botshield_test import client, ips as _ips


TRAP = "/flagged-trap"
PROBE = "/flagged-probe"


def _conf(body):
    return (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        + body
    )


def test_flagged_matches_an_address_carrying_the_flag(
    config_override, fresh_ip,
):
    """Two requests: the first trips the trap, the second is matched
    by a separate rule reading the flag."""
    conf = _conf(
        "    <BotShieldRule trap>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagIP    scanner_probe\n"
        "        BotShieldRespond   404\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule act>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldFlagged   scanner_probe\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        before = client.get(PROBE, xff=fresh_ip).status_code
        client.get(TRAP, xff=fresh_ip)
        after = client.get(PROBE, xff=fresh_ip).status_code
    assert before != 451, "not flagged yet; the rule must not fire"
    assert after == 451, "flagged now; the rule must fire"


def test_flagged_does_not_match_an_unflagged_address(
    config_override, fresh_ip,
):
    """The control. A different address never trips the trap."""
    conf = _conf(
        "    <BotShieldRule act>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldFlagged   honeypot_hit\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        assert client.get(PROBE, xff=fresh_ip).status_code != 451


def test_read_is_live_within_one_walk(config_override, fresh_ip):
    """A rule sees a flag written by a rule above it, same request.

    This is the decision that separates flagged= from a snapshot: the
    trap and the response happen on the same request rather than the
    client getting one free pass.

    Note what the trap rule needs to make that reachable. A rule whose
    only action is a flag write returns PASS_DECLINE and ends the
    walk, so nothing below it runs and the live read has nothing to
    see. Scoring (or asking for a tier) is what keeps the walk going.
    That is pre-existing rule behaviour rather than anything flagged=
    introduced, but it is the difference between this working and not,
    so it is pinned here.
    """
    conf = _conf(
        "    <BotShieldRule trap>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagIP    scanner_probe\n"
        "        BotShieldScore     walk +1\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule act>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagged   scanner_probe\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        first = client.get(TRAP, xff=fresh_ip).status_code
    assert first == 451, (
        "the flag was written by the rule above and must be visible "
        "to this one on the same request"
    )


def test_order_matters_for_a_live_read(config_override, fresh_ip):
    """The same two rules in the other order do not fire on the first
    request, because nothing had written the flag yet when the reader
    ran. Pinning it so the cost of the live read is explicit rather
    than discovered."""
    conf = _conf(
        "    <BotShieldRule act>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagged   scanner_probe\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule trap>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagIP    scanner_probe\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        first = client.get(TRAP, xff=fresh_ip).status_code
        second = client.get(TRAP, xff=fresh_ip).status_code
    assert first != 451, "the reader ran before the writer"
    assert second == 451, "by the next request the flag is set"


def test_flagged_ands_with_the_rest_of_the_rule(config_override):
    """The reason this is a condition and not a family: it composes."""
    ip = _ips.fresh_ip()
    conf = _conf(
        "    <BotShieldRule trap>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagIP    scanner_probe\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule act>\n"
        "        BotShieldFlagged   scanner_probe\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        client.get(TRAP, xff=ip)
        on_probe = client.get(PROBE, xff=ip).status_code
        on_other = client.get("/", xff=ip).status_code
    assert on_probe == 451, "flagged and on the right path"
    assert on_other != 451, "flagged but the path differs; must not fire"


# --- the refusals ---------------------------------------------------


def test_matching_and_writing_the_same_flag_is_refused(config_override):
    """The rule that would make a flag unexpirable.

    It refreshes the expiry on every request it matches, and expiry is
    the only recovery for a client that cannot solve. The match earns
    nothing either: if the other conditions justify the write, they
    justify it whether or not the flag is already set.
    """
    conf = _conf(
        "    <BotShieldRule selffeed>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagged   scanner_probe\n"
        "        BotShieldFlagIP    scanner_probe\n"
        "    </BotShieldRule>"
    )
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


def test_matching_one_flag_and_writing_another_is_allowed(
    config_override, fresh_ip,
):
    """Escalation is the legitimate shape and stays.

    scanner_probe plus a sensitive path escalates to honeypot_hit. This
    does not self-feed: honeypot_hit's expiry is not refreshed by its
    own presence.
    """
    conf = _conf(
        "    <BotShieldRule escalate>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagged   scanner_probe\n"
        "        BotShieldFlagIP    honeypot_hit\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        assert client.get(TRAP, xff=fresh_ip).status_code != 451


def test_unknown_flag_name_is_refused(config_override):
    conf = _conf(
        "    <BotShieldRule bogus>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagged   not_a_real_flag\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


def test_negated_flagged_is_refused(config_override):
    """!flagged would fire on nearly every request.

    An address not carrying a flag is the ordinary case. The two
    conditions that take '!' are open sets where the complement has no
    name; this one has a name and it is 'almost everyone'.
    """
    conf = _conf(
        "    <BotShieldRule notflagged>\n"
        f"        BotShieldPath      {TRAP}\n"
        "        BotShieldFlagged   !scanner_probe\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with pytest.raises(Exception) as exc_info:
        with config_override(r"BotShieldEnabled\s+On", conf,
                             render=False, count=1):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)
