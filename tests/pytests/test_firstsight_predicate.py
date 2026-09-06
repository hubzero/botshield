"""BotShieldFirstSight — the Bloom signal, scoped to where you want it.

`firstsightip` and `droppedcookie` fire site-wide or not at all. The
docs recommend the first "on a login or registration path" and then
offer only a global weight, so the recommendation has not been writable.
As a predicate it is: path plus firstsight is an ordinary rule.

Two things about the filter these tests had to learn the hard way.

It records an address only on requests that reach the mint. A request a
rule refused never gets there, so a refusing rule does not register the
client. That looks like an oversight and is not: `droppedcookie` means
"known address arriving without a usable cookie", and its suspicion is
that the client was given a cookie and is not presenting it. A refused
request never reached a mint, so that client has nothing to present.
Recording refusals turned droppedcookie into a penalty for having been
blocked once -- 25 points against a threshold of 20 in this vhost.

So these rules score rather than refuse. A scoring rule returns
PASS_CONTINUE, the walk carries on, and the request reaches the mint
like any other.

Asserted on the decision reason rather than the status code, because
the dev vhost scores an unknown client past its own threshold and a 403
here could be either.
"""

from __future__ import annotations

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"

NEWCOMER = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule newcomer>\n"
    "        BotShieldPath        /firstsight-probe\n"
    "        BotShieldFirstSight  yes\n"
    "        BotShieldNoChallenge\n        BotShieldPenalty     1\n"
    "        BotShieldLogAs       newcomer\n"
    "    </BotShieldRule>\n"
)

RETURNING = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule returning>\n"
    "        BotShieldPath        /firstsight-probe\n"
    "        BotShieldFirstSight  no\n"
    "        BotShieldNoChallenge\n        BotShieldPenalty     1\n"
    "        BotShieldLogAs       returning\n"
    "    </BotShieldRule>\n"
)


def _get(path, ip):
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG)


def _fired(slc, ip, name):
    """Did the named rule match? A scoring rule names itself in the
    reason trace as requesttrigger:<name>."""
    return any(("requesttrigger:" + name) in (d.get("reason") or "")
               for d in slc.decision_lines(ip=ip))


def test_firstsight_yes_matches_only_the_first_request(config_override,
                                                       fresh_ip, log_slice):
    """A Bloom-fresh address matches; the same address then does not.

    The second request is the real assertion. Every request that reaches
    the mint feeds the filter, so an address is first-sight exactly
    once -- if the predicate read the filter after the write, or read it
    fresh each time, it would answer differently.
    """
    with config_override(r"BotShieldEnabled\s+On", NEWCOMER,
                         render=False, count=1):
        with log_slice as first:
            _get("/firstsight-probe", fresh_ip)
        assert _fired(first, fresh_ip, "newcomer"), (
            "a Bloom-fresh address should match firstsight=yes; "
            f"lines={first.decision_lines(ip=fresh_ip)}"
        )

        with log_slice as second:
            _get("/firstsight-probe", fresh_ip)
        assert not _fired(second, fresh_ip, "newcomer"), (
            "the address has been seen now, so firstsight=yes must "
            f"stop matching; lines={second.decision_lines(ip=fresh_ip)}"
        )


def test_firstsight_no_is_the_other_half(config_override, fresh_ip,
                                         log_slice):
    """firstsight=no is droppedcookie's half: matches from the second."""
    with config_override(r"BotShieldEnabled\s+On", RETURNING,
                         render=False, count=1):
        with log_slice as first:
            _get("/firstsight-probe", fresh_ip)
        assert not _fired(first, fresh_ip, "returning"), (
            "a first-sight address must not match firstsight=no; "
            f"lines={first.decision_lines(ip=fresh_ip)}"
        )

        with log_slice as second:
            _get("/firstsight-probe", fresh_ip)
        assert _fired(second, fresh_ip, "returning"), (
            "the address is known now, so firstsight=no should match; "
            f"lines={second.decision_lines(ip=fresh_ip)}"
        )


def test_firstsight_is_scoped_to_the_rule_path(config_override, fresh_ip,
                                               log_slice):
    """The point of the predicate: elsewhere the signal does nothing.

    The global heuristic cannot express this at any weight -- it applies
    to every path in the scope or to none.
    """
    with config_override(r"BotShieldEnabled\s+On", NEWCOMER,
                         render=False, count=1):
        with log_slice as slc:
            _get("/", fresh_ip)
        assert not _fired(slc, fresh_ip, "newcomer"), (
            "a first-sight address on an unrelated path must not be "
            f"caught by this rule; lines={slc.decision_lines(ip=fresh_ip)}"
        )


def test_a_refusing_rule_does_not_register_the_address(config_override,
                                                       fresh_ip, log_slice):
    """A refused request leaves the client still first-sight.

    Pinning the invariant rather than the accident. The filter answers
    "was this address given a chance to hold a cookie", and a refusal
    never reached the mint -- so the next request is still a newcomer,
    and droppedcookie does not fire on a client that was never offered
    a cookie to drop.
    """
    refusing = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule refuser>\n"
        "        BotShieldPath        /firstsight-refuse\n"
        "        BotShieldRespond     404\n"
        "        BotShieldLogAs       refuser\n"
        "    </BotShieldRule>\n"
        "    <BotShieldRule newcomer>\n"
        "        BotShieldPath        /firstsight-probe\n"
        "        BotShieldFirstSight  yes\n"
        "        BotShieldNoChallenge\n        BotShieldPenalty     1\n"
        "        BotShieldLogAs       newcomer\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", refusing,
                         render=False, count=1):
        assert _get("/firstsight-refuse", fresh_ip).status_code == 404

        with log_slice as slc:
            _get("/firstsight-probe", fresh_ip)
        assert _fired(slc, fresh_ip, "newcomer"), (
            "being refused should not have registered the address, so "
            "it is still first-sight; "
            f"lines={slc.decision_lines(ip=fresh_ip)}"
        )
