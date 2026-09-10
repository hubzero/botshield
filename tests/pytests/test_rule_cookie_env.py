"""T2 — cookie= and env= as BotShieldRule conditions.

The two open-set conditions. Every other condition in the rule language
is an enumeration whose complement has a name (solved=no, crawler=no,
cookies=any), so the language has never needed a negation operator. An
arbitrary cookie or variable is an open set: "not present" has no other
spelling.

The negation rides in the value, `!NAME`, because a block line's key is
its directive name and cannot take a prefix. The cookie family wrote it
`!cookie=NAME`, prefixing the key, which has no block-form equivalent.

Operators, all present-implying except the first negation:

    BotShieldCookie   NAME        present
    BotShieldCookie  !NAME        absent
    BotShieldCookie   NAME=VAL    equals
    BotShieldCookie   NAME!VAL    present, not equal
    BotShieldCookie   NAME~SUB    present, contains

env is narrower on purpose -- present, absent, equals, no contains --
because rich matching belongs in whatever set the variable. That is
also the answer to "why no regex": SetEnvIfExpr has a regex engine, and
this condition composes with it.

The point of doing this in the rule rather than leaving the cookie and
env families alone is that a rule can AND them with everything else. A
CookieTrigger could never say "this cookie AND this path AND not yet
solved".
"""

from __future__ import annotations

import pytest

from botshield_test import client


PROBE = "/rule-cookie-env-probe"


def _conf(condition: str) -> str:
    return (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule ce-probe>\n"
        f"        BotShieldPath      {PROBE}\n"
        f"        {condition}\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )


def _hit(config_override, fresh_ip, condition, cookies=None):
    """451 means the rule matched; anything else means it did not."""
    with config_override(r"BotShieldEnabled\s+On", _conf(condition), count=1):
        return client.get(PROBE, xff=fresh_ip, cookies=cookies).status_code


# --- cookie= --------------------------------------------------------


def test_cookie_present(config_override, fresh_ip):
    assert _hit(config_override, fresh_ip, "BotShieldCookie PHPSESSID",
                {"PHPSESSID": "abc"}) == 451


def test_cookie_present_does_not_match_when_absent(config_override, fresh_ip):
    assert _hit(config_override, fresh_ip, "BotShieldCookie PHPSESSID",
                {"other": "abc"}) != 451


def test_cookie_absent_matches_when_missing(config_override, fresh_ip):
    """The case with no other spelling, and the reason `!` exists."""
    assert _hit(config_override, fresh_ip, "BotShieldCookie !PHPSESSID",
                {"other": "abc"}) == 451


def test_cookie_absent_does_not_match_when_present(config_override, fresh_ip):
    assert _hit(config_override, fresh_ip, "BotShieldCookie !PHPSESSID",
                {"PHPSESSID": "abc"}) != 451


def test_cookie_equals(config_override, fresh_ip):
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier=guest",
                {"tier": "guest"}) == 451
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier=guest",
                {"tier": "member"}) != 451


def test_cookie_not_equal_requires_presence(config_override, fresh_ip):
    """`NAME!VAL` is present-but-different, not absent-or-different.

    The distinction between this and `!NAME` is the one worth keeping
    sharp: a client with no cookie at all has not sent a different
    value, it has sent nothing.
    """
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier!guest",
                {"tier": "member"}) == 451
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier!guest",
                {"tier": "guest"}) != 451
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier!guest",
                {"other": "x"}) != 451


def test_cookie_contains(config_override, fresh_ip):
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier~ues",
                {"tier": "guest"}) == 451
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier~ues",
                {"tier": "member"}) != 451


def test_cookie_value_may_contain_other_operators(config_override, fresh_ip):
    """The first operator after the name wins; the rest is the value.

    `tier=a~b` is an equality test against the literal `a~b`, not a
    contains test. Worth pinning: an operator writing a base64 or
    URL-ish cookie value will hit this.
    """
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier=a~b",
                {"tier": "a~b"}) == 451
    assert _hit(config_override, fresh_ip, "BotShieldCookie tier=a~b",
                {"tier": "b"}) != 451


# --- env= -----------------------------------------------------------


ENV_CONF = (
    "BotShieldEnabled On\n"
    "    BotShieldChallengeAtLeast none\n"
    "    SetEnvIfExpr \"true\" BS_RULE_ENV=high\n"
    "    <BotShieldRule ce-env>\n"
    f"        BotShieldPath      {PROBE}\n"
    "        %s\n"
    "        BotShieldRespond   451\n"
    "    </BotShieldRule>"
)


def _env_hit(config_override, fresh_ip, condition, set_var=True):
    conf = ENV_CONF % condition
    if not set_var:
        conf = conf.replace(
            '    SetEnvIfExpr "true" BS_RULE_ENV=high\n', "")
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        return client.get(PROBE, xff=fresh_ip).status_code


def test_env_present(config_override, fresh_ip):
    assert _env_hit(config_override, fresh_ip,
                    "BotShieldEnv BS_RULE_ENV") == 451


def test_env_absent(config_override, fresh_ip):
    assert _env_hit(config_override, fresh_ip,
                    "BotShieldEnv !BS_RULE_ENV", set_var=False) == 451
    assert _env_hit(config_override, fresh_ip,
                    "BotShieldEnv !BS_RULE_ENV") != 451


def test_env_equals(config_override, fresh_ip):
    assert _env_hit(config_override, fresh_ip,
                    "BotShieldEnv BS_RULE_ENV=high") == 451
    assert _env_hit(config_override, fresh_ip,
                    "BotShieldEnv BS_RULE_ENV=low") != 451


# --- the two mistakes worth catching at config time -----------------


def test_negated_name_with_operator_is_refused(config_override, fresh_ip):
    """`!NAME=VAL` conflates absence with mismatch, and is refused.

    The cookie family refused the same combination for the same reason.
    An operator who wants "present but not this value" is pointed at
    `NAME!VAL` by name rather than left to discover it.
    """
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            _conf("BotShieldCookie !tier=guest"), count=1,
        ):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


def test_module_own_cookie_is_refused(config_override, fresh_ip):
    """The module's own cookie has states a presence test cannot say.

    Redirected to BotShieldBSCookie, which distinguishes verified from
    missing from invalid -- the distinction that matters and that
    `cookie=__Host-bs_session` would flatten.
    """
    with pytest.raises(Exception) as exc_info:
        with config_override(
            r"BotShieldEnabled\s+On",
            _conf("BotShieldCookie __Host-bs_session"), count=1,
        ):
            pass
    assert "returned non-zero exit status" in str(exc_info.value)


# --- the reason this is in the rule and not a family ----------------


def test_cookie_ands_with_the_rest_of_the_rule(config_override, fresh_ip):
    """A CookieTrigger could never say this.

    The condition composes with path= and solved= in one rule, which is
    the whole argument for folding the family in rather than leaving it
    beside.
    """
    conf = (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        "    <BotShieldRule ce-and>\n"
        f"        BotShieldPath      {PROBE}\n"
        "        BotShieldCookie    tier=guest\n"
        "        BotShieldSolved    no\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        both = client.get(PROBE, xff=fresh_ip,
                          cookies={"tier": "guest"}).status_code
        wrong_cookie = client.get(PROBE, xff=fresh_ip,
                                  cookies={"tier": "member"}).status_code
        wrong_path = client.get("/", xff=fresh_ip,
                                cookies={"tier": "guest"}).status_code
    assert both == 451, "all three conditions held; the rule must fire"
    assert wrong_cookie != 451, "cookie value differed; must not fire"
    assert wrong_path != 451, "path differed; must not fire"


# --- ported from the cookie and env families -------------------------
#
# These were the only coverage of properties that outlive those
# families: the bulk cookie predicates, the session-name directive that
# feeds one of them, the module's own cookie states, and mod_rewrite as
# an env producer.


def _rule(body):
    return (
        "BotShieldEnabled On\n"
        "    BotShieldChallengeAtLeast none\n"
        + body
    )


def test_cookies_none_and_any(config_override, fresh_ip):
    """cookies=none is the bulk predicate, distinct from !NAME.

    !NAME asks about one cookie; cookies=none asks whether the request
    carried any at all. Its complement is nameable (cookies=any), which
    is why this one takes no '!'.
    """
    conf = _rule(
        "    <BotShieldRule ce-bulk>\n"
        "        BotShieldPath      " + PROBE + "\n"
        "        BotShieldCookies   none\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        assert client.get(PROBE, xff=fresh_ip).status_code == 451
        assert client.get(PROBE, xff=fresh_ip,
                          cookies={"foo": "bar"}).status_code != 451


def test_cookies_session_and_the_name_directive(config_override, fresh_ip):
    """cookies=session matches the curated list, and
    BotShieldSessionCookieName extends it.

    That directive had exactly one test anywhere, in the cookie family.
    It outlives the family, so its coverage has to.
    """
    conf = _rule(
        "    BotShieldSessionCookieName my_custom_session\n"
        "    <BotShieldRule ce-sess>\n"
        "        BotShieldPath      " + PROBE + "\n"
        "        BotShieldCookies   session\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        curated = client.get(PROBE, xff=fresh_ip,
                             cookies={"PHPSESSID": "x"}).status_code
        added = client.get(PROBE, xff=fresh_ip,
                           cookies={"my_custom_session": "x"}).status_code
        unrelated = client.get(PROBE, xff=fresh_ip,
                               cookies={"my_token": "x"}).status_code
    assert curated == 451, "PHPSESSID is on the curated list"
    assert added == 451, "BotShieldSessionCookieName must extend the list"
    assert unrelated != 451, "an unlisted name is not a session cookie"


def test_bscookie_states(config_override, fresh_ip):
    """The module's own cookie has three states, not a presence bit.

    This is why cookie=__Host-bs_session is refused: missing and
    invalid are different facts about a client, and the difference
    decides whether it is challenged or refused.
    """
    def probe(state, cookies):
        conf = _rule(
            "    <BotShieldRule ce-bs>\n"
            "        BotShieldPath      " + PROBE + "\n"
            "        BotShieldBSCookie  " + state + "\n"
            "        BotShieldRespond   451\n"
            "    </BotShieldRule>"
        )
        with config_override(r"BotShieldEnabled\s+On", conf, count=1):
            return client.get(PROBE, xff=fresh_ip,
                              cookies=cookies).status_code

    assert probe("missing", None) == 451
    assert probe("invalid",
                 {"__Host-bs_session": "obviously-bogus"}) == 451
    assert probe("missing",
                 {"__Host-bs_session": "obviously-bogus"}) != 451


def test_env_from_a_rewrite_producer(config_override, fresh_ip):
    """RewriteRule [E=VAR:VAL] sets the variable at fixups; the rule
    reads it.

    This is the composition the module leans on instead of owning a
    regex engine, and it matters more as a rule condition than it did
    as a family: the variable can be ANDed with the path and the UA in
    one place now.
    """
    conf = _rule(
        "    RewriteEngine On\n"
        "    RewriteRule ^/rw-probe /index.html [E=BS_FROM_RW:1,L]\n"
        "    <BotShieldRule ce-rw>\n"
        "        BotShieldEnv       BS_FROM_RW\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        hit = client.get("/rw-probe", xff=fresh_ip).status_code
        miss = client.get("/index.html", xff=fresh_ip).status_code
    assert hit == 451, "RewriteRule [E=...] must light up the condition"
    assert miss != 451, "the variable is only set on the rewritten path"
