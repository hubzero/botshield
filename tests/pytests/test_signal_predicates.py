"""ua=@scraper and acceptlanguage: the last two heuristics as conditions.

Both are parity with a signal that already existed globally, and both
reuse a spelling the vocabulary already had rather than inventing one.
@scraper joins @bot and @fake-bot; BotShieldAcceptLanguage "" mirrors
BotShieldUserAgent "" for the same reason -- absence is not a substring,
so it needs its own token.

The scraper token list is shared with the heuristic rather than copied,
so these tests are also the guard against the two drifting apart.
"""

from __future__ import annotations

from botshield_test import client


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
CURL_UA = "curl/8.4.0"
ACCEPT_LANG = "en-US,en;q=0.9"

SCRAPER = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule scraper-probe>\n"
    "        BotShieldPath        /signal-probe\n"
    "        BotShieldUserAgent   @scraper\n"
    "        BotShieldRespond     403\n"
    "        BotShieldLogAs       scraper-probe\n"
    "    </BotShieldRule>\n"
)

NO_AL = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule no-al>\n"
    "        BotShieldPath            /signal-probe\n"
    "        BotShieldAcceptLanguage  \"\"\n"
    "        BotShieldRespond         403\n"
    "        BotShieldLogAs           no-al\n"
    "    </BotShieldRule>\n"
)

HAS_AL = (
    "BotShieldEnabled On\n"
    "    <BotShieldRule has-al>\n"
    "        BotShieldPath            /signal-probe\n"
    "        BotShieldAcceptLanguage  *\n"
    "        BotShieldRespond         403\n"
    "        BotShieldLogAs           has-al\n"
    "    </BotShieldRule>\n"
)


def test_scraper_selector_matches_a_library_ua(config_override, fresh_ip):
    with config_override(r"BotShieldEnabled\s+On", SCRAPER,
                         render=False, count=1):
        hit = client.get("/signal-probe", xff=fresh_ip, ua=CURL_UA)
        assert hit.status_code == 403, (
            f"curl's UA carries a known library token; got {hit.status_code}"
        )


def test_scraper_selector_leaves_a_browser_alone(config_override, fresh_ip):
    """The control. Without it the test above passes on any 403 at all."""
    with config_override(r"BotShieldEnabled\s+On", SCRAPER,
                         render=False, count=1):
        miss = client.get("/signal-probe", xff=fresh_ip, ua=BROWSER_UA,
                          accept_language=ACCEPT_LANG)
        assert miss.status_code != 403, (
            f"a browser UA must not match @scraper; got {miss.status_code}"
        )


def test_acceptlanguage_empty_matches_a_missing_header(config_override,
                                                       fresh_ip):
    with config_override(r"BotShieldEnabled\s+On", NO_AL,
                         render=False, count=1):
        hit = client.get("/signal-probe", xff=fresh_ip, ua=BROWSER_UA)
        assert hit.status_code == 403, (
            f"no Accept-Language should match; got {hit.status_code}"
        )


def test_acceptlanguage_empty_ignores_a_present_header(config_override,
                                                       fresh_ip):
    with config_override(r"BotShieldEnabled\s+On", NO_AL,
                         render=False, count=1):
        miss = client.get("/signal-probe", xff=fresh_ip, ua=BROWSER_UA,
                          accept_language=ACCEPT_LANG)
        assert miss.status_code != 403, (
            f"a request carrying Accept-Language must not match "
            f'acceptlanguage=""; got {miss.status_code}'
        )


def test_acceptlanguage_star_is_the_inverse(config_override, fresh_ip):
    with config_override(r"BotShieldEnabled\s+On", HAS_AL,
                         render=False, count=1):
        hit = client.get("/signal-probe", xff=fresh_ip, ua=BROWSER_UA,
                         accept_language=ACCEPT_LANG)
        assert hit.status_code == 403, (
            f"acceptlanguage=* should match a present header; got "
            f"{hit.status_code}"
        )


def test_acceptlanguage_rejects_a_substring(config_override):
    """Narrow on purpose: this is a signal, not a header matcher.

    Accepting `en-US` here would be the beginning of a second matching
    language with its own escaping and case rules, which is a decision
    to take deliberately rather than by letting a value through.
    """
    import pytest
    with pytest.raises(Exception) as exc:
        with config_override(
            r"BotShieldEnabled\s+On",
            "BotShieldEnabled On\n"
            "    <BotShieldRule bad-al>\n"
            "        BotShieldPath            /signal-probe\n"
            "        BotShieldAcceptLanguage  en-US\n"
            "        BotShieldRespond         403\n"
            "    </BotShieldRule>\n",
            render=False, count=1,
        ):
            pass
    msg = str(exc.value)
    assert "non-zero exit status" in msg or "acceptlanguage" in msg, msg


def test_a_new_predicate_counts_as_a_condition_on_its_own(config_override,
                                                          fresh_ip):
    """A rule conditioned only on a signal is a legal rule.

    The tests above all pair the new predicates with path=, so none of
    them would notice that firstsight= and acceptlanguage= were missing
    from the needs at least one match key check -- a rule with either
    as its only condition was refused at config time. Converting the dev
    vhost's heuristics into rules is what found it: h-missingal has
    nothing but acceptlanguage.
    """
    only_al = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule al-only>\n"
        "        BotShieldAcceptLanguage  \"\"\n"
        "        BotShieldNoChallenge\n"
        "        BotShieldPenalty         3\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", only_al,
                         render=False, count=1):
        # Parsing is the assertion; a refused config raises on entry.
        assert client.get("/", xff=fresh_ip, ua=BROWSER_UA).status_code


def test_firstsight_alone_is_also_a_condition(config_override, fresh_ip):
    only_fs = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule fs-only>\n"
        "        BotShieldFirstSight  yes\n"
        "        BotShieldNoChallenge\n"
        "        BotShieldPenalty     3\n"
        "    </BotShieldRule>\n"
    )
    with config_override(r"BotShieldEnabled\s+On", only_fs,
                         render=False, count=1):
        assert client.get("/", xff=fresh_ip, ua=BROWSER_UA).status_code
