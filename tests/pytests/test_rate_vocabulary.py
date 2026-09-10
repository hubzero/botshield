"""delay= and rate= -- a rule's two ways of carrying a window.

    BotShieldDelay <seconds>        one request per window, EACH crawler
    BotShieldRate  <n> <seconds>    n requests per window, SHARED

The unit is always seconds and seconds take a fraction. The counter
keeps milliseconds, so `BotShieldDelay 0.5` is 500ms exactly -- the
thing robots.txt could say with `Crawl-delay: 0.5` and the module used
to read as "no delay at all".

The two words are the difference in who shares the window. That used
to be a separate countper= knob whose default, `total`, was the trap:
@bot with one request a second under `total` gave the entire crawler
population one request a second between them.
"""

from __future__ import annotations

import time

import pytest

from botshield_test import apache, client

# Two UAs the classifier gives distinct known slugs, and neither needs
# IP verification to land in @bot -- a spoofed Googlebot from a test
# address classifies FAKE_BOT and would not match @bot at all.
UA_A = "curl/8.0.1"
UA_B = "Go-http-client/2.0"


def _rule(body: str, name: str = "vocab") -> str:
    return (
        "BotShieldEnabled On\n"
        f"    <BotShieldRule {name}>\n"
        f"{body}\n"
        "    </BotShieldRule>"
    )


def _dump_line(name: str) -> str:
    body = apache.policy_dump()
    line = [ln for ln in body.splitlines() if ln.startswith(name)]
    assert line, f"rule {name} missing from dump; body={body[:400]}"
    return line[0]


# --- spellings -------------------------------------------------------


@pytest.mark.parametrize("spelling, shown", [
    ("1", "delay=1"),
    ("10", "delay=10"),
    ("0.5", "delay=0.5"),        # the one whole seconds could not say
    ("1.5", "delay=1.5"),
    ("0.001", "delay=0.001"),    # the smallest window
    ("2.500", "delay=2.5"),      # trailing zeros do not survive
    ("0", "delay=0"),            # no limit, kept for robots.txt fidelity
])
def test_delay_prints_as_written(config_override, spelling, shown):
    conf = _rule(
        "        BotShieldPath   /delay-dump\n"
        f"        BotShieldDelay  {spelling}",
        name="delay-dump",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        line = _dump_line("delay-dump")
    assert shown in line, line
    assert "countper" not in line and "budget=" not in line, line


@pytest.mark.parametrize("spelling, shown", [
    ("30 60", "rate=30/60"),      # container form: two words
    ("30/60", "rate=30/60"),      # flat form: one token
    ("30 / 60", "rate=30/60"),
    ("5 0.5", "rate=5/0.5"),
    ("1 1", "rate=1/1"),
])
def test_rate_prints_as_written(config_override, spelling, shown):
    conf = _rule(
        "        BotShieldPath   /rate-dump\n"
        f"        BotShieldRate   {spelling}",
        name="rate-dump",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        line = _dump_line("rate-dump")
    assert shown in line, line


@pytest.mark.parametrize("bad", [
    "10sec",      # no unit words -- the unit is always seconds
    "10min",      # ... and this one read as 10 would be off by sixty
    "-1",
    "lots",
    "0.0001",     # rounds to zero ms without being zero: no limit at all
    "90000",      # over a day
])
def test_bad_delays_are_refused(config_override, bad):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  f"        BotShieldDelay {bad}"),
            render=False, count=1,
        ):
            pass


@pytest.mark.parametrize("bad", [
    "30",         # a count and no window
    "0/60",
    "-5/60",
    "1000001/60",
    "30/0",       # a zero window is not a rate; delay=0 is that spelling
    "30/min",
    "30/60sec",
    "lots/60",
])
def test_bad_rates_are_refused(config_override, bad):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  f"        BotShieldRate {bad}"),
            render=False, count=1,
        ):
            pass


@pytest.mark.parametrize("line", [
    "BotShieldBudget   5",
    "BotShieldPer      sec",
    "BotShieldCountPer slug",
])
def test_the_old_words_are_gone(config_override, line):
    """Retired, not aliased. A config still carrying them must fail to
    load rather than quietly having no limit."""
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  f"        {line}"),
            render=False, count=1,
        ):
            pass


# --- who shares the window -------------------------------------------


def test_delay_gives_each_crawler_its_own_window(config_override, fresh_ip):
    """The whole point of the word.

    Under a shared window these three requests spend from one bucket
    and crawler B is refused. Under delay each crawler has its own, so
    only a repeat from the *same* crawler is.
    """
    conf = _rule(
        "        BotShieldPath      /delay-probe\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldDelay     1",
        name="per-crawler",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        first_a = client.get("/delay-probe", xff=fresh_ip, ua=UA_A)
        first_b = client.get("/delay-probe", xff=fresh_ip, ua=UA_B)
        again_a = client.get("/delay-probe", xff=fresh_ip, ua=UA_A)

    assert first_a.status_code != 429, (
        f"first request from crawler A was refused; got {first_a.status_code}"
    )
    assert first_b.status_code != 429, (
        f"crawler B was refused on its first request, so it is sharing "
        f"A's window -- that is rate= behaviour; got {first_b.status_code}"
    )
    assert again_a.status_code == 429, (
        f"crawler A repeated inside its own window and was admitted; got "
        f"{again_a.status_code}"
    )


def test_rate_makes_them_share(config_override, fresh_ip):
    """The contrast, so the test above is not passing by accident."""
    conf = _rule(
        "        BotShieldPath      /rate-probe\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldRate      1 1",
        name="shared",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        client.get("/rate-probe", xff=fresh_ip, ua=UA_A)
        second = client.get("/rate-probe", xff=fresh_ip, ua=UA_B)

    assert second.status_code == 429, (
        f"a different crawler was admitted under rate=, so the window is "
        f"not shared; got {second.status_code}"
    )


# --- the fraction is real --------------------------------------------


def test_a_half_second_window_is_half_a_second(config_override, fresh_ip):
    """Not a display nicety. Refused inside the window, admitted once
    it has elapsed -- and the window is anchored to the first request,
    not to a wall-clock tick, so no alignment is needed."""
    conf = _rule(
        "        BotShieldPath      /half-probe\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldDelay     0.5",
        name="half",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        first = client.get("/half-probe", xff=fresh_ip, ua=UA_A)
        inside = client.get("/half-probe", xff=fresh_ip, ua=UA_A)
        time.sleep(0.7)
        after = client.get("/half-probe", xff=fresh_ip, ua=UA_A)

    assert first.status_code != 429, first.status_code
    assert inside.status_code == 429, (
        f"a repeat inside a 500ms window was admitted; got {inside.status_code}"
    )
    assert after.status_code != 429, (
        f"700ms later the window should have rolled; got {after.status_code}. "
        f"If this reads as a whole second, the fraction was truncated."
    )


def test_retry_after_rounds_up_never_zero(config_override, fresh_ip):
    """A sub-second remainder must not become Retry-After: 0, which
    invites an immediate retry that cannot succeed."""
    conf = _rule(
        "        BotShieldPath      /retry-probe\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldDelay     0.5",
        name="retry",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        client.get("/retry-probe", xff=fresh_ip, ua=UA_A)
        refused = client.get("/retry-probe", xff=fresh_ip, ua=UA_A)
    assert refused.status_code == 429, refused.status_code
    ra = refused.headers.get("Retry-After")
    assert ra is not None and int(ra) >= 1, f"Retry-After={ra!r}"


def test_rate_each_gives_each_crawler_the_budget(config_override, fresh_ip):
    """`rate=2/1 each` is two a second PER crawler. Under the default
    (shared) the two crawlers would spend from one window and B's first
    request would be refused; under each, B has its own two, and only
    A's third is refused. The dump prints the word back."""
    conf = _rule(
        "        BotShieldPath      /each-probe\n"
        "        BotShieldUserAgent @bot\n"
        "        BotShieldRate      2 60 each",
        name="per-each",
    )
    with config_override(r"BotShieldEnabled\s+On", conf,
                         render=False, count=1):
        a1 = client.get("/each-probe", xff=fresh_ip, ua=UA_A)
        a2 = client.get("/each-probe", xff=fresh_ip, ua=UA_A)
        b1 = client.get("/each-probe", xff=fresh_ip, ua=UA_B)
        a3 = client.get("/each-probe", xff=fresh_ip, ua=UA_A)
        body = apache.policy_dump()
    assert a1.status_code != 429 and a2.status_code != 429, (a1.status_code, a2.status_code)
    assert b1.status_code != 429, (
        f"crawler B was refused on its first request, so it is sharing "
        f"A's window -- 'each' was not honoured; got {b1.status_code}"
    )
    assert a3.status_code == 429, (
        f"crawler A's third request inside its own window was admitted; "
        f"got {a3.status_code}"
    )
    line = [ln for ln in body.splitlines() if ln.startswith("per-each")]
    assert line and "rate=2/60 each" in line[0], line


@pytest.mark.parametrize("bad", ["2/60 every", "2/60 each shared"])
def test_rate_refuses_other_sharing_words(config_override, bad):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            _rule("        BotShieldPath /x\n"
                  f"        BotShieldRate {bad}"),
            render=False, count=1,
        ):
            pass
