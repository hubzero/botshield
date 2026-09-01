"""BotShieldScoring On|Off — implicit scoring as an opt-in.

Off is the default, and that is the point of the directive rather than
an incidental choice. Every lockout this module has caused came from an
implicit weight or tier floor nobody had written down summing past a
threshold nobody had read: the #5168 challenge loop, the scanner_probe
tier_floor of incident #1, and the ten-hour Googlebot outage on
2026-09-01. An explicit rule states what it does; a score states it
only after you reconstruct the arithmetic.

What Off suppresses is the IMPLICIT path only:

  - built-in heuristics contributing score
  - flag triggers contributing score or tier_floor
  - the score-to-tier threshold evaluation

What it must NOT touch is an explicit tier= or status= on a rule. That
boundary is the whole risk in this directive: get it wrong in the
"off means no tiers at all" direction and the site silently stops
challenging anyone. The last two tests here exist to pin exactly that,
because nothing else in the suite would notice.
"""

from __future__ import annotations

import pytest

from botshield_test import client


SCRAPER_UA = "curl/8.7.1"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)


def test_scoring_off_does_not_challenge_on_its_own(
    config_override, fresh_ip,
):
    """A first-sight client with no cookie is the population the score
    system existed to challenge. With scoring off and no rule saying
    otherwise, it passes."""
    with config_override(
        r"BotShieldScoring\s+On",
        'BotShieldScoring Off',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip, ua=SCRAPER_UA)

    assert r.status_code != 403, (
        f"scoring off must not challenge on its own; got "
        f"{r.status_code}. This is the whole directive: no rule asked "
        f"for a challenge, so none should happen."
    )


def test_scoring_on_restores_the_implicit_challenge(
    config_override, fresh_ip,
):
    """The mirror image, so a pass above cannot be an accident of some
    unrelated breakage."""
    with config_override(
        r"BotShieldScoring\s+On",
        'BotShieldScoring On',
        count=1,
    ):
        r = client.get("/", xff=fresh_ip, ua=SCRAPER_UA)

    assert r.status_code == 403, (
        f"scoring on must restore the first-sight challenge; got "
        f"{r.status_code}"
    )


def test_explicit_tier_still_fires_with_scoring_off(
    config_override, log_slice, fresh_ip,
):
    """The boundary that matters most.

    An explicit tier= on a rule is not scoring, and turning scoring off
    must leave it working. If this regresses, a deployment that moved
    its policy into rules -- which is the direction the directive
    pushes -- would stop challenging entirely and nothing else in the
    suite would fail.
    """
    with config_override(
        r"BotShieldScoring\s+On",
        'BotShieldScoring Off\n'
        '    BotShieldRequestTrigger gate-test path="/" '
        'status=pass tier=non-interactive ttl=0 log=gate-test',
        count=1,
    ):
        with log_slice as slc:
            r = client.get("/", xff=fresh_ip, ua=BROWSER_UA)
            lines = slc.decision_lines(ip=fresh_ip)

    assert r.status_code == 403, (
        f"an explicit tier=non-interactive must still challenge with scoring "
        f"off; got {r.status_code}"
    )
    assert any("gate-test" in d["reason"] for d in lines), (
        f"the challenge must be attributable to the rule that asked "
        f"for it, not to a score; lines={lines}"
    )


def test_explicit_status_still_fires_with_scoring_off(
    config_override, fresh_ip,
):
    """Same boundary for status= — a block is not scoring either."""
    with config_override(
        r"BotShieldScoring\s+On",
        'BotShieldScoring Off\n'
        '    BotShieldRequestTrigger block-test path="/wp-admin" '
        'status=404 ttl=0 log=block-test',
        count=1,
    ):
        r = client.get("/wp-admin/index.php", xff=fresh_ip, ua=BROWSER_UA)

    assert r.status_code == 404, (
        f"an explicit status=404 must still fire with scoring off; got "
        f"{r.status_code}"
    )
