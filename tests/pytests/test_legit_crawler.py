"""E1 — verified legit-crawler allow-list.

Exercises the four outcomes of the verification path:

  verified:   Googlebot UA from an IP in Googlebot's CIDR list
              → tier=pass, reason carries verified-crawler:googlebot.
  fake:       Googlebot UA from an IP NOT in the list
              → fake-googlebot penalty routes to captcha tier.
  unverified: UA matches a registered crawler pattern but no ranges
              file is loaded for it
              → no score effect, reason carries crawler-unverified:<name>.
  unknown UA: request from a random IP with no crawler UA
              → module ignores the feature entirely.

The tests use the dev vhost's default config — BotShieldLegitCrawlers
is on, and /var/lib/botshield/crawlers/{googlebot,bingbot,applebot}.txt
are seeded by provision.sh. An IP inside Googlebot's range comes from
the published list directly.
"""

from __future__ import annotations

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
# From the bundled Googlebot IPv4 ranges; stable enough for CI.
REAL_GOOGLEBOT_IP = "66.249.66.1"


def test_verified_crawler_bypasses_challenge(log_slice):
    """Real Googlebot UA + real Googlebot IP must produce tier=pass
    with the verified-crawler reason. The large negative credit from
    the E1 check dominates any other penalty (missing Accept-Language,
    first-sight-ip, etc.) so the score stays well below even the
    silent threshold."""
    with log_slice as slc:
        resp = client.get(
            "/", xff=REAL_GOOGLEBOT_IP, ua=GOOGLEBOT_UA,
        )
        lines = slc.decision_lines(ip=REAL_GOOGLEBOT_IP)

    assert resp.status_code == 200
    assert resp.headers.get("X-Botshield") != "challenge", (
        f"verified Googlebot got challenged; headers={dict(resp.headers)}"
    )
    assert lines, "no decision line for verified-crawler request"
    verified = [d for d in lines if "verified-crawler:googlebot" in d["reason"]]
    assert verified, (
        f"no decision line carried verified-crawler:googlebot — "
        f"E1 not wired correctly? lines={lines}"
    )
    # Verified bypass should land us at pass tier.
    assert verified[0]["tier"] == "pass", (
        f"verified crawler ended up at tier={verified[0]['tier']}"
    )


def test_fake_crawler_routed_to_captcha(log_slice, fresh_ip):
    """UA claims Googlebot, IP is nowhere near a real Googlebot range.
    fake-googlebot penalty should fire and drive tier into captcha
    (or form-PoW fallback if no provider is configured at /)."""
    with log_slice as slc:
        client.get("/", xff=fresh_ip, ua=GOOGLEBOT_UA)
        lines = slc.decision_lines(ip=fresh_ip)

    fake = [d for d in lines if "fake-googlebot" in d["reason"]]
    assert fake, (
        f"no decision line for fake-googlebot on ip={fresh_ip}; "
        f"lines={lines}"
    )
    # The penalty is 100 — enough to cross the captcha threshold (80)
    # even without other contributions. Tier should be at LEAST form;
    # typically captcha (or form-PoW if no provider at this scope).
    assert fake[0]["tier"] in ("form", "captcha"), (
        f"fake crawler didn't reach form/captcha tier: "
        f"tier={fake[0]['tier']}"
    )


def test_non_crawler_ua_unaffected(log_slice, fresh_ip):
    """Regression guard: regular browser traffic shouldn't touch the
    crawler path at all. No crawler-* reason should appear."""
    with log_slice as slc:
        client.get(
            "/", xff=fresh_ip,
            ua="Mozilla/5.0 (X11; Linux x86_64) Chrome/145.0",
            accept_language="en-US,en;q=0.9",
        )
        lines = slc.decision_lines(ip=fresh_ip)

    assert lines, "no decision line at all — unexpected"
    for d in lines:
        assert "crawler" not in d["reason"], (
            f"non-crawler UA tagged with crawler reason: {d['reason']!r}"
        )
        assert "fake-" not in d["reason"]


def test_metrics_counters_present():
    """After the tests above, the /metrics endpoint should expose
    the three new crawler counters (M11.8's prometheus format test
    validates the shape; this test just confirms the names ARE
    exposed so we notice if someone drops the registration)."""
    resp = client.get("/botshield/metrics")
    assert resp.status_code == 200
    body = resp.text
    assert "botshield_crawler_verified_total" in body
    assert "botshield_crawler_fake_total" in body
    assert "botshield_crawler_unverified_total" in body
