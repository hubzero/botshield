"""Built-in ACL for the observability endpoints.

The dashboard pages and /metrics reveal internal vhost names, traffic
volumes, challenge and solve rates and SHM capacities. They used to be
served to anyone who asked, with the shipped config recommending a
<Location> the operator had to remember to write. These tests hold the
new default: neither is served until its own directive names who may
read it. One directive per endpoint, so the directive name says which
endpoint it opens.

Denial is 404, not 403, so a scan learns nothing about whether the
surface exists. Every case here therefore distinguishes "closed" from
"open" by 404 vs 200, and the deny path is verified to leave a decision
log line so a probe is not invisible.
"""

from __future__ import annotations

import pytest

from botshield_test import apache, client
from botshield_test.logs import decision_log_slice


DASHBOARD_PAGES = [
    "/botshield/dashboard",
    "/botshield/dashboard/bots",
    "/botshield/dashboard/responses",
    "/botshield/dashboard/internals",
]

# Public by design: these reveal nothing a challenged visitor does not
# already see, so gating them with the dashboard would be a regression
# for operators who link the explainer from a challenge page.
PUBLIC_ENDPOINTS = [
    "/botshield/preview",
    "/botshield/preview/interactive",
    "/botshield/safeguard-info",
]


# The instance config grants localhost, the way a real deployment does.
# These tests replace that pair of lines wholesale, so a test asking for
# the closed state really gets a vhost with no directive at all.
BASELINE = (r"BotShieldDashboardAccess 127\.0\.0\.1 ::1\n"
            r"\s*BotShieldMetricsAccess 127\.0\.0\.1 ::1")


def _acl(*lines: str):
    """Replace the baseline grant with exactly `lines` (none = closed)."""
    return apache.config_override(
        BASELINE, "\n    ".join(lines), count=1,
    )


@pytest.mark.parametrize("path", DASHBOARD_PAGES + ["/botshield/metrics"])
def test_closed_by_default(path):
    """With no directive, every observability endpoint is 404. This is
    the whole point of the change: the safe state must not depend on
    the operator having read a comment."""
    with _acl():
        assert client.get(path).status_code == 404, (
            f"{path} served with no access directive at all"
        )


@pytest.mark.parametrize("path", PUBLIC_ENDPOINTS)
def test_public_endpoints_unaffected(path):
    """The ACL must not catch the preview or explainer pages.

    Asserted as "not 404" rather than "200": the preview pages render
    real interstitials and an interstitial is served with 403, which is
    a served page. 404 is the ACL's refusal and the only status that
    would mean these got gated."""
    resp = client.get(path)
    assert resp.status_code != 404, (
        f"{path} is not an observability surface and must stay public"
    )
    assert "<!DOCTYPE HTML" in resp.text.upper(), (
        f"{path} returned {resp.status_code} but no page"
    )


def test_all_opens_the_endpoint():
    """`all` is the explicit opt-in to the old world-readable
    behaviour, for operators who front the module with something else."""
    with _acl("BotShieldDashboardAccess all",
              "BotShieldMetricsAccess all"):
        assert client.get("/botshield/dashboard").status_code == 200
        assert client.get("/botshield/metrics").status_code == 200


def test_matching_address_opens_the_endpoint():
    with _acl("BotShieldDashboardAccess 127.0.0.1 ::1",
              "BotShieldMetricsAccess 127.0.0.1 ::1"):
        assert client.get("/botshield/dashboard").status_code == 200
        assert client.get("/botshield/metrics").status_code == 200


def test_non_matching_cidr_denies():
    """A grant to somebody else is not a grant to us. Guards against an
    empty or always-true match, which would look identical to a correct
    implementation in every other test here."""
    with _acl("BotShieldDashboardAccess 10.99.0.0/16",
              "BotShieldMetricsAccess 10.99.0.0/16"):
        assert client.get("/botshield/dashboard").status_code == 404
        assert client.get("/botshield/metrics").status_code == 404


def test_endpoints_are_independent():
    """The reason there are two directives: opening one must not open
    the other. A Prometheus scraper should not get the dashboard as a
    side effect of being allowed to scrape."""
    with _acl("BotShieldMetricsAccess 127.0.0.1 ::1"):
        assert client.get("/botshield/metrics").status_code == 200
        assert client.get("/botshield/dashboard").status_code == 404

    with _acl("BotShieldDashboardAccess 127.0.0.1 ::1"):
        assert client.get("/botshield/dashboard").status_code == 200
        assert client.get("/botshield/metrics").status_code == 404


def test_grant_covers_dashboard_subpages():
    """One dashboard grant covers the whole family. The router matches
    the /dashboard/ prefix rather than a list of pages, so a page added
    later is gated by config that already exists."""
    with _acl("BotShieldDashboardAccess 127.0.0.1 ::1"):
        for path in DASHBOARD_PAGES:
            assert client.get(path).status_code == 200, path


def test_none_closes_an_open_endpoint():
    """`none` is how a vhost refuses a grant. Written after `all` in the
    same scope it must win, or the keyword is useless for its actual
    purpose of narrowing an inherited grant."""
    with _acl("BotShieldDashboardAccess all",
              "BotShieldDashboardAccess none",
              "BotShieldMetricsAccess all",
              "BotShieldMetricsAccess none"):
        assert client.get("/botshield/dashboard").status_code == 404
        assert client.get("/botshield/metrics").status_code == 404


def test_directives_accumulate():
    """Two lines are a union, so an operator can keep one network per
    line with its own comment."""
    with _acl("BotShieldDashboardAccess 10.99.0.0/16",
              "BotShieldDashboardAccess 127.0.0.1 ::1"):
        assert client.get("/botshield/dashboard").status_code == 200


def test_denial_is_recorded():
    """A refused probe must leave a trace. The response is a 404 and the
    access-log line is suppressed like every other hit on these
    surfaces, so the decision log is the only record there is.

    Read through decision_log_slice rather than log_slice: these lines
    go straight to the decision-log fd and never reach the error log."""
    with _acl():
        with decision_log_slice() as slc:
            client.get("/botshield/dashboard")
            client.get("/botshield/metrics")
            lines = slc.grep("observe-denied")

    assert any("observe-denied:dashboard" in ln for ln in lines), lines
    assert any("observe-denied:metrics" in ln for ln in lines), lines
    # Still outcome=observe, so a grep for traffic to these surfaces
    # finds refused probes alongside served hits.
    assert all("outcome=observe" in ln for ln in lines), lines


BAD_DIRECTIVES = [
    ("BotShieldDashboardAccess", "no arguments"),
    ("BotShieldMetricsAccess", "no arguments, metrics"),
    ("BotShieldDashboardAccess all none", "contradictory keywords"),
    ("BotShieldDashboardAccess all 10.0.0.1", "keyword with address"),
    ("BotShieldDashboardAccess none 10.0.0.1", "none with address"),
    ("BotShieldDashboardAccess notanip", "unparseable address"),
    ("BotShieldDashboardAccess 10.0.0.0/99", "impossible prefix length"),
    ("BotShieldMetricsAccess notanip", "unparseable address, metrics"),
]


@pytest.mark.parametrize("snippet,what", BAD_DIRECTIVES,
                         ids=[w.replace(" ", "_").replace(",", "")
                              for _, w in BAD_DIRECTIVES])
def test_bad_directive_rejected(snippet, what):
    """Config-time rejection, naming the directive. An ACL that parses
    to something other than what the operator wrote is the failure that
    matters: silently dropping an unparseable entry from an allow list
    fails open on the surface it was meant to protect."""
    rc, err = apache.configtest(snippet)
    assert rc != 0, f"configtest accepted {what}: {snippet!r}"
    assert snippet.split()[0] in err, (
        f"error for {snippet!r} does not name the directive. "
        f"stderr:\n{err[-400:]}"
    )
