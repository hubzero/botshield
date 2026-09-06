"""POST <prefix>/admin/unflag — the way back off the flagged list.

Until this existed there was no way to un-flag an address short of
waiting out the window or deleting the state file, which also throws
away every counter the dashboard draws from. An operator who flagged
the wrong /24 had the choice of waiting or losing their history.

The tests that matter most here are the ones about who may call it.
This is the module's only surface that changes state on request, so
"closed until a directive names someone" is not a default, it is the
feature; and the round trip has to prove the entry actually went away
rather than that the endpoint said it did.

On why these read the decision log instead of the status code: a
challenge interstitial is served with 403 and so is a flag block. The
first draft asserted `!= 403` for "the flag is gone", which fails on an
address that is unflagged but still challenged on its own merits --
exactly the state the test wants to see. The reason field separates
them; the status code cannot.
"""

from __future__ import annotations

from botshield_test import client, ips as _ips


BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
ACCEPT_LANG = "en-US,en;q=0.9"

UNFLAG = "/botshield/admin/unflag"

# The address the flag lands on is spoofed per-request via XFF; the
# address allowed to call the admin endpoint is the loopback the test
# client actually connects from. Keeping them separate is deliberate --
# it means no test can pass by accident because the caller and the
# target happened to be the same address.
ADMIN_OPEN = "    BotShieldAdminAccess 127.0.0.1 ::1\n"

# A rule that flags the address, and a flag trigger that turns that
# flag into a refusal. The refusal is what makes the flag observable
# from outside: without it a cleared flag and an uncleared one look
# identical over HTTP.
FLAGGING = (
    "BotShieldEnabled On\n"
    + ADMIN_OPEN
    + '    BotShieldRule probe path="/unflag-probe" respond=404 '
    "flagip=scanner_probe logas=unflag-probe\n"
    "    BotShieldFlagTrigger scanner_probe action=block status=403\n"
)


def _get(path, ip):
    return client.get(path, xff=ip, ua=BROWSER_UA,
                      accept_language=ACCEPT_LANG)


def _unflag(**fields):
    """POST as the operator: loopback caller, no XFF, header present."""
    return client.post(UNFLAG, data=fields,
                       headers={"X-BotShield-Unflag": "1"},
                       ua=BROWSER_UA)


def _blocked_by_flag(slc, ip):
    """Did a flag refuse this address, per the decision log?"""
    return any("flagblock" in (d.get("reason") or "")
               for d in slc.decision_lines(ip=ip))


def test_unflag_is_closed_until_a_directive_names_someone(fresh_ip):
    """No BotShieldAdminAccess in the dev vhost, so: 404.

    404 rather than 403 for the same reason the dashboard uses it -- a
    403 confirms the endpoint is there to someone scanning for it. That
    matters more here than on a page you can only read.
    """
    resp = _unflag(addr=fresh_ip)
    assert resp.status_code == 404, (
        f"a write surface must be closed by default; got "
        f"{resp.status_code}"
    )


def test_unflag_clears_the_flag_and_the_refusal_stops(config_override,
                                                      fresh_ip, log_slice):
    """The round trip, asserted on behaviour rather than on the reply.

    Flag the address, watch the flag start refusing an unrelated path,
    clear it, watch that stop. The endpoint's own "cleared 1" is
    checked too, but it is the weaker claim: it would still be printed
    by a function that reported a write it never made.
    """
    with config_override(r"BotShieldEnabled\s+On", FLAGGING, count=1):
        probe = _get("/unflag-probe", fresh_ip)
        assert probe.status_code == 404

        with log_slice as slc:
            _get("/", fresh_ip)
        assert _blocked_by_flag(slc, fresh_ip), (
            "the flag should be refusing this address before the clear"
        )

        cleared = _unflag(addr=fresh_ip)
        assert cleared.status_code == 200, (
            f"unflag should be permitted from loopback; got "
            f"{cleared.status_code} {cleared.text!r}"
        )
        assert "cleared 1" in cleared.text, (
            f"expected one slot cleared; got {cleared.text!r}"
        )

        with log_slice as after:
            _get("/", fresh_ip)
        assert not _blocked_by_flag(after, fresh_ip), (
            "still refused by the flag after unflag, so the clear did "
            "not reach the table"
        )


def test_unflag_reports_zero_for_an_address_that_was_never_flagged(
    config_override, fresh_ip,
):
    """Zero is an answer, not an error.

    The usual reason someone is here is that they believe an address is
    flagged. Being told plainly that it is not is the useful reply; a
    404 or a 400 would send them looking for a mistake in the request.
    """
    with config_override(r"BotShieldEnabled\s+On", FLAGGING, count=1):
        resp = _unflag(addr=fresh_ip)
        assert resp.status_code == 200
        assert "cleared 0" in resp.text, (
            f"expected a plain zero; got {resp.text!r}"
        )


def test_unflag_refuses_get(config_override, fresh_ip):
    """A link checker, a prefetch, or a history entry must not clear."""
    with config_override(r"BotShieldEnabled\s+On", FLAGGING, count=1):
        resp = client.get(f"{UNFLAG}?addr={fresh_ip}", ua=BROWSER_UA,
                          headers={"X-BotShield-Unflag": "1"})
        assert resp.status_code == 405, (
            f"GET must not be a way to clear flags; got "
            f"{resp.status_code}"
        )


def test_unflag_requires_the_header_a_form_cannot_send(config_override,
                                                       fresh_ip):
    """The ACL passes an operator's browser, so the header is the gate.

    An allowed address is an allowed browser, and a browser visits
    pages. A cross-origin form POST cannot set a request header, so
    requiring one means the request was constructed on purpose.
    """
    with config_override(r"BotShieldEnabled\s+On", FLAGGING, count=1):
        resp = client.post(UNFLAG, data={"addr": fresh_ip}, ua=BROWSER_UA)
        assert resp.status_code == 400, (
            f"a bare form POST must not be accepted; got "
            f"{resp.status_code}"
        )


def test_unflag_rejects_an_address_it_cannot_parse(config_override):
    """A typo has to fail loudly, not clear nothing and report zero."""
    with config_override(r"BotShieldEnabled\s+On", FLAGGING, count=1):
        resp = _unflag(addr="not-an-address")
        assert resp.status_code == 400, (
            f"expected a refusal; got {resp.status_code} {resp.text!r}"
        )
        assert "bad address" in resp.text, (
            f"the reason has to survive to the caller, not be replaced "
            f"by Apache's error document; got {resp.text!r}"
        )


def test_unflag_names_an_unknown_flag_from_the_live_table(config_override,
                                                          fresh_ip):
    """The error lists the flags that exist, generated from the table.

    The hand-written version of this list had already gone stale --
    `blocked` was missing from it -- and this endpoint is where an
    operator types a flag name by hand.
    """
    with config_override(r"BotShieldEnabled\s+On", FLAGGING, count=1):
        resp = _unflag(addr=fresh_ip, flags="no_such_flag")
        assert resp.status_code == 400
        assert "blocked" in resp.text, (
            f"the known-flag list should come from the table and so "
            f"include 'blocked'; got {resp.text!r}"
        )


def test_unflag_can_clear_one_flag_and_leave_another(config_override,
                                                     fresh_ip, log_slice):
    """flags= is a selector, and the entry survives with the rest.

    Clearing every flag on an address is the blunt case. An operator
    who wants to lift one wrong signal without discarding the rest of
    what the address earned needs the entry to stay.
    """
    two = (
        "BotShieldEnabled On\n"
        + ADMIN_OPEN
        + '    BotShieldRule p1 path="/unflag-two" respond=404 '
        "flagip=scanner_probe,honeypot_hit logas=unflag-two\n"
        "    BotShieldFlagTrigger honeypot_hit action=block status=403\n"
    )
    with config_override(r"BotShieldEnabled\s+On", two, count=1):
        assert _get("/unflag-two", fresh_ip).status_code == 404

        # Drop the flag that is not doing the blocking.
        resp = _unflag(addr=fresh_ip, flags="scanner_probe")
        assert resp.status_code == 200
        assert "cleared 1" in resp.text, resp.text

        with log_slice as slc:
            _get("/", fresh_ip)
        assert _blocked_by_flag(slc, fresh_ip), (
            "honeypot_hit was not asked for and must still be refusing"
        )


def test_unflag_accepts_a_cidr_and_clears_every_member(config_override,
                                                       fresh_ip, log_slice):
    """The case the single-address clear could not do at all.

    The table is hashed on the whole address, so a prefix has no
    bucket to probe -- neighbouring addresses land nowhere near each
    other. Clearing a range means walking the table, which is why it
    is a separate function rather than an argument to the other one.
    """
    head = fresh_ip.rsplit(".", 1)[0]
    a, b = f"{head}.11", f"{head}.12"
    # Outside the /24 being cleared, so it proves the walk stops where
    # the prefix does rather than emptying the table.
    outside = _ips.fresh_ip()
    while outside.rsplit(".", 1)[0] == head:
        outside = _ips.fresh_ip()

    with config_override(r"BotShieldEnabled\s+On", FLAGGING, count=1):
        for ip in (a, b, outside):
            assert _get("/unflag-probe", ip).status_code == 404

        resp = _unflag(addr=f"{head}.0/24")
        assert resp.status_code == 200
        # At least mine. Not exactly mine: fresh_ip hands out addresses
        # that share a /24 with other tests' fresh addresses, and a
        # neighbour someone else flagged is cleared too -- correctly,
        # and the count says so.
        cleared = int(resp.text.split()[-1])
        assert cleared >= 2, (
            f"both addresses in the /24 should go; got {resp.text!r}"
        )

        for ip in (a, b):
            with log_slice as slc:
                _get("/", ip)
            assert not _blocked_by_flag(slc, ip), (
                f"{ip} is still refused by the flag after the range clear"
            )

        with log_slice as slc:
            _get("/", outside)
        assert _blocked_by_flag(slc, outside), (
            f"{outside} is outside {head}.0/24 and should still be "
            f"refused; the walk cleared more than the prefix"
        )
