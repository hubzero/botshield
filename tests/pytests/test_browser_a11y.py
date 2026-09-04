"""M11.6 follow-up: basic accessibility smoke for the interstitial.

The M11.6 plan mentioned "challenge page passes basic a11y smoke
(submit button reachable by keyboard, form has visible label,
etc.)" — shipped here after the M11 audit.

Uses axe-core (bundled in tests/pytests/assets/) — the same
a11y engine Lighthouse uses internally. Smoke-scale: we assert
zero `critical` and zero `serious` violations. `moderate` and
`minor` violations are logged but don't fail (enough manual WCAG
review has happened that we don't want to rubber-stamp pre-
existing non-critical findings; a single new critical issue is a
real regression signal).

One trick worth flagging: the silent-tier interstitial auto-submits
after a 250 ms setTimeout → location.reload(). If axe runs during
that window the page can reload out from under us. We install an
init script that neutralizes `location.reload` so the interstitial
DOM stays put long enough to scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from botshield_test import config


pytestmark = [pytest.mark.acceptance, pytest.mark.browser]

# Challenged while unsolved, served once solved -- the round trip these
# tests need. "/" no longer challenges a recognised browser UA (see the
# browser-gate comment in tests/setup/botshield-dev.conf), and /silent-demo
# re-challenges even a solved client, so neither can carry these.
CHALLENGE_PATH = "/browser-gate.html"


def _pin_interstitial(page):
    """Keep the interstitial on screen for the duration of the scan.

    The silent tier solves its proof-of-work and reloads on its own --
    ~400ms on this hardware. Every assertion here is about the
    challenge DOM, so without this the page under test navigates away
    mid-scan and the test asserts against the origin page instead.
    Aborting the verify POST stops the reload without touching the
    markup being scanned.
    """
    page.route("**/botshield/embedded-verify", lambda r: r.abort())


_AXE_PATH = Path(__file__).resolve().parent / "assets" / "axe.min.js"
assert _AXE_PATH.is_file(), f"axe-core missing at {_AXE_PATH}"


_HOLD_INTERSTITIAL_JS = """
// Neutralize the interstitial's auto-submit so axe can scan the
// rendered DOM without racing a location.reload(). The cookie is
// still set; we just don't refresh.
window.__bs_original_reload = window.location.reload;
Object.defineProperty(window.location, 'reload', {
    configurable: true,
    value: () => { /* suppressed for a11y scan */ },
});
"""


# Non-critical impact levels we log but don't fail on. Pre-existing
# issues at this level would make every new test red-box; we want
# the gate narrow so a genuine regression stands out.
_FAIL_IMPACTS = {"critical", "serious"}


def _run_axe(page):
    """Inject axe-core into the page, run it, return the parsed
    results dict. Caller asserts on the `violations` list."""
    page.add_script_tag(path=str(_AXE_PATH))
    return page.evaluate(
        # axe.run() resolves with an object containing violations /
        # passes / incomplete / inapplicable. We only act on
        # violations; the rest are forensics.
        "async () => await axe.run(document, "
        "{ resultTypes: ['violations'] })"
    )


def _format_violations(violations, limit=5):
    """Pretty-print the first `limit` violations for assertion
    messages. Each violation has `id`, `impact`, `description`, and
    `nodes` (the DOM elements flagged)."""
    out = []
    for v in violations[:limit]:
        nodes = v.get("nodes") or []
        target = nodes[0].get("target", ["?"])[0] if nodes else "?"
        out.append(
            f"  [{v.get('impact')}] {v.get('id')}: "
            f"{v.get('description')} ({len(nodes)} node(s), e.g. {target})"
        )
    return "\n".join(out)


def test_interstitial_no_critical_a11y_violations(bs_browser_context):
    """Navigate to the silent-tier interstitial, run axe-core, assert
    no critical / serious violations. The bs_browser_context fixture
    is tuned to land cookieless suspicious requests in silent tier."""
    ctx = bs_browser_context
    ctx.add_init_script(_HOLD_INTERSTITIAL_JS)
    page = ctx.new_page()

    _pin_interstitial(page)
    resp = page.goto(config.BASE_URL + CHALLENGE_PATH)
    assert resp.headers.get("x-botshield") == "challenge", (
        "fixture didn't land at the interstitial — a11y scan needs "
        "the challenge DOM, not the origin page"
    )
    assert "Verify you are human" in page.title()

    results = _run_axe(page)
    violations = results.get("violations", [])
    critical = [v for v in violations if v.get("impact") in _FAIL_IMPACTS]

    # Minor / moderate issues are logged but not failed — they're
    # forensic data in the CI report, not a gate.
    minor = [v for v in violations if v.get("impact") not in _FAIL_IMPACTS]
    if minor:
        print(
            f"\nnon-blocking a11y findings ({len(minor)}):\n"
            + _format_violations(minor)
        )

    assert not critical, (
        f"interstitial has {len(critical)} critical/serious a11y "
        f"violation(s):\n" + _format_violations(critical)
    )


def test_interstitial_submit_button_keyboard_reachable(
    bs_browser_context_form,
):
    """The form's verify button must be reachable via Tab alone.
    M11.6 called this out explicitly — a user on a screen reader or
    without a mouse must be able to trigger the challenge by
    keyboard. Exercised against form tier (click-to-verify variant);
    silent tier auto-submits so there's nothing for a keyboard user
    to do there."""
    ctx = bs_browser_context_form
    ctx.add_init_script(_HOLD_INTERSTITIAL_JS)
    page = ctx.new_page()

    _pin_interstitial(page)
    page.goto(config.BASE_URL + CHALLENGE_PATH)
    assert "Verify you are human" in page.title()

    # Walk forward with Tab, asserting we eventually focus the
    # interstitial's verify button (<button id="btn">) without
    # falling off the end of the tab order. Bounded to prevent a
    # broken tab-order from looping forever.
    hit = False
    for _ in range(30):
        page.keyboard.press("Tab")
        focused_id = page.evaluate(
            "() => document.activeElement && document.activeElement.id"
        )
        if focused_id == "btn":
            hit = True
            break

    assert hit, (
        "tab-walked 30 elements without landing on #btn; "
        "keyboard users can't complete the challenge"
    )


def test_interstitial_has_lang_attribute(bs_browser_context):
    """Screen readers need <html lang=...> to pronounce content
    correctly. WCAG 3.1.1 (Language of Page) is a Level A criterion
    — mandatory, not nice-to-have."""
    ctx = bs_browser_context
    ctx.add_init_script(_HOLD_INTERSTITIAL_JS)
    page = ctx.new_page()

    _pin_interstitial(page)
    page.goto(config.BASE_URL + CHALLENGE_PATH)
    assert "Verify you are human" in page.title()

    lang = page.evaluate("() => document.documentElement.lang || null")
    assert lang, "interstitial <html> element has no lang attribute"
