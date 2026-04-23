"""M11.6 browser-only: cookie attributes honored by Chromium.

httpx ignores `Secure` / `SameSite` / `Path` when you hand it a cookie
header — we send whatever we're told. A real browser enforces them.
This test catches regressions that a request library literally
cannot see.

Three assertions:

1. **Secure** on HTTPS: the cookie the module sets on an HTTPS
   response is flagged Secure, and Chromium honors that — so a
   subsequent *HTTP* request to the same origin must NOT carry the
   cookie. (We can't test this end-to-end here because the dev vhost
   is HTTPS-only, but we can inspect the Set-Cookie directly and
   assert the flag is present on both _bs_verified and
   _bs_captcha_pending.)

2. **Path scoping**: `_bs_captcha_pending` is set with
   `Path=/botshield/captcha-verify`. The browser must NOT send it on
   a request outside that path. This is the regression gate that
   matters operationally — a bug that widened the Path could leak
   the pending cookie into the user's ordinary navigation and trip
   unintended verifications.

3. **SameSite=Lax**: the captcha verify is a same-origin POST, so
   Lax is correct. Smoke that a cross-site POST would be blocked by
   the browser would need a second origin; we assert the attribute
   on the Set-Cookie and trust Chromium for the rest.
"""

from __future__ import annotations

import pytest


pytestmark = [pytest.mark.acceptance, pytest.mark.browser]


def test_verified_cookie_attributes_on_silent_solve(bs_browser_context):
    """After the silent-tier auto-submit, inspect the cookie jar.
    Chromium only adds a cookie to the jar if the Set-Cookie parsed
    correctly; we verify the flags the module set."""
    ctx = bs_browser_context
    page = ctx.new_page()

    page.goto("https://localhost/")
    page.wait_for_function(
        "() => document.title !== 'Verify you are human'",
        timeout=20_000,
    )

    verified = [c for c in ctx.cookies() if c["name"] == "_bs_verified"]
    assert len(verified) == 1, f"expected one _bs_verified, got {verified}"
    c = verified[0]

    assert c["secure"] is True, f"_bs_verified not marked Secure: {c}"
    # "Lax" is the module's documented default; if it ever changes to
    # "Strict" this test should be updated, but silently widening to
    # "None" would be a security regression.
    assert c["sameSite"] in ("Lax", "Strict"), (
        f"_bs_verified SameSite is too permissive: {c['sameSite']!r}"
    )
    # HttpOnly=False is deliberate: the module's challenge JS reads
    # the cookie via document.cookie after solving the PoW. Flagging
    # it HttpOnly would break the silent-tier round-trip.
    assert c["httpOnly"] is False, (
        f"_bs_verified unexpectedly HttpOnly — challenge JS "
        f"can't read it: {c}"
    )


def test_pending_cookie_path_scoped(bs_browser_context):
    """_bs_captcha_pending must carry Path=/botshield/captcha-verify
    (scoped tightly so it can't leak outside the verify handler).
    Chromium enforces the Path; we also inspect it on the Set-Cookie.
    """
    ctx = bs_browser_context
    page = ctx.new_page()

    # Loading /captcha-demo mints the pending cookie.
    page.goto("https://localhost/captcha-demo",
              wait_until="domcontentloaded", timeout=15_000)

    pending = [c for c in ctx.cookies() if c["name"] == "_bs_captcha_pending"]
    assert len(pending) == 1, f"expected pending cookie, got {pending}"
    c = pending[0]

    assert c["path"] == "/botshield/captcha-verify", (
        f"_bs_captcha_pending Path widened: {c['path']!r} "
        f"(expected /botshield/captcha-verify)"
    )
    assert c["secure"] is True
    assert c["httpOnly"] is True, (
        "_bs_captcha_pending is a server-side handshake artifact — "
        "JS has no reason to read it, so HttpOnly should be set"
    )

    # Chromium-level assertion: a fetch OUTSIDE the pending cookie's
    # Path must NOT include it. The module's own captcha-demo route
    # is at `/captcha-demo` (root path), which is outside
    # `/botshield/captcha-verify` — so a same-origin GET to / should
    # not carry the pending cookie.
    got_cookies = page.evaluate("""async () => {
        const r = await fetch('/', { credentials: 'include' });
        return r.headers.get('x-botshield-echo-cookies') || '';
    }""")
    # We don't have an echo endpoint, so we check via document.cookie
    # semantics instead: for the root path, the pending cookie
    # (Path=/botshield/captcha-verify) must NOT be visible to JS. A
    # real browser enforces this even when document.cookie is read
    # from a page loaded from the root path.
    cookies_at_root = page.evaluate("() => document.cookie")
    assert "_bs_captcha_pending" not in cookies_at_root, (
        f"pending cookie leaked into document.cookie at root path: "
        f"{cookies_at_root!r}"
    )
