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
   assert the flag is present on both __Host-bs_session and
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

    verified = [c for c in ctx.cookies() if c["name"] == "__Host-bs_session"]
    assert len(verified) == 1, f"expected one __Host-bs_session, got {verified}"
    c = verified[0]

    assert c["secure"] is True, f"__Host-bs_session not marked Secure: {c}"
    # "Lax" is the module's documented default; if it ever changes to
    # "Strict" this test should be updated, but silently widening to
    # "None" would be a security regression.
    assert c["sameSite"] in ("Lax", "Strict"), (
        f"__Host-bs_session SameSite is too permissive: {c['sameSite']!r}"
    )
    # Security review LOW #1 — HttpOnly=True is now correct: the
    # M1 widget JS used to mint the cookie via document.cookie (which
    # required JS-readability), but was refactored to POST the PoW
    # solution to /botshield/embedded-verify so the server emits
    # Set-Cookie with HttpOnly. Closes XSS-driven cookie theft.
    assert c["httpOnly"] is True, (
        f"__Host-bs_session should be HttpOnly post-LOW#1: {c}"
    )
    # Session-cookie semantics: no Expires=, no Max-Age=. Browser
    # discards on session end. The server-side expires_at field
    # inside the GCM envelope is the hard cap that catches cookies
    # surviving a long-lived browser session.
    assert c["expires"] in (-1, None), (
        f"__Host-bs_session is a session cookie; Playwright reports "
        f"expires={c['expires']!r} (expected -1 / None). The "
        f"Set-Cookie should not carry Expires= or Max-Age="
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

    # Chromium-level Path enforcement. Playwright's
    # `context.cookies(url=...)` returns the cookies the browser
    # WOULD send with a request to `url` — the same filter Chromium
    # applies before it attaches the Cookie header. That's the real
    # regression gate: if the Path attribute widened to /, the
    # pending cookie would appear in cookies_at_root.
    #
    # (document.cookie wouldn't work here — the pending cookie is
    # HttpOnly, so JS never sees it regardless of Path. An assertion
    # built on document.cookie would pass even if the Path leaked.)
    cookies_for_root = ctx.cookies(urls="https://localhost/")
    cookies_for_verify = ctx.cookies(
        urls="https://localhost/botshield/captcha-verify/turnstile"
    )

    names_root = {c["name"] for c in cookies_for_root}
    names_verify = {c["name"] for c in cookies_for_verify}

    assert "_bs_captcha_pending" not in names_root, (
        f"pending cookie would be sent on a request to /: {names_root}. "
        f"Chromium's Path enforcement says the cookie's Path scope "
        f"widened beyond /botshield/captcha-verify."
    )
    assert "_bs_captcha_pending" in names_verify, (
        f"pending cookie missing from request to the verify endpoint: "
        f"{names_verify}. Path should match /botshield/captcha-verify."
    )
