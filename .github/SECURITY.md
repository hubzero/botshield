# Security Policy

## Reporting a vulnerability

**Please do not open public issues for security bugs.** Use GitHub's
[private security advisory](https://github.com/hubzero/botshield/security/advisories/new)
flow — it gives us a private channel to triage, fix, and coordinate
disclosure before the bug becomes public knowledge. A GitHub account
is required (free); the form is the only supported reporting channel.

When you report, please include:

- A clear description of the bug and its impact.
- Reproduction steps or a proof-of-concept (a minimal Apache config
  + request shape is ideal).
- The mod_botshield version / commit you tested against.
- Any thoughts on a fix or workaround if you have them.

We aim to acknowledge new reports within **3 working days** and to
ship a fix on a timeline proportional to severity (typically 7-30
days for confirmed high-severity bugs; lower-severity items move
through normal release cadence).

## Scope

In scope:

- The `mod_botshield` C module and its directives.
- The bundled tools under `tools/` and the test harness under
  `tests/setup/`.
- The dev vhost at `tests/setup/botshield-dev.conf` only insofar as it
  exposes a real misconfiguration risk (e.g., a directive default
  that's unsafe).

Out of scope:

- Issues in third-party captcha providers (Cloudflare Turnstile,
  hCaptcha, reCAPTCHA, Friendly Captcha, GeeTest) — report those
  upstream.
- Issues in Apache HTTP Server, APR, libcurl, OpenSSL, or other
  dependencies — report those upstream.
- DoS attacks against the captcha-verify endpoint that exceed the
  configured rate limit + in-flight semaphore (those caps exist
  precisely to bound the attack surface; if you can show a path
  *around* them, that's in scope).
- Configurations that intentionally weaken the module
  (`BotShieldDebug On`, an unprotected `BotShieldStateFile` path,
  etc.).

## What counts as a vulnerability

The most interesting bug classes for this module:

- **Cookie tampering** that escapes the AES-GCM authenticator.
- **Replay attacks** against the cookie, embedded-bootstrap nonce
  table, or captcha pending cookie that bypass the intended freshness
  guarantees.
- **Score / flag laundering** — paths that let a flagged client
  reset their reputation outside the intended forgiveness model.
- **Worker starvation** or runaway memory usage on adversarial
  input (the LibFuzzer corpus under `tests/fuzz/` is the existing
  baseline; a crash there is a real bug).
- **HTTP-level confusion** — request smuggling, response splitting,
  log-injection escapes, header forwarding gaps in
  `X-BotShield-Feedback` / `X-BotShield-Claims`.
- **Directive defaults** that produce an unsafe configuration
  unbeknownst to the operator.

If you're not sure whether something qualifies, file the report
anyway and we'll triage it together.
