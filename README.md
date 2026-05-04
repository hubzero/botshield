<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-botshield-header.svg">
    <img src="docs/assets/logo-botshield-header-light.svg" alt="mod_botshield" width="600">
  </picture>
</p>

<p align="center">
  <strong>Disciplined Judgment. Proportionate Response.</strong>
</p>

<p align="center">
  <a href="https://github.com/hubzero/botshield/actions/workflows/ci.yml"><img src="https://github.com/hubzero/botshield/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://hubzero.github.io/botshield/"><img src="https://img.shields.io/badge/docs-Pages-blue" alt="docs"></a>
  <a href="https://httpd.apache.org/"><img src="https://img.shields.io/badge/Apache-2.4-D22128?logo=apache&logoColor=white" alt="Apache 2.4 module"></a>
  <a href="https://en.cppreference.com/w/c"><img src="https://img.shields.io/badge/language-C99-blue" alt="C99"></a>
  <a href="#whats-shipped"><img src="https://img.shields.io/badge/status-beta-orange" alt="status: beta"></a>
</p>

Adaptive bot mitigation for the Apache HTTP Server.

BotShield scores requests, tracks short-term reputation, and decides
whether to pass, challenge, slow down, or block before application
code has to absorb the traffic.

**Status: beta.** Stable shape, exercising in dev; not yet a production
deployment. Architecture, threat model, and per-extension design notes
live in [DESIGN.md](DESIGN.md). Site handbook is rendered to
GitHub Pages from `docs-src/`; see the [documentation index](#documentation)
below.

## What's shipped

- **Tiered challenges.** Pass / silent (no-click auto-submit) / form
  (checkbox interstitial) / captcha (third-party provider). Per-scope
  configurable; multi-provider cohabitation on one vhost. Captcha
  providers: Turnstile, hCaptcha, reCAPTCHA v2 + v3, Friendly Captcha,
  GeeTest v4.
- **Cookie envelope.** AES-256-GCM authenticated encryption,
  per-purpose HKDF-derived keys, verify-only secondary key for
  graceful rotation. Per-cookie hourly forgiveness cap closes the
  rebuild-budget evasion. Cookies are session-scoped at the
  browser layer (no `Expires=` / `Max-Age=`); the server-side
  `expires_at` field is the hard cap. Every pass through the
  handler mints `__Host-bs_session` so the next request from the
  same browser carries an identifier (most cookies carry trust=0
  — they're per-session markers, not trust receipts).
- **Sparse server state.** SHM flagged-IP table with seqlock-guarded
  lockless reads, rotating Bloom filter for first-sight IP signals,
  crash-durable persistence via `mod_watchdog` snapshots + shutdown
  save.
- **Policy.** Path / cookie / env / load / scope / flag triggers
  (path triggers carry optional UA / IP cohort gates), per-cohort
  rate limits, in-module robots.txt parser
  (RFC 9309 + Crawl-delay extension), repeated-429 escalation,
  anti-loop safeguard (302 redirect to a built-in explainer or to
  a configured `BotShieldSafeguardRedirectURL` after a client loops
  on challenges without solving).
- **Verify-endpoint hardening.** HMAC-signed pending cookie + per-IP
  rate limit + global in-flight semaphore on `/captcha-verify`.
  One-time-use nonces + IP-bound bootstrap on the embedded silent
  path.
- **Observability.** Structured `key=value` decision-log line per
  request, 41 Prometheus metrics at `<prefix>/metrics`, `mod_status`
  contribution hook.
- **Multi-vhost isolation.** Default-isolate per `ServerName`; opt
  into shared reputation via `BotShieldShareScope`.
- **Log-only / shadow mode.** Scope-level `BotShieldEnabled LogOnly`
  and per-rule `mode=observe` for staging policy changes without
  enforcement. Counterfactual outcomes (`~challenge`, `~block`,
  `~rate_limited`) surface in the decision log so you can see what
  the rule would have done.
- **Accessibility.** Default interstitial passes WCAG 2.1 AA on every
  variant.

## Quick start

You need Apache 2.4 development headers — `apache2-dev` on
Debian/Ubuntu, `httpd-devel` on RHEL-family.

```sh
make enable     # build, install, a2enmod, configtest, reload
```

Step-by-step equivalents: `make`, `sudo make install`,
`sudo a2enmod botshield`, `sudo apachectl configtest && sudo
systemctl reload apache2`. `make disable` removes the module without
deleting the `.so`.

Minimal vhost configuration:

```apache
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
    # ... SSLEngine, cert files, etc.

    BotShieldEnabled    On
    BotShieldSecretFile /etc/botshield/secret
    BotShieldAlgorithm  sha256-zeros
</VirtualHost>
```

Generate the secret with `openssl rand -hex 32 > /etc/botshield/secret;
chmod 600 /etc/botshield/secret`. Full setup walkthrough in
[`docs-src/getting-started.md`](docs-src/getting-started.md).

## Documentation

Site handbook (rendered to
[hubzero.github.io/botshield](https://hubzero.github.io/botshield/)
from these sources):

| Topic | Source |
|---|---|
| Getting started — install, first vhost, smoke test | [`docs-src/getting-started.md`](docs-src/getting-started.md) |
| Site model — scoring, tiers, cookie reputation, multi-vhost | [`docs-src/site-model.md`](docs-src/site-model.md) |
| Directives reference | [`docs-src/directives.md`](docs-src/directives.md) |
| Policy — triggers, rate limits, robots.txt | [`docs-src/policy.md`](docs-src/policy.md) |
| Captcha tier — providers, hardening, configuration | [`docs-src/captcha.md`](docs-src/captcha.md) |
| Deployment — reverse proxy, slowloris, capacity sizing, secret rotation | [`docs-src/deployment.md`](docs-src/deployment.md) |
| Staging policy changes — shadow mode + per-rule observe | [`docs-src/staging.md`](docs-src/staging.md) |
| Observability — decision log, metrics, mod_status | [`docs-src/observability.md`](docs-src/observability.md) |
| Troubleshooting | [`docs-src/troubleshooting.md`](docs-src/troubleshooting.md) |
| FAQ | [`docs-src/faq.md`](docs-src/faq.md) |

Internal references:

- [DESIGN.md](DESIGN.md) — current-state design specification.
- [CHANGELOG.md](CHANGELOG.md) — date-organized log of changes.
- [tests/README.md](tests/README.md) — test, fuzz, and benchmark
  framework.

## Module-owned endpoints

Under `BotShieldEndpointPrefix` (default `/botshield`):

| Path | Method | Purpose |
|---|---|---|
| `<prefix>/captcha-verify` | POST | Bare verify URL (single-provider vhosts) |
| `<prefix>/captcha-verify/<provider>` | POST | Per-provider verify URL |
| `<prefix>/metrics` | GET | Prometheus 0.0.4 text exposition |
| `<prefix>/policy-status` | GET | Active policy readback (rate limits, block paths, robots.txt) |
| `<prefix>/embedded.js` | GET | Embedded silent-verify wrapper |
| `<prefix>/form-widget.js` | GET | Inline form-captcha widget shell |
| `<prefix>/safeguard-info` | GET | Built-in explainer page rendered when challenge-safeguard trips (and no `BotShieldSafeguardRedirectURL` is set). Accepts `?return=<urlencoded path>` |

Access control is delegated to standard Apache mechanisms — wrap any
of them in `<Location>` with `Require ip` / `AuthType Basic` to
restrict, e.g.:

```apache
<Location /botshield/metrics>
    Require ip 10.0.0.0/8
</Location>
```

## Local development

The repo ships a working HTTPS dev vhost at
`apache/botshield-dev.conf` that exercises every directive against
the committed `tests/site/` docroot. Bring it up:

```sh
sudo tests/setup/provision.sh
```

Idempotent — safe to re-run. After it completes, the dev vhost
listens on `https://localhost/`. Test infrastructure (pytest harness,
fuzz, benchmarks) is documented in
[`tests/README.md`](tests/README.md).

## License

MIT. See [LICENSE](LICENSE).
