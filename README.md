# mod_botshield

Low-latency bot detection for Apache 2.4. Cookieless requests get a
self-contained proof-of-work interstitial; verified visitors receive a
short-lived cookie and pass through on their next request.

**Status: beta.** End-to-end tiered routing works — pass, silent
(no-click auto-submit splash), form (checkbox interstitial), and
captcha (third-party provider). Server-side HMAC signing, scoring
heuristics, shared-memory flagged-IP table with lockless reads,
rotating Bloom filter for first-sight IP signals, crash-durable state
persistence (mod_watchdog periodic snapshots plus shutdown save), and
captcha-verify-endpoint hardening (per-IP rate limit, global in-flight
semaphore, HMAC-signed challenge-pending cookie, log throttling) are
all shipped. Captcha tier routes to Cloudflare Turnstile, hCaptcha,
Google reCAPTCHA v2, Google reCAPTCHA v3 (with score threshold),
Friendly Captcha, and GeeTest v4 — configurable per scope, with
multi-provider cohabitation on one vhost. Observability is shipped:
structured `key=value` decision-log line per request, 41 Prometheus
metrics at `<prefix>/metrics`, and a `mod_status` contribution hook.
Accessibility passes WCAG 2.1 AA on every interstitial variant.
Production hardening is shipped through M10.4: clean under ASan +
UBSan, load-tested, MPM-matrix-verified across event / worker /
prefork with graceful-restart coverage, and 8h-soak-clean (1.4M
requests, +4MB RSS, zero crashes). The overnight soak now runs as
a pytest test (`tests/pytests/test_soak.py`), kicked off nightly
via the GitHub Actions workflow. The test suite shipped through
M11.8: 60+ pytest tests backed by a reusable `botshield_test`
framework (`httpx` client, transactional `config_override`,
structured decision-log parser, time-salted IP allocator,
data-driven per-provider captcha specs, a real Chromium via
Playwright for the acceptance layer, axe-core a11y smoke,
hypothesis property tests for cookie tampering, Prometheus
exposition-format validator, session-scoped MPM matrix, and a
LibFuzzer harness for the cookie parser). CI splits a fast
per-PR lane from a browser lane and a nightly soak.

## How it works

1. An `APR_HOOK_FIRST` handler runs before Apache's content generator.
   URLs under `BotShieldEndpointPrefix` (default `/botshield`) route to
   the module's own handlers (`/botshield/captcha-verify/<provider>`,
   `/botshield/metrics`) before tier dispatch. If the URI ends in a
   static-asset extension (`.css`, `.js`, `.png`, `.svg`, …), the
   module declines so the challenge page's own linked assets work.
2. Each request gets a score. Heuristics (missing User-Agent, missing
   Accept-Language, scraper UA tokens), the flagged-IP table lookup
   (SHM, seqlock-guarded), a first-sight Bloom check, and any rep
   carried in a signed `_bs_verified` cookie all compose into one
   effective score.
3. The score picks a tier — **pass** below `BotShieldScoreSilent`,
   **silent** up to `BotShieldScoreHard`, **form** up to
   `BotShieldScoreCaptcha`, **captcha** at or above. Below silent the
   module returns `DECLINED` and Apache serves the real content —
   legitimate visitors never see us and never receive a cookie.
4. Tier behavior:
   - **silent** — minimal "checking your browser" splash that
     auto-submits a SHA-256 proof-of-work on load.
   - **form** — reCAPTCHA-shaped checkbox widget; user clicks to start
     the PoW.
   - **captcha** — third-party provider widget (Turnstile / hCaptcha /
     reCAPTCHA v2/v3 / Friendly Captcha / GeeTest v4); on success the
     client POSTs the provider's token to `/botshield/captcha-verify/
     <provider>`, the module siteverifies via libcurl (tight timeout,
     fail-open on provider outage), and issues the cookie.

   PoW tiers produce an HMAC-signed 15-field cookie; captcha tier
   produces the same envelope with `alg="captcha-<provider>"`.
5. Each decision emits two log lines: a human-readable prose line and
   a stable `key=value` structured line (`mod_botshield: decision
   tier=<t> outcome=<o> …`) parseable with a ~50-line awk script.
   Every decision also increments matching SHM counters exported at
   `/botshield/metrics` (Prometheus text) and via a `mod_status`
   contribution hook.
6. The next request carries the cookie; the server re-derives the
   HMAC, checks freshness, and declines — Apache serves the real
   content. Flags (honeypot hits, scanner probes) live in SHM, not the
   cookie, so replaying an older cookie can't launder an IP flag.

## Build

You need Apache 2.4 development headers — `apache2-dev` on Debian/Ubuntu,
`httpd-devel` on RHEL-family.

```
make enable     # build, install, a2enmod, configtest, reload
```

Step-by-step equivalents:

```
make            # compile with apxs -c
make install    # install the .so into Apache's modules dir
sudo a2enmod botshield
sudo apachectl configtest && sudo systemctl reload apache2
```

`make disable` removes the module without deleting the `.so`.

## Minimal configuration

```apache
<VirtualHost *:443>
    ServerName example.test
    DocumentRoot /var/www/example
    # ... SSLEngine, cert files, etc.

    BotShieldEnabled On
</VirtualHost>
```

## Deployment behind a reverse proxy or load balancer

`mod_botshield` keys its IP-based signals — the flagged-IP table, the
Bloom filter, the score per IP — on `r->useragent_ip`, which is the
TCP peer Apache saw. If Apache sits behind a reverse proxy or load
balancer, that peer is the proxy, not the real client.

**The fix is the stock Apache module `mod_remoteip`.** Configure it
to trust your edge hops, and it will rewrite `r->useragent_ip` to the
real client before any botshield hook runs. This is the same module
used for accurate `%a` in access logs — if your logs already show
real client IPs, you're done. If not:

```apache
LoadModule remoteip_module modules/mod_remoteip.so

RemoteIPHeader        X-Forwarded-For
RemoteIPTrustedProxy  10.0.0.0/8
RemoteIPTrustedProxy  2001:db8:cafe::/48
# ... one RemoteIPTrustedProxy per edge CIDR ...

<VirtualHost *:443>
    ServerName example.com
    BotShieldEnabled     On
    BotShieldSecretFile  /etc/botshield/secret
    BotShieldAlgorithm   sha256-zeros
</VirtualHost>
```

We deliberately do not reimplement this. `mod_remoteip` handles
`X-Forwarded-For`, `Forwarded:` (RFC 7239), trusted-proxy CIDR
matching for both v4 and v6, and multi-hop chains — all in Apache
core, battle-tested, maintained. A site that skips this and just
enables `BotShieldEnabled` behind a proxy will flag its own load
balancer and then challenge every legitimate visitor.

For a single-host deployment with no proxy in front, no extra
configuration is needed — `r->useragent_ip` already is the client.

## Slow-client / slowloris defense

`mod_botshield`'s body-read paths (the form-captcha verify, the M8
captcha-verify endpoint, the embedded-verify endpoint) inherit
Apache's slow-client defense. Apache's `Timeout` directive bounds
how long a worker can be held by a stalled client; the default is
60 seconds.

**For production deployments, pair `mod_botshield` with
`mod_reqtimeout`.** It gives finer-grained controls than `Timeout`
and is the standard Apache answer to slowloris-class attacks. A
typical configuration:

```apache
LoadModule reqtimeout_module modules/mod_reqtimeout.so

RequestReadTimeout header=20-40,minrate=500
RequestReadTimeout body=20,minrate=500
```

We deliberately do not implement our own slow-client defense.
`mod_reqtimeout` is in Apache core, battle-tested, and applies to
the whole vhost — `mod_botshield`-owned endpoints get the same
protection as the application's own handlers without any extra
config on our side.

## Directives

### Core

| Directive | Default | Purpose |
|---|---|---|
| `BotShieldEnabled on\|off` | `off` | Master on/off for the enclosing scope |
| `BotShieldDebug on\|off` | `off` | Return `403 "Hello World"` for every request (smoke test) |
| `BotShieldSecretFile /path` | unset (required) | HMAC key for cookie/challenge signing; mode 0600, ≥ 16 bytes |
| `BotShieldAlgorithm <name>` | unset (required) | PoW algorithm. Only `sha256-zeros` is built in today; `sha384-zeros`, `sha512-zeros`, `pbkdf2-sha256`, `argon2id` are reserved registry slots |
| `BotShieldCookieTTL N` | `3600` | Seconds a verified cookie is honoured |
| `BotShieldCookieDomain ".example.com"` | unset (host-only) | Set-Cookie Domain= attribute so rep follows across subdomains |
| `BotShieldDifficulty N` | `4` | Leading hex zeros the PoW must produce (1..8) |
| `BotShieldEndpointPrefix /path` | `/botshield` | URL prefix for module-owned handlers (captcha-verify, metrics) |

### Tier thresholds and forgiveness

| Directive | Default | Purpose |
|---|---|---|
| `BotShieldScoreSilent N` | `20` | Score at or above which the silent-PoW tier is picked |
| `BotShieldScoreHard N` | `50` | Score at or above which the form-PoW tier is picked |
| `BotShieldScoreCaptcha N` | `80` | Score at or above which the captcha tier is picked |
| `BotShieldForgivenessSilent N` | `10` | Score credit on a successful silent-PoW pass |
| `BotShieldForgivenessForm N` | `25` | Score credit on a successful form-PoW pass |
| `BotShieldForgivenessCaptcha N` | `50` | Score credit on a successful captcha pass |

### Widget customization

| Directive | Default | Purpose |
|---|---|---|
| `BotShieldPromptText "..."` | `I'm not a robot` | Label next to the checkbox |
| `BotShieldLogoFile /path.svg` | embedded Guardian | SVG served inline as the logo (≤ 64 KB) |
| `BotShieldLogoLabel "..."` | `botshield` | Small caption under the logo |
| `BotShieldHelp off\|on\|button` | `button` | Help visibility: nothing, always-on panel, or a `?` link that expands |
| `BotShieldHelpFile /path.html` | built-in text | HTML fragment used as the help panel (≤ 64 KB) |
| `BotShieldChallengeFile /path.html` | built-in shell | Full HTML page template wrapping the widget; must contain the marker `<!-- BOTSHIELD -->` (≤ 256 KB) |
| `BotShieldShowLogo on\|off` | `on` | Show the brand column |
| `BotShieldShowLabel on\|off` | `on` | Show the prompt text; when off, moves to the button's `aria-label` |
| `BotShieldShowBox on\|off` | `on` | Show the widget's outer box (border/background/shadow) |

### Captcha tier (M8)

| Directive | Default | Purpose |
|---|---|---|
| `BotShieldCaptchaProvider <name>` | unset | `turnstile` / `hcaptcha` / `recaptcha-v2` / `recaptcha-v3` / `friendly` / `geetest` |
| `BotShieldCaptchaSiteKey "..."` | unset | Provider-public site key (GeeTest: captcha_id) |
| `BotShieldCaptchaSecretFile /path` | unset | Provider secret (mode 0600). For GeeTest this is the captcha_key used to HMAC the lot_number |
| `BotShieldCaptchaTimeout N` | `1000` | Siteverify HTTP timeout in ms (100..5000). Fail-open on timeout |
| `BotShieldRecaptchaV3MinScore 0..1` | `0.5` | Reject v3 verifications below this score even on `success:true` |

### Captcha-verify endpoint hardening (M8.1)

| Directive | Default | Purpose |
|---|---|---|
| `BotShieldCaptchaRateLimit N` | `30` | Per-IP verify POSTs per minute (0 disables, range 0..1000). Over cap → 429 with Retry-After, no libcurl |
| `BotShieldCaptchaMaxInFlight N` | `64` | Global cap on concurrent outbound siteverify calls (1..1024). Over cap → 503, no libcurl |

### Flagged-IP table / Bloom filter / state (M5+M6)

| Directive | Default | Purpose |
|---|---|---|
| `BotShieldFlagIP <bits> [ttl]` | unset | Flag the client IP when this scope is hit. Bits: `honeypot_hit`, `scanner_probe`, `fake_crawler`, `pow_fail_streak` |
| `BotShieldShmSize 8M` | `8M` | Total SHM budget (128K..256M) |
| `BotShieldFlaggedIPCapacity N` | `50000` | Flagged-IP slot count (1024..1000000) |
| `BotShieldIPv6PrefixLen N` | `64` | IPv6 mask length for flagged-IP keying; v4 always /32 |
| `BotShieldBloomIPs N` | `1000000` | Expected working-set size; drives Bloom filter dimensions |
| `BotShieldBloomWindow N` | `604800` | Bloom rotation window in seconds (rotation at window/2) |
| `BotShieldBloomFPRate 0.01` | `0.01` | Target false-positive rate |
| `BotShieldStateFile /path` | unset (persistence off) | SHM snapshot path. **Must be at main-server scope**, not inside `<VirtualHost>` |
| `BotShieldStateSaveInterval N` | `300` | Periodic save interval in seconds (0 = shutdown-only); requires `mod_watchdog` |

All directives are valid in server config, `<VirtualHost>`, `<Directory>`,
`<Location>`, `<Files>`, and their `*Match` variants. **Not `.htaccess`** —
keeping bot-protection config out of writable filesystem locations is a
deliberate choice. SHM-sizing and state-file directives must live at
main-server scope (not inside `<VirtualHost>`), since the SHM segment is
module-global.

File-backed `*File` directives read their targets **once at config-parse
time** and cache the bytes on the per-directory config — no per-request
file I/O. Missing, unreadable, or oversized files fail `apachectl
configtest`, so a broken template can't be reloaded into a running server.

## Per-URL scoping

`<Location>` is usually what you want for a bot gate — routes don't always
map 1:1 to filesystem paths. Example: gate only login and the JSON API,
leave the rest of the site alone:

```apache
BotShieldEnabled Off

<LocationMatch "^/(login|api)(/|$)">
    BotShieldEnabled On
</LocationMatch>
```

## Customizing the challenge page

Three layers, each independent:

- **Widget content** — prompt, logo, caption, help text are all strings
  or files you provide.
- **Widget chrome** — `BotShieldShow{Logo,Label,Box}` strip the widget
  down to a lone checkbox if you want to style the surroundings yourself.
- **Page shell** — `BotShieldChallengeFile` replaces the full page HTML
  with your own template. The module splices the widget in at
  `<!-- BOTSHIELD -->` so the DOM contract the JavaScript relies on stays
  module-controlled.

See `apache/botshield-dev.conf` for worked examples of each.

## Accessibility

The default interstitial passes axe-core WCAG 2.1 AA with zero
violations — landmarks, focus-visible outlines, `aria-live` status on the
progress message, `prefers-reduced-motion` handling, and sufficient
contrast in both light and dark regions of the widget. Stripping chrome
preserves accessibility: the prompt moves to `aria-label` when visually
hidden, the live-status region is always present, and the screen-reader-
only `<h1>` is emitted regardless of how much chrome you've removed.

## Security note

Cookies are HMAC-SHA-256-signed over a 13-field canonical envelope; any
edit to the score, flag bitmap, tier marker, or PoW proof invalidates
the signature and forces a fresh challenge. Cookies carrying a genuine
PoW solve can still be replayed within their TTL (default 1 h), which
is why flags and the first-sight Bloom filter live in shared memory
rather than only in the cookie — an attacker can replay yesterday's
lower-score cookie, but an IP that tripped a honeypot stays flagged
across restarts via the periodic state-file snapshots.

The captcha-verify endpoint (`<prefix>/captcha-verify/<provider>`) is
guarded by six layers of pre-libcurl checks: Content-Type prefilter,
8 KB body cap, token-field presence and length bound, HMAC-signed
`_bs_captcha_pending` cookie (set at interstitial render, required at
verify, HttpOnly/Secure/SameSite=Lax/Max-Age=300), per-IP rate limit
(`BotShieldCaptchaRateLimit`), and a global in-flight semaphore
(`BotShieldCaptchaMaxInFlight`). Each check rejects cheaply **before**
any outbound call — the verify endpoint cannot be trivially weaponized
as a siteverify amplifier or worker-starvation vector.

## Module-owned endpoints

Under `BotShieldEndpointPrefix` (default `/botshield`):

| Path | Method | Purpose |
|---|---|---|
| `<prefix>/captcha-verify` | POST | Bare verify URL for single-provider vhosts |
| `<prefix>/captcha-verify/<provider>` | POST | Per-provider verify URL (multi-provider vhosts) |
| `<prefix>/metrics` | GET | Prometheus 0.0.4 text exposition |

Access control is delegated to standard Apache mechanisms — put a
`<Location>` with `Require ip ...` or `AuthType Basic` around the
metrics endpoint, for example:

```apache
<Location /botshield/metrics>
    Require ip 10.0.0.0/8
</Location>
```

## Observability

Every decision emits a stable `key=value` line alongside the existing
prose log:

```
mod_botshield: decision tier=captcha outcome=verified ip=203.0.113.42
    score=0 cookie=- provider=turnstile alg=captcha-turnstile
    reason="-" path="/captcha-demo"
```

The decision log emits at Apache's `info` level. Apache's default
`LogLevel` is `warn`, so the line is invisible until you opt in.
Bump just this module to make it visible without raising the
verbosity of the rest of the server:

```apache
LogLevel mod_botshield:info
```

The `reason`, `path`, and `tag` fields are quoted; embedded `"`
and `\` characters are URL-percent-encoded (`%22` and `%5C`) so a
hand-rolled HTTP client sending an adversarial URI can't break
log-parser tokenization. Browser traffic is unaffected — browsers
already %-encode those bytes before sending.

Enum sets:

- `tier`     = `none` | `pass` | `silent` | `form` | `captcha`
- `outcome`  = `declined` | `challenged` | `verified` | `rejected` |
               `failopen` | `rate_limited` | `inflight_capped` |
               `pending_missing` | `misconfigured` | `debug`
- `cookie`   = `ok` | `expired` | `bad_sig` | `bad_format` | `absent` | `-`
- `provider` = `-` or registry name

Every decision also increments SHM counters exported at `<prefix>/metrics`:

- `botshield_tier_<t>_total` — 5 tier counters
- `botshield_outcome_<o>_total` — 10 outcome counters
- `botshield_cookie_<c>_total` — 5 cookie counters
- `botshield_provider_<p>_total` — 6 provider counters
- Plus persistence counters/gauges, Bloom popcount gauges, flagged-IP
  table utilization, in-flight captcha count, SHM capacity static values

Counter names mechanically track the log enum vocabulary — there is no
parallel taxonomy. Adding an outcome value adds one row to the
string→index lookup or the string simply doesn't increment a counter
(with a visible WARNING), so drift is loud, not silent.

When `mod_status` is loaded and `ExtendedStatus On` is set, the module
also contributes to `/server-status` via an optional hook: a compact
HTML table in browser mode, `BotShield<Name>: N` key-value lines in
`?auto` mode.

## Development

`apache/botshield-dev.conf` is a working HTTPS dev vhost that exercises
each directive on its own URL of a fake "Crestline Research Library"
test site:

**Widget customization:**

| Path | What it demonstrates |
|---|---|
| `/` | Default widget |
| `/debug` | `BotShieldDebug` 403 smoke test |
| `/about.html` | Custom prompt, logo file, logo caption, help file, help always-on |
| `/search.html` | All chrome toggles off — just a bare checkbox |
| `/api/users.json` | `BotShieldShowBox off` — widget without outer box |
| `/login.html` | `BotShieldChallengeFile` — widget spliced into a site-themed page |
| `/admin/.env` | Honeypot scope — hits flag the IP via `BotShieldFlagIP honeypot_hit` |

**Captcha providers** (each uses the provider's published test or
placeholder keys; see the dev config comments for what each key
actually does):

| Path | Provider | Notes |
|---|---|---|
| `/captcha-demo` | Turnstile | Cloudflare always-pass dummies; full end-to-end works |
| `/hcaptcha-demo` | hCaptcha | Always-pass dummies; POST body must use the documented test token |
| `/recaptcha-v2-demo` | reCAPTCHA v2 | Google's published test pair; any token accepted by the test secret |
| `/recaptcha-v3-demo` | reCAPTCHA v3 | Placeholder keys — real v3 keys from the reCAPTCHA admin console are needed for a true score-threshold test |
| `/friendly-demo` | Friendly Captcha | Placeholder keys; real keys from friendlycaptcha.com |
| `/geetest-demo` | GeeTest v4 | Placeholder keys; real keys from dashboard.geetest.com |

**Module-owned endpoints:**

| Path | What |
|---|---|
| `/botshield/captcha-verify/<provider>` | Per-provider verify POST target |
| `/botshield/metrics` | Prometheus text exposition |
| `/server-status` | Apache `mod_status` (enables the botshield contribution hook) |

The test site lives under `testsite/` and is git-ignored. See the header
of `apache/botshield-dev.conf` for how to set up the self-signed cert
and docroot.

## License

MIT. See `LICENSE`.
