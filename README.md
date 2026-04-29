# mod_botshield

Low-latency bot detection for Apache 2.4. Cookieless requests get a
self-contained proof-of-work interstitial; verified visitors receive a
short-lived cookie and pass through on their next request.

**Status: beta.** Stable shape, exercising in dev; not yet a
production deployment.

What's shipped:

- **Tiered challenges.** Pass / silent (no-click auto-submit) / form
  (checkbox interstitial) / captcha (third-party provider).
  Per-scope configurable; multi-provider cohabitation on one vhost.
  Captcha providers: Turnstile, hCaptcha, reCAPTCHA v2 + v3,
  Friendly Captcha, GeeTest v4.
- **Cookie envelope.** AES-256-GCM authenticated encryption,
  per-purpose HKDF-derived keys, verify-only secondary key for
  graceful rotation. Per-cookie hourly forgiveness cap closes the
  rebuild-budget evasion.
- **Sparse server state.** SHM flagged-IP table with seqlock-guarded
  lockless reads, rotating Bloom filter for first-sight IP signals,
  crash-durable persistence via `mod_watchdog` snapshots + shutdown
  save.
- **Policy.** Path / cookie / env / load / scope / flag triggers,
  per-cohort rate limits and block-paths, in-module robots.txt
  parser (RFC 9309 + Crawl-delay extension), repeated-429
  escalation, anti-loop safeguard.
- **Verify-endpoint hardening.** HMAC-signed pending cookie + per-IP
  rate limit + global in-flight semaphore on `/captcha-verify`. One-
  time-use nonces + IP-bound bootstrap on the embedded silent path.
- **Observability.** Structured `key=value` decision-log line per
  request, 41 Prometheus metrics at `<prefix>/metrics`, `mod_status`
  contribution hook.
- **Multi-vhost isolation.** Default-isolate per `ServerName`; opt
  into shared reputation via `BotShieldShareScope`.
- **Shadow mode.** Global and per-rule observe for staging policy
  changes without enforcement.
- **Accessibility.** Default interstitial passes WCAG 2.1 AA on
  every variant.

Production hardening: clean under ASan + UBSan, MPM-matrix-verified
across event / worker / prefork with graceful-restart coverage,
8h-soak-clean (1.4M requests, +4MB RSS, zero crashes).

Tests: ~250 pytest cases backed by the `botshield_test` framework
(httpx client, transactional `config_override`, structured
decision-log parser, time-salted IP allocator, real Chromium via
Playwright, axe-core a11y smoke, Hypothesis property tests,
LibFuzzer harnesses for the cookie + robots parsers). CI splits a
fast per-PR lane from a browser lane; the 8h soak and LibFuzzer
campaigns are wired but `workflow_dispatch`-only, kicked off
manually before a release.

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

   PoW tiers produce an AES-256-GCM-encrypted 15-field cookie;
   captcha tier produces the same envelope with `alg="captcha-
   <provider>"`.
5. Each decision emits two log lines: a human-readable prose line and
   a stable `key=value` structured line (`mod_botshield: decision
   tier=<t> outcome=<o> …`) parseable with a ~50-line awk script.
   Every decision also increments matching SHM counters exported at
   `/botshield/metrics` (Prometheus text) and via a `mod_status`
   contribution hook.
6. The next request carries the cookie; the server GCM-decrypts +
   verifies the auth tag, checks freshness, and declines — Apache
   serves the real
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

## Staging policy changes

mod_botshield supports two complementary dry-run modes so operators can
deploy new rules without affecting production traffic until they're
confident the matches are correct.

### Per-rule observe mode

Add `mode=observe` to any directive that supports it (`BotShieldPathTrigger`,
`BotShieldBlockPath`, `BotShieldRateLimit`, `BotShieldFlagTrigger`, …):

```apache
BotShieldPathTrigger /admin/$ flag=scanner_probe mode=observe
```

The rule still evaluates against every matching request, but takes no
action. Matches appear in the decision log with an `:observe` suffix:

```
botshield: path-trigger:scanner-trap:observe ip=1.2.3.4 path=/admin/
```

Watch the log for a few hours or days. When matches look correct, remove
`mode=observe` and reload Apache to flip the rule to enforce.

### Global `BotShieldShadowMode`

For staging a whole policy revision at once, set the server-wide flag:

```apache
BotShieldShadowMode on
```

This forces every rule to observe regardless of its per-rule setting —
useful before a release or when comparing a new ruleset against
production traffic without any enforcement risk. Flip back to `off` when
you're ready to enforce.

### How they combine

Either signal is sufficient: a rule runs in observe mode if EITHER its
per-rule mode is observe OR `BotShieldShadowMode on` is set. There is no
priority order to memorize. Use per-rule observe for staging single
rules; use `BotShieldShadowMode` for staging an entire policy.

### What "observe" means precisely

- The rule's predicate evaluates normally (path match, cohort match, etc.)
- The decision log records the would-have-done outcome with `:observe`
  suffix
- The matching observe-mode metric counter increments
  (e.g. `block_path_observed_total`, `trigger_observed_total`)
- No flag bits are set on the IP
- No score is added to the request
- No status code, redirect, or log tag side-effect is emitted

The audit trail captures everything the rule WOULD have done; the
response is unaffected.

## Understanding scoring

mod_botshield uses a single signed-integer score per request to decide
how much friction to apply. Higher score = more suspicious = stronger
challenge. Operators tune four thresholds and rely on the module to
collect signals consistently.

### How score is collected

Throughout the request lifecycle, signals call `bs_score_add` with a
penalty (positive = suspicious, negative = credit) and a reason string.
Built-in signals (current defaults — verify against
`src/mod_botshield.c` if tuning matters):

| Signal | Penalty | Reason |
|---|---|---|
| Missing `User-Agent` | +40 | `missing-user-agent` |
| Missing `Accept-Language` | +15 | `missing-accept-language` |
| Scraper-pattern UA | +50 | `scraper-ua:<pattern>` |
| First-sight IP (not in Bloom filter) | +5 | `first-sight-ip` |
| Block-path match | +100 | `block-path:<name>` |
| Rate-limit exceeded | +50 | `rate-limit-exceeded:<name>` |
| Robots.txt Disallow violation | +100 | `robots-block:<group>` |
| Honeypot hit (default flag-trigger) | +60 | `flag-trigger:honeypot_hit` |
| Fake-bot detection (default) | +80 | `flag-trigger:fake_bot` |
| Verified legit-crawler match | -∞ (forces pass) | `verified-<name>` |
| `app_verified_human` cookie credit (default) | -80 | `flag-trigger:app_verified_human` |
| Operator path / load / cookie / env / flag triggers with `action=score add=N` | configured | `<family>-trigger:<name>` |

Every entry carries its reason; the per-request decision log lists
them all so you can see exactly which signals contributed.

The number of distinct reasons recorded per request is capped at 16
(`BS_SCORE_MAX_REASONS`). Past the cap, further calls still
contribute their penalty to the running total but are dropped from
the audit trail. A one-shot DEBUG log line fires on the first drop
so the diagnostic surfaces under verbose logging.

### Composition

When the policy decision is made, two values are summed into one
effective score:

```
effective = heuristic_total + cookie_score
```

- **heuristic_total** — sum of `bs_score_add` calls for THIS request,
  inclusive of any `BotShieldFlagTrigger action=score add=N` effects
  fired by flags set on the IP or carried in the prior cookie.
- **cookie_score** — accumulated reputation in the prior `_bs_verified`
  cookie. Carries forward across requests; expires with the cookie.

A separate **tier floor** can also apply: any
`BotShieldFlagTrigger action=tier_floor min=<tier>` rule firing on a
set flag bit lifts the final tier to AT LEAST that level after
threshold mapping. Score-derived tier wins when it's already above
the floor — never silently downgrades. The floor lifts produce a
`flag-tier-floor:<tier>` reason.

### Threshold ladder

The composed `effective` score maps to a tier via three configurable
thresholds:

| Score range | Tier | Behavior |
|---|---|---|
| `effective < score_silent` | PASS | request continues normally |
| `score_silent ≤ effective < score_hard` | SILENT | invisible JS proof-of-work |
| `score_hard ≤ effective < score_captcha` | FORM | visible form-submitted PoW |
| `score_captcha ≤ effective` | CAPTCHA | third-party captcha (falls back to FORM if no provider configured) |

Defaults:

- `BotShieldScoreSilent`  20
- `BotShieldScoreHard`    50
- `BotShieldScoreCaptcha` 80

Tune the thresholds to your tolerance for friction. Lower = more
requests hit challenges; higher = more requests pass freely.

### Inspecting decisions

The decision log line for every served challenge includes the full
breakdown:

```
mod_botshield: <action> effective=N tier=<tier> heuristic=N
               cookie_score=N reasons=[reason:penalty,reason:penalty,...]
```

When tuning thresholds or debugging unexpected challenges, grep the
log for the request and read the `reasons` array — exactly which
signals contributed and how much.

### Tuning workflow

1. Start with `BotShieldShadowMode on` to dry-run all rules without
   enforcement (see "Staging policy changes" above).
2. Watch the decision log for several days under real traffic.
3. Adjust thresholds and per-rule penalties based on observed
   distributions of `effective` and the per-reason contributions.
4. Flip `BotShieldShadowMode off` when satisfied.
5. Subsequent rule additions can be staged with per-rule
   `mode=observe` without affecting the rest.

### Cookie reputation

Once a request passes through (challenged or not), mod_botshield
issues a `_bs_verified` cookie carrying the user's accumulated
reputation. On subsequent requests that cookie's score field becomes
the `cookie_score` term in the composition. Repeated good behavior
accumulates negative `cookie_score` (forgiveness credit applied at
challenge-issue time); repeated suspicious behavior accumulates
positive.

The reputation persists across requests but expires with the cookie
TTL (`BotShieldCookieTTL`, default 1 hour). After expiry users start
fresh.

## Multi-vhost deployments

mod_botshield gives each vhost its own isolated bot reputation by
default. A bot flagged on `site-a.example.com` doesn't carry that flag
to `site-b.example.com`. Operators running many vhosts on one Apache
instance get per-site detection without configuring anything.

### Default behavior: auto-isolation per ServerName

Each vhost's reputation namespace is derived from its `ServerName`
directive. Two vhosts with different `ServerName` values automatically
maintain separate reputation. No configuration required.

```apache
<VirtualHost *:443>
    ServerName site-a.example.com
    # bot reputation isolated to site-a.example.com
</VirtualHost>

<VirtualHost *:443>
    ServerName site-b.example.com
    # bot reputation isolated to site-b.example.com
</VirtualHost>
```

A bot that hits a honeypot on `site-a.example.com` and gets flagged
appears clean to `site-b.example.com` on its next visit. This is usually
what you want — different sites have different threat models.

### Opt-in shared reputation

Sometimes you want sibling vhosts to share state — dev/prod
environments, www/api subdomains under the same brand, redundant
frontends. Set `BotShieldShareScope` to the same string on each vhost:

```apache
<VirtualHost *:443>
    ServerName www.example.com
    BotShieldShareScope example-cluster
</VirtualHost>

<VirtualHost *:443>
    ServerName api.example.com
    BotShieldShareScope example-cluster
</VirtualHost>
```

Both vhosts now share one reputation namespace. A bot flagged on either
site is flagged on the other.

The scope token is hashed; any string works, just keep it consistent
across the vhosts you want grouped. Different tokens produce
independent groups.

### Scaling

A single Apache instance can handle hundreds of vhosts sharing one
shared-memory segment. The per-slot namespace tag lets all vhosts
coexist without spawning per-vhost SHM segments — operationally simpler
than running per-vhost bot-detection instances.

For very large deployments, monitor SHM utilization via the existing
headroom watchdog and tune `BotShieldFlaggedIPCapacity`,
`BotShieldRateLimitEscalateCapacity`, and `BotShieldSafeguardCapacity`
to fit the aggregate traffic.

### When ServerName is missing

A vhost without a `ServerName` directive falls back to the global
default namespace (`ns_id=0`). All such vhosts share reputation.
mod_botshield logs a NOTICE at startup so operators see the fallback.
For explicit isolation on a vhost without ServerName, set
`BotShieldShareScope` to a unique-per-vhost token.

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

Cookies are AES-256-GCM authenticated-encrypted over a 15-field
canonical envelope: any edit to the score, flag bitmap, tier marker,
forgiveness window, or PoW proof fails the GCM tag check and forces
a fresh challenge. The AES key is HKDF-derived per-purpose from the
master secret, and a secondary verify-only key (`BotShieldSecondary
SecretFile`) supports graceful rotation. Cookies carrying a genuine
PoW solve can still be replayed within their TTL (default 1 h), which
is why flags and the first-sight Bloom filter live in shared memory
rather than only in the cookie — an attacker can replay yesterday's
lower-score cookie, but an IP that tripped a honeypot stays flagged
across restarts via the periodic state-file snapshots. The per-cookie
hourly forgiveness cap (E15) prevents using cookie expiry as a budget-
reset bypass.

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
LogLevel botshield_module:info
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

## Local development

The repo ships a working HTTPS dev vhost at
`apache/botshield-dev.conf` that exercises every directive against
the committed `tests/site/` docroot. The vhost paths are templated
through `${BS_REPO}`, so `tests/setup/provision.sh` wires it to
your checkout location automatically:

```bash
sudo tests/setup/provision.sh
```

This is **idempotent** — safe to re-run. It builds + installs the
module, generates a self-signed cert at `/etc/ssl/botshield-dev/`,
seeds `/etc/botshield/` with provider dummy secrets, sets up the
test docroot, and reloads Apache. After it completes, the dev vhost
listens on `https://localhost/` with the test fixture as DocumentRoot
and the rendered docs site mounted at `https://localhost/mod_botshield/`.

The vhost has `<Location>` blocks demonstrating every per-URL widget
customization, every captcha provider, and the honeypot scope; read
`apache/botshield-dev.conf` for the full inventory. Test infrastructure
(pytest harness, fuzz, benchmarks) is documented in
[`tests/README.md`](tests/README.md).

## License

MIT. See `LICENSE`.
