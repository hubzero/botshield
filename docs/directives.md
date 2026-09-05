# Directive reference

mod_botshield registers 100 directives at config time. This page is
the canonical reference, grouped by family. The
underlying source-of-truth is `bs_cmds[]` in `src/botshield.c:142` —
when tuning behavior, treat the source as authoritative
when it disagrees with a doc page.

## Scope and validity

Most directives accept `RSRC_CONF | ACCESS_CONF` — they're valid in
server config, `<VirtualHost>`, `<Directory>`, `<Location>`,
`<Files>`, and their `*Match` variants.

A few are server-scope only (`RSRC_CONF`); placing them inside
`<VirtualHost>` emits a NOTICE and the directive is ignored. The
SHM segment is module-global, so any directive that sizes the
segment or backs it with a state file lives at the main server
level. These directives carry an explicit "(server scope only)"
note in the table.

`.htaccess` is never valid for any BotShield directive — `OR_ALL`
is never used. Bot-protection config in writable filesystem
locations is a deliberate non-goal.

File-backed `*File` directives read their targets **once at config-
parse time** and cache the bytes on the per-directory config — no
per-request file I/O. Missing, unreadable, or oversized files fail
`apachectl configtest`, so a broken template can't be reloaded
into a running server.

## Core

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldEnabled` | `on\|off\|logonly` | `off` |
| `BotShieldChallenge` | `on\|off` | `on` |
| `BotShieldDebug` | `on\|off` | `off` |
| `BotShieldSecretFile` | `/path` | unset (required) |
| `BotShieldSecondarySecretFile` | `/path` | unset |
| `BotShieldAlgorithm` | `<name>` | unset (required) |
| `BotShieldCookieTTL` | `N` (sec) | `3600` (range 1..86400) |
| `BotShieldCookieDomain` | `".example.com"` | unset (host-only) |
| `BotShieldDifficulty` | `N` | `3` (range 1..16) |
| `BotShieldEndpointPrefix` | `/path` | `/botshield` |
| `BotShieldInteractiveArmMs` | `N` (ms) | `300` (range 0..2000) |
| `BotShieldInteractiveMinSolveMs` | `N` (ms) | `400` (range 0..5000) |

`BotShieldEnabled` is the master gate. It is tri-state:

- `on` — enforce. Tier decisions serve interstitials, triggers
  and rate-limit rules act on matches.
- `off` — module declines every request in scope; same shape as
  unloading the module on this path.
- `logonly` — observe-only. The handler runs and emits decision
  logs, but every enforcement-suppression site short-circuits:
  tier dispatch logs `outcome=~challenge` and declines instead of
  serving the interstitial; trigger / rate-limit matches log
  `:observe` and skip side effects. Use this to stage
  a whole policy revision before flipping enforcement on. See
  [staging](staging.md).

Because `BotShieldEnabled` is per-`<Directory>` / `<Location>`,
operators can carve out exceptions:

    BotShieldEnabled LogOnly                # vhost: observe
    <Location "/about">
        BotShieldEnabled On                 # /about: enforce
    </Location>

`BotShieldChallenge Off` makes a scope **block-only**: triggers, rate
limits and scoring all still run and still log, but no interstitial,
form or captcha is ever rendered — any selected tier collapses back to
`pass`, and the suppression appears in the decision log as
`challengeoff:<tier>`.

Use it where an explicit `status=4xx` trigger is meant to be the only
action. Parking `BotShieldScoreNonInteractive`/`Interactive`/`Captcha` at `10000` is
**not** equivalent, which is easy to get wrong: a flag `tier_floor` is
MAX'd in *after* the score-to-tier decision and ignores thresholds
entirely, so an IP carrying `honeypot_hit`, `fake_bot`, `scanner_probe`
or `pow_fail_streak` is still challenged. `BotShieldChallenge Off` is
applied after the floor, so it holds.

**This has bitten a production deployment, so it is worth spelling out
what the ceiling does and does not buy.** A hub running only the silent
tier parked `Hard` and `Captcha` at `10000`, believing form and captcha
were unreachable. They were not: the compiled-in flag defaults force a
tier directly.

| flag | forced tier | score |
|---|---|---|
| `honeypot_hit` | captcha | 60 |
| `fake_bot` | captcha | 80 |
| `scanner_probe` | **form** | 50 |
| `pow_fail_streak` | silent | 30 |

A residential visitor who had already solved a silent challenge —
`cookie=solved` — was pushed into the untested form widget six seconds
later because their IP carried `scanner_probe`. 124 of the 132
interactive-tier decisions in that window carried solve proof.

To genuinely cap the tier, reset each floor and re-add only the score:

```apache
BotShieldFlagTrigger honeypot_hit  reset action=score add=60
BotShieldFlagTrigger fake_bot      reset action=score add=80
BotShieldFlagTrigger scanner_probe reset action=score add=50
```

`reset` is required rather than stylistic: **tier floors MAX across
triggers**, so adding a lower floor beside the compiled-in one is
silently useless — it MAXes straight back up. `pow_fail_streak` needs
no reset; its floor is already `noninteractive`.

`BotShieldDebug` returns `403 "Hello World"` for every request in
scope — useful as a smoke test that the hook is firing.

`BotShieldSecretFile` and `BotShieldAlgorithm` are required. The
module emits `503 X-Botshield: misconfigured` for any request
where both are not resolved on the scope. `BotShieldSecondarySecretFile`
is the verify-only secondary key for graceful rotation — see
[deployment](deployment.md#secret-rotation).

`BotShieldAlgorithm` only `sha256zeros` is built-in today;
`sha384-zeros`, `sha512-zeros`, `pbkdf2-sha256`, `argon2id` are
reserved registry slots that fail with a clear "not implemented"
diagnostic.

`BotShieldCookieDomain` adds a `Domain=` attribute to Set-Cookie so
reputation follows across subdomains. Default is host-only. When
HTTPS is in use AND no domain is set, the module emits the
`__Host-bs_session` cookie name; otherwise the legacy
`_bs_session`. Verify path checks both.

`BotShieldDifficulty` is the leading-hex-zeros count for the PoW, so
expected work is `2^(4*d)` hashes: `3` is 4,096, `4` is 65,536. Each
step up multiplies client cost by **16**, not by a little.

Measured on live traffic rather than estimated. At `4`, 905 real solves
cost a median 329ms of client CPU, p90 1019ms, p99 5188ms, and 34% of
visitors spent over half a second; Android was worst at a 733ms median.
At `3` the same population runs a ~50ms median. The default is `3`.

Raising it is rarely worth it. Proof-of-work here is a *capability*
test — it proves a real JS engine ran — not an economic barrier. A
native solver is 15–43× faster than a browser at the same difficulty,
so cost falls on your visitors far harder than on a competent bot, and
a cookie amortises the bot's one solve across the whole
`BotShieldCookieTTL` window. Of those 905 solves, 2 carried any failed
attestation probe: the population that runs the JS is already clean.

There is no master switch for the implicit path. `BotShieldScoring`
used to be one, and it was removed: the module now ships **no default
rules at all**, and an unset score threshold never fires, so nothing
scores and score never decides a tier until an operator writes both a
heuristic or flag trigger and a threshold.

That removal is the same lesson the directive was a workaround for.
Every lockout this module has caused came from an implicit weight or
tier floor nobody had written down summing past a threshold nobody had
read. A switch to turn that off is worse than not inventing it: a
default every deployment has to disable was not a default. An explicit
rule states what it does; a score states it only once you reconstruct
the arithmetic.

`BotShieldInteractiveArmMs` withholds the interactive tier's checkbox
for this many milliseconds after load (0 shows it immediately). The
widget renders at full size with a spinner meanwhile, so nothing shifts
and there is no dead control to click — a visible control that swallows
clicks teaches people the page is broken, and it is the confident fast
clickers who hit it.

The delay is not the point; the fact that the delay is *ours* is. A
bare time floor is a guess about how fast people are and it charges the
quick ones. Withholding the control makes "window + reaction" a fact,
so the server can floor at least the window for free. It also yields a
sharper signal: a person clicks hundreds of ms after the reveal, a
poller within a few, and that gap is reported as an `attest:` failure.
`100` is a good production value — below the threshold where a delay
registers at all, while the gap signal is unaffected by the shrink.

`BotShieldInteractiveMinSolveMs` refuses an interactive-tier solve that
returns sooner than this after the challenge was issued (0 disables).
The clock is entirely the server's — the issue stamp rides in the
bootstrap HMAC — so a client cannot shorten it.

Measured, not guessed. A warmed headless browser needed 177ms to load,
render and land a trusted click, and 239ms cold; the first version of
this floor was 150ms, which sat under both and therefore cost an
attacker nothing. Note what it does and does not do: it will not stop a
bot that sleeps, and a *cold* browser is slow enough to clear any
sane floor on its own. What it does is make waiting mandatory and
server-observed, so the delay is real wall time per request rather than
a field the client fills in. Watch `reason=solve_too_fast` for false
positives.

`BotShieldEndpointPrefix` is the URL prefix for module-owned
handlers (`/botshield/captcha-verify`, `/botshield/metrics`,
`/botshield/embedded.js`, `/botshield/safeguard-info` etc.).

Under that prefix, `<prefix>/preview` is an index of the pages a client
can be shown, rendered from the live templates rather than from copies
that drift:

| Route | Shows |
|---|---|
| `<prefix>/preview/noninteractive` | The self-solving widget, pinned mid-check (the preview's proof-of-work is set unsolvable so it cannot complete and navigate away) |
| `<prefix>/preview/interactive` | The same widget with a live checkbox waiting for a click |
| `<prefix>/preview/safeguard` | The anti-loop explainer, also served at `<prefix>/safeguard-info`, which is the URL clients actually reach |

They mint nothing and are useful for design review and for seeing what
a visitor sees without having to trip a challenge yourself. They serve
`403`, like the real interstitials, because the same code path renders
them.
Change it if it collides with real app routes.

## Tier thresholds and forgiveness

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldScoreNonInteractive` | `N` | `20` |
| `BotShieldScoreInteractive` | `N` | `50` |
| `BotShieldScoreCaptcha` | `N` | `80` |
| `BotShieldForgivenessNonInteractive` | `N` | `10` |
| `BotShieldForgivenessInteractive` | `N` | `25` |
| `BotShieldForgivenessCaptcha` | `N` | `50` |
| `BotShieldForgivenessCapPerHour` | `N` | `200` (0 disables) |

Tier dispatch ladder:

- `score < BotShieldScoreNonInteractive` → pass
- `BotShieldScoreNonInteractive ≤ score < BotShieldScoreInteractive` → silent
- `BotShieldScoreInteractive ≤ score < BotShieldScoreCaptcha` → form
- `BotShieldScoreCaptcha ≤ score` → captcha (or form if no provider)

See [site model](site-model.md) for the full scoring
discussion.

`BotShieldForgivenessCapPerHour` caps total cookie-side
forgiveness in any rolling 60-minute window. Default 200 ≈ 4–8
nochallenge outcomes worth of credit. Lower for stricter farming
resistance; 0 disables (legacy behavior).

## Silent-tier dispatch

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldNonInteractiveMode` | `interstitial\|embedded` | `interstitial` |

`interstitial` (the default) serves a no-click splash page that
auto-submits a SHA-256 PoW on load — the legacy noninteractive-tier
behavior. `embedded` instead hands off to the site-included
`/botshield/embedded.js` wrapper: the page serves DECLINED (real
content) and the wrapper does the PoW in a Web Worker, then POSTs
the result back to `/botshield/embedded-verify` to mint
`_bs_session` on the next request. Embedded mode trades a brief
window where the cookie isn't yet on the client (the very first
request goes through unverified) for a zero-interstitial UX.

Embedded mode requires you to include the wrapper
script in your page templates; without it, the request still
serves the real content but no cookie ever lands.

## Widget customization

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldPromptText` | `"text"` | `I'm not a robot` |
| `BotShieldLogoFile` | `/path.svg` | embedded Guardian |
| `BotShieldLogoLabel` | `"text"` | `botshield` |
| `BotShieldShowLogo` | `on\|off` | `on` |
| `BotShieldShowLabel` | `on\|off` | `on` |
| `BotShieldShowBox` | `on\|off` | `on` |
| `BotShieldHelp` | `off\|on\|button` | `button` |
| `BotShieldHelpFile` | `/path.html` | built-in text |
| `BotShieldChallengeFile` | `/path.html` | built-in shell |

`BotShieldChallengeFile` replaces the full HTML page that wraps the
widget; the file must contain `<!-- BOTSHIELD -->` where the widget
is spliced in. Other widget directives still apply to the widget
block itself. Max 256 KiB.

Logo and help files are 64 KiB max each. Logo content is served
inline as `<img>`-equivalent SVG; help content is rendered as
trusted HTML (no escaping — you own sanitization).

`BotShieldShowLogo/Label/Box` strip widget chrome down to a lone
checkbox if the surrounding page styles its own chrome. When label
is hidden it moves to the button's `aria-label` — accessibility is
preserved.

## Captcha tier

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldCaptchaProvider` | `<name>` | unset |
| `BotShieldCaptchaSiteKey` | `"key"` | unset |
| `BotShieldCaptchaSecretFile` | `/path` | unset |
| `BotShieldCaptchaTimeout` | `N` (ms) | `1000` (100..5000) |
| `BotShieldCaptchaConnectTimeout` | `N` (ms) | `250` (50..5000) |
| `BotShieldRecaptchaV3MinScore` | `0..1` | `0.5` |
| `BotShieldCaptchaExpectedHostname` | `"name"` or `""` | server hostname |
| `BotShieldCaptchaExpectedAction` | `"action"` or `""` | `botshield` |
| `BotShieldCaptchaCABundle` | `/path` | libcurl default |
| `BotShieldFormCaptcha` | `on\|off` | `off` |

Provider names: `turnstile`, `hcaptcha`, `recaptcha-v2`,
`recaptcha-v3`, `friendly`, `geetest`. See
[captcha](captcha.md) for the wire-protocol details.

`BotShieldCaptchaTimeout` is the total siteverify HTTP budget; on
timeout the verify path fails open. `BotShieldCaptchaConnectTimeout`
is the connect phase only — tighter, raised on links with
transient packet loss.

`BotShieldRecaptchaV3MinScore` only matters for `recaptcha-v3`.
Reject verifications below this score even on `success: true`.

`BotShieldCaptchaExpectedHostname` / `Action`: empty string
disables the check; unset uses defaults (`server_hostname` /
`"botshield"`). GeeTest binds host/action via HMAC and doesn't
return them in the response, so these are no-ops for that
provider.

`BotShieldFormCaptcha` intercepts POSTs and validates the
captcha token inline rather than via interstitial. Requires a
captcha provider configured on the same scope.

## Captcha-verify endpoint hardening

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldCaptchaRateLimit` | `N` (per IP per minute) | `30` (0..1000) | server / vhost |
| `BotShieldCaptchaMaxInFlight` | `N` (global concurrent) | `64` (1..1024) | server only |

Both reject before any libcurl call. `RateLimit` returns 429 with
Retry-After; `MaxInFlight` returns 503. 0 on `RateLimit` disables.

## SHM sizing and persistence

All directives in this section are **server scope only**. Inside
`<VirtualHost>` they emit a NOTICE and are ignored.

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldShmSize` | `<size>` (`128K..256M`) | `16M` |
| `BotShieldFlaggedIPCapacity` | `N` | `50000` (1024..1000000) |
| `BotShieldIPv6PrefixLen` | `N` (0..128) | `64` |
| `BotShieldBloomIPs` | `N` | `1000000` (1000..10000000) |
| `BotShieldBloomWindow` | `N` (sec) | `604800` (3600..2592000) |
| `BotShieldDataDir` | `/path` | `/var/lib/botshield` |
| `BotShieldDbStatsFile` | `/path` | `/run/botshield/db-load.stats` |
| `BotShieldFpmStatsFile` | `/path` | `/run/botshield/fpm-load.stats` |
| `BotShieldStateFile` | `/path` | `<datadir>/state.bin` |
| `BotShieldStateSaveInterval` | `N` (sec) | `300` (0=shutdown-only) |
| `BotShieldRateLimitEscalateCapacity` | `N` | `50000` |
| `BotShieldSafeguardCapacity` | `N` | `50000` |
| `BotShieldEmbeddedNonceCapacity` | `N` | `32768` (1024..1048576) |

`BotShieldShmSize` is the total budget for the flagged-IP / strike
/ safeguard tables and the Bloom buffers.
`BotShieldFlaggedIPCapacity` etc. size individual tables within
that budget — the headroom watchdog will flag if the segment is
underprovisioned.

`BotShieldIPv6PrefixLen` masks IPv6 client IPs before keying the
SHM tables. Default `/64` is per-subscriber for typical ISP
allocations; tighter values (`/56`, `/48`) flag larger blocks of
addresses sharing reputation.

`BotShieldStateFile` gives crash-durable persistence to the flagged-IP
table, the Bloom filters, and the metrics counters and dashboard bucket
rings. Rate-limit counters are deliberately excluded — see
[Deployment](deployment.md). The periodic save requires `mod_watchdog`;
the graceful-shutdown save runs regardless. State format mismatches on
load reject the file with a NOTICE and start fresh — never a startup
failure.

**It defaults** to `<BotShieldDataDir>/state.bin` wherever the module is
enabled on any vhost. Without a state file every restart — including
one triggered by logrotate — silently empties the flagged-IP table, the
Bloom filters and every dashboard counter, and nothing in the output
says so. That is a default that enables no enforcement and changes no
decision; it only stops the module forgetting what it already learned.

### `BotShieldDataDir` and running two instances

`BotShieldDataDir` is the one directive a second httpd instance on the
same host has to set. Everything the module owns on disk lives in it:

| File | What it is |
|---|---|
| `secret` | the auto-generated cookie-signing key |
| `state.bin` | flagged-IP table, Bloom filters, counters |

Both default into `/var/lib/botshield`, so two instances that leave it
alone share both. Sharing the state file loses reputation data;
**sharing the secret is worse**, because whichever instance writes it
last invalidates every cookie the other has issued. Give the second one
its own:

```apache
BotShieldDataDir /var/lib/botshield/instance2
```

The directory is created at startup — during post-config, the one
moment the module runs as root — and chowned to the Apache user, which
is required rather than tidy: the periodic state save runs in a child
after the privilege drop, while the shutdown save runs in the root
parent. It is created recursively, so nesting under the default works
with the parent absent. If it cannot be created the module logs a
NOTICE and starts cold; a convenience default is never a reason to
refuse to start.

Deriving a per-instance name automatically was tried and rejected.
`ServerRoot` and `DefaultRuntimeDir` are both unusable: instances
routinely share a `ServerRoot`, and the runtime dir is ephemeral and
reset at boot. The listen set does work, being the one thing the OS
forces two instances to differ on, but it changes whenever an operator
edits `Listen`, which would rename the files and start that instance
cold. A default that quietly moves is worse than one you declare.

The two stats paths default to what the sidecars in `tools/` publish:
`botshield-dbmon.service` passes
`--state-file /run/botshield/db-load.state` and the monitor derives its
`.stats` companion from that name, so the two halves are one shipped
convention. Installing the units is therefore enough to light up the
dashboard's load graph, with no directive. A missing file is the normal
case for a deployment without the sidecars and costs one failed open
per watchdog tick; the graph simply stays empty.

Unlike `BotShieldDataDir` these are read-only and operator-published,
so two instances sharing them is correct — they are reading the same
host's telemetry.

### These are all server scope, and enforced

Every directive in the table above is **rejected inside
`<VirtualHost>`**, with an error naming the directive. They are
resolved once from the main server: the SHM segment is sized and
attached before vhosts merge, and the load watchdog is registered
against the main `server_rec`. A copy on a vhost is parsed and then
never read.

This used to be a startup NOTICE, which was not enough. The failure it
produces is invisible in the shape operators actually check — the
config parses, configtest is green, httpd starts, and the directive
simply does nothing. `BotShieldDbStatsFile` in a vhost left the
dashboard reporting "no monitor" behind a clean configtest. `RSRC_CONF`
permits vhost context, so Apache will not catch it; the module has to.

## UA classification and allow list

Each request gets one User-Agent classification, computed once and
cached for every downstream consumer. It composes four passes:
real-browser templates, the knownbot directory, verified-bot IP
cross-check, and a heuristic scan for bot-shaped UAs matching
nothing else.

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldClassify` | `on\|off`, or `[all\|none] [+/-<pass>]...` | all four passes on | server / vhost |
| `BotShieldAllowBot` | `<name> <ua-pattern> [<target>]` | builtin only | server / vhost |
| `BotShieldAllowRangesRefreshInterval` | `N` (sec, 0..86400) | `0` (disabled) | server / vhost |
| `BotShieldBotDirectory` | `/path` (TSV) | unset (compiled-in baseline) | server / vhost |
| `BotShieldBotDirectoryRefreshInterval` | `N` (sec) | `300` (0=disabled) | server / vhost |
| `BotShieldBrowserTemplates` | `/path` (text) | unset (compiled-in baseline) | server / vhost |
| `BotShieldBrowserTemplatesRefreshInterval` | `N` (sec) | `300` (0=disabled) | server / vhost |

`BotShieldClassify` toggles individual passes — `browsers`,
`known-bots`, `verified-bots`, `unknown-bots`. Mixing the two
grammars is a config-time error:

```apache
BotShieldClassify Off                   # standalone form, one token
BotShieldClassify All -verified-bots    # compositional form
BotShieldClassify None +browsers        # start from nothing, add back
```

Each disabled pass has a fail-safe rather than a silent behavior
change: `-browsers` treats every UA as a browser for robots.txt
wildcard purposes; `-known-bots` skips the directory walk, so no bot
slug reaches the log; `-verified-bots` skips the IP cross-check and
matched UAs degrade to knownbot, earning neither verified-bot credit
nor fake-bot penalty (the intended response to stale CIDR data);
`-unknown-bots` skips the bot-token substring scan.

`BotShieldAllowBot` registers a UA pattern + IP-range pair. The third
arg is a path to a CIDR file, a single CIDR, comma-separated inline
CIDRs, or `*` alone for UA-only matching (logged as
`knownbot:<name>`, score 0); omit it for
`/var/lib/botshield/bots/<name>.txt`. A `<name>` matching a bundled
built-in (`googlebot`, `bingbot`, `applebot`, `googleother`,
`siteimprove`) replaces that built-in. See
[policy](policy.md#allow-list-verified-crawlers) for the
verified / fake / unverified outcomes.

`BotShieldAllowRangesRefreshInterval` re-stats the verified-bot CIDR
files (`<name>.txt` plus an operator sidecar `<base>.local.txt`) and
atomic-swaps a rebuilt range set on any mtime change. The sidecar is
the supported seam for scanner IPs absent from a vendor's public
feed. Recommended 60-300 when enabled; `0` keeps the config-time load
and needs a graceful restart to pick up edits.

The two data-source pairs override their compiled-in baselines
without a rebuild — refresh the files with
`services/refresh/botshield-refresh.py directory` and
`services/refresh/botshield-refresh.py user-agents`, and the watchdog re-parses on
mtime change. If a file disappears or fails to parse, lookups fall
back to the baseline codegenned into the `.so` at build time.
`BotShieldBotDirectory` is TSV (`pattern|slug|category|followsRobotsTxt`,
`#` comments); `BotShieldBrowserTemplates` is one normalized UA
template per line (runs of `[0-9._]+` replaced by `X`).

## Rate limit

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldRateLimit` | `<name> [budget=N] [per=U] [ua=...] [ipspec=...] [mode=...]` (or legacy `<name> <budget> <per> <ua-pattern> <ipspec> [mode=observe]`) | none |
| `BotShieldBotRateLimit` | `off`, or `<target> <delay-sec>`, or `<target> <budget> <per>` | none |
| `BotShieldRateLimitEscalate` | `<rate-rule> <strikes> <per> [status=N] [ttl=N]` | none |

### Alternation on `ua=`

`ua=` accepts a comma-separated list of `@selectors`, matching if any
one does:

```apache
BotShieldRule api-bot path="/api/*" \
    ua=@search,@ai-input,@ai-train,@monitor \
    status=403 ttl=0 log=api-bot
```

That replaces four rules identical but for a single token. Expanded at
parse time into one entry per alternative — this family is strict
first-match-wins, so N adjacent entries differing only on the UA axis
and carrying identical actions are exactly equivalent to one entry with
an OR. Copies take a `#N` name internally; the decision log is
unaffected, since it reports the action's `log=` tag, which every copy
shares.

**Only `@selectors` split.** A bare substring pattern is passed through
untouched, because a User-Agent legitimately contains commas —
`Mozilla/5.0 (X11; Linux x86_64)` is full of them — and splitting those
would silently change what an existing rule matches.

Match keys: `ua=<substring>`, `ua=@<botgroup>`, or `ua=""` (no/empty
User-Agent) for the UA gate
(`*` or omit for any UA); `ipspec=<spec>` for the IP gate (CIDR file
path, comma-separated inline CIDRs, `*` or omit for any IP). Both
axes can't be wildcard — that's rejected at config time.

Rate keys: `budget=N` (required) and `per=<sec|min|hour>` (required;
also accepts `s`/`m`/`h`). Plain integer for `per` is rejected.

The legacy 5-arg positional form is still accepted (form is detected
by sniffing for `=` in the args); no deprecation warning yet.

`BotShieldBotRateLimit` caps volume per knownbot slug rather than
per cohort. `<target>` is a bot slug or UA substring resolved against
the bot directory, `@<botgroup>` (`search`, `ai-input`, `ai-train`,
`monitor`), or `*`. The two-arg form is Crawl-delay shaped — one
request per `<delay-sec>`, where `0` admits everything. Precedence is
specific > `@botgroup` > `*`.

`*` pre-allocates one counter per directory slug not covered by a
more specific rule, so each unmatched bot gets its own budget rather
than sharing one; three reserved aggregate slots at the same budget
cover unknownbot, fake-bot, and slugs a mid-run directory refresh
added after startup. Because the slug universe is bounded by the
directory, every slot is allocated at config time — request time is a
single hash probe. Over-budget returns 429 + `Retry-After` with reason
`botrate:<slug>`. Robots.txt `Crawl-delay` groups feed the same
machinery.

### Nothing is rate limited until you say so

There is no default. An unset `BotShieldBotRateLimit` rate-limits
nothing, the same as every other policy family in this module.

It used to work the other way. Enabling the module with no
`BotShieldBotRateLimit` anywhere synthesised a wildcard of one request
per second per directory slug, and the synthesised entry carried no
mode, which means enforce. The result was real 429s to traffic nobody
had decided to throttle, including named crawlers arriving with a
published identity. It was invisible twice over: absent from the config
because nobody wrote it, and absent from the policy dump because the
dump only knew about directives. On the deployment this was built for
it was returning 429s to Applebot, GPTBot and Claude-User, and the way
it came to light was reading a decision log, which is not how an
operator should have to discover what their server is enforcing.

Two sources now, both of which an operator can point at:

```apache
BotShieldBotRateLimit * 1 sec mode=observe   # count, refuse nobody
BotShieldBotRateLimit @ai-train 10 min       # a real limit
BotShieldBotRateLimit off                    # disable the subsystem
```

and a `Crawl-delay` in a configured robots.txt, which feeds the same
machinery.

`off` declines robots.txt `Crawl-delay` groups, which is the only
implicit source left now that the default is gone. Rules written in the
config still apply: `off` never meant "ignore what I explicitly asked
for". It exists because a robots.txt is frequently maintained by
somebody other than whoever configures this module, and an operator has
to be able to refuse a `Crawl-delay` appearing in a file they do not
own.

`httpd -t -D DUMP_BOTSHIELD_POLICY` lists every directive-derived entry
with its budget, window, scope, and whether it enforces or observes.
Crawl-delay entries register after that dump runs, so they appear in
its robots.txt section rather than this one.

## Robots.txt enforcement

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldRobotsTxt` | `/path` | unset |
| `BotShieldRobotsRefreshInterval` | `N` (sec) | `60` (0=disabled) |
| `BotShieldRobotsWildcardScope` | `heuristic\|strict\|off` | `heuristic` |
| `BotShieldRobotsMode` | `enforce\|observe` | `enforce` |

`BotShieldRobotsMode observe` records what a `Disallow` would have done
without returning 403 — the way to see what enforcing a robots.txt you
did not write would cost before you enforce it.

See [policy](policy.md#robots-txt-enforcement) for the matcher
semantics and refresh model.

## Triggers

| Directive | Predicate args | Action keys |
|---|---|---|
| `BotShieldRequestTrigger` | `<name>` + any of `path=<glob>` `query=<glob>` `cookies=none\|any\|session` `ua=<substring>\|@<botgroup>\|""` `ipspec=<spec>` — ANDed, at least one required | `status=`, `redirect=`, `log=`, `accesslog=`, `flag=`, `ttl=`, `burn=`, `penalty=`, `mode=` (no `credit=`) |
| `BotShieldCookieTrigger` | `<name> <pred>` (see policy page) | `status=`, `redirect=`, `log=`, `accesslog=`, `flag=`, `ttl=`, `burn=`, `penalty=`, `credit=`, `mode=` |
| `BotShieldEnvTrigger` | `<name> <env-pred>` (see policy page) | `status=`, `log=`, `accesslog=`, `flag=`, `ttl=`, `burn=`, `penalty=`, `credit=`, `mode=` (no `redirect=`) |
| `BotShieldFeedbackTrigger` | `<event>` | `flag=`, `ttl=`, `log=`, `accesslog=`, `mode=` |
| `BotShieldLoadTrigger` | `<name> state=<n>\|state>=<n>` | `status=`, `log=`, `accesslog=`, `penalty=`, `mode=` (no `redirect=`, `flag=`, `ttl=`, `burn=`) |
| `BotShieldSessionCookieName` | `<name>` (single arg, repeatable) | n/a (feeds cookies=session predicate) |

See [policy](policy.md#triggers-predicate-action-engine)
for full predicate vocabulary and family-by-family semantics.

`BotShieldSessionCookieName` registers a name that the
`cookies=session` cookietrigger predicate considers a session
cookie. Repeatable; each call appends.

### `accesslog=off` — keep a request out of the access log

`log=<tag>` names a tag that rides the decision line as `tag="<x>"`
for fail2ban handoff. `accesslog=off` is separate and independent: it
suppresses the access-log line for a matching request.

They compose, which is the point — a scanner probe usually wants both:

```apache
BotShieldRequestTrigger env-probe path="/.env" status=403 \
    log=scanner-probe accesslog=off
```

(An earlier development build overloaded `log=off` for this. That form is
now rejected at config time with a pointer here, rather than silently
being treated as a tag named "off" and losing the suppression.)

The mechanism is Apache's own. `log_transaction` is a `RUN_ALL` hook
declared with `(OK, DECLINED)`, so a hook returning any other value
breaks the chain. The module's `bs_propagate_decision_env` hook runs at
`APR_HOOK_FIRST` — ahead of mod_log_config — and returns `DONE` when the
marker is set. Nothing downstream ever formats or writes a line.

Three consequences to understand before using it:

- **A `CustomLog`-based decision log is suppressed too.** mod_log_config
  services every `CustomLog` from a single hook function, so there is no
  way to keep one and starve another. `BotShieldDecisionLog` is written
  by the module itself and is **unaffected**, as is the error-log line —
  pair the two and you get the useful split: flood traffic out of an
  archived access log, every decision still recorded in a
  separately-rotated detection log.
- **Third-party loggers are also skipped** if their `log_transaction`
  hook is ordered after this module's (audit logging, analytics).
- **It never applies under `mode=observe` or `BotShieldEnabled LogOnly`.**
  The action engine returns before any side effect in that path, so a
  dry run always leaves its evidence.

If you want a request dropped from one specific `CustomLog` while
keeping the others, this is the wrong tool — use mod_log_config's own
conditional form,
which can key off the decision the module already published to the
request environment:

```apache
CustomLog logs/access.log combined "expr=%{reqenv:BS_OUTCOME} != 'block'"
```

That is the right tool when you only want to thin one log.

### `BotShieldRequestTrigger` — match on any request property

Every match key is optional and they **AND** together; at least one is
required. A rule with no condition would match every request, which is
what `BotShieldTrigger` in an Apache scope is for, so the parser rejects
it.

| Key | Matches against | Notes |
|---|---|---|
| `path=<glob>` | `r->uri` — path only, **no** query string | must start with `/`, ≤256 chars |
| `query=<glob>` | the query string alone | e.g. `query="*return=*"` |
| `cookies=none\|any\|session` | the parsed `Cookie` header | bulk forms only |
| `ua=<substring>\|@<botgroup>[,@<botgroup>...]\|""` | User-Agent | `*` means "any", same as omitting. `ua=""` matches a request with **no** User-Agent header, or one present but empty — absence is not a substring, so it needs its own spelling. A **comma list of `@selectors`** matches if any of them does. |
| `ipspec=<spec>` | client IP | `*`, a CIDR list, or a file path |

Globs take `*` wildcards and a trailing `$` anchor. Named-cookie
predicates (`cookie=<n>`, `cookie=<n>~<substr>`, `bs-cookie=<state>`)
stay on [`BotShieldCookieTrigger`](#triggers) — that vocabulary does not
compress into one key.

**What a matching rule can do.** Four outcomes, set by the action keys:

| Intent | Keys | Effect |
|---|---|---|
| Block | `status=403` (family default) | Refused from the policy walk. No scoring, no cookie mint, no render. |
| Challenge | `status=nochallenge tier=noninteractive` | Invisible auto-submitting check. `tier=interactive` for the visible one. |
| Captcha | `status=nochallenge tier=captcha` | The configured provider's widget. |
| Score only | `status=nochallenge penalty=<n>` | Adds to the score and lets normal thresholds decide. |

`tier=` and `penalty=` both require `status=nochallenge`, because a concrete
status short-circuits the request before any tier is chosen. `tier=`
accepts `pass`, `noninteractive`, `interactive` and `captcha`, and
composes by MAX with the score-derived tier and any flag tier floor —
it raises the floor, it never downgrades.

`tier=` sets that floor on **this request only**. That is the
difference from `flag=` plus a `BotShieldFlagTrigger` tier floor, which
writes per-IP state with a TTL: a client that solves the challenge
would keep being re-challenged for the life of a flag it has no way to
clear. Use `flag=` when you want the reputation to persist, `tier=`
when you want to challenge the request in front of you.

> A bare `status=nochallenge` — with neither `tier=` nor `penalty=` — keeps its
> original meaning of "record the match and decline out of the handler".
> That skips scoring entirely, so it will *disable* challenges the
> defaults would otherwise have raised on those requests. It is a
> logging-and-flagging form, not a no-op.

```apache
# cookieless crawler walking a login redirect chain: path AND query AND
# cookie-state, one cheap 403 from the policy walk, tagged for fail2ban
# and kept out of the access log
BotShieldRequestTrigger login-trap path="/login*" query="*return=*" \
    cookies=none status=403 log=login-trap accesslog=off

# no path condition at all — any URL carrying ?debug=1
BotShieldRequestTrigger debugparam query="*debug=1*" penalty=20

# no User-Agent at all. Absence is not a substring, so this is the one
# UA form the pattern match cannot express. Note ua="" is a restriction
# and ua=* is not: "*" (or omitting the key) means "any", which is why a
# rule carrying only ua=* is rejected as having no condition.
BotShieldRequestTrigger no-ua ua="" status=nochallenge tier=noninteractive log=no-ua
```

Because it fires from the policy walk it short-circuits **before**
scoring, so a `status=4xx` rule never renders a challenge and never
reaches PHP.

**Remembering a client is opt-in.** A rule fires, returns its status,
and forgets — unless you ask it to remember. There are two kinds of
memory and both default to doing nothing.

`flag=<name>` with `ttl=<seconds>` marks the **address**. Everything
sharing that address is marked with it, which is the point behind a
hosting range and the problem behind a residential NAT.

`burn=<seconds>` marks the **cookie session**. The mark travels inside
the cookie the client keeps handing back, so it catches the one browser
that actually tripped the rule and no one else sharing its address. A
client that throws cookies away escapes this entirely — and pays the
full challenge gate regardless, because it can never hold a solve
either, so it costs nothing that was not already being paid.

```apache
# the address, for an hour. Right when the source itself is what you
# distrust; wrong when it is a NAT with real users behind it.
<BotShieldRule env-probe>
    BotShieldPath    /.env
    BotShieldStatus  404
    BotShieldFlag    scanner_probe
    BotShieldTTL     3600
    BotShieldLog     env-probe
</BotShieldRule>

# the browser, for a day. The probe gets its 404 and a cookie carrying
# the mark; that session is refused from its next request onward, and
# the neighbours are untouched.
<BotShieldRule wp-probe>
    BotShieldPath    /wp-admin/*
    BotShieldStatus  404
    BotShieldBurn    86400
    BotShieldLog     wp-probe
</BotShieldRule>
```

> **This family used to flag by default**, `scanner_probe` for 3600 s,
> inherited from `BotShieldPathTrigger` where the target was a handful
> of scanners probing `/.env` and per-IP memory was worth having. It was
> the wrong default for high-cardinality traffic: at roughly one request
> per address the flag is never read again and it churns the
> 50,000-slot flagged-IP table. Worse, `scanner_probe` carries a
> compiled-in `tier_floor` of `interactive` that **overrides parked
> score thresholds**, so a rule written to block quietly began rendering
> interstitials to whoever shared that address next — with nothing in
> the config saying so.
>
> **Migrating:** a rule written before 2026-09-05 that relied on the
> default now flags nothing. Add `BotShieldFlag scanner_probe` and
> `BotShieldTTL 3600` to keep the old behaviour. `BotShieldTTL 0`,
> which used to be how you switched the default off, is now what the
> default already is and can be deleted.

#### Migrating from `BotShieldPathTrigger`

`BotShieldPathTrigger` was renamed on 2026-08-01 and its path glob moved
from a positional argument to the `path=` key. The old name had stopped
being accurate when the family gained `ua=`/`ipspec=`; `query=`,
`cookies=` and `exists=` made "path" one dimension out of six. Making
path a key is also what allows a rule with no path condition at all.

**The old name was removed on 2026-08-10** and now fails with Apache's
`Invalid command` at config time — loudly, at startup, not silently at
runtime:

```apache
# before
BotShieldPathTrigger blocked "/wp-admin/*" status=403
# after
BotShieldRequestTrigger blocked path="/wp-admin/*" status=403
```

A note on quoting: values are unquoted by the module, so
`path="/login*"` and `path=/login*` behave identically. Apache's
`TAKE_ARGV` tokenizer only strips quotes that begin a token, so without
this a quoted `key="value"` would retain its quotes and silently never
match.

## Per-scope triggers

| Directive | Syntax | Scope |
|---|---|---|
| `BotShieldTrigger` | `[reset] [status=N\|pass] [redirect=URL] [log=tag] [accesslog=on\|off] [flag=NAME] [ttl=N] [penalty=N] [credit=N] [mode=enforce\|observe]` | server / vhost / Directory / Location / LocationMatch / Files / If |

The Apache scope the directive lives in IS the predicate; no path
glob argument. Multiple `BotShieldTrigger` lines in one scope
each append a separate action; they all fire on a pass, the first
non-pass status short-circuits. `reset` (no other args) drops
inherited triggers from outer scopes and clears earlier same-scope
entries.

This is the directive that replaces the legacy `BotShieldFlagIP`
— the equivalent today is `BotShieldTrigger flag=<name> ttl=<sec>`.

## Flag triggers

| Directive | Syntax |
|---|---|
| `BotShieldFlagTrigger` | `<flag> [reset] [action=<verb> args...] [mode=observe]` |

Action verbs: `action=score add=N` (signed N -1000..1000),
`action=tier_floor min=<tier>` (raise effective tier; tier is one
of `pass`/`noninteractive`/`interactive`/`captcha`). The `reset` keyword clears
all earlier triggers (compiled-in defaults + prior
declarations) for the named flag at post-config time.

**A `tier_floor` bypasses your score thresholds.** It is MAX'd in
*after* the score-to-tier decision, so it does not consult
`BotShieldScoreNonInteractive`/`Interactive`/`Captcha` at all. Four of the compiled-in
defaults carry one — `honeypot_hit` and `fake_bot` (captcha),
`scanner_probe` (form), `pow_fail_streak` (silent) — so an IP carrying
any of them is challenged even in a scope whose thresholds are parked to
disable challenges entirely. To make a scope genuinely block-only, reset
the floors and keep the scores:

```apache
BotShieldFlagTrigger honeypot_hit    reset action=score add=60
BotShieldFlagTrigger fake_bot        reset action=score add=80
BotShieldFlagTrigger scanner_probe   reset action=score add=50
BotShieldFlagTrigger pow_fail_streak reset action=score add=30
```

**A flag score at or above `BotShieldScoreNonInteractive` is an unbreakable
loop, not a challenge.** The replacement scores above fix the
`tier_floor` bypass but leave a second trap, and `add=50` against the
default silent threshold of `20` walks straight into it. Solving does
not clear a flag. Forgiveness reduces the score carried *in the
cookie*, and then `bs_apply_flag_triggers` re-adds the flag's score on
the very next request — `botshield.c` says so at the forgiveness site:

> No floor on the forgiven score even on flagged cookies. Flag effects
> are re-applied at request time [...] so a forgiven-to-zero score on a
> flagged cookie is simply re-raised on the next request.

So a flagged client is re-challenged forever however many times it
solves. In production this looked like `pow_ok` succeeding roughly once
a second, each success followed immediately by another
`outcome=challenged` carrying `cookie=solved` and
`forgive-capped:0/10` — the hourly forgiveness cap exhausted by the
loop it could not escape. The affected user had tripped
`scanner_probe` while filing a support ticket about being blocked: the
attachment upload posts a negative ticket id, which reads as probing.

Keep flag scores **below** `BotShieldScoreNonInteractive` unless you intend the
flag alone to challenge indefinitely. A flag worth less than the
threshold still contributes toward a challenge in combination with
other signals, which is usually what was meant:

```apache
# with the default BotShieldScoreNonInteractive of 20
BotShieldFlagTrigger scanner_probe   reset action=score add=10
```

Setting `add=0` is worse than a low value: it discards the evidence
rather than de-weighting it. And note this trap is invisible in
testing that solves once — it only appears on the *second* request
after a solve.

Flag bits: `honeypot_hit`, `scanner_probe`, `fake_bot`,
`pow_fail_streak`, `app_verified_human`, `app_verified_session`,
`app_trust_signal`. See
[policy](policy.md#flag-trigger-family) for the starter
slate and override semantics.

## Heuristic triggers

| Directive | Syntax |
|---|---|
| `BotShieldHeuristicTrigger` | `<name>\|all [reset] [action=<verb> args...] [mode=observe]` |

Same action grammar as the flag family, but the predicate is a
built-in heuristic on the request itself rather than a flag bit. This
is the operator handle for retuning the built-in penalties — they are
not separate directives.

| Heuristic | Fires when | Default |
|---|---|---|
| `missingua` | User-Agent absent or empty | `score add=40` |
| `missingal` | Accept-Language absent | `score add=5` |
| `scraperua` | UA contains a known HTTP-library token | `score add=10` |
| `firstsightip` | Bloom-filter miss — genuinely new IP, arriving with no usable cookie | `score add=20` |
| `droppedcookie` | Bloom-known IP arriving with no usable cookie | `score add=25` |

`scraperua` is deliberately low. robots.txt tells undeclared clients
they may fetch anything outside the `Disallow` list at the published
`Crawl-delay`; a weight of 50 put an unrenderable checkbox in front of
`curl`, `wget` and `python-requests` instead — the module enforcing a
policy the site never published. At 10 it composes with other signals
rather than deciding on its own, and volume abuse is caught by the rate
limit, which is what the published policy actually promises.
`missingal` is 5 for the same reason: almost nothing scripted sends
`Accept-Language`.

`firstsightip` and `droppedcookie` are the two halves of one signal —
both fire unless the request carries a cookie that **proves a challenge
was solved**, differing on whether the IP is already in the Bloom filter.

A merely valid cookie is not enough. Under always-mint every client
receives a signature-valid cookie on its first request, so waiving these
two on validity alone would let a bot mint one, keep it, and permanently
suppress a penalty it never earned. The waiver requires solve evidence
(`passes_silent`, `passes_form`, or `passes_captcha`) in the
authenticated rep block — the same evidence the safeguard-clear path
requires. A real browser pays for this exactly once: it arrives with no
proof, scores `droppedcookie` into the noninteractive tier, clears it in one
auto-submitted round trip, and every later request carries proof. `firstsightip` sits at
exactly `BotShieldScoreNonInteractive`, so **an enabled scope challenges any
request with no session context by default**, with no rule to write.
That is usually what you want on a login or registration path, where the
check is invisible and a real browser clears it in one auto-submitted
round trip. Lower it if you enable BotShield site-wide and would rather
new visitors reach content without a check.

Action verbs are `action=score add=N` (signed, -1000..1000) and
`action=tier_floor min=<tier>`. `<name> reset` clears the compiled-in
default plus prior declarations for that one heuristic; `all reset`
wipes every entry so the slate can be rebuilt from zero.
`mode=observe` logs the match with an `:observe` suffix instead of
applying it.

A `droppedcookie` hit is ambiguous by design — private-browsing
resets and manual cookie clears look the same as evasion — so the
default penalty is deliberately mild.

## Safeguard

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldSafeguard` | `on\|off` | **`on`** | server / vhost |
| `BotShieldSafeguardThreshold` | `N` | `5` | server / vhost |
| `BotShieldSafeguardWindow` | `N` (sec) | `600` | server / vhost |
| `BotShieldSafeguardTTL` | `N` (sec) | `900` | server / vhost |
| `BotShieldSafeguardRedirectURL` | `<url>` | unset (uses built-in explainer) | server / vhost |

Challenge-loop suppression, **on by default** — only an explicit
`Off` disables it. A client that cannot solve the challenge (JS
disabled, a privacy extension, an old browser) would otherwise be
re-challenged forever with nothing in the logs shouting about it, and
that client is indistinguishable from a non-JS crawler. The redirect
resolves that without having to tell them apart: it is useful to a
human and useless to a crawler. The tripped client is **not** admitted
— it lands on an explainer, never on protected content, and its
flagged-IP entry survives.

When a client has been issued the
threshold number of challenges within the window without ever
returning a verified cookie, the next request gets a 302 redirect
to break the loop.

`BotShieldSafeguardRedirectURL` lets the operator point the
redirect at their own page (a status page, a help article, a
login flow). When unset, the module redirects to its built-in
explainer at `<BotShieldEndpointPrefix>/safeguard-info`. The
original URI is appended as `?return=<urlencoded path>` regardless
of which target is chosen, so the user can resume their journey
once the underlying problem is fixed. The return parameter is
validated for same-origin shape (must start with a single `/`,
no scheme, no double-slash) to prevent open-redirect abuse.

The built-in explainer page describes common reasons the
auto-check failed (JavaScript disabled, privacy extension,
browser version) and offers a Continue link back to the original
URL. It is auto-routed by the module — no `<Location>` carve-out
needed.

See [policy](policy.md#safeguard) and
[site model](site-model.md#tier-ladder) for the
behavior arc.

## Load-aware throttling

Sampling and hysteresis:

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldLoadStateFile` | `/path` | unset | server only |
| `BotShieldLoadRefreshInterval` | `N` (sec) | `1` | server only |
| `BotShieldLoadWarmThreshold` | `N` (% workers busy) | `65` | server only |
| `BotShieldLoadHotThreshold` | `N` (% workers busy) | `85` | server only |
| `BotShieldLatencyWarm` | `N` (ms) | `250` | server only |
| `BotShieldLatencyHot` | `N` (ms) | `1000` | server only |
| `BotShieldLoadAvgWarm` | `N` (per-CPU ratio) | `1.0` | server only |
| `BotShieldLoadAvgHot` | `N` (per-CPU ratio) | `1.5` | server only |
| `BotShieldDbStatsFile` | `/path` | `/run/botshield/db-load.stats` | server only |
| `BotShieldFpmStatsFile` | `/path` | `/run/botshield/fpm-load.stats` | server only |

`BotShieldLoadStateFile` points at an external single-word state
file (managed by an out-of-band collector) that overrides the
scoreboard sample. Useful when load decisions should key on a
metric Apache itself doesn't see (queue depth, downstream
saturation, etc.).

### Why the busy-worker ratio is often the wrong signal

`BotShieldLoadWarmThreshold` and `BotShieldLoadHotThreshold` are a
percentage of `MaxRequestWorkers`, which is only meaningful if that
setting reflects what the machine can actually serve. It frequently
does not. On a host running `MaxRequestWorkers 1024` against 6 cores,
four separate outages ran at 25-30 busy workers — the site returning
500s and taking half a minute per request — which is **2-3%**
utilisation. No threshold on that ratio can distinguish those outages
from an idle server.

`BotShieldLatencyWarm` / `BotShieldLatencyHot` exist for that case.
They compare the **mean request latency**, measured as a delta between
watchdog ticks, against a duration you choose. On the host above the
same outages moved this number from ~31ms to 29,000-36,000ms — roughly
a thousandfold, on the same data the worker ratio read as flat.

It is derived from Apache's own per-worker counters, the same ones
`mod_status` sums for `Total Duration` and `Total Accesses`, read
straight out of the scoreboard the watchdog already walks. No extra
sampling cost and no external process. Two consequences worth knowing:

- It requires `ExtendedStatus On`. Without it Apache never maintains
  those counters and the metric reports *unavailable* rather than
  zero — zero would mean "answering instantly", which is the opposite
  of what a missing measurement means.
- It averages over **all** requests, static files included, so a flood
  of cheap static hits dilutes it. It answers "is the server slow right
  now", not "is this endpoint slow".

`BotShieldDbStatsFile` reads key=value telemetry from an external
database monitor for the dashboard's graph. Database load reaches
policy through `BotShieldLoadStateFile`, not through this — the module
never links a database client, because blocking I/O has no place in
the watchdog and a database too sick to answer must not be able to
stall the code whose job is to shed load because the database is sick.

The trigger family that consumes the state lives under
`BotShieldLoadTrigger` (above). See
[policy](policy.md#load-triggers).

## Multi-vhost reputation

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldShareScope` | `<token>` | derived from ServerName |

Vhosts with the same token share one reputation namespace. See
[deployment](deployment.md#multi-vhost-reputation).

## Observability endpoint access

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldDashboardAccess` | `<addr\|cidr>...` \| `all` \| `none` | closed | server / vhost |
| `BotShieldMetricsAccess` | `<addr\|cidr>...` \| `all` \| `none` | closed | server / vhost |

Who may read each observability endpoint. **Each is closed until its own
directive names someone**, and a refused request gets 404, not 403, so a
scan cannot tell the endpoint exists.

```apache
BotShieldDashboardAccess 127.0.0.1 ::1
BotShieldMetricsAccess   127.0.0.1 ::1
```

One directive per endpoint, so opening one never opens the other. A
Prometheus scraper and an admin browser are rarely the same host:

```apache
BotShieldMetricsAccess   10.9.0.5
BotShieldDashboardAccess 10.1.0.0/16
```

The dashboard grant covers every page under `/dashboard/`. The router
matches the prefix rather than a list of pages, so a page added in a
later release is covered by config that already exists.

Directives accumulate, so keep one network per line with its reason next
to it. Two keywords stand in place of the whole list: `all` serves the
endpoint to everyone, and `none` closes it and refuses a grant inherited
from server scope. Neither can be combined with addresses; that is a
config-time error rather than a silent resolution, because these lists
get edited by commenting lines in and out and a leftover `all` above a
careful CIDR list should not quietly win.

Matching is on the same client address the module scores, so
`mod_remoteip` applies exactly as it does to Apache's own `Require ip`.

### Why this is not a `<Location>`

`Require ip` on these paths has a failure mode worth knowing. Each authz
denial writes an `AH01630` line to the error log, the dashboard
auto-refreshes every 30 seconds, and a fail2ban jail watching that log
counts five denials in two minutes as an attack. On a HubZero host the
shipped `apache-hz_access_denied` jail then bans the viewer at the
firewall for ten hours — off the whole site, not just the dashboard.
That happened on geodynamics.org on 2026-08-08.

These directives refuse inside the module and write nothing to the error
log, so there is nothing for a jail to count. Verified by probe: eight
refused dashboard requests produced zero error-log lines from the
module.

No `<Location>` block is needed to make these endpoints reachable. They
sit under the vhost's DocumentRoot as far as the directory walk is
concerned, so whatever grants the document root grants them, and the
module applies the ACL after that. A `Require all granted` written
specifically for them does nothing.

They deliberately stop at an IP list. Apache already has authentication
and authorization, they compose by wrapping the path in a `<Location>`,
and a second half-implementation inside this module would be the worse
of the two. The IP list is the part Apache cannot supply on the module's
behalf, because the module has to decide whether to serve the endpoint
at all. To add a password, compound the two — Apache decides whether the
request reaches the module, the module decides whether the endpoint is
served:

```apache
BotShieldDashboardAccess 10.1.0.0/16

<LocationMatch "^/botshield/dashboard">
    AuthType Basic
    AuthName "BotShield"
    AuthUserFile /etc/httpd/botshield.htpasswd
    Require valid-user
</LocationMatch>
```

Read the resolved lists back with `httpd -t -D DUMP_BOTSHIELD_POLICY`,
which prints one line per endpoint. A wrong allowlist is otherwise
discovered by being locked out of the page you would have used to
diagnose it.

Refused requests are recorded in the decision log as `outcome=observe`
with `reason="observe-denied:<surface>"`. The response is a 404 and the
access-log line is suppressed like every other hit on these endpoints,
so that line is the only trace a probe leaves.

## Decision log

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldDecisionLog` | `/path`, `logs/path`, or `"\|program"` | rotating log beside `ErrorLog` | server / vhost |
| `BotShieldAccessLog` | `on`, `off`, `suppress=<outcome,...>` | `on` | server / vhost / dir |

`BotShieldAccessLog` controls the *Apache* access-log line for requests
BotShield decided on, not this log. See
[observability](observability.md) for which outcomes are
suppressed by default and why.

A module-owned decision log, written directly from the decision path
instead of through mod_log_config:

```apache
BotShieldDecisionLog logs/botshield.log
BotShieldDecisionLog "|/usr/bin/rotatelogs /var/log/httpd/bs.%Y%m%d 86400"
```

Relative paths resolve against `ServerRoot`, exactly like `ErrorLog`.
A value beginning with `|` is a piped-log spec handed to Apache's own
`ap_open_piped_log`, so `rotatelogs` and friends work as they do for any
other Apache log.

### The default is already rotated

With no directive the module builds this itself:

```
|<sbindir>/rotatelogs -n 7 -L <dir>/botshield.log.current <dir>/botshield.log 100M
```

Both halves are deduced rather than hardcoded. `<sbindir>` comes from
`apxs -q SBINDIR` at build time, the same apxs that compiled the
module. `<dir>` is the directory holding the main server's `ErrorLog`,
so the decision log lands beside it.

Rotation is the default rather than a plain file because the fallback
is a file that grows without bound, and this log records every request
the access log suppresses. On this deployment that is 100 MB about
every 38 hours. An unbounded default is a disk-full incident with a
long fuse.

`ErrorLog` is the anchor for a reason found in testing. A fixed
`logs/botshield.log` resolves through `ServerRoot`, and two instances
sharing a `ServerRoot` then default to the *same file* — a test
instance's rotator opened production's decision log. Two `rotatelogs`
on one `-n` slot set truncate each other's slots, which is the exact
failure that ate a day of this log. Anchoring to `ErrorLog` means
instances that already log separately get separate decision logs; two
instances sharing an `ErrorLog` path would still collide, but their
error logs already do.

If `rotatelogs` is not present the default degrades to an unrotated
file and says so with a NOTICE. If it is present but fails to spawn,
the module warns and falls back to the same file rather than refusing
to start — a convenience default must never be why httpd will not come
up. A pipe *you* configured failing is still a hard error, because you
asked for it.

### Rotation and the path your monitoring reads

`rotatelogs -n N` cycles round-robin through `logfile`, `logfile.1` …
`logfile.N-1`. **Which file is current changes over the day**, and the
base name is the live one only until the first rotation. Anything that
reads the base name directly is a bug that hides itself: it returns
real, correctly formatted, *stale* data, which reads as a traffic
collapse rather than as a mistake.

Pass `-L` so a fixed path always hard-links to whichever file is open:

```apache
BotShieldDecisionLog "|/usr/sbin/rotatelogs -n 7 \
    -L /var/log/httpd/botshield.log.current \
    /var/log/httpd/botshield.log 100M"
```

Monitoring then reads `botshield.log.current` and never has to know
about the rotation. The link is re-pointed on each rotation, so a
reader that opens by path each time always lands on the live file.
Use `tail -F` (follow by name), not `tail -f`, which holds the old
inode across a rotation.

Timestamped names (`bs.%Y%m%d`) do not have this problem, because the
current name is derivable — but they also grow without bound, which is
what `-n` is for. `-L` is what makes `-n` safe to monitor.


Why it exists: a `CustomLog` cannot survive `accesslog=off`, because
mod_log_config serves every `CustomLog` from the single
`log_transaction` hook that `accesslog=off` breaks. An owned log is
independent of the access log, which is what lets you **rapid-rotate the
detection log and archive the access log separately**. It also records
boring passes at full fidelity with no `LogLevel` change.

One descriptor per vhost, opened at `post_config` before the children
fork; one write per line, no request-path locking. **If the log cannot
be opened, startup fails** — a decision log you asked for and did not
get is a silent blind spot.

Optional. Without it the authoritative record remains the error-log
`mod_botshield: decision ...` line, plus whatever `CustomLog` you wire
up. See [observability](observability.md#where-the-decision-line-goes)
for the line format and the trade-offs between all three routes.

## Log-only / staging mode

Folded into `BotShieldEnabled` (tri-state `on` / `off` /
`logonly`). See the [Core](#core) section above and the
[staging](staging.md) guide.

## App bridge

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldAppFeedback` | `on\|off` | `off` |
| `BotShieldAppFeedbackHeader` | `<header-name>` | `X-BotShield-Feedback` |
| `BotShieldAppClaims` | `on\|off` | `off` |
| `BotShieldAppIntegrationSecretFile` | `/path` | unset (required for either above) |

See [captcha](captcha.md#app-bridge) for the wire format
and security model.

## Where to next

- Conceptual model and scoring: [site model](site-model.md).
- Deployment topology and capacity: [deployment](deployment.md).
- Per-family policy semantics: [policy](policy.md).
- Captcha and app-bridge integration: [captcha](captcha.md).
- Decision log and metrics: [observability](observability.md).
