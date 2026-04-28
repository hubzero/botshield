# Directive reference

mod_botshield registers 78 directives at config time. This page is
the canonical operator-facing reference, grouped by family. The
underlying source-of-truth is `bs_cmds[]` in `src/botshield.c:139` —
operators tuning behavior should treat the source as authoritative
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
| `BotShieldEnabled` | `on\|off` | `off` |
| `BotShieldDebug` | `on\|off` | `off` |
| `BotShieldSecretFile` | `/path` | unset (required) |
| `BotShieldSecondarySecretFile` | `/path` | unset |
| `BotShieldAlgorithm` | `<name>` | unset (required) |
| `BotShieldCookieTTL` | `N` (sec) | `3600` (range 1..86400) |
| `BotShieldCookieDomain` | `".example.com"` | unset (host-only) |
| `BotShieldDifficulty` | `N` | `4` (range 1..16) |
| `BotShieldEndpointPrefix` | `/path` | `/botshield` |

`BotShieldEnabled` is the master gate. `BotShieldDebug` returns
`403 "Hello World"` for every request in scope — useful as a smoke
test that the hook is firing.

`BotShieldSecretFile` and `BotShieldAlgorithm` are required. The
module emits `503 X-Botshield: misconfigured` for any request
where both are not resolved on the scope. `BotShieldSecondarySecretFile`
is the verify-only secondary key for graceful rotation — see
[deployment](../deployment/index.html#secret-rotation).

`BotShieldAlgorithm` only `sha256-zeros` is built-in today;
`sha384-zeros`, `sha512-zeros`, `pbkdf2-sha256`, `argon2id` are
reserved registry slots that fail with a clear "not implemented"
diagnostic.

`BotShieldCookieDomain` adds a `Domain=` attribute to Set-Cookie so
reputation follows across subdomains. Default is host-only. When
HTTPS is in use AND no domain is set, the module emits the
`__Host-bs_verified` cookie name; otherwise the legacy
`_bs_verified`. Verify path checks both.

`BotShieldDifficulty` is the leading-hex-zeros count for the PoW.
Higher = more client work. 4 is ~100ms on a modern phone; 6 is
~3s; 8 is ~50s — don't go above 6 without a reason.

`BotShieldEndpointPrefix` is the URL prefix for module-owned
handlers (`/botshield/captcha-verify`, `/botshield/metrics`,
`/botshield/embedded.js` etc.). Change it if it collides with
real app routes.

## Tier thresholds and forgiveness

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldScoreSilent` | `N` | `20` |
| `BotShieldScoreHard` | `N` | `50` |
| `BotShieldScoreCaptcha` | `N` | `80` |
| `BotShieldForgivenessSilent` | `N` | `10` |
| `BotShieldForgivenessForm` | `N` | `25` |
| `BotShieldForgivenessCaptcha` | `N` | `50` |
| `BotShieldForgivenessCapPerHour` | `N` | `200` (0 disables) |

Tier dispatch ladder:

- `score < BotShieldScoreSilent` → pass
- `BotShieldScoreSilent ≤ score < BotShieldScoreHard` → silent
- `BotShieldScoreHard ≤ score < BotShieldScoreCaptcha` → form
- `BotShieldScoreCaptcha ≤ score` → captcha (or form if no provider)

See [operator model](../operator-model/index.html) for the full scoring
discussion.

`BotShieldForgivenessCapPerHour` (E15) caps total cookie-side
forgiveness in any rolling 60-minute window. Default 200 ≈ 4–8
challenge-passes worth of credit. Lower for stricter farming
resistance; 0 disables (legacy behavior).

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
trusted HTML (no escaping — operator owns sanitization).

`BotShieldShowLogo/Label/Box` strip widget chrome down to a lone
checkbox if the surrounding page styles its own chrome. When label
is hidden it moves to the button's `aria-label` — accessibility is
preserved.

## Captcha tier (M8)

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
[captcha](../captcha/index.html) for the wire-protocol details.

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

`BotShieldFormCaptcha` (E18) intercepts POSTs and validates the
captcha token inline rather than via interstitial. Requires a
captcha provider configured on the same scope.

## Captcha-verify endpoint hardening (M8.1)

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
| `BotShieldStateFile` | `/path` | unset (persistence off) |
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

`BotShieldStateFile` enables crash-durable persistence; the
periodic save requires `mod_watchdog`, the graceful-shutdown save
runs regardless. State format mismatches on load reject the file
with a NOTICE and start fresh — never a startup failure.

## Allow list (E1)

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldAllow` | `on\|off` | `off` | any |
| `BotShieldAllowBot` | `<name> <ua-pattern> [<target>]` | builtin only | server / vhost |

`BotShieldAllow` is the master gate for the allow-list family.

`BotShieldAllowBot` registers a UA pattern + IP-range pair. The
third arg is a path to a CIDR file, comma-separated inline CIDRs
(prefixed with `*,`), or `*` alone for UA-only matching. See
[policy](../policy/index.html#allow-list-e1-verified-crawlers) for the
verified / fake / unverified outcomes.

## Rate limit + block-path (E2.1, E9)

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldRateLimit` | `<name> <budget> <window-sec> <ua-pattern> <ipspec> [mode=observe]` | none |
| `BotShieldRateLimitEscalate` | `<rate-rule> <strikes> <per-sec> [status=N] [ttl=N]` | none |
| `BotShieldBlockPath` | `<name> <path-glob> <ua-pattern> <ipspec> [mode=observe]` | none |

Cohort: `<ua-pattern>` is a substring or `""`/`*` for any UA;
`<ipspec>` is a path to a CIDR file, comma-separated inline CIDRs,
or `*` for any IP. Both axes can't be wildcard — that's rejected
at config time.

`BotShieldRateLimitEscalate` upgrades repeated 429s on the same
client to a stickier status code — see
[policy](../policy/index.html#repeated-429-escalation-e9).

## Robots.txt enforcement (E2.2)

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldRobotsTxt` | `/path` | unset |
| `BotShieldRobotsRefreshInterval` | `N` (sec) | `60` (0=disabled) |
| `BotShieldRobotsWildcardScope` | `heuristic\|strict\|off` | `heuristic` |

See [policy](../policy/index.html#robotstxt-enforcement-e22) for the matcher
semantics and refresh model.

## Triggers (E3, E4, E6, E7.3, E11.2)

| Directive | Predicate args | Action keys |
|---|---|---|
| `BotShieldPathTrigger` | `<name> <path-glob>` | `status=`, `redirect=`, `log=`, `flag=`, `ttl=`, `penalty=`, `mode=` (no `credit=`) |
| `BotShieldCookieTrigger` | `<name> <pred>` | `status=`, `redirect=`, `log=`, `flag=`, `ttl=`, `penalty=`, `credit=`, `mode=` |
| `BotShieldEnvTrigger` | `<name> env=<var>[=...]` | `status=`, `redirect=`, `log=`, `flag=`, `ttl=`, `penalty=`, `credit=`, `mode=` |
| `BotShieldFeedbackTrigger` | `<event>` | `flag=`, `ttl=`, `log=`, `mode=` |
| `BotShieldLoadTrigger` | `<name> state=<n>\|state>=<n>` | `status=`, `log=`, `penalty=`, `mode=` |
| `BotShieldSessionCookieName` | `<name>` (single arg, repeatable) | n/a (feeds cookies=session predicate) |

See [policy](../policy/index.html#triggers--predicate-action-engine-e3-e4-e6-e73-e112)
for full predicate vocabulary and family-by-family semantics.

`BotShieldSessionCookieName` registers a name that the
`cookies=session` cookie-trigger predicate considers a session
cookie. Repeatable; each call appends.

## Flag triggers (E14)

| Directive | Syntax |
|---|---|
| `BotShieldFlagIP` | `<bits> [ttl-sec]` |
| `BotShieldFlagTrigger` | `<rule-name> flag=<bit-name> action=<verb>=<value> [mode=observe]` |

Action verbs: `score add=N` (positive penalty / negative credit),
`tier_floor min=<tier>` (raise effective tier).

Flag bits: `honeypot_hit`, `scanner_probe`, `fake_bot`,
`pow_fail_streak`, `app_verified_human`, `app_verified_session`,
`app_trust_signal`. See
[policy](../policy/index.html#flag-trigger-family-e14) for compiled-in
defaults and override semantics.

## Safeguard (E10)

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldSafeguard` | `on\|off` | `on` | server / vhost |
| `BotShieldSafeguardThreshold` | `N` | `5` | server / vhost |
| `BotShieldSafeguardWindow` | `N` (sec) | `600` | server / vhost |
| `BotShieldSafeguardTTL` | `N` (sec) | `900` | server / vhost |

E10 challenge-loop suppression. See
[policy](../policy/index.html#safeguard-e10).

## Load-aware throttling (E11)

Sampling and hysteresis (E11.1):

| Directive | Syntax | Default | Scope |
|---|---|---|---|
| `BotShieldLoadStateFile` | `/path` | unset | server only |
| `BotShieldLoadRefreshInterval` | `N` (sec) | `1` | server only |
| `BotShieldLoadWarmThreshold` | `N` (% workers busy) | `70` | server only |
| `BotShieldLoadHotThreshold` | `N` (% workers busy) | `90` | server only |

`BotShieldLoadStateFile` points at an external single-word state
file (managed by an out-of-band collector) that overrides the
scoreboard sample. Useful when load decisions should key on a
metric Apache itself doesn't see (queue depth, downstream
saturation, etc.).

The trigger family that consumes the state lives under
`BotShieldLoadTrigger` (above). See
[policy](../policy/index.html#load-triggers-e112).

## Multi-vhost reputation (E13)

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldShareScope` | `<token>` | derived from ServerName |

Vhosts with the same token share one reputation namespace. See
[deployment](../deployment/index.html#multi-vhost-reputation).

## Shadow mode (E12)

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldShadowMode` | `on\|off` | unset (off) |

Tri-state: unset means "inherit from outer scope or off if no
outer scope". When on, every gating decision flips to observe-mode
regardless of per-rule setting. See [staging](../staging/index.html).

## App bridge (E5, E8.2)

| Directive | Syntax | Default |
|---|---|---|
| `BotShieldAppFeedback` | `on\|off` | `off` |
| `BotShieldAppFeedbackHeader` | `<header-name>` | `X-BotShield-Feedback` |
| `BotShieldAppClaims` | `on\|off` | `off` |
| `BotShieldAppIntegrationSecretFile` | `/path` | unset (required for either above) |

See [captcha](../captcha/index.html#app-bridge-e5--e82) for the wire format
and security model.

## Where to next

- Conceptual model and scoring: [operator model](../operator-model/index.html).
- Deployment topology and capacity: [deployment](../deployment/index.html).
- Per-family policy semantics: [policy](../policy/index.html).
- Captcha and app-bridge integration: [captcha](../captcha/index.html).
- Decision log and metrics: [observability](../observability/index.html).
