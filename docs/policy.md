# Policy

mod_botshield decides which requests deserve friction by composing
six policy families on top of the score-driven tier ladder. This
page covers each family's directive, predicate shape, side effects,
and where it sits in the runtime walk.

The runtime order (one pass per request, first short-circuit wins):

1. **Cookie triggers** — pre-handler state. Cookie family
   accumulates pass-with-credit across multiple matches.
2. **Env triggers** — predicate on Apache environment
   variables (`SetEnvIfExpr`, mod_rewrite `[E=…]`). First-match
   wins; gated on `ap_is_initial_req` so internal-redirect legs
   don't double-apply.
3. **Load triggers** — predicate on the global load_state
   sampled by the load watchdog.
4. **Path triggers** — predicate on the request URI.
5. **Block-path** — cohort + path-glob → 403.
6. **Robots.txt Disallow** — RFC 9309 matcher → 403.
7. **Rate-limit** — cohort + budget → 429 with Retry-After.
8. **Robots.txt Crawl-delay** — per-group rate cap.

The policy walk runs *before* the built-in heuristics, so a
matching policy rule can short-circuit the request even when the
client also has a valid `_bs_session` cookie. Allow-list checks
and built-in heuristics (missing-UA, missing-Accept-Language,
scraper-pattern UA) run after the policy walk if the walk
returns OK; flagtrigger effects are applied last, against the
IP's accumulated flag bitmap.

## Allow list — verified crawlers

`BotShieldAllowBot` registers a UA pattern + IP-range pair that
the allow-list classifier checks during the heuristics phase.
Verified crawlers (UA matches AND IP is in the published range)
get a hard pass — they bypass the score ladder entirely.

```apache
BotShieldAllowVerifiedBots on
BotShieldAllowBot googlebot "Googlebot/" /var/lib/botshield/bots/googlebot.txt
BotShieldAllowBot bingbot   "bingbot/"   /var/lib/botshield/bots/bingbot.txt
BotShieldAllowBot internal-monitor "MonitorBot/" 10.0.0.0/8,2001:db8::/32
```

The third arg is shape-inspected — no separate flag or sentinel:

- **starts with `/`** → absolute path to a CIDR file (one CIDR per
  line, `#` comments, blank lines OK, IPv4 + IPv6).
- **contains `/` or `:`** → comma-separated inline CIDRs.
- **`*` alone** → UA-match only; no IP check. Logged with reason
  `allow-bot-ua:<name>` instead of `allow-bot:<name>`.
- **omitted** → default file path
  `/var/lib/botshield/bots/<name>.txt`.

The CIDR file is read once at config-parse time (size cap 1 MiB) and
cached on the per-server config. Refresh with a reload.

A built-in seed list covers Googlebot, Bingbot, Applebot, Yandex,
DuckDuckBot, and a handful of others — all installed under
`/var/lib/botshield/bots/`. The `services/refresh/botshield-refresh.py` script
fetches each provider's published JSON and rewrites the CIDR files
in place.

### Verified vs fake

A request whose UA matches a registered bot pattern is one of three
states:

- **verified** — UA matches, IP is in the range. Hard pass with
  reason `verified-<name>`.
- **fake** — UA matches, IP is NOT in the range. Strong penalty
  with reason `fake-<name>`. Fake-bot detection is one of the
  most reliable signals — bot operators love claiming Googlebot.
- **unverified** — UA matches, classifier hit but ranges aren't
  loaded for this name. Logged with reason `bot-unverified` for
  visibility, no score effect.

## Rate limits and block paths

`BotShieldRateLimit` caps requests-per-window for a cohort. Hits
return 429 with `Retry-After` and add 50 to the score. Cohorts pair
a UA-substring matcher with an IP spec:

```apache
BotShieldRateLimit api-burst budget=60 per=min ipspec=10.0.0.0/8,2001:db8::/48
BotShieldRateLimit scrapers  budget=10 per=min ua="wget"
BotShieldRateLimit ai-bots   budget=1  per=sec ua=@ai-train
```

Match keys (any of):
- `ua=<substring>` or `ua=@<botgroup>` — UA gate; omit or set to
  `*` for any UA.
- `ipspec=<spec>` — same shape as `BotShieldAllowBot`: a path to
  a CIDR file, comma-separated inline CIDRs, or omit / `*` for
  any IP.

Rate keys (required):
- `budget=<N>` — requests allowed per window (fixed-window counter,
  atomic CAS-updated SHM slot).
- `per=<sec|min|hour>` (also accepts `s`/`m`/`h`) — bare integer
  rejected.

Both axes can't be `*`/omitted — that would rate-limit every
request, rejected at config time. The legacy 5-arg positional form
`<name> <budget> <per> <ua-pattern> <ipspec>` is still accepted.

For path-conditional 403s, use `BotShieldRequestTrigger` with
`status=403` plus optional `ua=` / `ipspec=` match keys (the
former `BotShieldBlockPath` directive, retired):

```apache
<BotShieldRequestTrigger legacy-admin>
    BotShieldPath         /wp-admin/*
    BotShieldStatus       403
</BotShieldRequestTrigger>
<BotShieldRequestTrigger aggressive-scraper>
    BotShieldPath         /
    BotShieldUserAgent    AhrefsBot
    BotShieldStatus       403
</BotShieldRequestTrigger>
```

Match keys (any of):
- `ua=<substring>` or `ua=@<botgroup>` — UA gate
- `ipspec=<spec>` — same shape as `BotShieldAllowBot` (CIDR file,
  comma-separated inline CIDRs, or omit/`*` for "any IP")

Action keys (any of): `status=`, `redirect=`, `flag=`, `ttl=`,
`penalty=`, `log=`, `mode=enforce|observe`. Convention is match
keys first, action keys after — the parser doesn't enforce ordering
but readability rewards consistency.

### Repeated-429 escalation

`BotShieldRateLimitEscalate` upgrades a rule that's already been
firing — repeated 429s on the same IP escalate to 403 (or any
configurable status):

```apache
BotShieldRateLimitEscalate api-burst 5 min status=403 ttl=3600
```

Args: `<rate-rule> <strikes> <per> [status=N] [ttl=N]`. `<per>`
accepts `sec`/`min`/`hour` (same as `BotShieldRateLimit`). If a
rate-limited cohort triggers `<strikes>` 429s within the window,
the IP is upgraded to the configured status for `ttl` seconds
(lives in the strike SHM table). The original rate-limit rule
still runs; the escalation is a separate decision applied on top.

### Path-pattern semantics

Path globs use a single `*` wildcard at the trailing edge. A
non-trailing `*` (e.g. `/api/*/v2/`) emits a NOTICE at config-parse
time — the v1 matcher would have treated the inner `*` as a
literal byte; the current matcher follows RFC 9309's leftmost
greedy semantics. The NOTICE warns that intent may have
shifted; existing configs aren't broken, just verified.

## Robots.txt enforcement

`BotShieldRobotsTxt` plugs in a parsed RFC 9309 robots.txt file as
a policy source. Disallow rules become `robotsblock:<group>`
matches; Crawl-delay rules become per-group rate limits.

```apache
BotShieldRobotsTxt              /etc/botshield/robots.txt
BotShieldRobotsRefreshInterval  60
BotShieldRobotsWildcardScope    heuristic
```

Args:

- **`BotShieldRobotsTxt <path>`** — path to the robots.txt file. A
  background watchdog re-parses on mtime change.
- **`BotShieldRobotsRefreshInterval <sec>`** — how often the
  watchdog checks mtime. Default 60. Set to 0 to disable
  hot-reload (mtime change won't be picked up until next restart).
- **`BotShieldRobotsWildcardScope <mode>`** — how strict the
  matcher is on `User-agent: *` rules:
  - `heuristic` (default): wildcard rules apply only when no more
    specific group matches. Closest to your intent — a `*`
    block doesn't override a tighter Googlebot allow.
  - `strict`: RFC-9309 strict semantics. Wildcard rules participate
    in matching like any other group. May produce surprising
    overrides when wildcard and named groups conflict.
  - `off`: ignore wildcard groups entirely. Only named-group rules
    apply.

Group iteration is exposed by `httpd -t -D DUMP_BOTSHIELD_POLICY`
for inspection (see [observability](observability.md)).

### Reading the effective policy

`httpd -t -D DUMP_BOTSHIELD_POLICY` also prints the tier thresholds
and every flag trigger **after** `reset` processing, each with the
source it came from:

```
## Tier thresholds (effective)
noninteractive      20   configured
interactive          50   configured
captcha               -   unset - never fires (suggested: 80)

## Flag triggers (effective, after reset)
# flag              action      value    mode      source
honeypot_hit       score       +60      enforce   configured
pow_fail_streak    tier_floor  interactive  enforce   configured
```

The source column is the point. "Not in the config file" and "not in
effect" are different things, and two production lockouts came from
confusing them: a flag was configured to score 50 against a
`BotShieldScoreNonInteractive` of 20 that was a compiled-in default and
appeared nowhere an operator could read. The config said `add=50` and
nothing on the system said what 50 meant.

There are no compiled-in thresholds any more, for that reason. A tier
with no threshold configured never fires, and the dump says so along
with a suggested starting value.

Two interactions are called out inline rather than left to
documentation nobody consults at the moment it matters:

`~` — a flag scoring at or above the noninteractive threshold. Such a
flag is a challenge switch rather than a contributing signal. Bounded by
`flags_excused` (one solve clears it for that cookie), so the residual
risk is a client that *cannot* solve.

`!!` — a `tier_floor` at or above `interactive` while that threshold is
parked. The floor is MAX'd in after the score-to-tier decision and
ignores thresholds entirely, so parking them does not contain it.

## Triggers — predicate-action engine

Five trigger families share one config-time action engine and one
request-time executor. Each family differs only in its predicate;
they all funnel through the same `bs_trigger_action` struct and
the same shared action keys.

| Family | Directive | Predicate |
|---|---|---|
| Path | `BotShieldRequestTrigger` | URI glob |
| Cookie | `BotShieldCookieTrigger` | Cookie name + value (or bulk shape) |
| Env | `BotShieldEnvTrigger` | Apache env var |
| Feedback | `BotShieldFeedbackTrigger` | App-emitted event name (response path) |
| Load | `BotShieldLoadTrigger` | Global load_state |

### Shared action keys

Every family parses `<predicate-args> <action-key>=<value>...`. The
action keys are:

| Key | Effect |
|---|---|
| `status=<code>` | HTTP status to return. `pass` lets the request continue (cookie/env families accumulate; path family declines to real handler) |
| `redirect=<url>` | Send an HTTP redirect with the chosen status (default 302) |
| `log=<tag>` | Stash a tag in `r->notes` for the access log (`%{BS-…}n`) and the decision-log line |
| `flag=<name>` | Add a flag bit on the IP's flagged-IP entry (e.g. `flag=honeypot_hit`) |
| `ttl=<sec>` | TTL on the flag-IP entry. Required when `flag=` is set |
| `penalty=N` | Add N to the request score |
| `credit=N` | Subtract N from the request score (rejected on the path family — paths can't credit) |
| `mode=observe` | Per-rule observe mode: predicate evaluates, side-effects suppressed. See [staging](staging.md) |

### Path triggers

```apache
<BotShieldRequestTrigger admin-honeypot>
    BotShieldPath         /admin/.env
    BotShieldStatus       403
    BotShieldFlag         honeypot_hit
    BotShieldTTL          3600
    BotShieldLog          admin-trap
</BotShieldRequestTrigger>
<BotShieldRequestTrigger api-burst-trap>
    BotShieldPath         /api/*/burst
    BotShieldPenalty      30
    BotShieldLog          api-burst
</BotShieldRequestTrigger>
```

First-match wins (declaration order). On match, the path family's
`status=nochallenge` short-circuits to `DECLINED` (real handler runs); any
other status is the response code.

### Cookie triggers

```apache
<BotShieldCookieTrigger session-active>
    BotShieldCookie       sessionid
    BotShieldStatus       nochallenge
    BotShieldCredit       10
</BotShieldCookieTrigger>
<BotShieldCookieTrigger weak-session>
    BotShieldCookie       sessionid=guest
    BotShieldPenalty      15
    BotShieldLog          guest-session
</BotShieldCookieTrigger>
<BotShieldCookieTrigger no-cookies>
    BotShieldCookies      none
    BotShieldPenalty      5
    BotShieldLog          cookieless
</BotShieldCookieTrigger>
```

Predicate shapes:

- `cookie=<name>` — named cookie present (any value).
- `!cookie=<name>` — named cookie absent.
- `cookie=<name>=<value>` — exact value match.
- `cookie=<name>!<value>` — value mismatch.
- `cookie=<name>~<substring>` — value contains substring.
- `cookies=none` / `cookies=any` — bulk: empty cookie map / any
  cookie set.
- `cookies=session` — bulk: any of the names declared via
  `BotShieldSessionCookieName` is set.
- `bs-cookie=verified` / `bs-cookie=missing` / `bs-cookie=invalid` —
  the BotShield-cookie-state note set by `bs_handler` (no double
  HMAC check). Predicates against the module's own `_bs_session`
  cookie name are rejected — use these instead.

Cookie family accumulates: `status=nochallenge` keeps walking and
collecting credits/penalties from later cookie triggers. First
non-pass status short-circuits.

### Env triggers

```apache
SetEnvIfExpr "%{HTTP:CF-Connecting-IP} =~ /:/" BS_IPV6=1
<BotShieldEnvTrigger ipv6-hint>
    BotShieldEnv          BS_IPV6
    BotShieldStatus       nochallenge
    BotShieldCredit       2
</BotShieldEnvTrigger>

SetEnvIf User-Agent "(?i)\bcurl\b" BS_CLI=1
<BotShieldEnvTrigger curl-hint>
    BotShieldEnv          BS_CLI
    BotShieldPenalty      10
    BotShieldLog          cli
</BotShieldEnvTrigger>
```

Predicate shapes:

- `env=<name>` — env var present (any value, including empty).
- `!env=<name>` — env var absent.
- `env=<name>=<value>` — exact value match.

Narrower than cookie by design — no substring/contains shape and
no bulk-state analog. If you need rich matching, set a
coarse bucket upstream (`SetEnvIfExpr`, ModSecurity rule, etc.)
and consume the bucket here. `redirect=` is not a valid action
key on env or load triggers.

Env triggers gate on `ap_is_initial_req(r)` to prevent double-
application on internal redirect legs (ErrorDocument, RewriteRule
without R). The env producer would otherwise fire a second time
and double-count score/flag.

### Feedback triggers

App emits a response header `X-BotShield-Feedback: event=<name>;sig=<hmac>`;
the module verifies the HMAC and looks up the event name in the
configured feedback-trigger table:

```apache
BotShieldAppFeedback                  on
BotShieldAppIntegrationSecretFile     /etc/botshield/app-integration-secret
<BotShieldFeedbackTrigger scanner-hit>
    BotShieldFlag         honeypot_hit
    BotShieldTTL          3600
    BotShieldLog          app-trap
</BotShieldFeedbackTrigger>
<BotShieldFeedbackTrigger human-pass>
    BotShieldFlag         app_verified_human
    BotShieldTTL          3600
</BotShieldFeedbackTrigger>
```

The event-name → action indirection is the security property: a
compromised app can emit any event name, but only configured
mappings reach module memory. Wire format details and signing are
covered in [captcha](captcha.md).

Feedback runs on the response path but its side effect is
future-request state (the flagged-IP write). Both
`BotShieldEnabled LogOnly` and per-trigger `mode=observe` apply —
either gates the filter into logging `feedbacktrigger:<event>:
observe` and skipping the SHM mutation. See
[staging](staging.md).

### Load triggers

```apache
BotShieldLoadStateFile          /run/botshield/load-state
BotShieldLoadRefreshInterval    1
BotShieldLoadWarmThreshold      65
BotShieldLoadHotThreshold       85

<BotShieldLoadTrigger be-strict>
    BotShieldState        >=warm
    BotShieldPenalty      20
    BotShieldLog          brownout
</BotShieldLoadTrigger>
<BotShieldLoadTrigger drop-noise>
    BotShieldState        hot
    BotShieldStatus       503
    BotShieldLog          hot-shed
</BotShieldLoadTrigger>
```

Predicates: `state=<name>` (exact match) or `state>=<name>` (at
least). State names: `normal`, `warm`, `hot`. Hysteresis settles
the state machine over a few sample ticks before rules fire — a
single load spike doesn't flip the global state.

Load state is sampled from the Apache scoreboard plus an optional
external state file (set by an out-of-band collector — e.g.
collectd writing a single-word state every second). The external
file lets you key load decisions on whatever metric makes sense
for your deployment, not just Apache's busy-worker count.

## Flag-trigger family

Flag triggers map flag bits → actions, applied after the policy
walk against the IP's accumulated flag bitmap (IP-side via
flagged-IP table + cookie-side via prior `_bs_session`). They
have a different action surface than the five trigger families
above:

```apache
<BotShieldFlagTrigger honeypot_hit>
    BotShieldAction       tier_floor
    BotShieldMin          captcha
</BotShieldFlagTrigger>
<BotShieldFlagTrigger honeypot_hit>
    BotShieldAction       score
    BotShieldAdd          60
</BotShieldFlagTrigger>
<BotShieldFlagTrigger app_verified_human>
    BotShieldAction       score
    BotShieldAdd          -80
</BotShieldFlagTrigger>
```

Args: `<flag> [reset] [action=<verb> args...]`. The first arg names
a flag bit (`honeypot_hit`, `scanner_probe`, `fake_bot`,
`pow_fail_streak`, `app_verified_human`, `app_verified_session`,
`app_trust_signal`); each invocation appends one trigger entry for
that bit.

Two action verbs:

- **`action=score add=N`** — accumulate signed N into the
  request's score (positive penalty / negative credit). SUM
  accumulates across triggers.
- **`action=tier_floor min=<tier>`** — set a minimum tier; `<tier>`
  is `pass` / `noninteractive` / `interactive` / `captcha`. MAX accumulates
  (strictest wins).

The `reset` keyword is directive-level (not an action verb): a
line of the form `BotShieldFlagTrigger <flag> reset` clears every
prior declaration for that flag from this scope at post-config
time. `reset` may appear with or without a trailing `action=...`:

```apache
# Clear whatever this scope already declared for honeypot_hit,
# install only one tier-floor rule:
<BotShieldFlagTrigger honeypot_hit>
    BotShieldReset
    BotShieldAction       tier_floor
    BotShieldMin          interactive
</BotShieldFlagTrigger>

# Disarm a flag entirely:
<BotShieldFlagTrigger pow_fail_streak>
    BotShieldReset
</BotShieldFlagTrigger>
```

### No compiled-in defaults

The module seeds nothing at config-parse time. A fresh install
scores nothing and challenges nothing until you declare both a
flag trigger and a tier threshold — the module used to seed a
sensible-looking slate automatically, and that was removed: a
default every deployment has to disable was not a default, and
every lockout this module has caused traced back to an implicit
weight nobody had written down.

The slate it used to seed is kept as a documented starting point
rather than deleted outright — [the flag-triggers example](examples.md)
and its heuristic-trigger counterpart, with the same values these
paired score + tier_floor rows used to carry:

| Flag | Starter action |
|---|---|
| `honeypot_hit` | `score add=+60`, `tier_floor min=captcha` |
| `fake_bot` | `score add=+80`, `tier_floor min=captcha` |
| `scanner_probe` | `score add=+50`, `tier_floor min=interactive` |
| `pow_fail_streak` | `score add=+30`, `tier_floor min=noninteractive` |
| `app_verified_human` | `score add=-80` |
| `app_verified_session` | `score add=-40` |
| `app_trust_signal` | `score add=-20` |

Trust signals (credits) are score-only by design; no credit ever
forces tier *down*. A verified-human flag can't unlock a request
that already tripped a different tier_floor.

None of this is active unless you paste it into your own config.
Once you have, a later `BotShieldFlagTrigger` line for the same
flag bit and action verb adds to it (SUM for score, MAX for
tier_floor) — use `reset` first if you want to replace rather than
accumulate.

### Per-Apache-scope triggers — `BotShieldTrigger`

For everything else you want to do at a specific Apache
scope — flag the IP, add a penalty, return a status, observe in
log-only mode — there's a single per-scope directive:

```apache
<Location "/admin/.env">
    <BotShieldTrigger>
        BotShieldFlag         honeypot_hit
        BotShieldTTL          3600
        BotShieldLog          admin-trap
    </BotShieldTrigger>
</Location>

<LocationMatch "(?i)/wp-(login|admin)">
    <BotShieldTrigger>
        BotShieldFlag         scanner_probe
        BotShieldTTL          3600
        BotShieldPenalty      20
        BotShieldLog          wp-trap
    </BotShieldTrigger>
</LocationMatch>

<Files "*.php">
    <If "%{REQUEST_URI} =~ m#/uploads/#">
        <BotShieldTrigger>
            BotShieldStatus       403
            BotShieldLog          php-in-uploads
        </BotShieldTrigger>
    </If>
</Files>
```

The Apache scope match IS the predicate — no separate path glob,
because Apache already evaluated the scope. Action keys mirror the
cookie family: `status` / `redirect` / `log` / `flag` / `ttl` /
`penalty` / `credit` / `mode`. Multiple `BotShieldTrigger` lines
in one scope each append a separate action; they all fire on a
pass, the first non-pass status short-circuits.

`BotShieldTrigger` works in any Apache container the parser
accepts (server config, `<VirtualHost>`, `<Directory>`,
`<Location>`, `<LocationMatch>`, `<Files>`, `<If>`, etc.) — the
same set that `Require` and `Header` work in. This is the
recommended way to express anything `<Location>`-shaped.

#### Reset semantics — opting out of inherited triggers

By default a child scope inherits its parent's `BotShieldTrigger`
list and concatenates its own. To drop the inherited list,
declare `BotShieldTrigger reset` in the child:

```apache
<Location "/api">
    <BotShieldTrigger>
        BotShieldPenalty      10
        BotShieldLog          api-tax
    </BotShieldTrigger>
</Location>

<Location "/api/health">
    <BotShieldTrigger>
        BotShieldReset
    </BotShieldTrigger>
</Location>

<Location "/api/internal">
    <BotShieldTrigger>
        BotShieldReset
    </BotShieldTrigger>
    <BotShieldTrigger>
        BotShieldStatus       nochallenge
        BotShieldLog          internal-allow
    </BotShieldTrigger>
</Location>
```

`reset` as the first arg drops triggers inherited from outer
scopes (and clears any earlier `BotShieldTrigger` entries
appended in the same scope before the reset).

### `nochallenge` waives the challenge, not the policy

`status=nochallenge` means "do not put an interstitial in front of
this request". It does not mean "exempt this request from everything".
Rate limits and robots.txt Disallow still apply to a request that
matched such a rule.

That distinction used to not exist. A bare pass returned out of the
policy walk immediately, which skipped robots.txt, the cohort rate
limits and the per-slug bot rate limit along with the challenge. A rule
written to let declared crawlers read content without an interstitial
was therefore also making them unratelimitable across most of the site,
and nothing in the config said so.

The rule still shadows later rules on the same path: this family is
first-match-wins and a `nochallenge` declared first stops the walk,
exactly as before. What changed is only that the walk continues into
the enforcement stages rather than returning.

`pass` is no longer accepted, and a config still using it fails
configtest rather than reloading with a changed meaning. The word was
ambiguous in practice and not just in principle: the decision log
emitted `tier=pass` on 14,066 lines of a single day on one deployment,
meaning "no challenge was served", so an operator grepping for the
rule spelling and the outcome spelling got each other's matches.

`nochallenge` is now the only spelling, on every surface. It says what
happens rather than what the module declined to do, and it carries no
dash, so it survives being split out of a `reason` token.

## Safeguard

The safeguard suppresses a challenge loop: a client that has been
issued challenges repeatedly within the safeguard window without
ever returning a verified cookie gets a 302 redirect
(`tier=safeguard outcome=redirect`) to a configured
`BotShieldSafeguardRedirectURL` or to the built-in explainer at
`<BotShieldEndpointPrefix>/safeguard-info`. The original URI is
appended as `?return=<urlencoded path>`. The per-IP counter clears
on redirect so a fresh failure cycle starts after the client
engages with the redirect target.

```apache
BotShieldSafeguard             on
BotShieldSafeguardThreshold    5
BotShieldSafeguardWindow       600
BotShieldSafeguardTTL          900
# Optional. When unset, the redirect points at
# /botshield/safeguard-info (the module's built-in explainer).
BotShieldSafeguardRedirectURL  /help/auto-check-failed
```

Defaults: 5 missed verifications in 600 seconds → 900-second pass-
through window. The IP's flagged-IP entry is preserved so the
suspicious behavior is still recorded for downstream signals; only
the in-line challenge is suppressed.

Sites staging a fresh deployment with aggressive thresholds
are the most likely to trip this. Watch the
`tier_nochallenge_total` counter for an unusual climb under "safeguard"
reasons in the decision log (safeguard rolls into pass for metric
binning; the decision log reason `challengesafeguard` is the
filter).

## Where to next

- Captcha and app-bridge protocols: [captcha](captcha.md).
- Safe rule rollout: [staging](staging.md).
- Metrics and dashboards: [observability](observability.md).
- Full directive reference: [directives](directives.md).
