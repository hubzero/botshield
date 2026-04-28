# Policy

mod_botshield decides which requests deserve friction by composing
six policy families on top of the score-driven tier ladder. This
page covers each family's directive, predicate shape, side effects,
and where it sits in the runtime walk.

The runtime order (one pass per request, first short-circuit wins):

1. **Cookie triggers (E4)** — pre-handler state. Cookie family
   accumulates pass-with-credit across multiple matches.
2. **Env triggers (E6)** — predicate on Apache environment
   variables (`SetEnvIfExpr`, mod_rewrite `[E=…]`). First-match
   wins; gated on `ap_is_initial_req` so internal-redirect legs
   don't double-apply.
3. **Load triggers (E11.2)** — predicate on the global load_state
   sampled by E11.1.
4. **Path triggers (E3)** — predicate on the request URI.
5. **Block-path (E2.1)** — cohort + path-glob → 403.
6. **Robots.txt Disallow (E2.2)** — RFC 9309 matcher → 403.
7. **Rate-limit (E2.1)** — cohort + budget → 429 with Retry-After.
8. **Robots.txt Crawl-delay (E2.2)** — per-group rate cap.

Allow-list (E1) and the built-in heuristics run inside the score
fold-up that precedes this walk; flag-trigger effects (E14) are
applied after policy completes against the IP's accumulated flag
bitmap.

## Allow list (E1) — verified crawlers

`BotShieldAllowBot` registers a UA pattern + IP-range pair that the
allow-list classifier checks before any other gate runs. Verified
crawlers (UA matches AND IP is in the published range) get a hard
pass — they bypass the score ladder entirely.

```apache
BotShieldAllow on
BotShieldAllowBot googlebot "Googlebot/" /var/lib/botshield/bots/googlebot.txt
BotShieldAllowBot bingbot   "bingbot/"   /var/lib/botshield/bots/bingbot.txt
BotShieldAllowBot internal-monitor "MonitorBot/" *,10.0.0.0/8,2001:db8::/32
```

Three forms for the third arg:

- **path to a CIDR file** — one CIDR per line, `#` comments, blank
  lines OK, IPv4 + IPv6.
- **inline CIDRs** — leading `*,` then comma-separated CIDRs (the
  `*` is a sentinel signaling "inline" rather than a path).
- **`*` alone** — UA-match only; no IP check. Logged with reason
  `allow-bot-ua:<name>` instead of `allow-bot:<name>`.

The CIDR file is read once at config-parse time (size cap 1 MiB) and
cached on the per-server config. Refresh with a reload.

A built-in seed list covers Googlebot, Bingbot, Applebot, Yandex,
DuckDuckBot, and a handful of others — all installed under
`/var/lib/botshield/bots/`. The `tools/refresh-bot-ranges.sh` script
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
  operator visibility, no score effect.

## Rate limits and block paths (E2.1)

`BotShieldRateLimit` caps requests-per-window for a cohort. Hits
return 429 with `Retry-After` and add 50 to the score. Cohorts pair
a UA-substring matcher with an IP spec:

```apache
BotShieldRateLimit api-burst 60 60 "" 10.0.0.0/8,2001:db8::/48
BotShieldRateLimit scrapers  10 60 "wget|curl|python" *
```

Args: `<name> <budget> <window-sec> <ua-pattern> <ipspec>`.

- `<budget>` requests are allowed per `<window-sec>` (fixed-window
  counter, atomic CAS-updated SHM slot).
- `<ua-pattern>` is a substring or `""` for "any UA".
- `<ipspec>` is the same shape as `BotShieldAllowBot` — a path to a
  CIDR file, comma-separated inline CIDRs, or `*` for "any IP".

Not both axes can be `""` / `*` — that would rate-limit every
request, rejected at config time.

`BotShieldBlockPath` is the same cohort + a path glob → 403:

```apache
BotShieldBlockPath legacy-admin "/wp-admin/*" "" *
BotShieldBlockPath aggressive-scraper "/" "AhrefsBot|SEMrushBot" *
```

Args: `<name> <path-glob> <ua-pattern> <ipspec>`.

### Repeated-429 escalation (E9)

`BotShieldRateLimitEscalate` upgrades a rule that's already been
firing — repeated 429s on the same IP escalate to 403 (or any
configurable status):

```apache
BotShieldRateLimitEscalate api-burst 5 60 status=403 ttl=3600
```

If a rate-limited cohort triggers `<strikes>` 429s within
`<per-sec>`, the IP is upgraded to the configured status for `ttl`
seconds (lives in the strike SHM table). The original rate-limit
rule still runs; the escalation is a separate decision applied on
top.

### Path-pattern semantics

Path globs use a single `*` wildcard at the trailing edge. A
non-trailing `*` (e.g. `/api/*/v2/`) emits a NOTICE at config-parse
time — the v1 matcher would have treated the inner `*` as a
literal byte; the current matcher follows RFC 9309's leftmost
greedy semantics. The NOTICE warns operators that intent may have
shifted; existing configs aren't broken, just verified.

## Robots.txt enforcement (E2.2)

`BotShieldRobotsTxt` plugs in a parsed RFC 9309 robots.txt file as
a policy source. Disallow rules become `block-path:robots:<group>`
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
    specific group matches. Closest to operator intent — a `*`
    block doesn't override a tighter Googlebot allow.
  - `strict`: RFC-9309 strict semantics. Wildcard rules participate
    in matching like any other group. May produce surprising
    overrides when wildcard and named groups conflict.
  - `off`: ignore wildcard groups entirely. Only named-group rules
    apply.

Group iteration is exposed at `<prefix>/policy-status` for
operator inspection (see [observability](../observability/index.html)).

## Triggers — predicate-action engine (E3, E4, E6, E7.3, E11.2)

Five trigger families share one config-time action engine and one
request-time executor. Each family differs only in its predicate;
they all funnel through the same `bs_trigger_action` struct and
the same shared action keys.

| Family | Directive | Predicate |
|---|---|---|
| Path (E3) | `BotShieldPathTrigger` | URI glob |
| Cookie (E4) | `BotShieldCookieTrigger` | Cookie name + value (or bulk shape) |
| Env (E6) | `BotShieldEnvTrigger` | Apache env var |
| Feedback (E7.3) | `BotShieldFeedbackTrigger` | App-emitted event name (response path) |
| Load (E11.2) | `BotShieldLoadTrigger` | Global load_state |

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
| `mode=observe` | Per-rule observe mode: predicate evaluates, side-effects suppressed. See [staging](../staging/index.html) |

### Path triggers (E3)

```apache
BotShieldPathTrigger admin-honeypot "/admin/.env" \
    status=403 flag=honeypot_hit ttl=3600 log=admin-trap
BotShieldPathTrigger api-burst-trap "/api/*/burst" \
    penalty=30 log=api-burst
```

First-match wins (declaration order). On match, the path family's
`status=pass` short-circuits to `DECLINED` (real handler runs); any
other status is the response code.

### Cookie triggers (E4)

```apache
BotShieldCookieTrigger session-active sessionid=present \
    status=pass credit=10
BotShieldCookieTrigger weak-session sessionid=eq:guest \
    penalty=15 log=guest-session
BotShieldCookieTrigger no-cookies cookies=none \
    penalty=5 log=cookieless
```

Predicates:

- `<name>=present` / `<name>=absent` — named cookie presence.
- `<name>=eq:<val>` / `<name>=ne:<val>` / `<name>=contains:<val>` —
  named cookie value matchers.
- `cookies=none` / `cookies=any` — bulk: empty cookie map / any
  cookie set.
- `cookies=session` — bulk: any of the names declared via
  `BotShieldSessionCookieName` is set.
- `bs=verified` / `bs=missing` / `bs=invalid` — the BotShield-
  cookie-state note set by `bs_handler` (no double HMAC check).

Cookie family accumulates: `status=pass` keeps walking and
collecting credits/penalties from later cookie triggers. First
non-pass status short-circuits.

### Env triggers (E6)

```apache
SetEnvIfExpr "%{HTTP:CF-Connecting-IP} =~ /:/" BS_IPV6=1
BotShieldEnvTrigger ipv6-hint env=BS_IPV6 status=pass credit=2

SetEnvIf User-Agent "(?i)\bcurl\b" BS_CLI=1
BotShieldEnvTrigger curl-hint env=BS_CLI penalty=10 log=cli
```

Predicates: `env=<name>=present` / `=absent` / `=eq:<val>`. Env is
narrower than cookie by design — rich matching belongs in the
upstream module that sets the var.

Env triggers gate on `ap_is_initial_req(r)` to prevent double-
application on internal redirect legs (ErrorDocument, RewriteRule
without R). The env producer would otherwise fire a second time
and double-count score/flag.

### Feedback triggers (E7.3)

App emits a response header `X-BotShield-Feedback: event=<name>;sig=<hmac>`;
the module verifies the HMAC and looks up the event name in the
configured feedback-trigger table:

```apache
BotShieldAppFeedback                  on
BotShieldAppIntegrationSecretFile     /etc/botshield/app-integration-secret
BotShieldFeedbackTrigger scanner-hit  flag=honeypot_hit ttl=3600 log=app-trap
BotShieldFeedbackTrigger human-pass   flag=app_verified_human ttl=3600
```

The event-name → action indirection is the security property: a
compromised app can emit any event name, but only configured
mappings reach module memory. Wire format details and signing are
covered in [captcha](../captcha/index.html).

Feedback runs on the response path. It honors `BotShieldShadowMode`
and per-trigger `mode=observe` — observe matches log
`feedback-trigger:<event>:observe` without mutating the flagged-IP
table. See [staging](../staging/index.html).

### Load triggers (E11.2)

```apache
BotShieldLoadStateFile          /run/botshield/load-state
BotShieldLoadRefreshInterval    1
BotShieldLoadWarmThreshold      70
BotShieldLoadHotThreshold       90

BotShieldLoadTrigger be-strict state>=warm penalty=20 log=brownout
BotShieldLoadTrigger drop-noise state=hot   status=503 log=hot-shed
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

## Flag-trigger family (E14)

Flag triggers map flag bits → actions, applied after the policy
walk against the IP's accumulated flag bitmap (IP-side via
flagged-IP table + cookie-side via prior `_bs_verified`). They
have a different action surface than the five trigger families
above:

```apache
BotShieldFlagTrigger honeypot_hit_strict   flag=honeypot_hit \
    action=tier_floor min=captcha
BotShieldFlagTrigger honeypot_score        flag=honeypot_hit \
    action=score add=60
BotShieldFlagTrigger app_human_credit      flag=app_verified_human \
    action=score add=-80
```

Two action verbs:

- **`action=score add=N`** — accumulate into the request's score
  (positive penalty / negative credit).
- **`action=tier_floor min=<tier>`** — lift the tier to AT LEAST
  `<tier>` regardless of score. Score-derived tier wins when
  already above the floor.

A third verb (`action=reset`) is a config-time sentinel for
operators who want to override a compiled-in default, consumed
before the request path runs.

### Compiled-in defaults

mod_botshield seeds the flag-trigger table at config-parse time
with sensible defaults so a fresh install gets honeypot / fake-bot
detection without any additional config. Each detection-signal
flag is seeded as paired score + tier_floor rows:

| Flag | Default action |
|---|---|
| `honeypot_hit` | `score add=+60`, `tier_floor min=captcha` |
| `fake_bot` | `score add=+80`, `tier_floor min=captcha` |
| `scanner_probe` | `score add=+50`, `tier_floor min=form` |
| `pow_fail_streak` | `score add=+30`, `tier_floor min=silent` |
| `app_verified_human` | `score add=-80` |
| `app_verified_session` | `score add=-40` |
| `app_trust_signal` | `score add=-20` |

Trust signals (credits) are score-only by design; no credit ever
forces tier *down*. A verified-human flag can't unlock a request
that already tripped a different tier_floor.

Operator-supplied `BotShieldFlagTrigger` directives override the
defaults for the matching flag bit + action verb pair (later
declarations win, same as every other trigger family).

### Setting flags by location

`BotShieldFlagIP` flags any IP that reaches the configured scope:

```apache
<Location "/admin/.env">
    BotShieldFlagIP honeypot_hit 3600
</Location>

<Location "/wp-login.php">
    BotShieldFlagIP scanner_probe 3600
</Location>
```

Args: `<bits> [ttl-sec]`. Multiple bits can be comma-separated.
TTL defaults to 3600 if omitted. Range: 60..2592000.

This is the operator handle for honeypot / scanner-bait `<Location>`
blocks. Any request hitting the scope adds the named bits to the
IP's flagged-IP entry; subsequent requests fold those bits through
the flag-trigger table.

## Safeguard (E10)

The safeguard suppresses a challenge loop: a client that has been
issued challenges repeatedly within the safeguard window without
ever returning a verified cookie gets pass-through (`tier=safeguard
outcome=declined`) to break the loop.

```apache
BotShieldSafeguard          on
BotShieldSafeguardThreshold 5
BotShieldSafeguardWindow    600
BotShieldSafeguardTTL       900
```

Defaults: 5 missed verifications in 600 seconds → 900-second pass-
through window. The IP's flagged-IP entry is preserved so the
suspicious behavior is still recorded for downstream signals; only
the in-line challenge is suppressed.

Operators staging a fresh deployment with aggressive thresholds
are the most likely to trip this. Watch the
`tier_pass_total` counter for an unusual climb under "safeguard"
reasons in the decision log (safeguard rolls into pass for metric
binning; the decision log reason `challenge-safeguard` is the
filter).

## Where to next

- Captcha and app-bridge protocols: [captcha](../captcha/index.html).
- Safe rule rollout: [staging](../staging/index.html).
- Metrics and dashboards: [observability](../observability/index.html).
- Full directive reference: [directives](../directives/index.html).
