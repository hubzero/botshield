# Changelog

## 2026-07-31 (accesslog=off)

### Changed — `log=off` becomes `accesslog=on|off`

Renamed before it reached a release. Suppression is now its own key
instead of a reserved value of `log=`:

```apache
BotShieldPathTrigger env-probe "/.env" status=403 \
    log=scanner-probe accesslog=off
```

The clarity is the smaller reason. The real problem with the overload was
that it made the two meanings **mutually exclusive** — a rule could name
a fail2ban tag or suppress its access-log line, never both. That cost the
tag on precisely the traffic most worth tagging, since a scanner probe
usually wants both. Separate keys compose.

`log=off` is now rejected at config time with a message naming the
replacement, rather than silently degrading to a tag literally spelled
"off" and dropping suppression a config depended on. `log=` with an empty
value is likewise an error now instead of setting an empty tag.

`accesslog=` accepts `on` (the default) or `off`; anything else is a
config error. Added to the known-keys list of all six families that share
the action-key parser, so an unknown-key diagnostic lists it.

Struct field `suppress_log` renamed to `suppress_access_log` to match.

Behavior is otherwise unchanged: suppression still breaks the
`log_transaction` chain via `DONE`, still leaves `BotShieldDecisionLog`
and the error-log line intact, and still never fires under
`mode=observe` / `BotShieldEnabled LogOnly`.

## 2026-07-31 (log=off)

### Added — `BotShieldDecisionLog`, a module-owned decision log

```apache
BotShieldDecisionLog logs/botshield-decisions.log
BotShieldDecisionLog "|/usr/bin/rotatelogs /var/log/httpd/bs.%Y%m%d 86400"
```

Written directly from `bs_decision_log` rather than through
mod_log_config, which makes it independent of the access log. That is
the point: `log=off` can suppress access logging for flood traffic while
this log still records every decision, so a detection log can be
rapid-rotated while the access log is archived on its own schedule.

Reuses Apache's own plumbing rather than reinventing it —
`ap_open_piped_log` / `ap_piped_log_write_fd` for `|program` specs (so
`rotatelogs` works as it does for any Apache log), and
`ap_server_root_relative` + `apr_file_open(WRITE|CREATE|APPEND)` for
paths.

- One descriptor per vhost, opened at `post_config` before the children
  fork, so every worker inherits it.
- One `apr_file_write` of a pre-formatted line per decision, no
  request-path locking: lines are well under `PIPE_BUF`, so concurrent
  appends from separate processes do not interleave. Same guarantee
  mod_log_config relies on.
- An `O_APPEND` descriptor survives logrotate `copytruncate`. A
  move-and-create rotation would strand it until the next graceful
  restart — use a piped spec for that style.
- **Failure to open is fatal at startup.** A decision log the operator
  asked for and did not get is a silent blind spot.

Line shape is the same `key=value` payload as the error-log line, with
an ISO-8601 UTC timestamp prepended and the User-Agent appended. There
is deliberately no HTTP status field: this writes at decision time,
before the response is finalized, so `r->status` is not yet the code the
client receives (a block would log `200` while the handler goes on to
return `403`). `outcome=` is authoritative and, unlike a status code,
distinguishes `block` from `rate_limited` from `challenged`.

`bs_decision_log` was refactored to build its payload once and feed both
sinks. The error-log line is byte-identical to before — the pytest
framework parses decisions out of that file, so its shape is a contract.

The `CustomLog` + `%{BS_*}e` route still works and remains the right
choice for composing botshield fields into an existing format.

### Added — `log=off` suppresses access logging for matching requests

`log=` on the six trigger families that share the action-key parser
(path, cookie, env, feedback, load, and the per-scope `BotShieldTrigger`)
gains a reserved value:

```apache
BotShieldPathTrigger env-probe "/.env" status=403 log=off
```

A value still names a tag that rides the decision line as `tag="<x>"`.
The literal `off` instead suppresses **all** access logging for a
matching request.

Mechanism: `log_transaction` is a `RUN_ALL` hook declared with
`(OK, DECLINED)`, so any other return value breaks the chain.
`bs_propagate_decision_env` already sat on that hook at
`APR_HOOK_FIRST` — ahead of mod_log_config — to re-publish `BS_*` env
across internal redirects; it now also returns `DONE` when the trigger
set the `BS_NOLOG` marker. No later logger formats or writes anything.

Three properties operators should know:

- **All-or-nothing.** mod_log_config services every `CustomLog`
  directive from one hook function, so there is no way to keep one log
  and starve another. `log=off` therefore discards this module's own
  decision-log line along with the access-log line. The error-log line
  from `bs_decision_log` is unaffected.
- **Third-party loggers are skipped too** when their `log_transaction`
  hook is ordered after this module's.
- **Never fires under observe.** The suppression is applied after the
  observe short-circuit in `bs_apply_trigger_action`, so `mode=observe`
  and `BotShieldEnabled LogOnly` always leave their evidence.

To trim one specific log while keeping the others, use mod_log_config's
own conditional form against the decision this module already publishes
to the request environment, not `log=off`:

```apache
CustomLog logs/access.log combined "expr=%{reqenv:BS_OUTCOME} != 'block'"
```

Cost of the overload: a tag literally spelled `off` is now unreachable.
Accepted, to keep one key for "what happens to the log" instead of two.

`BotShieldRateLimitEscalate` has its own arg parser and is unchanged —
its `log=<tag>` still only names a tag.

## 2026-05-03 (RateLimit cohort-grammar unification)

### Added — `BotShieldRateLimit` accepts key=value form

`BotShieldRateLimit` now accepts a key=value form alongside the
existing 5-arg positional form. Same cohort vocabulary as
`BotShieldPathTrigger` (`ua=`, `ipspec=`), plus `budget=` / `per=`
for the rate parameters and the existing `mode=enforce|observe`.

```apache
# NEW — key=value form
BotShieldRateLimit api-burst budget=60 per=min ua="GPTBot"
BotShieldRateLimit ai-bots   budget=1  per=sec ua=@ai-train
BotShieldRateLimit corp-only budget=100 per=min ipspec=10.0.0.0/8
BotShieldRateLimit staging   budget=5  per=sec ua="X" mode=observe

# LEGACY — still works
BotShieldRateLimit api-burst 60 min "GPTBot" * mode=observe
```

Form is detected by sniffing args — every arg after `<name>`
contains `=` → new shape; any positional arg without `=` → legacy.
No deprecation warning yet; soft migration. The runtime behavior
is identical for either form.

Defaults in the new form: omit `ua=` → match any UA; omit
`ipspec=` → match any IP. Both omitted is rejected at config time
(same both-`*` rejection as before — that would rate-limit every
request on the server). Required: `budget=` and `per=`.

This is the cohort vocabulary that `BotShieldPathTrigger` adopted
in the BlockPath retirement; consolidating `BotShieldRateLimit`
onto the same grammar means operators learn one cohort syntax for
every directive that takes one.

## 2026-05-03 (path-trigger absorbs block-path)

### Changed — `BotShieldBlockPath` retired; cohort gating moves into `BotShieldPathTrigger`

`BotShieldPathTrigger` gains two new optional match keys, `ua=` and
`ipspec=`, that AND with the path glob. Same cohort grammar as
`BotShieldRateLimit` (UA substring, `@botgroup`, polymorphic ipspec).
With those keys plus `status=4xx`, PathTrigger fully subsumes what
`BotShieldBlockPath` used to do — and composes naturally with the
other trigger action keys (`flag=`, `ttl=`, `redirect=`, `mode=`,
`penalty=`, `log=`).

`BotShieldBlockPath` is removed. **Breaking change**, no soft-deprecate
window. Configs that referenced it will fail at config-time with
`unknown directive`.

#### Migration

```apache
# BEFORE
BotShieldBlockPath legacy-admin "/wp-admin/*" "" *
BotShieldBlockPath ai-pubs       "/publications/*" "@ai-train" *
BotShieldBlockPath admin-locked  "/admin"          "*" "10.0.0.0/8"

# AFTER
BotShieldPathTrigger legacy-admin "/wp-admin/*" status=403
BotShieldPathTrigger ai-pubs      "/publications/*" ua=@ai-train status=403
BotShieldPathTrigger admin-locked "/admin"          ipspec=10.0.0.0/8 status=403
```

Convention: write match keys (`ua=`, `ipspec=`) before action keys
(`status=`, `penalty=`, etc.). Parser doesn't enforce ordering, but
operators reading a rule should be able to see at a glance where the
"who/where" predicate ends and the "what to do" action begins.

Defaults if you omit a match key:
- omit `ua=` → match any UA (same as `ua=*`)
- omit `ipspec=` → match any IP (same as `ipspec=*`)
- both omitted → no cohort gating, just path-glob (same as today's
  PathTrigger semantics)

#### Metrics retired

- `botshield_block_path_hit_total` — gone. Path-triggers that fire
  with status=4xx don't have a per-family hit counter; the request
  outcome lands in the standard `decision_total{outcome}` and the
  decision log carries `path-trigger:<name>` in the reason chain.
- `botshield_block_path_observed_total` — gone. Observe-mode path
  triggers bump the shared `botshield_trigger_observed_total` (which
  already covers cookie/env/load/path observe).

Operators who scraped these counters should switch to
`botshield_decision_total{outcome="block"}` plus the decision-log
reason tag.

#### `/botshield/policy-status`

The `## BotShieldBlockPath (directive)` section is removed. Cohort-
scoped path rules now appear as PathTrigger entries (visible in the
emitted directive list, future enhancement: render the cohort in the
status page too).

#### Reason tag

A path-trigger fire emits `path-trigger:<name>` in the decision log
(was: `block-path:<name>` for BlockPath). If you grep logs for
`block-path:`, switch to `path-trigger:`.

The `~block` would-outcome under `BotShieldEnabled LogOnly` continues
to work — path triggers with `status>=400` set it on the would-fire
path the same way BlockPath did.

## 2026-05-03 (botgroups)

### Added — botgroup vocabulary throughout

Adopt the names from the IETF aipref content-signal vocabulary
(`search`, `ai-input`, `ai-train`) plus a mod_botshield extension
`monitor` for operational crawler categories. Group membership is
attached per directory entry at codegen time (mapped from category)
and surfaced as a new selector `@<botgroup>` in three directives
plus robots.txt.

#### Directory schema

`bs_known_bot_entry` gains a `botgroup` field;
`tools/gen-bot-directory.py` maps Cloudflare bot-directory categories
to botgroups at codegen time:

  | bot-directory category    | botgroup   |
  |---------------------------|------------|
  | AI_CRAWLER                | ai-train   |
  | AI_ASSISTANT, AI_SEARCH   | ai-input   |
  | ACADEMIC_RESEARCH         | ai-train   |
  | SEARCH_ENGINE_CRAWLER     | search     |
  | SEARCH_ENGINE_OPTIMIZATION| search     |
  | PAGE_PREVIEW, ARCHIVER    | search     |
  | MONITORING_AND_ANALYTICS  | monitor    |
  | ACCESSIBILITY             | monitor    |
  | (other)                   | NULL       |

  Today's directory: 166 search, 135 monitor, 47 ai-train, 33 ai-input,
  250 NULL. Per-bot override via `vendor/bot-directory.local.json`
  with an explicit `botgroup` field. `bs_known_bots_resolve_by_botgroup`
  helper enumerates slugs by botgroup.

  `bs_ua_class` gains a `known_botgroup` field, populated alongside
  `known_slug` and `known_category` at classification time so
  downstream code reads it once per request.

#### Directive `@botgroup` selector

  - `BotShieldBotRateLimit @search 1 sec` — rate-limit by botgroup.
    Per-slug allocation (each bot in the group gets its own counter
    at the entry's budget). Specific slug rules still win over
    @botgroup; @botgroup wins over `*` wildcard.
  - `BotShieldPathTrigger ai-train-pubs /publications/* ua=@ai-train status=403`
    — 403 when classified-as-ai-train hits the path. (Was previously
    expressed as `BotShieldBlockPath ai-train-pubs @ai-train *
    /publications/*`; see the path-trigger-absorbs-block-path entry
    above.)
  - `BotShieldRateLimit search-burst @search * 100 sec` — cohort
    rate limit by botgroup. Bonus side-effect of extending the shared
    cohort matcher.

  Cohort matcher (`bs_cohort_matches`) reads `cls->known_botgroup`
  directly — no per-request directory walk.

#### Robots.txt `User-agent: @botgroup`

  ```
  User-agent: @ai-train
  Disallow: /publications/
  Crawl-delay: 3600
  ```

  At parse time, `@`-prefixed User-agent stanzas are stored as-is.
  At query time, `robots_query` accepts a `botgroup` parameter
  (caller passes `cls->known_botgroup` from policy.c); `@botgroup`
  stanzas match when the request's classified botgroup equals the
  stanza value. Crawl-delay flows through bot_rate's slug-keyed
  machinery as before. Disallow rules apply the same way as
  UA-substring stanzas — same group qualifies, same path-rule
  longest-match-wins logic.

  Caveat — this is a server-side-only convention. Real-world
  scrapers reading the file see `@ai-train` and (correctly) ignore
  the stanza as not-applicable. For *publishing* preferences to
  AI companies that honor aipref, use the `Content-Signal:` HTTP
  header (separate feature, not yet implemented).

### Operator-facing summary

A coherent botgroup-aware policy:

```apache
# rate-limit by botgroup (per-slug allocation; each bot independent)
BotShieldBotRateLimit @search    1 sec
BotShieldBotRateLimit @ai-train  1 hour
BotShieldBotRateLimit @ai-input  0          # admit all (effectively block via 0=admit)
BotShieldBotRateLimit @monitor   5 sec

# hard 403 by botgroup+path
BotShieldPathTrigger ai-train-pubs /publications/* ua=@ai-train status=403

# robots.txt declarative form (server-side enforcement only)
User-agent: @ai-train
Disallow: /publications/
Crawl-delay: 3600
```

Specific slugs still override @botgroup (e.g.,
`BotShieldBotRateLimit googlebot 0` excepts Googlebot from any
@search rule). Operator workflow stays the same: write rules in
order of specificity, the matcher picks the most-specific.

## 2026-05-03 (latest)

### Added

- `BotShieldBotRateLimit` — three forms now, two new:

  ```apache
  BotShieldBotRateLimit Off                       # NEW
  BotShieldBotRateLimit <slug> <delay-sec>        # NEW (Crawl-delay style)
  BotShieldBotRateLimit <slug> <budget> <per>     # original
  ```

  - `Off` — disable post_config default synthesis. Specific entries
    (if any) still apply; just no automatic wildcard.
  - `<slug> <delay>` — 1 request per `<delay>` seconds. Matches
    robots.txt Crawl-delay convention. `0` admits all (per-slug
    opt-out sentinel).

- Default rate-limit synthesis. When `BotShieldEnabled On|LogOnly`
  is set and no operator `BotShieldBotRateLimit` directive was
  configured, post_config synthesizes `* 1 sec` automatically. Each
  directory slug gets its own counter at 1 req/sec — Crawl-delay-
  style, generous enough that well-behaved crawlers aren't
  affected, aggressive ones are throttled. Logs a NOTICE at
  startup so operators know it fired:

  ```
  mod_botshield: BotShieldBotRateLimit default applied: * 1 sec
  ```

  Operators wanting a different default: explicit
  `BotShieldBotRateLimit *` with their preferred budget.
  Operators wanting NO rate limit: `BotShieldBotRateLimit Off`.

### Changed

- `bs_bot_rate_check` honors `BotShieldEnabled LogOnly` —
  over-budget hits log `bot-rate:<slug>:observe` +
  `~rate_limited` would-outcome instead of returning 429.
  Mirrors the directive rate-limit cohort path's observe handling.

## 2026-05-03 (later)

### Added

- `BotShieldBotRateLimit` directive — slug-keyed rate limit per known
  bot identity. Args: `<slug-or-pattern-or-*> <budget> <per>`.

  ```apache
  BotShieldBotRateLimit googlebot 1000 min   # specific slug
  BotShieldBotRateLimit Google    5000 min   # pattern → all Google-family slugs share one budget
  BotShieldBotRateLimit *         200  min   # per-slug fallback
  ```

  Slug-or-pattern resolves against the bot directory (substring
  match, case-insensitive). A pattern like `Google` covers every
  directory entry whose pattern contains "Google" — `googlebot`,
  `google-other`, `google-extended`, etc. — sharing **one** counter
  across the family. A specific slug like `googlebot` matches just
  that one entry.

  `*` is the wildcard fallback — at post_config it pre-allocates
  one counter slot **per directory slug** that isn't covered by a
  specific rule. Each unmatched bot gets its own counter at the
  wildcard budget. This matches robots.txt's per-bot self-discipline
  semantic (each crawler reads the spec and obeys its own rate
  limit) without coordinating across bots. Two reserved aggregate
  slots additionally cap the `unknown-bot` and `fake-bot` labels
  (no stable slug; aggregate cap at the wildcard budget).

  Lookup at request time is one O(1) hash probe + one atomic CAS.
  Slot universe is bounded by the directory size (~640 today);
  pool size bumped to 2,048 (16 KB SHM) to leave headroom for
  directive rate limits, robots.txt groups, and directory growth.

  Over-budget responses: 429 + Retry-After + score+=50 +
  decision-log reason `bot-rate:<slug>`. Browser-classified UAs,
  unknown-ua, and empty-ua bypass the wildcard entirely (the rule
  applies to bots, not real users or unclassified clients).

  When `*` is configured, three reserved aggregate slots back the
  wildcard:
    - `unknown-bot` aggregate — caps requests with the
      heuristic-substring label (`bot`, `crawl`, `spider`, etc.) at
      the wildcard budget.
    - `fake-bot` aggregate — caps requests where the verified-bot
      pattern matched but the IP cross-check failed.
    - `wildcard-fallback` aggregate — catches "classified-as-known/
      verified-bot but the slug isn't in the post_config slug map"
      requests. This protects the gap between bot-directory updates
      arriving via watchdog refresh and the next graceful-restart
      (which would re-allocate per-slug counters at post_config).
      The actual slug name is preserved in the decision-log reason
      (`bot-rate:<slug>`), so the observability stays clean even
      while multiple unmapped slugs share one counter.

### Changed

- Rate-counter SHM pool: `BS_E21_RATE_SLOTS` raised from 256 → 2048
  (16 KB total). Headroom for the bot-rate-limit per-slug pre-
  allocation plus existing directive rate limits and robots.txt
  Crawl-delay groups.

- **robots.txt Crawl-delay rekeyed onto the slug-keyed bot-rate
  machinery** (formerly per-group-index slot pool at `policy.c:540`).
  Each robots.txt group's User-agent stanzas resolve at post_config
  to a slug set via the bot directory; the group's Crawl-delay
  becomes the slug entries' window. Both sources (directive +
  robots.txt) now feed one `slug → counter` map. Directive entries
  override robots.txt-derived ones on conflict (a config-time
  NOTICE flags overwrites).

  Operator-visible changes:

  - **Decision-log reason rename**: `robots-rate:<group_name>` →
    `bot-rate:<slug>`. Operators with grep/dashboard tooling on
    the old reason will need to update.
  - **Robots.txt User-agent stanzas that don't resolve to a
    directory slug get no enforcement.** Add matching entries to
    `vendor/bot-directory.local.json` if you want enforcement for
    a UA that isn't in the upstream directory.
  - **`BotShieldRateLimit` cohort matching no longer suppresses
    robots.txt Crawl-delay** (the legacy `directive_rate_matched`
    short-circuit was retired). Cohort directives and bot-rate are
    now independent families that compose — whichever trips first
    short-circuits the policy walk. Operators wanting "directive
    overrides robots.txt for this slug" should use
    `BotShieldBotRateLimit <slug> <budget> <per>` directly, which
    overwrites the robots.txt-derived entry on the same slug.

## 2026-05-03

### Changed (breaking — decision-log reasons)

- Unified UA-classifier reason vocabulary in the decision log. Every
  request now gets **exactly one UA-class tag**:

  | classifier outcome | reason | score |
  |---|---|---|
  | UA matched + IP cross-checked + IP confirmed | `verified-bot:name` | `BS_CREDIT_ALLOW` |
  | UA matched + IP cross-checked + IP failed | `fake-bot:name` | `BS_PENALTY_FAKE_BOT` |
  | UA matched, no IP check ran (any reason) | `known-bot:name` | 0 |
  | directory match (only) | `known-bot:slug` | 0 |
  | unknown-bot heuristic substring | `unknown-bot:token` | 0 |
  | browser-template match | `browser:slug` | 0 |
  | UA present, no classifier signal | `unknown-ua` | 0 |
  | no `User-Agent` header | `empty-ua` | 0 |

  Browser slugs identify the family from distinctive UA tokens:
  `chrome`, `chrome-mobile`, `chrome-ios`, `firefox`, `firefox-ios`,
  `edge`, `edge-mobile`, `edge-ios`, `safari`, `safari-mobile`,
  `opera`, `opera-ios`, `samsung`, `brave`, `duckduckgo`, `yandex`,
  `avg`, `avast`, `adguard`, `median`, `obsidian`, `scalboost`,
  `ios-webview`, plus a generic `browser` fallback when a template
  matched but no family token was recognized. Order of detection
  matters because Chromium derivatives carry `Chrome/` in their UA;
  the family-token check (`Edg/`, `OPR/`, `EdgA/`, `SamsungBrowser/`,
  `Brave`, etc.) wins before the bare-Chrome catch.

  Renames against the previous vocabulary:
  - `allow-bot:<name>` → `verified-bot:<name>` (now strictly means
    "IP cross-check ran and confirmed").
  - `allow-bot-ua:<name>` → `known-bot:<name>` **and the score
    drops to 0** (see breaking-behavior note below).
  - `bot-unverified:<name>` → `known-bot:<name>` (score unchanged
    at 0; the diagnostic stays available via the
    `bot_unverified_total` Prometheus counter).
  - `fake-<name>` → `fake-bot:<name>` (consistent prefix).

  New tags emitted that weren't before: `unknown-bot:<token>`,
  `unknown-ua`, `empty-ua`. These give the absence-of-tag the
  unambiguous meaning "browser-template match."

- **Behavior change for `BotShieldAllowBot * <name>` (UA-only mode):**
  declarations using `*` (operator opts out of IP verification) no
  longer grant `BS_CREDIT_ALLOW` to the matched UA. They contribute
  the UA pattern to the known-bot pool — score 0, no automatic
  pass-tier credit. Verified-bot credit now requires a real IP
  cross-check. Operators who relied on UA-only auto-pass should
  add a `rangesPath` (or comma-separated CIDR list) so the IP
  cross-check can actually run.

- `BotShieldClassify -verified-bots` semantics tightened to match.
  Previously, matched UAs were treated as "UA-only verified" and
  got `BS_CREDIT_ALLOW`. Now they degrade to `known-bot:<name>`
  with score 0 — neither verified-bot credit nor fake-bot penalty.
  Same fail-safe response to stale CIDR data, with the asymmetry
  removed.

  Operators with grep/dashboard tooling on the old reason names
  (`allow-bot:`, `allow-bot-ua:`, `bot-unverified:`, `fake-`)
  will need to update their patterns.

## 2026-05-02

### Added
- `BotShieldClassify` directive — granular per-pass control for the
  unified UA classifier. Two grammars:

      BotShieldClassify On|Off                     # standalone
      BotShieldClassify [All|None] [+/-flag]...    # compositional

  Recognized flags: `browsers`, `known-bots`, `verified-bots`,
  `unknown-bots`. Default is all four passes enabled. Mixing
  standalone with deltas is a config-time error; use `All`/`None`
  for the compositional form.

  Each disabled pass has a deliberate fail-safe so the module
  degrades permissively instead of silently misclassifying:
    - `-browsers` — `bs_ua_is_crawler_candidate` returns 0 for all
      UAs (treat as browsers), so robots.txt wildcard rules don't
      punish real users when templates are stale.
    - `-known-bots` — AC directory walk skipped; no
      `known-bot:<slug>` log tag.
    - `-verified-bots` — UA-classifier match still runs; IP
      cross-check skipped; matched UAs degrade to
      `known-bot:<name>` with score 0 (neither verified-bot credit
      nor fake-bot penalty). The natural response to stale CIDR
      data without disabling verified-bot detection entirely.
    - `-unknown-bots` — heuristic substring scan skipped.
- `vendor/verified-bots.json` — the bundled set of verified-bot
  built-ins (googlebot, bingbot, applebot, googleother, siteimprove)
  used to live as a hardcoded C array in `src/allowlist.c`. Moving
  it to a vendor JSON gains the same `.local`-overlay capability
  the bot-directory and browser-templates data sources already
  have, without any new module directive. Per-data-source layering
  is now consistent across the three:

      bot-directory   — external upstream + .builtin + .local (4 layers)
      top-user-agents — same 4 layers
      verified-bots   — .json + .local (3 layers, no .builtin
                        because no external upstream — we maintain
                        the curated set ourselves)

  Operators wanting to tune the set (disable `applebot`, add a
  custom bot, etc.) drop their changes into
  `vendor/verified-bots.local.json` (gitignored) and re-run
  `make build`.
- 180-day data-source staleness check at `post_config`. stat()s
  every loaded runtime file (bot-directory TSV, browser-templates
  TXT, per-bot CIDR ranges) and emits a `NOTICE` per file older
  than 180 days, pointing operators at the matching refresh tool
  plus the `BotShieldClassify` flag that would gracefully degrade
  the affected pass. Hardcoded threshold — generous enough that
  healthy deployments never see the message; the harder lever
  (`BotShieldClassify`) stays the configurable surface.

### Removed
- `BotShieldAllowVerifiedBots` directive. The verified-bot
  machinery is now activated by default (built-ins always load).
  Operators wanting "verified-bot opt-in" should use
  `BotShieldClassify -verified-bots` (skip the IP cross-check;
  matched UAs still get `allow-bot:` credit) or edit
  `vendor/verified-bots.local.json` to disable specific built-ins.
  Breaking change: existing configs containing the directive will
  fail with "Invalid command" until removed. The corresponding
  `bs_server_cfg.verified_bots_enabled` field and
  `bs_set_verified_bots` setter are gone too.

## 2026-05-01

### Added
- Vendored snapshot of the Cloudflare bot directory
  (`vendor/bot-directory.json`, ~600 entries) classifies known bots
  for robots.txt wildcard-rule application. Real browsers and
  custom apps bypass `User-agent: *` rules; entries matching the
  directory fall under wildcard policy. Codegenned into a static
  `bs_known_bots[]` table at build, optionally overridden by a
  TSV file at `BotShieldBotDirectory` and refreshed in-place via
  `tools/refresh-bot-directory.py` + a per-worker `mod_watchdog`
  tick (`BotShieldBotDirectoryRefreshInterval`, default 5 min).
  This is UA-only — *not* a trust authority. A scraper claiming
  `User-Agent: Googlebot/2.1` matches the directory and is
  classified as a bot, which is the desired outcome (subject to
  whatever wildcard policy applies). Real verification (UA token
  + IP-range cross-check) remains the verified-bot machinery.
- Browser-templates UA classifier
  (`vendor/top-user-agents.json`, top-100 real-browser UAs from
  microlinkhq/top-user-agents, codegenned into
  `generated_browser_templates.c`). Used by
  `bs_ua_is_crawler_candidate` in policy.c to distinguish real-
  browser UAs from everything else when applying robots.txt
  `User-agent: *` rules. Runtime override via
  `BotShieldBrowserTemplates` + `BotShieldBrowserTemplatesRefreshInterval`,
  same atomic-swap + one-tick destroy-grace pattern as the bot
  directory.
- `GoogleOther` to the built-in verified-bot allowlist
  (googlebot, bingbot, applebot, googleother, siteimprove). Closes
  a real coverage gap on help.hubzero.org where Google's research /
  experimental crawler family was matching no verified entry and
  getting challenged at silent tier despite being a legitimate
  Google crawler. UA token is the literal "GoogleOther" substring;
  IP ranges live in Google's `special-crawlers.json` (separate
  from Googlebot's `common-crawlers.json`) and are pulled into
  `/var/lib/botshield/bots/googleother.txt` by
  `tools/refresh-bot-ranges.sh`, now extended to cover both feeds.
- Live-reload of verified-bot CIDR files via per-vhost watchdog
  (`BotShieldAllowRangesRefreshInterval <0..86400>`, default 0 =
  disabled). On any mtime change to a canonical or sidecar file
  the module rebuilds the active range set in a private subpool
  and atomic-swaps it into place; the previously-active state is
  held one tick before destruction so in-flight readers can't
  deref freed memory. Per-worker (singleton=0) so each child
  picks up the change within one tick.
- Operator sidecar convention for verified-bot CIDRs:
  `<canonical-base>.local.txt` is co-loaded next to
  `<base>.txt` and concatenated into the active range set. The
  supported seam for adding custom enterprise-scanner IPs that
  aren't published in a vendor's public feed (e.g. dedicated
  Siteimprove enterprise scans contracted for one site) without
  fully redeclaring the bot via `BotShieldAllowBot` and without
  losing cron-driven canonical updates. Missing sidecar = no
  extras, malformed sidecar = hard error so operator typos
  surface.

### Changed
- Bot-directory request-time lookup switched from sequential
  `strcasestr` over the pattern array to Aho-Corasick. Single UA
  scan visits the trie at every position with O(|UA|) work
  regardless of pattern count; bench on real-traffic UAs shows
  ~152× speedup against the sequential baseline. ~5500 trie nodes
  for the current ~600-entry directory, ~200 KB per worker
  steady-state, fully owned by APR pools (no malloc). Build at
  post_config and on every runtime-override refresh; failure path
  falls back to sequential `strcasestr` rather than failing the
  module load.
- Folded `BotShieldLogOnly` into `BotShieldEnabled` as a tri-state
  TAKE1 directive: `On` (enforce) / `Off` (disabled) / `LogOnly`
  (observe). The standalone `BotShieldLogOnly` directive and
  `bs_server_cfg.log_only` field are removed. The new shape lives
  on `bs_dir_cfg.enabled` (already a tristate) at `RSRC_CONF |
  ACCESS_CONF` scope, so per-`<Location>` overrides work without
  any further refactor:

      BotShieldEnabled LogOnly                # vhost: observe
      <Location "/about">
          BotShieldEnabled On                 # /about: enforce
      </Location>

  The 5 enforcement-suppression sites (tier dispatch, BlockPath
  observe, RateLimit observe, heuristic-trigger executor,
  app-feedback filter, form-captcha) now read
  `dcfg->enabled == BS_ENABLED_LOGONLY` from `r->per_dir_config`
  instead of a server-scope flag.
- Interstitial response is now `403 Forbidden` with
  `X-Robots-Tag: noindex, nofollow` instead of `200 OK`. Search
  engines that hit a protected URL won't index the placeholder
  ("Verifying you are human...") as if it were the page content.
  Browsers still execute inline JS / captcha widgets on 4xx
  responses, so the silent-tier auto-solve and captcha widgets
  keep working for legitimate clients (matches the Cloudflare /
  DataDome / Akamai pattern).

### Fixed
- M9.2 metrics: tilde-prefixed counterfactual outcomes
  (`~challenge`, `~block`, `~rate_limited`) no longer log a
  `metrics: unknown outcome` warning per LogOnly-suppressed
  decision. The override applies only to operator-facing surfaces
  (decision-log line + `BS_OUTCOME` env); the counter bump uses
  the original `allow` because that's what actually happened.
  Per-family `*_observed_total` counters continue to capture the
  staging-volume signal.

### Hygiene
- Bench harness for the browser-templates UA classifier
  (`tools/bench-browser-classifier.c`) compares the custom
  classifier against a POSIX-regex equivalent built from the same
  template set. The custom path wins by ~19× on the test corpus,
  validating the choice not to lean on regex.
- Bench harness for the bot-directory lookup
  (`tools/bench-bot-directory.c`) compares sequential
  `strcasestr`, a first-byte bucket variant, and Aho-Corasick.
  AC wins ~152× over sequential, motivating the lookup switch.

## 2026-04-30

### Changed
- Renamed `BotShieldShadowMode` → `BotShieldLogOnly` (directive,
  setter `bs_set_shadow_mode` → `bs_set_log_only`, server-cfg field
  `shadow_mode` → `log_only`). The new name describes what the flag
  does in plain English; "shadow mode" was security jargon that
  required prior context to recognize. Per-rule `mode=observe` is
  unchanged. Beta software, no in-the-wild configs to migrate.
- `BotShieldLogOnly` now also short-circuits the tier-decision
  dispatch in `bs_handler` (was: trigger / rate-limit / block-path /
  form-captcha rules only). Non-PASS tier decisions emit an
  `outcome=~challenge` decision log line (the leading tilde marks a
  suppressed counterfactual: real action was allow, this is what
  *would* have been served) and decline rather than serving an
  interstitial. Lets an operator stage a bare `BotShieldEnabled On`
  on a fresh vhost and watch what the module would do without any
  client seeing a challenge.

## 2026-04-29

### Added
- `make test-clean` target — wipes pytest caches, reports,
  test-results, `.playwright-mcp/`, and `__pycache__/` trees.
  Spares `.venv/` and `.hypothesis/examples/`. Anchor check +
  `$(CURDIR)` absolute paths bound the `rm -rf` blast radius.
- CI job `docs-fresh`: rebuilds the site on PR, fails if rebuild
  produces a diff vs committed `docs/` — catches "edited a markdown
  source, forgot to rebuild" at PR review.
- Tracked `tests/site/` as the dev-vhost docroot (4-file fixture:
  `index.html`, `bs-custom-help.html`, `bs-custom-page.html`,
  `assets/logos/01-guardian.svg`).
- Fixed-rate benchmark `tests/bench/run-rate-bench.sh` — switched
  from vegeta to `oha` after vegeta / wrk2 / h2load all failed in
  WSL2 (ephemeral-port + worker-pool churn / empty histograms /
  HTTP/2-first throttling). Hits 1k/5k/10k RPS within 0.1% of
  target.

### Changed
- `bs_post_config` decomposed into 13 named phase helpers + 25-line
  orchestrator (911-line monolith → checklist; LTO inlines back so
  no runtime cost).
- `bs_handler` partial extraction: `bs_route_module_endpoint` and
  `bs_apply_safeguard` lifted out (567 → 468 lines); 10-step flow
  preamble at top.
- Archaeological label pass: ~23 stale markers pruned (PoC,
  "Phase 2", "review fix", "E14 (rework)").
- Self-review comment pass: SipHash-2-4 algorithm explanation in
  `shm.c`; longest-substring-match-anywhere algorithm explanation
  in `bs_ua_classify`; misc doc-drift fixes.
- Test docroot moved from gitignored `testsite/` to tracked
  `tests/site/`; existing testsite content preserved at
  `~/mod_botshield-testsite/`.
- `docs/` committed for GitHub Pages serving from `main:/docs`.

### Fixed
- Four documentation lies: stale "TODO: add a nonce SHM table" /
  "phase 2 nonce table" / "captcha stubs to form until that ships" /
  drifted `bs_check_policy` order list (now includes load + scope
  triggers).
- `bs_apply_rep_carry` docstring claimed flag-penalty floor that no
  longer existed.

### Removed
- Nightly cron for 8 h soak + LibFuzzer (cookie + robots, 30 m
  each) — both moved to `workflow_dispatch` only.
- `testsite/` directory (replaced by `tests/site/`).
- `REVIEWS.md` from repo (in-session tracking only).
- `/testsite/` from `.gitignore`.

### Hygiene
- Gitignore: `.hypothesis/`, `.claude/`, `.codex`,
  `.playwright-mcp/`, `.pytest_cache/` (anywhere), `.vscode/`.

---

## 2026-04-28

### Added
- Comparative benchmark suite at `tests/bench/` — 12 scenarios from
  baseline static-file through trigger-heavy / kitchen-sink config,
  wrk-driven, results saved per timestamp. Cookied scenario mints
  a real `_bs_verified` and replays. `LogLevel info` scenario
  measures decision-log overhead.
- Site handbook: 9 markdown source files (~2,400 lines) under
  `docs-src/`, rendered to `docs/` via `tools/build_site.py`.
- Performance section in `docs-src/deployment.md` with single-
  connection / saturation / fixed-rate framing.
- `BotShieldTrigger` — per-Apache-scope trigger directive (replaces
  `BotShieldFlagIP`). Allows `mode=observe` on
  `BotShieldFeedbackTrigger`.
- `.editorconfig` for indent / line endings / trailing whitespace.

### Changed
- File-split campaign continued (Phases 6–34): triggers, config
  (incl. directive-setter distribution), templates, formcaptcha,
  score, policy, heuristics; followed by `botshield.h` slimming
  (Phases 29–34) — score / triggers / challenge / captcha / robots
  types relocated to feature headers.
- Code-duplication review: three shared helpers —
  `bs_captcha_carry_and_mint`, `bs_captcha_https_post`,
  `bs_load_secret_file`.
- Renamed `PLAN.md` → `CHANGELOG.md` (in-source references).
- E12 (shadow mode) now also wraps the app-feedback path
  (`bs_app_feedback_filter` honors `shadow_mode` + per-trigger
  `observe`).

### Fixed
- Bench harness was measuring challenge-issuance, not pass-through —
  wrk's default no-UA / no-Accept-Language triggered heuristic
  challenges. Fixed by adding browser-like headers and a post-run
  bytes/req sanity check.
- `BotShieldShmSize` help text claimed wrong default.
- Security review batch (1 HIGH + 4 LOW/MED): assorted hardening.

### Removed
- Stripped security-scan severity labels (HIGH/MED/LOW #N) from
  source comments — review-history archaeology, not code rationale.

---

## 2026-04-27

### Changed
- **Cookie format: GCM-only on the wire.** Retired the legacy
  HMAC-only envelope. The dual-format compat switch from E8.1
  is gone; verify path is single-format. Secondary-key fallback
  (E16) still provides graceful rotation.
- **Secret consolidation.** Collapsed `app_feedback_secret` and
  `app_claims_secret` into one shared `app_integration_secret` —
  the two protocols' canonical forms are structurally distinct
  (single-field vs seven-field) so cross-replay isn't possible,
  and you no longer maintain two key files.
- **E14 rework: replaced adaptive-intensity machinery with
  `BotShieldFlagTrigger`.** Original E14 design used a flag-meta
  registry with `penalty=` / `next_difficulty=` / `next_tier=`
  fields; reworked design folds intensity into the unified trigger
  directive (`action=score score=N` + `action=tier_floor tier=…`)
  so adaptive policy lives in the same syntax as path / cookie /
  env triggers. Built-in defaults seeded in
  `bs_default_flag_triggers[]`.
- **File-split campaign begins** (Phases 1–5, 7–10): extracted
  `shm.{c,h}` (renamed from `botshield_shm`), `crypto.{c,h}`,
  `allowlist.{c,h}`, `metrics.{c,h}`; created `botshield.h`
  umbrella header for cross-cutting types; renamed
  `mod_botshield.c` → `botshield.c`. Then extracted `silent.{c,h}`,
  `captcha.{c,h}`, `bridge.{c,h}`, `challenge.{c,h}`,
  `cookie.{c,h}`, `load.{c,h}`.
- Path matcher consolidation: promoted `bs_rb_path_match` from the
  robots-internal helper to project-wide `bs_path_match`; retired
  the placeholder.
- Issuance refactor (Phase 1 + Phase 2): extracted carry-forward
  predicate + rep math, then install-side helper.
- Build with `-fvisibility=hidden`; only `botshield_module` is
  exported.

### Added
- `BotShieldCaptchaCABundle` directive (libcurl LOW finding).
- TLS pin + `CURLOPT_NOPROGRESS` on captcha siteverify.
- `BotShieldCookieDomain` directive surfaces in docs.
- Cacheline-segmented `bs_shm_header` (performance LOW finding).
- Documentation on shadow / observe modes, multi-vhost reputation
  isolation, scoring + tier-decision system, pending-cookie threat
  model.

### Fixed
- **MEDIUM #1: render-side carry-forward leak.** A path through the
  challenge-render hook could carry forward rep from an expired
  cookie (the issuance-side gate caught this; the render side did
  not). Closed; pytest regression added.
- DoS LOW: pre-validate numeric IPs via `inet_pton` instead of
  APR's flag-based filter.
- Decision-log: URL-encode `"` and `\` in quoted fields.
- `test_secret_rotation` flake: NUL-free hex key in fixture.
- Memory-safety / lifecycle / race LOW batch.

### Removed
- Bash test archive retired (paid off in M11.5).

---

## 2026-04-26

### Added
- Nonce SHM table for embedded-bootstrap one-time-use binding
  (security review MEDIUM #2 Phase 2). Closes replay-multiplier
  attack on the embedded-verify path.
- IP-bind on the bootstrap → verify pathway (security review
  MEDIUM #2 Phase 1) — bootstrap signs `(nonce, bound_ip,
  expires_at)` under a per-purpose HKDF key; verify rejects
  mismatches.
- HKDF-derived per-purpose keys (`bs:cookie:gcm:v1`, `:pending:v1`,
  `:bootstrap:v1`), cached at config-load (LOW #3).
- HttpOnly + `__Host-` prefix on `_bs_verified` (LOW #1, #2).
- `sudoers.d.example` for test-rig privilege scoping (LOW #15).
- Captcha-verify endpoint hardening (M8.1): pending cookie + per-IP
  rate limit + global in-flight semaphore.

### Changed
- Cookie tokenizer rewritten + post_config restore + mutex split
  (HIGH #3, #4, #6).
- Rate-counter: pack window+count into one u64 CAS for lock-free
  rollover.
- `bs_curl_easy_setopt` return codes checked via `BS_SETOPT` helper.
- `bs_read_form_body` surfaces 413 on overflow instead of silent
  truncate.
- libcurl: HTTPS-only protocol allowlist; abort on response
  truncation; reject connect to RFC1918 / loopback / link-local.
- Seqlocks: explicit C11 release/acquire memory ordering for
  portability across x86_64 / AArch64 / POWER.
- SHM writes: `trylock` + drop instead of blocking lock under
  contention — load-shed under volumetric DDoS.
- Graceful restart: clean SHM hand-off across generations
  (snapshot/restore pattern for the bs_shm global).
- `state_save`: bounded `timedlock` instead of indefinite blocking.
- Bloom: byte-atomic state-save copy + trylock on rotation.
- form-captcha: `AP_MODE_GETLINE` conformance + de-chunked header
  fix-up; reject body with embedded NUL (smuggling defense).
- Carry-forward: refuse expired cookies (replay-resistance).
- Embedded bootstrap: 120 s challenge expiry instead of cookie_ttl.
- Pending-cookie: dropped mis-justified 60 s post-expiry grace.
- Probe-saturation log throttle: SHM-shared, not per-worker
  (LOW #10).
- LibFuzzer harness: explicit per-input timeout / RSS + nightly CI
  job.
- Strict canonical-form check in cookie verify (INFO #1).
- `provision.sh` refuses to build if repo path is group/world-
  writable (preempts a make-install hijack on shared boxes).

### Fixed
- **E10**: `tier="safeguard"` decision lines bin to
  `BS_M_TIER_PASS` in metrics index (Gemini reviewer caught the
  unrecognized tier label dropping increments with WARNINGs).
- **E11**: `LoadWarmRise` / `LoadHotRise` / `LoadNormalFall` in
  `<VirtualHost>` were silently ignored — propagation loop only
  copied four of seven load fields up to `main_scfg`.
- **E12**: `BotShieldFormCaptcha` (E18) didn't honor global
  `BotShieldShadowMode` — added shadow gate after body-read but
  before policy decision (transport errors still fire; those are
  misconfiguration, not policy).
- **E13/E14**: vhost-scope state-file warning; flag-config
  stickiness across `apachectl graceful` (pristine
  `bs_flag_metadata_defaults` + reset helper); adaptive intensity
  through embedded-bootstrap PoW path.
- **E15**: E18 form-captcha success was wiping prior cookie's
  `forgive_window_start` / `_consumed` via `memset(&next_rep, 0)` —
  closed the forgiveness-washing seam.
- **E16**: pending-cookie path missed the `secret_secondary`
  fallback during key rotation. All four cookie-secret verify sites
  now have it.
- **E17**: same forgiveness-washing seam in
  `bs_embedded_verify_pow` and `bs_embedded_verify_provider`. Both
  now read prior cookie + carry forward via `bs_apply_rep_carry`.
- **E18**: filter readbytes contract violation; body-read off-by-
  one NUL; Set-Cookie `apr_table_set` clobbering prior rows. All
  six Set-Cookie write sites now use `apr_table_add`.

### Hygiene
- LOW batch: passes_* clamp + connect-timeout directive + header
  pinning + relaxed atomic loads on probe paths + tests/run reads
  JUnit XML + soak RSS scopes to dev pid + test client `verify`
  flag scoped to loopback.

---

## 2026-04-25

### Added
- **E10 — Challenge safeguard / anti-loop.** After N challenges in
  window without solving, fall through to `DECLINED` with reason
  `challenge-safeguard`. Defaults: threshold 5, window 1 h, TTL
  1 h. Cleared on successful solve.
- **E11.1 — Load-aware throttling sampler.** Three-state model
  (`normal` / `warm` / `hot`) sampled from Apache scoreboard's
  busy-worker ratio via mod_watchdog. Asymmetric hysteresis;
  optional file-based override.
- **E11.2 — `BotShieldLoadTrigger`** plumbed into the E7.2 trigger
  family. Predicates: `equal=`, `gte=`.
- **E12 — Shadow mode / dry-run.** Global
  `BotShieldShadowMode on` and per-rule `mode observe` for staging
  policy changes without enforcement. Decision log emits
  `would-block-path:<name>:observe` etc.
- **E13 — Per-vhost SHM namespacing.** Default-isolate via
  `siphash(ServerName)`, opt-in shared via `BotShieldShareScope
  <token>`. `(ip, ns_id)` matched on every SHM lookup.
- **E13.1 — Capacity headroom watchdog.** Per-table fill gauges
  (`shm_*_used` / `shm_*_capacity`); 5-minute rewarn cooldown.
- **E14 — Adaptive challenge intensity** (initial flag-registry
  approach; later reworked 2026-04-27 into `BotShieldFlagTrigger`).
- **E17 — Embedded silent verification.** Wrapper-injected silent-
  tier verifier; five endpoints under `<prefix>/embedded*`.
  `BotShieldSilentMode <interstitial|embedded>` directive.
  Adapters for invisible Turnstile (E17.2), reCAPTCHA v3 score
  (E17.3), invisible hCaptcha (E17.4a), invisible reCAPTCHA v2 +
  Friendly auto-start (E17.4b/c). M7 fallback on
  `worker-src 'self'` CSP.
- **E18 — Inline form captcha.** Verify-on-submit captcha for
  HTML forms; reuses M8 provider config; mints `_bs_verified` on
  success. **E18.3** JSON body support; **E18.4** form-widget
  shell at `/botshield/form-widget.js`.

### Changed
- Resolved open questions #3 (forgiveness cap) and #5 (secret
  rotation); renamed in-source comments to E16 / E17; renumbered
  E15..E17 to match physical PLAN order.
- E15 — Forgiveness cap per rolling window: per-cookie hourly cap
  (default 200 points) carried in canonical fields; cookie
  protocol bumped v1 → v2 (13 → 15 fields) with strict v1
  rejection.
- E16 — Cookie secret rotation: `BotShieldSecondarySecretFile`
  verify-only secondary key.
- E18 multipart explicitly out of scope (deferred → permanently
  deferred).

### Fixed
- De-flake `test_escalation_isolates_per_ip` and
  `test_robots_live_refresh`.

---

## 2026-04-24

### Added
- **E4 — Cookie triggers.** `BotShieldCookieTrigger <name>
  <predicate> <action>` matching on cookie presence / value /
  `_bs_verified`-state. Pass matches accumulate; first non-pass
  short-circuits.
- **E5 — App-to-module reputation feedback.** Bidirectional:
  inbound `X-BotShield-Feedback` HMAC-signed JSON envelope
  (login_success, fraud_detected, abuse_signal); output filter
  consumes the header, never forwards.
- **E6 — `BotShieldEnvTrigger`.** Trigger predicates that read
  `r->subprocess_env` populated by upstream Apache modules
  (`SetEnvIf`, `RewriteRule [E=...]`, ModSecurity v2).
- **E7.1 / E7.2 / E7.3 — Trigger family normalization.**
  `BotShieldTrigger` renamed to `BotShieldPathTrigger`; shared
  action engine (`bs_apply_trigger_action`); feedback-trigger
  directive + E5 wire-format change + dispatch order cleanup.
- **E8.1 — AES-256-GCM cookie confidentiality** + compat switch
  (later retired 2026-04-27 to GCM-only).
- **E8.2 — Signed `X-Botshield-Claims` module-to-app channel.**
- **E9 — `BotShieldRateLimitEscalate`.** Strike table (open-
  addressed, keyed `(ip, rule_slot, ns_id)`) escalates response on
  sustained rate-limit hits.

### Fixed
- **E4**: documented + tested "pass accumulates, non-pass short-
  circuits" semantics.
- **E5**: feedback header stripped on Apache's error-response
  chain too.
- **E6**: APR-table name case-insensitivity documented + redirect
  gate.

---

## 2026-04-23

### Added
- **E1 — Allow family / verified-bot policy.** `BotShieldAllow
  on` + `BotShieldAllowBot <name> <ua-pattern> [path |
  inline-cidrs | *]`. Trie-based UA classifier; per-bot CIDR
  files. Built-ins for Googlebot, Bingbot, Applebot.
- **E2.1 — Policy enforcement core.** `BotShieldRateLimit`,
  `BotShieldBlockPath`, cohort matcher (`*` / inline CIDRs /
  file-of-CIDRs), SHM-backed fixed-window counters.
- **E2.2 — In-module robots.txt parser.** RFC 9309 + Crawl-delay.
  Hand-rolled, defensive caps (1 MB / 2 KB lines / 64 groups /
  256 rules / 32 UAs / 3600 s). Live refresh via mod_watchdog
  (E2.2.2). `/botshield/policy-status` admin endpoint (E2.2.3).
  Per-segment-prefix UA matching.
- **E3 — Path-based triggers** (`BotShieldTrigger`, later renamed
  to `BotShieldPathTrigger` in E7.1).
- **E4 — Cookie triggers** (continues 2026-04-24).
- **M11.5 — bash test retirement.** Ported remaining bash tests;
  archived `tests/lib/common.sh` and friends.
- **M11.6 — Playwright + Chromium real-browser acceptance** layer.
  `@browser` marker. A11y smoke for the interstitial — caught a
  real fix in passing.
- **M11.7 — CI + reporting polish.** Rerun-on-flake for
  `@live_network`, HTML reports, CI split (test-fast vs
  test-browser), soak port to pytest.
- **M11.8 — Property + format testing.** Hypothesis cookie fuzz,
  Prometheus exposition-format validator, MPM matrix tests.
- **M11.8d — LibFuzzer harness for `bs_verify_cookie`.**

### Fixed
- M11.5 review fixes: `tests/run` false-green + false-fail; stale
  docs.
- M11.6 review fixes: pending-cookie Path test; stale marker docs.
- E1 review fixes: longest-match, drop UA prefilter, per-server
  merge.
- E2.1 review fixes: case-insensitive UA, ordered rule precedence.
- E2.2 review fixes: duplicate-UA union, server-scope inheritance.
- M11 audit fixes: inflight-cap test, screenshot-on-failure,
  cookie-fuzz hardening.
- Soak as pytest; LoadGenerator drain accounting.
- Security review fixes: captcha binding, bounded pre-HMAC parse,
  cookie-domain charset; overflow-guard `size*nmemb` in
  `bs_curl_write_cb`; tests/run empty-selection; strict directive
  parsing.

---

## 2026-04-22

The day everything basic shipped.

### Added
- **M2 — Signed-envelope verification protocol.** Crypto helpers,
  PoW algorithm registry (`sha256-zeros` + reserved rows for
  sha384 / sha512 / pbkdf2 / argon2id), HMAC-SHA-256 canonical-
  form challenge envelope.
- **M3 — Per-request scoring.** `bs_request_score`,
  `bs_score_add(penalty, ttl, reason)`, threshold ladder (pass /
  silent / hard / captcha), built-in heuristics.
- **M4a — Cookie reputation across re-issues.** Score + flag
  bitmap + passes_silent / passes_form / passes_captcha +
  challenged_at carried through forgiveness math.
- **M4b — Happy-path routing.** Score < silent → `DECLINED` with
  no cookie; legitimate users never carry BotShield state.
- **M5a — Flagged-IP SHM table** (rollback-proof bad-actor
  memory). **M5a.1**: IPv6 /64 aggregation.
- **M5b — Rotating two-buffer Bloom filter** for first-sight IP
  signal.
- **M6 — State persistence.** Snapshots flagged-IP +
  Bloom buffers across `apachectl graceful`. Save-path concurrency
  + directory-fsync follow-up. **M6.1**: periodic snapshots via
  mod_watchdog (soft dependency).
- **Catch-up M6.1 → M10.1.** Bulk merge bringing M7 (silent
  auto-submit), M8 (captcha tier with 6 providers + libcurl
  hardening), M8.1 (verify-endpoint hardening), M9.1/.2/.3
  (decision log + SHM counters + Prometheus), M10.1 (sanitizer
  build) into the tree.
- **M10.4 — Soak test runner + analyzer** (later ported to pytest
  in M11.7).
- **M11.1 — Tests/ framework skeleton** + 4 ported tests.
- **M11.2 — Per-milestone gates** ported into `tests/integration`.
- **M11.3 — Acceptance flows**, remaining provider ports, CI hook.
- **M11.4 — Pytest framework foundation** + 3 migrated POC tests.

### Fixed
- M11.3 review fixes: truth-in-advertising; `tests/run` false-pass
  hole.
- Stale `BotShieldCookieTTL` default in directive help.
- Muddled cookie-outcomes comment from M4b.

### Docs
- README section on deploying behind a reverse proxy.

---

## 2026-04-21

### Added
- **M0 — Skeleton.** Module builds, loads, reads config.
  `BotShieldDebug On` returns 403 "Hello World" to prove the hook
  fires.
- **M1 — Baseline challenge widget.** Self-contained HTML
  interstitial (inline CSS, JS, Guardian SVG; zero external
  assets). Client-side SHA-256 PoW with visible progress.
  Asset-extension pass-through. Chrome toggles for the verification
  widget customization.
- MIT LICENSE + README.
