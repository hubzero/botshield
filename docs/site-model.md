# Site model

mod_botshield decides every request along two orthogonal axes: a
**tier** (what the visitor experiences) and a **score** (how
suspicious the request looks). This page explains the tier ladder,
how the score is composed, how cookie-carried reputation interacts
with the heuristics, and the day-to-day tuning workflow.

## Tier ladder

mod_botshield supports four user-facing tiers plus a passive
"safeguard" rendering reserved for challenge-loop suppression.

| Tier | What the user sees | When it fires |
|---|---|---|
| `pass` | Real content | `effective < BotShieldScoreNonInteractive` (default `< 20`) |
| `noninteractive` | "Checking your browser…" splash; auto-submits a SHA-256 PoW | `BotShieldScoreNonInteractive ≤ effective < BotShieldScoreInteractive` (default `20..49`) |
| `interactive` | reCAPTCHA-shaped checkbox interstitial; user clicks once, PoW runs | `BotShieldScoreInteractive ≤ effective < BotShieldScoreCaptcha` (default `50..79`) |
| `captcha` | Third-party provider widget (Turnstile / hCaptcha / reCAPTCHA / Friendly / GeeTest) | `effective ≥ BotShieldScoreCaptcha` (default `≥ 80`). Falls back to `interactive` if no provider configured on the scope |

A fifth value, `safeguard`, can appear in decision logs. It marks
challenge-loop suppression: a client that has been issued
challenges repeatedly within the safeguard window without ever
returning a verified cookie gets `tier=safeguard outcome=redirect`
— a 302 to a configured `BotShieldSafeguardRedirectURL` (or to the
built-in explainer at `<BotShieldEndpointPrefix>/safeguard-info`)
with the original URI appended as `?return=<urlencoded path>`. The
explainer covers common reasons the auto-check failed (JS disabled,
privacy extension, browser version) and offers a Continue link
back to the original URL. The flagged-IP entry is preserved so the
suspicious behavior is still recorded for downstream signals.

Below `BotShieldScoreNonInteractive` the module returns `DECLINED` to
Apache; the content handler runs as if mod_botshield weren't loaded.
**Legitimate visitors never see us and never receive a cookie.**

## Score composition

Every challenge decision is driven by a single signed integer
computed at request time:

```
effective = heuristic_total + cookie_score
```

- **`heuristic_total`** — sum of `bs_score_add` calls that fired
  during this request. Includes built-in heuristics, allow-list /
  rate-limit / robots / trigger families, and
  `BotShieldFlagTrigger action=score` effects fired by flags set on
  the IP or carried in the prior cookie.
- **`cookie_score`** — accumulated reputation in the prior
  `_bs_session` cookie, if one was presented and verified. Carries
  forward across requests; expires with the cookie TTL.

A separate **tier floor** can lift the final tier independent of the
score: any `BotShieldFlagTrigger action=tier_floor min=<tier>` that
fires on a set flag bit raises the chosen tier to AT LEAST that
level. Score-derived tier wins when it's already above the floor —
floors never silently downgrade. Floor lifts produce a
`flagtierfloor:<tier>` reason so the reasoning is visible in the
log.

## Built-in heuristic signals

These run on every request before any configured trigger
or cohort. Signs are absolute; the score either rises or stays put.

| Signal | Penalty | Reason in log |
|---|---|---|
| Missing `User-Agent` | +40 | `missinguseragent` |
| Missing `Accept-Language` | +15 | `missingacceptlanguage` |
| Scraper-pattern UA | +50 | `scraperua:<pattern>` |
| First-sight IP (not in Bloom filter) | +5 | `firstsightip` |
| Path-trigger fire (status=4xx) | per-rule `penalty=` | `path-trigger:<name>` |
| Rate-limit exceeded | +50 | `ratelimitexceeded:<name>` |
| Robots.txt Disallow | +100 | `robotsblock:<group>` |
| Honeypot hit (default flag trigger) | +60 | `flagtrigger:honeypot_hit` |
| Fake-bot detection (default flag trigger) | +80 | `flagtrigger:fake_bot` |
| Verified legit-crawler match | forces pass | `verified-<name>` |
| `app_verified_human` cookie credit (default flagtrigger) | -80 | `flagtrigger:app_verified_human` |
| Configured path / load / cookie / env / flag triggers with `action=score add=N` | configured | `<family>-trigger:<name>` |

Default thresholds and penalty values appear here for orientation.
Treat the source (`src/score.h`, `src/heuristics.c`,
`src/triggers.c`, defaults registered in `bs_default_flag_triggers`)
as authoritative — see the [directives](directives.md) page for
how to override every value.

The number of distinct reason entries recorded per request is
capped at 16 (`BS_SCORE_MAX_REASONS`). Past the cap, further calls
still contribute their penalty to the running total but are dropped
from the audit trail. A one-shot DEBUG line fires on the first drop
so the diagnostic surfaces under verbose logging.

## Cookie-carried reputation

Every pass through the handler mints `_bs_session` (or
`__Host-bs_session` on HTTPS). The cookie's role is twofold: it
carries any accumulated reputation forward, and on a fresh visitor
it serves as a per-session marker so the next request from the
same browser doesn't relitigate the entire heuristic stack. Most
issued cookies carry `trust=0` (no challenge solved yet) and are
"this user has been here" markers; cookies issued after a real
solve carry the accumulated reputation block.

The wire format is an authenticated AES-256-GCM envelope; the
plaintext fields include:

- `score` — running total
- `flags` — credit/penalty bits accumulated across challenges
- `passes_silent` / `passes_form` / `passes_captcha` — counters of
  successful challenges at each tier
- `forgive_window_start` / `forgive_consumed` — forgiveness-cap
  state (see below)
- `expires_at` — unix timestamp; cookies past expiry fail verify

The `Set-Cookie` line carries no `Expires` or `Max-Age` attribute
— it's a session cookie at the browser layer and gets discarded
when the browsing session ends. The `expires_at` field inside the
envelope still acts as a server-side hard cap, so a stale cookie
that survives via a long-lived browser session still gets
rejected on verify.

On subsequent requests that cookie's `score` field becomes the
`cookie_score` term in the composition. Repeated good behavior
accumulates negative `cookie_score` (forgiveness credit applied at
challenge-issue time); repeated suspicious behavior accumulates
positive.

The decision log's `cookie=` field reports one of `solved` (verified
**and** carrying challenge-solve proof), `ok` (verified, no such proof
— a presence cookie), `expired`, `bad_sig`, `bad_format`, `absent`, or
`minted` (no incoming cookie; this response set a fresh one).

`solved` and `ok` are disjoint and the distinction matters: under
always-mint every client holds a valid cookie after one request, so
`ok` says only that the client keeps a cookie jar. `solved` is the
only state that waives `firstsightip` / `droppedcookie`. The
`cookie_solved_total` and `cookie_ok_total` Prometheus counters track
the two separately, alongside `cookie_minted_total` for always-mint
volume, and the dashboard's cookie-state bar shows them as separate
slices.

Expect few `cookie=solved` lines in the decision log itself: a client
holding solve proof usually passes, and passes are not actionable
outcomes, so they are counted but not written. Read the counters, not
the log, for this ratio.

The reputation persists across requests but expires with the cookie
TTL (`BotShieldCookieTTL`, default 1 hour). After expiry users
start fresh.

### Forgiveness

Each successful challenge applies a negative score credit
("forgiveness") so a client that has just proven itself doesn't
get re-challenged on the next request:

| Tier | Default credit | Directive |
|---|---|---|
| `noninteractive` | -10 | `BotShieldForgivenessNonInteractive` |
| `interactive` | -25 | `BotShieldForgivenessInteractive` |
| `captcha` | -50 | `BotShieldForgivenessCaptcha` |

### Forgiveness cap

To prevent farming — bot operators stockpiling forgiveness credit by
solving many cheap challenges then trading the score down — the
cookie carries a per-client hourly cap on accumulated forgiveness:

```apache
BotShieldForgivenessCapPerHour 200
```

Default is 200 points per rolling hour, ≈ 4–8 nochallenge outcomes
worth of credit. The cap state lives in the cookie itself, so
forgiveness honors the cap across cookie re-issues without server-
side bookkeeping.

Set to 0 to disable the cap (legacy behavior). Set to a smaller
value for stricter farming resistance.

### Carry-forward gate

When the module mints a fresh cookie (silent verify, form-captcha
verify, captcha-verify, embedded-verify), it tries to carry the
prior cookie's reputation block forward. Carry-forward is gated:

- `signature mismatch` → reject; rep bytes can't be trusted.
- `expired` → reject; indefinite reputation transfer is exactly the
  evasion this gate prevents.
- pre-auth errors with no rep struct populated → reject.
- everything else → carry forward, apply the per-tier forgiveness
  credit through the cap, increment the matching `passes_*`
  counter.

## Inspecting decisions

Every decision emits two log lines: a human-readable prose line and
a stable `key=value` structured line. The structured line is what
you query when tuning:

```
mod_botshield: decision tier=noninteractive outcome=challenged ip=192.0.2.42
    score=37 cookie=absent provider=- alg=sha256zeros
    reason="firstsightip,missingacceptlanguage" path="/login"
```

Bump the module's log level to make these visible:

```apache
LogLevel botshield_module:info
```

The `reason` field is the comma-joined reason names captured by
`bs_score_add`. The `tag` field (when present) is the
configured `log=<tag>` value from the matching trigger. See
[observability](observability.md) for the full decision-log
vocabulary.

For verbose debugging — the per-reason penalty values, not just the
names — the prose log line at `info` level carries the full
breakdown:

```
mod_botshield: <action> effective=37 tier=noninteractive heuristic=37
    cookie_score=0 reasons=[firstsightip:5,missingacceptlanguage:15,scraperua:python-requests:50]
```

Grep the log for the request, read the reasons array, see exactly
which signals contributed and how much.

## Tuning workflow

1. Start with `BotShieldEnabled LogOnly` to dry-run all rules without
   enforcement (see [staging](staging.md)).
2. Watch the decision log for several days under real traffic.
3. Inspect the distribution of `effective` and per-reason
   contributions. The `botshield_tier_<t>_total` and
   `botshield_outcome_<o>_total` Prometheus counters at
   `<prefix>/metrics` give the same data without grep.
4. Adjust thresholds and per-rule penalties based on observed
   distributions:
   - Too many challenges on legitimate traffic → raise
     `BotShieldScoreNonInteractive` / `BotShieldScoreInteractive` /
     `BotShieldScoreCaptcha`, or lower the offending heuristic's
     penalty.
   - Bots slipping through → lower thresholds, raise scraper-UA
     penalty, add `BotShieldRule` rules for known-bad paths.
5. Switch to `BotShieldEnabled On` when satisfied.
6. Subsequent rule additions can be staged with per-rule
   `mode=observe` without affecting the rest.

## How tier dispatch maps to outcomes

The combination of tier and outcome in the decision log captures
the full lifecycle of a request. Not every (tier, outcome) pair is
reachable; the common ones:

| tier | outcome | What happened |
|---|---|---|
| `pass` | `allow` | Score below silent threshold; real handler ran |
| `pass` | `verified` | Valid cookie; allowed to real handler |
| `noninteractive` | `challenged` | Interstitial served; client is solving PoW |
| `noninteractive` | `verified` | Client solved PoW; cookie minted |
| `noninteractive` | `~challenge` | LogOnly: would have served interstitial |
| `interactive` | `challenged` | Form-PoW interstitial served (HTTP 403) |
| `interactive` | `verified` | Client solved form PoW; cookie minted |
| `captcha` | `challenged` | Captcha widget served (HTTP 403) |
| `captcha` | `verified` | Provider siteverify accepted; cookie minted |
| `captcha` | `failopen` | Provider siteverify timed out; treated as pass to avoid blocking on a third-party outage |
| `captcha` | `rate_limited` | Per-IP captcha-verify rate cap exceeded |
| `captcha` | `inflight_capped` | Global captcha-verify in-flight cap exceeded |
| `safeguard` | `redirect` | challenge-loop suppression; 302 to the explainer (or operator-configured URL) with `?return=<original URI>` |

See [observability](observability.md) for the complete enum
vocabulary and how it maps to counters.

## Where to next

- Allow lists, rate limits, robots, triggers: [policy](policy.md).
- Captcha integration: [captcha](captcha.md).
- Safe rule rollout: [staging](staging.md).
- Metrics and dashboards: [observability](observability.md).
