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
| `pass` | Real content | `effective < BotShieldScoreSilent` (default `< 20`) |
| `silent` | "Checking your browser…" splash; auto-submits a SHA-256 PoW | `BotShieldScoreSilent ≤ effective < BotShieldScoreHard` (default `20..49`) |
| `form` | reCAPTCHA-shaped checkbox interstitial; user clicks once, PoW runs | `BotShieldScoreHard ≤ effective < BotShieldScoreCaptcha` (default `50..79`) |
| `captcha` | Third-party provider widget (Turnstile / hCaptcha / reCAPTCHA / Friendly / GeeTest) | `effective ≥ BotShieldScoreCaptcha` (default `≥ 80`). Falls back to `form` if no provider configured on the scope |

A fifth value, `safeguard`, can appear in decision logs. It marks
the challenge-loop suppression: a client that has been issued
challenges repeatedly within the safeguard window without ever
returning a verified cookie gets `tier=safeguard outcome=declined`
— pass-through to the real content with no challenge — to break the
loop. The flagged-IP entry is preserved so the suspicious behavior
is still recorded for downstream signals.

Below `BotShieldScoreSilent` the module returns `DECLINED` to
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
  rate-limit / block-path / robots / trigger families, and
  `BotShieldFlagTrigger action=score` effects fired by flags set on
  the IP or carried in the prior cookie.
- **`cookie_score`** — accumulated reputation in the prior
  `_bs_verified` cookie, if one was presented and verified. Carries
  forward across requests; expires with the cookie TTL.

A separate **tier floor** can lift the final tier independent of the
score: any `BotShieldFlagTrigger action=tier_floor min=<tier>` that
fires on a set flag bit raises the chosen tier to AT LEAST that
level. Score-derived tier wins when it's already above the floor —
floors never silently downgrade. Floor lifts produce a
`flag-tier-floor:<tier>` reason so the reasoning is visible in the
log.

## Built-in heuristic signals

These run on every request before any configured trigger
or cohort. Signs are absolute; the score either rises or stays put.

| Signal | Penalty | Reason in log |
|---|---|---|
| Missing `User-Agent` | +40 | `missing-user-agent` |
| Missing `Accept-Language` | +15 | `missing-accept-language` |
| Scraper-pattern UA | +50 | `scraper-ua:<pattern>` |
| First-sight IP (not in Bloom filter) | +5 | `first-sight-ip` |
| Block-path match | +100 | `block-path:<name>` |
| Rate-limit exceeded | +50 | `rate-limit-exceeded:<name>` |
| Robots.txt Disallow | +100 | `robots-block:<group>` |
| Honeypot hit (default flag trigger) | +60 | `flag-trigger:honeypot_hit` |
| Fake-bot detection (default flag trigger) | +80 | `flag-trigger:fake_bot` |
| Verified legit-crawler match | forces pass | `verified-<name>` |
| `app_verified_human` cookie credit (default flag-trigger) | -80 | `flag-trigger:app_verified_human` |
| Configured path / load / cookie / env / flag triggers with `action=score add=N` | configured | `<family>-trigger:<name>` |

Default thresholds and penalty values appear here for orientation.
Treat the source (`src/score.h`, `src/heuristics.c`,
`src/triggers.c`, defaults registered in `bs_default_flag_triggers`)
as authoritative — see the [directives](../directives/index.html) page for
how to override every value.

The number of distinct reason entries recorded per request is
capped at 16 (`BS_SCORE_MAX_REASONS`). Past the cap, further calls
still contribute their penalty to the running total but are dropped
from the audit trail. A one-shot DEBUG line fires on the first drop
so the diagnostic surfaces under verbose logging.

## Cookie-carried reputation

Once a request passes (challenged or not), mod_botshield issues a
`_bs_verified` (or `__Host-bs_verified` on HTTPS) cookie carrying
the user's accumulated reputation. The wire format is an
authenticated AES-256-GCM envelope; the plaintext fields include:

- `score` — running total
- `flags` — credit/penalty bits accumulated across challenges
- `passes_silent` / `passes_form` / `passes_captcha` — counters of
  successful challenges at each tier
- `forgive_window_start` / `forgive_consumed` — forgiveness-cap
  state (see below)
- `expires_at` — unix timestamp; cookies past expiry fail verify

On subsequent requests that cookie's `score` field becomes the
`cookie_score` term in the composition. Repeated good behavior
accumulates negative `cookie_score` (forgiveness credit applied at
challenge-issue time); repeated suspicious behavior accumulates
positive.

The reputation persists across requests but expires with the cookie
TTL (`BotShieldCookieTTL`, default 1 hour). After expiry users
start fresh.

### Forgiveness

Each successful challenge applies a negative score credit
("forgiveness") so a client that has just proven itself doesn't
get re-challenged on the next request:

| Tier | Default credit | Directive |
|---|---|---|
| `silent` | -10 | `BotShieldForgivenessSilent` |
| `form` | -25 | `BotShieldForgivenessForm` |
| `captcha` | -50 | `BotShieldForgivenessCaptcha` |

### Forgiveness cap

To prevent farming — bot operators stockpiling forgiveness credit by
solving many cheap challenges then trading the score down — the
cookie carries a per-client hourly cap on accumulated forgiveness:

```apache
BotShieldForgivenessCapPerHour 200
```

Default is 200 points per rolling hour, ≈ 4–8 challenge-passes
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
mod_botshield: decision tier=silent outcome=challenged ip=192.0.2.42
    score=37 cookie=absent provider=- alg=sha256-zeros
    reason="first-sight-ip,missing-accept-language" path="/login"
```

Bump the module's log level to make these visible:

```apache
LogLevel botshield_module:info
```

The `reason` field is the comma-joined reason names captured by
`bs_score_add`. The `tag` field (when present) is the
configured `log=<tag>` value from the matching trigger. See
[observability](../observability/index.html) for the full decision-log
vocabulary.

For verbose debugging — the per-reason penalty values, not just the
names — the prose log line at `info` level carries the full
breakdown:

```
mod_botshield: <action> effective=37 tier=silent heuristic=37
    cookie_score=0 reasons=[first-sight-ip:5,missing-accept-language:15,scraper-ua:python-requests:50]
```

Grep the log for the request, read the reasons array, see exactly
which signals contributed and how much.

## Tuning workflow

1. Start with `BotShieldEnabled LogOnly` to dry-run all rules without
   enforcement (see [staging](../staging/index.html)).
2. Watch the decision log for several days under real traffic.
3. Inspect the distribution of `effective` and per-reason
   contributions. The `botshield_tier_<t>_total` and
   `botshield_outcome_<o>_total` Prometheus counters at
   `<prefix>/metrics` give the same data without grep.
4. Adjust thresholds and per-rule penalties based on observed
   distributions:
   - Too many challenges on legitimate traffic → raise
     `BotShieldScoreSilent` / `BotShieldScoreHard` /
     `BotShieldScoreCaptcha`, or lower the offending heuristic's
     penalty.
   - Bots slipping through → lower thresholds, raise scraper-UA
     penalty, add `BotShieldPathTrigger` rules for known-bad paths.
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
| `silent` | `challenged` | Interstitial served; client is solving PoW |
| `silent` | `verified` | Client solved PoW; cookie minted |
| `silent` | `~challenge` | LogOnly: would have served interstitial |
| `form` | `challenged` | Form-PoW interstitial served (HTTP 403) |
| `form` | `verified` | Client solved form PoW; cookie minted |
| `captcha` | `challenged` | Captcha widget served (HTTP 403) |
| `captcha` | `verified` | Provider siteverify accepted; cookie minted |
| `captcha` | `failopen` | Provider siteverify timed out; treated as pass to avoid blocking on a third-party outage |
| `captcha` | `rate_limited` | Per-IP captcha-verify rate cap exceeded |
| `captcha` | `inflight_capped` | Global captcha-verify in-flight cap exceeded |
| `safeguard` | `allow` | challenge-loop suppression; pass-through |

See [observability](../observability/index.html) for the complete enum
vocabulary and how it maps to counters.

## Where to next

- Allow lists, rate limits, robots, triggers: [policy](../policy/index.html).
- Captcha integration: [captcha](../captcha/index.html).
- Safe rule rollout: [staging](../staging/index.html).
- Metrics and dashboards: [observability](../observability/index.html).
