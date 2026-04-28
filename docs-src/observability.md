# Observability

mod_botshield exposes three observability surfaces: a structured
per-decision log line, a Prometheus exposition endpoint, and a
`mod_status` contribution hook. All three derive from one
canonical decision-log vocabulary — there is no parallel taxonomy.

## Decision log

Every gated request emits a stable `key=value` structured line at
`info` level (`bs_decision_log`); challenge-issuing requests also
emit an `info` prose line carrying per-reason penalty values, and
pass-through decisions emit a `debug` prose line. The structured
line is the canonical surface — operators tail at `info` and parse
the `key=value` form; the prose lines are forensic detail.

The structured line:

```
mod_botshield: decision tier=<t> outcome=<o> ip=<i> score=<n>
    cookie=<c> provider=<p|-> alg=<a|-> reason="<r|->" path="<u>"
    [tag="<tag>"]
```

The decision log emits at Apache's `info` level. Default
`LogLevel warn` hides it. Bump just this module:

```apache
LogLevel mod_botshield:info
```

`reason`, `path`, and `tag` are double-quoted; embedded `"` and
`\` characters are URL-percent-encoded (`%22`, `%5C`) so an
adversarial URI can't break log-parser tokenization. Browser
traffic is unaffected — browsers already %-encode those bytes.

### Field vocabulary

The set of values each field can take is fixed and validated at
commit time by a small awk validator (`tests/scripts/decision-log-
awk-validator.sh`).

| Field | Values |
|---|---|
| `tier` | `none`, `pass`, `silent`, `form`, `captcha`, `safeguard` |
| `outcome` | `declined`, `challenged`, `verified`, `rejected`, `failopen`, `rate_limited`, `inflight_capped`, `pending_missing`, `misconfigured`, `debug` |
| `cookie` | `ok`, `expired`, `bad_sig`, `bad_format`, `absent`, `-` |
| `provider` | `-`, `turnstile`, `hcaptcha`, `recaptcha-v2`, `recaptcha-v3`, `friendly`, `geetest` |
| `alg` | `-`, `sha256-zeros`, `captcha-<provider>` |
| `reason` | quoted short string (comma-joined reason names) or `-` |

`tier=safeguard` is emitted for challenge-loop suppression
(pass-through with the flagged-IP entry preserved). For metrics it
bins into `tier_pass_total` since it's functionally pass-through;
operators wanting to dashboard the safeguard rate scrape the
decision log for `reason="challenge-safeguard"`.

### Reason-name vocabulary

The `reason` field is a comma-joined list of reason tokens captured
by `bs_score_add` calls during the request. Each token usually
takes the shape `<family>:<name>` so the source family is visible:

| Token shape | Source |
|---|---|
| `missing-user-agent`, `missing-accept-language`, `scraper-ua:<pattern>` | Built-in heuristics |
| `first-sight-ip` | Bloom filter |
| `verified-<name>`, `fake-<name>`, `bot-unverified` | allow list |
| `block-path:<name>` | block-path |
| `rate-limit-exceeded:<name>` | rate limit |
| `robots-block:<group>` | robots.txt |
| `flag-trigger:<flag>` | flag-trigger score action |
| `flag-tier-floor:<tier>` | flag-trigger tier-floor action |
| `path-trigger:<name>`, `cookie-trigger:<name>`, `env-trigger:<name>`, `load-trigger:<name>`, `feedback-trigger:<event>` | trigger families |
| `<reason>:observe` | Any of the above with `mode=observe` or under `BotShieldShadowMode on` (see [staging](../staging/index.html)) |
| `would-flag-trigger:<flag>:observe`, `would-block:<name>`, `would-rate-limit:<name>` | Observe-mode "would have done" reasons |
| `challenge-safeguard` | safeguard pass-through |

### Verbose prose line

Alongside the structured line, the prose line carries the per-
reason penalty values (not just the names) for forensic debugging:

```
mod_botshield: <action> effective=37 tier=silent heuristic=37
    cookie_score=0 reasons=[first-sight-ip:5,missing-accept-language:15,scraper-ua:python-requests:50]
```

Grep the log for the request, read the reasons array, see exactly
which signals contributed and how much.

## Prometheus metrics

The module exports SHM-backed counters and gauges at
`<prefix>/metrics` (default `/botshield/metrics`) in Prometheus 0.0.4
exposition format.

### Access control

The endpoint is unauthenticated. Wrap it in a `<Location>` with
your own ACL — operators usually scrape from a network the public
internet can't reach:

```apache
<Location /botshield/metrics>
    Require ip 10.0.0.0/8
    Require ip 2001:db8::/48
</Location>
```

Or with HTTP Basic auth, `Require valid-user`, etc.

### Counter inventory

Counter names mechanically track the decision-log enum vocabulary —
adding a new enum value adds one row to the string→index lookup
or the string simply doesn't increment a counter (with a visible
WARNING). Drift is loud, not silent.

| Counter family | Count | Source field |
|---|---|---|
| `botshield_tier_<t>_total` | 5 | one per non-`safeguard` tier; `safeguard` bins into `pass` |
| `botshield_outcome_<o>_total` | 10 | one per `outcome` enum |
| `botshield_cookie_<c>_total` | 5 | one per `cookie` enum |
| `botshield_provider_<p>_total` | 6 | one per built-in provider |

Plus persistence metrics:

| Metric | Type | Meaning |
|---|---|---|
| `botshield_state_saves_total` | counter | Successful state-file snapshots |
| `botshield_state_loads_total` | counter | Successful state-file loads at startup |
| `botshield_state_save_last_unix` | gauge | Unix time of last save |
| `botshield_state_save_last_bytes` | gauge | Bytes written in last save |
| `botshield_state_save_last_duration_microseconds` | gauge | Microseconds taken by last save |
| `botshield_state_load_last_kept` | gauge | Slots restored from last load |
| `botshield_state_load_last_dropped` | gauge | Slots discarded (TTL expired, format mismatch) |

Allow-list and policy counters:

| Metric | Type | Meaning |
|---|---|---|
| `botshield_bot_allow_total` | counter | Verified-crawler matches |
| `botshield_bot_fake_total` | counter | UA-claims-bot but IP doesn't match |
| `botshield_bot_unverified_total` | counter | UA matches a registered bot but no ranges loaded |
| `botshield_rate_limit_exceeded_total` | counter | Total rate-limit 429s |
| `botshield_block_path_hit_total` | counter | Total block-path 403s |
| `botshield_rate_limit_observed_total` | counter | Observe-mode rate-limit matches |
| `botshield_block_path_observed_total` | counter | Observe-mode block-path matches |
| `botshield_trigger_observed_total` | counter | Observe-mode trigger matches across families |

Plus SHM utilization gauges (computed at scrape time, cached 1 s
per worker):

| Metric | Type | Meaning |
|---|---|---|
| `botshield_shm_flagged_used`, `botshield_shm_flagged_capacity` | gauge | Flagged-IP slot utilization |
| `botshield_shm_strike_used`, `botshield_shm_strike_capacity` | gauge | Rate-limit-escalate strike-table utilization |
| `botshield_shm_safeguard_used`, `botshield_shm_safeguard_capacity` | gauge | Safeguard-table utilization |
| `botshield_bloom_bits_set_active`, `botshield_bloom_bits_set_warming` | gauge | Bloom buffer fill (current + warming buffer) |
| `botshield_bloom_window_seconds` | gauge | Configured Bloom rotation window |
| `botshield_captcha_inflight_current` | gauge | Outbound captcha-verify calls in flight |
| `botshield_cv_rate_slot_capacity`, `botshield_cv_log_slot_capacity` | gauge | Captcha-verify rate / log-throttle slot capacity |
| `botshield_load_state` | gauge | Current load tier (0=normal, 1=warm, 2=hot) |
| `botshield_load_state_changes_total` | counter | Load-state transitions since startup |

### Sample scrape

```
$ curl -s http://localhost/botshield/metrics | head -20
# HELP botshield_tier_pass_total Decisions where the request passed.
# TYPE botshield_tier_pass_total counter
botshield_tier_pass_total 1428931
# HELP botshield_tier_silent_total Decisions where the silent challenge tier was issued.
# TYPE botshield_tier_silent_total counter
botshield_tier_silent_total 84217
...
```

### Validating the format

A small validator script
(`tests/scripts/prometheus-format-validator.sh`) parses the entire
output to confirm 0.0.4 compliance. The pytest suite runs the
validator on every release.

## mod_status contribution

When `mod_status` is loaded and `ExtendedStatus On` is set, the
module contributes to `/server-status` via an optional hook.
Browser mode renders a compact HTML table; `?auto` mode renders
`BotShield<Name>: N` key-value lines parseable by external
collectors.

```
$ curl -s http://localhost/server-status?auto
...
BotShieldTierPassTotal: 1428931
BotShieldTierSilentTotal: 84217
BotShieldTierFormTotal: 18402
BotShieldTierCaptchaTotal: 4521
BotShieldFlaggedIpUsed: 38241
BotShieldFlaggedIpCapacity: 50000
...
```

mod_status is a recommended-but-optional dependency. Without it the
metrics endpoint and decision log still cover everything.

## Policy-status admin page

`<prefix>/policy-status` (default `/botshield/policy-status`) is a
plain-text dump of the rules currently being enforced — directive
rate-limits, directive block-paths, and robots.txt-derived groups.
Reads the same scfg fields `bs_check_policy` walks at request time,
so it's authoritative.

```
$ curl -s http://localhost/botshield/policy-status
mod_botshield policy at request time
====================================

Rate limits:
  api-burst    budget=60   window=60s  cohort=(*, 10.0.0.0/8)  shm_slot=0
  scrapers     budget=10   window=60s  cohort=(wget|curl|python, *)  shm_slot=1

Block paths:
  legacy-admin "/wp-admin/*"  cohort=(*, *)
  ...

robots.txt groups:
  user-agent=googlebot  rules=14  crawl_delay=0
  user-agent=*          rules=8   crawl_delay=10
```

Wrap the path in a `<Location>` with your own ACL — the page
reveals operator config (already on disk in `/etc/apache2/`) but no
cookie secrets or client IPs.

## Capacity headroom watchdog

The headroom watchdog (registered with `mod_watchdog`) samples
each SHM table's utilization once per minute. When utilization
crosses 50% it logs a NOTICE; at 70% a WARN; at 90% an ERROR.

```
mod_botshield: capacity headroom: flagged_ip 38241/50000 (76%)
mod_botshield: capacity headroom: bloom_a 73% filled (rotation
                 watcher will trigger at 50% past midpoint)
```

Operators usually use these as the cue to raise capacity directives
and reload — see [deployment](../deployment/index.html) for sizing guidance.

## Debug mode

`BotShieldDebug on` returns `403 "Hello World"` for every request
in scope. Useful as a smoke test that the module is intercepting
the request:

```apache
<Location /botshield-smoke>
    BotShieldDebug on
</Location>
```

```sh
curl -i http://localhost/botshield-smoke
# HTTP/1.1 403 Forbidden
# ...
# Hello World
```

Pair with `LogLevel mod_botshield:debug` to surface request-path
DEBUG lines (cookie parse traces, score-add per-reason values, SHM
slot probes). Disable in production — the verbose lines are
expensive at scale.

## Where to next

- Tier model and scoring: [operator model](../operator-model/index.html).
- Policy families: [policy](../policy/index.html).
- Captcha and app-bridge: [captcha](../captcha/index.html).
- Safe rule rollout: [staging](../staging/index.html).
- Common issues: [troubleshooting](../troubleshooting/index.html).
