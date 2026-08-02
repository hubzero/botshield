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
line is the canonical surface — tail at `info` and parse
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
LogLevel botshield_module:info
```

`reason`, `path`, and `tag` are double-quoted; embedded `"` and
`\` characters are URL-percent-encoded (`%22`, `%5C`) so an
adversarial URI can't break log-parser tokenization. Browser
traffic is unaffected — browsers already %-encode those bytes.

### Where the decision line goes

There are three routes, and they are not equivalent.

**1. The error log (always).** The line above is written by
`bs_decision_log` via `ap_log_rerror`, so it lands in whichever
`ErrorLog` covers the request — a vhost's own `ErrorLog` if it defines
one. This is the authoritative record: it needs no configuration, and
`accesslog=off` does not suppress it. It is also what the pytest suite parses.
The cost is Apache's `[timestamp] [:notice] [pid]` prefix, interleaving
with every other message, and boring passes demoted to `debug`.

**2. `BotShieldDecisionLog` (recommended for a dedicated file).** A
module-owned file, written at decision time:

```apache
BotShieldDecisionLog logs/botshield-decisions.log
# or hand rotation to Apache's helper:
BotShieldDecisionLog "|/usr/bin/rotatelogs /var/log/httpd/bs.%Y%m%d 86400"
```

Line shape — the same `key=value` payload as the error-log line, with an
ISO-8601 UTC timestamp in front and the User-Agent appended:

```
2026-07-31T15:50:07.677Z tier=pass outcome=block ip=203.0.113.9 score=0
    cookie=minted provider=- alg=- reason="env-trigger:login-trap:0"
    path="/login?return=..." ua="Mozilla/5.0 ..."
```

Because it is written by the module rather than mod_log_config, it is
**independent of the access log** — which is the point: it survives
`accesslog=off`, so you can keep flood traffic out of an archived access log
while still recording every decision in a rapidly-rotated detection log.
It also records boring passes at full fidelity, with no `LogLevel`
change.

There is deliberately **no HTTP status field**. This writes at decision
time, before the response is finalized, so `r->status` is not yet the
code the client receives — a block would log `200` while the handler
goes on to return `403`. `outcome=` is the authoritative decision and,
unlike a status code, distinguishes `block` from `rate_limited` from
`challenged`.

Operational notes: one descriptor per vhost, opened at `post_config`
before the children fork, one `apr_file_write` per line with no
request-path locking (lines are well under `PIPE_BUF`, so concurrent
appends from multiple processes do not interleave — the same guarantee
mod_log_config relies on). An `O_APPEND` descriptor survives logrotate's
`copytruncate`; a move-and-create rotation would strand it until the next
graceful restart, so use a piped spec if you want that style. If the log
cannot be opened, **startup fails** — a decision log you asked for and
did not get is a silent blind spot.

**3. A `CustomLog` via mod_log_config (legacy).** The module publishes
every field to `subprocess_env` (`BS_TIER`, `BS_OUTCOME`, …) plus a
`BOTSHIELD` marker, so a `CustomLog` can render them:

```apache
CustomLog logs/botshield-decisions.log botshield env=BOTSHIELD
```

Still supported, and the right choice if you want to compose botshield
fields into an existing format. Two limitations: it cannot survive
`accesslog=off` (mod_log_config serves every `CustomLog` from the one
hook `accesslog=off` breaks), and it must be declared **inside** the vhost if that
vhost defines its own `CustomLog` — mod_log_config's fallback semantics
mean a server-scope declaration never fires for such a vhost, which is
an easy way to end up with a silently empty decision log.

### Trimming access-log volume without losing decisions

To thin one specific `CustomLog` while keeping the others, gate it on the
decision rather than reaching for `accesslog=off`:

```apache
CustomLog logs/access.log combined "expr=%{reqenv:BS_OUTCOME} != 'block'"
```

### Field vocabulary

The set of values each field can take is fixed and validated at
commit time by a small awk validator (`tests/scripts/decision-log-
awk-validator.sh`).

| Field | Values |
|---|---|
| `tier` | `none`, `pass`, `silent`, `form`, `captcha`, `safeguard` |
| `outcome` | `allow`, `challenged`, `verified`, `block`, `redirect`, `failopen`, `rate_limited`, `inflight_capped`, `pending_missing`, `misconfigured`, `debug` (plus tilde-prefixed counterfactuals: `~challenge`, `~block`, `~rate_limited` under `BotShieldEnabled LogOnly`) |
| `cookie` | `ok`, `expired`, `bad_sig`, `bad_format`, `absent`, `minted`, `-` |
| `provider` | `-`, `turnstile`, `hcaptcha`, `recaptcha-v2`, `recaptcha-v3`, `friendly`, `geetest` |
| `alg` | `-`, `sha256-zeros`, `captcha-<provider>` |
| `reason` | quoted short string (comma-joined reason names) or `-` |

`tier=safeguard` is emitted for challenge-loop suppression: the
client gets a 302 redirect to a configured
`BotShieldSafeguardRedirectURL` (or to the built-in explainer at
`<BotShieldEndpointPrefix>/safeguard-info`) with the original URI
appended as `?return=<urlencoded path>`. The flagged-IP entry is
preserved. The pre-2026 silent pass-through is gone — silent
pass-through gave bots free access for the safeguard TTL, the
redirect makes the failure visible to legitimate clients and
gives bots a non-protected page to land on. The matching
`outcome=redirect` increments `outcome_redirect_total`; tier
counts go to `tier_pass_total` (safeguard bins into pass for the
tier counter).

### Reason-name vocabulary

The `reason` field is a comma-joined list of reason tokens captured
by `bs_score_add` calls during the request. Each token usually
takes the shape `<family>:<name>` so the source family is visible:

| Token shape | Source |
|---|---|
| `missing-user-agent`, `missing-accept-language`, `scraper-ua:<pattern>` | Built-in heuristics |
| `first-sight-ip` | Bloom filter |
| `verified-<name>`, `fake-<name>`, `bot-unverified` | allow list |
| `rate-limit-exceeded:<name>` | rate limit |
| `robots-block:<group>` | robots.txt |
| `flag-trigger:<flag>` | flag-trigger score action |
| `flag-tier-floor:<tier>` | flag-trigger tier-floor action |
| `path-trigger:<name>`, `cookie-trigger:<name>`, `env-trigger:<name>`, `load-trigger:<name>`, `feedback-trigger:<event>` | trigger families |
| `<reason>:observe` | Any of the above with `mode=observe` or under `BotShieldEnabled LogOnly` (see [staging](../staging/index.html)) |
| `would-flag-trigger:<flag>:observe`, `would-block:<name>`, `would-rate-limit:<name>` | Observe-mode "would have done" reasons |
| `challenge-safeguard` | safeguard redirect |

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
your own ACL — usually scrape from a network the public
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
| `botshield_outcome_<o>_total` | 11 | one per `outcome` enum (incl. `outcome_redirect_total` for safeguard) |
| `botshield_cookie_<c>_total` | 6 | one per `cookie` enum (incl. `cookie_minted_total` for always-mint events) |
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
| `botshield_rate_limit_observed_total` | counter | Observe-mode rate-limit matches |
| `botshield_trigger_observed_total` | counter | Observe-mode trigger matches across families (path/cookie/env/load/scope) |

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
rate-limits and robots.txt-derived groups. Reads the same scfg
fields `bs_check_policy` walks at request time, so it's
authoritative.

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
reveals site config (already on disk in `/etc/apache2/`) but no
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

Use these as the cue to raise capacity directives
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

Pair with `LogLevel botshield_module:debug` to surface request-path
DEBUG lines (cookie parse traces, score-add per-reason values, SHM
slot probes). Disable in production — the verbose lines are
expensive at scale.

## Where to next

- Tier model and scoring: [site model](../site-model/index.html).
- Policy families: [policy](../policy/index.html).
- Captcha and app-bridge: [captcha](../captcha/index.html).
- Safe rule rollout: [staging](../staging/index.html).
- Common issues: [troubleshooting](../troubleshooting/index.html).
