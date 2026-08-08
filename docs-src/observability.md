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
BotShieldDecisionLog logs/botshield.log
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
CustomLog logs/botshield.log botshield env=BOTSHIELD
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

### The decision log

`BotShieldDecisionLog` defaults to **`logs/botshield.log`** (server-root
relative, like Apache's own `ErrorLog`) for any server with
`BotShieldEnabled` somewhere in it. A module that is loaded but never
switched on writes nothing, so installing the package does not litter
`/var/log/httpd` on hosts that never turn it on.

Defaulting it on is what makes the "recorded somewhere" guarantee hold
without configuration: access-log suppression is also a default, so
without a decision log by default the two would compose into requests
that appear in no log at all.

Set the directive to move it, or to hand it to a piped-log program that
owns its own rotation.

### Controlling decision-log volume

```apache
BotShieldDecisionLog logs/botshield.log \
    outcomes=block,verified,rate_limited,misconfigured,failopen,redirect
```

| Key | Effect |
|---|---|
| *(omitted)* | The **default set** — `block`, `verified`, `rate_limited`, `misconfigured`, `failopen`, `redirect` — **union whatever `BotShieldAccessLog` is suppressing** for that request. |
| `outcomes=<list>` | Exactly these, overriding the union. Each is written **in full**. |

**The union is the point.** Suppressing a line from the access log and
omitting the same outcome from the decision log makes the request vanish
from every log on the box: it happened, the server answered it, and
nothing records it. Deriving the default from the access-log mask makes
*"every request the server answered is recorded somewhere"* a property
of the module, rather than of an operator remembering to keep two
directives in step.

It is computed per request, because `BotShieldAccessLog` is
per-directory while `BotShieldDecisionLog` is per-server — there is no
single suppression set at config time to union with.

Requests BotShield never evaluated are never suppressed from the access
log, so the invariant covers them too.

**Naming `outcomes=` overrides the union** and accepts the resulting
gap. That is a legitimate choice — the volume is real — but it is now an
explicit one.

`all` is accepted in the list as an explicit "everything".

**Why filter by outcome.** Under a flood the log is dominated by one
repeated outcome — measured live at 5,000 near-identical `challenged`
lines a minute, **258 MB/hr** at 1,125 bytes a line.

Whatever retention your rotation buys, that volume is what spends it.
Work it out for your own rule rather than assuming: a size-triggered
rotation checked on a timer does **not** rotate the moment the size is
hit, only at the next check, so the live file grows to a full check
interval's worth of data no matter how small the size threshold is. The
deployment this was built for runs `size 100M rotate 6 compress` from an
hourly cron, which under this load means each rotated file covers one
hour and roughly six hours are kept — the live file reaching ~258 MB
between checks, and the seven files totalling ~570 MB compressed.

Filtering trades per-request detail for that retention. The counts never
move: every outcome stays exact in `/botshield/metrics` and on the
dashboard.

**Why there is no sample rate.** It would be the obvious way to keep a
cheap trace of the noisy outcome, and it is deliberately not offered. A
security log's most important property is that an absent line means the
event did not happen. Sampling destroys that for every outcome it
touches, and destroys it silently — you cannot tell a quiet period from
a thinned one by reading the file. An outcome is either recorded
completely or not at all.

What you give up is per-request detail for the outcomes you exclude, not
knowledge that they occurred: **every outcome is always counted** in
`/botshield/metrics` and on `/botshield/dashboard`, exactly, regardless
of this setting. Filtering only decides whether a per-request line is
written.

When you do need forensic detail on a filtered outcome — attacker IPs,
UA patterns, paths — add it to the list for as long as the incident
lasts and accept the volume. That is a deliberate, reversible decision
rather than a standing lottery.

Startup states exactly what is being recorded, because a filtered log
looks identical to a complete one from the outside:

    decision log active: logs/botshield.log (outcomes=verified,
    block,failopen,rate_limited,misconfigured,redirect only, each logged in
    full; other outcomes get no per-request line but are still counted
    exactly in /botshield/metrics and the dashboard)

Note this lands in the **vhost's** `ErrorLog`, not the main one.

### Controlling the access log

`BotShieldAccessLog` decides whether a request BotShield acted on also
gets an Apache access-log line. Scope-level (`RSRC_CONF | ACCESS_CONF`)
and keyed on the **outcome**:

```apache
<LocationMatch "^/(login|register)(/|$)">
    BotShieldEnabled   On
    BotShieldAccessLog suppress=challenged,block
</LocationMatch>
```

| Form | Effect |
|---|---|
| *(omitted)* | **Default.** Suppresses `challenged`, `block`, `rate_limited`, `redirect` — the outcomes where BotShield generated the response and the application never ran. |
| `on` | Restores full logging. |
| `off` | Suppresses every outcome BotShield decided on. |
| `suppress=<outcome[,…]>` | Suppresses exactly those. |

The default deliberately leaves the access log **incomplete** relative
to what the server answered. That is a real tradeoff in a file many
sites treat as a system of record, so it is announced once at startup
rather than left to be discovered by someone hunting for missing
requests:

    access-log lines are suppressed by default for responses BotShield
    generated (challenged, block, rate_limited, redirect) - those requests
    never reached the application. They are still counted in
    botshield_requests_total and on the dashboard. 'BotShieldAccessLog on'
    restores full logging.

`allow` and the verify-endpoint outcomes are **not** suppressed by
default: those either reached the origin or are the module answering its
own endpoint, and both are real traffic. Nothing is ever hidden from
`botshield_requests_total`, the dashboard, or the decision log.

If you audit from the access log, set `BotShieldAccessLog on`.

Outcome names are the decision-log vocabulary, validated against the
same table the log and metrics use.

**Why this exists next to the `accesslog=on|off` action key.** That key
is a *trigger* action, so it only covers requests some rule's predicate
matched. Once the scoring defaults started raising challenges on their
own, that stopped being the same set: a scope could be fully protected
and still writing megabytes an hour of access-log noise from challenged
requests no rule happened to match — with the only workaround being to
invent a rule whose sole purpose was logging. Measured on a live flood:
`/register` challenges were adding ~31 MB/hr that way. This directive
follows the decision instead of the rule.

The action key still works and is still the right tool for
"this specific rule's matches shouldn't be logged". Both compose;
either one suppressing is enough.

**Two things it deliberately will not do.** Requests BotShield never
evaluated always log — this cannot silence the site. And under
`LogOnly`, a counterfactual (`~block`) is not suppressed: nothing was
enforced, the origin answered, and hiding it would misrepresent real
traffic on the strength of a decision that never took effect.

Suppressing the access log does not touch the decision log, which is
the point — the access log is the traffic record, the decision log is
the security record.

### Observing robots.txt before enforcing it

Two directives let robots.txt-derived rules record without acting, so a
file most sites publish and never enforce can be measured first:

```apache
BotShieldRobotsMode   observe                  # Disallow -> ~block, no 403
BotShieldBotRateLimit * 1 sec mode=observe     # Crawl-delay -> ~rate_limited, no 429
```

Both are independent of `BotShieldEnabled`, so a scope can enforce its
scoring while robots.txt stays advisory. `BotShieldRobotsMode observe`
also suppresses the +100 score and the 1-hour flag, not just the status
— otherwise the penalty follows the client into later requests and
changes its tier, which is enforcement by another route.

`mode=enforce|observe` may follow any `BotShieldBotRateLimit` form. It
matters most for the **synthesised** wildcard: when the module is
enabled at vhost scope and no rule is written, a `* 1 sec` limit is
created automatically. Nobody chose it, and it enforces wherever
`BotShieldEnabled On` applies — on the deployment this was built for,
that meant real 429s to verified Bingbot before anyone had decided to
rate-limit it. Writing the rule out explicitly with `mode=observe`
replaces the synthetic default and keeps the evidence without refusing
anyone.

### Client classification — who is visiting

**Retired and non-existent agent identities** are classified `fake-bot`
without any IP check. Three are recognised: `Google-Extended`, which was
never a crawler at all (a robots.txt control token governing whether
content Googlebot already fetched may train Gemini), and `Claude-Web`
and `anthropic-ai`, both retired by Anthropic in favour of `ClaudeBot` /
`Claude-User` / `Claude-SearchBot`.

Unlike the allow-list fake-bot path these need no ranges file: no IP
could make them genuine. The check runs *before* the directory walk,
which matters because upstream carries a broad bare-`Claude` pattern
that would otherwise classify `Claude-Web` as a trusted known bot.

### Observability endpoints stay out of the access log

`/botshield/dashboard`, `/botshield/metrics` and
`/botshield/policy-status` are suppressed from the access log by default
and recorded in the decision log as `outcome=observe`. They are the
measuring instrument, not traffic: a dashboard left open on a 10s
refresh measured 8.1% of all requests on one deployment, distorting
every figure derived from the access log.

They are deliberately not routed through the normal decision path, so
viewing the dashboard does not count as a decision and cannot inflate
the numbers the page displays. Volume is still visible as
`botshield_responses_observe_total`.



Every request is classified once at `post_read_request` and the result
cached, so recording it costs a pointer deref. Six classes, on the
dashboard as **Client classification** and in Prometheus as
`botshield_clients_*_total`:

| Class | Meaning |
|---|---|
| `browser` | UA matched a real-browser template. |
| `verified-bot` | UA matched the allow list **and** the IP is in that crawler's published ranges. |
| `known-bot` | UA is in the bot directory, but not IP-verified. |
| `unknown-bot` | UA has bot-shaped tokens with no directory entry. |
| `fake-bot` | UA claims a crawler, IP is outside its published ranges — spoofed. |
| `unknown` | Matched no classifier. |

The distinction that matters operationally is `verified-bot` vs
`fake-bot`: both send the same User-Agent, and only the IP cross-check
separates them. A rising `fake-bot` count is someone impersonating a
crawler; a rising `known-bot` count with `verified-bot` flat can mean a
ranges file has gone stale rather than that traffic changed.

The metrics index is a deliberate copy of `bs_ua_class_label` rather
than a cast of it. This one is persisted in the state file, so its
numbering is a wire format; `bs_m_class_idx()` maps between the two in
one place, and a new label added to the classifier without a case there
fails the build.

Like the other traffic dimensions it lives in the bucket rings and the
per-vhost blocks, so it is windowed and tabbed with everything else.

### Response breakout — who answered

The status-class counters cannot tell a BotShield 403 from an
application 403. `botshield_responses_*` splits them:

| Metric | Meaning |
|---|---|
| `botshield_responses_origin_total` | The application answered. BotShield did not respond. |
| `botshield_responses_challenge_total` | BotShield served an interstitial. |
| `botshield_responses_block_total` | BotShield refused the request. |
| `botshield_responses_rate_limited_total` | BotShield rate-limited or shed the request. |
| `botshield_responses_redirect_total` | BotShield issued a safeguard redirect. |
| `botshield_responses_endpoint_total` | A functional BotShield endpoint answered (verify, bootstrap, assets). |
| `botshield_responses_observe_total` | An observability endpoint answered (dashboard, metrics, policy-status). |

Classification reads the env the decision path already stashes, so it
costs two table lookups. Three cases bin as **origin** even though a
decision was recorded:

- `allow` / `verified` — the request went on to the application.
- A `~`-prefixed counterfactual — under `LogOnly` the log says `~block`
  but nothing was blocked. Counting it as ours would overstate
  enforcement in precisely the mode chosen not to enforce.
- No `BS_OUTCOME` at all — the scope was never evaluated.

`misconfigured` and `debug` do terminate the request, so they bin as
**block**: a refusal should never be invisible, even when its cause is
a config bug rather than policy.

**Why `observe` is separate.** The dashboard and the metrics scrape are
the measuring instrument, not traffic. A dashboard left open on a 10s
refresh is 360 requests an hour of self-inflicted load; folded in with
the verify endpoints it would quietly dominate the breakdown. They are
still counted in `requests_total` — that has to keep matching the
access logs — just kept separable, and on the dashboard the segment
wears a neutral rather than a policy colour.

The dashboard shows the share as a KPI and the breakdown as its own bar
scaled to BotShield's own responses, rather than as segments inside the
status chart: on a healthy site the origin is the overwhelming majority
of traffic, which would squeeze every BotShield response into an
unreadable sliver.

### Per-vhost breakdown

Every distinct `ServerName` gets its own metrics block, and
`/botshield/dashboard` shows a tab row to switch between them:

    /botshield/dashboard?vh=all      aggregate (default)
    /botshield/dashboard?vh=<n>      one vhost, by directory index

Vhosts that share a `ServerName` — the usual `:80` and `:443` pair —
share one block, on the grounds that an operator reads the dashboard
thinking in sites rather than listeners. Past 32 distinct names the
overflow shares one slot labelled `(other vhosts)`, with a NOTICE at
startup; nothing is silently dropped.

`/botshield/metrics` and `mod_status` are **unchanged** — both still
report the server-wide aggregate with no vhost dimension. The global
block is still written directly rather than summed at read time, so
the dashboard's "All vhosts" tab cannot disagree with the Prometheus
numbers.

Cost is a second set of relaxed atomic adds per event: the global block
and the vhost's block. Storage is one `bs_metrics` per vhost — the same
struct as the global one, so a few hundred bytes per vhost go unused on
server-wide-only fields, in exchange for no second struct to drift and
no separate read path.

Per-vhost blocks are persisted, and restored by **matching ServerName**
rather than saved position. Adding or removing a vhost therefore
re-files history correctly instead of shifting every site onto its
neighbour's numbers; a saved vhost that no longer exists is dropped and
a new one starts at zero, both reported at startup:

    per-vhost metrics restored for 3 of 4 saved vhost(s); 1 no longer configured

### Site-wide traffic counters

BotShield also counts **every** request the server handles, on every
vhost, whether or not it evaluated them. Collection happens in the
`log_transaction` hook, which is registered at server scope and runs
once per client request (subrequests never reach it), so these are
independent of where `BotShieldEnabled` is switched on.

| Metric | Meaning |
|---|---|
| `botshield_requests_total` | Every request logged, anywhere on the server. |
| `botshield_requests_with_cookie_total` | Requests that arrived carrying a BotShield session cookie. |
| `botshield_requests_status_{2xx,3xx,4xx,5xx,other}_total` | Response status class. `4xx` includes BotShield's own blocks. |

The point of the denominator is coverage. With the enable scoped to a
`<Location>`, `decisions / requests_total` is the fraction of site
traffic BotShield actually sees — a number that is otherwise easy to
assume is 100% when it is single digits. The dashboard shows it
directly as **Evaluated**.

These fields are in the bucket rings too, so all of it is windowed
alongside the decision counters.

Cost is three relaxed atomic adds per ring plus three cumulative, on
every request including static assets. That is deliberate — anything
more expensive would tax the whole site rather than just the protected
scopes.

Outcome meanings, grouped by where they originate:

| Outcome | Meaning |
|---|---|
| `allow` | Request reached origin — `pass` tier, asset bypass, silent embedded pass-through, or safeguard pass. |
| `challenged` | An interstitial was served. |
| `verified` | A challenge was **completed**: captcha siteverify returned OK, or an embedded-verify PoW was accepted. One per solve. |
| `block` | Refused outright — invalid cookie, a `status=` trigger, failed captcha verify. |
| `rate_limited` | Refused with 429 by a rate limit. Kept distinct from `block` so policy-refusal is separable from volume-refusal. |
| `redirect` | A 302 was issued (safeguard explainer). |
| `failopen` | Siteverify was unreachable (timeout, network error, provider 5xx) and the request was let through rather than blocking on a provider outage. |
| `pending_missing` | A verify POST arrived with no pending cookie, or a tampered one — typically a replayed or hand-crafted POST. |
| `inflight_capped` | Rejected by the global in-flight semaphore. Backpressure, not a verdict on the client. |
| `misconfigured` | Terminated on missing scope config or internal state. Non-zero means a config bug, not a bot. |
| `debug` | A `BotShieldDebug`-forced 403. Should be zero in production. |

`failopen`, `pending_missing` and `inflight_capped` only arise on the
verify endpoints, so they stay at zero unless a captcha provider or the
embedded silent mode is in use.

**`verified` counts solves, not requests.** A client that completes a
silent/form PoW returns on a *fresh* request carrying its new cookie,
which logs `outcome=allow cookie=ok`. Do not compute a solve rate from
`cookie=ok` — that counts every request bearing a valid cookie, so one
human browsing 50 pages would read as 50 solves. Before 2026-08-01 the
PoW path emitted nothing at all, so a deployment running the silent or
form tier with no captcha provider reported a permanent 0% solve rate
while challenges were in fact being solved.

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
| `botshield_resp_status_mismatch_total` | counter | **Should always be 0 — alert on any non-zero value.** Requests recorded as answered by BotShield (challenge / block / rate-limit / safeguard redirect) where the client nevertheless received a 2xx, meaning the application answered. See [Invariant check](#invariant-check) below. |

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

### Invariant check

`botshield_resp_status_mismatch_total` is not a workload metric. It
counts violations of a claim the module makes about itself, and the only
correct value is **0**.

When BotShield records `outcome=challenged`, `block`, `rate_limited` or a
safeguard `redirect`, it is asserting that *it* produced the response and
the application never ran. The interstitial sets `403`, a block sets
`403`, rate-limiting sets `429`, the safeguard sets `302` — so a client
receiving a **2xx** on such a request means the application answered
after all, and the decision log is overstating enforcement.

Both halves of that comparison were already being computed side by side
at `log_transaction` — the response kind from the origin request, the
final status from the end of the internal-redirect chain — and then filed
into two separate marginal tallies (`req_resp[]` and `req_status[]`).
Marginals cannot express "these two happened on the *same* request": you
could read 500 challenges and 40,000 2xx off a scrape and never learn
whether any single request was both. This counter closes that gap.

Excluded by design, because a 2xx is their correct outcome: `origin`
(the application answering), the module's own endpoints (`verify`,
`embedded.js`, assets), and the observability endpoints. `~`-prefixed
counterfactuals and `allow`/`verified` already bin as `origin`, so
LogOnly and shadow mode never trip it.

A non-zero value almost always means something downstream overrode
BotShield's response — an `ErrorDocument`, or a rewrite re-dispatching to
the application after the handler ran. That is the silent-failure shape
worth alerting on: green configtest, running httpd, nothing else
complaining, and traffic quietly less protected than the logs claim.

The module also emits one `WARNING` to the error log naming the outcome,
the status and the URI, **throttled to one line per minute** across all
workers — this check runs on every request, so an unthrottled line would
mean one log entry per request exactly when the fault is systematic. The
counter is the signal to alert on; the log line only tells you where to
look.

```
# Alert if this is ever above zero.
botshield_resp_status_mismatch_total > 0
```

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
