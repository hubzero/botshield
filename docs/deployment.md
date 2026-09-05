# Deployment

This page covers real-world deployment topology: where the
configuration lives, reverse proxies and load balancers, slowloris
defense, multi-vhost reputation isolation, secret rotation, and
capacity sizing.

## Where the configuration lives

Two decisions here are load-bearing, and both fail quietly when you get
them wrong.

**Include it from somewhere your configuration management does not
regenerate.** If vhosts on this host are generated from templates by
Ansible, Puppet, or a CMS that writes Apache config, then the module's
configuration must not live in a generated file, and neither must the
`Include` line that pulls it in. Put the configuration in its own file
and include it from a directory the generator leaves alone:

```sh
echo 'Include conf/botshield.conf' \
  | sudo tee /etc/httpd/conf.d/25-botshield.conf
```

A deployment that put this in the vhost instead lost every enforcing
scope the next time the vhost was regenerated. The site ran unprotected
for two days, and the config test stayed green throughout, because
nothing was syntactically wrong. There was nothing left to be wrong.

**Include it at main server scope, not inside a `<VirtualHost>`.** The
data-directory and state directives are server scope only. They are
read once, before vhosts merge. A directive of that class inside a
vhost is now rejected at config-parse time rather than accepted and
ignored, which is a recent change: an earlier version accepted
`BotShieldDbStatsFile` inside a vhost, discarded it, reported `Syntax
OK`, and left the dashboard saying no monitor was configured, which
reads as a missing directive rather than a discarded one. Everything at
main scope is inherited by every vhost on the host. To confine it to
one hostname, wrap it:

```apache
<If "%{HTTP_HOST} == 'www.example.org'">
    BotShieldEnabled On
</If>
```

`docs/examples/full-site.conf.example` is a complete configuration
built around both rules, with the enforcing scopes commented out in the
order worth enabling them.

### A green config test is not a rehearsal

`apachectl configtest` parses the configuration. It does not run
`post_config`, which is where shared memory is sized, the watchdog is
and the watchdog is registered. A
configuration can test clean and still change behaviour on reload.

Gate the reload on the test's **exit code**, not on reading its output:

```sh
sudo apachectl configtest && sudo systemctl reload httpd
```

Piping the test to `tail` and restarting in the same command regardless
took a production site down for thirty seconds. Before each reload of a
newly enforcing scope, check there is headroom in the scoreboard:

```sh
curl -s http://127.0.0.1/server-status?auto \
  | grep '^Scoreboard' | tr -cd '.' | wc -c        # want > 100 free
```

To see what the configuration actually resolves to, including which
thresholds are unset and which rules are in effect, ask the module
rather than reading the file:

```sh
httpd -t -D DUMP_BOTSHIELD_POLICY
```

## Behind a reverse proxy or load balancer

mod_botshield keys every IP-based signal (flagged-IP table, Bloom
filter, rate limiters, score) on `r->useragent_ip` — the TCP peer
Apache sees. If Apache sits behind a reverse proxy or load balancer
(CDN, AWS ELB, nginx in front, etc.) that peer is the proxy, not the
real client. **Without `mod_remoteip`, the module will flag your own
edge and challenge every legitimate visitor.**

The fix is the stock Apache module `mod_remoteip`. Configure it to
trust your edge hops; it will rewrite `r->useragent_ip` to the real
client before any botshield hook runs:

```apache
LoadModule remoteip_module modules/mod_remoteip.so

RemoteIPHeader        X-Forwarded-For
RemoteIPTrustedProxy  10.0.0.0/8
RemoteIPTrustedProxy  2001:db8:cafe::/48
# ... one RemoteIPTrustedProxy per edge CIDR ...
```

This is the same module used for accurate `%a` in access logs — if
your access logs already show real client IPs, you're done.

We deliberately do not reimplement this. `mod_remoteip` parses
the configured header (typically `X-Forwarded-For`) as a comma-
separated chain of IPs, matches each hop against the trusted-
proxy CIDR list, and rewrites `r->useragent_ip` to the leftmost
untrusted address — IPv4 and IPv6, multi-hop chains, all in
Apache core, battle-tested, maintained. If your edge sends
RFC 7239 `Forwarded:` headers instead, terminate them at the
edge and have it forward `X-Forwarded-For` for Apache; mod_remoteip
itself does not parse the RFC 7239 grammar.

For a single-host deployment with no proxy in front, no extra
configuration is needed: `r->useragent_ip` already equals the client
IP.

## Slow-client / slowloris defense

mod_botshield's body-read paths (form-captcha verify, the
captcha-verify endpoint, embedded-verify endpoint) inherit Apache's
slow-client defense. Apache's `Timeout` directive bounds how long a
worker can be held by a stalled client; the default is 60 seconds.

For production deployments, pair mod_botshield with
`mod_reqtimeout`. It gives finer-grained controls than `Timeout` and
is the standard Apache answer to slowloris-class attacks:

```apache
LoadModule reqtimeout_module modules/mod_reqtimeout.so

RequestReadTimeout header=20-40,minrate=500
RequestReadTimeout body=20,minrate=500
```

We deliberately do not implement our own slow-client defense.
`mod_reqtimeout` is in Apache core, applies to the whole vhost, and
mod_botshield's endpoints get the same protection as the
application's own handlers.

## HTTPS / `__Host-` cookie prefix

When the request is HTTPS *and* you have not configured
`BotShieldCookieDomain`, mod_botshield emits the verified cookie as
`__Host-bs_session`. Browsers refuse to accept `__Host-` cookies
over plain HTTP, refuse cookies with a `Domain=` attribute, and
constrain `Path=/` — closing several cookie-injection attack classes
that the legacy `_bs_session` name still has to support for HTTP
deployments.

Verify path checks both names (host-prefix first), so existing
clients with the legacy cookie still work during the transition.

## Multi-vhost reputation

Each vhost gets its own isolated bot reputation by default. A bot
flagged on `site-a.example.com` doesn't carry that flag to
`site-b.example.com`. Sites running many vhosts on one Apache
instance get per-site detection without configuring anything.

### Default: auto-isolation per ServerName

Each vhost's reputation namespace is derived from its `ServerName`
directive — two vhosts with different `ServerName` values
automatically maintain separate reputation. No configuration required.

```apache
<VirtualHost *:443>
    ServerName site-a.example.com
    BotShieldEnabled on
</VirtualHost>

<VirtualHost *:443>
    ServerName site-b.example.com
    BotShieldEnabled on
</VirtualHost>
```

Different sites usually have different threat models — the strict
isolation is what most sites want.

### Opt-in shared reputation: `BotShieldShareScope`

When sibling vhosts should share state — dev/prod environments,
www/api subdomains under the same brand, redundant frontends — set
`BotShieldShareScope` to the same string on each vhost:

```apache
<VirtualHost *:443>
    ServerName www.example.com
    BotShieldShareScope example-cluster
</VirtualHost>

<VirtualHost *:443>
    ServerName api.example.com
    BotShieldShareScope example-cluster
</VirtualHost>
```

Both vhosts now share one reputation namespace. A bot flagged on
either site is flagged on the other. The scope token is hashed; any
string works, just keep it consistent across the vhosts you want
grouped. Different tokens produce independent groups.

### Missing `ServerName`

A vhost without a `ServerName` directive falls back to the global
default namespace (`ns_id=0`). All such vhosts share reputation;
mod_botshield logs a NOTICE at startup so the fallback is visible.
For explicit isolation on a vhost without `ServerName`, set
`BotShieldShareScope` to a unique-per-vhost token.

### One SHM segment, scaling

A single Apache instance can handle hundreds of vhosts sharing one
shared-memory segment. The per-slot namespace tag lets all vhosts
coexist without per-vhost SHM segments. Monitor SHM utilization via
the headroom watchdog (logs at `info`) and tune capacity directives
for aggregate traffic.

## Capacity sizing

Default budgets fit a single-site deployment seeing ~1M unique IPs
per week. Larger deployments (or aggregations across many vhosts)
should size capacity directives to match.

| Directive | Default | What it limits |
|---|---|---|
| `BotShieldShmSize` | `16M` | Total SHM budget (header + tables + Bloom buffers). Range 128K..256M |
| `BotShieldFlaggedIPCapacity` | `50000` | Open-addressed slot count for flagged IPs. Range 1024..1000000 |
| `BotShieldBloomIPs` | `1000000` | Expected unique-IPs working set. Drives Bloom filter dimensions |
| `BotShieldBloomWindow` | `604800` | Bloom rotation window (seconds). Rotation at window/2 |
| `BotShieldRateLimitEscalateCapacity` | `50000` | strike-table slots |
| `BotShieldSafeguardCapacity` | `50000` | challenge-loop suppression slots |
| `BotShieldEmbeddedNonceCapacity` | `32768` | embedded-bootstrap nonce table |

These are server-scope only — placed inside `<VirtualHost>` they
emit a NOTICE and are ignored. The SHM segment is module-global, so
sizing happens once at the main-server level.

The headroom watchdog logs notices when any table approaches
capacity, so you can size reactively rather than guess
up-front. Look for log lines of the form:

```
mod_botshield: capacity headroom: flagged_ip 38241/50000 (76%)
```

## Performance characteristics

The in-tree benchmark suite in `tests/bench/` measures pass-through
cost against a tiny Apache static-file endpoint. That workload is
useful because it makes fixed per-request cost visible, but it is
also the harshest possible denominator: a 140-byte static response
on localhost is much cheaper than a normal application request.

Latest saved measurements combine the single-connection and
saturation `wrk` sweep (`tests/bench/run-bench.sh`) with the
fixed-rate `oha` sweep (`tests/bench/run-rate-bench.sh`). All run
against localhost with browser-like request headers:

| Measurement | Result | How to read it |
|---|---:|---|
| Single connection, Apache static baseline | ~310us p50 | Cheapest local request path. |
| Single connection, `BotShieldEnabled on`, no policy features | ~318us p50 | About **+8us** for the basic pass-through path. |
| Fixed-rate 1k / 5k rps | p50 and p99 deltas mostly noise | Non-saturating traffic stays flat. |
| Fixed-rate 10k rps, trigger-heavy policy | ~+0.03ms p50, ~+0.28ms p99 | Real cost, still well below normal app latency. |
| Fixed-rate 10k rps, kitchen-sink policy | ~+0.05ms p50, ~+2.7ms p99 | Broadest config shows tail growth before median pain. |
| Saturation `-t4 -c100`, trigger-heavy / kitchen-sink policies | ~20% lower static-file RPS | Capacity-ceiling result, amplified by the tiny static baseline. |

The practical reading is: BotShield has a real per-request cost,
but the absolute cost on passing traffic is small. The worst-looking
RPS percentage comes from saturating Apache with a tiny static file
over loopback; it should not be read as "every production request
gets 20% slower." The fixed-rate pass is the better proxy for normal
operation: even at 10k rps, median latency barely moves, and the
largest effect is a tail-latency signal in the broadest policy
configuration. For dynamic application traffic, network RTT,
FastCGI/PHP startup, framework work, database calls, and template
rendering usually dominate the few microseconds to low milliseconds
BotShield adds.

Where the overhead earns its keep: every bot request handled before
the backend avoids invoking the application at all. Avoiding even
one framework bootstrap, database query, or upstream proxy trip can
save more work than many pass-through BotShield checks cost.

The `tests/bench/run-bench.sh` and `tests/bench/run-rate-bench.sh`
drivers reproduce these measurements on your own hardware. Raw
`wrk` / `oha` output is saved under `tests/bench/results/` so
you can inspect the full latency and throughput distribution
when sizing a deployment.

## State persistence

mod_botshield can snapshot the SHM tables to disk at a configured
interval (or only at clean shutdown) and reload on next start. This
lets the flagged-IP table, the Bloom filters, and the metrics
counters behind `/botshield/dashboard` and `/botshield/metrics`
survive Apache restarts.

Rate-limit counters are **not** persisted. They are short-window
buckets whose whole meaning is "requests in the last N seconds", so
restoring them from a file written minutes ago would either
double-count or restore a window that has already elapsed. They
restart empty by design.

```apache
BotShieldStateFile         /var/lib/botshield/state.bin
BotShieldStateSaveInterval 300
```

Both directives are server-scope. The default is "no persistence"
(`BotShieldStateFile` unset). Periodic saves require `mod_watchdog`;
the graceful-shutdown save runs regardless.

The state file format is versioned. Format-version drift between
saves and loads (e.g. after upgrading the module) results in the
table starting fresh with a NOTICE — never a startup failure.

Persisting metrics matters more than it looks if you rotate logs by
restarting Apache: without a state file, a nightly restart zeroes the
dashboard's 24-hour and all-time windows every night, and the
"outstanding challenges" gauge resets along with them.

The dashboard's bucket rings are epoch-stamped per slot, so downtime
needs no special handling on reload: slots whose epoch has fallen
outside the requested window are skipped by the reader. Restarting
after 20 minutes of downtime shows a 15-minute window that has
correctly aged to empty, while the all-time counters carry over.

## Secret rotation

mod_botshield supports a verify-only secondary key for graceful HMAC
rotation. The flow:

1. Generate a new master secret. Install it as a fresh file
   (e.g. `/etc/botshield/secret.new`).
2. Configure both files, with the **new** key as primary and the
   **old** key as secondary:

   ```apache
   BotShieldSecretFile          /etc/botshield/secret.new
   BotShieldSecondarySecretFile /etc/botshield/secret.old
   ```

   Reload Apache. New cookies are signed with the new key; existing
   cookies still verify against the secondary.

3. After the cookie TTL elapses (default 1 h, or
   `BotShieldCookieTTL` if you raised it), every in-flight cookie has
   been re-issued under the new key. Drop the secondary:

   ```apache
   BotShieldSecretFile /etc/botshield/secret.new
   ```

   Reload. The old secret can now be deleted.

The secondary covers four verify call sites: HMAC `_bs_session`,
GCM `_bs_session`, the captcha-pending cookie, and the
embedded-verify PoW path. App-bridge keys
(`BotShieldAppIntegrationSecretFile`) and captcha provider secrets
are out of rotation scope; rotate those by reloading with the new
file.

## Upgrading through the vocabulary change

The module's own words are now dashless, on every surface, and the
`pass` spelling is gone. This breaks configs and dashboards that used
the old ones, so read this before putting a newer module on a server
that already runs an older config.

**The module and its config must move together.** `respond=pass` is a
configtest failure now, not a warning. A server whose module is
upgraded while its config still says `pass` will pass its running
state until something reloads it, and then fail to come back. Stage
both, run `apachectl configtest` against the pair, and only then
reload.

What to change in a config:

| Old | New |
|---|---|
| `respond=pass`, `respond=challenge-pass` | `respond=nochallenge` |
| `tier=pass` | `tier=nochallenge` |
| `tier=non-interactive`, `min=non-interactive` | `noninteractive` |
| `BotShieldHeuristicTrigger first-sight-ip` and the other dashed heuristic names | `firstsightip`, `missingua`, `missingal`, `scraperua`, `droppedcookie` |

What to change outside the config. Decision-log tokens lost their
dashes, so a grep or alert matching `request-trigger`, `known-bot`,
`flag-tier-floor` or `first-sight-ip` now matches nothing; the
[reason-name vocabulary](observability.md#reason-name-vocabulary)
lists the current set. Two Prometheus counters were renamed to agree
with the log, `botshield_tier_pass_total` to
`botshield_tier_nochallenge_total` and
`botshield_tier_non_interactive_total` to
`botshield_tier_noninteractive_total`, so any panel or alerting rule
naming those needs the new name.

What deliberately did not change: bot slugs such as
`claude-searchbot`, the `@ai-train` and `@fake-bot` botgroup
selectors, the `BotShieldClassify` pass names, your own `log=` labels,
and the challenge endpoint paths. Every one of those is either
somebody else's identifier or a URL, and all of them appear in a
`reason` token only after the first colon.

## Where to next

- Tier model, scoring, decision log: [site model](site-model.md).
- Allow lists, rate limits, triggers: [policy](policy.md).
- Captcha and app-bridge integration: [captcha](captcha.md).
- Staging policy changes safely: [staging](staging.md).
- Metrics + decision log + mod_status: [observability](observability.md).
