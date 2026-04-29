# Deployment

This page covers real-world deployment topology: reverse proxies and
load balancers, slowloris defense, multi-vhost reputation isolation,
secret rotation, and capacity sizing.

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
`__Host-bs_verified`. Browsers refuse to accept `__Host-` cookies
over plain HTTP, refuse cookies with a `Domain=` attribute, and
constrain `Path=/` — closing several cookie-injection attack classes
that the legacy `_bs_verified` name still has to support for HTTP
deployments.

Verify path checks both names (host-prefix first), so existing
clients with the legacy cookie still work during the transition.

## Multi-vhost reputation

Each vhost gets its own isolated bot reputation by default. A bot
flagged on `site-a.example.com` doesn't carry that flag to
`site-b.example.com`. Operators running many vhosts on one Apache
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
isolation is what most operators want.

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
capacity, so operators can size reactively rather than guess
up-front. Look for log lines of the form:

```
mod_botshield: capacity headroom: flagged_ip 38241/50000 (76%)
```

## Performance characteristics

Per-request overhead the module adds, measured by the in-tree
benchmark suite in `tests/bench/`. The numbers below come from
30-second `wrk` sweeps against a 140-byte static file on Apache
2.4, localhost loopback (no real network), Linux x86_64, with
realistic browser headers attached. They show the *floor* of the
module's cost — production traffic depends on hardware, kernel,
network RTT, header mix, and request rate, all of which dominate
or shape the numbers below.

**Single-connection isolation** (`-t 1 -c 1`) — the cleanest
"what does each request actually cost?" measurement, no
contention effects:

| Configuration | p50 latency | Δ vs Apache static |
|---|---|---|
| Apache static (no module) | ~310us | — |
| `BotShieldEnabled on`, no features | ~318us | **+8us** |

**Sustained concurrent load** (`-t 4 -c 100`) — the throughput
shape. Multi-connection deltas are dominated by loopback
contention and Apache worker dynamics, not the module:

| Configuration | RPS hit vs Apache static |
|---|---|
| Module loaded, all scopes disabled | -13% |
| `BotShieldEnabled on`, no features | -10% |
| + allow-list (6 verified-bot entries) | -11% |
| + trigger families (3 cookie, 1 env, 3 path, 1 scope) | -21% |
| + robots.txt (10-rule wildcard group + named groups) | -15% |
| + `LogLevel botshield_module:info` (decision log) | -9% |
| + valid `_bs_verified` cookie attached | -18% |
| Everything on (kitchen sink) | -20% |

What to take from these:

- **Just loading the module** costs ~13% RPS at high concurrency
  even with no scope enabling it. Apache calls the request hook
  regardless; the hook short-circuits, but the function call +
  scope-enabled check still happens.
- **Enabling the module** on top of having loaded it is roughly
  free. Bare-on (`-10%`) is within noise of module-loaded-disabled
  (`-13%`). The actual heuristics + Bloom + score-composition
  per-request work doesn't measurably move the dial.
- **Trigger families are the dominant configuration cost.** Both
  the trigger-only scenario (`-21%`) and kitchen-sink (`-20%`)
  cluster around the same hit. Each request walks the trigger
  arrays in declaration order; the more rules, the longer the walk.
- **Robots.txt enforcement** adds ~5% over bare-on.
- **Allow-list** is sub-noise — the UA classifier trie is fast.
- **The decision-log emission** (`LogLevel botshield_module:info`)
  is sub-noise. Operators can turn observability on without
  measurable RPS hit.
- **Carrying a valid cookie isn't a perf win.** GCM-decrypt +
  canonical reconstruction + algorithm verify cost roughly what
  the heuristic walk they sometimes replace cost. The cookie
  path's purpose is correctness (carrying reputation), not cheap
  pass-through.

The `tests/bench/run-bench.sh` driver reproduces these in your own
environment in ~12 minutes. Run it before sizing a new deployment
or whenever you want a fresh baseline against your production
hardware.

### Putting the overhead in perspective

Eight microseconds isn't intuitively meaningful in isolation.
Some reference points for the same hardware tier:

- One L3 cache miss on a modern x86 CPU is ~10-30 ns; mod_botshield
  bare-on adds the equivalent of ~300-800 cache misses worth of
  work per request. Routine for a function that does multiple SHM
  reads, a Bloom probe, and several short string comparisons.
- One TCP loopback round-trip to localhost is ~10-30 µs on the
  same machine; the entire bare-on cost fits comfortably within
  the cost of just *one* loopback round-trip.
- One typical real-network RTT (20-100 ms WAN, 1-5 ms intra-DC)
  is 1,000-10,000× larger than the per-request overhead. For any
  request crossing a real network, the module's contribution is
  in the noise.
- One PHP request through a framework (Laravel, Symfony, Django,
  Rails) typically spends 20-200 ms in bootstrap + ORM + template
  render + database round-trips, *before* the application's own
  business logic runs. Mod_botshield's 8 µs is 0.004-0.04% of that.
- A static-file response on Apache (the bench's worst case for
  amortizing the cost) takes ~310 µs on loopback. Adding the
  module turns that into ~318 µs — a real percentage delta on a
  best-case request, but the absolute hit is still well under
  the cost of a single SQL query or a single Redis lookup.

The multi-connection -10% to -20% RPS hit at sustained `-c 100`
load looks larger because the static-file workload is so cheap
that any added per-request work shows up as a meaningful fraction.
The same module added to a typical PHP / framework backend would
shrink to a sub-1% RPS hit — the application's own work dominates.

Where the overhead earns its keep: every bot request that
mod_botshield blocks at the silent tier never invokes the backend,
which means an entire framework bootstrap doesn't run, which
means tens of milliseconds of CPU time saved per blocked request.
On a site where ~10% of traffic is unwanted scraping, blocking it
upstream of the application saves orders of magnitude more
backend cycles than the module costs the legitimate 90%. That's
the trade the design assumes.

## State persistence

mod_botshield can snapshot the SHM tables to disk at a configured
interval (or only at clean shutdown) and reload on next start. This
lets the flagged-IP table, Bloom filters, and rate-limit counters
survive Apache restarts.

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

The secondary covers four verify call sites: HMAC `_bs_verified`,
GCM `_bs_verified`, the captcha-pending cookie, and the
embedded-verify PoW path. App-bridge keys
(`BotShieldAppIntegrationSecretFile`) and captcha provider secrets
are out of rotation scope; rotate those by reloading with the new
file.

## Where to next

- Tier model, scoring, decision log: [operator model](../operator-model/index.html).
- Allow lists, rate limits, triggers: [policy](../policy/index.html).
- Captcha and app-bridge integration: [captcha](../captcha/index.html).
- Staging policy changes safely: [staging](../staging/index.html).
- Metrics + decision log + mod_status: [observability](../observability/index.html).
