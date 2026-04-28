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

We deliberately do not reimplement this. `mod_remoteip` handles
`X-Forwarded-For`, `Forwarded:` (RFC 7239), trusted-proxy CIDR
matching for both v4 and v6, and multi-hop chains — all in Apache
core, battle-tested, maintained.

For a single-host deployment with no proxy in front, no extra
configuration is needed: `r->useragent_ip` already equals the client
IP.

## Slow-client / slowloris defense

mod_botshield's body-read paths (form-captcha verify, M8
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
| `BotShieldRateLimitEscalateCapacity` | `50000` | E9 strike-table slots |
| `BotShieldSafeguardCapacity` | `50000` | E10 challenge-loop suppression slots |
| `BotShieldEmbeddedNonceCapacity` | `32768` | E17 embedded-bootstrap nonce table |

These are server-scope only — placed inside `<VirtualHost>` they
emit a NOTICE and are ignored. The SHM segment is module-global, so
sizing happens once at the main-server level.

The headroom watchdog logs notices when any table approaches
capacity, so operators can size reactively rather than guess
up-front. Look for log lines of the form:

```
mod_botshield: capacity headroom: flagged_ip 38241/50000 (76%)
```

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
GCM `_bs_verified`, the M8.1 captcha-pending cookie, and the
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
