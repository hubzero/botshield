# Troubleshooting

This page covers the most common visible issues, the
diagnostic for each, and the fix or workaround.

## Module fails to load

**Symptom**: `apachectl configtest` reports
`Cannot load /usr/lib/apache2/modules/mod_botshield.so` or
`undefined symbol: ...`.

**Diagnostic**: check the dynamic-linker symbol resolution:

```sh
ldd /usr/lib/apache2/modules/mod_botshield.so
```

A missing OpenSSL / libcurl / json-c shared library shows up as
`not found`. Install the matching `-dev` package and rebuild
(`make && sudo make install`).

If the `.so` symbol resolution is clean, look at the Apache error
log on startup — directive parsing errors emit a clear diagnostic
identifying the line and the offending token.

## "Misconfigured" 503 responses

**Symptom**: every request to a gated scope gets HTTP 503 with
header `X-Botshield: misconfigured`. Decision log shows
`outcome=misconfigured`.

**Diagnostic**: the master HMAC key (`BotShieldSecretFile`) and/or
the PoW algorithm (`BotShieldAlgorithm`) is unset on the active
scope. mod_botshield refuses to mint cookies without both — fail-
closed by design. Check that:

```apache
BotShieldSecretFile /etc/botshield/secret
BotShieldAlgorithm  sha256-zeros
```

are present at server scope or inherited into the request scope.

The secret file must be mode 0600 and at least 16 bytes. The
config-time loader logs a clear diagnostic if the file is too loose
or too short, refusing to start rather than defaulting to a weak
key.

## Every legitimate request is being challenged

**Symptom**: real users see the interstitial; the decision log
shows everything as `tier=silent` or higher.

**Most common cause**: Apache is behind a reverse proxy and
`mod_remoteip` is not configured. mod_botshield is keying the IP
signals on your edge load balancer, not the real client.

**Diagnostic**: look at the `ip=` field in the decision log. If it
matches your edge's IP, that's the issue. Configure
`mod_remoteip` per [deployment](../deployment/index.html).

**Second-most common cause**: the heuristic thresholds are too low
for your traffic mix. `BotShieldScoreSilent` defaults to 20; a
request with `missing-accept-language` (15 points) and
`first-sight-ip` (5 points) hits the silent tier on its first
request. For sites where most visitors don't send `Accept-
Language` (legitimate use cases exist), raise `BotShieldScoreSilent`
to 30 or 40.

**Tuning workflow**:

1. Set `BotShieldEnabled LogOnly` to dry-run all rules.
2. Watch the decision log under real traffic for 24–48 hours.
3. Sample the `effective` distribution and per-reason
   contributions.
4. Raise thresholds or lower individual heuristic penalties to
   match.

See [site model](../site-model/index.html) for the full tuning
discussion.

## Bots passing through unchallenged

**Symptom**: scrapers / spammers / exploitation attempts visible in
access logs aren't being gated. Decision log shows `tier=pass`.

**Diagnostics**:

1. Confirm the request actually reached mod_botshield. The
   decision log line should be present. If absent, check that the
   module is loaded and `BotShieldEnabled On` is in scope.
2. If the line is present, look at the `score` field. A bot that
   hits no heuristic (sends a normal-looking UA, accepts language,
   has been seen before) won't trigger anything.

**Fixes**:

- **Honeypot scopes**: drop `<Location>` blocks for paths only
  bots scan (`/wp-admin/`, `/.env`, `/.git/`) with
  `BotShieldTrigger flag=honeypot_hit ttl=3600`. The bot trips
  the honeypot, the IP is flagged, future requests get the
  flag-trigger penalty + tier_floor=captcha. See
  [policy](../policy/index.html).
- **Path triggers**: for paths that bots target but legitimate
  users don't, add `BotShieldPathTrigger` rules with a penalty,
  status=403, or both. UA / IP cohort gating goes inline as
  `ua=...` / `ipspec=...` keys.
- **Rate-limit**: if you see scraper UA patterns, add a
  `BotShieldRateLimit` cohort.
- **Allow-list verification**: if a "bot" is claiming to be
  Googlebot but doesn't have Googlebot's IP range, the fake-bot
  detection fires automatically — assuming `BotShieldAllowBot
  googlebot ...` is configured. Check the decision log for
  reason=`fake-googlebot` to confirm it's working.

## Captcha-verify endpoint returns 403 / 429 / 503

**Symptom**: clients fail to verify even with a valid captcha
token.

**Diagnostic**: check the decision log for the verify request.
The `outcome` field tells you which guard triggered:

| Outcome | Meaning | Fix |
|---|---|---|
| `pending_missing` | The HMAC-signed `_bs_captcha_pending` cookie is missing or invalid. Browser dropped it (3rd-party cookie blocking, SameSite, redirect chain) | Confirm the interstitial is being served from the same origin as the verify endpoint; check Cookie attributes against browser dev tools |
| `rate_limited` | Per-IP cap exceeded (default 30/min) | Raise `BotShieldCaptchaRateLimit` or distribute traffic across IPs |
| `inflight_capped` | Global concurrent siteverify cap (default 64) | Raise `BotShieldCaptchaMaxInFlight` or scale Apache workers |
| `failopen` | Provider siteverify timed out | Check provider status; raise `BotShieldCaptchaTimeout` if your network is slow to the provider; treat as transient and retry |
| `rejected` | Provider returned `success: false` | Token was invalid (replay, wrong sitekey/secret pair, expired). Test with the provider's published always-pass test pair to isolate config drift |

## Decision log lines missing

**Symptom**: requests are gated (challenges visible to client) but
nothing in the error log.

**Cause**: Apache's default `LogLevel` is `warn`; the module's
decision log is at `info`.

**Fix**:

```apache
LogLevel botshield_module:info
```

Reload. Confirm:

```sh
sudo tail -f /var/log/apache2/error.log | grep "mod_botshield: decision"
```

For verbose request-path diagnostics (cookie parsing, SHM slot
probes, per-reason penalty values), use `LogLevel botshield_module:debug` —
expensive at scale, fine for staging.

## State file format mismatch on startup

**Symptom**: error log on startup:

```
mod_botshield: state file format mismatch (file=v2 module=v3); discarding
```

**Cause**: you upgraded the module to a version with a new SHM
state format. Slot bytes from the old file don't map cleanly into
the new layout, so the module rejects the file and starts the
table fresh.

This is by design: a slot-level migration could fabricate
incorrect state in ways that take days to surface as wrong
decisions. Discarding is safer than silent corruption.

**Fix**: nothing required — the table will re-populate from live
traffic over the next ~hour as flagged IPs re-trigger. If the
table was holding very long-TTL flags that you don't want to lose,
restore from a pre-upgrade backup of the state file (you do back
it up, right?).

## SHM segment too small

**Symptom**: error log shows `apr_shm_create` failed during
`post_config`, or capacity headroom watchdog is logging at WARN
or ERROR for an extended period.

**Cause**: aggregate traffic across vhosts has outgrown the
default 16 MiB SHM budget.

**Fix**: raise `BotShieldShmSize` (server scope only):

```apache
BotShieldShmSize 64M
```

Range: 128K..256M. The headroom watchdog reports each table's
utilization separately; size the largest contributor first
(usually `flagged_ip` or `bloom_a/b`).

## Cookie not being honored across reload

**Symptom**: after `apachectl graceful` users get re-challenged
even though their cookie was valid.

**Cause**: secret-file rotation isn't done correctly, or the
challenge interstitial JS made a hard reload that dropped the
cookie.

**Diagnostic**: tail decision log for `cookie=bad_sig`. If you see
a spike right after a graceful, the secret is mismatched. Check
`BotShieldSecretFile` content didn't change inadvertently.

For zero-disruption secret rotation use `BotShieldSecondarySecretFile`
— see [deployment](../deployment/index.html#secret-rotation).

## Multi-vhost: bot flagged on one site appears on another

**Symptom**: vhosts that should be isolated are sharing reputation.

**Most common cause**: missing `ServerName`. mod_botshield uses
`ServerName` to derive the namespace; vhosts without one fall back
to the global `ns_id=0` namespace and share state.

**Diagnostic**: startup log will show:

```
mod_botshield: NOTICE: vhost without ServerName falling back to
              ns_id=0; configure BotShieldShareScope for isolation
```

**Fix**: set `ServerName` on every gated vhost, or configure
`BotShieldShareScope <unique-token>` on each.

## `mod_status` contribution not showing

**Symptom**: `/server-status` doesn't include the `BotShield<Name>`
lines.

**Diagnostic checklist**:

1. `mod_status` is loaded (`apachectl -M | grep status`).
2. `ExtendedStatus On` is set (often the default in newer Apache;
   confirm).
3. The request reaches `mod_status` (vhost / location is correct).

`mod_status` is an optional dependency. Without it the
`/botshield/metrics` Prometheus endpoint covers everything. The
contribution hook is purely additive.

## Where to next

- Real-world deployment topology: [deployment](../deployment/index.html).
- Tier model, scoring, decision log: [site model](../site-model/index.html).
- Policy and rule families: [policy](../policy/index.html).
- Captcha + app-bridge integration: [captcha](../captcha/index.html).
- Metrics and dashboards: [observability](../observability/index.html).
