# Getting started

mod_botshield is an Apache 2.4 module that filters bot and scraper
traffic in-process before Apache hands the request to PHP / FastCGI /
upstream. This page covers installing the module, applying a minimal
working configuration, and verifying that requests are being gated.

## Prerequisites

You need:

- Apache 2.4 with the development headers (`apache2-dev` on
  Debian/Ubuntu, `httpd-devel` on RHEL-family).
- OpenSSL development headers (`libssl-dev`).
- libcurl + json-c development headers (`libcurl4-openssl-dev`,
  `libjson-c-dev`) — required even if you don't use the captcha tier.
- A 64-bit Linux platform. The module is exercised on Linux x86-64;
  other Unix-like platforms with APR + Apache 2.4 likely work but are
  not part of the regression matrix.

Optional but recommended:

- `mod_watchdog` for periodic state-file snapshots and the headroom
  monitor. The module degrades gracefully without it (state save
  still runs at clean shutdown, the headroom log lines disappear).
- `mod_status` for the `/server-status` contribution hook.
- `mod_remoteip` if Apache sits behind a reverse proxy or load
  balancer. See [deployment](../deployment/index.html) for why this is critical.
- `mod_reqtimeout` for slow-client / slowloris defense. See
  [deployment](../deployment/index.html) for the recommended settings.

## Build and install

```sh
make enable
```

`make enable` is the one-shot path: it compiles, installs the `.so`
into Apache's modules directory, runs `a2enmod botshield`,
`apachectl configtest`, and `systemctl reload apache2`. If any step
fails the script stops before the reload.

Step-by-step equivalents if you'd rather drive each phase yourself:

```sh
make                                      # apxs -c
sudo make install                         # cp .so to modules dir
sudo a2enmod botshield                    # writes mods-enabled symlink
sudo apachectl configtest                 # syntax check before reload
sudo systemctl reload apache2             # graceful reload
```

`make disable` removes the module from `mods-enabled` without
deleting the `.so` — useful for quickly rolling back during
deployment.

## Generate a master secret

mod_botshield refuses to start without `BotShieldSecretFile`. The
file holds the master HMAC key from which per-purpose subkeys are
HKDF-derived at config-load time (cookie GCM, pending-cookie HMAC,
embedded-bootstrap binding). It must be:

- mode 0600 (the file watcher rejects looser modes at startup).
- between 16 bytes and 1 KiB.
- a single value; no leading whitespace, no embedded NULs.

A 32-byte hex string is a reasonable default:

```sh
sudo install -m 600 /dev/null /etc/botshield/secret
sudo openssl rand -hex 32 | sudo tee /etc/botshield/secret >/dev/null
```

Keep this file off your repo and out of any backup that gets shared.
Rotation is supported via `BotShieldSecondarySecretFile` — see the
[deployment](../deployment/index.html) page.

## Minimal configuration

Drop a single block into the vhost you want gated:

```apache
<VirtualHost *:443>
    ServerName example.test
    DocumentRoot /var/www/example
    # SSLEngine, certs, logs, etc.

    BotShieldEnabled    on
    BotShieldSecretFile /etc/botshield/secret
    BotShieldAlgorithm  sha256-zeros
</VirtualHost>
```

That's the floor. Everything else (tier thresholds, forgiveness,
allow lists, captcha providers, triggers) ships with reasonable
defaults documented on the [site model](../site-model/index.html) and
[directives](../directives/index.html) pages.

`BotShieldAlgorithm sha256-zeros` is currently the only built-in PoW
algorithm. Other names (`sha384-zeros`, `pbkdf2-sha256`, `argon2id`)
are reserved registry slots that fail with a clear "not implemented"
diagnostic if you set them — there's no silent fallback.

## Verify it's running

After reload, confirm the module is loaded and a real request is
being processed.

**1. Module loaded.**

```sh
apachectl -M 2>&1 | grep botshield
# expected: botshield_module (shared)
```

**2. Module is decorating requests.** Every gated request gets an
`X-Botshield-Env: <env>` response header (the env name comes from
the `BotShieldEnv` directive if you set one, or `prod` by default).
This is the cheapest end-to-end smoke test:

```sh
curl -skI https://example.test/ | grep -i x-botshield
# expected: X-Botshield-Env: prod
```

**3. Decisions are being logged.** mod_botshield emits a structured
`key=value` decision line per request at Apache's `info` level.
The default `LogLevel warn` hides them. Bump just this module:

```apache
LogLevel botshield_module:info
```

Reload and tail the error log:

```sh
sudo tail -f /var/log/apache2/error.log | grep "mod_botshield: decision"
```

You should see one line per request:

```
[Tue Apr 28 10:00:00 2026] [botshield:info] mod_botshield:
  decision tier=pass outcome=declined ip=192.0.2.1 score=0
  cookie=absent provider=- alg=- reason="-" path="/"
```

`tier=pass outcome=declined` is the happy path — the module
inspected the request, decided it didn't warrant friction, and
declined so Apache served the real content.

**4. The challenge widget renders.** Force a challenge by spoofing a
scraper UA so the heuristic score crosses `BotShieldScoreSilent`
(default 20):

```sh
curl -sk -A "python-requests/2.31" https://example.test/ | grep -c BOTSHIELD
# expected: 1 (the widget marker is present in the rendered page)
```

If you don't see the widget, the heuristic configuration on your
scope likely diverges from the defaults — see
[site model](../site-model/index.html#tuning-workflow) for the
tuning workflow and [observability](../observability/index.html) for how
to inspect what each request scored.

## Test that PoW completes

Open the gated URL in a real browser. The interstitial should
auto-submit (silent tier) or render the checkbox widget (form tier),
solve a few seconds of SHA-256 PoW, and bounce back to the real page.
Reload — you should see the real content immediately. The browser
now holds a `_bs_session` cookie carrying the signed envelope and
accumulated reputation.

## Disable temporarily

If you need to bypass the module without removing it from Apache's
config (e.g. emergency rollback during a misfire):

```sh
sudo make disable && sudo systemctl reload apache2
```

`make disable` flips `a2dismod botshield` so Apache no longer loads
the `.so`. Any directives in your vhost configs become unrecognized
on the next reload, so this is a "stop everything" switch — for
gradual rollback prefer `BotShieldEnabled LogOnly` (see
[staging](../staging/index.html)).

## Where to next

- Real-world deployments behind a proxy: [deployment](../deployment/index.html).
- Tier model, scoring, and tuning: [site model](../site-model/index.html).
- Allow lists, rate limits, and triggers: [policy](../policy/index.html).
- Third-party captcha integration: [captcha](../captcha/index.html).
- Metrics, decision log, mod_status: [observability](../observability/index.html).
