# Deploying mod_botshield to a HubZero hub

Written from the geodynamics.org deployment (2026-07-30 → 2026-08-08),
including the ways it went wrong. Ships with `botshield.conf`, which is
the entire configuration in one file.

---

## 0. The one rule that matters most

**BotShield configuration must not live in a vhost file or its m4
source.**

`hzcms` regenerates `/etc/httpd/sites.d/*.conf` from
`/etc/httpd/sites-m4/*.m4`. On geodynamics the config was placed in the
vhost and mirrored into the m4, with parity verified after every change.
On **2026-08-06 10:33** the vhost was regenerated from an m4 that no
longer carried the edits:

- every `BotShieldEnabled` scope silently disappeared
- the six legacy `mod_rewrite` scraping rules came back
- the decision log stopped mid-sentence at 10:34
- `/login?return=…` served 200 unprotected for two days
- nothing failed and nothing alerted — green configtest, running httpd

The module stayed loaded, because `conf.modules.d/` and `conf.d/` are not
hzcms-managed. Only the vhost content was lost.

So: one file, `conf/botshield.conf`, activated by **one line inside the
content-serving vhost**.

### Vhost scope, not main scope — on a HubZero hub this is not a choice

The obvious move is to activate from `conf.d/`, which puts the config at
main-server scope where every vhost inherits it and hzcms cannot touch it.
**Do not do that on a hub with many vhosts.** Two independent reasons:

**1. It is the wrong architecture.** A HubZero hub's vhost count is mostly
TLS-termination-plus-redirect shells. qubeshub.org has 102 namevhosts, and
101 of them are identical: `DocumentRoot /var/www/html` (a dummy), a
single `RedirectMatch (/.*|$) https://qubeshub.org/groups/<name>$1`, and
nothing else — no PHP, no `ProxyPass`, no `fcgi`, no `RewriteRule`. They
serve no application content, so there is nothing to protect. And
`RedirectMatch` is `mod_alias`, resolved during URL translation *before*
BotShield's handler, so BotShield could not act on those requests even if
it were enabled — same precedence problem as `mod_rewrite` (§6). Crawlers
following the redirect land on the real vhost, where BotShield is active,
so coverage is already complete.

**2. Main scope currently multiplies the heuristics.** Enabling at main
scope on qubeshub made every heuristic fire **once per vhost** — 107
times. Measured, across three independent penalties:

```
first-sight-ip          20 -> score 2140      (2140 / 20 = 107)
dropped-cookie          25 -> score 2675      (2675 / 25 = 107)
missing-accept-language  5 -> score  535      ( 535 /  5 = 107)
```

Ordinary Chrome and Firefox users landed in `tier=captcha`. It also
exhausted the 2048-slot rate-counter pool instantly (each enabled vhost
pre-allocates one slot per directory entry, 740), so the wildcard and all
three aggregates silently fell through to **no rate limit at all** —
the opposite of what the config asked for. Re-scoped to one vhost:
`first-sight-ip` appears exactly once, scores 20 and 30, no pool
exhaustion.

The cause is in `bs_resolve_heuristic_triggers` (`src/config.c:865`),
which reads and writes the same field — `vcfg->heuristic_triggers` is
"operator declarations" on input and "resolved list" on output. Visit one
`bs_server_cfg` twice and the second visit treats the first's output,
defaults included, as operator input and re-seeds. `bs_merge_rule_array`
returns the caller's array object unchanged when one side is empty
(`if (nadd == 0) return base;`), so these arrays are shared across server
configs rather than copied. `bs_resolve_flag_triggers` (`config.c:762`)
has the same read-write-same-field shape and is probably silently
affected too — flag triggers carry no additive score.

Because the config belongs in the vhost anyway, this bug does not block
deployment. Fix it before anyone relies on main scope.

> **geodynamics.org deviates from this, by operator decision
> (2026-08-08).** Its `Include conf/botshield.conf` sits inside the
> `<VirtualHost>` in `sites.d/geodynamics-ssl.conf`, not in `conf.d/`, and
> the m4 is deliberately not mirrored — the line will be folded into the
> config system once the setup is stable. The policy file itself is still
> outside the vhost, so a regeneration costs only that one line. Recovery
> is one `echo` and a reload. For a fresh hub, prefer `conf.d/`.
>
> Because the include is inside a vhost there, `BotShieldStateFile` and
> `BotShieldStateSaveInterval` stay in `conf.d/20-botshield-state.conf` at
> main scope — see §4.

---

## 1. Prerequisites

Two of these have bitten us.

```bash
# The execute bit on gcc/as has drifted to 754 on this fleet repeatedly,
# probably by config management. `make` then fails with a confusing
# libtool "Permission denied".
ls -l /usr/bin/gcc /usr/bin/as            # want -rwxr-xr-x
sudo chmod 755 /usr/bin/gcc /usr/bin/as   # if not

sudo dnf install -y httpd-devel json-c-devel openssl-devel libcurl-devel
sudo httpd -M | grep mpm                  # expect mpm_event
```

### Worker capacity is a hard prerequisite

The invisible challenge is affordable at 1024 workers and caused an
outage at 400. On 2026-07-31 enabling the challenge tier rendered 5,145
interstitials in ~1 minute, took Apache from 69/400 to 344/400 busy
workers, and produced `AH03490 scoreboard is full` with HTTPS timeouts.

Re-tested 2026-08-02 under a live flood at ~65 decisions/sec with the
tuning below: **22–95 busy workers of 1024**, load 0.26/core, free
scoreboard slots flat at ~704. Request rate actually *fell* (63→33 rps),
because challenged clients stop retrying as hard.

`/etc/httpd/conf.d/10-mpm-tuning.conf`:

```apache
<IfModule mpm_event_module>
    ServerLimit           16
    ThreadLimit           64
    ThreadsPerChild       64
    MaxRequestWorkers     1024
    StartServers          5
    MinSpareThreads       128
    MaxSpareThreads       512
    ListenBacklog         1024
</IfModule>
```

`ListenBacklog 1024` is what stopped 1.2M dropped connections during the
geodynamics flood — a bigger effect than anything BotShield itself did.
Also set `Timeout 30` in `/etc/httpd/conf.d/timeout.conf`.

BotShield cannot help with connection-level cost. With near-unique IPs
per request, much worker occupancy is TLS handshake and slow-client `R`
state, which is upstream of any HTTP-layer decision; `DESIGN.md`
delegates that to `mod_reqtimeout`.

---

## 2. Build and install the module

```bash
git clone https://github.com/hubzero/botshield && cd botshield
make build
sudo install -m 644 src/.libs/botshield.so \
     /usr/lib64/httpd/modules/mod_botshield.so
sudo install -m 644 apache/30-botshield.conf \
     /etc/httpd/conf.modules.d/30-botshield.conf
```

That drop-in holds `LoadModule` and the `botshield` `LogFormat` nickname
only — no policy, no `CustomLog`.

It must stay in `conf.modules.d/`, not `conf.d/`. This host has non-stock
include ordering: `conf.modules.d/*.conf` is httpd.conf **line 3**, but
`sites.d/*.conf` is **line 70** and `conf.d/*.conf` is **line 71** —
vhosts are parsed *before* `conf.d`. Merge-based directives don't care,
but `LogFormat` nicknames resolve at parse time, so a nickname defined in
`conf.d` would be undefined when the vhosts reference it.

> **The first-ever module load needs `systemctl restart`, not `reload`.**
> A reload leaves it uninitialised and risks segfaults.

---

## 3. Runtime state

```bash
sudo mkdir -p /var/lib/botshield/bots
sudo chown apache:apache /var/lib/botshield /var/lib/botshield/bots
sudo chmod 700 /var/lib/botshield
```

`/var/lib/botshield/secret` is generated automatically on first start.

### Verified-crawler IP ranges

**Do not just `cp apache/bots/*.txt`.** That directory ships only four
files and is missing `googleother.txt`, while the compiled-in allow list
expects **five** bots — so the module logs `googleother ranges file not
loaded ... UA will classify as unverified` on every startup. Generate
them instead:

```bash
# writes /var/lib/botshield/bots/{googlebot,googleother,bingbot,applebot,siteimprove}.txt
sudo tools/refresh-bot-ranges.sh
sudo chown apache:apache /var/lib/botshield/bots/*.txt
sudo chmod 640 /var/lib/botshield/bots/*.txt
```

Run it into a scratch directory first (`refresh-bot-ranges.sh /tmp/bots`)
and diff — it is a network fetch against four providers, and one of its
parsers is currently broken (below).

Why this matters in both directions: a **missing** ranges file degrades
safely — the bot scores 0, it does not trip the fake-bot penalty. A
**stale** one does not. A real Googlebot arriving from a range you don't
have is classified `fake-bot` (+100) and challenged, which is an SEO
incident. Google added 6 CIDRs between 2026-07-30 and 08-08 (309 → 315),
so this drifts on a scale of days.

**The siteimprove parser is broken as of 2026-08-08.** It scrapes an HTML
help-center article with no JSON feed, and now yields 0 addresses against
a sanity threshold of 30:

```
only 0 crawler IPs parsed (threshold 30); page structure likely changed
WARN: parse failed for siteimprove (HTML structure change?)
```

The threshold guard is doing its job — the script leaves the last-good
file in place rather than writing an empty one, and exits 0 for the other
providers. Consequences: `siteimprove.txt` is frozen at 44 CIDRs, and if
Siteimprove rotates addresses their accessibility scanner starts getting
challenged. This matters specifically because the legacy `mod_rewrite`
rules being retired in §6 carried a `!Siteimprove.com` **UA** exemption,
and BotShield replaces it with an **IP-verified** one — stricter, and
correct (a spoofed Siteimprove UA no longer walks through), but dependent
on that file being current.

**Known gap:** `BotShieldAllowRangesRefreshInterval` defaults to 0, so
ranges never self-refresh at runtime. Cron the script (the module reads
the files at startup, so pair it with a graceful restart), or accept
drift.

---

## 4. Install the configuration

One file, one activation line.

```bash
sudo install -m 644 botshield.conf /etc/httpd/conf/botshield.conf

# edit BotShieldRobotsTxt to this hub's robots.txt path
sudo vi /etc/httpd/conf/botshield.conf

echo 'Include conf/botshield.conf' \
  | sudo tee /etc/httpd/conf.d/25-botshield.conf

sudo apachectl configtest && sudo systemctl restart httpd   # first load
```

Split by scope. Two files, because the two halves need different scopes:

- **`conf/botshield.conf`** — the policy, included from **inside the
  content-serving `<VirtualHost>`** (see §0 for why not main scope). The
  m4 is deliberately not mirrored, so hzcms will drop only that one
  `Include` line; recovery is one `echo` and a reload.
- **`conf.d/20-botshield-state.conf`** — `BotShieldStateFile` and
  `BotShieldStateSaveInterval` only. These are `RSRC_CONF` and are read
  once *before* vhosts merge, so inside a vhost they parse cleanly and
  are then **ignored with a NOTICE**. They must sit at main scope, and
  `conf.d/` is both main scope and hzcms-proof.

If you see `BotShieldStateFile placed inside <VirtualHost> ... is
ignored` in configtest output, the split is wrong — the state directives
are still in the vhost-scoped file.

### What the file does as shipped

**It enforces nothing.** It observes the whole site and records what it
*would* have done. Specifically:

| § | Setting | Why |
|---|---|---|
| 1 | `BotShieldStateFile` + `SaveInterval 300` | survive restarts |
| 2 | `BotShieldRobotsMode observe` | record robots.txt violations, refuse nobody |
| 2 | `BotShieldRobotsWildcardScope off` | do not treat unrecognised UAs as crawlers |
| 3 | `BotShieldBotRateLimit * 1 sec mode=observe` | **suppress an enforcing default** |
| 4 | `BotShieldEnabled LogOnly` | full pipeline, no action |
| 6 | enforcing `<LocationMatch>` blocks | **all commented out** |
| 7 | dashboard/metrics/policy-status | localhost only |

Three of those need justifying, because they look redundant and are not:

**§3 is not redundant.** When the module is enabled at vhost scope and no
`BotShieldBotRateLimit` directive exists, `post_config` *synthesises*
`* 1 sec` — and the synthetic entry carries no mode, so it **enforces**.
Nobody writes it and it returns real 429s. On geodynamics this throttled
verified Bingbot before rate-limiting had been agreed to. Stating it
explicitly with `mode=observe` suppresses the synthesis. (Verified in
`src/bot_rate.c:325–385`.)

**§2 `WildcardScope off` is a mobile-users safeguard.** The default is
`heuristic`, which applies the `User-agent: *` group to any crawler
candidate — and `bs_ua_is_crawler_candidate()` is literally
`!is_browser`. A UA the browser templates miss is therefore treated as a
crawler. Mobile Chrome was missed, so real phones took
`Disallow: /login*` as a hard 403 with no challenge to solve, for about
two hours. Every browser probe run beforehand had been desktop. Leave it
`off` until §9's mobile check passes on *this* host.

**§6 stays commented** because observe-first is the only rollout that has
worked. `BotShieldRobotsRefreshInterval` is not set at all: its default
is already 60s.

Everything else is a module default and needs no directive — the
challenge itself, access-log suppression, the decision log path and its
outcome set, safeguard, state format.

### Scope caveat

A main-scope `<LocationMatch>` is inherited by **every** vhost on the
host, including proxy/vnc/webdav endpoints. Harmless for `LogOnly`, and
harmless for the enforcing paths on a hub whose other vhosts never serve
them. To confine it to one hostname, wrap the directive:

```apache
<If "%{HTTP_HOST} == 'qubeshub.org'">
    BotShieldEnabled LogOnly
</If>
```

### Validating a config edit without touching the live server

`-c` is processed after the main config, so the module is loaded and the
`<IfModule>` guard is true:

```bash
sudo httpd -t -c 'Include /etc/httpd/conf/botshield.conf'; echo "exit=$?"
```

Confirm such a test isn't vacuous by injecting a deliberate bad value
inside the guard and checking that configtest *fails*. If a false
`<IfModule>` skipped the block, "Syntax OK" would mean nothing.

---

## 5. Log rotation — not optional

The decision log measured **258 MB/hour** under flood.

`/etc/hubzero/logrotate-botshield.conf`:

```
/var/log/httpd/botshield.log {
	copytruncate
	size 100M
	rotate 6
	compress
	missingok
	notifempty
	nomail
	su root access-logs
}
```

A size threshold checked on a timer does **not** rotate when the size is
reached, only at the next check — so the live file grows to a full check
interval regardless of `100M`. **The check interval, not the size, is
what bounds the live file.** Hourly checks at 258 MB/hr meant a ~258 MB
live file. Check every 15 minutes instead.

`/etc/cron.d/botshield-logrotate` (replaces the earlier
`/etc/cron.hourly/botshield-logrotate` — remove that file, or it rotates
twice on the hour):

```
MAILTO=""
*/15 * * * * root /usr/sbin/logrotate -s /var/lib/logrotate/botshield.status /etc/hubzero/logrotate-botshield.conf
```

Bounds the live file to ~100 MB plus one interval of overshoot: ~165 MB
at flood rate, ~115 MB at the ~54 MB/hr qubeshub was writing while
enforcing four scopes on 2026-08-08.

Two consequences of shortening the interval, both worth a decision
rather than a surprise:

- **`rotate 6` is a count, not a duration, so faster rotation buys less
  history.** Measured on qubeshub: 126 MB per ~1.9 h, so six rotations
  is ~11 hours. Under flood it is ~2.3 hours — likely shorter than the
  incident you would be reading it for. Raise `rotate` if the decision
  log is your evidence trail; the files compress ~9:1 (126 MB → 13.6 MB),
  so `rotate 24` costs ~330 MB.
- **`copytruncate` loses whatever is written between the copy and the
  truncate.** That race now runs four times an hour instead of once. It
  is a handful of lines and is the price of not signalling httpd; note
  it before treating decision-log counts as exact.

---

## 6. Bring enforcement up, one scope per reload

Uncomment one `<LocationMatch>` block in §6 of `botshield.conf`, then:

```bash
# ServerLimit is 16. With all children spawned, a reload has nowhere to
# put the new generation — that is AH03490 and a site outage. Two
# geodynamics outages were caused this way.
curl -s http://127.0.0.1/server-status?auto \
  | grep '^Scoreboard' | tr -cd '.' | wc -c      # want > 100

sudo apachectl configtest && sudo systemctl reload httpd
```

**Gate the reload on configtest's exit code, as above.** Reading its
output is not enough: piping configtest to `tail`, seeing the failure,
and running `systemctl restart` in the same command anyway took the site
down ~30 seconds.

`configtest` does not exercise `post_config` — the
`bs_post_config_first_pass_skip` sentinel swallows the single pass, so
SHM/mutex/secret init is untested. A green configtest is not a rehearsal
for a reload.

Order used on geodynamics, each verified before the next:

1. `^/(login|register)(/|$)` — highest value; the unbounded
   `/login?return=` space is what drew the original flood
2. `^/resources/browse`
3. `^/citations/browse`
4. `^/publications`
5. `^/groups/[^/]+/publications`
6. `^/events/[0-9]{4}/` — month/day/week only

On (6): events are **not indexed in Solr** (zero event docs) and are
reachable only by walking the calendar — 16 of 380 were linked from
`/events`, 0 from search. The **year** view is therefore deliberately
left unenforced and followable as the sanctioned bounded crawl path
(~22 pages). Enforcing it makes events undiscoverable.

If the hub uses Shibboleth SAML, also uncomment the `^/login/`
`BotShieldEnabled Off` block so the callback is never challenged.

### Why `LocationMatch` and not `mod_rewrite`

`mod_rewrite` runs at URL translation, *before* BotShield's handler. A
rewrite-based block is invisible to every BotShield metric and to the
decision log, and it lands in the access log instead. Migrating the six
legacy rules into BotShield cut the access log from 31 MB/hr to ~1 MB/hr.
Derive the scope list from **traffic**, not from the existing rewrite
rules — doing the latter is how `/citations/browse` was missed.

**Retiring the legacy rules (done on geodynamics 2026-08-08).** Leaving
them in place alongside BotShield is not neutral: rewrite wins, so the
BotShield scope on that path becomes decorative. Comment them out once
the corresponding scope is enabled and verified — comment, not delete,
since the m4 still carries them and will restore them anyway.

Confirm the handover by response size: the legacy rule returns a bare
**403 / 199 bytes**, BotShield returns the **403 / 10,158-byte**
interstitial.

```
/resources/browse?tag=x                403  10158B  <- botshield
/publications/browse?search=x          403  10158B
/publications?tags=abc                 403  10158B
/groups/foo/publications?search=x      403  10158B
/publications/browse/browse?search=x   403  10158B
```

Two rules on geodynamics were deliberately **kept**, because BotShield
does not cover them: the `Detectify` + `action=pdf` block (403) and the
`MSIE|Trident` → 426 block. Check what else is bundled in that region
before commenting a range.

Mind the exemptions they carried. All six had `!Siteimprove.com` — a
**UA-trusted** exemption. BotShield replaces it with an **IP-verified**
one via `siteimprove.txt`, which is stricter and better (a spoofed
Siteimprove UA no longer passes) but depends on that file being current —
and its refresh parser is currently broken (§3).

**It applies to qubeshub too — the earlier claim here that it did not was
wrong.** `sites.d/qubeshub-ssl.conf` carried **seven** of these rules.
Always check the specific vhost file, not a glob that can miss:

```bash
sudo grep -c 'Reject aggressive scraping' /etc/httpd/sites.d/qubeshub-ssl.conf
```

**Retired on qubeshub 2026-08-08 15:00 EDT**, in this order — the order
is the point, since reversing it leaves the paths unprotected in between:

1. **Map each rule to a covering scope, and enable any that are
   missing.** Six of the seven were already covered by `^/publications`
   and `^/community/(groups|members)`; only `/resources/browse?tag=` had
   none, so that scope went in first, on its own reload. Note that bare
   `/groups/X/…` 302-redirects onto `/community/groups/X`, and the old
   rules matched `THE_REQUEST` as an *unanchored substring*, so
   `^/community/(groups|members)` covers both spellings — check for that
   before adding a redundant scope.
2. **Verify each scope is actually enforcing** — `outcome=challenged`,
   not `~challenge`, in the decision log — *before* touching the vhost.
3. **Comment the rules out and reload.** Confirm handover two ways: the
   bare `403 / 199 B` signature stops (it ceased at 14:57 here, on the
   reload), and the paths become visible in the decision log for the
   first time (497 `outcome=challenged` in the first three minutes).
4. **Confirm verified crawlers still pass.** Siteimprove kept passing on
   `/resources/browse?tag=` as `verified-bot:siteimprove score=-995`,
   now IP-verified rather than UA-trusted.

Kept on qubeshub, same as geodynamics: the `Detectify` + `action=pdf`
block and the `MSIE|Trident` → 426 block.

One condition needed no replacement because it had already stopped
working: `%{HTTP_COOKIE} ^$` matches only requests with *no cookie at
all*, and BotShield mints `__Host-bs_session` on every pass — so any
cookie-retaining client was already walking through all seven rules
untouched. Leaving both layers in place was not just redundant, it was
degrading.

---

## 7. Read the observe data before enforcing

```bash
# who ignores robots.txt Disallow
grep -oE 'robots-block:[a-z0-9-]+:observe' /var/log/httpd/botshield.log \
  | sort | uniq -c | sort -rn

# who exceeds the declared Crawl-delay
grep -oE 'bot-rate:[a-z0-9-]+:observe' /var/log/httpd/botshield.log \
  | sort | uniq -c | sort -rn

# what would be challenged, by client class
grep 'outcome=~challenge' /var/log/httpd/botshield.log \
  | grep -oE '(browser|known-bot|unknown-bot|verified-bot|fake-bot|unknown-ua)' \
  | sort | uniq -c | sort -rn
```

On geodynamics this showed Bingbot causing ~90% of crawl-delay violations
(~50 429s/hr if enforced) and three AI crawlers ignoring `Disallow: /`.
Enforcing means 429s to Bing — a deliberate SEO tradeoff, not an obvious
win. It was left in observe mode pending a decision.

To enforce: change `BotShieldRobotsMode observe` → `enforce` and drop
`mode=observe` from the rate limit.

---

## 8. HubZero core patches

Independent of BotShield, and the more durable fix: six components
generate unbounded URL spaces that crawlers enumerate forever. These are
**upstream bugs** — every HubZero site running them has the same spaces.
Fixing the `/login?return=` recursion is what actually ended the flood;
BotShield only bought time.

Cherry-pick from the geodynamics site repo (`2.4-main`):

```
c97b0a25f6  Close three unbounded URL spaces that crawlers were enumerating
62e92f74eb  404 repeated /browse segments in the members and publications routers
```

| File | Bug |
|---|---|
| `com_users/site/controllers/auth.php` | `/login?return=b64(/login?return=…)` — unbounded recursion depth |
| `com_members/site/controllers/profiles.php` | reflects `REQUEST_URI` into a login `return=` — unbounded cardinality |
| `com_members/site/router.php` | `/members/browse/browse/browse…` accepted as a profile section |
| `com_publications/site/router.php` | `/publications/browse/browse` read as a category name |
| `com_events/site/controllers/events.php` | calendar answered 200 for any year; crawled 1977–2099 |
| `com_events/site/views/**` (7 files) | missing `rel=nofollow` on calendar navigation |

The shared root cause in three of these is
`Request::getString('REQUEST_URI', …, 'server')` reflected into a
generated URL. Grep for that signature across the codebase.

Also `mod_notices/tmpl/default.php`: the site-notice close link appends
`?sitenotice=close` to `REQUEST_URI` without stripping an existing copy,
so each render adds one — observed at 11 copies. Latent unless a notice
is published.

Site-local files are gitignored and must be applied by hand:

- **`robots.txt`** — add `Disallow: /register*` beside `/login*`. Bing was
  crawling `/register?return=<base64>` and collecting 429s because only
  `/login*` was declared.
- **`app/templates/dynamic/index.php`** — `rel="nofollow"` on the header
  login/signup links, and guard `$loginReturnQuery` so an auth page can't
  embed its own URL as a return value.

These patches live in a repo that is **not** hzcms-managed, which is why
they survived the 08-06 regeneration that destroyed the module config.

---

## 9. Verification

```bash
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
H=https://qubeshub.org

curl -sSi -A "$UA" "$H/login?return=/x" | head -1       # challenge once enforcing
curl -sSo /dev/null -w '%{http_code}\n' -A "$UA" "$H/"  # homepage untouched

# mobile must NOT be hard-blocked — this is the regression that locked
# real users out of /login for two hours
curl -sSo /dev/null -w '%{http_code}\n' \
  -A 'Mozilla/5.0 (Linux; Android 14; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36' \
  "$H/login"

curl -sS http://127.0.0.1/botshield/dashboard?w=60
```

- [ ] `httpd -M | grep botshield` shows the module
- [ ] `/var/log/httpd/botshield.log` is being written
- [ ] enforcing path challenges a cookieless browser
- [ ] solving the PoW once grants access across all enforcing paths
      (interstitial → sha256-zeros PoW → POST `/botshield/embedded-verify`)
- [ ] **mobile** browser gets a solvable challenge, never a bare 403
- [ ] a verified crawler passes (`verified-bot:` in the log)
- [ ] a spoofed crawler is caught (`fake-bot:`, score ~130)
- [ ] counters do **not** reset across `systemctl restart`
- [ ] `grep -rc BotShield /etc/httpd/sites.d/ /etc/httpd/sites-m4/` is **0**
- [ ] all **five** ranges files present; no `googleother ... not loaded` in the error log
- [ ] no `Require ip` on the dashboard block (§10), or you have verified
      the fail2ban consequence deliberately

That last check is the regression test for §0. Worth a cron job:
if a `BotShield` directive ever appears in a vhost, someone has
reintroduced the failure mode; if `conf.d/25-botshield.conf` ever
disappears, protection is off.

---

## 10. Locking down the dashboard — and the fail2ban trap

`/botshield/dashboard`, `/metrics` and `/policy-status` are **not
authenticated**. On a public vhost they reveal internal vhost names,
traffic volumes, challenge/solve rates and SHM capacities to anyone.

**The obvious fix is a trap. Do not use `Require ip` alone.**

HubZero ships a fail2ban jail `apache-hz_access_denied` watching
`<hub>-error.log` and `error_log`. Confirmed identical on both
geodynamics.org and qubeshub.org:

```
maxretry = 5        findtime = 120s        bantime = 36000s  (10 hours)
```

It matches `AH01630: client denied by server configuration` — exactly
what a `Require ip` denial writes. The dashboard auto-refreshes every
30 seconds. So a denied dashboard writes an AH01630 line every 30s,
crosses 5-in-120s in about two minutes, and fail2ban bans the viewer's IP
**at the firewall, for the entire site, for ten hours**.

This is not hypothetical. On 2026-08-08 adding `Require ip` to that block
locked the operator out of all of geodynamics.org:

```
11:49:43  Require ip added, dashboard restricted
11:50:14  403  AH01630   <- dashboard auto-refresh
11:50:17  403  AH01630
11:50:19  403  AH01630
11:51:28  403  AH01630
11:51:49  403  AH01630   <- 5 in 95s -> banned 10h, whole site
```

The recovery:

```bash
sudo fail2ban-client status apache-hz_access_denied     # find the IP
sudo fail2ban-client set apache-hz_access_denied unbanip <IP>
sudo nft list ruleset | grep <IP>                       # confirm gone
```

Also note `Require ip 127.0.0.1` may be **dead config**. If `:443` listens
only on a public address — as on geodynamics — there is no loopback 443 at
all, and a request from the host to its own vhost presents the host's
public IP. The rule can never match, so it silently denies everyone.
Check `Listen` before relying on it.

And an allowlist tends not to stay correct: operator VPN egress was
observed rotating across three unrelated /16s
(`138.199.35.117`, `149.40.62.54`, `146.70.246.163`) within days.

### Options that actually work

- **SSH tunnel** — `ssh -L 8443:<vhost-ip>:443 <host>`, then browse
  `https://localhost:8443/botshield/dashboard`. Traffic arrives sourced
  from the host itself, so there is no allowlist to maintain and no ban
  can occur. Costs a cert-name warning and no config change. Recommended.
- **Auth** (`AuthType Basic` + `Require valid-user`) — works from any
  network, but verify its failure mode against `apache-error` and
  `apache-hz_access_denied` first. Repeated auth failures on an
  auto-refreshing page are the same shape of problem.
- **World-readable** — what `botshield.conf` ships (`Require all
  granted`), and what geodynamics runs by operator decision. No ban risk;
  accepts the exposure.

Whatever you choose, the functional endpoints — `embedded-verify`,
`embedded.js`, `embedded-bootstrap`, `safeguard-info` — **must stay
public**. They are the challenge flow itself.

---

## 11. Rollback

```bash
sudo rm /etc/httpd/conf.d/25-botshield.conf
sudo apachectl configtest && sudo systemctl reload httpd
```

Removing the one activation line disables everything; the module stays
loaded and inert. To remove entirely, also delete
`conf.modules.d/30-botshield.conf` and restart.

---

## 12. Traps, in the order we hit them

| Trap | Consequence |
|---|---|
| Config in the vhost/m4 | `hzcms` regenerated it away; protection silently lost for 2 days |
| `reload` on first-ever module load | uninitialised module, segfault risk |
| Reload with no free scoreboard slots | `AH03490`, site outage (twice) |
| configtest piped to `tail`, restart run anyway | httpd refused to start, ~30s outage |
| configtest treated as a rehearsal | it does not run `post_config` |
| `BotShieldRobotsTxt` without `RobotsMode observe` | GPTBot/ClaudeBot 403'd within minutes |
| Synthesised `* 1 sec` bot rate limit | real 429s to verified Bingbot, unrequested |
| `RobotsWildcardScope heuristic` + incomplete browser templates | mobile users hard-403'd out of login |
| `status=` omitted from a request trigger | family default is 403 — the rule keeps blocking |
| bare `status=pass` on a request trigger | declines out of the handler, **disabling** the challenge |
| Stale verified-bot ranges | real Googlebot scored `fake-bot` +100 and challenged |
| A default declared in two tables | edit one, it compiles, deploys, and changes nothing |
| Scope list derived from old rewrite rules | missed `/citations/browse`; derive from traffic |
| `Require ip` on the auto-refreshing dashboard | 5 AH01630 in 120s → fail2ban banned the operator off the whole site for 10h |
| `Require ip 127.0.0.1` where `:443` has no loopback listener | dead rule; silently denies everyone |
| `cp apache/bots/*.txt` as the ranges install | ships 4 of 5 files; `googleother` unverified on every startup |
| Legacy `mod_rewrite` left alongside BotShield | rewrite wins at translation; the BotShield scope is decorative |
| Config at main scope on a many-vhost hub | heuristics fire once per vhost (×107); browsers scored into `tier=captcha`; rate-counter pool exhausted → no rate limiting at all |
| Enabling on redirect-only vhosts | nothing to protect, and `RedirectMatch` resolves before the handler anyway |

**Order of operations that works:** module in → observe everything → read
the log → enforce one scope per reload → fix the URL spaces in §8 →
restrict the dashboard.

The §8 code fixes are what actually ended the flood. BotShield bought the
time to find them.

---

## Appendix — qubeshub.org pre-flight, measured 2026-08-08 11:42 EDT

Read-only survey of the target host. The platform is identical to
geodynamics: Rocky 8.10, httpd 2.4.37, mpm_event, and the same non-stock
include ordering (`conf.modules.d` line 3, `sites.d` line 70, `conf.d`
line 71), so every ordering caveat above applies verbatim.
`/var/www/qubeshub/robots.txt` exists, so the §2 path in `botshield.conf`
is already correct. `sudo` is NOPASSWD. `sites.d/` and `sites-m4/` are
root-only, and `hzcms` manages them — §0 applies here too.

### Four things must be fixed before §4

**1. The toolchain will not build.** Both files carry the drift described
in §1:

```
-rwxr-xr-- 1 root root /usr/bin/gcc      # 754, needs 755
-rwxr-xr-- 1 root root /usr/bin/as       # 754, needs 755
```

**2. `json-c-devel` is not installed** (`httpd-devel` is).

```bash
sudo chmod 755 /usr/bin/gcc /usr/bin/as
sudo dnf install -y json-c-devel
```

**3. `MaxRequestWorkers` is 400 — the exact capacity that caused the
2026-07-31 outage.** There is no `10-mpm-tuning.conf` and no
`timeout.conf` on this host; `conf.modules.d/00-mpm.conf` contains only
the `LoadModule` line, so every MPM setting is at its default. Measured
scoreboard:

```
total slots : 400        (ServerLimit 16 x ThreadsPerChild 25)
idle        : 374
reading     : 24
writing     : 2
free '.'    : 0
```

Load average was 13.31 on 6 cores (2.2/core) at rest, with 74–125 busy
workers. **Do not enable any enforcing scope on this host until the §1
MPM tuning is installed.** Enabling the challenge tier at 400 workers is
what produced `AH03490` and HTTPS timeouts on geodynamics; at 1024 the
same flood cost 22–95 workers.

**4. Free scoreboard slots are 0**, so all 16 process slots are already
allocated and a graceful reload has nowhere to put the new generation.
On this host, use `systemctl restart httpd`, not `reload`, until the MPM
tuning raises `ServerLimit`. This is the AH03490 condition from §6.

### Traffic already worth acting on

Of 65,984 requests logged today, **31,638 (48%) are a secret-scanning
campaign** from a single tight range, all `curl/8.7.1`:

```
9266  185.177.72.67      3104  185.177.72.23
6175  185.177.72.68      3099  185.177.72.70
3239  185.177.72.12      3027  185.177.72.22
3118  185.177.72.53
```

Probing for leaked credentials and infrastructure state, not content:
`/terraform.tfstate`, `/terraform.tfstate.backup`, `/rootkey.csv`,
`/web.config`, `/wp-json/gravitysmtp/v1/tests/mock-data`, and `/@fs/root`
(243 hits — a Vite dev-server arbitrary-file-read probe).

This is not a crawler and robots.txt is irrelevant to it. It is what the
`scanner_probe` flag and the flagged-IP table exist for, and being a
single `/24` it is cheap to drop outright — arguably ahead of the
BotShield rollout:

```apache
<RequireAll>
    Require all granted
    Require not ip 185.177.72.0/24
</RequireAll>
```

Also present: **SemrushBot** at 3,201 requests, mostly hammering
`/bedrock/participant_template.php?event_id=…&event_web_site=…` — the
same bot that was stuck enumerating geodynamics events, and another
reflected-parameter URL space worth checking against §8.

Lower priority, but the same bugs as geodynamics: 6,651 requests to a
double-slash `//` path, 1,019 to `/robots.txt/` with a trailing slash,
729 carrying `return=`, 811 hitting `/browse`.

### robots.txt gap

`/var/www/qubeshub/robots.txt` (80 lines) already declares
`Crawl-delay: 1`, `Disallow: /login*`, `Disallow: /publications/browse`,
and a long `Disallow: /` blocklist of AI crawlers (Amazonbot,
anthropic-ai, Applebot-Extended, Bytespider, CCBot, ClaudeBot, …).

It is missing **`Disallow: /register*`** — the same gap that had Bing
crawling `/register?return=<base64>` on geodynamics. Add it beside
`/login*` (§8).

Because `Crawl-delay: 1` is declared, the §3 rate-limit discussion is
live on this host from day one: the crawl-delay is real policy here, and
`mode=observe` is what keeps it from becoming 429s before you have looked
at who violates it.

### Confirmed identical: the fail2ban trap

`apache-hz_access_denied` is present on qubeshub with the same parameters
as geodynamics — `maxretry 5`, `findtime 120s`, `bantime 36000s` — and
watches `/var/log/httpd/qubeshub-error.log` and `error_log`. It had **76
IPs banned** at survey time. Everything in §10 applies here unchanged: do
not put `Require ip` on the dashboard.

### Legacy scraping rewrites — CORRECTION (2026-08-08, post-enforcement)

**The 11:42 pre-flight said qubeshub has no "Reject aggressive scraping"
rules. That was wrong.** `sites.d/qubeshub-ssl.conf` lines 80–123 carry
**seven** of them, plus a Detectify PDF block and an IE `R=426`. The
pre-flight grep missed them; §6's retirement step is *not* a no-op here.
Verify with `grep -c 'Reject aggressive scraping'
/etc/httpd/sites.d/qubeshub-ssl.conf` — expect 7, not 0.

They all share this shape:

```apache
RewriteCond %{HTTP_USER_AGENT} !Siteimprove.com
RewriteCond %{THE_REQUEST}     /publications/browse [NC]
RewriteCond %{QUERY_STRING}    (^|&)search= [NC]
RewriteCond %{HTTP_COOKIE}     ^$
RewriteRule .* - [R=403,L]
```

Covered: `/resources/browse?tag=`, `/publications/browse?search=`,
`/publications/browse/browse?search=`, `/groups/*/publications?search=`,
`/publications?tag=`, `/groups/simiode/publications?tag=`,
`/groups/*/publications?tag=`.

Three things follow, all measured over the 14:11–14:45 EDT window with
four scopes enforcing:

**1. They mask BotShield, exactly as §6 predicts.** `mod_rewrite` runs at
URL translation, before BotShield's handler, so `[R=403,L]` ends the
request first. ~19,000 requests were 403'd this way in ~34 minutes and
**not one appears in the decision log** — BotShield never saw them. Spot
check: pick a 403 from the access log and grep its IP in
`botshield.log`; it will not be there.

**2. The decision log therefore undercounts.** Traffic to the busiest
crawl paths on the site is invisible to it, so "what BotShield is
handling" is not "what is hitting the site". Read the access log
alongside it before sizing anything.

**3. `%{HTTP_COOKIE} ^$` and BotShield's always-mint cookie are on a
collision course.** The rules only fire on requests with *no cookie at
all*, and BotShield mints `__Host-bs_session` on every pass — so any
client that has been through BotShield once and retains the cookie walks
straight through all seven. It is not yet happening at scale (2 of 8,607
on `/publications/browse?search=`, 112 of 10,887 on group publications
search) because these crawlers are one-shot IPs that discard cookies.
A cookie-retaining crawler bypasses the whole set. Retire these into
BotShield policy rather than leaving both layers in place.

One thing they do **not** do: `[R=403]` from `mod_rewrite` does not emit
`AH01630` (that is `authz_core`), so these 19k denials do not feed the
`apache-hz_access_denied` jail. The 388 `AH01630` lines in
`qubeshub-error.log` are the `185.177.72.0/24` scanner probing `i.php` /
`phpi.php`, unrelated to this.

### Recommended order for this host

1. `chmod 755` the toolchain, install `json-c-devel`
2. install `10-mpm-tuning.conf` + `timeout.conf`, `systemctl restart`
3. consider dropping `185.177.72.0/24` outright
4. build and install the module (§2), `systemctl restart` (first load)
5. runtime state (§3)
6. `botshield.conf` + the one-line include, still enforcing nothing (§4)
7. let it observe, then read §7
8. only then uncomment scopes, one per reload (§6)
