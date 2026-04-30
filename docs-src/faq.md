# FAQ

## Strategy and positioning

### Does this just block all bots?

No, and that's deliberate. The goal isn't bot elimination — it's
*site control over the terms of access*. Search-engine
crawlers, LLM training bots, archival crawlers, monitoring
agents, partner integrations — many of these are bots a site
*wants* to reach the content, but on conditions the site sets:
when, how often, which paths, with what rate cap, with what
attribution. mod_botshield's primitives are built around setting
those terms:

- **Allow-list.** When `BotShieldAllow on` is set and the
  configured CIDR ranges are loaded, verified crawlers (UA-and-IP
  match against the published ranges) bypass the score ladder
  entirely. The built-in seed list covers Googlebot, Bingbot,
  and Applebot; you add others via `BotShieldAllowBot` and
  refresh ranges out of band with `tools/refresh-bot-ranges.sh`.
- **Robots.txt enforcement.** A bot that ignores your `Disallow`
  rules gets enforced at the policy layer — robots.txt is no
  longer advisory text the bot can skip; it's enforced at your
  origin.
- **Rate limits and cohorts.** Welcome a known crawler at 60
  requests / minute but not 600. Different rates for different
  cohorts. Different rates by path.
- **Trigger families.** Time-of-day, load-aware, per-route,
  env-driven rules — narrow the gate when needed, open it
  otherwise.
- **The challenge tier ladder.** Anything not on the allow-list
  gets graduated friction (silent, form, captcha) sized to the
  client's score, not a binary block.

A site that wanted to block every bot could do that with much
less than mod_botshield offers. The reason this module exists is
that "block everything that isn't a real human browser" is the
*wrong* answer for most sites — they want search-engine
indexing, want LLM crawlers to cite them under controlled terms,
want monitoring to reach health endpoints, want partner bots to
hit their API. mod_botshield is the policy surface for saying
yes-with-conditions instead of no.

### Should I use mod_botshield instead of Cloudflare?

Probably not. Cloudflare's bot product solves a different scope of
problem than mod_botshield does, and a site that can sit behind
Cloudflare and accept the trade-offs is usually better served doing
exactly that.

What Cloudflare gives you that mod_botshield doesn't:

- **Edge filtering.** Traffic Cloudflare drops never touches your
  origin at all — saving bandwidth, TLS termination, and the cost
  of even a 1 ms decision per request.
- **Massive cross-customer bot intelligence.** Cloudflare sees
  traffic across millions of sites and reuses signals (botnets,
  scraper fleets, residential-proxy ranges, fingerprintable
  headless browsers) the moment they appear anywhere.
- **DDoS protection at scale.** Cloudflare absorbs volumetric and
  application-layer attacks orders of magnitude bigger than a
  single Apache instance can survive.
- **Managed challenges and turnkey product.** No tuning, no
  capacity sizing, no log-grepping. Pay the bill, get a
  policy.

What mod_botshield gives you that Cloudflare doesn't:

- **No third party in the request path.** Your traffic never
  leaves your trust boundary.
- **No vendor lock-in or recurring cost.** Bot mitigation that
  goes beyond simple known-bad-IP blocking is typically a paid
  tier with managed CDNs.
- **Direct control.** You write the rules in Apache config you
  already understand; you don't have to learn a separate dashboard
  or wait for a vendor to add a feature.

The honest one-liner: if you can put your site behind Cloudflare
and you don't have a specific reason not to, do that. mod_botshield
is for the cases where you can't or won't.

### Why not just use Cloudflare?

You should. If Cloudflare is a viable option for your site, that's
the answer. mod_botshield exists for the cases where Cloudflare
isn't a fit:

- **The site can't go behind a third-party CDN.**
- **The cost model doesn't work for your deployment.** When the
  CDN's bot-mitigation pricing exceeds the budget you have for
  the problem, an in-process Apache module may be the right fit.
- **The expensive thing isn't the bandwidth.** mod_botshield's
  whole reason for existence is to keep the application stack
  *asleep*. A real framework bootstrap (PHP / Python / Ruby / Node
  — pick your language) loads configuration, middleware, an ORM,
  plugins / modules / event listeners, and typically opens a
  database connection or pulls one from a pool. That's tens to
  hundreds of milliseconds of work per cold request before the
  first line of business logic runs. Multiplied by millions of
  bot requests per week that adds up whether the bytes are cheap
  or not. A CDN can't always make that decision because it
  doesn't know which routes wake the framework and which serve
  from disk.
- **You want to own the rules.** mod_botshield's policy lives in
  Apache config. For sites that need explainable, auditable bot
  policy, the in-process model fits better than a vendor-curated
  ruleset.

If none of those apply, you're paying configuration tax for
protection you could have gotten cheaper from a CDN.

### How is this different from mod_security?

mod_security is a WAF — pattern-matching rules against request
attributes (URI, headers, body) to block known attack signatures
(SQL injection, XSS, RFI, scanner UAs). It's brilliant at what it
does. mod_botshield is a *bot* mitigator — proof-of-work
challenges, scoring, cookie-carried reputation, captcha
integration. The two are complementary; running them together is
a sensible pattern (mod_security for attacks, mod_botshield for
scrapers).

The clearest functional split:

- mod_security stops a malicious *request* (drop the SQL
  injection, the XSS payload, the path-traversal attempt).
- mod_botshield stops a malicious *client* (challenge the scraper,
  flag the honeypot tripper, force a captcha on the credential-
  stuffing source).

There's overlap on UA-pattern blocking and rate limiting, but the
fundamental machinery is different.

### How is this different from fail2ban?

fail2ban watches log files, matches patterns, and adds firewall
rules. It's a great tool for SSH brute force, repeated 401s, and
similar log-driven detection. For HTTP bot mitigation it has two
limits:

- **Latency.** A bot finishes scraping by the time the log line is
  processed and the firewall rule lands. mod_botshield decides
  per-request, in-process, before the application runs.
- **No proof-of-work option.** fail2ban can ban or not-ban; it
  can't issue a challenge that costs the client time and lets
  legitimate users through.

For "an IP is doing something obviously bad, ban it for an hour"
fail2ban is fine. For "this request is suspicious, make the client
prove they're human" you want mod_botshield (or Cloudflare).

## Detection and accuracy

### Will it block real users?

Below `BotShieldScoreSilent` (default 20) the module returns
DECLINED to Apache; the user's request flows through normally and
they never see mod_botshield at all. The default heuristics are
tuned to keep typical browser traffic below that threshold, but
the line is closer than it looks: a request with no
`Accept-Language` header (15 points) plus a first-time IP not in
the Bloom filter (5 points) lands at exactly 20, which trips the
silent tier. Browsers in some configurations (privacy modes that
strip headers, certain mobile webviews, intranet apps with
non-default settings) can reach the threshold on a clean first
request. The captcha-tier fail-open story is on the captcha side;
the silent / form tiers themselves are real friction even for a
legitimate first-time visitor.

If real users *are* hitting challenges, the likely causes are:

- Apache is behind a proxy and `mod_remoteip` isn't configured —
  every request looks like it comes from the edge LB. See
  [troubleshooting](../troubleshooting/index.html).
- The score thresholds are too low for the site's traffic mix.
- A path-trigger or block-path is matching legitimate routes.

[Staging](../staging/index.html) describes the
`BotShieldShadowMode on` workflow for catching false positives
before they hit users.

### Do bots actually solve proof-of-work challenges?

Some of them. The reality is graduated:

- **Cheap scrapers** (Python `requests`, `curl`, `wget`,
  HTTP-library clients with no JS engine) cannot solve PoW. They
  fail at the silent and form tiers. This is the bulk of scraper
  traffic.
- **Headless browsers** (Puppeteer, Playwright, Selenium) *can*
  solve PoW because they execute JavaScript. They can also solve
  Cloudflare's managed challenges and most non-captcha gates.
- **Sophisticated bot operators** can throw real CPU at PoW
  trivially — a 4-leading-zero SHA-256 challenge is cheap.

So mod_botshield's PoW tier is not a bot-eliminator. It's a
*friction tax*: it makes scraping economically worse than not
scraping, so a scraper that can scrape an unprotected site gets
better ROI moving on. Combined with reputation (the cookie carries
score; flagged IPs get tier_floor=captcha; honeypot trippers get
+60 score on every request) and the third-party captcha tier for
the suspicious tail, the cumulative effect is: scrapers go
elsewhere, real users barely notice.

For paths that genuinely cannot ever serve a bot, the captcha
tier with hostname/action binding is the design's strongest
friction setting.

### What about Googlebot, Bingbot, GPTBot — bots I want to allow?

The allow-list family handles this. `BotShieldAllowBot` registers
a UA pattern and a published IP range; verified crawlers (UA
matches AND IP is in the range) bypass the score ladder entirely.
mod_botshield ships a built-in seed list for the major search-
engine crawlers; `tools/refresh-bot-ranges.sh` fetches and updates
the CIDR files.

Importantly, the allow-list also catches *fakes*: a request whose
UA matches "Googlebot/" but whose IP isn't Googlebot's gets a
strong penalty (`fake-googlebot`) — bot operators love claiming
to be search engines. See [policy](../policy/index.html#allow-list-e1-verified-crawlers).

For LLM crawlers (GPTBot, ClaudeBot, anthropic-ai, Google-
Extended) — sites that want to block them by default can pair
`BotShieldRobotsTxt` with a robots.txt carrying `Disallow: /` for
those groups. mod_botshield enforces robots.txt at the policy
layer, not as advisory text the bot can ignore.

### What about API endpoints — clients that legitimately can't run JavaScript?

Three tools for this case:

1. **Don't gate them.** API routes usually deserve a different
   policy than user-facing routes. Scope `BotShieldEnabled` with
   `<LocationMatch>` to exclude `/api/...`.
2. **Allow-list specific clients.** If your API has a fixed set
   of trusted callers (mobile app, partner integrations,
   internal services) put their UA + IP range in
   `BotShieldAllowBot` so they bypass the score ladder.
3. **Use the app-bridge.** The signed app-feedback protocol lets
   your application classify clients after-the-fact and feed the
   verdict back into mod_botshield's reputation. JWT-authenticated
   clients can carry reputation across requests without
   needing to solve PoW. See
   [captcha](../captcha/index.html#app-bridge).

A fourth option for IoT-style clients: implement the silent-tier
PoW protocol in your client. The wire format is documented;
nothing forces you to use a browser to satisfy it.

## Operations and overhead

### Is there overhead per request?

For requests that pass through (real users, valid cookies,
verified crawlers): a few microseconds to a few hundred. The hot
path is heuristic checks (header presence) + Bloom filter probe
(one SHM read, no locks) + optional cookie verify (an AES-256-GCM
open over a small base64-decoded envelope).

The in-tree benchmark suite (`tests/bench/`) measures this on a
small Apache static-file endpoint. That is intentionally a harsh
case for percentage overhead: the baseline request is so cheap
that any fixed per-request work looks large.

The latest saved runs include both saturation tests and fixed-rate
tests at 1k, 5k, and 10k requests/second. `BotShieldEnabled on`
with no policy features added about **8 microseconds** to the
single-connection p50 latency. At fixed rates, 1k and 5k rps were
essentially flat; at 10k rps, heavy policies stayed in the
tens-of-microseconds range at p50, with low-millisecond p99 tail
growth only in the kitchen-sink configuration. The saturation test
still shows roughly 20% lower static-file RPS for heavy policies,
but that is a capacity-ceiling measurement, not normal request
latency. See
[deployment](../deployment/index.html#performance-characteristics)
for the measurement summary.

For challenged requests: there's a one-time PoW cost paid by the
*client* (server work is constant — sign a challenge, sign a
verify cookie); the server-side latency is dominated by HMAC
operations. For the captcha tier: one outbound libcurl siteverify
call, bounded by `BotShieldCaptchaTimeout` (default 1 s, fail-
open on timeout).

These are synthetic-load numbers, not field measurement. Real
production overhead depends on hardware, kernel version, network
RTT, and header mix. The benchmark suggests the module's
contribution is well below the cost of any meaningful upstream
handler (PHP startup, framework bootstrap, database round-trip).

### Will it slow my site down?

For real users the module returns DECLINED below the silent
threshold and the request flows through Apache normally. The
worst case for a passing request is a few hundred microseconds of
HMAC + header checks. That's well below typical framework
bootstrap, database query, or template render times — mod_botshield
isn't the bottleneck.

For challenged requests, yes, the user experiences friction
(silent splash for a couple seconds; form-PoW for a few seconds
of clicked PoW; captcha for as long as the provider takes). That's
the entire point: *make scraping expensive without making real use
expensive*. The threshold tuning workflow in
[staging](../staging/index.html) is your handle on where
that line falls.

### Does it work with PHP / FastCGI / mod_php / mod_proxy / nginx upstream?

Yes to all of those. mod_botshield runs as an Apache
`APR_HOOK_FIRST` request handler that decides before any content
generator runs. By the time PHP / FastCGI / mod_proxy gets the
request, mod_botshield has already returned DECLINED (real
content) or short-circuited with a challenge response. The
upstream sees only the requests that mod_botshield decided to
forward.

`mod_proxy_balancer`, `mod_rewrite`, `mod_alias`, `mod_dir` —
none of them interact with mod_botshield in surprising ways. The
hook ordering is documented in
[deployment](../deployment/index.html) and
[observability](../observability/index.html).

### Does it work in containers / Kubernetes?

Yes — it's just an Apache module. The constraints are:

- The SHM segment is per-Apache-instance. Two Apache pods don't
  share reputation. For per-pod isolation that's fine; for cross-
  pod sharing you'd need to centralize on a shared backend (which
  is out of scope today — see "What it doesn't do").
- The state file (`BotShieldStateFile`) lets a pod's reputation
  survive restarts if you mount it from a persistent volume.
  Without persistence, a restarted pod starts with a clean
  flagged-IP table.
- `mod_remoteip` configuration is critical when traffic comes from
  an ingress controller (nginx-ingress, AWS ALB Ingress, Traefik).
  See [deployment](../deployment/index.html).

### How much memory does it use?

Default: 16 MiB SHM segment shared across all workers, growing as
sites raise capacity directives. Per-process overhead is
negligible (the `.so` is a few hundred KB; no per-request heap
allocation outside of Apache's `r->pool` which is freed at request
end).

The 8-hour soak (1.4M requests) showed +4 MB RSS growth. SHM
sizing is documented in [deployment](../deployment/index.html#capacity-sizing).

## Privacy and compliance

### Does it phone home? Send data anywhere?

No. The module makes outbound network calls in two
configured categories:

1. **Captcha siteverify.** When `BotShieldCaptchaProvider` is
   configured, mod_botshield makes one HTTPS POST per verify
   attempt to the configured provider's siteverify URL with the
   client's captcha token (and the client IP as the `remoteip`
   field). This fires from three paths: the `/captcha-verify`
   endpoint, the silent-tier embedded-verify endpoint when an
   site pairs silent with a captcha provider, and the
   form-captcha fixup. No siteverify call ever happens without
   a captcha provider explicitly configured on the scope.

   The captcha widget itself loads provider JavaScript on the
   client side (Turnstile / hCaptcha / etc.) — that's a
   third-party request from the *client's* browser to the
   provider, not from your Apache. It's still a side-channel
   that lets the provider see the client's IP.

2. **Bot-range refresh script.** `tools/refresh-bot-ranges.sh`
   fetches published JSON from search-engine providers
   (Googlebot, Bingbot, etc.) and rewrites the CIDR files in
   `/var/lib/botshield/bots/`. This runs only when you
   invoke it (cron or manual); the module itself never makes
   these calls at runtime.

No telemetry. No analytics. No phoning the project. The module is
a single `.so` that runs in your Apache.

### What client data does it store?

- **Flagged-IP table (SHM).** Client IP (masked to
  `BotShieldIPv6PrefixLen` for v6) + flag bitmap + TTL. No UA, no
  paths, no headers. Survives restart if `BotShieldStateFile` is
  configured.
- **Bloom filter.** Client IP fingerprint (lossy; you can't
  recover IPs from the filter). Used for "first-sight"
  detection.
- **Strike + safeguard tables.** Same shape as flagged-IP —
  client IP keys, small slot data.
- **Verified cookie.** AES-256-GCM encrypted; carries the
  client's accumulated score, flag bits, and challenge counters.
  Lives in the *client's* browser, not on the server.
- **Pending cookie.** HMAC-signed; lives in the client's browser
  for 5 minutes between interstitial render and captcha verify.
- **Decision log.** Client IP, request path, decision tier, and
  reason tokens go to Apache's error log. Sensitive header values
  (Cookie, Authorization, etc.) are not logged.

The module avoids storing request bodies, header values
(including `Cookie`, `Authorization`, and the like), or
application-side session data. IPs and request paths may still
be personal data under GDPR or comparable regimes — see the
data-protection notes below.

### GDPR / data-protection considerations?

The module's data footprint (client IP + flag bits + TTL) is
generally classified as personal data under GDPR. Considerations:

- **Lawful basis.** Bot mitigation is generally a "legitimate
  interest" — preventing scraping of site data. Document the
  basis in your privacy notice.
- **Retention.** Flagged-IP entries expire after the configured
  TTL (default 1 hour for honeypot hits). The Bloom filter
  rotates with `BotShieldBloomWindow` (default 7 days).
  Reputation in the verified cookie expires with the cookie TTL
  (default 1 hour).
- **Right to erasure.** A request to forget an IP can be
  satisfied by reloading Apache (clears in-memory state) and
  deleting the state file (clears persisted state). There's no
  finer-grained "forget this IP" API today; build it via your
  own admin tooling if you need it.
- **Data residency.** With the captcha tier enabled, the
  captcha provider sees the client IP twice: once via the
  server-to-provider siteverify call (which sends `remoteip`
  in the POST body), and once via the provider's client-side
  JavaScript that the interstitial loads. Both are third-party
  data flows from the client's perspective, governed by the
  provider's terms. With the captcha tier disabled,
  mod_botshield is in-process and IP data does not leave the
  server.

The captcha-provider relationship is governed by the provider's
terms; review them as part of your processor map.

## Architecture and edge cases

### Does it support IPv6?

Yes. v4 keys at `/32`, v6 keys at the configured prefix length
(`BotShieldIPv6PrefixLen`, default 64 — per-subscriber for typical
ISP allocations; tighter values like `/56` or `/48` flag larger
blocks of addresses sharing reputation).

### What happens during a captcha-provider outage?

mod_botshield fails open for siteverify timeouts. If
`BotShieldCaptchaTimeout` (default 1 s) elapses before the
provider responds, the verification path treats the request as
passing — same outcome it would get without the provider. A
WARNING-level log line carries the literal string `failing open`
so you can grep / alert on it. The Prometheus metrics
count these as `outcome=failopen`.

The reasoning: a third-party provider outage shouldn't black-hole
legitimate traffic. Sites preferring fail-closed semantics
can wrap the provider in a circuit breaker (e.g. require captcha
tier through a different path that doesn't fail-open) but that
isn't the default.

### What happens if mod_watchdog isn't loaded?

mod_botshield degrades gracefully:

- Periodic state-file snapshots stop. The graceful-shutdown save
  still runs.
- The capacity headroom watchdog stops emitting NOTICE/WARN
  lines. You can read the same data from the on-demand
  Prometheus gauges (`botshield_shm_flagged_used` etc.).
- The robots.txt mtime-poller stops. You must reload Apache
  to pick up robots.txt changes.
- The load sampler stops; load triggers won't fire.

None of these are fatal. The module continues to serve requests
and apply policy.

### What happens during graceful restart?

Apache's `apachectl graceful` re-runs `post_config` once. The SHM
segment is preserved across the restart (Apache attaches to the
existing segment rather than creating a new one), so flagged-IP
state, Bloom filters, rate-limit counters all persist. The state
file is loaded if configured.

Cookies signed before the restart still verify if the master
secret is unchanged. For zero-disruption secret rotation, see the
secondary-secret flow in [deployment](../deployment/index.html#secret-rotation).

### Does it cache anything that could go stale?

Bot ranges (CIDR files for `BotShieldAllowBot`) are read once at
config-parse time and cached on the per-server config. To pick up
a new bot range, reload Apache.

Robots.txt is parsed at startup and re-parsed by the watchdog on
mtime change. Default refresh interval 60 s; tunable via
`BotShieldRobotsRefreshInterval`.

The captcha provider's site key, secret, and CA bundle are read
once at config-parse time. To pick up a key rotation, reload
Apache.

### Why an Apache module instead of an nginx module / reverse proxy?

mod_botshield is Apache 2.4-specific because that's the
deployment target it was built for. The architecture (request-
phase hook, SHM-backed reputation, in-process scoring) maps to
nginx's `ngx_http_*_module` shape with some translation, but no
nginx port exists today.

For nginx deployments the practical answer is: put nginx in front
of Apache (with `mod_remoteip` configured for the X-Forwarded-For
chain), let Apache + mod_botshield handle the bot mitigation. Or
use Cloudflare / other CDN in front of nginx for the same effect.

## What it doesn't do

### Distributed reputation across multiple Apache instances

Each Apache instance has its own SHM segment. There's no
out-of-the-box mechanism for sharing reputation across pods /
hosts / data centers. For deployments where a single bot's
behavior should affect all your instances, you have three
options:

1. **Sticky sessions at the LB level.** Ensure each client lands
   on the same Apache instance via consistent hashing. Reputation
   tracks per-instance but a given client's reputation is
   coherent within their session.
2. **Edge filtering.** Put the cross-instance signal at the edge
   (Cloudflare, AWS WAF, etc.) and let mod_botshield handle
   per-instance decisions.
3. **App-bridge.** Have your application centralize bot
   classification via a shared backend (Redis, your own
   database) and feed the verdict to each Apache instance via
   the X-BotShield-Feedback protocol.

Centralized SHM (Redis-backed reputation, pubsub flag
synchronization) is on the long-term roadmap but not shipped.

### Browser fingerprinting

Commercial bot-management products use canvas/WebGL/font
fingerprinting, TLS JA3, and many other signals to score
how-bot-like a client is. mod_botshield doesn't do any of this.
It's deliberately a small, transparent, Apache-config-driven set
of signals: header presence, IP reputation, scope-based triggers,
and proof-of-work.

If you need fingerprint-based scoring, that's the kind of problem
specialized vendors solve. mod_botshield aims at the bulk of bot
traffic those products bill heavily to handle — scrapers,
scanners, credential stuffers, simple harvesters — and leaves the
long-tail of headless-Chrome-with-residential-IP
sophistication to specialized vendors.

### Permanent bans

Flagged-IP entries always have a TTL. There's no "ban this IP
forever" directive. The reasoning: ban-forever lists at scale are
operationally hostile (need GUI for un-banning, accumulate ASN-
level mistakes, become impossible to audit). The combination of
flag-TTL + tier_floor=captcha + accumulating cookie reputation
gives you "this IP gets a captcha every time, indefinitely while
the abuse continues" without the binary ban semantics.

For genuinely permanent blocks (a CIDR you never want to see),
use Apache's `Require not ip` or your firewall — both handle
permanent denial better than mod_botshield does.

## Where to next

- Install + minimal config: [getting-started](../getting-started/index.html).
- Tier model and scoring: [site model](../site-model/index.html).
- Allow lists, triggers, robots: [policy](../policy/index.html).
- Captcha + app-bridge: [captcha](../captcha/index.html).
- Common operational issues: [troubleshooting](../troubleshooting/index.html).
- Full directive reference: [directives](../directives/index.html).
