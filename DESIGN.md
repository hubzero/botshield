# mod_botshield — design

mod_botshield is an Apache 2.4 module that filters bot and scraper
traffic **in-process, before Apache hands a request to PHP / FastCGI /
upstream**. The economic model is "keep cheap filtering cheap and let
expensive backends sleep." A PHP startup cost of ~1 ms multiplied by
millions of filtered requests per week is real money; mod_botshield's
job is to filter those requests below 1 ms each so the upstream never
spins up.

Scale target: ~1 M unique IPs per week on one site. Overhead target:
sub-millisecond per cookied request; bounded, visible latency on
challenged requests.

The module operates on two orthogonal axes:

- **Challenge tier** — what the user experiences: `pass`, noninteractive
  JavaScript (JS) Proof-of-Work (PoW), form-PoW interstitial, full
  third-party captcha.
- **Verification protocol** — how the server trusts that a challenge
  was solved: an authenticated AES-256-GCM cookie envelope that
  doubles as both challenge proof and carrier of accumulated
  reputation.

Per-user state lives **in the user's cookie**, not in server memory,
so a 1 M-IPs-per-week site does not blow out shared memory. Server
state is deliberately sparse: a rotating Bloom filter for "have we
seen this IP this week", a flagged-IP table for IPs that tripped a
serious event, and a few small tables for per-rule strike accounting,
anti-loop safeguards, and replay defense. The happy path is invisible:
users who score 0 never see a challenge and never carry a cookie from
the module.

## Threat model

The module addresses concrete adversaries, not abstract "bots":

- **LLM training crawlers** (`GPTBot`, `ClaudeBot`, `anthropic-ai`,
  `CCBot`, `PerplexityBot`, `Bytespider`, `Amazonbot`,
  `Applebot-Extended`, `Meta-ExternalAgent`, `cohere-ai`, `Diffbot`,
  `ChatGPT-User`). Self-identifying, frequently ignore robots.txt,
  pull full text at huge volume.
- **Distributed scrapers** rotating residential IPs (50k+ concurrent),
  bypassing per-IP rate limits. Often plain `requests` / `httpx` /
  `aiohttp` — no JS engine.
- **Headless-browser scrapers**, smaller population, capable of
  solving the PoW. The module makes them pay the cost per page.
- **Probing scanners**: low-volume scans for `/.env`, `/.git/`,
  `/wp-admin/`, etc. High-signal bait for the scoring engine.

Slowloris / slow-read defense is largely delegated to `mod_reqtimeout`.
Body-read paths in the module (form-captcha verify, M8 captcha-verify,
embedded-verify) inherit Apache's `Timeout` (60 s default).

## Non-goals

- Replacing a cloud WAF — signature matching, L3 DDoS absorption, and
  global IP-reputation feeds live at the edge.
- Out-detecting the ML providers — Turnstile / hCaptcha / reCAPTCHA
  are trained on billions of sessions; the module *composes* them, it
  does not compete with them.
- Being a rule engine — no DSL, no regex-heavy policy files. Per-
  request code uses hand-rolled byte scanners (memcmp / memchr); regex
  is reserved for config-time validation only.
- Being provider-agnostic — Apache first; nginx is a separate project.
- Permanent ban management — the module logs stable tags so external
  systems (fail2ban, etc.) can turn them into longer-lived bans.

## Source layout

The module is built into a single shared object (`mod_botshield.so`)
from 23 paired `.c`/`.h` feature files in `src/`, plus three
unpaired codegenned translation units (`generated_bot_directory.c`,
`generated_browser_templates.c`, `generated_verified_bots.c` — see
Build & install for the codegen step). The build is via
apxs (`Makefile`); cross-file symbols are namespaced `bs_` / `BS_`
and the `.so` is linked with `-fvisibility=hidden` so only
`botshield_module` itself escapes the dynamic-linker symbol table.

Header layout follows a hub-and-spoke shape: the central
`botshield.h` hosts the cross-cutting `bs_dir_cfg` / `bs_server_cfg`
config nucleus, operator-tunable defaults, and the module symbol
declaration. Each feature's own types and constants live in its
feature header — `score.h` (tier + score system), `triggers.h`
(trigger + policy families), `challenge.h` (bs_challenge envelope +
PoW registry), `captcha.h` (M8 provider registry), `cookie.h`
(cookie wire constants), `robots.h` (active-state bundle), `crypto.h`
(primitives + bounded parsers), `allowlist.h` (verified-crawler
classifier + IP helpers), `ua_class.h` (the unified per-request
classification struct the other UA passes feed).

The headers split roughly in two. The type-bearing leaves that
relocated content out of `botshield.h` during the shrink arc
(`score.h`, `triggers.h`, `challenge.h`, `captcha.h`, `crypto.h`,
`metrics.h`, `robots.h`, `shm.h`) forward-declare `bs_dir_cfg` /
`bs_server_cfg` and are self-contained; the four UA-classification
headers added later (`ua_class.h`, `bot_directory.h`,
`browser_classifier.h`, `bot_rate.h`) are self-contained too, and
were written that way from the start — they take their inputs as
plain arguments and so need no config forward-declaration at all.
The remaining feature
headers (`allowlist.h`, `bridge.h`, `config.h`, `cookie.h`,
`formcaptcha.h`, `heuristics.h`, `load.h`, `policy.h`, `non_interactive.h`,
`templates.h`) still `#include "botshield.h"` for full visibility
into the config structs they parameterize. Decoupling those would
deliver an incremental-rebuild win — punted as a follow-up.

| File | Responsibility |
|------|---------------|
| `botshield.{c,h}` | Module entry point: `bs_handler` request dispatch, `cmds[]` directive table, hook registration, `botshield_module` struct. Hosts the central `bs_dir_cfg` / `bs_server_cfg` config types and operator-tunable defaults. Also: bot-name token validation, asset-extension skip list |
| `config.{c,h}` | Config lifecycle: `create_dir_cfg` / `merge_dir_cfg` / `create_server_cfg` / `merge_server_cfg` / `post_config` / `child_init`. Setters for top-level / UI / score-threshold / forgiveness / SHM-sizing / state-file / rate-limit / safeguard directives |
| `crypto.{c,h}` | OpenSSL wrappers: `bs_sha256`, `bs_hmac_sha256`, `bs_ct_equal`, `bs_hkdf_derive_key`, `bs_gcm_encrypt`, `bs_gcm_decrypt`, hex codec. Plus `BotShieldSecretFile` / `BotShieldSecondarySecretFile` setters and the bounded integer parsers (`bs_parse_int_bounded`, `bs_parse_uint32_bounded`, `bs_parse_int64_bounded`) used at config-time and on the cookie parse path |
| `shm.{c,h}` | Single-segment SHM layout: header, flagged-IP / strike / safeguard / nonce tables, two Bloom buffers, captcha-verify rate + log slots, fixed-window rate-counter pool, M9.2 metrics block. Open-addressing seqlock helpers, SipHash-2-4, popcount, `bs_state_save` / `bs_state_load`, `bs_headroom_watchdog_cb` |
| `cookie.{c,h}` | AES-GCM cookie envelope: `bs_build_cookie_prefix_gcm`, `bs_build_cookie_payload`, `bs_build_set_cookie`, `bs_install_verified_cookie`, `bs_verify_cookie_gcm`, `bs_verify_cookie`. Cookie-header tokenizer (`bs_parse_cookies_once`, `bs_get_cookie_value`, `bs_get_verified_cookie_value`). Carry-forward predicate + math (`bs_should_carry_prior_rep`, `bs_carry_forward_eligible`, `bs_apply_rep_carry`). Cookie wire-format constant (`BS_GCM_COUNTER_SEP`) |
| `challenge.{c,h}` | Challenge issuance (`bs_issue_challenge`), PoW algorithm registry + lookup (`bs_find_algorithm`), canonical pipe-delimited HMAC input (`bs_challenge_canonical`), inline-JSON renderer (`bs_challenge_json`), bootstrap-binding helpers (`bs_format_bound_ip_hex`, `bs_compute_bootstrap_sig`). `BotShieldAlgorithm` setter. Hosts `bs_challenge` envelope, `bs_rep_state` reputation block, `bs_pow_algorithm` registry types, and challenge wire constants (`BS_PROTOCOL_VERSION`, `BS_SALT_BYTES`, `BS_NONCE_BYTES`) |
| `score.{c,h}` | Per-request score struct on `r->request_config`, `bs_score_add` accumulator, reason renderers (`bs_decision_reason_names`, `bs_score_reasons_joined`), `bs_apply_flag_triggers` walker, `bs_decide_tier` score → tier picker, `bs_tier_name`. Hosts `bs_tier` and `bs_non_interactive_mode` enums, `bs_score_entry` / `bs_request_score` types, score thresholds (`BS_DEFAULT_SCORE_*`) and heuristic penalties (`BS_PENALTY_*`) |
| `policy.{c,h}` | `bs_check_policy` request-time policy walker (cookie / env / load / path triggers, robots, rate-limit, robots Crawl-delay). `bs_policy_dump` for `-D DUMP_BOTSHIELD_POLICY` |
| `triggers.{c,h}` | Per-family trigger setters (`bs_set_request_trigger`, `bs_set_cookie_trigger`, `bs_set_env_trigger`, `bs_set_feedback_trigger`, `bs_set_load_trigger`), shared action-key parser, `bs_apply_trigger_action` executor. `bs_set_flag_ip` and `bs_set_flag_trigger` setters for the E14 flagtrigger family. `bs_cookie_pred_match` predicate evaluator. Hosts the shared action engine (`bs_trigger_action`, `bs_trigger_family`, `BS_T*` enums), per-family entry types (`bs_request_trigger_entry` et al.), the E2.1 cohort + rate-limit types (`bs_cohort`, `bs_rate_limit_entry`, `bs_rate_escalate_entry`, `bs_rate_counter`), and the E14 flagtrigger entry type (`bs_flag_trigger_entry`, `bs_flag_action_kind`) |
| `captcha.{c,h}` | M8 provider registry (`bs_find_provider`), libcurl-backed `bs_captcha_siteverify` shared shim, `bs_geetest_siteverify` provider-specific verifier, M8.1 pending cookie (`bs_mint_pending_cookie`, `bs_clear_pending_cookie`), `bs_captcha_verify_handler`, URL-encoded form lookup helper (`bs_form_get`). All eleven captcha directive setters. Hosts `bs_captcha_provider` registry struct, `bs_captcha_result` enum, `bs_captcha_siteverify_fn` typedef |
| `non_interactive.{c,h}` | E17 embedded handlers: `bs_embedded_js_handler`, `bs_embedded_worker_handler`, `bs_embedded_bootstrap_handler`, `bs_embedded_verify_handler`, `bs_form_widget_handler`. `BotShieldNonInteractiveMode` setter |
| `templates.{c,h}` | Static HTML/CSS/JS strings for the PoW widget, captcha-tier widgets, and the page shell. Two-step substitution renderer (`bs_render_challenge_page`) |
| `formcaptcha.{c,h}` | E18 fixup hook (`bs_form_captcha_fixup`) and the `BS_FORM_REPLAY` input filter (`bs_form_replay_filter`) for body replay |
| `bridge.{c,h}` | E5 inbound: `BOTSHIELD_APP_FEEDBACK` output filter (`bs_app_feedback_filter` + `bs_app_feedback_insert_filter`) that strips the response header and applies the signed event. E8.2 outbound: `bs_app_claims_set` strips client X-Botshield-* and emits a fresh signed `X-Botshield-Claims`. Setters for `BotShieldAppFeedback`, `BotShieldAppFeedbackHeader`, `BotShieldAppClaims`, `BotShieldAppIntegrationSecretFile` |
| `load.{c,h}` | E11 load-aware throttling: `bs_load_watchdog_cb` (scoreboard sampler + external-state-file poller + hysteresis), `bs_load_current` lockless reader. Four `BotShieldLoad*` setters |
| `allowlist.{c,h}` | E1 verified-crawler classifier: `bs_ua_classifier`, `bs_ua_classify`, CIDR loaders (`bs_allow_load_ranges`, `bs_allow_load_ranges_from_string`), `bs_allow_ip_in_ranges`, request-time `bs_check_allow`, builtin bot table (`bs_builtin_bots`). Setters `bs_set_allow_enabled`, `bs_set_allow_bot`. Also hosts shared IP helpers (`bs_parse_client_ip`, `bs_mask_ipv6_prefix`) |
| `ua_class.{c,h}` | Unified per-request UA classification: `bs_classify_request_ua` walks browser-templates → bot directory → verified-bot IP cross-check in that order (browser-first, so real users pay one pass) and caches the single answer on `r->pool` via `apr_pool_userdata` for every downstream consumer. `bs_classify_request_hook`, label stringifier `bs_ua_class_label_str`. Hosts the `bs_ua_class` struct + `bs_ua_class_label` enum. Setter `bs_set_classify` (`BotShieldClassify` — per-pass enable/disable, each disabled pass with a documented fail-safe) |
| `bot_directory.{c,h}` | Known-bot lookup over a bundled snapshot of the Cloudflare bot directory (~600 crawlers). Aho-Corasick construction (`bs_known_bots_build_ac`, `bs_known_bots_build_baseline`), `bs_ua_is_known_bot`, botgroup / slug resolvers (`bs_known_bots_resolve_slugs`, `bs_known_bots_resolve_by_botgroup`), TSV-override load + atomic publish + watchdog (`bs_known_bots_load`, `bs_known_bots_publish`, `bs_bot_directory_watchdog_cb`). Setters `BotShieldBotDirectory`, `BotShieldBotDirectoryRefreshInterval`. UA-only, deliberately not a trust authority — IP-verified crawler identity is `allowlist.{c,h}`'s job |
| `browser_classifier.{c,h}` | Strict-template real-browser matcher: `bs_ua_is_browser`, `bs_ua_browser_slug`, `bs_browser_family`. Normalizes runs of `[0-9._]+` to `X` then requires a full-string match against the deduped top-100 UA template set, so appended tokens fail by design. Runtime-override load + publish + watchdog (`bs_browser_templates_load` / `_publish` / `_watchdog_cb`). Setters `BotShieldBrowserTemplates`, `BotShieldBrowserTemplatesRefreshInterval` |
| `bot_rate.{c,h}` | Slug-keyed bot rate limiting. All slot allocation happens at post_config (`bs_bot_rate_init`) because the slug universe is bounded by the directory size — no dynamic SHM mutation, no per-request inserts; request time is an O(1) hash probe (`bs_bot_rate_check`). Fed from two sources: the `BotShieldBotRateLimit` directive and robots.txt `Crawl-delay` groups. Hosts `bs_bot_rate_slot`; setter `bs_set_bot_rate_limit` |
| `robots.{c,h}` | RFC 9309 parser + matcher: `robots_parse_file`, `robots_parse_buf`, `robots_query`, group-iteration accessors. `bs_path_match` shared path-glob matcher. `bs_robots_load` (mtime-gated load + atomic publish), `bs_robots_watchdog_cb`. Setters `BotShieldRobotsTxt`, `BotShieldRobotsRefreshInterval`, `BotShieldRobotsWildcardScope`. Hosts the active-state bundle (`bs_robots_state`), `bs_robots_wildcard_scope` enum, and `BS_ROBOTS_REFRESH_*` sentinels |
| `heuristics.{c,h}` | `bs_run_builtin_heuristics`: missing UA / missing Accept-Language / scraper-token UA penalties + the E1 allow-list call |
| `metrics.{c,h}` | `bs_decision_log` (one structured line + counter bumps), cookie-status mapper, trigger-tag stash, `bs_metrics_handler` (`/metrics` Prometheus 0.0.4), `bs_status_hook` (mod_status contribution). Also the module-owned decision log: `bs_set_decision_log` (`BotShieldDecisionLog`), `bs_open_decision_logs` (post_config, `ap_open_piped_log` for `|program` specs), and `bs_propagate_decision_env` — the `log_transaction` hook that re-publishes `BS_*` env across an internal redirect and returns `DONE` to break the logging chain for `accesslog=off` |

### Source style

The C source follows the [Apache httpd developer style guide](
https://httpd.apache.org/dev/styleguide.html) — the same
conventions httpd-trunk's `mod_proxy`, `mod_rewrite`, and
`mod_ssl` use: 4-space indentation with no tabs, Allman braces
for function definitions, K&R braces for control flow, pointer
asterisks adjacent to the identifier (`type *name`), 80-column
soft target (the upstream guide says 78; the few-column
divergence is immaterial). Module-internal naming
conventions — `bs_` for cross-file symbols, `BS_` for macros,
all cross-file public symbols namespaced — are enforced by code
review.

Style is **human-maintained**. An `.editorconfig` at the repo
root locks indentation, line endings, and trailing-whitespace
handling — that's what most editors actually consume. Beyond
that, layout choices that contributors should match by hand
include:

- Manually aligned `case X:     return Y;` registry tables
  where the alignment makes the table readable as a column.
- One-argument-per-line function signatures when the call site
  benefits from vertical scanning, even when the line would fit
  in 80 columns.
- Multi-line call continuation indented to the opening paren or
  one extra level (4 spaces) — whichever reads more clearly for
  the call.
- Block comments wrapped to 70-72 columns with full sentences;
  the comment is read as prose, not as code annotation.

We deliberately do not run `clang-format` (or `indent`) blanket
passes. The existing manual layout consistently produces more
readable code than any clang-format profile we could write
preserves. The discipline has held across the source-reorg arcs
without drift, which is the empirical answer to "do we need a
reformatter?" — no.

If you want a quick consistency check on a touch-up before
committing, eyeball the diff against the surrounding style. The
`.editorconfig` will catch the easy mistakes (tabs, wrong
indent depth, trailing whitespace).

## Operator model

Four tiers, decided per request from a running score plus carried
reputation:

| Tier | Behavior |
|------|----------|
| `pass`    | Real handler runs; if there was no cookie, none is issued. Legitimate users experience the module as invisible |
| `noninteractive` | Either the M7 auto-submit splash (default, `BotShieldNonInteractiveMode interstitial`) or E17's embedded mode where the real page is served and a wrapper script POSTs back to `/embedded-verify` (`BotShieldNonInteractiveMode embedded`) |
| `interactive` | Visible reCAPTCHA-shaped checkbox the user clicks; the page's JS Worker solves the PoW. The checkbox is withheld for `BotShieldInteractiveArmMs` after load, and a solve faster than `BotShieldInteractiveMinSolveMs` is rejected |
| `captcha` | Configured third-party provider's widget (Turnstile, hCaptcha, reCAPTCHA v2/v3, Friendly, GeeTest). Falls through to form-PoW with `reason="captcha_fallback"` if no provider is configured on the scope |

A successful challenge at any tier mints (or re-issues) the
`_bs_session` cookie with the prior reputation carried forward, less
a tier-dependent forgiveness amount on the score (subject to the
hourly cap). Flags survive forgiveness — score can decay to zero, but
flag bits do not clear within cookie TTL.

Score crosses three configurable thresholds
(`BotShieldScoreNonInteractive`, `BotShieldScoreInteractive`,
`BotShieldScoreCaptcha`) to pick the tier. **None has a default**: an
unset threshold never fires, so a deployment that configures no
thresholds never reaches a tier by score at all. The policy dump prints
each one as either its configured value or
`unset - never fires (suggested: N)`. The E14 flagtrigger walker can also
push a tier floor up (never down) regardless of score.

## Request lifecycle

`bs_handler` is registered at `APR_HOOK_FIRST` so it runs before the
default static-file handler. Its walk:

1. **Module-disabled and subrequest gate.** `cfg->enabled != 1` or
   `!ap_is_initial_req(r)` → `DECLINED`. The module never operates on
   subrequests (mod_include, ap_sub_req_lookup_*, etc.).
2. **Endpoint dispatch.** URLs starting with `BotShieldEndpointPrefix`
   (default `/botshield`) are routed to module-owned handlers:
   - `/botshield/captcha-verify` and `/botshield/captcha-verify/<name>`
     → `bs_captcha_verify_handler`
   - `/botshield/metrics` → `bs_metrics_handler`
   - `/botshield/embedded.js` → `bs_embedded_js_handler`
   - `/botshield/embedded-worker.js` → `bs_embedded_worker_handler`
   - `/botshield/embedded-bootstrap` → `bs_embedded_bootstrap_handler`
   - `/botshield/embedded-verify` → `bs_embedded_verify_handler`
   - `/botshield/form-widget.js` → `bs_form_widget_handler`
   - Any other `<prefix>/...` path → 404 with `X-Botshield: unknownendpoint`
3. **Debug short-circuit.** `BotShieldDebug On` → 403 "Hello World"
   regardless of any other state.
4. **Asset pass-through.** `bs_is_asset_uri` (`src/botshield.c:728`)
   matches a fixed compiled-in list of 21 suffixes (defined in
   `BS_ASSET_EXTS[]` at `src/botshield.c:720`) against the URI
   tail (case-insensitive, query string stripped) and returns
   `DECLINED` so a cookieless first page load still pulls its CSS /
   images. The full list:
   - styles + scripts: `.css`, `.js`, `.mjs`, `.map`
   - images: `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg`,
     `.ico`, `.bmp`
   - fonts: `.woff`, `.woff2`, `.ttf`, `.eot`, `.otf`
   - media: `.mp3`, `.mp4`, `.webm`, `.ogg`

   Anything not in this list — including `.json`, `.xml`, paths
   with no extension at all — is subject to the gate. The list
   is not configurable; adding a suffix requires a code change.
5. **Misconfiguration check.** Without both `BotShieldSecretFile`
   (master key) and `BotShieldAlgorithm` resolved on the scope, return
   503 `X-Botshield: misconfigured`.
6. **Cookie verify.** `bs_get_verified_cookie_value` looks for
   `__Host-bs_session` first then unprefixed `_bs_session`;
   `bs_verify_cookie` GCM-decrypts (primary then secondary key for
   E16 rotation) and parses canonical fields. Three outcomes:
   - `NULL` reason → cookie fully valid; rep is trustworthy.
   - Non-`NULL` reason but signature did verify → cookie failed a
     later check (expired, bad counter); rep was server-signed so
     it's still safe to carry forward via `bs_should_carry_prior_rep`.
   - Non-`NULL` reason `"signature mismatch"` → bytes can't be
     trusted; discard.
   On a fully-valid verify, E10 safeguard state for that IP is
   cleared (a successful solve proves the client *can* progress).
   The verdict is published to `r->notes[BS_CK_STATE_NOTE]` for E4
   cookietrigger predicates (`bs-cookie=verified|missing|invalid`).
7. **Policy walk.** `bs_check_policy` runs the eight-family policy
   walker. On `DECLINED` (status=nochallenge trigger) → log + DECLINED. On
   any other HTTP status → 403/429/etc. with the appropriate
   decision-log outcome.
8. **Heuristics + flag-IP lookup.** `bs_run_builtin_heuristics`
   scores missing-UA / missing-Accept-Language / scraper-UA-tokens
   plus the E1 allow-list dispatch. `bs_flagged_ip_lookup` reads the
   masked client IP from SHM; presence emits a coarse `flaggedip`
   reason.
9. **First-sight Bloom check.** Only when the request is cookieless
   or signature-mismatched and the masked IP isn't in either Bloom
   buffer, add a `+5 firstsightip` penalty. Never penalizes a
   client we've already transacted with.
10. **Flag-trigger walk.** `bs_apply_flag_triggers` walks
    `scfg->flag_triggers` over the union of IP-side and
    cookie-side flag bits, applying SCORE actions and accumulating a
    TIER_FLOOR via MAX.
11. **Score → tier.** `bs_decide_tier(cfg, effective_score)` with
    `effective_score = heuristic_total + cookie_score`. The
    flagtrigger floor is then MAX'd in.
12. **Pass tier.** Below the noninteractive threshold → emit E8.2 X-Botshield-
    Claims (when enabled), log decision, return `DECLINED`. The real
    handler runs.
13. **Bloom feed.** Once a challenge is committed-to, the IP is added
    to the active Bloom buffer (writes stay off the ~99% happy path).
14. **Safeguard / anti-loop.** E10's `bs_safeguard_check` returns
    true if N presentations have piled up without a solve. The client
    is then 302-redirected to `BotShieldSafeguardRedirectURL`, or to
    the built-in explainer at `<prefix>/safeguard-info`, with the
    original URI appended as `?return=`. It is **not** passed through
    — it never reaches protected content, and its flagged-IP entry
    survives. Logged `tier=safeguard outcome=redirect`. Enabled by
    default; only an explicit `BotShieldSafeguard Off` disables it.
    Otherwise the presentation is recorded.
15. **E17 embedded short-circuit.** `tier == BS_TIER_NONINTERACTIVE &&
    cfg->non_interactive_mode == BS_NON_INTERACTIVE_MODE_EMBEDDED` and the safeguard
    presentation count is below `BS_DEFAULT_EMBEDDED_FALLBACK_THRESHOLD`
    → log noninteractive/declined, `DECLINED`. The wrapper script handles
    verification. After threshold consecutive embedded dispatches
    without `_bs_session` arriving, fall through to M7 with a
    `embeddedfallbackm7` reason.
16. **Carry-forward + rep build.** `bs_apply_rep_carry` clamps
    forgiveness against the per-cookie hourly cap (E15), subtracts
    from prior score, bumps the appropriate `passes_*` counter (LOW
    #7 clamp). First-time challenges start with zero rep.
17. **Issue + render.** `bs_issue_challenge` fills a fresh
    `bs_challenge` with version/alg/salt/nonce/difficulty/expiry/
    auto_tier/signature. `bs_challenge_json` produces the inline JSON
    (with E17 bound-IP HMAC for embedded mode).
    `bs_render_challenge_page` picks the widget (PoW for noninteractive/interactive,
    captcha provider widget for captcha tier when configured), splices
    into the page shell, writes the response.
18. **Decision log.** `bs_decision_log` writes one structured line
    and bumps M9.2 counters.

Flag-IP writes are not a separate lifecycle step: a scope that wants
to flag the client writes `BotShieldTrigger flag=<name> ttl=<sec>`,
and the flag lands inside the policy walk at step 7 via
`bs_apply_trigger_action` like any other trigger action.

## Cookie envelope

The module's primary trust artifact is the `_bs_session` (or
`__Host-bs_session` — see Cookie name selection below) cookie. It is
self-contained and HMAC-authenticated via AES-256-GCM, carrying the
PoW proof, the `auto_tier` flavor flag, and the reputation block in a
single envelope.

### Wire format

```
cookie value = base64url( alg_id(1) || nonce(12) || ciphertext || tag(16) )
               "."
               counter_str
```

`alg_id` is `BS_COOKIE_ALG_GCM = 0x01` and is used as the single
byte of associated authenticated data so an attacker cannot swap the
byte to drive verification into a different parse. The plaintext is
the canonical pipe-delimited string described below; the counter is
appended outside the envelope because the M2 / M7 PoW client-solves
the counter and only the server's signature on the rest of the
envelope binds the challenge to the (salt, nonce, difficulty) it
enforces.

For server-issued captcha cookies the counter is the literal string
`"captcha"`; for M2/M7 PoW cookies it is the decimal counter the
client solved.

### Canonical HMAC plaintext

Both the issue side (signs this string) and the verify side
(recomputes and compares with constant-time equality) produce the
exact same canonical bytes for a given `bs_challenge`:

```
v|alg|salthex|noncehex|difficulty|expires_at
 |score|flags|pass_s|pass_f|pass_c|challenged_at|auto
 |forgive_window_start|forgive_consumed
```

Pipe-delimited ASCII. The `forgive_*` fields were added in protocol
version 2 (E15); v1 cookies fail the version check and trigger a
fresh challenge. `auto` is the noninteractive-tier (M7) marker — 1 means the
challenge was served as the no-click splash, 0 means form-PoW. Knowing
which tier was actually served is what lets the verify path pick
`passes_non_interactive` vs `passes_interactive` and the matching forgiveness amount.

### Cookie payload over the wire

```
base64url( canonical || "|" || sighex || "|" || counter )
```

The single base64 blob is parsed by splitting on `|`; no JSON parser
required. The `'.'` separator inside the GCM cookie is outside the
base64 alphabet so the (envelope, counter) split point is
unambiguous.

### Verify path

`bs_verify_cookie_gcm` finds the `'.'`, base64-decodes the prefix,
checks the alg-id byte, AES-GCM-decrypts using the HKDF-derived
`derived_gcm_cookie` key. On primary-key tag failure it retries with
`derived_gcm_cookie_2` if E16 secondary rotation is configured. AES-
GCM's authenticated decryption guarantees a wrong key fails cleanly
without leaking plaintext, so the retry is safe.

After decrypt: parse canonical fields (version check, alg-name lookup
in `bs_algorithms[]`, hex decode salt + nonce + signature, bounded
parse of the integer fields via `bs_parse_int_bounded`), check
`expires_at`, dispatch to the algorithm's verify function with the
counter string. Pre-auth errors (no key, oversize, missing `'.'`)
leave `*out_ch` untouched; post-auth rejections (expired, bad counter)
populate `*out_ch` so the carry-forward code can use the rep.

### Cookie-name selection

`bs_build_set_cookie` emits `__Host-bs_session` when:
- the request is HTTPS (`r->server->server_hostname` plus
  `is_https`), AND
- no `BotShieldCookieDomain` is configured (the `__Host-` prefix
  forbids `Domain=`).

Otherwise it emits the unprefixed `_bs_session`. Verify reads either
name and prefers `__Host-bs_session` (modern HTTPS deployments)
falling back to `_bs_session` (cross-subdomain SSO via Domain=). The
cookie attributes set on every issue: `Path=/`, `SameSite=Lax`,
`HttpOnly`, `Secure` on HTTPS, `Domain=` only when the
operator-configured cookie_domain is in use.

No `Expires=` / `Max-Age=` is emitted — the cookie is session-scoped
at the browser layer, so closing the browser drops it.
`bs_build_set_cookie` takes `expires_at` and deliberately discards it
(`(void)expires_at`); the challenge envelope's `expires_at` field is
the authoritative hard cap and is enforced server-side on verify. A
client that hoards the cookie past its TTL gains nothing.

## Cryptography

OpenSSL is the only crypto provider; libcrypto is linked via apxs.
All primitives live in `crypto.{c,h}`.

### Primitives

- `bs_sha256` — SHA-256 of arbitrary bytes; client-side PoW reuses
  the same algorithm.
- `bs_hmac_sha256` — HMAC-SHA-256 used for the bootstrap-binding
  HMAC (E17 IP binding), the M8.1 pending cookie, and both halves of
  the E5 / E8.2 app-integration channel.
- `bs_ct_equal` — constant-time equality for any signature / tag
  comparison.
- `bs_gcm_encrypt` / `bs_gcm_decrypt` — AES-256-GCM with the alg-id
  byte as AAD; envelope format documented above.
- `bs_to_hex` / `bs_from_hex` — defensive hex codec; the decoder
  takes an explicit `in_len` parameter to prevent OOB reads on
  malformed input.

### Per-purpose key derivation

`BotShieldSecretFile` loads a master key (16+ bytes, mode-0600).
`bs_hkdf_derive_key` (RFC 5869 HKDF-Expand) derives three independent
purpose-specific keys at config-load time:

```
derived_gcm_cookie     = HKDF(master, info="bs:gcm-cookie:v1")
derived_hmac_pending   = HKDF(master, info="bs:hmac-pending:v1")
derived_hmac_bootstrap = HKDF(master, info="bs:hmac-bootstrap:v1")
```

Leaking any one of these gives an attacker no information about the
others (one-way per purpose-tag). The request path uses the derived
keys directly with zero per-request HKDF cost.

When `BotShieldSecondarySecretFile` is configured (E16), the same
derivation runs against the secondary master and lands in
`derived_*_2` slots. Issue always uses primary; verify tries primary
first then secondary on tag failure.

### Operator key rotation (E16)

```
1. Operator generates a new key file. Moves OLD key to a secondary
   path. Sets BotShieldSecretFile to the new key,
   BotShieldSecondarySecretFile to the OLD key. Reloads Apache.
2. Verify accepts cookies signed under either key. Issue mints under
   the new key only.
3. After one BotShieldCookieTTL window, every active cookie has
   cycled to the new key.
4. Operator removes BotShieldSecondarySecretFile and reloads.
```

The cookie envelope deliberately does *not* carry a `kid` field —
trial-and-error verify costs one extra GCM-decrypt attempt per
cookie that fails the primary, which is cheap.

## Score system

The per-request score is allocated lazily on `r->request_config` via
`bs_get_score(r, create=1)`. Every penalty / credit source in the
module funnels through one primitive:

```c
void bs_score_add(request_rec *r, int penalty, int ttl_seconds,
                  const char *reason);
```

`penalty=0` records a reason without affecting the total — used for
observe-mode entries, status=nochallenge entries, and informational reasons
like `flaggedip`. The `ttl_seconds` field is accepted for API
stability but currently ignored by downstream consumers; the
flagged-IP table carries its own TTL set at insert time.

The `bs_request_score` struct holds the total plus an array of
`bs_score_entry { penalty, ttl_seconds, reason }`. The reason cap is
`BS_SCORE_MAX_REASONS = 16` — once the array fills, further drops
DEBUG-log a one-shot `cap_warned` notice and the total still
accumulates correctly.

Two reason renderers serve the decision log:
- `bs_decision_reason_names` — comma-joined names, returns `"-"`
  when no entries fired (the M9.1 `reason="…"` field).
- `bs_score_reasons_joined` — bracketed `[name:penalty,...]`, used
  in the verbose audit-log line that runs alongside the structured
  decision log.

`bs_decide_tier` is the score → tier picker, parameterized by the
three thresholds on `bs_dir_cfg`. **An unset threshold never fires**,
so score decides nothing until the operator sets one;
`BS_DEFAULT_SCORE_*` survive only as the suggested values the policy
dump prints beside an unset tier. Tier names returned by
`bs_tier_name`: `"pass"`, `"noninteractive"`, `"interactive"`, `"captcha"`, or `"?"`
for an unknown enum.

Heuristic penalties. These are the weights a **declared**
`BotShieldHeuristicTrigger` uses; none is applied unless the operator
declares it, since no rules are seeded:

| Reason | Penalty | When |
|--------|---------|------|
| `missinguseragent` | `BS_PENALTY_MISSING_UA` (40) | `r->headers_in["User-Agent"]` is absent or empty |
| `missingacceptlanguage` | `BS_PENALTY_MISSING_AL` (5) | No Accept-Language header |
| `scraperua` | `BS_PENALTY_SCRAPER_UA` (10) | UA contains a token from the curated scraper-token list (curl, wget, python-requests, …) |
| `firstsightip` | `BS_PENALTY_FIRST_SIGHT_IP` (20) | Bloom filter has not seen this IP this window |
| `droppedcookie` | `BS_PENALTY_DROPPED_COOKIE` (25) | Client discarded a cookie it was issued |
| `allow-bot:<name>` | `BS_CREDIT_ALLOW` (-1000) | E1 verified-crawler hit; large negative credit dominates other signals |
| `allow-bot-ua:<name>` | -1000 | E1 UA-only-trust match (`BotShieldAllowBot ... *`) |
| `fake-<name>` | +100 | E1 UA matched but client IP not in published ranges |

## Reputation state and forgiveness

`bs_rep_state` is the cookie-carried reputation block:

```c
typedef struct {
    int          score;
    apr_uint32_t flags;
    int          passes_non_interactive;
    int          passes_form;
    int          passes_captcha;
    apr_time_t   challenged_at;
    apr_uint32_t forgive_window_start;
    apr_uint32_t forgive_consumed;
} bs_rep_state;
```

`flags` is a bitmap of the registered flag-bits the client has
accumulated (see Flag registry below). `passes_non_interactive` / `_form` /
`_captcha` are operator-visible counters bumped on each successful
challenge of that tier.

### Carry-forward gate

`bs_should_carry_prior_rep(cverr, prior_ch)` returns 1 only when:
- `cverr != "signature mismatch"` (rep bytes can be trusted), AND
- `cverr != "expired"` (TTL is the only mechanism
  preventing indefinite reputation transfer across cookie
  generations), AND
- if `cverr` is some other pre-auth error, `*prior_ch` was actually
  populated.

The same predicate is consulted on both the render-side (in
`bs_handler` when building `next_rep` for the to-be-issued challenge)
and the issuance-side (`bs_carry_forward_eligible` in cookie.c when
minting a fresh cookie at /embedded-verify, /captcha-verify, or the
form-captcha replay path). Sharing the predicate prevents drift —
otherwise an expired cookie's rep could be transplanted via the
interstitial-render path (the `next_rep` is baked into the challenge
envelope and round-tripped through the JS, arriving at /embedded-
verify before issuance-side carry-forward sees it).

### Forgiveness math

On a successful challenge pass, `bs_apply_rep_carry` adjusts the
prior score by the per-tier forgiveness amount:

| Tier passed | `BotShieldForgiveness*` default |
|-------------|--------------------------------|
| Non-interactive PoW |  10 |
| Form PoW    |  25 |
| Captcha     |  50 |

Score is clamped at zero (never negative). Flag bits do not clear via
forgiveness; they decay only via flagged-IP TTL.

### Hourly forgiveness cap (E15)

`bs_forgiveness_apply_cap` clamps the requested forgiveness against
`BotShieldForgivenessCapPerHour` (default 200, 0 disables). The
window is rolling: `forgive_window_start` rolls when more than
`BS_FORGIVE_WINDOW_SEC` (3600) have elapsed since the prior window
started. When the cap kicks in, the request's reason chain carries
`forgive-capped:<granted>/<requested>` for operator visibility.

Tracking lives **per-cookie** (not per-IP-SHM): bot drops cookie →
counter resets but ALSO drops the score-debt forgiveness was meant
to whittle down, so cookie-rotation is no escape.

###  "ever-passed" clamp

Each `passes_*` counter is clamped to a minimum of 1 once any tier
of that kind has been passed, so the value can be used as a boolean
"this client has ever cleared this challenge level" by downstream
trust signals.

## SHM segment

A single APR shared-memory segment (`apr_shm_create` against pconf,
default `BS_DEFAULT_SHM_SIZE = 16 MiB`) holds five tables and a
small fixed header. One `apr_shm_create` + one `apr_global_mutex_create`
carry the whole thing — and cross-table state-save/load is therefore
one transaction.

### Header layout

`bs_shm_header` is three 64-byte cachelines, segregated by access
pattern:

- **Cacheline 0 (write-once configuration)**: magic
  (`BS_SHM_MAGIC = 'BSHD'`), format_version (`BS_SHM_FORMAT_VERSION = 2`),
  flagged_capacity, bloom_buf_bytes, bloom_window_secs, cv_rate_slots,
  cv_log_slots, `siphash_key[16]` (RAND_bytes at post_config).
- **Cacheline 1 (hot-read, rare-write)**: `bloom_active` (which of
  the two bloom buffers is currently the writer), load-state cell
  (`load_state`, `load_state_since_sec`, `load_escalation_streak`,
  `load_recovery_streak`, `load_state_changes`).
- **Cacheline 2 (write-frequently)**: `cv_inflight` (M8.1 in-flight
  siteverify count), `bloom_next_rotate`, three log-throttle
  timestamps for probe-saturation warnings.

The deliberate cacheline segregation prevents false sharing between
fields with very different read/write rates.

### Five tables

All four reputation tables (flagged-IP, strike, safeguard, nonce)
share the same open-addressing + per-slot seqlock pattern: bucket
selection via SipHash-2-4 keyed on the segment's `siphash_key`,
linear probe with a per-table probe limit, atomic version bump for
write coordination. The tables use a unified empty-marker convention
since `BS_SHM_FORMAT_VERSION = 2`: each slot carries an explicit
`apr_uint32_t used` field where 0 means empty (apr_shm_create zeroes
the segment, so a fresh table starts correctly with no init pass).
All four are namespaced by `ns_id` (E13 — see Reputation namespacing
below).

#### Flagged-IP table (M5.1)

```c
typedef struct {
    apr_uint32_t  version;       /* seqlock counter */
    apr_uint32_t  used;          /* 0 = empty slot */
    unsigned char ip[16];
    apr_uint32_t  flags;         /* OR'd flag bitmap */
    apr_uint32_t  ns_id;
    apr_int64_t   expires_at;
} bs_flagged_ip_slot;
```

Default 50 000 slots; fixed-size, configurable via
`BotShieldFlaggedIPCapacity` (range 1024..1 000 000). Probe limit
`BS_FLAGGED_PROBE_LIMIT = 10`. Within the probe window:
exact-IP+ns_id match (merge flags, refresh TTL), else first empty
slot, else first stale slot, else overwrite the first slot in the
probe and log a rate-limited warning.

Reads use the seqlock: `version` odd = mid-write, even = quiescent.
Reader retries up to `BS_FLAGGED_MAX_READ_SPINS = 3` times when it
catches an odd version or mismatched begin/end versions, then skips
the slot.

Writers take the global mutex briefly to bump `version` odd → write
payload → bump even.

#### Strike table (E9)

```c
typedef struct {
    apr_uint32_t  version, used;
    unsigned char ip[16];
    apr_uint32_t  rule_slot;
    apr_uint32_t  ns_id;
    apr_uint32_t  strike_window_start;
    apr_uint32_t  strike_count;
    apr_int64_t   escalation_until;    /* 0 = not escalated */
} bs_strike_slot;
```

Default 50 000 slots, `BotShieldRateLimitEscalateCapacity` adjustable.
Per-(client_ip, rate_rule_slot) strike accounting. Strike counter
windowed on `strike_window_start`; idle entries roll over.
`escalation_until == 0` → not yet crossed threshold; non-zero → in
escalated state until the timestamp. Each fresh strike during
escalation slides the timestamp forward.

#### Safeguard table (E10)

```c
typedef struct {
    apr_uint32_t  version, used;
    unsigned char ip[16];
    apr_uint32_t  present_window_start;
    apr_uint32_t  present_count;
    apr_int64_t   safeguard_until;
    apr_uint32_t  ns_id;
    apr_uint32_t  _pad;
} bs_safeguard_slot;
```

Default 50 000 slots, `BotShieldSafeguardCapacity` adjustable.
`present_count` accumulates inside the window; resets on
`bs_safeguard_clear` (a valid `_bs_session` arrived) or on window
roll. `safeguard_until == 0` → inactive; non-zero → request-time
check returns "safeguard active" until timestamp passes. TTL slides
on each fresh presentation.

`bs_safeguard_present_count` is also read by the E17 embedded → M7
fallback to decide when the wrapper isn't doing its job (CSP-blocked,
no JS, etc.) — same SHM table, no fourth structure.

#### Nonce table

```c
typedef struct {
    apr_uint32_t  version, used;
    apr_uint64_t  nonce_hash;     /* siphash24(siphash_key, nonce||ns_id) */
    apr_int64_t   expires_at;
    apr_uint32_t  ns_id;
    apr_uint32_t  _pad;
} bs_nonce_slot;
```

Default 32 768 slots (`BotShieldEmbeddedNonceCapacity` range
1024..1 048 576). Records every successfully-redeemed embedded-
bootstrap challenge nonce with its expiry so `/embedded-verify` can
reject replays. `bs_embedded_nonce_consume` is atomic
claim-or-reject; eviction on expiry. The 64-bit SipHash key bucket
defeats precomputed-collision attacks against eviction.

#### Bloom filter (M5.2)

Two equal-sized byte buffers in SHM, sized as
`m ≈ BS_BLOOM_BITS_PER_IP * BotShieldBloomIPs / 8` bytes each. K =
`BS_BLOOM_K = 7` hash positions per insert / query. The 7 hashes are
computed via two SipHash outputs combined via Kirsch-Mitzenmacher
double hashing — per-insert hash cost is two SipHash-2-4s, not seven.

Operation:
- **Active** buffer accepts writes (atomic `__atomic_or_fetch` on
  uint64 slots — no lock, no CAS).
- **Warming** buffer is read-only.
- **Query** ORs across both buffers — an IP counts as seen if either
  has it.
- **Rotate** every `BotShieldBloomWindow / 2`: warming buffer is
  zeroed and becomes active, prior active becomes warming.
  `header->bloom_active` index is atomic; rotation timestamp lives
  in `header->bloom_next_rotate`. Rotation is opportunistic on
  insert (`bs_bloom_rotate_if_due` runs cheap if not due) — single
  writer coordinates via the global mutex.

Per-IP lifetime: between `window/2` (inserted right before a
rotation) and `window` (right after).

Feed policy: only when the handler has already committed to
challenging this client — keeps the ~99% happy-path traffic off the
write set. Read policy: only on cookieless / sig-mismatched requests.

### Captcha-verify rate + log slots (M8.1)

Two parallel ring tables, each `BS_DEFAULT_CV_RATE_SLOTS = 4096` /
`BS_DEFAULT_CV_LOG_SLOTS = 2048` slots. One uint64 per slot,
encoding `(unix_minute << 20) | count`:

```
bits 63..20  unix-minute window start
bits 19..0   count within that window (0..1M)
```

Rolling to a new minute is a CAS of the whole slot. The rate ring
gates verify endpoint POSTs per IP per minute (default 30/min via
`BotShieldCaptchaRateLimit`); the log ring throttles
REJECTED/ERROR log lines to one per IP per minute with a
`×N since last` suffix.

`cv_inflight` is a separate atomic counter on the `bs_shm_header`,
incremented before `curl_easy_perform` and decremented on every
return path. `BotShieldCaptchaMaxInFlight` (default 64) caps it; over
cap returns 503 with a WARNING and never invokes libcurl.

### Rate-counter pool (E2.1)

Fixed-window counter slots opaque from the SHM layer's perspective
(`void *rate_counters`):

```c
typedef struct {
    apr_uint32_t count;
    apr_uint32_t window_start_sec;
} bs_rate_counter;
```

`BS_E21_RATE_SLOTS = 256` slots from a flat pool, allocated in
post_config. `BS_E22_ROBOTS_SLOT_POOL = 16` slots are reserved for
robots.txt-derived Crawl-delay groups. Atomic CAS on each field
separately (32-bit atomics on each); approximate fixed-window rather
than exact sliding window — correct for rate-limiting semantics
operators expect.

### Persistence (M6)

`BotShieldStateFile` (default unset = persistence off) names a binary
file:

```
header:
  magic:        'BSHD' (BS_STATE_MAGIC = 0x44485342)
  version:      uint32 = BS_STATE_FORMAT_VERSION (3)
  saved_at:     uint64 unix millis (little-endian)
  record_count: uint32
records (repeated):
  entry_type:   uint8   (1 = bloom buffer, 2 = flagged IP,
                         3 = reserved for verified-bot cache)
  entry_size:   uint16
  entry_data:   bytes
trailer:
  crc32:        uint32 of all preceding bytes
```

Lifecycle:
- `bs_post_config` reads the file into SHM, discarding records whose
  `expires_at` has passed.
- A pool cleanup on the parent's conf pool writes SHM back to disk
  on clean shutdown (including graceful reload / restart).
- `bs_state_save_watchdog_cb` registered against mod_watchdog runs
  every `BotShieldStateSaveInterval` seconds (default 300) and
  calls `bs_state_save`. If mod_watchdog isn't loaded, periodic
  saves silently degrade to "shutdown-only" with a NOTICE.
- Atomic durability: write `<path>.tmp`, `apr_file_sync`,
  `apr_file_rename`, then fsync the parent directory.
- The flagged-IP table is copied under the global mutex (so a
  racing writer can't be captured mid-update). Bloom buffers are
  byte arrays mutated by single-byte atomic OR; per-byte reads are
  torn-free, so they're memcpy-ed without the lock.

Format / magic / checksum / dimension-mismatch all degrade to "start
fresh" rather than failing Apache startup. SHM counters are not
persisted and reset across `apachectl graceful` (a standard
Prometheus convention, detected by clients via monotonic-decrease
checks). Bloom + flagged-IP state survives the graceful round-trip
via the save/load dance running in the right pool-cleanup order.

The `bs_state_cleanup_ctx` snapshot pattern wraps a generation's
`bs_shm` at cleanup-registration time so a graceful restart's
cleanup save targets *its own* snapshot rather than whatever the new
generation's `post_config` has now made `bs_shm` point at.

### Capacity-headroom watchdog (E13.1)

`bs_headroom_watchdog_cb` walks the four SHM tables + Bloom buffers
once per tick and emits NOTICE / WARNING when usage crosses
configured thresholds:

- `BS_HEADROOM_NOTICE_PCT = 50` → NOTICE
- `BS_HEADROOM_WARN_PCT = 70` → WARNING
- `BS_HEADROOM_REWARN_SEC = 300` → minimum re-warn interval per
  table

Operators get visibility into "the table is filling up before it
saturates," with rate-limited noise.

## Allowlist (E1)

Verified-bot policy: not just UA-string matching, but identity
verification by CIDR. The classifier and CIDR loader live in
`allowlist.{c,h}`; the request-time orchestrator `bs_check_allow` is
called from `bs_run_builtin_heuristics`.

### UA classifier

`bs_ua_classifier` is an opaque substring trie. Operations:
- `bs_ua_classifier_create(p)` allocates an empty classifier.
- `bs_ua_classifier_add(c, name, pattern)` registers a UA substring;
  duplicates use last-writer-wins.
- `bs_ua_classify(c, ua)` walks the trie at every position in `ua`
  and returns the longest terminal match. A specific
  `CorpBot/Admin` pattern shadows a generic `CorpBot` because of
  longest-match-wins.

### CIDR loader

- `bs_allow_load_ranges(p, path, &out, &err)` parses a CIDR file
  into `apr_array_header_t` of `apr_ipsubnet_t *`. One CIDR per
  line, `#` comments, blank lines OK, IPv4 + IPv6.
  `BS_CRAWLER_MAX_RANGES_FILE = 1 MiB` hard cap.
- `bs_allow_load_ranges_from_string(p, csv, ...)` is the inline-
  CIDR variant used by `BotShieldAllowBot ... "<cidr>,<cidr>"`.
- `bs_allow_ip_in_ranges(ranges, r)` validates `r->useragent_ip`
  with `inet_pton` first (defends against blocking DNS via
  apr_sockaddr_info_get), then walks the array.

### Request-time orchestration

`bs_check_allow`:
1. UA classifier on `r->headers_in["User-Agent"]`.
2. No match → return (no penalty, no credit).
3. Match `<name>` + UA-only mode (`BotShieldAllowBot ... *`) →
   `bs_score_add(-1000, "allow-bot-ua:<name>")` and bump
   `bot_allow_total` counter.
4. Match `<name>` + IP in ranges → `bs_score_add(-1000,
   "allow-bot:<name>")` and bump `bot_allow_total`.
5. Match `<name>` + IP miss → `bs_score_add(+100,
   "fake-<name>")` and bump `bot_fake_total`.
6. Match `<name>` + ranges not loaded → `bs_score_add(0,
   "bot-unverified:<name>")` (benign) and bump
   `bot_unverified_total`.

### Built-in seed list

`bs_builtin_bots[]` registers five crawlers — Googlebot, bingbot,
Applebot, GoogleOther and Siteimprove — and it is **not gated by a
directive**: the allowlist is always loaded, so an operator can flip
`BotShieldClassify`'s verified-bots flag at any time without a reload
that rebuilds it. That flag controls whether the IP cross-check runs at
request time, not whether the list exists. Each bot has a default
ranges file
`/var/lib/botshield/bots/<name>.txt`. Operators refresh the files
out-of-module via `services/refresh/botshield-refresh.py` (cron); the module
reads them once at startup and serves stale ranges if a refresh
fails.

PTR + forward-confirm verification (Yandex, DuckDuck, Facebook,
LinkedIn, Twitter) is deferred — the providers that only publish via
PTR are lower-value UA-spoofing targets than the CIDR-publishing
ones, and an async resolver + cache + revalidation state machine is
not worth the engineering cost for marginal coverage.

## Policy enforcement

`bs_check_policy` (in `policy.c`) is the request-time policy walker.
It runs every operator-configured family in a fixed order. Each
family's matcher / action lives in its own feature file
(`triggers.c`, `robots.c`, …); `bs_check_policy` is the orchestrator.

### Walk order

1. **E4 cookie triggers** — declaration order; `pass` triggers
   accumulate credit/penalty (layered reputation), first non-pass
   trigger short-circuits.
2. **E6 env-var triggers** — declaration order, first match wins;
   main requests only.
3. **E11.2 load triggers** — `state==target` or `state>=target`,
   first match wins.
4. **E3 path triggers** — declaration order, first match wins.
   Optional `ua=` / `ipspec=` keys on the directive populate a
   bs_cohort that ANDs with the path-glob (this is the surface
   that absorbed the retired BotShieldBlockPath).
5. **E2.2 robots.txt Disallow** — wildcard-gated, longest-match-
   wins between Allow/Disallow within the matching group.
6. **E2.1 BotShieldRateLimit** — fixed-window counter; over-budget
   → 429 + Retry-After. With E9 strike escalation: repeat 429s on
   the same rule promote into a configurable status (default 403).
7. **E2.2 robots.txt Crawl-delay** — wildcard-gated; per-group rate
   limit. Skipped if a directive rate-limit cohort already matched
   ("operator overrides robots.txt").

Returns from `bs_check_policy`:
- `OK` — no rule fired; caller continues to heuristics.
- `DECLINED` — a `status=nochallenge` trigger fired; caller short-circuits
  to DECLINED so the real handler runs.
- Any other HTTP_* code — short-circuit with that status.

### Cohorts (E2.1 + shared)

```c
typedef struct {
    const char         *ua_pattern;
    int                 ua_any;
    int                 ip_any;
    const char         *path;        /* explicit ranges-file path */
    const char         *inline_cidrs;
    apr_array_header_t *ranges;      /* resolved at post_config */
} bs_cohort;
```

Cohort match is UA-match AND IP-match. UA match is case-insensitive
substring (`strcasestr`); IP match is `apr_ipsubnet_test`. `*` means
"any" on either axis; both-`*` is rejected at config time so a typo
can't accidentally throttle every request. The polymorphic ipspec
mirrors E1 — omitted = default path, `/...` = explicit path, `*` =
"any", contains `/` or `:` = inline CIDRs.

Precedence for overlapping rules: declaration order, first match
wins. Re-declaring a rule by name replaces the entry in place,
preserving surrounding order. Across main/vhost scopes, vhost entries
lead in the merged array; main-scope entries act as fallbacks.

### Rate-limit (E2.1)

```c
typedef struct {
    const char   *name;
    bs_cohort     cohort;
    apr_uint32_t  budget;
    apr_uint32_t  window_sec;
    int           shm_slot;
    const bs_rate_escalate_entry *escalate;
    int           mode;
} bs_rate_limit_entry;
```

Directive: `BotShieldRateLimit <name> <budget> <per> <ua> <ipspec>`,
`<per>` is `sec`/`min`/`hour` (or `s`/`m`/`h`).

Storage: each entry's `shm_slot` indexes into `bs_shm.rate_counters[]`,
allocated in post_config. Atomic CAS on each `count` /
`window_start_sec` field separately. Over-budget → 429 + `Retry-After`
+ `bs_score_add(+50, "ratelimitexceeded:<name>")`.

### Block-path (E2.1)

Path-conditional 403s are expressed via the E3 path-trigger family
with `status=403` + optional `ua=` / `ipspec=` match keys (the
former E2.1 BotShieldBlockPath was retired in favor of this).
Path-glob uses the same `bs_path_match` matcher as robots.txt
(prefix + `*` anywhere + trailing `$` end-anchor).

### Strike escalation (E9)

```c
typedef struct bs_rate_escalate_entry {
    const char   *rule_name;
    apr_uint32_t  strikes;
    apr_uint32_t  per_sec;
    int           status_code;
    int           ttl_sec;
    const char   *log_tag;
} bs_rate_escalate_entry;
```

Directive: `BotShieldRateLimitEscalate <rate-name> <strikes> <per>
[status=<code>] [ttl=<sec>] [log=<tag>]`. Per-(client_ip, rate_rule_slot)
strike accounting in the SHM strike table (see SHM segment); each 429
on the named rule increments. Over the strike threshold within the
window, subsequent requests against the same rule return the
escalated status (default 403) for `ttl_sec` (default 1800). The TTL
slides on each fresh strike. `log=<tag>` rides the decision line on
threshold crossing for fail2ban handoff, with reason
`ratelimitabuse:<name>`.

E9 escalation only applies to BotShield-generated 429s on a named
`BotShieldRateLimit` rule. robots.txt Crawl-delay 429s are not
strike-eligible in v1 (no operator handle for them).

### Robots.txt enforcement (E2.2)

The parser (`robots.{c,h}`) is APR-only — no Apache httpd.h
dependency — so it's also drivable from a standalone fuzz harness.
`robots_parse_file` / `robots_parse_buf` build an opaque `robots_doc`;
`robots_query` does a one-shot UA + path lookup, filling a
`robots_match` struct.

Semantics follow RFC 9309 plus the Crawl-delay de facto extension:

- **UA matching** is per-segment prefix, case-insensitive: the UA
  header is split on `;`; within each segment we strip leading
  whitespace and `(`, then the robots.txt token must be a prefix of
  what remains. Captures `Mozilla/5.0 (compatible; GPTBot/1.0; ...)`
  → matches `User-agent: GPTBot` cleanly without the over-matching
  of a whole-UA `strcasestr`.
- **Duplicate-UA groups are accumulative** (RFC 9309 §2.2.1): when
  the same User-agent token appears in multiple stanzas,
  `robots_query` walks every qualifying group and applies
  longest-match-wins across the union for Allow / Disallow.
  Crawl-delay is the max across duplicates (most restrictive). The
  first qualifying group's name is reported as the reason.
- **Path matching**: prefix + `*` wildcard anywhere + `$`
  end-anchor + longest-match-wins between Allow/Disallow (Allow wins
  ties).
- **Defensive caps**: `BOTSHIELD_ROBOTS_MAX_BYTES = 1 MiB`. Lines
  over 2048 bytes truncated with a count surfaced via
  `robots_doc_truncated_lines`.

Reason strings:
- `robotsblock:<group>` — 403, `+100` score.
- `robots-rate:<group>` — 429 + Retry-After, `+50` score.

`<group>` is the normalized first-UA of the matching group
(lowercase, `[a-z0-9-]`).

### Wildcard `User-agent: *` semantics

`BotShieldRobotsWildcardScope` controls how `*` rules are applied:

- `heuristic` (default): apply only to UAs that look like crawlers.
  The crawler-candidate test:
  1. **Real-browser-prefix denylist** — UA starts with `Mozilla/`,
     `Opera/`, `Firefox/`, `Edge/`, `Safari/` AND does not contain
     `bot`/`crawl`/`spider`/`fetch`/`slurp` → not a crawler
     candidate.
  2. **Bot-token allowlist** — UA contains
     `bot`/`crawl`/`spider`/`fetch`/`slurp` → crawler candidate.
  3. **E1-classifier match** — UA already matched a specific cohort
     → that cohort's specific rule applies; `*` rules are the
     fallback only when no specific match.
  Anything else → do not apply `*` rules. Conservative on the "hit
  a real user" axis.
- `strict` — apply `*` rules to every UA (operator's call;
  dangerous).
- `off` — ignore `*` groups entirely.

### Live refresh (E2.2.2)

```c
typedef struct bs_robots_state {
    robots_doc *doc;
    apr_pool_t *pool;
    apr_time_t  mtime;
    int        *slot_by_group_idx;
} bs_robots_state;
```

`scfg->robots` points at the active bundle; readers use
`__atomic_load_n` and writers `__atomic_store_n` to swap the pointer.
`scfg->robots_pending` holds the previously-active bundle for one
refresh cycle before its pool is destroyed — by then any in-flight
request reading the displaced doc has long finished.

`bs_robots_load` is the single entry point for both initial
post_config load and the watchdog refresh. It `stat()`s first; mtime
unchanged ⇒ O(1) no-op; only re-parses on change.

`bs_robots_watchdog_cb` is registered per vhost via mod_watchdog's
OPTIONAL_FN; per-vhost instance name prevents cross-vhost
interference. Soft dependency: if mod_watchdog isn't loaded, refresh
degrades to post_config-only with a NOTICE.
`BotShieldRobotsRefreshInterval` (default 60, 0 disables, max 86400)
controls cadence.

The SHM rate-counter slot pool reserved for robots groups
(`BS_E22_ROBOTS_SLOT_POOL = 16`) is keyed by group name in
`scfg->robots_slot_by_name` (lives in pconf). Editing robots.txt
preserves rate-counter state for groups whose name didn't change —
operators don't lose the in-flight Crawl-delay window when they edit
the file.

### The policy dump (E2.2.3)

`httpd -t -D DUMP_BOTSHIELD_POLICY` prints every active rule with its
source, for each vhost that enables the module: directive
`rate_limits` (name, budget, window, cohort), the effective tier
thresholds, the flag triggers after `reset` resolution, and
robots.txt-derived groups (source path, mtime, wildcard-scope mode,
refresh interval, slot-pool usage, per-group UA tokens, each
Allow/Disallow rule, Crawl-delay + slot).

`bs_policy_dump` runs from the `test_config` hook, the same hook core
uses for `DUMP_VHOSTS` and `DUMP_MODULES`, so the flag composes with
those. Two consequences follow from being a configtest rather than a
request:

- **It reads the config on disk, not the running config.** That is the
  point: it answers "what will this config do?" before a reload, which
  is when an operator can still change their mind.
- **No live counters.** A configtest process never attaches the
  rate-counter SHM, so consumption is not reportable here; the
  dashboard and the metrics endpoint cover that. robots.txt is parsed
  by the dump itself (the parse is pure), so parse errors do surface,
  but Crawl-delay groups all report `slot=-1` because slot assignment
  happens at startup.

This was an HTTP endpoint (`<prefix>/policy-status`). It should not
have been. The dashboard and metrics are runtime state, which is why
`mod_status` is a URL; this is resolved *configuration*, static
between reloads, and Apache already had an idiom for that. Config
introspection behind shell access cannot be forgotten into being
world-readable, and of the three surfaces this was the worst to
expose: counters tell an attacker how much noise they are making, a
policy dump tells them which rules exist and what to avoid.

### Triggers

Five trigger families share one config-time action engine and one
request-time executor (`triggers.{c,h}`). The families differ in
predicate shape but funnel through the same `bs_trigger_action` and
the same `bs_apply_trigger_action`.

#### Action engine

```c
typedef struct {
    int           status_code;    /* HTTP code or BS_TRIGGER_STATUS_PASS = -1 */
    const char   *redirect_url;
    const char   *log_tag;
    apr_uint32_t  flag_bit;       /* single BS_FLAG_* bit; 0 if ttl_sec==0 */
    int           ttl_sec;        /* 0 = don't flag */
    int           penalty;        /* 0..1000 */
    int           credit;         /* 0..1000 (rejected on path family) */
    int           status_explicit;
    int           mode;           /* BS_TMODE_ENFORCE / BS_TMODE_OBSERVE */
    int           suppress_access_log; /* accesslog=off; independent of log_tag */
} bs_trigger_action;
```

Action key parsers: `status=<code|pass>`, `redirect=<url>` (only for
families that support it), `log=<tag>`, `accesslog=on|off`, `flag=<bit>`,
`ttl=<sec>`, `penalty=<n>`, `credit=<n>`, `mode=enforce|observe`.

`log=<tag>` and `accesslog=on|off` are separate keys on purpose. An
earlier development build overloaded `log=off` for suppression, which
made the two mutually exclusive — and that cost the fail2ban tag on
exactly the traffic most worth tagging, since a scanner probe typically
wants both a tag and no access-log line. `log=off` is now rejected at
config time with a pointer to `accesslog=off`, rather than silently
degrading to a tag named "off" and dropping suppression a config relied
on.

`accesslog=off` suppresses the access-log line for a matching request.
`log_transaction` is a `RUN_ALL` hook declared `(OK, DECLINED)`, so
`bs_propagate_decision_env` — registered at `APR_HOOK_FIRST`, ahead of
mod_log_config — returns `DONE` when the `BS_NOLOG` env marker is set,
and the chain breaks before any logger runs. Consequences, all
deliberate: mod_log_config services every `CustomLog` from one hook
function, so this discards the module's own decision-log line along with
the access-log line (the `bs_decision_log` error-log line is
unaffected); any third-party `log_transaction` hook ordered after ours is
skipped too; and it is applied after the observe short-circuit, so
`mode=observe` / `BotShieldEnabled LogOnly` never suppress. Operators
wanting to trim one specific log while keeping others should use
mod_log_config's conditional form against `%{reqenv:BS_OUTCOME}` rather
than this key.

`bs_apply_trigger_action` records score, flags the IP if asked, sets
`r->notes` trigger-tag for the decision log, emits any redirect
Location, returns one of:

- `BS_TEXEC_OBSERVE` — observe-mode match; caller continues.
- `BS_TEXEC_PASS_DECLINE` — path-family pass; caller returns
  DECLINED.
- `BS_TEXEC_PASS_CONTINUE` — cookie-family pass; caller keeps
  accumulating.
- `BS_TEXEC_PASS_BREAK` — env/load-family pass; caller ends loop.
- `BS_TEXEC_STATUS` — concrete status; caller returns
  `a->status_code`.

The same E5 feedback path uses the executor with the
flag/ttl/optional-log subset.

#### Path triggers (E3)

`BotShieldRule <name> <path-glob> [key=value ...]`. Anyone
hitting the path triggers the action — unscoped (unlike E2.1
a path trigger with `ua=`/`ipspec=` keys, which is cohort-scoped).
Default `status=403`, default `flag=scanner_probe`, default
`ttl=3600`.

Under `status=nochallenge`: the request flows through to the real handler
with `DECLINED`; `penalty` is **ignored** (only flag-IP + log
side-effects survive). This is the one family where pass means
"don't score this request"; cookie/env/load triggers diverge.

#### Cookie triggers (E4)

`BotShieldCookieTrigger <name> <cookie-match> [key=value ...]`.

Predicate kinds (`enum bs_cookie_pred_kind`):

| Predicate | Meaning |
|-----------|---------|
| `cookie=<name>` | Cookie present (any value) |
| `cookie=<name>=<value>` | Cookie equals value exactly |
| `cookie=<name>~<substr>` | Cookie value contains substring |
| `cookie=<name>!<value>` | Cookie present but value is NOT given |
| `!cookie=<name>` | Cookie absent |
| `cookies=none` | Request carries no cookies at all |
| `cookies=any` | Request carries at least one cookie |
| `cookies=session` | Request carries a known-session cookie name |
| `bs-cookie=verified` | `_bs_session` valid (HMAC + freshness ok) |
| `bs-cookie=missing` | No `_bs_session` on the request |
| `bs-cookie=invalid` | Present but verification failed |

The session cookie list is curated: PHPSESSID, JSESSIONID,
ASP.NET_SessionId, session_id, connect.sid, laravel_session.
Operators extend via `BotShieldSessionCookieName <name>` (each
invocation appends).

`bs-cookie=<state>` reads the verdict already computed in
`bs_handler` and stashed at `r->notes[BS_CK_STATE_NOTE]` — does not
re-verify.

Cookie name validation for per-named predicates:
`[A-Za-z0-9_-]{1,64}`. Triggers against the raw `_bs_session`
cookie name are redirected at config-time to use `bs-cookie=<state>`
(which exposes the verdict, not the raw bytes).

Semantic divergence from path triggers:
- **`credit=` / `penalty=` always apply**, even under `status=nochallenge`,
  because the cookie signal exists on this request. (Path-family
  pass is "don't score"; cookie-family pass is "score this now,
  let the request through.")
- **Pass triggers accumulate within a family.** The walk continues
  scanning; each matching pass-trigger adds its credit/penalty.
  First non-pass match short-circuits.

The Cookie header is parsed once per request via
`bs_parse_cookies_once` — pool-allocated `apr_table_t` memoized on
`r->notes`. Every E4 trigger consults that map (O(1) hash lookup);
no re-scanning the raw header per trigger.

#### Env triggers (E6)

`BotShieldEnvTrigger <name> <env-match> [key=value ...]`. Reads
`r->subprocess_env`. Predicate kinds: `env=<var>` (present),
`env=<var>=<value>` (exact match, case-sensitive), `!env=<var>`
(absent).

Like E4, `credit/penalty` apply under `status=nochallenge` (env signals
exist on this request). No `redirect=` (env signals shape scoring,
not response). Main requests only — `ap_is_initial_req(r)`.

The env table is `r->subprocess_env`; the module never consults OS
env (CGI-boundary). Producers run before `bs_handler`: `SetEnvIf` /
`SetEnvIfNoCase` / `BrowserMatch` at header_parser; `SetEnvIfExpr` /
`RewriteRule [E=...]` at fixups; ModSecurity v2 phase-1 `setenv` at
header processing.

#### Load triggers (E11.2)

`BotShieldLoadTrigger <name> <load-match> [key=value ...]`. Predicate
kinds: `state=normal|warm|hot` or `state>=normal|warm|hot`. The
match consumes the cached load state via `bs_load_current()` (lockless
atomic read on `bs_shm.header->load_state`).

Action keys: `credit=`, `penalty=`, `status=<code|pass>`, `log=<tag>`.
**`flag=` / `ttl=` / `redirect=` are rejected** at config-time: load
is global state, not per-IP behavior.

#### Feedback triggers (E7.3)

`BotShieldFeedbackTrigger <event> [key=value ...]`. Required:
`flag=<bit>`, `ttl=<sec>`. Optional: `log=<tag>`. Maps an app-signed
event name (E5 wire format) to module memory. **No** status,
redirect, penalty, or credit — the response has already been served.

The shared executor enforces the subset: `bs_apply_trigger_action`
called with `BS_TFAMILY_FEEDBACK` only writes flag+ttl+log.

#### Flag triggers (E14)

```c
typedef struct {
    const char         *flag_name;
    apr_uint32_t        flag_bit;
    bs_flag_action_kind action;       /* SCORE / TIER_FLOOR / RESET */
    int                 score_add;
    bs_tier             tier_min;
    int                 mode;
    int                 from_default;
} bs_flag_trigger_entry;
```

Two runtime action verbs:

- `score add=N` — signed delta, range -1000..1000. SUMs across
  triggers. Applied via `bs_score_add` at request time.
- `tier_floor min=<tier>` — `pass`/`noninteractive`/`interactive`/`captcha`. MAXes
  across triggers. Score-derived tier wins when it's already at-or-
  above the floor — never silently downgrades.

`reset` is a config-time sentinel that clears prior operator
declarations for the named flag before this directive's effect is
added. It once also cleared compiled-in defaults, which was most of
what operators used it for; with none seeded, it now only matters when
a vhost is narrowing something an enclosing scope declared.

`bs_apply_flag_triggers` walks `scfg->flag_triggers` over the union
of IP-side and cookie-side flag bits. `mode=observe` entries log a
`wouldflagtrigger:<flag>:observe` reason and skip the side effect.

**Nothing is seeded.** `BS_SEED_DEFAULT_RULES` is 0, and it gates both
the flagtrigger and heuristic-trigger seed loops, so a vhost that
declares no triggers has none. The tables still exist in the source as
`bs_default_flag_triggers` / `bs_default_heuristic_triggers`, and
`tests/setup/botshield-dev.conf` carries the same slate as ordinary
directives for anyone who wants it.

The slate that used to be seeded:

| Flag | Former default action |
|------|----------------|
| `honeypot_hit`         | score add=+60, tier_floor min=captcha |
| `fake_bot`             | score add=+80, tier_floor min=captcha |
| `scanner_probe`        | score add=+50, tier_floor min=interactive |
| `pow_fail_streak`      | score add=+30, tier_floor min=noninteractive |
| `app_verified_human`   | score add=-80 |
| `app_verified_session` | score add=-40 |
| `app_trust_signal`     | score add=-20 |

It was removed because a default every deployment has to disable was
not a default. Production carried six lines whose only purpose was
switching off behaviour the module had invented — one
`HeuristicTrigger all reset`, three flag resets, and two thresholds
parked at 10000 against a highest observed score of 50. Every lockout
this module has caused came from an implicit weight or tier floor
nobody had written down summing past a threshold nobody had read.

The shape those rows took is still worth knowing if you write the
slate yourself. Each detection-signal flag needs two rows — one
`BS_FLAG_ACT_SCORE` and one `BS_FLAG_ACT_TIER_FLOOR` — so the score
addend lands even if `bs_decide_tier` would otherwise have stopped at
a lower tier. Trust signals are score-only by design; no credit ever
forces tier *down*, so a verified-human flag cannot unlock a request
that already tripped a different tier_floor.

A flag scoring at or above the noninteractive threshold is a challenge
switch rather than a contributing signal, and the policy dump flags
that inline with `~`.

`BotShieldTrigger flag=<name> [ttl=<sec>]` is the operator handle for
honeypot / scanner-bait `<Location>` blocks: the enclosing Apache
scope is the predicate, so any request reaching it adds the named bit
to the IP's flagged-IP entry (`bs_flagged_ip_add`, `src/triggers.c:470`)
with the configured TTL (default 3600). This replaced the standalone
`BotShieldFlagIP` directive — one action grammar for every trigger
family rather than a bespoke directive for the flag case.

## Tier renderers

### Pass tier

`tier == BS_TIER_PASS` after the flag-floor MAX → log decision
`tier=nochallenge outcome=declined`, set E8.2 X-Botshield-Claims when
enabled, return `DECLINED`. Real handler runs.

### Non-interactive tier — interstitial mode (M7)

`bs_render_challenge_page` with `tier=noninteractive` + `issue_auto=1` →
auto-submit splash (no user click). The page's CSS variant renders
the widget as a neutral "checking your browser…" splash. Inline JS
keys off the `auto: true` field in the embedded challenge JSON
(HMAC-covered like every other field) and starts the Worker on
`DOMContentLoaded`.

### Non-interactive tier — embedded mode (E17)

`cfg->non_interactive_mode == BS_NON_INTERACTIVE_MODE_EMBEDDED` → `bs_handler` returns
`DECLINED`. The real page renders. The operator-included
`<script src="/botshield/embedded.js" defer></script>` then:

1. Fetches `GET <prefix>/embedded-bootstrap` for a per-page PoW
   challenge (`bs_embedded_bootstrap_handler`).
2. Runs the PoW solver in a Web Worker
   (`<prefix>/embedded-worker.js`).
3. Submits via `POST <prefix>/embedded-verify`
   (`bs_embedded_verify_handler`).

#### Bootstrap response

JSON with PoW envelope (salt, nonce, difficulty, expires_at), a
fresh `bs_challenge` rep block carried forward from the prior
cookie if eligible, and the IP-binding HMAC pair:

- `bound_ip_hex` — `bs_format_bound_ip_hex(r->useragent_ip, ...)`.
  Encodes the IPv4-mapped-or-v6 address into a stable hex string.
- `bootstrap_sig` — `bs_compute_bootstrap_sig` HMAC over
  (nonce, bound_ip_hex, expires_at) using the
  `derived_hmac_bootstrap` purpose key.

#### Verify path

`bs_embedded_verify_handler` re-derives `bound_ip_hex` from the
client's current `r->useragent_ip` and recomputes the bootstrap HMAC.
If the IP doesn't match, the verify rejects (the
challenge is bound to the IP that requested it; an attacker can't
hand a solved challenge to an accomplice on a different IP).

The challenge nonce is then atomically claimed via
`bs_embedded_nonce_consume` against the SHM nonce table (
phase 2). Collision = "this nonce was already redeemed" → reject as
replay.

On accept, `bs_install_verified_cookie` mints `_bs_session` and the
client's next request rides through `DECLINED`.

### Form-PoW tier

`bs_render_challenge_page` with `tier=interactive` + `issue_auto=0` →
visible reCAPTCHA-shaped checkbox. The user clicks the checkbox; the
inline JS spins up a Worker that hashes
`SHA-256(salt || nonce || counter)` until it has `difficulty` leading
hex zeros, then auto-submits the embedded form. The form POSTs to
the same URL; the cookie is already set on the response, so the
follow-up GET rides through cookie-valid.

### Captcha tier (M8)

`bs_render_challenge_page` with `tier=captcha` + a configured
`cfg->captcha_provider` → render the provider's widget inline. With
no configured provider, the renderer falls through to form-PoW with
reason `captcha_fallback`.

#### Provider registry

```c
static const bs_captcha_provider bs_providers[] = {
    { "turnstile",    1, "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                         "cf-turnstile-response", ..., NULL /* shared shim */ },
    { "hcaptcha",     1, "https://api.hcaptcha.com/siteverify",
                         "h-captcha-response",    ..., NULL },
    { "recaptcha-v2", 1, "https://www.google.com/recaptcha/api/siteverify",
                         "g-recaptcha-response",  ..., NULL },
    { "recaptcha-v3", 1, "https://www.google.com/recaptcha/api/siteverify",
                         "g-recaptcha-response",  ..., NULL },
    { "friendly",     1, "https://api.friendlycaptcha.com/api/v1/siteverify",
                         "frc-captcha-solution",  ..., NULL /* "solution" body field */ },
    { "geetest",      1, "https://gcaptcha4.geetest.com/validate",
                         "geetest-token",         ..., bs_geetest_siteverify },
    { NULL }
};
```

Two response-contract families:

- **Google family** (Turnstile / hCaptcha / reCAPTCHA / Friendly):
  `{"success":bool, "error-codes":[...]}`. Shared libcurl + json-c
  path (`bs_captcha_siteverify` with NULL `siteverify_fn`).
- **GeeTest**: client token is a JSON blob (lot_number, pass_token,
  gen_time, captcha_output); server signs lot_number with
  `HMAC-SHA256(captcha_key, lot_number)` and POSTs five form fields.
  Provider-specific verify function (`bs_geetest_siteverify`).

#### Verify endpoint flow

1. Client POSTs to `/botshield/captcha-verify` (or
   `/botshield/captcha-verify/<provider>` for cohabitation) with a
   hidden `return_to` field (sanity-checked to same-origin
   relative path only).
2. Pre-libcurl prefilters:
   - Content-Type must start with
     `application/x-www-form-urlencoded`.
   - Body capped at `BS_MAX_CAPTCHA_TOKEN = 4096` for tokens,
     `BS_MAX_CAPTCHA_BODY = 8192` total response.
   - Pending cookie (M8.1) must be present and validate.
   - Per-IP rate cap (M8.1) must not be exceeded.
   - Global in-flight cap (M8.1) must not be exceeded.
3. libcurl shim with `BS_CAPTCHA_CONNECT_TIMEOUT = 250 ms`
   connect timeout + operator-tunable total
   (`BotShieldCaptchaTimeout` 100..5000, default 1000).
   `SSL_VERIFYPEER` + `SSL_VERIFYHOST` on. Optional
   `BotShieldCaptchaCABundle` for stripped container images that
   lack `/etc/ssl/certs`.
4. Fail-open on timeout / network error / 4xx-5xx / unrecognized
   response shape — logs at `APLOG_WARNING` with literal string
   "failing open" so it greps cleanly.
5. **Binding-metadata validation**:
   - `BotShieldCaptchaExpectedHostname` (default vhost
     `server_hostname`; empty disables) — provider response's
     `hostname` field must echo it.
   - `BotShieldCaptchaExpectedAction` (default `botshield`; empty
     disables) — provider response's `action` field must echo it
     (Turnstile + reCAPTCHA v3).
   - `BotShieldRecaptchaV3MinScore` (default 0.5) — reCAPTCHA v3
     score must be ≥.
6. On success: `bs_install_verified_cookie` mints `_bs_session`
   with `alg=captcha-<provider>`, `passes_captcha` bumped
   ( clamp), forgiveness applied. Redirect to `return_to` or
   the configured fail-redirect.

### Pending cookie (M8.1)

`_bs_captcha_pending` is an HTTPOnly signed envelope minted at
interstitial render time:

```
<nonce_hex>|<expiry_sec>|<hmac_hex>
hmac = HMAC-SHA256(derived_hmac_pending,
                   "pending:" || nonce || ":" || expiry)
```

Required at verify before libcurl. Missing/expired/tampered → 403
"challenge cookie missing" with no libcurl call. Cleared (`Max-Age=0`)
on successful verify so a stale cookie can't be reused.

This converts blind `curl -d ... /botshield/captcha-verify/...` spray
into a guaranteed early reject.

## Templates

`templates.{c,h}` owns the static HTML/CSS/JS strings and the
two-step substitution renderer.

### Two-step substitution

1. The widget template is filled with per-request bits (prompt,
   logo, label, help, the inline challenge JSON or captcha sitekey
   + verify URL). Result: a self-contained widget block with scoped
   CSS.
2. The page shell — built-in `BS_DEFAULT_PAGE_TEMPLATE` or
   operator-provided `BotShieldChallengeFile` — gets the widget
   block spliced in at the `<!-- BOTSHIELD -->` marker.

`bs_render_challenge_page` sets `r->status`, `Content-Type`,
`Cache-Control: no-store`, `X-Botshield: challenge`, then writes the
body via `ap_rputs`. Returns 1 if the served widget came from the
captcha-provider family, 0 if it was the PoW widget. Caller emits
the surrounding decision-log entry.

### Widget variants

- **PoW widget** (M2/M7): inline JS, inline CSS, inline embedded
  challenge JSON. Two visual modes — visible checkbox (interactive tier) or
  neutral "checking your browser" splash (noninteractive tier with
  `auto:true`). WCAG 2.1 AA; landmarks, `aria-live` status, focus
  order, reduced-motion, `<html lang>`, `.bs-sr` clip-offscreen
  technique on the noninteractive-tier label so axe-core sees the accessible
  name.
- **Captcha widgets** (M8): three render templates keyed on provider
  - "render" pattern (Turnstile / hCaptcha / reCAPTCHA v2 /
    Friendly), "execute" pattern (reCAPTCHA v3), or `initGeetest4`
    pattern (GeeTest).

### Operator overrides

- `BotShieldChallengeFile <path>` — full HTML page template with the
  `<!-- BOTSHIELD -->` marker. Loaded once at startup, capped at
  `BS_MAX_PAGE_BYTES = 256 KiB`.
- `BotShieldLogoFile <path>` — SVG inline; `BS_MAX_LOGO_BYTES = 64
  KiB`.
- `BotShieldHelpFile <path>` — HTML fragment for the help panel;
  `BS_MAX_HELP_BYTES = 64 KiB`. Contents are trusted (no escaping).
- `BotShieldPromptText`, `BotShieldLogoLabel` — short strings;
  HTML-escaped at render.
- `BotShieldShowLogo` / `BotShieldShowLabel` / `BotShieldShowBox` —
  visibility flags.
- `BotShieldHelp <off|on|button>` — help-panel mode. `button`
  shows a `?` link that toggles the explainer.

## App integration bridge

Two halves of one signed-wire-format integration share one HMAC key
file (`BotShieldAppIntegrationSecretFile`). The two protocols'
canonical forms are structurally distinct so cross-replay between
directions is impossible — one key is sufficient (parser-level
domain separation, not key separation).

### Inbound: X-BotShield-Feedback (E5)

Wire format on the app's response:

```
event=<name>[;kid=<id>];sig=<hex>
```

HMAC-SHA-256 covers everything before `;sig=` using the shared
secret. The app sets the header on its response; the module's output
filter `bs_app_feedback_filter` strips and applies in one pass.

#### Filter discipline

- Registered via `ap_register_output_filter` at
  `AP_FTYPE_PROTOCOL - 1` so it runs after `mod_headers` (which
  re-applies `Header always` directives at FIXUP_HEADERS_OUT)
  but before the protocol serializer.
- Inserted on every initial request via both
  `ap_hook_insert_filter` (normal chain) AND
  `ap_hook_insert_error_filter` (error chain via `ap_die`). Apache
  builds a separate output filter chain for 4xx/5xx responses,
  including `ErrorDocument` redirects; the normal-chain
  `insert_filter` doesn't fire there. Same handle, same callback —
  the filter is idempotent and one-shot per request, so
  double-registration is safe.
- **Strips unconditionally when present**, even with
  `BotShieldAppFeedback off`. An app emitting the header during a
  configuration mistake should never leak it to the client. The
  *feature-off* optimization is "don't parse or validate when off,"
  not "don't touch the table."
- **Duplicate headers**: rejected (no flag applied, INFO log) and
  every instance stripped. Refusing to guess which copy is
  authoritative prevents an app-bug + header-injection combo from
  letting a client plant the second header.
- **Subrequests skipped** via `ap_is_initial_req(r)`.

#### Event-to-flag mapping

E5 went through a wire-format rework in E7.3: the body now carries
`event=<name>` only, and the flag/ttl/log come from
`BotShieldFeedbackTrigger <event>` configuration. The signer covers
`event=<name>` only; the responder validates the HMAC, looks up the
event in `scfg->feedback_triggers`, and applies the configured
flag-bit + TTL via `bs_flagged_ip_add` (with the configured log-tag
on the decision log).

Apps cannot invent new flags without a matching directive
configuration — keeps the scoring surface auditable.

### Outbound: X-Botshield-Claims (E8.2)

On the request path's pass leg, the module strips any client-
supplied `X-Botshield-*` (case-insensitive) and emits a single
signed claim envelope on `r->headers_in` so the backend reads
sanctioned BotShield state without poking at the encrypted cookie.

Wire format:

```
v=1;score=<n>;tier=<pass|noninteractive|interactive|captcha>;cookie=<ok|expired|bad_sig|bad_format|absent|->;flags=<space-sep flag names>;passes=s=<n>,f=<n>,c=<n>;ts=<unix>;sig=<hex>
```

HMAC-SHA-256 covers the body before `;sig=`. The strip-before-set is
the trust anchor for apps that don't bother to verify the HMAC; the
signed envelope is for apps that want value-integrity even across an
untrusted Apache→backend hop.

`BotShieldAppClaims on` enables it; without
`BotShieldAppIntegrationSecretFile` set, `bs_app_claims_set` returns
an error string the caller logs at WARNING level.

## Load-aware throttling (E11)

Origin overload protection — not a generic DoS shield. The job is
to help Apache shed low-trust traffic when the server is hot,
without becoming a host-health agent.

### Sampler

`bs_load_watchdog_cb` runs once per `BotShieldLoadRefreshInterval`
seconds (default 1, range 1..60) under mod_watchdog. Each tick:

1. **Apache scoreboard sample** — busy-worker count over total
   workers (via the public `ap_scoreboard` API). Compute a busy
   ratio.
2. **External state file** (optional) — `BotShieldLoadStateFile`
   names a small file whose body is `normal`, `warm`, or `hot`.
   The watchdog stat-polls `mtime`; only re-reads on change.
3. **Most-severe-wins merge** — internal sample vs external
   override, take the more severe.
4. **Hysteresis state machine** — asymmetric:
   - Ratio ≥ `BotShieldLoadWarmThreshold` (default 65 %) →
     escalating sample. Promotion to `warm` after
     `BS_DEFAULT_LOAD_WARM_RISE = 3` consecutive escalating samples.
   - Ratio ≥ `BotShieldLoadHotThreshold` (default 85 %) → hotter
     sample. From `warm`, promotion to `hot` after
     `BS_DEFAULT_LOAD_HOT_RISE = 2` more.
   - Below warm threshold for `BS_DEFAULT_LOAD_NORMAL_FALL = 5`
     consecutive samples → demote one level. Slow recovery prevents
     flap.
5. **Atomic publish** — write the resolved state into
   `bs_shm.header->load_state` via `__atomic_store_n`. Increment
   `load_state_changes` and `load_state_since_sec` on transitions.

### Lockless reader

`bs_load_current()` is `__atomic_load_n(&header->load_state,
__ATOMIC_RELAXED)`, called from E11.2's `BotShieldLoadTrigger`
predicate matcher in `bs_check_policy`. No scoreboard scans on the
hot path.

`bs_load_state` enum: `BS_LOAD_NORMAL = 0`, `BS_LOAD_WARM = 1`,
`BS_LOAD_HOT = 2`. The numeric ordering is exposed as the
`shm_load_state` gauge (Prometheus) and consumed by
`state>=warm`-style predicates.

## Safeguard / anti-loop (E10)

A borderline-real client gets stuck in repeated noninteractive / captcha
churn (CSP, blockers, broken JS, privacy tooling). Safeguard's job:
stop the loop and pick a deterministic lower-churn behavior.

### State

The safeguard SHM table (see SHM segment) carries
`(present_window_start, present_count, safeguard_until)` per masked
IP. Every challenge presentation calls
`bs_safeguard_record_presentation` (regardless of
`BotShieldSafeguard` master switch — E17 embedded mode reads the
count). When `present_count >= BotShieldSafeguardThreshold` (default
5) inside `BotShieldSafeguardWindow` (default 600 sec):

- `safeguard_until = now + BotShieldSafeguardTTL` (default 900 sec).
- The TTL slides on each fresh presentation during active safeguard
  so a chronically broken client stays in safeguard rather than
  dropping in and out at every window boundary.

`bs_safeguard_clear` is called from `bs_handler` after a
fully-valid cookie verifies — a successful solve proves the client
*can* progress, so the accumulated history was transient noise.

### Behavior under safeguard

When `BotShieldSafeguard On` and `bs_safeguard_check()` returns
true, the request is short-circuited with reason
`challengesafeguard`, `tier=safeguard outcome=redirect`, and
returns `DECLINED`. The real handler runs.

Safeguard:
- **Does not** mint `_bs_session` (no trust grant).
- **Does not** override 403 / 429 hard blocks (those come from
  `bs_check_policy` which runs first).
- Only suppresses the BotShield interstitial.

### E17 embedded fallback

The same SHM table is consumed by E17's embedded → M7 fallback. After
`BS_DEFAULT_EMBEDDED_FALLBACK_THRESHOLD = 3` consecutive noninteractive-tier-
embedded dispatches in the safeguard window without `_bs_session`
arriving, the embedded short-circuit is bypassed and M7 issues a
visible interstitial. M7's own safeguard threshold catches the case
where M7 also fails.

## Reputation namespacing (E13)

Module-global SHM with per-vhost isolation by default:

- Each vhost auto-isolates by `siphash(ServerName)` resolved at
  post_config — different vhosts don't share flagged-IP / Bloom /
  strike / safeguard reputation.
- `BotShieldShareScope <token>` is the opt-in to *share* across
  vhosts (two vhosts with the same token compute the same `ns_id`).
- A missing `ServerName` AND no `BotShieldShareScope` falls back to
  `ns_id=0` (a server-wide global namespace) with a NOTICE so
  operators spot the unintended sharing.

Implementation:

- `apr_uint32_t ns_id` field in every reputation slot (flagged-IP,
  strike, safeguard, nonce).
- `ns_id` mixed into SipHash inputs for bucket selection on all four
  tables and the K=7 Bloom probes — different namespaces get
  disjoint bucket distributions and independent Bloom probes.
- Lookups reject slots whose `ns_id` doesn't match.
- Writes record the calling vhost's `ns_id` on the slot.

`BS_STATE_FORMAT_VERSION` was bumped 1 → 2 → 3 across the namespacing
+ empty-marker reworks; older state files are rejected with a NOTICE
and the table starts fresh (slot-level migration was deemed more
dangerous than letting it rebuild from live traffic).

`bs_warn_if_virtual_scope` emits a NOTICE on every SHM-sizing
directive placed inside `<VirtualHost>` (`BotShieldShmSize`,
`BotShieldFlaggedIPCapacity`, `BotShieldBloomIPs`,
`BotShieldBloomWindow`, `BotShieldRateLimitEscalateCapacity`,
`BotShieldSafeguardCapacity`) — those are read off the main server's
scfg only, since the SHM segment is module-global.

## Inline form captcha (E18)

Operator opts a scope into form-captcha validation via
`BotShieldFormCaptcha on`. The fixup hook
(`bs_form_captcha_fixup`, registered at `APR_HOOK_MIDDLE` of
`ap_hook_fixups`) runs before content handlers but after auth/header
processing, so the request body is still readable from the input
filter chain.

### Body shapes

- `application/x-www-form-urlencoded` — direct field extraction via
  `bs_form_get`.
- `application/json` — parsed with json-c (already linked for E5 /
  E8.2). Same token field name as the URL-encoded path.
- `multipart/form-data` — out of scope. Streaming parser + temp-file
  buckets aren't a fit. Returns 415 with diagnostic so operators
  notice. Operators with file-upload forms put the captcha on a
  separate non-upload form.

### Body cap + replay

- Body capped at `BS_FORM_CAPTCHA_BODY_MAX = 256 KiB`. Oversize →
  413.
- Wrong content-type → 415 (fail-loud, not silent allow).
- Missing scope provider config → 503.
- Bad token / hostname mismatch / action mismatch / v3 score below
  threshold → 403, app handler never runs.

The fixup hook reads the entire body via `ap_get_brigade` against
the request's input filter chain into a 256 KiB pool-allocated
buffer. After siteverify decides, the hook adds a one-shot input
filter (`BS_FORM_REPLAY`) at the top of `r->input_filters` that
emits the buffered body + EOS when the downstream handler asks for
it. `ap_add_input_filter_handle` puts the filter ahead of the (now
drained) protocol filters, so the handler's first read hits the
buffered copy. The filter self-removes via `ap_remove_input_filter`
after first emission so subsequent reads see only EOS.

### Success path

Successful verify mints `_bs_session` with `passes_captcha=1` (free
side effect — future BotShield friction skips this client) and
returns `DECLINED`. The app handler runs as if BotShield wasn't
there.

## Shadow mode (E12)

Two layers:

- **Per-rule `mode=observe`** on any trigger / rate-limit / block-
  path action. Observe-mode matches log a stable `would-X` reason
  (`would-block`, `would-rate-limit`, `wouldflagtrigger:<flag>:
  observe`) but skip the side effect.
- **Scope-level `BotShieldEnabled LogOnly`**: tri-state directive
  on `bs_dir_cfg.enabled` (`On` / `Off` / `LogOnly`). When the
  effective dir-cfg is in `LogOnly`, every match (regardless of
  per-rule `mode=`) becomes observe-mode AND tier-decision dispatch
  (noninteractive / interactive / captcha) short-circuits to an `outcome=~challenge`
  decision log line. The leading tilde marks a suppressed
  counterfactual: the real outcome was always `allow` (request
  flowed through), and the tilde-prefixed value is what *would*
  have been served under enforcement. Greppable as `outcome=~`.
  Useful for staging a whole policy revision before flipping
  enforcement on. Because the field lives in `bs_dir_cfg` at
  `RSRC_CONF | ACCESS_CONF` scope, operators can carve out
  per-`<Location>` exceptions: vhost-wide `LogOnly`, then
  `BotShieldEnabled On` inside a `<Location "/about">` to enforce
  one path while leaving the rest observational.

Reason strings carry the `:observe` suffix. Metrics counters split:
`rate_limit_observed_total` and `trigger_observed_total` (which
covers path/cookie/env/load/scope observe) are separate from
`rate_limit_exceeded_total`. Operators correlate observed volume
with would-be-hit volume before promoting `enforce`.

## Observability (M9)

### Decision log (M9.1)

One structured `key=value` line per terminal decision, alongside
the existing prose lines:

```
mod_botshield: decision tier=<t> outcome=<o> ip=<i> score=<n>
    cookie=<c> provider=<p|-> alg=<a|-> reason="<r|->" path="<u>"
    [tag="<x>"]
```

Tag suffix is emitted only when a trigger set a `log=<tag>` action;
absent tag means a normal decision line shape, byte-identical to
pre-tag emissions.

Enum vocabularies (validated at commit time by an awk script):

| Field | Values |
|-------|--------|
| `tier` | `none`, `pass`, `noninteractive`, `interactive`, `captcha`, `safeguard` |
| `outcome` | `declined`, `challenged`, `verified`, `rejected`, `failopen`, `rate_limited`, `inflight_capped`, `pending_missing`, `misconfigured`, `debug` |
| `cookie` | `ok`, `expired`, `bad_sig`, `bad_format`, `absent`, `-` |
| `provider` | `-` or registry name (`turnstile`, `hcaptcha`, `recaptcha-v2`, `recaptcha-v3`, `friendly`, `geetest`) |
| `alg` | `-` or registry entry (`sha256zeros` or `captcha-<provider>`) |
| `reason` | quoted short string or `-` |

`reason` and `path` are double-quoted for logfmt safety; everything
else is unquoted enum so the format parses with a small awk script.

Emission goes through `bs_decision_log` — one central helper. Reason
construction lives in `bs_decision_reason_names` (walks the
request-scoped score struct).

### SHM counters (M9.2)

Every `bs_decision_log` call bumps up to four counter dimensions
(tier, outcome, cookie when `!= "-"`, provider when `!= "-"`).
Counter names derive mechanically from the M9.1 enum strings — no
parallel vocabulary. Adding a new enum value means adding one row to
the string→index lookup; forgetting to do so logs one WARNING and
skips the increment rather than silently inventing a bucket.

The `bs_metrics` block lives in SHM next to the rate-counter pool
(~264 bytes). Children inherit via fork. Counters are not persisted
and reset across `apachectl graceful` (Prometheus convention).

#### Counter inventory

| Set | Names | Count |
|-----|-------|-------|
| `tier_<t>_total` | one per tier enum | 5 |
| `outcome_<o>_total` | one per outcome enum | 10 |
| `cookie_<c>_total` | one per cookie enum (excluding `-`) | 5 |
| `provider_<p>_total` | one per built-in provider | 6 |
| persistence | `state_saves_total`, `state_loads_total` | 2 |
| E1 | `bot_allow_total`, `bot_fake_total`, `bot_unverified_total` | 3 |
| E2.1 | `rate_limit_exceeded_total` | 1 |
| E12 | `rate_limit_observed_total`, `trigger_observed_total` | 2 |

#### Gauges (computed when scraped, cached 1 s per worker)

`captcha_inflight_current`, `shm_flagged_used`, `shm_flagged_capacity`,
`shm_strike_used`, `shm_strike_capacity`, `shm_safeguard_used`,
`shm_safeguard_capacity`, `bloom_bits_set_active`,
`bloom_bits_set_warming`, `bloom_window_seconds`,
`cv_rate_slot_capacity`, `cv_log_slot_capacity`, `load_state`,
`load_state_changes_total`, plus `state_save_last_*` and
`state_load_last_*` family.

All counters use `apr_uint64_t`, atomic via
`__atomic_fetch_add(..., __ATOMIC_RELAXED)` for
GCC/clang-toolchain consistency. Gauge reads use `__atomic_load_n`
on each u64 — on x86_64 64-bit aligned reads are already atomic,
but the intrinsic keeps the compiler from reordering across
concurrent writers.

### Export surface (M9.3)

Two endpoints under `BotShieldEndpointPrefix` (default `/botshield`):

#### `/botshield/metrics` — Prometheus 0.0.4 text exposition

`bs_metrics_handler` emits `Content-Type: text/plain; version=0.0.4`,
deterministic ordering (enum order within each dimension), metric
names hardcoded as string literals (no runtime sprintf on the scrape
path). Each metric has `# HELP` / `# TYPE` / value in that order.

Access control deliberately delegated to Apache — operators gate the
endpoint with `<Location>` + `Require ip ...` / `AuthType Basic` /
etc. The module emits everything to anyone who reaches the handler.

#### mod_status contribution

`bs_status_hook` is registered via
`APR_OPTIONAL_HOOK(ap, status_hook, ...)` — fires only when
mod_status is loaded. Renders:

- `AP_STATUS_SHORT` (`?auto` mode) → `BotShield<Name>: N` key-value
  lines.
- HTML mode → `<h2>mod_botshield</h2>` + a compact two-column table
  (tier × outcome).

Optional hook means no hard linkage — module builds and runs
identically when mod_status isn't loaded.

## Production hardening

### Sanitizer build (M10.1)

`make sanitize` builds with `-fsanitize=address,undefined
-fno-sanitize=object-size -fno-omit-frame-pointer -g -O1` (apxs
forwards via `-Wc,...` / `-Wl,...`). `-fno-sanitize=object-size` is
deliberate: `__builtin_object_size` can't see through APR pool
allocation (chunks are bulk-malloced, individual `apr_palloc` slices
are sub-allocations the compiler doesn't track), so this check
produces spurious "insufficient space" reports on any pool-returned
string. The rest of UBSan's checks (null pointer deref, signed
overflow, array bounds, shift overflow, alignment, bool/enum-load,
etc.) still fire normally.

Sanitizer-driven hardening fixes already merged include:

- `curl_global_init` moved to `bs_post_config` (single-threaded,
  pre-fork); the lazy-init static guard raced under `mpm_event`.
  Failure now fails post_config loud.
- `__thread` storage for thread-local gauge caches.
- `__atomic_load_n` on captcha-verify ring observation reads (CAS
  still validates).
- Bloom rotation: atomic-store loop + brief global mutex.
- `bs_state_save` duration clamped to ≥ 0 (wall-clock rollback).

### Hardening flags (M10.2)

Additional compiler flags forwarded through apxs:
`-Wc,-Wall -Wc,-Wextra -Wc,-Wno-unused-parameter -Wc,-fvisibility=hidden`.
Symbols namespaced with `bs_` / `BS_` prefix; only `botshield_module`
escapes. Only the request-handler entry, hook callbacks, and
directive setters are reachable from Apache; everything else is
file-`static` or `bs_*` with hidden visibility.

### MPM matrix (M10.3)

Verified on `mpm_event`, `mpm_worker`, `mpm_prefork`. Module loads,
`/metrics` serves, `/server-status` renders the botshield
contribution (HTML + `?auto`), captcha-verify works end-to-end,
`cv_inflight` returns to 0 at idle. Graceful-restart-mid-traffic
correctness verified — state file save fires on old `pconf`
cleanup, state file load fires on new parent, `/metrics` serves on
the new parent.

SHM counters reset across `apachectl graceful` on all three MPMs
(because `apr_shm_create` is bound to `pconf`, which Apache destroys
+ recreates on graceful). Bloom + flagged-IP state survives via the
state file. Counter reset is a standard Prometheus convention.

### Soak (M10.4)

Overnight run at moderate rps: memory steady, counters monotonic,
state-file saves succeeding, log file in budget. Soak runs through
the pytest framework (`tests/pytests/test_soak.py`) with a session-
scoped `soak_load` fixture that drives traffic while the test body
samples metrics and asserts invariants.

## Testing surface (M11)

### pytest harness (M11.4–M11.7)

Layout in `tests/`:
- `pytests/` — pytest tests (50+ files).
- `botshield_test/` — the Python package: `client.py` (httpx-based),
  `apache.py` (control + `config_override` context manager that
  always reverts on exit), `logs.py` (`log_slice` + `decision_lines`
  structured iterators), `metrics.py` (snapshot/delta), `cookies.py`
  + `pow.py`, `ips.py` (`fresh_ip` allocator with xdist coordination),
  `enums.py` (single source for TIERS / OUTCOMES / COOKIES /
  PROVIDERS).
- `setup/provision.sh` — idempotent box setup: self-signed cert,
  `/etc/botshield/*` secrets at 0600, `/var/lib/botshield`, dev
  vhost install, `a2enmod botshield`.
- `fuzz/` — LibFuzzer harnesses.
- `bash-legacy/` — archived bash suite (reference).

Markers + CI job split:
- `@pytest.mark.slow` — skipped in per-PR fast lane.
- `@pytest.mark.live_network` — third-party providers; skipped if
  the provider's siteverify is unreachable. Uses
  `pytest-rerunfailures --reruns 2` only for this marker —
  Cloudflare / Google can burp; everything else has zero reruns.
- `@pytest.mark.browser` — Playwright-based; separate CI job.
- `@pytest.mark.serial` — runs outside xdist pools.

Fast lane runs `pytest -n auto`; full lane includes browser +
live_network + slow.

### Browser tests (a11y / Playwright) (M11.6, M11.8)

- Real Chromium via pytest-playwright. Three acceptance flows:
  pass-tier (no challenge), interactive-tier (PoW worker, auto-submit,
  redirect, cookie attribute enforcement), captcha-tier (Turnstile
  always-pass sitekey).
- `tests/pyproject.toml` `addopts` sets
  `--screenshot=only-on-failure --video=retain-on-failure` so every
  invocation gets the artifacts.
- `test_browser_a11y.py` runs axe-core (Deque's engine, bundled at
  `tests/pytests/assets/axe.min.js`, MPL-2.0) against the noninteractive
  interstitial, asserts zero critical + zero serious violations,
  plus targeted keyboard-tab-to-`#btn` checks against the interactive-tier
  variant and `<html lang>` assertion.
- Cookie attribute assertions impossible in bash: `Secure` /
  `SameSite` / `Path` honored by a real browser (Chromium enforces
  these; `curl -b` ignores them).
- Hypothesis property tests for the HMAC cookie round-trip — any
  random payload that signs correctly verifies; any single-bit
  flip of the signature fails.
- Prometheus exposition-format validation against
  `/botshield/metrics` via `prometheus_client.parser.text_string_to_metric_families`.

### LibFuzzer (M11.8)

Two harnesses in `tests/fuzz/`:

- `fuzz_cookie.c` — drives `bs_cookie_parse` (and a pool-stub layer
  for the GCM verify path). The `_fuzz_stubs.h` shim lets the
  cookie code compile against an APR-only TU without dragging in
  the full Apache symbols.
- `fuzz_robots.c` — drives `robots_parse_buf` + `robots_query` +
  the public group-iteration accessors. APR-only TU (no Apache
  stubs needed).

`make fuzz-robots-run DURATION=<sec>` or
`tests/fuzz/run.sh --target robots`. Seed corpora at
`tests/fuzz/corpus-robots/` and `tests/fuzz/corpus/`.

The module declaration (`AP_DECLARE_MODULE(botshield)`) and
`bs_register_hooks` are wrapped in `#ifndef BS_FUZZ_HARNESS` so the
fuzz target can `#include` source files verbatim without fighting
the linker on Apache symbols.

## Module entry surface

### Directive table

`bs_cmds[]` registers 100 directives. The retired `BotShieldPathTrigger`
stub that used to sit alongside them is gone, so an old config naming
it now fails with Apache's generic "Invalid command" rather than a
migration note.
The family groupings below summarize the surface — the canonical
per-directive spec (handler, arg count, scope flags, help text) is
the `bs_cmds[]` table at `src/botshield.c:142`.

| Family | Directives |
|--------|-----------|
| Top-level / UI | `BotShieldEnabled`, `BotShieldChallenge`, `BotShieldDebug`, `BotShieldCookieTTL`, `BotShieldDifficulty`, `BotShieldPromptText`, `BotShieldLogoFile`, `BotShieldLogoLabel`, `BotShieldShowLogo`, `BotShieldShowLabel`, `BotShieldShowBox`, `BotShieldHelp`, `BotShieldHelpFile`, `BotShieldChallengeFile`, `BotShieldEndpointPrefix` |
| Crypto | `BotShieldSecretFile`, `BotShieldSecondarySecretFile`, `BotShieldAlgorithm` |
| Score / forgiveness | `BotShieldScoreNonInteractive`, `BotShieldScoreInteractive`, `BotShieldScoreCaptcha`, `BotShieldForgivenessNonInteractive`, `BotShieldForgivenessInteractive`, `BotShieldForgivenessCaptcha`, `BotShieldForgivenessCapPerHour` |
| Cookie | `BotShieldCookieDomain` |
| Captcha (M8 + E18) | `BotShieldCaptchaProvider`, `BotShieldCaptchaSiteKey`, `BotShieldCaptchaSecretFile`, `BotShieldCaptchaTimeout`, `BotShieldCaptchaConnectTimeout`, `BotShieldRecaptchaV3MinScore`, `BotShieldCaptchaExpectedHostname`, `BotShieldCaptchaExpectedAction`, `BotShieldCaptchaCABundle`, `BotShieldCaptchaRateLimit`, `BotShieldCaptchaMaxInFlight`, `BotShieldFormCaptcha` |
| Non-interactive (E17) | `BotShieldNonInteractiveMode` |
| SHM sizing | `BotShieldShmSize`, `BotShieldFlaggedIPCapacity`, `BotShieldIPv6PrefixLen`, `BotShieldBloomIPs`, `BotShieldBloomWindow`, `BotShieldStateFile`, `BotShieldStateSaveInterval`, `BotShieldRateLimitEscalateCapacity`, `BotShieldSafeguardCapacity`, `BotShieldEmbeddedNonceCapacity` |
| UA classification (E1) | `BotShieldClassify`, `BotShieldAllowBot`, `BotShieldAllowRangesRefreshInterval`, `BotShieldBotDirectory`, `BotShieldBotDirectoryRefreshInterval`, `BotShieldBrowserTemplates`, `BotShieldBrowserTemplatesRefreshInterval` |
| Policy (E2.1 / E9) | `BotShieldRateLimit`, `BotShieldBotRateLimit`, `BotShieldRateLimitEscalate` |
| Robots (E2.2) | `BotShieldRobotsTxt`, `BotShieldRobotsRefreshInterval`, `BotShieldRobotsWildcardScope` |
| Triggers | `BotShieldTrigger` (per-scope), `BotShieldRule` (E3, formerly BotShieldPathTrigger), `BotShieldCookieTrigger` (E4), `BotShieldEnvTrigger` (E6), `BotShieldFeedbackTrigger` (E7.3), `BotShieldLoadTrigger` (E11.2), `BotShieldFlagTrigger` (E14), `BotShieldHeuristicTrigger`, `BotShieldSessionCookieName` (E4) |
| Safeguard (E10) | `BotShieldSafeguard`, `BotShieldSafeguardThreshold`, `BotShieldSafeguardWindow`, `BotShieldSafeguardTTL`, `BotShieldSafeguardRedirectURL` |
| Load (E11) | `BotShieldLoadStateFile`, `BotShieldLoadRefreshInterval`, `BotShieldLoadWarmThreshold`, `BotShieldLoadHotThreshold` |
| Multi-vhost (E13) | `BotShieldShareScope` |
| Observability | `BotShieldDecisionLog` |
| App bridge (E5 / E8.2) | `BotShieldAppFeedback`, `BotShieldAppFeedbackHeader`, `BotShieldAppClaims`, `BotShieldAppIntegrationSecretFile` |

Most directives use `RSRC_CONF | ACCESS_CONF` (server / vhost /
`<Directory>` / `<Location>`); SHM-sizing and certain server-global
directives use `RSRC_CONF` only and emit a NOTICE if placed inside
`<VirtualHost>` (`bs_warn_if_virtual_scope`).

The module is not valid in `.htaccess` — `OR_ALL` is never used.

`AP_INIT_TAKE_ARGV` is used for the trigger families (including
`BotShieldFlagTrigger` and `BotShieldHeuristicTrigger`), the two
rate-limit setters, and `BotShieldClassify` because Apache has no
TAKE4/5 macros and because those directives take a variable-length
key=value tail; setters enforce argc themselves.

### Hook registration

`bs_register_hooks` (gated under `#ifndef BS_FUZZ_HARNESS`) wires:

| Hook | Callback | Order |
|------|----------|-------|
| `ap_hook_post_config` | `bs_post_config` | `APR_HOOK_MIDDLE` |
| `ap_hook_child_init`  | `bs_child_init`  | `APR_HOOK_MIDDLE` |
| `ap_hook_handler`     | `bs_handler`     | `APR_HOOK_FIRST` (runs before default file handler) |
| `ap_hook_post_read_request` | `bs_classify_request_hook` | `APR_HOOK_LAST` (after mod_remoteip has rewritten `r->useragent_ip`, so the verified-bot IP cross-check sees the real client) |
| `ap_hook_log_transaction` | `bs_propagate_decision_env` | `APR_HOOK_FIRST` (ahead of mod_log_config: re-publishes `BS_*` env across an internal redirect, and returns `DONE` to break the chain for `accesslog=off`) |
| `ap_hook_fixups`      | `bs_form_captcha_fixup` (E18) | `APR_HOOK_MIDDLE` |
| `ap_register_input_filter("BS_FORM_REPLAY")` | `bs_form_replay_filter` (E18) | `AP_FTYPE_RESOURCE` |
| `ap_register_output_filter("BOTSHIELD_APP_FEEDBACK")` | `bs_app_feedback_filter` (E5) | `AP_FTYPE_PROTOCOL - 1` |
| `ap_hook_insert_filter` | `bs_app_feedback_insert_filter` | `APR_HOOK_MIDDLE` |
| `ap_hook_insert_error_filter` | `bs_app_feedback_insert_filter` | `APR_HOOK_MIDDLE` |
| `APR_OPTIONAL_HOOK(ap, status_hook, ...)` | `bs_status_hook` | `APR_HOOK_MIDDLE` |

`bs_post_config` additionally registers per-vhost mod_watchdog
callbacks:

- `bs_state_save_watchdog_cb` (M6 — periodic state save)
- `bs_robots_watchdog_cb` (E2.2.2 — robots.txt refresh, per vhost
  with a configured path)
- `bs_load_watchdog_cb` (E11 — scoreboard sampler)
- `bs_headroom_watchdog_cb` (E13.1 — capacity-headroom watchdog)

mod_watchdog is a soft dependency throughout. Without it, periodic
saves degrade to shutdown-only, robots refresh degrades to
post_config-only, the load sampler doesn't run (state stays at
`normal`), and the headroom watchdog doesn't run. Each degradation
emits a NOTICE so operators see the change.

### Module struct

```c
#pragma GCC visibility push(default)
AP_DECLARE_MODULE(botshield) = {
    STANDARD20_MODULE_STUFF,
    bs_create_dir_cfg,
    bs_merge_dir_cfg,
    bs_create_server_cfg,
    bs_merge_server_cfg,
    bs_cmds,
    bs_register_hooks,
    AP_MODULE_FLAG_NONE
};
#pragma GCC visibility pop
```

The `visibility default` pragma keeps `botshield_module` exported
even though the rest of the `.so` is built with
`-fvisibility=hidden`. Apache's `LoadModule` resolves it via dlsym.

### Config lifecycle

Apache 2.4 invokes `post_config` twice on cold boot (syntax-check
pass, then real init). `bs_post_config` skips the first via a
userdata sentinel keyed on `s->process->pool` so HKDF derivation,
SHM segment creation, watchdog registration, and cross-vhost
validation only run once.

`bs_create_dir_cfg` allocates `bs_dir_cfg` with all tri-state fields
set to `BS_UNSET = -1` so merges can distinguish "operator wrote 0"
from "inherit from parent." `bs_merge_dir_cfg` uses the
`bs_effective_int(value, fallback)` pattern at request-time to
resolve `-1` to a hard default.

`bs_merge_server_cfg` merges arrays by appending vhost entries first
then main-scope entries, preserving the "more-specific scope wins on
first-match" idiom.

`bs_child_init` per-worker init attaches to the SHM mutex inherited
from the parent; idempotent under graceful restart.

## Build & install

`apxs` flow via `Makefile`:

```
make            build only
make install    build + install .so into Apache's modules dir
make enable     install + a2enmod + configtest + reload
make disable    a2dismod + reload
make reload     configtest + reload
make clean      remove build artifacts
make docs       build the static project site into ./docs
make sanitize       build with ASan + UBSan + frame pointers + -g
make install-sanitize  install the sanitized .so
```

Source layout in the Makefile:

```
MAIN_SRC := src/botshield.c
EXTRA_SRC := src/robots.c src/shm.c src/crypto.c src/allowlist.c
             src/metrics.c src/challenge.c src/cookie.c src/load.c
             src/triggers.c src/config.c src/templates.c
             src/formcaptcha.c src/score.c src/policy.c
             src/heuristics.c src/non_interactive.c src/captcha.c
             src/bridge.c
```

`apxs` derives the `.la` / `.so` name from the first source — hence
`botshield.c` is first. Extra `.c` files compile into the same shared
object and share the module's pool / APR linkage. The installed `.so`
is named `mod_botshield.so` via apxs's `-n` flag.

LibFuzzer harnesses in `tests/fuzz/` build their own way (LLVM clang,
not apxs); each `#include`s the relevant source files verbatim with
`BS_FUZZ_HARNESS` defined to elide the Apache module declaration and
hook registration.

Direct dependencies (from `botshield.c` includes):
- httpd / APR (Apache 2.4).
- OpenSSL (libcrypto) for HMAC, EVP/AES-GCM, HKDF, RAND.
- libcurl for captcha siteverify.
- json-c for siteverify response parsing and E18 JSON-body parsing.
- mod_watchdog (soft) for periodic save / robots refresh / load
  sampler / headroom watchdog.
- mod_status (soft) for the status-hook contribution.
