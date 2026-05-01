# Changelog

## 2026-05-01

### Changed
- Folded `BotShieldLogOnly` into `BotShieldEnabled` as a tri-state
  TAKE1 directive: `On` (enforce) / `Off` (disabled) / `LogOnly`
  (observe). The standalone `BotShieldLogOnly` directive and
  `bs_server_cfg.log_only` field are removed. The new shape lives
  on `bs_dir_cfg.enabled` (already a tristate) at `RSRC_CONF |
  ACCESS_CONF` scope, so per-`<Location>` overrides work without
  any further refactor:

      BotShieldEnabled LogOnly                # vhost: observe
      <Location "/about">
          BotShieldEnabled On                 # /about: enforce
      </Location>

  The 5 enforcement-suppression sites (tier dispatch, BlockPath
  observe, RateLimit observe, heuristic-trigger executor,
  app-feedback filter, form-captcha) now read
  `dcfg->enabled == BS_ENABLED_LOGONLY` from `r->per_dir_config`
  instead of a server-scope flag.
- Interstitial response is now `403 Forbidden` with
  `X-Robots-Tag: noindex, nofollow` instead of `200 OK`. Search
  engines that hit a protected URL won't index the placeholder
  ("Verifying you are human...") as if it were the page content.
  Browsers still execute inline JS / captcha widgets on 4xx
  responses, so the silent-tier auto-solve and captcha widgets
  keep working for legitimate clients (matches the Cloudflare /
  DataDome / Akamai pattern).

### Fixed
- M9.2 metrics: tilde-prefixed counterfactual outcomes
  (`~challenge`, `~block`, `~rate_limited`) no longer log a
  `metrics: unknown outcome` warning per LogOnly-suppressed
  decision. The override applies only to operator-facing surfaces
  (decision-log line + `BS_OUTCOME` env); the counter bump uses
  the original `allow` because that's what actually happened.
  Per-family `*_observed_total` counters continue to capture the
  staging-volume signal.

## 2026-04-30

### Changed
- Renamed `BotShieldShadowMode` → `BotShieldLogOnly` (directive,
  setter `bs_set_shadow_mode` → `bs_set_log_only`, server-cfg field
  `shadow_mode` → `log_only`). The new name describes what the flag
  does in plain English; "shadow mode" was security jargon that
  required prior context to recognize. Per-rule `mode=observe` is
  unchanged. Beta software, no in-the-wild configs to migrate.
- `BotShieldLogOnly` now also short-circuits the tier-decision
  dispatch in `bs_handler` (was: trigger / rate-limit / block-path /
  form-captcha rules only). Non-PASS tier decisions emit an
  `outcome=~challenge` decision log line (the leading tilde marks a
  suppressed counterfactual: real action was allow, this is what
  *would* have been served) and decline rather than serving an
  interstitial. Lets an operator stage a bare `BotShieldEnabled On`
  on a fresh vhost and watch what the module would do without any
  client seeing a challenge.

## 2026-04-29

### Added
- `make test-clean` target — wipes pytest caches, reports,
  test-results, `.playwright-mcp/`, and `__pycache__/` trees.
  Spares `.venv/` and `.hypothesis/examples/`. Anchor check +
  `$(CURDIR)` absolute paths bound the `rm -rf` blast radius.
- CI job `docs-fresh`: rebuilds the site on PR, fails if rebuild
  produces a diff vs committed `docs/` — catches "edited a markdown
  source, forgot to rebuild" at PR review.
- Tracked `tests/site/` as the dev-vhost docroot (4-file fixture:
  `index.html`, `bs-custom-help.html`, `bs-custom-page.html`,
  `assets/logos/01-guardian.svg`).
- Fixed-rate benchmark `tests/bench/run-rate-bench.sh` — switched
  from vegeta to `oha` after vegeta / wrk2 / h2load all failed in
  WSL2 (ephemeral-port + worker-pool churn / empty histograms /
  HTTP/2-first throttling). Hits 1k/5k/10k RPS within 0.1% of
  target.

### Changed
- `bs_post_config` decomposed into 13 named phase helpers + 25-line
  orchestrator (911-line monolith → checklist; LTO inlines back so
  no runtime cost).
- `bs_handler` partial extraction: `bs_route_module_endpoint` and
  `bs_apply_safeguard` lifted out (567 → 468 lines); 10-step flow
  preamble at top.
- Archaeological label pass: ~23 stale markers pruned (PoC,
  "Phase 2", "review fix", "E14 (rework)").
- Self-review comment pass: SipHash-2-4 algorithm explanation in
  `shm.c`; longest-substring-match-anywhere algorithm explanation
  in `bs_ua_classify`; misc doc-drift fixes.
- Test docroot moved from gitignored `testsite/` to tracked
  `tests/site/`; existing testsite content preserved at
  `~/mod_botshield-testsite/`.
- `docs/` committed for GitHub Pages serving from `main:/docs`.

### Fixed
- Four documentation lies: stale "TODO: add a nonce SHM table" /
  "phase 2 nonce table" / "captcha stubs to form until that ships" /
  drifted `bs_check_policy` order list (now includes load + scope
  triggers).
- `bs_apply_rep_carry` docstring claimed flag-penalty floor that no
  longer existed.

### Removed
- Nightly cron for 8 h soak + LibFuzzer (cookie + robots, 30 m
  each) — both moved to `workflow_dispatch` only.
- `testsite/` directory (replaced by `tests/site/`).
- `REVIEWS.md` from repo (in-session tracking only).
- `/testsite/` from `.gitignore`.

### Hygiene
- Gitignore: `.hypothesis/`, `.claude/`, `.codex`,
  `.playwright-mcp/`, `.pytest_cache/` (anywhere), `.vscode/`.

---

## 2026-04-28

### Added
- Comparative benchmark suite at `tests/bench/` — 12 scenarios from
  baseline static-file through trigger-heavy / kitchen-sink config,
  wrk-driven, results saved per timestamp. Cookied scenario mints
  a real `_bs_verified` and replays. `LogLevel info` scenario
  measures decision-log overhead.
- Site handbook: 9 markdown source files (~2,400 lines) under
  `docs-src/`, rendered to `docs/` via `tools/build_site.py`.
- Performance section in `docs-src/deployment.md` with single-
  connection / saturation / fixed-rate framing.
- `BotShieldTrigger` — per-Apache-scope trigger directive (replaces
  `BotShieldFlagIP`). Allows `mode=observe` on
  `BotShieldFeedbackTrigger`.
- `.editorconfig` for indent / line endings / trailing whitespace.

### Changed
- File-split campaign continued (Phases 6–34): triggers, config
  (incl. directive-setter distribution), templates, formcaptcha,
  score, policy, heuristics; followed by `botshield.h` slimming
  (Phases 29–34) — score / triggers / challenge / captcha / robots
  types relocated to feature headers.
- Code-duplication review: three shared helpers —
  `bs_captcha_carry_and_mint`, `bs_captcha_https_post`,
  `bs_load_secret_file`.
- Renamed `PLAN.md` → `CHANGELOG.md` (in-source references).
- E12 (shadow mode) now also wraps the app-feedback path
  (`bs_app_feedback_filter` honors `shadow_mode` + per-trigger
  `observe`).

### Fixed
- Bench harness was measuring challenge-issuance, not pass-through —
  wrk's default no-UA / no-Accept-Language triggered heuristic
  challenges. Fixed by adding browser-like headers and a post-run
  bytes/req sanity check.
- `BotShieldShmSize` help text claimed wrong default.
- Security review batch (1 HIGH + 4 LOW/MED): assorted hardening.

### Removed
- Stripped security-scan severity labels (HIGH/MED/LOW #N) from
  source comments — review-history archaeology, not code rationale.

---

## 2026-04-27

### Changed
- **Cookie format: GCM-only on the wire.** Retired the legacy
  HMAC-only envelope. The dual-format compat switch from E8.1
  is gone; verify path is single-format. Secondary-key fallback
  (E16) still provides graceful rotation.
- **Secret consolidation.** Collapsed `app_feedback_secret` and
  `app_claims_secret` into one shared `app_integration_secret` —
  the two protocols' canonical forms are structurally distinct
  (single-field vs seven-field) so cross-replay isn't possible,
  and you no longer maintain two key files.
- **E14 rework: replaced adaptive-intensity machinery with
  `BotShieldFlagTrigger`.** Original E14 design used a flag-meta
  registry with `penalty=` / `next_difficulty=` / `next_tier=`
  fields; reworked design folds intensity into the unified trigger
  directive (`action=score score=N` + `action=tier_floor tier=…`)
  so adaptive policy lives in the same syntax as path / cookie /
  env triggers. Built-in defaults seeded in
  `bs_default_flag_triggers[]`.
- **File-split campaign begins** (Phases 1–5, 7–10): extracted
  `shm.{c,h}` (renamed from `botshield_shm`), `crypto.{c,h}`,
  `allowlist.{c,h}`, `metrics.{c,h}`; created `botshield.h`
  umbrella header for cross-cutting types; renamed
  `mod_botshield.c` → `botshield.c`. Then extracted `silent.{c,h}`,
  `captcha.{c,h}`, `bridge.{c,h}`, `challenge.{c,h}`,
  `cookie.{c,h}`, `load.{c,h}`.
- Path matcher consolidation: promoted `bs_rb_path_match` from the
  robots-internal helper to project-wide `bs_path_match`; retired
  the placeholder.
- Issuance refactor (Phase 1 + Phase 2): extracted carry-forward
  predicate + rep math, then install-side helper.
- Build with `-fvisibility=hidden`; only `botshield_module` is
  exported.

### Added
- `BotShieldCaptchaCABundle` directive (libcurl LOW finding).
- TLS pin + `CURLOPT_NOPROGRESS` on captcha siteverify.
- `BotShieldCookieDomain` directive surfaces in docs.
- Cacheline-segmented `bs_shm_header` (performance LOW finding).
- Documentation on shadow / observe modes, multi-vhost reputation
  isolation, scoring + tier-decision system, pending-cookie threat
  model.

### Fixed
- **MEDIUM #1: render-side carry-forward leak.** A path through the
  challenge-render hook could carry forward rep from an expired
  cookie (the issuance-side gate caught this; the render side did
  not). Closed; pytest regression added.
- DoS LOW: pre-validate numeric IPs via `inet_pton` instead of
  APR's flag-based filter.
- Decision-log: URL-encode `"` and `\` in quoted fields.
- `test_secret_rotation` flake: NUL-free hex key in fixture.
- Memory-safety / lifecycle / race LOW batch.

### Removed
- Bash test archive retired (paid off in M11.5).

---

## 2026-04-26

### Added
- Nonce SHM table for embedded-bootstrap one-time-use binding
  (security review MEDIUM #2 Phase 2). Closes replay-multiplier
  attack on the embedded-verify path.
- IP-bind on the bootstrap → verify pathway (security review
  MEDIUM #2 Phase 1) — bootstrap signs `(nonce, bound_ip,
  expires_at)` under a per-purpose HKDF key; verify rejects
  mismatches.
- HKDF-derived per-purpose keys (`bs:cookie:gcm:v1`, `:pending:v1`,
  `:bootstrap:v1`), cached at config-load (LOW #3).
- HttpOnly + `__Host-` prefix on `_bs_verified` (LOW #1, #2).
- `sudoers.d.example` for test-rig privilege scoping (LOW #15).
- Captcha-verify endpoint hardening (M8.1): pending cookie + per-IP
  rate limit + global in-flight semaphore.

### Changed
- Cookie tokenizer rewritten + post_config restore + mutex split
  (HIGH #3, #4, #6).
- Rate-counter: pack window+count into one u64 CAS for lock-free
  rollover.
- `bs_curl_easy_setopt` return codes checked via `BS_SETOPT` helper.
- `bs_read_form_body` surfaces 413 on overflow instead of silent
  truncate.
- libcurl: HTTPS-only protocol allowlist; abort on response
  truncation; reject connect to RFC1918 / loopback / link-local.
- Seqlocks: explicit C11 release/acquire memory ordering for
  portability across x86_64 / AArch64 / POWER.
- SHM writes: `trylock` + drop instead of blocking lock under
  contention — load-shed under volumetric DDoS.
- Graceful restart: clean SHM hand-off across generations
  (snapshot/restore pattern for the bs_shm global).
- `state_save`: bounded `timedlock` instead of indefinite blocking.
- Bloom: byte-atomic state-save copy + trylock on rotation.
- form-captcha: `AP_MODE_GETLINE` conformance + de-chunked header
  fix-up; reject body with embedded NUL (smuggling defense).
- Carry-forward: refuse expired cookies (replay-resistance).
- Embedded bootstrap: 120 s challenge expiry instead of cookie_ttl.
- Pending-cookie: dropped mis-justified 60 s post-expiry grace.
- Probe-saturation log throttle: SHM-shared, not per-worker
  (LOW #10).
- LibFuzzer harness: explicit per-input timeout / RSS + nightly CI
  job.
- Strict canonical-form check in cookie verify (INFO #1).
- `provision.sh` refuses to build if repo path is group/world-
  writable (preempts a make-install hijack on shared boxes).

### Fixed
- **E10**: `tier="safeguard"` decision lines bin to
  `BS_M_TIER_PASS` in metrics index (Gemini reviewer caught the
  unrecognized tier label dropping increments with WARNINGs).
- **E11**: `LoadWarmRise` / `LoadHotRise` / `LoadNormalFall` in
  `<VirtualHost>` were silently ignored — propagation loop only
  copied four of seven load fields up to `main_scfg`.
- **E12**: `BotShieldFormCaptcha` (E18) didn't honor global
  `BotShieldShadowMode` — added shadow gate after body-read but
  before policy decision (transport errors still fire; those are
  misconfiguration, not policy).
- **E13/E14**: vhost-scope state-file warning; flag-config
  stickiness across `apachectl graceful` (pristine
  `bs_flag_metadata_defaults` + reset helper); adaptive intensity
  through embedded-bootstrap PoW path.
- **E15**: E18 form-captcha success was wiping prior cookie's
  `forgive_window_start` / `_consumed` via `memset(&next_rep, 0)` —
  closed the forgiveness-washing seam.
- **E16**: pending-cookie path missed the `secret_secondary`
  fallback during key rotation. All four cookie-secret verify sites
  now have it.
- **E17**: same forgiveness-washing seam in
  `bs_embedded_verify_pow` and `bs_embedded_verify_provider`. Both
  now read prior cookie + carry forward via `bs_apply_rep_carry`.
- **E18**: filter readbytes contract violation; body-read off-by-
  one NUL; Set-Cookie `apr_table_set` clobbering prior rows. All
  six Set-Cookie write sites now use `apr_table_add`.

### Hygiene
- LOW batch: passes_* clamp + connect-timeout directive + header
  pinning + relaxed atomic loads on probe paths + tests/run reads
  JUnit XML + soak RSS scopes to dev pid + test client `verify`
  flag scoped to loopback.

---

## 2026-04-25

### Added
- **E10 — Challenge safeguard / anti-loop.** After N challenges in
  window without solving, fall through to `DECLINED` with reason
  `challenge-safeguard`. Defaults: threshold 5, window 1 h, TTL
  1 h. Cleared on successful solve.
- **E11.1 — Load-aware throttling sampler.** Three-state model
  (`normal` / `warm` / `hot`) sampled from Apache scoreboard's
  busy-worker ratio via mod_watchdog. Asymmetric hysteresis;
  optional file-based override.
- **E11.2 — `BotShieldLoadTrigger`** plumbed into the E7.2 trigger
  family. Predicates: `equal=`, `gte=`.
- **E12 — Shadow mode / dry-run.** Global
  `BotShieldShadowMode on` and per-rule `mode observe` for staging
  policy changes without enforcement. Decision log emits
  `would-block-path:<name>:observe` etc.
- **E13 — Per-vhost SHM namespacing.** Default-isolate via
  `siphash(ServerName)`, opt-in shared via `BotShieldShareScope
  <token>`. `(ip, ns_id)` matched on every SHM lookup.
- **E13.1 — Capacity headroom watchdog.** Per-table fill gauges
  (`shm_*_used` / `shm_*_capacity`); 5-minute rewarn cooldown.
- **E14 — Adaptive challenge intensity** (initial flag-registry
  approach; later reworked 2026-04-27 into `BotShieldFlagTrigger`).
- **E17 — Embedded silent verification.** Wrapper-injected silent-
  tier verifier; five endpoints under `<prefix>/embedded*`.
  `BotShieldSilentMode <interstitial|embedded>` directive.
  Adapters for invisible Turnstile (E17.2), reCAPTCHA v3 score
  (E17.3), invisible hCaptcha (E17.4a), invisible reCAPTCHA v2 +
  Friendly auto-start (E17.4b/c). M7 fallback on
  `worker-src 'self'` CSP.
- **E18 — Inline form captcha.** Verify-on-submit captcha for
  HTML forms; reuses M8 provider config; mints `_bs_verified` on
  success. **E18.3** JSON body support; **E18.4** form-widget
  shell at `/botshield/form-widget.js`.

### Changed
- Resolved open questions #3 (forgiveness cap) and #5 (secret
  rotation); renamed in-source comments to E16 / E17; renumbered
  E15..E17 to match physical PLAN order.
- E15 — Forgiveness cap per rolling window: per-cookie hourly cap
  (default 200 points) carried in canonical fields; cookie
  protocol bumped v1 → v2 (13 → 15 fields) with strict v1
  rejection.
- E16 — Cookie secret rotation: `BotShieldSecondarySecretFile`
  verify-only secondary key.
- E18 multipart explicitly out of scope (deferred → permanently
  deferred).

### Fixed
- De-flake `test_escalation_isolates_per_ip` and
  `test_robots_live_refresh`.

---

## 2026-04-24

### Added
- **E4 — Cookie triggers.** `BotShieldCookieTrigger <name>
  <predicate> <action>` matching on cookie presence / value /
  `_bs_verified`-state. Pass matches accumulate; first non-pass
  short-circuits.
- **E5 — App-to-module reputation feedback.** Bidirectional:
  inbound `X-BotShield-Feedback` HMAC-signed JSON envelope
  (login_success, fraud_detected, abuse_signal); output filter
  consumes the header, never forwards.
- **E6 — `BotShieldEnvTrigger`.** Trigger predicates that read
  `r->subprocess_env` populated by upstream Apache modules
  (`SetEnvIf`, `RewriteRule [E=...]`, ModSecurity v2).
- **E7.1 / E7.2 / E7.3 — Trigger family normalization.**
  `BotShieldTrigger` renamed to `BotShieldPathTrigger`; shared
  action engine (`bs_apply_trigger_action`); feedback-trigger
  directive + E5 wire-format change + dispatch order cleanup.
- **E8.1 — AES-256-GCM cookie confidentiality** + compat switch
  (later retired 2026-04-27 to GCM-only).
- **E8.2 — Signed `X-Botshield-Claims` module-to-app channel.**
- **E9 — `BotShieldRateLimitEscalate`.** Strike table (open-
  addressed, keyed `(ip, rule_slot, ns_id)`) escalates response on
  sustained rate-limit hits.

### Fixed
- **E4**: documented + tested "pass accumulates, non-pass short-
  circuits" semantics.
- **E5**: feedback header stripped on Apache's error-response
  chain too.
- **E6**: APR-table name case-insensitivity documented + redirect
  gate.

---

## 2026-04-23

### Added
- **E1 — Allow family / verified-bot policy.** `BotShieldAllow
  on` + `BotShieldAllowBot <name> <ua-pattern> [path |
  inline-cidrs | *]`. Trie-based UA classifier; per-bot CIDR
  files. Built-ins for Googlebot, Bingbot, Applebot.
- **E2.1 — Policy enforcement core.** `BotShieldRateLimit`,
  `BotShieldBlockPath`, cohort matcher (`*` / inline CIDRs /
  file-of-CIDRs), SHM-backed fixed-window counters.
- **E2.2 — In-module robots.txt parser.** RFC 9309 + Crawl-delay.
  Hand-rolled, defensive caps (1 MB / 2 KB lines / 64 groups /
  256 rules / 32 UAs / 3600 s). Live refresh via mod_watchdog
  (E2.2.2). `/botshield/policy-status` admin endpoint (E2.2.3).
  Per-segment-prefix UA matching.
- **E3 — Path-based triggers** (`BotShieldTrigger`, later renamed
  to `BotShieldPathTrigger` in E7.1).
- **E4 — Cookie triggers** (continues 2026-04-24).
- **M11.5 — bash test retirement.** Ported remaining bash tests;
  archived `tests/lib/common.sh` and friends.
- **M11.6 — Playwright + Chromium real-browser acceptance** layer.
  `@browser` marker. A11y smoke for the interstitial — caught a
  real fix in passing.
- **M11.7 — CI + reporting polish.** Rerun-on-flake for
  `@live_network`, HTML reports, CI split (test-fast vs
  test-browser), soak port to pytest.
- **M11.8 — Property + format testing.** Hypothesis cookie fuzz,
  Prometheus exposition-format validator, MPM matrix tests.
- **M11.8d — LibFuzzer harness for `bs_verify_cookie`.**

### Fixed
- M11.5 review fixes: `tests/run` false-green + false-fail; stale
  docs.
- M11.6 review fixes: pending-cookie Path test; stale marker docs.
- E1 review fixes: longest-match, drop UA prefilter, per-server
  merge.
- E2.1 review fixes: case-insensitive UA, ordered rule precedence.
- E2.2 review fixes: duplicate-UA union, server-scope inheritance.
- M11 audit fixes: inflight-cap test, screenshot-on-failure,
  cookie-fuzz hardening.
- Soak as pytest; LoadGenerator drain accounting.
- Security review fixes: captcha binding, bounded pre-HMAC parse,
  cookie-domain charset; overflow-guard `size*nmemb` in
  `bs_curl_write_cb`; tests/run empty-selection; strict directive
  parsing.

---

## 2026-04-22

The day everything basic shipped.

### Added
- **M2 — Signed-envelope verification protocol.** Crypto helpers,
  PoW algorithm registry (`sha256-zeros` + reserved rows for
  sha384 / sha512 / pbkdf2 / argon2id), HMAC-SHA-256 canonical-
  form challenge envelope.
- **M3 — Per-request scoring.** `bs_request_score`,
  `bs_score_add(penalty, ttl, reason)`, threshold ladder (pass /
  silent / hard / captcha), built-in heuristics.
- **M4a — Cookie reputation across re-issues.** Score + flag
  bitmap + passes_silent / passes_form / passes_captcha +
  challenged_at carried through forgiveness math.
- **M4b — Happy-path routing.** Score < silent → `DECLINED` with
  no cookie; legitimate users never carry BotShield state.
- **M5a — Flagged-IP SHM table** (rollback-proof bad-actor
  memory). **M5a.1**: IPv6 /64 aggregation.
- **M5b — Rotating two-buffer Bloom filter** for first-sight IP
  signal.
- **M6 — State persistence.** Snapshots flagged-IP +
  Bloom buffers across `apachectl graceful`. Save-path concurrency
  + directory-fsync follow-up. **M6.1**: periodic snapshots via
  mod_watchdog (soft dependency).
- **Catch-up M6.1 → M10.1.** Bulk merge bringing M7 (silent
  auto-submit), M8 (captcha tier with 6 providers + libcurl
  hardening), M8.1 (verify-endpoint hardening), M9.1/.2/.3
  (decision log + SHM counters + Prometheus), M10.1 (sanitizer
  build) into the tree.
- **M10.4 — Soak test runner + analyzer** (later ported to pytest
  in M11.7).
- **M11.1 — Tests/ framework skeleton** + 4 ported tests.
- **M11.2 — Per-milestone gates** ported into `tests/integration`.
- **M11.3 — Acceptance flows**, remaining provider ports, CI hook.
- **M11.4 — Pytest framework foundation** + 3 migrated POC tests.

### Fixed
- M11.3 review fixes: truth-in-advertising; `tests/run` false-pass
  hole.
- Stale `BotShieldCookieTTL` default in directive help.
- Muddled cookie-outcomes comment from M4b.

### Docs
- README section on deploying behind a reverse proxy.

---

## 2026-04-21

### Added
- **M0 — Skeleton.** Module builds, loads, reads config.
  `BotShieldDebug On` returns 403 "Hello World" to prove the hook
  fires.
- **M1 — Baseline challenge widget.** Self-contained HTML
  interstitial (inline CSS, JS, Guardian SVG; zero external
  assets). Client-side SHA-256 PoW with visible progress.
  Asset-extension pass-through. Chrome toggles for the verification
  widget customization.
- MIT LICENSE + README.
