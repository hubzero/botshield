# Review tracker

Per-extension review status. Earlier extensions (E1–E9) were reviewed
by an external AI reviewer. Extensions E10+ will be self-reviewed by
Claude until/unless an external reviewer is available again.

**Self-review caveat:** reviewing one's own code introduces
confirmation bias — the reviewer already understands why the code
looks the way it does, which makes them less likely to question
shapes a fresh reader would push back on. Self-reviews are *better
than nothing* but should not be treated as having caught the same
class of issues an independent reviewer would. The hardening phase
should weight self-reviewed extensions accordingly: more aggressive
fuzzing, broader test scenarios, tighter security-review skill
application.

## Reviewed

| Extension | Reviewer  | Outcome | Findings |
|-----------|-----------|---------|----------|
| E1        | external (high-confidence) | issues found | shipped — see commit `8c104e8` |
| E2.1      | external (high-confidence) | issues found | shipped — see commit `72d4594` |
| E2.2      | external (high-confidence) | issues found | shipped — see commit `2e93674` |
| E3        | (implicit) | — | rewritten by E7 normalization; covered by E7 review |
| E4        | external (high-confidence) | issues found | shipped — see commit `abdf087` |
| E5        | external (high-confidence) | issues found | shipped — see commit `ce65f42` |
| E6        | external (high-confidence) | issues found | shipped — see commit `ad360ca` |
| E7 (.1/.2/.3) | Gemini 3.1 Pro Preview, 2026-04-26 | **low-confidence "clean"** | pure praise, no findings — see "Gemini-3.1-Pro caveat" below |
| E8.1      | Gemini 3.1 Pro Preview, 2026-04-26 | **low-confidence "clean"** | pure praise, no findings — see caveat |
| E8.2      | Gemini 3.1 Pro Preview, 2026-04-26 | **low-confidence "clean"** | pure praise, no findings — see caveat |
| E9        | Gemini 3.1 Pro Preview, 2026-04-26 | **low-confidence "clean"** | pure praise + one optional observation — see caveat |
| E10       | Gemini 3.1 Pro Preview, 2026-04-26 | one real finding | metrics-vocabulary bug fixed: `tier="safeguard"` was unrecognized by `bs_m_tier_idx`, causing every safeguard activation to drop a metric increment with a WARNING. Fix: alias `"safeguard"` → `BS_M_TIER_PASS` in the metrics index (decision-log line stays distinct, metric counter binned to pass). Recovers credibility for the Gemini reviewer relative to E7-E9. |
| E11 (E11.1+E11.2) | Gemini 3.1 Pro Preview + self-audit, 2026-04-26 | one real finding (self-audit) | Gemini returned pure praise; self-audit caught a vhost-propagation gap: `BotShieldLoadWarmRise` / `LoadHotRise` / `LoadNormalFall` directives, when set inside `<VirtualHost>`, parsed and merged into the vhost's cfg but were silently ignored at watchdog time because the post-config propagation loop only copied the first four load fields (state-file, refresh-sec, warm-pct, hot-pct) up to main_scfg. Hysteresis fields stayed zero, compiled defaults applied. Fix: extend the propagation loop to include all three hysteresis fields. |
| E12       | Gemini 3.1 Pro Preview + self-audit, 2026-04-26 | one real finding (self-audit) | Gemini returned pure praise; self-audit caught a cross-extension regression: E18 (`BotShieldFormCaptcha on`) didn't honor `BotShieldShadowMode on`. E18 was added after E12 and never plumbed through the global shadow flag, so operators staging a full BotShield policy under shadow mode would still see E18's hard-403s on bad/missing tokens — breaking the dry-run mental model. Fix: bs_form_captcha_fixup checks `scfg->shadow_mode == 1` after body-read but before any policy-level decision; if on, installs the body-replay filter and returns DECLINED with a `form-captcha:observe` log line. Transport-level errors (415/413/400/503-misconfigured) intentionally still fire under shadow mode — those are misconfiguration, not policy. |
| E13 (E13.1) | Gemini 3.1 Pro Preview + self-audit, 2026-04-26 | one real finding (self-audit) | Gemini returned pure praise on the architectural claims (which checked out: state-file siphash_key restore order, mutex-protected state_save, per-slot ns_id matching, slot pad alignment). Self-audit caught the same vhost-scope-silently-ignored pattern as E11: `BotShieldStateFile` and `BotShieldStateSaveInterval` accept `RSRC_CONF` (main + vhost), but only `main_scfg`'s value is read at post_config — operators dropping these inside `<VirtualHost>` (where the rest of BotShield's directives naturally live) get silent no-ops. Fix: apply `bs_warn_if_virtual_scope` to both setters, same pattern as the SHM-sizing directives. Operators now get a clear NOTICE telling them to move the directive to the main server scope. |
| E14       | Gemini 3.1 Pro Preview + self-audit, 2026-04-26 | two findings (one Gemini, one self-audit) | (1) Gemini caught config-stickiness across `apachectl graceful`: the global `bs_flag_metadata` array is mutated in place by `BotShieldFlag` directives but never reset between config passes. Removing a directive line + graceful-reload would silently keep the prior mutation in memory. Fix: pristine `bs_flag_metadata_defaults` constant + `bs_flag_meta_reset_to_defaults()` helper called from `bs_create_server_cfg` for the main server. (2) Self-audit caught a cross-extension gap: E14's adaptive difficulty was wired into the M7 issue path but NOT into the E17 embedded-bootstrap PoW path. A flagged-IP client visiting an embedded-mode page would get the baseline-difficulty challenge, not the adaptive-bumped one. Fix: the bootstrap now does flag lookup (IP-side via flagged-IP table, cookie-side via prior_ch parse) and applies the same clamp-against-MaxDifficulty logic as M7. |

### Gemini-3.1-Pro caveat

The Gemini 3.1 Pro Preview reviews of E7, E8.1, E8.2, and E9 returned
zero findings across substantial new C code with concurrency, AES-GCM
crypto, HMAC, SHM tables, and request-body inspection. A real review
of code that complex almost always surfaces *something* — at minimum
comment drift, misleading variable names, error-path resource
handling, or "have you considered…" questions. Pure unqualified praise
across all four reviews is a smell.

Possible explanations: Gemini wasn't a good fit for this codebase, the
prompt was too laudatory, the model defaulted to flattery on a hard
target, or the codebase happens to be unusually clean. The first three
are more likely than the fourth.

**Treat E7, E8.1, E8.2, E9 as effectively unreviewed for hardening
purposes** — a real review pass should hit them too. Move them down
the priority list (they're less urgent than the truly-unreviewed E10+
because at least one set of eyes saw them) but don't skip them.

## Pending review (priority order)

High priority — load-bearing or new-attack-surface code:

1. ~~**E13 / E13.1** — per-vhost SHM namespacing~~ — reviewed
   2026-04-26 (Gemini + self-audit), one finding (vhost-scope state
   file directives), fixed.
2. **E16** — cookie secret rotation. Multi-key verify on HMAC + GCM
   paths is exactly where timing side-channel or fall-through bugs
   historically appear. Verify constant-time comparison still
   constant-time when cycling through a list. Verify fall-through
   doesn't leak which key matched.
3. **E17** (E17.1, E17.2, E17.3, E17.4a, E17.4b, E17.4c, finish) —
   embedded silent verification. Substantial new attack surface:
   `/embedded-bootstrap`, `/embedded-verify`, `/embedded.js`,
   `/embedded-worker.js`, JSON parsing of attacker-controlled bodies,
   provider dispatch logic. Worth a careful pass.
4. **E18** (E18 v1, E18.3, E18.4) — inline form captcha. Body
   inspection at fixup hook + body-replay filter. Same risk shape as
   mod_security; need to check for body-handling bugs (NUL
   truncation, encoding mismatches, replay correctness across
   handler patterns).

Lower priority — smaller surface, less new attack-surface:

5. ~~**E10** — challenge safeguard~~ — reviewed 2026-04-26 (Gemini),
   one finding, fixed.
6. ~~**E11 / E11.1 / E11.2** — load-aware throttling~~ — reviewed
   2026-04-26 (Gemini + self-audit), one finding, fixed.
7. ~~**E12** — shadow mode / dry-run~~ — reviewed 2026-04-26
   (Gemini + self-audit), one finding (cross-extension regression
   in E18), fixed.
8. ~~**E14** — adaptive challenge intensity~~ — reviewed 2026-04-26
   (Gemini + self-audit), two findings, both fixed.
9. **E15** — forgiveness cap.

Tail — already had a low-confidence review pass; re-review when
covering the high-priority block:

10. **E7** (revisit) — re-review after E13/E16/E17/E18 are real-reviewed.
11. **E8.1** (revisit) — same.
12. **E8.2** (revisit) — same.
13. **E9** (revisit) — same.

## Open observations (non-required)

These are accepted-as-shipped items where a reviewer noted a small
deviation or a "could be improved" point. Tracked here so the
hardening phase has a concrete punch list.

- **E9 — dedicated metric counter.** PLAN E9 suggested an explicit
  `botshield_rate_limit_escalated_total` counter; the implementation
  uses the decision-log reason `rate-limit-abuse:<name>` plus the
  `shm_strike_used` / `shm_strike_capacity` gauges instead. Gemini
  reviewer accepted as adequate observability. **Add the dedicated
  counter only if operators report wanting it for dashboard
  alerting** — currently low value.

## Self-review process

When self-reviewing an extension, work the following checklist before
declaring "looks good":

1. **Read PLAN.md for this extension first.** Catch deliverable gaps
   before reading code (which biases toward "code looks fine").
2. **Re-read the implementing commit message verbatim.** Note any
   "deferred" or "out of scope" items not in the headline plan.
3. **Find every C function added by this extension** via grep.
   Inspect each one for:
   - Bounded input handling (no `atoi` on attacker bytes; use the
     existing `bs_parse_*_bounded` helpers).
   - Lock discipline (mutex held only across SHM writes; reads use
     seqlock).
   - Memory: pool-allocated, no `malloc`/`free`; no raw pointer
     arithmetic past buffer ends.
   - Cleanup: `OPENSSL_cleanse` for stack secrets; pool cleanup
     handlers for resources that outlive a single function.
   - Concurrency: thread-safe under MPM-event; no static mutable
     state outside SHM-or-mutex.
4. **Find every test added by this extension.** Check coverage for:
   - Happy path (positive case).
   - Each error/reject path (negative cases).
   - Edge cases: empty input, max-bound input, unicode, NUL bytes,
     CRLF in inputs.
5. **Check directive surface.** Every new `BotShield*` directive:
   - Has docs (the AP_INIT description string).
   - Rejects malformed values at config time, not request time.
   - Inherits/overrides correctly across server / VirtualHost /
     Location scopes.
6. **Check decision-log integration.** New behaviors should surface
   in the reason chain so operators can debug.
7. **Check metrics surface.** New SHM tables should expose
   `_used` / `_capacity` gauges (E13.1 set the precedent).
8. **List "what would I attack if I were a bot."** Try to defeat
   the new code's claims. Spend at least 5 minutes on adversarial
   thinking before signing off.
9. **Verify E12 (shadow mode) integration** for any new policy
   enforcement — the rule should observe-mode cleanly.
10. **Verify E13 (ns_id) integration** for any new SHM table — slots
    should match on `(ip, ns_id)` for namespace isolation.

After self-review, write findings (or "no findings") into this doc
under the extension's row. If findings are real, ship a review-fix
commit using the same message convention as `E*-review-fix:` /
`E* review fixes:`.
