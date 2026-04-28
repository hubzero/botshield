/* policy.c — request-time policy walker.
 *
 * Implements bs_check_policy, the orchestrator that runs operator-
 * configured policy families against the request in fixed order
 * before bs_handler falls through to score-based tier selection.
 * See policy.h for the family ordering and return-code contract.
 *
 * The matchers / action engines for each family live in their own
 * feature files (triggers.c, robots.c, etc.); this file owns only
 * the walk + the rate-limit / cohort-match local helpers. */
#include <string.h>
#include <strings.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_atomic.h>
#include <apr_time.h>

#include "botshield.h"
#include "allowlist.h"   /* bs_allow_ip_in_ranges (cohort match) */
#include "cookie.h"      /* bs_parse_cookies_once */
#include "load.h"        /* bs_load_current */
#include "metrics.h"     /* bs_set_trigger_tag */
#include "policy.h"
#include "robots.h"      /* bs_path_match, robots_query, robots_match */
#include "score.h"       /* bs_score_add */
#include "shm.h"         /* bs_shm.metrics, rate_counters, strike helpers */
#include "triggers.h"    /* bs_apply_trigger_action, bs_cookie_pred_match */

/* Cohort match at request time. Returns 1 when this request belongs
 * to the cohort. UA match is case-insensitive via strcasestr to
 * match the directive's documented contract. strcasestr is a GNU
 * extension, already relied on elsewhere in the module on the
 * platforms we target (Linux/FreeBSD/macOS). */
static int bs_cohort_matches(const bs_cohort *c,
                             const char *ua, request_rec *r)
{
    if (!c->ua_any) {
        if (!ua || !c->ua_pattern || !strcasestr(ua, c->ua_pattern)) return 0;
    }
    if (!c->ip_any) {
        if (!c->ranges || !bs_allow_ip_in_ranges(c->ranges, r)) return 0;
    }
    return 1;
}

/* Fixed-window admission test. Returns 1 if the request fits under
 * budget (count was incremented), 0 if the window is full.
 *
 * Under pathological contention the CAS loop bounces; cap the retry
 * count and err on admitting rather than emitting spurious 429s.
 *
 * Security review MEDIUM #4 — the prior shape did the window-roll
 * via two separate stores (CAS window_start_sec, then plain
 * __atomic_store_n on count = 1). Between those two operations,
 * another thread could land an increment via the bottom-of-loop
 * count-CAS path; the count=1 store then wiped that increment,
 * yielding a slightly-larger-than-budget window straddling the
 * rollover. Pack window_start_sec and count into a single u64 and
 * CAS them together — same shape as bs_cv_counter_bump. The
 * struct is already laid out 8-byte-packed for this. Each CAS
 * either rolls the window AND sets count atomically, or
 * increments count alone — no torn intermediate visible to
 * other threads. */
static int bs_rate_counter_admit(bs_rate_counter *slot,
                                 apr_uint32_t budget,
                                 apr_uint32_t window_sec)
{
    _Static_assert(sizeof(bs_rate_counter) == sizeof(apr_uint64_t),
                   "bs_rate_counter must be 8 bytes for u64 CAS");
    apr_uint64_t *p64 = (apr_uint64_t *)slot;
    apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
    for (int i = 0; i < 32; i++) {
        apr_uint64_t observed = __atomic_load_n(p64, __ATOMIC_RELAXED);
        bs_rate_counter snap;
        memcpy(&snap, &observed, sizeof(snap));
        apr_uint64_t next;
        bs_rate_counter cand;
        if (now < snap.window_start_sec ||
            now - snap.window_start_sec >= window_sec) {
            cand.count            = 1;
            cand.window_start_sec = now;
        } else {
            if (snap.count >= budget) return 0;
            cand.count            = snap.count + 1;
            cand.window_start_sec = snap.window_start_sec;
        }
        memcpy(&next, &cand, sizeof(next));
        if (__atomic_compare_exchange_n(p64, &observed, next,
                0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            return 1;
        }
        /* CAS lost — re-read */
    }
    return 1;
}

/* Is this UA a plausible crawler for the purpose of applying
 * robots.txt User-agent: * rules in heuristic mode? See PLAN.md for
 * the rationale — the point is to avoid rate-limiting or blocking
 * real users' browsers, which never read robots.txt and so should
 * never be subject to its rules. */
static int bs_ua_is_crawler_candidate(const char *ua)
{
    if (!ua || !*ua) return 0;

    int has_bot_token =
           strcasestr(ua, "bot")    != NULL
        || strcasestr(ua, "crawl")  != NULL
        || strcasestr(ua, "spider") != NULL
        || strcasestr(ua, "fetch")  != NULL
        || strcasestr(ua, "slurp")  != NULL;
    if (has_bot_token) return 1;

    /* Bot-less UA that starts with a real-browser prefix: skip.
     * Everything else (curl/python/etc.) defaults to candidate —
     * those tools are used by scrapers and rarely by humans. */
    static const char *const browser_prefixes[] = {
        "Mozilla/", "Opera/", "Firefox/", "Edge/", "Safari/", NULL
    };
    for (int i = 0; browser_prefixes[i]; i++) {
        apr_size_t plen = strlen(browser_prefixes[i]);
        if (strncasecmp(ua, browser_prefixes[i], plen) == 0) return 0;
    }
    return 1;
}

/* BS_CK_STATE_NOTE / _VERIFIED / _MISSING / _INVALID are now
 * declared cross-file in botshield.h — set by bs_handler after the
 * `_bs_verified` verification pass; consumed by triggers.c's
 * cookie-trigger evaluator and by bs_check_policy below. */


/* Request-time E2.1 + E2.2 + E3 + E4 + E6 check. Return values:
 *   OK                     — no rule fired; continue to heuristics.
 *   DECLINED               — a trigger with status=pass fired; the
 *                            bs_handler short-circuits to DECLINED
 *                            so the real handler runs, with the
 *                            flag-IP / log side effects already
 *                            applied.
 *   any other HTTP_* code  — short-circuit with that status. The
 *                            handler returns it directly so Apache's
 *                            ErrorDocument machinery can render the
 *                            response body.
 *
 * Order:
 *   1. E4 cookie triggers (declaration order; pass accumulates,
 *      first non-pass short-circuits).
 *   2. E6 env-var triggers (declaration order, first match wins).
 *   3. E3 path triggers (declaration order, first match wins).
 *   4. Directive block_paths (declaration order, first match wins).
 *   5. robots.txt Disallow (if configured).
 *   6. Directive rate_limits.
 *   7. robots.txt Crawl-delay (if configured).
 *
 * Cookie triggers run first so reputation signals always land on
 * the decision log, even when a later rule short-circuits. Env
 * triggers run next — another reputation/policy shape driven by
 * upstream Apache modules (SetEnvIf / ModSecurity / etc.). Path
 * triggers are the most specific per-path intent the operator
 * can write — a trigger on `/.env` should win against any
 * cohort-scoped block-path that also happens to match. Operator
 * directives always get first say in each family after that;
 * robots.txt fills in where the operator hasn't declared
 * explicit rules.
 *
 * Precedence divergences from E3 (strict first-match-wins, no
 * accumulation) worth keeping straight:
 *  - E4 cookies: credit/penalty always apply (even under
 *    status=pass); pass matches accumulate across triggers;
 *    first non-pass trigger short-circuits the walk.
 *  - E6 env: credit/penalty always apply (E4-style), but the
 *    family uses strict first-match-wins — a pass match ends
 *    the env-trigger loop without considering later entries. */
int bs_check_policy(request_rec *r)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg) return OK;

    /* E4 — cookie triggers. Declaration order; **pass triggers
     * accumulate, first non-pass trigger short-circuits the walk**.
     * That split exists to make the canonical layered-reputation
     * pattern work — `app-session credit=15` + `app-auth
     * credit=40` should stack to a 55-point credit when both
     * cookies are present, not lose the second credit to first-
     * match-wins. Contrast E3 path triggers, which are strict
     * first-match-wins with no accumulation: paths are one-off
     * matches, cookies are ongoing-state signals that naturally
     * compose.
     *
     * Runs before E3 path triggers so reputation signals land on
     * the decision log even when a later rule short-circuits.
     *
     * Divergences from E3 to keep straight while reading this loop:
     *  1. credit/penalty apply regardless of status (even under
     *     status=pass, because the cookie IS this request's state).
     *  2. pass matches don't end the walk — they accumulate. */
    if (scfg->cookie_triggers && scfg->cookie_triggers->nelts > 0) {
        apr_table_t *cmap = bs_parse_cookies_once(r);
        const char *bs_state = apr_table_get(r->notes, BS_CK_STATE_NOTE);
        for (int i = 0; i < scfg->cookie_triggers->nelts; i++) {
            bs_cookie_trigger_entry *c = APR_ARRAY_IDX(
                scfg->cookie_triggers, i, bs_cookie_trigger_entry *);
            if (!bs_cookie_pred_match(c, cmap, scfg->session_names,
                                      bs_state)) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_COOKIE, &c->action,
                "cookie-trigger", c->name);
            /* Cookie family: BS_TEXEC_PASS_CONTINUE keeps accumulating
             * credits; BS_TEXEC_STATUS short-circuits. PASS_BREAK /
             * PASS_DECLINE aren't produced for this family. */
            if (o == BS_TEXEC_STATUS) return c->action.status_code;
        }
    }

    /* E6 — env-var triggers. Declaration order, first match wins.
     * Gate: once per client-visible request. `ap_is_initial_req` is
     * (r->main == NULL && r->prev == NULL) per httpd's protocol.c,
     * which both excludes subrequests (where producer env
     * propagation differs) and blocks re-application on internal-
     * redirect legs (ErrorDocument, RewriteRule-without-R) where
     * the env producer would fire a second time and double-count
     * score/flag. The header docs only advertise the main-vs-
     * subrequest distinction, so we restate the full intent here.
     * Reads r->subprocess_env, the table SetEnvIf / RewriteRule
     * [E=...] / BrowserMatch / ModSecurity v2 setenv all populate
     * at phases that run before the handler. */
    if (ap_is_initial_req(r)
        && scfg->env_triggers && scfg->env_triggers->nelts > 0) {
        for (int i = 0; i < scfg->env_triggers->nelts; i++) {
            bs_env_trigger_entry *t = APR_ARRAY_IDX(
                scfg->env_triggers, i, bs_env_trigger_entry *);
            const char *v = apr_table_get(r->subprocess_env,
                                          t->env_name);
            int matched = 0;
            switch (t->pred_kind) {
            case BS_EP_NAMED_PRESENT:
                matched = (v != NULL);
                break;
            case BS_EP_NAMED_ABSENT:
                matched = (v == NULL);
                break;
            case BS_EP_NAMED_EQ:
                matched = (v != NULL
                        && t->env_value != NULL
                        && strcmp(v, t->env_value) == 0);
                break;
            }
            if (!matched) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_ENV, &t->action,
                "env-trigger", t->name);
            /* Env family: BS_TEXEC_PASS_BREAK ends the loop (env
             * signals are discrete; no accumulation). STATUS
             * short-circuits. */
            if (o == BS_TEXEC_STATUS) return t->action.status_code;
            if (o == BS_TEXEC_PASS_BREAK) break;
        }
    }

    /* E11.2 — load triggers. Match on the global cached load state
     * (BS_LOAD_NORMAL/WARM/HOT). First-match-wins; alternative-
     * specificity rules (state>=warm vs state=hot) are stacked by
     * declaration order with the more specific one declared first. */
    if (scfg->load_triggers && scfg->load_triggers->nelts > 0) {
        bs_load_state cur = bs_load_current();
        for (int i = 0; i < scfg->load_triggers->nelts; i++) {
            bs_load_trigger_entry *t = APR_ARRAY_IDX(
                scfg->load_triggers, i, bs_load_trigger_entry *);
            int matched = 0;
            switch (t->pred_kind) {
            case BS_LP_EQ: matched = (cur == t->target_state); break;
            case BS_LP_GE: matched = (cur >= t->target_state); break;
            }
            if (!matched) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_LOAD, &t->action,
                "load-trigger", t->name);
            if (o == BS_TEXEC_STATUS) return t->action.status_code;
            if (o == BS_TEXEC_PASS_BREAK) break;
        }
    }

    /* E3 — path triggers. First match wins; no accumulation. */
    if (scfg->path_triggers && scfg->path_triggers->nelts > 0) {
        for (int i = 0; i < scfg->path_triggers->nelts; i++) {
            bs_path_trigger_entry *t = APR_ARRAY_IDX(
                scfg->path_triggers, i, bs_path_trigger_entry *);
            if (!bs_path_match(t->path_pattern, r->uri)) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_PATH, &t->action,
                "path-trigger", t->name);
            /* Path family: PASS decays to DECLINED (handler lets
             * the real Apache response through); STATUS emits
             * Location/code short-circuit. CONTINUE/BREAK aren't
             * produced for this family. */
            if (o == BS_TEXEC_PASS_DECLINE) return DECLINED;
            if (o == BS_TEXEC_STATUS)       return t->action.status_code;
        }
    }

    const char *ua = apr_table_get(r->headers_in, "User-Agent");

    /* Block paths first: if the request would be 403ed anyway there's
     * no point charging it a token from a rate bucket it's also in.
     * Ordered-array iteration — first match wins; declaration order
     * is the precedence. E12: a matched rule in observe mode (or
     * any matched rule when global shadow_mode is on) logs
     * `would-block-path:<name>` instead of returning 403, and the
     * walk continues so subsequent rules still get their say. */
    int global_shadow = (scfg->shadow_mode == 1);
    if (scfg->block_paths && scfg->block_paths->nelts > 0) {
        for (int i = 0; i < scfg->block_paths->nelts; i++) {
            bs_block_path_entry *e = APR_ARRAY_IDX(
                scfg->block_paths, i, bs_block_path_entry *);
            if (!bs_path_match(e->path_pattern, r->uri)) continue;
            if (!bs_cohort_matches(&e->cohort, ua, r)) continue;
            int observe = global_shadow || (e->mode == BS_TMODE_OBSERVE);
            if (observe) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "block-path:", e->name,
                                ":observe", NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->block_path_observed_total,
                        1, __ATOMIC_RELAXED);
                }
                continue;
            }
            bs_score_add(r, BS_PENALTY_BLOCK_PATH, 3600,
                apr_pstrcat(r->pool, "block-path:", e->name, NULL));
            if (bs_shm.metrics) {
                __atomic_fetch_add(&bs_shm.metrics->block_path_hit_total,
                                   1, __ATOMIC_RELAXED);
            }
            return HTTP_FORBIDDEN;
        }
    }

    /* E2.2 — robots.txt Disallow enforcement. Queried once for
     * (ua, path); the result also carries the Crawl-delay we'll use
     * below, so stash it.
     *
     * Atomic load of scfg->robots so we never see a half-swapped
     * state bundle. The bundle's fields are immutable after publish,
     * and the previous bundle is held one refresh cycle before its
     * pool is reclaimed — see bs_robots_refresh. */
    bs_robots_state *rstate =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    robots_match rmatch = { -1, 0, 1, 0, NULL };
    int robots_apply = 0;
    if (rstate && rstate->doc && ua) {
        robots_query(rstate->doc, ua, r->uri, &rmatch);
        if (rmatch.group_idx >= 0) {
            robots_apply = 1;
            if (rmatch.is_wildcard) {
                switch (scfg->robots_wildcard_scope) {
                case BS_ROBOTS_WILDCARD_OFF:
                    robots_apply = 0;
                    break;
                case BS_ROBOTS_WILDCARD_HEURISTIC:
                    if (!bs_ua_is_crawler_candidate(ua)) robots_apply = 0;
                    break;
                case BS_ROBOTS_WILDCARD_STRICT:
                default:
                    /* apply regardless */
                    break;
                }
            }
        }
    }
    if (robots_apply && !rmatch.allowed) {
        bs_score_add(r, BS_PENALTY_BLOCK_PATH, 3600,
            apr_pstrcat(r->pool, "robots-block:",
                        rmatch.group_name ? rmatch.group_name : "?", NULL));
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->block_path_hit_total,
                               1, __ATOMIC_RELAXED);
        }
        return HTTP_FORBIDDEN;
    }

    /* A directive rate-limit cohort that MATCHES this request is
     * authoritative for it — operator policy overrides robots.txt in
     * the rate-limit family. If a directive matched, we skip the
     * robots.txt crawl-delay check below regardless of whether the
     * directive admitted or tripped. */
    int directive_rate_matched = 0;
    if (scfg->rate_limits && scfg->rate_limits->nelts > 0) {
        bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
        unsigned char client_ip[16];
        int have_ip = bs_parse_client_ip(r->useragent_ip, client_ip);
        if (have_ip) bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
        apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
        for (int i = 0; i < scfg->rate_limits->nelts; i++) {
            bs_rate_limit_entry *e = APR_ARRAY_IDX(
                scfg->rate_limits, i, bs_rate_limit_entry *);
            if (!bs_cohort_matches(&e->cohort, ua, r)) continue;
            directive_rate_matched = 1;
            if (e->shm_slot < 0 || !counters) continue;

            /* E12 — observe mode (per-rule or global shadow_mode).
             * The counter still ticks (so `would-rate-limit` volume
             * answers the operator's "what would this fire?"
             * question accurately), but over-budget hits log
             * `rate-limit-exceeded:<name>:observe` instead of
             * returning 429. E9 escalation is also fully suppressed
             * — we don't bump strikes, and any pre-existing
             * escalation state is ignored for this rule under
             * observe. */
            int observe = global_shadow || (e->mode == BS_TMODE_OBSERVE);

            if (!observe && e->escalate && have_ip
                && bs_strike_check_escalated(client_ip,
                                             (apr_uint32_t)e->shm_slot,
                                             now_t, scfg->ns_id)) {
                /* E9 — escalation gate. Active only outside observe
                 * mode; observe must not enforce. */
                bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                    apr_pstrcat(r->pool, "rate-limit-abuse:",
                                e->name, NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_exceeded_total,
                        1, __ATOMIC_RELAXED);
                }
                return e->escalate->status_code;
            }

            if (bs_rate_counter_admit(&counters[e->shm_slot],
                                      e->budget, e->window_sec)) {
                continue;
            }
            /* Over budget. */
            if (observe) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "rate-limit-exceeded:",
                                e->name, ":observe", NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_observed_total,
                        1, __ATOMIC_RELAXED);
                }
                continue;
            }
            /* Enforce: Retry-After = seconds remaining in window. */
            apr_uint32_t win = __atomic_load_n(
                &counters[e->shm_slot].window_start_sec, __ATOMIC_RELAXED);
            apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
            apr_uint32_t retry = (now >= win && now - win < e->window_sec)
                                  ? e->window_sec - (now - win) : 1;
            apr_table_setn(r->err_headers_out, "Retry-After",
                apr_psprintf(r->pool, "%u", retry));
            bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                apr_pstrcat(r->pool, "rate-limit-exceeded:",
                            e->name, NULL));
            if (bs_shm.metrics) {
                __atomic_fetch_add(&bs_shm.metrics->rate_limit_exceeded_total,
                                   1, __ATOMIC_RELAXED);
            }
            /* E9 — strike accounting. Record this 429 under the
             * (ip, rule) entry; if the strike count crosses the
             * threshold inside the per-window, log the operator's
             * tag once for fail2ban handoff. The threshold-crossing
             * request itself returns 429; subsequent ones promote
             * to status_code via bs_strike_check_escalated above. */
            if (e->escalate && have_ip) {
                int crossed = bs_strike_record_429(r, client_ip,
                    (apr_uint32_t)e->shm_slot,
                    e->escalate->per_sec, e->escalate->strikes,
                    e->escalate->ttl_sec,
                    now_t, scfg->ns_id);
                if (crossed) {
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                        "mod_botshield: rate-limit-abuse threshold "
                        "crossed for '%s' from ip=%s; escalating to "
                        "status=%d for %ds%s%s%s",
                        e->name, r->useragent_ip,
                        e->escalate->status_code, e->escalate->ttl_sec,
                        e->escalate->log_tag ? " tag=\"" : "",
                        e->escalate->log_tag ? e->escalate->log_tag : "",
                        e->escalate->log_tag ? "\"" : "");
                    bs_set_trigger_tag(r, e->escalate->log_tag);
                }
            }
            return HTTP_TOO_MANY_REQUESTS;
        }
    }

    /* E2.2 — robots.txt Crawl-delay enforcement. Budget=1 per
     * Crawl-delay seconds; slot assignment is held inside rstate's
     * bundle (allocated at post_config + preserved by name across
     * refreshes). Skipped when a directive rate-limit already
     * matched this request: operator policy is authoritative in the
     * rate family. */
    if (robots_apply && rmatch.crawl_delay_sec > 0
        && !directive_rate_matched
        && rstate && rstate->slot_by_group_idx
        && rmatch.group_idx < robots_group_count(rstate->doc)) {
        int slot_idx = rstate->slot_by_group_idx[rmatch.group_idx];
        bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
        if (slot_idx >= 0 && counters) {
            bs_rate_counter *slot = &counters[slot_idx];
            if (!bs_rate_counter_admit(slot, 1,
                    (apr_uint32_t)rmatch.crawl_delay_sec)) {
                apr_uint32_t win = __atomic_load_n(
                    &slot->window_start_sec, __ATOMIC_RELAXED);
                apr_uint32_t now =
                    (apr_uint32_t)apr_time_sec(apr_time_now());
                apr_uint32_t wsec =
                    (apr_uint32_t)rmatch.crawl_delay_sec;
                apr_uint32_t retry = (now >= win && now - win < wsec)
                                      ? wsec - (now - win) : 1;
                apr_table_setn(r->err_headers_out, "Retry-After",
                    apr_psprintf(r->pool, "%u", retry));
                bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                    apr_pstrcat(r->pool, "robots-rate:",
                        rmatch.group_name ? rmatch.group_name : "?",
                        NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_exceeded_total,
                        1, __ATOMIC_RELAXED);
                }
                return HTTP_TOO_MANY_REQUESTS;
            }
        }
    }

    return OK;
}

/* ======================================================================
 * E2.2.3 — /botshield/policy-status
 *
 * Plain-text dump of the rules currently being enforced:
 *   - BotShieldRateLimit directives (directive rate_limits array).
 *   - BotShieldBlockPath directives (directive block_paths array).
 *   - robots.txt-derived groups (if BotShieldRobotsTxt is set) —
 *     source file path, mtime, every group's UA tokens + rules +
 *     Crawl-delay.
 *
 * Goal is operator-visibility: when E2.2.2 hot-swaps a freshly-edited
 * robots.txt, operators can curl this page to confirm what the module
 * is actually enforcing, rather than guessing. Also useful for
 * verifying that `BotShieldAllow` overrides have landed.
 *
 * No authentication / no rate limit built in. Treat like mod_status —
 * operators wrap it in `<Location>` with their own ACL. The page
 * doesn't reveal cookie secrets or client IPs; the most sensitive
 * content is the operator's own directive config, which is already
 * on disk in /etc/apache2/.
 *
 * Format is plain text (not Prometheus) — this is meant to be read
 * by humans over curl; structured consumers use /botshield/metrics.
 * ====================================================================== */

static void bs_psh_cohort_ipspec(request_rec *r, const bs_cohort *c)
{
    if (c->ip_any) { ap_rputs("*", r); return; }
    if (c->inline_cidrs) {
        ap_rprintf(r, "inline(%s)", c->inline_cidrs);
        return;
    }
    if (c->path) {
        ap_rprintf(r, "file(%s)", c->path);
        return;
    }
    ap_rprintf(r, "<%d ranges>", c->ranges ? c->ranges->nelts : 0);
}

static void bs_psh_render_counter(request_rec *r, int slot_idx,
                                  apr_uint32_t budget)
{
    bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
    if (slot_idx < 0 || !counters) {
        ap_rputs("-/-", r);
        return;
    }
    apr_uint32_t cnt = __atomic_load_n(&counters[slot_idx].count,
                                       __ATOMIC_RELAXED);
    ap_rprintf(r, "%u/%u", cnt, budget);
}

int bs_policy_status_handler(request_rec *r, bs_dir_cfg *cfg)
{
    (void)cfg;
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }
    ap_set_content_type(r, "text/plain; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    if (!scfg) {
        ap_rputs("# scfg unavailable\n", r);
        return OK;
    }

    char tbuf[APR_RFC822_DATE_LEN + 1] = { 0 };
    apr_rfc822_date(tbuf, apr_time_now());
    ap_rprintf(r, "# mod_botshield policy status\n"
                  "# vhost:       %s\n"
                  "# server_time: %s\n\n",
        r->server->server_hostname ? r->server->server_hostname : "-",
        tbuf);

    /* --- directive rate limits --- */
    ap_rputs("## BotShieldRateLimit (directive)\n", r);
    if (!scfg->rate_limits || scfg->rate_limits->nelts == 0) {
        ap_rputs("# (none)\n\n", r);
    } else {
        ap_rputs("# name               budget  window  ua                          "
                 "ipspec                slot  count/budget\n", r);
        for (int i = 0; i < scfg->rate_limits->nelts; i++) {
            bs_rate_limit_entry *e = APR_ARRAY_IDX(
                scfg->rate_limits, i, bs_rate_limit_entry *);
            ap_rprintf(r, "%-18s  %6u  %4us   %-26s  ",
                e->name, e->budget, e->window_sec,
                e->cohort.ua_any ? "*"
                    : apr_psprintf(r->pool, "\"%s\"", e->cohort.ua_pattern));
            bs_psh_cohort_ipspec(r, &e->cohort);
            ap_rprintf(r, "%*s  %4d  ",
                       (int)(22 - (e->cohort.ip_any ? 1
                          : (int)(strlen("file()") + (e->cohort.path ? strlen(e->cohort.path) : 0)
                                  + (e->cohort.inline_cidrs ? strlen(e->cohort.inline_cidrs) : 0)))),
                       "", e->shm_slot);
            bs_psh_render_counter(r, e->shm_slot, e->budget);
            ap_rputs("\n", r);
        }
        ap_rputs("\n", r);
    }

    /* --- directive block paths --- */
    ap_rputs("## BotShieldBlockPath (directive)\n", r);
    if (!scfg->block_paths || scfg->block_paths->nelts == 0) {
        ap_rputs("# (none)\n\n", r);
    } else {
        ap_rputs("# name               path-glob                     "
                 "ua                          ipspec\n", r);
        for (int i = 0; i < scfg->block_paths->nelts; i++) {
            bs_block_path_entry *e = APR_ARRAY_IDX(
                scfg->block_paths, i, bs_block_path_entry *);
            ap_rprintf(r, "%-18s  %-28s  %-26s  ",
                e->name, e->path_pattern,
                e->cohort.ua_any ? "*"
                    : apr_psprintf(r->pool, "\"%s\"", e->cohort.ua_pattern));
            bs_psh_cohort_ipspec(r, &e->cohort);
            ap_rputs("\n", r);
        }
        ap_rputs("\n", r);
    }

    /* --- robots.txt --- */
    ap_rputs("## robots.txt (BotShieldRobotsTxt)\n", r);
    if (!scfg->robots_txt_path) {
        ap_rputs("# (not configured)\n", r);
        return OK;
    }
    bs_robots_state *rs =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    ap_rprintf(r, "# path:                %s\n", scfg->robots_txt_path);
    if (!rs) {
        ap_rputs("# status:              not loaded (parse failed or "
                 "file missing at post_config)\n", r);
        return OK;
    }
    char mbuf[APR_RFC822_DATE_LEN + 1] = { 0 };
    apr_rfc822_date(mbuf, rs->mtime);
    ap_rprintf(r, "# mtime:               %s\n"
                  "# groups:              %d\n"
                  "# slot pool:           %d/%d used\n"
                  "# wildcard scope:      %s\n"
                  "# refresh interval:    %d s%s\n",
        mbuf,
        robots_group_count(rs->doc),
        scfg->robots_slot_pool_used, scfg->robots_slot_pool_size,
        scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_STRICT ? "strict"
          : scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_OFF ? "off"
          : "heuristic",
        scfg->robots_refresh_interval,
        scfg->robots_refresh_interval == 0 ? " (live-refresh disabled)" : "");

    int n = robots_group_count(rs->doc);
    for (int i = 0; i < n; i++) {
        ap_rprintf(r, "\n### group[%d] \"%s\"  wildcard=%s\n", i,
            robots_group_name_at(rs->doc, i),
            robots_group_is_wildcard_at(rs->doc, i) ? "yes" : "no");
        int n_ua = robots_group_ua_count_at(rs->doc, i);
        for (int u = 0; u < n_ua; u++) {
            ap_rprintf(r, "  user-agent: %s\n",
                robots_group_ua_at(rs->doc, i, u));
        }
        int n_rules = robots_group_rule_count_at(rs->doc, i);
        for (int k = 0; k < n_rules; k++) {
            const char *pat = NULL;
            int allow = 0;
            if (robots_group_rule_at(rs->doc, i, k, &pat, &allow)) {
                ap_rprintf(r, "  %-9s %s\n",
                    allow ? "Allow:" : "Disallow:", pat ? pat : "");
            }
        }
        int cd = robots_group_crawl_delay_at(rs->doc, i);
        if (cd > 0) {
            int slot = (rs->slot_by_group_idx && i < n)
                     ? rs->slot_by_group_idx[i] : -1;
            ap_rprintf(r, "  Crawl-delay: %ds  slot=%d  ", cd, slot);
            bs_psh_render_counter(r, slot, 1);
            ap_rputs("\n", r);
        }
    }
    return OK;
}
