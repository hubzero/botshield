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
#include "allowlist.h"     /* bs_allow_ip_in_ranges (cohort match) */
#include "bot_rate.h"      /* bs_bot_rate_check */
#include "bot_directory.h" /* bs_ua_is_known_bot (Cloudflare directory) */
#include "browser_classifier.h" /* bs_ua_is_browser (top-100 templates) */
#include "ua_class.h"     /* unified per-request classification */
#include "cookie.h"        /* bs_parse_cookies_once */
#include "load.h"          /* bs_load_current */
#include "metrics.h"       /* bs_set_trigger_tag */
#include "policy.h"
#include "robots.h"        /* bs_path_match, robots_query, robots_match */
#include "score.h"         /* bs_score_add */
#include "shm.h"           /* bs_shm.metrics, rate_counters, strike helpers */
#include "triggers.h"      /* bs_apply_trigger_action, bs_cookie_pred_match */

/* Cohort match at request time. Returns 1 when this request belongs
 * to the cohort. UA axis can be:
 *   ua_any=1              matches any UA            (ua=* or omitted)
 *   ua_none=1             absent or empty UA only   (ua="")
 *   ua_class_bot=1        any real bot   (ua=@bot)
 *   ua_class_fake=1       spoofed bot    (ua=@fake-bot)
 *   ua_botgroup != NULL   matches by classified botgroup
 *                         (search/ai-input/ai-train/monitor)
 *   ua_pattern != NULL    matches by UA-substring (case-insensitive)
 * IP axis: ip_any=1 OR client IP ∈ ranges. */
static int bs_cohort_matches(const bs_cohort *c,
                             const char *ua, request_rec *r)
{
    if (!c->ua_any) {
        if (c->ua_none) {
            /* Absent and present-but-empty are the same thing to a
             * policy author, and both occur in the wild: some clients
             * omit the header, others send "User-Agent:" with nothing
             * after it. Treating them differently would be a trap. */
            if (ua && *ua) return 0;
        } else if (c->ua_class_bot) {
            /* @bot — the classifier says this IS a bot. Verified,
             * known and unknown-bot; NOT fake-bot, which is a client
             * lying about being one and must not inherit an exemption
             * written for real crawlers. Same three the dashboard's
             * Bots tab counts, so policy and reporting agree on who a
             * bot is. */
            const bs_ua_class *cls = bs_classify_request_ua(r);
            if (!cls) return 0;
            if (cls->label != BS_UA_CLASS_VERIFIED_BOT
             && cls->label != BS_UA_CLASS_KNOWN_BOT
             && cls->label != BS_UA_CLASS_UNKNOWN_BOT) return 0;
        } else if (c->ua_class_fake) {
            const bs_ua_class *cls = bs_classify_request_ua(r);
            if (!cls || cls->label != BS_UA_CLASS_FAKE_BOT) return 0;
        } else if (c->ua_botgroup) {
            const bs_ua_class *cls = bs_classify_request_ua(r);
            if (!cls || !cls->known_botgroup) return 0;
            if (strcasecmp(cls->known_botgroup, c->ua_botgroup) != 0) return 0;
        } else if (c->ua_pattern) {
            if (!ua || !strcasestr(ua, c->ua_pattern)) return 0;
        } else {
            return 0;
        }
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
 *  the prior shape did the window-roll
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
int bs_rate_counter_admit(bs_rate_counter *slot,
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

/* Is this UA a plausible crawler for applying robots.txt
 * User-agent: * rules in heuristic mode? Reads the unified
 * classification cached on r->pool by bs_classify_request_hook.
 *
 * Semantics: real-browser template match → not a candidate
 * (browsers don't read robots.txt and shouldn't be subject to
 * its restrictions); everything else (known-bot, fake-bot,
 * verified-bot, unknown — including Mozilla-prefix scrapers
 * with custom appended tokens) defaults to candidate.
 *
 * The bot-token heuristic (bot/crawl/spider/fetch/slurp) was
 * dropped: with ~600-entry AC directory + the strict browser-
 * template check, anything those substrings would catch already
 * lands on the candidate side via the "not a browser" default.
 *
 * Trade-off (unchanged from prior implementation): a brand-new
 * browser entering the top-100 won't match the strict-template
 * check until the runtime template file is refreshed; until then
 * those visitors are misclassified as candidates. The runtime-
 * refresh watchdog bounds that to one refresh interval. */
static int bs_ua_is_crawler_candidate(request_rec *r)
{
    /* Browser fail-safe: if BotShieldClassify -browsers disabled
     * the strict-template pass, treat all UAs as if they were
     * real browsers (not candidates). Otherwise stale templates
     * would silently misclassify real users as candidates and
     * subject them to robots.txt wildcard rules. */
    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    if (scfg && !scfg->classify.browsers) return 0;

    const bs_ua_class *c = bs_classify_request_ua(r);
    return !c->is_browser;
}

/* BS_CK_STATE_NOTE / _VERIFIED / _MISSING / _INVALID are now
 * declared cross-file in botshield.h — set by bs_handler after the
 * `_bs_session` verification pass; consumed by triggers.c's
 * cookie-trigger evaluator and by bs_check_policy below. */


/* Request-time policy check (cookie / env / load / scope / path
 * triggers + robots.txt + rate_limits).
 * Return values:
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
 *   1. Cookie triggers (declaration order; pass accumulates,
 *      first non-pass short-circuits).
 *   2. Env-var triggers (declaration order, first match wins).
 *   3. Load triggers (declaration order, first match wins).
 *   4. Scope triggers — per-Apache-scope BotShieldTrigger entries
 *      (merged-scope order, first match wins).
 *   5. Path triggers (declaration order, first match wins).
 *      A path trigger with `ua=` / `ipspec=` keys ANDs the cohort
 *      match with the path glob; trigger fires only when both match.
 *   6. robots.txt Disallow (if configured).
 *   7. Directive rate_limits.
 *   8. robots.txt Crawl-delay (if configured).
 *
 * Cookie triggers run first so reputation signals always land on
 * the decision log, even when a later rule short-circuits. Env
 * triggers run next — another reputation/policy shape driven by
 * upstream Apache modules (SetEnvIf / ModSecurity / etc.). Load
 * and scope triggers run before path triggers to let global state
 * (server load, per-vhost or per-<Location> scope) gate path-
 * specific rules. Path triggers are the most specific per-path
 * intent the operator can write; robots.txt fills in where the
 * operator hasn't declared explicit rules.
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

    /* BotShieldTrigger — per-Apache-scope triggers. Apache's
     * scope-match has already evaluated; walk the merged dcfg
     * list in declaration order. Each entry's pass continues
     * (multiple BotShieldTriggers in one scope all fire); a
     * status short-circuits the walk. */
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    if (dcfg && dcfg->scope_triggers && dcfg->scope_triggers->nelts > 0) {
        for (int i = 0; i < dcfg->scope_triggers->nelts; i++) {
            bs_trigger_action *a = APR_ARRAY_IDX(
                dcfg->scope_triggers, i, bs_trigger_action *);
            const char *tag = a->log_tag ? a->log_tag : "scope";
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_SCOPE, a,
                "scope-trigger", tag);
            if (o == BS_TEXEC_STATUS) return a->status_code;
            /* PASS_CONTINUE / OBSERVE → keep walking */
        }
    }

    const char *ua = apr_table_get(r->headers_in, "User-Agent");

    /* E3 — path triggers. First match wins; no accumulation. A trigger
     * with `ua=` or `ipspec=` keys carries a populated cohort that
     * ANDs with the path-glob match (path-only triggers leave
     * has_cohort==0 and skip the cohort check). */
    if (scfg->request_triggers && scfg->request_triggers->nelts > 0) {
        /* Cookie map is parsed lazily and only once, and only if some
         * rule actually carries a cookies= condition — the common case
         * (path-only rules) must not pay for it. */
        apr_table_t *rt_cmap = NULL;
        for (int i = 0; i < scfg->request_triggers->nelts; i++) {
            bs_request_trigger_entry *t = APR_ARRAY_IDX(
                scfg->request_triggers, i, bs_request_trigger_entry *);
            /* Every dimension is optional; absent means "no restriction".
             * Ordered cheapest-first: path and query are byte globs, the
             * cohort may hit the UA classifier / CIDR ranges. */
            /* bscookie= : read the verdict bs_handler published to
             * r->notes before this walk. Absent note means the cookie
             * stage has not run for this request, which is not the same
             * as "verified" -- treat it as no match rather than
             * silently passing a rule that asked about proof. */
            if (t->crawler_pred >= 0) {
                const bs_ua_class *uc = bs_classify_request_ua(r);
                if (bs_ua_is_declared_crawler(uc) != t->crawler_pred) {
                    continue;
                }
            }
            if (t->bscookie_pred >= 0) {
                const char *st = apr_table_get(r->notes, BS_CK_STATE_NOTE);
                if (!st) continue;
                int ok;
                switch (t->bscookie_pred) {
                case BS_BSC_VERIFIED:
                    ok = !strcmp(st, BS_CK_STATE_VERIFIED); break;
                case BS_BSC_MISSING:
                    ok = !strcmp(st, BS_CK_STATE_MISSING);  break;
                case BS_BSC_INVALID:
                    ok = !strcmp(st, BS_CK_STATE_INVALID);  break;
                case BS_BSC_ANY_BAD:
                    ok = strcmp(st, BS_CK_STATE_VERIFIED) != 0; break;
                default: ok = 0; break;
                }
                if (!ok) continue;
            }
            if (t->path_patterns) {
                int hit = 0;
                for (int pi = 0; pi < t->path_patterns->nelts; pi++) {
                    if (bs_path_match(APR_ARRAY_IDX(t->path_patterns, pi,
                                                    const char *), r->uri)) {
                        hit = 1; break;
                    }
                }
                if (!hit) continue;
            }
            if (t->query_pattern
                && !bs_path_match(t->query_pattern, r->args ? r->args : ""))
                continue;
            if (t->cookie_pred >= 0) {
                if (!rt_cmap) rt_cmap = bs_parse_cookies_once(r);
                bs_cookie_trigger_entry probe;
                memset(&probe, 0, sizeof(probe));
                probe.pred_kind = t->cookie_pred;
                if (!bs_cookie_pred_match(&probe, rt_cmap,
                                          scfg->session_names, NULL))
                    continue;
            }
            if (t->exists_pred >= 0) {
                /* map_to_storage has already stat()ed for us, so this
                 * is a struct read. filetype is APR_NOFILE when nothing
                 * resolved; a directory counts as existing, which is
                 * what "files or directories that exist" has to mean
                 * for an admin UI whose assets live in real folders.
                 *
                 * Requests the core never resolved to a path at all
                 * (proxied, or answered before map_to_storage) read as
                 * "does not exist" -- correct for exists=no rules,
                 * which are the scanner-facing ones. */
                int have = (r->finfo.filetype != APR_NOFILE);
                if (have != t->exists_pred) continue;
            }
            /* Load axis before the cohort: an atomic read is cheaper
             * than the UA classifier, and under a shed ladder most
             * rules will not be at their level. */
            if (t->minload >= 0 && (int)bs_load_current() < t->minload)
                continue;
            if (t->solved_pred >= 0) {
                const char *sv = apr_table_get(r->notes, BS_CK_SOLVED_NOTE);
                int solved = (sv && *sv == '1');
                if (solved != t->solved_pred) continue;
            }
            if (t->has_cohort && !bs_cohort_matches(&t->cohort, ua, r))
                continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_REQUEST, &t->action,
                "request-trigger", t->name);
            /* Path family: PASS decays to DECLINED (handler lets
             * the real Apache response through); STATUS emits
             * Location/code short-circuit. CONTINUE/BREAK aren't
             * produced for this family. */
            if (o == BS_TEXEC_PASS_DECLINE) return DECLINED;
            if (o == BS_TEXEC_STATUS)       return t->action.status_code;
            /* tier=: the rule asked for a challenge, so the request
             * must reach the scoring pipeline. Keep walking. */
            if (o == BS_TEXEC_PASS_CONTINUE) continue;
        }
    }

    int global_log_only = (dcfg && dcfg->enabled == BS_ENABLED_LOGONLY);

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
        const bs_ua_class *cls_for_robots = bs_classify_request_ua(r);
        const char *robots_botgroup = (cls_for_robots
                                       && cls_for_robots->known_botgroup)
                                    ? cls_for_robots->known_botgroup : NULL;
        robots_query(rstate->doc, ua, robots_botgroup, r->uri, &rmatch);
        if (rmatch.group_idx >= 0) {
            robots_apply = 1;
            if (rmatch.is_wildcard) {
                switch (scfg->robots_wildcard_scope) {
                case BS_ROBOTS_WILDCARD_OFF:
                    robots_apply = 0;
                    break;
                case BS_ROBOTS_WILDCARD_HEURISTIC:
                    if (!bs_ua_is_crawler_candidate(r)) robots_apply = 0;
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
        const char *rgroup = rmatch.group_name ? rmatch.group_name : "?";
        /* Observe mode must not enforce -- the same contract the
         * rate-limit path below has always honoured. Without this,
         * switching BotShieldRobotsTxt on turned every Disallow into a
         * hard 403 even under BotShieldEnabled LogOnly, so there was no
         * way to find out who ignores your robots.txt before starting
         * to refuse them. That is the wrong order for a rule set an
         * operator has often published but never enforced.
         *
         * The score bump and the flag are suppressed too, not just the
         * status: a +100 with a 1-hour TTL would follow the client into
         * later requests and change their tier, which is enforcement by
         * another route. */
        int robots_observe = global_log_only
                          || (scfg && scfg->robots_mode
                                        == BS_ROBOTS_MODE_OBSERVE);
        if (robots_observe) {
            bs_score_add(r, 0, 0,
                apr_pstrcat(r->pool, "robots-block:", rgroup,
                            ":observe", NULL));
            bs_set_would_outcome(r, "~block");
            if (bs_shm.metrics) {
                __atomic_fetch_add(&bs_shm.metrics->trigger_observed_total,
                                   1, __ATOMIC_RELAXED);
            }
        } else {
            /* Robots.txt Disallow → 403 with a +100 score hit and a
             * 1-hour flag, mirroring the deny weight an explicit
             * BotShieldRequestTrigger ... status=403 would carry. */
            bs_score_add(r, 100, 3600,
                apr_pstrcat(r->pool, "robots-block:", rgroup, NULL));
            return HTTP_FORBIDDEN;
        }
    }

    /* A directive rate-limit cohort that MATCHES this request is
     * authoritative for it. (Pre-rekey, this also suppressed the
     * robots.txt Crawl-delay check below; that legacy enforcement
     * has been replaced by bs_bot_rate_check, which absorbs
     * robots.txt and is independent of cohort-based rate limits —
     * the two compose naturally, whichever trips first wins.) */
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
            if (e->shm_slot < 0 || !counters) continue;

            /* E12 — observe mode (per-rule or global log-only).
             * The counter still ticks (so `would-rate-limit` volume
             * answers the operator's "what would this fire?"
             * question accurately), but over-budget hits log
             * `rate-limit-exceeded:<name>:observe` instead of
             * returning 429. E9 escalation is also fully suppressed
             * — we don't bump strikes, and any pre-existing
             * escalation state is ignored for this rule under
             * observe. */
            int observe = global_log_only || (e->mode == BS_TMODE_OBSERVE);

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
                bs_set_would_outcome(r, "~rate_limited");
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

    /* Slug-keyed bot rate limit. Absorbs both BotShieldBotRateLimit
     * directives and robots.txt Crawl-delay groups (the latter
     * resolved to slugs at post_config via the bot directory). The
     * legacy group-index keyed Crawl-delay enforcement was retired
     * here when the rekey landed; bot_rate_check now covers both
     * sources via one slug→counter map. Lookup keys on
     * cls->known_slug or cls->verified_name (then unknown-bot /
     * fake-bot / wildcard-fallback aggregates). Composes with
     * BotShieldRateLimit directive cohorts above: whichever trips
     * first short-circuits the policy walk. */
    {
        int botrate_rv = bs_bot_rate_check(r);
        if (botrate_rv != OK) return botrate_rv;
    }

    return OK;
}

/* ======================================================================
 * E2.2.3 — the policy dump (-D DUMP_BOTSHIELD_POLICY)
 *
 * Plain-text dump of the rules currently being enforced:
 *   - BotShieldRateLimit directives (directive rate_limits array).
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

static void bs_psh_cohort_ipspec(const bs_cohort *c)
{
    if (c->ip_any) { fputs("*", stdout); return; }
    if (c->inline_cidrs) {
        printf("inline(%s)", c->inline_cidrs);
        return;
    }
    if (c->path) {
        printf("file(%s)", c->path);
        return;
    }
    printf("<%d ranges>", c->ranges ? c->ranges->nelts : 0);
}

/* Dump the effective policy for one vhost to stdout, for
 * `httpd -t -D DUMP_BOTSHIELD_POLICY`.
 *
 * This was an HTTP endpoint (<prefix>/policy-status). It should not
 * have been: dashboard and metrics are runtime state, which is why
 * mod_status is a URL, but this is resolved CONFIGURATION -- static
 * between reloads, and Apache already has an idiom for that in the
 * -D DUMP_VHOSTS / DUMP_MODULES / DUMP_CONFIG family. Those need
 * shell access, which is the right bar for config introspection and
 * cannot be forgotten into being world-readable -- the endpoint was
 * served to anyone, and of the three it was the worst to expose:
 * counters tell an attacker how much noise they are making, a
 * policy dump tells them which rules exist and what to avoid. */
void bs_policy_dump(server_rec *s, apr_pool_t *p, bs_dir_cfg *cfg)
{

    bs_server_cfg *scfg =
        ap_get_module_config(s->module_config, &botshield_module);
    if (!scfg) {
        fputs("# scfg unavailable\n", stdout);
        return;
    }

    /* Identified the way `httpd -S` identifies a vhost: name, port, and
     * the config file and line that defined it. Two vhosts on one name
     * and different ports are otherwise indistinguishable in the dump. */
    printf("# mod_botshield policy dump\n"
                  "# vhost: %s:%u (%s:%u)\n\n",
        s->server_hostname ? s->server_hostname : "-",
        (unsigned) (s->addrs ? s->addrs->host_port : s->port),
        s->defn_name ? s->defn_name : "-",
        (unsigned) s->defn_line_number);

    /* --- observability ACL ---
     *
     * Printed first because it is the setting most likely to be wrong
     * in a way the operator only discovers by being locked out of the
     * page they would have used to diagnose it. */
    fputs("## Observability endpoint access\n", stdout);
    {
        const bs_observe_acl *acls[2] = { &scfg->observe_dashboard,
                                          &scfg->observe_metrics };
        const char *names[2] = { "BotShieldDashboardAccess",
                                 "BotShieldMetricsAccess" };
        for (int k = 0; k < 2; k++) {
            const bs_observe_acl *a = acls[k];
            if (a->allow_all) {
                printf("%-26s ALL - served to everyone\n", names[k]);
                continue;
            }
            if (!a->specs || a->specs->nelts == 0) {
                printf("%-26s closed - no directive, requests get 404\n",
                       names[k]);
                continue;
            }
            printf("%-26s", names[k]);
            for (int n = 0; n < a->specs->nelts; n++) {
                printf(" %s", APR_ARRAY_IDX(a->specs, n, const char *));
            }
            fputs("\n", stdout);
        }
    }
    fputs("\n", stdout);

    /* --- directive rate limits --- */
    fputs("## BotShieldRateLimit (directive)\n", stdout);
    if (!scfg->rate_limits || scfg->rate_limits->nelts == 0) {
        fputs("# (none)\n\n", stdout);
    } else {
        /* No live counter column. A configtest process never attaches
         * the scoreboard SHM, so the count could only ever print as
         * "-/-"; live consumption belongs to the dashboard and the
         * metrics endpoint, which run inside a serving child. */
        fputs("# name               budget  window  ua                          "
                 "ipspec\n", stdout);
        for (int i = 0; i < scfg->rate_limits->nelts; i++) {
            bs_rate_limit_entry *e = APR_ARRAY_IDX(
                scfg->rate_limits, i, bs_rate_limit_entry *);
            printf("%-18s  %6u  %4us   %-26s  ",
                e->name, e->budget, e->window_sec,
                e->cohort.ua_any ? "*"
                    : apr_psprintf(p, "\"%s\"", e->cohort.ua_pattern));
            bs_psh_cohort_ipspec(&e->cohort);
            fputs("\n", stdout);
        }
        fputs("\n", stdout);
    }

    /* --- robots.txt --- */
    /* --- effective tier thresholds ---
     *
     * Printed with their source because "not in the config file" and
     * "not in effect" are different things, and confusing them is what
     * made a flag worth 50 points a permanent challenge loop: the 20
     * it had to clear was a compiled-in default that appeared nowhere
     * an operator could read. */
    {
        /* Configured values, not resolved defaults: unset means never,
         * so the advisories below must not fire against a threshold
         * that does not exist. */
        int sil = cfg ? cfg->score_non_interactive : BS_UNSET;
        int hrd = cfg ? cfg->score_interactive     : BS_UNSET;

        /* Report what is EFFECTIVE, which since the no-default-rules
         * change means: an unset threshold never fires. Printing the
         * compiled default as though it applied made this page state
         * the opposite of the truth on the one endpoint whose job is
         * saying what is in force -- a reader would conclude
         * cumulative scoring was live at 20 when score decides
         * nothing. The compiled values are still shown, marked as the
         * suggested starting point they now are. */
        fputs("## Tier thresholds (effective)\n", stdout);
        struct { const char *name; int cfgval; int dflt; } th[] = {
            { "non-interactive", cfg ? cfg->score_non_interactive : BS_UNSET,
              BS_DEFAULT_SCORE_NON_INTERACTIVE },
            { "interactive",     cfg ? cfg->score_interactive     : BS_UNSET,
              BS_DEFAULT_SCORE_INTERACTIVE },
            { "captcha",         cfg ? cfg->score_captcha         : BS_UNSET,
              BS_DEFAULT_SCORE_CAPTCHA },
        };
        for (int t = 0; t < 3; t++) {
            if (th[t].cfgval == BS_UNSET) {
                printf("%-16s %6s   unset - never fires "
                              "(suggested: %d)\n",
                           th[t].name, "-", th[t].dflt);
            } else {
                printf("%-16s %6d   configured\n",
                           th[t].name, th[t].cfgval);
            }
        }
        fputs("\n", stdout);

        /* --- effective flag triggers, after reset processing --- */
        fputs("## Flag triggers (effective, after reset)\n", stdout);
        if (!scfg->flag_triggers || scfg->flag_triggers->nelts == 0) {
            fputs("# (none)\n\n", stdout);
        } else {
            fputs("# flag              action      value    mode      "
                     "source\n", stdout);
            int warned = 0;
            for (int i = 0; i < scfg->flag_triggers->nelts; i++) {
                bs_flag_trigger_entry *e = APR_ARRAY_IDX(
                    scfg->flag_triggers, i, bs_flag_trigger_entry *);
                const char *act = e->action == BS_FLAG_ACT_SCORE ? "score"
                                : e->action == BS_FLAG_ACT_TIER_FLOOR
                                  ? "tier_floor" : "reset";
                char val[32];
                if (e->action == BS_FLAG_ACT_SCORE) {
                    apr_snprintf(val, sizeof(val), "%+d", e->score_add);
                } else if (e->action == BS_FLAG_ACT_TIER_FLOOR) {
                    apr_snprintf(val, sizeof(val), "%s",
                                 bs_tier_name(e->tier_min));
                } else {
                    apr_snprintf(val, sizeof(val), "-");
                }
                printf("%-18s %-11s %-8s %-9s %s\n",
                           e->flag_name, act, val,
                           e->mode == BS_TMODE_OBSERVE ? "observe" : "enforce",
                           e->from_default ? "compiled default" : "configured");
                /* The two conditions that have actually locked users
                 * out of this deployment. Reported here rather than
                 * only in the docs, because both were invisible in the
                 * config that produced them. */
                /* Note what this does NOT say any more. Before
                 * flags_excused it said "forever", which was accurate
                 * then: flags re-apply every request and solving did
                 * not clear them. It is no longer true -- a client that
                 * solves once has the flags it carried at that moment
                 * excused for the life of the cookie -- and leaving the
                 * stronger wording in would push operators into
                 * lowering scores that no longer need lowering. */
                if (e->action == BS_FLAG_ACT_SCORE
                    && e->mode != BS_TMODE_OBSERVE
                    && sil != BS_UNSET && e->score_add >= sil) {
                    printf("  ~  %s scores %+d on its own, at or above "
                                  "the non-interactive threshold of %d: this flag is a "
                                  "challenge switch, not a contributing "
                                  "signal. Bounded by flags_excused -- one "
                                  "solve clears it for that cookie -- so a "
                                  "client that CANNOT solve stays "
                                  "challenged.\n",
                               e->flag_name, e->score_add, sil);
                    warned++;
                }
                if (e->action == BS_FLAG_ACT_TIER_FLOOR
                    && e->mode != BS_TMODE_OBSERVE
                    && e->tier_min >= BS_TIER_INTERACTIVE
                      && hrd == BS_UNSET) {
                    printf("  !! %s forces tier %s, which is MAXed in "
                                  "after the score decision and ignores the "
                                  "parked hard threshold of %d.\n",
                               e->flag_name, bs_tier_name(e->tier_min), hrd);
                    warned++;
                }
            }
            printf("# %d note(s). '!!' is a fault; '~' is a design\n"
                          "# consequence worth knowing.\n\n", warned);
        }
    }

    fputs("## robots.txt (BotShieldRobotsTxt)\n", stdout);
    if (!scfg->robots_txt_path) {
        fputs("# (not configured)\n", stdout);
        return;
    }
    bs_robots_state *rs =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    printf("# path:                %s\n", scfg->robots_txt_path);
    if (!rs) {
        fputs("# status:              NOT LOADED - parse failed or file "
                 "missing (see the error log above)\n", stdout);
        return;
    }
    char mbuf[APR_RFC822_DATE_LEN + 1] = { 0 };
    apr_rfc822_date(mbuf, rs->mtime);
    /* No slot-pool line: like the per-group slot numbers, pool usage is
     * SHM bookkeeping, and the figure this process computes is nominal
     * anyway. */
    printf("# mtime:               %s\n"
                  "# groups:              %d\n"
                  "# wildcard scope:      %s\n",
        mbuf,
        robots_group_count(rs->doc),
        scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_STRICT ? "strict"
          : scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_OFF ? "off"
          : "heuristic");
    if (scfg->robots_refresh_interval > 0)
        printf("# refresh interval:    %d s\n",
               scfg->robots_refresh_interval);
    else
        fputs("# refresh interval:    off - reload to pick up edits\n",
              stdout);

    int n = robots_group_count(rs->doc);
    for (int i = 0; i < n; i++) {
        printf("\n### group[%d] \"%s\"  wildcard=%s\n", i,
            robots_group_name_at(rs->doc, i),
            robots_group_is_wildcard_at(rs->doc, i) ? "yes" : "no");
        int n_ua = robots_group_ua_count_at(rs->doc, i);
        for (int u = 0; u < n_ua; u++) {
            printf("  user-agent: %s\n",
                robots_group_ua_at(rs->doc, i, u));
        }
        int n_rules = robots_group_rule_count_at(rs->doc, i);
        for (int k = 0; k < n_rules; k++) {
            const char *pat = NULL;
            int allow = 0;
            if (robots_group_rule_at(rs->doc, i, k, &pat, &allow)) {
                printf("  %-9s %s\n",
                    allow ? "Allow:" : "Disallow:", pat ? pat : "");
            }
        }
        int cd = robots_group_crawl_delay_at(rs->doc, i);
        if (cd > 0) {
            /* No slot number: which SHM counter slot a group landed
             * in is bookkeeping, not policy, and it differs between
             * this configtest and the server being tested. */
            printf("  Crawl-delay: %ds", cd);
            fputs("\n", stdout);
        }
    }
    return;
}
