/* policy.h — request-time policy walker.
 *
 * bs_check_policy is the request-path entry point that fans out
 * across every operator-configured policy family in this order:
 *
 *   1. E4 cookie triggers     (declaration order; pass accumulates,
 *                              first non-pass short-circuits)
 *   2. E6 env-var triggers    (declaration order, first match wins)
 *   3. E11.2 load triggers    (state>=warm / state=hot)
 *   4. E3 path triggers       (declaration order, first match wins;
 *                              optional ua=/ipspec= cohort gate ANDs
 *                              with the path glob)
 *   5. E2.2 robots.txt Disallow (configured robots.txt)
 *   6. E2.1 BotShieldRateLimit (with E9 strike escalation)
 *   7. E2.2 robots.txt Crawl-delay (per-group rate limit)
 *
 * Each family's matcher / action is owned by its own feature file
 * (triggers.c, robots.c, etc.) — bs_check_policy is just the
 * orchestrator that walks them in the right order and converts the
 * outcomes into Apache-friendly status codes.
 *
 * E2.1 specifics — BotShieldRateLimit and BotShieldRequestTrigger share
 * one cohort definition: a (ua-substring?, ipspec?) predicate pair.
 * The ipspec reuses E1's polymorphic shape — omitted / explicit path
 * / '*' / inline CIDRs — via bs_allow_load_ranges{,_from_string}.
 * Cohort matching at request time is UA-match AND IP-match, with '*'
 * as "any" on either axis (but not both — that would rate-limit
 * every request, which the setter rejects at config time).
 *
 * Storage:
 *  - Config: scfg->rate_limits and scfg->request_triggers arrays, keyed
 *    by name; merged across main/vhost scope via bs_merge_server_cfg.
 *  - Runtime: rate counters live in SHM as a flat slot array
 *    (bs_shm.rate_counters[]). Each bs_rate_limit_entry's shm_slot
 *    is an index assigned in post_config. Fixed-window counter model
 *    with atomic CAS updates — approximate rather than exact sliding
 *    window, but the right trade for a rate limiter (smaller code,
 *    no per-bucket mutex, burst-at-boundary harmless because the
 *    downstream score_add hook still records it).
 *
 * On trip:
 *  - Path-trigger status=4xx → that status + score change per the
 *    trigger's penalty/credit/log keys.
 *  - Rate-limit exceeded → 429 + Retry-After: <seconds remaining in
 *    window> + bs_score_add(+50, "rate-limit-exceeded:<name>"). */
#ifndef BOTSHIELD_POLICY_H
#define BOTSHIELD_POLICY_H

#include <httpd.h>

#include "botshield.h"
#include "triggers.h"   /* bs_rate_counter */

#ifdef __cplusplus
extern "C" {
#endif

/* Returns:
 *   OK                     no rule fired; caller continues to heuristics.
 *   DECLINED               a status=pass trigger fired; caller short-
 *                          circuits to DECLINED so the real handler
 *                          runs (with flag-IP / log side effects
 *                          already applied here).
 *   any other HTTP_* code  short-circuit with that status. */
int bs_check_policy(request_rec *r);

/* /botshield/policy-status admin endpoint (E2.2.3). Plain-text
 * dump of the rules currently being enforced — directive
 * rate_limits and robots.txt-derived groups. Reads the same scfg
 * fields bs_check_policy walks at request time. Operators wrap the
 * URL in a <Location> with their own ACL; the page reveals operator
 * config (already on disk in /etc/apache2/) but no cookie secrets
 * or client IPs. */
int bs_policy_status_handler(request_rec *r, bs_dir_cfg *cfg);

/* Atomic fixed-window admission test against a SHM rate-counter
 * slot. Returns 1 if the request fits under budget (count was
 * incremented), 0 if the window is full. Shared with bot_rate.c
 * for the slug-keyed bot rate limit. */
int bs_rate_counter_admit(bs_rate_counter *slot,
                          apr_uint32_t budget,
                          apr_uint32_t window_sec);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_POLICY_H */
