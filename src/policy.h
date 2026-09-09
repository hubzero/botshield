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
 *   6. (was E2.1 BotShieldRateLimit; a rule's rate=/delay= window
 *      is spent inside step 4 since 2026-09-09, E9 strikes included)
 *   7. E2.2 robots.txt Crawl-delay (per-group rate limit)
 *
 * Each family's matcher / action is owned by its own feature file
 * (triggers.c, robots.c, etc.) — bs_check_policy is just the
 * orchestrator that walks them in the right order and converts the
 * outcomes into Apache-friendly status codes.
 *
 * E2.1 specifics — a rule's cohort is a (ua-substring?, ipspec?)
 * predicate pair.
 * The ipspec reuses E1's polymorphic shape — omitted / explicit path
 * / '*' / inline CIDRs — via bs_allow_load_ranges{,_from_string}.
 * Cohort matching at request time is UA-match AND IP-match, with '*'
 * as "any" on either axis (but not both — that would rate-limit
 * every request, which the setter rejects at config time).
 *
 * Storage:
 *  - Config: the scfg->request_triggers array, keyed by name; merged
 *    across main/vhost scope via bs_merge_server_cfg.
 *  - Runtime: rate counters live in SHM as a flat slot array
 *    (bs_shm.rate_counters[]). Each windowed rule's shm_slot
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
 *    window> + bs_score_add(+50, "ratelimitexceeded:<name>"). */
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

/* Dump one vhost's effective policy to stdout for
 * `httpd -t -D DUMP_BOTSHIELD_POLICY`. Was an HTTP endpoint; config
 * introspection belongs behind shell access, not a URL. */
void bs_policy_dump(server_rec *s, apr_pool_t *p, bs_dir_cfg *cfg);

/* Atomic fixed-window admission test against a SHM rate-counter
 * slot. Returns 1 if the request fits under budget (count was
 * incremented), 0 if the window is full. Shared with bot_rate.c
 * for the slug-keyed bot rate limit. */
int bs_rate_counter_admit(bs_rate_counter *slot,
                          apr_uint32_t budget,
                          apr_uint32_t window_ms);

/* Flag the request's client address. Shared with bot_rate.c so the
 * slug-keyed limit records a trip the same way the cohort limit does;
 * a refusal that only one of the two remembers is worse than one
 * neither remembers, because the difference is invisible in the log. */
void bs_flag_client(request_rec *r, apr_uint32_t bits, int ttl_sec);

/* TTL for a rate-abuse flag, derived from the budget window the
 * client overspent and clamped to [BS_RATE_FLAG_TTL_MIN,
 * BS_RATE_FLAG_TTL_MAX]. A minute's budget is remembered for a
 * minute, an hour's for an hour -- so the flag's lifetime tracks the
 * limit that produced it without an operator setting a second number
 * that has to agree with the first. */
int bs_rate_flag_ttl(apr_uint32_t window_ms);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_POLICY_H */
