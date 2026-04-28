/* policy.h — request-time policy walker.
 *
 * bs_check_policy is the request-path entry point that fans out
 * across every operator-configured policy family in this order:
 *
 *   1. E4 cookie triggers     (declaration order; pass accumulates,
 *                              first non-pass short-circuits)
 *   2. E6 env-var triggers    (declaration order, first match wins)
 *   3. E11.2 load triggers    (state>=warm / state=hot)
 *   4. E3 path triggers       (declaration order, first match wins)
 *   5. E2.1 BotShieldBlockPath (cohort + path glob → 403)
 *   6. E2.2 robots.txt Disallow (configured robots.txt)
 *   7. E2.1 BotShieldRateLimit (with E9 strike escalation)
 *   8. E2.2 robots.txt Crawl-delay (per-group rate limit)
 *
 * Each family's matcher / action is owned by its own feature file
 * (triggers.c, robots.c, etc.) — bs_check_policy is just the
 * orchestrator that walks them in the right order and converts the
 * outcomes into Apache-friendly status codes.
 *
 * E2.1 specifics — BotShieldRateLimit + BotShieldBlockPath share one
 * cohort definition: a (ua-substring?, ipspec?) predicate pair. The
 * ipspec reuses E1's polymorphic shape — omitted / explicit path /
 * '*' / inline CIDRs — via bs_allow_load_ranges{,_from_string}.
 * Cohort matching at request time is UA-match AND IP-match, with '*'
 * as "any" on either axis (but not both — that would rate-limit or
 * block every request, which the setter rejects at config time).
 *
 * Storage:
 *  - Config: scfg->rate_limits / scfg->block_paths arrays, keyed by
 *    name; merged across main/vhost scope via bs_merge_server_cfg.
 *  - Runtime: rate counters live in SHM as a flat slot array
 *    (bs_shm.rate_counters[]). Each bs_rate_limit_entry's shm_slot
 *    is an index assigned in post_config. Fixed-window counter model
 *    with atomic CAS updates — approximate rather than exact sliding
 *    window, but the right trade for a rate limiter (smaller code,
 *    no per-bucket mutex, burst-at-boundary harmless because the
 *    downstream score_add hook still records it).
 *
 * On trip:
 *  - Block-path hit → 403 + bs_score_add(+100, "block-path:<name>").
 *  - Rate-limit exceeded → 429 + Retry-After: <seconds remaining in
 *    window> + bs_score_add(+50, "rate-limit-exceeded:<name>"). */
#ifndef BOTSHIELD_POLICY_H
#define BOTSHIELD_POLICY_H

#include <httpd.h>

#include "botshield.h"

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

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_POLICY_H */
