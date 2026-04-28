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
 * outcomes into Apache-friendly status codes. */
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
