/* score.h — per-request scoring + flag-trigger walker.
 *
 * The score system aggregates penalty/credit signals across all the
 * heuristics, triggers, rate-limit decisions, and flag-trigger
 * runtime. Each entry records (penalty, ttl_seconds, reason) so the
 * decision log can replay why a tier was chosen.
 *
 * Score → tier mapping happens later in bs_handler (compares total
 * to bs_dir_cfg->score_silent / _hard / _captcha thresholds), but
 * the score struct itself is request-scoped and lives on
 * r->request_config under the module's slot.
 *
 * The flag-trigger walker is on the request side too — it consumes
 * scfg->flag_triggers entries (configured at config time via
 * BotShieldFlagTrigger directives, with compiled-in defaults
 * seeded by bs_post_config). For each flag bit set on the request,
 * the walker accumulates SCORE actions via bs_score_add and
 * resolves a TIER_FLOOR via MAX. */
#ifndef BOTSHIELD_SCORE_H
#define BOTSHIELD_SCORE_H

#include <httpd.h>
#include <apr_pools.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Allocate (or fetch the existing) per-request score struct on
 * r->request_config. create=0 returns NULL if none exists yet. */
bs_request_score *bs_get_score(request_rec *r, int create);

/* Append a (penalty, ttl_seconds, reason) entry to the request's
 * score. penalty=0 records a reason without changing the total
 * (used for observe-mode + status=pass entries). reason must
 * outlive the request. The reason cap (BS_SCORE_MAX_REASONS = 16)
 * silently drops overflow entries; the total still accumulates. */
void bs_score_add(request_rec *r, int penalty, int ttl_seconds,
                  const char *reason);

/* Comma-joined reason names for the decision log's reason field.
 * Returns "-" when no entries fired. */
const char *bs_decision_reason_names(apr_pool_t *p,
                                     const bs_request_score *s);

/* "[reason:penalty,reason:penalty,...]" — bracketed reasons with
 * penalty values, for the verbose audit-log line. Returns "[]"
 * when no entries fired. */
const char *bs_score_reasons_joined(apr_pool_t *p,
                                    const bs_request_score *s);

/* E14 flag-trigger walker. For each entry in scfg->flag_triggers
 * whose flag_bit is set in all_flags:
 *   - SCORE actions accumulate via bs_score_add
 *   - TIER_FLOOR actions MAX into *out_tier_floor
 * mode=observe entries log a `would-flag-trigger:<flag>:observe`
 * reason and skip the side effect. Returns the count of triggers
 * that fired (informational). */
int bs_apply_flag_triggers(request_rec *r,
                           const struct bs_server_cfg *scfg,
                           apr_uint32_t all_flags,
                           bs_tier *out_tier_floor);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_SCORE_H */
