/* score.h — per-request scoring + flag-trigger walker.
 *
 * The score system aggregates penalty/credit signals across all the
 * heuristics, triggers, rate-limit decisions, and flag-trigger
 * runtime. Each entry records (penalty, ttl_seconds, reason) so the
 * decision log can replay why a tier was chosen.
 *
 * Score → tier mapping happens via bs_decide_tier (compares total to
 * bs_dir_cfg->score_silent / _hard / _captcha thresholds), but the
 * score struct itself is request-scoped and lives on r->request_config
 * under the module's slot.
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
#include <apr_tables.h>
#include <apr_time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — bs_dir_cfg / bs_server_cfg are defined in
 * botshield.h. Declared here as forwards so this header is self-
 * contained: TUs that need score-system types do not have to also
 * pull botshield.h through this file. */
struct bs_dir_cfg;
struct bs_server_cfg;
typedef struct bs_dir_cfg bs_dir_cfg;

/* ======================================================================
 * Score thresholds + heuristic penalties
 * ====================================================================== */

/* Score → tier cut-points (defaults; operator-tunable via the
 * BotShieldScoreSilent / Hard / Captcha directives). */
#define BS_DEFAULT_SCORE_SILENT   20
#define BS_DEFAULT_SCORE_HARD     50
#define BS_DEFAULT_SCORE_CAPTCHA  80

/* Cap on stored reason entries per request. Overflow is silently
 * dropped; the score total still accumulates. */
#define BS_SCORE_MAX_REASONS      16

/* Built-in heuristic penalties (consumed by heuristics.c). */
#define BS_PENALTY_MISSING_UA     40
#define BS_PENALTY_MISSING_AL     15
#define BS_PENALTY_SCRAPER_UA     50

/* ======================================================================
 * Tier + silent-mode enums (decision dispatch)
 * ====================================================================== */

typedef enum {
    BS_TIER_PASS    = 0,
    BS_TIER_SILENT  = 1,
    BS_TIER_HARD    = 2,
    BS_TIER_CAPTCHA = 3
} bs_tier;

/* E17 — what flavor of silent-tier dispatch to use. INTERSTITIAL is
 * the legacy M7 splash that auto-submits the PoW. EMBEDDED hands off
 * to a wrapper script the operator has already included on the page;
 * the page serves DECLINED (real content) and the wrapper does the
 * PoW in a Web Worker, then POSTs back to /botshield/embedded-verify
 * to mint _bs_session. */
typedef enum {
    BS_SILENT_MODE_UNSET        = -1,
    BS_SILENT_MODE_INTERSTITIAL =  0,
    BS_SILENT_MODE_EMBEDDED     =  1
} bs_silent_mode;

/* ======================================================================
 * Score system
 * ====================================================================== */

typedef struct {
    int         penalty;
    int         ttl_seconds;   /* accepted for API stability; unused
                                * today (bs_score_add stores it but
                                * downstream consumers haven't
                                * materialized — the flagged-IP table
                                * carries its own TTL set at insert).
                                * Kept so callers can annotate "this
                                * penalty represents an N-second-worth
                                * signal" without the API churning if
                                * we ever wire it up. */
    const char *reason;        /* static string or r->pool-allocated */
} bs_score_entry;

typedef struct {
    int                 total;
    apr_array_header_t *entries;
    int                 cap_warned;   /* DEBUG-logged when entries
                                       * first hit BS_SCORE_MAX_REASONS
                                       * so further drops don't spam
                                       * the log. apr_pcalloc gives us
                                       * 0 for free. */
} bs_request_score;

/* ======================================================================
 * Score API
 * ====================================================================== */

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

/* Score-to-tier picker. Three configurable cut-points
 * (BotShieldScoreSilent / Hard / Captcha) gate four tiers
 * (pass / silent / form / captcha). The README "Understanding
 * scoring" section covers operator tuning; templates.h documents
 * the per-tier interstitial rendering. */
bs_tier bs_decide_tier(const bs_dir_cfg *cfg, int score);

/* Tier-name string for the decision log + claims-bridge wire
 * format. Returns "pass" / "silent" / "form" / "captcha", or "?"
 * for an unknown enum value. */
const char *bs_tier_name(bs_tier t);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_SCORE_H */
