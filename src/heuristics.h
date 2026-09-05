/* heuristics.h — built-in score signals exposed via the
 * BotShieldHeuristicTrigger directive.
 *
 * Heuristics are named, compile-time predicates that an operator binds
 * actions to via BotShieldHeuristicTrigger. The five ship today:
 *
 *   - missingua      : UA header absent or empty
 *   - missingal      : Accept-Language header absent or empty
 *   - scraperua      : UA contains a known HTTP-library token
 *                       (curl/Wget/python-requests/...)
 *   - firstsightip  : never-seen-before client IP (Bloom-filter miss).
 *                       Bloom is populated eagerly (every request) so
 *                       this fires only on truly first visits.
 *   - droppedcookie  : Bloom-known IP that arrived without a usable
 *                       cookie (absent / bad-sig / bad-format). Stronger
 *                       signal than first-sight: we've transacted with
 *                       this IP before, so a missing cookie is anomalous
 *                       (private-browsing reset, manual cookie clear,
 *                       or evasion).
 *
 * Each is seeded with a sensible default action at post_config (see
 * bs_default_heuristic_triggers in config.c). Operators tune by
 * adding more BotShieldHeuristicTrigger directives, which append
 * after the defaults; declaring `<name> reset` clears prior entries
 * for that name; declaring `all reset` wipes the slate completely so
 * the operator can build it up from zero. Same action vocabulary as
 * BotShieldFlagTrigger: `score add=N` or `tier_floor min=<tier>`,
 * with optional `mode=observe`.
 *
 * Predicates split into two phases:
 *   HEADER       — fire in bs_run_builtin_heuristics, before client
 *                  IP / cookie state is known. UA/header checks live
 *                  here.
 *   POST_COOKIE  — fire in bs_handler after cookie + IP are known.
 *                  firstsightip is the only one. */
#ifndef BOTSHIELD_HEURISTICS_H
#define BOTSHIELD_HEURISTICS_H

#include <httpd.h>
#include <http_config.h>

#include "botshield.h"
#include "score.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BS_H_MISSING_UA      = 0,
    BS_H_MISSING_AL,
    BS_H_SCRAPER_UA,
    BS_H_FIRST_SIGHT_IP,
    BS_H_DROPPED_COOKIE,
    BS_H_COUNT,
    /* Sentinel for `all reset` — never appears in a request-time entry. */
    BS_H_ALL             = -1,
} bs_heuristic_id;

typedef enum {
    BS_HP_HEADER = 0,        /* fires from bs_run_builtin_heuristics */
    BS_HP_POST_COOKIE,       /* fires from bs_handler after cookie parse */
} bs_heuristic_phase;

typedef enum {
    BS_HEUR_ACT_SCORE      = 0,
    BS_HEUR_ACT_TIER_FLOOR,
    BS_HEUR_ACT_RESET,       /* sentinel: per-name reset */
    BS_HEUR_ACT_RESET_ALL,   /* sentinel: `all reset` */
} bs_heuristic_action_kind;

typedef struct {
    int                       id;            /* bs_heuristic_id, or BS_H_ALL */
    bs_heuristic_action_kind  action;
    int                       score_add;     /* signed, -1000..1000 */
    bs_tier                   tier_min;      /* used iff action==TIER_FLOOR */
    int                       mode;          /* bs_trigger_mode */
    int                       from_default;
} bs_heuristic_trigger_entry;

/* Compile-time metadata table for the named heuristics. Looked up by
 * name at config time; iterated by id at request time. */
typedef struct {
    const char        *name;
    bs_heuristic_id    id;
    bs_heuristic_phase phase;
    int                default_score_add;
} bs_heuristic_meta;

const bs_heuristic_meta *bs_heuristic_for_name(const char *name);
const bs_heuristic_meta *bs_heuristic_for_id  (bs_heuristic_id id);
size_t bs_heuristic_count(void);

/* Walk the HEADER-phase heuristics. Called once per request from
 * bs_handler before client-IP / cookie state is needed. Caller is
 * responsible for not running this when a verified cookie is in play
 * (penalties on a known-good client are nonsense). */
void bs_run_builtin_heuristics(request_rec *r);

/* Apply the action(s) bound to a single heuristic id. Used by
 * bs_handler for the POST_COOKIE phase (currently just first-sight-
 * ip). The caller has already evaluated the predicate; this just
 * walks scfg->heuristic_triggers and applies matching entries. */
void bs_apply_heuristic(request_rec *r, bs_heuristic_id id);

/* Directive setter: BotShieldHeuristicTrigger <name>|all [reset]
 * [action=<verb> args...]. Detailed grammar in the help text on
 * AP_INIT_TAKE_ARGV. */
const char *bs_set_heuristic_trigger(cmd_parms *cmd, void *dconf,
                                     int argc, char *const argv[]);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_HEURISTICS_H */
