/* heuristics.c — built-in score signals exposed via
 * BotShieldHeuristicTrigger. See heuristics.h for the operator model.
 *
 * The four named heuristics (missingua / missingal / scraperua /
 * firstsightip) live in a metadata registry below. Each has a
 * predicate function (compiled in) and a phase tag. At post_config,
 * scfg->heuristic_triggers is seeded with default actions matching
 * the prior hardcoded behavior (40/15/50/5 score adds). At request
 * time, bs_run_builtin_heuristics walks the array applying actions
 * for HEADER-phase entries whose predicates match; bs_apply_heuristic
 * handles POST_COOKIE-phase entries from bs_handler. */
#include <string.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr_strings.h>
#include <apr_tables.h>

#include "botshield.h"
#include "allowlist.h"   /* bs_check_allow */
#include "heuristics.h"
#include "score.h"       /* bs_score_add */
#include "triggers.h"    /* BS_TMODE_* */

/* Compile-time predicate signature. Returns a non-NULL reason string
 * on match (caller emits it through bs_score_add), NULL on no match.
 * For most heuristics the reason is the metadata name; scraperua
 * builds "scraperua-<token>" so the matched token shows in the
 * decision log. The pool is r->pool; reason strings come from
 * apr_psprintf or string literals. */
typedef const char *(*bs_heuristic_pred_fn)(request_rec *r);

static const char *bs_pred_missing_ua(request_rec *r)
{
    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    return (!ua || !*ua) ? "missinguseragent" : NULL;
}

static const char *bs_pred_missing_al(request_rec *r)
{
    const char *al = apr_table_get(r->headers_in, "Accept-Language");
    return (!al || !*al) ? "missingacceptlanguage" : NULL;
}

/* Which HTTP-library token, if any, this User-Agent carries.
 *
 * Shared with the ua=@scraper cohort selector so a rule and the
 * scraperua score ask the same question of the same list. Two copies
 * of this list would drift, and a rule and a score disagreeing about
 * what a scraper is is the kind of split this vocabulary is meant to
 * remove.
 *
 * Case-sensitive on purpose — both casings appear in the wild and are
 * listed. This flags rather than blocks, so a false positive costs a
 * tier bump. */
const char *bs_ua_scraper_token(request_rec *r)
{
    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (!ua || !*ua) return NULL;
    static const char *const scraper_tokens[] = {
        "curl", "Wget", "wget",
        "python", "Python", "python-requests",
        "urllib", "httpx", "aiohttp",
        "Go-http-client", "okhttp", "axios", "scrapy",
        "java", "Java", "libwww", "lwp-request",
        NULL
    };
    for (int i = 0; scraper_tokens[i]; i++) {
        if (strstr(ua, scraper_tokens[i])) return scraper_tokens[i];
    }
    return NULL;
}

static const char *bs_pred_scraper_ua(request_rec *r)
{
    const char *tok = bs_ua_scraper_token(r);
    return tok ? apr_psprintf(r->pool, "scraperua-%s", tok) : NULL;
}

/* firstsightip's predicate is the bloom-miss check in bs_handler;
 * by the time bs_apply_heuristic is called for it, the caller has
 * already established the match. The reason string is fixed. */
static const char *bs_pred_first_sight_ip(request_rec *r)
{
    (void)r;
    return "firstsightip";
}

/* Same dispatch shape as firstsightip: bs_handler establishes the
 * Bloom-hit + cookie-absent / bad-sig / bad-format combination
 * before calling bs_apply_heuristic; this predicate just returns the
 * fixed reason name. */
static const char *bs_pred_dropped_cookie(request_rec *r)
{
    (void)r;
    return "droppedcookie";
}

typedef struct {
    bs_heuristic_meta      meta;
    bs_heuristic_pred_fn   pred;
} bs_heuristic_def;

static const bs_heuristic_def bs_heuristic_defs[] = {
    { { "missingua",      BS_H_MISSING_UA,      BS_HP_HEADER, BS_PENALTY_MISSING_UA },
      bs_pred_missing_ua },
    { { "missingal",      BS_H_MISSING_AL,      BS_HP_HEADER, BS_PENALTY_MISSING_AL },
      bs_pred_missing_al },
    { { "scraperua",      BS_H_SCRAPER_UA,      BS_HP_HEADER, BS_PENALTY_SCRAPER_UA },
      bs_pred_scraper_ua },
    /* 20 == BS_DEFAULT_SCORE_NON_INTERACTIVE, deliberately. Both post-cookie
     * heuristics fire only when the request carries no usable cookie,
     * so together they mean "no session context". droppedcookie (known
     * IP) was already 25 and acted on; firstsightip (new IP) sat at 5
     * and did not, which left exactly one hole: a crawler spreading one
     * request across many addresses is first-sight every time and was
     * never challenged on score alone. Setting it to the noninteractive
     * threshold closes that without an operator having to write a rule
     * -- an enabled scope now challenges any request with no session
     * context, invisibly, and a real browser clears it in one
     * auto-submitted round trip. */
    { { "firstsightip",  BS_H_FIRST_SIGHT_IP,  BS_HP_POST_COOKIE, BS_PENALTY_FIRST_SIGHT_IP },
      bs_pred_first_sight_ip },
    { { "droppedcookie",  BS_H_DROPPED_COOKIE,  BS_HP_POST_COOKIE, BS_PENALTY_DROPPED_COOKIE },
      bs_pred_dropped_cookie },
};
#define BS_HEURISTIC_COUNT \
    (sizeof(bs_heuristic_defs) / sizeof(bs_heuristic_defs[0]))

const bs_heuristic_meta *bs_heuristic_for_name(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < BS_HEURISTIC_COUNT; i++) {
        if (strcmp(bs_heuristic_defs[i].meta.name, name) == 0) {
            return &bs_heuristic_defs[i].meta;
        }
    }
    return NULL;
}

const bs_heuristic_meta *bs_heuristic_for_id(bs_heuristic_id id)
{
    for (size_t i = 0; i < BS_HEURISTIC_COUNT; i++) {
        if (bs_heuristic_defs[i].meta.id == id) {
            return &bs_heuristic_defs[i].meta;
        }
    }
    return NULL;
}

size_t bs_heuristic_count(void) { return BS_HEURISTIC_COUNT; }

/* Apply one heuristic-trigger entry's action when its predicate has
 * matched. Mirrors the score / tier_floor verbs of bs_apply_flag_
 * triggers. Observe-mode emits a `:observe` reason and skips the
 * side effect — same shape as the trigger family's observe path. */
static void bs_apply_heuristic_entry(request_rec *r,
                                     const bs_heuristic_trigger_entry *e,
                                     const char *reason)
{
    if (e->mode == BS_TMODE_OBSERVE) {
        bs_score_add(r, 0, 0,
            apr_pstrcat(r->pool, reason, ":observe", NULL));
        return;
    }
    if (e->action == BS_HEUR_ACT_SCORE) {
        bs_score_add(r, e->score_add, 3600, reason);
    } else if (e->action == BS_HEUR_ACT_TIER_FLOOR) {
        /* Tier-floor application currently flows through the
         * flagtrigger walker's tier_floor accumulator; for now
         * emit a reason so the decision log shows the matched
         * heuristic, and let the flagtrigger walker handle the
         * actual MAX-tier accumulation if the operator wires
         * tier-floor flags via flag triggers. */
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "%s:tier_floor", reason));
    }
    /* RESET / RESET_ALL sentinels are consumed at post_config time;
     * if one ever leaks into the request-time array, ignore. */
}

void bs_run_builtin_heuristics(request_rec *r)
{
    /* E1: crawler allow-list runs first. A verified crawler adds a
     * large negative penalty that dominates anything else scoring
     * might pile on (scraper UA tokens in "Googlebot" etc.) and
     * collapses tier dispatch to pass. */
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    bs_check_allow(r, dcfg);

    bs_server_cfg *scfg = ap_get_module_config(
        r->server->module_config, &botshield_module);
    if (!scfg || !scfg->heuristic_triggers
        || scfg->heuristic_triggers->nelts == 0) {
        return;
    }

    /* Pre-compute predicate results for every HEADER-phase heuristic
     * once. Multiple operator entries can bind to the same heuristic
     * (e.g. score add=20 + tier_floor min=noninteractive), so
     * caching the
     * evaluation avoids re-running the predicate per entry. */
    const char *match_reason[BS_H_COUNT];
    int evaluated[BS_H_COUNT] = { 0 };
    for (int i = 0; i < BS_H_COUNT; i++) match_reason[i] = NULL;

    for (int i = 0; i < scfg->heuristic_triggers->nelts; i++) {
        bs_heuristic_trigger_entry *e = APR_ARRAY_IDX(
            scfg->heuristic_triggers, i, bs_heuristic_trigger_entry *);
        if (e->id < 0 || e->id >= BS_H_COUNT) continue;
        if (e->action == BS_HEUR_ACT_RESET
            || e->action == BS_HEUR_ACT_RESET_ALL) continue;
        const bs_heuristic_def *def = &bs_heuristic_defs[e->id];
        if (def->meta.phase != BS_HP_HEADER) continue;
        if (!evaluated[e->id]) {
            match_reason[e->id] = def->pred(r);
            evaluated[e->id] = 1;
        }
        if (match_reason[e->id]) {
            bs_apply_heuristic_entry(r, e, match_reason[e->id]);
        }
    }
}

void bs_apply_heuristic(request_rec *r, bs_heuristic_id id)
{
    bs_server_cfg *scfg = ap_get_module_config(
        r->server->module_config, &botshield_module);
    if (!scfg || !scfg->heuristic_triggers) return;
    if (id < 0 || id >= BS_H_COUNT) return;
    const bs_heuristic_def *def = &bs_heuristic_defs[id];
    const char *reason = def->pred(r);
    if (!reason) reason = def->meta.name;
    for (int i = 0; i < scfg->heuristic_triggers->nelts; i++) {
        bs_heuristic_trigger_entry *e = APR_ARRAY_IDX(
            scfg->heuristic_triggers, i, bs_heuristic_trigger_entry *);
        if (e->id != (int)id) continue;
        if (e->action == BS_HEUR_ACT_RESET
            || e->action == BS_HEUR_ACT_RESET_ALL) continue;
        bs_apply_heuristic_entry(r, e, reason);
    }
}

/* BotShieldHeuristicTrigger <name>|all [reset] [action=<verb> args...]
 *
 * Same shape as BotShieldFlagTrigger. Five accepted forms:
 *
 *   BotShieldHeuristicTrigger all reset
 *   BotShieldHeuristicTrigger missingua reset
 *   BotShieldHeuristicTrigger missingua reset action=score add=20
 *   BotShieldHeuristicTrigger scraperua action=score add=80
 *   BotShieldHeuristicTrigger firstsightip action=tier_floor
 *     min=noninteractive
 *
 * `all reset` is consumed at post_config time and clears every
 * compiled-in default + every prior operator entry, giving the
 * operator a clean slate to build up from. Per-name reset clears
 * only that name's entries. Reset is a directive-level keyword,
 * not an action verb — keeping the two concerns syntactically
 * distinct prevents conflict with future runtime verbs.
 *
 * Storage: each parsed line appends a bs_heuristic_trigger_entry to
 * scfg->heuristic_triggers. Reset entries appear inline as
 * sentinels; bs_resolve_heuristic_triggers consumes them. */
const char *bs_set_heuristic_trigger(cmd_parms *cmd, void *dconf,
                                     int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 1) {
        return "BotShieldHeuristicTrigger: expects <name>|all "
               "[reset] [action=<verb> args...]";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    const char *name = argv[0];

    /* `all reset` — global wipe sentinel. */
    if (strcasecmp(name, "all") == 0) {
        if (argc != 2 || strcasecmp(argv[1], "reset") != 0) {
            return "BotShieldHeuristicTrigger all: only 'reset' is "
                   "valid (no action verbs); use the per-name form "
                   "to add entries after the wipe";
        }
        bs_heuristic_trigger_entry *r = apr_pcalloc(cmd->pool,
            sizeof(*r));
        r->id           = BS_H_ALL;
        r->action       = BS_HEUR_ACT_RESET_ALL;
        r->mode         = BS_TMODE_ENFORCE;
        r->from_default = 0;
        *(bs_heuristic_trigger_entry **)apr_array_push(
            scfg->heuristic_triggers) = r;
        return NULL;
    }

    const bs_heuristic_meta *hm = bs_heuristic_for_name(name);
    if (!hm) {
        return apr_psprintf(cmd->pool,
            "BotShieldHeuristicTrigger: unknown heuristic '%s'. "
            "Known names: missingua, missingal, scraperua, "
            "firstsightip; or 'all reset' to wipe.", name);
    }

    int idx = 1;
    int saw_reset = 0;
    if (idx < argc && strcasecmp(argv[idx], "reset") == 0) {
        saw_reset = 1;
        idx++;
        bs_heuristic_trigger_entry *r = apr_pcalloc(cmd->pool,
            sizeof(*r));
        r->id           = hm->id;
        r->action       = BS_HEUR_ACT_RESET;
        r->mode         = BS_TMODE_ENFORCE;
        r->from_default = 0;
        *(bs_heuristic_trigger_entry **)apr_array_push(
            scfg->heuristic_triggers) = r;
    }
    /* Bare `reset` with nothing after — done. */
    if (idx >= argc) return NULL;

    if (strncasecmp(argv[idx], "action=", 7) != 0) {
        if (saw_reset) {
            return apr_psprintf(cmd->pool,
                "BotShieldHeuristicTrigger '%s' reset: extra arg '%s' "
                "must begin with 'action=' (or omit it for a bare "
                "reset)", name, argv[idx]);
        }
        return apr_psprintf(cmd->pool,
            "BotShieldHeuristicTrigger '%s': expected 'reset' or "
            "'action=' as the second token; got '%s'",
            name, argv[idx]);
    }
    const char *verb = argv[idx] + 7;
    idx++;

    bs_heuristic_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->id           = hm->id;
    e->mode         = BS_TMODE_ENFORCE;
    e->from_default = 0;

    if (strcasecmp(verb, "score") == 0) {
        e->action = BS_HEUR_ACT_SCORE;
        int saw_add = 0;
        for (; idx < argc; idx++) {
            const char *arg = argv[idx];
            if (strncasecmp(arg, "add=", 4) == 0) {
                char *e2 = NULL;
                long n = strtol(arg + 4, &e2, 10);
                if (!e2 || *e2 || n < -1000 || n > 1000) {
                    return apr_psprintf(cmd->pool,
                        "BotShieldHeuristicTrigger '%s' action=score: "
                        "add='%s' must be an integer in -1000..1000",
                        name, arg + 4);
                }
                e->score_add = (int)n;
                saw_add = 1;
            } else if (strcasecmp(arg, "mode=observe") == 0) {
                e->mode = BS_TMODE_OBSERVE;
            } else if (strcasecmp(arg, "mode=enforce") == 0) {
                e->mode = BS_TMODE_ENFORCE;
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldHeuristicTrigger '%s' action=score: "
                    "unknown arg '%s' (want add=N or mode=observe)",
                    name, arg);
            }
        }
        if (!saw_add) {
            return apr_psprintf(cmd->pool,
                "BotShieldHeuristicTrigger '%s' action=score: missing "
                "required 'add=N'", name);
        }
    } else if (strcasecmp(verb, "tier_floor") == 0) {
        e->action = BS_HEUR_ACT_TIER_FLOOR;
        int saw_min = 0;
        for (; idx < argc; idx++) {
            const char *arg = argv[idx];
            if (strncasecmp(arg, "min=", 4) == 0) {
                const char *t = arg + 4;
                if      (strcasecmp(t, "nochallenge") == 0) e->tier_min = BS_TIER_PASS;
                else if (strcasecmp(t, "noninteractive") == 0)
                    e->tier_min = BS_TIER_NONINTERACTIVE;
                else if (strcasecmp(t, "interactive") == 0)
                    e->tier_min = BS_TIER_INTERACTIVE;
                else if (strcasecmp(t, "captcha") == 0) e->tier_min = BS_TIER_CAPTCHA;
                else {
                    return apr_psprintf(cmd->pool,
                        "BotShieldHeuristicTrigger '%s' action=tier_floor: "
                        "min='%s' must be one of nochallenge/noninteractive/interactive/captcha",
                        name, t);
                }
                saw_min = 1;
            } else if (strcasecmp(arg, "mode=observe") == 0) {
                e->mode = BS_TMODE_OBSERVE;
            } else if (strcasecmp(arg, "mode=enforce") == 0) {
                e->mode = BS_TMODE_ENFORCE;
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldHeuristicTrigger '%s' action=tier_floor: "
                    "unknown arg '%s' (want min=<tier> or mode=observe)",
                    name, arg);
            }
        }
        if (!saw_min) {
            return apr_psprintf(cmd->pool,
                "BotShieldHeuristicTrigger '%s' action=tier_floor: "
                "missing required 'min=<tier>'", name);
        }
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldHeuristicTrigger '%s': unknown action verb '%s' "
            "(want score or tier_floor)", name, verb);
    }

    *(bs_heuristic_trigger_entry **)apr_array_push(
        scfg->heuristic_triggers) = e;
    return NULL;
}
