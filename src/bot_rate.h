/* bot_rate.h — slug-keyed bot rate limit.
 *
 * Cap aggregate request volume per known-bot slug (or per-pattern set
 * resolved against the bot directory). The slug universe is bounded
 * by the directory size, so all slot allocation happens at
 * post_config — no dynamic SHM mutation, no per-request hash inserts.
 *
 * Sources of rules:
 *   - BotShieldBotRateLimit directive (operator config)
 *   - robots.txt Crawl-delay groups (their User-agent stanzas resolve
 *     to slug sets via the directory)
 *
 * Wildcard semantics: "*" allocates one rate-limit slot PER directory
 * slug not covered by a specific rule. Each unmatched bot gets its
 * own counter at the wildcard budget — matches robots.txt convention
 * (per-bot self-discipline) and bounds total slot use to the
 * directory size. The unknown-bot and fake-bot labels (no stable
 * slug) share two reserved aggregate slots, also at the wildcard
 * budget.
 *
 * Lookup at request time: O(1) hash probe.
 *   1. cls->known_slug    → slug-table lookup
 *   2. cls->verified_name → slug-table lookup
 *   3. cls->is_unknown_bot → unknown-bot aggregate slot
 *   4. cls->is_fake_bot    → fake-bot aggregate slot
 *   5. otherwise → no rate limit applies. */
#ifndef BOTSHIELD_BOT_RATE_H
#define BOTSHIELD_BOT_RATE_H

#include <httpd.h>
#include <http_config.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_hash.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Per-slug rate-limit holder — one per (slug, budget, window) pairing.
 * Specific entries with multi-slug resolution share one holder across
 * all their slugs. Wildcard-derived entries each get their own holder
 * (one per directory slug), all carrying the wildcard's budget. */
typedef struct bs_bot_rate_slot {
    int          shm_slot;       /* index into bs_shm.rate_counters; -1 = unallocated */
    apr_uint32_t budget;
    apr_uint32_t window_sec;
    const char  *origin;         /* "directive" or "wildcard" or "robots.txt" */
} bs_bot_rate_slot;

/* One configured rule (directive or robots.txt-derived). Three
 * shapes:
 *   specific (default):  slugs = resolved set (sharing one counter slot)
 *   is_wildcard = 1:     slugs = NULL; expands at init over directory
 *   is_botgroup = 1:     slugs = resolved set; per-slug allocation
 *                        like wildcard but filtered by botgroup */
typedef struct bs_bot_rate_entry {
    const char         *origin;
    int                 is_wildcard;
    int                 is_botgroup;     /* @botgroup selector */
    const char         *botgroup_name;   /* "search"/"ai-input"/etc.; non-NULL when is_botgroup */
    apr_uint32_t        budget;
    apr_uint32_t        window_sec;
    apr_array_header_t *slugs;       /* const char *; NULL for wildcard */
    int                 shm_slot;    /* shared across this entry's slugs (specific only) */
} bs_bot_rate_entry;

/* Per-vhost state. */
typedef struct bs_bot_rate_state {
    apr_array_header_t  *entries;            /* bs_bot_rate_entry*, declaration order */
    apr_hash_t          *by_slug;            /* slug → bs_bot_rate_slot* */
    bs_bot_rate_slot    *unknown_bot_holder; /* NULL if no wildcard */
    bs_bot_rate_slot    *fake_bot_holder;    /* NULL if no wildcard */
    /* Catches "classified-as-bot but slug not in by_slug" — covers
     * new directory slugs added mid-run via watchdog refresh that
     * haven't been allocated their own counter (post_config snapshot
     * doesn't see them). Single aggregate slot at the wildcard
     * budget; the actual slug name is preserved in the decision-log
     * reason so operators see which bot tripped. NULL if no
     * wildcard rule is configured. */
    bs_bot_rate_slot    *wildcard_fallback_holder;
    bs_bot_rate_entry   *wildcard_entry;     /* NULL if no * rule */
    /* Set by `BotShieldBotRateLimit Off` — skip the post_config
     * default-synthesis step. Specific entries (if any) still
     * apply. Operators wanting "no rate limit at all" use this;
     * operators wanting "default + specific overrides" simply omit
     * the wildcard directive. */
    int                  default_disabled;
} bs_bot_rate_state;

/* BotShieldBotRateLimit. Three forms:
 *
 *   Off                              # disable the post_config
 *                                      default-synthesis step
 *   <slug-or-pattern-or-*> <delay>   # 1 req per <delay> seconds
 *                                      (Crawl-delay style); 0 = admit all
 *   <slug-or-pattern-or-*> <budget> <per>
 *                                    # 3-arg form: <budget> requests
 *                                      per <per> period (sec/min/hour)
 *
 * Slug-or-pattern resolves via bs_known_bots_resolve_slugs. "*"
 * reserves the wildcard-fallback semantic. Budget 1..1000000; delay
 * 0..86400 seconds. */
const char *bs_set_bot_rate_limit(cmd_parms *cmd, void *dconf,
                                  int argc, char *const argv[]);

/* Called from bs_post_config (after the existing rate-limit slot
 * assignment for directive cohorts). Assigns shm_slots per the rules
 * above, builds the slug→holder hash. *next_slot is the running
 * cursor into the rate-counter pool (shared with directive rate
 * limits + robots.txt). */
void bs_bot_rate_init(apr_pool_t *pconf, server_rec *s, int *next_slot);

/* Runtime check called from bs_check_policy. Returns:
 *   OK                       — admitted, or no rule matched
 *   HTTP_TOO_MANY_REQUESTS   — over budget; caller short-circuits
 * On 429: emits Retry-After + score+=BS_PENALTY_RATE_LIMIT +
 * decision-log reason "bot-rate:<slug>" + bumps the metric. */
int bs_bot_rate_check(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_BOT_RATE_H */
