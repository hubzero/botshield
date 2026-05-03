/* bot_rate.c — slug-keyed bot rate limit.
 *
 * Per-slug rate-limit slots, all assigned at post_config from the
 * shared SHM rate-counter pool. Reuses bs_rate_counter +
 * bs_rate_counter_admit from policy.c — same fixed-window counter
 * shape as directive rate limits. */
#include "bot_rate.h"
#include "bot_directory.h"
#include "botshield.h"
#include "policy.h"        /* bs_rate_counter_admit */
#include "robots.h"        /* bs_robots_state, robots_group_* */
#include "score.h"
#include "shm.h"
#include "triggers.h"      /* bs_rate_counter, BS_PENALTY_RATE_LIMIT */
#include "ua_class.h"

#include <string.h>

#include <apr_atomic.h>
#include <apr_strings.h>
#include <http_log.h>


/* Parse "<budget> <per>" into (budget, window_sec). Returns NULL
 * on success, an error string on failure. */
static const char *
parse_budget_window(apr_pool_t *p, const char *budget_s, const char *per_s,
                    apr_uint32_t *out_budget, apr_uint32_t *out_window)
{
    char *end;
    long bn = strtol(budget_s, &end, 10);
    if (!end || *end || bn < 1 || bn > 1000000) {
        return apr_psprintf(p,
            "budget '%s' must be 1..1000000", budget_s);
    }
    apr_uint32_t window;
    if      (!strcasecmp(per_s, "sec")  || !strcasecmp(per_s, "s")) window = 1;
    else if (!strcasecmp(per_s, "min")  || !strcasecmp(per_s, "m")) window = 60;
    else if (!strcasecmp(per_s, "hour") || !strcasecmp(per_s, "h")) window = 3600;
    else return apr_psprintf(p,
            "per '%s' must be sec|min|hour (or s|m|h)", per_s);
    *out_budget = (apr_uint32_t)bn;
    *out_window = window;
    return NULL;
}


const char *bs_set_bot_rate_limit(cmd_parms *cmd, void *dconf,
                                  int argc, char *const argv[])
{
    (void)dconf;
    if (argc != 3) {
        return "BotShieldBotRateLimit: expects <slug-or-pattern-or-*> "
               "<budget> <per>";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!scfg->bot_rate_state) {
        scfg->bot_rate_state = apr_pcalloc(cmd->pool,
                                           sizeof(*scfg->bot_rate_state));
        scfg->bot_rate_state->entries = apr_array_make(cmd->pool, 8,
            sizeof(bs_bot_rate_entry *));
    }
    bs_bot_rate_state *st = scfg->bot_rate_state;

    apr_uint32_t budget = 0, window = 0;
    const char *err = parse_budget_window(cmd->pool, argv[1], argv[2],
                                          &budget, &window);
    if (err) {
        return apr_psprintf(cmd->pool, "BotShieldBotRateLimit: %s", err);
    }

    bs_bot_rate_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->origin     = "directive";
    e->shm_slot   = -1;
    e->budget     = budget;
    e->window_sec = window;

    if (strcmp(argv[0], "*") == 0) {
        e->is_wildcard = 1;
        if (st->wildcard_entry) {
            return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: '*' already defined; only one "
                "wildcard entry is permitted per scope");
        }
        st->wildcard_entry = e;
    } else {
        e->slugs = bs_known_bots_resolve_slugs(cmd->pool, argv[0]);
        if (e->slugs->nelts == 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: '%s' did not resolve to any "
                "directory slug; check spelling or update vendor/"
                "bot-directory*.json", argv[0]);
        }
    }

    *(bs_bot_rate_entry **)apr_array_push(st->entries) = e;
    return NULL;
}


/* Allocate a holder + assign a slot. Returns NULL on slot exhaustion;
 * caller falls through (request gets no bot rate limit, graceful
 * degradation). */
static bs_bot_rate_slot *
allocate_holder(apr_pool_t *pconf, server_rec *sv,
                const char *what, int *next_slot,
                apr_uint32_t budget, apr_uint32_t window_sec,
                const char *origin)
{
    if (*next_slot >= (int)bs_shm.rate_counter_count) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: BotShieldBotRateLimit: rate-counter pool "
            "exhausted (%d slots); %s falls through to no-rate-limit. "
            "Increase BS_E21_RATE_SLOTS in src/config.c and rebuild.",
            (int)bs_shm.rate_counter_count, what);
        return NULL;
    }
    bs_bot_rate_slot *h = apr_pcalloc(pconf, sizeof(*h));
    h->shm_slot   = (*next_slot)++;
    h->budget     = budget;
    h->window_sec = window_sec;
    h->origin     = origin;
    return h;
}


/* Returns 1 if this vhost's robots.txt has at least one group with a
 * positive Crawl-delay (i.e., something we'd register as a bot_rate
 * entry). Used to decide whether to lazy-init bot_rate_state when no
 * BotShieldBotRateLimit directive was configured. */
static int robots_has_crawl_delay(bs_server_cfg *scfg)
{
    if (!scfg) return 0;
    bs_robots_state *rstate =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    if (!rstate || !rstate->doc) return 0;
    int n = robots_group_count(rstate->doc);
    for (int g = 0; g < n; g++) {
        if (robots_group_crawl_delay_at(rstate->doc, g) > 0) return 1;
    }
    return 0;
}


/* Walk this vhost's parsed robots.txt and register one bot_rate
 * entry per group with a Crawl-delay. The group's User-agent
 * stanzas resolve to a slug-set via the bot directory; all matching
 * slugs share one counter at the group's Crawl-delay budget.
 *
 * Robots.txt User-agent: * resolves to bot_rate_state.wildcard_entry,
 * but only if a directive wildcard isn't already set (directive wins
 * on conflict; same rule as specific entries). Stanzas that don't
 * resolve to any directory slug are logged + skipped (the group has
 * no enforcement until the operator adds matching directory entries
 * to vendor/bot-directory.local.json).
 *
 * Called from bs_bot_rate_init BEFORE the directive-entry pass — so
 * directives processed second naturally overwrite robots.txt entries
 * on slug conflict (per "later wins" semantics). */
static int register_robots_entries(apr_pool_t *pconf, server_rec *sv,
                                   bs_server_cfg *scfg,
                                   bs_bot_rate_state *st,
                                   int *next_slot)
{
    bs_robots_state *rstate =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    if (!rstate || !rstate->doc) return 0;

    int registered = 0;
    int n = robots_group_count(rstate->doc);
    for (int g = 0; g < n; g++) {
        int crawl_delay = robots_group_crawl_delay_at(rstate->doc, g);
        if (crawl_delay <= 0) continue;

        const char *gname = robots_group_name_at(rstate->doc, g);
        bs_bot_rate_entry *e = apr_pcalloc(pconf, sizeof(*e));
        e->origin     = "robots.txt";
        e->budget     = 1;
        e->window_sec = (apr_uint32_t)crawl_delay;
        e->shm_slot   = -1;

        if (robots_group_is_wildcard_at(rstate->doc, g)) {
            e->is_wildcard = 1;
            if (st->wildcard_entry) {
                /* Directive wildcard already set in bs_set_bot_rate_limit;
                 * directive wins. */
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                    "mod_botshield: robots.txt User-agent: * "
                    "Crawl-delay: %d ignored — BotShieldBotRateLimit "
                    "* directive already configured (directive wins)",
                    crawl_delay);
                continue;
            }
            st->wildcard_entry = e;
            registered++;
            continue;   /* wildcard expansion happens later in init */
        }

        /* Specific group: resolve UA stanzas to a deduped slug set. */
        e->slugs = apr_array_make(pconf, 4, sizeof(const char *));
        apr_hash_t *seen = apr_hash_make(pconf);
        int ua_count = robots_group_ua_count_at(rstate->doc, g);
        for (int u = 0; u < ua_count; u++) {
            const char *ua = robots_group_ua_at(rstate->doc, g, u);
            if (!ua || !*ua) continue;
            apr_array_header_t *resolved =
                bs_known_bots_resolve_slugs(pconf, ua);
            for (int s2 = 0; s2 < resolved->nelts; s2++) {
                const char *slug = APR_ARRAY_IDX(resolved, s2,
                                                 const char *);
                if (!apr_hash_get(seen, slug, APR_HASH_KEY_STRING)) {
                    apr_hash_set(seen, slug, APR_HASH_KEY_STRING,
                                 (void *)1);
                    *(const char **)apr_array_push(e->slugs) = slug;
                }
            }
        }

        if (e->slugs->nelts == 0) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: robots.txt group '%s' has Crawl-delay: "
                "%d but its User-agent stanza(s) don't resolve to any "
                "directory slug; group has no rate-limit enforcement. "
                "Add matching entries to vendor/bot-directory.local.json "
                "if you want this group enforced.",
                gname ? gname : "?", crawl_delay);
            continue;
        }

        /* Allocate slot + register slugs immediately (before directive
         * pass runs). Conflict logging is suppressed here — robots.txt
         * is the FIRST source of entries, so by_slug is empty. The
         * directive pass below may overwrite these with NOTICE. */
        bs_bot_rate_slot *h = allocate_holder(pconf, sv,
            apr_pstrcat(pconf, "robots.txt ",
                APR_ARRAY_IDX(e->slugs, 0, const char *), NULL),
            next_slot, e->budget, e->window_sec, e->origin);
        if (!h) continue;
        e->shm_slot = h->shm_slot;
        for (int j = 0; j < e->slugs->nelts; j++) {
            const char *slug = APR_ARRAY_IDX(e->slugs, j, const char *);
            apr_hash_set(st->by_slug, slug, APR_HASH_KEY_STRING, h);
        }
        registered++;
    }
    return registered;
}


void bs_bot_rate_init(apr_pool_t *pconf, server_rec *s, int *next_slot)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *scfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!scfg) continue;

        /* Lazy-init state when robots.txt has rate-limit content but
         * no directives were configured. */
        if (!scfg->bot_rate_state) {
            if (!robots_has_crawl_delay(scfg)) continue;
            scfg->bot_rate_state = apr_pcalloc(pconf,
                sizeof(*scfg->bot_rate_state));
            scfg->bot_rate_state->entries = apr_array_make(pconf, 8,
                sizeof(bs_bot_rate_entry *));
        }
        bs_bot_rate_state *st = scfg->bot_rate_state;
        st->by_slug = apr_hash_make(pconf);

        /* Pass 0 — robots.txt-derived entries. Processed first so the
         * directive pass can overwrite (directive wins on conflict). */
        int robots_count = register_robots_entries(pconf, sv, scfg, st,
                                                   next_slot);

        int specific_count = 0;
        int wildcard_count = 0;

        /* Pass 1 — specific entries. Each entry's resolved slugs
         * share ONE counter slot at the entry's budget. */
        for (int i = 0; i < st->entries->nelts; i++) {
            bs_bot_rate_entry *e = APR_ARRAY_IDX(st->entries, i,
                                                 bs_bot_rate_entry *);
            if (e->is_wildcard) continue;
            const char *first_slug = (e->slugs && e->slugs->nelts > 0)
                ? APR_ARRAY_IDX(e->slugs, 0, const char *) : "?";
            bs_bot_rate_slot *h = allocate_holder(pconf, sv,
                apr_pstrcat(pconf, "directive ", first_slug, NULL),
                next_slot, e->budget, e->window_sec, e->origin);
            if (!h) continue;
            e->shm_slot = h->shm_slot;
            specific_count++;
            for (int j = 0; j < e->slugs->nelts; j++) {
                const char *slug = APR_ARRAY_IDX(e->slugs, j,
                                                 const char *);
                bs_bot_rate_slot *prior = apr_hash_get(st->by_slug,
                    slug, APR_HASH_KEY_STRING);
                if (prior) {
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                        "mod_botshield: BotShieldBotRateLimit: slug "
                        "'%s' already mapped (prior origin=%s); later "
                        "definition (origin=%s) wins",
                        slug, prior->origin, e->origin);
                }
                apr_hash_set(st->by_slug, slug, APR_HASH_KEY_STRING, h);
            }
        }

        /* Pass 2 — wildcard. For every directory slug not yet mapped,
         * allocate a separate slot at the wildcard's budget. Plus the
         * two reserved aggregate slots (unknown-bot, fake-bot). */
        if (st->wildcard_entry) {
            apr_uint32_t budget = st->wildcard_entry->budget;
            apr_uint32_t window = st->wildcard_entry->window_sec;
            for (int i = 0; bs_known_bots[i].slug != NULL; i++) {
                const char *slug = bs_known_bots[i].slug;
                if (apr_hash_get(st->by_slug, slug, APR_HASH_KEY_STRING)) {
                    continue;   /* covered by specific entry */
                }
                bs_bot_rate_slot *h = allocate_holder(pconf, sv,
                    apr_pstrcat(pconf, "wildcard ", slug, NULL),
                    next_slot, budget, window, "wildcard");
                if (!h) break;  /* pool exhausted; remaining slugs unprotected */
                apr_hash_set(st->by_slug, slug, APR_HASH_KEY_STRING, h);
                wildcard_count++;
            }
            st->unknown_bot_holder = allocate_holder(pconf, sv,
                "unknown-bot aggregate", next_slot,
                budget, window, "wildcard:unknown-bot");
            st->fake_bot_holder    = allocate_holder(pconf, sv,
                "fake-bot aggregate", next_slot,
                budget, window, "wildcard:fake-bot");
            /* v2a — fallback for slugs added mid-run that missed
             * the post_config snapshot (e.g., bot-directory watchdog
             * refresh adds entries; their slugs aren't in by_slug
             * until graceful-restart). Aggregate semantics until
             * v2b's SHM-resident slot table lands. */
            st->wildcard_fallback_holder = allocate_holder(pconf, sv,
                "wildcard-fallback aggregate", next_slot,
                budget, window, "wildcard:fallback");

            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: BotShieldBotRateLimit: %d directive + "
                "%d robots.txt slot(s) + %d wildcard slot(s) + %s%s%s"
                "aggregate(s) (pool cursor at %d/%d)",
                specific_count, robots_count, wildcard_count,
                st->unknown_bot_holder        ? "unknown-bot "        : "",
                st->fake_bot_holder           ? "fake-bot "           : "",
                st->wildcard_fallback_holder  ? "wildcard-fallback "  : "",
                *next_slot, (int)bs_shm.rate_counter_count);
        } else if (specific_count > 0 || robots_count > 0) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: BotShieldBotRateLimit: %d directive + "
                "%d robots.txt slot(s); no wildcard rule (unmatched "
                "bots not rate-limited)",
                specific_count, robots_count);
        }
    }
}


int bs_bot_rate_check(request_rec *r)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg || !scfg->bot_rate_state || !scfg->bot_rate_state->by_slug) {
        return OK;
    }
    bs_bot_rate_state *st = scfg->bot_rate_state;

    const bs_ua_class *cls = bs_classify_request_ua(r);
    if (!cls) return OK;

    bs_bot_rate_slot *holder = NULL;
    const char *slug_for_log = NULL;

    /* Lookup order: known_slug → verified_name → unknown-bot
     * aggregate → fake-bot aggregate. */
    if (cls->known_slug && *cls->known_slug) {
        holder = apr_hash_get(st->by_slug, cls->known_slug,
                              APR_HASH_KEY_STRING);
        if (holder) slug_for_log = cls->known_slug;
    }
    if (!holder && cls->verified_name && *cls->verified_name) {
        holder = apr_hash_get(st->by_slug, cls->verified_name,
                              APR_HASH_KEY_STRING);
        if (holder) slug_for_log = cls->verified_name;
    }
    if (!holder && cls->is_unknown_bot && st->unknown_bot_holder) {
        holder = st->unknown_bot_holder;
        slug_for_log = "unknown-bot";
    }
    if (!holder && cls->is_fake_bot && st->fake_bot_holder) {
        holder = st->fake_bot_holder;
        slug_for_log = "fake-bot";
    }
    /* v2a — wildcard-fallback aggregate. Catches the
     * "classified-as-known/verified-bot but slug missed by_slug"
     * case (new directory slugs added mid-run via watchdog refresh
     * before graceful-restart). The actual slug name is preserved
     * in slug_for_log so operators see which bot tripped, even
     * though the counter is shared with other unmapped slugs. */
    if (!holder && st->wildcard_fallback_holder) {
        const char *fallback_slug = NULL;
        if (cls->known_slug && *cls->known_slug)         fallback_slug = cls->known_slug;
        else if (cls->verified_name && *cls->verified_name) fallback_slug = cls->verified_name;
        if (fallback_slug) {
            holder = st->wildcard_fallback_holder;
            slug_for_log = fallback_slug;
        }
    }

    if (!holder || holder->shm_slot < 0) return OK;

    bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
    if (!counters) return OK;
    bs_rate_counter *slot = &counters[holder->shm_slot];

    if (bs_rate_counter_admit(slot, holder->budget, holder->window_sec)) {
        return OK;
    }

    /* Over budget. */
    apr_uint32_t win = __atomic_load_n(&slot->window_start_sec,
                                       __ATOMIC_RELAXED);
    apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
    apr_uint32_t retry = (now >= win && now - win < holder->window_sec)
                          ? holder->window_sec - (now - win) : 1;
    apr_table_setn(r->err_headers_out, "Retry-After",
        apr_psprintf(r->pool, "%u", retry));
    bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
        apr_pstrcat(r->pool, "bot-rate:",
            slug_for_log ? slug_for_log : "?", NULL));
    if (bs_shm.metrics) {
        __atomic_fetch_add(&bs_shm.metrics->rate_limit_exceeded_total,
                           1, __ATOMIC_RELAXED);
    }
    return HTTP_TOO_MANY_REQUESTS;
}
