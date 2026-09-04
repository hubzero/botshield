/* bot_rate.c — slug-keyed bot rate limit.
 *
 * Per-slug rate-limit slots, all assigned at post_config from the
 * shared SHM rate-counter pool. Reuses bs_rate_counter +
 * bs_rate_counter_admit from policy.c — same fixed-window counter
 * shape as directive rate limits. */
#include "bot_rate.h"
#include "bot_directory.h"
#include "botshield.h"
#include "metrics.h"       /* bs_set_would_outcome */
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


/* Parse a single integer "<delay-sec>" into (budget=1, window). 0 is
 * accepted and means "admit all" — bs_rate_counter_admit treats
 * window_sec=0 as a constantly-rolling window where every CAS lands
 * a fresh count=1. */
static const char *
parse_delay(apr_pool_t *p, const char *delay_s,
            apr_uint32_t *out_budget, apr_uint32_t *out_window)
{
    char *end;
    long ns = strtol(delay_s, &end, 10);
    if (!end || *end || ns < 0 || ns > 86400) {
        return apr_psprintf(p,
            "delay '%s' must be 0..86400 seconds (0 admits all)",
            delay_s);
    }
    *out_budget = 1;
    *out_window = (apr_uint32_t)ns;
    return NULL;
}


const char *bs_set_bot_rate_limit(cmd_parms *cmd, void *dconf,
                                  int argc, char *const argv[])
{
    (void)dconf;
    /* 4 args is the 3-arg form plus a trailing mode=; the mode token is
     * consumed below, after the Off check. */
    if (argc < 1 || argc > 4) {
        return "BotShieldBotRateLimit: expects 'Off', or "
               "<slug-or-pattern-or-*> <delay-sec>, or "
               "<slug-or-pattern-or-*> <budget> <per>";
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

    /* 1-arg form: 'Off' — disable post_config default synthesis. */
    if (argc == 1) {
        if (strcasecmp(argv[0], "off") != 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: single-arg form must be 'Off'; "
                "got '%s'. Use <slug> <delay-sec>, or "
                "<slug> <budget> <per>.", argv[0]);
        }
        st->default_disabled = 1;
        return NULL;
    }

    /* Optional trailing mode=enforce|observe, consumed before the
     * positional parse so the existing 2- and 3-arg forms are
     * unchanged. */
    int want_observe = 0;
    bs_bot_rate_scope want_scope = BS_BOT_RATE_EACH;
    /* Both trailing tokens are optional and order-independent, so a
     * loop rather than two positional checks. */
    while (argc > 1) {
        const char *last = argv[argc - 1];
        if (strncasecmp(last, "mode=", 5) == 0) {
            const char *m = last + 5;
            if (!strcasecmp(m, "observe"))      want_observe = 1;
            else if (!strcasecmp(m, "enforce")) want_observe = 0;
            else return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: mode='%s' must be enforce or "
                "observe", m);
        } else if (strncasecmp(last, "scope=", 6) == 0) {
            const char *sc = last + 6;
            if      (!strcasecmp(sc, "each"))  want_scope = BS_BOT_RATE_EACH;
            else if (!strcasecmp(sc, "group")) want_scope = BS_BOT_RATE_GROUP;
            else if (!strcasecmp(sc, "total")) want_scope = BS_BOT_RATE_TOTAL;
            else return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: scope='%s' must be each, group "
                "or total", sc);
        } else {
            break;
        }
        argc--;
    }
    if (argc < 2 || argc > 3) {
        return "BotShieldBotRateLimit: expected <slug> <delay-sec> or "
               "<slug> <budget> <per>, optionally followed by "
               "mode=enforce|observe and/or scope=each|group|total";
    }

    apr_uint32_t budget = 0, window = 0;
    const char *err = (argc == 2)
        ? parse_delay(cmd->pool, argv[1], &budget, &window)
        : parse_budget_window(cmd->pool, argv[1], argv[2], &budget, &window);
    if (err) {
        return apr_psprintf(cmd->pool, "BotShieldBotRateLimit: %s", err);
    }

    bs_bot_rate_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->origin     = "directive";
    e->shm_slot   = -1;
    e->observe    = want_observe;
    e->budget     = budget;
    e->window_sec = window;
    e->scope      = want_scope;

    /* The selector and the scope have to agree. A shared budget over a
     * population of one is scope=each wearing a costume, and silently
     * accepting it would put an operator one typo away from believing
     * a group cap exists when it does not. */
    if (want_scope == BS_BOT_RATE_GROUP && argv[0][0] != '@') {
        return apr_psprintf(cmd->pool,
            "BotShieldBotRateLimit: scope=group requires an @botgroup "
            "selector; '%s' names %s. Use '@search', '@ai-input', "
            "'@ai-train' or '@monitor'.", argv[0],
            strcmp(argv[0], "*") == 0 ? "every bot (did you mean "
                                        "scope=total?)" : "one bot");
    }
    if (want_scope == BS_BOT_RATE_TOTAL && strcmp(argv[0], "*") != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldBotRateLimit: scope=total applies to every bot "
            "and so requires the '*' selector; got '%s'.", argv[0]);
    }

    if (want_scope == BS_BOT_RATE_TOTAL) {
        /* Not the per-slug wildcard: this rule allocates exactly one
         * counter and never expands over the directory, so it must not
         * claim wildcard_entry -- doing so would suppress the per-slug
         * default synthesis and leave individual bots uncapped. The
         * two `*` rules are complementary and expected together. */
        if (st->global_entry) {
            return "BotShieldBotRateLimit: scope=total already defined; "
                   "only one total ceiling is permitted per scope";
        }
        st->global_entry = e;
    } else if (want_scope == BS_BOT_RATE_GROUP) {
        /* Resolution is for validation only -- the group counter is
         * wired to slugs at post_config via the directory's botgroup
         * field, so it picks up slugs added by a mid-run refresh that
         * this snapshot never saw. */
        const char *bg_name = argv[0] + 1;
        if (!*bg_name) {
            return "BotShieldBotRateLimit: '@' must be followed by a "
                   "botgroup name (search, ai-input, ai-train, monitor)";
        }
        e->botgroup_name = apr_pstrdup(cmd->pool, bg_name);
        apr_array_header_t *probe =
            bs_known_bots_resolve_by_botgroup(cmd->pool, bg_name);
        if (probe->nelts == 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: '@%s' did not resolve to any "
                "directory slug. Recognized botgroups: search, ai-input, "
                "ai-train, monitor.", bg_name);
        }
    } else if (strcmp(argv[0], "*") == 0) {
        e->is_wildcard = 1;
        if (st->wildcard_entry) {
            return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: '*' already defined; only one "
                "wildcard entry is permitted per scope");
        }
        st->wildcard_entry = e;
    } else if (argv[0][0] == '@') {
        /* @botgroup selector — resolve to all directory slugs whose
         * `botgroup` field matches. Each matched slug gets its own
         * counter (per-slug allocation, like the * wildcard but
         * scoped to one botgroup). */
        const char *bg_name = argv[0] + 1;
        if (!*bg_name) {
            return "BotShieldBotRateLimit: '@' must be followed by a "
                   "botgroup name (search, ai-input, ai-train, monitor)";
        }
        e->is_botgroup = 1;
        e->botgroup_name = apr_pstrdup(cmd->pool, bg_name);
        e->slugs = bs_known_bots_resolve_by_botgroup(cmd->pool, bg_name);
        if (e->slugs->nelts == 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: '@%s' did not resolve to any "
                "directory slug. Recognized botgroups: search, ai-input, "
                "ai-train, monitor. Check spelling or update data/"
                "bot-directory*.json with explicit botgroup fields.",
                bg_name);
        }
    } else {
        e->slugs = bs_known_bots_resolve_slugs(cmd->pool, argv[0]);
        if (e->slugs->nelts == 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldBotRateLimit: '%s' did not resolve to any "
                "directory slug; check spelling or update data/"
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
                const char *origin, int observe)
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
    h->observe    = observe;
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
 * to data/bot-directory.local.json).
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
                "Add matching entries to data/bot-directory.local.json "
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
            next_slot, e->budget, e->window_sec, e->origin, e->observe);
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

        /* Default synthesis condition: module is enabled at vhost
         * scope (On or LogOnly), no operator BotShieldBotRateLimit
         * directive was configured, and the operator didn't write
         * `BotShieldBotRateLimit Off` to opt out. The default is
         * `* 1 sec` — 1 req/sec per directory slug, Crawl-delay-style. */
        bs_dir_cfg *dcfg = ap_get_module_config(sv->lookup_defaults,
                                                &botshield_module);
        int module_enabled = dcfg
            && (dcfg->enabled == BS_ENABLED_ON
             || dcfg->enabled == BS_ENABLED_LOGONLY);

        /* Lazy-init state when there's robots.txt content or the
         * module is enabled (so the default can fire). */
        if (!scfg->bot_rate_state) {
            int robots = robots_has_crawl_delay(scfg);
            if (!robots && !module_enabled) continue;
            scfg->bot_rate_state = apr_pcalloc(pconf,
                sizeof(*scfg->bot_rate_state));
            scfg->bot_rate_state->entries = apr_array_make(pconf, 8,
                sizeof(bs_bot_rate_entry *));
        }
        bs_bot_rate_state *st = scfg->bot_rate_state;

        /* Pre-init synthesis: if the operator wrote nothing, install
         * a synthetic wildcard at 1 req/sec. The synthetic entry
         * goes through the same pre-allocation path as a directive
         * wildcard. */
        if (module_enabled
            && !st->wildcard_entry
            && !st->default_disabled
            && st->entries->nelts == 0) {
            bs_bot_rate_entry *def = apr_pcalloc(pconf, sizeof(*def));
            def->origin     = "default";
            def->is_wildcard = 1;
            def->budget     = 1;
            def->window_sec = 1;
            def->shm_slot   = -1;
            st->wildcard_entry = def;
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: BotShieldBotRateLimit default applied: "
                "* 1 sec (1 req/sec per directory slug). Override with "
                "explicit BotShieldBotRateLimit directives, or "
                "'BotShieldBotRateLimit Off' to disable entirely.");
        }

        st->by_slug = apr_hash_make(pconf);

        /* Pass 0 — robots.txt-derived entries. Processed first so the
         * directive pass can overwrite (directive wins on conflict). */
        int robots_count = register_robots_entries(pconf, sv, scfg, st,
                                                   next_slot);

        int specific_count = 0;
        int botgroup_count = 0;
        int wildcard_count = 0;

        /* Pass 1 — specific entries (substring-resolved or
         * literal-slug-resolved). Each entry's resolved slug set
         * shares ONE counter slot at the entry's budget. */
        for (int i = 0; i < st->entries->nelts; i++) {
            bs_bot_rate_entry *e = APR_ARRAY_IDX(st->entries, i,
                                                 bs_bot_rate_entry *);
            /* scope=group and scope=total allocate one shared counter
             * in the tier passes below and carry no slug list at all,
             * so they must not reach the per-slug walk -- it
             * dereferences e->slugs unconditionally. */
            if (e->is_wildcard || e->is_botgroup) continue;
            if (e->scope != BS_BOT_RATE_EACH) continue;
            const char *first_slug = (e->slugs && e->slugs->nelts > 0)
                ? APR_ARRAY_IDX(e->slugs, 0, const char *) : "?";
            bs_bot_rate_slot *h = allocate_holder(pconf, sv,
                apr_pstrcat(pconf, "directive ", first_slug, NULL),
                next_slot, e->budget, e->window_sec, e->origin, e->observe);
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

        /* Pass 2 — @botgroup entries. For each entry, walk its
         * resolved slug set; for slugs not yet mapped (specific
         * entries already claimed them), allocate one slot per slug
         * at the entry's budget. Per-slug allocation, NOT aggregate
         * — matches the wildcard pattern but scoped to a botgroup. */
        for (int i = 0; i < st->entries->nelts; i++) {
            bs_bot_rate_entry *e = APR_ARRAY_IDX(st->entries, i,
                                                 bs_bot_rate_entry *);
            if (!e->is_botgroup) continue;
            for (int j = 0; j < e->slugs->nelts; j++) {
                const char *slug = APR_ARRAY_IDX(e->slugs, j,
                                                 const char *);
                if (apr_hash_get(st->by_slug, slug, APR_HASH_KEY_STRING)) {
                    continue;   /* specific entry won */
                }
                bs_bot_rate_slot *h = allocate_holder(pconf, sv,
                    apr_pstrcat(pconf, "botgroup:", e->botgroup_name,
                                " ", slug, NULL),
                    next_slot, e->budget, e->window_sec,
                    apr_pstrcat(pconf, "botgroup:", e->botgroup_name,
                                NULL), e->observe);
                if (!h) break;
                apr_hash_set(st->by_slug, slug, APR_HASH_KEY_STRING, h);
                botgroup_count++;
            }
        }

        /* Pass 3 — wildcard. For every directory slug not yet mapped,
         * allocate a separate slot at the wildcard's budget. Plus the
         * four reserved aggregate slots (unknown-bot, no-ua, fake-bot,
         * wildcard-fallback). */
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
                    next_slot, budget, window, "wildcard", st->wildcard_entry->observe);
                if (!h) break;  /* pool exhausted; remaining slugs unprotected */
                apr_hash_set(st->by_slug, slug, APR_HASH_KEY_STRING, h);
                wildcard_count++;
            }
            st->unknown_bot_holder = allocate_holder(pconf, sv,
                "unknown-bot aggregate", next_slot,
                budget, window, "wildcard:unknown-bot", st->wildcard_entry->observe);
            st->no_ua_holder       = allocate_holder(pconf, sv,
                "no-ua aggregate", next_slot,
                budget, window, "wildcard:no-ua", st->wildcard_entry->observe);
            st->fake_bot_holder    = allocate_holder(pconf, sv,
                "fake-bot aggregate", next_slot,
                budget, window, "wildcard:fake-bot", st->wildcard_entry->observe);
            /* v2a — fallback for slugs added mid-run that missed
             * the post_config snapshot (e.g., bot-directory watchdog
             * refresh adds entries; their slugs aren't in by_slug
             * until graceful-restart). Aggregate semantics until
             * v2b's SHM-resident slot table lands. */
            st->wildcard_fallback_holder = allocate_holder(pconf, sv,
                "wildcard-fallback aggregate", next_slot,
                budget, window, "wildcard:fallback", st->wildcard_entry->observe);

            /* fallthrough to the tier-2/3 allocation below */
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: BotShieldBotRateLimit: %d directive + "
                "%d robots.txt + %d botgroup + %d wildcard slot(s) + "
                "%s%s%s%saggregate(s) (pool cursor at %d/%d)",
                specific_count, robots_count, botgroup_count,
                wildcard_count,
                st->unknown_bot_holder        ? "unknown-bot "        : "",
                st->no_ua_holder              ? "no-ua "              : "",
                st->fake_bot_holder           ? "fake-bot "           : "",
                st->wildcard_fallback_holder  ? "wildcard-fallback "  : "",
                *next_slot, (int)bs_shm.rate_counter_count);
        } else if (specific_count > 0 || botgroup_count > 0
                   || robots_count > 0) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: BotShieldBotRateLimit: %d directive + "
                "%d robots.txt + %d botgroup slot(s); no wildcard rule "
                "(unmatched bots not rate-limited)",
                specific_count, robots_count, botgroup_count);
        }

        /* ---- Tier 2: one shared counter per scope=group rule ---- */
        for (int i = 0; i < st->entries->nelts; i++) {
            bs_bot_rate_entry *e = APR_ARRAY_IDX(st->entries, i,
                                                 bs_bot_rate_entry *);
            if (e->scope != BS_BOT_RATE_GROUP) continue;
            if (!st->group_holders) {
                st->group_holders = apr_hash_make(pconf);
            }
            if (apr_hash_get(st->group_holders, e->botgroup_name,
                             APR_HASH_KEY_STRING)) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                    "mod_botshield: BotShieldBotRateLimit: '@%s "
                    "scope=group' declared more than once; keeping the "
                    "first", e->botgroup_name);
                continue;
            }
            bs_bot_rate_slot *h = allocate_holder(pconf, sv,
                apr_pstrcat(pconf, "group aggregate ",
                            e->botgroup_name, NULL),
                next_slot, e->budget, e->window_sec,
                "directive:group", e->observe);
            if (!h) continue;
            h->label = apr_pstrcat(pconf, "@", e->botgroup_name, NULL);
            apr_hash_set(st->group_holders, e->botgroup_name,
                         APR_HASH_KEY_STRING, h);
        }

        /* Wire every allocated slug to its group counter, once, so the
         * request path never touches the directory. Done from the
         * directory's botgroup field rather than from the rule's
         * resolved slug list: a mid-run directory refresh can add slugs
         * this snapshot never saw, and they should still count against
         * their group. */
        if (st->group_holders) {
            int wired = 0;
            for (apr_hash_index_t *hi = apr_hash_first(pconf, st->by_slug);
                 hi; hi = apr_hash_next(hi)) {
                const void *k; void *v;
                apr_hash_this(hi, &k, NULL, &v);
                bs_bot_rate_slot *h = v;
                const char *cat = NULL, *bg = NULL;
                if (!h) continue;
                bs_bot_dir_lookup_slug((const char *)k, &cat, &bg);
                if (!bg) continue;
                h->group = apr_hash_get(st->group_holders, bg,
                                        APR_HASH_KEY_STRING);
                if (h->group) wired++;
            }
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: BotShieldBotRateLimit: %d group "
                "aggregate(s), %d slug(s) wired to one",
                apr_hash_count(st->group_holders), wired);
        }

        /* ---- Tier 3: the total ceiling ---- */
        if (st->global_entry) {
            st->global_holder = allocate_holder(pconf, sv,
                "total ceiling", next_slot,
                st->global_entry->budget, st->global_entry->window_sec,
                "directive:total", st->global_entry->observe);
            if (st->global_holder) {
                st->global_holder->label = "*";
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                    "mod_botshield: BotShieldBotRateLimit: total "
                    "ceiling %u req / %us across every bot (%s). This "
                    "is a circuit breaker: if it trips in normal "
                    "operation it is set too low.",
                    st->global_entry->budget,
                    st->global_entry->window_sec,
                    st->global_entry->observe ? "observe" : "enforce");
            }
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

    /* LogOnly observe — over-budget gets logged as ~rate_limited
     * instead of returning 429. Mirrors the directive rate-limit
     * cohort path's observe handling at policy.c:478-488. */
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    int log_only = dcfg && dcfg->enabled == BS_ENABLED_LOGONLY;

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
    /* Before the unknown-bot check, because is_no_ua implies
     * is_unknown_bot and the more specific bucket must win. */
    if (!holder && cls->is_no_ua && st->no_ua_holder) {
        holder = st->no_ua_holder;
        slug_for_log = "no-ua";
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

    /* Count the request before deciding on it. This is "requests seen
     * attributed to this slot", not "requests admitted": a bot that is
     * being 429'd is precisely the one an operator wants to find on the
     * bots page, and a total that excluded its refusals would shrink as
     * the limiter started working. */
    if (bs_shm.rate_totals &&
        (apr_size_t)holder->shm_slot < bs_shm.rate_counter_count) {
        __atomic_fetch_add(&bs_shm.rate_totals[holder->shm_slot], 1,
                           __ATOMIC_RELAXED);
    }

    /* Sample the agent for the bots page. The whole fixed-size block is
     * written from a NUL-padded local, so whichever child lands last
     * leaves a terminated string even if two interleave mid-copy.
     *
     * Skipped when the stored sample already matches: for a single-bot
     * slot that is every request after the first, and the compare is
     * cheaper than dirtying a shared cacheline 200 times a second. */
    if (bs_shm.rate_ua &&
        (apr_size_t)holder->shm_slot < bs_shm.rate_counter_count) {
        const char *ua = apr_table_get(r->headers_in, "User-Agent");
        char *dst = bs_shm.rate_ua + (apr_size_t)holder->shm_slot
                                     * BS_RATE_UA_MAX;
        if (!ua) ua = "";
        if (strncmp(dst, ua, BS_RATE_UA_MAX - 1) != 0) {
            char buf[BS_RATE_UA_MAX];
            memset(buf, 0, sizeof(buf));
            apr_cpystrn(buf, ua, sizeof(buf));
            memcpy(dst, buf, sizeof(buf));
        }
    }

    bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
    if (!counters) return OK;

    /* ---- Multi-tier evaluation ------------------------------------
     * Three budgets can apply to one request: this bot's own, its
     * botgroup's, and the total ceiling. Every applicable tier is
     * charged even when an earlier one has already refused, because a
     * tier that stops counting during the event it exists to detect
     * undercounts exactly when its number matters. The refusal is the
     * first tier that trips, most specific first, and Retry-After is
     * the longest wait among those that tripped -- retrying sooner
     * than the widest budget allows is guaranteed to fail again.
     *
     * The status differs by tier and that difference is the point. A
     * slug trip means this client exceeded its own quota: 429. A group
     * or total trip means the client did nothing wrong and the site is
     * out of what it is willing to give: 503 with Retry-After, which
     * crawlers treat as "come back later" rather than as a signal to
     * drop the URL. Answering 429 there would blame a well-behaved bot
     * for a capacity decision. */
    bs_bot_rate_slot *tiers[3];
    int ntiers = 0;
    tiers[ntiers++] = holder;
    if (holder->group)    tiers[ntiers++] = holder->group;
    if (st->global_holder) tiers[ntiers++] = st->global_holder;

    bs_bot_rate_slot *tripped = NULL;   /* first (most specific) */
    apr_uint32_t retry_max = 0;
    apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
    int tripped_is_slug = 0;

    for (int i = 0; i < ntiers; i++) {
        bs_bot_rate_slot *t = tiers[i];
        if (t->shm_slot < 0) continue;
        if (bs_rate_counter_admit(&counters[t->shm_slot],
                                  t->budget, t->window_sec)) {
            continue;
        }
        if (!tripped) {
            tripped = t;
            tripped_is_slug = (i == 0);
        }
        apr_uint32_t win = __atomic_load_n(
            &counters[t->shm_slot].window_start_sec, __ATOMIC_RELAXED);
        apr_uint32_t rt = (now >= win && now - win < t->window_sec)
                            ? t->window_sec - (now - win) : 1;
        if (rt > retry_max) retry_max = rt;
    }

    if (!tripped) {
        return OK;
    }
    /* Reported as whichever tier refused: "bot-rate:@ai-train" reads
     * very differently from "bot-rate:claude-searchbot", and an
     * operator seeing the latter would go tune the wrong budget. */
    const char *trip_label = tripped->label ? tripped->label
                           : (slug_for_log ? slug_for_log : "?");
    holder = tripped;
    slug_for_log = trip_label;

    /* Over budget. Observe when the scope is LogOnly, or when the rule
     * itself says mode=observe. The per-rule form matters because the
     * wildcard default is synthesised rather than written: enabling the
     * module at vhost scope starts enforcing a crawl-delay nobody
     * chose, and there is otherwise no way to watch it first short of
     * turning rate limiting off entirely and losing the evidence. */
    if (log_only || holder->observe) {
        /* Observation only — log a ~rate_limited would-outcome and
         * a :observe-suffixed reason, don't 429 the request.
         * Mirrors the directive rate-limit cohort observe path. */
        bs_score_add(r, 0, 0,
            apr_pstrcat(r->pool, "bot-rate:",
                slug_for_log ? slug_for_log : "?",
                ":observe", NULL));
        bs_set_would_outcome(r, "~rate_limited");
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->rate_limit_observed_total,
                               1, __ATOMIC_RELAXED);
        }
        return OK;
    }
    apr_table_setn(r->err_headers_out, "Retry-After",
        apr_psprintf(r->pool, "%u", retry_max ? retry_max : 1));
    /* The score penalty is the client's record of misbehaviour, so it
     * is charged only when the client is the one who overspent. A bot
     * refused because the site hit its own ceiling has done nothing to
     * earn a mark against it, and would otherwise accumulate score
     * toward a challenge for being present during someone else's
     * spike. */
    bs_score_add(r, tripped_is_slug ? BS_PENALTY_RATE_LIMIT : 0,
                 tripped_is_slug ? 3600 : 0,
                 apr_pstrcat(r->pool, "bot-rate:", trip_label, NULL));
    if (bs_shm.metrics) {
        __atomic_fetch_add(&bs_shm.metrics->rate_limit_exceeded_total,
                           1, __ATOMIC_RELAXED);
    }
    return tripped_is_slug ? HTTP_TOO_MANY_REQUESTS
                           : HTTP_SERVICE_UNAVAILABLE;
}
