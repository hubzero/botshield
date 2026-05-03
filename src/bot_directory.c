/* bot_directory.c — known-bot UA classifier with runtime override.
 *
 * Two-tier storage:
 *
 *   bs_known_bots[]               compile-time baseline (rodata)
 *   bs_bot_directory_active       runtime override pointer (atomic)
 *
 * The lookup atomically loads the active pointer; if non-NULL it
 * walks that state's entries, otherwise it walks the baseline.
 *
 * The runtime override is loaded from a TSV file via
 * bs_known_bots_load + bs_known_bots_publish. A watchdog
 * (bs_bot_directory_watchdog_cb) periodically stat()s the source
 * file and re-loads on mtime change. The atomic swap follows the
 * robots.c pattern: previously-active state is held one watchdog
 * tick before its pool is destroyed, so concurrent readers can't
 * dereference freed memory.
 *
 * All lookups are O(N) sequential strcasestr over the active table.
 * For ~600 short patterns that's sub-microsecond on typical UAs.
 * If lookups become hot-path concern, profile first; the request
 * pipeline is dominated by other costs (heuristic walk, cookie
 * verify, GCM ops). */
#include "bot_directory.h"
#include "botshield.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <apr_atomic.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <http_log.h>
#include <mod_watchdog.h>   /* AP_WATCHDOG_STATE_RUNNING */


/* --- Module-global active/pending state ------------------------- */

/* Atomically-loaded pointer to the current runtime override. NULL
 * means "use compiled-in baseline". Module-global because the bot
 * directory is conceptually module-wide — a UA classification
 * shouldn't differ per vhost.
 *
 * Per-worker propagation: each Apache worker process has its own
 * copy of this pointer (post-fork memory). The mod_watchdog
 * registration in bs_init_bot_directory uses singleton=0 so each
 * worker child gets its own watchdog tick and updates its own
 * state independently. Updates propagate within one refresh
 * interval per worker. */
static bs_known_bots_state *bs_bot_directory_active  = NULL;

/* Held one watchdog tick before pool destruction. Lets concurrent
 * readers finish dereferencing before we tear down their state.
 * Owned by whatever watchdog callback dropped it here; cleaned on
 * the next tick. */
static bs_known_bots_state *bs_bot_directory_pending = NULL;


/* --- Lookup ------------------------------------------------------ */

/* Sparse-edges scan. For ~5,500 nodes typical at this pattern
 * count, most nodes have 1-2 edges; linear scan over edges is
 * faster than a hash or 256-way table for that distribution and
 * uses far less memory. */
static int bs_ac_find_edge(const bs_ac_node *n, unsigned char b)
{
    for (int i = 0; i < n->edge_count; i++) {
        if (n->edges[i].byte == b) return n->edges[i].target;
    }
    return -1;
}

int bs_ua_is_known_bot(const char *ua,
                       const char **out_slug,
                       const char **out_category)
{
    if (out_slug)     *out_slug = NULL;
    if (out_category) *out_category = NULL;
    if (!ua || !*ua) return 0;

    /* Atomic-load the active runtime override. Acquire ordering
     * pairs with the release-store in bs_known_bots_publish so we
     * always see a fully-constructed state. */
    bs_known_bots_state *st =
        __atomic_load_n(&bs_bot_directory_active, __ATOMIC_ACQUIRE);

    /* AC fast path. Single linear pass over the UA; constant work
     * per byte regardless of pattern count. ~152x faster than the
     * sequential strcasestr loop at ~600 patterns (verified by
     * tools/bench-bot-directory.c). */
    if (st && st->ac_nodes && st->entries) {
        int cur = 0;
        for (const char *p = ua; *p; p++) {
            unsigned char b = (unsigned char)tolower((unsigned char)*p);
            /* Follow goto, falling back via failure links until we
             * either find a transition or land at the root. */
            while (cur != 0 && bs_ac_find_edge(&st->ac_nodes[cur], b) < 0) {
                cur = st->ac_nodes[cur].fail;
            }
            int next = bs_ac_find_edge(&st->ac_nodes[cur], b);
            if (next >= 0) cur = next;
            int idx = st->ac_nodes[cur].pattern_idx;
            if (idx >= 0) {
                if (out_slug)     *out_slug = st->entries[idx].slug;
                if (out_category) *out_category = st->entries[idx].category;
                return 1;
            }
        }
        return 0;
    }

    /* Fallback: AC build failed or compiled-in baseline hasn't had
     * its AC built yet. Sequential strcasestr — slow but correct. */
    const bs_known_bot_entry *entries = st ? st->entries : bs_known_bots;
    if (!entries) return 0;

    for (const bs_known_bot_entry *e = entries; e->pattern != NULL; e++) {
        if (strcasestr(ua, e->pattern) != NULL) {
            if (out_slug)     *out_slug = e->slug;
            if (out_category) *out_category = e->category;
            return 1;
        }
    }
    return 0;
}


/* --- Aho-Corasick builder ---------------------------------------- */

/* Build representation. Per-node `edges` is a growable APR array
 * scoped to the build subpool; the master nodes array is also a
 * growable APR array. After the trie + failure links are computed,
 * we copy a compact form into st->pool and destroy the build pool
 * — reclaiming all the temporary scratch in one shot.
 *
 * No malloc/realloc anywhere in this code path. Apache convention:
 * everything memory-tracked through APR pools, no manual frees. */
typedef struct ac_build_node {
    apr_array_header_t *edges;       /* of bs_ac_edge */
    int                 fail;
    int                 pattern_idx;
} ac_build_node;

static int ac_build_find_edge(const ac_build_node *n, unsigned char b)
{
    bs_ac_edge *e = (bs_ac_edge *)n->edges->elts;
    for (int i = 0; i < n->edges->nelts; i++) {
        if (e[i].byte == b) return e[i].target;
    }
    return -1;
}

int bs_known_bots_build_ac(server_rec *s, bs_known_bots_state *st)
{
    if (!st || !st->pool || !st->entries || st->count == 0) return -1;

    /* Build subpool: lifetime is just this function. Created as a
     * child of st->pool so that on any unexpected error path
     * (longjmp out of an APR exception, etc.) the parent's
     * destruction reaps the build scratch automatically. We
     * destroy it explicitly on the success path so the freed
     * memory returns to st->pool's free list before the swap
     * publishes the new state. */
    apr_pool_t *build_pool = NULL;
    if (apr_pool_create(&build_pool, st->pool) != APR_SUCCESS) {
        if (s) ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
            "mod_botshield: bot-directory AC build: "
            "subpool creation failed (falling back to sequential)");
        st->ac_nodes      = NULL;
        st->ac_node_count = 0;
        return -1;
    }

    apr_array_header_t *nodes =
        apr_array_make(build_pool, 256, sizeof(ac_build_node));

    /* Helper macro for the index-vs-pointer dance: apr_array_push
     * may realloc the underlying storage so previous element
     * pointers are invalidated. We use indices throughout and
     * re-fetch with NODE(i) immediately after any push. */
    #define NODE(i) (&((ac_build_node *)nodes->elts)[(i)])

    /* Root = node 0 */
    {
        ac_build_node *root = apr_array_push(nodes);
        root->edges       = apr_array_make(build_pool, 4,
                                           sizeof(bs_ac_edge));
        root->fail        = 0;
        root->pattern_idx = -1;
    }

    /* Insert each pattern (lowercased; lookup is case-insensitive). */
    for (apr_size_t i = 0; i < st->count; i++) {
        const char *pat = st->entries[i].pattern;
        if (!pat || !*pat) continue;
        int cur = 0;
        for (const char *p = pat; *p; p++) {
            unsigned char b = (unsigned char)tolower((unsigned char)*p);
            int next = ac_build_find_edge(NODE(cur), b);
            if (next < 0) {
                /* Allocate new node first; the push may realloc
                 * the nodes array. After the push we re-fetch
                 * cur's pointer via NODE(cur). */
                next = nodes->nelts;
                ac_build_node *new_node = apr_array_push(nodes);
                new_node->edges       = apr_array_make(build_pool, 4,
                                                       sizeof(bs_ac_edge));
                new_node->fail        = 0;
                new_node->pattern_idx = -1;

                bs_ac_edge *e = apr_array_push(NODE(cur)->edges);
                e->byte   = b;
                e->target = next;
            }
            cur = next;
        }
        /* Mark terminal — first-pattern wins on duplicates. */
        if (NODE(cur)->pattern_idx < 0) {
            NODE(cur)->pattern_idx = (int)i;
        }
    }

    int count = nodes->nelts;

    /* Failure-link BFS. Root's failure stays 0 (self). Each non-
     * root node's failure is the longest proper suffix of its
     * label that's also a prefix in the trie. Output propagation:
     * if our node isn't terminal but the failure-link target is,
     * copy the failure target's pattern_idx so traversal landing
     * on us still produces a match. */
    int *queue = apr_palloc(build_pool, sizeof(int) * count);
    int qh = 0, qt = 0;

    /* Depth-1 nodes: failure = root */
    {
        ac_build_node *root = NODE(0);
        bs_ac_edge    *e    = (bs_ac_edge *)root->edges->elts;
        for (int i = 0; i < root->edges->nelts; i++) {
            int child = e[i].target;
            NODE(child)->fail = 0;
            queue[qt++] = child;
        }
    }

    while (qh < qt) {
        int u = queue[qh++];
        bs_ac_edge *u_edges = (bs_ac_edge *)NODE(u)->edges->elts;
        int         u_count = NODE(u)->edges->nelts;
        for (int i = 0; i < u_count; i++) {
            unsigned char b = u_edges[i].byte;
            int           v = u_edges[i].target;

            int f = NODE(u)->fail;
            while (f != 0 && ac_build_find_edge(NODE(f), b) < 0) {
                f = NODE(f)->fail;
            }
            int next_via_f = ac_build_find_edge(NODE(f), b);
            if (next_via_f < 0 || next_via_f == v) {
                NODE(v)->fail = 0;
            } else {
                NODE(v)->fail = next_via_f;
            }
            if (NODE(v)->pattern_idx < 0
                && NODE(NODE(v)->fail)->pattern_idx >= 0) {
                NODE(v)->pattern_idx = NODE(NODE(v)->fail)->pattern_idx;
            }
            queue[qt++] = v;
        }
    }

    /* Copy compact form into st->pool. */
    bs_ac_node *final_nodes = apr_pcalloc(st->pool,
                                          sizeof(bs_ac_node) * count);
    for (int i = 0; i < count; i++) {
        ac_build_node *bn = NODE(i);
        final_nodes[i].fail        = bn->fail;
        final_nodes[i].pattern_idx = bn->pattern_idx;
        final_nodes[i].edge_count  = bn->edges->nelts;
        if (bn->edges->nelts > 0) {
            apr_size_t bytes = sizeof(bs_ac_edge)
                             * (apr_size_t)bn->edges->nelts;
            final_nodes[i].edges = apr_palloc(st->pool, bytes);
            memcpy(final_nodes[i].edges, bn->edges->elts, bytes);
        }
    }

    /* Reclaim all build scratch (nodes array, per-node edges
     * arrays, BFS queue) in one shot. */
    apr_pool_destroy(build_pool);

    st->ac_nodes      = final_nodes;
    st->ac_node_count = count;

    if (s) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
            "mod_botshield: bot-directory AC built "
            "(%d nodes from %" APR_SIZE_T_FMT " patterns)",
            count, st->count);
    }
    #undef NODE
    return 0;
}


/* --- TSV parser -------------------------------------------------- */

/* In-place trim leading/trailing whitespace. Returns the trimmed
 * pointer (still inside the original buffer; no allocation). */
static char *bs_trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t'
                    || end[-1] == '\r' || end[-1] == '\n')) {
        end--;
    }
    *end = '\0';
    return s;
}

bs_known_bots_state *bs_known_bots_load(server_rec *s,
                                        const char *path,
                                        apr_pool_t *parent_pool)
{
    if (!path || !*path) return NULL;

    apr_pool_t *pool = NULL;
    if (apr_pool_create(&pool, parent_pool) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: bot-directory: pool create failed");
        return NULL;
    }

    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, path,
                                    APR_READ | APR_BUFFERED,
                                    APR_OS_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, s,
            "mod_botshield: bot-directory: cannot open %s "
            "(falling back to compiled-in baseline)", path);
        apr_pool_destroy(pool);
        return NULL;
    }

    apr_finfo_t finfo;
    apr_file_info_get(&finfo, APR_FINFO_MTIME, f);

    apr_array_header_t *rows =
        apr_array_make(pool, 256, sizeof(bs_known_bot_entry));

    char line[2048];
    int lineno = 0;
    int parse_errors = 0;
    while (apr_file_gets(line, sizeof(line), f) == APR_SUCCESS) {
        lineno++;
        char *trimmed = bs_trim(line);
        if (!*trimmed || *trimmed == '#') continue;

        /* Pipe-delimited: pattern|slug|category|followsRobotsTxt */
        char *pattern = trimmed;
        char *p1 = strchr(pattern, '|');
        if (!p1) {
            if (parse_errors++ < 3) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                    "mod_botshield: bot-directory %s:%d: "
                    "missing field separator '|'; skipping",
                    path, lineno);
            }
            continue;
        }
        *p1++ = '\0';
        char *slug = p1;
        char *p2 = strchr(slug, '|');
        if (!p2) {
            if (parse_errors++ < 3) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                    "mod_botshield: bot-directory %s:%d: "
                    "expected 4 fields; skipping", path, lineno);
            }
            continue;
        }
        *p2++ = '\0';
        char *category = p2;
        char *p3 = strchr(category, '|');
        if (p3) *p3 = '\0';   /* fourth field (followsRobotsTxt)
                               * silently ignored — reserved for
                               * future use, doesn't gate parsing. */

        if (!*pattern) {
            if (parse_errors++ < 3) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                    "mod_botshield: bot-directory %s:%d: "
                    "empty pattern; skipping", path, lineno);
            }
            continue;
        }

        bs_known_bot_entry *e = (bs_known_bot_entry *)
            apr_array_push(rows);
        e->pattern  = apr_pstrdup(pool, pattern);
        e->slug     = apr_pstrdup(pool, slug);
        e->category = apr_pstrdup(pool, category);
    }

    apr_file_close(f);

    if (rows->nelts == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
            "mod_botshield: bot-directory %s parsed to zero entries; "
            "ignoring (compiled-in baseline stays active)", path);
        apr_pool_destroy(pool);
        return NULL;
    }

    /* Append NULL sentinel for the strcasestr loop. */
    bs_known_bot_entry *sentinel = (bs_known_bot_entry *)
        apr_array_push(rows);
    sentinel->pattern = sentinel->slug = sentinel->category = NULL;

    bs_known_bots_state *st = apr_pcalloc(pool, sizeof(*st));
    st->pool         = pool;
    st->entries      = (const bs_known_bot_entry *)rows->elts;
    st->count        = (apr_size_t)(rows->nelts - 1);   /* exclude sentinel */
    st->source_mtime = finfo.mtime;
    st->source_path  = apr_pstrdup(pool, path);

    /* Build AC automaton — production lookup uses this. Failure
     * here isn't fatal; lookup falls back to sequential
     * strcasestr (~150x slower but correct). */
    bs_known_bots_build_ac(s, st);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
        "mod_botshield: bot-directory loaded %s "
        "(%" APR_SIZE_T_FMT " entries%s)",
        path, st->count,
        parse_errors ? ", parse warnings logged above" : "");
    return st;
}


/* --- Baseline state from compiled-in bs_known_bots[] ------------- */

/* Build a state struct around the compiled-in baseline patterns.
 * Used at post_config when no runtime override is configured (or
 * when the override file fails to load) so the no-override case
 * still benefits from the AC fast path. The baseline data is
 * static rodata; we wrap it in a state struct + AC trie owned by
 * a fresh pool. */
bs_known_bots_state *bs_known_bots_build_baseline(server_rec *s,
                                                  apr_pool_t *parent_pool)
{
    apr_pool_t *pool = NULL;
    if (apr_pool_create(&pool, parent_pool) != APR_SUCCESS) return NULL;

    bs_known_bots_state *st = apr_pcalloc(pool, sizeof(*st));
    st->pool         = pool;
    st->entries      = bs_known_bots;       /* rodata */
    st->count        = bs_known_bots_count; /* rodata */
    st->source_mtime = 0;
    st->source_path  = "compiled-in baseline";

    bs_known_bots_build_ac(s, st);
    return st;
}


/* --- Atomic publish + drain -------------------------------------- */

void bs_known_bots_publish(server_rec *s,
                           bs_known_bots_state *new_state)
{
    /* Drain any state held over from the previous tick. By the time
     * we reach this call point, any concurrent reader that was
     * mid-walk on `pending` has had at least one watchdog tick to
     * complete. The robots.c lifecycle relies on the same
     * assumption. */
    bs_known_bots_state *to_destroy = bs_bot_directory_pending;
    bs_bot_directory_pending = NULL;

    /* Swap in the new active state. Release ordering pairs with the
     * acquire load in bs_ua_is_known_bot. */
    bs_known_bots_state *prior = __atomic_exchange_n(
        &bs_bot_directory_active, new_state, __ATOMIC_ACQ_REL);

    /* The previous active state moves into pending; it'll be
     * destroyed on the next watchdog tick. */
    bs_bot_directory_pending = prior;

    if (to_destroy) {
        apr_pool_destroy(to_destroy->pool);
    }

    if (s) {
        if (new_state) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                "mod_botshield: bot-directory active: %s "
                "(%" APR_SIZE_T_FMT " entries)",
                new_state->source_path, new_state->count);
        } else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                "mod_botshield: bot-directory: reverted to "
                "compiled-in baseline");
        }
    }
}


/* --- Watchdog ---------------------------------------------------- */

apr_status_t bs_bot_directory_watchdog_cb(int state, void *data,
                                          apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;

    server_rec *s = data;
    if (!s) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(s->module_config, &botshield_module);
    if (!scfg || !scfg->bot_directory_path) return APR_SUCCESS;

    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, scfg->bot_directory_path,
                               APR_FINFO_MTIME, s->process->pconf);
    if (rv != APR_SUCCESS) return APR_SUCCESS;

    bs_known_bots_state *active =
        __atomic_load_n(&bs_bot_directory_active, __ATOMIC_ACQUIRE);
    if (active && active->source_mtime == finfo.mtime) return APR_SUCCESS;

    bs_known_bots_state *fresh = bs_known_bots_load(
        s, scfg->bot_directory_path, s->process->pconf);
    if (!fresh) return APR_SUCCESS;

    bs_known_bots_publish(s, fresh);
    return APR_SUCCESS;
}


/* --- Directive setters ------------------------------------------ */

const char *bs_set_bot_directory(cmd_parms *cmd, void *dconf,
                                 const char *path)
{
    (void)dconf;
    if (!path || !*path) {
        return "BotShieldBotDirectory: path required";
    }
    if (path[0] != '/') {
        return "BotShieldBotDirectory: path must be absolute";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->bot_directory_path = apr_pstrdup(cmd->pool, path);
    return NULL;
}

const char *bs_set_bot_directory_refresh_interval(cmd_parms *cmd,
                                                  void *dconf,
                                                  const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end || v < 0 || v > 86400) {
        return apr_psprintf(cmd->pool,
            "BotShieldBotDirectoryRefreshInterval: '%s' must be an "
            "integer 0..86400 seconds (0 = disable live refresh)",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->bot_directory_refresh_interval = (int)v;
    return NULL;
}
