/* bot_directory.h — known-bot UA classifier backed by a vendored
 * snapshot of the Cloudflare bot directory, with optional runtime
 * override.
 *
 * Two-tier storage:
 *
 *   Compile-time baseline: src/generated_bot_directory.c (codegenned
 *     from vendor/bot-directory.json at build). The static
 *     bs_known_bots[] array is always available and compiled into the
 *     .so. If no runtime override is configured, this is what every
 *     lookup uses.
 *
 *   Runtime override: an operator-controlled TSV file at the path
 *     given by BotShieldBotDirectory. Re-parsed by a watchdog at
 *     BotShieldBotDirectoryRefreshInterval. Refreshed in-place via
 *     tools/refresh-bot-directory.py without rebuilding the module.
 *     If the file disappears or fails to parse, the lookup falls back
 *     to the compiled-in baseline.
 *
 * Purpose: distinguish "this UA belongs to a known crawler/bot" from
 * "this UA looks like a real user." Used as the classifier feeding
 * BotShield's robots.txt wildcard-rule application — known-bot UAs
 * fall under wildcard policy; everything else (real browsers, custom
 * apps) bypasses it.
 *
 * UA-only: this is NOT a trust authority. A scraper that sets
 * `User-Agent: Googlebot/2.1` matches the directory and is classified
 * as a bot — which is exactly the outcome we want, since they end up
 * subject to whatever robots.txt policy applies to bots. Real
 * authentication of crawlers (UA token + published IP-range cross-
 * check) is the verified-bot machinery (allowlist.h), independent
 * of this. */
#ifndef BOTSHIELD_BOT_DIRECTORY_H
#define BOTSHIELD_BOT_DIRECTORY_H

#include <apr.h>
#include <apr_pools.h>
#include <apr_time.h>
#include <httpd.h>
#include <http_config.h>   /* cmd_parms for the directive setters */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *pattern;    /* UA substring to match (case-insensitive) */
    const char *slug;       /* canonical bot slug, e.g. "google" */
    const char *category;   /* category from upstream taxonomy */
    /* Bot-group classification — names taken from the IETF aipref
     * content-signal vocabulary (search, ai-input, ai-train) plus a
     * mod_botshield extension "monitor" for operational categories.
     * Computed from `category` at codegen time; per-bot override via
     * vendor/bot-directory.local.json with an explicit `botgroup`
     * field.
     *
     * Values: "search", "ai-input", "ai-train", "monitor", or NULL
     * (operational/ambiguous bots — security scanners, generic
     * libraries, OTHER). Used by BotShieldBotRateLimit @botgroup,
     * BotShieldBlockPath @botgroup, and robots.txt User-agent:
     * @botgroup stanzas. */
    const char *botgroup;
} bs_known_bot_entry;

/* Generated baseline: array terminated by an all-NULL sentinel.
 * Lifetime is process — these point into static rodata. */
extern const bs_known_bot_entry bs_known_bots[];
extern const apr_size_t bs_known_bots_count;

/* Aho-Corasick node. The lookup hot path walks these: at each UA
 * byte, follow goto-edges (or fall back via failure-link) and
 * record output if the node is terminal. ~5500 nodes for the
 * current ~600-entry directory; sparse-edges (most nodes have 1-2
 * children). Lookup is O(UA-length) regardless of pattern count. */
typedef struct bs_ac_edge {
    unsigned char byte;
    int           target;
} bs_ac_edge;

typedef struct bs_ac_node {
    bs_ac_edge *edges;       /* pool-allocated; sorted by byte for
                              * the linear scan in find_edge */
    int         edge_count;
    int         fail;        /* failure-link node index */
    int         pattern_idx; /* into state->entries[]; -1 if not
                              * terminal. Output propagation: if
                              * this state has a non-terminal goto
                              * but its failure-link target is
                              * terminal, we copy its pattern_idx
                              * here so any visit to this node
                              * still produces a match. */
} bs_ac_node;

/* Runtime state — built once at post_config (from compiled-in
 * baseline) and rebuilt on each runtime-override file change. The
 * patterns + AC trie are owned by a private pool whose lifetime
 * extends one watchdog tick beyond the swap so concurrent readers
 * always see fully-constructed memory. */
typedef struct bs_known_bots_state {
    apr_pool_t                 *pool;
    const bs_known_bot_entry   *entries;     /* NULL-terminated */
    apr_size_t                  count;
    bs_ac_node                 *ac_nodes;    /* index 0 = root */
    int                         ac_node_count;
    apr_time_t                  source_mtime;
    const char                 *source_path; /* for diagnostics */
} bs_known_bots_state;

/* Build an AC automaton from the patterns currently in `st->entries`
 * into pool-allocated storage. Sets st->ac_nodes + st->ac_node_count.
 * Returns 0 on success, non-zero on any allocation failure (caller
 * leaves state without AC; lookup falls back to sequential
 * strcasestr — slow but correct).
 *
 * Called once during bs_known_bots_load (file path) and once for
 * the compiled-in baseline at post_config. Construction time is
 * dominated by the trie insert pass; for ~600 patterns it's <1 ms. */
int bs_known_bots_build_ac(server_rec *s, bs_known_bots_state *st);

/* Wrap the compiled-in bs_known_bots[] table in a state struct +
 * freshly-built AC automaton owned by a subpool of parent_pool.
 * Used at post_config to seed the active state when no runtime
 * override is configured (or when the override fails to load),
 * so the no-override case still gets the AC fast path instead of
 * falling back to sequential strcasestr. */
bs_known_bots_state *bs_known_bots_build_baseline(server_rec *s,
                                                  apr_pool_t *parent_pool);

/* Returns 1 if the UA matches any directory entry; 0 otherwise.
 * Atomically loads the active runtime-override state, falling back
 * to the compiled-in baseline if no override is loaded.
 *
 * On match, *out_slug, *out_category, *out_botgroup (any of which
 * may be NULL to skip) are populated with pointers into the active
 * state's storage — callers must NOT free them and must NOT retain
 * across a watchdog refresh. *out_botgroup is NULL when the matched
 * entry's category doesn't map to a botgroup.
 * NULL UA returns 0. */
int bs_ua_is_known_bot(const char *ua,
                       const char **out_slug,
                       const char **out_category,
                       const char **out_botgroup);

/* Parse a TSV file at `path` into a fresh state allocated from a
 * subpool of `parent_pool`. Returns NULL on any failure (open,
 * malformed line, no usable entries) — caller leaves the current
 * active state in place.
 *
 * TSV format: pipe-delimited fields per record, comments begin with
 * '#', blank lines skipped. Each record is:
 *
 *   pattern|slug|category|followsRobotsTxt
 *
 * (followsRobotsTxt is a 0/1 flag carried for future use; currently
 * stored but not read by the runtime classifier.) */
bs_known_bots_state *bs_known_bots_load(server_rec *s,
                                        const char *path,
                                        apr_pool_t *parent_pool);

/* Atomically swap `new_state` in as the active runtime override.
 * The previously-active state is held one watchdog tick before its
 * pool is destroyed (so concurrent readers can't dereference freed
 * memory). Pass NULL to revert to the compiled-in baseline. */
void bs_known_bots_publish(server_rec *s,
                           bs_known_bots_state *new_state);

/* mod_watchdog tick callback. Registered at post_config with
 * singleton=0 so each worker child gets its own tick — the bot-
 * directory active pointer is process-local, so per-worker ticks
 * are required for updates to reach all workers within one refresh
 * interval. Each tick stat()s the source file and re-loads on
 * mtime change (early-out if mtime unchanged). */
apr_status_t bs_bot_directory_watchdog_cb(int state, void *data,
                                          apr_pool_t *pool);

/* Resolve an operator-supplied UA-pattern argument (from a directive
 * or robots.txt User-agent stanza) to the SET of directory slugs the
 * pattern covers.
 *
 * Substring semantics: an arg like "Google" includes every directory
 * entry whose .pattern field contains "Google" (case-insensitive) —
 * "Googlebot/", "GoogleOther/", "Google-Extended", etc. — so all the
 * Google-family slugs share the resolved set. An arg like "Googlebot"
 * narrows to just the googlebot slug. Reads the active runtime-
 * override state if present, otherwise the compiled-in baseline.
 *
 * Returns an apr_array of `const char *` slug pointers allocated from
 * `pool`. Empty array (nelts == 0) means no directory entry matched
 * the pattern — caller should warn the operator. The returned slug
 * pointers are duplicated into `pool`, safe to retain. */
apr_array_header_t *bs_known_bots_resolve_slugs(apr_pool_t *pool,
                                                const char *pattern);

/* Resolve all directory slugs whose `botgroup` field matches the
 * given group name (case-insensitive). Returns an apr_array of
 * `const char *` slug pointers allocated from `pool`. Empty array if
 * no entries match (botgroup misspelled, or no bots in that
 * category). Used by the @botgroup selector in BotShieldBotRateLimit
 * / BlockPath / robots.txt extension. */
apr_array_header_t *bs_known_bots_resolve_by_botgroup(apr_pool_t *pool,
                                                      const char *botgroup);

/* Setters wired into bs_cmds[]. */
const char *bs_set_bot_directory(cmd_parms *cmd, void *dconf,
                                 const char *path);
const char *bs_set_bot_directory_refresh_interval(cmd_parms *cmd,
                                                  void *dconf,
                                                  const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_BOT_DIRECTORY_H */
