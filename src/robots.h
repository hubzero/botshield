/* robots.h — mod_botshield's robots.txt parser + matcher.
 *
 * Public surface:
 *   - robots_parse_file / robots_parse_buf: build an opaque robots_doc
 *     from a file on disk or an in-memory buffer, pool-allocated.
 *   - robots_query: one-shot enforcement query — given (UA, path),
 *     fills a robots_match struct with the matching group's name,
 *     wildcard flag, allow/deny decision, and Crawl-delay.
 *   - Group-iteration helpers for post_config (SHM slot allocation).
 *
 * Semantics follow RFC 9309 plus the Crawl-delay de facto extension:
 *   - UA matching is case-insensitive prefix-token against
 *     User-agent: lines; most-specific-group wins; User-agent: *
 *     is the fallback when no specific group matches.
 *   - Path matching: prefix with '*' wildcards anywhere and optional
 *     trailing '$' end-anchor; longest-match-wins between Allow and
 *     Disallow rules within a group.
 *   - Crawl-delay: integer seconds per group (0 = unset).
 *
 * No Apache httpd.h dependency — pure APR. Callable from the module
 * and from a future standalone test harness.
 */
#ifndef BOTSHIELD_ROBOTS_H
#define BOTSHIELD_ROBOTS_H

#include <apr_pools.h>
#include <apr_errno.h>
#include <apr_time.h>

#include <httpd.h>
#include <http_config.h>

/* Forward decl — bs_robots_load takes a bs_server_cfg pointer.
 * We avoid including botshield.h here because botshield.h
 * declares bs_robots_state with a robots_doc * field (forward-
 * declared in botshield.h itself); pulling the umbrella in here
 * would create a circular include. */
struct bs_server_cfg;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct robots_doc robots_doc;

/* ======================================================================
 * Active-state bundle
 *
 * One per active parse, swapped atomically by the refresh watchdog.
 * The owning subpool (`pool`) is a child of pconf and is destroyed
 * when this bundle is finally retired — one refresh cycle after
 * being displaced — so request-path readers holding pointers into
 * doc's pool never see freed memory.
 * ====================================================================== */

typedef struct bs_robots_state {
    robots_doc *doc;
    apr_pool_t *pool;              /* owns doc; sized for one doc */
    apr_time_t  mtime;              /* source file mtime when parsed */
    int        *slot_by_group_idx;  /* length = robots_group_count(doc) */
} bs_robots_state;

enum bs_robots_wildcard_scope {
    BS_ROBOTS_WILDCARD_UNSET     = -1,
    BS_ROBOTS_WILDCARD_HEURISTIC = 0,
    BS_ROBOTS_WILDCARD_STRICT    = 1,
    BS_ROBOTS_WILDCARD_OFF       = 2,
};

/* E2.2 — robots refresh interval (seconds between mtime checks).
 * UNSET sentinel inherits at request-time from the operator's directive
 * value or the compiled-in default. */
#define BS_ROBOTS_REFRESH_UNSET    (-1)
#define BS_ROBOTS_REFRESH_DEFAULT  60

typedef struct robots_match {
    int          group_idx;       /* -1 if no group matched */
    int          is_wildcard;     /* 1 if matching group was User-agent: * */
    int          allowed;         /* 1 if path allowed, 0 if Disallowed */
    int          crawl_delay_sec; /* 0 if no Crawl-delay on matching group */
    const char  *group_name;      /* normalized id (lowercase, [a-z0-9-]);
                                   * pool-alloc'd; NULL if no match */
} robots_match;

/* Parse a robots.txt file. On APR_SUCCESS, *out is set to a new doc
 * allocated in `p`. On error, *err is an operator-readable diagnostic
 * (also pool-alloc'd) and *out is NULL.
 *
 * Size caps: refuses files over BOTSHIELD_ROBOTS_MAX_BYTES (1 MiB —
 * no legitimate robots.txt approaches this). Lines over 2048 bytes
 * are truncated with a warning. */
apr_status_t robots_parse_file(apr_pool_t *p, const char *path,
                               robots_doc **out, const char **err);

/* Parse from an in-memory buffer. Useful for tests and for future
 * live-refresh where the module reads the file itself. */
apr_status_t robots_parse_buf(apr_pool_t *p, const char *buf,
                              apr_size_t len,
                              robots_doc **out, const char **err);

/* One-shot enforcement query. Fills *out with the result of matching
 * (ua, signal, path) against doc. Safe to call with doc=NULL or
 * ua=NULL — produces a "no match" result.
 *
 * `signal` is the request's classified content-signal (see
 * bs_ua_class.known_signal) — "search", "ai-input", "ai-train",
 * "monitor", or NULL. Stanzas of the form `User-agent: @<signal>`
 * match when the request's `signal` argument equals that signal
 * name. Pass NULL when no signal is known; @signal stanzas won't
 * match in that case (UA-substring stanzas still apply). */
void robots_query(const robots_doc *doc,
                  const char *ua, const char *signal,
                  const char *path,
                  robots_match *out);

/* Group iteration — used at post_config time to allocate one SHM
 * rate-counter slot per group that carries a Crawl-delay, and by
 * the /botshield/policy-status handler to render the parsed doc. */
int         robots_group_count(const robots_doc *doc);
/* Number of lines that exceeded BOTSHIELD_ROBOTS_MAX_LINE and got
 * truncated during the parse. Caller emits a NOTICE if non-zero so
 * operators see the silent truncation. */
int         robots_doc_truncated_lines(const robots_doc *doc);
const char *robots_group_name_at(const robots_doc *doc, int idx);
int         robots_group_is_wildcard_at(const robots_doc *doc, int idx);
int         robots_group_crawl_delay_at(const robots_doc *doc, int idx);

/* Per-group content accessors. `ua_at` returns the lowercased UA
 * token the parser stored; `rule_at` fills out the pattern pointer
 * and the allow flag (1 = Allow, 0 = Disallow). All string pointers
 * are pool-allocated inside the doc and share its lifetime. Out-
 * of-range indices return NULL (strings) or 0 (counts/flags). */
int         robots_group_ua_count_at(const robots_doc *doc, int idx);
const char *robots_group_ua_at(const robots_doc *doc, int idx, int ua_idx);
int         robots_group_rule_count_at(const robots_doc *doc, int idx);
int         robots_group_rule_at(const robots_doc *doc, int idx, int rule_idx,
                                 const char **out_pattern, int *out_allow);

/* RFC 9309 path-pattern match.
 *
 * Pattern may contain '*' (matches any byte sequence; multiple '*'s
 * permitted, segments between them are literal and must appear in
 * order) and may end with '$' (anchor to end of path).
 *
 * Returns 1 on match, 0 otherwise. An empty pattern never matches.
 *
 * Originally robots.txt-internal but promoted to public so
 * BotShieldPathTrigger and BotShieldBlockPath share the same
 * matcher rather than maintaining a parallel placeholder. */
int bs_path_match(const char *pattern, const char *path);

/* --- E2.2 directive setters --- *
 *
 * BotShieldRobotsTxt <path>           — point at a robots.txt file.
 * BotShieldRobotsRefreshInterval <s>  — live-refresh cadence (0 disables).
 * BotShieldRobotsWildcardScope mode   — User-agent: * group enforcement
 *                                       (heuristic / strict / off). */
const char *bs_set_robots_txt(cmd_parms *cmd, void *dconf,
                              const char *path);
const char *bs_set_robots_refresh_interval(cmd_parms *cmd, void *dconf,
                                           const char *arg);
const char *bs_set_robots_wildcard_scope(cmd_parms *cmd, void *dconf,
                                         const char *arg);

/* --- E2.2.2 module-side loader --- *
 *
 * Stat + (conditionally) parse + atomically publish the robots.txt
 * pointed to by scfg->robots_txt_path. Called both at post_config
 * (initial load) and from the watchdog callback (refresh). When
 * the source file's mtime is unchanged, it's a cheap no-op. */
apr_status_t bs_robots_load(server_rec *sv, struct bs_server_cfg *scfg,
                            apr_pool_t *pconf);

/* mod_watchdog tick callback — one registration per vhost with a
 * BotShieldRobotsTxt directive. Calls bs_robots_load when the
 * watchdog reports RUNNING; bs_robots_load returns fast when mtime
 * hasn't changed. */
apr_status_t bs_robots_watchdog_cb(int state, void *data,
                                   apr_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_ROBOTS_H */
