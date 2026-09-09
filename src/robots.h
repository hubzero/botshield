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

/* Whether robots.txt Disallow rules enforce or merely record.
 *
 * Observe exists because a robots.txt is usually published long before
 * anyone enforces it, and switching enforcement on is a real change in
 * what the site refuses. An operator needs to see who actually ignores
 * the file before starting to 403 them -- and the answer is often
 * surprising, since the violators tend to be crawlers the operator
 * would have assumed were well behaved. */
typedef enum {
    BS_ROBOTS_MODE_UNSET   = -1,
    BS_ROBOTS_MODE_ENFORCE = 0,
    BS_ROBOTS_MODE_OBSERVE = 1
} bs_robots_mode;

typedef struct robots_match {
    int          group_idx;       /* -1 if no group matched */
    int          is_wildcard;     /* 1 if matching group was User-agent: * */
    int          allowed;         /* 1 if path allowed, 0 if Disallowed */
    int          crawl_delay_ms;  /* 0 if no Crawl-delay on matching group */
    const char  *group_name;      /* the governing group: the one whose
                                   * rule decided `allowed`, else the first
                                   * relevant one; NULL if no match */
    /* The governing group's knobs, when it refused. status 0 means
     * the default (403); log_tag NULL means none. */
    int          status;
    const char  *log_tag;
    /* An observe group whose Disallow was the longest match of all
     * and stepped aside. NULL when none did. The caller logs it as
     * `robotsblock:<name>:observe` and then acts on `allowed`, which
     * only the enforcing groups decided. */
    const char  *observed_group;
} robots_match;

/* An inline group: <BotShieldRobotRule name> inside <BotShieldRobots>.
 * Config-time constant, in pconf; merged into every document
 * bs_robots_load builds, so it survives a live refresh of the file. */
typedef struct bs_robots_inline_rule {
    const char *pattern;
    int         allow;
} bs_robots_inline_rule;

typedef struct bs_robots_inline_group {
    const char         *name;          /* the block's name, [a-z0-9-]{1,32} */
    apr_array_header_t *user_agents;   /* const char *, as written */
    apr_array_header_t *rules;         /* bs_robots_inline_rule, in order */
    int                 crawl_delay_ms;
    int                 status;        /* 0 = default */
    int                 mode;          /* bs_robots_mode; UNSET inherits */
    const char         *log_tag;
} bs_robots_inline_group;

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
 * (ua, botgroup, path) against doc. Safe to call with doc=NULL or
 * ua=NULL — produces a "no match" result.
 *
 * `botgroup` is the request's classified botgroup (see
 * bs_ua_class.known_botgroup) — "search", "ai-input", "ai-train",
 * "monitor", or NULL. Stanzas of the form `User-agent: @<botgroup>`
 * match when the request's `botgroup` argument equals that group
 * name. Pass NULL when no botgroup is known; @botgroup stanzas
 * won't match in that case (UA-substring stanzas still apply). */
void robots_query(const robots_doc *doc,
                  const char *ua, const char *botgroup,
                  const char *path, int default_mode,
                  robots_match *out);

/* Build a document with no file behind it, and add an inline group to
 * a document (parsed or empty). The group's UA tokens are lowercased
 * and its name taken as given, so a file group and an inline group
 * with the same name share a Crawl-delay slot, as duplicate names in
 * one file already do. */
robots_doc  *robots_doc_empty(apr_pool_t *p);
apr_status_t robots_doc_add_inline(robots_doc *doc,
                                   const bs_robots_inline_group *g,
                                   const char **err);

/* Group iteration — used at post_config time to allocate one SHM
 * rate-counter slot per group that carries a Crawl-delay, and by
 * the -D DUMP_BOTSHIELD_POLICY dump to render the parsed doc. */
int         robots_group_count(const robots_doc *doc);
/* Number of lines that exceeded BOTSHIELD_ROBOTS_MAX_LINE and got
 * truncated during the parse. Caller emits a NOTICE if non-zero so
 * operators see the silent truncation. */
int         robots_doc_truncated_lines(const robots_doc *doc);
const char *robots_group_name_at(const robots_doc *doc, int idx);
int         robots_group_is_wildcard_at(const robots_doc *doc, int idx);
int         robots_group_crawl_delay_ms_at(const robots_doc *doc, int idx);
/* The per-group knobs an inline group may carry. mode is the raw
 * value -- BS_ROBOTS_MODE_UNSET when the group inherits the
 * container's; the caller resolves it. status 0 is the default. */
int         robots_group_mode_at(const robots_doc *doc, int idx);
int         robots_group_status_at(const robots_doc *doc, int idx);
const char *robots_group_log_tag_at(const robots_doc *doc, int idx);
int         robots_group_is_inline_at(const robots_doc *doc, int idx);
/* Format a millisecond delay as robots.txt seconds; see robots.c. */
const char *robots_fmt_seconds(char *buf, apr_size_t n, int ms);

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
 * BotShieldRule reuses the same matcher rather than
 * maintaining a parallel placeholder. */
int bs_path_match(const char *pattern, const char *path);

/* --- <BotShieldRobots> --- *
 *
 * The one configuration surface for robots.txt enforcement. Inside:
 *   BotShieldRobotsTxt <path>          the file (optional)
 *   BotShieldMode enforce|observe      the file's and the default mode
 *   BotShieldWildcardScope <scope>     heuristic|strict|off
 *   BotShieldRefreshInterval <s>       live-refresh cadence, 0 disables
 *   <BotShieldRobotRule name> ... </>  an inline group: BotShieldUserAgent
 *                                      (repeatable), BotShieldDisallow /
 *                                      BotShieldAllow (repeatable),
 *                                      BotShieldCrawlDelay, BotShieldRespond,
 *                                      BotShieldMode, BotShieldLogAs
 * One container per server scope; a second is refused. */
const char *bs_open_robots(cmd_parms *cmd, void *dconf, const char *arg);

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
