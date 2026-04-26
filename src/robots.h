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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct robots_doc robots_doc;

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
 * (ua, path) against doc. Safe to call with doc=NULL or ua=NULL —
 * produces a "no match" result. */
void robots_query(const robots_doc *doc,
                  const char *ua, const char *path,
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

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_ROBOTS_H */
