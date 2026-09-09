/* robots.c — mod_botshield's robots.txt parser + loader + matcher.
 *
 * See robots.h for the public surface. Semantics follow RFC 9309 plus
 * the Crawl-delay de facto extension.
 *
 * Three concerns under one roof:
 *   - Pure-APR parser/matcher (robots_parse_file, robots_query,
 *     bs_path_match). The internals here read like a small stand-
 *     alone library — minimal dependencies, untrusted-input hardening,
 *     length caps + unknown-key tolerance.
 *   - Module-level loader (bs_robots_load + bs_robots_watchdog_cb).
 *     Stat + (conditionally) parse + atomically publish into the
 *     server cfg, with mod_watchdog driving periodic refresh.
 *   - Directive setters (bs_set_robots_*) and one config-time
 *     validator (bs_path_pattern_warn_middle_star).
 *
 * Defensive parsing — operator-controlled input that the watchdog
 * hot-reloads while requests are in flight, so we treat the file
 * as untrusted. Length caps, line caps, and unknown-key tolerance
 * keep a malformed file from crashing the module or blowing memory.
 */
#include "shm.h"
#include "robots.h"

#include <http_log.h>
#include <mod_watchdog.h>

#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_lib.h>

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>

#include "botshield.h"

/* Sanity caps — no legitimate robots.txt approaches any of these. */
#define BOTSHIELD_ROBOTS_MAX_BYTES           (1024 * 1024)
#define BOTSHIELD_ROBOTS_MAX_LINE            2048
#define BOTSHIELD_ROBOTS_MAX_GROUPS          64
#define BOTSHIELD_ROBOTS_MAX_RULES_PER_GROUP 256
#define BOTSHIELD_ROBOTS_MAX_UAS_PER_GROUP   32
#define BOTSHIELD_ROBOTS_MAX_CRAWL_DELAY_SEC 3600

typedef struct robots_rule {
    const char *pattern;  /* raw path pattern, may contain '*' and trailing '$' */
    int         allow;    /* 1 = Allow, 0 = Disallow */
} robots_rule;

typedef struct robots_group {
    apr_array_header_t *user_agents;  /* const char *, lowercased */
    apr_array_header_t *rules;        /* robots_rule * */
    int                 crawl_delay_ms; /* milliseconds, 0 if unset */
    const char         *name;         /* normalized id, derived from first UA */
    int                 is_wildcard;  /* 1 when first UA is "*" */
    /* Knobs only an inline group can carry. A file group has the
     * defaults: mode UNSET (inherit the container's), status 0 (403),
     * no tag. */
    int                 mode;         /* bs_robots_mode */
    int                 status;
    const char         *log_tag;
    int                 is_inline;    /* 1 for a <BotShieldRobotRule> */
} robots_group;

struct robots_doc {
    apr_pool_t         *pool;
    apr_array_header_t *groups;       /* robots_group * */
    /* Count of lines that exceeded
     * BOTSHIELD_ROBOTS_MAX_LINE and got truncated during parse.
     * bs_robots_load reads via robots_doc_truncated_lines() and
     * emits a NOTICE so operators see the silent truncation the
     * parser-header docs claim is reported. */
    int                 truncated_lines;
};

/* ---------- helpers ---------- */

static char *bs_rb_lower_dup(apr_pool_t *p, const char *s)
{
    if (!s) return NULL;
    char *out = apr_pstrdup(p, s);
    for (char *q = out; *q; q++) {
        *q = (char)apr_tolower((unsigned char)*q);
    }
    return out;
}

/* Derive a reason-string identifier from the group's first UA. Lowercase
 * letters, digits, and '-' preserved; everything else collapses to '-'.
 * Runs of '-' collapse to one. Empty result becomes "unnamed". */
static const char *bs_rb_group_name_from_ua(apr_pool_t *p, const char *ua)
{
    if (!ua || !*ua) return "unnamed";
    if (strcmp(ua, "*") == 0) return "wildcard";

    char *buf = apr_pcalloc(p, strlen(ua) + 1);
    int   bi  = 0;
    int   last_dash = 1;   /* so leading garbage doesn't produce leading '-' */
    for (const char *q = ua; *q; q++) {
        unsigned char c = (unsigned char)apr_tolower((unsigned char)*q);
        int keep = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (keep) {
            buf[bi++] = (char)c;
            last_dash = (c == '-');
        } else if (!last_dash) {
            buf[bi++] = '-';
            last_dash = 1;
        }
    }
    /* strip trailing '-' */
    while (bi > 0 && buf[bi - 1] == '-') bi--;
    buf[bi] = '\0';
    return (bi > 0) ? buf : "unnamed";
}

/* Trim trailing whitespace from a mutable string (leading whitespace is
 * handled by the caller skipping the pointer forward). */
static void bs_rb_rstrip(char *s)
{
    apr_size_t n = strlen(s);
    while (n > 0) {
        unsigned char c = (unsigned char)s[n - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            s[--n] = '\0';
        } else {
            break;
        }
    }
}

/* ---------- path matching (RFC 9309) ----------
 *
 * Pattern may contain '*' (matches any sequence) and may end with '$'
 * (anchor to end of path). Segments between '*'s are literal and must
 * appear in order; the first segment must be a prefix of the path.
 *
 * Returns 1 on match, 0 otherwise. An empty pattern never matches —
 * empty Disallow/Allow is robots.txt's "no rule" sentinel and is
 * filtered out at parse time.
 *
 * Public surface — also used by BotShieldRule in
 * triggers.c. The earlier bs_path_glob_match placeholder in
 * botshield.c was retired once this matcher landed; one path
 * matcher across the codebase. */
int bs_path_match(const char *pattern, const char *path)
{
    if (!pattern || !*pattern || !path) return 0;

    apr_size_t plen = strlen(pattern);
    int anchored = 0;
    if (pattern[plen - 1] == '$') {
        anchored = 1;
        plen--;
        if (plen == 0) return *path == '\0';
    }

    apr_size_t pi  = 0;
    const char *ppos = path;
    int         first = 1;

    while (pi < plen) {
        apr_size_t seg_start = pi;
        while (pi < plen && pattern[pi] != '*') pi++;
        apr_size_t seg_len = pi - seg_start;

        if (seg_len > 0) {
            if (first) {
                /* First segment anchors at the start of path. */
                if (strncmp(ppos, pattern + seg_start, seg_len) != 0) return 0;
                ppos += seg_len;
            } else {
                /* Subsequent segment — find anywhere in the remaining
                 * path. strstr wants a null-terminated needle; we build
                 * one from the segment since segments are short. */
                char needle[256];
                if (seg_len >= sizeof(needle)) return 0;
                memcpy(needle, pattern + seg_start, seg_len);
                needle[seg_len] = '\0';
                const char *found = strstr(ppos, needle);
                if (!found) return 0;
                ppos = found + seg_len;
            }
            first = 0;
        } else {
            first = 0;  /* a leading '*' consumes nothing but switches mode */
        }

        if (pi < plen && pattern[pi] == '*') pi++;
    }

    if (anchored && *ppos != '\0') return 0;
    return 1;
}

/* ---------- UA group matching ---------- */

/* Case-insensitive per-segment prefix match. Real UAs structure
 * their product tokens with `;` as the separator between segments,
 * especially in the Mozilla-compat form:
 *
 *   Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)
 *
 * (RFC 9110 doesn't name these `;`-separated pieces; "segment" here
 * is descriptive, not a spec term.) We split the UA on `;`, strip
 * leading whitespace and `(` from each segment, then check if the
 * segment *starts with* the robots.txt token (case-insensitive).
 * This is more accurate than a blanket strcasestr — a `User-agent:
 * Bot` token under the old rule would match anything with "bot"
 * anywhere in the UA, including real browsers whose UA happens to
 * mention 'bot' inside a URL. Under the segment rule it only
 * matches when a segment's product token begins with `Bot`. */
static int bs_rb_ua_segment_match(const char *ua, const char *token)
{
    if (!ua || !token || !*token) return 0;
    apr_size_t tlen = strlen(token);
    const char *seg = ua;
    while (seg) {
        while (*seg == ' ' || *seg == '\t' || *seg == '(') seg++;
        if (strncasecmp(seg, token, tlen) == 0) return 1;
        const char *sep = strchr(seg, ';');
        if (!sep) break;
        seg = sep + 1;
    }
    return 0;
}

/* Does a User-agent token apply to this request? Three cases:
 *   "*"             — wildcard, applies only as fallback
 *   "@<botgroup>"   — matches when request's classified botgroup
 *                     equals <botgroup>
 *   <substring>     — case-insensitive segment-prefix match against UA
 * Returns 1 on match (excluding wildcard, which the caller handles
 * separately for specificity ordering). */
static int bs_rb_token_matches(const char *tok, const char *ua,
                               const char *botgroup)
{
    if (!tok || !*tok) return 0;
    if (tok[0] == '@') {
        if (!botgroup) return 0;
        return strcasecmp(tok + 1, botgroup) == 0;
    }
    return bs_rb_ua_segment_match(ua, tok);
}

/* Determine the "specificity" of the match: the length of the
 * longest User-agent token across the doc that matches this request.
 * Returns 0 when only the `*` fallback matches (or nothing matches),
 * so callers can distinguish the wildcard fallback case.
 * `*_has_wildcard` is set to 1 if any group's UA list contains `*`. */
static int bs_rb_best_token_len(const robots_doc *doc, const char *ua,
                                const char *botgroup, int *out_has_wildcard)
{
    int best_len = 0;
    int has_wildcard = 0;
    for (int i = 0; i < doc->groups->nelts; i++) {
        robots_group *g = APR_ARRAY_IDX(doc->groups, i, robots_group *);
        for (int j = 0; j < g->user_agents->nelts; j++) {
            const char *tok = APR_ARRAY_IDX(g->user_agents, j, const char *);
            if (strcmp(tok, "*") == 0) { has_wildcard = 1; continue; }
            if (bs_rb_token_matches(tok, ua, botgroup)) {
                int len = (int)strlen(tok);
                if (len > best_len) best_len = len;
            }
        }
    }
    if (out_has_wildcard) *out_has_wildcard = has_wildcard;
    return best_len;
}

/* Does this group qualify for the winning specificity? If
 * `best_len > 0`, the group qualifies iff it contains a UA token of
 * length == best_len that matches the request. If `best_len == 0`
 * (no specific match), the group qualifies iff it contains `*`. */
static int bs_rb_group_qualifies(const robots_group *g, const char *ua,
                                 const char *botgroup, int best_len)
{
    for (int j = 0; j < g->user_agents->nelts; j++) {
        const char *tok = APR_ARRAY_IDX(g->user_agents, j, const char *);
        if (best_len == 0) {
            if (strcmp(tok, "*") == 0) return 1;
        } else {
            if (strcmp(tok, "*") == 0) continue;
            if ((int)strlen(tok) == best_len
                && bs_rb_token_matches(tok, ua, botgroup)) return 1;
        }
    }
    return 0;
}

/* Previously a per-group longest-match-wins evaluator. robots_query
 * now folds this loop into its union-of-groups walk inline, so the
 * standalone helper has no remaining callers. Kept out of the file
 * deliberately. */

/* ---------- parsing ---------- */

/* Parser state: groups accumulate, consecutive User-agent: lines
 * extend the CURRENT group; the first rule line (Allow/Disallow/
 * Crawl-delay) after a User-agent "closes" the UA list, and the
 * next User-agent: line after that starts a new group. */
typedef struct {
    apr_pool_t   *pool;
    robots_doc   *doc;
    robots_group *cur;           /* group currently being built, or NULL */
    int           cur_expect_ua; /* 1 while extending UAs; 0 once rules begin */
} bs_rb_parser;

static robots_group *bs_rb_new_group(bs_rb_parser *st)
{
    robots_group *g = apr_pcalloc(st->pool, sizeof(*g));
    g->user_agents = apr_array_make(st->pool, 4, sizeof(const char *));
    g->rules       = apr_array_make(st->pool, 8, sizeof(robots_rule *));
    g->crawl_delay_ms = 0;
    g->is_wildcard = 0;
    g->name        = "unnamed";
    g->mode        = BS_ROBOTS_MODE_UNSET;
    g->status      = 0;
    g->log_tag     = NULL;
    g->is_inline   = 0;
    return g;
}

static void bs_rb_flush_group(bs_rb_parser *st)
{
    if (!st->cur) return;
    if (st->cur->user_agents->nelts == 0) {
        /* Orphan rules with no preceding User-agent: — RFC 9309 says
         * discard. */
        st->cur = NULL;
        return;
    }
    if (st->doc->groups->nelts >= BOTSHIELD_ROBOTS_MAX_GROUPS) {
        st->cur = NULL;
        return;
    }
    /* Derive name from the first UA (already lowercased). */
    const char *first_ua = APR_ARRAY_IDX(st->cur->user_agents, 0, const char *);
    st->cur->name = bs_rb_group_name_from_ua(st->pool, first_ua);
    st->cur->is_wildcard = (strcmp(first_ua, "*") == 0);
    *(robots_group **)apr_array_push(st->doc->groups) = st->cur;
    st->cur = NULL;
}

static void bs_rb_add_ua(bs_rb_parser *st, const char *ua_raw)
{
    /* Strip a leading User-agent: "foo" style of quoting? Not supported
     * by the RFC. Just trim surrounding whitespace and lowercase. */
    while (*ua_raw == ' ' || *ua_raw == '\t') ua_raw++;
    if (!*ua_raw) return;

    /* A new UA after a rule-line starts a fresh group. */
    if (st->cur && !st->cur_expect_ua) {
        bs_rb_flush_group(st);
    }
    if (!st->cur) {
        st->cur = bs_rb_new_group(st);
        st->cur_expect_ua = 1;
    }
    if (st->cur->user_agents->nelts >= BOTSHIELD_ROBOTS_MAX_UAS_PER_GROUP) {
        return;  /* silently drop — pathological input */
    }

    *(const char **)apr_array_push(st->cur->user_agents) =
        bs_rb_lower_dup(st->pool, ua_raw);
}

static void bs_rb_add_rule(bs_rb_parser *st, const char *pattern, int allow)
{
    if (!st->cur) return;          /* no group open; discard */
    if (!pattern || !*pattern) {
        /* Empty Disallow/Allow is robots.txt's "no rule" sentinel.
         * For Disallow it's "allow everything for this group" — we
         * represent that by simply not adding a rule. For Allow it's
         * a no-op. */
        st->cur_expect_ua = 0;     /* still closes UA section */
        return;
    }
    if (st->cur->rules->nelts >= BOTSHIELD_ROBOTS_MAX_RULES_PER_GROUP) {
        st->cur_expect_ua = 0;
        return;
    }
    robots_rule *r = apr_pcalloc(st->pool, sizeof(*r));
    r->pattern = apr_pstrdup(st->pool, pattern);
    r->allow   = allow ? 1 : 0;
    *(robots_rule **)apr_array_push(st->cur->rules) = r;
    st->cur_expect_ua = 0;
}

static void bs_rb_set_crawl_delay(bs_rb_parser *st, const char *value)
{
    if (!st->cur) return;
    /* strtod, not strtol. `Crawl-delay: 0.5` is a real line, and the
     * whole-second reader this replaced stopped at the '.', failed the
     * trailing-character check and returned -- so the group kept 0
     * and the crawler got no delay at all, the opposite of what the
     * file asked. Stored in milliseconds so the fraction reaches the
     * counter. A value that rounds to nothing is treated as absent. */
    char *end = NULL;
    double v = strtod(value, &end);
    if (!end || end == value) return;
    if (*end != '\0' && *end != ' ' && *end != '\t') return;
    if (!(v > 0.0) || v > BOTSHIELD_ROBOTS_MAX_CRAWL_DELAY_SEC) return;
    int ms = (int)(v * 1000.0 + 0.5);
    if (ms <= 0) return;
    st->cur->crawl_delay_ms = ms;
    st->cur_expect_ua = 0;
}

/* Process one parsed line. `line` has been comment-stripped and rstripped;
 * leading whitespace has already been skipped by the caller. */
static void bs_rb_handle_line(bs_rb_parser *st, char *line)
{
    if (!*line) return;

    char *colon = strchr(line, ':');
    if (!colon) return;            /* unrecognized; tolerate */
    *colon = '\0';
    char *key = line;
    char *val = colon + 1;

    /* Trim trailing whitespace from key, leading from value. */
    bs_rb_rstrip(key);
    while (*val == ' ' || *val == '\t') val++;
    bs_rb_rstrip(val);

    if (!*key) return;

    if (!strcasecmp(key, "user-agent")) {
        bs_rb_add_ua(st, val);
    } else if (!strcasecmp(key, "disallow")) {
        bs_rb_add_rule(st, val, 0);
    } else if (!strcasecmp(key, "allow")) {
        bs_rb_add_rule(st, val, 1);
    } else if (!strcasecmp(key, "crawl-delay")) {
        bs_rb_set_crawl_delay(st, val);
    }
    /* Unknown keys (Sitemap, Host, Clean-param, Request-rate, Noindex,
     * etc.) are silently ignored — robots.txt is open to vendor
     * extensions and we shouldn't error on them. */
}

static apr_status_t bs_rb_parse(apr_pool_t *p, const char *buf, apr_size_t len,
                                robots_doc **out, const char **err)
{
    if (len > BOTSHIELD_ROBOTS_MAX_BYTES) {
        if (err) *err = apr_psprintf(p,
            "robots.txt too large (%" APR_SIZE_T_FMT " > %d bytes)",
            len, BOTSHIELD_ROBOTS_MAX_BYTES);
        return APR_EINVAL;
    }

    robots_doc *doc = apr_pcalloc(p, sizeof(*doc));
    doc->pool   = p;
    doc->groups = apr_array_make(p, 8, sizeof(robots_group *));

    bs_rb_parser st = { 0 };
    st.pool = p;
    st.doc  = doc;

    /* Skip UTF-8 BOM if present. */
    if (len >= 3 && (unsigned char)buf[0] == 0xEF
                 && (unsigned char)buf[1] == 0xBB
                 && (unsigned char)buf[2] == 0xBF) {
        buf += 3; len -= 3;
    }

    /* Iterate lines. Copy each into a fixed-size scratch buffer so we
     * can null-terminate and mutate without touching the input. Lines
     * over MAX_LINE are truncated (caller sees a warning through the
     * summary log, not an error). */
    char line[BOTSHIELD_ROBOTS_MAX_LINE];
    apr_size_t i = 0;
    while (i < len) {
        apr_size_t start = i;
        while (i < len && buf[i] != '\n') i++;
        apr_size_t llen = i - start;
        if (i < len) i++;          /* consume '\n' */

        /* Strip everything after '#' first — comments can cover the
         * whole line. */
        apr_size_t clen = llen;
        for (apr_size_t k = 0; k < clen; k++) {
            if (buf[start + k] == '#') { clen = k; break; }
        }
        if (clen == 0) continue;

        apr_size_t copy_len = clen;
        if (copy_len >= sizeof(line)) {
            copy_len = sizeof(line) - 1;
            doc->truncated_lines++;
        }
        memcpy(line, buf + start, copy_len);
        line[copy_len] = '\0';

        /* Skip leading whitespace. */
        char *ls = line;
        while (*ls == ' ' || *ls == '\t' || *ls == '\r') ls++;

        bs_rb_handle_line(&st, ls);
    }

    bs_rb_flush_group(&st);

    *out = doc;
    if (err) *err = NULL;
    return APR_SUCCESS;
}

apr_status_t robots_parse_buf(apr_pool_t *p, const char *buf, apr_size_t len,
                              robots_doc **out, const char **err)
{
    if (!out) return APR_EINVAL;
    *out = NULL;
    if (!p || !buf) {
        if (err) *err = "null buffer or pool";
        return APR_EINVAL;
    }
    return bs_rb_parse(p, buf, len, out, err);
}

apr_status_t robots_parse_file(apr_pool_t *p, const char *path,
                               robots_doc **out, const char **err)
{
    if (!out) return APR_EINVAL;
    *out = NULL;

    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, path, APR_READ | APR_BINARY,
                                    APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        char errbuf[128];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        if (err) *err = apr_psprintf(p,
            "cannot open %s: %s", path, errbuf);
        return rv;
    }

    apr_finfo_t fi;
    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, f);
    if (rv != APR_SUCCESS || fi.size < 0) {
        apr_file_close(f);
        if (err) *err = apr_psprintf(p, "cannot stat %s", path);
        return APR_EINVAL;
    }
    if (fi.size > BOTSHIELD_ROBOTS_MAX_BYTES) {
        apr_file_close(f);
        if (err) *err = apr_psprintf(p,
            "%s is %" APR_OFF_T_FMT " bytes; cap is %d",
            path, fi.size, BOTSHIELD_ROBOTS_MAX_BYTES);
        return APR_EINVAL;
    }
    apr_size_t fsize = (apr_size_t)fi.size;
    char *buf = apr_palloc(p, fsize + 1);
    apr_size_t got = fsize;
    rv = apr_file_read(f, buf, &got);
    apr_file_close(f);
    if (rv != APR_SUCCESS) {
        if (err) *err = apr_psprintf(p, "read error on %s", path);
        return rv;
    }
    buf[got] = '\0';
    return bs_rb_parse(p, buf, got, out, err);
}

/* ---------- query API ---------- */

/* RFC 9309 §2.2.1: "if the product token matches multiple
 * user-agent lines, all of the matching [groups] are applied."
 * Real robots.txt files sometimes fan a single crawler across
 * several stanzas; applying only one under-enforces.
 *
 * Evaluation:
 *   1. Scan all groups once to find the longest matching UA token
 *      (best_len) and whether any group carries `*`.
 *   2. If best_len > 0: every group with a UA token of that length
 *      that matches the crawler UA is "relevant."
 *      If best_len == 0 and `*` exists: every group with `*` is
 *      relevant; is_wildcard = 1.
 *   3. Walk the union of rules across all relevant groups; return
 *      longest-match-wins Allow/Disallow (Allow wins length ties
 *      per RFC 9309).
 *   4. Crawl-delay: take the max across relevant groups' non-zero
 *      values — most restrictive wins.
 *   5. group_idx reports the first relevant group; group_name the
 *      governing one.
 *
 * Two verdicts are kept through step 3: one over every relevant
 * group, one over the enforcing groups alone. The enforcing verdict
 * is the answer. The other exists so an observe group whose Disallow
 * was the longest match of all can be named in `observed_group`: it
 * logs what it would have done and steps aside, and the longest
 * enforcing rule still applies. That is how BotShieldMode observe on
 * a request rule already behaves -- an observed rule never shadows an
 * enforced one -- and the word means the same thing here.
 *
 * `default_mode` is the container's; a group with mode UNSET takes
 * it. Pass BS_ROBOTS_MODE_OBSERVE to observe the whole set. */
void robots_query(const robots_doc *doc, const char *ua, const char *botgroup,
                  const char *path, int default_mode, robots_match *out)
{
    if (!out) return;
    out->group_idx       = -1;
    out->is_wildcard     = 0;
    out->allowed         = 1;
    out->crawl_delay_ms  = 0;
    out->group_name      = NULL;
    out->status          = 0;
    out->log_tag         = NULL;
    out->observed_group  = NULL;
    if (!doc || !ua || !doc->groups || doc->groups->nelts == 0) return;

    int has_wildcard = 0;
    int best_len = bs_rb_best_token_len(doc, ua, botgroup, &has_wildcard);
    if (best_len == 0 && !has_wildcard) return;  /* nothing to enforce */

    int first_relevant_idx = -1;
    int max_crawl_delay    = 0;
    int all_len = -1, all_allow = 1, all_gidx = -1;   /* every group */
    int enf_len = -1, enf_allow = 1, enf_gidx = -1;   /* enforcing only */

    for (int i = 0; i < doc->groups->nelts; i++) {
        robots_group *g = APR_ARRAY_IDX(doc->groups, i, robots_group *);
        if (!bs_rb_group_qualifies(g, ua, botgroup, best_len)) continue;
        if (first_relevant_idx < 0) first_relevant_idx = i;

        if (g->crawl_delay_ms > max_crawl_delay) {
            max_crawl_delay = g->crawl_delay_ms;
        }
        if (!path) continue;

        int gmode = (g->mode == BS_ROBOTS_MODE_UNSET) ? default_mode : g->mode;
        int observe = (gmode == BS_ROBOTS_MODE_OBSERVE);

        for (int k = 0; k < g->rules->nelts; k++) {
            robots_rule *r = APR_ARRAY_IDX(g->rules, k, robots_rule *);
            if (!bs_path_match(r->pattern, path)) continue;
            int len = (int)strlen(r->pattern);
            if (len > all_len) {
                all_len = len; all_allow = r->allow; all_gidx = i;
            } else if (len == all_len && r->allow && !all_allow) {
                all_allow = 1; all_gidx = i;
            }
            if (observe) continue;
            if (len > enf_len) {
                enf_len = len; enf_allow = r->allow; enf_gidx = i;
            } else if (len == enf_len && r->allow && !enf_allow) {
                enf_allow = 1; enf_gidx = i;
            }
        }
    }

    if (first_relevant_idx < 0) return;

    robots_group *fg = APR_ARRAY_IDX(doc->groups, first_relevant_idx,
                                     robots_group *);
    out->group_idx       = first_relevant_idx;
    out->is_wildcard     = (best_len == 0);
    out->crawl_delay_ms  = max_crawl_delay;
    out->group_name      = fg->name;
    if (!path) return;

    out->allowed = (enf_len >= 0) ? enf_allow : 1;
    if (enf_len >= 0) {
        robots_group *eg = APR_ARRAY_IDX(doc->groups, enf_gidx,
                                         robots_group *);
        out->group_name = eg->name;
        out->status     = eg->status;
        out->log_tag    = eg->log_tag;
    }
    if (all_len >= 0 && !all_allow) {
        robots_group *og = APR_ARRAY_IDX(doc->groups, all_gidx,
                                         robots_group *);
        int ogmode = (og->mode == BS_ROBOTS_MODE_UNSET)
                   ? default_mode : og->mode;
        if (ogmode == BS_ROBOTS_MODE_OBSERVE) out->observed_group = og->name;
    }
}

int robots_group_count(const robots_doc *doc)
{
    return (doc && doc->groups) ? doc->groups->nelts : 0;
}

int robots_doc_truncated_lines(const robots_doc *doc)
{
    return doc ? doc->truncated_lines : 0;
}

static robots_group *bs_rb_group_at(const robots_doc *doc, int idx)
{
    if (!doc || !doc->groups) return NULL;
    if (idx < 0 || idx >= doc->groups->nelts) return NULL;
    return APR_ARRAY_IDX(doc->groups, idx, robots_group *);
}

const char *robots_group_name_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->name : NULL;
}

int robots_group_is_wildcard_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->is_wildcard : 0;
}

/* Milliseconds as the seconds robots.txt would write: 30000 -> "30",
 * 500 -> "0.5", 1500 -> "1.5". Three decimals is exact for any
 * millisecond count; trailing zeros are dropped so a whole number
 * prints as one. `buf` should hold 32 bytes. */
const char *robots_fmt_seconds(char *buf, apr_size_t n, int ms)
{
    if (ms % 1000 == 0) {
        apr_snprintf(buf, n, "%d", ms / 1000);
        return buf;
    }
    apr_snprintf(buf, n, "%d.%03d", ms / 1000, ms % 1000);
    apr_size_t l = strlen(buf);
    while (l && buf[l - 1] == '0') buf[--l] = '\0';
    return buf;
}

int robots_group_crawl_delay_ms_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->crawl_delay_ms : 0;
}

int robots_group_mode_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->mode : BS_ROBOTS_MODE_UNSET;
}

int robots_group_status_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->status : 0;
}

const char *robots_group_log_tag_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->log_tag : NULL;
}

int robots_group_is_inline_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->is_inline : 0;
}

/* ---------- inline groups ---------- */

robots_doc *robots_doc_empty(apr_pool_t *p)
{
    robots_doc *doc = apr_pcalloc(p, sizeof(*doc));
    doc->pool   = p;
    doc->groups = apr_array_make(p, 8, sizeof(robots_group *));
    return doc;
}

apr_status_t robots_doc_add_inline(robots_doc *doc,
                                   const bs_robots_inline_group *ig,
                                   const char **err)
{
    if (err) *err = NULL;
    if (!doc || !ig) return APR_EINVAL;
    if (doc->groups->nelts >= BOTSHIELD_ROBOTS_MAX_GROUPS) {
        if (err) *err = apr_psprintf(doc->pool,
            "group cap of %d reached", BOTSHIELD_ROBOTS_MAX_GROUPS);
        return APR_ENOSPC;
    }
    robots_group *g = apr_pcalloc(doc->pool, sizeof(*g));
    g->user_agents = apr_array_make(doc->pool, 4, sizeof(const char *));
    g->rules       = apr_array_make(doc->pool, 8, sizeof(robots_rule *));
    for (int i = 0; i < ig->user_agents->nelts; i++) {
        const char *ua = APR_ARRAY_IDX(ig->user_agents, i, const char *);
        if (g->user_agents->nelts >= BOTSHIELD_ROBOTS_MAX_UAS_PER_GROUP) break;
        *(const char **)apr_array_push(g->user_agents) =
            bs_rb_lower_dup(doc->pool, ua);
    }
    for (int i = 0; i < ig->rules->nelts; i++) {
        const bs_robots_inline_rule *ir =
            &APR_ARRAY_IDX(ig->rules, i, bs_robots_inline_rule);
        if (g->rules->nelts >= BOTSHIELD_ROBOTS_MAX_RULES_PER_GROUP) break;
        robots_rule *r = apr_pcalloc(doc->pool, sizeof(*r));
        r->pattern = apr_pstrdup(doc->pool, ir->pattern);
        r->allow   = ir->allow;
        *(robots_rule **)apr_array_push(g->rules) = r;
    }
    const char *first_ua = APR_ARRAY_IDX(g->user_agents, 0, const char *);
    g->crawl_delay_ms = ig->crawl_delay_ms;
    g->name           = apr_pstrdup(doc->pool, ig->name);
    g->is_wildcard    = (strcmp(first_ua, "*") == 0);
    g->mode           = ig->mode;
    g->status         = ig->status;
    g->log_tag        = ig->log_tag ? apr_pstrdup(doc->pool, ig->log_tag)
                                    : NULL;
    g->is_inline      = 1;
    *(robots_group **)apr_array_push(doc->groups) = g;
    return APR_SUCCESS;
}

int robots_group_ua_count_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return (g && g->user_agents) ? g->user_agents->nelts : 0;
}

const char *robots_group_ua_at(const robots_doc *doc, int idx, int ua_idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    if (!g || !g->user_agents) return NULL;
    if (ua_idx < 0 || ua_idx >= g->user_agents->nelts) return NULL;
    return APR_ARRAY_IDX(g->user_agents, ua_idx, const char *);
}

int robots_group_rule_count_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return (g && g->rules) ? g->rules->nelts : 0;
}

int robots_group_rule_at(const robots_doc *doc, int idx, int rule_idx,
                         const char **out_pattern, int *out_allow)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    if (!g || !g->rules) return 0;
    if (rule_idx < 0 || rule_idx >= g->rules->nelts) return 0;
    robots_rule *r = APR_ARRAY_IDX(g->rules, rule_idx, robots_rule *);
    if (!r) return 0;
    if (out_pattern) *out_pattern = r->pattern;
    if (out_allow)   *out_allow   = r->allow;
    return 1;
}

/* --- E2.2 directive setters --- */

/* E2.2 — BotShieldRobotsTxt <path>: point the module at a robots.txt
 * file. Parsing deferred to post_config so pconf's allocator is alive
 * for the doc's lifetime. Empty/absent path is the default "don't
 * enforce robots.txt" state; operators turn it on by pointing at a
 * file. */
/* ======================================================================
 * <BotShieldRobots> -- the container
 *
 * Apache has already built the block's children by the time this runs
 * and hung them off cmd->directive; a nested <BotShieldRobotRule>
 * arrives as a child whose own children are the group's lines. None of
 * the inner names are registered directives: they mean something only
 * in here, and Apache reports an outer one as unknown on its own.
 *
 * One container per server scope. It is the set within which robots
 * precedence is computed -- a rule's meaning depends on its siblings,
 * because a longer Allow elsewhere in the set changes what a Disallow
 * covers -- so two containers would be two independent sets, and a
 * redefinition is refused the way <BotShieldMatch> refuses one.
 * ====================================================================== */

/* The rest of a directive line, one layer of quotes removed. */
static const char *bs_rb_dir_value(apr_pool_t *p, const ap_directive_t *d)
{
    char *v = apr_pstrdup(p, d->args ? d->args : "");
    apr_size_t n = strlen(v);
    while (n && apr_isspace(v[n - 1])) v[--n] = '\0';
    if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
        v[n - 1] = '\0';
        v++;
    }
    return v;
}

static const char *bs_rb_where(apr_pool_t *p, const ap_directive_t *d)
{
    return apr_psprintf(p, "%s:%d", d->filename ? d->filename : "?",
                        d->line_num);
}

static const char *bs_rb_parse_mode(const char *v, int *out)
{
    if (!strcasecmp(v, "enforce"))      *out = BS_ROBOTS_MODE_ENFORCE;
    else if (!strcasecmp(v, "observe")) *out = BS_ROBOTS_MODE_OBSERVE;
    else return "must be enforce or observe";
    return NULL;
}

/* <BotShieldRobotRule name> ... </BotShieldRobotRule> */
static const char *bs_rb_parse_inline_group(cmd_parms *cmd,
                                            const ap_directive_t *d,
                                            bs_robots_inline_group **out)
{
    apr_pool_t *p = cmd->pool;
    /* d->args is "name>" -- the closing bracket travels with it. */
    char *spec = apr_pstrdup(p, d->args ? d->args : "");
    apr_size_t n = strlen(spec);
    while (n && apr_isspace(spec[n - 1])) spec[--n] = '\0';
    if (!n || spec[n - 1] != '>') {
        return apr_psprintf(p, "<BotShieldRobotRule> at %s is missing its "
                            "closing '>'", bs_rb_where(p, d));
    }
    spec[--n] = '\0';
    while (n && apr_isspace(spec[n - 1])) spec[--n] = '\0';
    const char *name = ap_getword_conf(p, (const char **)&spec);
    if (!name || !*name) {
        return apr_psprintf(p, "<BotShieldRobotRule> at %s needs a name: "
                            "<BotShieldRobotRule ai-crawlers>",
                            bs_rb_where(p, d));
    }
    if (strlen(name) > 32) {
        return apr_psprintf(p, "<BotShieldRobotRule %s>: name must be at "
                            "most 32 characters", name);
    }
    for (const char *c = name; *c; c++) {
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9')
              || *c == '-')) {
            return apr_psprintf(p, "<BotShieldRobotRule %s>: name must be "
                                "[a-z0-9-]; it is the group's id in the "
                                "decision log and the dump", name);
        }
    }

    bs_robots_inline_group *g = apr_pcalloc(p, sizeof(*g));
    g->name        = name;
    g->user_agents = apr_array_make(p, 4, sizeof(const char *));
    g->rules       = apr_array_make(p, 8, sizeof(bs_robots_inline_rule));
    g->mode        = BS_ROBOTS_MODE_UNSET;
    int seen_delay = 0, seen_status = 0, seen_mode = 0, seen_tag = 0;

    for (const ap_directive_t *c = d->first_child; c; c = c->next) {
        const char *dir = c->directive;
        const char *val = bs_rb_dir_value(p, c);
        if (!strcasecmp(dir, "BotShieldUserAgent")) {
            if (!*val) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldUserAgent needs a "
                "token (a product token, '*', or @botgroup)", name);
            if (g->user_agents->nelts >= BOTSHIELD_ROBOTS_MAX_UAS_PER_GROUP)
                return apr_psprintf(p, "<BotShieldRobotRule %s>: more than "
                    "%d user agents", name, BOTSHIELD_ROBOTS_MAX_UAS_PER_GROUP);
            *(const char **)apr_array_push(g->user_agents) = val;
        } else if (!strcasecmp(dir, "BotShieldDisallow")
                || !strcasecmp(dir, "BotShieldAllow")) {
            /* An empty Disallow is a real line in robots.txt ("allow
             * everything") and means nothing here, where absence
             * already means that. Refuse it rather than store a
             * pattern that can never match. */
            if (!*val) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: %s needs a path pattern "
                "(/ for everything)", name, dir);
            if (*val != '/' && *val != '*') return apr_psprintf(p,
                "<BotShieldRobotRule %s>: %s '%s' must start with '/' "
                "(or '*')", name, dir, val);
            if (g->rules->nelts >= BOTSHIELD_ROBOTS_MAX_RULES_PER_GROUP)
                return apr_psprintf(p, "<BotShieldRobotRule %s>: more than "
                    "%d rules", name, BOTSHIELD_ROBOTS_MAX_RULES_PER_GROUP);
            bs_robots_inline_rule *r = apr_array_push(g->rules);
            r->pattern = val;
            r->allow   = !strcasecmp(dir, "BotShieldAllow");
            bs_path_pattern_warn_middle_star(cmd, "BotShieldRobotRule",
                                             name, val);
        } else if (!strcasecmp(dir, "BotShieldCrawlDelay")) {
            if (seen_delay++) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldCrawlDelay given twice",
                name);
            char *end = NULL;
            double v = strtod(val, &end);
            if (!end || end == val || *end || !(v > 0.0)
                || v > BOTSHIELD_ROBOTS_MAX_CRAWL_DELAY_SEC) {
                return apr_psprintf(p, "<BotShieldRobotRule %s>: "
                    "BotShieldCrawlDelay '%s' must be seconds, above 0 and "
                    "at most %d; fractions are fine (0.5)", name, val,
                    BOTSHIELD_ROBOTS_MAX_CRAWL_DELAY_SEC);
            }
            int ms = (int)(v * 1000.0 + 0.5);
            if (ms <= 0) return apr_psprintf(p, "<BotShieldRobotRule %s>: "
                "BotShieldCrawlDelay '%s' rounds to no time at all", name, val);
            g->crawl_delay_ms = ms;
        } else if (!strcasecmp(dir, "BotShieldRespond")) {
            if (seen_status++) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldRespond given twice", name);
            char *end = NULL;
            long s = strtol(val, &end, 10);
            if (!end || *end || s < 400 || s > 599) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldRespond '%s' must be a "
                "4xx or 5xx status", name, val);
            if (s == 429) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldRespond 429 is the "
                "Crawl-delay answer, not a refusal; a Disallow that "
                "answers 429 tells the crawler to come back", name);
            g->status = (int)s;
        } else if (!strcasecmp(dir, "BotShieldMode")) {
            if (seen_mode++) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldMode given twice", name);
            const char *e = bs_rb_parse_mode(val, &g->mode);
            if (e) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldMode '%s' %s", name, val, e);
        } else if (!strcasecmp(dir, "BotShieldLogAs")) {
            if (seen_tag++) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldLogAs given twice", name);
            if (!*val) return apr_psprintf(p,
                "<BotShieldRobotRule %s>: BotShieldLogAs needs a tag", name);
            g->log_tag = val;
        } else {
            return apr_psprintf(p, "<BotShieldRobotRule %s>: '%s' at %s is "
                "not a robots setting. Inside a group: BotShieldUserAgent, "
                "BotShieldDisallow, BotShieldAllow, BotShieldCrawlDelay, "
                "BotShieldRespond, BotShieldMode, BotShieldLogAs.",
                name, dir, bs_rb_where(p, c));
        }
    }
    if (g->user_agents->nelts == 0) {
        return apr_psprintf(p, "<BotShieldRobotRule %s> names no "
            "BotShieldUserAgent, so it is addressed to nobody", name);
    }
    if (g->rules->nelts == 0 && g->crawl_delay_ms == 0) {
        return apr_psprintf(p, "<BotShieldRobotRule %s> has no "
            "BotShieldDisallow, BotShieldAllow or BotShieldCrawlDelay, so "
            "it says nothing", name);
    }
    *out = g;
    return NULL;
}

const char *bs_open_robots(cmd_parms *cmd, void *dconf, const char *arg)
{
    (void)dconf;
    apr_pool_t *p = cmd->pool;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);

    char *spec = apr_pstrdup(p, arg ? arg : "");
    apr_size_t n = strlen(spec);
    while (n && apr_isspace(spec[n - 1])) spec[--n] = '\0';
    if (!n || spec[n - 1] != '>') {
        return "<BotShieldRobots> is missing its closing '>'";
    }
    spec[--n] = '\0';
    while (n && apr_isspace(spec[n - 1])) spec[--n] = '\0';
    if (n) {
        return apr_psprintf(p, "<BotShieldRobots> takes no argument; "
                            "'%s' was given", spec);
    }
    if (scfg->robots_container_seen) {
        return "<BotShieldRobots> is already defined in this scope. One "
               "container per scope: it is the set within which robots.txt "
               "precedence is computed, and two would be two independent "
               "sets. Put every group in the one block.";
    }
    scfg->robots_container_seen = 1;

    apr_array_header_t *groups =
        apr_array_make(p, 4, sizeof(bs_robots_inline_group *));
    int seen_txt = 0, seen_mode = 0, seen_scope = 0, seen_ival = 0;

    for (const ap_directive_t *d = cmd->directive->first_child; d;
         d = d->next) {
        const char *dir = d->directive;
        const char *val = bs_rb_dir_value(p, d);
        if (!strcasecmp(dir, "BotShieldRobotsTxt")) {
            if (seen_txt++) return "<BotShieldRobots>: BotShieldRobotsTxt "
                                   "given twice";
            if (!*val) return "<BotShieldRobots>: BotShieldRobotsTxt needs a path";
            if (*val != '/') return apr_psprintf(p, "<BotShieldRobots>: "
                "BotShieldRobotsTxt '%s' must be an absolute path", val);
            scfg->robots_txt_path = apr_pstrdup(p, val);
        } else if (!strcasecmp(dir, "BotShieldMode")) {
            if (seen_mode++) return "<BotShieldRobots>: BotShieldMode given twice";
            const char *e = bs_rb_parse_mode(val, &scfg->robots_mode);
            if (e) return apr_psprintf(p, "<BotShieldRobots>: BotShieldMode "
                                       "'%s' %s", val, e);
        } else if (!strcasecmp(dir, "BotShieldWildcardScope")) {
            if (seen_scope++) return "<BotShieldRobots>: BotShieldWildcardScope "
                                     "given twice";
            if (!strcasecmp(val, "heuristic"))
                scfg->robots_wildcard_scope = BS_ROBOTS_WILDCARD_HEURISTIC;
            else if (!strcasecmp(val, "strict"))
                scfg->robots_wildcard_scope = BS_ROBOTS_WILDCARD_STRICT;
            else if (!strcasecmp(val, "off"))
                scfg->robots_wildcard_scope = BS_ROBOTS_WILDCARD_OFF;
            else return apr_psprintf(p, "<BotShieldRobots>: "
                "BotShieldWildcardScope '%s' not one of heuristic|strict|off",
                val);
        } else if (!strcasecmp(dir, "BotShieldRefreshInterval")) {
            if (seen_ival++) return "<BotShieldRobots>: BotShieldRefreshInterval "
                                    "given twice";
            char *end = NULL;
            long v = strtol(val, &end, 10);
            if (!end || end == val || *end || v < 0 || v > 86400) {
                return apr_psprintf(p, "<BotShieldRobots>: "
                    "BotShieldRefreshInterval '%s' must be an integer "
                    "0..86400 seconds (0 = no live refresh)", val);
            }
            scfg->robots_refresh_interval = (int)v;
        } else if (!strcasecmp(dir, "<BotShieldRobotRule")) {
            bs_robots_inline_group *g = NULL;
            const char *e = bs_rb_parse_inline_group(cmd, d, &g);
            if (e) return e;
            for (int i = 0; i < groups->nelts; i++) {
                bs_robots_inline_group *o =
                    APR_ARRAY_IDX(groups, i, bs_robots_inline_group *);
                if (strcmp(o->name, g->name) == 0) {
                    return apr_psprintf(p, "<BotShieldRobotRule %s> is "
                        "defined twice in this <BotShieldRobots>", g->name);
                }
            }
            *(bs_robots_inline_group **)apr_array_push(groups) = g;
        } else {
            return apr_psprintf(p, "<BotShieldRobots>: '%s' at %s is not a "
                "robots setting. Inside the container: BotShieldRobotsTxt, "
                "BotShieldMode, BotShieldWildcardScope, "
                "BotShieldRefreshInterval, or a <BotShieldRobotRule name> "
                "block.", dir, bs_rb_where(p, d));
        }
    }
    if (!scfg->robots_txt_path && groups->nelts == 0) {
        return "<BotShieldRobots> is empty: give it a BotShieldRobotsTxt "
               "file, a <BotShieldRobotRule> block, or both";
    }
    scfg->robots_groups = groups;
    return NULL;
}

/* The bs_path_pattern_warn_middle_star helper below is a config-time
 * validator shared by E3 BotShieldRule (triggers.c) and the
 * request-path glob matcher (robots.c's bs_path_match). Lives here
 * so both callers find it without circular includes. */

/* Surface a NOTICE at config-load when a pattern contains a non-
 * trailing '*'. Under the retired v1 matcher those characters were
 * treated as literal bytes (which essentially never matched any
 * URI). Under the RFC 9309 matcher they're proper wildcards. The
 * behavior change is desired for operators who intended wildcards;
 * for operators who fat-fingered a '*' the warning gives them a
 * heads-up so the new match doesn't surprise them. The trailing '*'
 * (or '*' followed only by '$') is the documented v1 shape and
 * stays silent — its behavior didn't change. */
void bs_path_pattern_warn_middle_star(cmd_parms *cmd,
                                      const char *directive,
                                      const char *name,
                                      const char *pattern)
{
    const char *star = strchr(pattern, '*');
    if (!star) return;
    /* Find the last '*'. Anything past the last '*' that isn't
     * empty or "$" means there's content after a wildcard, i.e.
     * the wildcard is non-trailing. */
    const char *last_star = star;
    for (const char *q = star + 1; *q; q++) {
        if (*q == '*') last_star = q;
    }
    const char *tail = last_star + 1;
    if (*tail == '\0') return;        /* trailing '*' — v1 shape */
    if (tail[0] == '$' && tail[1] == '\0') return; /* '*$' — v1 shape */
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server,
        "mod_botshield: %s '%s' pattern '%s' contains a non-trailing "
        "'*'; interpreted per RFC 9309 (matches any byte sequence at "
        "this position). The retired v1 matcher treated middle '*' "
        "as a literal byte. If the literal was intended, this rule "
        "will no longer match.",
        directive, name, pattern);
}

/* ======================================================================
 * E2.2.2 — live-refresh of robots.txt via mod_watchdog
 *
 * bs_robots_load(): stat + (conditionally) parse + publish. Runs both
 * at post_config (initial load) and at each watchdog tick (refresh).
 * When the source file's mtime is unchanged, it's a cheap no-op.
 *
 * Atomic-swap model: active state lives in scfg->robots (read with
 * __atomic_load_n on the request path). When a fresh doc is built,
 * we atomically publish it, push the outgoing state into
 * scfg->robots_pending, and destroy whatever pool was in the
 * previous pending slot. That gives each displaced doc at least one
 * refresh interval of grace — more than enough for any in-flight
 * request to finish reading pointers into its pool.
 *
 * Slot stability: SHM rate-counter slots are keyed by group name via
 * scfg->robots_slot_by_name, which lives in pconf and survives
 * refresh. A group whose name reappears in the new doc keeps its
 * existing slot (and its in-flight Crawl-delay window); a genuinely
 * new group gets a fresh slot from the reserved pool. The map never
 * shrinks — operators who delete a crawler from robots.txt leave a
 * stale entry, which is harmless (no lookup targets it). If they
 * re-add it, the old slot is reused.
 * ====================================================================== */
apr_status_t bs_robots_load(server_rec *sv, bs_server_cfg *scfg,
                            apr_pool_t *pconf)
{
    if (!scfg || !bs_robots_configured(scfg)) return APR_EINVAL;

    bs_robots_state *cur =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    apr_finfo_t fi;
    apr_status_t rv;
    fi.mtime = 0;
    if (scfg->robots_txt_path) {
        /* Stat first — if mtime is unchanged since the active doc was
         * parsed, there's nothing to do. This is the common case on
         * every refresh tick. */
        rv = apr_stat(&fi, scfg->robots_txt_path,
                      APR_FINFO_MTIME | APR_FINFO_SIZE, pconf);
        if (rv != APR_SUCCESS) {
            char errbuf[128];
            apr_strerror(rv, errbuf, sizeof(errbuf));
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, sv,
                "mod_botshield: robots.txt %s stat failed (%s); "
                "keeping previous state",
                scfg->robots_txt_path, errbuf);
            return rv;
        }
        if (cur && cur->mtime == fi.mtime) {
            return APR_SUCCESS;
        }
    } else if (cur) {
        /* Inline groups only: config-time constants, built once. */
        return APR_SUCCESS;
    }

    /* Build the new state in a fresh subpool we control. Destroying
     * this subpool later frees the doc and its slot map in one go,
     * without touching anything else in pconf. */
    apr_pool_t *npool = NULL;
    apr_pool_create(&npool, pconf);

    robots_doc *doc = NULL;
    const char *parse_err = NULL;
    if (scfg->robots_txt_path) {
        rv = robots_parse_file(npool, scfg->robots_txt_path,
                               &doc, &parse_err);
        if (rv != APR_SUCCESS || !doc) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, sv,
                "mod_botshield: robots.txt %s parse failed (%s); "
                "keeping previous state",
                scfg->robots_txt_path,
                parse_err ? parse_err : "unknown error");
            apr_pool_destroy(npool);
            return rv;
        }
    } else {
        doc = robots_doc_empty(npool);
    }

    /* The inline groups join the same document, so precedence is
     * computed across the file and the config together: that is what
     * makes the container the scope rather than a wrapper. Re-added
     * on every refresh of the file, since the doc is rebuilt whole. */
    if (scfg->robots_groups) {
        for (int i = 0; i < scfg->robots_groups->nelts; i++) {
            bs_robots_inline_group *ig = APR_ARRAY_IDX(
                scfg->robots_groups, i, bs_robots_inline_group *);
            const char *aerr = NULL;
            if (robots_doc_add_inline(doc, ig, &aerr) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
                    "mod_botshield: <BotShieldRobotRule %s> not added: %s",
                    ig->name, aerr ? aerr : "unknown error");
            }
        }
    }

    /* Surface truncated lines (the parser
     * silently caps any line > BOTSHIELD_ROBOTS_MAX_LINE). The
     * documented contract said operators "see a warning through
     * the summary log"; this emits that warning. */
    int n_truncated = robots_doc_truncated_lines(doc);
    if (n_truncated > 0) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: robots.txt %s: %d line(s) exceeded the "
            "parser line limit and were truncated during parse",
            scfg->robots_txt_path, n_truncated);
    }
    int n_groups = robots_group_count(doc);
    bs_robots_state *ns = apr_pcalloc(npool, sizeof(*ns));
    ns->doc   = doc;
    ns->pool  = npool;
    ns->mtime = fi.mtime;
    ns->slot_by_group_idx = apr_pcalloc(npool,
        (n_groups > 0 ? n_groups : 1) * sizeof(int));

    int delay_count = 0, slot_reused = 0, slot_new = 0, slot_exhausted = 0;
    for (int i = 0; i < n_groups; i++) {
        ns->slot_by_group_idx[i] = -1;
        int cd = robots_group_crawl_delay_ms_at(doc, i);
        if (cd <= 0) continue;
        delay_count++;
        const char *name = robots_group_name_at(doc, i);
        int *slot_ptr = apr_hash_get(scfg->robots_slot_by_name,
                                     name, APR_HASH_KEY_STRING);
        if (slot_ptr) {
            ns->slot_by_group_idx[i] = *slot_ptr;
            slot_reused++;
            continue;
        }
        if (scfg->robots_slot_pool_used < scfg->robots_slot_pool_size) {
            int slot = scfg->robots_slot_pool_base
                     + scfg->robots_slot_pool_used++;
            ns->slot_by_group_idx[i] = slot;
            /* Persist the mapping in pconf so future refreshes see
             * it. Copy name into pconf too — the doc's pool will be
             * destroyed on replacement and its name string with it. */
            int *persist = apr_palloc(pconf, sizeof(int));
            *persist = slot;
            apr_hash_set(scfg->robots_slot_by_name,
                         apr_pstrdup(pconf, name),
                         APR_HASH_KEY_STRING, persist);
            slot_new++;
        } else {
            slot_exhausted++;
        }
    }

    /* Publish the new state. scfg->robots_pending currently holds
     * the bundle displaced one refresh ago (or NULL at first load);
     * destroy its pool now — more than one refresh interval has
     * passed since any request took a pointer to it. */
    bs_robots_state *to_destroy = scfg->robots_pending;
    bs_robots_state *displaced  = cur;
    __atomic_store_n(&scfg->robots, ns, __ATOMIC_RELEASE);
    bs_gen_note_built(BS_GEN_ROBOTS);
    scfg->robots_pending = displaced;
    if (to_destroy && to_destroy->pool) {
        apr_pool_destroy(to_destroy->pool);
        bs_gen_note_freed(BS_GEN_ROBOTS);
    }

    if (slot_exhausted > 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
            "mod_botshield: robots.txt slot pool exhausted "
            "(%d/%d used); %d Crawl-delay groups will not enforce "
            "until an Apache reload resizes the pool",
            scfg->robots_slot_pool_used, scfg->robots_slot_pool_size,
            slot_exhausted);
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
        "mod_botshield: robots %s %sloaded - %d groups (%d inline), "
        "%d with Crawl-delay (%d slots reused, %d new)",
        scfg->robots_txt_path ? scfg->robots_txt_path
                              : "<BotShieldRobots> (no file)",
        cur ? "re" : "", n_groups,
        scfg->robots_groups ? scfg->robots_groups->nelts : 0,
        delay_count, slot_reused, slot_new);
    return APR_SUCCESS;
}

/* mod_watchdog tick callback — one registration per vhost with a
 * BotShieldRobotsTxt directive. State-transition events (STARTING,
 * STOPPING) do nothing; RUNNING calls bs_robots_load which returns
 * fast when mtime hasn't changed. */
apr_status_t bs_robots_watchdog_cb(int state, void *data,
                                          apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    /* data was passed as the server_rec at registration; retrieve
     * scfg from it so we always see the live pointer. pconf is
     * reachable through sv->process->pconf. */
    server_rec *sv = data;
    if (!sv) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(sv->module_config, &botshield_module);
    if (!scfg || !scfg->robots_txt_path) return APR_SUCCESS;
    bs_robots_load(sv, scfg, sv->process->pconf);
    return APR_SUCCESS;
}
