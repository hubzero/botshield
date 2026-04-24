/* robots.c — mod_botshield's robots.txt parser + matcher.
 *
 * See robots.h for the public surface. Semantics follow RFC 9309 plus
 * the Crawl-delay de facto extension. Pure APR; no Apache httpd.h.
 *
 * Defensive parsing — this is operator-controlled input today, but
 * E2.2b will watch the file for changes and hot-reload it, so we treat
 * it as untrusted. Length caps, line caps, and unknown-key tolerance
 * keep a malformed file from crashing the module or blowing memory.
 */
#include "robots.h"

#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_lib.h>

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>

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
    int                 crawl_delay;  /* seconds, 0 if unset */
    const char         *name;         /* normalized id, derived from first UA */
    int                 is_wildcard;  /* 1 when first UA is "*" */
} robots_group;

struct robots_doc {
    apr_pool_t         *pool;
    apr_array_header_t *groups;       /* robots_group * */
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
 * filtered out at parse time. */
static int bs_rb_path_match(const char *pattern, const char *path)
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

/* Determine the "specificity" of the match: the length of the
 * longest User-agent token across the doc that matches this UA.
 * Returns 0 when only the `*` fallback matches (or nothing
 * matches), so callers can distinguish the wildcard fallback
 * case. `*_has_wildcard` is set to 1 if any group's UA list
 * contains `*`; `*_doc_has_any_match` is 1 if a specific (non-`*`)
 * token matched. */
static int bs_rb_best_token_len(const robots_doc *doc, const char *ua,
                                int *out_has_wildcard)
{
    int best_len = 0;
    int has_wildcard = 0;
    for (int i = 0; i < doc->groups->nelts; i++) {
        robots_group *g = APR_ARRAY_IDX(doc->groups, i, robots_group *);
        for (int j = 0; j < g->user_agents->nelts; j++) {
            const char *tok = APR_ARRAY_IDX(g->user_agents, j, const char *);
            if (strcmp(tok, "*") == 0) { has_wildcard = 1; continue; }
            if (bs_rb_ua_segment_match(ua, tok)) {
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
 * length == best_len that matches the crawler UA. If `best_len == 0`
 * (no specific match), the group qualifies iff it contains `*`. */
static int bs_rb_group_qualifies(const robots_group *g,
                                 const char *ua, int best_len)
{
    for (int j = 0; j < g->user_agents->nelts; j++) {
        const char *tok = APR_ARRAY_IDX(g->user_agents, j, const char *);
        if (best_len == 0) {
            if (strcmp(tok, "*") == 0) return 1;
        } else {
            if (strcmp(tok, "*") == 0) continue;
            if ((int)strlen(tok) == best_len
                && bs_rb_ua_segment_match(ua, tok)) return 1;
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
    g->crawl_delay = 0;
    g->is_wildcard = 0;
    g->name        = "unnamed";
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
    char *end = NULL;
    long v = strtol(value, &end, 10);
    if (!end || (*end != '\0' && *end != ' ' && *end != '\t')) return;
    if (v <= 0 || v > BOTSHIELD_ROBOTS_MAX_CRAWL_DELAY_SEC) return;
    st->cur->crawl_delay = (int)v;
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
        if (copy_len >= sizeof(line)) copy_len = sizeof(line) - 1;
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
 *      values — most restrictive wins. The RFC is silent on
 *      duplicates; max is the safe interpretation for rate-limit
 *      enforcement (if any stanza says "wait 60s," honor it).
 *   5. group_idx / group_name report the first relevant group —
 *      stable identifier for the decision log and for the slot
 *      lookup downstream (duplicate-name groups share an SHM slot
 *      by construction of scfg->robots_slot_by_name). */
void robots_query(const robots_doc *doc, const char *ua, const char *path,
                  robots_match *out)
{
    if (!out) return;
    out->group_idx       = -1;
    out->is_wildcard     = 0;
    out->allowed         = 1;
    out->crawl_delay_sec = 0;
    out->group_name      = NULL;
    if (!doc || !ua || !doc->groups || doc->groups->nelts == 0) return;

    int has_wildcard = 0;
    int best_len = bs_rb_best_token_len(doc, ua, &has_wildcard);
    if (best_len == 0 && !has_wildcard) return;  /* nothing to enforce */

    int best_rule_len = -1;
    int best_allow    = 1;
    int first_relevant_idx = -1;
    int max_crawl_delay    = 0;

    for (int i = 0; i < doc->groups->nelts; i++) {
        robots_group *g = APR_ARRAY_IDX(doc->groups, i, robots_group *);
        if (!bs_rb_group_qualifies(g, ua, best_len)) continue;
        if (first_relevant_idx < 0) first_relevant_idx = i;

        if (g->crawl_delay > max_crawl_delay) {
            max_crawl_delay = g->crawl_delay;
        }
        if (!path) continue;

        for (int k = 0; k < g->rules->nelts; k++) {
            robots_rule *r = APR_ARRAY_IDX(g->rules, k, robots_rule *);
            if (!bs_rb_path_match(r->pattern, path)) continue;
            int len = (int)strlen(r->pattern);
            if (len > best_rule_len) {
                best_rule_len = len;
                best_allow = r->allow;
            } else if (len == best_rule_len && r->allow) {
                best_allow = 1;
            }
        }
    }

    if (first_relevant_idx < 0) return;

    robots_group *fg = APR_ARRAY_IDX(doc->groups, first_relevant_idx,
                                     robots_group *);
    out->group_idx       = first_relevant_idx;
    out->is_wildcard     = (best_len == 0);
    out->crawl_delay_sec = max_crawl_delay;
    out->group_name      = fg->name;
    out->allowed         = (path && best_rule_len >= 0) ? best_allow : 1;
}

int robots_group_count(const robots_doc *doc)
{
    return (doc && doc->groups) ? doc->groups->nelts : 0;
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

int robots_group_crawl_delay_at(const robots_doc *doc, int idx)
{
    robots_group *g = bs_rb_group_at(doc, idx);
    return g ? g->crawl_delay : 0;
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
