/* allowlist.c — verified-crawler building blocks. See allowlist.h
 * for the operator-level design narrative; this file owns the
 * data-structure and parsing internals. */

#include "allowlist.h"

#include <ctype.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_network_io.h>

const bs_allow_bot_entry bs_builtin_bots[] = {
    { "googlebot", "Googlebot", NULL, NULL, 0 },
    { "bingbot",   "bingbot",   NULL, NULL, 0 },
    { "applebot",  "Applebot",  NULL, NULL, 0 },
    { NULL, NULL, NULL, NULL, 0 }
};

/* --- UA classifier ---------------------------------------------- *
 *
 * Vanilla trie, case-insensitive (lower at each step), one terminal
 * per declared pattern. No Aho-Corasick failure links — simpler to
 * read, indistinguishable on realistic UAs. Designed to scale to
 * ~400 patterns (Cloudflare Radar's worked list) without the linear-
 * scan wall a dumb match list would hit.
 *
 * Pure read-only at request time; populated in post_config and
 * immutable thereafter. */

typedef struct bs_ua_trie_child {
    unsigned char c;                /* lowercased char this edge matches */
    struct bs_ua_trie_node *node;
} bs_ua_trie_child;

typedef struct bs_ua_trie_node {
    bs_ua_trie_child *kids;         /* pool-allocated, grown on insert */
    int n_kids;
    int cap_kids;
    const char *name;               /* non-NULL → terminal (match here) */
} bs_ua_trie_node;

struct bs_ua_classifier {
    apr_pool_t *pool;               /* for node allocation */
    bs_ua_trie_node *root;
    int n_patterns;                 /* for logging */
};

bs_ua_classifier *bs_ua_classifier_create(apr_pool_t *p)
{
    bs_ua_classifier *c = apr_pcalloc(p, sizeof(*c));
    c->pool = p;
    c->root = apr_pcalloc(p, sizeof(*c->root));
    return c;
}

static bs_ua_trie_node *bs_ua_trie_walk(bs_ua_trie_node *n, unsigned char c)
{
    c = (unsigned char)tolower(c);
    for (int i = 0; i < n->n_kids; i++) {
        if (n->kids[i].c == c) return n->kids[i].node;
    }
    return NULL;
}

static bs_ua_trie_node *bs_ua_trie_edge_get_or_add(apr_pool_t *p,
                                                   bs_ua_trie_node *n,
                                                   unsigned char c)
{
    c = (unsigned char)tolower(c);
    for (int i = 0; i < n->n_kids; i++) {
        if (n->kids[i].c == c) return n->kids[i].node;
    }
    /* Grow children array. Most nodes have 1-3 kids; start at 2, double. */
    if (n->n_kids == n->cap_kids) {
        int new_cap = n->cap_kids ? n->cap_kids * 2 : 2;
        bs_ua_trie_child *nk = apr_palloc(p,
            (apr_size_t)new_cap * sizeof(*nk));
        if (n->n_kids > 0) {
            memcpy(nk, n->kids, (apr_size_t)n->n_kids * sizeof(*nk));
        }
        n->kids = nk;
        n->cap_kids = new_cap;
    }
    bs_ua_trie_node *child = apr_pcalloc(p, sizeof(*child));
    n->kids[n->n_kids].c = c;
    n->kids[n->n_kids].node = child;
    n->n_kids++;
    return child;
}

apr_status_t bs_ua_classifier_add(bs_ua_classifier *c,
                                  const char *name, const char *pattern)
{
    if (!name || !pattern || !*pattern) return APR_EINVAL;
    bs_ua_trie_node *n = c->root;
    for (const char *p = pattern; *p; p++) {
        n = bs_ua_trie_edge_get_or_add(c->pool, n, (unsigned char)*p);
        if (!n) return APR_ENOMEM;
    }
    /* Last-writer-wins on duplicate registration — the operator
     * probably meant to override. */
    n->name = name;
    c->n_patterns++;
    return APR_SUCCESS;
}

const char *bs_ua_classify(const bs_ua_classifier *c, const char *ua)
{
    if (!c || !ua || !*ua) return NULL;

    /* No prefilter: an earlier revision short-circuited on a hardcoded
     * bot/crawl/spider/fetch/slurp token list, but that silently made
     * operator-defined patterns unreachable for UAs that didn't happen
     * to contain one of those tokens. Correctness beats the ~1 µs we'd
     * save on non-bot traffic, and the trie walk is already O(|ua|)
     * with a small constant (most positions die within 1–2 edges
     * because the trie is sparse). */
    const char *best_name = NULL;
    size_t best_len = 0;
    for (const char *start = ua; *start; start++) {
        bs_ua_trie_node *n = c->root;
        size_t len = 0;
        for (const char *p = start; *p; p++) {
            n = bs_ua_trie_walk(n, (unsigned char)*p);
            if (!n) break;
            len++;
            if (n->name && len > best_len) {
                best_name = n->name;
                best_len  = len;
            }
        }
    }
    return best_name;
}

/* --- CIDR list loader ------------------------------------------- *
 *
 * Plain-text format, one CIDR per line, # for comments, empty lines
 * OK. Accepts both IPv4 and IPv6. apr_ipsubnet_create parses the
 * CIDR; we hold them in an apr_array_header_t of apr_ipsubnet_t *
 * that the request-time matcher scans. */

/* Push one CIDR token into the array. Handles the in-place "/mask"
 * split so apr_ipsubnet_create sees a clean (ip, mask) pair. The
 * token is mutated in place — callers hand in a scratch copy. */
static apr_status_t bs_allow_push_cidr(apr_pool_t *p,
                                       apr_array_header_t *arr,
                                       char *token,
                                       const char **out_err)
{
    /* trim surrounding whitespace */
    while (*token == ' ' || *token == '\t') token++;
    apr_size_t l = strlen(token);
    while (l > 0 && (token[l-1] == ' ' || token[l-1] == '\t')) {
        token[--l] = '\0';
    }
    if (!*token) return APR_SUCCESS;   /* empty token = skip silently */

    char *slash = strchr(token, '/');
    apr_ipsubnet_t *net = NULL;
    apr_status_t rv;
    if (slash) {
        *slash = '\0';
        rv = apr_ipsubnet_create(&net, token, slash + 1, p);
    } else {
        rv = apr_ipsubnet_create(&net, token, NULL, p);
    }
    if (rv != APR_SUCCESS) {
        char errbuf[256];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        *out_err = apr_psprintf(p, "invalid CIDR '%s': %s", token, errbuf);
        return APR_EINVAL;
    }
    APR_ARRAY_PUSH(arr, apr_ipsubnet_t *) = net;
    return APR_SUCCESS;
}

apr_status_t bs_allow_load_ranges_from_string(apr_pool_t *p,
                                              const char *csv,
                                              apr_array_header_t **out,
                                              const char **out_err)
{
    *out = NULL;
    *out_err = NULL;
    if (!csv || !*csv) {
        *out_err = "empty CIDR list";
        return APR_EINVAL;
    }
    apr_array_header_t *arr =
        apr_array_make(p, 4, sizeof(apr_ipsubnet_t *));
    char *scratch = apr_pstrdup(p, csv);
    char *saveptr = NULL;
    for (char *tok = apr_strtok(scratch, ",", &saveptr); tok;
         tok = apr_strtok(NULL, ",", &saveptr)) {
        apr_status_t rv = bs_allow_push_cidr(p, arr, tok, out_err);
        if (rv != APR_SUCCESS) return rv;
    }
    if (arr->nelts == 0) {
        *out_err = "no valid CIDRs parsed from inline list";
        return APR_EINVAL;
    }
    *out = arr;
    return APR_SUCCESS;
}

apr_status_t bs_allow_load_ranges(apr_pool_t *p, const char *path,
                                  apr_array_header_t **out,
                                  const char **out_err)
{
    *out = NULL;
    *out_err = NULL;

    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, path, APR_FOPEN_READ,
                                    APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        char errbuf[256];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        *out_err = apr_psprintf(p, "cannot open '%s': %s", path, errbuf);
        return rv;
    }

    apr_finfo_t fi;
    rv = apr_file_info_get(&fi, APR_FINFO_SIZE, f);
    if (rv == APR_SUCCESS && fi.size > BS_CRAWLER_MAX_RANGES_FILE) {
        apr_file_close(f);
        *out_err = apr_psprintf(p,
            "'%s' is %" APR_OFF_T_FMT " bytes — above %d cap",
            path, fi.size, BS_CRAWLER_MAX_RANGES_FILE);
        return APR_EINVAL;
    }

    apr_array_header_t *arr =
        apr_array_make(p, 32, sizeof(apr_ipsubnet_t *));
    char line[512];
    int lineno = 0;

    while (apr_file_gets(line, sizeof(line), f) == APR_SUCCESS) {
        lineno++;
        char *s = line;
        /* trim trailing CR/LF/whitespace */
        apr_size_t l = strlen(s);
        while (l > 0 && (s[l-1] == '\n' || s[l-1] == '\r' ||
                         s[l-1] == ' '  || s[l-1] == '\t')) {
            s[--l] = '\0';
        }
        /* skip leading whitespace */
        while (*s == ' ' || *s == '\t') s++;
        /* skip blanks + comments */
        if (!*s || *s == '#') continue;

        const char *push_err = NULL;
        rv = bs_allow_push_cidr(p, arr, s, &push_err);
        if (rv != APR_SUCCESS) {
            apr_file_close(f);
            *out_err = apr_psprintf(p,
                "'%s' line %d: %s", path, lineno,
                push_err ? push_err : "parse error");
            return rv;
        }
    }
    apr_file_close(f);

    if (arr->nelts == 0) {
        *out_err = apr_psprintf(p, "'%s' contained no CIDR entries", path);
        return APR_EINVAL;
    }

    *out = arr;
    return APR_SUCCESS;
}

int bs_allow_ip_in_ranges(const apr_array_header_t *ranges, request_rec *r)
{
    if (!ranges || ranges->nelts == 0) return 0;
    /* Convert the client IP string into an apr_sockaddr_t that
     * apr_ipsubnet_test can inspect. The client IP has already been
     * normalized by mod_remoteip (if wired) — we take it as-is. */
    const char *ip_str = r->useragent_ip;
    if (!ip_str || !*ip_str) return 0;

    /* Defense-in-depth: r->useragent_ip should already be a numeric
     * address (mod_remoteip rewrites it before our hooks run), but
     * if mod_remoteip is misconfigured or absent a non-numeric
     * value would otherwise trigger a blocking DNS lookup on the
     * worker thread inside apr_sockaddr_info_get (5–30 s OS
     * resolver timeout). Use inet_pton directly to prove the
     * input is numeric IPv4 or IPv6 before letting APR's parser
     * see it; if both fail, refuse. apr_sockaddr_info_get
     * downstream is then guaranteed to short-circuit on the
     * inet_pton path it does internally — the DNS fallback is
     * unreachable from this code path by construction. */
    unsigned char ipv4_probe[4];
    unsigned char ipv6_probe[16];
    if (inet_pton(AF_INET, ip_str, ipv4_probe) != 1 &&
        inet_pton(AF_INET6, ip_str, ipv6_probe) != 1) {
        return 0;
    }
    apr_sockaddr_t *sa = NULL;
    apr_status_t rv = apr_sockaddr_info_get(&sa, ip_str,
                                            APR_UNSPEC, 0, 0,
                                            r->pool);
    if (rv != APR_SUCCESS || !sa) return 0;

    for (int i = 0; i < ranges->nelts; i++) {
        apr_ipsubnet_t *net = APR_ARRAY_IDX(ranges, i, apr_ipsubnet_t *);
        if (apr_ipsubnet_test(net, sa)) return 1;
    }
    return 0;
}
