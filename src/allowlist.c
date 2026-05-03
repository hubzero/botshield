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
#include <apr_hash.h>

#include <http_config.h>
#include <http_log.h>
#include <mod_watchdog.h>

#include "botshield.h"
#include "score.h"
#include "shm.h"
#include "ua_class.h"

/* bs_builtin_bots[] is now defined in src/generated_verified_bots.c,
 * codegenned from vendor/verified-bots.json by
 * tools/gen-verified-bots.py. The .json file is the source of
 * truth for the bundled set of verified-bot entries; an operator
 * overlay at vendor/verified-bots.local.json (gitignored) can add
 * entries or override built-ins on slug collision. See
 * tools/gen-verified-bots.py for the layering details. */

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

/* Find the longest registered pattern that appears as a substring of
 * `ua`, anywhere in the string. Algorithm: slide a start position
 * across the UA; from each start, walk the trie matching consecutive
 * characters; track the longest pattern terminal hit. Returns the
 * registered name of the winning pattern, NULL if no pattern matched.
 *
 * Worst case is O(|ua| * max_pattern_length), but the trie is sparse
 * (most start positions die within 1-2 edges) so realistic cost is
 * close to O(|ua|). Equivalent to Aho-Corasick without the failure-
 * link bookkeeping; the simpler form is fast enough at the ~400-
 * pattern scale this classifier targets. */
const char *bs_ua_classify(const bs_ua_classifier *c, const char *ua)
{
    if (!c || !ua || !*ua) return NULL;

    /* No prefilter: an earlier revision short-circuited on a hardcoded
     * bot/crawl/spider/fetch/slurp token list, but that silently made
     * operator-defined patterns unreachable for UAs that didn't happen
     * to contain one of those tokens. Correctness beats the ~1 µs we'd
     * save on non-bot traffic. */
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

const char *bs_allow_sidecar_path(apr_pool_t *p, const char *canonical)
{
    if (!canonical || !*canonical) return NULL;
    apr_size_t l = strlen(canonical);
    /* Convention: "<base>.txt" → "<base>.local.txt"; otherwise
     * "<canonical>.local". Keeps the common case readable
     * (siteimprove.txt + siteimprove.local.txt next to each other)
     * while still working for operators who pointed the directive
     * at a file with no .txt suffix. */
    if (l > 4 && strcmp(canonical + l - 4, ".txt") == 0) {
        char *base = apr_pstrmemdup(p, canonical, l - 4);
        return apr_pstrcat(p, base, ".local.txt", NULL);
    }
    return apr_pstrcat(p, canonical, ".local", NULL);
}

apr_status_t bs_allow_load_ranges_with_sidecar(
    apr_pool_t *p,
    const char *canonical_path,
    const char *sidecar_path,
    apr_array_header_t **out,
    apr_time_t *out_canonical_mtime,
    apr_time_t *out_sidecar_mtime,
    const char **out_err)
{
    *out = NULL;
    if (out_err) *out_err = NULL;
    if (out_canonical_mtime) *out_canonical_mtime = 0;
    if (out_sidecar_mtime)   *out_sidecar_mtime   = 0;

    apr_array_header_t *canon = NULL;
    apr_status_t rv = bs_allow_load_ranges(p, canonical_path, &canon, out_err);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_finfo_t fi;
    if (apr_stat(&fi, canonical_path, APR_FINFO_MTIME, p) == APR_SUCCESS) {
        if (out_canonical_mtime) *out_canonical_mtime = fi.mtime;
    }

    /* Sidecar is optional — missing file = no extras. Any other
     * problem (parse error, permissions, oversize) is a hard
     * error: silently dropping a malformed sidecar would let
     * operator typos disappear without surfacing. */
    if (sidecar_path && *sidecar_path) {
        apr_finfo_t sfi;
        apr_status_t srv = apr_stat(&sfi, sidecar_path, APR_FINFO_MTIME, p);
        if (srv == APR_SUCCESS) {
            if (out_sidecar_mtime) *out_sidecar_mtime = sfi.mtime;
            apr_array_header_t *side = NULL;
            const char *side_err = NULL;
            srv = bs_allow_load_ranges(p, sidecar_path, &side, &side_err);
            if (srv != APR_SUCCESS) {
                if (out_err) *out_err = side_err
                    ? apr_psprintf(p, "sidecar %s: %s",
                                   sidecar_path, side_err)
                    : apr_psprintf(p, "sidecar %s: parse error",
                                   sidecar_path);
                return srv;
            }
            for (int i = 0; i < side->nelts; i++) {
                APR_ARRAY_PUSH(canon, apr_ipsubnet_t *) =
                    APR_ARRAY_IDX(side, i, apr_ipsubnet_t *);
            }
        }
        /* APR_STATUS_IS_ENOENT or any other stat failure → treat as
         * no sidecar present. Don't propagate; operator hasn't asked
         * for a sidecar and the canonical loaded fine. */
    }

    *out = canon;
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

/* --- E1 directive setters --- */

/* BotShieldAllowBot <name> <ua-pattern> [<target>] — register a
 * bot (or override a built-in). The optional third argument is
 * polymorphic — shape-inspected here, not a separate directive:
 *
 *   _(omitted)_           → default file path
 *                           /var/lib/botshield/bots/<name>.txt
 *   starts with '/'       → explicit file path
 *   equals "*"            → UA-only mode; trust on UA match with no
 *                           IP verification. Logs allow-bot-ua:<name>.
 *   anything else         → inline CIDR (single, or comma-separated
 *                           for multiple: "10.0.0.0/8,192.168.0.0/16").
 *
 * Supersedes the two-directive shape (Pattern + Ranges) we
 * initially landed — one directive per bot, config-local. */
const char *bs_set_allow_bot(cmd_parms *cmd, void *dconf,
                                    const char *name,
                                    const char *pattern,
                                    const char *target)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldAllowBot: name '%s' must be [a-z0-9-]{1,32}",
            name);
    }
    if (!pattern || !*pattern) {
        return "BotShieldAllowBot: pattern (arg 2) cannot be empty";
    }
    if (strlen(pattern) > 128) {
        return "BotShieldAllowBot: pattern over 128 chars "
               "(pick a shorter distinctive substring)";
    }

    bs_allow_bot_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name    = apr_pstrdup(cmd->pool, name);
    e->pattern = apr_pstrdup(cmd->pool, pattern);

    if (target && *target) {
        if (strcmp(target, "*") == 0) {
            e->ua_only = 1;
        } else if (target[0] == '/') {
            e->path = apr_pstrdup(cmd->pool, target);
        } else if (strchr(target, '/') || strchr(target, ':')) {
            /* Contains a '/' (CIDR mask) or ':' (IPv6) — treat as
             * inline CIDR list. Validation deferred to post_config
             * where pconf's allocator is alive. */
            e->inline_cidrs = apr_pstrdup(cmd->pool, target);
        } else {
            return apr_psprintf(cmd->pool,
                "BotShieldAllowBot: arg 3 '%s' unrecognized — use "
                "'*' (UA-only), an absolute file path, or a CIDR "
                "(single or comma-separated)", target);
        }
    }

    apr_hash_set(scfg->allow_bots, e->name, APR_HASH_KEY_STRING, e);
    return NULL;
}

/* ======================================================================
 * E1 — Verified legit-crawler allow-list.
 *
 * "Real Googlebot" vs "someone claiming to be Googlebot" is the
 * question. UA strings are forgeable; IP ranges aren't. The design:
 *
 *   1. Match the UA against a classifier (trie) built from both
 *      module built-ins and operator-registered patterns. Returns a
 *      crawler name or NULL.
 *   2. If classified, look up the matching CIDR list for that name
 *      and test the client IP against it.
 *   3. Match → verified-<name>; apply a large negative penalty so
 *      tier dispatch collapses to pass.
 *   4. No match → fake-<name>; apply BS_PENALTY_FAKE_BOT so the
 *      request sails into captcha tier with a loud reason.
 *   5. Classified but no ranges loaded → "unverified" — log, don't
 *      score either way. Operator hasn't authorized verification
 *      for this crawler yet.
 *
 * The UA classifier is a vanilla trie (no Aho-Corasick failure
 * links — simpler to read, indistinguishable on realistic UAs).
 * Designed to scale to ~400 patterns (Cloudflare Radar's worked
 * list) without the linear-scan wall we'd hit otherwise.
 *
 * Pure read-only at request time; all state is populated in
 * post_config and immutable thereafter. The module never touches
 * the network for this feature — ranges come from disk files that
 * operators refresh out-of-band via tools/refresh-crawler-ranges.sh.
 * ====================================================================== */

#define BS_PENALTY_FAKE_BOT  100   /* enough to force captcha tier */
#define BS_CREDIT_ALLOW       (-1000) /* dominates any other penalty */


/* --- Request-time entry point ---
 *
 * Called from bs_run_builtin_heuristics. Reads the unified
 * classification cached on r->pool by bs_classify_request_hook
 * (post_read_request) — the UA classifier walk + IP cross-check
 * have already run there. This function is now just the score-
 * emission and metrics-bump policy applied to the cached answer.
 *
 * Emits at most one bs_score_add call per request (dominant
 * penalty/credit). */
void bs_check_allow(request_rec *r,
                                   const bs_dir_cfg *cfg)
{
    (void)cfg;
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    /* Activation gate: bot_classifier is only created when
     * verified_bots_enabled or any operator BotShieldAllowBot is
     * configured. No classifier = nothing to score. */
    if (!scfg || !scfg->bot_classifier) return;

    const bs_ua_class *c = bs_classify_request_ua(r);
    if (!c || !c->verified_name) return;
    const char *name = c->verified_name;

    /* UA-only mode: operator's `*` target. Different reason-string
     * than full verify so operators can distinguish in log analysis. */
    if (c->verified_ua_only) {
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->bot_allow_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, BS_CREDIT_ALLOW, 0,
            apr_pstrcat(r->pool, "allow-bot-ua:", name, NULL));
        return;
    }

    if (c->verified_unranged) {
        /* Pattern matched but no ranges loaded — operator hasn't
         * authorized IP verification for this bot (missing/malformed
         * file, or declared without a path+not-UA-only). Log but
         * don't score either way. */
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->bot_unverified_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, 0, 0,
            apr_pstrcat(r->pool, "bot-unverified:", name, NULL));
        return;
    }

    if (c->is_verified_bot) {
        /* Verified — large negative penalty dominates tier decision. */
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->bot_allow_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, BS_CREDIT_ALLOW, 0,
            apr_pstrcat(r->pool, "allow-bot:", name, NULL));
    } else if (c->is_fake_bot) {
        /* Fake: claims crawler UA but IP isn't in that crawler's
         * published ranges. Large penalty drives the request straight
         * to captcha tier; the reason string surfaces in the log. */
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->bot_fake_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, BS_PENALTY_FAKE_BOT, 3600,
            apr_pstrcat(r->pool, "fake-", name, NULL));
    }
}

/* Parse r->useragent_ip into a 16-byte network-order buffer. IPv4
 * becomes v6-mapped (::ffff:a.b.c.d) so the table is keyed uniformly.
 * Returns 1 on success, 0 if the string is unparseable. */
int bs_parse_client_ip(const char *ip_str, unsigned char out[16])
{
    if (!ip_str || !*ip_str) return 0;
    struct in_addr v4;
    if (inet_pton(AF_INET, ip_str, &v4) == 1) {
        memset(out, 0, 10);
        out[10] = 0xff; out[11] = 0xff;
        memcpy(out + 12, &v4, 4);
        return 1;
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip_str, &v6) == 1) {
        memcpy(out, &v6, 16);
        return 1;
    }
    return 0;
}

/* Apply an IPv6 prefix mask in-place so same-subnet v6 clients collapse
 * to one key in the flagged-IP table. This bounds the attacker's ability
 * to rotate through a /64 allocation to shed flags.
 *
 * IPv4 (carried as v6-mapped, ::ffff:a.b.c.d) is never masked: the v4
 * economy is per-/32, not per-/24.
 *
 * prefix_bits == 128 or prefix_bits <= 0 → no-op. */
void bs_mask_ipv6_prefix(unsigned char ip[16], int prefix_bits)
{
    static const unsigned char v4mapped[12] =
        { 0,0,0,0, 0,0,0,0, 0,0, 0xff,0xff };
    if (memcmp(ip, v4mapped, 12) == 0) return;       /* v4-in-v6: leave alone */
    if (prefix_bits <= 0 || prefix_bits >= 128) return;

    int full_bytes  = prefix_bits / 8;
    int extra_bits  = prefix_bits % 8;
    if (extra_bits) {
        unsigned char keep = (unsigned char)(0xff << (8 - extra_bits));
        ip[full_bytes] &= keep;
        full_bytes++;
    }
    for (int i = full_bytes; i < 16; i++) ip[i] = 0;
}

/* --- Live-reloadable bot-ranges machinery ------------------------- *
 *
 * Modeled on bot_directory.c / browser_classifier.c: a private
 * subpool per generation, atomic-swap of the active pointer, one-
 * tick destroy-grace for concurrent readers. Per-vhost rather than
 * module-global because bot-range configuration is server-scope —
 * different vhosts can have different operator overrides via
 * BotShieldAllowBot. */

bs_bot_ranges_state *bs_allow_ranges_build(
    const bs_bot_ranges_manifest *manifest)
{
    if (!manifest || !manifest->pool) return NULL;

    apr_pool_t *gen_pool = NULL;
    if (apr_pool_create(&gen_pool, manifest->pool) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, manifest->s,
            "mod_botshield: allow-ranges: subpool create failed; "
            "active state unchanged");
        return NULL;
    }

    bs_bot_ranges_state *st = apr_pcalloc(gen_pool, sizeof(*st));
    st->pool        = gen_pool;
    st->by_name     = apr_hash_make(gen_pool);
    st->file_mtimes = apr_hash_make(gen_pool);

    int loaded = 0, missing = 0, bad = 0;

    if (manifest->file_bots) {
        for (int i = 0; i < manifest->file_bots->nelts; i++) {
            const bs_bot_file_manifest_entry *e =
                &APR_ARRAY_IDX(manifest->file_bots, i,
                               bs_bot_file_manifest_entry);

            apr_array_header_t *arr = NULL;
            apr_time_t cm = 0, sm = 0;
            const char *err = NULL;
            apr_status_t rv = bs_allow_load_ranges_with_sidecar(
                gen_pool, e->canonical_path, e->sidecar_path,
                &arr, &cm, &sm, &err);

            /* Always record observed mtimes — the watchdog uses these
             * for change detection regardless of whether the load
             * succeeded. A missing canonical with mtime=0 plus a
             * future appearance becomes a 0→non-zero transition,
             * which correctly triggers a reload. */
            bs_bot_file_mtimes *mt = apr_pcalloc(gen_pool, sizeof(*mt));
            mt->canonical_mtime = cm;
            mt->sidecar_mtime   = sm;
            apr_hash_set(st->file_mtimes, e->name,
                         APR_HASH_KEY_STRING, mt);

            if (rv == APR_SUCCESS && arr) {
                apr_hash_set(st->by_name, e->name,
                             APR_HASH_KEY_STRING, arr);
                loaded++;
            } else if (APR_STATUS_IS_ENOENT(rv)) {
                missing++;
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, manifest->s,
                    "mod_botshield: bot '%s' ranges file '%s' not "
                    "loaded (%s) - UA will classify as unverified",
                    e->name, e->canonical_path,
                    err ? err : "missing");
            } else {
                bad++;
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, manifest->s,
                    "mod_botshield: bot '%s' ranges '%s' malformed "
                    "(%s) - skipping", e->name, e->canonical_path,
                    err ? err : "parse error");
            }
        }
    }

    if (manifest->inline_bots) {
        for (int i = 0; i < manifest->inline_bots->nelts; i++) {
            const bs_bot_inline_manifest_entry *e =
                &APR_ARRAY_IDX(manifest->inline_bots, i,
                               bs_bot_inline_manifest_entry);
            apr_array_header_t *arr = NULL;
            const char *err = NULL;
            apr_status_t rv = bs_allow_load_ranges_from_string(
                gen_pool, e->inline_cidrs, &arr, &err);
            if (rv == APR_SUCCESS) {
                apr_hash_set(st->by_name, e->name,
                             APR_HASH_KEY_STRING, arr);
                loaded++;
            } else {
                bad++;
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, manifest->s,
                    "mod_botshield: bot '%s' inline CIDRs malformed "
                    "(%s) - skipping", e->name,
                    err ? err : "parse error");
            }
        }
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, manifest->s,
        "mod_botshield: allow-ranges build: %d loaded, %d missing, "
        "%d malformed", loaded, missing, bad);
    return st;
}

void bs_allow_ranges_publish(server_rec *s,
                             bs_bot_ranges_state *new_state)
{
    bs_server_cfg *scfg =
        ap_get_module_config(s->module_config, &botshield_module);
    if (!scfg || !scfg->bot_ranges_manifest) return;

    bs_bot_ranges_manifest *m = scfg->bot_ranges_manifest;

    /* Two-step destroy: the slot holds the state we parked at the
     * previous publish — by now any reader that loaded that pointer
     * has long since finished its hash lookup. Drop it before
     * parking a new one. */
    bs_bot_ranges_state *to_destroy = m->pending_drain;
    m->pending_drain = NULL;

    bs_bot_ranges_state *prior = __atomic_exchange_n(
        &scfg->bot_ranges, new_state, __ATOMIC_ACQ_REL);

    m->pending_drain = prior;

    if (to_destroy) {
        apr_pool_destroy(to_destroy->pool);
    }
}

apr_status_t bs_allow_ranges_watchdog_cb(int state, void *data,
                                         apr_pool_t *pool)
{
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;

    server_rec *s = data;
    if (!s) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(s->module_config, &botshield_module);
    if (!scfg || !scfg->bot_ranges_manifest) return APR_SUCCESS;

    bs_bot_ranges_manifest *m = scfg->bot_ranges_manifest;
    bs_bot_ranges_state *active =
        __atomic_load_n(&scfg->bot_ranges, __ATOMIC_ACQUIRE);

    /* Inline bots can't change at runtime (string came from the
     * directive); only file-backed bots need stat()ing. Walk the
     * manifest and compare against last observed mtimes. */
    int changed = 0;
    if (m->file_bots) {
        for (int i = 0; i < m->file_bots->nelts && !changed; i++) {
            const bs_bot_file_manifest_entry *e =
                &APR_ARRAY_IDX(m->file_bots, i,
                               bs_bot_file_manifest_entry);

            apr_finfo_t fi;
            apr_time_t cm = 0, sm = 0;
            if (apr_stat(&fi, e->canonical_path,
                         APR_FINFO_MTIME, pool) == APR_SUCCESS) {
                cm = fi.mtime;
            }
            if (e->sidecar_path
                && apr_stat(&fi, e->sidecar_path,
                            APR_FINFO_MTIME, pool) == APR_SUCCESS) {
                sm = fi.mtime;
            }

            const bs_bot_file_mtimes *prev = (active && active->file_mtimes)
                ? apr_hash_get(active->file_mtimes, e->name,
                               APR_HASH_KEY_STRING)
                : NULL;
            if (!prev
                || prev->canonical_mtime != cm
                || prev->sidecar_mtime   != sm) {
                changed = 1;
            }
        }
    }
    if (!changed) return APR_SUCCESS;

    bs_bot_ranges_state *fresh = bs_allow_ranges_build(m);
    if (!fresh) return APR_SUCCESS;
    bs_allow_ranges_publish(s, fresh);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: allow-ranges reloaded "
        "(file change detected, %d bots active)",
        (int)apr_hash_count(fresh->by_name));
    return APR_SUCCESS;
}

/* BotShieldAllowRangesRefreshInterval <seconds> — watchdog tick
 * cadence for the verified-bot CIDR files. 0 disables (post_config
 * load remains in effect; reload via graceful restart). 86400 max
 * is just a sanity ceiling — the live-refresh story is meant for
 * "operator added an IP, want it live in <minute>", not
 * once-a-day. */
const char *bs_set_allow_ranges_refresh_interval(cmd_parms *cmd,
                                                 void *dconf,
                                                 const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end || v < 0 || v > 86400) {
        return apr_psprintf(cmd->pool,
            "BotShieldAllowRangesRefreshInterval: '%s' must be an "
            "integer 0..86400 seconds (0 = disable live refresh)",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(
        cmd->server->module_config, &botshield_module);
    scfg->allow_ranges_refresh_interval = (int)v;
    return NULL;
}
