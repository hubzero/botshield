/* classify-uas.c — standalone UA classifier mirroring mod_botshield's
 * unified per-request classification (see src/ua_class.c).
 *
 * Run a stream of (IP, UA) pairs through the same browser-first
 * pipeline the live module uses and report what each request would
 * be labeled. Useful for:
 *
 *   - Sanity-checking the directory + browser-templates + verified-
 *     bot machinery against a real traffic sample (access log,
 *     botshield decision log).
 *   - Spotting UAs that fall through to "unknown" — candidates for
 *     directory updates or operator BotShieldAllowBot declarations.
 *   - Comparing classifier output before/after a vendor data
 *     refresh.
 *
 * Self-contained: links nothing from the module, parses the same
 * data/runtime data the module reads at startup. The
 * classification logic mirrors src/ua_class.c (browser-first
 * short-circuit; bot directory + verified-bot only on miss).
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o /tmp/classify-uas tools/classify-uas.c \
 *       -I/usr/include/json-c -ljson-c
 *
 * Run (auto-detects access / decision / tsv from first line):
 *   /tmp/classify-uas /var/log/httpd/help-decisions.log
 *   sudo cat /var/log/httpd/access_log | /tmp/classify-uas
 *
 * Options:
 *   --bot-directory PATH    pipe-delimited TSV (refresh-bot-directory.py
 *                           output). Default: /var/lib/botshield/bot-directory.tsv,
 *                           falls back to data/bot-directory.json.
 *   --browser-templates PATH JSON array of UA strings.
 *                           Default: data/top-user-agents.json.
 *   --bots-dir PATH         Directory holding <name>.txt + <name>.local.txt
 *                           for verified-bot CIDR ranges.
 *                           Default: /var/lib/botshield/bots.
 *   --format FORMAT         auto | access | decision | tsv | ua
 *                           access  — Apache combined: IP at front, UA quoted at end
 *                           decision — botshield: ts ip ... ua="..."
 *                           tsv     — IP\tUA per line
 *                           ua      — UA per line (verified-bot skipped, no IP)
 *   --summary               Skip per-line output; just print the count summary.
 *   --no-summary            Skip the trailing summary table.
 *   -v / --verbose          Include known-slug, verified-name, IP per line.
 *   -h / --help             This message.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <json-c/json.h>

/* ============================================================== */
/* Static config defaults                                           */
/* ============================================================== */

static const char *DEFAULT_BOT_TSV          = "/var/lib/botshield/bot-directory.tsv";
static const char *DEFAULT_BOT_JSON         = "data/bot-directory.json";
static const char *DEFAULT_BOT_BUILTIN_JSON = "data/bot-directory.builtin.json";
static const char *DEFAULT_BOT_LOCAL_JSON   = "data/bot-directory.local.json";
static const char *DEFAULT_BROWSER_RUNTIME  = "/var/lib/botshield/browser-templates.txt";
static const char *DEFAULT_BROWSER_JSON     = "data/top-user-agents.json";
static const char *DEFAULT_BROWSER_BUILTIN_JSON = "data/top-user-agents.builtin.json";
static const char *DEFAULT_BROWSER_LOCAL_JSON   = "data/top-user-agents.local.json";
static const char *DEFAULT_BOTS_DIR         = "/var/lib/botshield/bots";

/* Mirrors src/allowlist.c bs_builtin_bots[]. Operator overrides
 * (BotShieldAllowBot) aren't read here — diagnostic scope. */
static const struct {
    const char *name;
    const char *pattern;
} VERIFIED_BOTS[] = {
    { "googlebot",   "Googlebot"       },
    { "bingbot",     "bingbot"         },
    { "applebot",    "Applebot"        },
    { "googleother", "GoogleOther"     },
    { "siteimprove", "Siteimprove.com" },
    { NULL, NULL }
};

/* ============================================================== */
/* Bot directory                                                    */
/* ============================================================== */

typedef struct {
    char *pattern;     /* lowercased UA substring */
    char *slug;
    char *category;
} bot_pat;

static bot_pat *g_bots      = NULL;
static int      g_bots_n    = 0;
static int      g_bots_cap  = 0;

static void bot_add(const char *pattern, const char *slug, const char *category)
{
    if (g_bots_n == g_bots_cap) {
        g_bots_cap = g_bots_cap ? g_bots_cap * 2 : 64;
        g_bots = realloc(g_bots, (size_t)g_bots_cap * sizeof(*g_bots));
    }
    char *p = strdup(pattern);
    for (char *q = p; *q; q++) *q = (char)tolower((unsigned char)*q);
    g_bots[g_bots_n].pattern  = p;
    g_bots[g_bots_n].slug     = strdup(slug ? slug : "");
    g_bots[g_bots_n].category = strdup(category ? category : "");
    g_bots_n++;
}

static int load_bot_directory_tsv(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[4096];
    int ok = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r' ||
                         line[l-1] == ' '  || line[l-1] == '\t')) {
            line[--l] = '\0';
        }
        if (!*line || *line == '#') continue;
        /* pattern|slug|category|followsRobotsTxt */
        char *p = line;
        char *bar1 = strchr(p, '|');         if (!bar1) continue;
        *bar1 = '\0';
        char *slug = bar1 + 1;
        char *bar2 = strchr(slug, '|');      if (!bar2) continue;
        *bar2 = '\0';
        char *cat  = bar2 + 1;
        char *bar3 = strchr(cat, '|');       if (bar3) *bar3 = '\0';
        bot_add(p, slug, cat);
        ok = 1;
    }
    fclose(f);
    return ok ? 0 : -1;
}

static int load_bot_directory_json(const char *path)
{
    json_object *arr = json_object_from_file(path);
    if (!arr || !json_object_is_type(arr, json_type_array)) {
        if (arr) json_object_put(arr);
        return -1;
    }
    int n = (int)json_object_array_length(arr);
    for (int i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(arr, i);
        json_object *slug = NULL, *cat = NULL, *pats = NULL;
        json_object_object_get_ex(e, "slug", &slug);
        json_object_object_get_ex(e, "category", &cat);
        json_object_object_get_ex(e, "userAgentPatterns", &pats);
        if (!slug || !pats || !json_object_is_type(pats, json_type_array))
            continue;
        const char *slug_s = json_object_get_string(slug);
        const char *cat_s  = cat ? json_object_get_string(cat) : "";
        int np = (int)json_object_array_length(pats);
        for (int j = 0; j < np; j++) {
            json_object *p = json_object_array_get_idx(pats, j);
            const char *p_s = json_object_get_string(p);
            if (p_s && *p_s) bot_add(p_s, slug_s, cat_s);
        }
    }
    json_object_put(arr);
    return g_bots_n > 0 ? 0 : -1;
}

/* Returns slug + category if any pattern matches anywhere in `ua`
 * (case-insensitive). NULL slug means no match. */
static void bot_lookup(const char *ua_lower, const char **out_slug,
                       const char **out_cat)
{
    *out_slug = *out_cat = NULL;
    for (int i = 0; i < g_bots_n; i++) {
        if (strstr(ua_lower, g_bots[i].pattern)) {
            *out_slug = g_bots[i].slug;
            *out_cat  = g_bots[i].category;
            return;
        }
    }
}

/* ============================================================== */
/* Browser templates                                                */
/* ============================================================== */

static char **g_browser_norm = NULL;   /* normalized templates */
static int    g_browser_n    = 0;
static int    g_browser_cap  = 0;

/* Mirror of bs_browser_normalize: collapse runs of [0-9._]+ to a
 * single 'X'. Output written into `out` (caller-sized). */
static void browser_normalize(const char *ua, char *out, size_t out_cap)
{
    if (!out_cap) return;
    size_t w = 0;
    int in_version = 0;
    for (const char *p = ua; *p && w + 1 < out_cap; p++) {
        unsigned char c = (unsigned char)*p;
        int is_v = (c >= '0' && c <= '9') || c == '.' || c == '_';
        if (is_v) {
            if (!in_version) { out[w++] = 'X'; in_version = 1; }
        } else {
            out[w++] = (char)c;
            in_version = 0;
        }
    }
    out[w] = '\0';
}

static void browser_template_push_normalized(const char *s)
{
    char buf[2048];
    browser_normalize(s, buf, sizeof(buf));
    if (g_browser_n == g_browser_cap) {
        g_browser_cap = g_browser_cap ? g_browser_cap * 2 : 32;
        g_browser_norm = realloc(g_browser_norm,
            (size_t)g_browser_cap * sizeof(char *));
    }
    g_browser_norm[g_browser_n++] = strdup(buf);
}

static int load_browser_templates_json(const char *path)
{
    json_object *arr = json_object_from_file(path);
    if (!arr || !json_object_is_type(arr, json_type_array)) {
        if (arr) json_object_put(arr);
        return -1;
    }
    int n = (int)json_object_array_length(arr);
    int added = 0;
    for (int i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(arr, i);
        const char *s = json_object_get_string(e);
        if (!s || !*s) continue;
        browser_template_push_normalized(s);
        added++;
    }
    json_object_put(arr);
    return added > 0 ? 0 : -1;
}

/* Load the runtime-flat-text browser templates file emitted by
 * tools/refresh-top-user-agents.py. One pre-normalized template per
 * line, '#' comments. Already-merged with the local overlay, so
 * preferring this file over the JSON pair is the most faithful
 * mirror of what the live module reads. */
static int load_browser_templates_runtime(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[2048];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r' ||
                         line[l-1] == ' '  || line[l-1] == '\t')) {
            line[--l] = '\0';
        }
        if (!*line || line[0] == '#') continue;
        /* Already normalized — push verbatim. */
        if (g_browser_n == g_browser_cap) {
            g_browser_cap = g_browser_cap ? g_browser_cap * 2 : 32;
            g_browser_norm = realloc(g_browser_norm,
                (size_t)g_browser_cap * sizeof(char *));
        }
        g_browser_norm[g_browser_n++] = strdup(line);
        added++;
    }
    fclose(f);
    return added > 0 ? 0 : -1;
}

static int browser_match(const char *ua)
{
    char buf[2048];
    browser_normalize(ua, buf, sizeof(buf));
    for (int i = 0; i < g_browser_n; i++) {
        if (strcmp(buf, g_browser_norm[i]) == 0) return 1;
    }
    return 0;
}

/* ============================================================== */
/* Verified-bot ranges                                              */
/* ============================================================== */

typedef struct {
    /* Stored as parsed network address + prefix-bit count. v4
     * addresses are kept as v4-mapped v6 so one comparator handles
     * both families. */
    uint8_t  addr[16];
    uint8_t  prefix;     /* 0..128, in v6 bits */
    uint8_t  is_v4;      /* original family, for diagnostics only */
} cidr_t;

typedef struct {
    cidr_t *items;
    int     count;
    int     cap;
} cidr_set;

static cidr_set g_ranges[8];   /* parallel to VERIFIED_BOTS[] */

static void cidr_v4_to_v6_mapped(const struct in_addr *in, uint8_t out[16])
{
    memset(out, 0, 10);
    out[10] = 0xff; out[11] = 0xff;
    memcpy(out + 12, in, 4);
}

/* Parse "1.2.3.0/24" or "2001:db8::/32" (or bare host without /N).
 * Returns 0 on success. */
static int cidr_parse(const char *raw, cidr_t *out)
{
    char buf[64];
    size_t l = strlen(raw);
    if (l >= sizeof(buf)) return -1;
    memcpy(buf, raw, l + 1);

    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }

    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, buf, &v4) == 1) {
        cidr_v4_to_v6_mapped(&v4, out->addr);
        out->is_v4  = 1;
        out->prefix = (uint8_t)(prefix < 0 ? 128 : 96 + prefix);
        return 0;
    }
    if (inet_pton(AF_INET6, buf, &v6) == 1) {
        memcpy(out->addr, &v6, 16);
        out->is_v4  = 0;
        out->prefix = (uint8_t)(prefix < 0 ? 128 : prefix);
        return 0;
    }
    return -1;
}

static void cidr_set_push(cidr_set *s, cidr_t c)
{
    if (s->count == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 16;
        s->items = realloc(s->items, (size_t)s->cap * sizeof(cidr_t));
    }
    s->items[s->count++] = c;
}

static int load_ranges_file(const char *path, cidr_set *out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r' ||
                         line[l-1] == ' '  || line[l-1] == '\t')) {
            line[--l] = '\0';
        }
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (!*s || *s == '#') continue;
        cidr_t c;
        if (cidr_parse(s, &c) == 0) cidr_set_push(out, c);
    }
    fclose(f);
    return 0;
}

static int parse_client_ip(const char *ip, uint8_t out[16])
{
    if (!ip || !*ip) return 0;
    struct in_addr v4;
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        cidr_v4_to_v6_mapped(&v4, out);
        return 1;
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        memcpy(out, &v6, 16);
        return 1;
    }
    return 0;
}

static int cidr_contains(const cidr_t *c, const uint8_t ip[16])
{
    int full = c->prefix / 8;
    int rem  = c->prefix % 8;
    if (memcmp(c->addr, ip, (size_t)full) != 0) return 0;
    if (rem == 0) return 1;
    uint8_t mask = (uint8_t)(0xff << (8 - rem));
    return (c->addr[full] & mask) == (ip[full] & mask);
}

static int cidr_set_contains(const cidr_set *s, const uint8_t ip[16])
{
    for (int i = 0; i < s->count; i++) {
        if (cidr_contains(&s->items[i], ip)) return 1;
    }
    return 0;
}

/* ============================================================== */
/* Classifier (mirror of src/ua_class.c)                            */
/* ============================================================== */

typedef enum {
    CLS_UNKNOWN = 0,
    CLS_BROWSER,
    CLS_UNKNOWN_BOT,            /* heuristic substring match (bot/crawl/spider/curl/...) */
    CLS_KNOWN_BOT,
    CLS_FAKE_BOT,
    CLS_VERIFIED_BOT,
    CLS_VERIFIED_UNRANGED,    /* operator hasn't loaded ranges yet */
} class_t;

typedef struct {
    class_t     cls;
    const char *known_slug;
    const char *known_category;
    const char *verified_name;     /* non-NULL iff a built-in pattern matched */
    const char *unknown_bot_token; /* matched substring when cls=CLS_UNKNOWN_BOT */
} result_t;

static const char *cls_str(class_t c)
{
    switch (c) {
    case CLS_BROWSER:           return "browser";
    case CLS_UNKNOWN_BOT:       return "unknown-bot";
    case CLS_KNOWN_BOT:         return "known-bot";
    case CLS_FAKE_BOT:          return "fake-bot";
    case CLS_VERIFIED_BOT:      return "verified-bot";
    case CLS_VERIFIED_UNRANGED: return "verified-unranged";
    default:                    return "unknown";
    }
}

/* Mirrors src/ua_class.c bs_unknown_bot_tokens — keep in sync. */
static const char *const UNKNOWN_BOT_TOKENS[] = {
    "bot", "crawl", "spider", "spyder",
    "fetch", "slurp", "scrap", "curl", "wget",
    "http",   /* RFC 9309-style +http(s):// self-ID URLs */
    NULL
};

static int verified_match(const char *ua, int *out_idx)
{
    for (int i = 0; VERIFIED_BOTS[i].name; i++) {
        if (strcasestr(ua, VERIFIED_BOTS[i].pattern)) {
            *out_idx = i;
            return 1;
        }
    }
    return 0;
}

static void classify(const char *ip, const char *ua, result_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!ua || !*ua) { out->cls = CLS_UNKNOWN; return; }

    /* Browser-first short-circuit (matches src/ua_class.c). */
    if (browser_match(ua)) {
        out->cls = CLS_BROWSER;
        return;
    }

    /* Bot directory pass. Lowercase the UA once for substring checks. */
    char ua_lower[2048];
    size_t l = strlen(ua);
    if (l >= sizeof(ua_lower)) l = sizeof(ua_lower) - 1;
    for (size_t i = 0; i < l; i++) {
        ua_lower[i] = (char)tolower((unsigned char)ua[i]);
    }
    ua_lower[l] = '\0';
    bot_lookup(ua_lower, &out->known_slug, &out->known_category);

    /* Verified-bot UA pattern + IP cross-check. */
    int vidx = -1;
    if (verified_match(ua, &vidx)) {
        out->verified_name = VERIFIED_BOTS[vidx].name;
        if (g_ranges[vidx].count == 0) {
            out->cls = CLS_VERIFIED_UNRANGED;
            return;
        }
        uint8_t ip_bytes[16];
        if (ip && parse_client_ip(ip, ip_bytes)
            && cidr_set_contains(&g_ranges[vidx], ip_bytes)) {
            out->cls = CLS_VERIFIED_BOT;
        } else {
            /* No IP, or IP not in the published ranges. */
            out->cls = CLS_FAKE_BOT;
        }
        return;
    }

    if (out->known_slug) {
        out->cls = CLS_KNOWN_BOT;
        return;
    }

    /* Last-resort heuristic — bot-y substring match. */
    for (const char *const *t = UNKNOWN_BOT_TOKENS; *t; t++) {
        if (strcasestr(ua, *t)) {
            out->cls               = CLS_UNKNOWN_BOT;
            out->unknown_bot_token = *t;
            return;
        }
    }

    out->cls = CLS_UNKNOWN;
}

/* ============================================================== */
/* Input parsing                                                    */
/* ============================================================== */

typedef enum { FMT_AUTO, FMT_ACCESS, FMT_DECISION, FMT_TSV, FMT_UA } fmt_t;

/* Extract a quoted token starting at `*p` (which points just after
 * the opening quote). Writes a NUL-terminated copy into out[out_cap]
 * and advances *p past the closing quote. Returns 0 on success. */
static int read_quoted(const char **p, char *out, size_t out_cap)
{
    size_t w = 0;
    while (**p && **p != '"' && w + 1 < out_cap) {
        out[w++] = *(*p)++;
    }
    if (**p != '"') return -1;
    out[w] = '\0';
    (*p)++;
    return 0;
}

/* Apache combined: IP - - [date] "REQ" status size "ref" "UA" ...
 * Some deployments prepend timestamp; handle that by hunting for
 * the IP — first whitespace-delimited token that parses as an
 * IP address. UA is the last quoted field on the line. */
static int parse_access_log(const char *line, char *ip_out, size_t ip_cap,
                            char *ua_out, size_t ua_cap)
{
    /* Find an IP token. Try every whitespace-delimited word. */
    const char *p = line;
    int got_ip = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        size_t l = (size_t)(p - start);
        if (l >= 7 && l < 64) {
            char buf[64];
            memcpy(buf, start, l);
            buf[l] = '\0';
            uint8_t scratch[16];
            if (parse_client_ip(buf, scratch)) {
                strncpy(ip_out, buf, ip_cap - 1);
                ip_out[ip_cap - 1] = '\0';
                got_ip = 1;
                break;
            }
        }
    }
    if (!got_ip) return -1;

    /* Find the LAST quoted field on the line — that's the UA in
     * combined and most variants. */
    const char *last_open = NULL;
    for (const char *q = line; *q; q++) {
        if (*q == '"') {
            /* matched pairs: opening if preceded by space/start, closing otherwise */
            if (q == line || q[-1] == ' ' || q[-1] == '\t') {
                last_open = q;
            }
        }
    }
    /* Walk back: actually the UA is typically the second-to-last
     * quoted field in combined format — Referer is last for some
     * shapes, UA last for others. Try the last two pairs and pick
     * the one that doesn't look like a URL. */
    const char *opens[8] = {0};
    int n_opens = 0;
    int prev_was_close = 1;   /* start of line counts as "outside" */
    for (const char *q = line; *q; q++) {
        if (*q == '"') {
            if (prev_was_close && n_opens < 8) opens[n_opens++] = q;
            prev_was_close = !prev_was_close;
        }
    }
    if (n_opens == 0) return -1;
    static const char *const HTTP_METHODS[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
        "PATCH ", "OPTIONS ", "CONNECT ", "TRACE ",
        /* WebDAV methods — RFC 4918. Probes / vuln scanners
         * frequently send PROPFIND against root with empty UA. */
        "PROPFIND ", "PROPPATCH ", "MKCOL ", "COPY ",
        "MOVE ", "LOCK ", "UNLOCK ", "REPORT ", "SEARCH ",
        NULL
    };
    for (int i = n_opens - 1; i >= 0; i--) {
        const char *p2 = opens[i] + 1;
        char tmp[2048];
        if (read_quoted(&p2, tmp, sizeof(tmp)) != 0) continue;
        /* Skip empty / referer-shaped tokens. UA is rarely "-" or a URL. */
        if (!*tmp || strcmp(tmp, "-") == 0) continue;
        if (strncmp(tmp, "http://", 7) == 0
            || strncmp(tmp, "https://", 8) == 0) continue;
        /* Skip request-line fields. When the access log has UA="-" and
         * Referer="-", the LAST quoted field reachable from this loop
         * ends up being "GET /path HTTP/1.1" — which has no other
         * meaningful filter than its leading HTTP method. Without this
         * the request line gets misclassified as a fake UA en masse
         * (~26k hits on the help-access sample). */
        int looks_like_request = 0;
        for (const char *const *m = HTTP_METHODS; *m; m++) {
            size_t mlen = strlen(*m);
            if (strncmp(tmp, *m, mlen) == 0) { looks_like_request = 1; break; }
        }
        if (looks_like_request) continue;
        strncpy(ua_out, tmp, ua_cap - 1);
        ua_out[ua_cap - 1] = '\0';
        (void)last_open;
        return 0;
    }
    return -1;
}

/* botshield decision log: `<ts> <ip> <status> ... ua="..." path="..."` */
static int parse_decision_log(const char *line, char *ip_out, size_t ip_cap,
                              char *ua_out, size_t ua_cap)
{
    /* IP is the second whitespace-delimited token. */
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    while (*p && *p != ' ' && *p != '\t') p++;            /* skip ts */
    while (*p == ' ' || *p == '\t') p++;
    const char *ip_start = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    size_t ip_len = (size_t)(p - ip_start);
    if (ip_len == 0 || ip_len >= ip_cap) return -1;
    memcpy(ip_out, ip_start, ip_len);
    ip_out[ip_len] = '\0';

    const char *m = strstr(p, "ua=\"");
    if (!m) return -1;
    m += 4;
    const char *p2 = m;
    if (read_quoted(&p2, ua_out, ua_cap) != 0) return -1;
    return 0;
}

/* TSV: `IP\tUA` */
static int parse_tsv(const char *line, char *ip_out, size_t ip_cap,
                     char *ua_out, size_t ua_cap)
{
    const char *tab = strchr(line, '\t');
    if (!tab) return -1;
    size_t ip_len = (size_t)(tab - line);
    if (ip_len == 0 || ip_len >= ip_cap) return -1;
    memcpy(ip_out, line, ip_len);
    ip_out[ip_len] = '\0';
    strncpy(ua_out, tab + 1, ua_cap - 1);
    ua_out[ua_cap - 1] = '\0';
    return 0;
}

static fmt_t detect_format(const char *line)
{
    /* botshield: starts with ISO8601 timestamp, then space, then IP.
     * Match `YYYY-MM-DDT...Z `. */
    if (strlen(line) > 20 && line[4] == '-' && line[7] == '-'
        && line[10] == 'T' && (line[19] == 'Z' || line[19] == '.')) {
        return FMT_DECISION;
    }
    /* TSV: contains a tab. */
    if (strchr(line, '\t')) return FMT_TSV;
    /* Quoted UA → access log. */
    if (strchr(line, '"')) return FMT_ACCESS;
    return FMT_UA;
}

/* ============================================================== */
/* Main                                                              */
/* ============================================================== */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] [file]\n"
        "  --bot-directory PATH    pipe-delimited TSV (default %s,\n"
        "                          falls back to %s)\n"
        "  --browser-templates PATH JSON array (default %s)\n"
        "  --bots-dir PATH         dir with <name>.txt + sidecars\n"
        "                          (default %s)\n"
        "  --format FMT            auto|access|decision|tsv|ua\n"
        "  --summary               only print the count summary\n"
        "  --no-summary            skip the trailing summary table\n"
        "  -v / --verbose          include slug + verified-name + IP\n"
        "  -h / --help             this message\n",
        prog, DEFAULT_BOT_TSV, DEFAULT_BOT_JSON,
        DEFAULT_BROWSER_JSON, DEFAULT_BOTS_DIR);
}

int main(int argc, char **argv)
{
    const char *bot_path     = NULL;
    const char *browser_path = DEFAULT_BROWSER_JSON;
    const char *bots_dir     = DEFAULT_BOTS_DIR;
    const char *input_path   = NULL;
    fmt_t format = FMT_AUTO;
    int summary_only = 0;
    int no_summary   = 0;
    int verbose      = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--bot-directory")     && i+1 < argc) { bot_path     = argv[++i]; continue; }
        if (!strcmp(a, "--browser-templates") && i+1 < argc) { browser_path = argv[++i]; continue; }
        if (!strcmp(a, "--bots-dir")          && i+1 < argc) { bots_dir     = argv[++i]; continue; }
        if (!strcmp(a, "--format")            && i+1 < argc) {
            const char *f = argv[++i];
            if      (!strcmp(f, "auto"))     format = FMT_AUTO;
            else if (!strcmp(f, "access"))   format = FMT_ACCESS;
            else if (!strcmp(f, "decision")) format = FMT_DECISION;
            else if (!strcmp(f, "tsv"))      format = FMT_TSV;
            else if (!strcmp(f, "ua"))       format = FMT_UA;
            else { fprintf(stderr, "unknown format: %s\n", f); return 2; }
            continue;
        }
        if (!strcmp(a, "--summary"))    { summary_only = 1; continue; }
        if (!strcmp(a, "--no-summary")) { no_summary   = 1; continue; }
        if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) { verbose = 1; continue; }
        if (!strcmp(a, "-h") || !strcmp(a, "--help"))    { usage(argv[0]); return 0; }
        if (a[0] == '-')                   { fprintf(stderr, "unknown option: %s\n", a); return 2; }
        if (!input_path) { input_path = a; continue; }
        fprintf(stderr, "extra positional argument: %s\n", a);
        return 2;
    }

    /* Bot directory: prefer TSV (already-merged with builtin +
     * local overlays by tools/refresh-bot-directory.py — matches
     * what the live module reads at runtime). Fall back to vendor
     * JSON + the .builtin and .local overlays so the JSON path
     * also reflects the same augmentations. */
    if (bot_path) {
        if (load_bot_directory_tsv(bot_path) != 0
            && load_bot_directory_json(bot_path) != 0) {
            fprintf(stderr, "failed to load bot directory: %s\n", bot_path);
            return 1;
        }
    } else {
        struct stat st;
        if (stat(DEFAULT_BOT_TSV, &st) == 0
            && load_bot_directory_tsv(DEFAULT_BOT_TSV) == 0) {
            /* loaded merged TSV — overlays already baked in */
        } else if (load_bot_directory_json(DEFAULT_BOT_JSON) == 0) {
            /* upstream JSON loaded; layer the .builtin then .local
             * overlays on top in the same order the build / refresh
             * scripts use, so the diagnostic matches the live
             * module's view. */
            (void)load_bot_directory_json(DEFAULT_BOT_BUILTIN_JSON);
            (void)load_bot_directory_json(DEFAULT_BOT_LOCAL_JSON);
        } else {
            fprintf(stderr,
                "failed to load bot directory; tried %s and %s\n",
                DEFAULT_BOT_TSV, DEFAULT_BOT_JSON);
            return 1;
        }
    }

    /* Browser templates: prefer the runtime flat-text file
     * (already-merged with builtin + local overlays by
     * tools/refresh-top-user-agents.py and pre-normalized). Fall
     * back to vendor JSON + .builtin + .local overlays. */
    if (browser_path != DEFAULT_BROWSER_JSON) {
        /* operator passed an explicit path — use it directly */
        if (load_browser_templates_json(browser_path) != 0) {
            fprintf(stderr, "failed to load browser templates: %s\n",
                    browser_path);
            return 1;
        }
    } else {
        struct stat st;
        if (stat(DEFAULT_BROWSER_RUNTIME, &st) == 0
            && load_browser_templates_runtime(DEFAULT_BROWSER_RUNTIME) == 0) {
            /* loaded merged runtime templates */
        } else if (load_browser_templates_json(DEFAULT_BROWSER_JSON) == 0) {
            (void)load_browser_templates_json(DEFAULT_BROWSER_BUILTIN_JSON);
            (void)load_browser_templates_json(DEFAULT_BROWSER_LOCAL_JSON);
        } else {
            fprintf(stderr,
                "failed to load browser templates; tried %s and %s\n",
                DEFAULT_BROWSER_RUNTIME, DEFAULT_BROWSER_JSON);
            return 1;
        }
    }

    /* Verified-bot ranges. Missing files are fine — that bot just
     * won't have an IP cross-check (UA-match → verified-unranged). */
    for (int i = 0; VERIFIED_BOTS[i].name; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s.txt",
                 bots_dir, VERIFIED_BOTS[i].name);
        load_ranges_file(path, &g_ranges[i]);
        snprintf(path, sizeof(path), "%s/%s.local.txt",
                 bots_dir, VERIFIED_BOTS[i].name);
        load_ranges_file(path, &g_ranges[i]);    /* sidecar adds on top */
    }

    fprintf(stderr,
        "loaded: %d bot patterns, %d browser templates, ",
        g_bots_n, g_browser_n);
    int ranges_total = 0;
    for (int i = 0; VERIFIED_BOTS[i].name; i++) {
        ranges_total += g_ranges[i].count;
    }
    fprintf(stderr, "%d verified-bot CIDRs (across %d bots)\n",
            ranges_total, (int)(sizeof(VERIFIED_BOTS) / sizeof(VERIFIED_BOTS[0]) - 1));

    FILE *in = stdin;
    if (input_path && strcmp(input_path, "-") != 0) {
        in = fopen(input_path, "r");
        if (!in) {
            fprintf(stderr, "cannot open %s: %s\n",
                    input_path, strerror(errno));
            return 1;
        }
    }

    long counts[8] = {0};
    long total = 0;

    char line[8192];
    while (fgets(line, sizeof(line), in)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) {
            line[--l] = '\0';
        }
        if (!*line) continue;

        if (format == FMT_AUTO) format = detect_format(line);

        char ip[64]  = {0};
        char ua[2048] = {0};
        int rv = -1;
        switch (format) {
        case FMT_ACCESS:   rv = parse_access_log(line, ip, sizeof(ip), ua, sizeof(ua)); break;
        case FMT_DECISION: rv = parse_decision_log(line, ip, sizeof(ip), ua, sizeof(ua)); break;
        case FMT_TSV:      rv = parse_tsv(line, ip, sizeof(ip), ua, sizeof(ua)); break;
        case FMT_UA:
            strncpy(ua, line, sizeof(ua) - 1);
            ua[sizeof(ua) - 1] = '\0';
            rv = 0;
            break;
        default: break;
        }
        if (rv != 0 || !*ua) continue;

        result_t r;
        classify(ip[0] ? ip : NULL, ua, &r);
        counts[r.cls]++;
        total++;

        if (!summary_only) {
            if (verbose) {
                /* slug field: known_slug normally, or the matched
                 * heuristic token when cls=unknown-bot — gives
                 * operators the "why" for an unknown-bot tag. */
                const char *slug_or_token = r.known_slug
                    ? r.known_slug
                    : (r.unknown_bot_token ? r.unknown_bot_token : "-");
                printf("%-18s\t%-15s\t%s\t%s\t%s\n",
                    cls_str(r.cls),
                    ip[0] ? ip : "-",
                    slug_or_token,
                    r.verified_name ? r.verified_name : "-",
                    ua);
            } else {
                printf("%-18s\t%s\n", cls_str(r.cls), ua);
            }
        }
    }
    if (in != stdin) fclose(in);

    if (!no_summary) {
        fprintf(stderr, "\n=== summary (%ld lines classified) ===\n", total);
        const class_t order[] = {
            CLS_BROWSER, CLS_VERIFIED_BOT, CLS_FAKE_BOT,
            CLS_VERIFIED_UNRANGED, CLS_KNOWN_BOT,
            CLS_UNKNOWN_BOT, CLS_UNKNOWN
        };
        for (size_t i = 0; i < sizeof(order)/sizeof(order[0]); i++) {
            class_t c = order[i];
            double pct = total ? (100.0 * (double)counts[c] / (double)total) : 0;
            fprintf(stderr, "  %-18s %8ld  (%5.1f%%)\n",
                    cls_str(c), counts[c], pct);
        }
    }
    return 0;
}
