/* bench-bot-directory.c — head-to-head benchmark of three
 * approaches to the knownbot UA classifier:
 *
 *   1. SEQUENTIAL:   the production approach. strcasestr loop over
 *                    all ~557 patterns. First match wins; no match
 *                    walks the full table.
 *
 *   2. FIRST-BYTE:   bucket patterns by their (lowercased) first
 *                    byte. At lookup time, walk the UA byte-by-byte
 *                    and only test patterns whose first byte
 *                    appears in the UA. Cheap data structure (256
 *                    bucket heads) but skips most of the table when
 *                    the UA doesn't contain certain leading chars.
 *
 *   3. AHO-CORASICK: build a finite-state automaton from all
 *                    patterns at startup. Single linear pass over
 *                    the UA finds any match. Constant per-call cost
 *                    regardless of pattern count, at the cost of
 *                    larger startup time and memory footprint.
 *
 * All three load the same patterns from a TSV file (operator path
 * or BOTSHIELD_BOT_DIRECTORY_TSV env var) and run against a fixed
 * UA mix that includes both positives (real bots from the
 * directory) and negatives (real browser UAs and tools that
 * shouldn't match anything). The negative case is the worst case
 * for the sequential walker (full table scan); the AC and bucket
 * approaches should both win there.
 *
 * Build:
 *   gcc -O2 -o /tmp/bench-bd tools/bench-bot-directory.c
 *
 * Run:
 *   /tmp/bench-bd [iterations]    # default 200,000
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>


/* ======================================================================
 * Pattern loading
 * ====================================================================== */

typedef struct {
    char *pattern;        /* original case preserved */
    char *pattern_lower;  /* lowercased for AC + bucket */
    int   pattern_len;
} bot_pattern;

static bot_pattern *patterns      = NULL;
static int          patterns_n    = 0;
static int          patterns_cap  = 0;

static const char *resolve_tsv_path(void)
{
    const char *env = getenv("BOTSHIELD_BOT_DIRECTORY_TSV");
    if (env && *env) return env;
    return "/var/lib/botshield/bot-directory.tsv";
}

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) { fprintf(stderr, "OOM\n"); exit(1); }
    return p;
}

static char *str_lower_dup(const char *s) {
    size_t n = strlen(s);
    char *out = xmalloc(n + 1);
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)tolower((unsigned char)s[i]);
    }
    out[n] = 0;
    return out;
}

static void patterns_push(const char *p)
{
    if (patterns_n == patterns_cap) {
        patterns_cap = patterns_cap ? patterns_cap * 2 : 64;
        patterns = realloc(patterns, sizeof(bot_pattern) * patterns_cap);
        if (!patterns) { fprintf(stderr, "OOM\n"); exit(1); }
    }
    patterns[patterns_n].pattern       = strdup(p);
    patterns[patterns_n].pattern_lower = str_lower_dup(p);
    patterns[patterns_n].pattern_len   = (int)strlen(p);
    patterns_n++;
}

static void load_patterns(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        exit(1);
    }
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        /* strip newline + trailing whitespace */
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r' ||
                     line[n-1] == ' '  || line[n-1] == '\t')) {
            line[--n] = 0;
        }
        if (!n) continue;
        if (line[0] == '#') continue;
        /* pattern is the first field (pipe-delimited) */
        char *bar = strchr(line, '|');
        if (bar) *bar = 0;
        if (line[0]) patterns_push(line);
    }
    fclose(f);
    fprintf(stderr, "loaded %d patterns from %s\n", patterns_n, path);
}

/* ======================================================================
 * Approach 1 — sequential strcasestr (production today)
 * ====================================================================== */

static int classify_sequential(const char *ua)
{
    if (!ua || !*ua) return 0;
    for (int i = 0; i < patterns_n; i++) {
        if (strcasestr(ua, patterns[i].pattern) != NULL) return 1;
    }
    return 0;
}


/* ======================================================================
 * Approach 2 — first-byte bucket
 *
 * Each pattern goes into the bucket keyed by its lowercased first
 * byte. At lookup, scan the UA's bytes; for each byte (lowered)
 * walk that bucket's patterns and try strcasestr ANCHORED at the
 * current UA position. Effectively skips all patterns whose first
 * byte never appears in the UA.
 * ====================================================================== */

typedef struct bucket_entry {
    const char *pattern_lower;
    int         pattern_len;
    int         pattern_idx;
} bucket_entry;

static bucket_entry  *buckets[256];
static int            bucket_lens[256];
static int            bucket_caps[256];

static void bucket_push(unsigned char first, const char *pat_lower,
                        int pat_len, int idx)
{
    if (bucket_lens[first] == bucket_caps[first]) {
        bucket_caps[first] = bucket_caps[first] ? bucket_caps[first] * 2 : 8;
        buckets[first] = realloc(buckets[first],
            sizeof(bucket_entry) * bucket_caps[first]);
        if (!buckets[first]) { fprintf(stderr, "OOM\n"); exit(1); }
    }
    bucket_entry *e = &buckets[first][bucket_lens[first]++];
    e->pattern_lower = pat_lower;
    e->pattern_len   = pat_len;
    e->pattern_idx   = idx;
}

static double bucket_setup_seconds = 0.0;

static void bucket_setup(void)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < patterns_n; i++) {
        unsigned char first = (unsigned char)patterns[i].pattern_lower[0];
        bucket_push(first, patterns[i].pattern_lower,
                    patterns[i].pattern_len, i);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    bucket_setup_seconds =
        (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
}

/* memmem-like comparator for ASCII case-insensitive — patterns
 * already lowercased; lower the haystack byte at compare time. */
static int matches_at(const char *haystack_pos, int haystack_remaining,
                      const char *needle_lower, int needle_len)
{
    if (needle_len > haystack_remaining) return 0;
    for (int i = 0; i < needle_len; i++) {
        if (tolower((unsigned char)haystack_pos[i]) !=
            (unsigned char)needle_lower[i]) {
            return 0;
        }
    }
    return 1;
}

static int classify_bucket(const char *ua)
{
    if (!ua || !*ua) return 0;
    int ua_len = (int)strlen(ua);
    for (int i = 0; i < ua_len; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)ua[i]);
        bucket_entry *b = buckets[c];
        int          n = bucket_lens[c];
        for (int j = 0; j < n; j++) {
            if (matches_at(ua + i, ua_len - i,
                           b[j].pattern_lower, b[j].pattern_len)) {
                return 1;
            }
        }
    }
    return 0;
}


/* ======================================================================
 * Approach 3 — Aho-Corasick automaton
 *
 * Goto + failure + output. Each node has a sparse children list
 * (sorted by byte). Traversal: at each byte of the input, follow
 * goto if present, else follow failure link until we have a
 * match or reach the root. If any node along the way has output,
 * we've matched.
 *
 * Patterns and input are case-folded to lowercase for ASCII.
 * ====================================================================== */

typedef struct ac_edge {
    unsigned char byte;
    int           target;
} ac_edge;

typedef struct ac_node {
    ac_edge *edges;
    int      edge_count;
    int      edge_cap;
    int      fail;
    int      output;       /* 1 if any pattern ends here OR via fail */
} ac_node;

static ac_node *ac_nodes      = NULL;
static int      ac_node_count = 0;
static int      ac_node_cap   = 0;

static double ac_setup_seconds = 0.0;

static int ac_new_node(void)
{
    if (ac_node_count == ac_node_cap) {
        ac_node_cap = ac_node_cap ? ac_node_cap * 2 : 1024;
        ac_nodes = realloc(ac_nodes, sizeof(ac_node) * ac_node_cap);
        if (!ac_nodes) { fprintf(stderr, "OOM\n"); exit(1); }
    }
    ac_node *n = &ac_nodes[ac_node_count];
    memset(n, 0, sizeof(*n));
    n->fail = 0;
    return ac_node_count++;
}

static int ac_find_edge(ac_node *n, unsigned char b)
{
    /* linear scan — most nodes have few edges */
    for (int i = 0; i < n->edge_count; i++) {
        if (n->edges[i].byte == b) return n->edges[i].target;
    }
    return -1;
}

static void ac_add_edge(int from, unsigned char b, int to)
{
    ac_node *n = &ac_nodes[from];
    if (n->edge_count == n->edge_cap) {
        n->edge_cap = n->edge_cap ? n->edge_cap * 2 : 4;
        n->edges = realloc(n->edges, sizeof(ac_edge) * n->edge_cap);
        if (!n->edges) { fprintf(stderr, "OOM\n"); exit(1); }
    }
    n->edges[n->edge_count].byte   = b;
    n->edges[n->edge_count].target = to;
    n->edge_count++;
}

static void ac_insert(const char *pat_lower)
{
    int cur = 0;  /* root */
    for (const char *p = pat_lower; *p; p++) {
        unsigned char b = (unsigned char)*p;
        int next = ac_find_edge(&ac_nodes[cur], b);
        if (next < 0) {
            next = ac_new_node();
            ac_add_edge(cur, b, next);
        }
        cur = next;
    }
    ac_nodes[cur].output = 1;  /* terminal */
}

static void ac_build_failures(void)
{
    /* BFS from root. queue of node indices. */
    int *queue = xmalloc(sizeof(int) * ac_node_count);
    int qh = 0, qt = 0;

    /* depth-1 nodes' failure goes to root; enqueue them */
    for (int i = 0; i < ac_nodes[0].edge_count; i++) {
        int child = ac_nodes[0].edges[i].target;
        ac_nodes[child].fail = 0;
        queue[qt++] = child;
    }

    while (qh < qt) {
        int u = queue[qh++];
        ac_node *un = &ac_nodes[u];
        for (int i = 0; i < un->edge_count; i++) {
            unsigned char b = un->edges[i].byte;
            int           v = un->edges[i].target;

            int f = un->fail;
            while (f != 0 && ac_find_edge(&ac_nodes[f], b) < 0) {
                f = ac_nodes[f].fail;
            }
            int next_via_f = ac_find_edge(&ac_nodes[f], b);
            if (next_via_f < 0 || next_via_f == v) {
                ac_nodes[v].fail = 0;
            } else {
                ac_nodes[v].fail = next_via_f;
            }
            /* propagate output along failure chain */
            if (ac_nodes[ac_nodes[v].fail].output) ac_nodes[v].output = 1;
            queue[qt++] = v;
        }
    }
    free(queue);
}

static void ac_setup(void)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ac_new_node();   /* root = node 0 */
    for (int i = 0; i < patterns_n; i++) {
        ac_insert(patterns[i].pattern_lower);
    }
    ac_build_failures();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ac_setup_seconds =
        (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
}

static int classify_ac(const char *ua)
{
    if (!ua || !*ua) return 0;
    int cur = 0;
    for (const char *p = ua; *p; p++) {
        unsigned char b = (unsigned char)tolower((unsigned char)*p);
        /* follow goto, falling back via failure link */
        while (cur != 0 && ac_find_edge(&ac_nodes[cur], b) < 0) {
            cur = ac_nodes[cur].fail;
        }
        int next = ac_find_edge(&ac_nodes[cur], b);
        if (next >= 0) cur = next;
        if (ac_nodes[cur].output) return 1;
    }
    return 0;
}


/* ======================================================================
 * Test inputs
 *
 * Mix of positive (should match — the directory contains these
 * crawler families) and negative (real browsers + tools that
 * shouldn't match anything → worst case for the sequential
 * walker since every pattern is tried).
 * ====================================================================== */

static const char *const TEST_UAS[] = {
    /* Positive — real bots from the directory */
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Bytespider; +http://www.bytespider.com/)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; SiteCheck-sitecrawl by Siteimprove.com)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GoogleOther) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
    "GPTBot/1.0",
    "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",

    /* Negative — real browsers (no bot match) */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",

    /* Negative — non-browser tools (also no bot match) */
    "python-httpx/0.27",
    "curl/7.61.1",
    "Go-http-client/1.1",
    "PostmanRuntime/7.36.0",
    "Wget/1.20.3 (linux-gnu)",
    "MyCustomScraper/1.0",
    "InternalApp/2.5",
};
#define N_TEST_UAS (sizeof(TEST_UAS) / sizeof(TEST_UAS[0]))


/* ======================================================================
 * Bench driver
 * ====================================================================== */

typedef int (*classifier_fn)(const char *);

static double time_classifier(const char *name, classifier_fn fn,
                              long iterations, int *match_count_out)
{
    struct timespec t0, t1;
    int sum = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long iter = 0; iter < iterations; iter++) {
        for (size_t i = 0; i < N_TEST_UAS; i++) {
            sum += fn(TEST_UAS[i]);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    long total = iterations * (long)N_TEST_UAS;
    double ns = sec * 1e9 / total;
    int per_iter = sum / (int)iterations;
    printf("  %-12s  %12ld calls  %10.3f s  %9.1f ns/call  matches=%d\n",
           name, total, sec, ns, per_iter);
    if (match_count_out) *match_count_out = per_iter;
    return ns;
}


int main(int argc, char **argv)
{
    long iterations = (argc > 1) ? atol(argv[1]) : 200000L;
    if (iterations < 1) iterations = 200000L;

    const char *path = resolve_tsv_path();
    load_patterns(path);
    if (patterns_n < 100) {
        fprintf(stderr, "WARN: only %d patterns loaded — bench may be unrepresentative\n",
                patterns_n);
    }

    bucket_setup();
    ac_setup();

    printf("bench-bot-directory\n");
    printf("  patterns:  %d (loaded from %s)\n", patterns_n, path);
    printf("  test UAs:  %zu (positive + negative mix)\n", N_TEST_UAS);
    printf("  iterations: %ld per UA\n", iterations);
    printf("  total calls per run: %ld\n\n", iterations * (long)N_TEST_UAS);

    printf("setup costs:\n");
    printf("  sequential:  (none — array is the storage)\n");
    printf("  first-byte:  %.3f ms (bucket each pattern by lowered first byte)\n",
           bucket_setup_seconds * 1e3);
    printf("  AC:          %.3f ms (build trie + failure links, %d nodes)\n\n",
           ac_setup_seconds * 1e3, ac_node_count);

    /* Sanity: all three must agree on every test UA */
    int disagree = 0;
    for (size_t i = 0; i < N_TEST_UAS; i++) {
        int s = classify_sequential(TEST_UAS[i]);
        int b = classify_bucket(TEST_UAS[i]);
        int a = classify_ac(TEST_UAS[i]);
        if (s != b || s != a) {
            printf("DISAGREE [%2zu]: ua=\"%s\"\n              seq=%d bucket=%d ac=%d\n",
                   i, TEST_UAS[i], s, b, a);
            disagree++;
        }
    }
    if (disagree) {
        printf("\nFATAL: classifiers disagree on %d UAs — bench invalid.\n", disagree);
        return 2;
    }
    printf("agreement: all three classifiers match on all %zu test UAs\n\n",
           N_TEST_UAS);

    printf("results:\n");
    printf("  %-12s  %12s  %10s  %14s  %s\n",
           "approach", "calls", "elapsed", "per-call", "matches/iter");
    int seq_match = 0, buck_match = 0, ac_match = 0;
    double seq_ns  = time_classifier("sequential", classify_sequential, iterations, &seq_match);
    double buck_ns = time_classifier("first-byte", classify_bucket,    iterations, &buck_match);
    double ac_ns   = time_classifier("AC",         classify_ac,        iterations, &ac_match);

    printf("\nratio:\n");
    printf("  bucket / sequential = %.2fx %s\n",
           buck_ns / seq_ns, (buck_ns < seq_ns ? "(faster)" : "(slower)"));
    printf("  AC / sequential     = %.2fx %s\n",
           ac_ns / seq_ns, (ac_ns < seq_ns ? "(faster)" : "(slower)"));
    printf("  AC / bucket         = %.2fx %s\n",
           ac_ns / buck_ns, (ac_ns < buck_ns ? "(faster)" : "(slower)"));

    return 0;
}
