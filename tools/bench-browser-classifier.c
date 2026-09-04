/* bench-browser-classifier.c — head-to-head benchmark of the
 * strict-template browser classifier in two implementations:
 *
 *   1. CUSTOM:  the production approach. Walk UA byte-by-byte into
 *               a stack buffer, collapsing runs of [0-9._]+ to a
 *               single 'X'. Sequential strcmp against the 23
 *               normalized templates.
 *
 *   2. REGEX:   POSIX libc regex.h. Build one anchored regex per
 *               template (X → [0-9._]+), regcomp() at startup,
 *               regexec() against each UA. Try templates
 *               sequentially.
 *
 * Both run against the same template set (from data/top-user-
 * agents.json, hardcoded here for self-containment) and the same
 * UA test mix (positive: top-100 examples; negative: scrapers,
 * Mozilla-prefix-with-tail, custom apps).
 *
 * Build:
 *   gcc -O2 -o /tmp/bench-bc tools/bench-browser-classifier.c
 *
 * Run:
 *   /tmp/bench-bc [iterations]    # default 1,000,000
 *
 * Reports per-call latency (ns), setup cost, and memory footprint
 * estimate for each approach. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>


/* --- Template set (pre-normalized) ----------------------------- */

/* The 23 distinct version-masked templates from the top-100 list,
 * deduped + sorted. Same data as src/generated_browser_templates.c. */
static const char *const TEMPLATES[] = {
    "Mozilla/X (Linux; Android X; K) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X",
    "Mozilla/X (Linux; Android X; K) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (Linux; Android X; K) AppleWebKit/X (KHTML, like Gecko) SamsungBrowser/X Chrome/X Mobile Safari/X",
    "Mozilla/X (Linux; Android X; XRI Build/UKQX; wv) AppleWebKit/X (KHTML, like Gecko) Version/X Chrome/X Mobile Safari/X median",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Edg/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X OPR/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Version/X Safari/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Edg/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X OPR/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X YaBrowser/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) ScalboostBrowser/X Chrome/X Electron/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) obsidian/X Chrome/X Electron/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (XX; CrOS xX X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (XX; Linux xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (XX; Linux xX; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (XX; Ubuntu; Linux xX; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) CriOS/X Mobile/XEX Safari/X",
    "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Mobile/XEX",
    "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Version/X Mobile/XEX Safari/X",
};
#define N_TEMPLATES (sizeof(TEMPLATES) / sizeof(TEMPLATES[0]))


/* --- Test UA mix ------------------------------------------------ */

/* Mix of positive (real browser, should match) and negative
 * (scraper / Mozilla-prefix-with-tail / pure non-browser, should
 * not match). 30 entries — a realistic blend. The benchmark loops
 * over all of them per iteration, so total UAs tested per run is
 * iterations * 30. */
static const char *const TEST_UAS[] = {
    /* Positive — real browsers from various engines/platforms */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 OPR/115.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.69 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/115.0.0.0 Mobile Safari/537.36",

    /* Negative — Mozilla-prefix scrapers with extra trailing tokens */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 python-httpx/0.27",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 MyCustomScraper/1.0",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GoogleOther) Chrome/147.0.7727.137 Safari/537.36",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; SiteCheck-sitecrawl by Siteimprove.com; +https://siteimprove.com/bots) Chrome/135.0.7049.42 Safari/537.36",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",

    /* Negative — pure tools, no Mozilla prefix */
    "python-httpx/0.27",
    "curl/7.61.1",
    "Go-http-client/1.1",
    "PostmanRuntime/7.36.0",
    "Wget/1.20.3 (linux-gnu)",
    "PycURL/7.43.0.5 libcurl/7.61.1 OpenSSL/1.1.1k",
    "Gatus/1.0",
    "ClueWeb-Crawler/1.0",
    "AccessStatus",
};
#define N_TEST_UAS (sizeof(TEST_UAS) / sizeof(TEST_UAS[0]))


/* --- CUSTOM: normalize-and-compare ------------------------------ */

static int normalize_ua(const char *ua, char *out, size_t out_cap)
{
    if (!out_cap) return 0;
    size_t w = 0;
    int in_version = 0;
    for (const char *p = ua; *p; p++) {
        unsigned char c = (unsigned char)*p;
        int is_ver = (c >= '0' && c <= '9') || c == '.' || c == '_';
        if (is_ver) {
            if (!in_version) {
                if (w + 1 >= out_cap) return 0;
                out[w++] = 'X';
                in_version = 1;
            }
        } else {
            if (w + 1 >= out_cap) return 0;
            out[w++] = (char)c;
            in_version = 0;
        }
    }
    out[w] = '\0';
    return 1;
}

static int classify_custom(const char *ua)
{
    if (!ua || !*ua) return 0;
    char buf[1024];
    if (!normalize_ua(ua, buf, sizeof(buf))) return 0;
    for (size_t i = 0; i < N_TEMPLATES; i++) {
        if (strcmp(buf, TEMPLATES[i]) == 0) return 1;
    }
    return 0;
}


/* --- REGEX: POSIX regex.h --------------------------------------- */

/* Original (pre-normalized) UAs from the top-100 list. The regex
 * generator walks each one in raw form and emits [0-9._]+ in place
 * of every version run, sidestepping the X-placeholder ambiguity
 * (the literal "X" in "Mac OS X" would collide with a placeholder
 * X if we transformed the templates first). After dedup we have
 * the same 23 distinct patterns the templates produce. */
static const char *const RAW_UAS_FOR_REGEX[] = {
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; NRI Build/UKQN; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/119.0.6045.214 Mobile Safari/537.36 median",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 OPR/115.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/115.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.69 YaBrowser/24.10 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ScalboostBrowser/1.0 Chrome/130.0.6723.69 Electron/32.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/1.0 Chrome/130.0.6723.69 Electron/32.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.69 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Mobile/15E148 Safari/604.1",
};
#define N_RAW_UAS (sizeof(RAW_UAS_FOR_REGEX) / sizeof(RAW_UAS_FOR_REGEX[0]))

static regex_t compiled_regex[N_RAW_UAS];

/* Walk a raw UA, emit an anchored regex with [0-9._]+ where every
 * version run appeared. Escape regex metacharacters. This sidesteps
 * the X-placeholder ambiguity that would arise if we tried to
 * substitute X in the post-normalized template (the literal X in
 * "Mac OS X" is indistinguishable from a placeholder X). */
static char *raw_ua_to_regex(const char *ua)
{
    size_t cap = strlen(ua) * 12 + 4;
    char *pat = malloc(cap);
    if (!pat) return NULL;
    size_t w = 0;
    pat[w++] = '^';
    int in_version = 0;
    for (const char *p = ua; *p; p++) {
        char c = *p;
        int is_ver = (c >= '0' && c <= '9') || c == '.' || c == '_';
        if (is_ver) {
            if (!in_version) {
                const char *exp = "[0-9._]+";
                for (const char *e = exp; *e; e++) pat[w++] = *e;
                in_version = 1;
            }
        } else {
            in_version = 0;
            if (strchr("\\.+*?()[]{}|^$", c)) pat[w++] = '\\';
            pat[w++] = c;
        }
    }
    pat[w++] = '$';
    pat[w] = '\0';
    return pat;
}

static double regex_setup_seconds = 0.0;

static void regex_setup(void)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (size_t i = 0; i < N_RAW_UAS; i++) {
        char *pat = raw_ua_to_regex(RAW_UAS_FOR_REGEX[i]);
        if (!pat) {
            fprintf(stderr, "regex_setup: raw_ua_to_regex failed at %zu\n", i);
            exit(1);
        }
        int rc = regcomp(&compiled_regex[i], pat, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            char err[256];
            regerror(rc, &compiled_regex[i], err, sizeof(err));
            fprintf(stderr, "regex_setup: regcomp failed at %zu: %s\n  pat: %s\n",
                    i, err, pat);
            exit(1);
        }
        free(pat);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    regex_setup_seconds = (t1.tv_sec - t0.tv_sec)
                        + (t1.tv_nsec - t0.tv_nsec) / 1e9;
}

static int classify_regex(const char *ua)
{
    if (!ua || !*ua) return 0;
    for (size_t i = 0; i < N_RAW_UAS; i++) {
        if (regexec(&compiled_regex[i], ua, 0, NULL, 0) == 0) return 1;
    }
    return 0;
}


/* --- Bench infrastructure --------------------------------------- */

typedef int (*classifier_fn)(const char *);

static double time_classifier(const char *name, classifier_fn fn,
                              long iterations, int *out_match_count)
{
    struct timespec t0, t1;
    int match_count = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long iter = 0; iter < iterations; iter++) {
        for (size_t i = 0; i < N_TEST_UAS; i++) {
            match_count += fn(TEST_UAS[i]);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double seconds = (t1.tv_sec - t0.tv_sec)
                   + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    long total_calls = iterations * (long)N_TEST_UAS;
    double ns_per_call = seconds * 1e9 / total_calls;
    printf("  %-12s  %-10s  %12ld calls  %10.3f s  %8.1f ns/call  matches=%d\n",
           name, "", total_calls, seconds, ns_per_call,
           match_count / (int)iterations);
    if (out_match_count) *out_match_count = match_count / (int)iterations;
    return ns_per_call;
}


/* --- Main ------------------------------------------------------- */

int main(int argc, char **argv)
{
    long iterations = (argc > 1) ? atol(argv[1]) : 1000000L;
    if (iterations < 1) iterations = 1000000L;

    printf("bench-browser-classifier\n");
    printf("  templates: %zu\n", N_TEMPLATES);
    printf("  test UAs:  %zu (positive + negative mix)\n", N_TEST_UAS);
    printf("  iterations per UA: %ld\n", iterations);
    printf("  total calls per run: %ld\n\n", iterations * (long)N_TEST_UAS);

    /* Setup */
    regex_setup();
    printf("setup costs:\n");
    printf("  custom:       (none — static rodata)\n");
    printf("  regex:        %.3f ms (regcomp x %zu raw-UA-derived patterns)\n\n",
           regex_setup_seconds * 1e3, N_RAW_UAS);

    /* Sanity: both must agree on every test UA */
    int disagree = 0;
    for (size_t i = 0; i < N_TEST_UAS; i++) {
        int c = classify_custom(TEST_UAS[i]);
        int r = classify_regex(TEST_UAS[i]);
        if (c != r) {
            printf("DISAGREE: ua=\"%s\"  custom=%d regex=%d\n",
                   TEST_UAS[i], c, r);
            disagree++;
        }
    }
    if (disagree) {
        printf("\nFATAL: classifiers disagree on %d UAs — bench invalid.\n", disagree);
        return 2;
    }
    printf("agreement: classifiers match on all %zu test UAs\n\n",
           N_TEST_UAS);

    /* Time both */
    printf("results:\n");
    printf("  %-12s  %-10s  %12s  %10s  %14s  %s\n",
           "approach", "", "calls", "elapsed", "per-call", "matches/iter");
    double custom_ns = time_classifier("custom",  classify_custom, iterations, NULL);
    double regex_ns  = time_classifier("regex",   classify_regex,  iterations, NULL);

    /* Memory footprint estimate */
    size_t custom_bytes = 0;
    for (size_t i = 0; i < N_TEMPLATES; i++) custom_bytes += strlen(TEMPLATES[i]) + 1;
    custom_bytes += sizeof(TEMPLATES);

    /* Each compiled regex_t holds opaque DFA tables. POSIX doesn't
     * expose size; estimate by summing the originating pattern
     * sizes * 4 (typical NFA/DFA overhead for small patterns). The
     * regex_t struct itself is ~64 bytes; tables are heap-allocated
     * so the real cost is RSS not measurable from here. We report
     * the conservative estimate. */
    size_t regex_pat_bytes = 0;
    for (size_t i = 0; i < N_RAW_UAS; i++) {
        char *pat = raw_ua_to_regex(RAW_UAS_FOR_REGEX[i]);
        if (pat) { regex_pat_bytes += strlen(pat) + 1; free(pat); }
    }
    size_t regex_struct_bytes = sizeof(compiled_regex);

    printf("\nmemory:\n");
    printf("  custom:  %6zu B rodata  (templates + ptr table)\n",
           custom_bytes);
    printf("  regex:   ~%5zu B regex_t array + heap-allocated DFAs (POSIX hides exact size)\n",
           regex_struct_bytes);
    printf("           pattern source: %zu B (input to regcomp)\n",
           regex_pat_bytes);

    printf("\nratio: regex / custom = %.2fx slower\n", regex_ns / custom_ns);
    if (custom_ns < regex_ns) {
        printf("verdict: custom approach wins for this template set + UA mix.\n");
    } else {
        printf("verdict: regex wins; switch worth considering.\n");
    }
    return 0;
}
