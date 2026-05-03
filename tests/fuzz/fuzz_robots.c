/*
 * tests/fuzz/fuzz_robots.c — LibFuzzer harness for the robots.txt
 * parser + matcher.
 *
 * robots.txt is operator-controlled today, but E2.2.2 makes the
 * module re-read the file on the fly whenever its mtime changes —
 * and we'd like the module to degrade gracefully rather than crash
 * if anything at all goes wrong between "operator edits the file"
 * and "parser sees a fully-formed byte stream." Coverage-guided
 * byte fuzzing is the right fit: line-based parsers tend to hide
 * OOB reads in edge cases that are hard to think of in advance
 * (empty lines after BOM, colon-less keys, `;`-chains past the
 * line cap, path patterns ending mid-wildcard, etc.).
 *
 * What this harness proves (under ASan + UBSan):
 *   - robots_parse_buf never crashes on any byte sequence.
 *   - robots_query / the public group-iteration accessors never
 *     crash when called with the resulting doc + adversarial
 *     (UA, path) pairs.
 *   - The path matcher terminates — no infinite loop on any
 *     combination of `*` and `$`.
 *
 * Build: `make fuzz-robots` (see the top-level Makefile target).
 * Run  : `tests/fuzz/run.sh --target robots [seconds]`.
 *
 * Link model: we #include ../../src/robots.c so the parser's static
 * helpers are reachable. The robots.c module is APR-only (no httpd
 * symbols), so no fuzz stubs are needed — just plain APR init.
 */

#include <apr.h>
#include <apr_pools.h>
#include <apr_general.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Bring robots.c into this translation unit. It only calls APR +
 * libc; no Apache httpd.h, so no stubs needed. */
#include "../../src/robots.c"

static apr_pool_t *g_pool;

/* A handful of canonical UAs and paths for the post-parse query.
 * The fuzzer will exercise the parser primarily; the query calls
 * are secondary (make sure the resulting doc isn't traversable into
 * an OOB). Keeping these static so the corpus doesn't need to
 * encode them. */
static const char *const g_uas[] = {
    "GPTBot/1.0",
    "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0",
    "curl/8.6.0",
    "",
    "\x01\x02\x03",
};
static const char *const g_paths[] = {
    "/",
    "/admin",
    "/admin/",
    "/admin/secret/private.json",
    "/search?q=foo",
    "",
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    apr_initialize();
    apr_pool_create(&g_pool, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* 1 MiB cap mirrors BOTSHIELD_ROBOTS_MAX_BYTES. Inputs larger
     * than that return APR_EINVAL from the parser; exercising that
     * branch is fine, but reading past `size` would be a harness
     * bug, not a parser bug. */
    if (size > 2 * 1024 * 1024) return 0;

    robots_doc *doc = NULL;
    const char *err = NULL;
    apr_status_t rv = robots_parse_buf(g_pool, (const char *)data, size,
                                       &doc, &err);

    /* Even on parse failure we still exercise the query API with a
     * NULL doc — the public functions are documented to be
     * NULL-safe and LibFuzzer will happily find any missed guard. */
    for (size_t i = 0; i < sizeof(g_uas) / sizeof(g_uas[0]); i++) {
        for (size_t j = 0; j < sizeof(g_paths) / sizeof(g_paths[0]); j++) {
            robots_match m;
            robots_query(doc, g_uas[i], NULL, g_paths[j], &m);
        }
    }

    if (rv == APR_SUCCESS && doc) {
        int n = robots_group_count(doc);
        for (int gi = 0; gi < n; gi++) {
            (void)robots_group_name_at(doc, gi);
            (void)robots_group_is_wildcard_at(doc, gi);
            (void)robots_group_crawl_delay_at(doc, gi);
            int nu = robots_group_ua_count_at(doc, gi);
            for (int u = 0; u < nu; u++) {
                (void)robots_group_ua_at(doc, gi, u);
            }
            int nr = robots_group_rule_count_at(doc, gi);
            for (int k = 0; k < nr; k++) {
                const char *p = NULL;
                int a = 0;
                (void)robots_group_rule_at(doc, gi, k, &p, &a);
            }
        }
    }

    /* Clear the pool each iteration so per-iteration allocations
     * don't grow across millions of inputs. */
    apr_pool_clear(g_pool);
    return 0;
}
