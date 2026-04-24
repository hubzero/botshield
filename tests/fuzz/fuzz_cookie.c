/*
 * tests/fuzz/fuzz_cookie.c — LibFuzzer harness for bs_verify_cookie.
 *
 * Coverage-guided byte-level fuzz of the _bs_verified cookie parser.
 * Complements the hypothesis-driven byte-tamper test in
 * tests/pytests/test_cookie_property.py: that one runs over HTTP at
 * ~50 exec/sec with random mutation; libfuzzer runs in-process at
 * 10k–50k exec/sec with coverage-guided mutation, which is
 * dramatically more effective at finding edge cases in the field
 * splitter, hex parser, and base64 decode path.
 *
 * What this harness proves (under ASan + UBSan):
 *   - No crash / OOB / heap corruption on any byte sequence.
 *   - No UB on any byte sequence.
 *   - bs_verify_cookie returns some const char* (error string) or
 *     NULL (success) for every input — never hangs, never recurses
 *     unbounded.
 *
 * What it deliberately does NOT verify:
 *   - That a corrupted cookie produces the "right" error message —
 *     that's what the pytest hypothesis test handles, because HTTP-
 *     level assertions are easier than in-process semantic ones.
 *
 * Build: `make fuzz`  (see the top-level Makefile target).
 * Run  : `tests/fuzz/run.sh [seconds]`
 *
 * Strategy notes on the include:
 *   We #include src/mod_botshield.c directly so every static function
 *   (bs_from_hex, bs_challenge_canonical, bs_hmac_sha256,
 *   bs_ct_equal, bs_find_algorithm, the pow algorithm table) is
 *   reachable without exporting them in a header. The Apache runtime
 *   symbols (ap_log_rerror, ap_hook_*, module declaration, etc.) are
 *   supplied via _fuzz_stubs.h, #included ahead of mod_botshield.c to
 *   hijack specific call sites.
 *
 *   Cost of the approach: the module's post_config hooks and SHM
 *   setup never run under the harness, which is fine — we only
 *   fuzz bs_verify_cookie, which doesn't need them. The cost of
 *   the alternative (refactoring the parser into a linkable
 *   library) isn't justified for one fuzz target.
 */

/* Stubs for Apache/APR macros that otherwise pull in the whole
 * server runtime. Must be #included first so they define their
 * macros before mod_botshield.c expands them. */
#include "_fuzz_stubs.h"

/* Now the module itself. Defines bs_verify_cookie + all its helpers
 * as static functions in this translation unit. The module references
 * E2.2's robots.c symbols, so fold that file in too to satisfy the
 * single-TU link model this harness uses. */
#include "../../src/robots.c"
#include "../../src/mod_botshield.c"

/* --- Fuzz state (initialized once per process) ---------------------- */

static apr_pool_t *g_pool;     /* long-lived, reused for every input */
static bs_dir_cfg g_cfg;       /* fake per-dir config */
static request_rec g_req;      /* fake request — only r->pool is touched */

/* Minimal 32-byte HMAC secret. Stable across runs so the fuzzer can
 * learn to produce signatures that hit the post-signature-check code
 * (freshness, PoW counter verify) too, not just the pre-signature
 * rejection paths.
 */
static const unsigned char FUZZ_SECRET[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    apr_initialize();
    apr_pool_create(&g_pool, NULL);

    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.secret     = FUZZ_SECRET;
    g_cfg.secret_len = sizeof(FUZZ_SECRET);

    memset(&g_req, 0, sizeof(g_req));
    g_req.pool = g_pool;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* The cookie value parser expects a NUL-terminated C string. A
     * NUL anywhere in `data` would truncate the fuzz input, but that
     * exercises a legitimate real-world path (browser-supplied
     * cookie values are Unicode-ish but can be weird). Copy to a
     * fresh buffer and NUL-cap. */
    char *s = (char *)malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    bs_challenge ch;
    (void)bs_verify_cookie(&g_req, &g_cfg, s, &ch);

    free(s);

    /* Clear the pool each iteration so allocations don't grow
     * unboundedly across millions of inputs. This is why the pool
     * is persistent but its allocations are not. */
    apr_pool_clear(g_pool);
    return 0;
}
