/* tests/unit/score_unit.c — in-process tests for the scoring path.
 *
 * Runs the module's real heuristic and scoring code against synthetic
 * requests, with no Apache, no ports, no provisioning and no shared
 * state. A case is a request shape and an expected score, so the thing
 * asserted is the contract the module actually has rather than an HTTP
 * status that happens to fall out of it.
 *
 * Why this exists, concretely: the pytest suite asserted status codes,
 * which made every scoring test depend on the Bloom filter's contents.
 * A client scoring exactly at the threshold passed on a long-lived box
 * whose filter suppressed the first-sight term and failed in a cold
 * container. That is invisible when you assert 403 and obvious when you
 * assert 20.
 *
 * Same unity-build model as tests/fuzz: the stubs neuter Apache's
 * logging and gate out the module registration, then the sources are
 * included so everything becomes one translation unit.
 *
 * Build and run:
 *   make unit
 */

#include "../fuzz/_fuzz_stubs.h"

#include "../../src/robots.c"
#include "../../src/shm.c"
#include "../../src/crypto.c"
#include "../../src/allowlist.c"
#include "../../src/metrics.c"
#include "../../src/challenge.c"
#include "../../src/cookie.c"
#include "../../src/load.c"
#include "../../src/triggers.c"
#include "../../src/config.c"
#include "../../src/templates.c"
#include "../../src/formcaptcha.c"
#include "../../src/score.c"
#include "../../src/policy.c"
#include "../../src/heuristics.c"
#include "../../src/non_interactive.c"
#include "../../src/captcha.c"
#include "../../src/bridge.c"
/* Files added since tests/fuzz was written; the scoring path reaches
 * them through classification. */
#include "../../src/ua_class.c"
/* bs_trim is a file-static helper in both bot_directory.c and
 * browser_classifier.c. Harmless in the normal build, a redefinition in
 * a single translation unit. Renamed on the way in rather than touching
 * the sources, so the harness stays a reader of the module rather than
 * a reason to change it. */
#define bs_trim bs_trim_bot_directory
#include "../../src/bot_directory.c"
#undef bs_trim
#include "../../src/generated_bot_directory.c"
#include "../../src/browser_classifier.c"
#include "../../src/generated_browser_templates.c"
#include "../../src/generated_verified_bots.c"
#include "../../src/bot_rate.c"
#include "../../src/botshield.c"

#include <stdio.h>
#include <string.h>

/* Apache runtime symbols the scoring path never reaches.
 *
 * Stubbed rather than linked, because linking them means linking the
 * server, and a harness that needs the server is the thing this exists
 * to avoid. Each aborts rather than returning a plausible value: if the
 * scoring path ever does reach one, that is a change worth failing
 * loudly on rather than papering over with a zero. */
#define BS_UNREACHED(name) \
    do { fprintf(stderr, "score_unit: %s reached; the scoring path is " \
                 "no longer server-free\n", name); abort(); } while (0)

int ap_rprintf(request_rec *r, const char *fmt, ...) { (void)r; (void)fmt; BS_UNREACHED("ap_rprintf"); }
int ap_rwrite(const void *b, int n, request_rec *r) { (void)b; (void)n; (void)r; BS_UNREACHED("ap_rwrite"); }
void ap_set_content_type(request_rec *r, const char *t) { (void)r; (void)t; }
int ap_is_initial_req(request_rec *r) { (void)r; return 1; }
const char *ap_get_server_name(request_rec *r) { (void)r; return "unit.invalid"; }
int ap_exists_config_define(const char *n) { (void)n; return 0; }
char *ap_server_root_relative(apr_pool_t *p, const char *f) { (void)p; return (char *)f; }
char *ap_runtime_dir_relative(apr_pool_t *p, const char *f) { (void)p; return (char *)f; }
int ap_unescape_url(char *u) { (void)u; return 0; }
int ap_setup_client_block(request_rec *r, int p) { (void)r; (void)p; return 0; }
int ap_should_client_block(request_rec *r) { (void)r; return 0; }
long ap_get_client_block(request_rec *r, char *b, apr_size_t n) { (void)r; (void)b; (void)n; return 0; }
ap_filter_t *ap_add_input_filter_handle(ap_filter_rec_t *f, void *c, request_rec *r, conn_rec *co) { (void)f; (void)c; (void)r; (void)co; return NULL; }
ap_filter_t *ap_add_output_filter_handle(ap_filter_rec_t *f, void *c, request_rec *r, conn_rec *co) { (void)f; (void)c; (void)r; (void)co; return NULL; }
void ap_remove_input_filter(ap_filter_t *f) { (void)f; }
void ap_remove_output_filter(ap_filter_t *f) { (void)f; }
apr_status_t ap_get_brigade(ap_filter_t *f, apr_bucket_brigade *b, ap_input_mode_t m, apr_read_type_e t, apr_off_t n) { (void)f; (void)b; (void)m; (void)t; (void)n; return APR_SUCCESS; }
apr_status_t ap_pass_brigade(ap_filter_t *f, apr_bucket_brigade *b) { (void)f; (void)b; return APR_SUCCESS; }
piped_log *ap_open_piped_log(apr_pool_t *p, const char *c) { (void)p; (void)c; return NULL; }
apr_file_t *ap_piped_log_write_fd(piped_log *l) { (void)l; return NULL; }
int ap_extended_status = 0;
int ap_exists_scoreboard_image(void) { return 0; }
global_score *ap_get_scoreboard_global(void) { return NULL; }
worker_score *ap_get_scoreboard_worker_from_indexes(int i, int j) { (void)i; (void)j; return NULL; }
apr_status_t ap_unixd_set_global_mutex_perms(apr_global_mutex_t *m) { (void)m; return APR_SUCCESS; }
unixd_config_rec ap_unixd_config;
const char *ap_run_http_scheme(const request_rec *r) { (void)r; return "https"; }
char *ap_escape_html2(apr_pool_t *p, const char *s, int toasc) { (void)toasc; return apr_pstrdup(p, s); }

/* AP_DECLARE_MODULE is gated out by the harness flag, but the sources
 * pass &botshield_module to ap_get_module_config, which only needs a
 * module_index. Index 0 is fine: this process has exactly one module
 * and allocates its own config vectors. */
module AP_MODULE_DECLARE_DATA botshield_module;

static apr_pool_t *g_pool;

/* --- building a request ------------------------------------------- */

/* Apache's config vector is an array of void* indexed by module_index.
 * One slot is all this needs. */
static ap_conf_vector_t *make_cfg_vector(void)
{
    return (ap_conf_vector_t *)apr_pcalloc(g_pool, sizeof(void *) * 4);
}

typedef struct {
    const char *name;
    const char *ua;             /* NULL means no User-Agent header */
    const char *accept_language;/* NULL means no Accept-Language */
    int         first_sight;    /* Bloom miss, as bs_handler would find */
    int         dropped_cookie; /* Bloom hit, no solve proof */
    int         expect_score;
    const char *expect_reason;  /* substring that must appear, or NULL */
} score_case;

/* The slate from docs/examples/heuristic-triggers.conf.example, which
 * is also what tests/setup/botshield-dev.conf declares. Built directly
 * rather than parsed, so a config-syntax change cannot quietly turn
 * these into a different test. */
static void install_slate(bs_server_cfg *scfg)
{
    struct { int id; int add; } slate[] = {
        { BS_H_MISSING_UA,     40 },
        { BS_H_MISSING_AL,      5 },
        { BS_H_SCRAPER_UA,     10 },
        { BS_H_FIRST_SIGHT_IP,  5 },
        { BS_H_DROPPED_COOKIE, 25 },
    };
    scfg->heuristic_triggers = apr_array_make(
        g_pool, 8, sizeof(bs_heuristic_trigger_entry *));
    for (unsigned i = 0; i < sizeof(slate) / sizeof(slate[0]); i++) {
        bs_heuristic_trigger_entry *e = apr_pcalloc(g_pool, sizeof(*e));
        e->id        = slate[i].id;
        e->action    = BS_HEUR_ACT_SCORE;
        e->score_add = slate[i].add;
        e->tier_min  = BS_TIER_PASS;
        APR_ARRAY_PUSH(scfg->heuristic_triggers,
                       bs_heuristic_trigger_entry *) = e;
    }
}

static request_rec *make_request(const score_case *c, server_rec *s)
{
    request_rec *r = apr_pcalloc(g_pool, sizeof(*r));
    r->pool            = g_pool;
    r->server          = s;
    r->headers_in      = apr_table_make(g_pool, 8);
    r->headers_out     = apr_table_make(g_pool, 8);
    r->notes           = apr_table_make(g_pool, 8);
    r->subprocess_env  = apr_table_make(g_pool, 8);
    r->request_config  = make_cfg_vector();
    r->per_dir_config  = make_cfg_vector();
    r->uri             = "/";
    r->args            = NULL;
    r->useragent_ip    = "203.0.113.1";

    if (c->ua)              apr_table_set(r->headers_in, "User-Agent", c->ua);
    if (c->accept_language) apr_table_set(r->headers_in, "Accept-Language",
                                          c->accept_language);
    return r;
}

/* --- running one case ---------------------------------------------- */

static int run_case(const score_case *c, server_rec *s)
{
    request_rec *r = make_request(c, s);

    /* Header-phase heuristics are driven by their own predicates. The
     * two state-derived ones are established by bs_handler in the live
     * path, so the harness supplies them the same way it supplies a
     * header: as an input to the case. */
    bs_run_builtin_heuristics(r);
    if (c->first_sight)     bs_apply_heuristic(r, BS_H_FIRST_SIGHT_IP);
    if (c->dropped_cookie)  bs_apply_heuristic(r, BS_H_DROPPED_COOKIE);

    bs_request_score *sc = bs_get_score(r, 0);
    int total = sc ? sc->total : 0;
    const char *reasons = sc ? bs_score_reasons_joined(g_pool, sc) : "";

    int ok = (total == c->expect_score);
    if (ok && c->expect_reason && !strstr(reasons ? reasons : "",
                                          c->expect_reason)) {
        ok = 0;
    }
    printf("  %-4s %-34s score=%-4d expected=%-4d  %s\n",
           ok ? "ok" : "FAIL", c->name, total, c->expect_score,
           reasons ? reasons : "");
    return ok;
}

/* --- tier resolution ------------------------------------------------
 *
 * bs_decide_tier is a pure function of the three thresholds and a
 * score, which makes it the cheapest thing in the module to test and,
 * until now, one that was only ever exercised through an HTTP request.
 */

typedef struct {
    const char *name;
    int non_interactive, interactive, captcha;   /* -1 means unset */
    int score;
    bs_tier expect;
} tier_case;

static const char *tier_name(bs_tier t)
{
    switch (t) {
    case BS_TIER_PASS:           return "pass";
    case BS_TIER_NONINTERACTIVE: return "noninteractive";
    case BS_TIER_INTERACTIVE:    return "interactive";
    case BS_TIER_CAPTCHA:        return "captcha";
    default:                     return "?";
    }
}

static int run_tier_case(const tier_case *c)
{
    bs_dir_cfg *d = apr_pcalloc(g_pool, sizeof(*d));
    d->score_non_interactive = c->non_interactive;
    d->score_interactive     = c->interactive;
    d->score_captcha         = c->captcha;

    bs_tier got = bs_decide_tier(d, c->score);
    int ok = (got == c->expect);
    printf("  %-4s %-34s score=%-4d -> %-16s expected %s\n",
           ok ? "ok" : "FAIL", c->name, c->score, tier_name(got),
           tier_name(c->expect));
    return ok;
}

/* --- flag triggers and reset ordering --------------------------------
 *
 * reset drops every EARLIER entry for the same flag, which makes
 * declaration order load-bearing in a way nothing in the config syntax
 * hints at. That used not to matter: compiled-in defaults were seeded
 * ahead of every operator declaration, so a reset anywhere cleared
 * them. With the defaults gone, a reset placed above the declaration it
 * meant to cancel is a silent no-op -- which is exactly how two pytest
 * tests started failing, and is worth pinning here where the ordering
 * is visible in five lines rather than spread across a vhost file.
 */

static bs_flag_trigger_entry *flag_entry(const char *name, apr_uint32_t bit,
                                         bs_flag_action_kind act, int add)
{
    bs_flag_trigger_entry *e = apr_pcalloc(g_pool, sizeof(*e));
    e->flag_name = name;
    e->flag_bit  = bit;
    e->action    = act;
    e->score_add = add;
    e->tier_min  = BS_TIER_PASS;
    e->mode      = BS_TMODE_ENFORCE;
    return e;
}

/* Resolve a declaration list the way post_config does, then report how
 * many entries survive for the honeypot bit. */
static int resolve_and_count(server_rec *s, bs_server_cfg *scfg,
                             bs_flag_trigger_entry **decls, int n)
{
    scfg->flag_triggers = apr_array_make(g_pool, n ? n : 1, sizeof(void *));
    for (int i = 0; i < n; i++) {
        APR_ARRAY_PUSH(scfg->flag_triggers, bs_flag_trigger_entry *) = decls[i];
    }
    scfg->flag_triggers_resolved = 0;
    bs_resolve_flag_triggers(g_pool, s);

    int live = 0;
    for (int i = 0; i < scfg->flag_triggers->nelts; i++) {
        bs_flag_trigger_entry *e = APR_ARRAY_IDX(
            scfg->flag_triggers, i, bs_flag_trigger_entry *);
        if (e->flag_bit == BS_FLAG_HONEYPOT_HIT) live++;
    }
    return live;
}

static int run_reset_cases(server_rec *s, bs_server_cfg *scfg)
{
    int failures = 0;

    bs_flag_trigger_entry *decl =
        flag_entry("honeypot_hit", BS_FLAG_HONEYPOT_HIT, BS_FLAG_ACT_SCORE, 60);
    bs_flag_trigger_entry *reset =
        flag_entry("honeypot_hit", BS_FLAG_HONEYPOT_HIT, BS_FLAG_ACT_RESET, 0);

    struct { const char *name; bs_flag_trigger_entry *d[2]; int n; int expect; } cases[] = {
        { "reset after declaration clears it",  { NULL, NULL }, 2, 0 },
        { "reset before declaration is a no-op",{ NULL, NULL }, 2, 1 },
        { "declaration alone survives",         { NULL, NULL }, 1, 1 },
        { "reset alone clears nothing",         { NULL, NULL }, 1, 0 },
    };
    cases[0].d[0] = decl;  cases[0].d[1] = reset;
    cases[1].d[0] = reset; cases[1].d[1] = decl;
    cases[2].d[0] = decl;
    cases[3].d[0] = reset;

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int live = resolve_and_count(s, scfg, cases[i].d, cases[i].n);
        int ok = (live == cases[i].expect);
        if (!ok) failures++;
        printf("  %-4s %-34s honeypot entries=%d expected=%d\n",
               ok ? "ok" : "FAIL", cases[i].name, live, cases[i].expect);
    }
    return failures;
}

/* --- config inheritance ---------------------------------------------
 *
 * BotShieldDataDir is server scope and inherits. It was not doing so:
 * bs_merge_server_cfg starts from the vhost config, and a vhost that
 * never named a directory carried NULL, so everything resolving through
 * bs_data_path fell back to the compiled-in default however the main
 * server was configured. Nothing tested it, which is how a directive
 * documented as THE per-instance path came to govern the secret and
 * the state file and quietly share the crawler ranges.
 */

typedef struct {
    const char *name;
    const char *base_dir;   /* main server, NULL for unset */
    const char *add_dir;    /* vhost, NULL for unset */
    const char *expect;     /* what bs_data_path should produce */
} inherit_case;

static int run_inherit_case(const inherit_case *c)
{
    bs_server_cfg *base = apr_pcalloc(g_pool, sizeof(*base));
    bs_server_cfg *add  = apr_pcalloc(g_pool, sizeof(*add));
    base->data_dir = c->base_dir;
    add->data_dir  = c->add_dir;

    bs_server_cfg *merged = bs_merge_server_cfg(g_pool, base, add);
    const char *got = bs_data_path(g_pool, merged, "bots/googlebot.txt");

    int ok = (strcmp(got, c->expect) == 0);
    printf("  %-4s %-34s %s\n", ok ? "ok" : "FAIL", c->name, got);
    return ok;
}

int main(void)
{
    apr_initialize();
    apr_pool_create(&g_pool, NULL);

    server_rec *s = apr_pcalloc(g_pool, sizeof(*s));
    s->module_config = make_cfg_vector();
    s->process = apr_pcalloc(g_pool, sizeof(*s->process));
    s->process->pool = g_pool;

    bs_server_cfg *scfg = apr_pcalloc(g_pool, sizeof(*scfg));
    install_slate(scfg);
    ap_set_module_config(s->module_config, &botshield_module, scfg);

    static const score_case cases[] = {
        /* The case that made the pytest suite depend on Bloom warmth.
         * A framework client with no browser UA and no Accept-Language,
         * arriving from an address the filter has not seen, scores
         * exactly the dev vhost's noninteractive threshold of 20. */
        { "framework client, cold filter", "python-httpx/0.28", NULL,
          1, 0, 20, "scraperua" },
        /* The same client once the filter has seen it. Five points
         * lower, and on the other side of the line. Nothing about the
         * request changed. */
        { "framework client, warm filter", "python-httpx/0.28", NULL,
          0, 0, 15, "scraperua" },
        /* An ordinary visitor, which is what the default test client
         * should look like. */
        { "browser, cold filter",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 "
          "Safari/537.36", "en-US", 1, 0, 5, "firstsightip" },
        { "browser, warm filter",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
          "en-US", 0, 0, 0, NULL },
        { "no user-agent at all", NULL, "en-US", 0, 0, 40, "missinguseragent" },
        { "no headers at all", NULL, NULL, 0, 0, 45, "missingacceptlanguage" },
        { "cookie dropped after being seen",
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
          "en-US", 0, 1, 25, "droppedcookie" },
        { "scraper, every signal at once", "curl/8.4.0", NULL,
          1, 0, 20, "scraperua-curl" },
    };

    printf("scoring path, %zu cases\n", sizeof(cases) / sizeof(cases[0]));
    int failures = 0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (!run_case(&cases[i], s)) failures++;
    }

    static const tier_case tiers[] = {
        { "all unset never fires",        -1, -1, -1,  999, BS_TIER_PASS },
        { "below the first cut",          20, 50, 80,   19, BS_TIER_PASS },
        { "exactly the first cut",        20, 50, 80,   20, BS_TIER_NONINTERACTIVE },
        { "between first and second",     20, 50, 80,   49, BS_TIER_NONINTERACTIVE },
        { "exactly the second cut",       20, 50, 80,   50, BS_TIER_INTERACTIVE },
        { "exactly the third cut",        20, 50, 80,   80, BS_TIER_CAPTCHA },
        { "captcha unset stops at two",   20, 50, -1,  999, BS_TIER_INTERACTIVE },
        { "negative score is a pass",     20, 50, 80, -100, BS_TIER_PASS },
    };
    printf("\ntier resolution, %zu cases\n", sizeof(tiers) / sizeof(tiers[0]));
    for (unsigned i = 0; i < sizeof(tiers) / sizeof(tiers[0]); i++) {
        if (!run_tier_case(&tiers[i])) failures++;
    }

    printf("\nflagtrigger reset ordering, 4 cases\n");
    failures += run_reset_cases(s, scfg);

    static const inherit_case inherits[] = {
        { "vhost inherits the main dir", "/var/lib/bs-test", NULL,
          "/var/lib/bs-test/bots/googlebot.txt" },
        { "vhost overrides the main dir", "/var/lib/bs-test", "/srv/vhost",
          "/srv/vhost/bots/googlebot.txt" },
        { "neither set falls back",       NULL, NULL,
          BS_DEFAULT_DATA_DIR "/bots/googlebot.txt" },
        { "vhost only, main unset",       NULL, "/srv/vhost",
          "/srv/vhost/bots/googlebot.txt" },
    };
    printf("\nBotShieldDataDir inheritance, %zu cases\n",
           sizeof(inherits) / sizeof(inherits[0]));
    for (unsigned i = 0; i < sizeof(inherits) / sizeof(inherits[0]); i++) {
        if (!run_inherit_case(&inherits[i])) failures++;
    }

    printf("\n%s: %d failed\n", failures ? "FAIL" : "ok", failures);
    apr_pool_destroy(g_pool);
    apr_terminate();
    return failures ? 1 : 0;
}
