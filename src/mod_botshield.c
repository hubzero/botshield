/*
 * mod_botshield — tiered bot detection and challenge module for Apache 2.4.
 *
 * Baseline tier: if the request has no valid _bs_verified cookie, return a
 * self-contained HTML interstitial with a proof-of-work challenge in inline
 * JavaScript. The client solves the PoW (SHA-256 with N leading hex zeros),
 * sets the cookie, and reloads — the same URL now passes through to the
 * real content.
 *
 * Security note on this baseline: the cookie is set client-side and the
 * server only matches it by format + timestamp window. A motivated attacker
 * can forge a cookie matching the regex; this is the "static verify page"
 * tier from hubzero/c-site-verify. Server-side HMAC signing (milestone M1)
 * closes that gap. The tier is still useful because it filters every bot
 * that can't run JS (most of them, in practice).
 *
 * Scope: directives are valid in server config, <VirtualHost>, <Directory>,
 * <Location>, <Files>, and their regex/match variants. Not .htaccess.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_file_io.h"
#include "apr_base64.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_thread_mutex.h"
#include "apr_atomic.h"
#include "unixd.h"
#include "mod_watchdog.h"
#include "mod_status.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

module AP_MODULE_DECLARE_DATA botshield_module;

/* Tri-state for flag directives: -1 = unset (inherit), 0 = off, 1 = on.
 * Integer directives use -1 to mean "inherit" too. */
#define BS_UNSET              (-1)
#define BS_DEFAULT_COOKIE_TTL 3600  /* seconds a verified cookie is good for */
#define BS_DEFAULT_DIFFICULTY 4     /* leading hex zeros */
#define BS_CLOCK_SKEW_AHEAD   60    /* grace if client clock runs ahead */
#define BS_DEFAULT_FORGIVE_SILENT   10
#define BS_DEFAULT_FORGIVE_FORM     25
#define BS_DEFAULT_FORGIVE_CAPTCHA  50
#define BS_COOKIE_NAME        "_bs_verified"
#define BS_DEFAULT_PROMPT     "I\xe2\x80\x99m not a robot"   /* U+2019 */
#define BS_DEFAULT_LOGO_LABEL "botshield"
#define BS_MAX_LOGO_BYTES     (64 * 1024)
#define BS_MAX_HELP_BYTES     (64 * 1024)
#define BS_MAX_PAGE_BYTES     (256 * 1024)
#define BS_MAX_SECRET_BYTES   1024
#define BS_MIN_SECRET_BYTES   16
#define BS_WIDGET_MARKER      "<!-- BOTSHIELD -->"

/* Captcha tier (M8). Defaults kept small and boring: a 1 s HTTP verify
 * budget is enough for Cloudflare / hCaptcha / Google normally, and
 * short enough that a provider outage doesn't stall real users. */
#define BS_DEFAULT_ENDPOINT_PREFIX  "/botshield"
#define BS_DEFAULT_CAPTCHA_TIMEOUT  1000   /* milliseconds */
#define BS_MIN_CAPTCHA_TIMEOUT      100
#define BS_MAX_CAPTCHA_TIMEOUT      5000
#define BS_CAPTCHA_CONNECT_TIMEOUT  250    /* milliseconds, not operator-tunable */
#define BS_MAX_CAPTCHA_TOKEN        4096   /* Turnstile tokens are <= ~2 KB */
#define BS_MAX_CAPTCHA_BODY         8192   /* siteverify response cap */
#define BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE 0.5  /* Google's suggested baseline */

/* Challenge protocol (M4.1 + M7) —
 *   Wire format (embedded inline in the interstitial, JSON):
 *     { v, alg, salt, nonce, difficulty, expires_at,
 *       score, flags, passes_silent, passes_form, passes_captcha,
 *       challenged_at, auto, signature }
 *   Canonical HMAC input (deterministic, pipe-delimited ASCII):
 *     "v|alg|salthex|noncehex|difficulty|expires_at
 *      |score|flags|pass_s|pass_f|pass_c|challenged_at|auto"
 *   Cookie payload = base64( canonical || "|" || sighex || "|" || counter )
 *   — a single base64 blob the server can parse by splitting on '|',
 *     no JSON parser required.
 *
 *   `auto` is the silent-tier (M7) marker: 1 means the challenge was served
 *   as a no-click auto-submit splash, 0 means the form-PoW interstitial.
 *   HMAC-covered so an accepted cookie tells the server which tier actually
 *   served it — used to pick passes_silent vs passes_form and the matching
 *   forgiveness amount on verify.
 *
 * Keep in sync with the JS worker when the template ships the wire bits. */
#define BS_PROTOCOL_VERSION   1
#define BS_SALT_BYTES         16
#define BS_NONCE_BYTES        8
#define BS_SIG_BYTES          32  /* HMAC-SHA-256 output */
#define BS_COOKIE_FIELDS      15  /* full cookie payload; canonical is 13 */

/* Forward declarations for the PoW algorithm dispatch table. */
typedef struct bs_dir_cfg bs_dir_cfg;

/* Forward decls for the bounded numeric parsers. Defined later in the
 * file alongside bs_from_hex; hoisted here so the directive setters
 * in the config block below can use them (security review: directive
 * setters now use strict bounded parsing like the cookie verify
 * path, not libc atoi which silently accepts "60sec" as 60 and
 * invokes UB on overflow). */
static int bs_parse_int_bounded(const char *s,
                                long min_val, long max_val,
                                apr_size_t max_len,
                                long *out);
static int bs_parse_int64_bounded(const char *s,
                                  apr_int64_t min_val,
                                  apr_int64_t max_val,
                                  apr_int64_t *out);

/* Forward decl for bs_score_add — called from the E1 block, which
 * lives before the scoring section so its data structures are
 * available at post_config time. */
static void bs_score_add(request_rec *r, int penalty,
                         int ttl_seconds, const char *reason);

/* Reputation state carried in the cookie. Populated fresh on a first-time
 * challenge (all zeros), and merged forward with forgiveness on re-issues. */
typedef struct {
    int         score;
    apr_uint32_t flags;
    int         passes_silent;
    int         passes_form;
    int         passes_captcha;
    apr_time_t  challenged_at;  /* unix sec */
} bs_rep_state;

typedef struct {
    int          version;
    const char  *alg_name;              /* points into registry */
    unsigned char salt [BS_SALT_BYTES];
    unsigned char nonce[BS_NONCE_BYTES];
    int          difficulty;
    apr_time_t   expires_at;            /* unix seconds */
    bs_rep_state rep;                   /* carried forward across re-issues */
    int          auto_tier;             /* 1 = silent M7 auto-submit; 0 = form */
    unsigned char signature[BS_SIG_BYTES];
} bs_challenge;

typedef const char *(*bs_alg_issue_fn)(const bs_dir_cfg *cfg,
                                       bs_challenge *out);
typedef const char *(*bs_alg_verify_fn)(const bs_challenge *ch,
                                        const char *counter_str);

typedef struct {
    const char       *name;
    int               implemented;   /* 1 = callable, 0 = reserved */
    bs_alg_issue_fn   issue;
    bs_alg_verify_fn  verify;
} bs_pow_algorithm;

typedef struct bs_captcha_provider bs_captcha_provider;

/* Captcha result (moved up here so the siteverify fn pointer can use it). */
typedef enum {
    BS_CAPTCHA_OK       = 0,
    BS_CAPTCHA_REJECTED = 1,
    BS_CAPTCHA_TIMEOUT  = 2,
    BS_CAPTCHA_ERROR    = 3
} bs_captcha_result;

/* Provider-specific siteverify function. NULL on the provider row means
 * "use the shared secret/response/remoteip POST + json-c parse path."
 * Providers whose verify protocol diverges materially from the
 * Google-family contract (GeeTest: HMAC-signed fields, non-bool result
 * semantics, JSON blob as the client-side token) set this to their own
 * function instead. Same signature and same out-params as the default
 * path so the caller is agnostic. */
typedef bs_captcha_result (*bs_captcha_siteverify_fn)(
    request_rec *r,
    const bs_captcha_provider *prov,
    const unsigned char *secret, apr_size_t secret_len,
    const char *token, int timeout_ms,
    const char **out_details,
    long *out_http_code,
    double *out_score,
    /* Binding-metadata out-params. NULL is a legal value and means
     * "provider didn't return this field" — a valid signal (e.g.
     * GeeTest doesn't expose hostname/action over the wire because
     * its binding is HMAC-signed at request time). Callers only
     * compare when non-NULL. */
    const char **out_hostname,
    const char **out_action);

/* Captcha provider (M8). One entry per third-party provider we can
 * route to at the captcha tier. `implemented` mirrors bs_pow_algorithm.
 *
 * For the Google-family providers (Turnstile, hCaptcha, reCAPTCHA v2/v3,
 * Friendly Captcha), `siteverify_fn` is NULL and the shared default
 * path POSTs a body of the form
 *   secret=<secret>&<siteverify_field>=<token>&remoteip=<ip>
 * where `siteverify_field` defaults to "response" (Turnstile / hCaptcha /
 * reCAPTCHA family) or is set to e.g. "solution" (Friendly Captcha).
 *
 * For providers whose verify protocol doesn't fit that shape (GeeTest),
 * `siteverify_fn` is set to a provider-specific function and the rest
 * of the registry row is informational — the fn decides how to use it.
 *
 * `token_field` is the name of the hidden form input the interstitial
 * emits to carry the client's token to our verify endpoint.
 *
 * `widget_script_url` is the async script tag the interstitial embeds;
 * `widget_class` is the CSS class on the container div the provider's
 * script looks for (empty for providers with programmatic init). */
struct bs_captcha_provider {
    const char *name;
    int         implemented;
    const char *siteverify_url;
    const char *token_field;
    const char *widget_script_url;
    const char *widget_class;
    const char *siteverify_field;          /* NULL → "response" */
    bs_captcha_siteverify_fn siteverify_fn; /* NULL → shared path */
};

/* --- Flagged-IP bitmap and scoring ---
 *
 * Each bit represents a *serious* event we want to remember about an IP
 * even if its cookie is rolled back. Penalties per bit are listed inline
 * in bs_flag_penalty(). Bits are additive: an IP that triggered both a
 * honeypot and a scanner probe carries the sum. */
#define BS_FLAG_HONEYPOT_HIT      (1U << 0)
#define BS_FLAG_SCANNER_PROBE     (1U << 1)
#define BS_FLAG_FAKE_CRAWLER      (1U << 2)
#define BS_FLAG_POW_FAIL_STREAK   (1U << 3)

/* --- Shared-memory layout ---
 *
 * One APR shared-memory segment holds everything. Fields are laid out
 * contiguously: fixed header, flagged-IP table (M5.1), two Bloom filter
 * buffers (M5.2), captcha-verify rate-limit ring (M8.1), log-suppress
 * ring (M8.1), metrics counters (M9.2). Workers access the segment
 * through bs_shm, a module-global runtime struct populated in
 * post-config. */
#define BS_SHM_MAGIC              0x42534844  /* 'BSHD' */
#define BS_SHM_FORMAT_VERSION     1
#define BS_DEFAULT_SHM_SIZE       (8 * 1024 * 1024)
#define BS_DEFAULT_FLAGGED_SLOTS  50000
#define BS_FLAGGED_MIN_SLOTS      1024
#define BS_FLAGGED_MAX_SLOTS      1000000
#define BS_FLAGGED_PROBE_LIMIT    10   /* linear probe depth */
#define BS_FLAGGED_MAX_READ_SPINS 3    /* seqlock retry budget */

/* Rotating Bloom filter (M5.2). N=2 buffers with half-window rotation.
 * Fixed 1% false-positive rate → ~9.6 bits/element, k=7 hash functions.
 * If we ever need to tune FP, this is where it gets a directive. */
#define BS_BLOOM_BITS_PER_IP      10      /* 9.6 rounded up */
#define BS_BLOOM_K                7
#define BS_DEFAULT_BLOOM_IPS      1000000 /* one week of a medium site */
#define BS_DEFAULT_BLOOM_WINDOW   604800  /* 7 days in seconds */
#define BS_BLOOM_MIN_IPS          1000
#define BS_BLOOM_MAX_IPS          10000000
#define BS_BLOOM_MIN_WINDOW       3600    /* 1 hour */
#define BS_BLOOM_MAX_WINDOW       (30 * 86400)  /* 30 days */
#define BS_FIRST_SIGHT_PENALTY    5

/* Per-slot seqlock + payload. version bit 0 is a "write in progress"
 * marker: even = quiescent, odd = mid-write. Readers snapshot fields
 * between matching even versions. Slot size is 32 bytes (cache-line
 * friendly): keep it that way so the array stays compact. */
typedef struct {
    apr_uint32_t  version;       /* seqlock counter */
    apr_uint32_t  flags;         /* 0 = empty slot */
    unsigned char ip[16];        /* IPv6-mapped v4 or raw v6 */
    apr_int64_t   expires_at;    /* unix seconds; past means stale */
} bs_flagged_ip_slot;

typedef struct {
    apr_uint32_t  magic;            /* BS_SHM_MAGIC */
    apr_uint32_t  format_version;   /* BS_SHM_FORMAT_VERSION */
    apr_uint32_t  flagged_capacity; /* number of slots in the table */
    apr_uint32_t  _pad0;
    unsigned char siphash_key[16];  /* DoS-resistant hash key */
    apr_uint32_t  bloom_active;         /* 0 or 1 */
    apr_uint32_t  bloom_buf_bytes;      /* per-buffer size in bytes */
    apr_uint32_t  bloom_window_secs;    /* full window; rotations at half */
    apr_uint32_t  _pad1;
    apr_int64_t   bloom_next_rotate;    /* unix sec */
    /* M8.1 captcha endpoint guardrails. Slot arrays use a single fixed
     * power-of-two slot count so index = siphash(ip) & (slots-1). */
    apr_uint32_t  cv_rate_slots;        /* rate-limit slot count */
    apr_uint32_t  cv_log_slots;         /* log-suppress slot count */
    apr_uint32_t  cv_inflight;          /* in-flight siteverify counter */
    apr_uint32_t  _pad2;
} bs_shm_header;

/* Rate-limit / log-suppress slot encoding. One uint64 per slot:
 *   bits 63..20  unix-minute window start (enough for ~millions of years)
 *   bits 19..0   count within that window (0..1M)
 * Rolling over to a new minute is a CAS of the whole slot to
 * (new_minute << 20) | 1. Non-atomic reads are benign — a torn read
 * just gives a stale count that CAS will correct on the next attempt. */
typedef apr_uint64_t bs_cv_slot;
#define BS_CV_WINDOW_SHIFT  20
#define BS_CV_COUNT_MASK    ((apr_uint64_t)0xFFFFF)
#define BS_CV_SLOT(min, cnt) \
    (((apr_uint64_t)(min) << BS_CV_WINDOW_SHIFT) | \
     ((apr_uint64_t)(cnt) & BS_CV_COUNT_MASK))
#define BS_CV_WINDOW(slot) ((apr_uint64_t)(slot) >> BS_CV_WINDOW_SHIFT)
#define BS_CV_COUNT(slot)  ((apr_uint32_t)((slot) & BS_CV_COUNT_MASK))

#define BS_DEFAULT_CV_RATE_SLOTS  4096   /* 32 KB */
#define BS_DEFAULT_CV_LOG_SLOTS   2048   /* 16 KB */
#define BS_DEFAULT_CAPTCHA_RATE_LIMIT     30    /* verifies/min/IP */
#define BS_DEFAULT_CAPTCHA_MAX_INFLIGHT   64
#define BS_CAPTCHA_LOG_WINDOW_SEC         60    /* log-throttle window */

/* ---- M9.2 metrics (SHM-backed counters + gauges) ----
 *
 * Indices and label strings are 1:1 with the M9.1 decision-log enums.
 * Reviewer guidance: keep the counter vocabulary identical to the log
 * vocabulary so a new outcome is a visible build break, not a silent
 * metric drift. If you add a value to any enum below, the corresponding
 * string→index lookup in bs_metrics.c gets one new row; the rest of
 * M9.2/M9.3 (export, gauge readers) is mechanical. */
typedef enum {
    BS_M_TIER_NONE = 0,
    BS_M_TIER_PASS,
    BS_M_TIER_SILENT,
    BS_M_TIER_FORM,
    BS_M_TIER_CAPTCHA,
    BS_M_TIER_COUNT
} bs_m_tier;

typedef enum {
    BS_M_OUTCOME_DECLINED = 0,
    BS_M_OUTCOME_CHALLENGED,
    BS_M_OUTCOME_VERIFIED,
    BS_M_OUTCOME_REJECTED,
    BS_M_OUTCOME_FAILOPEN,
    BS_M_OUTCOME_RATE_LIMITED,
    BS_M_OUTCOME_INFLIGHT_CAPPED,
    BS_M_OUTCOME_PENDING_MISSING,
    BS_M_OUTCOME_MISCONFIGURED,
    BS_M_OUTCOME_DEBUG,
    BS_M_OUTCOME_COUNT
} bs_m_outcome;

typedef enum {
    BS_M_COOKIE_OK = 0,
    BS_M_COOKIE_EXPIRED,
    BS_M_COOKIE_BAD_SIG,
    BS_M_COOKIE_BAD_FORMAT,
    BS_M_COOKIE_ABSENT,
    BS_M_COOKIE_COUNT
} bs_m_cookie;

typedef enum {
    BS_M_PROV_TURNSTILE = 0,
    BS_M_PROV_HCAPTCHA,
    BS_M_PROV_RECAPTCHA_V2,
    BS_M_PROV_RECAPTCHA_V3,
    BS_M_PROV_FRIENDLY,
    BS_M_PROV_GEETEST,
    BS_M_PROV_COUNT
} bs_m_provider;

/* Fixed-layout counter block in SHM. Each decision-log call increments
 * up to four counters (tier, outcome, cookie when != "-", provider
 * when != "-"). Persistence gauges are updated only from the save/load
 * code paths, so no contention with the hot decision path. */
typedef struct {
    apr_uint64_t tier   [BS_M_TIER_COUNT];
    apr_uint64_t outcome[BS_M_OUTCOME_COUNT];
    apr_uint64_t cookie [BS_M_COOKIE_COUNT];
    apr_uint64_t provider[BS_M_PROV_COUNT];
    /* Persistence gauges (bumped / set by bs_state_save and bs_state_load). */
    apr_uint64_t state_saves_total;
    apr_uint64_t state_save_last_unix;
    apr_uint64_t state_save_last_bytes;
    apr_uint64_t state_save_last_duration_us;
    apr_uint64_t state_loads_total;
    apr_uint64_t state_load_last_kept;
    apr_uint64_t state_load_last_dropped;
    /* E1 — crawler verification. Aggregate across all crawlers;
     * per-crawler breakdown lives in the decision log, not here, so
     * we don't introduce labeled metrics yet. */
    apr_uint64_t crawler_verified_total;
    apr_uint64_t crawler_fake_total;
    apr_uint64_t crawler_unverified_total;
} bs_metrics;

/* Module-global runtime pointer struct. Populated once in post-config;
 * children inherit via fork. M5.2 just fills in bloom_bufs[] and
 * bloom_buf_bytes — no re-plumbing. */
typedef struct {
    apr_shm_t           *shm;
    apr_global_mutex_t  *mutex;
    const char          *mutex_filename;   /* for attaches in child_init */
    bs_shm_header       *header;
    bs_flagged_ip_slot  *flagged_table;
    apr_size_t           flagged_capacity;
    unsigned char       *bloom_bufs[2];    /* M5.2 rotating Bloom filter */
    apr_size_t           bloom_buf_bytes;  /* M5.2 per-buffer byte size */
    /* M8.1 */
    bs_cv_slot          *cv_rate_slots;    /* rate-limit ring */
    apr_size_t           cv_rate_slot_count;
    bs_cv_slot          *cv_log_slots;     /* log-suppress ring */
    apr_size_t           cv_log_slot_count;
    apr_uint32_t        *cv_inflight;      /* ptr into SHM header field */
    /* M9.2 */
    bs_metrics          *metrics;
} bs_shm_runtime;

static bs_shm_runtime bs_shm;

/* Help visibility modes (values are stored in bs_dir_cfg.help_mode). */
enum bs_help_mode {
    BS_HELP_OFF    = 0,  /* emit nothing */
    BS_HELP_ON     = 1,  /* always visible below the widget */
    BS_HELP_BUTTON = 2,  /* "?" link below widget; click to expand */
};
#define BS_DEFAULT_HELP_MODE BS_HELP_BUTTON

/* Scoring thresholds (penalty → tier) and heuristic penalties. */
#define BS_DEFAULT_SCORE_SILENT   20
#define BS_DEFAULT_SCORE_HARD     50
#define BS_DEFAULT_SCORE_CAPTCHA  80
#define BS_SCORE_MAX_REASONS      16

#define BS_PENALTY_MISSING_UA     40
#define BS_PENALTY_MISSING_AL     15
#define BS_PENALTY_SCRAPER_UA     50

typedef enum {
    BS_TIER_PASS    = 0,
    BS_TIER_SILENT  = 1,
    BS_TIER_HARD    = 2,
    BS_TIER_CAPTCHA = 3
} bs_tier;

typedef struct {
    int         penalty;
    int         ttl_seconds;   /* accepted for API stability; unused today
                                * (bs_score_add stores it but downstream
                                * consumers haven't materialized — the
                                * flagged-IP table carries its own TTL
                                * set at insert). Kept so callers can
                                * annotate "this penalty represents an
                                * N-second-worth signal" without the
                                * API churning if we ever wire it up. */
    const char *reason;        /* static string or r->pool-allocated */
} bs_score_entry;

typedef struct {
    int                 total;
    apr_array_header_t *entries;
} bs_request_score;

/* Default help panel content. HTML allowed because the string is emitted
 * directly into the panel; admins override via BotShieldHelpFile. */
static const char BS_DEFAULT_HELP_HTML[] =
"<p>A quick automated check that filters out bots. Your browser solves "
"a small math puzzle in the background \xe2\x80\x94 no pictures to "
"identify, and nothing personal is sent. It usually takes a second "
"or two.</p>";

/* Embedded Guardian shield — used when BotShieldLogoFile isn't set. */
static const char BS_DEFAULT_LOGO_SVG[] =
"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\" "
"focusable=\"false\">"
"<defs><linearGradient id=\"bsg\" x1=\"0\" x2=\"0\" y1=\"0\" y2=\"1\">"
"<stop offset=\"0\" stop-color=\"#3b7a66\"/>"
"<stop offset=\"1\" stop-color=\"#1a3a2e\"/>"
"</linearGradient></defs>"
"<path d=\"M32 4 L56 12 V32 C56 46 44 56 32 60 C20 56 8 46 8 32 V12 Z\" "
"fill=\"url(#bsg)\" stroke=\"#0f2a22\" stroke-width=\"1.5\"/>"
"<path d=\"M19 32 L28 41 L45 22\" fill=\"none\" stroke=\"#fff3b0\" "
"stroke-width=\"5.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
"</svg>";

struct bs_dir_cfg {
    int enabled;
    int debug;
    int cookie_ttl;
    int difficulty;
    int help_mode;              /* BS_HELP_* or BS_UNSET */
    int show_logo;              /* 0 = hide brand column, 1 = show, -1 = inherit */
    int show_label;             /* 0 = hide prompt text, 1 = show, -1 = inherit */
    int show_box;               /* 0 = no bounding box, 1 = boxed, -1 = inherit */
    const char *prompt;         /* e.g. "I'm not a robot" */
    const char *logo_svg;       /* full SVG content, loaded at config time */
    const char *logo_label;     /* small caption under the logo */
    const char *help_html;      /* panel content, loaded at config time */
    const char *challenge_html; /* full HTML page template with marker */
    const bs_pow_algorithm *algorithm;      /* chosen issue algorithm */
    const unsigned char    *secret;         /* HMAC key bytes */
    apr_size_t              secret_len;     /* key length */
    int score_silent;           /* score >= this → silent tier (logged only) */
    int score_hard;             /* score >= this → hard form-PoW tier */
    int score_captcha;          /* score >= this → captcha tier */
    int forgive_silent;         /* score credit on silent-tier pass */
    int forgive_form;           /* score credit on form-tier pass */
    int forgive_captcha;        /* score credit on captcha pass */
    const char *cookie_domain;  /* if set, Set-Cookie Domain= attribute */
    apr_uint32_t flag_on_match; /* BotShieldFlagIP: bits to add on any hit */
    int          flag_on_match_ttl;  /* entry TTL when flag_on_match fires */
    /* --- Captcha tier (M8) --- */
    const char *endpoint_prefix;            /* default "/botshield" */
    const bs_captcha_provider *captcha_provider;  /* NULL = tier unused */
    const char *captcha_site_key;           /* provider-public */
    const unsigned char *captcha_secret;    /* file bytes, mode-600 */
    apr_size_t  captcha_secret_len;
    int         captcha_timeout_ms;         /* siteverify HTTP timeout */
    /* reCAPTCHA v3: minimum score to accept, in [0.0, 1.0]. -1.0 = unset. */
    double      recaptcha_v3_min_score;
    /* M8.1 per-scope verify-endpoint rate limit. -1 unset, 0 disables. */
    int         captcha_rate_limit;
    /* Security review findings: binding-metadata validation on the
     * siteverify response. NULL = use a runtime default
     * (server_hostname, "botshield"); empty string = skip the check
     * (operator opted out). Turnstile + reCAPTCHA v2/v3 + hCaptcha
     * return `hostname`; reCAPTCHA v3 + Turnstile also return
     * `action`. Without these checks, a valid token for the same
     * sitekey but a different action or a different origin would
     * satisfy the verify handler. */
    const char *captcha_expected_hostname;
    const char *captcha_expected_action;
};

/* Per-server config — holds SHM sizing before post-config runs. Only the
 * main server's values are consulted; vhost-level overrides are logged
 * and ignored because the SHM segment is global. */
typedef struct {
    apr_size_t  shm_size;
    int         flagged_capacity;
    int         ipv6_prefix_bits;   /* 0..128; 64 = per-subscriber v6 key */
    int         bloom_ips;          /* expected working-set size */
    int         bloom_window_secs;  /* full window; rotation at window/2 */
    const char *state_file;         /* NULL = persistence off */
    int         state_save_interval;/* seconds; 0 = shutdown-only */
    int         captcha_max_inflight;  /* M8.1: cap on outstanding siteverifies */
    /* E1 — verified legit-crawler allow-list. State loaded in
     * post_config and read-only thereafter; lives at server scope
     * because the UA classifier + CIDR lists are global, not per-
     * directory. */
    int          crawlers_enabled;         /* master gate, default 0 */
    void        *crawler_classifier;       /* bs_ua_classifier *, opaque here */
    apr_hash_t  *crawler_ranges;           /* name → apr_array_header_t of apr_ipsubnet_t* */
    apr_table_t *crawler_range_overrides;  /* name → explicit path (directive overrides) */
    apr_table_t *crawler_extra_patterns;   /* name → UA pattern (operator-defined bots) */
} bs_server_cfg;

/* --- Config lifecycle --- */

static void *bs_create_dir_cfg(apr_pool_t *p, char *path)
{
    (void)path;
    bs_dir_cfg *cfg = apr_pcalloc(p, sizeof(*cfg));
    cfg->enabled    = BS_UNSET;
    cfg->debug      = BS_UNSET;
    cfg->cookie_ttl = BS_UNSET;
    cfg->difficulty = BS_UNSET;
    cfg->help_mode  = BS_UNSET;
    cfg->show_logo  = BS_UNSET;
    cfg->show_label = BS_UNSET;
    cfg->show_box   = BS_UNSET;
    cfg->algorithm  = NULL;
    cfg->secret     = NULL;
    cfg->secret_len = 0;
    cfg->score_silent  = BS_UNSET;
    cfg->score_hard    = BS_UNSET;
    cfg->score_captcha = BS_UNSET;
    cfg->forgive_silent  = BS_UNSET;
    cfg->forgive_form    = BS_UNSET;
    cfg->forgive_captcha = BS_UNSET;
    cfg->cookie_domain   = NULL;
    cfg->flag_on_match       = 0;
    cfg->flag_on_match_ttl   = 0;
    cfg->endpoint_prefix     = NULL;
    cfg->captcha_provider    = NULL;
    cfg->captcha_site_key    = NULL;
    cfg->captcha_secret      = NULL;
    cfg->captcha_secret_len  = 0;
    cfg->captcha_timeout_ms  = BS_UNSET;
    cfg->recaptcha_v3_min_score = -1.0;
    cfg->captcha_rate_limit  = BS_UNSET;
    cfg->captcha_expected_hostname = NULL;
    cfg->captcha_expected_action   = NULL;
    return cfg;
}

static void *bs_create_server_cfg(apr_pool_t *p, server_rec *s)
{
    (void)s;
    bs_server_cfg *scfg = apr_pcalloc(p, sizeof(*scfg));
    scfg->shm_size          = BS_DEFAULT_SHM_SIZE;
    scfg->flagged_capacity  = BS_DEFAULT_FLAGGED_SLOTS;
    scfg->ipv6_prefix_bits  = 64;   /* /64 aggregation by default */
    scfg->bloom_ips             = BS_DEFAULT_BLOOM_IPS;
    scfg->bloom_window_secs     = BS_DEFAULT_BLOOM_WINDOW;
    scfg->state_file            = NULL;
    scfg->state_save_interval   = 300;   /* 5 min default when state file set */
    scfg->captcha_max_inflight  = BS_DEFAULT_CAPTCHA_MAX_INFLIGHT;
    /* E1 crawler allow-list defaults — master gate off (opt-in).
     * crawler_classifier / crawler_ranges stay NULL and get built
     * in post_config if the master gate flips on. */
    scfg->crawlers_enabled         = 0;
    scfg->crawler_classifier       = NULL;
    scfg->crawler_ranges           = NULL;
    scfg->crawler_range_overrides  = apr_table_make(p, 4);
    scfg->crawler_extra_patterns   = apr_table_make(p, 4);
    return scfg;
}

static void *bs_merge_dir_cfg(apr_pool_t *p, void *base_v, void *add_v)
{
    bs_dir_cfg *base = base_v;
    bs_dir_cfg *add  = add_v;
    bs_dir_cfg *out  = apr_pcalloc(p, sizeof(*out));
    out->enabled    = (add->enabled    == BS_UNSET) ? base->enabled    : add->enabled;
    out->debug      = (add->debug      == BS_UNSET) ? base->debug      : add->debug;
    out->cookie_ttl = (add->cookie_ttl == BS_UNSET) ? base->cookie_ttl : add->cookie_ttl;
    out->difficulty = (add->difficulty == BS_UNSET) ? base->difficulty : add->difficulty;
    out->help_mode  = (add->help_mode  == BS_UNSET) ? base->help_mode  : add->help_mode;
    out->show_logo  = (add->show_logo  == BS_UNSET) ? base->show_logo  : add->show_logo;
    out->show_label = (add->show_label == BS_UNSET) ? base->show_label : add->show_label;
    out->show_box   = (add->show_box   == BS_UNSET) ? base->show_box   : add->show_box;
    out->prompt         = add->prompt         ? add->prompt         : base->prompt;
    out->logo_svg       = add->logo_svg       ? add->logo_svg       : base->logo_svg;
    out->logo_label     = add->logo_label     ? add->logo_label     : base->logo_label;
    out->help_html      = add->help_html      ? add->help_html      : base->help_html;
    out->challenge_html = add->challenge_html ? add->challenge_html : base->challenge_html;
    out->algorithm      = add->algorithm      ? add->algorithm      : base->algorithm;
    if (add->secret) {
        out->secret     = add->secret;
        out->secret_len = add->secret_len;
    } else {
        out->secret     = base->secret;
        out->secret_len = base->secret_len;
    }
    out->score_silent  = (add->score_silent  == BS_UNSET) ? base->score_silent  : add->score_silent;
    out->score_hard    = (add->score_hard    == BS_UNSET) ? base->score_hard    : add->score_hard;
    out->score_captcha = (add->score_captcha == BS_UNSET) ? base->score_captcha : add->score_captcha;
    out->forgive_silent  = (add->forgive_silent  == BS_UNSET) ? base->forgive_silent  : add->forgive_silent;
    out->forgive_form    = (add->forgive_form    == BS_UNSET) ? base->forgive_form    : add->forgive_form;
    out->forgive_captcha = (add->forgive_captcha == BS_UNSET) ? base->forgive_captcha : add->forgive_captcha;
    out->cookie_domain   = add->cookie_domain ? add->cookie_domain : base->cookie_domain;
    /* Flag-on-match is additive: a more-specific scope that adds a flag
     * is merged with any broader-scope flag, so an inner <Location> adds
     * its flag without losing the outer. */
    out->flag_on_match = base->flag_on_match | add->flag_on_match;
    out->flag_on_match_ttl = add->flag_on_match_ttl
                             ? add->flag_on_match_ttl : base->flag_on_match_ttl;
    out->endpoint_prefix  = add->endpoint_prefix  ? add->endpoint_prefix  : base->endpoint_prefix;
    out->captcha_provider = add->captcha_provider ? add->captcha_provider : base->captcha_provider;
    out->captcha_site_key = add->captcha_site_key ? add->captcha_site_key : base->captcha_site_key;
    if (add->captcha_secret) {
        out->captcha_secret     = add->captcha_secret;
        out->captcha_secret_len = add->captcha_secret_len;
    } else {
        out->captcha_secret     = base->captcha_secret;
        out->captcha_secret_len = base->captcha_secret_len;
    }
    out->captcha_timeout_ms = (add->captcha_timeout_ms == BS_UNSET)
                              ? base->captcha_timeout_ms : add->captcha_timeout_ms;
    out->recaptcha_v3_min_score = (add->recaptcha_v3_min_score < 0.0)
                                  ? base->recaptcha_v3_min_score
                                  : add->recaptcha_v3_min_score;
    out->captcha_rate_limit = (add->captcha_rate_limit == BS_UNSET)
                              ? base->captcha_rate_limit
                              : add->captcha_rate_limit;
    out->captcha_expected_hostname = add->captcha_expected_hostname
                                     ? add->captcha_expected_hostname
                                     : base->captcha_expected_hostname;
    out->captcha_expected_action   = add->captcha_expected_action
                                     ? add->captcha_expected_action
                                     : base->captcha_expected_action;
    return out;
}

static int bs_effective_int(int value, int fallback)
{
    return (value == BS_UNSET) ? fallback : value;
}

/* --- Directive setters --- */

static const char *bs_set_enabled(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->enabled = flag ? 1 : 0;
    return NULL;
}

static const char *bs_set_debug(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->debug = flag ? 1 : 0;
    return NULL;
}

static const char *bs_set_show_logo(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->show_logo = flag ? 1 : 0;
    return NULL;
}

static const char *bs_set_show_label(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->show_label = flag ? 1 : 0;
    return NULL;
}

static const char *bs_set_show_box(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->show_box = flag ? 1 : 0;
    return NULL;
}

static const char *bs_set_cookie_ttl(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    /* Strict parse — reject "60sec" and overflow, not just silently
     * truncate via atoi(). Review finding #2. */
    long n;
    if (!bs_parse_int_bounded(arg, 1, 86400, 6, &n)) {
        return "BotShieldCookieTTL: must be an integer 1..86400 (seconds)";
    }
    ((bs_dir_cfg *)cfg_v)->cookie_ttl = (int)n;
    return NULL;
}

static const char *bs_set_difficulty(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    long n;
    if (!bs_parse_int_bounded(arg, 1, 8, 2, &n)) {
        return "BotShieldDifficulty: must be an integer 1..8";
    }
    ((bs_dir_cfg *)cfg_v)->difficulty = (int)n;
    return NULL;
}

static const char *bs_set_score_int(const char *directive, int *slot,
                                    const char *arg, apr_pool_t *p)
{
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (end == arg || *end != '\0' || n < 0 || n > 10000) {
        return apr_psprintf(p,
            "%s: expected an integer in 0..10000, got '%s'", directive, arg);
    }
    *slot = (int)n;
    return NULL;
}

static const char *bs_set_score_silent(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldScoreSilent",
        &((bs_dir_cfg *)cfg_v)->score_silent, arg, cmd->pool);
}

static const char *bs_set_score_hard(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldScoreHard",
        &((bs_dir_cfg *)cfg_v)->score_hard, arg, cmd->pool);
}

static const char *bs_set_score_captcha(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldScoreCaptcha",
        &((bs_dir_cfg *)cfg_v)->score_captcha, arg, cmd->pool);
}

static const char *bs_set_forgive_silent(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldForgivenessSilent",
        &((bs_dir_cfg *)cfg_v)->forgive_silent, arg, cmd->pool);
}

static const char *bs_set_forgive_form(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldForgivenessForm",
        &((bs_dir_cfg *)cfg_v)->forgive_form, arg, cmd->pool);
}

static const char *bs_set_forgive_captcha(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldForgivenessCaptcha",
        &((bs_dir_cfg *)cfg_v)->forgive_captcha, arg, cmd->pool);
}

/* Forward decl: defined below in the SHM section, used by the directive
 * setter just beneath this comment. */
static apr_uint32_t bs_parse_flag_names(apr_pool_t *p, const char *s,
                                        const char **err);

static const char *bs_set_shm_size(cmd_parms *cmd, void *dconf, const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    /* Accept "N", "NK", "NM", "NG" (case-insensitive). */
    errno = 0;
    char *end = NULL;
    apr_int64_t n = apr_strtoi64(arg, &end, 10);
    if (errno != 0 || end == arg || n <= 0) {
        return "BotShieldShmSize: expected a positive integer byte count";
    }
    apr_int64_t mult = 1;
    if      (*end == 'K' || *end == 'k') mult = 1024;
    else if (*end == 'M' || *end == 'm') mult = 1024 * 1024;
    else if (*end == 'G' || *end == 'g') mult = 1024 * 1024 * 1024;
    else if (*end != '\0') {
        return apr_psprintf(cmd->pool,
            "BotShieldShmSize: unknown suffix '%c'", *end);
    }
    /* Guard the suffix multiply (security review #2). The explicit
     * max below (256 MiB) is the real gate, but catching an overflow
     * BEFORE the compare keeps signed-arithmetic UB off the table —
     * n * mult could wrap negative on pathological input and sneak
     * past the `bytes < 128K` check. */
    if (n > (256LL * 1024 * 1024) / mult) {
        return "BotShieldShmSize: value too large (overflows size_t)";
    }
    apr_int64_t bytes = n * mult;
    if (bytes < 128 * 1024 || bytes > (256LL * 1024 * 1024)) {
        return "BotShieldShmSize: must be between 128K and 256M";
    }
    scfg->shm_size = (apr_size_t)bytes;
    return NULL;
}

static const char *bs_set_flagged_capacity(cmd_parms *cmd, void *dconf,
                                           const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    long n;
    if (!bs_parse_int_bounded(arg, BS_FLAGGED_MIN_SLOTS,
                              BS_FLAGGED_MAX_SLOTS, 10, &n)) {
        return apr_psprintf(cmd->pool,
            "BotShieldFlaggedIPCapacity: must be an integer %d..%d",
            BS_FLAGGED_MIN_SLOTS, BS_FLAGGED_MAX_SLOTS);
    }
    scfg->flagged_capacity = (int)n;
    return NULL;
}

/* BotShieldFlagIP <flag_name>[,<flag_name>...] [ttl_seconds]
 * Any request that reaches this scope causes the client IP to be
 * inserted (or merged) into the flagged-IP table with the named bits.
 * Designed for explicit honeypot / scanner / test endpoints. */
static const char *bs_set_flag_ip(cmd_parms *cmd, void *cfg_v,
                                  const char *names, const char *ttl_str)
{
    bs_dir_cfg *cfg = cfg_v;
    const char *err = NULL;
    apr_uint32_t bits = bs_parse_flag_names(cmd->pool, names, &err);
    if (err) return apr_psprintf(cmd->pool, "BotShieldFlagIP: %s", err);
    if (!bits) return "BotShieldFlagIP: no flag bits resolved";

    int ttl = 3600;
    if (ttl_str && *ttl_str) {
        long n;
        if (!bs_parse_int_bounded(ttl_str, 60, 30 * 86400, 8, &n)) {
            return "BotShieldFlagIP: ttl must be an integer 60..2592000 "
                   "(seconds)";
        }
        ttl = (int)n;
    }
    cfg->flag_on_match     = bits;
    cfg->flag_on_match_ttl = ttl;
    return NULL;
}

/* Accept ".example.com" (leading dot for cross-subdomain) or "example.com"
 * (host-only). Empty string clears the directive, reverting to host-only.
 *
 * Security review #3: the value is embedded into both the Set-Cookie
 * header and (via bs_challenge_json) inline JSON in the interstitial
 * script. The previous check only rejected whitespace + semicolons,
 * which would have let quotes/backslashes through and given a
 * config-time script-injection footgun to any templating system
 * that ever hands this directive a non-human-typed value. Tighten
 * to DNS hostname charset only: [a-zA-Z0-9.-], max 253 chars per
 * RFC 1035. Leading dot permitted (cookie-domain convention). */
static const char *bs_set_cookie_domain(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg) return "BotShieldCookieDomain requires an argument";
    if (!*arg) { cfg->cookie_domain = NULL; return NULL; }

    apr_size_t len = strlen(arg);
    if (len > 253) {
        return apr_psprintf(cmd->pool,
            "BotShieldCookieDomain: '%s' exceeds 253-char RFC 1035 limit",
            arg);
    }
    /* First char may be '.' (leading-dot domain) or an alphanumeric. */
    for (apr_size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)arg[i];
        int ok = isalnum(c) || c == '.' || c == '-';
        if (!ok) {
            return apr_psprintf(cmd->pool,
                "BotShieldCookieDomain: '%s' contains a character "
                "outside [a-zA-Z0-9.-] — hostnames only", arg);
        }
    }
    cfg->cookie_domain = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *bs_set_prompt(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    if (!arg || !*arg) return "BotShieldPromptText cannot be empty";
    ((bs_dir_cfg *)cfg_v)->prompt = arg;
    return NULL;
}

static const char *bs_set_logo_label(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->logo_label = arg ? arg : "";
    return NULL;
}

/* Slurp a file at config-parse time and hand back its bytes allocated out
 * of the config pool. Size-capped so a misbehaving config can't blow up
 * Apache startup. Returns an error string on failure, NULL on success. */
static const char *bs_load_config_file(cmd_parms *cmd,
                                       const char *directive,
                                       const char *path,
                                       apr_size_t max_bytes,
                                       const char **out_content)
{
    apr_file_t *f = NULL;
    apr_status_t rv;
    apr_finfo_t info;

    rv = apr_file_open(&f, path, APR_FOPEN_READ | APR_FOPEN_BINARY,
                       APR_OS_DEFAULT, cmd->pool);
    if (rv != APR_SUCCESS) {
        char errbuf[256];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        return apr_psprintf(cmd->pool,
            "%s: cannot open '%s': %s", directive, path, errbuf);
    }
    rv = apr_file_info_get(&info, APR_FINFO_SIZE, f);
    if (rv != APR_SUCCESS) {
        apr_file_close(f);
        return apr_psprintf(cmd->pool,
            "%s: cannot stat '%s'", directive, path);
    }
    if (info.size <= 0 || (apr_size_t)info.size > max_bytes) {
        apr_file_close(f);
        return apr_psprintf(cmd->pool,
            "%s: '%s' size %" APR_OFF_T_FMT
            " is outside 1..%" APR_SIZE_T_FMT " bytes",
            directive, path, info.size, max_bytes);
    }
    char *buf = apr_palloc(cmd->pool, (apr_size_t)info.size + 1);
    apr_size_t n = (apr_size_t)info.size;
    rv = apr_file_read(f, buf, &n);
    apr_file_close(f);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
            "%s: read error on '%s'", directive, path);
    }
    buf[n] = '\0';
    *out_content = buf;
    return NULL;
}

static const char *bs_set_logo_file(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    return bs_load_config_file(cmd, "BotShieldLogoFile", arg,
                               BS_MAX_LOGO_BYTES, &cfg->logo_svg);
}

static const char *bs_set_help(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    bs_dir_cfg *cfg = cfg_v;
    if (strcasecmp(arg, "off") == 0)         cfg->help_mode = BS_HELP_OFF;
    else if (strcasecmp(arg, "on") == 0)     cfg->help_mode = BS_HELP_ON;
    else if (strcasecmp(arg, "button") == 0) cfg->help_mode = BS_HELP_BUTTON;
    else return "BotShieldHelp must be one of: off, on, button";
    return NULL;
}

static const char *bs_set_help_file(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    return bs_load_config_file(cmd, "BotShieldHelpFile", arg,
                               BS_MAX_HELP_BYTES, &cfg->help_html);
}

static const char *bs_set_challenge_file(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    const char *err = bs_load_config_file(cmd, "BotShieldChallengeFile", arg,
                                          BS_MAX_PAGE_BYTES, &cfg->challenge_html);
    if (err) return err;
    if (!strstr(cfg->challenge_html, BS_WIDGET_MARKER)) {
        return apr_psprintf(cmd->pool,
            "BotShieldChallengeFile: '%s' contains no '%s' marker where the "
            "verification widget should be inserted", arg, BS_WIDGET_MARKER);
    }
    return NULL;
}

/* ======================================================================
 * Crypto helpers, challenge struct, algorithm registry, issue/verify.
 * ====================================================================== */

/* --- Low-level crypto wrappers --- */

#define BS_SHA256_LEN 32

static void bs_sha256(const unsigned char *data, apr_size_t len,
                      unsigned char out[BS_SHA256_LEN])
{
    unsigned int outlen = BS_SHA256_LEN;
    EVP_Digest(data, (size_t)len, out, &outlen, EVP_sha256(), NULL);
}

static void bs_hmac_sha256(const unsigned char *key, apr_size_t keylen,
                           const unsigned char *data, apr_size_t datalen,
                           unsigned char out[BS_SIG_BYTES])
{
    unsigned int outlen = BS_SIG_BYTES;
    HMAC(EVP_sha256(), key, (int)keylen, data, datalen, out, &outlen);
}

/* Constant-time equality. Returns 1 on equal, 0 on not. */
static int bs_ct_equal(const unsigned char *a, const unsigned char *b,
                       apr_size_t len)
{
    unsigned char diff = 0;
    for (apr_size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* Hex helpers. Writes 2*len chars + NUL. */
static void bs_to_hex(const unsigned char *in, apr_size_t len, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (apr_size_t i = 0; i < len; i++) {
        out[i*2]   = H[(in[i] >> 4) & 0xF];
        out[i*2+1] = H[in[i] & 0xF];
    }
    out[len*2] = '\0';
}

/* Bounded integer parser for pre-HMAC cookie fields (security review
 * #2). atoi() and strtoul(..., NULL, 10) both invoke undefined
 * behavior on overflow per C11 §7.22.1 — atoi because the result
 * doesn't fit in int, strtoul because we never check errno. Our
 * ASan/UBSan fuzz can't reliably catch that because the dangerous
 * work happens inside libc, not in instrumented project code.
 *
 * Returns 1 on a clean parse within [min_val, max_val]; 0 otherwise.
 * The out pointer is left untouched on failure so callers can treat
 * 0-returns as "reject this cookie" without dancing around partial
 * state. Accepts optional leading + only; negative values must fall
 * within min_val to be accepted (no underflow tricks).
 *
 * max_len is a hard cap on the digit-string length — rejects gigantic
 * inputs before they reach strtol. A 64-bit long can hold up to 19
 * decimal digits, so any cookie field longer than that is obviously
 * junk and we bail without invoking libc at all. */
static int bs_parse_int_bounded(const char *s,
                                long min_val, long max_val,
                                apr_size_t max_len,
                                long *out)
{
    if (!s || !*s) return 0;
    apr_size_t len = strlen(s);
    if (len > max_len) return 0;

    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0)        return 0;  /* ERANGE or other libc complaint */
    if (!end || *end != '\0') return 0;  /* trailing junk */
    if (v < min_val || v > max_val) return 0;
    *out = v;
    return 1;
}

/* 32-bit unsigned variant for the flags field. strtoul also invokes
 * UB on overflow if errno isn't checked — same hardening. */
static int bs_parse_uint32_bounded(const char *s,
                                   apr_size_t max_len,
                                   apr_uint32_t *out)
{
    if (!s || !*s) return 0;
    if (strlen(s) > max_len) return 0;

    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0)        return 0;
    if (!end || *end != '\0') return 0;
    if (v > UINT32_MAX)    return 0;
    *out = (apr_uint32_t)v;
    return 1;
}

/* int64 variant for expires_at / challenged_at (apr_time_t seconds).
 * Same shape; max_len caps at 19 (largest int64 decimal expansion). */
static int bs_parse_int64_bounded(const char *s,
                                  apr_int64_t min_val,
                                  apr_int64_t max_val,
                                  apr_int64_t *out)
{
    if (!s || !*s) return 0;
    if (strlen(s) > 19) return 0;

    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno != 0)        return 0;
    if (!end || *end != '\0') return 0;
    if ((apr_int64_t)v < min_val || (apr_int64_t)v > max_val) return 0;
    *out = (apr_int64_t)v;
    return 1;
}

/* Returns 1 on success, 0 on malformed. out_len is bytes expected. */
static int bs_from_hex(const char *in, apr_size_t out_len, unsigned char *out)
{
    for (apr_size_t i = 0; i < out_len; i++) {
        int hi = -1, lo = -1;
        char c = in[i*2];
        if      (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        c = in[i*2+1];
        if      (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* --- Canonical form for HMAC input ---
 *
 * "v|alg|salthex|noncehex|difficulty|expires_at
 *  |score|flags|pass_s|pass_f|pass_c|challenged_at|auto"   (13 fields)
 *
 * Deterministic, ASCII, field-delimited. Both sign and verify produce this
 * exact string from the challenge struct — if a byte changes, the HMAC
 * changes, and tampering is detected. The rep fields follow the challenge
 * fields so existing M2 code reading positions 0..5 still lines up; the
 * M7 `auto` marker is appended at position 12 after challenged_at. */
static const char *bs_challenge_canonical(apr_pool_t *p,
                                          const bs_challenge *ch)
{
    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    bs_to_hex(ch->salt,  BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch->nonce, BS_NONCE_BYTES, nonce_hex);
    return apr_psprintf(p,
        "%d|%s|%s|%s|%d|%" APR_TIME_T_FMT
        "|%d|%u|%d|%d|%d|%" APR_TIME_T_FMT "|%d",
        ch->version, ch->alg_name, salt_hex, nonce_hex,
        ch->difficulty, ch->expires_at,
        ch->rep.score, (unsigned)ch->rep.flags,
        ch->rep.passes_silent, ch->rep.passes_form, ch->rep.passes_captcha,
        ch->rep.challenged_at,
        ch->auto_tier ? 1 : 0);
}

/* --- Algorithm: sha256-zeros ---
 *
 * The PoW our M1 widget already uses, now wrapped in the registry.
 * issue: pick salt+nonce, record in the challenge. (HMAC signing is done
 *   by the top-level issuer, not the per-alg callback.)
 * verify: check that SHA-256(salt || nonce || counter) has `difficulty`
 *   leading hex zero digits. */
static const char *bs_sha256_zeros_issue(const bs_dir_cfg *cfg,
                                         bs_challenge *out)
{
    (void)cfg;
    if (RAND_bytes(out->salt,  BS_SALT_BYTES)  != 1) return "RAND_bytes(salt)";
    if (RAND_bytes(out->nonce, BS_NONCE_BYTES) != 1) return "RAND_bytes(nonce)";
    return NULL;
}

static const char *bs_sha256_zeros_verify(const bs_challenge *ch,
                                          const char *counter_str)
{
    if (!counter_str || !*counter_str) return "empty counter";

    /* Accumulate salt || nonce || counter into a stack buffer. Salt+nonce
     * is 24 bytes; counter is a decimal ASCII integer, capped well below
     * 32 bytes by the cookie-size limit. */
    unsigned char buf[BS_SALT_BYTES + BS_NONCE_BYTES + 64];
    apr_size_t n = 0;
    memcpy(buf + n, ch->salt,  BS_SALT_BYTES);  n += BS_SALT_BYTES;
    memcpy(buf + n, ch->nonce, BS_NONCE_BYTES); n += BS_NONCE_BYTES;
    apr_size_t cslen = strlen(counter_str);
    if (cslen > sizeof(buf) - n) return "counter too long";
    memcpy(buf + n, counter_str, cslen); n += cslen;

    unsigned char digest[BS_SHA256_LEN];
    bs_sha256(buf, n, digest);

    /* Leading `difficulty` hex zero digits = first `difficulty`/2 bytes are
     * 0x00, and if difficulty is odd the high nibble of the next byte is 0. */
    int full_bytes = ch->difficulty / 2;
    int need_half  = ch->difficulty & 1;
    for (int i = 0; i < full_bytes; i++) {
        if (digest[i] != 0) return "insufficient leading zeros";
    }
    if (need_half && (digest[full_bytes] >> 4) != 0) {
        return "insufficient leading zeros";
    }
    return NULL;
}

/* --- Algorithm: captcha passthrough (M8) ---
 *
 * Captcha-earned cookies use the same signed envelope as PoW-earned
 * cookies, but there's no client-side PoW counter to check — provider
 * siteverify already confirmed the solve before the cookie was issued,
 * and the HMAC on the envelope protects every field. The verify fn is
 * a noop: counter presence is required (to keep the 15-field cookie
 * shape), but its contents are ignored. */
static const char *bs_captcha_issue(const bs_dir_cfg *cfg,
                                    bs_challenge *out)
{
    (void)cfg;
    /* Random salt/nonce so two captcha cookies issued to the same user
     * at the same second don't collide in logs or caches. Difficulty
     * is unused but valid (kept at whatever the handler passed in). */
    if (RAND_bytes(out->salt,  BS_SALT_BYTES)  != 1) return "RAND_bytes(salt)";
    if (RAND_bytes(out->nonce, BS_NONCE_BYTES) != 1) return "RAND_bytes(nonce)";
    return NULL;
}

static const char *bs_captcha_verify_noop(const bs_challenge *ch,
                                          const char *counter_str)
{
    (void)ch;
    if (!counter_str || !*counter_str) return "empty counter";
    /* Anything non-empty passes — the captcha provider already did the
     * real work. */
    return NULL;
}

/* --- Algorithm registry ---
 *
 * Static dispatch table. sha256-zeros is the PoW tier; captcha-turnstile
 * is the captcha tier's cookie alg — same signed envelope, provider
 * already did the client-side work. Reserved slots flip from 0→1 by
 * providing the two callbacks; no changes to the protocol or verify
 * code path. */
static const bs_pow_algorithm bs_algorithms[] = {
    { "sha256-zeros",          1, bs_sha256_zeros_issue, bs_sha256_zeros_verify },
    { "captcha-turnstile",     1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-hcaptcha",      1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-recaptcha-v2",  1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-recaptcha-v3",  1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-friendly",      1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-geetest",       1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "sha384-zeros",          0, NULL, NULL },
    { "sha512-zeros",      0, NULL, NULL },
    { "pbkdf2-sha256",     0, NULL, NULL },
    { "argon2id",          0, NULL, NULL },
    { NULL,                0, NULL, NULL }
};

static const bs_pow_algorithm *bs_find_algorithm(const char *name)
{
    for (int i = 0; bs_algorithms[i].name; i++) {
        if (strcmp(bs_algorithms[i].name, name) == 0) {
            return &bs_algorithms[i];
        }
    }
    return NULL;
}

/* --- Captcha provider registry (M8) ---
 *
 * Six providers built in today:
 *
 *   Render pattern (inline div + provider script renders a visible
 *   widget the user clicks):
 *     - turnstile  (Cloudflare)
 *     - hcaptcha
 *     - recaptcha-v2
 *     - friendly   (Friendly Captcha; no user click — invisible PoW)
 *
 *   Execute pattern (no visible widget; provider script runs in the
 *   background and returns a token):
 *     - recaptcha-v3  (adds numeric "score" field we threshold via
 *       BotShieldRecaptchaV3MinScore)
 *
 *   initGeetest4 pattern (imperative init, slider-based widget):
 *     - geetest      (v4; response is {"result":"success"/"fail",...}
 *       not {"success":bool,...}, and server signs lot_number with
 *       HMAC-SHA256(captcha_key) — provider-specific siteverify_fn)
 *
 * The interstitial render code picks one of three templates based on
 * provider name. The siteverify shim + json-c parser are shared across
 * the five Google-family providers; GeeTest has its own siteverify_fn
 * via the fn-pointer slot on the provider row.
 *
 * widget_script_url for v3 is the base URL — the render code appends
 * "?render=<sitekey>" at render time because v3's script needs the
 * sitekey baked into the URL query, not just the widget div. */
static bs_captcha_result bs_geetest_siteverify(request_rec *r,
    const bs_captcha_provider *prov, const unsigned char *secret,
    apr_size_t secret_len, const char *token, int timeout_ms,
    const char **out_details, long *out_http_code, double *out_score,
    const char **out_hostname, const char **out_action);

static const bs_captcha_provider bs_providers[] = {
    { "turnstile",    1,
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      "cf-turnstile-response",
      "https://challenges.cloudflare.com/turnstile/v0/api.js",
      "cf-turnstile",
      NULL, NULL },
    { "hcaptcha",     1,
      "https://api.hcaptcha.com/siteverify",
      "h-captcha-response",
      "https://js.hcaptcha.com/1/api.js",
      "h-captcha",
      NULL, NULL },
    { "recaptcha-v2", 1,
      "https://www.google.com/recaptcha/api/siteverify",
      "g-recaptcha-response",
      "https://www.google.com/recaptcha/api.js",
      "g-recaptcha",
      NULL, NULL },
    { "recaptcha-v3", 1,
      "https://www.google.com/recaptcha/api/siteverify",
      "g-recaptcha-response",
      "https://www.google.com/recaptcha/api.js",
      "" /* no widget class — v3 uses grecaptcha.execute(), not a div */,
      NULL, NULL },
    { "friendly",     1,
      "https://api.friendlycaptcha.com/api/v1/siteverify",
      "frc-captcha-solution",
      "https://cdn.jsdelivr.net/npm/friendly-challenge/widget.min.js",
      "frc-captcha",
      "solution" /* Friendly Captcha's POST field name is `solution` */,
      NULL },
    { "geetest",      1,
      "https://gcaptcha4.geetest.com/validate",
      "geetest-token" /* the hidden form input carrying a JSON blob */,
      "https://static.geetest.com/v4/gt4.js",
      "" /* programmatic init via initGeetest4() */,
      NULL /* shared body shape not used — custom fn handles signing */,
      bs_geetest_siteverify },
    { NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL }
};

static const bs_captcha_provider *bs_find_provider(const char *name)
{
    for (int i = 0; bs_providers[i].name; i++) {
        if (strcmp(bs_providers[i].name, name) == 0) {
            return &bs_providers[i];
        }
    }
    return NULL;
}

/* ======================================================================
 * Shared memory: flagged-IP table (M5.1) + Bloom reservations (M5.2).
 * ====================================================================== */

/* SipHash-2-4 — DoS-resistant hash for the flagged-IP bucket index.
 * Key is generated in post-config and lives in the SHM header, so
 * attackers can't precompute colliding IPs to evict stored entries. */

static inline apr_uint64_t bs_rotl64(apr_uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

#define BS_SIPROUND() do {                                         \
    v0 += v1; v1 = bs_rotl64(v1,13); v1 ^= v0; v0 = bs_rotl64(v0,32); \
    v2 += v3; v3 = bs_rotl64(v3,16); v3 ^= v2;                       \
    v0 += v3; v3 = bs_rotl64(v3,21); v3 ^= v0;                       \
    v2 += v1; v1 = bs_rotl64(v1,17); v1 ^= v2; v2 = bs_rotl64(v2,32); \
} while (0)

static apr_uint64_t bs_siphash24(const unsigned char key[16],
                                 const unsigned char *data, apr_size_t len)
{
    apr_uint64_t k0, k1;
    memcpy(&k0, key,     8);
    memcpy(&k1, key + 8, 8);

    apr_uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    apr_uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    apr_uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    apr_uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const unsigned char *end = data + (len - (len & 7));
    for (; data != end; data += 8) {
        apr_uint64_t m;
        memcpy(&m, data, 8);
        v3 ^= m;
        BS_SIPROUND(); BS_SIPROUND();
        v0 ^= m;
    }

    apr_uint64_t b = ((apr_uint64_t)len) << 56;
    switch (len & 7) {
        case 7: b |= ((apr_uint64_t)data[6]) << 48; /* fallthrough */
        case 6: b |= ((apr_uint64_t)data[5]) << 40; /* fallthrough */
        case 5: b |= ((apr_uint64_t)data[4]) << 32; /* fallthrough */
        case 4: b |= ((apr_uint64_t)data[3]) << 24; /* fallthrough */
        case 3: b |= ((apr_uint64_t)data[2]) << 16; /* fallthrough */
        case 2: b |= ((apr_uint64_t)data[1]) <<  8; /* fallthrough */
        case 1: b |= ((apr_uint64_t)data[0]);       /* fallthrough */
        case 0: break;
    }
    v3 ^= b;
    BS_SIPROUND(); BS_SIPROUND();
    v0 ^= b;
    v2 ^= 0xff;
    BS_SIPROUND(); BS_SIPROUND(); BS_SIPROUND(); BS_SIPROUND();
    return v0 ^ v1 ^ v2 ^ v3;
}
#undef BS_SIPROUND

/* Parse r->useragent_ip into a 16-byte network-order buffer. IPv4
 * becomes v6-mapped (::ffff:a.b.c.d) so the table is keyed uniformly.
 * Returns 1 on success, 0 if the string is unparseable. */
static int bs_parse_client_ip(const char *ip_str, unsigned char out[16])
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
static void bs_mask_ipv6_prefix(unsigned char ip[16], int prefix_bits)
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

static const char *bs_set_bloom_ips(cmd_parms *cmd, void *dconf,
                                    const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    long n;
    if (!bs_parse_int_bounded(arg, BS_BLOOM_MIN_IPS,
                              BS_BLOOM_MAX_IPS, 12, &n)) {
        return apr_psprintf(cmd->pool,
            "BotShieldBloomIPs: must be an integer %d..%d",
            BS_BLOOM_MIN_IPS, BS_BLOOM_MAX_IPS);
    }
    scfg->bloom_ips = (int)n;
    return NULL;
}

static const char *bs_set_bloom_window(cmd_parms *cmd, void *dconf,
                                       const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    long n;
    if (!bs_parse_int_bounded(arg, BS_BLOOM_MIN_WINDOW,
                              BS_BLOOM_MAX_WINDOW, 10, &n)) {
        return apr_psprintf(cmd->pool,
            "BotShieldBloomWindow: must be an integer %d..%d (seconds)",
            BS_BLOOM_MIN_WINDOW, BS_BLOOM_MAX_WINDOW);
    }
    scfg->bloom_window_secs = (int)n;
    return NULL;
}

static const char *bs_set_ipv6_prefix(cmd_parms *cmd, void *dconf,
                                      const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (end == arg || *end != '\0' || n < 0 || n > 128) {
        return apr_psprintf(cmd->pool,
            "BotShieldIPv6PrefixLen: expected an integer 0..128, got '%s'",
            arg);
    }
    scfg->ipv6_prefix_bits = (int)n;
    return NULL;
}

/* --- SHM lifecycle ---
 *
 * post-config (server-wide) runs twice; we do real init on the second
 * pass. Anonymous APR SHM is sufficient since Apache's children fork
 * from the parent and inherit the mapping — no explicit attach needed
 * in worker processes. Graceful restart rotates pconf, which cleans up
 * the old segment and its mutex automatically.
 *
 * For file-backed SHM (needed when Apache is configured to use a
 * non-fork MPM variant), apr_global_mutex_child_init is called from
 * our child-init hook to re-attach. */

static apr_status_t bs_shm_cleanup(void *unused)
{
    (void)unused;
    /* apr_shm_destroy/mutex_destroy are driven by pool cleanups
     * registered when we created them; nothing to do here beyond
     * resetting the runtime pointers so a subsequent post-config
     * starts fresh. */
    memset(&bs_shm, 0, sizeof(bs_shm));
    return APR_SUCCESS;
}

/* Context struct used by the M6 save-on-shutdown pool cleanup. Full
 * definition is here so post_config can sizeof() it; the implementation
 * (bs_state_load/save/cleanup) lives further down where the flagged-IP
 * slot type and Bloom buffers are already in scope. */
typedef struct bs_state_cleanup_ctx {
    apr_pool_t *pool;
    server_rec *server;
    const char *path;
} bs_state_cleanup_ctx;

static void          bs_state_load(apr_pool_t *p, server_rec *s,
                                   const char *path);
static apr_status_t  bs_state_cleanup(void *data);
static apr_status_t  bs_watchdog_save_cb(int state, void *data,
                                         apr_pool_t *pool);
static const char   *bs_get_cookie_value(request_rec *r, const char *name);

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
 *   4. No match → fake-<name>; apply BS_PENALTY_FAKE_CRAWLER so the
 *      request sails into captcha tier with a loud reason.
 *   5. Classified but no ranges loaded → "unverified" — log, don't
 *      score either way. Operator hasn't authorized verification
 *      for this crawler yet.
 *
 * The UA classifier is a vanilla trie (no Aho-Corasick failure
 * links — simpler to read, indistinguishable on realistic UAs).
 * A prefilter short-circuits non-crawler traffic in ~1 µs so the
 * trie only walks for bot-ish UAs. Designed to scale to ~400
 * patterns (Cloudflare Radar's worked list) without the linear-scan
 * wall we'd hit otherwise.
 *
 * Pure read-only at request time; all state is populated in
 * post_config and immutable thereafter. The module never touches
 * the network for this feature — ranges come from disk files that
 * operators refresh out-of-band via tools/refresh-crawler-ranges.sh.
 * ====================================================================== */

#define BS_PENALTY_FAKE_CRAWLER  100   /* enough to force captcha tier */
#define BS_CREDIT_VERIFIED       (-1000) /* dominates any other penalty */

/* --- UA classifier: trie with case-insensitive char match --- */

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

typedef struct {
    apr_pool_t *pool;               /* for node allocation */
    bs_ua_trie_node *root;
    int n_patterns;                 /* for logging */
} bs_ua_classifier;

static bs_ua_classifier *bs_ua_classifier_create(apr_pool_t *p)
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

/* Register a substring pattern. The pattern matches anywhere in a UA
 * (case-insensitive). Caller owns the memory for `name` — it must
 * outlive the classifier (typically a static string or pool-alloc
 * on the same pool). */
static apr_status_t bs_ua_classifier_add(bs_ua_classifier *c,
                                         const char *name,
                                         const char *pattern)
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

/* Cheap prefilter: does the UA contain any bot-ish token? Non-bot
 * UAs skip the trie walk entirely (~1 µs regardless of pattern
 * count). Tokens chosen to cover the overwhelming majority of
 * legitimate crawlers' UAs while being uncommon in human browsers. */
static int bs_ua_is_botlike(const char *ua)
{
    if (!ua) return 0;
    /* strcasestr is a GNU extension but present on every Linux we
     * target and on FreeBSD/macOS. Portable enough for our build. */
    return strcasestr(ua, "bot")    != NULL
        || strcasestr(ua, "crawl")  != NULL
        || strcasestr(ua, "spider") != NULL
        || strcasestr(ua, "fetch")  != NULL
        || strcasestr(ua, "slurp")  != NULL;
}

/* Classify: walk the trie from each position in the UA until we find
 * a terminal node. Returns the matched name (borrowed) or NULL.
 * O(|ua| × avg-depth) worst case; in practice most positions die
 * within the first few chars because the trie is sparse. */
static const char *bs_ua_classify(const bs_ua_classifier *c, const char *ua)
{
    if (!c || !ua || !*ua) return NULL;
    if (!bs_ua_is_botlike(ua)) return NULL;   /* hot path */

    for (const char *start = ua; *start; start++) {
        bs_ua_trie_node *n = c->root;
        for (const char *p = start; *p; p++) {
            n = bs_ua_trie_walk(n, (unsigned char)*p);
            if (!n) break;
            if (n->name) return n->name;   /* earliest / shortest match wins */
        }
    }
    return NULL;
}

/* --- Built-in crawler UA patterns ---
 *
 * Only crawlers with known-good bundled or operator-curated CIDR
 * ranges should go here — registering a UA with no ranges means the
 * module matches the UA but has nothing to verify against, which
 * surfaces as a perpetual "unverified" log entry. E2 will add
 * entries for the rate-limit-only crawlers (GPTBot, ClaudeBot, etc.)
 * that are classified but not verified.
 */
typedef struct {
    const char *name;       /* internal key; matches ranges-file basename */
    const char *pattern;    /* substring expected in UA (case-insensitive) */
} bs_builtin_crawler;

static const bs_builtin_crawler bs_builtin_crawlers[] = {
    { "googlebot", "Googlebot" },
    { "bingbot",   "bingbot"   },
    { "applebot",  "Applebot"  },
    { NULL, NULL }
};

/* --- CIDR list loader ---
 *
 * Plain-text format, one CIDR per line, # for comments, empty
 * lines OK. Accepts both IPv4 and IPv6. apr_ipsubnet_create parses
 * the CIDR; we hold them in an apr_array_header_t of
 * apr_ipsubnet_t* that the request-time matcher scans.
 *
 * Max file size: 1 MiB. A ranges file that big would mean thousands
 * of CIDRs, which no published provider list approaches; acts as a
 * sanity cap on accidental misconfiguration (pointing at a JSON
 * file, a log, etc.). */
#define BS_CRAWLER_MAX_RANGES_FILE  (1024 * 1024)

static apr_status_t bs_crawler_load_ranges(apr_pool_t *p,
                                           const char *path,
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

        /* apr_ipsubnet_create takes "ip/mask" or "ip/prefix-bits".
         * Split in place. */
        char *slash = strchr(s, '/');
        apr_ipsubnet_t *net = NULL;
        if (slash) {
            *slash = '\0';
            const char *mask = slash + 1;
            rv = apr_ipsubnet_create(&net, s, mask, p);
        } else {
            /* Bare IP — treat as /32 or /128 depending on family. */
            rv = apr_ipsubnet_create(&net, s, NULL, p);
        }
        if (rv != APR_SUCCESS) {
            char errbuf[256];
            apr_strerror(rv, errbuf, sizeof(errbuf));
            apr_file_close(f);
            *out_err = apr_psprintf(p,
                "'%s' line %d: invalid CIDR: %s", path, lineno, errbuf);
            return rv;
        }
        APR_ARRAY_PUSH(arr, apr_ipsubnet_t *) = net;
    }
    apr_file_close(f);

    if (arr->nelts == 0) {
        *out_err = apr_psprintf(p, "'%s' contained no CIDR entries", path);
        return APR_EINVAL;
    }

    *out = arr;
    return APR_SUCCESS;
}

/* Test a client IP (from r->useragent_ip) against a loaded CIDR list. */
static int bs_crawler_ip_in_ranges(const apr_array_header_t *ranges,
                                   request_rec *r)
{
    if (!ranges || ranges->nelts == 0) return 0;
    /* Convert the client IP string into an apr_sockaddr_t that
     * apr_ipsubnet_test can inspect. The client IP has already been
     * normalized by mod_remoteip (if wired) — we take it as-is. */
    const char *ip_str = r->useragent_ip;
    if (!ip_str || !*ip_str) return 0;

    apr_sockaddr_t *sa = NULL;
    apr_status_t rv = apr_sockaddr_info_get(&sa, ip_str,
                                            APR_UNSPEC, 0, 0, r->pool);
    if (rv != APR_SUCCESS || !sa) return 0;

    for (int i = 0; i < ranges->nelts; i++) {
        apr_ipsubnet_t *net = APR_ARRAY_IDX(ranges, i, apr_ipsubnet_t *);
        if (apr_ipsubnet_test(net, sa)) return 1;
    }
    return 0;
}

/* --- Request-time entry point ---
 *
 * Called from bs_run_builtin_heuristics. Does nothing unless E1 is
 * enabled via BotShieldLegitCrawlers on. Emits at most one
 * bs_score_add call per request (dominant penalty/credit).
 */
static void bs_check_legit_crawler(request_rec *r,
                                   const bs_dir_cfg *cfg)
{
    (void)cfg;
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg || !scfg->crawlers_enabled) return;
    if (!scfg->crawler_classifier) return;

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    const char *name = bs_ua_classify(scfg->crawler_classifier, ua);
    if (!name) return;

    /* Look up the ranges this crawler has loaded. */
    apr_array_header_t *ranges = NULL;
    if (scfg->crawler_ranges) {
        ranges = apr_hash_get(scfg->crawler_ranges, name, APR_HASH_KEY_STRING);
    }

    if (!ranges) {
        /* Crawler pattern matched but no ranges file configured or
         * loadable. Don't score either way — operator hasn't
         * authorized verification for this crawler. Metric records
         * the event for ops visibility. */
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->crawler_unverified_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, 0, 0,
            apr_pstrcat(r->pool, "crawler-unverified:", name, NULL));
        return;
    }

    if (bs_crawler_ip_in_ranges(ranges, r)) {
        /* Verified — large negative penalty dominates tier decision. */
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->crawler_verified_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, BS_CREDIT_VERIFIED, 0,
            apr_pstrcat(r->pool, "verified-crawler:", name, NULL));
    } else {
        /* Fake: claims crawler UA but IP isn't in that crawler's
         * published ranges. Large penalty drives the request straight
         * to captcha tier; the reason string surfaces in the log. */
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->crawler_fake_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, BS_PENALTY_FAKE_CRAWLER, 3600,
            apr_pstrcat(r->pool, "fake-", name, NULL));
    }
}

static int bs_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    (void)plog; (void)ptemp;

    /* Apache calls post-config twice; skip the first pass so we don't
     * create the SHM segment and then immediately discard it. */
    void *already;
    apr_pool_userdata_get(&already, "bs_post_config_done",
                          s->process->pool);
    if (!already) {
        apr_pool_userdata_set((const void *)1, "bs_post_config_done",
                              apr_pool_cleanup_null,
                              s->process->pool);
        return OK;
    }

    /* libcurl global init: must run once before any worker thread
     * touches a curl easy handle. curl_global_init is explicitly
     * documented as not thread-safe, so the per-request lazy-init
     * guard we used to have (bs_curl_ensure_init) had a race under
     * mpm_event where two workers could both see the flag unset and
     * race the init. Doing it here, in the parent process pre-fork
     * and single-threaded, is the only sound place for it. Children
     * inherit libcurl's global state via fork per libcurl's docs; no
     * additional init in bs_child_init is needed. curl_global_cleanup
     * is intentionally not paired — the process exits when Apache
     * exits, and the kernel reaps the handle.
     *
     * Fail loudly if curl global init fails: the captcha tier uses
     * libcurl on every verify, and curl_easy_init after a failed
     * global init is undefined behavior. Better to refuse to start
     * than to silently serve broken captcha. */
    CURLcode curl_rv = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_rv != CURLE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: curl_global_init failed: %s (CURLcode=%d). "
            "Refusing to start — the captcha tier needs working libcurl.",
            curl_easy_strerror(curl_rv), (int)curl_rv);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    bs_server_cfg *scfg = ap_get_module_config(s->module_config,
                                               &botshield_module);

    /* Compute SHM layout: header + flagged-IP table + two Bloom buffers
     * + M8.1 captcha rate-limit ring + M8.1 captcha log-suppress ring.
     * Each Bloom buffer is sized to hit ~1% FP at the configured
     * capacity (10 bits/IP, rounded up to a multiple of 8 so we can
     * atomic-OR on aligned u64 slots). The M8.1 rings are fixed-size
     * power-of-two arrays of bs_cv_slot (uint64 each); both rings are
     * module-global (not per-scope) since they guard one endpoint. */
    apr_size_t header_bytes = sizeof(bs_shm_header);
    apr_size_t table_bytes  = (apr_size_t)scfg->flagged_capacity
                              * sizeof(bs_flagged_ip_slot);

    apr_size_t bloom_bits   = (apr_size_t)scfg->bloom_ips
                              * BS_BLOOM_BITS_PER_IP;
    apr_size_t bloom_bytes  = (bloom_bits + 63) / 64 * 8;   /* u64-aligned */
    apr_size_t cv_rate_bytes = (apr_size_t)BS_DEFAULT_CV_RATE_SLOTS
                               * sizeof(bs_cv_slot);
    apr_size_t cv_log_bytes  = (apr_size_t)BS_DEFAULT_CV_LOG_SLOTS
                               * sizeof(bs_cv_slot);
    apr_size_t metrics_bytes = sizeof(bs_metrics);
    apr_size_t total_bytes  = header_bytes + table_bytes + 2 * bloom_bytes
                              + cv_rate_bytes + cv_log_bytes
                              + metrics_bytes;

    if (scfg->shm_size < total_bytes) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: BotShieldShmSize %" APR_SIZE_T_FMT
            " is too small; needs at least %" APR_SIZE_T_FMT " bytes "
            "(header + %d flagged-IP slots + 2x %" APR_SIZE_T_FMT
            "-byte Bloom buffers for %d IPs + %" APR_SIZE_T_FMT
            " bytes of M8.1 rings + %" APR_SIZE_T_FMT
            " bytes of M9.2 metrics)",
            scfg->shm_size, total_bytes, scfg->flagged_capacity,
            bloom_bytes, scfg->bloom_ips,
            cv_rate_bytes + cv_log_bytes, metrics_bytes);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_status_t rv = apr_shm_create(&bs_shm.shm, scfg->shm_size,
                                     NULL, pconf);
    if (rv != APR_SUCCESS) {
        char errbuf[128];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: apr_shm_create failed: %s", errbuf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    unsigned char *base = apr_shm_baseaddr_get(bs_shm.shm);
    memset(base, 0, scfg->shm_size);

    bs_shm.header = (bs_shm_header *)base;
    bs_shm.header->magic            = BS_SHM_MAGIC;
    bs_shm.header->format_version   = BS_SHM_FORMAT_VERSION;
    bs_shm.header->flagged_capacity = (apr_uint32_t)scfg->flagged_capacity;
    if (RAND_bytes(bs_shm.header->siphash_key,
                   sizeof(bs_shm.header->siphash_key)) != 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: RAND_bytes(siphash_key) failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    bs_shm.flagged_table    = (bs_flagged_ip_slot *)(base + header_bytes);
    bs_shm.flagged_capacity = scfg->flagged_capacity;
    bs_shm.bloom_bufs[0]    = base + header_bytes + table_bytes;
    bs_shm.bloom_bufs[1]    = bs_shm.bloom_bufs[0] + bloom_bytes;
    bs_shm.bloom_buf_bytes  = bloom_bytes;

    /* M8.1 rings follow the Bloom buffers. Both start zeroed by the
     * memset(base) above — a zero slot has window=0 < current_minute,
     * so any insert trips the "roll to new window" branch safely. */
    unsigned char *cv_rate_base =
        bs_shm.bloom_bufs[1] + bloom_bytes;
    unsigned char *cv_log_base =
        cv_rate_base + cv_rate_bytes;
    unsigned char *metrics_base =
        cv_log_base + cv_log_bytes;
    bs_shm.cv_rate_slots      = (bs_cv_slot *)cv_rate_base;
    bs_shm.cv_rate_slot_count = BS_DEFAULT_CV_RATE_SLOTS;
    bs_shm.cv_log_slots       = (bs_cv_slot *)cv_log_base;
    bs_shm.cv_log_slot_count  = BS_DEFAULT_CV_LOG_SLOTS;
    bs_shm.cv_inflight        = &bs_shm.header->cv_inflight;
    /* M9.2: metrics block sits after the log-suppress ring. All counters
     * start at zero thanks to the memset(base) above. */
    bs_shm.metrics            = (bs_metrics *)metrics_base;

    bs_shm.header->bloom_active        = 0;
    bs_shm.header->bloom_buf_bytes     = (apr_uint32_t)bloom_bytes;
    bs_shm.header->bloom_window_secs   = (apr_uint32_t)scfg->bloom_window_secs;
    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    bs_shm.header->bloom_next_rotate   = now + scfg->bloom_window_secs / 2;
    bs_shm.header->cv_rate_slots       = BS_DEFAULT_CV_RATE_SLOTS;
    bs_shm.header->cv_log_slots        = BS_DEFAULT_CV_LOG_SLOTS;
    bs_shm.header->cv_inflight         = 0;

    /* Global mutex protects the narrow insert/evict critical section.
     * Reads don't take the lock — they use the slot seqlock. */
    bs_shm.mutex_filename = apr_psprintf(pconf, "%s/botshield-mutex",
                                         ap_runtime_dir_relative(pconf, ""));
    rv = apr_global_mutex_create(&bs_shm.mutex, bs_shm.mutex_filename,
                                 APR_LOCK_DEFAULT, pconf);
    if (rv != APR_SUCCESS) {
        char errbuf[128];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: apr_global_mutex_create failed: %s", errbuf);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_global_mutex_perms(bs_shm.mutex);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: set_global_mutex_perms failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif

    apr_pool_cleanup_register(pconf, NULL, bs_shm_cleanup,
                              apr_pool_cleanup_null);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: SHM ready: %" APR_SIZE_T_FMT " bytes, "
        "flagged-IP capacity %d, "
        "Bloom %d IPs per %d s (2x %" APR_SIZE_T_FMT " bytes)",
        scfg->shm_size, scfg->flagged_capacity,
        scfg->bloom_ips, scfg->bloom_window_secs, bloom_bytes);

    /* Persistence (M6): load after SHM is ready, register save on
     * graceful shutdown. A missing or malformed file is non-fatal;
     * bs_state_load logs NOTICE and returns without touching SHM. */
    if (scfg->state_file) {
        bs_state_load(pconf, s, scfg->state_file);
        bs_state_cleanup_ctx *ctx = apr_palloc(pconf, sizeof(*ctx));
        ctx->pool   = pconf;
        ctx->server = s;
        ctx->path   = scfg->state_file;
        apr_pool_cleanup_register(pconf, ctx, bs_state_cleanup,
                                  apr_pool_cleanup_null);

        /* Optional periodic save via mod_watchdog. Soft dependency —
         * if mod_watchdog isn't loaded we degrade to shutdown-only
         * with a NOTICE. This is "normal degraded mode," not an
         * error; the graceful-shutdown save still runs either way. */
        if (scfg->state_save_interval > 0) {
            APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *fn_get =
                APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
            APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *fn_reg =
                APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
            if (fn_get && fn_reg) {
                ap_watchdog_t *wd = NULL;
                apr_status_t wrv = fn_get(&wd, "mod_botshield_state",
                                          0 /* not parent-only */,
                                          1 /* singleton */, pconf);
                if (wrv == APR_SUCCESS && wd) {
                    apr_interval_time_t ival =
                        apr_time_from_sec(scfg->state_save_interval);
                    wrv = fn_reg(wd, ival, ctx, bs_watchdog_save_cb);
                } else if (wrv == APR_SUCCESS) {
                    /* Docs say fn_get returns success + valid ptr or
                     * an error code, but be defensive. */
                    wrv = APR_EGENERAL;
                }
                if (wrv == APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                        "mod_botshield: periodic state save enabled via "
                        "mod_watchdog every %d s",
                        scfg->state_save_interval);
                } else {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, wrv, s,
                        "mod_botshield: watchdog registration failed; "
                        "state saves on graceful shutdown only");
                }
            } else {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                    "mod_botshield: mod_watchdog not loaded; periodic "
                    "state saves disabled (graceful shutdown save still "
                    "runs). Load mod_watchdog and keep "
                    "BotShieldStateSaveInterval set to enable periodic "
                    "saves.");
            }
        } else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                "mod_botshield: BotShieldStateSaveInterval=0; state saves "
                "on graceful shutdown only");
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: BotShieldStateFile not set; state is in-memory "
            "only and will reset on restart");
    }

    /* E1 — build the UA classifier and load ranges for each server
     * that enabled the feature. Walk s, s->next, s->next->next, ...
     * so a vhost-scope `BotShieldLegitCrawlers on` fires. Each
     * vhost gets its own classifier + ranges hash (the per-request
     * check reads from r->server's scfg, so the scoping matches). */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg || !vcfg->crawlers_enabled) continue;

        vcfg->crawler_classifier = bs_ua_classifier_create(pconf);
        vcfg->crawler_ranges     = apr_hash_make(pconf);

        /* Register built-ins, unless an operator pattern overrides. */
        for (const bs_builtin_crawler *b = bs_builtin_crawlers;
             b->name; b++) {
            const char *override =
                apr_table_get(vcfg->crawler_extra_patterns, b->name);
            bs_ua_classifier_add(vcfg->crawler_classifier, b->name,
                                 override ? override : b->pattern);
        }
        /* Register operator-declared patterns that aren't built-ins. */
        const apr_array_header_t *extras =
            apr_table_elts(vcfg->crawler_extra_patterns);
        for (int i = 0; i < extras->nelts; i++) {
            apr_table_entry_t *e =
                &((apr_table_entry_t *)extras->elts)[i];
            int is_builtin = 0;
            for (const bs_builtin_crawler *b = bs_builtin_crawlers;
                 b->name; b++) {
                if (strcmp(b->name, e->key) == 0) { is_builtin = 1; break; }
            }
            if (!is_builtin) {
                bs_ua_classifier_add(vcfg->crawler_classifier,
                                     e->key, e->val);
            }
        }

        /* Load ranges for every classifier-registered name. Prefer
         * operator override path, fall back to the default location.
         * Missing file is a NOTICE — the classifier still knows the
         * UA, requests just get "crawler-unverified:<name>". Malformed
         * file is a WARN — we don't fail startup for a CIDR typo. */
        const bs_builtin_crawler *all[64];
        int n_all = 0;
        for (const bs_builtin_crawler *b = bs_builtin_crawlers;
             b->name && n_all < 64; b++) {
            all[n_all++] = b;
        }
        /* Walk operator-declared names too. Build a synthetic
         * entry just to iterate; we don't mutate. */
        for (int i = 0; i < extras->nelts && n_all < 64; i++) {
            apr_table_entry_t *e =
                &((apr_table_entry_t *)extras->elts)[i];
            int dup = 0;
            for (int j = 0; j < n_all; j++) {
                if (strcmp(all[j]->name, e->key) == 0) { dup = 1; break; }
            }
            if (!dup) {
                bs_builtin_crawler *synth = apr_pcalloc(pconf, sizeof(*synth));
                synth->name    = apr_pstrdup(pconf, e->key);
                synth->pattern = apr_pstrdup(pconf, e->val);
                all[n_all++]   = synth;
            }
        }

        int loaded = 0, missing = 0, bad = 0;
        for (int i = 0; i < n_all; i++) {
            const char *name = all[i]->name;
            const char *override =
                apr_table_get(vcfg->crawler_range_overrides, name);
            const char *path = override
                ? override
                : apr_psprintf(pconf,
                    "/var/lib/botshield/crawlers/%s.txt", name);

            apr_array_header_t *arr = NULL;
            const char *err = NULL;
            apr_status_t rv = bs_crawler_load_ranges(pconf, path, &arr, &err);
            if (rv == APR_SUCCESS) {
                apr_hash_set(vcfg->crawler_ranges, name,
                             APR_HASH_KEY_STRING, arr);
                loaded++;
            } else if (APR_STATUS_IS_ENOENT(rv) || !override) {
                /* Missing file is quiet for built-ins (no override =
                 * operator hasn't wired cron yet). For explicit
                 * overrides missing, louder warning. */
                missing++;
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                    "mod_botshield: crawler '%s' ranges file '%s' "
                    "not loaded (%s) — UA will classify as unverified",
                    name, path, err ? err : "");
            } else {
                bad++;
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
                    "mod_botshield: crawler '%s' ranges file '%s' "
                    "malformed (%s) — skipping", name, path,
                    err ? err : "parse error");
            }
        }
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: crawler allow-list enabled; %d patterns, "
            "%d ranges files loaded (%d missing, %d malformed)",
            n_all, loaded, missing, bad);
    }

    return OK;
}

static void bs_child_init(apr_pool_t *p, server_rec *s)
{
    if (!bs_shm.mutex) return;
    apr_status_t rv = apr_global_mutex_child_init(&bs_shm.mutex,
                                                  bs_shm.mutex_filename, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: global_mutex_child_init failed");
    }
}

/* --- Flagged-IP table operations ---
 *
 * Writes take the global mutex briefly, wrap the slot payload in a
 * seqlock bump (odd → write → even), and probe up to BS_FLAGGED_PROBE_LIMIT
 * slots for either an existing match, an empty slot, or a stale slot to
 * reuse. Reads are lockless and use the seqlock to avoid torn fields.
 *
 * Eviction policy (simplest sufficient):
 *   1. Exact-IP match inside the probe window → merge flags, refresh TTL.
 *   2. Else an empty slot (flags == 0) → claim.
 *   3. Else the first stale slot (expires_at < now) → reclaim.
 *   4. Else the first slot encountered → overwrite (with a log-warning).
 */

static apr_uint32_t bs_flagged_bucket(const unsigned char ip[16])
{
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key, ip, 16);
    return (apr_uint32_t)(h % bs_shm.flagged_capacity);
}

/* Write into a slot under seqlock protection. Caller must hold the
 * global mutex. */
static void bs_flagged_write_slot(bs_flagged_ip_slot *slot,
                                  const unsigned char ip[16],
                                  apr_uint32_t flags, apr_int64_t expires_at)
{
    apr_uint32_t v = apr_atomic_read32(&slot->version);
    apr_atomic_set32(&slot->version, v | 1U);   /* begin: odd */
    /* Ensure the version-odd store is visible before the payload stores. */
    memcpy(slot->ip, ip, 16);
    slot->flags      = flags;
    slot->expires_at = expires_at;
    /* Version-bump to even publishes the payload to readers. */
    apr_atomic_set32(&slot->version, (v | 1U) + 1U);
}

static void bs_flagged_ip_add(request_rec *r,
                              const unsigned char ip[16],
                              apr_uint32_t flag_bits, int ttl_seconds)
{
    if (!bs_shm.flagged_table || !bs_shm.mutex) return;
    if (!flag_bits) return;
    if (ttl_seconds <= 0) ttl_seconds = 3600;

    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_int64_t expires_at = now + ttl_seconds;
    apr_uint32_t base = bs_flagged_bucket(ip);

    apr_status_t rv = apr_global_mutex_lock(bs_shm.mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: flagged-IP mutex_lock failed; dropping flag");
        return;
    }

    int victim = -1;
    for (unsigned i = 0; i < BS_FLAGGED_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.flagged_capacity;
        bs_flagged_ip_slot *slot = &bs_shm.flagged_table[idx];

        if (slot->flags && memcmp(slot->ip, ip, 16) == 0) {
            /* Merge flags, refresh TTL to whichever is later. */
            apr_uint32_t merged = slot->flags | flag_bits;
            apr_int64_t later   = slot->expires_at > expires_at
                                  ? slot->expires_at : expires_at;
            bs_flagged_write_slot(slot, ip, merged, later);
            apr_global_mutex_unlock(bs_shm.mutex);
            return;
        }
        if (slot->flags == 0 && victim < 0) {
            victim = (int)idx;
            /* Empty is good; keep looking only in case an exact-IP
             * match is further along — we want to merge, not duplicate. */
        }
        if (slot->expires_at > 0 && slot->expires_at < now && victim < 0) {
            victim = (int)idx;
        }
    }

    if (victim < 0) {
        /* Probe window was fully occupied with live non-matching entries.
         * Overwrite the first slot we looked at. Rate-limit the warning
         * so a sustained attack doesn't flood logs. */
        static apr_time_t last_warn = 0;
        apr_time_t now_t = apr_time_now();
        if (now_t - last_warn > apr_time_from_sec(60)) {
            last_warn = now_t;
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: flagged-IP table probe saturated at bucket %u "
                "(capacity %" APR_SIZE_T_FMT "); overwriting — consider "
                "raising BotShieldFlaggedIPCapacity",
                base, bs_shm.flagged_capacity);
        }
        victim = (int)base;
    }

    bs_flagged_write_slot(&bs_shm.flagged_table[victim], ip,
                          flag_bits, expires_at);
    apr_global_mutex_unlock(bs_shm.mutex);
}

/* Read under seqlock. Returns 1 if the IP has a live entry, writing
 * the merged flag bitmap into *out_flags. 0 on miss or all retries
 * skipped. Readers never block writers; a caught-mid-write slot is
 * skipped (probe continues to the next). */
static int bs_flagged_ip_lookup(const unsigned char ip[16],
                                apr_uint32_t *out_flags)
{
    if (!bs_shm.flagged_table) return 0;

    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_uint32_t base = bs_flagged_bucket(ip);

    for (unsigned i = 0; i < BS_FLAGGED_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.flagged_capacity;
        bs_flagged_ip_slot *slot = &bs_shm.flagged_table[idx];

        apr_uint32_t v1, v2;
        unsigned char  local_ip[16];
        apr_uint32_t   local_flags;
        apr_int64_t    local_expires;
        int spins = 0;
        for (;;) {
            v1 = apr_atomic_read32(&slot->version);
            if (v1 & 1U) {
                if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
                continue;
            }
            memcpy(local_ip, slot->ip, 16);
            local_flags   = slot->flags;
            local_expires = slot->expires_at;
            v2 = apr_atomic_read32(&slot->version);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;           /* slot too contended */
        if (local_flags == 0) continue;     /* empty */
        if (local_expires < now) continue;  /* stale */
        if (memcmp(local_ip, ip, 16) != 0) continue;

        *out_flags = local_flags;
        return 1;
    }
    return 0;
}

/* --- Rotating Bloom filter (M5.2) ---
 *
 * Two buffers share the same hash geometry. Writes go to the buffer
 * the active_index points at; queries check each buffer independently
 * and OR the results so "seen" means "fully present in A or fully
 * present in B" (not the weaker "each bit present in A or B"). Rotation
 * is driven by inserts (rotate-on-insert) and optionally by mod_watchdog
 * for low-traffic freshness — a CAS on bloom_next_rotate serializes the
 * rotation across processes without a lock. */

/* Compute k bit indices using SipHash + Kirsch-Mitzenmacher double
 * hashing: hash once to get h1, salt and re-hash for h2, then generate
 * each of the k indices as (h1 + i*h2) mod m_bits. */
static void bs_bloom_indices(const unsigned char ip[16],
                             apr_uint32_t *out, apr_size_t m_bits)
{
    apr_uint64_t h1 = bs_siphash24(bs_shm.header->siphash_key, ip, 16);
    unsigned char salted[16];
    memcpy(salted, ip, 16);
    salted[0] ^= 0x9e;   /* domain separator for the second hash */
    apr_uint64_t h2 = bs_siphash24(bs_shm.header->siphash_key,
                                   salted, 16);
    for (int i = 0; i < BS_BLOOM_K; i++) {
        out[i] = (apr_uint32_t)((h1 + (apr_uint64_t)i * h2) % m_bits);
    }
}

/* Single-winner rotation: CAS bloom_next_rotate from its current value
 * to now+window/2. The winner memsets the buffer about to become active
 * and flips bloom_active. Losers return without rotating. Idempotent
 * across the process group. */
static void bs_bloom_rotate_if_due(apr_int64_t now_sec)
{
    if (!bs_shm.bloom_bufs[0]) return;
    apr_int64_t due =
        (apr_int64_t)apr_atomic_read64(
            (apr_uint64_t *)&bs_shm.header->bloom_next_rotate);
    if (now_sec < due) return;

    apr_int64_t next = now_sec +
        (apr_int64_t)bs_shm.header->bloom_window_secs / 2;
    apr_uint64_t prev = apr_atomic_cas64(
        (apr_uint64_t *)&bs_shm.header->bloom_next_rotate,
        (apr_uint64_t)next, (apr_uint64_t)due);
    if ((apr_int64_t)prev != due) return;   /* another worker rotated */

    apr_uint32_t old_active = apr_atomic_read32(&bs_shm.header->bloom_active);
    apr_uint32_t new_active = old_active ^ 1U;
    /* Clear the buffer that's about to start accepting writes. It
     * currently holds the *oldest* data (~window/2 to window old); this
     * zero is what ages that cohort out.
     *
     * Sanitizer-readiness: the insert path writes the same bytes via
     * byte-level `__atomic_or_fetch`, so a plain `memset` here would be
     * a data race per the C memory model (TSAN flags it). Instead,
     * clear the buffer via a loop of relaxed atomic stores — on x86_64
     * this compiles to the same memory-bandwidth mov sequence as a
     * memset, but both sides of the concurrency are now atomic.
     *
     * Borrow the global mutex across the clear too. It doesn't stop
     * the lockless Bloom writers (they don't take it), so the atomic
     * loop is what actually fixes the race — but holding the mutex
     * does serialize against flagged-IP writers and makes rotation
     * a clean global checkpoint. Rotation fires at most twice per
     * week by default, so the brief mutex hold is free. */
    int held_mutex = 0;
    if (bs_shm.mutex &&
        apr_global_mutex_lock(bs_shm.mutex) == APR_SUCCESS) {
        held_mutex = 1;
    }
    apr_uint64_t *p64 = (apr_uint64_t *)bs_shm.bloom_bufs[new_active];
    apr_size_t n64 = bs_shm.bloom_buf_bytes / 8;
    for (apr_size_t i = 0; i < n64; i++) {
        __atomic_store_n(&p64[i], (apr_uint64_t)0, __ATOMIC_RELAXED);
    }
    /* Tail bytes if bloom_buf_bytes isn't a multiple of 8 (post_config
     * layout guarantees u64 alignment today, but keep the loop for
     * safety). */
    unsigned char *tail_start =
        (unsigned char *)bs_shm.bloom_bufs[new_active] + (n64 * 8);
    for (apr_size_t i = 0; i < bs_shm.bloom_buf_bytes - (n64 * 8); i++) {
        __atomic_store_n(&tail_start[i], (unsigned char)0,
                         __ATOMIC_RELAXED);
    }
    apr_atomic_set32(&bs_shm.header->bloom_active, new_active);
    if (held_mutex) apr_global_mutex_unlock(bs_shm.mutex);
}

static void bs_bloom_add(const unsigned char ip[16])
{
    if (!bs_shm.bloom_bufs[0]) return;
    bs_bloom_rotate_if_due((apr_int64_t)apr_time_sec(apr_time_now()));

    apr_size_t m_bits = (apr_size_t)bs_shm.bloom_buf_bytes * 8;
    apr_uint32_t indices[BS_BLOOM_K];
    bs_bloom_indices(ip, indices, m_bits);

    apr_uint32_t active = apr_atomic_read32(&bs_shm.header->bloom_active);
    unsigned char *buf = bs_shm.bloom_bufs[active & 1U];
    for (int i = 0; i < BS_BLOOM_K; i++) {
        apr_uint32_t bit_idx  = indices[i];
        apr_size_t   byte_idx = bit_idx / 8;
        unsigned char mask    = (unsigned char)(1U << (bit_idx % 8));
        __atomic_or_fetch(&buf[byte_idx], mask, __ATOMIC_RELAXED);
    }
}

/* Returns 1 if the IP's bits are fully present in buffer A or fully
 * present in buffer B. Lockless; plain atomic loads on bit slots. */
static int bs_bloom_seen(const unsigned char ip[16])
{
    if (!bs_shm.bloom_bufs[0]) return 0;
    apr_size_t m_bits = (apr_size_t)bs_shm.bloom_buf_bytes * 8;
    apr_uint32_t indices[BS_BLOOM_K];
    bs_bloom_indices(ip, indices, m_bits);

    int in_a = 1, in_b = 1;
    for (int i = 0; i < BS_BLOOM_K; i++) {
        apr_uint32_t bit_idx  = indices[i];
        apr_size_t   byte_idx = bit_idx / 8;
        unsigned char mask    = (unsigned char)(1U << (bit_idx % 8));
        unsigned char a = __atomic_load_n(&bs_shm.bloom_bufs[0][byte_idx],
                                          __ATOMIC_RELAXED);
        unsigned char b = __atomic_load_n(&bs_shm.bloom_bufs[1][byte_idx],
                                          __ATOMIC_RELAXED);
        if (!(a & mask)) in_a = 0;
        if (!(b & mask)) in_b = 0;
        if (!in_a && !in_b) return 0;
    }
    return in_a || in_b;
}

/* --- State persistence (M6) ---
 *
 * Narrow, boring format. Goal: survive graceful restart. Crashes lose
 * state since last save. Dimension mismatches, bad checksums, missing
 * file: all "start fresh," never fatal.
 *
 * File layout (little-endian, x86-64-native):
 *
 *   header    4B magic = 'BSHD'
 *             4B format_version (= 1)
 *             8B saved_at (unix sec)
 *            16B siphash_key (so restored flagged entries hash to the
 *                same buckets on restart — otherwise every entry
 *                becomes unfindable even though its bytes are preserved)
 *   flagged   4B capacity
 *             capacity * sizeof(bs_flagged_ip_slot)  bytes
 *   bloom     4B buf_bytes
 *             4B active_index
 *             8B next_rotate_at
 *             buf_bytes  (buffer 0 raw)
 *             buf_bytes  (buffer 1 raw)
 *   trailer   8B FNV-1a-64 over all preceding bytes
 *
 * This format is not cross-architecture portable. Fine — state files
 * belong to a deployment and don't travel between machines.
 *
 * Format_version is the only forward-compat knob. Bumping it means
 * older files are ignored at load (fresh start, logged). No migration
 * code; files are ephemeral enough to re-acquire. */

#define BS_STATE_MAGIC            0x44485342U      /* 'BSHD' little-endian */
#define BS_STATE_FORMAT_VERSION   1
#define BS_STATE_MAX_AGE_SECS     (14 * 86400)     /* discard anything older */

static apr_uint64_t bs_fnv64(apr_uint64_t h, const unsigned char *data,
                             apr_size_t len)
{
    for (apr_size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}
#define BS_FNV64_SEED 0xcbf29ce484222325ULL

/* Slurp a whole file into a freshly-allocated buffer. Returns NULL on
 * any error; *out_len is valid only on success. Used by load. */
static unsigned char *bs_state_read_all(apr_pool_t *p, const char *path,
                                        apr_size_t *out_len,
                                        const char **err)
{
    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, path,
                                    APR_FOPEN_READ | APR_FOPEN_BINARY,
                                    APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        *err = (APR_STATUS_IS_ENOENT(rv)) ? "no prior state file"
                                          : "cannot open state file";
        return NULL;
    }
    apr_finfo_t info;
    rv = apr_file_info_get(&info, APR_FINFO_SIZE, f);
    if (rv != APR_SUCCESS || info.size <= 0 ||
        info.size > (apr_off_t)(256 * 1024 * 1024)) {
        apr_file_close(f);
        *err = "bad size";
        return NULL;
    }
    unsigned char *buf = apr_palloc(p, (apr_size_t)info.size);
    apr_size_t want = (apr_size_t)info.size;
    rv = apr_file_read(f, buf, &want);
    apr_file_close(f);
    if (rv != APR_SUCCESS || want != (apr_size_t)info.size) {
        *err = "short read";
        return NULL;
    }
    *out_len = want;
    return buf;
}

/* Load a state file into the running SHM. Policy: any error is a clean
 * "start fresh" — we log NOTICE and return. No error is fatal. */
static void bs_state_load(apr_pool_t *p, server_rec *s, const char *path)
{
    const char *err = NULL;
    apr_size_t len = 0;
    unsigned char *buf = bs_state_read_all(p, path, &len, &err);
    if (!buf) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s: %s (starting fresh)",
            path, err ? err : "unavailable");
        return;
    }

    /* Minimum size: header (16) + siphash key (16) + flagged cap (4) +
     * bloom header (16) + trailer (8). */
    if (len < 60) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s too short (%" APR_SIZE_T_FMT
            " bytes); starting fresh", path, len);
        return;
    }

    /* Verify trailer fnv64 over all preceding bytes. */
    apr_uint64_t want_fnv;
    memcpy(&want_fnv, buf + len - 8, 8);
    apr_uint64_t got_fnv = bs_fnv64(BS_FNV64_SEED, buf, len - 8);
    if (want_fnv != got_fnv) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s checksum mismatch; starting fresh",
            path);
        return;
    }

    unsigned char *p_cur = buf;
    unsigned char *p_end = buf + len - 8;

    /* Header */
    apr_uint32_t magic, version;
    apr_int64_t  saved_at;
    memcpy(&magic,    p_cur, 4);  p_cur += 4;
    memcpy(&version,  p_cur, 4);  p_cur += 4;
    memcpy(&saved_at, p_cur, 8);  p_cur += 8;
    if (magic != BS_STATE_MAGIC) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s bad magic; starting fresh", path);
        return;
    }
    if (version != BS_STATE_FORMAT_VERSION) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s version %u (expected %u); "
            "starting fresh", path, version, BS_STATE_FORMAT_VERSION);
        return;
    }
    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_int64_t age = now - saved_at;
    if (age < 0 || age > BS_STATE_MAX_AGE_SECS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s is %" APR_INT64_T_FMT " s old; "
            "starting fresh", path, age);
        return;
    }

    /* SipHash key. Restoring this makes the already-randomized key from
     * post-config a no-op — exactly what we want, because the flagged-IP
     * entries we're about to copy were bucket-indexed under the saved
     * key. Without this restore, the entries would live in "wrong"
     * buckets on restart and lookups would miss. */
    if (p_end - p_cur < (ptrdiff_t)sizeof(bs_shm.header->siphash_key)) {
        goto corrupt;
    }
    memcpy(bs_shm.header->siphash_key, p_cur,
           sizeof(bs_shm.header->siphash_key));
    p_cur += sizeof(bs_shm.header->siphash_key);

    /* Flagged section */
    if (p_end - p_cur < 4) { goto corrupt; }
    apr_uint32_t saved_cap;
    memcpy(&saved_cap, p_cur, 4); p_cur += 4;
    if (saved_cap != (apr_uint32_t)bs_shm.flagged_capacity) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s flagged-IP capacity %u != "
            "current %" APR_SIZE_T_FMT "; starting fresh",
            path, saved_cap, bs_shm.flagged_capacity);
        return;
    }
    apr_size_t flagged_bytes = (apr_size_t)saved_cap * sizeof(bs_flagged_ip_slot);
    if ((apr_size_t)(p_end - p_cur) < flagged_bytes) { goto corrupt; }
    /* Copy flagged slots verbatim, dropping any whose expires_at has already
     * passed and resetting each slot's seqlock version to 0 so live readers
     * see a clean "fresh slot" state. */
    memcpy(bs_shm.flagged_table, p_cur, flagged_bytes);
    p_cur += flagged_bytes;
    int kept = 0, dropped = 0;
    for (apr_size_t i = 0; i < bs_shm.flagged_capacity; i++) {
        bs_flagged_ip_slot *slot = &bs_shm.flagged_table[i];
        slot->version = 0;
        if (slot->flags == 0) continue;
        if (slot->expires_at < now) {
            slot->flags = 0;
            memset(slot->ip, 0, 16);
            slot->expires_at = 0;
            dropped++;
        } else {
            kept++;
        }
    }

    /* Bloom section */
    if (p_end - p_cur < 16) { goto corrupt; }
    apr_uint32_t saved_buf_bytes, saved_active;
    apr_int64_t  saved_next_rotate;
    memcpy(&saved_buf_bytes,  p_cur, 4); p_cur += 4;
    memcpy(&saved_active,     p_cur, 4); p_cur += 4;
    memcpy(&saved_next_rotate, p_cur, 8); p_cur += 8;
    if (saved_buf_bytes != (apr_uint32_t)bs_shm.bloom_buf_bytes) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s bloom buf_bytes %u != "
            "current %" APR_SIZE_T_FMT "; flagged loaded, bloom fresh",
            path, saved_buf_bytes, bs_shm.bloom_buf_bytes);
        goto done_log;
    }
    if ((apr_size_t)(p_end - p_cur) < 2 * saved_buf_bytes) { goto corrupt; }
    memcpy(bs_shm.bloom_bufs[0], p_cur, saved_buf_bytes);
    p_cur += saved_buf_bytes;
    memcpy(bs_shm.bloom_bufs[1], p_cur, saved_buf_bytes);
    p_cur += saved_buf_bytes;
    apr_atomic_set32(&bs_shm.header->bloom_active, saved_active & 1U);
    bs_shm.header->bloom_next_rotate = saved_next_rotate;

done_log:
    /* M9.2 persistence gauges. Counters update before the log line so a
     * scraper that happens to hit during the post-config window sees
     * consistent values. */
    if (bs_shm.metrics) {
        __atomic_fetch_add(&bs_shm.metrics->state_loads_total, 1,
                           __ATOMIC_RELAXED);
        __atomic_store_n(&bs_shm.metrics->state_load_last_kept,
                         (apr_uint64_t)kept, __ATOMIC_RELAXED);
        __atomic_store_n(&bs_shm.metrics->state_load_last_dropped,
                         (apr_uint64_t)dropped, __ATOMIC_RELAXED);
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: state loaded from %s (age %" APR_INT64_T_FMT " s): "
        "flagged kept %d, dropped-stale %d, bloom buffers restored",
        path, age, kept, dropped);
    return;

corrupt:
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: state file %s truncated past header; starting fresh",
        path);
}

/* fsync the directory containing `path` so the post-rename directory
 * entry is durable on crash/power-loss. APR doesn't expose a
 * directory-fsync helper; fall back to plain POSIX open+fsync+close.
 * Errors are logged at INFO and non-fatal — the rename already
 * succeeded, and most filesystems flush the entry in time anyway. */
static void bs_fsync_parent_dir(apr_pool_t *p, server_rec *s,
                                const char *path)
{
    char *dir = apr_pstrdup(p, path);
    char *slash = strrchr(dir, '/');
    if (!slash) return;
    if (slash == dir) dir[1] = '\0';   /* "/state.bin" → "/" */
    else              *slash = '\0';
    int fd = open(dir, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_FROM_OS_ERROR(errno), s,
            "mod_botshield: state save: cannot open '%s' for fsync", dir);
        return;
    }
    if (fsync(fd) < 0) {
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_FROM_OS_ERROR(errno), s,
            "mod_botshield: state save: fsync('%s') failed", dir);
    }
    close(fd);
}

/* Write the current SHM contents to `path` atomically (write to .tmp,
 * fsync file, rename, fsync parent dir). Called at graceful shutdown
 * via pool cleanup. Any error is logged at WARNING but never fatal.
 *
 * Concurrency: the flagged-IP table is serialized under the global
 * mutex while we take the snapshot, so we can't capture a slot that's
 * mid-write. (A racing writer otherwise leaves the slot with version
 * odd + partially-written IP/flags; loading that would reset version
 * to 0 and present the half-written state as legitimately authored.)
 * The Bloom buffers are byte arrays mutated by single-byte atomic OR;
 * individual byte reads are torn-free, so a plain memcpy captures a
 * well-defined per-byte snapshot with no lock needed. */
static apr_status_t bs_state_save(apr_pool_t *p, server_rec *s,
                                  const char *path)
{
    apr_time_t t_start = apr_time_now();
    apr_size_t flagged_bytes = bs_shm.flagged_capacity
                               * sizeof(bs_flagged_ip_slot);
    apr_size_t bloom_bytes   = bs_shm.bloom_buf_bytes;
    apr_size_t key_bytes     = sizeof(bs_shm.header->siphash_key);
    apr_size_t total = 4 + 4 + 8                    /* header */
                     + key_bytes                    /* siphash key */
                     + 4 + flagged_bytes            /* flagged */
                     + 4 + 4 + 8 + 2 * bloom_bytes  /* bloom */
                     + 8;                           /* fnv */

    unsigned char *buf = apr_palloc(p, total);
    unsigned char *pc  = buf;

    apr_uint32_t magic   = BS_STATE_MAGIC;
    apr_uint32_t version = BS_STATE_FORMAT_VERSION;
    apr_int64_t  now     = (apr_int64_t)apr_time_sec(apr_time_now());
    memcpy(pc, &magic,   4); pc += 4;
    memcpy(pc, &version, 4); pc += 4;
    memcpy(pc, &now,     8); pc += 8;
    memcpy(pc, bs_shm.header->siphash_key, key_bytes); pc += key_bytes;

    apr_uint32_t cap = (apr_uint32_t)bs_shm.flagged_capacity;
    memcpy(pc, &cap, 4); pc += 4;

    /* Serialize the flagged-IP copy against bs_flagged_ip_add's
     * writer. Without the lock, a concurrent add's odd-version mid-
     * state can be captured; load resets version to 0 and ends up
     * publishing a logically-forged slot. */
    if (bs_shm.mutex) {
        apr_status_t lr = apr_global_mutex_lock(bs_shm.mutex);
        if (lr != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, lr, s,
                "mod_botshield: state save: could not lock mutex; "
                "skipping save to avoid writing an inconsistent snapshot");
            return lr;
        }
    }
    memcpy(pc, bs_shm.flagged_table, flagged_bytes);
    if (bs_shm.mutex) apr_global_mutex_unlock(bs_shm.mutex);
    pc += flagged_bytes;

    apr_uint32_t bb = (apr_uint32_t)bs_shm.bloom_buf_bytes;
    apr_uint32_t act = apr_atomic_read32(&bs_shm.header->bloom_active);
    apr_int64_t  nxt = bs_shm.header->bloom_next_rotate;
    memcpy(pc, &bb,  4); pc += 4;
    memcpy(pc, &act, 4); pc += 4;
    memcpy(pc, &nxt, 8); pc += 8;
    memcpy(pc, bs_shm.bloom_bufs[0], bb); pc += bb;
    memcpy(pc, bs_shm.bloom_bufs[1], bb); pc += bb;

    apr_uint64_t fnv = bs_fnv64(BS_FNV64_SEED, buf, pc - buf);
    memcpy(pc, &fnv, 8); pc += 8;
    /* pc - buf == total, by construction. */

    /* Atomic write: .tmp then rename. */
    const char *tmp_path = apr_psprintf(p, "%s.tmp", path);
    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, tmp_path,
        APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE
          | APR_FOPEN_BINARY,
        APR_FPROT_UREAD | APR_FPROT_UWRITE, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
            "mod_botshield: state save: cannot open %s for writing",
            tmp_path);
        return rv;
    }
    apr_size_t want = total;
    rv = apr_file_write(f, buf, &want);
    if (rv == APR_SUCCESS && want == total) {
        rv = apr_file_sync(f);
    }
    apr_file_close(f);
    if (rv != APR_SUCCESS || want != total) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
            "mod_botshield: state save: write/fsync failed");
        apr_file_remove(tmp_path, p);
        return rv;
    }
    rv = apr_file_rename(tmp_path, path, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
            "mod_botshield: state save: rename %s -> %s failed",
            tmp_path, path);
        apr_file_remove(tmp_path, p);
        return rv;
    }
    /* fsync the parent directory so the new directory entry is durable
     * across a crash/power-loss before the next periodic flush. Without
     * this, some filesystems can lose the rename even though the file
     * contents are already on disk. */
    bs_fsync_parent_dir(p, s, path);

    /* apr_time_t is microseconds since the epoch. apr_time_now() wraps
     * gettimeofday(), which is wall-clock time — subject to NTP jumps
     * and can go backward. Clamp the duration to 0 on a backward jump
     * so the metric and log line stay sensible; a single save with
     * duration=0 is visibly harmless, a negative duration is not. */
    apr_time_t t_end = apr_time_now();
    apr_int64_t duration_us = (apr_int64_t)(t_end - t_start);
    if (duration_us < 0) duration_us = 0;

    /* M9.2 persistence gauges — update before the log line so the value
     * shown and the value scraped are consistent. Counters are
     * module-global, not per-vhost, so no atomic-RMW race between
     * concurrent saves (watchdog + shutdown) matters in practice. */
    if (bs_shm.metrics) {
        __atomic_fetch_add(&bs_shm.metrics->state_saves_total, 1,
                           __ATOMIC_RELAXED);
        __atomic_store_n(&bs_shm.metrics->state_save_last_unix,
                         (apr_uint64_t)apr_time_sec(t_end),
                         __ATOMIC_RELAXED);
        __atomic_store_n(&bs_shm.metrics->state_save_last_bytes,
                         (apr_uint64_t)total, __ATOMIC_RELAXED);
        __atomic_store_n(&bs_shm.metrics->state_save_last_duration_us,
                         (apr_uint64_t)duration_us, __ATOMIC_RELAXED);
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: state saved to %s (%" APR_SIZE_T_FMT " bytes, "
        "%" APR_INT64_T_FMT " us)", path, total, duration_us);
    return APR_SUCCESS;
}

/* Pool cleanup trampoline. We stash the path in the cleanup data so
 * the callback can find it; the pool owns the string's memory. The
 * struct is defined up near post_config where it's first used. */
static apr_status_t bs_state_cleanup(void *data)
{
    bs_state_cleanup_ctx *ctx = data;
    if (!bs_shm.shm || !bs_shm.flagged_table || !bs_shm.bloom_bufs[0]) {
        return APR_SUCCESS;   /* post-config never completed; nothing to save */
    }
    bs_state_save(ctx->pool, ctx->server, ctx->path);
    return APR_SUCCESS;
}

static const char *bs_set_state_file(cmd_parms *cmd, void *dconf,
                                     const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!arg || !*arg) return "BotShieldStateFile requires a path";
    scfg->state_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *bs_set_state_save_interval(cmd_parms *cmd, void *dconf,
                                              const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    /* 0 = shutdown-only. Otherwise must be in a sane operational
     * range. Parse with the full 0..86400 envelope, then enforce
     * the "no 1..29 values" policy explicitly. */
    long n;
    if (!bs_parse_int_bounded(arg, 0, 86400, 6, &n)) {
        return "BotShieldStateSaveInterval: must be an integer 0..86400 "
               "(seconds)";
    }
    if (n != 0 && n < 30) {
        return "BotShieldStateSaveInterval: 0 (shutdown-only) or 30..86400 seconds";
    }
    scfg->state_save_interval = (int)n;
    return NULL;
}

/* --- E1 directive setters --- */

/* BotShieldLegitCrawlers on|off — master gate for the crawler
 * allow-list. Default off (opt-in). Applied at server scope. */
static const char *bs_set_crawlers_enabled(cmd_parms *cmd, void *dconf,
                                           int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->crawlers_enabled = flag ? 1 : 0;
    return NULL;
}

/* Character policy for crawler-name tokens: lowercase letters,
 * digits, hyphen. Used as both the hash key and the expected
 * basename of the ranges file. Rejects anything that could create
 * path-traversal surprises or cross-host confusion. */
static int bs_crawler_name_valid(const char *s)
{
    if (!s || !*s) return 0;
    apr_size_t len = strlen(s);
    if (len > 32) return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
            return 0;
        }
    }
    return 1;
}

/* BotShieldLegitCrawlerPattern <name> <substring> — register an
 * extra crawler UA pattern at runtime. Built-in crawlers
 * (googlebot, bingbot, applebot) are auto-registered and don't
 * need this. Setting a pattern for a built-in's name OVERRIDES
 * the built-in pattern (last writer wins — operator intent). */
static const char *bs_set_crawler_pattern(cmd_parms *cmd, void *dconf,
                                          const char *name,
                                          const char *pattern)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_crawler_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldLegitCrawlerPattern: name '%s' must be "
            "[a-z0-9-]{1,32}", name);
    }
    if (!pattern || !*pattern) {
        return "BotShieldLegitCrawlerPattern: pattern cannot be empty";
    }
    if (strlen(pattern) > 128) {
        return "BotShieldLegitCrawlerPattern: pattern over 128 chars "
               "(pick a shorter distinctive substring)";
    }
    /* Store for post_config — classifier doesn't exist yet. */
    apr_table_set(scfg->crawler_extra_patterns,
                  apr_pstrdup(cmd->pool, name),
                  apr_pstrdup(cmd->pool, pattern));
    return NULL;
}

/* BotShieldLegitCrawlerRanges <name> <path> — set/override the
 * ranges file path for a crawler. Built-in paths default to
 * /var/lib/botshield/crawlers/<name>.txt. */
static const char *bs_set_crawler_ranges(cmd_parms *cmd, void *dconf,
                                         const char *name,
                                         const char *path)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_crawler_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldLegitCrawlerRanges: name '%s' must be "
            "[a-z0-9-]{1,32}", name);
    }
    if (!path || !*path) {
        return "BotShieldLegitCrawlerRanges: path cannot be empty";
    }
    if (path[0] != '/') {
        return "BotShieldLegitCrawlerRanges: path must be absolute";
    }
    apr_table_set(scfg->crawler_range_overrides,
                  apr_pstrdup(cmd->pool, name),
                  apr_pstrdup(cmd->pool, path));
    return NULL;
}

/* mod_watchdog periodic-save callback. Runs in the parent/watchdog
 * process context with a short-lived pool. AP_WATCHDOG_STATE_RUNNING
 * fires at the configured interval. STARTING/STOPPING we ignore; the
 * graceful-shutdown save still happens via pool cleanup. */
static apr_status_t bs_watchdog_save_cb(int state, void *data,
                                        apr_pool_t *pool)
{
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    bs_state_cleanup_ctx *ctx = data;
    if (!ctx || !ctx->path) return APR_SUCCESS;
    if (!bs_shm.shm || !bs_shm.flagged_table || !bs_shm.bloom_bufs[0]) {
        return APR_SUCCESS;   /* SHM not up yet; nothing to save */
    }
    /* Use the callback's own pool so temporaries die with this tick. */
    bs_state_save(pool, ctx->server, ctx->path);
    return APR_SUCCESS;
}

/* Translate a flag bitmap (from the cookie's flags field OR the flagged-
 * IP table) into an additive score. M5.1 wires real numbers; bits are
 * independent so an IP with multiple flags pays the sum. */
static int bs_flag_penalty(apr_uint32_t flags)
{
    int p = 0;
    if (flags & BS_FLAG_HONEYPOT_HIT)     p += 60;
    if (flags & BS_FLAG_SCANNER_PROBE)    p += 50;
    if (flags & BS_FLAG_FAKE_CRAWLER)     p += 80;
    if (flags & BS_FLAG_POW_FAIL_STREAK)  p += 30;
    return p;
}

/* Parse a comma-joined flag-name list into a bit mask. Unknown tokens
 * return an error message in *err; *err is NULL on success. */
static const struct { const char *name; apr_uint32_t bit; } bs_flag_names[] = {
    { "honeypot_hit",    BS_FLAG_HONEYPOT_HIT    },
    { "scanner_probe",   BS_FLAG_SCANNER_PROBE   },
    { "fake_crawler",    BS_FLAG_FAKE_CRAWLER    },
    { "pow_fail_streak", BS_FLAG_POW_FAIL_STREAK },
    { NULL, 0 }
};

static apr_uint32_t bs_parse_flag_names(apr_pool_t *p, const char *s,
                                        const char **err)
{
    apr_uint32_t bits = 0;
    *err = NULL;
    const char *cur = s;
    while (cur && *cur) {
        const char *comma = strchr(cur, ',');
        apr_size_t len = comma ? (apr_size_t)(comma - cur) : strlen(cur);
        while (len && (*cur == ' ' || *cur == '\t')) { cur++; len--; }
        while (len && (cur[len-1] == ' ' || cur[len-1] == '\t')) { len--; }

        int matched = 0;
        for (int i = 0; bs_flag_names[i].name; i++) {
            apr_size_t nlen = strlen(bs_flag_names[i].name);
            if (nlen == len &&
                strncasecmp(cur, bs_flag_names[i].name, nlen) == 0) {
                bits |= bs_flag_names[i].bit;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            *err = apr_psprintf(p, "unknown flag name '%.*s' "
                "(known: honeypot_hit, scanner_probe, fake_crawler, "
                "pow_fail_streak)", (int)len, cur);
            return 0;
        }
        cur = comma ? comma + 1 : NULL;
    }
    return bits;
}

/* Render the challenge as JSON for inline embedding in the interstitial.
 * The JS worker reads window.__bsChallenge and uses it to drive the PoW
 * and to assemble the resulting cookie. Contents are deterministic —
 * hex digits, ASCII identifiers, integers — so no HTML escaping is
 * needed inside a <script> tag.
 *
 * Also carries the cookie_domain (if configured) so the JS can include
 * a Domain= attribute when calling document.cookie. */
static const char *bs_challenge_json(apr_pool_t *p, const bs_dir_cfg *cfg,
                                     const bs_challenge *ch)
{
    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    char sig_hex  [BS_SIG_BYTES * 2 + 1];
    bs_to_hex(ch->salt,      BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch->nonce,     BS_NONCE_BYTES, nonce_hex);
    bs_to_hex(ch->signature, BS_SIG_BYTES,   sig_hex);
    const char *domain_json = cfg->cookie_domain
        ? apr_psprintf(p, ",\"cookie_domain\":\"%s\"", cfg->cookie_domain)
        : "";
    return apr_psprintf(p,
        "{\"v\":%d,\"alg\":\"%s\",\"salt\":\"%s\",\"nonce\":\"%s\","
        "\"difficulty\":%d,\"expires_at\":%" APR_TIME_T_FMT ","
        "\"score\":%d,\"flags\":%u,"
        "\"passes_silent\":%d,\"passes_form\":%d,\"passes_captcha\":%d,"
        "\"challenged_at\":%" APR_TIME_T_FMT ",\"auto\":%d,"
        "\"signature\":\"%s\"%s}",
        ch->version, ch->alg_name, salt_hex, nonce_hex,
        ch->difficulty, ch->expires_at,
        ch->rep.score, (unsigned)ch->rep.flags,
        ch->rep.passes_silent, ch->rep.passes_form, ch->rep.passes_captcha,
        ch->rep.challenged_at, ch->auto_tier ? 1 : 0,
        sig_hex, domain_json);
}

/* --- Top-level issue / verify ---
 *
 * bs_issue_challenge fills the `ch` struct (salt, nonce, signature) from
 * config; the handler serializes to JSON for inline embedding. Stateless.
 *
 * bs_verify_cookie parses a base64-encoded cookie payload into a challenge
 * + counter, checks HMAC + expiry, dispatches the PoW check to the alg.
 * Returns NULL on accept, else a diagnostic string. */

/* Issue a fresh challenge. If `rep_in` is non-NULL its fields are copied
 * into the issued challenge verbatim — the handler has already applied
 * whatever forgiveness / increments are appropriate for the tier being
 * issued. If `rep_in` is NULL, rep starts at zero (first-ever challenge).
 * `auto_tier` controls the M7 silent-tier variant: 1 renders the interstitial
 * as an auto-submitting splash, 0 renders the form-PoW checkbox.
 * `alg_override` lets callers issue cookies under a non-default algorithm
 * (M8 uses this for captcha-turnstile). NULL = use cfg->algorithm. */
static const char *bs_issue_challenge(apr_pool_t *p, const bs_dir_cfg *cfg,
                                      int difficulty, int cookie_ttl,
                                      int auto_tier,
                                      const bs_pow_algorithm *alg_override,
                                      const bs_rep_state *rep_in,
                                      bs_challenge *out)
{
    if (!cfg->secret) {
        return "BotShieldSecretFile must be set";
    }
    const bs_pow_algorithm *alg = alg_override ? alg_override : cfg->algorithm;
    if (!alg) {
        return "BotShieldAlgorithm must be set (or alg_override provided)";
    }
    apr_time_t now = apr_time_sec(apr_time_now());
    out->version     = BS_PROTOCOL_VERSION;
    out->alg_name    = alg->name;
    out->difficulty  = difficulty;
    out->expires_at  = now + cookie_ttl;
    out->auto_tier   = auto_tier ? 1 : 0;
    if (rep_in) {
        out->rep = *rep_in;
    } else {
        out->rep.score          = 0;
        out->rep.flags          = 0;
        out->rep.passes_silent  = 0;
        out->rep.passes_form    = 0;
        out->rep.passes_captcha = 0;
        out->rep.challenged_at  = 0;
    }
    /* The challenged_at stamp records "when this cookie earned its
     * current PoW proof" — set unconditionally since an issued challenge
     * always implies a fresh PoW solve on acceptance. */
    out->rep.challenged_at = now;

    const char *err = alg->issue(cfg, out);
    if (err) return err;

    const char *canon = bs_challenge_canonical(p, out);
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon),
                   out->signature);
    return NULL;
}

/* Build the 15-field base64-encoded cookie payload for a challenge +
 * counter. Matches the format the interstitial JS produces so server-
 * set (M8 captcha) and client-set (M1/M7 PoW) cookies are indistinguish-
 * able on the wire. `counter_str` is the PoW counter for PoW cookies,
 * or the sentinel "captcha" for captcha-alg cookies (the alg's verify
 * only checks non-empty). */
static const char *bs_build_cookie_payload(apr_pool_t *p,
                                           const bs_challenge *ch,
                                           const char *counter_str)
{
    char sig_hex[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(ch->signature, BS_SIG_BYTES, sig_hex);
    const char *canon = bs_challenge_canonical(p, ch);
    const char *joined = apr_psprintf(p, "%s|%s|%s",
                                      canon, sig_hex, counter_str);
    apr_size_t joined_len = strlen(joined);
    char *b64 = apr_palloc(p, apr_base64_encode_len((int)joined_len) + 1);
    apr_base64_encode(b64, joined, (int)joined_len);
    return b64;
}

/* If `out_ch` is non-NULL, it is populated with the parsed challenge once
 * the HMAC signature has verified — even when the cookie is later rejected
 * for expiry or a bad PoW counter. That lets the caller salvage the cookie's
 * rep fields on re-challenge. On signature mismatch or any earlier error,
 * `out_ch` is untouched. */
static const char *bs_verify_cookie(request_rec *r, const bs_dir_cfg *cfg,
                                    const char *cookie_b64,
                                    bs_challenge *out_ch)
{
    if (!cfg->secret) return "no secret configured";

    /* Decode the base64 into a pool buffer large enough. apr_base64_decode
     * writes into the buffer and returns length; we add room for a NUL. */
    apr_size_t in_len = strlen(cookie_b64);
    if (in_len > BS_MAX_PAGE_BYTES) return "cookie absurdly long";
    char *decoded = apr_palloc(r->pool, apr_base64_decode_len(cookie_b64) + 1);
    int dec_len = apr_base64_decode(decoded, cookie_b64);
    if (dec_len <= 0) return "base64 decode failed";
    decoded[dec_len] = '\0';

    /* Expect 15 pipe-delimited fields (M4.1 + M7):
     *   0..5  : v, alg, salt, nonce, difficulty, expires_at
     *   6..11 : score, flags, passes_silent, passes_form, passes_captcha,
     *           challenged_at
     *   12    : auto       (0/1, M7 silent-tier marker)
     *   13    : sighex
     *   14    : counter
     * Split in place. */
    char *fields[BS_COOKIE_FIELDS];
    int nf = 0;
    char *p = decoded;
    fields[nf++] = p;
    while (*p && nf < BS_COOKIE_FIELDS) {
        if (*p == '|') { *p = '\0'; fields[nf++] = p + 1; }
        p++;
    }
    if (nf != BS_COOKIE_FIELDS) return "wrong field count";

    /* Parse + validate each field with a strict, bounded numeric
     * parser (security review #2). Using atoi()/strtoul() here
     * invokes UB on overflow because these are attacker-controlled
     * bytes and we're still BEFORE the HMAC check. bs_parse_*_bounded
     * caps the input length and handles ERANGE so libc never sees
     * something outside representable range. */
    long v;
    if (!bs_parse_int_bounded(fields[0], 0, INT_MAX, 10, &v)) return "bad version";
    int version = (int)v;
    if (version != BS_PROTOCOL_VERSION) return "bad protocol version";

    const bs_pow_algorithm *alg = bs_find_algorithm(fields[1]);
    if (!alg || !alg->implemented) return "unknown algorithm";

    bs_challenge ch;
    ch.version    = version;
    ch.alg_name   = alg->name;
    if (!bs_parse_int_bounded(fields[4], 1, 8, 2, &v)) return "bad difficulty";
    ch.difficulty = (int)v;

    if (strlen(fields[2]) != BS_SALT_BYTES * 2 ||
        !bs_from_hex(fields[2], BS_SALT_BYTES, ch.salt)) return "bad salt";
    if (strlen(fields[3]) != BS_NONCE_BYTES * 2 ||
        !bs_from_hex(fields[3], BS_NONCE_BYTES, ch.nonce)) return "bad nonce";

    apr_int64_t v64;
    if (!bs_parse_int64_bounded(fields[5], 0, APR_INT64_MAX, &v64)) return "bad expires_at";
    ch.expires_at = (apr_time_t)v64;

    /* Rep fields. These are still pre-HMAC — same bounded-parse
     * discipline. score is a signed int (allowed negative for credits);
     * passes_* are small flags; flags is a 32-bit bitmap. */
    if (!bs_parse_int_bounded(fields[6], INT_MIN, INT_MAX, 11, &v)) return "bad score";
    ch.rep.score = (int)v;
    if (!bs_parse_uint32_bounded(fields[7], 10, &ch.rep.flags)) return "bad flags";
    if (!bs_parse_int_bounded(fields[8],  0, 1, 1, &v)) return "bad passes_silent";
    ch.rep.passes_silent  = (int)v;
    if (!bs_parse_int_bounded(fields[9],  0, 1, 1, &v)) return "bad passes_form";
    ch.rep.passes_form    = (int)v;
    if (!bs_parse_int_bounded(fields[10], 0, 1, 1, &v)) return "bad passes_captcha";
    ch.rep.passes_captcha = (int)v;
    if (!bs_parse_int64_bounded(fields[11], 0, APR_INT64_MAX, &v64)) return "bad challenged_at";
    ch.rep.challenged_at  = (apr_time_t)v64;
    if (!bs_parse_int_bounded(fields[12], 0, 1, 1, &v)) return "bad auto";
    ch.auto_tier          = (int)v;

    unsigned char sig_from_client[BS_SIG_BYTES];
    if (strlen(fields[13]) != BS_SIG_BYTES * 2 ||
        !bs_from_hex(fields[13], BS_SIG_BYTES, sig_from_client)) {
        return "bad signature hex";
    }

    /* Re-derive the HMAC from canonical form + secret, and constant-time
     * compare with the client-supplied signature. The canonical form
     * now covers the rep fields, so a client that edits (say) the score
     * hoping to lower their own debt will fail here. */
    const char *canon = bs_challenge_canonical(r->pool, &ch);
    unsigned char sig_expected[BS_SIG_BYTES];
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon),
                   sig_expected);
    if (!bs_ct_equal(sig_expected, sig_from_client, BS_SIG_BYTES)) {
        return "signature mismatch";
    }

    /* Signature verified — expose the challenge to the caller even if
     * later checks reject, so rep can be carried forward. */
    memcpy(ch.signature, sig_from_client, BS_SIG_BYTES);
    if (out_ch) *out_ch = ch;

    /* Freshness — a signed cookie is still only valid until expires_at. */
    apr_time_t now = apr_time_sec(apr_time_now());
    if (now > ch.expires_at) return "expired";

    /* Final step: algorithm-specific PoW check on the counter. */
    return alg->verify(&ch, fields[14]);
}

/* --- New directive setters --- */

/* `BotShieldSecretFile /path` — HMAC key. Refuse world-readable and
 * group-readable files so an operator can't accidentally ship a key that
 * any local user on the box can exfiltrate. */
static const char *bs_set_secret_file(cmd_parms *cmd, void *cfg_v,
                                      const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;

    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecretFile: cannot stat '%s'", arg);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecretFile: '%s' is group- or world-accessible "
            "(mode %04o); chmod 600 it", arg, st.st_mode & 07777);
    }

    const char *buf = NULL;
    const char *err = bs_load_config_file(cmd, "BotShieldSecretFile", arg,
                                          BS_MAX_SECRET_BYTES, &buf);
    if (err) return err;

    /* Trim one trailing newline if present — common with `echo` output. */
    apr_size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') len--;
    if (len < BS_MIN_SECRET_BYTES) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecretFile: '%s' contains only %" APR_SIZE_T_FMT
            " bytes (minimum %d)", arg, len, BS_MIN_SECRET_BYTES);
    }

    cfg->secret     = (const unsigned char *)buf;
    cfg->secret_len = len;
    return NULL;
}

static const char *bs_set_algorithm(cmd_parms *cmd, void *cfg_v,
                                    const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    const bs_pow_algorithm *alg = bs_find_algorithm(arg);
    if (!alg) {
        return apr_psprintf(cmd->pool,
            "BotShieldAlgorithm: '%s' is not a recognized algorithm name",
            arg);
    }
    if (!alg->implemented) {
        return apr_psprintf(cmd->pool,
            "BotShieldAlgorithm: '%s' is reserved in the registry but not "
            "built into this module", arg);
    }
    cfg->algorithm = alg;
    return NULL;
}

/* --- M8 captcha directive setters --- */

/* `BotShieldEndpointPrefix /path` — URL prefix the module's own
 * handlers live under. Today: /captcha-verify[/<provider>] (M8),
 * /metrics (M9.3). Future: E7's /solver.js. Must start with '/' and
 * not end with '/'. */
static const char *bs_set_endpoint_prefix(cmd_parms *cmd, void *cfg_v,
                                          const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg || !*arg || arg[0] != '/') {
        return apr_psprintf(cmd->pool,
            "BotShieldEndpointPrefix: '%s' must start with '/'", arg ? arg : "");
    }
    apr_size_t len = strlen(arg);
    if (len > 1 && arg[len-1] == '/') {
        return apr_psprintf(cmd->pool,
            "BotShieldEndpointPrefix: '%s' must not end with '/'", arg);
    }
    /* Cheap sanity — no spaces, control chars, or query strings. Operators
     * don't mount endpoints at weird places on purpose. */
    for (apr_size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)arg[i];
        if (c <= ' ' || c == '?' || c == '#') {
            return apr_psprintf(cmd->pool,
                "BotShieldEndpointPrefix: '%s' contains an invalid char", arg);
        }
    }
    cfg->endpoint_prefix = arg;
    return NULL;
}

static const char *bs_set_captcha_provider(cmd_parms *cmd, void *cfg_v,
                                           const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    const bs_captcha_provider *p = bs_find_provider(arg);
    if (!p) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaProvider: '%s' is not a recognized provider "
            "(known: turnstile, hcaptcha, recaptcha-v2, recaptcha-v3, "
            "friendly, geetest)", arg);
    }
    if (!p->implemented) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaProvider: '%s' is reserved in the registry "
            "but not built into this module", arg);
    }
    cfg->captcha_provider = p;
    return NULL;
}

static const char *bs_set_captcha_site_key(cmd_parms *cmd, void *cfg_v,
                                           const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg || !*arg) {
        return "BotShieldCaptchaSiteKey: empty value";
    }
    /* Site keys are public; just cap length to something sane so a
     * misconfigured directive can't wedge the interstitial. */
    if (strlen(arg) > 256) {
        return "BotShieldCaptchaSiteKey: value longer than 256 bytes";
    }
    cfg->captcha_site_key = arg;
    return NULL;
}

/* Reuse the same mode-600 discipline as BotShieldSecretFile. */
static const char *bs_set_captcha_secret_file(cmd_parms *cmd, void *cfg_v,
                                              const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;

    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaSecretFile: cannot stat '%s'", arg);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaSecretFile: '%s' is group- or world-accessible "
            "(mode %04o); chmod 600 it", arg, st.st_mode & 07777);
    }

    const char *buf = NULL;
    const char *err = bs_load_config_file(cmd, "BotShieldCaptchaSecretFile",
                                          arg, BS_MAX_SECRET_BYTES, &buf);
    if (err) return err;

    apr_size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') len--;
    if (len == 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaSecretFile: '%s' is empty", arg);
    }
    cfg->captcha_secret     = (const unsigned char *)buf;
    cfg->captcha_secret_len = len;
    return NULL;
}

static const char *bs_set_captcha_timeout(cmd_parms *cmd, void *cfg_v,
                                          const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < BS_MIN_CAPTCHA_TIMEOUT ||
        v > BS_MAX_CAPTCHA_TIMEOUT) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaTimeout: '%s' must be an integer in %d..%d ms",
            arg, BS_MIN_CAPTCHA_TIMEOUT, BS_MAX_CAPTCHA_TIMEOUT);
    }
    cfg->captcha_timeout_ms = (int)v;
    return NULL;
}

/* `BotShieldRecaptchaV3MinScore 0.0..1.0` — threshold below which a
 * successful-but-low-score reCAPTCHA v3 verification is treated as a
 * rejection. Google's documented baseline is 0.5; operators tune down
 * (more permissive, fewer false rejections) or up (more strict) based
 * on observed traffic. */
static const char *bs_set_recaptcha_v3_min_score(cmd_parms *cmd,
                                                 void *cfg_v,
                                                 const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    double v = strtod(arg, &end);
    if (!end || *end != '\0' || v < 0.0 || v > 1.0) {
        return apr_psprintf(cmd->pool,
            "BotShieldRecaptchaV3MinScore: '%s' must be a number in 0.0..1.0",
            arg);
    }
    cfg->recaptcha_v3_min_score = v;
    return NULL;
}

/* `BotShieldCaptchaExpectedHostname <host|off>` — hostname the
 * captcha provider echoed back in the siteverify response must
 * equal this value. Default = r->server->server_hostname (the
 * vhost name). The literal value `off` (case-insensitive) disables
 * the check — stored internally as an empty string — for
 * multi-origin deployments where the operator enforces binding
 * elsewhere. Apache's directive parser rejects bare "" as zero
 * args so the sentinel is the ergonomic escape.
 *
 * DNS hostname charset only — matches the cookie-domain setter's
 * policy. Rejects quotes / backslashes / whitespace / anything that
 * could confuse later string comparison or logging. */
static const char *bs_set_captcha_expected_hostname(cmd_parms *cmd,
                                                    void *cfg_v,
                                                    const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg) return "BotShieldCaptchaExpectedHostname requires an argument";
    if (strcasecmp(arg, "off") == 0) {
        cfg->captcha_expected_hostname = "";
        return NULL;
    }
    if (strlen(arg) > 253) {
        return "BotShieldCaptchaExpectedHostname: longer than RFC 1035 limit";
    }
    for (const char *p = arg; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-')) {
            return apr_psprintf(cmd->pool,
                "BotShieldCaptchaExpectedHostname: '%s' contains "
                "a character outside [a-zA-Z0-9.-]", arg);
        }
    }
    cfg->captcha_expected_hostname = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* `BotShieldCaptchaExpectedAction <action|off>` — the action string
 * the client-side widget tagged the token with. Default =
 * "botshield" (matches the action embedded in the interstitial JS
 * for reCAPTCHA v3 and the Turnstile data-action attribute). The
 * literal value `off` disables the check. Restricted to printable
 * ASCII without whitespace or shell/quote metacharacters. */
static const char *bs_set_captcha_expected_action(cmd_parms *cmd,
                                                  void *cfg_v,
                                                  const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg) return "BotShieldCaptchaExpectedAction requires an argument";
    if (strcasecmp(arg, "off") == 0) {
        cfg->captcha_expected_action = "";
        return NULL;
    }
    if (strlen(arg) > 64) {
        return "BotShieldCaptchaExpectedAction: max 64 characters";
    }
    for (const char *p = arg; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20 || c >= 0x7f || c == '"' || c == '\'' ||
            c == '\\' || c == ';' || c == '&') {
            return apr_psprintf(cmd->pool,
                "BotShieldCaptchaExpectedAction: '%s' contains "
                "an unsafe character", arg);
        }
    }
    cfg->captcha_expected_action = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* `BotShieldCaptchaRateLimit N` — verify-endpoint attempts per IP per
 * minute. 0 disables the rate limiter entirely (not recommended);
 * default BS_DEFAULT_CAPTCHA_RATE_LIMIT = 30. */
static const char *bs_set_captcha_rate_limit(cmd_parms *cmd, void *cfg_v,
                                             const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < 0 || v > 1000) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaRateLimit: '%s' must be an integer 0..1000 "
            "(0 disables)", arg);
    }
    cfg->captcha_rate_limit = (int)v;
    return NULL;
}

/* `BotShieldCaptchaMaxInFlight N` — global cap on outstanding siteverify
 * calls. The underlying SHM counter is module-global, so if the
 * directive appears in more than one server_rec the last-parsed value
 * wins at runtime. Allowed anywhere (RSRC_CONF) so operators who only
 * have a vhost config can still set it; we don't pretend otherwise. */
static const char *bs_set_captcha_max_inflight(cmd_parms *cmd, void *cfg_v,
                                               const char *arg)
{
    (void)cfg_v;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 1024) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaMaxInFlight: '%s' must be an integer 1..1024",
            arg);
    }
    scfg->captcha_max_inflight = (int)v;
    return NULL;
}

/* ======================================================================
 * Captcha tier (M8) — libcurl siteverify shim.
 *
 * Deliberately boring: one POST per verify, short timeouts, small
 * response buffer capped at BS_MAX_CAPTCHA_BODY, no JSON dependency
 * (the one field we need is "success", and we look for the explicit
 * `"success":false` / `"success":true` forms Cloudflare documents).
 *
 * Fail policy:
 *   - OK        → cookie issued, user redirected to return_to.
 *   - REJECTED  → 403 logged at INFO with a short body snippet.
 *   - TIMEOUT   → cookie issued anyway (fail-open), WARNING logged.
 *   - ERROR     → same as TIMEOUT for request flow; logged at WARNING.
 *     The alternative (fail-closed) locks users out during a Cloudflare
 *     blip, which the plan rejected as worse than occasional permissive
 *     behavior.
 * ====================================================================== */

/* bs_captcha_result is defined near the provider struct so the provider-
 * specific siteverify fn pointer can reference it. */

typedef struct {
    char      *buf;      /* r->pool-allocated */
    apr_size_t cap;
    apr_size_t len;
    int        truncated;
} bs_curl_buffer;

static size_t bs_curl_write_cb(char *ptr, size_t size, size_t nmemb,
                               void *userdata)
{
    bs_curl_buffer *b = userdata;
    /* Overflow-guard the size*nmemb multiply (security review —
     * hardening point). libcurl's documented contract keeps `size`
     * at 1 in practice, and BS_MAX_CAPTCHA_BODY caps the target
     * buffer anyway, so a realistic overrun is vanishingly unlikely.
     * But the guard is two cheap comparisons and closes the class
     * entirely: an overflow would wrap `incoming` to a small value,
     * make our truncation accounting think we took the whole chunk
     * when we really dropped a mountain of bytes, and return a
     * mis-stated byte count to libcurl. Treat overflow as "drop
     * this chunk" same as the already-truncated branch.*/
    if (size > 0 && nmemb > SIZE_MAX / size) {
        b->truncated = 1;
        /* Return 0 to tell libcurl we consumed nothing — it will
         * abort the transfer with CURLE_WRITE_ERROR, which the
         * caller maps to BS_CAPTCHA_ERROR + fail-open. That's the
         * right behavior for an obviously-malformed provider
         * response: don't silently drop it. */
        return 0;
    }
    size_t incoming = size * nmemb;
    if (b->truncated) return incoming;   /* drain silently */
    size_t room = (b->len < b->cap) ? (b->cap - b->len) : 0;
    size_t take = (incoming < room) ? incoming : room;
    if (take > 0) {
        memcpy(b->buf + b->len, ptr, take);
        b->len += take;
    }
    if (take < incoming) b->truncated = 1;
    return incoming;  /* always "consume" everything so libcurl doesn't abort */
}

/* libcurl global state is initialized once in bs_post_config (see the
 * comment there). No per-request init guard here — curl_global_init is
 * not thread-safe, and doing it lazily from the request path would
 * race under mpm_event. */

/* URL-encode via libcurl and copy into the request pool so the caller
 * can free the libcurl buffer right away. */
static const char *bs_curl_escape_pool(apr_pool_t *p, CURL *curl,
                                       const char *in, apr_size_t in_len)
{
    char *esc = curl_easy_escape(curl, in, (int)in_len);
    if (!esc) return NULL;
    const char *dup = apr_pstrdup(p, esc);
    curl_free(esc);
    return dup;
}

/* Parse the siteverify response body with json-c. Returns:
 *   BS_CAPTCHA_OK        — explicit "success":true
 *   BS_CAPTCHA_REJECTED  — explicit "success":false; *out_details is set
 *                          to a comma-joined "error-codes" list, or the
 *                          empty string if the provider didn't send any.
 *   BS_CAPTCHA_ERROR     — malformed JSON, wrong shape, or "success" of
 *                          a non-boolean type. *out_details is a snippet
 *                          of the raw body for the log.
 * The Google-family providers (Turnstile, hCaptcha, reCAPTCHA v2/v3,
 * Friendly Captcha) all use the same {"success":bool,...} contract,
 * so one parser covers all of them. Friendly Captcha v1 writes its
 * error list under the key "errors" instead of "error-codes"; both
 * keys are accepted, preferring "error-codes" when present. GeeTest
 * uses a different response shape entirely and bypasses this parser
 * via its own siteverify_fn on the provider row.
 *
 * `out_score` is optional; when non-NULL it receives the numeric
 * "score" field if present (reCAPTCHA v3), or -1.0 if the response
 * didn't carry a score (other Google-family providers). The
 * handler uses it to apply BotShieldRecaptchaV3MinScore *after* the
 * success:true check — v3 threshold failures look the same as any
 * other REJECTED outcome to downstream code. */
static bs_captcha_result bs_captcha_parse_response(apr_pool_t *p,
                                                   const char *body,
                                                   apr_size_t body_len,
                                                   const char **out_details,
                                                   double *out_score,
                                                   const char **out_hostname,
                                                   const char **out_action)
{
    *out_details = "";
    if (out_score) *out_score = -1.0;
    if (out_hostname) *out_hostname = NULL;
    if (out_action)   *out_action   = NULL;
    if (!body || body_len == 0) return BS_CAPTCHA_ERROR;

    enum json_tokener_error jerr = json_tokener_success;
    json_object *root = json_tokener_parse_verbose(body, &jerr);
    if (!root || jerr != json_tokener_success) {
        if (root) json_object_put(root);
        /* 120-char snippet of whatever came back for the log. */
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(p, body, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
        return BS_CAPTCHA_ERROR;
    }

    /* Shape must be an object with a boolean `success` field. Anything
     * else (missing field, wrong type) is a protocol surprise. */
    bs_captcha_result out = BS_CAPTCHA_ERROR;
    if (json_object_is_type(root, json_type_object)) {
        json_object *succ = NULL;
        if (json_object_object_get_ex(root, "success", &succ) &&
            succ && json_object_is_type(succ, json_type_boolean)) {
            if (json_object_get_boolean(succ)) {
                out = BS_CAPTCHA_OK;
                /* v3 carries a numeric score field. Extract if present;
                 * providers that don't carry it leave out_score at -1.0. */
                json_object *sc = NULL;
                if (out_score &&
                    json_object_object_get_ex(root, "score", &sc) &&
                    sc && (json_object_is_type(sc, json_type_double) ||
                           json_object_is_type(sc, json_type_int))) {
                    *out_score = json_object_get_double(sc);
                }
                /* Binding metadata (security review #1). Turnstile +
                 * hCaptcha + reCAPTCHA v2 + v3 all return `hostname`.
                 * reCAPTCHA v3 + Turnstile also return `action`. Copy
                 * into the caller's pool so the original json_object
                 * can be freed without dangling the strings. */
                json_object *hn = NULL;
                if (out_hostname &&
                    json_object_object_get_ex(root, "hostname", &hn) &&
                    hn && json_object_is_type(hn, json_type_string)) {
                    const char *s = json_object_get_string(hn);
                    if (s) *out_hostname = apr_pstrdup(p, s);
                }
                json_object *act = NULL;
                if (out_action &&
                    json_object_object_get_ex(root, "action", &act) &&
                    act && json_object_is_type(act, json_type_string)) {
                    const char *s = json_object_get_string(act);
                    if (s) *out_action = apr_pstrdup(p, s);
                }
            } else {
                out = BS_CAPTCHA_REJECTED;
                /* Join the error-codes array into a compact string for
                 * the log. Most providers use "error-codes"; Friendly
                 * Captcha v1 uses "errors". Check both, preferring the
                 * standard name when both are present. */
                json_object *ec = NULL;
                if (!json_object_object_get_ex(root, "error-codes", &ec)) {
                    json_object_object_get_ex(root, "errors", &ec);
                }
                if (ec && json_object_is_type(ec, json_type_array)) {
                    int n = (int)json_object_array_length(ec);
                    char *joined = apr_pstrdup(p, "");
                    for (int i = 0; i < n; i++) {
                        json_object *e = json_object_array_get_idx(ec, i);
                        if (!e) continue;
                        const char *s = json_object_get_string(e);
                        if (!s) continue;
                        joined = apr_pstrcat(p, joined,
                                             i == 0 ? "" : ",", s, NULL);
                    }
                    *out_details = joined;
                }
            }
        }
    }

    if (out == BS_CAPTCHA_ERROR) {
        /* Couldn't find or interpret "success". Log a snippet. */
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(p, body, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
    }

    json_object_put(root);
    return out;
}

static bs_captcha_result bs_captcha_siteverify(request_rec *r,
                                               const bs_captcha_provider *prov,
                                               const unsigned char *secret,
                                               apr_size_t secret_len,
                                               const char *token,
                                               int timeout_ms,
                                               const char **out_details,
                                               long *out_http_code,
                                               double *out_score,
                                               const char **out_hostname,
                                               const char **out_action)
{
    *out_details  = "";
    *out_http_code = 0;
    if (out_score) *out_score = -1.0;
    if (out_hostname) *out_hostname = NULL;
    if (out_action)   *out_action   = NULL;

    CURL *curl = curl_easy_init();
    if (!curl) return BS_CAPTCHA_ERROR;

    /* Build URL-encoded body: secret=...&response=...&remoteip=... */
    const char *esc_secret = bs_curl_escape_pool(r->pool, curl,
        (const char *)secret, secret_len);
    const char *esc_token  = bs_curl_escape_pool(r->pool, curl,
        token, strlen(token));
    const char *esc_ip     = bs_curl_escape_pool(r->pool, curl,
        r->useragent_ip ? r->useragent_ip : "",
        r->useragent_ip ? strlen(r->useragent_ip) : 0);
    if (!esc_secret || !esc_token || !esc_ip) {
        curl_easy_cleanup(curl);
        return BS_CAPTCHA_ERROR;
    }
    const char *field = prov->siteverify_field ? prov->siteverify_field
                                               : "response";
    const char *body = apr_psprintf(r->pool,
        "secret=%s&%s=%s&remoteip=%s",
        esc_secret, field, esc_token, esc_ip);

    bs_curl_buffer resp = {
        .buf = apr_palloc(r->pool, BS_MAX_CAPTCHA_BODY),
        .cap = BS_MAX_CAPTCHA_BODY,
        .len = 0, .truncated = 0,
    };

    curl_easy_setopt(curl, CURLOPT_URL, prov->siteverify_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                     (long)BS_CAPTCHA_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_botshield/0.1");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bs_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    *out_http_code = http_code;

    if (rc == CURLE_OPERATION_TIMEDOUT) return BS_CAPTCHA_TIMEOUT;
    if (rc != CURLE_OK) {
        *out_details = curl_easy_strerror(rc);
        return BS_CAPTCHA_ERROR;
    }
    if (http_code < 200 || http_code >= 300) {
        *out_details = apr_psprintf(r->pool, "http-status-%ld", http_code);
        return BS_CAPTCHA_ERROR;
    }

    apr_size_t body_len = resp.len < resp.cap ? resp.len : resp.cap - 1;
    resp.buf[body_len] = '\0';
    return bs_captcha_parse_response(r->pool, resp.buf, body_len,
                                     out_details, out_score,
                                     out_hostname, out_action);
}

/* ----------------------------------------------------------------------
 * GeeTest v4 siteverify. Not the "Google family" shape:
 *
 *   client → server:  JSON blob of {lot_number, pass_token, gen_time,
 *                                   captcha_output} submitted as the
 *                                   `geetest-token` form field.
 *
 *   server → GeeTest: POST {siteverify_url}?captcha_id=<sitekey>
 *                     Content-Type: application/x-www-form-urlencoded
 *                     body: lot_number=...&captcha_output=...
 *                           &pass_token=...&gen_time=...&sign_token=...
 *                     where sign_token = HMAC-SHA256(captcha_key=secret,
 *                                                    lot_number) as hex.
 *
 *   GeeTest → server: {"result":"success"|"fail","reason":"...",...}
 *                     — "result" is a string, not a bool; "reason" is
 *                     the human-readable explanation.
 *
 * We map GeeTest's "success" / "fail" onto BS_CAPTCHA_OK /
 * BS_CAPTCHA_REJECTED the same way the shared path maps the boolean
 * from Google-family providers. Everything else (libcurl buffer,
 * timeouts, write callback, fail-open policy) is shared via the same
 * helpers the default shim uses. */
static apr_status_t bs_geetest_parse_client_token(apr_pool_t *p,
                                                  const char *token,
                                                  const char **out_lot_number,
                                                  const char **out_captcha_output,
                                                  const char **out_pass_token,
                                                  const char **out_gen_time,
                                                  const char **out_err)
{
    *out_lot_number    = NULL;
    *out_captcha_output = NULL;
    *out_pass_token    = NULL;
    *out_gen_time      = NULL;
    *out_err           = NULL;

    if (!token || !*token) {
        *out_err = "empty token";
        return APR_EINVAL;
    }
    json_object *root = json_tokener_parse(token);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root) json_object_put(root);
        *out_err = "token not a JSON object";
        return APR_EINVAL;
    }

    struct { const char *key; const char **out; } fields[] = {
        { "lot_number",     out_lot_number     },
        { "captcha_output", out_captcha_output },
        { "pass_token",     out_pass_token     },
        { "gen_time",       out_gen_time       },
        { NULL, NULL }
    };

    for (int i = 0; fields[i].key; i++) {
        json_object *v = NULL;
        if (!json_object_object_get_ex(root, fields[i].key, &v) || !v) {
            *out_err = apr_psprintf(p, "missing field '%s'", fields[i].key);
            json_object_put(root);
            return APR_EINVAL;
        }
        const char *s = json_object_get_string(v);
        if (!s) {
            *out_err = apr_psprintf(p, "non-string field '%s'", fields[i].key);
            json_object_put(root);
            return APR_EINVAL;
        }
        *fields[i].out = apr_pstrdup(p, s);
    }
    json_object_put(root);
    return APR_SUCCESS;
}

static bs_captcha_result bs_geetest_siteverify(request_rec *r,
                                               const bs_captcha_provider *prov,
                                               const unsigned char *secret,
                                               apr_size_t secret_len,
                                               const char *token,
                                               int timeout_ms,
                                               const char **out_details,
                                               long *out_http_code,
                                               double *out_score,
                                               const char **out_hostname,
                                               const char **out_action)
{
    *out_details   = "";
    *out_http_code = 0;
    if (out_score) *out_score = -1.0;
    /* GeeTest's binding is HMAC-signed over the request side (sign_token
     * covers lot_number), not a string echoed back in the response.
     * Leave the binding out-params NULL — the handler's shared check
     * will see NULL and skip hostname/action comparison for this
     * provider (intended behavior). */
    if (out_hostname) *out_hostname = NULL;
    if (out_action)   *out_action   = NULL;

    /* Need the sitekey (captcha_id) from per-dir cfg. Walk up from r. */
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    if (!cfg || !cfg->captcha_site_key) {
        *out_details = "captcha_id missing from scope";
        return BS_CAPTCHA_ERROR;
    }

    const char *lot_number, *captcha_output, *pass_token, *gen_time;
    const char *perr = NULL;
    if (bs_geetest_parse_client_token(r->pool, token,
            &lot_number, &captcha_output, &pass_token, &gen_time,
            &perr) != APR_SUCCESS) {
        *out_details = perr ? perr : "bad token";
        return BS_CAPTCHA_REJECTED;
    }

    /* sign_token = HMAC-SHA256(captcha_key=secret, lot_number) hex. */
    unsigned char sig[BS_SIG_BYTES];
    bs_hmac_sha256(secret, secret_len,
                   (const unsigned char *)lot_number, strlen(lot_number),
                   sig);
    char sign_token[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(sig, BS_SIG_BYTES, sign_token);

    CURL *curl = curl_easy_init();
    if (!curl) return BS_CAPTCHA_ERROR;

    const char *e_lot    = bs_curl_escape_pool(r->pool, curl, lot_number,     strlen(lot_number));
    const char *e_output = bs_curl_escape_pool(r->pool, curl, captcha_output, strlen(captcha_output));
    const char *e_pass   = bs_curl_escape_pool(r->pool, curl, pass_token,     strlen(pass_token));
    const char *e_time   = bs_curl_escape_pool(r->pool, curl, gen_time,       strlen(gen_time));
    const char *e_id     = bs_curl_escape_pool(r->pool, curl, cfg->captcha_site_key,
                                               strlen(cfg->captcha_site_key));
    if (!e_lot || !e_output || !e_pass || !e_time || !e_id) {
        curl_easy_cleanup(curl);
        return BS_CAPTCHA_ERROR;
    }
    const char *url = apr_psprintf(r->pool,
        "%s?captcha_id=%s", prov->siteverify_url, e_id);
    const char *body = apr_psprintf(r->pool,
        "lot_number=%s&captcha_output=%s&pass_token=%s"
        "&gen_time=%s&sign_token=%s",
        e_lot, e_output, e_pass, e_time, sign_token);

    bs_curl_buffer resp = {
        .buf = apr_palloc(r->pool, BS_MAX_CAPTCHA_BODY),
        .cap = BS_MAX_CAPTCHA_BODY,
        .len = 0, .truncated = 0,
    };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                     (long)BS_CAPTCHA_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_botshield/0.1");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bs_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    *out_http_code = http_code;

    if (rc == CURLE_OPERATION_TIMEDOUT) return BS_CAPTCHA_TIMEOUT;
    if (rc != CURLE_OK) {
        *out_details = curl_easy_strerror(rc);
        return BS_CAPTCHA_ERROR;
    }
    if (http_code < 200 || http_code >= 300) {
        *out_details = apr_psprintf(r->pool, "http-status-%ld", http_code);
        return BS_CAPTCHA_ERROR;
    }

    apr_size_t body_len = resp.len < resp.cap ? resp.len : resp.cap - 1;
    resp.buf[body_len] = '\0';

    /* Parse GeeTest response: {"result":"success"/"fail","reason":"..."}. */
    json_object *root = json_tokener_parse(resp.buf);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root) json_object_put(root);
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(r->pool, resp.buf, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
        return BS_CAPTCHA_ERROR;
    }

    bs_captcha_result out = BS_CAPTCHA_ERROR;
    json_object *res_o = NULL, *reason_o = NULL;
    if (json_object_object_get_ex(root, "result", &res_o) && res_o &&
        json_object_is_type(res_o, json_type_string)) {
        const char *res = json_object_get_string(res_o);
        if (res && strcmp(res, "success") == 0) {
            out = BS_CAPTCHA_OK;
        } else if (res && strcmp(res, "fail") == 0) {
            out = BS_CAPTCHA_REJECTED;
        }
    }
    if (json_object_object_get_ex(root, "reason", &reason_o) && reason_o &&
        json_object_is_type(reason_o, json_type_string)) {
        const char *reason = json_object_get_string(reason_o);
        if (reason) *out_details = apr_pstrdup(r->pool, reason);
    }
    if (out == BS_CAPTCHA_ERROR && (!*out_details || !**out_details)) {
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(r->pool, resp.buf, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
    }
    json_object_put(root);
    return out;
}

/* ----------------------------------------------------------------------
 * M8.1 verify-endpoint guardrails: per-IP rate limit, global in-flight
 * semaphore, per-IP log-throttle. All three live in SHM and use the
 * same "epoch-minute << 20 | count" slot encoding (bs_cv_slot). Reads
 * are torn-tolerant (a CAS loop corrects any bad read); writes are CAS.
 * ---------------------------------------------------------------------- */

/* Hash an IP to a slot index in a power-of-two table. Reuses the SHM
 * SipHash key so precomputed collisions are blocked. */
static apr_uint32_t bs_cv_slot_index(const unsigned char ip[16],
                                     apr_size_t slot_count)
{
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key, ip, 16);
    /* slot_count is a power of two at configuration time. */
    return (apr_uint32_t)(h & (apr_uint64_t)(slot_count - 1));
}

/* Try to increment a window counter at [slots[idx]] under `limit`.
 * Returns 1 on "accepted" (slot incremented, under cap) or 0 on
 * "rejected" (slot at or above cap in the current window). `cur_min`
 * is the current unix-minute. Uses CAS to roll a stale window and to
 * increment. */
static int bs_cv_counter_bump(bs_cv_slot *slots, apr_size_t idx,
                              apr_uint64_t cur_min, int limit)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        /* Relaxed atomic load makes the torn-tolerant observation
         * explicit to the compiler and TSAN; the CAS below will
         * either succeed (so what we read was consistent) or retry. */
        bs_cv_slot observed = __atomic_load_n(&slots[idx],
                                              __ATOMIC_RELAXED);
        bs_cv_slot next;
        if (BS_CV_WINDOW(observed) != cur_min) {
            next = BS_CV_SLOT(cur_min, 1);
        } else {
            apr_uint32_t count = BS_CV_COUNT(observed);
            if ((int)count >= limit) return 0;
            next = BS_CV_SLOT(cur_min, count + 1);
        }
        /* apr_atomic_cas64 isn't universally available; fall back to a
         * 32-bit CAS on the lower half since that's where the count
         * lives. The window rollover is idempotent — a concurrent
         * rollover just re-initializes to (cur_min, 1), which is
         * indistinguishable from our own rollover. */
        if (__sync_bool_compare_and_swap(&slots[idx], observed, next)) {
            return 1;
        }
    }
    /* Contention gave up — fail-open on rate (accept) rather than
     * flap-reject legitimate traffic. Alternate choice would be
     * fail-closed; either is defensible. */
    return 1;
}

/* Per-IP rate limit on the verify endpoint. Returns 1 if the request
 * is within the cap (allow through), 0 if over cap (reject with 429).
 * limit <= 0 disables the check. */
static int bs_captcha_rate_allowed(const unsigned char ip[16], int limit)
{
    if (limit <= 0 || !bs_shm.cv_rate_slots) return 1;
    apr_uint64_t cur_min =
        (apr_uint64_t)(apr_time_sec(apr_time_now()) / 60);
    apr_uint32_t idx =
        bs_cv_slot_index(ip, bs_shm.cv_rate_slot_count);
    return bs_cv_counter_bump(bs_shm.cv_rate_slots, idx, cur_min, limit);
}

/* Global in-flight siteverify semaphore. Returns 1 on acquire, 0 if
 * the cap was already reached (caller must return 503 without calling
 * libcurl). Every successful acquire MUST be paired with a release on
 * every return path. */
static int bs_captcha_inflight_acquire(int max_inflight)
{
    if (!bs_shm.cv_inflight || max_inflight <= 0) return 1;
    for (int attempt = 0; attempt < 8; attempt++) {
        apr_uint32_t cur = apr_atomic_read32(bs_shm.cv_inflight);
        if ((int)cur >= max_inflight) return 0;
        if (apr_atomic_cas32(bs_shm.cv_inflight, cur + 1, cur) == cur) {
            return 1;
        }
    }
    /* Heavy contention — fail-closed here so we don't overshoot the
     * cap under load. Cheap: contention at this level already means
     * we're near the cap. */
    return 0;
}

static void bs_captcha_inflight_release(void)
{
    if (!bs_shm.cv_inflight) return;
    apr_atomic_dec32(bs_shm.cv_inflight);
}

/* Per-IP log-throttle for verify-endpoint lines. Returns 1 if the
 * caller should emit the log, 0 if it should suppress. When emitting
 * after a rollover, *out_prev_count carries the number of events
 * suppressed during the previous window (0 if none or if this is the
 * first event for this slot). Callers typically format the log as
 * `... (×N in last 60s)` when out_prev_count > 1.
 *
 * Each IP gets one log per BS_CAPTCHA_LOG_WINDOW_SEC regardless of
 * how many events fired in between; the count tells the operator
 * how many were collapsed. */
static int bs_captcha_log_throttle(const unsigned char ip[16],
                                   apr_uint32_t *out_prev_count)
{
    if (out_prev_count) *out_prev_count = 0;
    if (!bs_shm.cv_log_slots) return 1;
    apr_uint64_t cur_min =
        (apr_uint64_t)(apr_time_sec(apr_time_now()) /
                       BS_CAPTCHA_LOG_WINDOW_SEC);
    apr_uint32_t idx =
        bs_cv_slot_index(ip, bs_shm.cv_log_slot_count);

    for (int attempt = 0; attempt < 4; attempt++) {
        bs_cv_slot observed = __atomic_load_n(&bs_shm.cv_log_slots[idx],
                                              __ATOMIC_RELAXED);
        if (BS_CV_WINDOW(observed) != cur_min) {
            /* Stale window → this is the first log in a new window.
             * Roll to (cur_min, 1); report how many were suppressed in
             * the old window (if any) so the caller can tell the
             * operator "N events collapsed since the last line". */
            apr_uint32_t prev = BS_CV_COUNT(observed);
            bs_cv_slot next = BS_CV_SLOT(cur_min, 1);
            if (__sync_bool_compare_and_swap(&bs_shm.cv_log_slots[idx],
                                              observed, next)) {
                if (out_prev_count) *out_prev_count = prev;
                return 1;
            }
        } else {
            /* Same window → bump the suppressed count, but don't log. */
            apr_uint32_t count = BS_CV_COUNT(observed);
            bs_cv_slot next = BS_CV_SLOT(cur_min, count + 1);
            if (__sync_bool_compare_and_swap(&bs_shm.cv_log_slots[idx],
                                              observed, next)) {
                return 0;   /* suppressed */
            }
        }
    }
    /* Contention → log (better to have the line than silently drop). */
    return 1;
}

/* Small helper: return " (×N in last 60s)" or "" for prepending to a
 * throttled log line. Allocated on r->pool. */
static const char *bs_log_suppress_suffix(apr_pool_t *p, apr_uint32_t n)
{
    if (n <= 1) return "";
    return apr_psprintf(p, " (×%u in last %ds)",
                        n, BS_CAPTCHA_LOG_WINDOW_SEC);
}

/* ---------- M9.1: structured per-decision log line ----------
 *
 * One machine-parseable line per terminal decision. Emitted alongside
 * the existing human-readable prose lines, not in place of them, so
 * operators tailing the log still see English and M9.2/M9.3 still have
 * a stable contract to count against.
 *
 * Format (keys always in this order; values always present or "-"):
 *
 *   mod_botshield: decision tier=<t> outcome=<o> ip=<i>
 *     score=<n> cookie=<c> provider=<p|-> alg=<a|->
 *     reason="<r|->" path="<u>"
 *
 * Enum values (see PLAN.md M9.1):
 *   tier     = none | pass | silent | form | captcha
 *   outcome  = declined | challenged | verified | rejected | failopen
 *              | rate_limited | inflight_capped | pending_missing
 *              | misconfigured | debug
 *   cookie   = ok | expired | bad_sig | bad_format | absent | -
 *
 * `reason` and `path` are double-quoted because they can carry
 * short-dashed strings from config/heuristics; everything else is a
 * known enum and left unquoted for logfmt readability. */
/* ---- M9.2: string → counter index lookups ----
 *
 * These mirror the M9.1 enum strings verbatim. If a string doesn't map,
 * return -1 — the caller logs a single WARNING and skips the increment
 * rather than silently corrupting counters (the validator should catch
 * this at M9.1 gate, so it's a defense-in-depth check). */
static int bs_m_tier_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "none")    == 0) return BS_M_TIER_NONE;
    if (strcmp(s, "pass")    == 0) return BS_M_TIER_PASS;
    if (strcmp(s, "silent")  == 0) return BS_M_TIER_SILENT;
    if (strcmp(s, "form")    == 0) return BS_M_TIER_FORM;
    if (strcmp(s, "captcha") == 0) return BS_M_TIER_CAPTCHA;
    return -1;
}

static int bs_m_outcome_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "declined")         == 0) return BS_M_OUTCOME_DECLINED;
    if (strcmp(s, "challenged")       == 0) return BS_M_OUTCOME_CHALLENGED;
    if (strcmp(s, "verified")         == 0) return BS_M_OUTCOME_VERIFIED;
    if (strcmp(s, "rejected")         == 0) return BS_M_OUTCOME_REJECTED;
    if (strcmp(s, "failopen")         == 0) return BS_M_OUTCOME_FAILOPEN;
    if (strcmp(s, "rate_limited")     == 0) return BS_M_OUTCOME_RATE_LIMITED;
    if (strcmp(s, "inflight_capped")  == 0) return BS_M_OUTCOME_INFLIGHT_CAPPED;
    if (strcmp(s, "pending_missing")  == 0) return BS_M_OUTCOME_PENDING_MISSING;
    if (strcmp(s, "misconfigured")    == 0) return BS_M_OUTCOME_MISCONFIGURED;
    if (strcmp(s, "debug")            == 0) return BS_M_OUTCOME_DEBUG;
    return -1;
}

static int bs_m_cookie_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "ok")         == 0) return BS_M_COOKIE_OK;
    if (strcmp(s, "expired")    == 0) return BS_M_COOKIE_EXPIRED;
    if (strcmp(s, "bad_sig")    == 0) return BS_M_COOKIE_BAD_SIG;
    if (strcmp(s, "bad_format") == 0) return BS_M_COOKIE_BAD_FORMAT;
    if (strcmp(s, "absent")     == 0) return BS_M_COOKIE_ABSENT;
    return -1;
}

static int bs_m_provider_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "turnstile")    == 0) return BS_M_PROV_TURNSTILE;
    if (strcmp(s, "hcaptcha")     == 0) return BS_M_PROV_HCAPTCHA;
    if (strcmp(s, "recaptcha-v2") == 0) return BS_M_PROV_RECAPTCHA_V2;
    if (strcmp(s, "recaptcha-v3") == 0) return BS_M_PROV_RECAPTCHA_V3;
    if (strcmp(s, "friendly")     == 0) return BS_M_PROV_FRIENDLY;
    if (strcmp(s, "geetest")      == 0) return BS_M_PROV_GEETEST;
    return -1;
}

/* ---- M9.2 on-demand gauge readers ----
 *
 * Called by the metrics export handler (M9.3) when a scraper GETs
 * /botshield/metrics. Not called on the hot decision path. Results
 * cached for 1 second via a tiny static struct so concurrent scrapes
 * don't each walk the flagged-IP table or popcount the Bloom bufs.
 *
 * The cache is deliberately process-local (not SHM) so a read by one
 * worker doesn't stale the value for another — if two workers answer
 * two concurrent scrapes they each do their own computation, but each
 * is still bounded at 1 Hz per worker. */
typedef struct {
    apr_time_t   expires_at;
    apr_uint64_t flagged_used;
    apr_uint64_t bloom_bits_active;
    apr_uint64_t bloom_bits_warming;
} bs_gauge_cache;

/* Thread-local storage. Each worker thread gets its own cache so
 * concurrent /metrics scrapes in one Apache process can't race on the
 * refresh, and we don't need a lock. The 1-second TTL means at worst
 * a thread computes fresh values once per scrape; cost is bounded. */
static __thread bs_gauge_cache bs_gauges = {0, 0, 0, 0};
#define BS_GAUGE_CACHE_TTL_US (1000 * 1000)  /* 1 second */

static apr_uint64_t bs_popcount_u64(apr_uint64_t x)
{
    return (apr_uint64_t)__builtin_popcountll(x);
}

static apr_uint64_t bs_popcount_buffer(const unsigned char *buf,
                                       apr_size_t bytes)
{
    apr_uint64_t total = 0;
    apr_size_t aligned_end = (bytes / 8) * 8;
    const apr_uint64_t *p64 = (const apr_uint64_t *)buf;
    apr_size_t n64 = aligned_end / 8;
    /* Relaxed atomic loads: the Bloom buffer is concurrently mutated
     * via byte-level __atomic_or_fetch in the insert path, so plain
     * u64 loads here would be a data race per the C memory model
     * (even though the hardware on x86_64 gives us the same answer).
     * The popcount result is inherently an approximation of a live
     * counter, so acquire ordering isn't needed — we just need TSAN
     * to see this as a race-tolerant read. */
    for (apr_size_t i = 0; i < n64; i++) {
        total += bs_popcount_u64(
            __atomic_load_n(&p64[i], __ATOMIC_RELAXED));
    }
    /* Tail bytes (Bloom buffers are u64-aligned per the post_config
     * layout, so aligned_end == bytes in practice — keep the loop for
     * safety if that ever changes). */
    for (apr_size_t i = aligned_end; i < bytes; i++) {
        total += (apr_uint64_t)__builtin_popcount(
            __atomic_load_n(&buf[i], __ATOMIC_RELAXED));
    }
    return total;
}

static void bs_gauges_refresh(void)
{
    apr_time_t now = apr_time_now();
    if (now < bs_gauges.expires_at) return;

    apr_uint64_t flagged_used = 0;
    if (bs_shm.flagged_table) {
        apr_int64_t now_sec = (apr_int64_t)apr_time_sec(now);
        for (apr_size_t i = 0; i < bs_shm.flagged_capacity; i++) {
            const bs_flagged_ip_slot *slot = &bs_shm.flagged_table[i];
            /* Skip odd versions (mid-write) — they don't count toward
             * populated slots. A torn read is fine because this is an
             * estimate anyway. */
            if ((slot->version & 1U) == 0 &&
                slot->flags != 0 &&
                slot->expires_at > now_sec) {
                flagged_used++;
            }
        }
    }
    apr_uint64_t bloom_active = 0, bloom_warming = 0;
    if (bs_shm.bloom_bufs[0] && bs_shm.bloom_buf_bytes) {
        apr_uint32_t act = apr_atomic_read32(&bs_shm.header->bloom_active);
        apr_size_t bb = bs_shm.bloom_buf_bytes;
        bloom_active  = bs_popcount_buffer(bs_shm.bloom_bufs[act & 1U], bb);
        bloom_warming = bs_popcount_buffer(bs_shm.bloom_bufs[(act & 1U) ^ 1], bb);
    }

    bs_gauges.flagged_used       = flagged_used;
    bs_gauges.bloom_bits_active  = bloom_active;
    bs_gauges.bloom_bits_warming = bloom_warming;
    bs_gauges.expires_at         = now + BS_GAUGE_CACHE_TTL_US;
}

/* Public gauge accessors. Each refreshes the cache if stale then
 * returns the cached value. M9.3's export handler calls these. */
static apr_uint64_t bs_metrics_flagged_used(void)
{
    bs_gauges_refresh();
    return bs_gauges.flagged_used;
}

static apr_uint64_t bs_metrics_bloom_bits(int active_buf)
{
    bs_gauges_refresh();
    return active_buf ? bs_gauges.bloom_bits_active
                      : bs_gauges.bloom_bits_warming;
}

static apr_uint32_t bs_metrics_inflight_cur(void)
{
    if (!bs_shm.cv_inflight) return 0;
    return apr_atomic_read32(bs_shm.cv_inflight);
}

/* Bump the M9.2 counters for one decision emission. `cookie` and
 * `provider` may be "-" (not applicable); those dimensions skip.
 * Unknown enum strings log one WARNING and skip that dimension — a
 * loud signal that the producer/consumer drifted out of sync. */
static void bs_metrics_bump(request_rec *r,
                            const char *tier, const char *outcome,
                            const char *cookie, const char *provider)
{
    if (!bs_shm.metrics) return;

    int ti = bs_m_tier_idx(tier);
    int oi = bs_m_outcome_idx(outcome);
    int ci = (cookie && strcmp(cookie, "-") != 0)
             ? bs_m_cookie_idx(cookie) : -1;
    int pi = (provider && strcmp(provider, "-") != 0)
             ? bs_m_provider_idx(provider) : -1;

    if (ti >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->tier[ti], 1, __ATOMIC_RELAXED);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown tier=\"%s\" — skipped",
            tier ? tier : "(null)");
    }
    if (oi >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->outcome[oi], 1, __ATOMIC_RELAXED);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown outcome=\"%s\" — skipped",
            outcome ? outcome : "(null)");
    }
    if (ci >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->cookie[ci], 1, __ATOMIC_RELAXED);
    } else if (cookie && strcmp(cookie, "-") != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown cookie=\"%s\" — skipped",
            cookie);
    }
    if (pi >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->provider[pi], 1, __ATOMIC_RELAXED);
    } else if (provider && strcmp(provider, "-") != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown provider=\"%s\" — skipped",
            provider);
    }
}

/* Map a bs_verify_cookie diagnostic to the cookie enum value. NULL
 * reason (accept) → "ok"; other diagnostics classify into the M9.1
 * documented enum. */
static const char *bs_decision_cookie_status(const char *verify_reason,
                                             int had_cookie)
{
    if (!had_cookie) return "absent";
    if (!verify_reason) return "ok";
    if (strcmp(verify_reason, "expired") == 0) return "expired";
    if (strcmp(verify_reason, "signature mismatch") == 0) return "bad_sig";
    return "bad_format";
}

/* Join the request's score-reason names (no penalties) into a single
 * comma-separated string for the decision line. Returns "-" when no
 * heuristic signal fired. */
static const char *bs_decision_reason_names(apr_pool_t *p,
                                            const bs_request_score *s)
{
    if (!s || !s->entries || s->entries->nelts == 0) return "-";
    char *out = apr_pstrdup(p, "");
    for (int i = 0; i < s->entries->nelts; i++) {
        bs_score_entry *e = &APR_ARRAY_IDX(s->entries, i, bs_score_entry);
        out = apr_pstrcat(p, out, i ? "," : "", e->reason, NULL);
    }
    return out;
}

static void bs_decision_log(request_rec *r,
                            const char *tier,
                            const char *outcome,
                            const char *cookie,
                            const char *provider,
                            const char *alg,
                            const char *reason,
                            int score)
{
    const char *ip       = (r->useragent_ip && *r->useragent_ip)
                           ? r->useragent_ip : "-";
    const char *path     = (r->unparsed_uri && *r->unparsed_uri)
                           ? r->unparsed_uri : "-";
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
        "mod_botshield: decision tier=%s outcome=%s ip=%s score=%d "
        "cookie=%s provider=%s alg=%s reason=\"%s\" path=\"%s\"",
        tier, outcome, ip, score,
        cookie   ? cookie   : "-",
        provider ? provider : "-",
        alg      ? alg      : "-",
        reason   ? reason   : "-",
        path);
    /* M9.2: counters derived from the same enum vocabulary. One log
     * line, up to four counter increments (tier, outcome, cookie when
     * applicable, provider when applicable). */
    bs_metrics_bump(r, tier, outcome, cookie, provider);
}

/* URL-decode an x-www-form-urlencoded value in place: '+' → ' ',
 * %XX → byte. Unrecognized sequences are left untouched; a value that
 * survives partial decoding will simply fail siteverify downstream. */
static void bs_urldecode_inplace(char *s)
{
    char *w = s;
    char *rp = s;
    while (*rp) {
        if (*rp == '+') { *w++ = ' '; rp++; continue; }
        if (*rp == '%' && rp[1] && rp[2]) {
            int hi = -1, lo = -1;
            char c = rp[1];
            if      (c >= '0' && c <= '9') hi = c - '0';
            else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
            c = rp[2];
            if      (c >= '0' && c <= '9') lo = c - '0';
            else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
            if (hi >= 0 && lo >= 0) {
                *w++ = (char)((hi << 4) | lo);
                rp += 3;
                continue;
            }
        }
        *w++ = *rp++;
    }
    *w = '\0';
}

/* Read the POST body into an r->pool buffer. Caps length at max_len to
 * prevent a malicious client from forcing us to buffer unbounded bytes
 * during captcha-verify. Returns NULL on error (already responded to
 * the client via ap_setup_client_block) or a pool-allocated NUL-
 * terminated buffer otherwise. */
static const char *bs_read_form_body(request_rec *r, apr_size_t max_len,
                                     apr_size_t *out_len)
{
    *out_len = 0;
    int rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if (rc != OK) return NULL;
    if (!ap_should_client_block(r)) {
        char *empty = apr_pcalloc(r->pool, 1);
        return empty;
    }
    char *buf = apr_palloc(r->pool, max_len + 1);
    apr_size_t total = 0;
    long n;
    char chunk[4096];
    while ((n = ap_get_client_block(r, chunk, sizeof(chunk))) > 0) {
        apr_size_t room = max_len - total;
        apr_size_t take = ((apr_size_t)n < room) ? (apr_size_t)n : room;
        memcpy(buf + total, chunk, take);
        total += take;
        if (total >= max_len) break;
    }
    if (n < 0) return NULL;
    buf[total] = '\0';
    *out_len = total;
    return buf;
}

/* Pick a single field value from a URL-encoded body. Returns a fresh
 * pool-allocated, URL-decoded copy, or NULL if the field is absent —
 * safe to call repeatedly on the same buffer. */
static char *bs_form_get(apr_pool_t *p, const char *body, const char *key)
{
    apr_size_t klen = strlen(key);
    const char *cur = body;
    while (cur && *cur) {
        const char *eq  = strchr(cur, '=');
        const char *amp = strchr(cur, '&');
        if (!eq || (amp && eq > amp)) {
            if (!amp) break;
            cur = amp + 1;
            continue;
        }
        apr_size_t this_klen = (apr_size_t)(eq - cur);
        const char *val     = eq + 1;
        const char *val_end = amp ? amp : (body + strlen(body));
        if (this_klen == klen && strncmp(cur, key, klen) == 0) {
            char *dup = apr_pstrmemdup(p, val, (apr_size_t)(val_end - val));
            bs_urldecode_inplace(dup);
            return dup;
        }
        if (!amp) break;
        cur = amp + 1;
    }
    return NULL;
}

/* Sanity-check a client-supplied return_to for use as a redirect target.
 * Accept only same-origin relative paths: must start with '/', must not
 * start with '//' (protocol-relative), no CR/LF (header injection), and
 * reasonable length. Returns NULL on reject, else the same pointer for
 * caller convenience. */
static const char *bs_sanitize_return_to(const char *s)
{
    if (!s || !*s) return NULL;
    apr_size_t len = strlen(s);
    if (len > 2048) return NULL;
    if (s[0] != '/') return NULL;
    if (s[1] == '/' || s[1] == '\\') return NULL;   /* //host, /\host */
    for (apr_size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n' || c == 0) return NULL;
    }
    return s;
}

/* Set-Cookie string for a server-issued _bs_verified cookie. Mirrors the
 * attributes the M1/M7 interstitial JS produces so a captcha-earned and
 * a PoW-earned cookie are indistinguishable on subsequent requests. */
static const char *bs_build_set_cookie(request_rec *r, const bs_dir_cfg *cfg,
                                       const char *payload_b64,
                                       apr_time_t expires_at)
{
    char expires_buf[APR_RFC822_DATE_LEN];
    apr_rfc822_date(expires_buf, apr_time_from_sec(expires_at + 60));
    const char *secure = "";
    /* Apache exposes the scheme via ap_run_http_scheme or r->server's
     * SSL config; simplest portable check is ap_is_https if mod_ssl is
     * loaded, else fall through. mod_ssl registers ssl_is_https as an
     * optional function; here we take the belt-and-suspenders route and
     * check the r->parsed_uri / r->server / request scheme via
     * ap_http_scheme(r). */
    const char *scheme = ap_http_scheme(r);
    if (scheme && strcmp(scheme, "https") == 0) {
        secure = "; Secure";
    }
    const char *domain = "";
    if (cfg->cookie_domain && *cfg->cookie_domain) {
        domain = apr_psprintf(r->pool, "; Domain=%s", cfg->cookie_domain);
    }
    return apr_psprintf(r->pool,
        "%s=%s; Path=/; Expires=%s%s%s; SameSite=Lax",
        BS_COOKIE_NAME, payload_b64, expires_buf, domain, secure);
}

/* ---- M8.1 challenge-origin "pending" cookie ----
 *
 * Name:  _bs_captcha_pending
 * Value: <nonce_hex>|<expiry_unix_sec>|<hmac_hex>
 *        hmac = HMAC-SHA256(cfg->secret, "pending:" || nonce_hex || ":"
 *                           || expiry_unix_sec_ascii)
 * Attrs: HttpOnly, Secure (on HTTPS), SameSite=Lax, Max-Age=300,
 *        Path=<endpoint_prefix>/captcha-verify (so it's only sent on
 *        verify POSTs, not every request).
 *
 * Minted at captcha-interstitial render time. Verified at the verify
 * endpoint before any libcurl call — missing / tampered / expired all
 * short-circuit to 403 cheaply. Turns blind POST spray at the verify
 * endpoint into a guaranteed early reject. */
#define BS_PENDING_COOKIE_NAME  "_bs_captcha_pending"
#define BS_PENDING_COOKIE_TTL   300   /* seconds */

static const char *bs_mint_pending_cookie(request_rec *r,
                                          const bs_dir_cfg *cfg)
{
    if (!cfg->secret) return NULL;
    unsigned char nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return NULL;
    char nonce_hex[sizeof(nonce) * 2 + 1];
    bs_to_hex(nonce, sizeof(nonce), nonce_hex);

    apr_time_t expiry = apr_time_sec(apr_time_now()) + BS_PENDING_COOKIE_TTL;
    const char *canon = apr_psprintf(r->pool,
        "pending:%s:%" APR_TIME_T_FMT, nonce_hex, expiry);
    unsigned char mac[BS_SIG_BYTES];
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon), mac);
    char mac_hex[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(mac, BS_SIG_BYTES, mac_hex);

    const char *value = apr_psprintf(r->pool,
        "%s|%" APR_TIME_T_FMT "|%s", nonce_hex, expiry, mac_hex);
    const char *prefix = cfg->endpoint_prefix
        ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    const char *scheme = ap_http_scheme(r);
    const char *secure = (scheme && strcmp(scheme, "https") == 0)
        ? "; Secure" : "";
    return apr_psprintf(r->pool,
        BS_PENDING_COOKIE_NAME "=%s; Path=%s/captcha-verify; "
        "HttpOnly%s; SameSite=Lax; Max-Age=%d",
        value, prefix, secure, BS_PENDING_COOKIE_TTL);
}

/* Returns NULL on accept; else a short diagnostic string. On accept,
 * the cookie stays on the request (the handler should emit a
 * Max-Age=0 clear after a successful siteverify so a stale cookie
 * isn't reused). Every failure reason returns to the caller the same
 * way — don't differentiate in the 403 response body, both to avoid
 * leaking validation details and to keep the response constant-time. */
static const char *bs_verify_pending_cookie(request_rec *r,
                                            const bs_dir_cfg *cfg)
{
    if (!cfg->secret) return "no server secret";
    const char *raw = bs_get_cookie_value(r, BS_PENDING_COOKIE_NAME);
    if (!raw || !*raw) return "missing";
    if (strlen(raw) > 256) return "too long";

    char *mut = apr_pstrdup(r->pool, raw);
    char *nonce_hex = mut;
    char *bar1 = strchr(mut, '|');
    if (!bar1) return "bad format";
    *bar1++ = '\0';
    char *expiry_str = bar1;
    char *bar2 = strchr(expiry_str, '|');
    if (!bar2) return "bad format";
    *bar2++ = '\0';
    char *mac_hex = bar2;
    if (strlen(nonce_hex) != 32) return "bad nonce";
    if (strlen(mac_hex)   != BS_SIG_BYTES * 2) return "bad mac length";
    /* nonce must be valid hex — quick check. */
    unsigned char scratch[16];
    if (!bs_from_hex(nonce_hex, sizeof(scratch), scratch)) return "bad nonce hex";

    /* Bounded parse before HMAC (security review #2). apr_atoi64
     * silently clamps/wraps on overflow without signalling; use the
     * bounded helper so gigantic junk is rejected cleanly instead
     * of feeding a nonsense timestamp into the freshness check. */
    apr_int64_t expiry_raw;
    if (!bs_parse_int64_bounded(expiry_str, 1, APR_INT64_MAX, &expiry_raw)) {
        return "bad expiry";
    }
    apr_time_t expiry = (apr_time_t)expiry_raw;
    if (expiry + BS_CLOCK_SKEW_AHEAD < apr_time_sec(apr_time_now())) {
        return "expired";
    }

    const char *canon = apr_psprintf(r->pool,
        "pending:%s:%" APR_TIME_T_FMT, nonce_hex, expiry);
    unsigned char expect[BS_SIG_BYTES];
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon), expect);
    unsigned char got[BS_SIG_BYTES];
    if (!bs_from_hex(mac_hex, BS_SIG_BYTES, got)) return "bad mac hex";
    if (!bs_ct_equal(expect, got, BS_SIG_BYTES)) return "sig mismatch";
    return NULL;
}

/* Set-Cookie clearing the pending cookie (Max-Age=0). Called after a
 * successful verify so a captured cookie can't be replayed. */
static const char *bs_clear_pending_cookie(request_rec *r,
                                           const bs_dir_cfg *cfg)
{
    const char *prefix = cfg->endpoint_prefix
        ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    const char *scheme = ap_http_scheme(r);
    const char *secure = (scheme && strcmp(scheme, "https") == 0)
        ? "; Secure" : "";
    return apr_psprintf(r->pool,
        BS_PENDING_COOKIE_NAME "=; Path=%s/captcha-verify; "
        "HttpOnly%s; SameSite=Lax; Max-Age=0",
        prefix, secure);
}

/* M8 verify handler. Mounted at <prefix>/captcha-verify; POSTed to by
 * the interstitial's form submit when the provider's widget callback
 * fires. On success, server-issues a signed captcha-turnstile cookie
 * and 302s back to the page the user tried to reach. */
/* ---- M9.3: Prometheus text metrics handler ----
 *
 * Mounted at <prefix>/metrics. Emits counters + gauges in a fixed
 * deterministic order with hardcoded metric names (no runtime name
 * construction → no apr_psprintf on the scrape path). Each counter
 * read uses __atomic_load_n with RELAXED; on x86_64 64-bit aligned
 * reads are already atomic, but the intrinsic keeps the compiler
 * from reordering across concurrent writers.
 *
 * Access control is deliberately delegated to Apache: operators gate
 * this endpoint with `<Location /botshield/metrics>` + Require ip /
 * AuthType Basic / etc. The module emits everything to anyone who
 * reaches the handler. Keeps metric exposition out of policy-code. */

#define BS_M_PREFIX "botshield_"

static apr_uint64_t bs_mload(const apr_uint64_t *p)
{
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

/* Emit one Prometheus metric: HELP, TYPE, value. Using a single
 * ap_rprintf per line keeps the scrape path free of intermediate
 * buffers. `name` and `help` are string literals from the caller. */
static void bs_m_emit_counter(request_rec *r, const char *name,
                              const char *help, apr_uint64_t val)
{
    ap_rprintf(r, "# HELP %s%s %s\n", BS_M_PREFIX, name, help);
    ap_rprintf(r, "# TYPE %s%s counter\n", BS_M_PREFIX, name);
    ap_rprintf(r, "%s%s %" APR_UINT64_T_FMT "\n", BS_M_PREFIX, name, val);
}

static void bs_m_emit_gauge(request_rec *r, const char *name,
                            const char *help, apr_uint64_t val)
{
    ap_rprintf(r, "# HELP %s%s %s\n", BS_M_PREFIX, name, help);
    ap_rprintf(r, "# TYPE %s%s gauge\n", BS_M_PREFIX, name);
    ap_rprintf(r, "%s%s %" APR_UINT64_T_FMT "\n", BS_M_PREFIX, name, val);
}

static int bs_metrics_handler(request_rec *r, bs_dir_cfg *cfg)
{
    (void)cfg;
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }
    if (!bs_shm.metrics) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("# metrics not initialized\n", r);
        return OK;
    }

    /* Prometheus exposition format 0.0.4. Content-Type per the spec. */
    ap_set_content_type(r,
        "text/plain; version=0.0.4; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    bs_metrics *m = bs_shm.metrics;

    /* --- Decision counters (ordered tier → outcome → cookie → provider) --- */

    bs_m_emit_counter(r, "tier_none_total",
        "Decisions reaching no tier (pre-tier terminations like debug/asset/misconfig).",
        bs_mload(&m->tier[BS_M_TIER_NONE]));
    bs_m_emit_counter(r, "tier_pass_total",
        "Decisions at tier=pass (no challenge served, request DECLINED).",
        bs_mload(&m->tier[BS_M_TIER_PASS]));
    bs_m_emit_counter(r, "tier_silent_total",
        "Decisions at tier=silent (auto-submit splash interstitial served).",
        bs_mload(&m->tier[BS_M_TIER_SILENT]));
    bs_m_emit_counter(r, "tier_form_total",
        "Decisions at tier=form (checkbox PoW interstitial served).",
        bs_mload(&m->tier[BS_M_TIER_FORM]));
    bs_m_emit_counter(r, "tier_captcha_total",
        "Decisions at tier=captcha (third-party provider widget served or verified).",
        bs_mload(&m->tier[BS_M_TIER_CAPTCHA]));

    bs_m_emit_counter(r, "outcome_declined_total",
        "Decisions where the module returned DECLINED to Apache (pass tier + asset).",
        bs_mload(&m->outcome[BS_M_OUTCOME_DECLINED]));
    bs_m_emit_counter(r, "outcome_challenged_total",
        "Decisions that served an interstitial.",
        bs_mload(&m->outcome[BS_M_OUTCOME_CHALLENGED]));
    bs_m_emit_counter(r, "outcome_verified_total",
        "Captcha verifications that passed siteverify.",
        bs_mload(&m->outcome[BS_M_OUTCOME_VERIFIED]));
    bs_m_emit_counter(r, "outcome_rejected_total",
        "Requests rejected before or by provider siteverify.",
        bs_mload(&m->outcome[BS_M_OUTCOME_REJECTED]));
    bs_m_emit_counter(r, "outcome_failopen_total",
        "Siteverify calls that failed open (timeout, network error, provider 5xx).",
        bs_mload(&m->outcome[BS_M_OUTCOME_FAILOPEN]));
    bs_m_emit_counter(r, "outcome_rate_limited_total",
        "Verify requests rejected by per-IP rate limit.",
        bs_mload(&m->outcome[BS_M_OUTCOME_RATE_LIMITED]));
    bs_m_emit_counter(r, "outcome_inflight_capped_total",
        "Verify requests rejected by global in-flight semaphore.",
        bs_mload(&m->outcome[BS_M_OUTCOME_INFLIGHT_CAPPED]));
    bs_m_emit_counter(r, "outcome_pending_missing_total",
        "Verify POSTs missing or with tampered pending cookie.",
        bs_mload(&m->outcome[BS_M_OUTCOME_PENDING_MISSING]));
    bs_m_emit_counter(r, "outcome_misconfigured_total",
        "Terminations due to missing scope config or internal state.",
        bs_mload(&m->outcome[BS_M_OUTCOME_MISCONFIGURED]));
    bs_m_emit_counter(r, "outcome_debug_total",
        "BotShieldDebug-forced 403 responses.",
        bs_mload(&m->outcome[BS_M_OUTCOME_DEBUG]));

    bs_m_emit_counter(r, "cookie_ok_total",
        "Rep cookies that verified fully (signature + freshness + PoW).",
        bs_mload(&m->cookie[BS_M_COOKIE_OK]));
    bs_m_emit_counter(r, "cookie_expired_total",
        "Rep cookies with valid signature but past expires_at.",
        bs_mload(&m->cookie[BS_M_COOKIE_EXPIRED]));
    bs_m_emit_counter(r, "cookie_bad_sig_total",
        "Rep cookies with HMAC signature mismatch.",
        bs_mload(&m->cookie[BS_M_COOKIE_BAD_SIG]));
    bs_m_emit_counter(r, "cookie_bad_format_total",
        "Rep cookies that failed structural parsing (field count, hex, etc).",
        bs_mload(&m->cookie[BS_M_COOKIE_BAD_FORMAT]));
    bs_m_emit_counter(r, "cookie_absent_total",
        "Requests with no rep cookie.",
        bs_mload(&m->cookie[BS_M_COOKIE_ABSENT]));

    bs_m_emit_counter(r, "provider_turnstile_total",
        "Decisions tagged with provider=turnstile.",
        bs_mload(&m->provider[BS_M_PROV_TURNSTILE]));
    bs_m_emit_counter(r, "provider_hcaptcha_total",
        "Decisions tagged with provider=hcaptcha.",
        bs_mload(&m->provider[BS_M_PROV_HCAPTCHA]));
    bs_m_emit_counter(r, "provider_recaptcha_v2_total",
        "Decisions tagged with provider=recaptcha-v2.",
        bs_mload(&m->provider[BS_M_PROV_RECAPTCHA_V2]));
    bs_m_emit_counter(r, "provider_recaptcha_v3_total",
        "Decisions tagged with provider=recaptcha-v3.",
        bs_mload(&m->provider[BS_M_PROV_RECAPTCHA_V3]));
    bs_m_emit_counter(r, "provider_friendly_total",
        "Decisions tagged with provider=friendly.",
        bs_mload(&m->provider[BS_M_PROV_FRIENDLY]));
    bs_m_emit_counter(r, "provider_geetest_total",
        "Decisions tagged with provider=geetest.",
        bs_mload(&m->provider[BS_M_PROV_GEETEST]));

    /* --- Persistence counters + gauges --- */

    bs_m_emit_counter(r, "state_saves_total",
        "Successful state-file saves (shutdown + periodic).",
        bs_mload(&m->state_saves_total));
    bs_m_emit_counter(r, "state_loads_total",
        "Successful state-file loads at post-config.",
        bs_mload(&m->state_loads_total));
    bs_m_emit_gauge(r, "state_save_last_unix",
        "Unix seconds of the last successful state save.",
        bs_mload(&m->state_save_last_unix));
    bs_m_emit_gauge(r, "state_save_last_bytes",
        "Byte length of the last successful state save.",
        bs_mload(&m->state_save_last_bytes));
    bs_m_emit_gauge(r, "state_save_last_duration_microseconds",
        "Wall-clock microseconds the last save took (build + fsync + rename + dir fsync).",
        bs_mload(&m->state_save_last_duration_us));
    bs_m_emit_gauge(r, "state_load_last_kept",
        "Flagged-IP entries kept across the last state load.",
        bs_mload(&m->state_load_last_kept));
    bs_m_emit_gauge(r, "state_load_last_dropped",
        "Flagged-IP entries dropped as stale during the last state load.",
        bs_mload(&m->state_load_last_dropped));

    /* --- E1 crawler-verification counters --- */

    bs_m_emit_counter(r, "crawler_verified_total",
        "Requests whose crawler UA matched the published IP ranges for "
        "that crawler (legit-bot bypass applied).",
        bs_mload(&m->crawler_verified_total));
    bs_m_emit_counter(r, "crawler_fake_total",
        "Requests with a known-crawler UA whose IP was NOT in that "
        "crawler's published ranges (penalty applied, routed to captcha tier).",
        bs_mload(&m->crawler_fake_total));
    bs_m_emit_counter(r, "crawler_unverified_total",
        "Requests whose crawler UA matched a known pattern but no ranges "
        "file is configured for that crawler (no score effect, logged).",
        bs_mload(&m->crawler_unverified_total));

    /* --- On-demand gauges (may refresh a 1-second cache) --- */

    bs_m_emit_gauge(r, "captcha_inflight_current",
        "Current in-flight captcha siteverify calls.",
        (apr_uint64_t)bs_metrics_inflight_cur());
    bs_m_emit_gauge(r, "shm_flagged_used",
        "Flagged-IP slots currently populated with non-expired entries.",
        bs_metrics_flagged_used());
    bs_m_emit_gauge(r, "shm_flagged_capacity",
        "Configured BotShieldFlaggedIPCapacity.",
        (apr_uint64_t)bs_shm.flagged_capacity);
    bs_m_emit_gauge(r, "bloom_bits_set_active",
        "Set bits in the active Bloom buffer (popcount; ~population proxy).",
        bs_metrics_bloom_bits(1));
    bs_m_emit_gauge(r, "bloom_bits_set_warming",
        "Set bits in the warming Bloom buffer.",
        bs_metrics_bloom_bits(0));
    bs_m_emit_gauge(r, "bloom_window_seconds",
        "Configured BotShieldBloomWindow (full window; rotation at half).",
        (apr_uint64_t)(bs_shm.header
                       ? bs_shm.header->bloom_window_secs : 0));
    bs_m_emit_gauge(r, "cv_rate_slot_capacity",
        "Fixed size of the verify-endpoint rate-limit ring (slots).",
        (apr_uint64_t)bs_shm.cv_rate_slot_count);
    bs_m_emit_gauge(r, "cv_log_slot_capacity",
        "Fixed size of the verify-endpoint log-suppress ring (slots).",
        (apr_uint64_t)bs_shm.cv_log_slot_count);

    return OK;
}

/* ---- M9.3: mod_status contribution ----
 *
 * Called from `mod_status` (when loaded) for /server-status. Two
 * output modes:
 *   AP_STATUS_SHORT  — machine-readable text; one "Key: value" line
 *                      per top-line metric. Same vocabulary as the
 *                      Prometheus names, without the "botshield_"
 *                      prefix (mod_status uses its own keys already).
 *   default          — compact HTML: <h2> + two <table>s. Only the
 *                      top-line counters + gauges an operator glances
 *                      at; full detail lives at /botshield/metrics.
 *
 * Allocation-free: direct ap_rprintf to the active response. No copy
 * of the metrics struct — atomic loads on each access. */
static int bs_status_hook(request_rec *r, int flags)
{
    if (!bs_shm.metrics) return DECLINED;
    bs_metrics *m = bs_shm.metrics;

    if (flags & AP_STATUS_SHORT) {
        ap_rprintf(r,
            "BotShieldTierPass: %" APR_UINT64_T_FMT "\n"
            "BotShieldTierSilent: %" APR_UINT64_T_FMT "\n"
            "BotShieldTierForm: %" APR_UINT64_T_FMT "\n"
            "BotShieldTierCaptcha: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeVerified: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeRejected: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeFailopen: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeRateLimited: %" APR_UINT64_T_FMT "\n"
            "BotShieldCaptchaInflightCurrent: %u\n"
            "BotShieldFlaggedUsed: %" APR_UINT64_T_FMT "\n"
            "BotShieldFlaggedCapacity: %" APR_SIZE_T_FMT "\n",
            bs_mload(&m->tier[BS_M_TIER_PASS]),
            bs_mload(&m->tier[BS_M_TIER_SILENT]),
            bs_mload(&m->tier[BS_M_TIER_FORM]),
            bs_mload(&m->tier[BS_M_TIER_CAPTCHA]),
            bs_mload(&m->outcome[BS_M_OUTCOME_VERIFIED]),
            bs_mload(&m->outcome[BS_M_OUTCOME_REJECTED]),
            bs_mload(&m->outcome[BS_M_OUTCOME_FAILOPEN]),
            bs_mload(&m->outcome[BS_M_OUTCOME_RATE_LIMITED]),
            bs_metrics_inflight_cur(),
            bs_metrics_flagged_used(),
            bs_shm.flagged_capacity);
        return OK;
    }

    ap_rputs("<hr />\n<h2>mod_botshield</h2>\n", r);
    ap_rputs("<table border=\"0\" cellspacing=\"0\" cellpadding=\"3\">\n",
             r);
    ap_rputs("<tr><th>tier</th><th>total</th>"
             "<th></th><th>outcome</th><th>total</th></tr>\n", r);
    /* Two parallel columns: tier distribution on the left, outcome
     * highlights on the right. Keeps the row count tight. */
    const struct { const char *label; apr_uint64_t val; } rows[] = {
        { "pass",    bs_mload(&m->tier[BS_M_TIER_PASS])    },
        { "silent",  bs_mload(&m->tier[BS_M_TIER_SILENT])  },
        { "form",    bs_mload(&m->tier[BS_M_TIER_FORM])    },
        { "captcha", bs_mload(&m->tier[BS_M_TIER_CAPTCHA]) },
        { "none",    bs_mload(&m->tier[BS_M_TIER_NONE])    },
    };
    const struct { const char *label; apr_uint64_t val; } out_rows[] = {
        { "verified",        bs_mload(&m->outcome[BS_M_OUTCOME_VERIFIED])        },
        { "rejected",        bs_mload(&m->outcome[BS_M_OUTCOME_REJECTED])        },
        { "failopen",        bs_mload(&m->outcome[BS_M_OUTCOME_FAILOPEN])        },
        { "rate_limited",    bs_mload(&m->outcome[BS_M_OUTCOME_RATE_LIMITED])    },
        { "pending_missing", bs_mload(&m->outcome[BS_M_OUTCOME_PENDING_MISSING]) },
    };
    for (int i = 0; i < 5; i++) {
        ap_rprintf(r,
            "<tr><td>%s</td><td align=\"right\">%" APR_UINT64_T_FMT "</td>"
            "<td>&nbsp;&nbsp;</td>"
            "<td>%s</td><td align=\"right\">%" APR_UINT64_T_FMT "</td></tr>\n",
            rows[i].label, rows[i].val,
            out_rows[i].label, out_rows[i].val);
    }
    ap_rputs("</table>\n", r);
    ap_rprintf(r,
        "<p>captcha in-flight: %u &nbsp;&nbsp; "
        "flagged IPs: %" APR_UINT64_T_FMT " / %" APR_SIZE_T_FMT " &nbsp;&nbsp; "
        "last state save: %" APR_UINT64_T_FMT " bytes in %" APR_UINT64_T_FMT " \xc2\xb5s "
        "&nbsp;&nbsp;"
        "<a href=\"/botshield/metrics\">full metrics</a></p>\n",
        bs_metrics_inflight_cur(),
        bs_metrics_flagged_used(),
        bs_shm.flagged_capacity,
        bs_mload(&m->state_save_last_bytes),
        bs_mload(&m->state_save_last_duration_us));

    return OK;
}

static int bs_captcha_verify_handler(request_rec *r, bs_dir_cfg *cfg)
{
    /* Response from this endpoint must never be cached by any
     * intermediary — verify is stateful (issues a cookie) and the body
     * only ever contains status text. Set the header early so every
     * return path inherits it. */
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    /* For consistency in the decision log, resolve a provider name up
     * front even if config is partial — misconfigured paths still want
     * a defensible value to emit. */
    const char *prov_name = (cfg->captcha_provider
                             && cfg->captcha_provider->name)
                            ? cfg->captcha_provider->name : "-";

    if (r->method_number != M_POST) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "POST");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("POST required.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "method_not_allowed", 0);
        return OK;
    }

    /* M8.1 cheap prefilter: Content-Type must be form-urlencoded. Reject
     * anything else (JSON bodies, multipart, unset, etc.) immediately —
     * we only parse form bodies downstream and a mismatched type is
     * either a misconfigured client or junk traffic. */
    const char *ctype = apr_table_get(r->headers_in, "Content-Type");
    if (!ctype || strncmp(ctype, "application/x-www-form-urlencoded",
                          sizeof("application/x-www-form-urlencoded") - 1) != 0) {
        r->status = HTTP_UNSUPPORTED_MEDIA_TYPE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-bad-content-type");
        ap_rputs("application/x-www-form-urlencoded required.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "bad_content_type", 0);
        return OK;
    }

    if (!cfg->captcha_provider || !cfg->captcha_site_key ||
        !cfg->captcha_secret || !cfg->secret) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: captcha-verify called on a scope without full "
            "captcha config (provider=%s, sitekey=%s, secret=%s)",
            cfg->captcha_provider ? "set" : "unset",
            cfg->captcha_site_key ? "set" : "unset",
            cfg->captcha_secret   ? "set" : "unset");
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Captcha verification is not configured on this scope.\n", r);
        bs_decision_log(r, "captcha", "misconfigured", "-",
                        prov_name, "-", "-", 0);
        return OK;
    }

    /* M8.1 pending-cookie check. A valid cookie proves the client hit
     * our interstitial within the last 5 minutes; missing or tampered
     * means this is either a blind POST spray or a badly-timed replay.
     * Short-circuit to 403 before any rate slot or body parse. */
    const char *pend_err = bs_verify_pending_cookie(r, cfg);
    if (pend_err) {
        /* Log throttled — a flood of blind POSTs must not drown the log. */
        unsigned char ip_for_log[16];
        int have_ip_for_log =
            bs_parse_client_ip(r->useragent_ip, ip_for_log);
        apr_uint32_t prev = 0;
        int emit = have_ip_for_log
            ? bs_captcha_log_throttle(ip_for_log, &prev) : 1;
        if (emit) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: captcha-verify pending cookie %s%s — 403",
                pend_err, bs_log_suppress_suffix(r->pool, prev));
        }
        r->status = HTTP_FORBIDDEN;
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-pending-missing");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Challenge session missing or expired.\n", r);
        bs_decision_log(r, "captcha", "pending_missing", "-",
                        prov_name, "-", pend_err, 0);
        return OK;
    }

    /* M8.1 per-IP rate limit — *before* reading the body so a flood of
     * junk POSTs gets rejected for ~nothing. 0 disables; default 30. */
    unsigned char client_ip[16];
    int have_ip = bs_parse_client_ip(r->useragent_ip, client_ip);
    if (have_ip) {
        int rate_limit = bs_effective_int(cfg->captcha_rate_limit,
                                          BS_DEFAULT_CAPTCHA_RATE_LIMIT);
        if (!bs_captcha_rate_allowed(client_ip, rate_limit)) {
            /* Logged at INFO via the throttle so a flood doesn't drown
             * the log. First hit per IP per window emits; rest suppress. */
            apr_uint32_t prev = 0;
            int emit = bs_captcha_log_throttle(client_ip, &prev);
            if (emit) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "mod_botshield: captcha-verify rate limit%s "
                    "(ip=%s, limit=%d/min) — 429",
                    bs_log_suppress_suffix(r->pool, prev),
                    r->useragent_ip ? r->useragent_ip : "?", rate_limit);
            }
            r->status = HTTP_TOO_MANY_REQUESTS;
            apr_table_setn(r->err_headers_out, "Retry-After", "60");
            apr_table_setn(r->err_headers_out, "X-Botshield",
                           "captcha-rate-limited");
            ap_set_content_type(r, "text/plain; charset=utf-8");
            ap_rputs("Too many captcha verification attempts.\n", r);
            bs_decision_log(r, "captcha", "rate_limited", "-",
                            prov_name, "-", "-", 0);
            return OK;
        }
    }

    /* M8.1 body size tightened to 8 KB total (was BS_MAX_CAPTCHA_TOKEN
     * + 4096 ~= 12 KB). The largest legitimate body is a GeeTest JSON
     * blob of ~2 KB + return_to ~= 3 KB; 8 KB is comfortable headroom
     * and caps the work a hostile client can force us to buffer. */
    apr_size_t body_len = 0;
    const char *body = bs_read_form_body(r, 8 * 1024, &body_len);
    if (!body) {
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "body_read_failed", 0);
        return HTTP_BAD_REQUEST;
    }
    char *token     = bs_form_get(r->pool, body,
                                  cfg->captcha_provider->token_field);
    char *return_to = bs_form_get(r->pool, body, "return_to");

    const char *safe_return = bs_sanitize_return_to(return_to);
    if (!safe_return) safe_return = "/";

    if (!token || !*token) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: captcha-verify: missing token field '%s'",
            cfg->captcha_provider->token_field);
        r->status = HTTP_BAD_REQUEST;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Missing captcha token.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "no_token", 0);
        return OK;
    }
    if (strlen(token) > BS_MAX_CAPTCHA_TOKEN) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: captcha-verify: token longer than %d bytes",
            BS_MAX_CAPTCHA_TOKEN);
        r->status = HTTP_BAD_REQUEST;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Captcha token too long.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "token_too_long", 0);
        return OK;
    }

    /* M8.1 global in-flight semaphore. Holds for the duration of the
     * libcurl call; all return paths below release before returning. */
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    int max_inflight = scfg ? scfg->captcha_max_inflight
                            : BS_DEFAULT_CAPTCHA_MAX_INFLIGHT;
    if (!bs_captcha_inflight_acquire(max_inflight)) {
        apr_uint32_t prev = 0;
        int emit = have_ip
            ? bs_captcha_log_throttle(client_ip, &prev) : 1;
        if (emit) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: captcha-verify in-flight cap reached%s "
                "(max=%d) — 503; provider likely slow",
                bs_log_suppress_suffix(r->pool, prev), max_inflight);
        }
        r->status = HTTP_SERVICE_UNAVAILABLE;
        apr_table_setn(r->err_headers_out, "Retry-After", "2");
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-saturated");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Captcha verification busy, try again shortly.\n", r);
        bs_decision_log(r, "captcha", "inflight_capped", "-",
                        prov_name, "-", "-", 0);
        return OK;
    }

    int timeout = bs_effective_int(cfg->captcha_timeout_ms,
                                   BS_DEFAULT_CAPTCHA_TIMEOUT);

    const char *details = NULL;
    long http_code = 0;
    double score = -1.0;
    const char *resp_hostname = NULL;
    const char *resp_action   = NULL;
    /* Provider-specific verify path overrides the shared shim when set.
     * GeeTest is the current user (HMAC-signed body, non-bool result
     * semantics); the other five providers leave siteverify_fn NULL. */
    bs_captcha_siteverify_fn verify_fn =
        cfg->captcha_provider->siteverify_fn
        ? cfg->captcha_provider->siteverify_fn
        : bs_captcha_siteverify;
    bs_captcha_result result = verify_fn(
        r, cfg->captcha_provider,
        cfg->captcha_secret, cfg->captcha_secret_len,
        token, timeout, &details, &http_code, &score,
        &resp_hostname, &resp_action);
    /* In-flight semaphore released as soon as the libcurl call returns.
     * The rest of the handler (cookie issuance, redirect) doesn't hold
     * a provider slot. */
    bs_captcha_inflight_release();

    /* Security review #1: bind the token to this origin + flow.
     *   - hostname: provider-echoed domain of the site where the
     *     challenge was solved. Check against the configured expected
     *     hostname (default = r->server->server_hostname) so a token
     *     minted on another origin but sharing the same sitekey can't
     *     satisfy verification here.
     *   - action (reCAPTCHA v3, Turnstile): the string the client
     *     widget tagged the token with. We embed `action: 'botshield'`
     *     in the interstitial JS, so a token from a different form on
     *     the same sitekey will carry a different action. Without this
     *     check, reCAPTCHA v3 in particular is score-threshold-only,
     *     which a stolen-from-elsewhere token with a high score would
     *     sail through.
     *
     * Mismatch flips OK → REJECTED with a descriptive details string
     * so the prose + decision log both carry the "why". An operator
     * can opt out of either check by setting the directive value to
     * the empty string. */
    if (result == BS_CAPTCHA_OK) {
        const char *expected_host =
            cfg->captcha_expected_hostname
                ? cfg->captcha_expected_hostname
                : (r->server && r->server->server_hostname
                       ? r->server->server_hostname : "");
        const char *expected_action =
            cfg->captcha_expected_action
                ? cfg->captcha_expected_action
                : "botshield";

        if (resp_hostname && *expected_host &&
            strcmp(resp_hostname, expected_host) != 0) {
            details = apr_psprintf(r->pool,
                "hostname-mismatch:got=%s,expected=%s",
                resp_hostname, expected_host);
            result = BS_CAPTCHA_REJECTED;
        } else if (resp_action && *expected_action &&
                   strcmp(resp_action, expected_action) != 0) {
            details = apr_psprintf(r->pool,
                "action-mismatch:got=%s,expected=%s",
                resp_action, expected_action);
            result = BS_CAPTCHA_REJECTED;
        }
    }

    /* reCAPTCHA v3 score threshold. Applied *after* success:true — the
     * provider said the token is valid; we still reject if the signal
     * is too weak. A missing score on a v3 response is a protocol
     * surprise (v3 always returns one); treat that as ERROR so the
     * fail-open path runs rather than silently accepting or rejecting.
     * The plain REJECTED path above stays exactly as it was. */
    /* Log-throttle is only invoked from failure branches so a flood of
     * happy-path OKs doesn't bump the slot counter and starve later
     * REJECTED/WARNING emissions. OK paths log unconditionally — the
     * throttle exists to protect against hostile/broken traffic. */
    int is_v3 = (strcmp(cfg->captcha_provider->name, "recaptcha-v3") == 0);
    if (result == BS_CAPTCHA_OK && is_v3) {
        double min_score = (cfg->recaptcha_v3_min_score >= 0.0)
            ? cfg->recaptcha_v3_min_score
            : BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE;
        if (score < 0.0) {
            apr_uint32_t prev = 0;
            int emit = have_ip
                ? bs_captcha_log_throttle(client_ip, &prev) : 1;
            if (emit) ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: reCAPTCHA v3 response missing score%s — "
                "failing open (provider=%s http=%ld)",
                bs_log_suppress_suffix(r->pool, prev),
                cfg->captcha_provider->name, http_code);
            /* fall through to success path (fail-open) */
        } else if (score < min_score) {
            apr_uint32_t prev = 0;
            int emit = have_ip
                ? bs_captcha_log_throttle(client_ip, &prev) : 1;
            if (emit) ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: captcha REJECTED%s "
                "(provider=%s http=%ld score=%.2f min=%.2f)",
                bs_log_suppress_suffix(r->pool, prev),
                cfg->captcha_provider->name, http_code,
                score, min_score);
            r->status = HTTP_FORBIDDEN;
            ap_set_content_type(r, "text/plain; charset=utf-8");
            apr_table_setn(r->err_headers_out, "X-Botshield", "captcha-rejected");
            ap_rputs("Verification score too low. Go back and try again.\n", r);
            bs_decision_log(r, "captcha", "rejected", "-",
                            cfg->captcha_provider->name, "-",
                            apr_psprintf(r->pool, "low_score:%.2f", score),
                            0);
            return OK;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: captcha OK (provider=%s http=%ld "
                "score=%.2f min=%.2f return_to=%s)",
                cfg->captcha_provider->name, http_code,
                score, min_score, safe_return);
        }
    } else if (result == BS_CAPTCHA_REJECTED) {
        apr_uint32_t prev = 0;
        int emit = have_ip
            ? bs_captcha_log_throttle(client_ip, &prev) : 1;
        if (emit) ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: captcha REJECTED%s "
            "(provider=%s http=%ld error-codes=[%s])",
            bs_log_suppress_suffix(r->pool, prev),
            cfg->captcha_provider->name, http_code,
            details ? details : "");
        r->status = HTTP_FORBIDDEN;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->err_headers_out, "X-Botshield", "captcha-rejected");
        ap_rputs("Captcha verification failed. Go back and try again.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        cfg->captcha_provider->name, "-",
                        (details && *details) ? details : "-", 0);
        return OK;
    } else if (result == BS_CAPTCHA_TIMEOUT || result == BS_CAPTCHA_ERROR) {
        /* Fail-open is an attack surface while a provider is unavailable.
         * The WARNING-level log line carries the literal string
         * "failing open" so operators can grep/alert on it; M9.2 counts
         * these as outcome=failopen. */
        apr_uint32_t prev = 0;
        int emit = have_ip
            ? bs_captcha_log_throttle(client_ip, &prev) : 1;
        if (emit) ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: captcha %s — failing open%s "
            "(provider=%s http=%ld detail=\"%s\")",
            result == BS_CAPTCHA_TIMEOUT ? "TIMEOUT" : "ERROR",
            bs_log_suppress_suffix(r->pool, prev),
            cfg->captcha_provider->name, http_code,
            details ? details : "");
        /* fall through to success path */
    } else {
        /* Plain OK, non-v3 provider. */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: captcha OK (provider=%s http=%ld return_to=%s)",
            cfg->captcha_provider->name, http_code, safe_return);
    }

    /* Issue a captcha-alg signed cookie. Rep starts from any prior
     * cookie if one is still valid, with captcha forgiveness applied. */
    const char *prior_val = bs_get_cookie_value(r, BS_COOKIE_NAME);
    bs_challenge prior_ch = { 0 };
    int have_prior = 0;
    if (prior_val && *prior_val) {
        if (bs_verify_cookie(r, cfg, prior_val, &prior_ch) != NULL) {
            /* Either signature-ok-but-expired (ok to carry rep) or
             * signature-mismatch. Only carry forward if the sig was ok —
             * same invariant as bs_handler. We can't distinguish here
             * without re-parsing; err on the side of carrying forward
             * only when the struct was fully populated. */
            if (prior_ch.alg_name) have_prior = 1;
        } else {
            have_prior = 1;
        }
    }

    bs_rep_state next_rep;
    if (have_prior) {
        int forgive = bs_effective_int(cfg->forgive_captcha,
                                       BS_DEFAULT_FORGIVE_CAPTCHA);
        int floor   = bs_flag_penalty(prior_ch.rep.flags);
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < floor) new_score = floor;
        if (new_score < 0)     new_score = 0;
        next_rep = prior_ch.rep;
        next_rep.score          = new_score;
        next_rep.passes_captcha = prior_ch.rep.passes_captcha + 1;
    } else {
        next_rep.score          = 0;
        next_rep.flags          = 0;
        next_rep.passes_silent  = 0;
        next_rep.passes_form    = 0;
        next_rep.passes_captcha = 1;
        next_rep.challenged_at  = 0;   /* overwritten by issue() */
    }

    int ttl        = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);
    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);

    /* Cookie alg name is derived from provider name by convention so
     * adding a provider doesn't require touching this handler — just the
     * two registries. If bs_algorithms[] is missing the matching entry,
     * that's a build-time oversight, not a config error, so fail hard. */
    const char *cookie_alg_name = apr_psprintf(r->pool, "captcha-%s",
                                               cfg->captcha_provider->name);
    const bs_pow_algorithm *captcha_alg = bs_find_algorithm(cookie_alg_name);
    if (!captcha_alg || !captcha_alg->implemented) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: cookie alg '%s' missing from registry — "
            "provider '%s' is wired up but its cookie-alg row isn't",
            cookie_alg_name, cfg->captcha_provider->name);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Service error: captcha cookie alg not registered.\n", r);
        bs_decision_log(r, "captcha", "misconfigured", "-",
                        cfg->captcha_provider->name, cookie_alg_name,
                        "cookie_alg_missing", 0);
        return OK;
    }

    bs_challenge ch;
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          /* auto_tier */ 0,
                                          captcha_alg, &next_rep, &ch);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: captcha cookie issue failed: %s", ierr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Service error: could not issue cookie.\n", r);
        bs_decision_log(r, "captcha", "misconfigured", "-",
                        cfg->captcha_provider->name, cookie_alg_name,
                        "issue_failed", 0);
        return OK;
    }

    const char *payload = bs_build_cookie_payload(r->pool, &ch, "captcha");
    const char *set_cookie = bs_build_set_cookie(r, cfg, payload,
                                                 ch.expires_at);
    /* Two Set-Cookie headers: the verified-rep cookie, and a Max-Age=0
     * clear for the pending cookie so the solved challenge can't be
     * replayed. apr_table_add (not setn) preserves both. */
    apr_table_add(r->err_headers_out, "Set-Cookie", set_cookie);
    apr_table_add(r->err_headers_out, "Set-Cookie",
                  bs_clear_pending_cookie(r, cfg));
    apr_table_setn(r->headers_out, "Location",      safe_return);
    apr_table_setn(r->headers_out, "X-Botshield",   "captcha-ok");
    r->status = HTTP_SEE_OTHER;   /* 303 — POST→GET redirect */
    /* Decision log: verified = real OK, failopen = provider was
     * unavailable but we issued anyway. The v3 missing-score branch
     * also falls through here — detect via details carrying an ERROR/
     * TIMEOUT marker stored earlier. Simplest: re-check `result`. */
    const char *d_outcome = (result == BS_CAPTCHA_OK) ? "verified" : "failopen";
    const char *d_reason  = "-";
    if (result == BS_CAPTCHA_TIMEOUT) d_reason = "provider_timeout";
    else if (result == BS_CAPTCHA_ERROR) d_reason = "provider_error";
    bs_decision_log(r, "captcha", d_outcome, "-",
                    cfg->captcha_provider->name, cookie_alg_name,
                    d_reason, 0);
    return OK;
}




static bs_request_score *bs_get_score(request_rec *r, int create)
{
    bs_request_score *s = ap_get_module_config(r->request_config,
                                               &botshield_module);
    if (!s && create) {
        s = apr_pcalloc(r->pool, sizeof(*s));
        s->entries = apr_array_make(r->pool, 4, sizeof(bs_score_entry));
        ap_set_module_config(r->request_config, &botshield_module, s);
    }
    return s;
}

/* `reason` must outlive the request — static string or r->pool-allocated.
 * `ttl_seconds` is accepted for API stability but ignored in M3 (the
 * request-scoped struct dies with the request). The long-term stores
 * are narrower than the API implies: M4 puts accumulated rep in the
 * user's cookie (per-user, server-stateless); M5 puts serious-event
 * flags in an SHM flagged-IP table (sparse, per-IP). `ttl_seconds`
 * feeds the latter when the caller is a serious-event source. */
static void bs_score_add(request_rec *r, int penalty,
                         int ttl_seconds, const char *reason)
{
    bs_request_score *s = bs_get_score(r, 1);
    if (s->entries->nelts >= BS_SCORE_MAX_REASONS) return;
    bs_score_entry *e = apr_array_push(s->entries);
    e->penalty     = penalty;
    e->ttl_seconds = ttl_seconds;
    e->reason      = reason;
    s->total      += penalty;
}

/* Build a compact "[reason:penalty,reason:penalty,...]" string for logs. */
static const char *bs_score_reasons_joined(apr_pool_t *p,
                                           const bs_request_score *s)
{
    if (!s || !s->entries || s->entries->nelts == 0) return "[]";
    char *out = apr_pstrdup(p, "[");
    for (int i = 0; i < s->entries->nelts; i++) {
        bs_score_entry *e = &APR_ARRAY_IDX(s->entries, i, bs_score_entry);
        out = apr_pstrcat(p, out, i ? "," : "",
                          e->reason, ":", apr_itoa(p, e->penalty), NULL);
    }
    return apr_pstrcat(p, out, "]", NULL);
}

/* Cheap built-in signals, run on requests we're about to challenge. Called
 * after the cookie check — a verified cookie skips scoring entirely. */
static void bs_run_builtin_heuristics(request_rec *r)
{
    /* E1: crawler allow-list runs first. A verified crawler adds a
     * large negative penalty that dominates anything else scoring
     * might pile on (scraper UA tokens in "Googlebot" etc.) and
     * collapses tier dispatch to pass. */
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    bs_check_legit_crawler(r, dcfg);

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (!ua || !*ua) {
        bs_score_add(r, BS_PENALTY_MISSING_UA, 3600, "missing-user-agent");
    }
    const char *al = apr_table_get(r->headers_in, "Accept-Language");
    if (!al || !*al) {
        bs_score_add(r, BS_PENALTY_MISSING_AL, 3600, "missing-accept-language");
    }

    /* Obvious scraper / HTTP-library UA fragments. Case-sensitive on
     * purpose — we pick both casings where both actually appear in the
     * wild. Matches are flagged, not blocked, so false positives only
     * cost a tier bump. */
    if (ua && *ua) {
        static const char *const scraper_tokens[] = {
            "curl", "Wget", "wget",
            "python", "Python", "python-requests",
            "urllib", "httpx", "aiohttp",
            "Go-http-client", "okhttp", "axios", "scrapy",
            "java", "Java", "libwww", "lwp-request",
            NULL
        };
        for (int i = 0; scraper_tokens[i]; i++) {
            if (strstr(ua, scraper_tokens[i])) {
                bs_score_add(r, BS_PENALTY_SCRAPER_UA, 3600,
                    apr_psprintf(r->pool, "scraper-ua-%s", scraper_tokens[i]));
                break;
            }
        }
    }
}

/* Pick a tier from the running score. Each tier has its own
 * interstitial: silent → auto-submit splash; form → reCAPTCHA-shaped
 * checkbox; captcha → configured third-party provider's widget. When
 * captcha tier is selected but no provider is configured on the scope,
 * the render code falls through to form-PoW (documented in the
 * decision log as reason="captcha_fallback"). */
static bs_tier bs_decide_tier(const bs_dir_cfg *cfg, int score)
{
    int silent  = bs_effective_int(cfg->score_silent,  BS_DEFAULT_SCORE_SILENT);
    int hard    = bs_effective_int(cfg->score_hard,    BS_DEFAULT_SCORE_HARD);
    int captcha = bs_effective_int(cfg->score_captcha, BS_DEFAULT_SCORE_CAPTCHA);
    if (score >= captcha) return BS_TIER_CAPTCHA;
    if (score >= hard)    return BS_TIER_HARD;
    if (score >= silent)  return BS_TIER_SILENT;
    return BS_TIER_PASS;
}

static const char *bs_tier_name(bs_tier t)
{
    switch (t) {
        case BS_TIER_PASS:    return "pass";
        case BS_TIER_SILENT:  return "silent";
        case BS_TIER_HARD:    return "form";
        case BS_TIER_CAPTCHA: return "captcha";
    }
    return "?";
}

static const command_rec bs_cmds[] = {
    AP_INIT_FLAG("BotShieldEnabled",    bs_set_enabled,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Turn mod_botshield on/off for the enclosing scope (default: off)"),
    AP_INIT_FLAG("BotShieldDebug",      bs_set_debug,      NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "If on, return 403 'Hello World' for every request in the "
                 "enclosing scope (default: off)"),
    AP_INIT_TAKE1("BotShieldCookieTTL", bs_set_cookie_ttl, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Seconds a verified cookie stays valid (default: 3600, "
                 "range 1..86400)"),
    AP_INIT_TAKE1("BotShieldDifficulty",bs_set_difficulty, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Number of leading hex zeros the PoW must produce (default: 4)"),
    AP_INIT_TAKE1("BotShieldPromptText", bs_set_prompt,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Label shown next to the checkbox (default: \"I'm not a robot\"). "
                 "HTML-escaped at render time."),
    AP_INIT_TAKE1("BotShieldLogoFile",   bs_set_logo_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to an SVG file served inline as the widget logo. "
                 "Read once at startup; must be <= 64 KB. "
                 "Default: embedded Guardian shield."),
    AP_INIT_TAKE1("BotShieldLogoLabel",  bs_set_logo_label,NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Small caption under the logo (default: \"botshield\"). "
                 "Empty string hides it."),
    AP_INIT_FLAG("BotShieldShowLogo",   bs_set_show_logo,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Show the brand column — logo + caption (default: on). "
                 "Off removes the whole column from the widget."),
    AP_INIT_FLAG("BotShieldShowLabel",  bs_set_show_label, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Show the prompt text next to the checkbox (default: on). "
                 "Off hides the text and moves it to the button's aria-label "
                 "so screen readers still hear it."),
    AP_INIT_FLAG("BotShieldShowBox",    bs_set_show_box,   NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Show the widget's outer box — border, background, shadow "
                 "(default: on). Off leaves just the controls for the admin's "
                 "page to style around."),
    AP_INIT_TAKE1("BotShieldHelp",       bs_set_help,      NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Help visibility: off | on | button (default: button). "
                 "'button' shows a '?' link under the widget that toggles "
                 "an explainer panel."),
    AP_INIT_TAKE1("BotShieldHelpFile",   bs_set_help_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to an HTML fragment used as the help panel content. "
                 "Read once at startup; must be <= 64 KB. Contents are "
                 "trusted (no escaping). Default: a built-in explanation."),
    AP_INIT_TAKE1("BotShieldChallengeFile", bs_set_challenge_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to a full HTML page that wraps the verification "
                 "widget. Must contain the marker '" BS_WIDGET_MARKER "' "
                 "where the widget should be inserted. Read once at startup; "
                 "must be <= 256 KB. Other BotShield* directives still apply "
                 "to the widget block."),
    AP_INIT_TAKE1("BotShieldSecretFile", bs_set_secret_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to the HMAC key used to sign challenge cookies. "
                 "Must be mode 0600 (not group- or world-accessible) and "
                 ">= 16 bytes. Read once at startup."),
    AP_INIT_TAKE1("BotShieldAlgorithm",  bs_set_algorithm,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Proof-of-work algorithm name. Only 'sha256-zeros' is built "
                 "into this module today; 'sha384-zeros' / 'sha512-zeros' / "
                 "'pbkdf2-sha256' / 'argon2id' are registry slots reserved "
                 "for future opt-in builds."),
    AP_INIT_TAKE1("BotShieldScoreSilent",  bs_set_score_silent,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the silent-PoW tier is picked "
                 "(default: 20). Serves a no-click auto-submit splash."),
    AP_INIT_TAKE1("BotShieldScoreHard",    bs_set_score_hard,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the form-PoW tier is picked "
                 "(default: 50). Serves the checkbox interstitial."),
    AP_INIT_TAKE1("BotShieldScoreCaptcha", bs_set_score_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the captcha tier is picked "
                 "(default: 80). Serves the configured third-party "
                 "provider's widget; falls through to form-PoW if no "
                 "BotShieldCaptchaProvider is set on the scope."),
    AP_INIT_TAKE1("BotShieldForgivenessSilent", bs_set_forgive_silent, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful silent-PoW pass "
                 "(default: 10). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessForm",   bs_set_forgive_form,   NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful form-PoW pass "
                 "(default: 25). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessCaptcha",bs_set_forgive_captcha,NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful captcha pass "
                 "(default: 50). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldCookieDomain", bs_set_cookie_domain, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "If set, Set-Cookie for _bs_verified includes a Domain= "
                 "attribute so reputation follows users across subdomains. "
                 "Use '.example.com' for subdomain sharing. Default: host-only."),
    AP_INIT_TAKE1("BotShieldEndpointPrefix", bs_set_endpoint_prefix, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "URL prefix for module-owned handlers (default: /botshield). "
                 "Must start with '/' and not end with '/'. Change it if this "
                 "collides with real app routes."),
    AP_INIT_TAKE1("BotShieldCaptchaProvider", bs_set_captcha_provider, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Third-party captcha provider for the captcha tier. Built "
                 "in: 'turnstile' (Cloudflare), 'hcaptcha', 'recaptcha-v2', "
                 "'recaptcha-v3' (with BotShieldRecaptchaV3MinScore), "
                 "'friendly' (Friendly Captcha), 'geetest' (GeeTest v4). "
                 "Unrecognized names fail at configtest time."),
    AP_INIT_TAKE1("BotShieldCaptchaSiteKey", bs_set_captcha_site_key, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Provider-public site key embedded in the captcha widget."),
    AP_INIT_TAKE1("BotShieldCaptchaSecretFile", bs_set_captcha_secret_file,
                 NULL, RSRC_CONF | ACCESS_CONF,
                 "Path to the captcha provider's secret key, used in "
                 "server-side siteverify calls. Must be mode 0600 (not "
                 "group- or world-accessible). Read once at startup."),
    AP_INIT_TAKE1("BotShieldCaptchaTimeout", bs_set_captcha_timeout, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Siteverify HTTP call timeout in milliseconds "
                 "(default: 1000, range 100..5000). On timeout the module "
                 "fails open — issues the cookie and logs a WARNING."),
    AP_INIT_TAKE1("BotShieldRecaptchaV3MinScore",
                 bs_set_recaptcha_v3_min_score, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Minimum score (0.0..1.0) to accept a reCAPTCHA v3 "
                 "verification (default: 0.5). Scores below this are "
                 "logged as REJECTED with the numeric score."),
    AP_INIT_TAKE1("BotShieldCaptchaExpectedHostname",
                 bs_set_captcha_expected_hostname, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Hostname the captcha provider must echo back in the "
                 "siteverify response for the token to be accepted. "
                 "Default: the vhost's server_hostname. Empty string "
                 "disables the check (for multi-origin deployments)."),
    AP_INIT_TAKE1("BotShieldCaptchaExpectedAction",
                 bs_set_captcha_expected_action, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Action string the client widget must tag the captcha "
                 "token with (reCAPTCHA v3 + Turnstile). Default: "
                 "'botshield'. Empty string disables the check. "
                 "Mismatch rejects the token."),
    AP_INIT_TAKE1("BotShieldCaptchaRateLimit", bs_set_captcha_rate_limit,
                 NULL, RSRC_CONF | ACCESS_CONF,
                 "Max captcha-verify POSTs per IP per minute (default: 30, "
                 "range 0..1000; 0 disables). Over cap returns 429 Retry-"
                 "After without calling the provider. Scope: per-dir."),
    AP_INIT_TAKE1("BotShieldCaptchaMaxInFlight", bs_set_captcha_max_inflight,
                 NULL, RSRC_CONF,
                 "Global cap on concurrent outbound siteverify calls "
                 "(default: 64, range 1..1024). Over cap returns 503 "
                 "with WARNING. Server-scope only."),
    AP_INIT_TAKE1("BotShieldShmSize", bs_set_shm_size, NULL,
                 RSRC_CONF,
                 "Total shared-memory budget for flagged-IP table and "
                 "(future) Bloom filter. Accepts K/M/G suffixes. "
                 "Default: 8M. Range: 128K..256M."),
    AP_INIT_TAKE1("BotShieldFlaggedIPCapacity", bs_set_flagged_capacity, NULL,
                 RSRC_CONF,
                 "Slot count in the flagged-IP hash table. Each slot is "
                 "32 bytes. Default: 50000 (≈ 1.6 MB). "
                 "Range: 1024..1000000."),
    AP_INIT_TAKE1("BotShieldIPv6PrefixLen", bs_set_ipv6_prefix, NULL,
                 RSRC_CONF,
                 "Native-IPv6 clients are keyed on this prefix length in "
                 "the flagged-IP table. Default 64 — one subscriber "
                 "allocation is one identity, so an attacker with a /64 "
                 "can't rotate addresses to shed a flag. 128 disables "
                 "aggregation. IPv4 (v6-mapped) keys are never masked."),
    AP_INIT_TAKE1("BotShieldBloomIPs", bs_set_bloom_ips, NULL,
                 RSRC_CONF,
                 "Expected working-set size for the first-sight Bloom "
                 "filter. Drives buffer size at ~10 bits/IP (1% FP). "
                 "Default 1000000 (2.4 MB total for the two buffers). "
                 "Range 1000..10000000."),
    AP_INIT_TAKE1("BotShieldBloomWindow", bs_set_bloom_window, NULL,
                 RSRC_CONF,
                 "Full lifetime window for Bloom entries, in seconds. "
                 "Rotation happens at half-window. Default 604800 (1 week) "
                 "→ 3.5 day guaranteed minimum lifetime, 7 day max. "
                 "Range 3600..2592000."),
    AP_INIT_TAKE1("BotShieldStateFile", bs_set_state_file, NULL,
                 RSRC_CONF,
                 "Path to a binary file used to persist flagged-IP and "
                 "Bloom state across graceful restarts. Written atomically "
                 "at clean shutdown; loaded (with checksum and dimension "
                 "checks) at startup. Any problem at load time is treated "
                 "as 'start fresh'. Unset (default) disables persistence."),
    AP_INIT_TAKE1("BotShieldStateSaveInterval", bs_set_state_save_interval, NULL,
                 RSRC_CONF,
                 "Seconds between periodic state snapshots via mod_watchdog. "
                 "Default 300 (5 min). 0 disables periodic saves (only the "
                 "graceful-shutdown save runs). Range when non-zero: "
                 "30..86400. Requires mod_watchdog to be loaded; otherwise "
                 "degrades to shutdown-only with a NOTICE."),
    AP_INIT_TAKE12("BotShieldFlagIP", bs_set_flag_ip, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Flag the client IP with one or more bits when a request "
                 "hits this scope. Flag names: honeypot_hit, scanner_probe, "
                 "fake_crawler, pow_fail_streak. Optional second argument "
                 "is the TTL in seconds (default 3600). Use inside a "
                 "<Location> for honeypot paths."),
    /* E1 */
    AP_INIT_FLAG("BotShieldLegitCrawlers", bs_set_crawlers_enabled,
                 NULL, RSRC_CONF,
                 "Enable the verified legit-crawler allow-list. Default "
                 "off. When on, classified crawler UAs are matched "
                 "against loaded IP ranges: in-range gets a large "
                 "negative penalty (tier=pass bypass); out-of-range "
                 "gets a fake-<name> penalty routing to captcha tier."),
    AP_INIT_TAKE2("BotShieldLegitCrawlerPattern",
                 bs_set_crawler_pattern, NULL, RSRC_CONF,
                 "Register an extra crawler UA pattern. Two args: "
                 "<name> <substring>. Name is used as the ranges-file "
                 "basename and decision-log identifier; substring is a "
                 "case-insensitive needle looked for in the UA header. "
                 "Built-in crawlers are auto-registered; this directive "
                 "extends the list."),
    AP_INIT_TAKE2("BotShieldLegitCrawlerRanges",
                 bs_set_crawler_ranges, NULL, RSRC_CONF,
                 "Set or override the CIDR ranges file path for a "
                 "crawler. Two args: <name> <path>. Default path is "
                 "/var/lib/botshield/crawlers/<name>.txt. File format "
                 "is plain text, one CIDR per line, # for comments."),
    { NULL }
};

/* --- Asset-extension skip list ---
 *
 * Requests whose URI ends in one of these suffixes pass through without a
 * challenge. This keeps CSS/JS/images/fonts on the real page from being
 * replaced by the interstitial on first load. Anything not in this list —
 * including JSON, XML, paths with no extension — is subject to the gate. */
static const char *const BS_ASSET_EXTS[] = {
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".ogg",
    NULL
};

static int bs_is_asset_uri(const char *uri)
{
    if (!uri) return 0;
    const char *q = strchr(uri, '?');
    apr_size_t len = q ? (apr_size_t)(q - uri) : strlen(uri);
    for (int i = 0; BS_ASSET_EXTS[i]; i++) {
        apr_size_t elen = strlen(BS_ASSET_EXTS[i]);
        if (len >= elen &&
            strncasecmp(uri + len - elen, BS_ASSET_EXTS[i], elen) == 0) {
            return 1;
        }
    }
    return 0;
}

/* --- Cookie extraction ---
 *
 * Find the value of a named cookie in the request's Cookie header, at a
 * name-boundary (so e.g. `other_bs_verified=` won't shadow `_bs_verified=`).
 * Returns a pool-allocated copy of the value with trailing whitespace
 * trimmed, or NULL if the cookie isn't present. The value itself is not
 * validated here — callers decode and verify. */
static const char *bs_get_cookie_value(request_rec *r, const char *name)
{
    const char *cookies = apr_table_get(r->headers_in, "Cookie");
    if (!cookies) return NULL;

    apr_size_t nlen = strlen(name);
    const char *p = cookies;
    while ((p = strstr(p, name)) != NULL) {
        int at_boundary = (p == cookies) ||
                          (p[-1] == ';')  ||
                          (p[-1] == ' ')  ||
                          (p[-1] == '\t');
        if (at_boundary && p[nlen] == '=') {
            const char *v = p + nlen + 1;
            const char *end = strchr(v, ';');
            if (!end) end = v + strlen(v);
            while (end > v && (end[-1] == ' ' || end[-1] == '\t')) end--;
            return apr_pstrmemdup(r->pool, v, (apr_size_t)(end - v));
        }
        p += nlen;
    }
    return NULL;
}

/* --- Challenge page templates ---
 *
 * Rendering is a two-step substitution:
 *
 *   1. BS_WIDGET_TEMPLATE — the self-contained widget block (scoped CSS,
 *      widget markup, help slot, live-status element, JS). apr_psprintf
 *      fills the content substitutions (prompt/%s, logo/%s, label/%s,
 *      help/%s, difficulty/%d, cookie_ttl/%d). This block carries all
 *      the styles needed to render the widget — no <head> CSS required.
 *
 *   2. BS_DEFAULT_PAGE_TEMPLATE — a page shell (<!DOCTYPE>, <head>, body
 *      layout) with a BS_WIDGET_MARKER placeholder where the widget
 *      block is injected. When the admin sets BotShieldChallengeFile,
 *      their file replaces this shell — but the widget block stays
 *      module-controlled so the JS/DOM contract doesn't drift.
 *
 * Targets WCAG 2.1 AA: body-text contrast >= 4.5:1, UI-component
 * contrast >= 3:1, visible :focus-visible outline, no color-only
 * affordances, aria-live polite status, prefers-reduced-motion aware.
 *
 * Keep literal `%` out of the template — escape as %% for real percent. */

static const char BS_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.75rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:left}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-widget{display:inline-flex;align-items:center;\n"
" background:#fafafa;border:1px solid #d3d9dd;border-radius:4px;\n"
" box-shadow:0 1px 1px rgba(0,0,0,.04);min-width:300px}\n"
".bs-widget.bs-bare{background:transparent;border:0;box-shadow:none;\n"
" min-width:0;padding:0}\n"
".bs-widget.bs-bare .bs-btn{padding:0;border-radius:4px}\n"
".bs-widget.bs-auto{background:transparent;border:0;box-shadow:none;\n"
" min-width:0;padding:0}\n"
".bs-widget.bs-auto .bs-btn{padding:.6rem 0;cursor:default;\n"
" pointer-events:none;justify-content:center}\n"
/* Silent-tier visual cleanup: the brand column is purely decorative
 * so display:none-ing it is fine, but the label carries the button's
 * accessible name — visually hide it via the screen-reader-only
 * technique so the a11y tree still exposes "Verify you are human"
 * to axe/screen readers. An earlier revision display:none'd the
 * label too, which made axe-core's button-name check fail
 * critical (caught by tests/pytests/test_browser_a11y.py). */
".bs-widget.bs-auto .bs-brand{display:none}\n"
".bs-widget.bs-auto .bs-label{position:absolute;width:1px;height:1px;\n"
" padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);\n"
" white-space:nowrap;border:0}\n"
".bs-widget.bs-auto ~ .bs-help-toggle,\n"
".bs-widget.bs-auto ~ .bs-help{display:none}\n"
".bs-btn{display:inline-flex;align-items:center;gap:.85rem;\n"
" flex:1;padding:.9rem 1rem;background:transparent;border:0;\n"
" font:inherit;color:#1f2530;cursor:pointer;text-align:left;\n"
" border-top-left-radius:4px;border-bottom-left-radius:4px}\n"
".bs-btn:focus-visible{outline:3px solid #2f5d50;outline-offset:-3px}\n"
".bs-check{width:28px;height:28px;border:2px solid #7a8487;\n"
" border-radius:3px;background:#fff;flex-shrink:0;position:relative}\n"
".bs-label{font-size:15px;font-weight:500;color:#1f2530}\n"
".bs-brand{display:flex;flex-direction:column;align-items:center;\n"
" gap:.15rem;padding:.65rem 1rem;border-left:1px solid #e4e7ea;\n"
" color:#55605e;line-height:1;user-select:none}\n"
".bs-brand svg{display:block;width:32px;height:32px}\n"
".bs-brand .nm{font-size:11px;font-weight:600;letter-spacing:.03em;\n"
" color:#1f2530;margin-top:.3rem}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-working .bs-check{border:none;background:transparent;\n"
" border:3px solid #e4e7ea;border-top-color:#2f5d50;\n"
" border-radius:50%%;animation:bs-spin .8s linear infinite}\n"
".bs-done .bs-check{background:#2f5d50;border-color:#2f5d50}\n"
".bs-done .bs-check::after{content:\"\";position:absolute;\n"
" left:9px;top:4px;width:6px;height:12px;border:solid #fff;\n"
" border-width:0 2.5px 2.5px 0;transform:rotate(45deg)}\n"
".bs-working .bs-btn,.bs-done .bs-btn{pointer-events:none}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-help-toggle{display:inline-flex;align-items:center;gap:.4rem;\n"
" background:transparent;border:0;padding:.25rem .5rem;font:inherit;\n"
" font-size:12px;color:#55605e;cursor:pointer;border-radius:3px}\n"
".bs-help-toggle:hover{color:#2f5d50}\n"
".bs-help-toggle:hover .bs-help-icon{background:#2f5d50}\n"
".bs-help-toggle:focus-visible{outline:2px solid #2f5d50;outline-offset:2px}\n"
".bs-help-icon{display:inline-flex;align-items:center;\n"
" justify-content:center;width:16px;height:16px;border-radius:50%%;\n"
" background:#55605e;color:#fff;font-size:11px;font-weight:700;line-height:1}\n"
".bs-help{max-width:420px;background:#eef2f0;border-left:3px solid #2f5d50;\n"
" border-radius:4px;padding:.85rem 1rem;font-size:13px;line-height:1.5;\n"
" color:#1f2530;text-align:left}\n"
".bs-help :first-child{margin-top:0}\n"
".bs-help :last-child{margin-bottom:0}\n"
".bs-help a{color:#2f5d50}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
"@keyframes bs-spin{to{transform:rotate(360deg)}}\n"
"@media (prefers-reduced-motion: reduce){\n"
" .bs-working .bs-check{animation:none;border-top-color:#7a8487}\n"
"}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<div class=\"bs-widget%s\" id=\"c\">\n"
" <button type=\"button\" class=\"bs-btn\" id=\"btn\""
" aria-describedby=\"msg\"%s>\n"
"  <span class=\"bs-check\" id=\"cb\" aria-hidden=\"true\"></span>\n"
"  %s"
" </button>\n"
" %s"
"</div>\n"
"%s"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script>window.__bsChallenge=%s;</script>\n"
"<script>\n"
"(function(){\n"
" var CH = window.__bsChallenge;\n"
" if (!CH) return;\n"
" var COOKIE_NAME = '" BS_COOKIE_NAME "';\n"
" var box = document.getElementById('c');\n"
" var msg = document.getElementById('msg');\n"
" var btn = document.getElementById('btn');\n"
" function hexToBytes(h){\n"
"  var b = new Uint8Array(h.length/2);\n"
"  for (var i=0; i<b.length; i++) b[i] = parseInt(h.substr(i*2,2),16);\n"
"  return b;\n"
" }\n"
" function meetsTarget(digest, difficulty){\n"
"  var fb = Math.floor(difficulty/2);\n"
"  for (var i=0; i<fb; i++) if (digest[i] !== 0) return false;\n"
"  if (difficulty & 1) return (digest[fb] >> 4) === 0;\n"
"  return true;\n"
" }\n"
" function begin(){\n"
"  box.classList.add('bs-working');\n"
"  btn.setAttribute('aria-disabled', 'true');\n"
"  startChallenge();\n"
" }\n"
" if (CH.auto){\n"
"  msg.textContent = 'Checking your browser\\u2026';\n"
"  if (document.readyState === 'loading') {\n"
"   document.addEventListener('DOMContentLoaded', begin, {once:true});\n"
"  } else {\n"
"   begin();\n"
"  }\n"
" } else {\n"
"  btn.addEventListener('click', function h(e){\n"
"   if(!e.isTrusted) return;\n"
"   btn.removeEventListener('click', h);\n"
"   begin();\n"
"  });\n"
" }\n"
" function startChallenge(){\n"
"  var saltB  = hexToBytes(CH.salt);\n"
"  var nonceB = hexToBytes(CH.nonce);\n"
"  var counter = 0;\n"
"  var BATCH = 2048;\n"
"  var t0 = Date.now();\n"
"  msg.textContent = 'Verifying\\u2026';\n"
"  function doBatch(){\n"
"   var promises = [];\n"
"   var start = counter;\n"
"   for (var i=0; i<BATCH; i++){\n"
"    var cstr = String(start+i);\n"
"    var buf = new Uint8Array(saltB.length + nonceB.length + cstr.length);\n"
"    buf.set(saltB, 0);\n"
"    buf.set(nonceB, saltB.length);\n"
"    for (var j=0; j<cstr.length; j++) buf[saltB.length+nonceB.length+j] = cstr.charCodeAt(j);\n"
"    promises.push(crypto.subtle.digest('SHA-256', buf));\n"
"   }\n"
"   Promise.all(promises).then(function(results){\n"
"    for (var i=0; i<results.length; i++){\n"
"     if (meetsTarget(new Uint8Array(results[i]), CH.difficulty)){\n"
"      finish(start+i); return;\n"
"     }\n"
"    }\n"
"    counter = start + BATCH;\n"
"    var elapsed = ((Date.now()-t0)/1000).toFixed(1);\n"
"    msg.textContent = 'Verifying\\u2026 (' + counter.toLocaleString() +\n"
"                      ' hashes, ' + elapsed + 's)';\n"
"    setTimeout(doBatch, 0);\n"
"   }).catch(function(err){\n"
"    msg.textContent = 'Verification failed: ' + (err && err.message || err);\n"
"   });\n"
"  }\n"
"  function finish(counterVal){\n"
"   box.classList.remove('bs-working');\n"
"   box.classList.add('bs-done');\n"
"   msg.textContent = 'Verified \\u2014 reloading\\u2026';\n"
"   var fields = [CH.v, CH.alg, CH.salt, CH.nonce, CH.difficulty,\n"
"                 CH.expires_at,\n"
"                 CH.score, CH.flags,\n"
"                 CH.passes_silent, CH.passes_form, CH.passes_captcha,\n"
"                 CH.challenged_at, CH.auto,\n"
"                 CH.signature, counterVal];\n"
"   var payload = btoa(fields.join('|'));\n"
"   var exp = new Date((CH.expires_at + 60) * 1000).toUTCString();\n"
"   var secure = (location.protocol === 'https:') ? '; Secure' : '';\n"
"   var domain = CH.cookie_domain ? '; Domain=' + CH.cookie_domain : '';\n"
"   document.cookie = COOKIE_NAME + '=' + payload +\n"
"                     '; Path=/; Expires=' + exp + domain +\n"
"                     '; SameSite=Lax' + secure;\n"
"   setTimeout(function(){ location.reload(); }, 250);\n"
"  }\n"
"  doBatch();\n"
" }\n"
" var ht = document.querySelector('.bs-help-toggle');\n"
" if (ht) {\n"
"  ht.addEventListener('click', function(){\n"
"   var expanded = ht.getAttribute('aria-expanded') === 'true';\n"
"   ht.setAttribute('aria-expanded', expanded ? 'false' : 'true');\n"
"   var panel = document.getElementById('bs-help');\n"
"   if (panel) panel.hidden = expanded;\n"
"  });\n"
" }\n"
"})();\n"
"</script>\n";

/* Captcha-tier widget template (M8). Embeds the provider's async script
 * + a container div with the provider's CSS class and our site key, and
 * a form that POSTs back to /<prefix>/captcha-verify when the provider's
 * JS callback fires. Printf substitutions (in order):
 *   %s script_url, %s form_action, %s return_to_esc, %s widget_class,
 *   %s site_key, %s provider_name_esc.
 * The scoped <style> block re-declares a small subset of the PoW widget
 * CSS so we don't depend on BS_WIDGET_TEMPLATE's styles being present. */
static const char BS_CAPTCHA_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.85rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:center}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-prompt{font-size:15px;font-weight:500;color:#1f2530;margin:0}\n"
".bs-sub{font-size:13px;color:#55605e;margin:0}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<p class=\"bs-prompt\">Please complete the check to continue.</p>\n"
"<p class=\"bs-sub\">Provided by %s.</p>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<form id=\"bscf\" method=\"POST\" action=\"%s\">\n"
" <input type=\"hidden\" name=\"return_to\" value=\"%s\">\n"
" <div class=\"%s\" data-sitekey=\"%s\" data-action=\"botshield\""
" data-callback=\"bsOnSolve\"></div>\n"
"</form>\n"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script src=\"%s\" async defer></script>\n"
"<script>\n"
"function bsOnSolve(token){\n"
" var m = document.getElementById('msg');\n"
" if (m) m.textContent = 'Verifying\\u2026';\n"
" document.getElementById('bscf').submit();\n"
"}\n"
"</script>\n";

/* reCAPTCHA v3 widget template (M8). Different from the render-pattern
 * template above — v3 has no visible widget; the script runs
 * grecaptcha.execute() on load and auto-submits the form once the
 * token comes back. Printf substitutions (in order):
 *   %s provider_name_esc, %s form_action, %s return_to_esc,
 *   %s token_field, %s script_url_with_render_param, %s sitekey_js_esc.
 * The CSS reuses the subset that BS_CAPTCHA_WIDGET_TEMPLATE defines so
 * we don't grow a second copy of every style rule. */
static const char BS_RECAPTCHA_V3_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.85rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:center}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-prompt{font-size:15px;font-weight:500;color:#1f2530;margin:0}\n"
".bs-sub{font-size:13px;color:#55605e;margin:0}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
".bs-spin{width:32px;height:32px;border:3px solid #e4e7ea;\n"
" border-top-color:#2f5d50;border-radius:50%%;\n"
" animation:bs-spin .8s linear infinite}\n"
"@keyframes bs-spin{to{transform:rotate(360deg)}}\n"
"@media (prefers-reduced-motion: reduce){\n"
" .bs-spin{animation:none;border-top-color:#7a8487}\n"
"}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<p class=\"bs-prompt\">Checking your browser\\u2026</p>\n"
"<div class=\"bs-spin\" aria-hidden=\"true\"></div>\n"
"<p class=\"bs-sub\">Provided by %s.</p>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<form id=\"bscf\" method=\"POST\" action=\"%s\">\n"
" <input type=\"hidden\" name=\"return_to\" value=\"%s\">\n"
" <input type=\"hidden\" name=\"%s\" id=\"bs-token\" value=\"\">\n"
"</form>\n"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script src=\"%s\" async defer></script>\n"
"<script>\n"
"(function(){\n"
" var sk = '%s';\n"
" function exec(){\n"
"  grecaptcha.ready(function(){\n"
"   grecaptcha.execute(sk, {action: 'botshield'}).then(function(t){\n"
"    document.getElementById('bs-token').value = t;\n"
"    var m = document.getElementById('msg');\n"
"    if (m) m.textContent = 'Verifying\\u2026';\n"
"    document.getElementById('bscf').submit();\n"
"   });\n"
"  });\n"
" }\n"
" function start(){\n"
"  if (typeof grecaptcha !== 'undefined' && grecaptcha.ready) {\n"
"   exec();\n"
"  } else {\n"
"   setTimeout(start, 50);\n"
"  }\n"
" }\n"
" if (document.readyState === 'loading') {\n"
"  document.addEventListener('DOMContentLoaded', start, {once:true});\n"
" } else {\n"
"  start();\n"
" }\n"
"})();\n"
"</script>\n";

/* GeeTest v4 widget template (M8). GeeTest neither renders into a
 * named div (like Turnstile/hCaptcha/v2/Friendly) nor calls execute
 * directly (like reCAPTCHA v3) — instead its gt4.js exposes a global
 * initGeetest4({captchaId, product}, callback) that produces a captcha
 * object the caller drops into a container and wires for onSuccess.
 * Printf substitutions (in order):
 *   %s provider_name_esc, %s form_action, %s return_to_esc,
 *   %s token_field, %s widget_script_url, %s sitekey_js_esc.
 * When the user solves the slider, our onSuccess handler pulls
 * captchaObj.getValidate() (a 4-field object) and stringifies it into
 * the hidden input named `token_field` so the verify handler can parse
 * it apart. */
static const char BS_GEETEST_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.85rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:center}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-prompt{font-size:15px;font-weight:500;color:#1f2530;margin:0}\n"
".bs-sub{font-size:13px;color:#55605e;margin:0}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
"#bs-gt{min-height:60px;display:flex;justify-content:center}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<p class=\"bs-prompt\">Please complete the check to continue.</p>\n"
"<p class=\"bs-sub\">Provided by %s.</p>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<form id=\"bscf\" method=\"POST\" action=\"%s\">\n"
" <input type=\"hidden\" name=\"return_to\" value=\"%s\">\n"
" <input type=\"hidden\" name=\"%s\" id=\"bs-token\" value=\"\">\n"
"</form>\n"
"<div id=\"bs-gt\" aria-live=\"polite\"></div>\n"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script src=\"%s\" async defer></script>\n"
"<script>\n"
"(function(){\n"
" var captchaId = '%s';\n"
" function boot(){\n"
"  if (typeof initGeetest4 === 'undefined') { setTimeout(boot, 50); return; }\n"
"  initGeetest4({captchaId: captchaId, product: 'bind'}, function(cap){\n"
"   cap.appendTo('#bs-gt');\n"
"   cap.onSuccess(function(){\n"
"    var v = cap.getValidate();\n"
"    document.getElementById('bs-token').value = JSON.stringify(v);\n"
"    var m = document.getElementById('msg');\n"
"    if (m) m.textContent = 'Verifying\\u2026';\n"
"    document.getElementById('bscf').submit();\n"
"   });\n"
"  });\n"
" }\n"
" if (document.readyState === 'loading') {\n"
"  document.addEventListener('DOMContentLoaded', boot, {once:true});\n"
" } else {\n"
"  boot();\n"
" }\n"
"})();\n"
"</script>\n";

/* Built-in page shell used when BotShieldChallengeFile isn't set. The
 * marker position mirrors what we ask admins to use in their templates —
 * one canonical insertion point inside <main>. */
static const char BS_DEFAULT_PAGE_TEMPLATE[] =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<meta name=\"robots\" content=\"noindex,nofollow\">\n"
"<meta name=\"theme-color\" content=\"#2f5d50\">\n"
"<title>Verify you are human</title>\n"
"<style>\n"
" html,body{margin:0;padding:0}\n"
" body{background:#f5f5f2;min-height:100vh;display:flex;\n"
"  flex-direction:column;align-items:center;justify-content:center;\n"
"  padding:1rem;font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<main>\n"
BS_WIDGET_MARKER "\n"
"</main>\n"
"</body>\n"
"</html>\n";

/* --- Request handler ---
 *
 * Registered at APR_HOOK_FIRST so we run before the default static-file
 * handler. */
static int bs_handler(request_rec *r)
{
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    if (!cfg || cfg->enabled != 1) {
        return DECLINED;
    }
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    /* Module-owned endpoint routing (M8). URLs under BotShieldEndpointPrefix
     * (default /botshield) are served by this module's own handlers, not
     * the tier dispatch. Today:
     *   <prefix>/captcha-verify             — single-provider vhost
     *   <prefix>/captcha-verify/<name>      — per-provider cohabitation
     * The bare form still works for the single-provider case so the old
     * dev config and the first-provider-on-a-vhost case keep working.
     * Done before the debug / asset / cookie paths so operators can hit
     * the verify endpoint regardless of surrounding scope. */
    const char *prefix = cfg->endpoint_prefix
        ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    apr_size_t prefix_len = strlen(prefix);
    if (r->uri && strncmp(r->uri, prefix, prefix_len) == 0 &&
        r->uri[prefix_len] == '/') {
        const char *sub = r->uri + prefix_len;
        if (strcmp(sub, "/captcha-verify") == 0 ||
            strncmp(sub, "/captcha-verify/", 16) == 0) {
            return bs_captcha_verify_handler(r, cfg);
        }
        if (strcmp(sub, "/metrics") == 0) {
            return bs_metrics_handler(r, cfg);
        }
        /* Unknown module endpoint under the prefix → 404, so a typo in
         * an operator's template fails loudly instead of falling through
         * to Apache and serving some unrelated file. */
        r->status = HTTP_NOT_FOUND;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->err_headers_out, "X-Botshield", "unknown-endpoint");
        ap_rputs("Not found.\n", r);
        bs_decision_log(r, "none", "rejected", "-", "-", "-",
                        "unknown_endpoint", 0);
        return OK;
    }

    /* Debug override keeps the first-commit behavior available for tests. */
    if (cfg->debug == 1) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_botshield: debug mode — forcing 403 for %s",
                      r->unparsed_uri);
        r->status = HTTP_FORBIDDEN;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->headers_out,    "Cache-Control", "no-store");
        apr_table_setn(r->err_headers_out, "X-Botshield",  "debug-403");
        ap_rputs("Hello World\n", r);
        bs_decision_log(r, "none", "debug", "-", "-", "-", "-", 0);
        return OK;
    }

    /* Static assets pass through — a cookieless first page load must still
     * render its CSS/images so the PoW page is usable. */
    if (bs_is_asset_uri(r->uri)) {
        bs_decision_log(r, "pass", "declined", "-", "-", "-", "asset", 0);
        return DECLINED;
    }

    int ttl        = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);
    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);

    /* Without a secret+algorithm we can't sign challenges or verify cookies.
     * Refuse the scope with a 503 so misconfiguration is immediately visible
     * rather than silently weaker. */
    if (!cfg->secret || !cfg->algorithm) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_botshield: BotShieldEnabled On requires both "
                      "BotShieldSecretFile and BotShieldAlgorithm in scope "
                      "(for %s)", r->uri);
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->headers_out, "Cache-Control", "no-store");
        apr_table_setn(r->err_headers_out, "X-Botshield", "misconfigured");
        ap_rputs("Service unavailable: mod_botshield misconfigured.\n", r);
        bs_decision_log(r, "none", "misconfigured", "-", "-", "-", "-", 0);
        return OK;
    }

    /* Parse the cookie if present. Three outcomes from bs_verify_cookie:
     *   - NULL reason                  — cookie fully valid; rep is
     *     trustworthy and the holder has solved their PoW. We still
     *     compute effective score so a fresh signal can force a
     *     re-challenge.
     *   - non-NULL, sig did verify     — cookie failed a later check
     *     (expired, PoW counter doesn't satisfy difficulty, etc.).
     *     Rep was server-signed so it's still safe to carry forward.
     *   - non-NULL, "signature mismatch" — HMAC didn't verify; bytes
     *     in the cookie can't be trusted. Discard entirely.
     */
    const char *cookie_val = bs_get_cookie_value(r, BS_COOKIE_NAME);
    bs_challenge prior_ch = { 0 };
    int have_prior_rep   = 0;
    int cookie_fully_ok  = 0;
    const char *cookie_verify_reason = NULL;
    int cookie_had_val = (cookie_val && *cookie_val);
    if (cookie_had_val) {
        cookie_verify_reason = bs_verify_cookie(r, cfg, cookie_val, &prior_ch);
        if (!cookie_verify_reason) {
            cookie_fully_ok = 1;
            have_prior_rep  = 1;
        } else {
            if (strcmp(cookie_verify_reason, "signature mismatch") != 0) {
                have_prior_rep = 1;
            }
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_botshield: " BS_COOKIE_NAME " rejected: %s",
                          cookie_verify_reason);
        }
    }
    const char *cookie_status =
        bs_decision_cookie_status(cookie_verify_reason, cookie_had_val);

    /* Score the request. Heuristics always run — a fully-valid cookie
     * doesn't exempt you from fresh request-level signals that might
     * have pushed you into a tier that requires a re-challenge. */
    bs_run_builtin_heuristics(r);

    /* Flagged-IP table (M5.1): look up the client IP. Hits add the
     * serious-event bitmap's penalty to effective_score, rollback-proof
     * because the flag lives in SHM, not in the cookie.
     *
     * IPv6 native addresses are masked to the operator-configured prefix
     * (default /64) so an attacker can't trivially rotate within their
     * ISP allocation to shed a flag. v4-mapped addresses are left at /32. */
    unsigned char client_ip[16];
    int have_client_ip =
        bs_parse_client_ip(r->useragent_ip, client_ip);
    if (have_client_ip) {
        bs_server_cfg *scfg = ap_get_module_config(
            r->server->module_config, &botshield_module);
        bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
    }
    apr_uint32_t ip_flags = 0;
    int ip_flag_penalty = 0;
    if (have_client_ip &&
        bs_flagged_ip_lookup(client_ip, &ip_flags)) {
        ip_flag_penalty = bs_flag_penalty(ip_flags);
        bs_score_add(r, ip_flag_penalty,
                     /* ttl unused here — flag TTL lives in SHM */ 0,
                     "flagged-ip");
    }

    /* First-sight Bloom lookup (M5.2). Policy: only on cookieless or
     * signature-mismatched requests. Sig-verified cookies (even if
     * expired) mean we've already transacted with this browser, so
     * the first-sight signal would just be noise. A valid cookie
     * likewise skips this. */
    if (have_client_ip && !have_prior_rep &&
        !bs_bloom_seen(client_ip)) {
        bs_score_add(r, BS_FIRST_SIGHT_PENALTY, 0, "first-sight-ip");
    }

    /* Fetch the score struct *after* all per-request adds. Using create=1
     * so a request with zero hits still gets a valid (empty) pointer and
     * the log line prints reasons=[] consistently. */
    bs_request_score *score = bs_get_score(r, 1);
    int heuristic_total = score->total;

    /* effective_score composes four things: the per-request heuristic
     * total (already inclusive of the ip-flag penalty above), the
     * cookie's accumulated rep score, and the flag-penalty floor the
     * cookie's own flag bitmap implies. */
    int cookie_score    = have_prior_rep ? prior_ch.rep.score : 0;
    int cookie_flag_floor = have_prior_rep ? bs_flag_penalty(prior_ch.rep.flags) : 0;
    int effective       = heuristic_total + cookie_score + cookie_flag_floor;
    bs_tier tier        = bs_decide_tier(cfg, effective);

    /* BotShieldFlagIP: if any scope the request matched sets flag bits,
     * land them in the flagged-IP table now. Fires on every hit to the
     * scope, so honeypot paths and scanner-trap paths should be reached
     * only by actors that deserve the flag. */
    if (cfg->flag_on_match && have_client_ip) {
        bs_flagged_ip_add(r, client_ip, cfg->flag_on_match,
                          cfg->flag_on_match_ttl
                            ? cfg->flag_on_match_ttl : 3600);
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: flagged IP %s bits=0x%x ttl=%d scope=%s",
            r->useragent_ip, (unsigned)cfg->flag_on_match,
            cfg->flag_on_match_ttl ? cfg->flag_on_match_ttl : 3600,
            r->uri);
    }

    /* Happy path: score below the silent threshold → pass through.
     * If there's no cookie this means no cookie is ever issued —
     * legitimate users experience mod_botshield as invisible. */
    if (tier == BS_TIER_PASS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_botshield: pass %s effective=%d "
                      "(heuristic=%d cookie_score=%d cookie_flag_floor=%d "
                      "ip_flag_penalty=%d ip_flags=0x%x) cookie_ok=%d",
                      r->uri, effective, heuristic_total, cookie_score,
                      cookie_flag_floor, ip_flag_penalty, (unsigned)ip_flags,
                      cookie_fully_ok);
        bs_decision_log(r, "pass", "declined", cookie_status,
                        "-", "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

    /* Not pass tier — we will issue a challenge. Feed the Bloom filter
     * now that we've committed to challenging this client; that keeps
     * writes off the ~99% happy path. */
    if (have_client_ip) bs_bloom_add(client_ip);

    /* Decide whether this challenge will be served as the M7 silent-tier
     * auto-submit splash or as the form-PoW interstitial. Captcha tier
     * (M8) still stubs to form until that ships. */
    int issue_auto = (tier == BS_TIER_SILENT);

    /* Build the rep state to carry into the new cookie. Forgiveness +
     * pass-counter bump are picked from the tier the *prior* cookie was
     * served under (prior_ch.auto_tier), because that records what the
     * user actually just solved. First-time challenges have no prior
     * tier, so they increment whichever counter matches the tier we're
     * about to issue. */
    bs_rep_state next_rep;
    if (have_prior_rep) {
        int forgive = prior_ch.auto_tier
            ? bs_effective_int(cfg->forgive_silent, BS_DEFAULT_FORGIVE_SILENT)
            : bs_effective_int(cfg->forgive_form,   BS_DEFAULT_FORGIVE_FORM);
        int floor   = bs_flag_penalty(prior_ch.rep.flags);
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < floor) new_score = floor;
        if (new_score < 0)     new_score = 0;
        next_rep = prior_ch.rep;
        next_rep.score = new_score;
        if (prior_ch.auto_tier) {
            next_rep.passes_silent = prior_ch.rep.passes_silent + 1;
        } else {
            next_rep.passes_form   = prior_ch.rep.passes_form + 1;
        }
    } else {
        next_rep.score          = 0;
        next_rep.flags          = 0;
        next_rep.passes_silent  = issue_auto ? 1 : 0;
        next_rep.passes_form    = issue_auto ? 0 : 1;
        next_rep.passes_captcha = 0;
        next_rep.challenged_at  = 0;   /* overwritten by issue() */
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "mod_botshield: challenging %s (alg=%s, difficulty=%d, "
                  "ttl=%d) effective=%d tier=%s heuristic=%d reasons=%s "
                  "cookie_score=%d cookie_flags=0x%x cookie_ok=%d "
                  "passes=[s:%d f:%d c:%d]",
                  r->unparsed_uri, cfg->algorithm->name, difficulty, ttl,
                  effective, bs_tier_name(tier), heuristic_total,
                  bs_score_reasons_joined(r->pool, score),
                  have_prior_rep ? cookie_score : -1,
                  have_prior_rep ? (unsigned)prior_ch.rep.flags : 0,
                  cookie_fully_ok,
                  next_rep.passes_silent, next_rep.passes_form,
                  next_rep.passes_captcha);

    /* Issue a fresh signed challenge; the worker reads it from the page.
     * The next_rep struct carries forgiveness-adjusted rep from any
     * sig-verified prior cookie. */
    bs_challenge challenge;
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          issue_auto, NULL,
                                          &next_rep, &challenge);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_botshield: issue failed: %s", ierr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Service error: could not issue challenge.\n", r);
        bs_decision_log(r, bs_tier_name(tier), "misconfigured",
                        cookie_status, "-", "-", "issue_failed", effective);
        return OK;
    }
    const char *challenge_js = bs_challenge_json(r->pool, cfg, &challenge);

    const char *prompt     = cfg->prompt     ? cfg->prompt     : BS_DEFAULT_PROMPT;
    const char *logo_svg   = cfg->logo_svg   ? cfg->logo_svg   : BS_DEFAULT_LOGO_SVG;
    const char *logo_label = cfg->logo_label ? cfg->logo_label : BS_DEFAULT_LOGO_LABEL;
    int help_mode  = bs_effective_int(cfg->help_mode,  BS_DEFAULT_HELP_MODE);
    int show_logo  = bs_effective_int(cfg->show_logo,  1);
    int show_label = bs_effective_int(cfg->show_label, 1);
    int show_box   = bs_effective_int(cfg->show_box,   1);
    const char *help_content = cfg->help_html ? cfg->help_html : BS_DEFAULT_HELP_HTML;

    const char *help_html = "";
    if (help_mode == BS_HELP_ON) {
        help_html = apr_psprintf(r->pool,
            "<div class=\"bs-help\" id=\"bs-help\">%s</div>\n", help_content);
    } else if (help_mode == BS_HELP_BUTTON) {
        help_html = apr_psprintf(r->pool,
            "<button type=\"button\" class=\"bs-help-toggle\""
            " aria-expanded=\"false\" aria-controls=\"bs-help\">"
            "<span class=\"bs-help-icon\" aria-hidden=\"true\">?</span>"
            "<span>What is this?</span></button>\n"
            "<div class=\"bs-help\" id=\"bs-help\" hidden>%s</div>\n",
            help_content);
    }

    /* Chrome toggles: build conditional widget fragments. When the label is
     * hidden, move the prompt text to an aria-label on the button so the
     * button keeps an accessible name. */
    const char *prompt_esc = ap_escape_html(r->pool, prompt);
    const char *widget_mod = apr_pstrcat(r->pool,
                                         show_box   ? "" : " bs-bare",
                                         issue_auto ? " bs-auto" : "",
                                         NULL);
    const char *aria_attr  = show_label
        ? ""
        : apr_psprintf(r->pool, " aria-label=\"%s\"", prompt_esc);
    const char *prompt_span = show_label
        ? apr_psprintf(r->pool,
              "<span class=\"bs-label\">%s</span>\n", prompt_esc)
        : "";
    const char *brand_div = show_logo
        ? apr_psprintf(r->pool,
              "<div class=\"bs-brand\" aria-hidden=\"true\">%s"
              "<span class=\"nm\">%s</span></div>\n",
              logo_svg, ap_escape_html(r->pool, logo_label))
        : "";

    /* Render the widget block once, then splice it into the page shell at
     * BS_WIDGET_MARKER. The shell is either the admin's BotShieldChallengeFile
     * or our built-in default — same splice code path either way.
     *
     * Captcha tier (M8): if we're at captcha tier AND a provider is fully
     * configured, render the provider's widget instead of the PoW checkbox.
     * If captcha tier resolves but no provider/key/secret is configured,
     * the handler already issued a PoW challenge above and we stub to
     * form-PoW here — preserves the pre-M8 fall-through behavior and lets
     * operators opt in to captcha only on scopes they've configured. */
    char *widget;
    int use_captcha_widget = (tier == BS_TIER_CAPTCHA)
        && cfg->captcha_provider
        && cfg->captcha_site_key
        && cfg->captcha_secret;
    if (use_captcha_widget) {
        /* M8.1: mint a short-lived HMAC-signed "pending" cookie so the
         * verify endpoint can short-circuit random POST spray before
         * calling libcurl. Set early so it rides out on the challenge
         * response. If mint fails (RAND_bytes) we still render — worst
         * case is the verify endpoint falls back to rate-limit + in-
         * flight cap as the only guardrails. */
        const char *pending = bs_mint_pending_cookie(r, cfg);
        if (pending) {
            apr_table_add(r->err_headers_out, "Set-Cookie", pending);
        }
        const char *prefix = cfg->endpoint_prefix
            ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
        /* Per-provider verify URL: {prefix}/captcha-verify/{provider}.
         * Encoding the provider in the path lets operators run multiple
         * providers on one vhost by giving each its own <Location> block
         * with the matching secret/sitekey. Operators running a single
         * provider don't need to notice — any scope-level override still
         * works because the verify URL's per-dir config is independent. */
        const char *verify_url = apr_pstrcat(r->pool, prefix,
            "/captcha-verify/", cfg->captcha_provider->name, NULL);
        const char *return_esc  = ap_escape_html(r->pool,
            r->unparsed_uri ? r->unparsed_uri : "/");
        const char *provider_esc = ap_escape_html(r->pool,
            cfg->captcha_provider->name);
        const char *pname = cfg->captcha_provider->name;
        if (strcmp(pname, "recaptcha-v3") == 0) {
            /* v3 script URL embeds the sitekey in its query string, so
             * the render-pattern widget_script_url from the registry
             * isn't used directly — build it here instead. */
            const char *v3_script_url = apr_psprintf(r->pool,
                "%s?render=%s",
                cfg->captcha_provider->widget_script_url,
                cfg->captcha_site_key);
            widget = apr_psprintf(r->pool, BS_RECAPTCHA_V3_WIDGET_TEMPLATE,
                provider_esc,
                verify_url,
                return_esc,
                cfg->captcha_provider->token_field,
                v3_script_url,
                cfg->captcha_site_key);
        } else if (strcmp(pname, "geetest") == 0) {
            widget = apr_psprintf(r->pool, BS_GEETEST_WIDGET_TEMPLATE,
                provider_esc,
                verify_url,
                return_esc,
                cfg->captcha_provider->token_field,
                cfg->captcha_provider->widget_script_url,
                cfg->captcha_site_key);
        } else {
            widget = apr_psprintf(r->pool, BS_CAPTCHA_WIDGET_TEMPLATE,
                provider_esc,
                verify_url,
                return_esc,
                cfg->captcha_provider->widget_class,
                cfg->captcha_site_key,
                cfg->captcha_provider->widget_script_url);
        }
    } else {
        widget = apr_psprintf(r->pool, BS_WIDGET_TEMPLATE,
                              widget_mod,
                              aria_attr,
                              prompt_span,
                              brand_div,
                              help_html,
                              challenge_js);
    }

    const char *page = cfg->challenge_html ? cfg->challenge_html
                                           : BS_DEFAULT_PAGE_TEMPLATE;
    const char *marker_pos = strstr(page, BS_WIDGET_MARKER);

    char *body;
    if (marker_pos) {
        apr_size_t prefix_len = (apr_size_t)(marker_pos - page);
        body = apr_pstrcat(r->pool,
                           apr_pstrmemdup(r->pool, page, prefix_len),
                           widget,
                           marker_pos + sizeof(BS_WIDGET_MARKER) - 1,
                           NULL);
    } else {
        /* Shouldn't happen — config-time check rejects files without the
         * marker, and the built-in default has it hard-coded. Fall back to
         * appending so we still serve *something* if someone trips this. */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_botshield: challenge page has no '%s' marker; "
                      "appending widget at end", BS_WIDGET_MARKER);
        body = apr_pstrcat(r->pool, page, widget, NULL);
    }

    r->status = HTTP_OK;
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Botshield",   "challenge");
    ap_rputs(body, r);

    /* Decision log for the challenge we just served. For non-captcha
     * tiers the provider/alg are the PoW algorithm the cookie will be
     * signed under; captcha tier names the configured provider and its
     * cookie alg. When captcha tier falls through to form-PoW (no
     * provider configured), report the actual served tier (form) with
     * reason "captcha_fallback". */
    const char *served_tier_name = bs_tier_name(tier);
    const char *served_provider  = "-";
    const char *served_alg       = cfg->algorithm
                                   ? cfg->algorithm->name : "-";
    const char *served_reason    = bs_decision_reason_names(r->pool, score);
    if (use_captcha_widget) {
        served_provider = cfg->captcha_provider->name;
        served_alg      = apr_psprintf(r->pool, "captcha-%s",
                                       cfg->captcha_provider->name);
    } else if (tier == BS_TIER_CAPTCHA) {
        /* Captcha tier asked for but no provider configured on this
         * scope — interstitial we actually served is form-PoW. Label
         * honestly. */
        served_tier_name = "form";
        served_reason    = (!score || !score->entries ||
                            score->entries->nelts == 0)
            ? "captcha_fallback"
            : apr_pstrcat(r->pool, "captcha_fallback,", served_reason, NULL);
    }
    bs_decision_log(r, served_tier_name, "challenged", cookie_status,
                    served_provider, served_alg, served_reason, effective);
    return OK;
}

/* --- Hook registration --- */

/* Gated under the same BS_FUZZ_HARNESS flag as the module
 * declaration below: the hook-registration calls (ap_hook_*,
 * APR_OPTIONAL_HOOK) reference Apache symbols the fuzz harness
 * doesn't link against, and the fuzz target never invokes this
 * function. No effect on the normal apxs build. */
#ifndef BS_FUZZ_HARNESS
static void bs_register_hooks(apr_pool_t *p)
{
    (void)p;
    ap_hook_post_config (bs_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init  (bs_child_init,  NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler     (bs_handler,     NULL, NULL, APR_HOOK_FIRST);
    /* mod_status optional hook: fires only when mod_status is loaded.
     * If it isn't, APR_OPTIONAL_HOOK silently registers nothing — no
     * hot-path cost and no hard linkage to mod_status. */
    APR_OPTIONAL_HOOK(ap, status_hook, bs_status_hook,
                      NULL, NULL, APR_HOOK_MIDDLE);
}
#endif

/* The module declaration pulls in Apache's core runtime symbols
 * (hooks, module registration) that the LibFuzzer harness in
 * tests/fuzz/ doesn't link against. Wrap it so the fuzz target can
 * #include this file verbatim without fighting the linker. No
 * effect on the normal apxs build. */
#ifndef BS_FUZZ_HARNESS
AP_DECLARE_MODULE(botshield) = {
    STANDARD20_MODULE_STUFF,
    bs_create_dir_cfg,    /* per-directory config creator */
    bs_merge_dir_cfg,     /* per-directory config merger  */
    bs_create_server_cfg, /* per-server config creator    */
    NULL,                 /* per-server config merger     */
    bs_cmds,              /* config directives            */
    bs_register_hooks,    /* hook registration            */
    AP_MODULE_FLAG_NONE   /* flags                        */
};
#endif
