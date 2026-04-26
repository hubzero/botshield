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
#include "scoreboard.h"

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

#include "robots.h"   /* E2.2 — robots.txt parser/matcher */

module AP_MODULE_DECLARE_DATA botshield_module;

/* Tri-state for flag directives: -1 = unset (inherit), 0 = off, 1 = on.
 * Integer directives use -1 to mean "inherit" too. */
#define BS_UNSET              (-1)
#define BS_DEFAULT_COOKIE_TTL 3600  /* seconds a verified cookie is good for */
#define BS_DEFAULT_DIFFICULTY 4     /* leading hex zeros */
#define BS_DEFAULT_MAX_DIFFICULTY 8 /* matches the BotShieldDifficulty
                                     * upper-bound; adaptive bumps from
                                     * BotShieldFlag clamp here. Operator
                                     * raises with BotShieldMaxDifficulty
                                     * (1..16) at server scope. */
#define BS_MAX_DIFFICULTY_HARDCAP 16
#define BS_CLOCK_SKEW_AHEAD   60    /* grace if client clock runs ahead */
#define BS_DEFAULT_FORGIVE_SILENT   10
#define BS_DEFAULT_FORGIVE_FORM     25
#define BS_DEFAULT_FORGIVE_CAPTCHA  50
/* E15 — per-cookie hourly cap on accumulated forgiveness.
 * 200 points/hour ≈ 4-8 challenge-passes worth of credit; enough for
 * a real user pinned at borderline-suspicious to keep transacting,
 * tight enough that a patient bot solving every few minutes stops
 * earning forgiveness past the cap. */
#define BS_DEFAULT_FORGIVE_CAP_PER_HOUR  200
#define BS_FORGIVE_WINDOW_SEC            3600
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
/* Bumped 1->2 for E15: rep envelope grew two fields
 * (forgive_window_start, forgive_consumed). Old (v1) cookies fail
 * the version check and trigger a fresh challenge — one-time
 * disruption per client on upgrade. The same shape lets future rep
 * extensions ride without code-flow changes. */
#define BS_PROTOCOL_VERSION   2
#define BS_SALT_BYTES         16
#define BS_NONCE_BYTES        8
#define BS_SIG_BYTES          32  /* HMAC-SHA-256 output */
#define BS_COOKIE_FIELDS      17  /* full cookie payload; canonical is 15 */

/* E8.1 — AES-256-GCM cookie wire format.
 *
 * Wire format:   base64( alg_id(1) || nonce(12) || ct || tag(16) )
 *                + "." + counter
 *
 *   alg_id is authenticated via AAD so an attacker can't swap
 *   primitives. ct is the AES-GCM encryption of the same canonical
 *   pipe-delimited form the HMAC path builds. Counter rides outside
 *   the ciphertext because the PoW JS builds the cookie client-side
 *   without the AES key — it appends its computed counter to the
 *   server-issued encrypted prefix and sets the cookie. Server-built
 *   cookies (captcha tier) use "captcha" as the counter sentinel on
 *   the same dot-suffix.
 *
 * AES-256 key is derived from cfg->secret via SHA-256, so:
 *   - operators keep a single BotShieldSecretFile
 *   - HMAC and GCM use distinct domain-separated keys from the same
 *     material (HMAC uses the raw bytes; GCM uses the digest) */
#define BS_COOKIE_ALG_GCM     0x01
#define BS_GCM_NONCE_LEN      12
#define BS_GCM_TAG_LEN        16
#define BS_GCM_COUNTER_SEP    '.'
/* Separator byte in AES-GCM wire format between the base64 envelope
 * and the plaintext counter. `.` because it's not in standard base64
 * alphabet — unambiguous split point. */

/* E8.1 — BotShieldCookieFormat bitmap. Bits are accepted *verify*
 * formats; issuer prefers GCM when that bit is set. Both bits set
 * is the migration mode ("issue GCM, accept either"). Field value
 * BS_FMT_UNSET (-1) means operator didn't write the directive; the
 * effective format falls back to BS_FMT_HMAC (legacy default until
 * operators opt in). */
#define BS_FMT_HMAC           0x01
#define BS_FMT_GCM            0x02
#define BS_FMT_UNSET          (-1)

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
 * challenge (all zeros), and merged forward with forgiveness on re-issues.
 *
 * E15 — forgiveness cap per window. `forgive_window_start`
 * marks the start of the current rolling hour (unix sec); on every
 * verify-success we either roll the window if the prior one is over an
 * hour old, or clamp the new forgiveness so the running consumed total
 * stays at or below BotShieldForgivenessCapPerHour. The fields ride in
 * the cookie envelope (one bump of BS_PROTOCOL_VERSION) so the cap
 * survives across cookie re-issues but doesn't survive a deliberate
 * cookie drop — by design, since dropping the cookie also drops the
 * accumulated rep that forgiveness was meant to whittle down. */
typedef struct {
    int         score;
    apr_uint32_t flags;
    int         passes_silent;
    int         passes_form;
    int         passes_captcha;
    apr_time_t  challenged_at;        /* unix sec */
    apr_uint32_t forgive_window_start; /* unix sec; 0 = no window yet */
    apr_uint32_t forgive_consumed;     /* points used inside current window */
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
#define BS_FLAG_FAKE_BOT          (1U << 2)
#define BS_FLAG_POW_FAIL_STREAK   (1U << 3)
/* E5 — credit-carrying bits. Contribute negative penalty in
 * bs_flag_penalty so the app can push score down as well as up
 * via the app-feedback channel. Compose additively with penalty
 * bits: an IP that tripped a honeypot and later had the app
 * verify the human carries +60 + -80 = -20 until the shorter-
 * TTL bit expires. */
#define BS_FLAG_APP_VERIFIED_HUMAN   (1U << 4)
#define BS_FLAG_APP_VERIFIED_SESSION (1U << 5)
#define BS_FLAG_APP_TRUST_SIGNAL     (1U << 6)
/* Score floor for bs_flag_penalty output. Penalties can stack
 * unbounded (high-trust penalty-stacking is a valid state);
 * credits are clamped so a single huge credit can't lock out
 * all future enforcement if other signals later go bad. */
#define BS_FLAG_PENALTY_FLOOR        (-200)

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
/* E13 — bumped from 8M to 16M to accommodate the per-slot ns_id+pad
 * fields (8 bytes/slot across flagged-IP / strike / safeguard tables
 * at default capacities). 8M no longer fits the default config. */
#define BS_DEFAULT_SHM_SIZE       (16 * 1024 * 1024)
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
 * between matching even versions.
 *
 * E13: an `ns_id` field was added so vhosts can isolate their flagged-
 * IP reputation. Lookups match on (ip, ns_id); the same physical
 * table holds rows from many namespaces without cross-pollution. The
 * size grew from 32 to 40 bytes — a 25% memory hit on this table for
 * the namespace guarantee. */
typedef struct {
    apr_uint32_t  version;       /* seqlock counter */
    apr_uint32_t  flags;         /* 0 = empty slot */
    unsigned char ip[16];        /* IPv6-mapped v4 or raw v6 */
    apr_int64_t   expires_at;    /* unix seconds; past means stale */
    apr_uint32_t  ns_id;         /* E13 — reputation namespace */
    apr_uint32_t  _pad;          /* keep slot 8-byte aligned */
} bs_flagged_ip_slot;

/* E9 — repeated-429 escalation. Per-(client_ip, rate_rule_slot)
 * strike accounting in SHM. Same seqlock + open-addressing idiom as
 * flagged_table. `rule_slot == BS_STRIKE_EMPTY` flags an unused slot
 * (real rule slots are non-negative + small); strike counter is a
 * fixed window keyed off `strike_window_start` so an idle entry
 * eventually rolls over.
 *
 * `escalation_until == 0` means the strike-counter is accumulating
 * but the IP has not yet crossed the threshold. Non-zero means the
 * (ip, rule) pair is in the escalated state: subsequent requests
 * against this rule return the operator-configured status until the
 * timestamp passes. Each fresh strike during escalation extends
 * the timestamp (TTL slides on the last strike). */
typedef struct {
    apr_uint32_t  version;             /* seqlock counter */
    apr_uint32_t  rule_slot;           /* BS_STRIKE_EMPTY = unused */
    unsigned char ip[16];              /* masked per ipv6_prefix_bits */
    apr_uint32_t  strike_window_start; /* unix sec; 0 = no strikes yet */
    apr_uint32_t  strike_count;
    apr_int64_t   escalation_until;    /* unix sec; 0 = not escalated */
    apr_uint32_t  ns_id;               /* E13 — reputation namespace */
    apr_uint32_t  _pad;
} bs_strike_slot;

#define BS_STRIKE_EMPTY            0xFFFFFFFFu
#define BS_STRIKE_PROBE_LIMIT      8
#define BS_DEFAULT_STRIKE_SLOTS    50000
#define BS_STRIKE_MIN_SLOTS        1024
#define BS_STRIKE_MAX_SLOTS        1000000

/* E10 — challenge safeguard / anti-loop hysteresis. Per-IP SHM
 * tracking for "BotShield keeps presenting a challenge but this
 * client never solves it." Tripping safeguard stops the module
 * from re-issuing the same challenge for a short TTL so a broken
 * client (JS blocked, CSP-stripped, cookie handling buggy) gets a
 * stable non-looping outcome instead of an endless
 * challenge-reload-challenge loop.
 *
 * Same seqlock + open-addressing idiom as the flagged-IP and
 * strike tables. Slot layout:
 *
 *   `present_count` accumulates inside `present_window_start +
 *   window_sec`. It resets on any `bs_safeguard_clear` (called when
 *   a valid `_bs_verified` lands — they can solve, so history was
 *   noise). It also resets on window roll.
 *
 *   `safeguard_until` is 0 when inactive; non-zero means the
 *   request-time check returns "safeguard active" until the
 *   timestamp passes. Each fresh presentation during an active
 *   safeguard refreshes the TTL (TTL slides on the last attempt)
 *   so a client who stays broken keeps benefiting rather than
 *   dropping in and out of safeguard every window boundary. */
typedef struct {
    apr_uint32_t  version;              /* seqlock */
    apr_uint32_t  used;                 /* 0 = empty slot */
    unsigned char ip[16];               /* masked per ipv6_prefix_bits */
    apr_uint32_t  present_window_start; /* unix sec */
    apr_uint32_t  present_count;
    apr_int64_t   safeguard_until;      /* unix sec; 0 = inactive */
    apr_uint32_t  ns_id;                /* E13 — reputation namespace */
    apr_uint32_t  _pad;
} bs_safeguard_slot;

#define BS_SAFEGUARD_PROBE_LIMIT   8
#define BS_DEFAULT_SAFEGUARD_SLOTS 50000
#define BS_SAFEGUARD_MIN_SLOTS     1024
#define BS_SAFEGUARD_MAX_SLOTS     1000000
#define BS_DEFAULT_SAFEGUARD_THRESHOLD 5
#define BS_DEFAULT_SAFEGUARD_WINDOW    600
#define BS_DEFAULT_SAFEGUARD_TTL       900

/* E11 — load-aware throttling. A periodic watchdog tick samples
 * the Apache scoreboard's busy-worker ratio, optionally merges in
 * an external operator-set state from a watched file, and computes
 * a coarse cached state that the request path reads as a single
 * atomic u32. This is application-tier brownout, not DDoS defense:
 * help shed low-trust traffic when the origin is hot, leave verified
 * clients alone.
 *
 * State is a 3-value totally-ordered enum:
 *   normal < warm < hot
 *
 * "Most severe wins" merging: if internal sensing says warm and
 * external file says hot, result is hot. The external override is
 * the cleanest handoff for operators with their own monitoring —
 * they don't have to teach the monitor to talk Apache config. */
typedef enum {
    BS_LOAD_NORMAL = 0,
    BS_LOAD_WARM   = 1,
    BS_LOAD_HOT    = 2,
} bs_load_state;

#define BS_DEFAULT_LOAD_REFRESH_SEC      1
#define BS_DEFAULT_LOAD_WARM_RATIO_PCT   65    /* busy_workers / total */
#define BS_DEFAULT_LOAD_HOT_RATIO_PCT    85
/* Hysteresis: asymmetric. Easy to enter (3 escalating samples to
 * warm, 2 more to hot), slow to exit (5 normal samples to demote
 * one level). Tunes the responsiveness vs. flap-resistance
 * tradeoff. Operators rarely need to override; the constants are
 * exposed via directives below for when they do. */
#define BS_DEFAULT_LOAD_WARM_RISE        3
#define BS_DEFAULT_LOAD_HOT_RISE         2
#define BS_DEFAULT_LOAD_WARM_FALL        5
#define BS_DEFAULT_LOAD_NORMAL_FALL      5

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
    /* E11 — cached load state. Updated by the watchdog tick;
     * read lockless from the request path. The hysteresis fields
     * are tick-private; only the watchdog thread reads/writes
     * them, so they don't need atomic ordering. */
    apr_uint32_t  load_state;             /* bs_load_state enum value */
    apr_uint32_t  load_state_since_sec;   /* unix sec at last transition */
    apr_uint32_t  load_escalation_streak; /* samples wanting higher state */
    apr_uint32_t  load_recovery_streak;   /* samples wanting lower state */
    apr_uint32_t  load_state_changes;     /* monotonic counter for metrics */
    apr_uint32_t  _pad3;
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
    apr_uint64_t bot_allow_total;
    apr_uint64_t bot_fake_total;
    apr_uint64_t bot_unverified_total;
    /* E2.1 — policy enforcement counters. */
    apr_uint64_t rate_limit_exceeded_total;
    apr_uint64_t block_path_hit_total;
    /* E12 — shadow / observe-mode counters. Separate from the
     * enforcement counters above so operators can graph "what the
     * staged rule would have blocked" without polluting the real-
     * blocks dashboards. */
    apr_uint64_t rate_limit_observed_total;
    apr_uint64_t block_path_observed_total;
    apr_uint64_t trigger_observed_total;
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
    /* E2.1 — rate-limit fixed-window counters. Flat slot array in
     * SHM; each bs_rate_limit_entry gets a slot index assigned at
     * post_config. Sized by bs_rate_counter_count. */
    void                *rate_counters;     /* bs_rate_counter *, opaque here */
    apr_size_t           rate_counter_count;
    /* E9 — strike table for repeated-429 escalation. Open-addressed
     * SHM hash, key = (client_ip, rule_slot). Sized by
     * BotShieldRateLimitEscalateCapacity. */
    bs_strike_slot      *strike_table;
    apr_size_t           strike_capacity;
    /* E10 — safeguard table for anti-loop hysteresis. Same shape
     * as strike_table but keyed by masked IP only (no rule_slot).
     * Sized by BotShieldSafeguardCapacity. */
    bs_safeguard_slot   *safeguard_table;
    apr_size_t           safeguard_capacity;
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

/* E17 PoC — what flavor of silent-tier dispatch to use. INTERSTITIAL
 * is the legacy M7 splash that auto-submits the PoW. EMBEDDED hands
 * off to a wrapper script the operator has already included on the
 * page; the page serves DECLINED (real content) and the wrapper does
 * the PoW in a Web Worker, then POSTs back to /botshield/embedded-
 * verify to mint _bs_verified. The "kicks in eventually" model: the
 * cookie may not be set in time for the very first request, but it
 * lands within a few page-views and from then on the client is
 * verified. */
typedef enum {
    BS_SILENT_MODE_UNSET        = -1,
    BS_SILENT_MODE_INTERSTITIAL =  0,   /* default; M7 splash */
    BS_SILENT_MODE_EMBEDDED     =  1    /* E17 background verify */
} bs_silent_mode;

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
    /* E16 — verify-only secondary secret for graceful
     * rotation. Issue path always uses `secret`; verify tries
     * `secret` first and falls back to `secret_secondary` so cookies
     * minted under the old key keep validating during a rotation
     * window. NULL = no rotation in progress. */
    const unsigned char    *secret_secondary;
    apr_size_t              secret_secondary_len;
    int                     cookie_format;  /* BS_FMT_* bitmap or BS_FMT_UNSET */
    int score_silent;           /* score >= this → silent tier (logged only) */
    int score_hard;             /* score >= this → hard form-PoW tier */
    int score_captcha;          /* score >= this → captcha tier */
    /* E17 PoC — what flavor of silent-tier challenge to issue. Stored
     * as a tri-state with UNSET sentinel so the merge picks the
     * right scope's value. */
    int silent_mode;            /* bs_silent_mode; UNSET inherits */
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

/* E2.2 — robots.txt state bundle. One of these per active parse;
 * swapped atomically by the refresh watchdog. The owning subpool
 * (`pool`) is a child of pconf and is destroyed when this bundle is
 * finally retired — one refresh cycle after being displaced — so
 * request-path readers holding pointers into doc's pool never see
 * freed memory. `slot_by_group_idx` maps each group index in doc to
 * its SHM rate-counter slot, or -1 for groups without a Crawl-delay
 * (or for which the slot pool was exhausted). */
typedef struct bs_robots_state {
    robots_doc    *doc;
    apr_pool_t    *pool;              /* owns doc; sized for one doc */
    apr_time_t     mtime;              /* source file mtime when parsed */
    int           *slot_by_group_idx;  /* length = robots_group_count(doc) */
} bs_robots_state;

/* Per-server config — holds SHM sizing before post-config runs. Only the
 * main server's values are consulted; vhost-level overrides are logged
 * and ignored because the SHM segment is global. */
typedef struct bs_server_cfg {
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
    int          allow_enabled;         /* master gate, default 0 */
    void        *bot_classifier;       /* bs_ua_classifier *, opaque here */
    apr_hash_t  *bot_ranges;           /* name → apr_array_header_t of apr_ipsubnet_t* */
    apr_hash_t *allow_bots;         /* name → bs_allow_bot_entry * (directive-defined) */
    /* E2.1 — policy enforcement (rate limit + path block). Ordered
     * arrays of entry pointers. Precedence at request time is
     * declaration order (first match wins). Upsert-by-name at
     * config time — re-declaring the same name replaces the entry
     * in place, preserving its position so operators can override
     * a rule without disturbing relative order of the others. */
    apr_array_header_t *rate_limits;   /* bs_rate_limit_entry * */
    /* E9 — repeated-429 escalation. One entry per
     * BotShieldRateLimitEscalate directive; each one references an
     * existing rate_limits rule by name. Linked into the matching
     * bs_rate_limit_entry::escalate at post_config. */
    apr_array_header_t *rate_escalates; /* bs_rate_escalate_entry * */
    /* Strike-table capacity (operator-tunable). Read at post_config
     * from the main server's scfg, same convention as flagged_capacity. */
    int                 strike_capacity;
    /* E10 — safeguard config. All server-scope so the single SHM
     * table is consistently sized. `safeguard_enabled=-1` is the
     * unset sentinel; merge picks add's value if set, else base's. */
    int                 safeguard_enabled;      /* -1 unset, 0 off, 1 on */
    int                 safeguard_threshold;    /* 0 = inherit / default */
    int                 safeguard_window;       /* seconds; 0 = default */
    int                 safeguard_ttl;          /* seconds; 0 = default */
    int                 safeguard_capacity;     /* 0 = default */
    /* E11 — load-aware throttling. All server-scope; the cached
     * state and watchdog are module-global. */
    const char         *load_state_file;        /* NULL = no external file */
    int                 load_refresh_sec;       /* watchdog tick; 0 = default */
    int                 load_warm_pct;          /* busy-ratio % for warm; 0 = default */
    int                 load_hot_pct;           /* busy-ratio % for hot; 0 = default */
    int                 load_warm_rise;         /* hysteresis; 0 = default */
    int                 load_hot_rise;          /* hysteresis; 0 = default */
    int                 load_normal_fall;       /* hysteresis; 0 = default */
    /* Tick-private: last successfully read external state and the
     * mtime that produced it. Stored on scfg (not SHM) because the
     * watchdog runs single-threaded per server; no contention. */
    bs_load_state       load_external_cached;
    apr_time_t          load_external_mtime;
    /* E12 — global shadow mode. -1 unset (merge picks parent's
     * value), 0 off, 1 on. When on, ALL trigger / rate-limit /
     * block-path rules behave as if mode=observe regardless of
     * their per-rule setting. Operator's panic-revert switch. */
    int                 shadow_mode;
    /* E13 — reputation namespace for SHM-backed state (flagged-IP,
     * strike, safeguard, Bloom). Derived at post_config: explicit
     * BotShieldShareScope token wins; otherwise siphash(ServerName)
     * truncated to u32. ns_id == 0 means "global default
     * namespace" — used as a graceful fallback when ServerName is
     * unset (rare but legal). Lookups in the SHM tables match on
     * (ip, ns_id) so different namespaces stop sharing reputation
     * even though they live in the same physical SHM segment.
     *
     * Default semantic: each vhost auto-isolates by ServerName.
     * Operators wanting two vhosts to share state set the same
     * BotShieldShareScope token on both; same string → same
     * ns_id → shared rows. */
    apr_uint32_t        ns_id;            /* effective; resolved post_config */
    const char         *share_scope_token; /* explicit override; NULL = default */
    /* E14 — adaptive challenge intensity ceiling. PoW difficulty
     * after BotShieldFlag's next_difficulty bumps is clamped against
     * this value (1..BS_MAX_DIFFICULTY_HARDCAP). 0 = inherit /
     * default (BS_DEFAULT_MAX_DIFFICULTY). Server-scope only — the
     * adaptive layer is module-global by design. */
    int                 max_difficulty;
    /* E15 — per-cookie hourly forgiveness cap. 0 =
     * inherit / use BS_DEFAULT_FORGIVE_CAP_PER_HOUR. Operators set
     * this at server scope to bound forgiveness-farming. */
    int                 forgive_cap_per_hour;
    apr_array_header_t *block_paths;   /* bs_block_path_entry * */
    /* E3 — path-based triggers. Same ordered-array + upsert-by-name
     * shape as E2.1; first match wins at request time. */
    apr_array_header_t *path_triggers; /* bs_path_trigger_entry * */
    /* E4 — cookie triggers. Same ordered-array + upsert-by-name
     * shape as E3. `session_names` is the list of cookie names
     * that `cookies=session` matches against — seeded with common
     * framework defaults at config creation, extended via
     * BotShieldSessionCookieName. Lowercased at add time for
     * cheap case-insensitive compare at request time. */
    apr_array_header_t *cookie_triggers;   /* bs_cookie_trigger_entry * */
    /* E6 — env-var triggers. Same ordered-array + upsert-by-name
     * shape as E3/E4. Precedence: declaration order, first match
     * wins (no accumulation); env signals are discrete per-request,
     * not layered reputation. */
    apr_array_header_t *env_triggers;      /* bs_env_trigger_entry * */
    /* E7.3 — feedback triggers. Signed event names from E5's
     * response-path header map to module memory (flag+ttl+log) via
     * these entries. Same ordered-array + upsert-by-name shape. */
    apr_array_header_t *feedback_triggers; /* bs_feedback_trigger_entry * */
    /* E11.2 — load triggers. Same ordered-array shape; predicate
     * matches against the global cached load_state (E11.1). */
    apr_array_header_t *load_triggers;     /* bs_load_trigger_entry * */
    apr_array_header_t *session_names;     /* const char * (lowercased) */
    /* E2.2 — robots.txt enforcement.
     *
     * `robots` is the active state bundle (parsed doc + owning
     * subpool + per-group SHM slot indices + source-file mtime) —
     * atomically swappable by the refresh watchdog without quiescing
     * the hot path. NULL until post_config successfully loads the
     * file.
     *
     * `robots_pending` holds the previously-active bundle for one
     * refresh cycle, then is destroyed at the next refresh. This
     * gives request-path readers at least one refresh interval to
     * finish using an old doc before its pool is reclaimed; with
     * refresh_interval >> max request duration the window is ample.
     *
     * `robots_slot_by_name` is a name → (int*) SHM-slot map
     * populated at post_config and updated (but not shrunk) by each
     * refresh. Keying by group name (not index) means unchanged
     * groups keep their rate-counter state across refreshes —
     * operators expect that rewriting robots.txt doesn't reset
     * Crawl-delay windows for crawlers whose entry didn't change.
     * The slot pool itself is reserved from bs_shm.rate_counters at
     * post_config; robots_slot_pool_base/size bound it and
     * robots_slot_pool_used tracks allocation. */
    const char         *robots_txt_path;
    int                 robots_wildcard_scope;       /* enum below */
    bs_robots_state    *robots;                      /* active bundle, atomic */
    bs_robots_state    *robots_pending;              /* awaits destruction */
    apr_hash_t         *robots_slot_by_name;         /* name → int * */
    int                 robots_slot_pool_base;       /* first reserved slot */
    int                 robots_slot_pool_size;       /* pool capacity */
    int                 robots_slot_pool_used;       /* slots assigned so far */
    int                 robots_refresh_interval;     /* seconds; 0 = off */
    /* E5 — app-to-module reputation feedback. Enabled gates the
     * parse/validate path; stripping the header always runs when
     * enabled=-1 (unset) or enabled=0 so a misconfigured app can
     * never leak the header to clients. Header name + secret are
     * per-scope. Secret bytes are loaded from the secret file at
     * post_config. */
    int                 app_feedback_enabled;        /* -1 unset, 0 off, 1 on */
    const char         *app_feedback_header;         /* default "X-BotShield-Feedback" */
    const char         *app_feedback_secret_file;    /* NULL = no key */
    const unsigned char *app_feedback_secret;        /* loaded bytes */
    apr_size_t          app_feedback_secret_len;
    /* E8.2 — module-to-app reputation export. Symmetric to E5 in
     * shape: signed envelope, separate secret file. The module sets
     * a single X-Botshield-Claims request header on the way to the
     * backend handler, having first stripped any client-supplied
     * X-Botshield-* (the strip is the trust anchor for apps that
     * skip HMAC verification). */
    int                 app_claims_enabled;          /* -1 unset, 0 off, 1 on */
    const char         *app_claims_secret_file;      /* NULL = no key */
    const unsigned char *app_claims_secret;          /* loaded bytes */
    apr_size_t          app_claims_secret_len;
} bs_server_cfg;

#define BS_APP_FEEDBACK_UNSET  (-1)
#define BS_APP_FEEDBACK_DEFAULT_HEADER  "X-BotShield-Feedback"

enum bs_robots_wildcard_scope {
    BS_ROBOTS_WILDCARD_UNSET     = -1,  /* directive not given at this scope */
    BS_ROBOTS_WILDCARD_HEURISTIC = 0,   /* default: crawler-candidate test */
    BS_ROBOTS_WILDCARD_STRICT    = 1,   /* apply * rules to all UAs */
    BS_ROBOTS_WILDCARD_OFF       = 2,   /* ignore * groups entirely */
};

/* Sentinel for robots_refresh_interval: the directive hasn't been
 * given at this scope. At post_config time this resolves to
 * BS_ROBOTS_REFRESH_DEFAULT (60s) unless a main/vhost override
 * replaced it via the merge hook. */
#define BS_ROBOTS_REFRESH_UNSET    (-1)
#define BS_ROBOTS_REFRESH_DEFAULT  60

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
    cfg->secret_secondary     = NULL;
    cfg->secret_secondary_len = 0;
    cfg->cookie_format = BS_FMT_UNSET;
    cfg->score_silent  = BS_UNSET;
    cfg->score_hard    = BS_UNSET;
    cfg->score_captcha = BS_UNSET;
    cfg->silent_mode   = BS_SILENT_MODE_UNSET;
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

/* Per-server merge for the Allow family.
 *
 * Apache calls this to combine main-scope + vhost-scope configs into
 * the effective scfg that hooks and request handlers see. The module
 * historically omitted a server merge, which meant main-scope
 * `BotShieldAllowBot` entries were invisible inside a vhost — a real
 * mismatch for the common "declare globally, enable per-vhost" shape.
 *
 * Policy:
 *  - Most fields: override (vhost) wins via pmemdup. Matches the
 *    historical no-merge behavior so existing per-vhost directives
 *    keep their scoping. (The merge is a null-op for any vhost that
 *    doesn't touch allow_bots at main scope.)
 *  - allow_bots: union of base + override, with override winning on
 *    key collision. apr_hash_overlay is last-writer-wins on the
 *    overlay arg, so passing (overlay=add, base=base) gives vhost-
 *    overrides-main. Operators can add to, or shadow, a main-scope
 *    bot declaration from a specific vhost. */
/* Merge two E2.1 rule arrays. Vhost (add) leads; main-scope (base)
 * entries whose name doesn't already appear in vhost are appended
 * as fallbacks. Both entry types start with `const char *name` as
 * their first field so we can dedup by reading *(const char **)entry
 * without a per-type callback. */
static apr_array_header_t *bs_merge_rule_array(apr_pool_t *p,
                                               apr_array_header_t *base,
                                               apr_array_header_t *add)
{
    int nadd  = add  ? add->nelts  : 0;
    int nbase = base ? base->nelts : 0;
    if (nadd == 0)  return base;
    if (nbase == 0) return add;

    apr_array_header_t *out = apr_array_copy(p, add);
    for (int i = 0; i < nbase; i++) {
        void *be = APR_ARRAY_IDX(base, i, void *);
        const char *bname = *(const char **)be;
        int shadowed = 0;
        for (int j = 0; j < out->nelts; j++) {
            void *oe = APR_ARRAY_IDX(out, j, void *);
            if (strcmp(*(const char **)oe, bname) == 0) {
                shadowed = 1;
                break;
            }
        }
        if (!shadowed) {
            *(void **)apr_array_push(out) = be;
        }
    }
    return out;
}

static void *bs_merge_server_cfg(apr_pool_t *p, void *base_v, void *add_v)
{
    bs_server_cfg *base = base_v;
    bs_server_cfg *add  = add_v;
    bs_server_cfg *out  = apr_pmemdup(p, add, sizeof(*add));

    if (base->allow_bots && apr_hash_count(base->allow_bots) > 0
        && add->allow_bots) {
        out->allow_bots = apr_hash_overlay(p, add->allow_bots,
                                           base->allow_bots);
    }
    /* E2.1 — ordered-array merge. Vhost entries lead (more-specific
     * wins on first-match), then main-scope entries as fallbacks.
     * If a name exists in both, the vhost version wins and the
     * main version is skipped entirely (no shadowed duplicates).
     *
     * Both struct types (bs_rate_limit_entry, bs_block_path_entry)
     * share a const char *name as their first field, so we can
     * key the dedup by the leading pointer word without branching
     * per-type. */
    out->rate_limits = bs_merge_rule_array(p, base->rate_limits,
                                           add->rate_limits);
    out->rate_escalates = bs_merge_rule_array(p, base->rate_escalates,
                                              add->rate_escalates);
    out->strike_capacity = (add->strike_capacity > 0)
                         ? add->strike_capacity : base->strike_capacity;
    /* E10 — safeguard merge. Only the main server's values steer
     * SHM sizing; merged-in overrides are harmless at per-vhost
     * scope because the table is module-global. */
    out->safeguard_enabled  = (add->safeguard_enabled != -1)
                            ? add->safeguard_enabled
                            : base->safeguard_enabled;
    out->safeguard_threshold = (add->safeguard_threshold > 0)
                             ? add->safeguard_threshold
                             : base->safeguard_threshold;
    out->safeguard_window   = (add->safeguard_window > 0)
                            ? add->safeguard_window
                            : base->safeguard_window;
    out->safeguard_ttl      = (add->safeguard_ttl > 0)
                            ? add->safeguard_ttl
                            : base->safeguard_ttl;
    out->safeguard_capacity = (add->safeguard_capacity > 0)
                            ? add->safeguard_capacity
                            : base->safeguard_capacity;
    /* E11 — load-state merge. Only the main server's values steer
     * the watchdog; vhost-level overrides are harmless because the
     * cached state is module-global. */
    out->load_state_file   = add->load_state_file ? add->load_state_file
                                                  : base->load_state_file;
    out->load_refresh_sec  = (add->load_refresh_sec > 0)
                           ? add->load_refresh_sec
                           : base->load_refresh_sec;
    out->load_warm_pct     = (add->load_warm_pct > 0)
                           ? add->load_warm_pct : base->load_warm_pct;
    out->load_hot_pct      = (add->load_hot_pct > 0)
                           ? add->load_hot_pct : base->load_hot_pct;
    out->load_warm_rise    = (add->load_warm_rise > 0)
                           ? add->load_warm_rise : base->load_warm_rise;
    out->load_hot_rise     = (add->load_hot_rise > 0)
                           ? add->load_hot_rise : base->load_hot_rise;
    out->load_normal_fall  = (add->load_normal_fall > 0)
                           ? add->load_normal_fall : base->load_normal_fall;
    /* E12 — shadow mode inherits unless explicitly set. */
    out->shadow_mode = (add->shadow_mode != -1)
                     ? add->shadow_mode : base->shadow_mode;
    /* E13 — namespace plumbing: explicit share_scope_token survives
     * the merge if either scope set it. ns_id is computed at
     * post_config from the merged config + ServerName, so the
     * field's value here is irrelevant; just take add's. */
    out->share_scope_token = add->share_scope_token
        ? add->share_scope_token : base->share_scope_token;
    out->ns_id = add->ns_id;
    /* E14 — child-set value wins; 0 means "inherit". */
    out->max_difficulty = (add->max_difficulty > 0)
        ? add->max_difficulty : base->max_difficulty;
    /* E15 — same merge shape. */
    out->forgive_cap_per_hour = (add->forgive_cap_per_hour > 0)
        ? add->forgive_cap_per_hour : base->forgive_cap_per_hour;
    out->block_paths = bs_merge_rule_array(p, base->block_paths,
                                           add->block_paths);
    out->path_triggers = bs_merge_rule_array(p, base->path_triggers,
                                             add->path_triggers);
    out->cookie_triggers = bs_merge_rule_array(p, base->cookie_triggers,
                                               add->cookie_triggers);
    out->env_triggers    = bs_merge_rule_array(p, base->env_triggers,
                                                add->env_triggers);
    out->feedback_triggers = bs_merge_rule_array(p, base->feedback_triggers,
                                                 add->feedback_triggers);
    out->load_triggers     = bs_merge_rule_array(p, base->load_triggers,
                                                 add->load_triggers);
    /* session_names: concatenate base + add, drop dups. Small lists,
     * O(n*m) is fine; happens once at config load. */
    if (base->session_names && add->session_names) {
        apr_array_header_t *merged = apr_array_copy(p, add->session_names);
        for (int i = 0; i < base->session_names->nelts; i++) {
            const char *bn = APR_ARRAY_IDX(base->session_names, i,
                                           const char *);
            int dup = 0;
            for (int j = 0; j < merged->nelts; j++) {
                if (strcmp(APR_ARRAY_IDX(merged, j, const char *), bn) == 0) {
                    dup = 1; break;
                }
            }
            if (!dup) *(const char **)apr_array_push(merged) = bn;
        }
        out->session_names = merged;
    }

    /* E2.2 server-scope inheritance — main-scope settings should
     * flow into vhosts that don't restate them. Each field uses a
     * sentinel ("unset at this scope") so we can tell "take the
     * base value" apart from "vhost explicitly chose the default." */
    if (!add->robots_txt_path && base->robots_txt_path) {
        out->robots_txt_path = base->robots_txt_path;
    }
    if (add->robots_wildcard_scope == BS_ROBOTS_WILDCARD_UNSET) {
        out->robots_wildcard_scope = base->robots_wildcard_scope;
    }
    if (add->robots_refresh_interval == BS_ROBOTS_REFRESH_UNSET) {
        out->robots_refresh_interval = base->robots_refresh_interval;
    }

    /* E5 — app feedback server-scope inheritance. */
    if (add->app_feedback_enabled == BS_APP_FEEDBACK_UNSET) {
        out->app_feedback_enabled = base->app_feedback_enabled;
    }
    if (!add->app_feedback_header && base->app_feedback_header) {
        out->app_feedback_header = base->app_feedback_header;
    }
    if (!add->app_feedback_secret_file && base->app_feedback_secret_file) {
        out->app_feedback_secret_file = base->app_feedback_secret_file;
        out->app_feedback_secret      = base->app_feedback_secret;
        out->app_feedback_secret_len  = base->app_feedback_secret_len;
    }
    /* E8.2 — app claims server-scope inheritance. Same shape. */
    if (add->app_claims_enabled == BS_APP_FEEDBACK_UNSET) {
        out->app_claims_enabled = base->app_claims_enabled;
    }
    if (!add->app_claims_secret_file && base->app_claims_secret_file) {
        out->app_claims_secret_file = base->app_claims_secret_file;
        out->app_claims_secret      = base->app_claims_secret;
        out->app_claims_secret_len  = base->app_claims_secret_len;
    }
    return out;
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
    /* E1 Allow-family defaults — master gate off (opt-in).
     * bot_classifier / bot_ranges stay NULL and get built in
     * post_config if the master gate flips on. allow_bots
     * collects directive-declared entries (and seeded built-ins)
     * keyed by name. */
    scfg->allow_enabled    = 0;
    scfg->bot_classifier   = NULL;
    scfg->bot_ranges       = NULL;
    scfg->allow_bots       = apr_hash_make(p);
    /* E2.1 — rate-limit + block-path ordered arrays; populated by
     * directives in declaration order, post_config resolves cohort
     * ipspecs and assigns SHM slots. */
    scfg->rate_limits      = apr_array_make(p, 4, sizeof(void *));
    scfg->rate_escalates   = apr_array_make(p, 2, sizeof(void *));
    scfg->strike_capacity  = 0;   /* 0 = inherit / use default */
    /* E10 — safeguard defaults. enabled=-1 is the unset sentinel so
     * the merge can pick the right scope's value; numeric fields
     * default to 0 which the post_config sizing + request-time
     * check treat as "use the compiled-in default." */
    scfg->safeguard_enabled   = -1;
    scfg->safeguard_threshold = 0;
    scfg->safeguard_window    = 0;
    scfg->safeguard_ttl       = 0;
    scfg->safeguard_capacity  = 0;
    /* E11 — load-state defaults. NULL state file = no external
     * override path; all numeric thresholds default to 0 (request-
     * time + post_config substitute the compile-time defaults). */
    scfg->load_state_file       = NULL;
    scfg->load_refresh_sec      = 0;
    scfg->load_warm_pct         = 0;
    scfg->load_hot_pct          = 0;
    scfg->load_warm_rise        = 0;
    scfg->load_hot_rise         = 0;
    scfg->load_normal_fall      = 0;
    scfg->load_external_cached  = BS_LOAD_NORMAL;
    scfg->load_external_mtime   = 0;
    /* E12 — global shadow mode unset. -1 sentinel means "inherit
     * from parent scope"; merge below picks the right value. */
    scfg->shadow_mode           = -1;
    /* E13 — namespace defaults. ns_id is filled in at post_config
     * once ServerName is final; here we just zero the field and
     * leave the explicit-token slot NULL. */
    scfg->ns_id                 = 0;
    scfg->share_scope_token     = NULL;
    /* E14 — 0 means "inherit / use BS_DEFAULT_MAX_DIFFICULTY". */
    scfg->max_difficulty        = 0;
    /* E15 — 0 means "inherit / use default". */
    scfg->forgive_cap_per_hour  = 0;
    scfg->block_paths      = apr_array_make(p, 4, sizeof(void *));
    scfg->path_triggers         = apr_array_make(p, 4, sizeof(void *));
    scfg->cookie_triggers  = apr_array_make(p, 4, sizeof(void *));
    scfg->env_triggers     = apr_array_make(p, 4, sizeof(void *));
    scfg->feedback_triggers = apr_array_make(p, 4, sizeof(void *));
    scfg->load_triggers     = apr_array_make(p, 4, sizeof(void *));
    /* Curated session-cookie-name defaults. Kept deliberately
     * short; long auto-lists turn `cookies=session` into a loose
     * matcher and undermine the bonus. Operators add their own
     * via BotShieldSessionCookieName. Stored lowercased. */
    scfg->session_names    = apr_array_make(p, 8, sizeof(const char *));
    static const char *const bs_session_name_defaults[] = {
        "phpsessid", "jsessionid", "asp.net_sessionid",
        "session_id", "connect.sid", "laravel_session",
        NULL
    };
    for (int i = 0; bs_session_name_defaults[i]; i++) {
        *(const char **)apr_array_push(scfg->session_names) =
            apr_pstrdup(p, bs_session_name_defaults[i]);
    }
    /* E2.2 — robots.txt defaults: no file configured, heuristic
     * wildcard scope, no parsed doc (populated in post_config). */
    scfg->robots_txt_path         = NULL;
    /* Sentinel defaults so bs_merge_server_cfg can tell "unset at
     * this scope" from "explicitly set to the default." An unset
     * field after merge resolves to its real default in post_config. */
    scfg->robots_wildcard_scope   = BS_ROBOTS_WILDCARD_UNSET;
    scfg->robots                  = NULL;
    scfg->robots_pending          = NULL;
    scfg->robots_slot_by_name     = apr_hash_make(p);
    scfg->robots_slot_pool_base   = -1;
    scfg->robots_slot_pool_size   = 0;
    scfg->robots_slot_pool_used   = 0;
    scfg->robots_refresh_interval = BS_ROBOTS_REFRESH_UNSET;
    /* E5 defaults — sentinel so bs_merge_server_cfg can tell
     * "unset at this scope" from explicit off. */
    scfg->app_feedback_enabled      = BS_APP_FEEDBACK_UNSET;
    scfg->app_feedback_header       = NULL;
    scfg->app_feedback_secret_file  = NULL;
    scfg->app_feedback_secret       = NULL;
    scfg->app_feedback_secret_len   = 0;
    /* E8.2 defaults — same UNSET sentinel shape as E5. */
    scfg->app_claims_enabled        = BS_APP_FEEDBACK_UNSET;
    scfg->app_claims_secret_file    = NULL;
    scfg->app_claims_secret         = NULL;
    scfg->app_claims_secret_len     = 0;
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
    /* E16 — same merge shape for the verify-only
     * secondary key. Independent of primary so an operator can
     * stage a rotation by setting just the secondary on a child
     * scope. */
    if (add->secret_secondary) {
        out->secret_secondary     = add->secret_secondary;
        out->secret_secondary_len = add->secret_secondary_len;
    } else {
        out->secret_secondary     = base->secret_secondary;
        out->secret_secondary_len = base->secret_secondary_len;
    }
    out->cookie_format = (add->cookie_format == BS_FMT_UNSET)
                       ? base->cookie_format
                       : add->cookie_format;
    out->score_silent  = (add->score_silent  == BS_UNSET) ? base->score_silent  : add->score_silent;
    out->score_hard    = (add->score_hard    == BS_UNSET) ? base->score_hard    : add->score_hard;
    out->score_captcha = (add->score_captcha == BS_UNSET) ? base->score_captcha : add->score_captcha;
    out->silent_mode   = (add->silent_mode   == BS_SILENT_MODE_UNSET)
                       ? base->silent_mode : add->silent_mode;
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

/* E17 PoC — `BotShieldSilentMode <interstitial|embedded>`. Per-scope
 * picker for what flavor of silent-tier challenge to issue. Default
 * `interstitial` matches the legacy M7 splash. `embedded` opts the
 * scope into background verification: BotShield serves the real
 * page (DECLINED) and relies on the operator-included
 * `<script src="/botshield/embedded.js" defer>` wrapper to run the
 * PoW in a Web Worker and POST the result back. The cookie may
 * arrive after the first request — see PLAN E17 for the
 * "kicks in eventually" guarantee. */
static const char *bs_set_silent_mode(cmd_parms *cmd, void *cfg_v,
                                      const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if      (!strcasecmp(arg, "interstitial")) cfg->silent_mode = BS_SILENT_MODE_INTERSTITIAL;
    else if (!strcasecmp(arg, "embedded"))     cfg->silent_mode = BS_SILENT_MODE_EMBEDDED;
    else {
        return apr_psprintf(cmd->pool,
            "BotShieldSilentMode: '%s' must be 'interstitial' or "
            "'embedded'", arg);
    }
    return NULL;
}

/* Forward decl: defined below in the SHM section, used by the directive
 * setter just beneath this comment. */
static apr_uint32_t bs_parse_flag_names(apr_pool_t *p, const char *s,
                                        const char **err);

/* E13 — log a NOTICE if an SHM-sizing directive is placed inside
 * <VirtualHost>. The single SHM segment is sized once at post_config
 * from the main server's scfg; per-vhost values for capacity directives
 * are silently ignored. The footgun was hard to spot in operator
 * configs — surface it explicitly so they don't think their override
 * took effect. */
static void bs_warn_if_virtual_scope(cmd_parms *cmd, const char *name)
{
    if (cmd->server && cmd->server->is_virtual) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server,
            "mod_botshield: %s placed inside <VirtualHost> at %s:%d "
            "is ignored — SHM is sized once from the main server "
            "scope. Move this directive outside <VirtualHost>.",
            name,
            cmd->directive && cmd->directive->filename
                ? cmd->directive->filename : "(unknown)",
            cmd->directive ? cmd->directive->line_num : 0);
    }
}

static const char *bs_set_shm_size(cmd_parms *cmd, void *dconf, const char *arg)
{
    bs_warn_if_virtual_scope(cmd, "BotShieldShmSize");
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
    bs_warn_if_virtual_scope(cmd, "BotShieldFlaggedIPCapacity");
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

/* Derive a 32-byte AES-256 key from operator secret bytes via
 * SHA-256. Two purposes:
 *   1. Accept any secret length — SHA-256 is defined for any input.
 *      The existing HMAC path uses the secret bytes directly (HMAC
 *      accepts variable-length keys), so having GCM run through a
 *      hash gives us one derived-key convention without forcing
 *      operators to manage two key files.
 *   2. Domain separation. HMAC reads the raw bytes; GCM reads the
 *      digest. A leaked-in-one-direction-but-not-the-other secret
 *      can't be trivially cross-applied even if someone mistakenly
 *      exports the derived bytes. Not cryptographically rigorous
 *      domain separation (a SHA-256 preimage is trivial with the
 *      original bytes), but it means AES ciphertexts produced under
 *      the HMAC-derived key won't decrypt under the raw bytes and
 *      vice versa. */
static void bs_derive_aes_key(const unsigned char *secret,
                              apr_size_t secret_len,
                              unsigned char out_key[32])
{
    bs_sha256(secret, secret_len, out_key);
}

/* AES-256-GCM encrypt. Wire layout:
 *     alg_id(1) || nonce(12) || ciphertext || tag(16)
 * The alg_id byte is the only AAD — authenticates the primitive
 * choice so an attacker can't swap 0x01 for (say) 0x02 and drive
 * the verifier into a different algorithm's parse.
 *
 * On success: writes the full envelope into *out_buf (caller-
 * provided, must be at least 1 + 12 + pt_len + 16 bytes), writes
 * the envelope length into *out_len, returns NULL.
 * On failure: returns an error string for logging; *out_len
 * untouched. */
static const char *bs_gcm_encrypt(const unsigned char *secret,
                                  apr_size_t secret_len,
                                  const unsigned char *pt,
                                  apr_size_t pt_len,
                                  unsigned char *out_buf,
                                  apr_size_t *out_len)
{
    unsigned char key[32];
    bs_derive_aes_key(secret, secret_len, key);

    out_buf[0] = BS_COOKIE_ALG_GCM;
    if (RAND_bytes(out_buf + 1, BS_GCM_NONCE_LEN) != 1) {
        return "RAND_bytes(gcm_nonce)";
    }
    unsigned char *nonce = out_buf + 1;
    unsigned char *ct    = out_buf + 1 + BS_GCM_NONCE_LEN;
    unsigned char *tag   = ct + pt_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "EVP_CIPHER_CTX_new";
    const char *err = NULL;
    int outlen = 0, finallen = 0, aadlen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        err = "EVP_EncryptInit_ex(aes_256_gcm)"; goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            BS_GCM_NONCE_LEN, NULL) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(SET_IVLEN)"; goto done;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        err = "EVP_EncryptInit_ex(key+nonce)"; goto done;
    }
    if (EVP_EncryptUpdate(ctx, NULL, &aadlen, out_buf, 1) != 1) {
        err = "EVP_EncryptUpdate(AAD)"; goto done;
    }
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &outlen, pt, (int)pt_len) != 1) {
            err = "EVP_EncryptUpdate(pt)"; goto done;
        }
    }
    if (EVP_EncryptFinal_ex(ctx, ct + outlen, &finallen) != 1) {
        err = "EVP_EncryptFinal_ex"; goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            BS_GCM_TAG_LEN, tag) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(GET_TAG)"; goto done;
    }
    *out_len = 1 + BS_GCM_NONCE_LEN + pt_len + BS_GCM_TAG_LEN;

done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return err;
}

/* AES-256-GCM decrypt. Expects the full envelope
 *     alg_id(1) || nonce(12) || ciphertext || tag(16)
 * Returns NULL on success (tag verified) with plaintext written
 * into *out_pt (caller-provided, must be at least env_len - 1 - 12
 * - 16 bytes) and the plaintext length in *out_pt_len. Returns an
 * error string on any failure including tag-mismatch. */
static const char *bs_gcm_decrypt(const unsigned char *secret,
                                  apr_size_t secret_len,
                                  const unsigned char *env,
                                  apr_size_t env_len,
                                  unsigned char *out_pt,
                                  apr_size_t *out_pt_len)
{
    if (env_len < (apr_size_t)(1 + BS_GCM_NONCE_LEN + BS_GCM_TAG_LEN)) {
        return "envelope too short";
    }
    if (env[0] != BS_COOKIE_ALG_GCM) return "unknown alg_id";

    apr_size_t ct_len = env_len - 1 - BS_GCM_NONCE_LEN - BS_GCM_TAG_LEN;
    const unsigned char *nonce = env + 1;
    const unsigned char *ct    = env + 1 + BS_GCM_NONCE_LEN;
    const unsigned char *tag   = ct + ct_len;

    unsigned char key[32];
    bs_derive_aes_key(secret, secret_len, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { OPENSSL_cleanse(key, sizeof(key)); return "EVP_CIPHER_CTX_new"; }
    const char *err = NULL;
    int outlen = 0, finallen = 0, aadlen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        err = "EVP_DecryptInit_ex(aes_256_gcm)"; goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            BS_GCM_NONCE_LEN, NULL) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(SET_IVLEN)"; goto done;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        err = "EVP_DecryptInit_ex(key+nonce)"; goto done;
    }
    if (EVP_DecryptUpdate(ctx, NULL, &aadlen, env, 1) != 1) {
        err = "EVP_DecryptUpdate(AAD)"; goto done;
    }
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, out_pt, &outlen, ct, (int)ct_len) != 1) {
            err = "EVP_DecryptUpdate(ct)"; goto done;
        }
    }
    /* Set expected tag BEFORE Final — required by EVP's GCM contract. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            BS_GCM_TAG_LEN, (void *)tag) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(SET_TAG)"; goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, out_pt + outlen, &finallen) != 1) {
        err = "gcm tag verification failed"; goto done;
    }
    *out_pt_len = (apr_size_t)(outlen + finallen);

done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    return err;
}

/* Effective cookie-format bitmap for a given dir_cfg, substituting
 * the legacy default when the operator hasn't written the directive
 * at any inherited scope. */
static int bs_effective_cookie_format(const bs_dir_cfg *cfg)
{
    return (cfg && cfg->cookie_format != BS_FMT_UNSET)
         ? cfg->cookie_format : BS_FMT_HMAC;
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
 *  |score|flags|pass_s|pass_f|pass_c|challenged_at|auto
 *  |forgive_window_start|forgive_consumed"                  (15 fields)
 *
 * Deterministic, ASCII, field-delimited. Both sign and verify produce this
 * exact string from the challenge struct — if a byte changes, the HMAC
 * changes, and tampering is detected. The rep fields follow the challenge
 * fields so existing M2 code reading positions 0..5 still lines up; the
 * M7 `auto` marker is appended at position 12 after challenged_at; the
 * E15 forgiveness-window pair is appended at 13..14. */
static const char *bs_challenge_canonical(apr_pool_t *p,
                                          const bs_challenge *ch)
{
    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    bs_to_hex(ch->salt,  BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch->nonce, BS_NONCE_BYTES, nonce_hex);
    /* v2 canonical = v1 canonical + forgive_window_start +
     * forgive_consumed (E15). 15 pipe-delimited fields
     * total; HMAC cookie body adds 2 more (sig_hex, counter) for 17. */
    return apr_psprintf(p,
        "%d|%s|%s|%s|%d|%" APR_TIME_T_FMT
        "|%d|%u|%d|%d|%d|%" APR_TIME_T_FMT "|%d|%u|%u",
        ch->version, ch->alg_name, salt_hex, nonce_hex,
        ch->difficulty, ch->expires_at,
        ch->rep.score, (unsigned)ch->rep.flags,
        ch->rep.passes_silent, ch->rep.passes_form, ch->rep.passes_captcha,
        ch->rep.challenged_at,
        ch->auto_tier ? 1 : 0,
        (unsigned)ch->rep.forgive_window_start,
        (unsigned)ch->rep.forgive_consumed);
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
    bs_warn_if_virtual_scope(cmd, "BotShieldBloomIPs");
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
    bs_warn_if_virtual_scope(cmd, "BotShieldBloomWindow");
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

/* Classify: walk the trie from each position in the UA and return
 * the longest terminal match (across all start positions). Longest-
 * match semantics matter when operators register overlapping patterns
 * — a more specific "CorpBot/Admin" must shadow a generic "CorpBot"
 * so specific overrides do what operators expect.
 *
 * No prefilter: an earlier revision short-circuited on a hardcoded
 * bot/crawl/spider/fetch/slurp token list, but that silently made
 * operator-defined patterns unreachable for UAs that didn't happen
 * to contain one of those tokens. Correctness beats the ~1 µs we'd
 * save on non-bot traffic, and the trie walk is already O(|ua|)
 * with a small constant (most positions die within 1–2 edges
 * because the trie is sparse). */
static const char *bs_ua_classify(const bs_ua_classifier *c, const char *ua)
{
    if (!c || !ua || !*ua) return NULL;

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

/* --- Bot entry used by the Allow family ---
 *
 * One of these per bot the operator has declared (or a built-in we
 * seed automatically). Lives in scfg->allow_bots keyed by `name`.
 *
 *  path      — explicit ranges-file path, or NULL for the default
 *              (/var/lib/botshield/bots/<name>.txt). Ignored when
 *              `ua_only` is set.
 *  inline_cidrs — comma-separated CIDR list from the directive's
 *              third arg, parsed at post_config; NULL if a path or
 *              UA-only mode is in use instead.
 *  ua_only   — 1 when the directive's third arg was `*`; the bot
 *              is allowed on UA match alone, no IP check. The
 *              decision log distinguishes this with the reason
 *              "allow-bot-ua:<name>" vs "allow-bot:<name>".
 */
typedef struct {
    const char *name;
    const char *pattern;
    const char *path;
    const char *inline_cidrs;
    int         ua_only;
} bs_allow_bot_entry;

static const bs_allow_bot_entry bs_builtin_bots[] = {
    { "googlebot", "Googlebot", NULL, NULL, 0 },
    { "bingbot",   "bingbot",   NULL, NULL, 0 },
    { "applebot",  "Applebot",  NULL, NULL, 0 },
    { NULL, NULL, NULL, NULL, 0 }
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

/* Push one CIDR token into the array. Handles the in-place "/mask"
 * split so apr_ipsubnet_create sees a clean (ip, mask) pair.
 * Returns APR_SUCCESS on push, or APR_EINVAL with *out_err set. The
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

/* Parse a comma-separated CIDR list string into an array. Used by
 * BotShieldAllowBot's inline-CIDR mode. APR has no multi-CIDR
 * helper — apr_strtok splits, bs_allow_push_cidr validates each. */
static apr_status_t bs_allow_load_ranges_from_string(apr_pool_t *p,
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

static apr_status_t bs_allow_load_ranges(apr_pool_t *p,
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

/* Test a client IP (from r->useragent_ip) against a loaded CIDR list. */
static int bs_allow_ip_in_ranges(const apr_array_header_t *ranges,
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
static void bs_check_allow(request_rec *r,
                                   const bs_dir_cfg *cfg)
{
    (void)cfg;
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg || !scfg->allow_enabled) return;
    if (!scfg->bot_classifier) return;

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    const char *name = bs_ua_classify(scfg->bot_classifier, ua);
    if (!name) return;

    /* Look up the bot entry + its (optional) ranges. */
    const bs_allow_bot_entry *entry = scfg->allow_bots
        ? apr_hash_get(scfg->allow_bots, name, APR_HASH_KEY_STRING)
        : NULL;
    /* Fall back to built-in entry if operator didn't declare this
     * name (the classifier's name came from the built-in pattern). */
    if (!entry) {
        for (const bs_allow_bot_entry *b = bs_builtin_bots;
             b->name; b++) {
            if (strcmp(b->name, name) == 0) { entry = b; break; }
        }
    }

    /* UA-only mode: operator explicitly said "trust this UA, no IP
     * verification." Different reason-string than full verify so
     * operators can distinguish in log analysis. */
    if (entry && entry->ua_only) {
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->bot_allow_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, BS_CREDIT_ALLOW, 0,
            apr_pstrcat(r->pool, "allow-bot-ua:", name, NULL));
        return;
    }

    apr_array_header_t *ranges = NULL;
    if (scfg->bot_ranges) {
        ranges = apr_hash_get(scfg->bot_ranges, name, APR_HASH_KEY_STRING);
    }

    if (!ranges) {
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

    if (bs_allow_ip_in_ranges(ranges, r)) {
        /* Verified — large negative penalty dominates tier decision. */
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->bot_allow_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_score_add(r, BS_CREDIT_ALLOW, 0,
            apr_pstrcat(r->pool, "allow-bot:", name, NULL));
    } else {
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

/* ======================================================================
 * E2.1 — Policy enforcement: rate limiting + path-based blocks
 *
 * Two feature families sharing one cohort definition:
 *
 *   BotShieldRateLimit <name> <budget> <per> <ua> <ipspec>
 *   BotShieldBlockPath <name> <path-glob> <ua> <ipspec>
 *
 * A "cohort" is a (ua-substring?, ipspec?) predicate pair. The ipspec
 * reuses E1's polymorphic shape — omitted / explicit path / '*' / inline
 * CIDRs — via bs_allow_push_cidr + bs_allow_load_ranges{,_from_string}.
 * Cohort matching at request time is UA-match AND IP-match, with '*'
 * as "any" on either axis (but not both — that would rate-limit or
 * block every request, which is almost always a mistake and the setter
 * rejects it at config time).
 *
 * Storage:
 *  - Config: scfg->rate_limits / scfg->block_paths hashes, keyed by
 *    name. Merged across main/vhost scope via bs_merge_server_cfg.
 *  - Runtime: rate counters live in SHM as a flat slot array
 *    (bs_shm.rate_counters[]). Each bs_rate_limit_entry's shm_slot
 *    is an index assigned in post_config. Fixed-window counter model
 *    with atomic CAS updates — approximate rather than exact sliding
 *    window, but that's the right trade for a rate limiter (smaller
 *    code, no per-bucket mutex, burst-at-boundary is harmless here
 *    because the downstream score_add hook still records it).
 *
 * On trip:
 *  - Block-path hit → 403 + bs_score_add(+100, "block-path:<name>").
 *  - Rate-limit exceeded → 429 + Retry-After: <seconds remaining in
 *    window> + bs_score_add(+50, "rate-limit-exceeded:<name>").
 * ====================================================================== */

#define BS_PENALTY_RATE_LIMIT  50   /* sustained violator → captcha tier */
#define BS_PENALTY_BLOCK_PATH 100   /* hit a forbidden path → flagged */

/* Shared (UA?, IP?) cohort predicate. Set either or both; the cohort
 * resolver rejects cohorts where both are '*' (would match everyone). */
typedef struct {
    const char         *ua_pattern;    /* substring match; NULL if ua_any */
    int                 ua_any;        /* 1 when operator wrote '*' */
    int                 ip_any;        /* 1 when operator wrote '*' */
    const char         *path;          /* ipspec file path, or NULL */
    const char         *inline_cidrs;  /* ipspec inline CIDRs, or NULL */
    apr_array_header_t *ranges;        /* resolved at post_config */
} bs_cohort;

/* Forward decl: rate_limit_entry references its escalation config
 * by pointer. Linked at post_config. */
typedef struct bs_rate_escalate_entry bs_rate_escalate_entry;

typedef struct {
    const char   *name;
    bs_cohort     cohort;
    apr_uint32_t  budget;
    apr_uint32_t  window_sec;
    int           shm_slot;          /* index into bs_shm.rate_counters; -1 unset */
    /* E9 — back-link to the escalation config for this rule, if
     * any. Resolved at post_config from scfg->rate_escalates by
     * matching name. NULL = no escalation; the rule behaves like
     * pre-E9. */
    const bs_rate_escalate_entry *escalate;
    /* E12 — observe-mode opt-in. Same enum as bs_trigger_action.mode.
     * When set to BS_TMODE_OBSERVE (or when the global shadow_mode
     * flag is on), over-budget hits log `would-rate-limit:<name>`
     * but don't return 429 / consume a token / bump strikes. */
    int           mode;              /* bs_trigger_mode */
} bs_rate_limit_entry;

/* E9 — BotShieldRateLimitEscalate config. Stored in
 * scfg->rate_escalates; linked into bs_rate_limit_entry::escalate
 * at post_config so the request-time path can branch in O(1). */
struct bs_rate_escalate_entry {
    const char   *rule_name;     /* must name a BotShieldRateLimit */
    apr_uint32_t  strikes;       /* threshold within the per window */
    apr_uint32_t  per_sec;       /* strike-counter window */
    int           status_code;   /* HTTP code on escalation; default 403 */
    int           ttl_sec;       /* escalation lifetime; default 1800 */
    const char   *log_tag;       /* fail2ban-friendly tag, NULL if unset */
};

typedef struct {
    const char *name;
    const char *path_pattern;        /* prefix / trailing '*' / trailing '$' */
    bs_cohort   cohort;
    /* E12 — observe-mode opt-in. When set (or when the global
     * shadow_mode flag is on), matched paths log
     * `would-block-path:<name>` but don't return 403 / write the
     * BS_PENALTY_BLOCK_PATH score. */
    int         mode;                /* bs_trigger_mode */
} bs_block_path_entry;

/* E3 — path-based triggers. One of these per BotShieldPathTrigger
 * directive. `status_code` holds either a concrete HTTP status
 * (e.g. 403, 429) or the BS_TRIGGER_STATUS_PASS sentinel meaning
 * "don't enforce anything on this request; let the real handler
 * respond." The sentinel uses a negative int so it can never
 * collide with a valid HTTP status code.
 *
 * `redirect_url` + `status_code` interact: when redirect is set,
 * status_code is a 3xx code (default 302 chosen at parse time);
 * bs_check_policy emits the Location header and returns
 * status_code from the handler.
 *
 * `flag_bit` is the M5.1 flag-IP bit to set for future requests
 * (default scanner_probe at parse time). `ttl_sec == 0` disables
 * IP flagging. `penalty` is only applied when status is a concrete
 * error code — under PASS it's bookkeeping-only and we skip the
 * score_add (see PLAN.md E3 semantics). */
#define BS_TRIGGER_STATUS_PASS   (-1)

/* E7.2 — shared action engine for path/cookie/env trigger families.
 *
 * Every trigger family parses a family-unique predicate (path-glob,
 * cookie-match, env-match) and shares the same action vocabulary
 * after the predicate: status / redirect / log / flag / ttl /
 * penalty / credit. `bs_trigger_action` holds the parsed action
 * surface; `bs_trigger_family` selects the semantic profile the
 * executor applies.
 *
 * Deliberate family differences that the profile encodes (not
 * erased by the shared engine):
 *   - allowed key subset
 *       path rejects credit=     (discrete events, not reputation)
 *       env  rejects redirect=   (scoring/flagging only)
 *   - status=pass scoring
 *       path skips score_add     (pass means "don't enforce here")
 *       cookie/env apply penalty-credit (signal is this request's
 *                                  state, so it belongs on this
 *                                  request's score)
 *   - pass-match iteration
 *       path decays to DECLINED  (hand off to real handler)
 *       cookie continues loop    (pass-credits accumulate)
 *       env breaks loop          (discrete env signals, no stacking)
 *   - family defaults
 *       path  status=403, flag=scanner_probe, ttl=3600
 *       cookie status=PASS, no flag
 *       env    status=PASS, no flag
 */
typedef enum {
    BS_TFAMILY_PATH = 0,
    BS_TFAMILY_COOKIE,
    BS_TFAMILY_ENV,
    /* Response-path family: E5 feedback. Signed `event=<name>`
     * header arrives on the response, module looks up the event in
     * scfg->feedback_triggers, and applies the configured action.
     * Only the future-request subset (flag/ttl/log) is supported —
     * the request is already served, so status/redirect/penalty/
     * credit would have nowhere to land. The shared parser rejects
     * those keys for this family. */
    BS_TFAMILY_FEEDBACK,
    /* E11.2 — host-state family. Predicate is a comparison against
     * the global cached load_state (BS_LOAD_NORMAL/WARM/HOT) — no
     * per-request match. Action surface is penalty/credit/status/
     * log; flag= is rejected because load is global state, not a
     * property worth memorizing per-IP. */
    BS_TFAMILY_LOAD,
} bs_trigger_family;

typedef struct {
    int           status_code;    /* HTTP code or BS_TRIGGER_STATUS_PASS */
    const char   *redirect_url;   /* NULL unless explicitly set */
    const char   *log_tag;
    apr_uint32_t  flag_bit;       /* single M5.1 bit; 0 if ttl_sec==0 */
    int           ttl_sec;        /* 0 = don't flag the IP */
    int           penalty;        /* 0..1000 */
    int           credit;         /* 0..1000 (rejected on path family) */
    int           status_explicit; /* 1 if operator wrote status= */
    /* E12 — shadow mode. BS_TMODE_ENFORCE (default) is normal
     * behavior. BS_TMODE_OBSERVE makes a matched rule LOG what it
     * would have done — :observe suffix on the reason string,
     * mode-specific metric counter — but applies no side effects:
     * no flag-IP, no score, no status/redirect, no log tag side-
     * effect. Operators stage new rules safely and watch the
     * decision log before turning enforce on. */
    int           mode;           /* bs_trigger_mode */
} bs_trigger_action;

typedef enum {
    BS_TMODE_ENFORCE = 0,
    BS_TMODE_OBSERVE,
} bs_trigger_mode;

typedef enum {
    BS_TEXEC_PASS_CONTINUE = 0,  /* pass-match; stay in family loop */
    BS_TEXEC_PASS_BREAK,         /* pass-match; exit this family's loop */
    BS_TEXEC_PASS_DECLINE,       /* pass-match; return DECLINED from policy */
    BS_TEXEC_STATUS,             /* emit status/redirect; short-circuit */
    /* E12 — observe-only match: rule fired but took no enforcing
     * action. Caller treats this as `continue` so subsequent rules
     * in the same family still get a chance. */
    BS_TEXEC_OBSERVE,
} bs_trigger_exec_outcome;

/* Forward declarations — bs_check_policy (E3 path) calls these; they
 * live alongside their primary users further down the file. */
static void bs_set_trigger_tag(request_rec *r, const char *tag);
static void bs_flagged_ip_add(request_rec *r,
                              const unsigned char ip[16],
                              apr_uint32_t flag_bits, int ttl_seconds,
                              apr_uint32_t ns_id);
static int  bs_parse_client_ip(const char *ip_str, unsigned char out[16]);
static void bs_mask_ipv6_prefix(unsigned char ip[16], int prefix_bits);
/* E9 — strike-table helpers used inside the rate-limit walk.
 * E13 — extra ns_id parameter for per-vhost reputation. */
static int  bs_strike_check_escalated(const unsigned char ip[16],
                                      apr_uint32_t rule_slot,
                                      apr_int64_t now,
                                      apr_uint32_t ns_id);
static int  bs_strike_record_429(request_rec *r,
                                 const unsigned char ip[16],
                                 apr_uint32_t rule_slot,
                                 const bs_rate_escalate_entry *cfg,
                                 apr_int64_t now,
                                 apr_uint32_t ns_id);

/* E11 — load-state read used by bs_check_policy's load-trigger
 * walk. Declaration here so the walk at line ~3540 compiles
 * before the body at line ~4150. */
static bs_load_state bs_load_current(void);

/* E10 — safeguard helpers. Called from bs_handler at two points:
 * just before issuing a challenge (check + record presentation)
 * and on successful cookie verify (clear the per-IP counter). */
static int  bs_safeguard_check(const unsigned char ip[16],
                               apr_int64_t now,
                               apr_uint32_t ns_id);
static void bs_safeguard_record_presentation(request_rec *r,
                                             bs_server_cfg *scfg,
                                             const unsigned char ip[16],
                                             apr_int64_t now,
                                             apr_uint32_t ns_id);
static void bs_safeguard_clear(const unsigned char ip[16],
                               apr_uint32_t ns_id);
static int  bs_safeguard_effective_int(int v, int dflt);
/* Shared action helpers — see definitions below. The server-cfg
 * struct body appears later in the file, so we forward-declare by
 * struct tag and use `struct bs_server_cfg *` in the signature. */
struct bs_server_cfg;
static void bs_trigger_action_init(bs_trigger_family fam,
                                   bs_trigger_action *a);
static const char *bs_parse_trigger_action_key(apr_pool_t *pool,
                                               bs_trigger_family fam,
                                               const char *arg,
                                               bs_trigger_action *a);
static const char *bs_finalize_trigger_action(apr_pool_t *pool,
                                              bs_trigger_family fam,
                                              bs_trigger_action *a);
static bs_trigger_exec_outcome bs_apply_trigger_action(
    request_rec *r,
    struct bs_server_cfg *scfg,
    bs_trigger_family fam,
    const bs_trigger_action *a,
    const char *family_tag,
    const char *trigger_name);

typedef struct {
    const char        *name;
    const char        *path_pattern;
    bs_trigger_action  action;       /* shared; see bs_trigger_action */
} bs_path_trigger_entry;

/* E4 — cookie triggers. Parallel feature to E3 path triggers, but
 * matched on the Cookie header rather than the request URI. Shares
 * the action surface with E3 (status / redirect / log / flag / ttl /
 * penalty) and adds `credit` for negative-score contributions —
 * the mechanism for "legitimate session → glide through tier
 * dispatch." Two deliberate semantic divergences from E3:
 *
 *  1. credit/penalty are applied to THIS request regardless of
 *     status (contrast E3 where status=pass ignores penalty).
 *     Cookies are persistent-state signals: the client carries
 *     them on THIS request and we want to shape its score.
 *  2. Cookie triggers evaluate BEFORE path triggers in
 *     bs_check_policy so the decision log shows reputation signals
 *     even when a later short-circuit fires.
 *
 * Predicate kinds — one per entry, populated by the setter:
 *   NAMED_PRESENT     cookie is present (any value)
 *   NAMED_ABSENT      cookie is absent
 *   NAMED_EQ          cookie has exactly this value
 *   NAMED_NE          cookie is present but value is NOT this
 *   NAMED_CONTAINS    cookie value contains this substring
 *   BULK_NONE         request has zero cookies
 *   BULK_ANY          request has at least one cookie
 *   BULK_SESSION      request has a cookie from the session-name list
 *   BS_VERIFIED       _bs_verified present and valid
 *   BS_MISSING        no _bs_verified at all
 *   BS_INVALID        _bs_verified present but HMAC/format failed */
enum bs_cookie_pred_kind {
    BS_CP_NAMED_PRESENT = 0,
    BS_CP_NAMED_ABSENT,
    BS_CP_NAMED_EQ,
    BS_CP_NAMED_NE,
    BS_CP_NAMED_CONTAINS,
    BS_CP_BULK_NONE,
    BS_CP_BULK_ANY,
    BS_CP_BULK_SESSION,
    BS_CP_BS_VERIFIED,
    BS_CP_BS_MISSING,
    BS_CP_BS_INVALID,
};

typedef struct {
    const char        *name;
    int                pred_kind;     /* enum bs_cookie_pred_kind */
    const char        *cname;         /* NULL unless kind is NAMED_* */
    const char        *cvalue;        /* NULL unless kind is NAMED_{EQ,NE,CONTAINS} */
    bs_trigger_action  action;        /* shared; see bs_trigger_action */
} bs_cookie_trigger_entry;

/* E6 — env-var triggers. Read a per-request env var from
 * r->subprocess_env and apply action accordingly. Producers
 * include Apache's `SetEnvIf` family, `BrowserMatch`,
 * `RewriteRule [E=...]`, and ModSecurity v2 `setenv`. All write
 * to the same apr_table_t at phases before the handler runs, so
 * bs_check_policy observes whatever the upstream chain wrote.
 *
 * Deliberately narrower than E3/E4: no substring/contains match,
 * no redirect action, strict first-match-wins precedence. Rich
 * matching belongs in the upstream module, which then sets a
 * coarse bucket variable E6 consumes.
 *
 * Predicate kinds:
 *   NAMED_PRESENT  env var is defined on the request (any value,
 *                  including empty string — Apache assigns an
 *                  empty string to `SetEnvIf X Y` with no value).
 *   NAMED_ABSENT   env var is not defined on the request.
 *   NAMED_EQ       env var has exactly the operator-specified
 *                  value (byte-for-byte, case-sensitive strcmp).
 *
 * Name-lookup semantics follow APR tables: `apr_table_get` matches
 * names case-insensitively. `env=BS_LEVEL` and `env=bs_level` hit
 * the same stored key. Operators running a mix of case forms should
 * assume they collide; picking one canonical case per project
 * (convention: uppercase) avoids accidental shadowing under
 * first-match-wins. Values stay case-sensitive because table
 * storage preserves the producer's bytes as-is. */
enum bs_env_pred_kind {
    BS_EP_NAMED_PRESENT = 0,
    BS_EP_NAMED_ABSENT,
    BS_EP_NAMED_EQ,
};

typedef struct {
    const char        *name;
    int                pred_kind;     /* enum bs_env_pred_kind */
    const char        *env_name;
    const char        *env_value;     /* NULL unless NAMED_EQ */
    bs_trigger_action  action;        /* shared; see bs_trigger_action */
} bs_env_trigger_entry;

/* E7.3 — BotShieldFeedbackTrigger <event> [key=value ...]. The
 * `event` is the app-visible name carried in the signed X-BotShield-
 * Feedback header body (`event=<name>`). The action bound to that
 * name — flag bit + TTL + optional log tag — lives in scfg; the app
 * can't set module internals through the wire anymore. One entry
 * per declaration; upsert-by-event-name. */
typedef struct {
    const char        *event;
    bs_trigger_action  action;
} bs_feedback_trigger_entry;

/* E11.2 — BotShieldLoadTrigger <name> <load-match> [key=value ...].
 * Predicate is a comparison against the global cached load_state.
 * Two predicate kinds:
 *   EQ:  state=normal | state=warm | state=hot     (exact match)
 *   GE:  state>=warm  | state>=hot                 (>= comparison)
 *
 * EQ + state=normal is mostly useful for documentation/tests;
 * operators in production usually want state>=warm to cover both
 * warm AND hot.
 *
 * Action surface inherits from bs_trigger_action; load-specific
 * limits are enforced by the shared parser (no flag/ttl/redirect). */
enum bs_load_pred_kind {
    BS_LP_EQ = 0,
    BS_LP_GE,
};

typedef struct {
    const char        *name;
    int                pred_kind;     /* enum bs_load_pred_kind */
    bs_load_state      target_state;
    bs_trigger_action  action;
} bs_load_trigger_entry;

/* SHM slot for the fixed-window counter. Packed to 8 bytes so
 * platforms with 64-bit atomics could later swap to a CAS-on-u64;
 * for v1 we use 32-bit atomics on each field separately, which is
 * adequate for the semantics we want (approximate fixed window). */
typedef struct {
    apr_uint32_t count;
    apr_uint32_t window_start_sec;
} bs_rate_counter;

/* Inspect a directive's (ua, ipspec) arg pair and populate a
 * bs_cohort. Returns NULL on success, or an Apache directive-error
 * string. Ranges resolution is deferred to post_config so we can
 * use pconf rather than cmd->temp_pool. */
static const char *bs_cohort_resolve(cmd_parms *cmd, bs_cohort *out,
                                     const char *ua, const char *ipspec)
{
    memset(out, 0, sizeof(*out));
    if (!ua || !*ua || strcmp(ua, "*") == 0) {
        out->ua_any = 1;
    } else {
        out->ua_pattern = apr_pstrdup(cmd->pool, ua);
    }
    if (!ipspec || !*ipspec || strcmp(ipspec, "*") == 0) {
        out->ip_any = 1;
    } else if (ipspec[0] == '/') {
        out->path = apr_pstrdup(cmd->pool, ipspec);
    } else if (strchr(ipspec, '/') || strchr(ipspec, ':')) {
        out->inline_cidrs = apr_pstrdup(cmd->pool, ipspec);
    } else {
        return apr_psprintf(cmd->pool,
            "ipspec '%s' unrecognized — use '*' (any IP), an absolute "
            "file path, or a CIDR (single or comma-separated)", ipspec);
    }
    /* Guard against cohorts that would match every request. Operators
     * who really want that can write it as two entries or a per-
     * location cap elsewhere. */
    if (out->ua_any && out->ip_any) {
        return "cohort must restrict on UA or IP (both were '*')";
    }
    return NULL;
}

/* Minimal v1 path-glob matcher:
 *   pattern ending in '$' → exact match against path (pattern minus $).
 *   pattern ending in '*' → prefix match (pattern minus *).
 *   otherwise              → prefix match against the whole pattern.
 * Full RFC 9309 semantics (middle wildcards, longest-match rules,
 * Allow-overrides-Disallow) arrive with robots.c in E2.2 — v1 covers
 * the shapes operators actually write by hand. */
static int bs_path_glob_match(const char *pattern, const char *path)
{
    if (!pattern || !*pattern || !path) return 0;
    apr_size_t plen = strlen(pattern);
    apr_size_t ulen = strlen(path);

    if (pattern[plen - 1] == '$') {
        if (ulen != plen - 1) return 0;
        return memcmp(pattern, path, plen - 1) == 0;
    }
    if (pattern[plen - 1] == '*') {
        if (ulen < plen - 1) return 0;
        return memcmp(pattern, path, plen - 1) == 0;
    }
    if (ulen < plen) return 0;
    return memcmp(pattern, path, plen) == 0;
}

/* Cohort match at request time. Returns 1 when this request belongs
 * to the cohort. UA match is case-insensitive via strcasestr to
 * match the directive's documented contract. strcasestr is a GNU
 * extension, already relied on elsewhere in the module on the
 * platforms we target (Linux/FreeBSD/macOS). */
static int bs_cohort_matches(const bs_cohort *c,
                             const char *ua, request_rec *r)
{
    if (!c->ua_any) {
        if (!ua || !c->ua_pattern || !strcasestr(ua, c->ua_pattern)) return 0;
    }
    if (!c->ip_any) {
        if (!c->ranges || !bs_allow_ip_in_ranges(c->ranges, r)) return 0;
    }
    return 1;
}

/* Fixed-window admission test. Returns 1 if the request fits under
 * budget (count was incremented), 0 if the window is full.
 *
 * Under pathological contention the CAS loop bounces; cap the retry
 * count and err on admitting rather than emitting spurious 429s. */
static int bs_rate_counter_admit(bs_rate_counter *slot,
                                 apr_uint32_t budget,
                                 apr_uint32_t window_sec)
{
    apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
    for (int i = 0; i < 32; i++) {
        apr_uint32_t cnt = __atomic_load_n(&slot->count, __ATOMIC_RELAXED);
        apr_uint32_t win = __atomic_load_n(&slot->window_start_sec,
                                           __ATOMIC_RELAXED);
        if (now < win || now - win >= window_sec) {
            apr_uint32_t expected = win;
            if (__atomic_compare_exchange_n(&slot->window_start_sec,
                    &expected, now, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                __atomic_store_n(&slot->count, 1, __ATOMIC_RELAXED);
                return 1;
            }
            continue;  /* someone else rolled the window; re-read */
        }
        if (cnt >= budget) return 0;
        apr_uint32_t expected = cnt;
        if (__atomic_compare_exchange_n(&slot->count, &expected, cnt + 1,
                0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            return 1;
        }
        /* CAS lost — retry with fresh count */
    }
    return 1;
}

/* Is this UA a plausible crawler for the purpose of applying
 * robots.txt User-agent: * rules in heuristic mode? See PLAN.md for
 * the rationale — the point is to avoid rate-limiting or blocking
 * real users' browsers, which never read robots.txt and so should
 * never be subject to its rules. */
static int bs_ua_is_crawler_candidate(const char *ua)
{
    if (!ua || !*ua) return 0;

    int has_bot_token =
           strcasestr(ua, "bot")    != NULL
        || strcasestr(ua, "crawl")  != NULL
        || strcasestr(ua, "spider") != NULL
        || strcasestr(ua, "fetch")  != NULL
        || strcasestr(ua, "slurp")  != NULL;
    if (has_bot_token) return 1;

    /* Bot-less UA that starts with a real-browser prefix: skip.
     * Everything else (curl/python/etc.) defaults to candidate —
     * those tools are used by scrapers and rarely by humans. */
    static const char *const browser_prefixes[] = {
        "Mozilla/", "Opera/", "Firefox/", "Edge/", "Safari/", NULL
    };
    for (int i = 0; browser_prefixes[i]; i++) {
        apr_size_t plen = strlen(browser_prefixes[i]);
        if (strncasecmp(ua, browser_prefixes[i], plen) == 0) return 0;
    }
    return 1;
}

/* E4 — BotShield-cookie-state note: set by bs_handler after the
 * `_bs_verified` verification pass so bs_check_policy's cookie-
 * trigger evaluator can surface the verdict via bs-cookie=<state>
 * predicates without re-running the HMAC check. Values: "verified"
 * (cookie valid), "missing" (no cookie at all), "invalid" (present
 * but HMAC/format/expiry check rejected). */
#define BS_CK_STATE_NOTE   "botshield-cookie-state"
#define BS_CK_STATE_VERIFIED  "verified"
#define BS_CK_STATE_MISSING   "missing"
#define BS_CK_STATE_INVALID   "invalid"

/* Parse-once tokenizer for the Cookie request header. Returns a
 * pool-allocated apr_table_t (name → value, case-insensitive on the
 * name per RFC 6265 in practice). Empty values are stored as ""
 * (matching `cookie=<name>` / `cookie=<name>=`). Duplicate names
 * take the first occurrence; subsequent ones are ignored. Cached on
 * r->notes as a hex-encoded pointer so the same map survives across
 * multiple cookie-trigger evaluations within the same request. */
#define BS_COOKIEMAP_NOTE  "botshield-parsed-cookies"
static apr_table_t *bs_parse_cookies_once(request_rec *r)
{
    const char *cached_hex = apr_table_get(r->notes, BS_COOKIEMAP_NOTE);
    if (cached_hex && *cached_hex) {
        apr_table_t *prev;
        if (sscanf(cached_hex, "%p", (void **)&prev) == 1 && prev) {
            return prev;
        }
    }

    apr_table_t *map = apr_table_make(r->pool, 8);
    const char *raw = apr_table_get(r->headers_in, "Cookie");
    if (raw && *raw) {
        char *buf = apr_pstrdup(r->pool, raw);
        char *state = NULL;
        for (char *tok = apr_strtok(buf, ";", &state); tok;
             tok = apr_strtok(NULL, ";", &state)) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (!*tok) continue;
            char *eq = strchr(tok, '=');
            const char *name;
            const char *value;
            if (eq) {
                *eq = '\0';
                name  = tok;
                value = eq + 1;
            } else {
                name  = tok;
                value = "";
            }
            /* Trim trailing whitespace from name (values are taken
             * as-is; cookie values are allowed to include leading
             * whitespace per RFC 6265 in practice, but we strip a
             * common one anyway). */
            apr_size_t nlen = strlen(name);
            while (nlen && (name[nlen-1] == ' ' || name[nlen-1] == '\t')) {
                ((char *)name)[--nlen] = '\0';
            }
            if (nlen == 0) continue;
            if (apr_table_get(map, name) != NULL) continue;  /* first wins */
            apr_table_setn(map, name, value);
        }
    }
    apr_table_setn(r->notes, BS_COOKIEMAP_NOTE,
                   apr_psprintf(r->pool, "%p", (void *)map));
    return map;
}

/* Is this cookie-name on the session-name list? */
static int bs_is_session_cookie_name(const apr_array_header_t *names,
                                     const char *name)
{
    if (!names) return 0;
    for (int i = 0; i < names->nelts; i++) {
        if (strcasecmp(APR_ARRAY_IDX(names, i, const char *), name) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Evaluate a single cookie-trigger predicate against the parsed
 * cookie map + BS-cookie state. Returns 1 on match, 0 on no match. */
static int bs_cookie_pred_match(const bs_cookie_trigger_entry *e,
                                apr_table_t *cmap,
                                const apr_array_header_t *session_names,
                                const char *bs_state)
{
    switch (e->pred_kind) {
    case BS_CP_NAMED_PRESENT:
        return apr_table_get(cmap, e->cname) != NULL;
    case BS_CP_NAMED_ABSENT:
        return apr_table_get(cmap, e->cname) == NULL;
    case BS_CP_NAMED_EQ: {
        const char *v = apr_table_get(cmap, e->cname);
        return v && strcmp(v, e->cvalue) == 0;
    }
    case BS_CP_NAMED_NE: {
        const char *v = apr_table_get(cmap, e->cname);
        return v && strcmp(v, e->cvalue) != 0;
    }
    case BS_CP_NAMED_CONTAINS: {
        const char *v = apr_table_get(cmap, e->cname);
        return v && strstr(v, e->cvalue) != NULL;
    }
    case BS_CP_BULK_NONE:
        return apr_is_empty_table(cmap);
    case BS_CP_BULK_ANY:
        return !apr_is_empty_table(cmap);
    case BS_CP_BULK_SESSION: {
        const apr_array_header_t *arr = apr_table_elts(cmap);
        for (int i = 0; i < arr->nelts; i++) {
            apr_table_entry_t *te = &((apr_table_entry_t *)arr->elts)[i];
            if (bs_is_session_cookie_name(session_names, te->key)) {
                return 1;
            }
        }
        return 0;
    }
    case BS_CP_BS_VERIFIED:
        return bs_state && strcmp(bs_state, BS_CK_STATE_VERIFIED) == 0;
    case BS_CP_BS_MISSING:
        return !bs_state
            || strcmp(bs_state, BS_CK_STATE_MISSING) == 0;
    case BS_CP_BS_INVALID:
        return bs_state && strcmp(bs_state, BS_CK_STATE_INVALID) == 0;
    }
    return 0;
}

/* Request-time E2.1 + E2.2 + E3 + E4 + E6 check. Return values:
 *   OK                     — no rule fired; continue to heuristics.
 *   DECLINED               — a trigger with status=pass fired; the
 *                            bs_handler short-circuits to DECLINED
 *                            so the real handler runs, with the
 *                            flag-IP / log side effects already
 *                            applied.
 *   any other HTTP_* code  — short-circuit with that status. The
 *                            handler returns it directly so Apache's
 *                            ErrorDocument machinery can render the
 *                            response body.
 *
 * Order:
 *   1. E4 cookie triggers (declaration order; pass accumulates,
 *      first non-pass short-circuits).
 *   2. E6 env-var triggers (declaration order, first match wins).
 *   3. E3 path triggers (declaration order, first match wins).
 *   4. Directive block_paths (declaration order, first match wins).
 *   5. robots.txt Disallow (if configured).
 *   6. Directive rate_limits.
 *   7. robots.txt Crawl-delay (if configured).
 *
 * Cookie triggers run first so reputation signals always land on
 * the decision log, even when a later rule short-circuits. Env
 * triggers run next — another reputation/policy shape driven by
 * upstream Apache modules (SetEnvIf / ModSecurity / etc.). Path
 * triggers are the most specific per-path intent the operator
 * can write — a trigger on `/.env` should win against any
 * cohort-scoped block-path that also happens to match. Operator
 * directives always get first say in each family after that;
 * robots.txt fills in where the operator hasn't declared
 * explicit rules.
 *
 * Precedence divergences from E3 (strict first-match-wins, no
 * accumulation) worth keeping straight:
 *  - E4 cookies: credit/penalty always apply (even under
 *    status=pass); pass matches accumulate across triggers;
 *    first non-pass trigger short-circuits the walk.
 *  - E6 env: credit/penalty always apply (E4-style), but the
 *    family uses strict first-match-wins — a pass match ends
 *    the env-trigger loop without considering later entries. */
static int bs_check_policy(request_rec *r)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg) return OK;

    /* E4 — cookie triggers. Declaration order; **pass triggers
     * accumulate, first non-pass trigger short-circuits the walk**.
     * That split exists to make the canonical layered-reputation
     * pattern work — `app-session credit=15` + `app-auth
     * credit=40` should stack to a 55-point credit when both
     * cookies are present, not lose the second credit to first-
     * match-wins. Contrast E3 path triggers, which are strict
     * first-match-wins with no accumulation: paths are one-off
     * matches, cookies are ongoing-state signals that naturally
     * compose.
     *
     * Runs before E3 path triggers so reputation signals land on
     * the decision log even when a later rule short-circuits.
     *
     * Divergences from E3 to keep straight while reading this loop:
     *  1. credit/penalty apply regardless of status (even under
     *     status=pass, because the cookie IS this request's state).
     *  2. pass matches don't end the walk — they accumulate. */
    if (scfg->cookie_triggers && scfg->cookie_triggers->nelts > 0) {
        apr_table_t *cmap = bs_parse_cookies_once(r);
        const char *bs_state = apr_table_get(r->notes, BS_CK_STATE_NOTE);
        for (int i = 0; i < scfg->cookie_triggers->nelts; i++) {
            bs_cookie_trigger_entry *c = APR_ARRAY_IDX(
                scfg->cookie_triggers, i, bs_cookie_trigger_entry *);
            if (!bs_cookie_pred_match(c, cmap, scfg->session_names,
                                      bs_state)) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_COOKIE, &c->action,
                "cookie-trigger", c->name);
            /* Cookie family: BS_TEXEC_PASS_CONTINUE keeps accumulating
             * credits; BS_TEXEC_STATUS short-circuits. PASS_BREAK /
             * PASS_DECLINE aren't produced for this family. */
            if (o == BS_TEXEC_STATUS) return c->action.status_code;
        }
    }

    /* E6 — env-var triggers. Declaration order, first match wins.
     * Gate: once per client-visible request. `ap_is_initial_req` is
     * (r->main == NULL && r->prev == NULL) per httpd's protocol.c,
     * which both excludes subrequests (where producer env
     * propagation differs) and blocks re-application on internal-
     * redirect legs (ErrorDocument, RewriteRule-without-R) where
     * the env producer would fire a second time and double-count
     * score/flag. The header docs only advertise the main-vs-
     * subrequest distinction, so we restate the full intent here.
     * Reads r->subprocess_env, the table SetEnvIf / RewriteRule
     * [E=...] / BrowserMatch / ModSecurity v2 setenv all populate
     * at phases that run before the handler. */
    if (ap_is_initial_req(r)
        && scfg->env_triggers && scfg->env_triggers->nelts > 0) {
        for (int i = 0; i < scfg->env_triggers->nelts; i++) {
            bs_env_trigger_entry *t = APR_ARRAY_IDX(
                scfg->env_triggers, i, bs_env_trigger_entry *);
            const char *v = apr_table_get(r->subprocess_env,
                                          t->env_name);
            int matched = 0;
            switch (t->pred_kind) {
            case BS_EP_NAMED_PRESENT:
                matched = (v != NULL);
                break;
            case BS_EP_NAMED_ABSENT:
                matched = (v == NULL);
                break;
            case BS_EP_NAMED_EQ:
                matched = (v != NULL
                        && t->env_value != NULL
                        && strcmp(v, t->env_value) == 0);
                break;
            }
            if (!matched) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_ENV, &t->action,
                "env-trigger", t->name);
            /* Env family: BS_TEXEC_PASS_BREAK ends the loop (env
             * signals are discrete; no accumulation). STATUS
             * short-circuits. */
            if (o == BS_TEXEC_STATUS) return t->action.status_code;
            if (o == BS_TEXEC_PASS_BREAK) break;
        }
    }

    /* E11.2 — load triggers. Match on the global cached load state
     * (BS_LOAD_NORMAL/WARM/HOT). First-match-wins; alternative-
     * specificity rules (state>=warm vs state=hot) are stacked by
     * declaration order with the more specific one declared first. */
    if (scfg->load_triggers && scfg->load_triggers->nelts > 0) {
        bs_load_state cur = bs_load_current();
        for (int i = 0; i < scfg->load_triggers->nelts; i++) {
            bs_load_trigger_entry *t = APR_ARRAY_IDX(
                scfg->load_triggers, i, bs_load_trigger_entry *);
            int matched = 0;
            switch (t->pred_kind) {
            case BS_LP_EQ: matched = (cur == t->target_state); break;
            case BS_LP_GE: matched = (cur >= t->target_state); break;
            }
            if (!matched) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_LOAD, &t->action,
                "load-trigger", t->name);
            if (o == BS_TEXEC_STATUS) return t->action.status_code;
            if (o == BS_TEXEC_PASS_BREAK) break;
        }
    }

    /* E3 — path triggers. First match wins; no accumulation. */
    if (scfg->path_triggers && scfg->path_triggers->nelts > 0) {
        for (int i = 0; i < scfg->path_triggers->nelts; i++) {
            bs_path_trigger_entry *t = APR_ARRAY_IDX(
                scfg->path_triggers, i, bs_path_trigger_entry *);
            if (!bs_path_glob_match(t->path_pattern, r->uri)) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_PATH, &t->action,
                "path-trigger", t->name);
            /* Path family: PASS decays to DECLINED (handler lets
             * the real Apache response through); STATUS emits
             * Location/code short-circuit. CONTINUE/BREAK aren't
             * produced for this family. */
            if (o == BS_TEXEC_PASS_DECLINE) return DECLINED;
            if (o == BS_TEXEC_STATUS)       return t->action.status_code;
        }
    }

    const char *ua = apr_table_get(r->headers_in, "User-Agent");

    /* Block paths first: if the request would be 403ed anyway there's
     * no point charging it a token from a rate bucket it's also in.
     * Ordered-array iteration — first match wins; declaration order
     * is the precedence. E12: a matched rule in observe mode (or
     * any matched rule when global shadow_mode is on) logs
     * `would-block-path:<name>` instead of returning 403, and the
     * walk continues so subsequent rules still get their say. */
    int global_shadow = (scfg->shadow_mode == 1);
    if (scfg->block_paths && scfg->block_paths->nelts > 0) {
        for (int i = 0; i < scfg->block_paths->nelts; i++) {
            bs_block_path_entry *e = APR_ARRAY_IDX(
                scfg->block_paths, i, bs_block_path_entry *);
            if (!bs_path_glob_match(e->path_pattern, r->uri)) continue;
            if (!bs_cohort_matches(&e->cohort, ua, r)) continue;
            int observe = global_shadow || (e->mode == BS_TMODE_OBSERVE);
            if (observe) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "block-path:", e->name,
                                ":observe", NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->block_path_observed_total,
                        1, __ATOMIC_RELAXED);
                }
                continue;
            }
            bs_score_add(r, BS_PENALTY_BLOCK_PATH, 3600,
                apr_pstrcat(r->pool, "block-path:", e->name, NULL));
            if (bs_shm.metrics) {
                __atomic_fetch_add(&bs_shm.metrics->block_path_hit_total,
                                   1, __ATOMIC_RELAXED);
            }
            return HTTP_FORBIDDEN;
        }
    }

    /* E2.2 — robots.txt Disallow enforcement. Queried once for
     * (ua, path); the result also carries the Crawl-delay we'll use
     * below, so stash it.
     *
     * Atomic load of scfg->robots so we never see a half-swapped
     * state bundle. The bundle's fields are immutable after publish,
     * and the previous bundle is held one refresh cycle before its
     * pool is reclaimed — see bs_robots_refresh. */
    bs_robots_state *rstate =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    robots_match rmatch = { -1, 0, 1, 0, NULL };
    int robots_apply = 0;
    if (rstate && rstate->doc && ua) {
        robots_query(rstate->doc, ua, r->uri, &rmatch);
        if (rmatch.group_idx >= 0) {
            robots_apply = 1;
            if (rmatch.is_wildcard) {
                switch (scfg->robots_wildcard_scope) {
                case BS_ROBOTS_WILDCARD_OFF:
                    robots_apply = 0;
                    break;
                case BS_ROBOTS_WILDCARD_HEURISTIC:
                    if (!bs_ua_is_crawler_candidate(ua)) robots_apply = 0;
                    break;
                case BS_ROBOTS_WILDCARD_STRICT:
                default:
                    /* apply regardless */
                    break;
                }
            }
        }
    }
    if (robots_apply && !rmatch.allowed) {
        bs_score_add(r, BS_PENALTY_BLOCK_PATH, 3600,
            apr_pstrcat(r->pool, "robots-block:",
                        rmatch.group_name ? rmatch.group_name : "?", NULL));
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->block_path_hit_total,
                               1, __ATOMIC_RELAXED);
        }
        return HTTP_FORBIDDEN;
    }

    /* A directive rate-limit cohort that MATCHES this request is
     * authoritative for it — operator policy overrides robots.txt in
     * the rate-limit family. If a directive matched, we skip the
     * robots.txt crawl-delay check below regardless of whether the
     * directive admitted or tripped. */
    int directive_rate_matched = 0;
    if (scfg->rate_limits && scfg->rate_limits->nelts > 0) {
        bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
        unsigned char client_ip[16];
        int have_ip = bs_parse_client_ip(r->useragent_ip, client_ip);
        if (have_ip) bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
        apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
        for (int i = 0; i < scfg->rate_limits->nelts; i++) {
            bs_rate_limit_entry *e = APR_ARRAY_IDX(
                scfg->rate_limits, i, bs_rate_limit_entry *);
            if (!bs_cohort_matches(&e->cohort, ua, r)) continue;
            directive_rate_matched = 1;
            if (e->shm_slot < 0 || !counters) continue;

            /* E12 — observe mode (per-rule or global shadow_mode).
             * The counter still ticks (so `would-rate-limit` volume
             * answers the operator's "what would this fire?"
             * question accurately), but over-budget hits log
             * `rate-limit-exceeded:<name>:observe` instead of
             * returning 429. E9 escalation is also fully suppressed
             * — we don't bump strikes, and any pre-existing
             * escalation state is ignored for this rule under
             * observe. */
            int observe = global_shadow || (e->mode == BS_TMODE_OBSERVE);

            if (!observe && e->escalate && have_ip
                && bs_strike_check_escalated(client_ip,
                                             (apr_uint32_t)e->shm_slot,
                                             now_t, scfg->ns_id)) {
                /* E9 — escalation gate. Active only outside observe
                 * mode; observe must not enforce. */
                bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                    apr_pstrcat(r->pool, "rate-limit-abuse:",
                                e->name, NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_exceeded_total,
                        1, __ATOMIC_RELAXED);
                }
                return e->escalate->status_code;
            }

            if (bs_rate_counter_admit(&counters[e->shm_slot],
                                      e->budget, e->window_sec)) {
                continue;
            }
            /* Over budget. */
            if (observe) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "rate-limit-exceeded:",
                                e->name, ":observe", NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_observed_total,
                        1, __ATOMIC_RELAXED);
                }
                continue;
            }
            /* Enforce: Retry-After = seconds remaining in window. */
            apr_uint32_t win = __atomic_load_n(
                &counters[e->shm_slot].window_start_sec, __ATOMIC_RELAXED);
            apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
            apr_uint32_t retry = (now >= win && now - win < e->window_sec)
                                  ? e->window_sec - (now - win) : 1;
            apr_table_setn(r->err_headers_out, "Retry-After",
                apr_psprintf(r->pool, "%u", retry));
            bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                apr_pstrcat(r->pool, "rate-limit-exceeded:",
                            e->name, NULL));
            if (bs_shm.metrics) {
                __atomic_fetch_add(&bs_shm.metrics->rate_limit_exceeded_total,
                                   1, __ATOMIC_RELAXED);
            }
            /* E9 — strike accounting. Record this 429 under the
             * (ip, rule) entry; if the strike count crosses the
             * threshold inside the per-window, log the operator's
             * tag once for fail2ban handoff. The threshold-crossing
             * request itself returns 429; subsequent ones promote
             * to status_code via bs_strike_check_escalated above. */
            if (e->escalate && have_ip) {
                int crossed = bs_strike_record_429(r, client_ip,
                    (apr_uint32_t)e->shm_slot, e->escalate, now_t,
                    scfg->ns_id);
                if (crossed) {
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                        "mod_botshield: rate-limit-abuse threshold "
                        "crossed for '%s' from ip=%s; escalating to "
                        "status=%d for %ds%s%s%s",
                        e->name, r->useragent_ip,
                        e->escalate->status_code, e->escalate->ttl_sec,
                        e->escalate->log_tag ? " tag=\"" : "",
                        e->escalate->log_tag ? e->escalate->log_tag : "",
                        e->escalate->log_tag ? "\"" : "");
                    bs_set_trigger_tag(r, e->escalate->log_tag);
                }
            }
            return HTTP_TOO_MANY_REQUESTS;
        }
    }

    /* E2.2 — robots.txt Crawl-delay enforcement. Budget=1 per
     * Crawl-delay seconds; slot assignment is held inside rstate's
     * bundle (allocated at post_config + preserved by name across
     * refreshes). Skipped when a directive rate-limit already
     * matched this request: operator policy is authoritative in the
     * rate family. */
    if (robots_apply && rmatch.crawl_delay_sec > 0
        && !directive_rate_matched
        && rstate && rstate->slot_by_group_idx
        && rmatch.group_idx < robots_group_count(rstate->doc)) {
        int slot_idx = rstate->slot_by_group_idx[rmatch.group_idx];
        bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
        if (slot_idx >= 0 && counters) {
            bs_rate_counter *slot = &counters[slot_idx];
            if (!bs_rate_counter_admit(slot, 1,
                    (apr_uint32_t)rmatch.crawl_delay_sec)) {
                apr_uint32_t win = __atomic_load_n(
                    &slot->window_start_sec, __ATOMIC_RELAXED);
                apr_uint32_t now =
                    (apr_uint32_t)apr_time_sec(apr_time_now());
                apr_uint32_t wsec =
                    (apr_uint32_t)rmatch.crawl_delay_sec;
                apr_uint32_t retry = (now >= win && now - win < wsec)
                                      ? wsec - (now - win) : 1;
                apr_table_setn(r->err_headers_out, "Retry-After",
                    apr_psprintf(r->pool, "%u", retry));
                bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                    apr_pstrcat(r->pool, "robots-rate:",
                        rmatch.group_name ? rmatch.group_name : "?",
                        NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_exceeded_total,
                        1, __ATOMIC_RELAXED);
                }
                return HTTP_TOO_MANY_REQUESTS;
            }
        }
    }

    return OK;
}

/* ======================================================================
 * E2.2.2 — live-refresh of robots.txt via mod_watchdog
 *
 * bs_robots_load(): stat + (conditionally) parse + publish. Runs both
 * at post_config (initial load) and at each watchdog tick (refresh).
 * When the source file's mtime is unchanged, it's a cheap no-op.
 *
 * Atomic-swap model: active state lives in scfg->robots (read with
 * __atomic_load_n on the request path). When a fresh doc is built,
 * we atomically publish it, push the outgoing state into
 * scfg->robots_pending, and destroy whatever pool was in the
 * previous pending slot. That gives each displaced doc at least one
 * refresh interval of grace — more than enough for any in-flight
 * request to finish reading pointers into its pool.
 *
 * Slot stability: SHM rate-counter slots are keyed by group name via
 * scfg->robots_slot_by_name, which lives in pconf and survives
 * refresh. A group whose name reappears in the new doc keeps its
 * existing slot (and its in-flight Crawl-delay window); a genuinely
 * new group gets a fresh slot from the reserved pool. The map never
 * shrinks — operators who delete a crawler from robots.txt leave a
 * stale entry, which is harmless (no lookup targets it). If they
 * re-add it, the old slot is reused.
 * ====================================================================== */
static apr_status_t bs_robots_load(server_rec *sv, bs_server_cfg *scfg,
                                   apr_pool_t *pconf)
{
    if (!scfg || !scfg->robots_txt_path) return APR_EINVAL;

    /* Stat first — if mtime is unchanged since the active doc was
     * parsed, there's nothing to do. This is the common case on
     * every refresh tick. */
    apr_finfo_t fi;
    apr_status_t rv = apr_stat(&fi, scfg->robots_txt_path,
                               APR_FINFO_MTIME | APR_FINFO_SIZE, pconf);
    if (rv != APR_SUCCESS) {
        char errbuf[128];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, sv,
            "mod_botshield: robots.txt %s stat failed (%s); "
            "keeping previous state",
            scfg->robots_txt_path, errbuf);
        return rv;
    }

    bs_robots_state *cur =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    if (cur && cur->mtime == fi.mtime) {
        return APR_SUCCESS;
    }

    /* Build the new state in a fresh subpool we control. Destroying
     * this subpool later frees the doc and its slot map in one go,
     * without touching anything else in pconf. */
    apr_pool_t *npool = NULL;
    apr_pool_create(&npool, pconf);

    robots_doc *doc = NULL;
    const char *parse_err = NULL;
    rv = robots_parse_file(npool, scfg->robots_txt_path,
                           &doc, &parse_err);
    if (rv != APR_SUCCESS || !doc) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, sv,
            "mod_botshield: robots.txt %s parse failed (%s); "
            "keeping previous state",
            scfg->robots_txt_path,
            parse_err ? parse_err : "unknown error");
        apr_pool_destroy(npool);
        return rv;
    }

    int n_groups = robots_group_count(doc);
    bs_robots_state *ns = apr_pcalloc(npool, sizeof(*ns));
    ns->doc   = doc;
    ns->pool  = npool;
    ns->mtime = fi.mtime;
    ns->slot_by_group_idx = apr_pcalloc(npool,
        (n_groups > 0 ? n_groups : 1) * sizeof(int));

    int delay_count = 0, slot_reused = 0, slot_new = 0, slot_exhausted = 0;
    for (int i = 0; i < n_groups; i++) {
        ns->slot_by_group_idx[i] = -1;
        int cd = robots_group_crawl_delay_at(doc, i);
        if (cd <= 0) continue;
        delay_count++;
        const char *name = robots_group_name_at(doc, i);
        int *slot_ptr = apr_hash_get(scfg->robots_slot_by_name,
                                     name, APR_HASH_KEY_STRING);
        if (slot_ptr) {
            ns->slot_by_group_idx[i] = *slot_ptr;
            slot_reused++;
            continue;
        }
        if (scfg->robots_slot_pool_used < scfg->robots_slot_pool_size) {
            int slot = scfg->robots_slot_pool_base
                     + scfg->robots_slot_pool_used++;
            ns->slot_by_group_idx[i] = slot;
            /* Persist the mapping in pconf so future refreshes see
             * it. Copy name into pconf too — the doc's pool will be
             * destroyed on replacement and its name string with it. */
            int *persist = apr_palloc(pconf, sizeof(int));
            *persist = slot;
            apr_hash_set(scfg->robots_slot_by_name,
                         apr_pstrdup(pconf, name),
                         APR_HASH_KEY_STRING, persist);
            slot_new++;
        } else {
            slot_exhausted++;
        }
    }

    /* Publish the new state. scfg->robots_pending currently holds
     * the bundle displaced one refresh ago (or NULL at first load);
     * destroy its pool now — more than one refresh interval has
     * passed since any request took a pointer to it. */
    bs_robots_state *to_destroy = scfg->robots_pending;
    bs_robots_state *displaced  = cur;
    __atomic_store_n(&scfg->robots, ns, __ATOMIC_RELEASE);
    scfg->robots_pending = displaced;
    if (to_destroy && to_destroy->pool) {
        apr_pool_destroy(to_destroy->pool);
    }

    if (slot_exhausted > 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
            "mod_botshield: robots.txt slot pool exhausted "
            "(%d/%d used); %d Crawl-delay groups will not enforce "
            "until an Apache reload resizes the pool",
            scfg->robots_slot_pool_used, scfg->robots_slot_pool_size,
            slot_exhausted);
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
        "mod_botshield: robots.txt %s %sloaded — %d groups, "
        "%d with Crawl-delay (%d slots reused, %d new)",
        scfg->robots_txt_path, cur ? "re" : "",
        n_groups, delay_count, slot_reused, slot_new);
    return APR_SUCCESS;
}

/* mod_watchdog tick callback — one registration per vhost with a
 * BotShieldRobotsTxt directive. State-transition events (STARTING,
 * STOPPING) do nothing; RUNNING calls bs_robots_load which returns
 * fast when mtime hasn't changed. */
static apr_status_t bs_robots_watchdog_cb(int state, void *data,
                                          apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    /* data was passed as the server_rec at registration; retrieve
     * scfg from it so we always see the live pointer. pconf is
     * reachable through sv->process->pconf. */
    server_rec *sv = data;
    if (!sv) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(sv->module_config, &botshield_module);
    if (!scfg || !scfg->robots_txt_path) return APR_SUCCESS;
    bs_robots_load(sv, scfg, sv->process->pconf);
    return APR_SUCCESS;
}

/* ======================================================================
 * E11 — Load-aware throttling.
 *
 * Watchdog tick samples the Apache scoreboard's busy-worker ratio,
 * optionally merges in an external operator-set state from a watched
 * file, and folds the result into a cached state with hysteresis.
 * Request path reads bs_shm.header->load_state as a single atomic
 * u32. No scoreboard scans on the hot path.
 *
 * State transitions write `load_state` last, after the streak
 * counters and `load_state_changes` metric, so an unlucky reader
 * sees a self-consistent snapshot — at worst a slightly stale
 * state for a few microseconds. That's fine for a coarse 3-value
 * brownout signal. */

static int bs_load_effective_int(int v, int dflt)
{
    return (v > 0) ? v : dflt;
}

/* Map a sampled busy-worker ratio (percent of total slots) to a
 * candidate state via the operator's thresholds. */
static bs_load_state bs_load_state_from_pct(int busy_pct,
                                            int warm_pct, int hot_pct)
{
    if (busy_pct >= hot_pct)  return BS_LOAD_HOT;
    if (busy_pct >= warm_pct) return BS_LOAD_WARM;
    return BS_LOAD_NORMAL;
}

/* Read + parse the external load-state file. Caches by mtime so a
 * sampler that ticks every second only does an open()/read() when
 * the file actually changed (operator's monitor wrote a new value).
 * On any error: leave the cache untouched and return whatever the
 * last successful read produced (or NORMAL if never read). */
static bs_load_state bs_load_read_external(server_rec *sv,
                                           bs_server_cfg *scfg)
{
    if (!scfg->load_state_file) return BS_LOAD_NORMAL;
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, scfg->load_state_file,
                               APR_FINFO_MTIME, sv->process->pconf);
    if (rv != APR_SUCCESS) {
        /* File missing is normal if the operator hasn't written one
         * yet. Don't log per-tick or we'd spam. */
        return scfg->load_external_cached;
    }
    if (finfo.mtime == scfg->load_external_mtime) {
        return scfg->load_external_cached;   /* unchanged */
    }

    apr_file_t *f = NULL;
    rv = apr_file_open(&f, scfg->load_state_file,
                       APR_READ | APR_BINARY, 0, sv->process->pconf);
    if (rv != APR_SUCCESS) return scfg->load_external_cached;

    char buf[32];
    apr_size_t got = sizeof(buf) - 1;
    rv = apr_file_read(f, buf, &got);
    apr_file_close(f);
    if (rv != APR_SUCCESS && rv != APR_EOF) {
        return scfg->load_external_cached;
    }
    buf[got] = '\0';
    /* Trim trailing whitespace/newline so `echo hot > file` works. */
    while (got > 0 && (buf[got-1] == '\n' || buf[got-1] == '\r'
                       || buf[got-1] == ' '  || buf[got-1] == '\t')) {
        buf[--got] = '\0';
    }
    /* Trim leading whitespace too. */
    char *p = buf;
    while (*p == ' ' || *p == '\t') p++;

    bs_load_state parsed;
    if      (!strcasecmp(p, "normal")) parsed = BS_LOAD_NORMAL;
    else if (!strcasecmp(p, "warm"))   parsed = BS_LOAD_WARM;
    else if (!strcasecmp(p, "hot"))    parsed = BS_LOAD_HOT;
    else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
            "mod_botshield: BotShieldLoadStateFile '%s' contains "
            "unrecognized value '%s' (expected normal|warm|hot); "
            "treating as normal",
            scfg->load_state_file, p);
        parsed = BS_LOAD_NORMAL;
    }
    scfg->load_external_cached = parsed;
    scfg->load_external_mtime  = finfo.mtime;
    if (parsed != BS_LOAD_NORMAL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: external load state from '%s': %s",
            scfg->load_state_file, p);
    }
    return parsed;
}

/* Sample the Apache scoreboard. Returns busy_pct = 100 *
 * busy_workers / total_worker_slots. "Busy" = anything that's
 * actively servicing a request: BUSY_READ/WRITE/KEEPALIVE/LOG/DNS
 * + GRACEFUL (still serving its current request). READY and DEAD
 * slots don't count as busy. */
static int bs_load_sample_scoreboard(void)
{
    if (!ap_exists_scoreboard_image()) return 0;
    global_score *gs = ap_get_scoreboard_global();
    if (!gs) return 0;
    int total = gs->server_limit * gs->thread_limit;
    if (total <= 0) return 0;

    int busy = 0;
    for (int i = 0; i < gs->server_limit; i++) {
        for (int j = 0; j < gs->thread_limit; j++) {
            worker_score *ws =
                ap_get_scoreboard_worker_from_indexes(i, j);
            if (!ws) continue;
            switch (ws->status) {
            case SERVER_BUSY_READ:
            case SERVER_BUSY_WRITE:
            case SERVER_BUSY_KEEPALIVE:
            case SERVER_BUSY_LOG:
            case SERVER_BUSY_DNS:
            case SERVER_GRACEFUL:
                busy++;
                break;
            default:
                break;
            }
        }
    }
    return (busy * 100) / total;
}

/* Apply hysteresis. Given a candidate state from this tick's
 * sampling, decide whether to promote/demote the cached state.
 * Asymmetric: easy to enter (3 escalating samples to warm; 2 more
 * to hot), slow to exit (5 normal samples to demote one level).
 * Reset the opposite streak whenever the candidate changes
 * direction.
 *
 * Writes through the SHM header. Single-thread (watchdog), so no
 * locking; readers see a consistent state because the final write
 * is to load_state itself. */
static void bs_load_apply_tick(server_rec *sv, bs_server_cfg *scfg,
                               bs_load_state candidate)
{
    if (!bs_shm.header) return;
    int warm_rise = bs_load_effective_int(scfg->load_warm_rise,
                        BS_DEFAULT_LOAD_WARM_RISE);
    int hot_rise  = bs_load_effective_int(scfg->load_hot_rise,
                        BS_DEFAULT_LOAD_HOT_RISE);
    int fall      = bs_load_effective_int(scfg->load_normal_fall,
                        BS_DEFAULT_LOAD_NORMAL_FALL);

    bs_load_state current = (bs_load_state)bs_shm.header->load_state;
    bs_load_state next    = current;

    if (candidate > current) {
        bs_shm.header->load_recovery_streak = 0;
        bs_shm.header->load_escalation_streak++;
        int need = (current == BS_LOAD_NORMAL) ? warm_rise : hot_rise;
        if ((int)bs_shm.header->load_escalation_streak >= need) {
            next = (bs_load_state)(current + 1);
            bs_shm.header->load_escalation_streak = 0;
        }
    } else if (candidate < current) {
        bs_shm.header->load_escalation_streak = 0;
        bs_shm.header->load_recovery_streak++;
        if ((int)bs_shm.header->load_recovery_streak >= fall) {
            next = (bs_load_state)(current - 1);
            bs_shm.header->load_recovery_streak = 0;
        }
    } else {
        /* Steady-state: any drift toward edge resets. */
        bs_shm.header->load_escalation_streak = 0;
        bs_shm.header->load_recovery_streak   = 0;
    }

    if (next != current) {
        const char *names[] = { "normal", "warm", "hot" };
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: load state %s -> %s",
            names[current], names[next]);
        bs_shm.header->load_state_since_sec =
            (apr_uint32_t)apr_time_sec(apr_time_now());
        bs_shm.header->load_state_changes++;
        /* Publish the new state last so a request reading the field
         * sees either the old or the new value, not torn metadata. */
        apr_atomic_set32(&bs_shm.header->load_state,
                         (apr_uint32_t)next);
    }
}

/* mod_watchdog tick. Sample, merge with external file, fold into
 * the cached state. Cheap enough to run every second per main
 * server. */
static apr_status_t bs_load_watchdog_cb(int state, void *data,
                                        apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    server_rec *sv = data;
    if (!sv) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(sv->module_config, &botshield_module);
    if (!scfg) return APR_SUCCESS;

    int warm_pct = bs_load_effective_int(scfg->load_warm_pct,
                       BS_DEFAULT_LOAD_WARM_RATIO_PCT);
    int hot_pct  = bs_load_effective_int(scfg->load_hot_pct,
                       BS_DEFAULT_LOAD_HOT_RATIO_PCT);
    int busy_pct = bs_load_sample_scoreboard();
    bs_load_state internal = bs_load_state_from_pct(busy_pct,
                                                    warm_pct, hot_pct);
    bs_load_state external = bs_load_read_external(sv, scfg);

    /* Most-severe-wins merge. */
    bs_load_state candidate = (internal > external) ? internal : external;
    bs_load_apply_tick(sv, scfg, candidate);
    return APR_SUCCESS;
}

/* Cheap request-path read of the cached state. Lockless atomic.
 * Used by E11.2's BotShieldLoadTrigger predicate matcher; the
 * forward declaration lives near the other request-time helpers
 * earlier in the file. */
static bs_load_state bs_load_current(void)
{
    if (!bs_shm.header) return BS_LOAD_NORMAL;
    return (bs_load_state)apr_atomic_read32(&bs_shm.header->load_state);
}

/* Forward decl for the Bloom popcount helper used by the headroom
 * tick below; the body lives further down with the metrics gauge
 * helpers. */
static apr_uint64_t bs_popcount_buffer(const unsigned char *buf,
                                       apr_size_t bytes);

/* E13.1 — capacity headroom monitoring. Periodic watchdog that walks
 * the four reputation tables and emits NOTICE / WARNING when load
 * factors approach the probe-saturation cliff. The reactive "probe
 * saturated" warnings still fire at the cliff (see bs_flagged_ip_add
 * / bs_strike_record_429 / bs_safeguard_record_presentation), but
 * those only fire when an insert actually overflows the probe window
 * — by then entries are already being overwritten. The forward-
 * looking warnings here give operators time to bump capacity
 * directives gracefully before that happens.
 *
 * Thresholds match the open-addressing displacement model:
 *   load 0.50 → ~0.1% insert displacement (NOTICE)
 *   load 0.70 → ~2.8%                     (WARNING)
 * Beyond 0.7 the cliff comes fast.
 *
 * For the Bloom filter the rated-FP design point sits at bit-fill
 * ≈ ln(2) ≈ 0.693 of total bits. We NOTICE at 0.50 fill (~0.1% FP),
 * WARNING at 0.70 (~1.5% FP), past which FP climbs sharply. */

#define BS_HEADROOM_NOTICE_PCT     50
#define BS_HEADROOM_WARN_PCT       70
#define BS_HEADROOM_REWARN_SEC     300

typedef struct {
    apr_int64_t flagged_last_warn;
    apr_int64_t strike_last_warn;
    apr_int64_t safeguard_last_warn;
    apr_int64_t bloom_last_warn;
} bs_headroom_state;

/* Single-process state — mod_watchdog runs callbacks in the parent
 * only, so static module-scope storage is sufficient. */
static bs_headroom_state bs_headroom = {0, 0, 0, 0};

static void bs_headroom_check_table(server_rec *sv,
                                    const char *table_name,
                                    const char *directive_name,
                                    apr_uint64_t used,
                                    apr_size_t capacity,
                                    apr_int64_t *last_warn,
                                    apr_int64_t now_sec)
{
    if (capacity == 0) return;
    int pct = (int)((used * 100) / capacity);
    int level;
    if      (pct >= BS_HEADROOM_WARN_PCT)   level = APLOG_WARNING;
    else if (pct >= BS_HEADROOM_NOTICE_PCT) level = APLOG_NOTICE;
    else { *last_warn = 0; return; }   /* below threshold; reset cooldown */

    if (now_sec - *last_warn < BS_HEADROOM_REWARN_SEC) return;
    *last_warn = now_sec;
    ap_log_error(APLOG_MARK, level, 0, sv,
        "mod_botshield: %s table at %d%% (%" APR_UINT64_T_FMT
        "/%" APR_SIZE_T_FMT "); approaching probe-saturation. "
        "Consider raising %s.",
        table_name, pct, used, capacity, directive_name);
}

static apr_status_t bs_headroom_watchdog_cb(int state, void *data,
                                            apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    server_rec *sv = data;
    if (!sv) return APR_SUCCESS;

    apr_int64_t now_sec = (apr_int64_t)apr_time_sec(apr_time_now());

    /* flagged-IP — count active (TTL-live) entries. Stale-but-still-
     * present slots understate load slightly, biasing toward late
     * warnings. Acceptable: the reactive cliff warning is the safety
     * net for the bias case. */
    if (bs_shm.flagged_table && bs_shm.flagged_capacity) {
        apr_uint64_t used = 0;
        for (apr_size_t i = 0; i < bs_shm.flagged_capacity; i++) {
            const bs_flagged_ip_slot *slot = &bs_shm.flagged_table[i];
            if ((slot->version & 1U) == 0 &&
                slot->flags != 0 &&
                slot->expires_at > now_sec) {
                used++;
            }
        }
        bs_headroom_check_table(sv, "flagged-IP",
            "BotShieldFlaggedIPCapacity",
            used, bs_shm.flagged_capacity,
            &bs_headroom.flagged_last_warn, now_sec);
    }

    /* strike — physical occupancy (any non-EMPTY rule_slot). */
    if (bs_shm.strike_table && bs_shm.strike_capacity) {
        apr_uint64_t used = 0;
        for (apr_size_t i = 0; i < bs_shm.strike_capacity; i++) {
            const bs_strike_slot *slot = &bs_shm.strike_table[i];
            if ((slot->version & 1U) == 0 &&
                slot->rule_slot != BS_STRIKE_EMPTY) {
                used++;
            }
        }
        bs_headroom_check_table(sv, "strike",
            "BotShieldRateLimitEscalateCapacity",
            used, bs_shm.strike_capacity,
            &bs_headroom.strike_last_warn, now_sec);
    }

    /* safeguard — physical occupancy. */
    if (bs_shm.safeguard_table && bs_shm.safeguard_capacity) {
        apr_uint64_t used = 0;
        for (apr_size_t i = 0; i < bs_shm.safeguard_capacity; i++) {
            const bs_safeguard_slot *slot = &bs_shm.safeguard_table[i];
            if ((slot->version & 1U) == 0 && slot->used != 0) {
                used++;
            }
        }
        bs_headroom_check_table(sv, "safeguard",
            "BotShieldSafeguardCapacity",
            used, bs_shm.safeguard_capacity,
            &bs_headroom.safeguard_last_warn, now_sec);
    }

    /* Bloom — bit-fill against the ln(2) rated-FP design point.
     * Both buffers OR'd at lookup, so the higher-fill buffer governs
     * the effective FP. Compare the peak fill across the two. */
    if (bs_shm.bloom_bufs[0] && bs_shm.bloom_buf_bytes) {
        apr_uint64_t total_bits = (apr_uint64_t)bs_shm.bloom_buf_bytes * 8;
        if (total_bits > 0) {
            apr_uint64_t bits_a = bs_popcount_buffer(
                bs_shm.bloom_bufs[0], bs_shm.bloom_buf_bytes);
            apr_uint64_t bits_b = bs_popcount_buffer(
                bs_shm.bloom_bufs[1], bs_shm.bloom_buf_bytes);
            apr_uint64_t peak = (bits_a > bits_b) ? bits_a : bits_b;
            int pct = (int)((peak * 100) / total_bits);
            int level;
            if      (pct >= BS_HEADROOM_WARN_PCT)   level = APLOG_WARNING;
            else if (pct >= BS_HEADROOM_NOTICE_PCT) level = APLOG_NOTICE;
            else { bs_headroom.bloom_last_warn = 0; goto bloom_done; }
            if (now_sec - bs_headroom.bloom_last_warn
                >= BS_HEADROOM_REWARN_SEC) {
                bs_headroom.bloom_last_warn = now_sec;
                ap_log_error(APLOG_MARK, level, 0, sv,
                    "mod_botshield: Bloom filter peak buffer at %d%% "
                    "fill (%" APR_UINT64_T_FMT "/%" APR_UINT64_T_FMT
                    " bits); false-positive rate climbing past design "
                    "point. Consider raising BotShieldBloomIPs or "
                    "shortening BotShieldBloomWindow.",
                    pct, peak, total_bits);
            }
bloom_done: ;
        }
    }

    return APR_SUCCESS;
}

/* ======================================================================
 * E5 — App-to-module reputation feedback.
 *
 * App emits `X-BotShield-Feedback: event=<name>[;kid=<id>];sig=<hex>` on
 * its response. Module reads, HMAC-verifies, parses, strips the header,
 * looks up `<name>` in scfg->feedback_triggers (see E7.3's
 * BotShieldFeedbackTrigger directive), and applies the configured
 * flag+ttl+log. The wire carries *event names*, not raw flag/ttl
 * policy — operators control the mapping from event → module memory
 * in their Apache config, so an app compromise can't poke arbitrary
 * flag bits.
 *
 * Flag bits can be penalty (honeypot_hit, scanner_probe, fake_bot,
 * pow_fail_streak) or credit (app_verified_human, app_verified_session,
 * app_trust_signal); same wire format, different bit semantics on the
 * config side of the event-name indirection.
 *
 * Implementation rules (see PLAN.md E5):
 *   1. Run as an output filter so stripping happens before the
 *      response reaches the client. log_transaction would be too late.
 *   2. Always strip when the header is present, even if the feature
 *      is off — a misconfigured app must not leak the header to clients.
 *   3. Duplicate headers → reject + strip all instances.
 *   4. Main request only (ap_is_initial_req).
 *   5. One-shot per request: the filter removes itself after processing.
 *
 * Wire-format change (E7.3): pre-E7.3 apps signed
 * `flag=<name>;ttl=<sec>;sig=<hex>` directly. The body now carries
 * `event=<name>;sig=<hex>` and the flag/ttl come from config. Apps
 * must migrate their signer; the old body shape is rejected at
 * HMAC-verify time (the `flag=` / `ttl=` tokens are no longer HMAC-
 * covered under the new wire format, so signatures won't match).
 * ====================================================================== */

static ap_filter_rec_t *bs_app_feedback_filter_handle;

/* Count how many header entries match `name` (case-insensitive)
 * across both headers_out tables. apr_table_get only returns the
 * first; we need the count to catch duplicates up front, before
 * calling apr_table_unset (which removes all of them). Check both
 * r->headers_out AND r->err_headers_out — mod_headers' "Header
 * set" writes to the former; "Header always set" writes to the
 * latter (which Apache still merges into the on-wire response
 * regardless of status). If we only looked at one, a conditional
 * `Header set` from a 404 handler would miss the strip. */
static int bs_count_header_in_table(apr_table_t *t, const char *name)
{
    if (!t) return 0;
    const apr_array_header_t *arr = apr_table_elts(t);
    int count = 0;
    for (int i = 0; i < arr->nelts; i++) {
        apr_table_entry_t *e = &((apr_table_entry_t *)arr->elts)[i];
        if (e->key && strcasecmp(e->key, name) == 0) count++;
    }
    return count;
}
static int bs_count_header(request_rec *r, const char *name)
{
    return bs_count_header_in_table(r->headers_out, name)
         + bs_count_header_in_table(r->err_headers_out, name);
}

/* Parse + HMAC-verify a single X-BotShield-Feedback value under the
 * E7.3 wire format (`event=<name>[;...];sig=<hex>`). On success the
 * pool-allocated event name lands in *out_event and NULL is returned.
 * On failure returns an error string for logging and leaves
 * *out_event untouched. Caller looks up the event in
 * scfg->feedback_triggers to decide what the event means. */
static const char *bs_app_feedback_verify(apr_pool_t *p,
                                          const unsigned char *key,
                                          apr_size_t key_len,
                                          const char *value,
                                          const char **out_event)
{
    if (!key || key_len == 0) return "no secret configured";
    if (!value || !*value) return "empty header value";

    /* Find ";sig=" — everything before it is HMAC-covered. */
    const char *sig_marker = strstr(value, ";sig=");
    if (!sig_marker) return "missing sig= field";
    apr_size_t signed_len = (apr_size_t)(sig_marker - value);
    const char *sig_hex = sig_marker + 5;
    if (strlen(sig_hex) != 64) return "sig must be 64 hex chars";

    unsigned char expected[32];
    bs_hmac_sha256(key, key_len,
                   (const unsigned char *)value, signed_len,
                   expected);
    unsigned char given[32];
    if (!bs_from_hex(sig_hex, 32, given)) return "sig not hex";
    if (!bs_ct_equal(expected, given, 32)) return "signature mismatch";

    /* Parse key=value pairs up to (but not including) ;sig=. The
     * only semantic key is event=; everything else (kid, tid, etc.)
     * is tolerated so apps can include their own correlation IDs
     * under the HMAC without churning this parser. */
    char *body = apr_pstrmemdup(p, value, signed_len);
    char *state = NULL;
    const char *event_name = NULL;
    for (char *tok = apr_strtok(body, ";", &state); tok;
         tok = apr_strtok(NULL, ";", &state)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = tok;
        const char *v = eq + 1;
        if (!strcasecmp(k, "event")) {
            event_name = v;
        }
        /* Pre-E7.3 bodies carried flag= / ttl= directly. Those
         * tokens would now be ignored here, but they were part of
         * the HMAC-covered bytes under the OLD key layout. Under
         * the new format the signer covers only event=<name>, so
         * an old body would fail HMAC verification above before
         * reaching this parse. No explicit "reject pre-E7.3"
         * branch is needed — the crypto catches it. */
    }

    if (!event_name || !*event_name) return "missing event= field";
    /* Event names follow the same constrained shape as trigger
     * names so operators can always reason about what a signed
     * body means. Enforced here so an injected ';' or '=' inside
     * the value can't confuse the upcoming lookup. */
    apr_size_t elen = strlen(event_name);
    if (elen == 0 || elen > 32) {
        return "event name must be 1..32 chars";
    }
    for (apr_size_t i = 0; i < elen; i++) {
        unsigned char c = (unsigned char)event_name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
              || c == '-';
        if (!ok) return "event name must be [a-z0-9-]";
    }

    *out_event = apr_pstrdup(p, event_name);
    return NULL;
}

/* Look up an event name in scfg->feedback_triggers. Returns the
 * matching entry or NULL. Declaration order, first match wins (no
 * accumulation — an event is a discrete app-originated signal). */
static const bs_feedback_trigger_entry *bs_feedback_trigger_find(
    struct bs_server_cfg *scfg, const char *event)
{
    if (!scfg || !scfg->feedback_triggers || !event) return NULL;
    for (int i = 0; i < scfg->feedback_triggers->nelts; i++) {
        bs_feedback_trigger_entry *e = APR_ARRAY_IDX(
            scfg->feedback_triggers, i, bs_feedback_trigger_entry *);
        if (strcmp(e->event, event) == 0) return e;
    }
    return NULL;
}

/* Output-filter callback. Runs once per initial request: reads
 * r->headers_out for the configured feedback header, strips every
 * occurrence, and (if the feature is enabled and exactly one copy
 * was found) validates the HMAC and updates the flagged-IP table. */
static apr_status_t bs_app_feedback_filter(ap_filter_t *f,
                                           apr_bucket_brigade *bb)
{
    request_rec *r = f->r;

    /* One-shot: remove before processing to avoid re-entry on
     * subsequent brigade passes. */
    ap_remove_output_filter(f);

    if (!ap_is_initial_req(r)) {
        return ap_pass_brigade(f->next, bb);
    }

    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    if (!scfg) return ap_pass_brigade(f->next, bb);

    const char *hname = scfg->app_feedback_header
                      ? scfg->app_feedback_header
                      : BS_APP_FEEDBACK_DEFAULT_HEADER;

    int n = bs_count_header(r, hname);
    if (n == 0) return ap_pass_brigade(f->next, bb);

    /* Snapshot the first value BEFORE we strip — we still want to
     * verify and apply it if there's exactly one. Check both tables
     * since mod_headers' `Header set` and `Header always set` go
     * to different ones. */
    const char *first_val = apr_table_get(r->headers_out, hname);
    if (!first_val) first_val = apr_table_get(r->err_headers_out, hname);
    char *snapshot = first_val ? apr_pstrdup(r->pool, first_val) : NULL;

    /* Always strip — see PLAN.md E5 rule 2. Removes every copy at
     * once (from both tables) so duplicates don't leak even when
     * we reject them. */
    apr_table_unset(r->headers_out, hname);
    apr_table_unset(r->err_headers_out, hname);

    int enabled = (scfg->app_feedback_enabled == 1);
    if (!enabled) {
        return ap_pass_brigade(f->next, bb);
    }

    if (n > 1) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: app feedback rejected: %d copies of "
            "'%s' on response (expected exactly 1)", n, hname);
        return ap_pass_brigade(f->next, bb);
    }

    if (!scfg->app_feedback_secret || scfg->app_feedback_secret_len == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: app feedback received but "
            "BotShieldAppFeedbackSecretFile not configured");
        return ap_pass_brigade(f->next, bb);
    }

    const char *event = NULL;
    const char *err = bs_app_feedback_verify(r->pool,
        scfg->app_feedback_secret, scfg->app_feedback_secret_len,
        snapshot, &event);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: app feedback rejected: %s", err);
        return ap_pass_brigade(f->next, bb);
    }

    /* Map event → action via BotShieldFeedbackTrigger. Unknown
     * events are a config-side miss, not an app-side attack — log
     * at info and skip. This is the indirection that keeps flag
     * names out of the wire format: a compromised app can emit any
     * event name, but only configured mappings have effect. */
    const bs_feedback_trigger_entry *ft =
        bs_feedback_trigger_find(scfg, event);
    if (!ft) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: app feedback event=%s unmapped "
            "(no BotShieldFeedbackTrigger entry); ignored", event);
        return ap_pass_brigade(f->next, bb);
    }

    unsigned char client_ip[16];
    if (bs_parse_client_ip(r->useragent_ip, client_ip)) {
        bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
        bs_flagged_ip_add(r, client_ip,
                          ft->action.flag_bit, ft->action.ttl_sec,
                          scfg->ns_id);
        if (ft->action.log_tag) {
            /* Feedback has no decision-log emission of its own, but
             * the tag belongs in r->notes so any subsequent access
             * log or custom format can pick it up via %{BS-...}n. */
            bs_set_trigger_tag(r, ft->action.log_tag);
        }
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: app feedback event=%s applied "
            "flag=0x%x ttl=%d", event,
            ft->action.flag_bit, ft->action.ttl_sec);
    }

    return ap_pass_brigade(f->next, bb);
}

/* Adds the one-shot filter to the chain for every request. Called
 * from ap_hook_insert_filter. Cheap — just appends to the filter
 * list; the real work is gated inside the filter on
 * ap_is_initial_req + the header being present. */
static void bs_app_feedback_insert_filter(request_rec *r)
{
    if (!ap_is_initial_req(r)) return;
    ap_add_output_filter_handle(bs_app_feedback_filter_handle,
                                NULL, r, r->connection);
}

/* Flag-bit registry. Maps the BS_FLAG_* defines to the canonical
 * names that appear in directives (`flag=honeypot_hit`), wire
 * formats (X-Botshield-Claims `flags=`), and the decision log.
 * Hoisted up the file so E8.2's claim-emit path can render the
 * bitmap without a forward-decl dance over an anonymous-struct
 * array (forward-declaring such arrays in C is awkward).
 *
 * E14 — registry now also carries adaptive metadata (penalty,
 * next_difficulty_delta, next_tier_floor). The values seeded here
 * are the built-in defaults; `BotShieldFlag` directive entries
 * override them by name. Compatibility shim `bs_flag_names` (no
 * metadata, just name+bit) is kept as a const projection for
 * call-sites that only iterate names. */
typedef struct {
    const char     *name;
    apr_uint32_t    bit;
    int             penalty;
    int             next_difficulty_delta;   /* signed; clamped at apply time */
    bs_tier         next_tier_floor;          /* PASS = no floor (default) */
} bs_flag_meta;

static bs_flag_meta bs_flag_metadata[] = {
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT,          60, 0, BS_TIER_PASS },
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE,         50, 0, BS_TIER_PASS },
    { "fake_bot",             BS_FLAG_FAKE_BOT,              80, 0, BS_TIER_PASS },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK,       30, 0, BS_TIER_PASS },
    { "app_verified_human",   BS_FLAG_APP_VERIFIED_HUMAN,   -80, 0, BS_TIER_PASS },
    { "app_verified_session", BS_FLAG_APP_VERIFIED_SESSION, -40, 0, BS_TIER_PASS },
    { "app_trust_signal",     BS_FLAG_APP_TRUST_SIGNAL,     -20, 0, BS_TIER_PASS },
};
#define BS_FLAG_META_COUNT \
    (sizeof(bs_flag_metadata) / sizeof(bs_flag_metadata[0]))

/* Read-only name+bit projection for legacy iteration sites. NULL-
 * terminated to match the prior bs_flag_names[] sentinel contract.
 * Built lazily because the metadata table isn't const after E14
 * (BotShieldFlag mutates it). */
static const struct { const char *name; apr_uint32_t bit; } bs_flag_names[] = {
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT         },
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE        },
    { "fake_bot",             BS_FLAG_FAKE_BOT             },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK      },
    { "app_verified_human",   BS_FLAG_APP_VERIFIED_HUMAN   },
    { "app_verified_session", BS_FLAG_APP_VERIFIED_SESSION },
    { "app_trust_signal",     BS_FLAG_APP_TRUST_SIGNAL     },
    { NULL, 0 }
};

static bs_flag_meta *bs_flag_meta_for_name(const char *name)
{
    for (size_t i = 0; i < BS_FLAG_META_COUNT; i++) {
        if (strcmp(bs_flag_metadata[i].name, name) == 0) {
            return &bs_flag_metadata[i];
        }
    }
    return NULL;
}

/* Forward decl: bs_tier_name lives further down with the rest of
 * the tier-dispatch helpers; bs_app_claims_set needs it. */
static const char *bs_tier_name(bs_tier t);

/* ======================================================================
 * E8.2 — Module-to-app reputation export.
 *
 * On the request path: strip any client-supplied X-Botshield-*, then
 * set a single signed X-Botshield-Claims header that the backend
 * handler reads to drive whatever app-side policy cares about
 * BotShield's verdict (request-by-request risk score, cookie state,
 * accumulated flag bitmap, etc.).
 *
 * Symmetric to E5 in shape:
 *   - signed envelope, key=value;...;sig=<hex>, HMAC-SHA-256
 *   - separate secret file (defense-in-depth vs. E5's inbound key)
 *   - unknown body keys tolerated (forward compat)
 *
 * Symmetric to E5 in trust posture: the strip-before-set is the
 * trust anchor for apps that don't bother to verify the HMAC. The
 * signed envelope is for apps that want value-integrity even across
 * an untrusted Apache→backend hop.
 * ====================================================================== */

/* Walk r->headers_in and unset every header whose name begins with
 * "X-Botshield-" (case-insensitive). apr_table_unset takes a key, so
 * we collect names first (snapshotting because table mutation during
 * iteration is undefined) then drop them all in a second pass. */
static void bs_app_claims_strip_incoming(request_rec *r)
{
    const apr_array_header_t *arr = apr_table_elts(r->headers_in);
    apr_array_header_t *to_unset =
        apr_array_make(r->pool, 4, sizeof(const char *));
    for (int i = 0; i < arr->nelts; i++) {
        apr_table_entry_t *e = &((apr_table_entry_t *)arr->elts)[i];
        if (e->key && strncasecmp(e->key, "X-Botshield-", 12) == 0) {
            *(const char **)apr_array_push(to_unset) = e->key;
        }
    }
    for (int i = 0; i < to_unset->nelts; i++) {
        apr_table_unset(r->headers_in,
                        APR_ARRAY_IDX(to_unset, i, const char *));
    }
}

/* Render the flag bitmap as a space-separated list of registry names
 * for the X-Botshield-Claims body. Empty string when no bits set —
 * apps see `flags=` (empty value) which the parser treats the same
 * as absent. */
static const char *bs_app_claims_flag_names(apr_pool_t *p,
                                            apr_uint32_t flags)
{
    if (!flags) return "";
    char *buf = apr_palloc(p, 256);
    apr_size_t off = 0;
    for (int i = 0; bs_flag_names[i].name; i++) {
        if (!(flags & bs_flag_names[i].bit)) continue;
        const char *n = bs_flag_names[i].name;
        apr_size_t nlen = strlen(n);
        if (off + nlen + 2 > 256) break;   /* defensive cap */
        if (off > 0) buf[off++] = ' ';
        memcpy(buf + off, n, nlen);
        off += nlen;
    }
    buf[off] = '\0';
    return buf;
}

/* Emit X-Botshield-Claims on the request to the backend. Called from
 * bs_handler's PASS leg — every value is finalized at that point.
 * Returns NULL on success or an error string the caller can log. */
static const char *bs_app_claims_set(request_rec *r,
                                     bs_server_cfg *scfg,
                                     int score,
                                     bs_tier tier,
                                     const char *cookie_status,
                                     apr_uint32_t flags,
                                     int passes_silent,
                                     int passes_form,
                                     int passes_captcha)
{
    if (!scfg || scfg->app_claims_enabled != 1) return NULL;
    if (!scfg->app_claims_secret || scfg->app_claims_secret_len == 0) {
        return "BotShieldAppClaimsSecretFile not configured";
    }

    bs_app_claims_strip_incoming(r);

    apr_time_t now = apr_time_sec(apr_time_now());
    const char *flag_names = bs_app_claims_flag_names(r->pool, flags);
    const char *body = apr_psprintf(r->pool,
        "v=1;score=%d;tier=%s;cookie=%s;flags=%s;"
        "passes=s=%d,f=%d,c=%d;ts=%" APR_TIME_T_FMT,
        score, bs_tier_name(tier), cookie_status, flag_names,
        passes_silent, passes_form, passes_captcha, now);

    unsigned char mac[BS_SIG_BYTES];
    bs_hmac_sha256(scfg->app_claims_secret, scfg->app_claims_secret_len,
                   (const unsigned char *)body, strlen(body), mac);
    char sig_hex[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(mac, BS_SIG_BYTES, sig_hex);

    const char *header_val = apr_psprintf(r->pool, "%s;sig=%s",
                                          body, sig_hex);
    apr_table_setn(r->headers_in, "X-Botshield-Claims", header_val);
    return NULL;
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
    /* E2.1 — fixed-size table of rate-limit counter slots. 256 slots
     * covers hand-written directives comfortably; E2.2's robots.txt
     * rules will share the same pool. Trivial size (~2 KB). */
    #define BS_E21_RATE_SLOTS 256
    apr_size_t e21_rate_bytes = BS_E21_RATE_SLOTS * sizeof(bs_rate_counter);
    /* E9 — strike table for repeated-429 escalation. Sized by the
     * main server's BotShieldRateLimitEscalateCapacity (default
     * BS_DEFAULT_STRIKE_SLOTS). */
    apr_size_t strike_slots = (scfg->strike_capacity > 0)
                            ? (apr_size_t)scfg->strike_capacity
                            : (apr_size_t)BS_DEFAULT_STRIKE_SLOTS;
    apr_size_t strike_bytes = strike_slots * sizeof(bs_strike_slot);
    /* E10 — safeguard table. Same ballpark size + tuning surface
     * as the strike table. */
    apr_size_t safeguard_slots = (scfg->safeguard_capacity > 0)
                               ? (apr_size_t)scfg->safeguard_capacity
                               : (apr_size_t)BS_DEFAULT_SAFEGUARD_SLOTS;
    apr_size_t safeguard_bytes = safeguard_slots
                               * sizeof(bs_safeguard_slot);
    apr_size_t total_bytes  = header_bytes + table_bytes + 2 * bloom_bytes
                              + cv_rate_bytes + cv_log_bytes
                              + metrics_bytes + e21_rate_bytes
                              + strike_bytes + safeguard_bytes;

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
    /* E2.1: rate-limit counter slots follow the metrics block. */
    bs_shm.rate_counters      = (bs_rate_counter *)(metrics_base
                                                    + metrics_bytes);
    bs_shm.rate_counter_count = BS_E21_RATE_SLOTS;
    /* E9: strike table follows rate counters. memset(base, 0) above
     * leaves all slots with rule_slot=0 by default — but 0 is a real
     * rule slot value, so we have to explicitly mark every slot
     * empty. One pass at startup is fine; slots are reused via
     * the open-addressing eviction policy thereafter. */
    bs_shm.strike_table = (bs_strike_slot *)((unsigned char *)bs_shm.rate_counters
                                             + e21_rate_bytes);
    bs_shm.strike_capacity = strike_slots;
    for (apr_size_t i = 0; i < strike_slots; i++) {
        bs_shm.strike_table[i].rule_slot = BS_STRIKE_EMPTY;
    }
    /* E10: safeguard table follows the strike table. memset(base,0)
     * leaves every `used` field at 0, which IS the "empty" sentinel
     * for this table — no explicit zero pass needed. */
    bs_shm.safeguard_table = (bs_safeguard_slot *)
        ((unsigned char *)bs_shm.strike_table + strike_bytes);
    bs_shm.safeguard_capacity = safeguard_slots;

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

    /* E1 — build the UA classifier + ranges hash for each server
     * that enabled the Allow family. Walk s, s->next, s->next->next,
     * ... so a vhost-scope `BotShieldAllow on` fires. Each vhost
     * gets its own classifier + ranges hash; per-request check reads
     * from r->server's scfg so scoping matches.
     *
     * Per-bot input shape:
     *   - Built-in bots (bs_builtin_bots[]) seed the Allow set
     *     unless an operator `BotShieldAllowBot` entry overrides
     *     by name.
     *   - Third-arg semantics inspected here, not at directive
     *     parse time, because we need pconf's allocator for the
     *     resulting apr_ipsubnet_t objects:
     *       - ua_only==1 (operator said `*`): no ranges loaded;
     *         request-time match gives allow-bot-ua:<name>.
     *       - inline_cidrs set: parse via
     *         bs_allow_load_ranges_from_string.
     *       - path set: load from that file.
     *       - neither: load from the default path. */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg || !vcfg->allow_enabled) continue;

        vcfg->bot_classifier = bs_ua_classifier_create(pconf);
        vcfg->bot_ranges     = apr_hash_make(pconf);

        /* Seed the Allow set: directive-declared entries win over
         * built-ins with the same name. Build a working hash keyed
         * on name. */
        apr_hash_t *working = apr_hash_make(pconf);
        for (const bs_allow_bot_entry *b = bs_builtin_bots; b->name; b++) {
            apr_hash_set(working, b->name, APR_HASH_KEY_STRING, b);
        }
        apr_hash_index_t *hi;
        for (hi = apr_hash_first(pconf, vcfg->allow_bots);
             hi; hi = apr_hash_next(hi)) {
            const void *k; void *v;
            apr_hash_this(hi, &k, NULL, &v);
            apr_hash_set(working, k, APR_HASH_KEY_STRING, v);
        }

        int n_bots = 0, loaded = 0, missing = 0, bad = 0, ua_only = 0;
        for (hi = apr_hash_first(pconf, working); hi; hi = apr_hash_next(hi)) {
            const void *k; void *v;
            apr_hash_this(hi, &k, NULL, &v);
            const bs_allow_bot_entry *e = v;
            n_bots++;

            /* Register the UA pattern in the classifier. */
            bs_ua_classifier_add(vcfg->bot_classifier, e->name, e->pattern);

            /* UA-only mode skips ranges entirely. */
            if (e->ua_only) {
                ua_only++;
                continue;
            }

            /* Inline CIDR list mode. */
            if (e->inline_cidrs) {
                apr_array_header_t *arr = NULL;
                const char *err = NULL;
                apr_status_t rv = bs_allow_load_ranges_from_string(
                    pconf, e->inline_cidrs, &arr, &err);
                if (rv == APR_SUCCESS) {
                    apr_hash_set(vcfg->bot_ranges, e->name,
                                 APR_HASH_KEY_STRING, arr);
                    loaded++;
                } else {
                    bad++;
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
                        "mod_botshield: bot '%s' inline CIDRs "
                        "malformed (%s) — skipping",
                        e->name, err ? err : "parse error");
                }
                continue;
            }

            /* File-path mode (explicit or default). */
            const char *path = e->path
                ? e->path
                : apr_psprintf(pconf,
                    "/var/lib/botshield/bots/%s.txt", e->name);

            apr_array_header_t *arr = NULL;
            const char *err = NULL;
            apr_status_t rv = bs_allow_load_ranges(pconf, path, &arr, &err);
            if (rv == APR_SUCCESS) {
                apr_hash_set(vcfg->bot_ranges, e->name,
                             APR_HASH_KEY_STRING, arr);
                loaded++;
            } else if (APR_STATUS_IS_ENOENT(rv) || !e->path) {
                missing++;
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                    "mod_botshield: bot '%s' ranges file '%s' "
                    "not loaded (%s) — UA will classify as unverified",
                    e->name, path, err ? err : "");
            } else {
                bad++;
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
                    "mod_botshield: bot '%s' ranges file '%s' "
                    "malformed (%s) — skipping", e->name, path,
                    err ? err : "parse error");
            }
        }
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: Allow enabled; %d bots "
            "(%d ranges loaded, %d ua-only, %d missing, %d malformed)",
            n_bots, loaded, ua_only, missing, bad);
    }

    /* E2.1 — resolve cohort ipspecs for every rate_limit / block_path
     * entry across main + vhost scopes, and assign SHM slot indices to
     * rate_limit entries. Shared counter pool across all vhosts; slot
     * indices are global, handed out in declaration order. If operators
     * ever exceed BS_E21_RATE_SLOTS, the overflow entries stay at
     * shm_slot=-1 and are silently skipped at request time (log warning
     * surfaces the condition). */
    int next_slot = 0;
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;

        /* Resolve a cohort's ipspec (path or inline CIDRs) into the
         * ranges array. Shared between rate_limits and block_paths. */
        #define BS_E21_RESOLVE_COHORT(c_, feature_, name_) do {              \
            if ((c_)->ip_any || (c_)->ranges) break;                         \
            const char *rerr = NULL;                                         \
            apr_status_t rrv = APR_SUCCESS;                                  \
            if ((c_)->inline_cidrs) {                                        \
                rrv = bs_allow_load_ranges_from_string(pconf,                \
                    (c_)->inline_cidrs, &(c_)->ranges, &rerr);               \
            } else if ((c_)->path) {                                         \
                rrv = bs_allow_load_ranges(pconf, (c_)->path,                \
                    &(c_)->ranges, &rerr);                                   \
            }                                                                \
            if (rrv != APR_SUCCESS) {                                        \
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,               \
                    "mod_botshield: %s '%s' ipspec load failed (%s) — "      \
                    "cohort will never match", feature_, name_,              \
                    rerr ? rerr : "unknown");                                \
                (c_)->ranges = NULL;                                         \
            }                                                                \
        } while (0)

        if (vcfg->rate_limits && vcfg->rate_limits->nelts > 0) {
            for (int i = 0; i < vcfg->rate_limits->nelts; i++) {
                bs_rate_limit_entry *e = APR_ARRAY_IDX(
                    vcfg->rate_limits, i, bs_rate_limit_entry *);
                BS_E21_RESOLVE_COHORT(&e->cohort,
                    "BotShieldRateLimit", e->name);
                if (e->shm_slot < 0) {
                    if (next_slot < (int)bs_shm.rate_counter_count) {
                        e->shm_slot = next_slot++;
                    } else {
                        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
                            "mod_botshield: rate-limit slot pool "
                            "exhausted (%d); '%s' will not enforce",
                            (int)bs_shm.rate_counter_count, e->name);
                    }
                }
            }
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: %d rate-limit cohorts wired",
                vcfg->rate_limits->nelts);
        }

        /* E9 — link each BotShieldRateLimitEscalate to its target
         * BotShieldRateLimit by name. Declarations may appear in
         * any order at config time; we resolve here once both arrays
         * are populated. Unlinked escalates (no matching rate rule)
         * log a warning and stay inert. */
        if (vcfg->rate_escalates && vcfg->rate_escalates->nelts > 0) {
            for (int i = 0; i < vcfg->rate_escalates->nelts; i++) {
                bs_rate_escalate_entry *esc = APR_ARRAY_IDX(
                    vcfg->rate_escalates, i, bs_rate_escalate_entry *);
                int linked = 0;
                if (vcfg->rate_limits) {
                    for (int j = 0; j < vcfg->rate_limits->nelts; j++) {
                        bs_rate_limit_entry *rl = APR_ARRAY_IDX(
                            vcfg->rate_limits, j, bs_rate_limit_entry *);
                        if (strcmp(rl->name, esc->rule_name) == 0) {
                            rl->escalate = esc;
                            linked = 1;
                            break;
                        }
                    }
                }
                if (!linked) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
                        "mod_botshield: BotShieldRateLimitEscalate '%s' "
                        "names no matching BotShieldRateLimit at this "
                        "scope; directive is inert",
                        esc->rule_name);
                }
            }
        }

        if (vcfg->block_paths && vcfg->block_paths->nelts > 0) {
            for (int i = 0; i < vcfg->block_paths->nelts; i++) {
                bs_block_path_entry *e = APR_ARRAY_IDX(
                    vcfg->block_paths, i, bs_block_path_entry *);
                BS_E21_RESOLVE_COHORT(&e->cohort,
                    "BotShieldBlockPath", e->name);
            }
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: %d block-path cohorts wired",
                vcfg->block_paths->nelts);
        }
        #undef BS_E21_RESOLVE_COHORT
    }

    /* E2.2 — resolve sentinel defaults for any vhost where the
     * directive wasn't given (either at the vhost or at main scope
     * that got merged down). After this loop every vhost's scfg has
     * concrete values; downstream code can read them as-is. */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;
        if (vcfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_UNSET) {
            vcfg->robots_wildcard_scope = BS_ROBOTS_WILDCARD_HEURISTIC;
        }
        if (vcfg->robots_refresh_interval == BS_ROBOTS_REFRESH_UNSET) {
            vcfg->robots_refresh_interval = BS_ROBOTS_REFRESH_DEFAULT;
        }

        /* E13 — derive the per-vhost reputation namespace ID.
         * Precedence: explicit BotShieldShareScope token first,
         * then siphash(ServerName), finally fallback to ns_id=0
         * (global default) with a NOTICE so operators see the
         * fallback. The siphash_key was randomized at SHM init
         * above, so the ns_id is stable for this Apache process
         * but unpredictable across restarts — which is fine since
         * persistence already keys on ns_id and old state files
         * get rejected on format mismatch. */
        const char *src = NULL;
        if (vcfg->share_scope_token) {
            apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key,
                (const unsigned char *)vcfg->share_scope_token,
                strlen(vcfg->share_scope_token));
            vcfg->ns_id = (apr_uint32_t)h;
            src = "BotShieldShareScope token";
        } else if (sv->server_hostname && *sv->server_hostname) {
            apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key,
                (const unsigned char *)sv->server_hostname,
                strlen(sv->server_hostname));
            vcfg->ns_id = (apr_uint32_t)h;
            src = "ServerName";
        } else {
            vcfg->ns_id = 0;
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: vhost has no ServerName and no "
                "BotShieldShareScope; using global ns_id=0. "
                "Reputation will be shared with any other vhost "
                "in this state. Set ServerName or "
                "BotShieldShareScope to opt into isolation.");
        }
        if (src) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, sv,
                "mod_botshield: vhost ns_id=0x%08x from %s",
                vcfg->ns_id, src);
        }
    }

    /* E2.2 — reserve an SHM rate-counter slot pool for each vhost's
     * robots.txt, then do the initial parse. The SHM slot pool is
     * sized once at post_config (cannot grow after); refresh reuses
     * slots by group name so rate-counter state survives across
     * refreshes. BS_E22_ROBOTS_SLOT_POOL is a deliberate overshoot —
     * most hand-maintained robots.txt files have <10 Crawl-delay
     * groups. */
    #define BS_E22_ROBOTS_SLOT_POOL 16
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg || !vcfg->robots_txt_path) continue;

        /* Reserve the pool from the global rate-counter table. */
        int pool_base = next_slot;
        int pool_size = BS_E22_ROBOTS_SLOT_POOL;
        if (pool_base + pool_size > (int)bs_shm.rate_counter_count) {
            pool_size = (int)bs_shm.rate_counter_count - pool_base;
            if (pool_size < 0) pool_size = 0;
        }
        vcfg->robots_slot_pool_base = pool_base;
        vcfg->robots_slot_pool_size = pool_size;
        vcfg->robots_slot_pool_used = 0;
        next_slot += pool_size;

        apr_status_t rv = bs_robots_load(sv, vcfg, pconf);
        if (rv != APR_SUCCESS) {
            /* bs_robots_load already logged a diagnostic; keep
             * scfg->robots at NULL so the request path short-
             * circuits out of robots.txt enforcement for this vhost. */
        }

        /* Register a per-vhost watchdog callback for live refresh.
         * Soft dependency on mod_watchdog — if not loaded, we keep
         * what post_config built and that's that. Per-vhost
         * singletons so the watchdog doesn't multiplex ticks across
         * vhosts with different refresh intervals. */
        if (vcfg->robots_refresh_interval > 0) {
            APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *fn_get =
                APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
            APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *fn_reg =
                APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
            if (fn_get && fn_reg) {
                /* Instance name is per-vhost so one operator bad
                 * state can't wedge another vhost's refresh. */
                const char *wd_name = apr_psprintf(pconf,
                    "mod_botshield_robots_%pp", (void *)sv);
                ap_watchdog_t *wd = NULL;
                apr_status_t wrv = fn_get(&wd, wd_name, 0, 1, pconf);
                if (wrv == APR_SUCCESS && wd) {
                    apr_interval_time_t ival = apr_time_from_sec(
                        vcfg->robots_refresh_interval);
                    wrv = fn_reg(wd, ival, sv, bs_robots_watchdog_cb);
                } else if (wrv == APR_SUCCESS) {
                    wrv = APR_EGENERAL;
                }
                if (wrv == APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                        "mod_botshield: robots.txt live-refresh "
                        "enabled every %d s",
                        vcfg->robots_refresh_interval);
                } else {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, wrv, sv,
                        "mod_botshield: robots.txt watchdog "
                        "registration failed; live-refresh disabled "
                        "(post_config load still in effect)");
                }
            } else {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                    "mod_botshield: mod_watchdog not loaded; "
                    "robots.txt live-refresh disabled (post_config "
                    "load still in effect; reload Apache after "
                    "editing robots.txt)");
            }
        }
    }

    /* E11 — load-state watchdog. One registration on the main
     * server only — the cached state is module-global, so per-vhost
     * registrations would just multiply the work for no gain. The
     * sampler reads scoreboard + (optional) external state file
     * once per tick and updates SHM. Soft dep on mod_watchdog. */
    {
        bs_server_cfg *main_scfg = ap_get_module_config(
            s->module_config, &botshield_module);
        /* Propagate load directives from any vhost to the main
         * scfg if main doesn't have them. Operators write
         * BotShieldLoadStateFile in vhost scope (config_override
         * lands inside <VirtualHost>); the watchdog runs against
         * main's scfg. Without this, the watchdog wouldn't see the
         * directive at all. First-vhost-wins for each field. */
        if (main_scfg) {
            for (server_rec *sv2 = s; sv2; sv2 = sv2->next) {
                bs_server_cfg *vc = ap_get_module_config(
                    sv2->module_config, &botshield_module);
                if (!vc || vc == main_scfg) continue;
                if (!main_scfg->load_state_file && vc->load_state_file)
                    main_scfg->load_state_file = vc->load_state_file;
                if (main_scfg->load_refresh_sec <= 0
                    && vc->load_refresh_sec > 0)
                    main_scfg->load_refresh_sec = vc->load_refresh_sec;
                if (main_scfg->load_warm_pct <= 0 && vc->load_warm_pct > 0)
                    main_scfg->load_warm_pct = vc->load_warm_pct;
                if (main_scfg->load_hot_pct <= 0 && vc->load_hot_pct > 0)
                    main_scfg->load_hot_pct = vc->load_hot_pct;
            }
        }
        if (main_scfg) {
            int refresh = bs_load_effective_int(
                main_scfg->load_refresh_sec,
                BS_DEFAULT_LOAD_REFRESH_SEC);
            APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *fn_get =
                APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
            APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *fn_reg =
                APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
            if (fn_get && fn_reg) {
                ap_watchdog_t *wd = NULL;
                apr_status_t wrv = fn_get(&wd,
                    "mod_botshield_load", 0, 1, pconf);
                if (wrv == APR_SUCCESS && wd) {
                    apr_interval_time_t ival = apr_time_from_sec(refresh);
                    wrv = fn_reg(wd, ival, s, bs_load_watchdog_cb);
                } else if (wrv == APR_SUCCESS) {
                    wrv = APR_EGENERAL;
                }
                if (wrv == APR_SUCCESS) {
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                        "mod_botshield: load-state sampler enabled "
                        "every %d s%s%s%s",
                        refresh,
                        main_scfg->load_state_file ? " (external file " : "",
                        main_scfg->load_state_file
                          ? main_scfg->load_state_file : "",
                        main_scfg->load_state_file ? ")" : "");
                } else {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, wrv, s,
                        "mod_botshield: load-state watchdog "
                        "registration failed; load state will stay "
                        "at 'normal'");
                }
            } else {
                /* No mod_watchdog → load state is permanently
                 * NORMAL. Quiet; only worth logging if the operator
                 * configured a state file (active intent). */
                if (main_scfg->load_state_file) {
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                        "mod_botshield: mod_watchdog not loaded; "
                        "BotShieldLoadStateFile inert (state stays "
                        "normal). Load mod_watchdog to enable.");
                }
            }
        }
    }

    /* E13.1 — capacity headroom watchdog. Independent of load-state
     * config; runs whenever mod_watchdog is available. 60s tick is
     * generous — table populations move on minute-to-hour timescales
     * and the rewarn cooldown is 5 min anyway. */
    {
        APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *fn_get =
            APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
        APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *fn_reg =
            APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
        if (fn_get && fn_reg) {
            ap_watchdog_t *wd = NULL;
            apr_status_t wrv = fn_get(&wd,
                "mod_botshield_headroom", 0, 1, pconf);
            if (wrv == APR_SUCCESS && wd) {
                apr_interval_time_t ival = apr_time_from_sec(60);
                wrv = fn_reg(wd, ival, s, bs_headroom_watchdog_cb);
            } else if (wrv == APR_SUCCESS) {
                wrv = APR_EGENERAL;
            }
            if (wrv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_INFO, wrv, s,
                    "mod_botshield: headroom watchdog "
                    "registration failed; capacity warnings "
                    "will not fire (reactive cliff warnings "
                    "still in place)");
            }
        }
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

/* E13 — bucket key folds in ns_id so different namespaces probe
 * different starting positions for the same IP. The slot's ns_id
 * field is the authoritative match check; mixing ns_id into the
 * hash is a load-balancing optimization, not a correctness one. */
static apr_uint32_t bs_flagged_bucket(const unsigned char ip[16],
                                      apr_uint32_t ns_id)
{
    unsigned char buf[16 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)( ns_id        & 0xFF);
    buf[17] = (unsigned char)((ns_id >>  8) & 0xFF);
    buf[18] = (unsigned char)((ns_id >> 16) & 0xFF);
    buf[19] = (unsigned char)((ns_id >> 24) & 0xFF);
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key,
                                  buf, sizeof(buf));
    return (apr_uint32_t)(h % bs_shm.flagged_capacity);
}

/* Write into a slot under seqlock protection. Caller must hold the
 * global mutex. */
static void bs_flagged_write_slot(bs_flagged_ip_slot *slot,
                                  const unsigned char ip[16],
                                  apr_uint32_t flags, apr_int64_t expires_at,
                                  apr_uint32_t ns_id)
{
    apr_uint32_t v = apr_atomic_read32(&slot->version);
    apr_atomic_set32(&slot->version, v | 1U);   /* begin: odd */
    /* Ensure the version-odd store is visible before the payload stores. */
    memcpy(slot->ip, ip, 16);
    slot->flags      = flags;
    slot->expires_at = expires_at;
    slot->ns_id      = ns_id;
    /* Version-bump to even publishes the payload to readers. */
    apr_atomic_set32(&slot->version, (v | 1U) + 1U);
}

static void bs_flagged_ip_add(request_rec *r,
                              const unsigned char ip[16],
                              apr_uint32_t flag_bits, int ttl_seconds,
                              apr_uint32_t ns_id)
{
    if (!bs_shm.flagged_table || !bs_shm.mutex) return;
    if (!flag_bits) return;
    if (ttl_seconds <= 0) ttl_seconds = 3600;

    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_int64_t expires_at = now + ttl_seconds;
    apr_uint32_t base = bs_flagged_bucket(ip, ns_id);

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

        if (slot->flags && slot->ns_id == ns_id
            && memcmp(slot->ip, ip, 16) == 0) {
            /* Merge flags, refresh TTL to whichever is later. */
            apr_uint32_t merged = slot->flags | flag_bits;
            apr_int64_t later   = slot->expires_at > expires_at
                                  ? slot->expires_at : expires_at;
            bs_flagged_write_slot(slot, ip, merged, later, ns_id);
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
                          flag_bits, expires_at, ns_id);
    apr_global_mutex_unlock(bs_shm.mutex);
}

/* Read under seqlock. Returns 1 if the IP has a live entry, writing
 * the merged flag bitmap into *out_flags. 0 on miss or all retries
 * skipped. Readers never block writers; a caught-mid-write slot is
 * skipped (probe continues to the next). */
static int bs_flagged_ip_lookup(const unsigned char ip[16],
                                apr_uint32_t *out_flags,
                                apr_uint32_t ns_id)
{
    if (!bs_shm.flagged_table) return 0;

    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_uint32_t base = bs_flagged_bucket(ip, ns_id);

    for (unsigned i = 0; i < BS_FLAGGED_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.flagged_capacity;
        bs_flagged_ip_slot *slot = &bs_shm.flagged_table[idx];

        apr_uint32_t v1, v2;
        unsigned char  local_ip[16];
        apr_uint32_t   local_flags;
        apr_int64_t    local_expires;
        apr_uint32_t   local_ns;
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
            local_ns      = slot->ns_id;
            v2 = apr_atomic_read32(&slot->version);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;           /* slot too contended */
        if (local_flags == 0) continue;     /* empty */
        if (local_expires < now) continue;  /* stale */
        if (local_ns != ns_id) continue;    /* E13: different namespace */
        if (memcmp(local_ip, ip, 16) != 0) continue;

        *out_flags = local_flags;
        return 1;
    }
    return 0;
}

/* --- E9: strike-table helpers (repeated-429 escalation) ---
 *
 * Same open-addressing + per-slot seqlock idiom as flagged_table.
 * The hash key is (masked client_ip, rule_slot); collisions across
 * different rules for the same IP are valid — they just probe to
 * different buckets via the rule_slot mixin.
 *
 * Reads (escalation check) are lockless via the seqlock. Writes
 * (recording a 429 strike) take the global mutex, same shared one
 * the flagged-IP path uses. Strike accounting is approximate under
 * concurrent worker races — same posture as the rate-counter
 * windows themselves; a few off-by-ones in the strike count don't
 * change the user-visible behavior. */

static apr_uint32_t bs_strike_bucket(const unsigned char ip[16],
                                     apr_uint32_t rule_slot,
                                     apr_uint32_t ns_id)
{
    /* Mix rule_slot AND ns_id into the SipHash input. rule_slot
     * keeps probe windows from clustering when one IP misbehaves
     * on multiple rules; ns_id (E13) puts different namespaces in
     * different buckets for load-balancing — the slot's ns_id
     * field is the authoritative match check. */
    unsigned char buf[16 + 4 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)( rule_slot        & 0xFF);
    buf[17] = (unsigned char)((rule_slot >> 8 ) & 0xFF);
    buf[18] = (unsigned char)((rule_slot >> 16) & 0xFF);
    buf[19] = (unsigned char)((rule_slot >> 24) & 0xFF);
    buf[20] = (unsigned char)( ns_id            & 0xFF);
    buf[21] = (unsigned char)((ns_id >> 8 )     & 0xFF);
    buf[22] = (unsigned char)((ns_id >> 16)     & 0xFF);
    buf[23] = (unsigned char)((ns_id >> 24)     & 0xFF);
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key,
                                  buf, sizeof(buf));
    return (apr_uint32_t)(h % bs_shm.strike_capacity);
}

/* Seqlock-protected lookup. Returns 1 if (ip, rule_slot, ns_id)
 * has an active escalation (escalation_until > now), 0 otherwise. */
static int bs_strike_check_escalated(const unsigned char ip[16],
                                     apr_uint32_t rule_slot,
                                     apr_int64_t now,
                                     apr_uint32_t ns_id)
{
    if (!bs_shm.strike_table || bs_shm.strike_capacity == 0) return 0;
    apr_uint32_t base = bs_strike_bucket(ip, rule_slot, ns_id);

    for (unsigned i = 0; i < BS_STRIKE_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.strike_capacity;
        bs_strike_slot *slot = &bs_shm.strike_table[idx];

        apr_uint32_t v1, v2;
        unsigned char local_ip[16];
        apr_uint32_t  local_rule;
        apr_int64_t   local_until;
        apr_uint32_t  local_ns;
        int spins = 0;
        for (;;) {
            v1 = apr_atomic_read32(&slot->version);
            if (v1 & 1U) {
                if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
                continue;
            }
            local_rule  = slot->rule_slot;
            memcpy(local_ip, slot->ip, 16);
            local_until = slot->escalation_until;
            local_ns    = slot->ns_id;
            v2 = apr_atomic_read32(&slot->version);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;
        if (local_rule == BS_STRIKE_EMPTY) continue;
        if (local_rule != rule_slot) continue;
        if (local_ns != ns_id) continue;
        if (memcmp(local_ip, ip, 16) != 0) continue;
        return local_until > now;
    }
    return 0;
}

/* Strike accounting under the shared mutex. Bumps the (ip, rule)
 * counter inside its `per_sec` window, sets escalation_until on
 * threshold crossing. Returns 1 if THIS call crossed the threshold
 * from "not escalated" to "escalated" (caller logs the operator's
 * tag exactly once); 0 otherwise (still below threshold, or already
 * in the escalated state and just refreshing the TTL). */
static int bs_strike_record_429(request_rec *r,
                                const unsigned char ip[16],
                                apr_uint32_t rule_slot,
                                const bs_rate_escalate_entry *cfg,
                                apr_int64_t now,
                                apr_uint32_t ns_id)
{
    if (!bs_shm.strike_table || !bs_shm.mutex || !cfg) return 0;
    apr_uint32_t base = bs_strike_bucket(ip, rule_slot, ns_id);

    apr_status_t rv = apr_global_mutex_lock(bs_shm.mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: strike-table mutex_lock failed; "
            "dropping strike");
        return 0;
    }

    int matched_idx = -1;
    int empty_idx   = -1;
    for (unsigned i = 0; i < BS_STRIKE_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.strike_capacity;
        bs_strike_slot *slot = &bs_shm.strike_table[idx];
        if (slot->rule_slot == BS_STRIKE_EMPTY) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (slot->rule_slot == rule_slot
            && slot->ns_id == ns_id
            && memcmp(slot->ip, ip, 16) == 0) {
            matched_idx = (int)idx;
            break;
        }
    }

    int target_idx;
    if (matched_idx >= 0) {
        target_idx = matched_idx;
    } else if (empty_idx >= 0) {
        target_idx = empty_idx;
    } else {
        static apr_time_t last_warn = 0;
        apr_time_t now_t = apr_time_now();
        if (now_t - last_warn > apr_time_from_sec(60)) {
            last_warn = now_t;
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: strike-table probe saturated at "
                "bucket %u (capacity %" APR_SIZE_T_FMT "); "
                "overwriting — consider raising "
                "BotShieldRateLimitEscalateCapacity",
                base, bs_shm.strike_capacity);
        }
        target_idx = (int)base;
    }

    bs_strike_slot *slot = &bs_shm.strike_table[target_idx];
    apr_uint32_t v0 = apr_atomic_read32(&slot->version);
    apr_atomic_set32(&slot->version, v0 | 1U);   /* begin write */

    int crossed = 0;
    apr_uint32_t now_sec = (apr_uint32_t)now;
    int fresh_slot = (matched_idx < 0);
    if (fresh_slot) {
        memcpy(slot->ip, ip, 16);
        slot->rule_slot           = rule_slot;
        slot->ns_id               = ns_id;
        slot->strike_window_start = now_sec;
        slot->strike_count        = 1;
        slot->escalation_until    = 0;
    } else {
        /* Window roll: reset count when the per-window has passed. */
        if (slot->strike_window_start == 0
            || now_sec - slot->strike_window_start >= cfg->per_sec) {
            slot->strike_window_start = now_sec;
            slot->strike_count        = 1;
        } else {
            slot->strike_count++;
        }
    }
    if (slot->strike_count >= cfg->strikes) {
        apr_int64_t prev_until = slot->escalation_until;
        slot->escalation_until = now + cfg->ttl_sec;
        if (prev_until <= now) crossed = 1;
    }

    apr_atomic_set32(&slot->version, (v0 | 1U) + 1U);   /* publish */
    apr_global_mutex_unlock(bs_shm.mutex);
    return crossed;
}

/* --- E10: challenge-safeguard helpers ---
 *
 * Anti-loop hysteresis. The rate-counter-strike pair (E9) said
 * "this client is hitting our rate limit harder than 429 is
 * deterring"; safeguard says "this client keeps getting presented
 * a challenge but never solves it." Different signal, same
 * mitigation pattern (per-IP SHM, short-lived trip state).
 *
 * Why safeguard isn't just another E9-style directive: the 429
 * case is behavior BotShield explicitly provoked ("you asked us
 * to rate-limit this cohort"). The safeguard case is a failure
 * mode — clients who are bad at solving challenges, whether from
 * malice (refusing to run JS) or infrastructure (CSP strips our
 * interstitial, blockers, privacy tooling). It applies everywhere
 * a challenge gets issued, independent of operator rule-sets. */

static int bs_safeguard_effective_int(int v, int dflt)
{
    return (v > 0) ? v : dflt;
}

static apr_uint32_t bs_safeguard_bucket(const unsigned char ip[16],
                                        apr_uint32_t ns_id)
{
    /* E13 — fold ns_id into the hash so vhosts with different
     * reputation namespaces get disjoint bucket distributions. */
    unsigned char buf[16 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)(ns_id      );
    buf[17] = (unsigned char)(ns_id >>  8);
    buf[18] = (unsigned char)(ns_id >> 16);
    buf[19] = (unsigned char)(ns_id >> 24);
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key, buf, sizeof(buf));
    /* Mix a distinct constant so this table's bucket distribution
     * isn't perfectly correlated with flagged_table / strike_table
     * for the same IP — reduces probe-window collisions across
     * tables under high saturation. */
    h ^= 0xC0FFEE00BA5EBA11ULL;
    return (apr_uint32_t)(h % bs_shm.safeguard_capacity);
}

/* Lockless read. Returns 1 if the IP has an active safeguard
 * (safeguard_until > now), 0 otherwise. Seqlock discipline matches
 * bs_flagged_ip_lookup and bs_strike_check_escalated. */
static int bs_safeguard_check(const unsigned char ip[16], apr_int64_t now,
                              apr_uint32_t ns_id)
{
    if (!bs_shm.safeguard_table || bs_shm.safeguard_capacity == 0) return 0;
    apr_uint32_t base = bs_safeguard_bucket(ip, ns_id);

    for (unsigned i = 0; i < BS_SAFEGUARD_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.safeguard_capacity;
        bs_safeguard_slot *slot = &bs_shm.safeguard_table[idx];

        apr_uint32_t v1, v2;
        apr_uint32_t  local_used;
        apr_uint32_t  local_ns_id;
        unsigned char local_ip[16];
        apr_int64_t   local_until;
        int spins = 0;
        for (;;) {
            v1 = apr_atomic_read32(&slot->version);
            if (v1 & 1U) {
                if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
                continue;
            }
            local_used  = slot->used;
            local_ns_id = slot->ns_id;
            memcpy(local_ip, slot->ip, 16);
            local_until = slot->safeguard_until;
            v2 = apr_atomic_read32(&slot->version);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;
        if (!local_used) continue;
        if (local_ns_id != ns_id) continue;
        if (memcmp(local_ip, ip, 16) != 0) continue;
        return local_until > now;
    }
    return 0;
}

/* Bump the presentation counter for this IP under the shared
 * mutex. Trips safeguard when `present_count` crosses
 * `threshold` inside `window` seconds. Each call during an
 * already-active safeguard refreshes safeguard_until (TTL slides
 * on the last presentation) so clients that stay broken keep
 * benefiting rather than oscillating at window boundaries. */
static void bs_safeguard_record_presentation(request_rec *r,
                                             bs_server_cfg *scfg,
                                             const unsigned char ip[16],
                                             apr_int64_t now,
                                             apr_uint32_t ns_id)
{
    if (!bs_shm.safeguard_table || !bs_shm.mutex || !scfg) return;
    int threshold = bs_safeguard_effective_int(scfg->safeguard_threshold,
                        BS_DEFAULT_SAFEGUARD_THRESHOLD);
    int window    = bs_safeguard_effective_int(scfg->safeguard_window,
                        BS_DEFAULT_SAFEGUARD_WINDOW);
    int ttl       = bs_safeguard_effective_int(scfg->safeguard_ttl,
                        BS_DEFAULT_SAFEGUARD_TTL);

    apr_uint32_t base = bs_safeguard_bucket(ip, ns_id);
    apr_status_t rv = apr_global_mutex_lock(bs_shm.mutex);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: safeguard-table mutex_lock failed; "
            "dropping presentation record");
        return;
    }

    int matched_idx = -1;
    int empty_idx   = -1;
    for (unsigned i = 0; i < BS_SAFEGUARD_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.safeguard_capacity;
        bs_safeguard_slot *slot = &bs_shm.safeguard_table[idx];
        if (!slot->used) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (slot->ns_id != ns_id) continue;
        if (memcmp(slot->ip, ip, 16) == 0) {
            matched_idx = (int)idx;
            break;
        }
    }

    int target_idx;
    if (matched_idx >= 0) {
        target_idx = matched_idx;
    } else if (empty_idx >= 0) {
        target_idx = empty_idx;
    } else {
        static apr_time_t last_warn = 0;
        apr_time_t now_t = apr_time_now();
        if (now_t - last_warn > apr_time_from_sec(60)) {
            last_warn = now_t;
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: safeguard-table probe saturated at "
                "bucket %u (capacity %" APR_SIZE_T_FMT "); overwriting "
                "— consider raising BotShieldSafeguardCapacity",
                base, bs_shm.safeguard_capacity);
        }
        target_idx = (int)base;
    }

    bs_safeguard_slot *slot = &bs_shm.safeguard_table[target_idx];
    apr_uint32_t v0 = apr_atomic_read32(&slot->version);
    apr_atomic_set32(&slot->version, v0 | 1U);   /* begin write */

    apr_uint32_t now_sec = (apr_uint32_t)now;
    int fresh_slot = (matched_idx < 0);
    if (fresh_slot) {
        memcpy(slot->ip, ip, 16);
        slot->used                 = 1;
        slot->ns_id                = ns_id;
        slot->present_window_start = now_sec;
        slot->present_count        = 1;
        slot->safeguard_until      = 0;
    } else if (slot->present_window_start == 0
               || now_sec - slot->present_window_start >= (apr_uint32_t)window) {
        /* Window rolled — start fresh counting from this presentation. */
        slot->present_window_start = now_sec;
        slot->present_count        = 1;
    } else {
        slot->present_count++;
    }
    if (slot->present_count >= (apr_uint32_t)threshold) {
        slot->safeguard_until = now + ttl;
    }

    apr_atomic_set32(&slot->version, (v0 | 1U) + 1U);
    apr_global_mutex_unlock(bs_shm.mutex);
}

/* Clear the (ip) entry. Called when a valid _bs_verified lands for
 * this IP — proves the client CAN solve, so accumulated presentation
 * history was noise (probably transient) and we want a fresh slate.
 * No-op if the entry isn't found; silent on error. */
static void bs_safeguard_clear(const unsigned char ip[16],
                               apr_uint32_t ns_id)
{
    if (!bs_shm.safeguard_table || !bs_shm.mutex) return;
    apr_uint32_t base = bs_safeguard_bucket(ip, ns_id);

    if (apr_global_mutex_lock(bs_shm.mutex) != APR_SUCCESS) return;
    for (unsigned i = 0; i < BS_SAFEGUARD_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.safeguard_capacity;
        bs_safeguard_slot *slot = &bs_shm.safeguard_table[idx];
        if (!slot->used) continue;
        if (slot->ns_id != ns_id) continue;
        if (memcmp(slot->ip, ip, 16) != 0) continue;
        apr_uint32_t v0 = apr_atomic_read32(&slot->version);
        apr_atomic_set32(&slot->version, v0 | 1U);
        slot->used                 = 0;
        slot->ns_id                = 0;
        slot->present_window_start = 0;
        slot->present_count        = 0;
        slot->safeguard_until      = 0;
        memset(slot->ip, 0, 16);
        apr_atomic_set32(&slot->version, (v0 | 1U) + 1U);
        break;
    }
    apr_global_mutex_unlock(bs_shm.mutex);
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
 * each of the k indices as (h1 + i*h2) mod m_bits.
 *
 * E13 — ns_id is folded into both h1 and h2 inputs so different
 * namespaces compute disjoint bit-position sets. Same physical
 * Bloom buffer, logically isolated states. The K=7 bit-position
 * draws make false-positive across namespaces negligible at our
 * load factors. */
static void bs_bloom_indices(const unsigned char ip[16],
                             apr_uint32_t *out, apr_size_t m_bits,
                             apr_uint32_t ns_id)
{
    unsigned char buf[16 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)( ns_id        & 0xFF);
    buf[17] = (unsigned char)((ns_id >>  8) & 0xFF);
    buf[18] = (unsigned char)((ns_id >> 16) & 0xFF);
    buf[19] = (unsigned char)((ns_id >> 24) & 0xFF);
    apr_uint64_t h1 = bs_siphash24(bs_shm.header->siphash_key,
                                   buf, sizeof(buf));
    buf[0] ^= 0x9e;   /* domain separator for the second hash */
    apr_uint64_t h2 = bs_siphash24(bs_shm.header->siphash_key,
                                   buf, sizeof(buf));
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

static void bs_bloom_add(const unsigned char ip[16], apr_uint32_t ns_id)
{
    if (!bs_shm.bloom_bufs[0]) return;
    bs_bloom_rotate_if_due((apr_int64_t)apr_time_sec(apr_time_now()));

    apr_size_t m_bits = (apr_size_t)bs_shm.bloom_buf_bytes * 8;
    apr_uint32_t indices[BS_BLOOM_K];
    bs_bloom_indices(ip, indices, m_bits, ns_id);

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
static int bs_bloom_seen(const unsigned char ip[16], apr_uint32_t ns_id)
{
    if (!bs_shm.bloom_bufs[0]) return 0;
    apr_size_t m_bits = (apr_size_t)bs_shm.bloom_buf_bytes * 8;
    apr_uint32_t indices[BS_BLOOM_K];
    bs_bloom_indices(ip, indices, m_bits, ns_id);

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
/* E13 — bumped from 1 to 2: bs_flagged_ip_slot grew an `ns_id`
 * field for per-vhost reputation namespacing. Old (v1) state
 * files are rejected with a NOTICE and the table starts fresh —
 * one-time cost on upgrade, no slot-level migration code needed
 * because flagged-IP TTLs are short anyway and most entries
 * would have aged out. */
#define BS_STATE_FORMAT_VERSION   2
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

/* --- E1 directive setters (Allow family) --- */

/* BotShieldAllow on|off — master gate for the Allow-list family.
 * Default off (opt-in). Applied at server scope. */
static const char *bs_set_allow_enabled(cmd_parms *cmd, void *dconf,
                                        int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->allow_enabled = flag ? 1 : 0;
    return NULL;
}

/* Character policy for bot-name tokens: lowercase letters, digits,
 * hyphen. Used as the hash key and the default ranges-file basename.
 * Rejects anything that could create path-traversal surprises or
 * cross-host confusion. */
static int bs_bot_name_valid(const char *s)
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
static const char *bs_set_allow_bot(cmd_parms *cmd, void *dconf,
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

/* Parse a "per" unit token into seconds. We accept sec/min/hour and
 * their single-letter aliases so operators can write whichever reads
 * best inline with their budget. Collapsed-unit forms like "60/min"
 * are deliberately not supported — Apache tokenizes args for us and
 * splitting them out keeps the directive parseable by eye. */
static int bs_rate_unit_seconds(const char *u)
{
    if (!u || !*u) return 0;
    if (!strcasecmp(u, "sec") || !strcasecmp(u, "s")
     || !strcasecmp(u, "second") || !strcasecmp(u, "seconds")) return 1;
    if (!strcasecmp(u, "min") || !strcasecmp(u, "m")
     || !strcasecmp(u, "minute") || !strcasecmp(u, "minutes")) return 60;
    if (!strcasecmp(u, "hour") || !strcasecmp(u, "h")
     || !strcasecmp(u, "hours")) return 3600;
    return 0;
}

/* BotShieldRateLimit <name> <budget> <per-unit> <ua> <ipspec> — cohort
 * rate-limit. Cohort semantics mirror BotShieldAllowBot (UA substring,
 * polymorphic ipspec, '*' for "any" on either axis). Both-'*' is
 * rejected because that would rate-limit every request on the server.
 * Budget + window are stored as-is; SHM slot assignment happens in
 * post_config.
 *
 * Apache doesn't ship AP_INIT_TAKE4/5, so this uses TAKE_ARGV and
 * enforces argc itself. */
/* E12 — parse the optional trailing `mode=enforce|observe` argv
 * token shared by BotShieldRateLimit and BotShieldBlockPath. The
 * directive grammar is positional (5 args for rate-limit, 4 for
 * block-path), so this is strict: the token must be the LAST
 * argument and it must be `mode=...`. Returns the parsed mode in
 * *out_mode and shrinks *argc by 1 if the token was consumed. */
static const char *bs_parse_optional_mode(apr_pool_t *p,
                                          const char *dname,
                                          int *argc,
                                          char *const argv[],
                                          int *out_mode)
{
    *out_mode = BS_TMODE_ENFORCE;
    if (*argc <= 0) return NULL;
    const char *last = argv[*argc - 1];
    if (strncmp(last, "mode=", 5) != 0) return NULL;
    const char *val = last + 5;
    if (!strcasecmp(val, "enforce")) {
        *out_mode = BS_TMODE_ENFORCE;
    } else if (!strcasecmp(val, "observe")) {
        *out_mode = BS_TMODE_OBSERVE;
    } else {
        return apr_psprintf(p,
            "%s: mode='%s' must be 'enforce' or 'observe'", dname, val);
    }
    (*argc)--;
    return NULL;
}

static const char *bs_set_rate_limit(cmd_parms *cmd, void *dconf,
                                     int argc, char *const argv[])
{
    (void)dconf;
    /* E12 — strip optional trailing mode= token before counting
     * positional args. */
    int mode = BS_TMODE_ENFORCE;
    {
        const char *merr = bs_parse_optional_mode(cmd->pool,
            "BotShieldRateLimit", &argc, argv, &mode);
        if (merr) return merr;
    }
    if (argc != 5) {
        return "BotShieldRateLimit: expects exactly 5 args — "
               "<name> <budget> <per> <ua> <ipspec> "
               "[mode=enforce|observe]";
    }
    const char *name     = argv[0];
    const char *budget_s = argv[1];
    const char *per_s    = argv[2];
    const char *ua       = argv[3];
    const char *ipspec   = argv[4];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimit: name '%s' must be [a-z0-9-]{1,32}", name);
    }
    char *end = NULL;
    long budget = strtol(budget_s, &end, 10);
    if (!end || *end || budget <= 0 || budget > 1000000) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimit: budget '%s' must be a positive integer "
            "≤ 1000000", budget_s);
    }
    int unit = bs_rate_unit_seconds(per_s);
    if (unit == 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimit: per '%s' must be one of "
            "sec/min/hour (or s/m/h)", per_s);
    }

    bs_rate_limit_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name       = apr_pstrdup(cmd->pool, name);
    e->budget     = (apr_uint32_t)budget;
    e->window_sec = (apr_uint32_t)unit;
    e->shm_slot   = -1;
    e->mode       = mode;   /* E12 */
    const char *err = bs_cohort_resolve(cmd, &e->cohort, ua, ipspec);
    if (err) return apr_pstrcat(cmd->pool,
        "BotShieldRateLimit: ", err, NULL);

    /* Upsert by name — a re-declaration replaces the entry in its
     * existing slot, preserving declaration order for the surrounding
     * rules. New names append. */
    for (int i = 0; i < scfg->rate_limits->nelts; i++) {
        bs_rate_limit_entry *ex =
            APR_ARRAY_IDX(scfg->rate_limits, i, bs_rate_limit_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->rate_limits, i, bs_rate_limit_entry *) = e;
            return NULL;
        }
    }
    *(bs_rate_limit_entry **)apr_array_push(scfg->rate_limits) = e;
    return NULL;
}

/* E9 — BotShieldRateLimitEscalate <rate-name> <strikes> <per>
 *      [status=<code>] [ttl=<sec>] [log=<tag>]
 *
 * Promotes repeated 429s on a named BotShieldRateLimit rule into a
 * stricter status (default 403) for a short TTL. The cross-rule
 * link is by name; the post_config phase resolves it into a direct
 * pointer on the matching bs_rate_limit_entry so the request-time
 * path branches in O(1).
 *
 * `<per>` accepts the same sec/min/hour suffixes as BotShieldRateLimit. */
static const char *bs_set_rate_limit_escalate(cmd_parms *cmd, void *dconf,
                                              int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 3) {
        return "BotShieldRateLimitEscalate: expects <rate-name> "
               "<strikes> <per> [key=value ...]";
    }
    const char *rule_name = argv[0];
    const char *strikes_s = argv[1];
    const char *per_s     = argv[2];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(rule_name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimitEscalate: rate-name '%s' must be "
            "[a-z0-9-]{1,32}", rule_name);
    }
    char *end = NULL;
    long strikes = strtol(strikes_s, &end, 10);
    if (!end || *end || strikes <= 0 || strikes > 1000000) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimitEscalate: strikes '%s' must be a "
            "positive integer <= 1000000", strikes_s);
    }
    int per = bs_rate_unit_seconds(per_s);
    if (per == 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimitEscalate: per '%s' must be one of "
            "sec/min/hour (or s/m/h)", per_s);
    }

    bs_rate_escalate_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->rule_name   = apr_pstrdup(cmd->pool, rule_name);
    e->strikes     = (apr_uint32_t)strikes;
    e->per_sec     = (apr_uint32_t)per;
    e->status_code = 403;       /* default per PLAN.md E9 */
    e->ttl_sec     = 1800;      /* default per PLAN.md E9 */
    e->log_tag     = NULL;

    for (int i = 3; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq  = strchr(arg, '=');
        if (!eq) {
            return apr_psprintf(cmd->pool,
                "BotShieldRateLimitEscalate: extra arg '%s' must be "
                "key=value", arg);
        }
        apr_size_t klen = (apr_size_t)(eq - arg);
        const char *val = eq + 1;
        #define BS_REK(n) (klen == sizeof(n)-1 && \
                           strncasecmp(arg, n, sizeof(n)-1) == 0)
        if (BS_REK("status")) {
            char *e2 = NULL;
            long code = strtol(val, &e2, 10);
            if (!e2 || *e2 || code < 100 || code > 599) {
                return apr_psprintf(cmd->pool,
                    "BotShieldRateLimitEscalate: status='%s' must be "
                    "an HTTP code 100..599", val);
            }
            if (code == 429) {
                /* Same code as the normal rate-limit response — no
                 * escalation effect. Reject so operators don't
                 * accidentally write a no-op directive. */
                return "BotShieldRateLimitEscalate: status=429 is a "
                       "no-op (same as the normal rate-limit "
                       "response); pick a stricter code (default 403)";
            }
            e->status_code = (int)code;
        } else if (BS_REK("ttl")) {
            char *e2 = NULL;
            long t = strtol(val, &e2, 10);
            if (!e2 || *e2 || t < 1 || t > 86400 * 30) {
                return apr_psprintf(cmd->pool,
                    "BotShieldRateLimitEscalate: ttl='%s' must be "
                    "1..2592000 seconds", val);
            }
            e->ttl_sec = (int)t;
        } else if (BS_REK("log")) {
            e->log_tag = apr_pstrdup(cmd->pool, val);
        } else {
            return apr_psprintf(cmd->pool,
                "BotShieldRateLimitEscalate: unknown key '%.*s' "
                "(known: status, ttl, log)", (int)klen, arg);
        }
        #undef BS_REK
    }

    /* Upsert by rule_name. Re-declaration replaces in place. */
    for (int i = 0; i < scfg->rate_escalates->nelts; i++) {
        bs_rate_escalate_entry *ex = APR_ARRAY_IDX(
            scfg->rate_escalates, i, bs_rate_escalate_entry *);
        if (strcmp(ex->rule_name, e->rule_name) == 0) {
            APR_ARRAY_IDX(scfg->rate_escalates, i,
                          bs_rate_escalate_entry *) = e;
            return NULL;
        }
    }
    *(bs_rate_escalate_entry **)apr_array_push(scfg->rate_escalates) = e;
    return NULL;
}

/* E9 — BotShieldRateLimitEscalateCapacity <n>. SHM slot count for
 * the strike table. Per-server-scope; only the main server's value
 * is used at post_config (the strike table is module-global). */
static const char *bs_set_rate_escalate_capacity(cmd_parms *cmd,
                                                 void *dconf,
                                                 const char *arg)
{
    (void)dconf;
    bs_warn_if_virtual_scope(cmd, "BotShieldRateLimitEscalateCapacity");
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end
        || n < BS_STRIKE_MIN_SLOTS || n > BS_STRIKE_MAX_SLOTS) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimitEscalateCapacity: '%s' must be %d..%d",
            arg, BS_STRIKE_MIN_SLOTS, BS_STRIKE_MAX_SLOTS);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->strike_capacity = (int)n;
    return NULL;
}

/* E10 — BotShieldSafeguard on|off. Master switch for the
 * anti-loop hysteresis. Off = pre-E10 behavior (challenge every
 * request that tier dispatch sends to challenge). On = track
 * presentations per IP and flip to a short-lived pass-through
 * after BotShieldSafeguardThreshold presentations within
 * BotShieldSafeguardWindow seconds without a solve.
 *
 * Default off: opt-in because safeguard does grant temporary
 * pass-through, which some operators will consider too soft
 * regardless of the narrow conditions. Operators who've seen
 * the stuck-loop failure mode in practice enable it. */
static const char *bs_set_safeguard(cmd_parms *cmd, void *dconf, int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->safeguard_enabled = flag ? 1 : 0;
    return NULL;
}

/* E10 — BotShieldSafeguardThreshold <N>. Number of presentations
 * within the window before safeguard trips. */
static const char *bs_set_safeguard_threshold(cmd_parms *cmd,
                                              void *dconf,
                                              const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 1000) {
        return apr_psprintf(cmd->pool,
            "BotShieldSafeguardThreshold: '%s' must be 1..1000", arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->safeguard_threshold = (int)n;
    return NULL;
}

/* E10 — BotShieldSafeguardWindow <seconds>. Counting window for
 * the threshold. Beyond this, old presentations roll off and the
 * counter resets on the next presentation. */
static const char *bs_set_safeguard_window(cmd_parms *cmd,
                                           void *dconf,
                                           const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 86400) {
        return apr_psprintf(cmd->pool,
            "BotShieldSafeguardWindow: '%s' must be 1..86400 seconds",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->safeguard_window = (int)n;
    return NULL;
}

/* E10 — BotShieldSafeguardTTL <seconds>. How long the safeguard
 * state lasts after the last presentation. Slides on each fresh
 * presentation during active safeguard (TTL resets) so a client
 * that stays broken doesn't oscillate at window boundaries. */
static const char *bs_set_safeguard_ttl(cmd_parms *cmd,
                                        void *dconf,
                                        const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 86400 * 7) {
        return apr_psprintf(cmd->pool,
            "BotShieldSafeguardTTL: '%s' must be 1..%d seconds",
            arg, 86400 * 7);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->safeguard_ttl = (int)n;
    return NULL;
}

/* E10 — BotShieldSafeguardCapacity <n>. SHM slot count. Same
 * per-server-scope convention as the other SHM-sizing directives:
 * only the main server's value is consulted at post_config. */
static const char *bs_set_safeguard_capacity(cmd_parms *cmd,
                                             void *dconf,
                                             const char *arg)
{
    (void)dconf;
    bs_warn_if_virtual_scope(cmd, "BotShieldSafeguardCapacity");
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end
        || n < BS_SAFEGUARD_MIN_SLOTS || n > BS_SAFEGUARD_MAX_SLOTS) {
        return apr_psprintf(cmd->pool,
            "BotShieldSafeguardCapacity: '%s' must be %d..%d",
            arg, BS_SAFEGUARD_MIN_SLOTS, BS_SAFEGUARD_MAX_SLOTS);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->safeguard_capacity = (int)n;
    return NULL;
}

/* E13 — BotShieldShareScope <token>. Per-vhost reputation
 * namespacing override. Default: each vhost auto-isolates by
 * siphash(ServerName) — different ServerNames don't share
 * flagged-IP / strike / safeguard / Bloom state. Two vhosts that
 * should share state set the same token here; same string → same
 * ns_id → shared rows in SHM.
 *
 * Empty token treated as "fall back to ServerName default" so
 * `BotShieldShareScope ""` is a config error rather than a
 * confusing reset. */
static const char *bs_set_share_scope(cmd_parms *cmd, void *dconf,
                                      const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldShareScope: token required (use a "
               "non-empty string; default isolation derives ns_id "
               "from ServerName when this directive is absent)";
    }
    /* Bound the token length defensively; long strings are pointless
     * since we hash to u32. */
    if (strlen(arg) > 128) {
        return "BotShieldShareScope: token over 128 chars";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->share_scope_token = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* E14 — BotShieldFlag <name> [penalty=N] [next_difficulty=±N]
 * [next_tier=silent|form|captcha]. Operator-side override of a
 * registered flag bit's metadata.
 *
 * The flag NAME determines the bit; the directive lets operators
 * tune what consequences riding that bit triggers without rewriting
 * every BotShieldFeedbackTrigger / BotShieldPathTrigger that writes
 * the flag. One declaration captures the policy for the whole
 * deployment.
 *
 * All three keys are optional; absent keys leave the prior (built-in
 * or last-set) value alone. Multiple BotShieldFlag directives for
 * the same name compose — last write wins per key. */
static const char *bs_set_flag(cmd_parms *cmd, void *dconf,
                               int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 1) {
        return "BotShieldFlag: expects <name> [penalty=N] "
               "[next_difficulty=±N] [next_tier=silent|form|captcha]";
    }
    const char *name = argv[0];
    bs_flag_meta *m = bs_flag_meta_for_name(name);
    if (!m) {
        return apr_psprintf(cmd->pool,
            "BotShieldFlag: unknown flag '%s'. Known flags: "
            "honeypot_hit, scanner_probe, fake_bot, pow_fail_streak, "
            "app_verified_human, app_verified_session, "
            "app_trust_signal", name);
    }
    if (argc < 2) {
        return apr_psprintf(cmd->pool,
            "BotShieldFlag: '%s' needs at least one key=value "
            "(penalty / next_difficulty / next_tier)", name);
    }
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq  = strchr(arg, '=');
        if (!eq) {
            return apr_psprintf(cmd->pool,
                "BotShieldFlag '%s': extra arg '%s' must be key=value",
                name, arg);
        }
        apr_size_t klen = (apr_size_t)(eq - arg);
        const char *val = eq + 1;
        #define BS_FK(n) (klen == sizeof(n)-1 && \
                          strncasecmp(arg, n, sizeof(n)-1) == 0)
        if (BS_FK("penalty")) {
            char *e2 = NULL;
            long p = strtol(val, &e2, 10);
            if (!e2 || *e2 || p < -1000 || p > 1000) {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlag '%s': penalty='%s' must be an "
                    "integer in -1000..1000", name, val);
            }
            m->penalty = (int)p;
        } else if (BS_FK("next_difficulty")) {
            char *e2 = NULL;
            long d = strtol(val, &e2, 10);
            if (!e2 || *e2 || d < -BS_MAX_DIFFICULTY_HARDCAP
                           || d >  BS_MAX_DIFFICULTY_HARDCAP) {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlag '%s': next_difficulty='%s' must be "
                    "an integer in -%d..+%d", name, val,
                    BS_MAX_DIFFICULTY_HARDCAP,
                    BS_MAX_DIFFICULTY_HARDCAP);
            }
            m->next_difficulty_delta = (int)d;
        } else if (BS_FK("next_tier")) {
            if      (strcasecmp(val, "pass")    == 0) m->next_tier_floor = BS_TIER_PASS;
            else if (strcasecmp(val, "silent")  == 0) m->next_tier_floor = BS_TIER_SILENT;
            else if (strcasecmp(val, "form")    == 0) m->next_tier_floor = BS_TIER_HARD;
            else if (strcasecmp(val, "captcha") == 0) m->next_tier_floor = BS_TIER_CAPTCHA;
            else {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlag '%s': next_tier='%s' must be one "
                    "of pass / silent / form / captcha", name, val);
            }
        } else {
            return apr_psprintf(cmd->pool,
                "BotShieldFlag '%s': unknown key '%.*s' "
                "(want penalty / next_difficulty / next_tier)",
                name, (int)klen, arg);
        }
        #undef BS_FK
    }
    return NULL;
}

/* E14 — BotShieldMaxDifficulty <N>. Server-scope ceiling for the
 * effective PoW difficulty after BotShieldFlag's adaptive bumps. The
 * existing BotShieldDifficulty range is 1..8 leading hex zeros
 * (already astronomical at 8 = 2^32 hashes). Adaptive bumps from
 * BotShieldFlag are clamped against this max. Default 8 — operators
 * who actually want adaptive headroom raise this explicitly so the
 * higher-cost ceiling is intentional. */
static const char *bs_set_max_difficulty(cmd_parms *cmd, void *dconf,
                                         const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > BS_MAX_DIFFICULTY_HARDCAP) {
        return apr_psprintf(cmd->pool,
            "BotShieldMaxDifficulty: '%s' must be an integer 1..%d",
            arg, BS_MAX_DIFFICULTY_HARDCAP);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->max_difficulty = (int)n;
    return NULL;
}

/* E15 — BotShieldForgivenessCapPerHour <N>. Server-
 * scope cap on the points of forgiveness any one cookie can earn
 * inside a rolling 1-hour window. 0 disables the cap (legacy
 * behavior). Range 1..1000 — beyond that the cap is effectively
 * absent anyway. */
static const char *bs_set_forgive_cap(cmd_parms *cmd, void *dconf,
                                      const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 0 || n > 1000) {
        return apr_psprintf(cmd->pool,
            "BotShieldForgivenessCapPerHour: '%s' must be an integer "
            "0..1000 (0 disables)", arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    /* Use 1 as a sentinel for "explicit 0 = disabled" so the merge's
     * "> 0 wins" doesn't lose an explicit-zero override; map 0 input
     * to a special sentinel that the apply helper treats as disabled.
     * Simplest: use INT_MAX as "uncapped" and let merge work normally. */
    scfg->forgive_cap_per_hour = (n == 0) ? INT_MAX : (int)n;
    return NULL;
}

/* Apply the per-cookie forgiveness cap. Modifies *consumed and
 * *window_start in place (reflecting the cookie state we'll write
 * out) and returns the number of points actually granted, which may
 * be less than `requested` if the cap kicks in. Window rolls if more
 * than BS_FORGIVE_WINDOW_SEC has passed since window_start. */
static int bs_forgiveness_apply_cap(int requested,
                                    int cap,
                                    apr_uint32_t now_sec,
                                    apr_uint32_t *window_start,
                                    apr_uint32_t *consumed)
{
    if (requested <= 0) return requested;
    if (cap <= 0 || cap == INT_MAX) {
        /* Uncapped: still update the window state for observability. */
        if (*window_start == 0 ||
            now_sec - *window_start >= BS_FORGIVE_WINDOW_SEC) {
            *window_start = now_sec;
            *consumed = 0;
        }
        *consumed = (apr_uint32_t)((apr_uint64_t)*consumed + requested
                                    > APR_UINT32_MAX
                                    ? APR_UINT32_MAX
                                    : *consumed + requested);
        return requested;
    }
    if (*window_start == 0 ||
        now_sec - *window_start >= BS_FORGIVE_WINDOW_SEC) {
        *window_start = now_sec;
        *consumed = 0;
    }
    int remaining = cap - (int)*consumed;
    if (remaining < 0) remaining = 0;
    int granted = (requested < remaining) ? requested : remaining;
    *consumed = (apr_uint32_t)(*consumed + granted);
    return granted;
}

/* E12 — BotShieldShadowMode on|off. Server-scope master switch
 * for dry-run enforcement. When on, every trigger / rate-limit /
 * block-path rule behaves as if mode=observe regardless of its
 * per-rule setting. Operators stage a whole config revision in one
 * shot, watch the decision log, then flip off to enforce. Off is
 * the default — operators opt in. */
static const char *bs_set_shadow_mode(cmd_parms *cmd, void *dconf,
                                      int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->shadow_mode = flag ? 1 : 0;
    return NULL;
}

/* E11 — BotShieldLoadStateFile <path>. Operator-writable file
 * whose body is `normal`, `warm`, or `hot` (whitespace tolerated).
 * Watchdog stat-polls mtime once per refresh tick; only re-reads
 * when mtime changed. Most-severe-wins merging means an external
 * `hot` overrides any internal sensing decision. */
static const char *bs_set_load_state_file(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldLoadStateFile: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldLoadStateFile: path must be absolute";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_state_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* E11 — BotShieldLoadRefreshInterval <seconds>. How often the
 * watchdog samples + reads the external file. Default 1s; the
 * lockless cached read on the request path keeps this from
 * affecting hot-path cost. */
static const char *bs_set_load_refresh(cmd_parms *cmd, void *dconf,
                                       const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 60) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadRefreshInterval: '%s' must be 1..60 seconds",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_refresh_sec = (int)n;
    return NULL;
}

/* E11 — BotShieldLoadWarmThreshold <percent>. Busy-worker ratio
 * (percent of total worker slots) at which a sample is classified
 * warm. Default 65. */
static const char *bs_set_load_warm_pct(cmd_parms *cmd, void *dconf,
                                        const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 99) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadWarmThreshold: '%s' must be 1..99 (percent)",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_warm_pct = (int)n;
    return NULL;
}

/* E11 — BotShieldLoadHotThreshold <percent>. Default 85; must be
 * strictly greater than the warm threshold. */
static const char *bs_set_load_hot_pct(cmd_parms *cmd, void *dconf,
                                       const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 99) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadHotThreshold: '%s' must be 1..99 (percent)",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_hot_pct = (int)n;
    return NULL;
}

/* BotShieldBlockPath <name> <path-glob> <ua> <ipspec> — cohort-
 * conditional path block. Matching requests get 403 + a scoring
 * hook. Glob semantics are minimal in v1 (prefix / trailing '*' /
 * trailing '$'); full RFC 9309 wildcards arrive in E2.2 with
 * robots.c so block-paths derived from robots.txt Disallow behave
 * identically to the reference parser.
 *
 * Uses TAKE_ARGV (Apache has no TAKE4). */
static const char *bs_set_block_path(cmd_parms *cmd, void *dconf,
                                     int argc, char *const argv[])
{
    (void)dconf;
    /* E12 — strip optional trailing mode= token before counting
     * positional args. */
    int mode = BS_TMODE_ENFORCE;
    {
        const char *merr = bs_parse_optional_mode(cmd->pool,
            "BotShieldBlockPath", &argc, argv, &mode);
        if (merr) return merr;
    }
    if (argc != 4) {
        return "BotShieldBlockPath: expects exactly 4 args — "
               "<name> <path-glob> <ua> <ipspec> "
               "[mode=enforce|observe]";
    }
    const char *name    = argv[0];
    const char *pattern = argv[1];
    const char *ua      = argv[2];
    const char *ipspec  = argv[3];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldBlockPath: name '%s' must be [a-z0-9-]{1,32}", name);
    }
    if (!pattern || !*pattern || pattern[0] != '/') {
        return "BotShieldBlockPath: path-glob must start with '/'";
    }
    if (strlen(pattern) > 256) {
        return "BotShieldBlockPath: path-glob longer than 256 chars";
    }

    bs_block_path_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name         = apr_pstrdup(cmd->pool, name);
    e->path_pattern = apr_pstrdup(cmd->pool, pattern);
    e->mode         = mode;   /* E12 */
    const char *err = bs_cohort_resolve(cmd, &e->cohort, ua, ipspec);
    if (err) return apr_pstrcat(cmd->pool,
        "BotShieldBlockPath: ", err, NULL);

    /* Upsert by name — same semantics as BotShieldRateLimit. */
    for (int i = 0; i < scfg->block_paths->nelts; i++) {
        bs_block_path_entry *ex =
            APR_ARRAY_IDX(scfg->block_paths, i, bs_block_path_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->block_paths, i, bs_block_path_entry *) = e;
            return NULL;
        }
    }
    *(bs_block_path_entry **)apr_array_push(scfg->block_paths) = e;
    return NULL;
}

/* E7.2 — shared action-engine implementation. One parser + one
 * executor across path/cookie/env trigger families; family-specific
 * matchers (path-glob / cookie / env) stay in their own setters and
 * request-time walks and feed the shared action struct into these
 * helpers. See the bs_trigger_action block at the top of the file
 * for the semantic profile each family gets. */

static const char *bs_trigger_family_dname(bs_trigger_family fam)
{
    switch (fam) {
    case BS_TFAMILY_PATH:     return "BotShieldPathTrigger";
    case BS_TFAMILY_COOKIE:   return "BotShieldCookieTrigger";
    case BS_TFAMILY_ENV:      return "BotShieldEnvTrigger";
    case BS_TFAMILY_FEEDBACK: return "BotShieldFeedbackTrigger";
    case BS_TFAMILY_LOAD:     return "BotShieldLoadTrigger";
    }
    return "BotShieldTrigger";      /* unreachable */
}

static void bs_trigger_action_init(bs_trigger_family fam,
                                   bs_trigger_action *a)
{
    memset(a, 0, sizeof(*a));
    switch (fam) {
    case BS_TFAMILY_PATH:
        /* Path defaults per PLAN.md E3: immediate 403, flag the IP
         * with scanner_probe for an hour. Operators override by
         * writing status=/flag=/ttl= explicitly. */
        a->status_code = 403;
        a->flag_bit    = BS_FLAG_SCANNER_PROBE;
        a->ttl_sec     = 3600;
        break;
    case BS_TFAMILY_COOKIE:
    case BS_TFAMILY_ENV:
        /* Cookie/env default is pass-with-score-shaping. No flag
         * unless operator asks; no short-circuit unless they do. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    case BS_TFAMILY_FEEDBACK:
        /* Feedback runs on the response path; status/redirect/
         * penalty/credit don't apply. status_code left at PASS as
         * a harmless sentinel — the executor path for this family
         * doesn't consult it. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    case BS_TFAMILY_LOAD:
        /* Load triggers default to pass-with-score-shaping. The
         * common case is "add some penalty/credit when warm/hot";
         * less common is "outright 403 expensive paths under hot."
         * Both are explicit operator decisions via status=. No
         * flag — load is a global state, not per-IP behavior. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    }
    a->penalty         = 0;
    a->credit          = 0;
    a->redirect_url    = NULL;
    a->log_tag         = NULL;
    a->status_explicit = 0;
}

static const char *bs_trigger_known_keys(bs_trigger_family fam)
{
    switch (fam) {
    case BS_TFAMILY_PATH:
        return "status, redirect, log, flag, ttl, penalty, mode";
    case BS_TFAMILY_COOKIE:
        return "status, redirect, log, flag, ttl, penalty, credit, mode";
    case BS_TFAMILY_ENV:
        return "status, log, flag, ttl, penalty, credit, mode";
    case BS_TFAMILY_FEEDBACK:
        /* No mode= for feedback: the response has already been
         * served, so "observe" doesn't have a meaningful no-op
         * compared to enforce. */
        return "flag, ttl, log";
    case BS_TFAMILY_LOAD:
        return "status, log, penalty, credit, mode";
    }
    return "";
}

/* Feedback-specific: status/redirect/penalty/credit make no sense
 * on the response path — all four are rejected at parse time with
 * a pointed error. Centralized so the messages stay consistent and
 * future keys are easier to vet per family. */
static int bs_trigger_key_is_response_only(const char *arg,
                                           apr_size_t klen)
{
    #define BS_KMATCH(n) (klen == sizeof(n)-1 && \
                          strncasecmp(arg, n, sizeof(n)-1) == 0)
    if (BS_KMATCH("status"))   return 1;
    if (BS_KMATCH("redirect")) return 1;
    if (BS_KMATCH("penalty"))  return 1;
    if (BS_KMATCH("credit"))   return 1;
    #undef BS_KMATCH
    return 0;
}

static const char *bs_parse_trigger_action_key(apr_pool_t *pool,
                                               bs_trigger_family fam,
                                               const char *arg,
                                               bs_trigger_action *a)
{
    const char *dname = bs_trigger_family_dname(fam);
    const char *eq = strchr(arg, '=');
    if (!eq) {
        return apr_psprintf(pool,
            "%s: extra arg '%s' must be key=value", dname, arg);
    }
    apr_size_t klen = (apr_size_t)(eq - arg);
    const char *val = eq + 1;

    /* Feedback family: reject the request-path-only keys up front
     * with a pointed error message so operators don't confuse this
     * family with the cookie/env surface. */
    if (fam == BS_TFAMILY_FEEDBACK
        && bs_trigger_key_is_response_only(arg, klen)) {
        return apr_psprintf(pool,
            "%s: %.*s= is not supported on feedback triggers "
            "(the response has already been served; feedback maps "
            "a signed event to flag/ttl only — use a cookie or path "
            "trigger for status/redirect/penalty/credit)",
            dname, (int)klen, arg);
    }

    #define BS_AK(n) (klen == sizeof(n)-1 && \
                      strncasecmp(arg, n, sizeof(n)-1) == 0)

    if (BS_AK("status")) {
        if (!strcasecmp(val, "pass")) {
            a->status_code = BS_TRIGGER_STATUS_PASS;
        } else {
            char *end = NULL;
            long code = strtol(val, &end, 10);
            if (!end || *end || code < 100 || code > 599) {
                return apr_psprintf(pool,
                    "%s: status='%s' must be an HTTP code 100..599 "
                    "or the literal 'pass'", dname, val);
            }
            a->status_code = (int)code;
        }
        a->status_explicit = 1;
    } else if (BS_AK("redirect")) {
        if (fam == BS_TFAMILY_ENV || fam == BS_TFAMILY_LOAD) {
            return apr_psprintf(pool,
                "%s: redirect= is not supported on this family "
                "(scoring/flagging only; use the path or cookie "
                "family for response-shaping redirects)", dname);
        }
        if (!*val) {
            return apr_psprintf(pool,
                "%s: redirect= requires a URL", dname);
        }
        a->redirect_url = apr_pstrdup(pool, val);
    } else if (BS_AK("log")) {
        a->log_tag = apr_pstrdup(pool, val);
    } else if (BS_AK("flag")) {
        if (fam == BS_TFAMILY_LOAD) {
            return apr_psprintf(pool,
                "%s: flag= is not supported on load triggers "
                "(load is global state; flagging individual IPs "
                "because the host is hot doesn't fit the model — "
                "use a cookie or env trigger if you want per-IP "
                "memory tied to a load condition)", dname);
        }
        const char *perr = NULL;
        apr_uint32_t bits = bs_parse_flag_names(pool, val, &perr);
        if (perr) return apr_psprintf(pool,
            "%s: flag=%s: %s", dname, val, perr);
        if (bits == 0 || (bits & (bits - 1)) != 0) {
            return apr_psprintf(pool,
                "%s: flag=%s must name exactly one bit",
                dname, val);
        }
        a->flag_bit = bits;
    } else if (BS_AK("ttl")) {
        if (fam == BS_TFAMILY_LOAD) {
            return apr_psprintf(pool,
                "%s: ttl= has no effect on load triggers (no flag "
                "is written, so there's nothing for ttl to govern)",
                dname);
        }
        char *end = NULL;
        long t = strtol(val, &end, 10);
        if (!end || *end || t < 0 || t > 86400 * 30) {
            return apr_psprintf(pool,
                "%s: ttl='%s' must be 0..2592000 (0 = don't flag)",
                dname, val);
        }
        a->ttl_sec = (int)t;
    } else if (BS_AK("penalty")) {
        char *end = NULL;
        long pn = strtol(val, &end, 10);
        if (!end || *end || pn < 0 || pn > 1000) {
            return apr_psprintf(pool,
                "%s: penalty='%s' must be 0..1000", dname, val);
        }
        a->penalty = (int)pn;
    } else if (BS_AK("mode")) {
        /* E12 — observe vs enforce. Default enforce; observe makes
         * the rule log a :observe match without taking the action.
         * Same enum across path/cookie/env/load families. Feedback
         * is response-path; observe doesn't have a meaningful no-op
         * there (the response already shipped), so reject. */
        if (fam == BS_TFAMILY_FEEDBACK) {
            return apr_psprintf(pool,
                "%s: mode= is not supported on feedback triggers "
                "(observe is meaningless on a response-path rule; "
                "if you don't want the event applied, just don't "
                "declare a BotShieldFeedbackTrigger for it)", dname);
        }
        if (!strcasecmp(val, "enforce")) {
            a->mode = BS_TMODE_ENFORCE;
        } else if (!strcasecmp(val, "observe")) {
            a->mode = BS_TMODE_OBSERVE;
        } else {
            return apr_psprintf(pool,
                "%s: mode='%s' must be 'enforce' or 'observe'",
                dname, val);
        }
    } else if (BS_AK("credit")) {
        if (fam == BS_TFAMILY_PATH) {
            return apr_psprintf(pool,
                "%s: credit= is not supported on path triggers "
                "(path matches are discrete events; running "
                "reputation belongs on cookie or env triggers)",
                dname);
        }
        char *end = NULL;
        long cn = strtol(val, &end, 10);
        if (!end || *end || cn < 0 || cn > 1000) {
            return apr_psprintf(pool,
                "%s: credit='%s' must be 0..1000", dname, val);
        }
        a->credit = (int)cn;
    } else {
        return apr_psprintf(pool,
            "%s: unknown key '%.*s' (known: %s)",
            dname, (int)klen, arg, bs_trigger_known_keys(fam));
    }
    #undef BS_AK
    return NULL;
}

static const char *bs_finalize_trigger_action(apr_pool_t *pool,
                                              bs_trigger_family fam,
                                              bs_trigger_action *a)
{
    const char *dname = bs_trigger_family_dname(fam);
    /* No flag without a TTL — clear the bit so the request-time
     * walk skips the flag_ip call and the decision log stays
     * honest about what persisted. */
    if (a->ttl_sec == 0) a->flag_bit = 0;

    /* Feedback triggers without an actionable flag are dead config —
     * the mapping has nowhere to land. Reject at parse time so
     * operators see it via configtest rather than as silent no-ops
     * at runtime. */
    if (fam == BS_TFAMILY_FEEDBACK) {
        if (!a->flag_bit || a->ttl_sec <= 0) {
            return apr_psprintf(pool,
                "%s: feedback triggers must set flag=<bit> and "
                "ttl=<sec>; the event mapping has no request-time "
                "surface otherwise", dname);
        }
        return NULL;   /* status/redirect checks don't apply here */
    }

    if (a->redirect_url) {
        if (a->status_code == BS_TRIGGER_STATUS_PASS) {
            return apr_psprintf(pool,
                "%s: status=pass and redirect= are mutually exclusive "
                "— a redirect IS the response", dname);
        }
        if (!a->status_explicit) {
            /* Default 302 when redirect is set without an explicit
             * status; lets operators write `redirect=<url>` without
             * also spelling out status=302. */
            a->status_code = 302;
            a->status_explicit = 1;
        }
        if (a->status_code < 300 || a->status_code >= 400) {
            return apr_psprintf(pool,
                "%s: redirect= requires a 3xx status (got %d)",
                dname, a->status_code);
        }
    }
    return NULL;
}

static bs_trigger_exec_outcome bs_apply_trigger_action(
    request_rec *r,
    struct bs_server_cfg *scfg,
    bs_trigger_family fam,
    const bs_trigger_action *a,
    const char *family_tag,
    const char *trigger_name)
{
    /* E12 — shadow / observe-mode short-circuit. If the rule is
     * observe-only, OR the global shadow_mode is on, log the match
     * with a :observe suffix and return without applying any side
     * effect (no flag-IP, no score, no status, no redirect, no log
     * tag — observe is a "what would have happened" probe).
     * Caller's loop treats BS_TEXEC_OBSERVE as `continue` so the
     * next rule still gets a chance — observed rules never shadow
     * enforced ones. */
    int global_shadow = (scfg && scfg->shadow_mode == 1);
    int observe = global_shadow || (a->mode == BS_TMODE_OBSERVE);
    if (observe) {
        bs_score_add(r, 0, 0,
            apr_pstrcat(r->pool, family_tag, ":", trigger_name,
                        ":observe", NULL));
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->trigger_observed_total,
                               1, __ATOMIC_RELAXED);
        }
        return BS_TEXEC_OBSERVE;
    }

    /* Flag-IP (future-request memory). Applies to all families
     * uniformly — flag_bit is already 0 when ttl_sec==0, so the
     * guard below is belt-and-suspenders. */
    if (a->flag_bit && a->ttl_sec > 0) {
        unsigned char client_ip[16];
        if (bs_parse_client_ip(r->useragent_ip, client_ip)) {
            bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
            bs_flagged_ip_add(r, client_ip, a->flag_bit, a->ttl_sec,
                              scfg->ns_id);
        }
    }
    bs_set_trigger_tag(r, a->log_tag);

    int is_pass = (a->status_code == BS_TRIGGER_STATUS_PASS);

    if (is_pass) {
        if (fam == BS_TFAMILY_PATH) {
            /* Path pass: record the match for the decision-log
             * reason trace but do NOT bump the score. "pass" here
             * means "don't enforce anything on this request" — the
             * flag-IP side-effect above is the trigger's only
             * future-request surface. */
            bs_score_add(r, 0, 0,
                apr_pstrcat(r->pool, family_tag, ":", trigger_name,
                            ":pass", NULL));
            return BS_TEXEC_PASS_DECLINE;
        }
        /* Cookie/env/load pass: apply penalty - credit on THIS
         * request's score. The signal is part of this request's
         * decision state (cookie carried, env set, host hot), so
         * the score contribution belongs here. */
        int delta = a->penalty - a->credit;
        bs_score_add(r, delta, 0,
            apr_pstrcat(r->pool, family_tag, ":", trigger_name, NULL));
        if (fam == BS_TFAMILY_COOKIE) return BS_TEXEC_PASS_CONTINUE;
        /* env + load: first-match-wins. Distinct load triggers
         * (state>=warm vs state=hot) are alternative-specificity
         * cases, not layered reputation — one match is enough. */
        return BS_TEXEC_PASS_BREAK;
    }

    /* Concrete status. Record reason; caller emits Location + the
     * status_code. Path family historically ignored `credit` — the
     * parser rejects credit= for path so a->credit is always 0 and
     * `penalty - credit` collapses to `penalty` for path too. */
    int delta = a->penalty - a->credit;
    bs_score_add(r, delta, 0,
        apr_pstrcat(r->pool, family_tag, ":", trigger_name, NULL));

    if (a->redirect_url) {
        apr_table_setn(r->headers_out, "Location", a->redirect_url);
    }
    return BS_TEXEC_STATUS;
}

/* E3 — BotShieldPathTrigger <name> <path-glob> [key=value ...].
 *
 * Path-unique bits live here; action-key parsing and cross-validation
 * are delegated to the shared bs_parse_trigger_action_key +
 * bs_finalize_trigger_action (see E7.2 above). Upsert-by-name
 * preserves declaration order. */
static const char *bs_set_path_trigger(cmd_parms *cmd, void *dconf,
                                       int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 2) {
        return "BotShieldPathTrigger: expects <name> <path-glob> "
               "[key=value ...]";
    }
    const char *name    = argv[0];
    const char *pattern = argv[1];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldPathTrigger: name '%s' must be [a-z0-9-]{1,32}", name);
    }
    if (!pattern || !*pattern || pattern[0] != '/') {
        return "BotShieldPathTrigger: path-glob must start with '/'";
    }
    if (strlen(pattern) > 256) {
        return "BotShieldPathTrigger: path-glob longer than 256 chars";
    }

    bs_path_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name         = apr_pstrdup(cmd->pool, name);
    e->path_pattern = apr_pstrdup(cmd->pool, pattern);
    bs_trigger_action_init(BS_TFAMILY_PATH, &e->action);

    for (int i = 2; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_PATH, argv[i], &e->action);
        if (err) return err;
    }
    const char *err = bs_finalize_trigger_action(cmd->pool,
        BS_TFAMILY_PATH, &e->action);
    if (err) return err;

    /* Upsert-by-name; preserves declaration order. */
    for (int i = 0; i < scfg->path_triggers->nelts; i++) {
        bs_path_trigger_entry *ex =
            APR_ARRAY_IDX(scfg->path_triggers, i, bs_path_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->path_triggers, i, bs_path_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_path_trigger_entry **)apr_array_push(scfg->path_triggers) = e;
    return NULL;
}

/* E4 — BotShieldSessionCookieName <name>. Each invocation appends
 * one cookie name to scfg->session_names (lowercased, deduped).
 * The list seeds the `cookies=session` predicate — matches any
 * cookie on the request whose name is in this list. Curated
 * defaults ship (PHPSESSID, JSESSIONID, etc.); this directive lets
 * operators add framework-specific names without editing the
 * module. Short by design — long auto-lists turn `cookies=session`
 * into a loose any-cookie-with-a-suggestive-name matcher. */
static const char *bs_set_session_cookie_name(cmd_parms *cmd, void *dconf,
                                              const char *name)
{
    (void)dconf;
    if (!name || !*name) {
        return "BotShieldSessionCookieName: name required";
    }
    apr_size_t nlen = strlen(name);
    if (nlen > 64) {
        return "BotShieldSessionCookieName: name over 64 chars";
    }
    for (apr_size_t i = 0; i < nlen; i++) {
        unsigned char c = (unsigned char)name[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_'
              || c == '.';
        if (!ok) return apr_psprintf(cmd->pool,
            "BotShieldSessionCookieName: '%s' contains invalid "
            "char '%c' (expect [A-Za-z0-9_-.])", name, (char)c);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    char *lower = apr_pstrdup(cmd->pool, name);
    for (char *p = lower; *p; p++) *p = (char)tolower((unsigned char)*p);
    /* Dedup — O(n) scan, list is tiny. */
    for (int i = 0; i < scfg->session_names->nelts; i++) {
        if (strcmp(APR_ARRAY_IDX(scfg->session_names, i,
                                 const char *), lower) == 0) {
            return NULL;
        }
    }
    *(const char **)apr_array_push(scfg->session_names) = lower;
    return NULL;
}

/* E4 — BotShieldCookieTrigger <name> <cookie-match> [key=value ...].
 *
 * Parses the cookie-match predicate (see PLAN.md E4 for the full
 * predicate grammar) and the action keys, enforces cross-
 * validation (status=pass + redirect= is a config error;
 * _bs_verified as cookie=name is redirected to bs-cookie=<state>),
 * and upserts by name. See bs_path_trigger_entry for the action-key
 * semantics shared with E3; the semantic divergences are:
 *
 *   - credit= always applies (even under status=pass), because a
 *     cookie is ongoing client state we want to shape this
 *     request's score for.
 *   - penalty= likewise always applies. Contrast E3 where it's
 *     ignored under pass.
 *   - status=pass is the DEFAULT; a credit trigger with no status
 *     set is pass-with-score-shaping. */
static int bs_ishex_or_alnum(char c)
{
    unsigned char u = (unsigned char)c;
    return (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z')
        || (u >= '0' && u <= '9') || u == '-' || u == '_' || u == '.';
}

static const char *bs_set_cookie_trigger(cmd_parms *cmd, void *dconf,
                                         int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 2) {
        return "BotShieldCookieTrigger: expects <name> <cookie-match> "
               "[key=value ...]";
    }
    const char *name     = argv[0];
    const char *match    = argv[1];
    bs_server_cfg *scfg  = ap_get_module_config(cmd->server->module_config,
                                                &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldCookieTrigger: name '%s' must be [a-z0-9-]{1,32}",
            name);
    }

    bs_cookie_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name = apr_pstrdup(cmd->pool, name);
    bs_trigger_action_init(BS_TFAMILY_COOKIE, &e->action);

    /* --- Parse the cookie-match predicate. --- */
    const char *m = match;
    int negated = 0;
    if (m[0] == '!') { negated = 1; m++; }
    if (!strncasecmp(m, "cookie=", 7)) {
        const char *rest = m + 7;
        if (!*rest) {
            return "BotShieldCookieTrigger: cookie= needs a name";
        }
        /* Parse cookie name up to '=' / '~' / '!' / end. */
        const char *op = rest;
        while (*op && *op != '=' && *op != '~' && *op != '!') {
            if (!bs_ishex_or_alnum(*op)) {
                return apr_psprintf(cmd->pool,
                    "BotShieldCookieTrigger: cookie name may only "
                    "contain [A-Za-z0-9_-.] (got '%c')", *op);
            }
            op++;
        }
        apr_size_t nlen = (apr_size_t)(op - rest);
        if (nlen == 0 || nlen > 64) {
            return "BotShieldCookieTrigger: cookie name must be 1..64 chars";
        }
        char *cname = apr_pstrmemdup(cmd->pool, rest, nlen);
        /* Reject the module's own cookie at this predicate level;
         * redirect operators to bs-cookie=<state>. */
        if (!strcasecmp(cname, BS_COOKIE_NAME)) {
            return "BotShieldCookieTrigger: declaring a predicate "
                   "against the module's own " BS_COOKIE_NAME
                   " cookie is not supported — use bs-cookie=verified "
                   "/ bs-cookie=missing / bs-cookie=invalid instead";
        }
        e->cname = cname;
        /* Dispatch on the operator chosen. */
        if (*op == '\0') {
            e->pred_kind = negated ? BS_CP_NAMED_ABSENT
                                   : BS_CP_NAMED_PRESENT;
        } else if (negated) {
            return "BotShieldCookieTrigger: '!' prefix may only be "
                   "combined with a bare cookie=<name> (absence "
                   "test); use cookie=<name>!<value> for value "
                   "mismatch";
        } else if (*op == '=') {
            e->pred_kind = BS_CP_NAMED_EQ;
            e->cvalue    = apr_pstrdup(cmd->pool, op + 1);
        } else if (*op == '~') {
            e->pred_kind = BS_CP_NAMED_CONTAINS;
            e->cvalue    = apr_pstrdup(cmd->pool, op + 1);
            if (!*e->cvalue) {
                return "BotShieldCookieTrigger: cookie=<name>~<substr> "
                       "needs a non-empty substring";
            }
        } else if (*op == '!') {
            e->pred_kind = BS_CP_NAMED_NE;
            e->cvalue    = apr_pstrdup(cmd->pool, op + 1);
        }
    } else if (!strncasecmp(m, "cookies=", 8)) {
        if (negated) {
            return "BotShieldCookieTrigger: '!' prefix cannot combine "
                   "with cookies=<state> — use the complementary "
                   "state (cookies=any is the complement of cookies=none)";
        }
        const char *state = m + 8;
        if      (!strcasecmp(state, "none"))    e->pred_kind = BS_CP_BULK_NONE;
        else if (!strcasecmp(state, "any"))     e->pred_kind = BS_CP_BULK_ANY;
        else if (!strcasecmp(state, "session")) e->pred_kind = BS_CP_BULK_SESSION;
        else {
            return apr_psprintf(cmd->pool,
                "BotShieldCookieTrigger: cookies='%s' not one of "
                "none|any|session", state);
        }
    } else if (!strncasecmp(m, "bs-cookie=", 10)) {
        if (negated) {
            return "BotShieldCookieTrigger: '!' prefix cannot combine "
                   "with bs-cookie=<state> — use the complementary "
                   "state directly";
        }
        const char *state = m + 10;
        if      (!strcasecmp(state, "verified")) e->pred_kind = BS_CP_BS_VERIFIED;
        else if (!strcasecmp(state, "missing"))  e->pred_kind = BS_CP_BS_MISSING;
        else if (!strcasecmp(state, "invalid"))  e->pred_kind = BS_CP_BS_INVALID;
        else {
            return apr_psprintf(cmd->pool,
                "BotShieldCookieTrigger: bs-cookie='%s' not one of "
                "verified|missing|invalid", state);
        }
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldCookieTrigger: unrecognized cookie-match '%s' "
            "(expected cookie=... / !cookie=... / cookies=... / "
            "bs-cookie=...)", match);
    }

    /* --- Parse action keys via shared engine (E7.2). --- */
    for (int i = 2; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_COOKIE, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_COOKIE, &e->action);
        if (err) return err;
    }

    /* Upsert-by-name. */
    for (int i = 0; i < scfg->cookie_triggers->nelts; i++) {
        bs_cookie_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->cookie_triggers, i, bs_cookie_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->cookie_triggers, i,
                          bs_cookie_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_cookie_trigger_entry **)apr_array_push(scfg->cookie_triggers) = e;
    return NULL;
}

/* E6 — BotShieldEnvTrigger <name> <env-match> [key=value ...].
 *
 * env-match shapes:
 *   env=<var>           present (any value, including empty)
 *   env=<var>=<value>   exact value match
 *   !env=<var>          absent
 *
 * Keys mirror E4's, minus `redirect` (E6 doesn't do response
 * shaping; scoring/flagging only). Predicate matching reads
 * `r->subprocess_env` at request time.
 *
 * Narrower by design than E3/E4: no substring/contains shape, no
 * cookie-bulk-state analog. Operators who need rich matching set
 * a coarse bucket upstream (SetEnvIfExpr, ModSecurity rule, etc.)
 * and consume the bucket here. */
static const char *bs_set_env_trigger(cmd_parms *cmd, void *dconf,
                                      int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 2) {
        return "BotShieldEnvTrigger: expects <name> <env-match> "
               "[key=value ...]";
    }
    const char *name  = argv[0];
    const char *match = argv[1];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldEnvTrigger: name '%s' must be [a-z0-9-]{1,32}",
            name);
    }

    bs_env_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name = apr_pstrdup(cmd->pool, name);
    bs_trigger_action_init(BS_TFAMILY_ENV, &e->action);

    /* --- Parse env-match predicate. --- */
    const char *m = match;
    int negated = 0;
    if (m[0] == '!') { negated = 1; m++; }
    if (strncmp(m, "env=", 4) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldEnvTrigger: unrecognized env-match '%s' "
            "(expected env=<var>, env=<var>=<value>, or "
            "!env=<var>)", match);
    }
    const char *rest = m + 4;
    if (!*rest) {
        return "BotShieldEnvTrigger: env= needs a variable name";
    }
    /* Env var name: POSIX-ish [A-Za-z_][A-Za-z0-9_]* but Apache is
     * liberal; we accept the same charset we allow on session-
     * cookie names and cookie-match names. Stored verbatim, but the
     * request-time lookup (`apr_table_get` on `r->subprocess_env`)
     * is case-insensitive per APR table semantics — two triggers
     * whose env names differ only in case will resolve to the same
     * stored value at runtime and shadow each other under
     * first-match-wins. */
    const char *op = rest;
    while (*op && *op != '=') {
        unsigned char c = (unsigned char)*op;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) {
            return apr_psprintf(cmd->pool,
                "BotShieldEnvTrigger: env var name contains "
                "invalid char '%c' (expect [A-Za-z0-9_-])", (char)c);
        }
        op++;
    }
    apr_size_t nlen = (apr_size_t)(op - rest);
    if (nlen == 0 || nlen > 128) {
        return "BotShieldEnvTrigger: env var name must be 1..128 chars";
    }
    e->env_name = apr_pstrmemdup(cmd->pool, rest, nlen);

    if (*op == '\0') {
        e->pred_kind = negated ? BS_EP_NAMED_ABSENT
                               : BS_EP_NAMED_PRESENT;
    } else if (negated) {
        return "BotShieldEnvTrigger: '!' prefix only combines with "
               "bare env=<var> (absence test); use env=<var>=<value> "
               "for value-mismatch semantics via a separate trigger";
    } else {
        /* *op == '=' */
        e->pred_kind  = BS_EP_NAMED_EQ;
        e->env_value  = apr_pstrdup(cmd->pool, op + 1);
        /* Empty expected-value is legitimate: SetEnvIf with no value
         * assigns "", so env=FOO= matches that case explicitly.
         * Distinct from env=FOO (matches empty OR non-empty). */
    }

    /* --- Parse action keys via shared engine (E7.2). --- */
    for (int i = 2; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_ENV, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_ENV, &e->action);
        if (err) return err;
    }

    /* Upsert-by-name (same as E3/E4). */
    for (int i = 0; i < scfg->env_triggers->nelts; i++) {
        bs_env_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->env_triggers, i, bs_env_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->env_triggers, i,
                          bs_env_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_env_trigger_entry **)apr_array_push(scfg->env_triggers) = e;
    return NULL;
}

/* E7.3 — BotShieldFeedbackTrigger <event> [key=value ...].
 *
 * Binds an app-signed event name (carried in E5's
 * X-BotShield-Feedback header body as `event=<name>;sig=<hex>`) to
 * a module-memory update. Required keys: flag=<bit> and ttl=<sec>
 * (the event has to land somewhere); optional log=<tag>. Response-
 * path only, so status/redirect/penalty/credit are rejected by the
 * shared parser. Upsert-by-event-name. */
static const char *bs_set_feedback_trigger(cmd_parms *cmd, void *dconf,
                                           int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 1) {
        return "BotShieldFeedbackTrigger: expects <event> "
               "[key=value ...]";
    }
    const char *event = argv[0];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(event)) {
        return apr_psprintf(cmd->pool,
            "BotShieldFeedbackTrigger: event '%s' must be "
            "[a-z0-9-]{1,32}", event);
    }

    bs_feedback_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->event = apr_pstrdup(cmd->pool, event);
    bs_trigger_action_init(BS_TFAMILY_FEEDBACK, &e->action);

    for (int i = 1; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_FEEDBACK, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_FEEDBACK, &e->action);
        if (err) return err;
    }

    /* Upsert-by-event. Last declaration for a given event wins its
     * slot, same model as the other trigger families. */
    for (int i = 0; i < scfg->feedback_triggers->nelts; i++) {
        bs_feedback_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->feedback_triggers, i, bs_feedback_trigger_entry *);
        if (strcmp(ex->event, e->event) == 0) {
            APR_ARRAY_IDX(scfg->feedback_triggers, i,
                          bs_feedback_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_feedback_trigger_entry **)
        apr_array_push(scfg->feedback_triggers) = e;
    return NULL;
}

/* E11.2 — BotShieldLoadTrigger <name> <load-match> [key=value ...].
 *
 * load-match shapes:
 *   state=normal   (exact match — typically only for tests/docs)
 *   state=warm
 *   state=hot
 *   state>=warm    (matches warm OR hot)
 *   state>=hot     (matches hot only — equivalent to state=hot but
 *                   reads more naturally in operator config when
 *                   paired with state>=warm rules)
 *
 * First-match-wins within the family (load triggers are alternative-
 * specificity cases, not layered reputation). Action keys: status,
 * log, penalty, credit. flag/ttl/redirect rejected at parse time —
 * load is a global signal, not per-IP behavior to memorize. */
static const char *bs_set_load_trigger(cmd_parms *cmd, void *dconf,
                                       int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 2) {
        return "BotShieldLoadTrigger: expects <name> <load-match> "
               "[key=value ...]";
    }
    const char *name  = argv[0];
    const char *match = argv[1];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadTrigger: name '%s' must be [a-z0-9-]{1,32}",
            name);
    }

    int pred_kind;
    const char *state_str;
    if (!strncmp(match, "state>=", 7)) {
        pred_kind = BS_LP_GE;
        state_str = match + 7;
    } else if (!strncmp(match, "state=", 6)) {
        pred_kind = BS_LP_EQ;
        state_str = match + 6;
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadTrigger: unrecognized load-match '%s' "
            "(expected state=<level> or state>=<level> where "
            "<level> is normal|warm|hot)", match);
    }
    bs_load_state target;
    if      (!strcasecmp(state_str, "normal")) target = BS_LOAD_NORMAL;
    else if (!strcasecmp(state_str, "warm"))   target = BS_LOAD_WARM;
    else if (!strcasecmp(state_str, "hot"))    target = BS_LOAD_HOT;
    else {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadTrigger: state '%s' must be one of "
            "normal|warm|hot", state_str);
    }

    bs_load_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name         = apr_pstrdup(cmd->pool, name);
    e->pred_kind    = pred_kind;
    e->target_state = target;
    bs_trigger_action_init(BS_TFAMILY_LOAD, &e->action);

    for (int i = 2; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_LOAD, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_LOAD, &e->action);
        if (err) return err;
    }

    /* Upsert-by-name. */
    for (int i = 0; i < scfg->load_triggers->nelts; i++) {
        bs_load_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->load_triggers, i, bs_load_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->load_triggers, i,
                          bs_load_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_load_trigger_entry **)apr_array_push(scfg->load_triggers) = e;
    return NULL;
}

/* E2.2 — BotShieldRobotsTxt <path>: point the module at a robots.txt
 * file. Parsing deferred to post_config so pconf's allocator is alive
 * for the doc's lifetime. Empty/absent path is the default "don't
 * enforce robots.txt" state; operators turn it on by pointing at a
 * file. */
static const char *bs_set_robots_txt(cmd_parms *cmd, void *dconf,
                                     const char *path)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!path || !*path) {
        return "BotShieldRobotsTxt: path required";
    }
    if (path[0] != '/') {
        return "BotShieldRobotsTxt: path must be absolute";
    }
    scfg->robots_txt_path = apr_pstrdup(cmd->pool, path);
    return NULL;
}

/* E2.2 — BotShieldRobotsRefreshInterval <seconds>. Governs the
 * mod_watchdog-driven live refresh (E2.2.2). 0 disables the
 * watchdog callback, reverting to post_config-only load
 * (edit robots.txt + reload Apache). Default 60s. Hard cap at
 * 86400 to catch typos that'd push refreshes into next week. */
static const char *bs_set_robots_refresh_interval(cmd_parms *cmd,
                                                  void *dconf,
                                                  const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end || v < 0 || v > 86400) {
        return apr_psprintf(cmd->pool,
            "BotShieldRobotsRefreshInterval: '%s' must be an integer "
            "0..86400 seconds (0 = disable live refresh)", arg);
    }
    scfg->robots_refresh_interval = (int)v;
    return NULL;
}

/* E5 — BotShieldAppFeedback on|off. Master gate for the
 * app-to-module reputation-feedback channel. Default off. Even
 * under off we still strip the feedback header from outgoing
 * responses (see bs_app_feedback_fixup), so a misconfigured app
 * can't leak it to clients during a staged rollout. */
static const char *bs_set_app_feedback(cmd_parms *cmd, void *dconf,
                                        int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_feedback_enabled = flag ? 1 : 0;
    return NULL;
}

/* E5 — BotShieldAppFeedbackHeader <name>. Header name the module
 * reads feedback from (and strips on its way out). Default
 * X-BotShield-Feedback. */
static const char *bs_set_app_feedback_header(cmd_parms *cmd, void *dconf,
                                               const char *name)
{
    (void)dconf;
    if (!name || !*name) {
        return "BotShieldAppFeedbackHeader: header name required";
    }
    apr_size_t nlen = strlen(name);
    if (nlen > 64) {
        return "BotShieldAppFeedbackHeader: name over 64 chars";
    }
    for (apr_size_t i = 0; i < nlen; i++) {
        unsigned char c = (unsigned char)name[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok) {
            return apr_psprintf(cmd->pool,
                "BotShieldAppFeedbackHeader: '%s' contains invalid "
                "char '%c'", name, (char)c);
        }
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_feedback_header = apr_pstrdup(cmd->pool, name);
    return NULL;
}

/* E5 — BotShieldAppFeedbackSecretFile <path>. HMAC key file for
 * validating app-feedback signatures. Mode-600-or-tighter + absolute
 * path, same hygiene as BotShieldSecretFile. Loaded at parse time so
 * it's in memory before the first request hits the hook. Separate
 * key from BotShieldSecretFile so compromise of one doesn't cross-
 * contaminate the other. */
static const char *bs_set_app_feedback_secret_file(cmd_parms *cmd,
                                                    void *dconf,
                                                    const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldAppFeedbackSecretFile: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldAppFeedbackSecretFile: path must be absolute";
    }

    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppFeedbackSecretFile: cannot stat '%s'", arg);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppFeedbackSecretFile: '%s' is group- or world-"
            "accessible (mode %04o); chmod 600 it",
            arg, st.st_mode & 07777);
    }

    const char *buf = NULL;
    const char *err = bs_load_config_file(cmd,
        "BotShieldAppFeedbackSecretFile", arg,
        BS_MAX_SECRET_BYTES, &buf);
    if (err) return err;

    apr_size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') len--;
    if (len < BS_MIN_SECRET_BYTES) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppFeedbackSecretFile: '%s' contains only "
            "%" APR_SIZE_T_FMT " bytes (minimum %d)",
            arg, len, BS_MIN_SECRET_BYTES);
    }

    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_feedback_secret_file = apr_pstrdup(cmd->pool, arg);
    scfg->app_feedback_secret      = (const unsigned char *)buf;
    scfg->app_feedback_secret_len  = len;
    return NULL;
}

/* E8.2 — BotShieldAppClaims on|off. Master gate for the module-to-
 * app reputation-export channel. Default off. When on, the module
 * sets a single signed X-Botshield-Claims header on the request to
 * the backend handler, having first stripped any client-supplied
 * X-Botshield-* (the strip is what makes the signed envelope safe
 * to trust on app reads — even if an app skips HMAC verification,
 * forged claim values can't survive the strip + set sequence). */
static const char *bs_set_app_claims(cmd_parms *cmd, void *dconf, int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_claims_enabled = flag ? 1 : 0;
    return NULL;
}

/* E8.2 — BotShieldAppClaimsSecretFile <path>. HMAC key for the
 * module-to-app channel. Same mode-600 hygiene + load-at-parse-time
 * discipline as BotShieldAppFeedbackSecretFile. Deliberately a
 * separate file: a leak of the inbound (app-signs) key shouldn't
 * also let an attacker forge module-originated claims, and vice
 * versa. */
static const char *bs_set_app_claims_secret_file(cmd_parms *cmd,
                                                 void *dconf,
                                                 const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldAppClaimsSecretFile: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldAppClaimsSecretFile: path must be absolute";
    }

    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppClaimsSecretFile: cannot stat '%s'", arg);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppClaimsSecretFile: '%s' is group- or world-"
            "accessible (mode %04o); chmod 600 it",
            arg, st.st_mode & 07777);
    }

    const char *buf = NULL;
    const char *err = bs_load_config_file(cmd,
        "BotShieldAppClaimsSecretFile", arg,
        BS_MAX_SECRET_BYTES, &buf);
    if (err) return err;

    apr_size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') len--;
    if (len < BS_MIN_SECRET_BYTES) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppClaimsSecretFile: '%s' contains only "
            "%" APR_SIZE_T_FMT " bytes (minimum %d)",
            arg, len, BS_MIN_SECRET_BYTES);
    }

    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_claims_secret_file = apr_pstrdup(cmd->pool, arg);
    scfg->app_claims_secret      = (const unsigned char *)buf;
    scfg->app_claims_secret_len  = len;
    return NULL;
}

/* E2.2 — BotShieldRobotsWildcardScope heuristic|strict|off.
 * Governs how the User-agent: * group in robots.txt is enforced:
 *   heuristic (default): apply only to UAs that look like crawlers
 *                        — real-browser prefix denylist + bot-token
 *                        allowlist (see PLAN.md).
 *   strict             : apply to every UA (operator's call; risks
 *                        rate-limiting or blocking real users).
 *   off                : ignore * groups entirely. */
static const char *bs_set_robots_wildcard_scope(cmd_parms *cmd, void *dconf,
                                                const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!arg || !*arg) return "BotShieldRobotsWildcardScope: mode required";
    if (!strcasecmp(arg, "heuristic")) {
        scfg->robots_wildcard_scope = BS_ROBOTS_WILDCARD_HEURISTIC;
    } else if (!strcasecmp(arg, "strict")) {
        scfg->robots_wildcard_scope = BS_ROBOTS_WILDCARD_STRICT;
    } else if (!strcasecmp(arg, "off")) {
        scfg->robots_wildcard_scope = BS_ROBOTS_WILDCARD_OFF;
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldRobotsWildcardScope: '%s' not one of "
            "heuristic|strict|off", arg);
    }
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
 * IP table) into an additive score. M5.1 wires penalty numbers; E5
 * extends the registry with credit bits (negative contributions) for
 * the app-to-module reputation-feedback channel. Bits are independent
 * and compose additively — an IP carrying BS_FLAG_HONEYPOT_HIT +
 * BS_FLAG_APP_VERIFIED_HUMAN contributes 60 + (-80) = -20 (net
 * credit) until the shorter-TTL bit expires. Output is clamped to
 * BS_FLAG_PENALTY_FLOOR so a single gigantic credit can't lock out
 * all future enforcement for that IP. */
static int bs_flag_penalty(apr_uint32_t flags)
{
    int p = 0;
    for (size_t i = 0; i < BS_FLAG_META_COUNT; i++) {
        if (flags & bs_flag_metadata[i].bit) p += bs_flag_metadata[i].penalty;
    }
    if (p < BS_FLAG_PENALTY_FLOOR) p = BS_FLAG_PENALTY_FLOOR;
    return p;
}

/* E14 — adaptive intensity accumulator. For a flag bitfield, walks
 * the registry and returns the cumulative difficulty-delta (sum) and
 * tier-floor (max). PASS tier-floor means "no floor" — the score-
 * derived tier wins. Negative difficulty-deltas (from credit flags)
 * compose; final clamping happens at the use site against the
 * configured BotShieldDifficulty range. */
typedef struct {
    int          difficulty_delta;
    bs_tier      tier_floor;
    apr_uint32_t bits_with_difficulty;   /* contributing flag bits */
    apr_uint32_t bits_with_tier;
} bs_flag_adaptive;

static bs_flag_adaptive bs_flag_adaptive_for(apr_uint32_t flags)
{
    bs_flag_adaptive r = { 0, BS_TIER_PASS, 0, 0 };
    for (size_t i = 0; i < BS_FLAG_META_COUNT; i++) {
        const bs_flag_meta *m = &bs_flag_metadata[i];
        if (!(flags & m->bit)) continue;
        if (m->next_difficulty_delta != 0) {
            r.difficulty_delta += m->next_difficulty_delta;
            r.bits_with_difficulty |= m->bit;
        }
        if (m->next_tier_floor > r.tier_floor) {
            r.tier_floor = m->next_tier_floor;
            r.bits_with_tier = m->bit;
        } else if (m->next_tier_floor != BS_TIER_PASS &&
                   m->next_tier_floor == r.tier_floor) {
            r.bits_with_tier |= m->bit;
        }
    }
    return r;
}

/* Flag-name registry moved up the file (near the early request-path
 * helpers) so E8.2's bs_app_claims_flag_names can render the bitmap
 * without a forward-declaration dance. Definition lives further up;
 * leave a placeholder comment here so a reader scanning E5/E6 still
 * sees where the table conceptually belongs. */

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
                "(known penalty bits: honeypot_hit, scanner_probe, "
                "fake_bot, pow_fail_streak; credit bits: "
                "app_verified_human, app_verified_session, "
                "app_trust_signal)", (int)len, cur);
            return 0;
        }
        cur = comma ? comma + 1 : NULL;
    }
    return bits;
}

/* E8.1 — GCM cookie prefix builder. Encrypts the same canonical
 * pipe-delimited form the HMAC path signs, base64-encodes
 *     alg_id(1) || nonce(12) || ciphertext || tag(16)
 * for the JS interstitial to append '.<counter>' to when the PoW
 * worker completes. Also used by the server-built captcha cookie
 * path, which appends '.captcha' on the module side. */
static const char *bs_build_cookie_prefix_gcm(apr_pool_t *p,
                                              const bs_dir_cfg *cfg,
                                              const bs_challenge *ch,
                                              const char **out_b64)
{
    if (!cfg->secret || cfg->secret_len == 0) return "no secret";
    const char *canon = bs_challenge_canonical(p, ch);
    apr_size_t pt_len = strlen(canon);
    apr_size_t env_cap = 1 + BS_GCM_NONCE_LEN + pt_len + BS_GCM_TAG_LEN;
    unsigned char *env = apr_palloc(p, env_cap);
    apr_size_t env_len = 0;
    const char *err = bs_gcm_encrypt(cfg->secret, cfg->secret_len,
                                     (const unsigned char *)canon, pt_len,
                                     env, &env_len);
    if (err) return err;
    char *b64 = apr_palloc(p, apr_base64_encode_len((int)env_len) + 1);
    apr_base64_encode(b64, (const char *)env, (int)env_len);
    *out_b64 = b64;
    return NULL;
}

/* Render the challenge as JSON for inline embedding in the interstitial.
 * The JS worker reads window.__bsChallenge and uses it to drive the PoW
 * and to assemble the resulting cookie. Contents are deterministic —
 * hex digits, ASCII identifiers, integers — so no HTML escaping is
 * needed inside a <script> tag.
 *
 * Also carries the cookie_domain (if configured) so the JS can include
 * a Domain= attribute when calling document.cookie.
 *
 * E8.1 — under GCM issue format the rep block is omitted from the
 * JSON (that's the whole point of encryption: the client shouldn't
 * see score/flags/passes_*). Instead the JSON carries an opaque
 * cookie_prefix base64 blob that the JS appends `.<counter>` to.
 * Under HMAC issue format the legacy shape stays byte-identical. */
static const char *bs_challenge_json(apr_pool_t *p, const bs_dir_cfg *cfg,
                                     const bs_challenge *ch)
{
    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    bs_to_hex(ch->salt,  BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch->nonce, BS_NONCE_BYTES, nonce_hex);
    const char *domain_json = cfg->cookie_domain
        ? apr_psprintf(p, ",\"cookie_domain\":\"%s\"", cfg->cookie_domain)
        : "";
    int fmt = bs_effective_cookie_format(cfg);
    if (fmt & BS_FMT_GCM) {
        const char *prefix_b64 = NULL;
        const char *err = bs_build_cookie_prefix_gcm(p, cfg, ch, &prefix_b64);
        if (!err) {
            return apr_psprintf(p,
                "{\"salt\":\"%s\",\"nonce\":\"%s\",\"difficulty\":%d,"
                "\"expires_at\":%" APR_TIME_T_FMT ",\"auto\":%d,"
                "\"cookie_prefix\":\"%s\"%s}",
                salt_hex, nonce_hex, ch->difficulty, ch->expires_at,
                ch->auto_tier ? 1 : 0, prefix_b64, domain_json);
        }
        /* Encryption failed at render time. Rather than serve a broken
         * page, fall through to the HMAC shape — the verifier will
         * still accept it if HMAC is in the allow-list. Operators see
         * the diagnostic in the error log. */
    }
    char sig_hex[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(ch->signature, BS_SIG_BYTES, sig_hex);
    return apr_psprintf(p,
        "{\"v\":%d,\"alg\":\"%s\",\"salt\":\"%s\",\"nonce\":\"%s\","
        "\"difficulty\":%d,\"expires_at\":%" APR_TIME_T_FMT ","
        "\"score\":%d,\"flags\":%u,"
        "\"passes_silent\":%d,\"passes_form\":%d,\"passes_captcha\":%d,"
        "\"challenged_at\":%" APR_TIME_T_FMT ",\"auto\":%d,"
        "\"forgive_window_start\":%u,\"forgive_consumed\":%u,"
        "\"signature\":\"%s\"%s}",
        ch->version, ch->alg_name, salt_hex, nonce_hex,
        ch->difficulty, ch->expires_at,
        ch->rep.score, (unsigned)ch->rep.flags,
        ch->rep.passes_silent, ch->rep.passes_form, ch->rep.passes_captcha,
        ch->rep.challenged_at, ch->auto_tier ? 1 : 0,
        (unsigned)ch->rep.forgive_window_start,
        (unsigned)ch->rep.forgive_consumed,
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

/* Parse the 15 pipe-delimited canonical-form fields (same shape
 * emitted by bs_challenge_canonical, whether it arrived cleartext
 * from an HMAC cookie or as GCM plaintext) into *ch. Returns NULL
 * on success or a diagnostic on parse failure. Caller has already
 * split the canonical string at '|' into fields[0..14].
 *
 * Field count grew from 13 to 15 with BS_PROTOCOL_VERSION 1->2 to
 * carry forgiveness-window state. The version check rejects v1
 * cookies before we read the new fields, so a malformed v1 won't
 * misalign reads. */
static const char *bs_parse_canonical_fields(char *const fields[],
                                              bs_challenge *ch)
{
    long v;
    apr_int64_t v64;
    if (!bs_parse_int_bounded(fields[0], 0, INT_MAX, 10, &v)) return "bad version";
    ch->version = (int)v;
    if (ch->version != BS_PROTOCOL_VERSION) return "bad protocol version";

    const bs_pow_algorithm *alg = bs_find_algorithm(fields[1]);
    if (!alg || !alg->implemented) return "unknown algorithm";
    ch->alg_name = alg->name;

    if (strlen(fields[2]) != BS_SALT_BYTES * 2 ||
        !bs_from_hex(fields[2], BS_SALT_BYTES, ch->salt)) return "bad salt";
    if (strlen(fields[3]) != BS_NONCE_BYTES * 2 ||
        !bs_from_hex(fields[3], BS_NONCE_BYTES, ch->nonce)) return "bad nonce";
    if (!bs_parse_int_bounded(fields[4], 1, 16, 2, &v)) return "bad difficulty";
    ch->difficulty = (int)v;
    if (!bs_parse_int64_bounded(fields[5], 0, APR_INT64_MAX, &v64)) return "bad expires_at";
    ch->expires_at = (apr_time_t)v64;

    if (!bs_parse_int_bounded(fields[6], INT_MIN, INT_MAX, 11, &v)) return "bad score";
    ch->rep.score = (int)v;
    if (!bs_parse_uint32_bounded(fields[7], 10, &ch->rep.flags)) return "bad flags";
    if (!bs_parse_int_bounded(fields[8],  0, 1, 1, &v)) return "bad passes_silent";
    ch->rep.passes_silent  = (int)v;
    if (!bs_parse_int_bounded(fields[9],  0, 1, 1, &v)) return "bad passes_form";
    ch->rep.passes_form    = (int)v;
    if (!bs_parse_int_bounded(fields[10], 0, 1, 1, &v)) return "bad passes_captcha";
    ch->rep.passes_captcha = (int)v;
    if (!bs_parse_int64_bounded(fields[11], 0, APR_INT64_MAX, &v64)) return "bad challenged_at";
    ch->rep.challenged_at  = (apr_time_t)v64;
    if (!bs_parse_int_bounded(fields[12], 0, 1, 1, &v)) return "bad auto";
    ch->auto_tier = (int)v;
    if (!bs_parse_uint32_bounded(fields[13], 10, &ch->rep.forgive_window_start))
        return "bad forgive_window_start";
    if (!bs_parse_uint32_bounded(fields[14], 10, &ch->rep.forgive_consumed))
        return "bad forgive_consumed";
    return NULL;
}

/* Build the base64-encoded cookie payload for a challenge + counter.
 * Dispatches on the effective cookie format:
 *   HMAC (legacy): base64(canonical | sig_hex | counter) in a single
 *                  15-field pipe-delimited blob — byte-identical to
 *                  what the JS interstitial assembles in HMAC mode.
 *   GCM  (E8.1):   base64(alg_id || nonce || ct || tag) + "." + counter
 *                  The server builds this form when issuing captcha
 *                  cookies (counter = "captcha"); the JS builds the
 *                  same shape in PoW mode from the cookie_prefix we
 *                  expose in bs_challenge_json. */
static const char *bs_build_cookie_payload(apr_pool_t *p,
                                           const bs_dir_cfg *cfg,
                                           const bs_challenge *ch,
                                           const char *counter_str)
{
    int fmt = bs_effective_cookie_format(cfg);
    if (fmt & BS_FMT_GCM) {
        const char *prefix_b64 = NULL;
        const char *err = bs_build_cookie_prefix_gcm(p, cfg, ch, &prefix_b64);
        if (err) return NULL;
        return apr_psprintf(p, "%s%c%s", prefix_b64,
                            BS_GCM_COUNTER_SEP, counter_str);
    }
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

/* Verify a legacy HMAC-format cookie. 15 pipe-delimited fields,
 * base64-encoded as a single blob. Caller guarantees the cookie
 * doesn't contain BS_GCM_COUNTER_SEP (the '.' split point for GCM). */
static const char *bs_verify_cookie_hmac(request_rec *r,
                                         const bs_dir_cfg *cfg,
                                         const char *cookie_b64,
                                         bs_challenge *out_ch)
{
    char *decoded = apr_palloc(r->pool, apr_base64_decode_len(cookie_b64) + 1);
    int dec_len = apr_base64_decode(decoded, cookie_b64);
    if (dec_len <= 0) return "base64 decode failed";
    decoded[dec_len] = '\0';

    /* 17 pipe-delimited fields (canonical 0-14, sig_hex 15, counter 16). */
    char *fields[BS_COOKIE_FIELDS];
    int nf = 0;
    char *p = decoded;
    fields[nf++] = p;
    while (*p && nf < BS_COOKIE_FIELDS) {
        if (*p == '|') { *p = '\0'; fields[nf++] = p + 1; }
        p++;
    }
    if (nf != BS_COOKIE_FIELDS) return "wrong field count";

    bs_challenge ch;
    memset(&ch, 0, sizeof(ch));
    const char *perr = bs_parse_canonical_fields(fields, &ch);
    if (perr) return perr;

    unsigned char sig_from_client[BS_SIG_BYTES];
    if (strlen(fields[15]) != BS_SIG_BYTES * 2 ||
        !bs_from_hex(fields[15], BS_SIG_BYTES, sig_from_client)) {
        return "bad signature hex";
    }

    /* HMAC-SHA-256 of canonical bytes. Constant-time compare.
     * E16 — try the primary key first, then fall back
     * to the secondary if configured. Both keys live in process
     * memory; no SHM or file I/O on the hot verify path. The extra
     * HMAC during a rotation window is negligible (low-µs) and only
     * pays off on cookies the primary key already rejected. */
    const char *canon = bs_challenge_canonical(r->pool, &ch);
    unsigned char sig_expected[BS_SIG_BYTES];
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon),
                   sig_expected);
    if (!bs_ct_equal(sig_expected, sig_from_client, BS_SIG_BYTES)) {
        if (!cfg->secret_secondary) return "signature mismatch";
        bs_hmac_sha256(cfg->secret_secondary, cfg->secret_secondary_len,
                       (const unsigned char *)canon, strlen(canon),
                       sig_expected);
        if (!bs_ct_equal(sig_expected, sig_from_client, BS_SIG_BYTES)) {
            return "signature mismatch";
        }
    }
    memcpy(ch.signature, sig_from_client, BS_SIG_BYTES);
    if (out_ch) *out_ch = ch;

    apr_time_t now = apr_time_sec(apr_time_now());
    if (now > ch.expires_at) return "expired";
    const bs_pow_algorithm *alg = bs_find_algorithm(fields[1]);
    return alg->verify(&ch, fields[16]);
}

/* Verify an E8.1 GCM-format cookie. `dot` points at the '.' that
 * separates the base64 envelope from the counter portion. */
static const char *bs_verify_cookie_gcm(request_rec *r,
                                        const bs_dir_cfg *cfg,
                                        const char *cookie_value,
                                        const char *dot,
                                        bs_challenge *out_ch)
{
    apr_size_t prefix_len = (apr_size_t)(dot - cookie_value);
    const char *counter = dot + 1;
    char *prefix_b64 = apr_pstrmemdup(r->pool, cookie_value, prefix_len);
    unsigned char *env = apr_palloc(r->pool,
                                    apr_base64_decode_len(prefix_b64));
    int env_len = apr_base64_decode((char *)env, prefix_b64);
    if (env_len < 1 + BS_GCM_NONCE_LEN + BS_GCM_TAG_LEN) {
        return "base64 decode failed";
    }

    apr_size_t pt_cap = (apr_size_t)env_len - 1 - BS_GCM_NONCE_LEN
                      - BS_GCM_TAG_LEN;
    unsigned char *pt = apr_palloc(r->pool, pt_cap + 1);
    apr_size_t pt_len = 0;
    /* E16 — try primary key first, then secondary if
     * configured. AES-GCM decrypt is authenticated; a wrong key
     * fails the tag check and bs_gcm_decrypt returns an error
     * without leaking plaintext. The retry is safe and the success
     * path is unchanged. */
    const char *derr = bs_gcm_decrypt(cfg->secret, cfg->secret_len,
                                      env, (apr_size_t)env_len,
                                      pt, &pt_len);
    if (derr && cfg->secret_secondary) {
        derr = bs_gcm_decrypt(cfg->secret_secondary,
                              cfg->secret_secondary_len,
                              env, (apr_size_t)env_len,
                              pt, &pt_len);
    }
    if (derr) {
        /* Map all GCM-decrypt failures to the same reason string the
         * HMAC path uses when the tag doesn't match — the caller
         * treats this as "don't carry rep forward", same behavior
         * desired here. */
        return "signature mismatch";
    }
    pt[pt_len] = '\0';

    /* pt is canonical form (15 pipe-delimited fields after E14 +
     * E15 — the count grew with BS_PROTOCOL_VERSION 1->2). */
    char *fields[15];
    int nf = 0;
    char *p = (char *)pt;
    fields[nf++] = p;
    while (*p && nf < 15) {
        if (*p == '|') { *p = '\0'; fields[nf++] = p + 1; }
        p++;
    }
    if (nf != 15) return "wrong field count";

    bs_challenge ch;
    memset(&ch, 0, sizeof(ch));
    const char *perr = bs_parse_canonical_fields(fields, &ch);
    if (perr) return perr;
    /* No sig field in GCM — the tag verification above already
     * authenticated every canonical byte. Expose ch for rep carry-
     * forward semantics parity with the HMAC path. */
    if (out_ch) *out_ch = ch;

    apr_time_t now = apr_time_sec(apr_time_now());
    if (now > ch.expires_at) return "expired";
    const bs_pow_algorithm *alg = bs_find_algorithm(fields[1]);
    return alg->verify(&ch, counter);
}

/* Dispatch on the cookie wire format. Writes to *out_ch once the
 * format-specific verifier has authenticated the bytes (either HMAC
 * of the canonical or GCM tag over the envelope); later semantic
 * rejections (expiry, bad counter) leave the struct populated for
 * rep carry-forward. On format rejection or pre-auth error, *out_ch
 * stays untouched. */
static const char *bs_verify_cookie(request_rec *r, const bs_dir_cfg *cfg,
                                    const char *cookie_value,
                                    bs_challenge *out_ch)
{
    if (!cfg->secret) return "no secret configured";
    apr_size_t val_len = strlen(cookie_value);
    if (val_len > BS_MAX_PAGE_BYTES) return "cookie absurdly long";

    int fmt = bs_effective_cookie_format(cfg);
    /* Standard base64 alphabet is [A-Za-z0-9+/=]; the '.' byte is
     * not part of it. Its presence unambiguously marks a GCM-format
     * cookie (envelope '.' counter). Absent → legacy HMAC. */
    const char *dot = strrchr(cookie_value, BS_GCM_COUNTER_SEP);
    if (dot) {
        if (!(fmt & BS_FMT_GCM)) return "GCM cookies not accepted";
        return bs_verify_cookie_gcm(r, cfg, cookie_value, dot, out_ch);
    }
    if (!(fmt & BS_FMT_HMAC)) return "HMAC cookies not accepted";
    return bs_verify_cookie_hmac(r, cfg, cookie_value, out_ch);
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

/* E16 — `BotShieldSecondarySecretFile /path`. Verify-
 * only secondary key for graceful HMAC/GCM secret rotation.
 *
 * Operator workflow:
 *   1. Generate the new key file. Add `BotShieldSecondarySecretFile`
 *      pointing at the OLD key. Reload Apache. Verify path now
 *      accepts BOTH old and new cookies; issue path uses the NEW key.
 *   2. Wait one BotShieldCookieTTL window so every active cookie has
 *      been re-issued under the new key.
 *   3. Remove the BotShieldSecondarySecretFile directive. Reload.
 *      Old cookies were either re-issued or expired naturally.
 *
 * Same mode-600 hygiene as BotShieldSecretFile. The file's bytes are
 * tried after the primary on every verify; cost is one extra
 * HMAC-SHA-256 (or AES-GCM open) per rejected primary, only during
 * the rotation window. */
static const char *bs_set_secondary_secret_file(cmd_parms *cmd,
                                                void *cfg_v,
                                                const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;

    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecondarySecretFile: cannot stat '%s'", arg);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecondarySecretFile: '%s' is group- or "
            "world-accessible (mode %04o); chmod 600 it",
            arg, st.st_mode & 07777);
    }

    const char *buf = NULL;
    const char *err = bs_load_config_file(cmd,
                                          "BotShieldSecondarySecretFile",
                                          arg, BS_MAX_SECRET_BYTES, &buf);
    if (err) return err;

    apr_size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') len--;
    if (len < BS_MIN_SECRET_BYTES) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecondarySecretFile: '%s' contains only "
            "%" APR_SIZE_T_FMT " bytes (minimum %d)",
            arg, len, BS_MIN_SECRET_BYTES);
    }

    cfg->secret_secondary     = (const unsigned char *)buf;
    cfg->secret_secondary_len = len;
    return NULL;
}

/* `BotShieldCookieFormat <hmac|gcm|gcm,hmac>` — E8.1. Controls which
 * wire formats the issuer emits and the verifier accepts. Value is
 * a comma-separated list of format tokens:
 *   hmac       legacy HMAC-SHA-256 envelope (cleartext fields, 32-
 *              byte signature). Default if the directive is absent.
 *   gcm        AES-256-GCM envelope. Cleartext fields don't appear
 *              in the cookie; rep block is confidential.
 *   gcm,hmac   issue GCM, accept either on verify. Migration mode
 *              for rolling the wire format over a longest-TTL cycle.
 * Issue preference: if the bitmap includes GCM, issue GCM; otherwise
 * issue HMAC. Verify accepts any format whose bit is set. */
static const char *bs_set_cookie_format(cmd_parms *cmd, void *cfg_v,
                                        const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg || !*arg) {
        return "BotShieldCookieFormat: requires at least one format "
               "(hmac, gcm, or a comma-separated list)";
    }
    int fmt = 0;
    char *buf = apr_pstrdup(cmd->pool, arg);
    char *state = NULL;
    for (char *tok = apr_strtok(buf, ",", &state); tok;
         tok = apr_strtok(NULL, ",", &state)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) end--;
        *end = '\0';
        if (!*tok) continue;
        if      (!strcasecmp(tok, "hmac")) fmt |= BS_FMT_HMAC;
        else if (!strcasecmp(tok, "gcm"))  fmt |= BS_FMT_GCM;
        else {
            return apr_psprintf(cmd->pool,
                "BotShieldCookieFormat: unknown format '%s' "
                "(known: hmac, gcm)", tok);
        }
    }
    if (!fmt) {
        return "BotShieldCookieFormat: at least one format required";
    }
    cfg->cookie_format = fmt;
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
    apr_uint64_t strike_used;
    apr_uint64_t safeguard_used;
    apr_uint64_t bloom_bits_active;
    apr_uint64_t bloom_bits_warming;
} bs_gauge_cache;

/* Thread-local storage. Each worker thread gets its own cache so
 * concurrent /metrics scrapes in one Apache process can't race on the
 * refresh, and we don't need a lock. The 1-second TTL means at worst
 * a thread computes fresh values once per scrape; cost is bounded. */
static __thread bs_gauge_cache bs_gauges = {0, 0, 0, 0, 0, 0};
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

    apr_int64_t now_sec = (apr_int64_t)apr_time_sec(now);
    apr_uint64_t flagged_used = 0;
    if (bs_shm.flagged_table) {
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
    /* E13.1 — strike + safeguard occupancy. "Used" here means the
     * slot would force a probe walk (rule_slot != EMPTY for strike,
     * used != 0 for safeguard), regardless of whether the entry is
     * still TTL-active. That's the right view for load-factor-based
     * probe-saturation warnings. */
    apr_uint64_t strike_used = 0;
    if (bs_shm.strike_table) {
        for (apr_size_t i = 0; i < bs_shm.strike_capacity; i++) {
            const bs_strike_slot *slot = &bs_shm.strike_table[i];
            if ((slot->version & 1U) == 0 &&
                slot->rule_slot != BS_STRIKE_EMPTY) {
                strike_used++;
            }
        }
    }
    apr_uint64_t safeguard_used = 0;
    if (bs_shm.safeguard_table) {
        for (apr_size_t i = 0; i < bs_shm.safeguard_capacity; i++) {
            const bs_safeguard_slot *slot = &bs_shm.safeguard_table[i];
            if ((slot->version & 1U) == 0 && slot->used != 0) {
                safeguard_used++;
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
    bs_gauges.strike_used        = strike_used;
    bs_gauges.safeguard_used     = safeguard_used;
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

static apr_uint64_t bs_metrics_strike_used(void)
{
    bs_gauges_refresh();
    return bs_gauges.strike_used;
}

static apr_uint64_t bs_metrics_safeguard_used(void)
{
    bs_gauges_refresh();
    return bs_gauges.safeguard_used;
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

/* Optional E3 trigger log-tag: set via r->notes so bs_decision_log
 * can emit it without changing the signature that 20+ call sites
 * already use. Read back as a pool-owned string; NULL = no tag. */
#define BS_TRIGGER_TAG_NOTE   "botshield-trigger-tag"
static void bs_set_trigger_tag(request_rec *r, const char *tag)
{
    if (!tag || !*tag) return;
    apr_table_setn(r->notes, BS_TRIGGER_TAG_NOTE,
                   apr_pstrdup(r->pool, tag));
}
static const char *bs_get_trigger_tag(request_rec *r)
{
    return apr_table_get(r->notes, BS_TRIGGER_TAG_NOTE);
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
    const char *tag      = bs_get_trigger_tag(r);
    /* tag= suffix only when a trigger set it; normal decision lines
     * stay byte-identical so existing log parsers don't break. */
    if (tag && *tag) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: decision tier=%s outcome=%s ip=%s score=%d "
            "cookie=%s provider=%s alg=%s reason=\"%s\" path=\"%s\" "
            "tag=\"%s\"",
            tier, outcome, ip, score,
            cookie   ? cookie   : "-",
            provider ? provider : "-",
            alg      ? alg      : "-",
            reason   ? reason   : "-",
            path, tag);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: decision tier=%s outcome=%s ip=%s score=%d "
            "cookie=%s provider=%s alg=%s reason=\"%s\" path=\"%s\"",
            tier, outcome, ip, score,
            cookie   ? cookie   : "-",
            provider ? provider : "-",
            alg      ? alg      : "-",
            reason   ? reason   : "-",
            path);
    }
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

/* ===========================================================
 * E17 PoC — embedded silent verification handlers.
 *
 * Three endpoints under <prefix>/embedded*:
 *   GET  /botshield/embedded.js         — static wrapper script
 *   GET  /botshield/embedded-bootstrap  — JSON: per-call PoW challenge
 *   POST /botshield/embedded-verify     — JSON: validates + sets cookie
 *
 * Activation: scope opts in via `BotShieldSilentMode embedded`.
 * Operator adds <script src="/botshield/embedded.js" defer> to their
 * page. When the request lands at silent tier, BotShield serves
 * DECLINED (real content) instead of the M7 splash; the wrapper runs
 * on page-load, fetches the bootstrap, solves PoW in a Web Worker,
 * and POSTs back. The verify endpoint mints _bs_verified the same
 * way the M7 form-PoW path does, so subsequent requests round-trip
 * cleanly.
 * =========================================================== */

/* The wrapper JS body. Self-contained IIFE; no external deps.
 *
 * Implementation notes:
 *   - blob:-URL Web Worker so we don't need a separate cacheable URL
 *     for the worker code. CSP-strict scopes need worker-src 'self'
 *     blob:; documented as a known gotcha for E17 hardening.
 *   - SubtleCrypto.digest is async, so PoW runs as Promise.all
 *     batches with setTimeout yields between them — same shape the
 *     M2 form interstitial uses, copied here for parity.
 *   - Short-circuit on existing _bs_verified cookie (cheap read of
 *     document.cookie). If the cookie is already there, no Worker
 *     is spawned and no fetch fires.
 *   - One Worker per page-load. _bsEmbeddedRan guard prevents
 *     double-spawn if embedded.js gets included twice. */
static const char BS_EMBEDDED_JS[] =
"(function(){\n"
" if (window._bsEmbeddedRan) return;\n"
" window._bsEmbeddedRan = true;\n"
" if (document.cookie && document.cookie.indexOf('_bs_verified=') !== -1) return;\n"
" fetch('/botshield/embedded-bootstrap', {credentials:'same-origin'})\n"
"  .then(function(r){ return r.ok ? r.json() : null; })\n"
"  .then(function(j){\n"
"   if (!j || j.mode !== 'silent') return;\n"
"   if (j.provider === 'turnstile') { runTurnstile(j); return; }\n"
"   if (j.provider === 'recaptcha-v3') { runRecaptchaV3(j); return; }\n"
"   if (j.provider === 'hcaptcha') { runHCaptcha(j); return; }\n"
"   if (j.provider !== 'pow' || !j.challenge) return;\n"
"   var ch = j.challenge;\n"
"   var workerSrc = '(' + (function(){\n"
"    self.onmessage = function(ev){\n"
"     var c = ev.data;\n"
"     var saltB = hexToBytes(c.salt);\n"
"     var nonceB = hexToBytes(c.nonce);\n"
"     var counter = 0;\n"
"     var BATCH = 1024;\n"
"     var LIMIT = 5000000;\n"
"     function doBatch(){\n"
"      var promises = [];\n"
"      var start = counter;\n"
"      for (var i=0;i<BATCH;i++){\n"
"       var cs = String(start+i);\n"
"       var buf = new Uint8Array(saltB.length + nonceB.length + cs.length);\n"
"       buf.set(saltB,0); buf.set(nonceB,saltB.length);\n"
"       for (var j=0;j<cs.length;j++) buf[saltB.length+nonceB.length+j] = cs.charCodeAt(j);\n"
"       promises.push(crypto.subtle.digest('SHA-256', buf));\n"
"      }\n"
"      Promise.all(promises).then(function(rs){\n"
"       for (var i=0;i<rs.length;i++){\n"
"        if (meets(new Uint8Array(rs[i]), c.difficulty)){\n"
"         self.postMessage({counter: start+i});\n"
"         return;\n"
"        }\n"
"       }\n"
"       counter = start + BATCH;\n"
"       if (counter > LIMIT){ self.postMessage({error:'limit'}); return; }\n"
"       setTimeout(doBatch, 0);\n"
"      }).catch(function(e){ self.postMessage({error:String(e)}); });\n"
"     }\n"
"     function hexToBytes(s){\n"
"      var o = new Uint8Array(s.length/2);\n"
"      for (var i=0;i<s.length;i+=2) o[i/2] = parseInt(s.substr(i,2),16);\n"
"      return o;\n"
"     }\n"
"     function meets(d,n){\n"
"      var fb = (n/2)|0; var hh = n&1;\n"
"      for (var i=0;i<fb;i++) if (d[i] !== 0) return false;\n"
"      if (hh && (d[fb] & 0xF0) !== 0) return false;\n"
"      return true;\n"
"     }\n"
"     doBatch();\n"
"    };\n"
"   }).toString() + ')()';\n"
"   var blob = new Blob([workerSrc], {type:'application/javascript'});\n"
"   var url = URL.createObjectURL(blob);\n"
"   var w = new Worker(url);\n"
"   w.onmessage = function(ev){\n"
"    if (ev.data && typeof ev.data.counter === 'number'){\n"
"     fetch('/botshield/embedded-verify', {\n"
"      method:'POST', credentials:'same-origin',\n"
"      headers:{'Content-Type':'application/json'},\n"
"      body: JSON.stringify({\n"
"       provider: 'pow',\n"
"       v: ch.v, alg: ch.alg, salt: ch.salt, nonce: ch.nonce,\n"
"       difficulty: ch.difficulty, expires_at: ch.expires_at,\n"
"       challenged_at: ch.challenged_at, auto: ch.auto,\n"
"       signature: ch.signature, counter: ev.data.counter\n"
"      })\n"
"     });\n"
"    }\n"
"    w.terminate();\n"
"    URL.revokeObjectURL(url);\n"
"   };\n"
"   w.postMessage(ch);\n"
"  })\n"
"  .catch(function(){});\n"
"\n"
" /* E17.2 — invisible Turnstile path. Cloudflare's api.js is loaded\n"
"    only when this scope's bootstrap says so; explicit-render mode\n"
"    so we control the lifecycle. We mount a hidden div and ask\n"
"    Turnstile for invisible execution; the success callback hands\n"
"    us a token that we POST back to the verify endpoint. The\n"
"    error-callback path is silent — failure here just means the\n"
"    next page-load will get a fresh bootstrap (re-challenge), which\n"
"    is benign under the 'kicks in eventually' model. */\n"
" function runTurnstile(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof turnstile === 'undefined') return;\n"
"   var c = document.createElement('div');\n"
"   c.style.display = 'none';\n"
"   document.body.appendChild(c);\n"
"   try {\n"
"    turnstile.render(c, {\n"
"     sitekey: j.sitekey,\n"
"     size: 'invisible',\n"
"     action: j.action || 'botshield',\n"
"     callback: function(token){\n"
"      fetch('/botshield/embedded-verify', {\n"
"       method:'POST', credentials:'same-origin',\n"
"       headers:{'Content-Type':'application/json'},\n"
"       body: JSON.stringify({provider:'turnstile', token: token})\n"
"      });\n"
"     },\n"
"     'error-callback': function(){}\n"
"    });\n"
"   } catch (e) { /* silent — see fail-mode comment */ }\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"\n"
" /* E17.3 — reCAPTCHA v3 invisible adapter. Materially different\n"
"    client API from Turnstile — Google's grecaptcha is always\n"
"    invisible (no widget element to mount), uses\n"
"    grecaptcha.execute() with action binding instead of\n"
"    render+callback. Server-side, the v3 path also goes through\n"
"    the same M8 siteverify and validates the response score\n"
"    against BotShieldRecaptchaV3MinScore. The wrapper just hands\n"
"    over the token; the policy is server-side. */\n"
" function runRecaptchaV3(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://www.google.com/recaptcha/api.js?render=' +\n"
"          encodeURIComponent(j.sitekey);\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof grecaptcha === 'undefined') return;\n"
"   try {\n"
"    grecaptcha.ready(function(){\n"
"     grecaptcha.execute(j.sitekey,\n"
"                        {action: j.action || 'botshield'})\n"
"      .then(function(token){\n"
"       fetch('/botshield/embedded-verify', {\n"
"        method:'POST', credentials:'same-origin',\n"
"        headers:{'Content-Type':'application/json'},\n"
"        body: JSON.stringify({provider:'recaptcha-v3', token: token})\n"
"       });\n"
"      }).catch(function(){});\n"
"    });\n"
"   } catch (e) {}\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"\n"
" /* E17.4a — hCaptcha invisible adapter. Token-based like\n"
"    Turnstile, but the client API splits render and execute:\n"
"    hcaptcha.render() returns a widget ID; the challenge fires\n"
"    only when the operator calls hcaptcha.execute(widgetId). For\n"
"    invisible mode we render with size:'invisible' (no UI ever\n"
"    shown — hCaptcha's risk engine decides whether to escalate to\n"
"    interactive UI; if it does, the error-callback fires and we\n"
"    silently fall through to the next page-load's bootstrap, same\n"
"    as Turnstile). The siteverify response shape matches Turnstile's\n"
"    {success, hostname, error-codes} contract — no action field,\n"
"    so the action-binding check on the server is a no-op for\n"
"    hCaptcha (the validator already skips when resp_action is\n"
"    NULL). */\n"
" function runHCaptcha(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://js.hcaptcha.com/1/api.js?render=explicit';\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof hcaptcha === 'undefined') return;\n"
"   var c = document.createElement('div');\n"
"   c.style.display = 'none';\n"
"   document.body.appendChild(c);\n"
"   try {\n"
"    var widgetId = hcaptcha.render(c, {\n"
"     sitekey: j.sitekey,\n"
"     size: 'invisible',\n"
"     callback: function(token){\n"
"      fetch('/botshield/embedded-verify', {\n"
"       method:'POST', credentials:'same-origin',\n"
"       headers:{'Content-Type':'application/json'},\n"
"       body: JSON.stringify({provider:'hcaptcha', token: token})\n"
"      });\n"
"     },\n"
"     'error-callback': function(){}\n"
"    });\n"
"    hcaptcha.execute(widgetId);\n"
"   } catch (e) {}\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"})();\n";

static int bs_embedded_js_handler(request_rec *r)
{
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }
    ap_set_content_type(r, "application/javascript; charset=utf-8");
    /* Short max-age so operators can iterate during the PoC without
     * fighting browser caches; production-hardening is E17.1's job. */
    apr_table_setn(r->headers_out, "Cache-Control", "public, max-age=60");
    ap_rputs(BS_EMBEDDED_JS, r);
    return OK;
}

/* GET /botshield/embedded-bootstrap — issue a fresh PoW challenge.
 *
 * Returns one of:
 *   {"mode":"off"}                          — cookie already valid; wrapper exits
 *   {"mode":"silent","challenge":{...}}     — solve this and POST to verify
 *
 * The challenge struct is HMAC-signed with cfg->secret, exactly the
 * same way bs_issue_challenge signs M2/M7 challenges. The verify
 * endpoint reconstructs the same canonical form from the JSON fields
 * and re-validates the HMAC, so the wrapper can't forge a challenge
 * the server didn't issue. */
static int bs_embedded_bootstrap_handler(request_rec *r,
                                         bs_dir_cfg *cfg)
{
    if (r->method_number != M_GET) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET");
        return OK;
    }
    ap_set_content_type(r, "application/json; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    /* If the client already has a valid _bs_verified, no point in
     * burning Worker cycles or loading provider scripts. The wrapper
     * short-circuits on its end too, but a redundant check here
     * costs almost nothing and keeps the bootstrap honest. */
    const char *cookie_val = bs_get_cookie_value(r, BS_COOKIE_NAME);
    if (cookie_val && *cookie_val) {
        bs_challenge tmp;
        const char *err = bs_verify_cookie(r, cfg, cookie_val, &tmp);
        if (!err) {
            ap_rputs("{\"mode\":\"off\"}\n", r);
            return OK;
        }
    }

    /* E17.2 — provider dispatch. If the scope has a captcha provider
     * configured (BotShieldCaptchaProvider + SiteKey + SecretFile),
     * surface that provider's invisible-mode adapter to the wrapper.
     * Otherwise fall back to native PoW. The wrapper's runtime check
     * on the `provider` field is what dispatches to the right
     * client-side path. */
    if (cfg->captcha_provider && cfg->captcha_provider->implemented &&
        cfg->captcha_site_key && cfg->captcha_secret) {
        /* `action` is the string the client widget tags its token
         * with. Both Turnstile and reCAPTCHA v3 understand actions;
         * server-side we validate the response carries it back so
         * tokens minted for a different form/scope can't be replayed
         * here. Operator can override via BotShieldCaptchaExpectedAction;
         * default "botshield" matches the M8 interstitial path. */
        const char *action = cfg->captcha_expected_action
            ? cfg->captcha_expected_action : "botshield";
        ap_rprintf(r,
            "{\"mode\":\"silent\",\"provider\":\"%s\","
            "\"sitekey\":\"%s\",\"action\":\"%s\"}\n",
            cfg->captcha_provider->name,
            cfg->captcha_site_key, action);
        return OK;
    }

    if (!cfg->secret || !cfg->algorithm) {
        ap_rputs("{\"mode\":\"off\"}\n", r);
        return OK;
    }

    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);
    int ttl = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);

    bs_challenge ch;
    memset(&ch, 0, sizeof(ch));
    /* Issue a fresh challenge with default-zero rep state. The
     * verify path will mint a cookie carrying this same rep, which
     * matches what a first-time silent-tier solver would receive. */
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          /* auto_tier */ 1, NULL, NULL, &ch);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: embedded-bootstrap issue failed: %s", ierr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_rputs("{\"error\":\"issue\"}\n", r);
        return OK;
    }

    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    char sig_hex  [BS_SIG_BYTES * 2 + 1];
    bs_to_hex(ch.salt,       BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch.nonce,      BS_NONCE_BYTES, nonce_hex);
    bs_to_hex(ch.signature,  BS_SIG_BYTES,   sig_hex);

    /* Native PoW path. Include challenged_at and auto so the wrapper
     * can round-trip them through the verify POST — the signature
     * in bs_challenge_canonical covers every rep field; if the
     * wrapper doesn't send back exactly the bytes we signed, the
     * signature recomputation in verify will mismatch. Score /
     * flags / passes_* / forgive_* are zero on a fresh challenge so
     * we don't need to surface them — they parse-default to 0 on
     * verify. */
    ap_rprintf(r,
        "{\"mode\":\"silent\",\"provider\":\"pow\","
        "\"challenge\":{"
        "\"v\":%d,\"alg\":\"%s\",\"salt\":\"%s\",\"nonce\":\"%s\","
        "\"difficulty\":%d,\"expires_at\":%" APR_TIME_T_FMT ","
        "\"challenged_at\":%" APR_TIME_T_FMT ",\"auto\":%d,"
        "\"signature\":\"%s\""
        "}}\n",
        ch.version, ch.alg_name, salt_hex, nonce_hex,
        ch.difficulty, ch.expires_at,
        ch.rep.challenged_at, ch.auto_tier,
        sig_hex);
    return OK;
}

/* Pull a string field out of a parsed JSON object, returning a pool-
 * allocated copy or NULL if missing/wrong-type. Bounded copy keeps
 * us from accepting unbounded input from a malicious client. */
static const char *bs_json_get_str(apr_pool_t *p, json_object *root,
                                   const char *key, apr_size_t max_len)
{
    json_object *v = NULL;
    if (!json_object_object_get_ex(root, key, &v)) return NULL;
    if (!json_object_is_type(v, json_type_string)) return NULL;
    const char *s = json_object_get_string(v);
    if (!s) return NULL;
    apr_size_t slen = strlen(s);
    if (slen > max_len) return NULL;
    return apr_pstrdup(p, s);
}

static int bs_json_get_int(json_object *root, const char *key,
                           int *out, int min_val, int max_val)
{
    json_object *v = NULL;
    if (!json_object_object_get_ex(root, key, &v)) return 0;
    if (!json_object_is_type(v, json_type_int)) return 0;
    int64_t n = json_object_get_int64(v);
    if (n < min_val || n > max_val) return 0;
    *out = (int)n;
    return 1;
}

/* PoW-path verify: reconstruct bs_challenge from the round-tripped
 * fields, validate HMAC + PoW counter, mint _bs_verified. Helper
 * pulled out of the dispatcher so the turnstile (and future
 * provider) paths can sit alongside cleanly. */
static int bs_embedded_verify_pow(request_rec *r, bs_dir_cfg *cfg,
                                  json_object *root)
{
    if (!cfg->secret || !cfg->algorithm) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        return OK;
    }

    /* Reconstruct the bs_challenge struct from the JSON. The HMAC
     * signature binds every byte of the canonical form, so any
     * tampered field invalidates the signature check below. */
    bs_challenge ch;
    memset(&ch, 0, sizeof(ch));
    int ok = 1;
    int int_v = 0;
    if (!bs_json_get_int(root, "v",          &int_v, 0, INT_MAX))      ok = 0;
    ch.version = int_v;
    if (!bs_json_get_int(root, "difficulty", &int_v, 1, BS_MAX_DIFFICULTY_HARDCAP)) ok = 0;
    ch.difficulty = int_v;
    int counter = 0;
    if (!bs_json_get_int(root, "counter",    &counter, 0, INT_MAX))     ok = 0;
    json_object *exp_v = NULL;
    apr_int64_t exp64 = 0;
    if (json_object_object_get_ex(root, "expires_at", &exp_v) &&
        json_object_is_type(exp_v, json_type_int)) {
        exp64 = json_object_get_int64(exp_v);
    } else {
        ok = 0;
    }
    ch.expires_at = (apr_time_t)exp64;

    /* challenged_at + auto are part of the canonical form the
     * signature covers, so the wrapper must round-trip them
     * verbatim. */
    json_object *ca_v = NULL;
    if (json_object_object_get_ex(root, "challenged_at", &ca_v) &&
        json_object_is_type(ca_v, json_type_int)) {
        ch.rep.challenged_at = (apr_time_t)json_object_get_int64(ca_v);
    } else {
        ok = 0;
    }
    if (!bs_json_get_int(root, "auto", &int_v, 0, 1)) ok = 0;
    ch.auto_tier = int_v;

    const char *alg_name = bs_json_get_str(r->pool, root, "alg", 64);
    const char *salt_hex = bs_json_get_str(r->pool, root, "salt",
                                           BS_SALT_BYTES * 2);
    const char *nonce_hex = bs_json_get_str(r->pool, root, "nonce",
                                            BS_NONCE_BYTES * 2);
    const char *sig_hex  = bs_json_get_str(r->pool, root, "signature",
                                           BS_SIG_BYTES * 2);
    if (!alg_name || !salt_hex || !nonce_hex || !sig_hex) ok = 0;
    if (!ok) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    const bs_pow_algorithm *alg = bs_find_algorithm(alg_name);
    if (!alg || !alg->implemented) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }
    ch.alg_name = alg->name;

    if (strlen(salt_hex)  != BS_SALT_BYTES * 2  ||
        !bs_from_hex(salt_hex,  BS_SALT_BYTES,  ch.salt) ||
        strlen(nonce_hex) != BS_NONCE_BYTES * 2 ||
        !bs_from_hex(nonce_hex, BS_NONCE_BYTES, ch.nonce) ||
        strlen(sig_hex)   != BS_SIG_BYTES * 2   ||
        !bs_from_hex(sig_hex,   BS_SIG_BYTES,   ch.signature)) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    /* Validate the HMAC against the canonical form. This proves the
     * server issued the challenge and nothing in transit changed. */
    const char *canon = bs_challenge_canonical(r->pool, &ch);
    unsigned char sig_expected[BS_SIG_BYTES];
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon),
                   sig_expected);
    if (!bs_ct_equal(sig_expected, ch.signature, BS_SIG_BYTES)) {
        /* Try secondary key if rotation is in progress (E16). */
        if (cfg->secret_secondary) {
            bs_hmac_sha256(cfg->secret_secondary, cfg->secret_secondary_len,
                           (const unsigned char *)canon, strlen(canon),
                           sig_expected);
        }
        if (!cfg->secret_secondary ||
            !bs_ct_equal(sig_expected, ch.signature, BS_SIG_BYTES)) {
            r->status = HTTP_FORBIDDEN;
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: embedded-verify(pow): bad signature");
            return OK;
        }
    }

    apr_time_t now = apr_time_sec(apr_time_now());
    if (now > ch.expires_at) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: embedded-verify(pow): challenge expired");
        return OK;
    }

    char counter_str[24];
    apr_snprintf(counter_str, sizeof(counter_str), "%d", counter);
    const char *verr = alg->verify(&ch, counter_str);
    if (verr) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: embedded-verify(pow): PoW reject: %s", verr);
        return OK;
    }

    /* Mint _bs_verified the same way the M7 form-PoW does — same
     * cookie shape, same expiry, same signature path. The counter
     * the wrapper found rides into the cookie body so future
     * requests can replay-detect. */
    ch.rep.passes_silent = 1;
    canon = bs_challenge_canonical(r->pool, &ch);
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon),
                   ch.signature);
    const char *payload = bs_build_cookie_payload(r->pool, cfg, &ch,
                                                  counter_str);
    if (!payload) {
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        return OK;
    }
    apr_table_set(r->err_headers_out, "Set-Cookie",
                  bs_build_set_cookie(r, cfg, payload, ch.expires_at));

    r->status = HTTP_NO_CONTENT;
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
        "mod_botshield: embedded-verify(pow): cookie minted (counter=%d)",
        counter);
    return OK;
}

/* Provider-path verify (E17.2 — first lands Turnstile invisible).
 * The wrapper has called the provider's invisible widget and got a
 * token; we siteverify it against the configured provider via the
 * existing M8 client, then mint _bs_verified using the same
 * captcha-<provider> cookie alg the M8 interstitial path uses.
 *
 * Body shape: {"provider":"<name>","token":"<token>"}. */
static int bs_embedded_verify_provider(request_rec *r, bs_dir_cfg *cfg,
                                       json_object *root,
                                       const char *provider_name)
{
    if (!cfg->captcha_provider || !cfg->captcha_provider->implemented ||
        !cfg->captcha_secret) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: embedded-verify(%s): scope has no "
            "captcha provider configured for this provider name",
            provider_name);
        return OK;
    }
    if (strcmp(cfg->captcha_provider->name, provider_name) != 0) {
        r->status = HTTP_BAD_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: embedded-verify(%s): wrapper claimed "
            "provider but scope is configured for '%s'",
            provider_name, cfg->captcha_provider->name);
        return OK;
    }

    const char *token = bs_json_get_str(r->pool, root, "token",
                                        BS_MAX_CAPTCHA_TOKEN);
    if (!token || !*token) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    /* Reuse M8's siteverify path. Same provider entry, same
     * secret/sitekey, same body shape — the only difference vs.
     * /captcha-verify is that we don't redirect afterward and that
     * we mint a cookie marked passes_silent=1 instead of
     * passes_captcha=1. */
    int timeout_ms = cfg->captcha_timeout_ms > 0
        ? cfg->captcha_timeout_ms : BS_DEFAULT_CAPTCHA_TIMEOUT;
    const char *details = NULL;
    long http_code = 0;
    double score = -1.0;
    const char *resp_hostname = NULL, *resp_action = NULL;
    bs_captcha_result res = bs_captcha_siteverify(r,
        cfg->captcha_provider, cfg->captcha_secret,
        cfg->captcha_secret_len, token, timeout_ms,
        &details, &http_code, &score, &resp_hostname, &resp_action);

    if (res != BS_CAPTCHA_OK) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: embedded-verify(%s): siteverify rejected "
            "(http=%ld details=\"%s\")", provider_name, http_code,
            details ? details : "");
        return OK;
    }

    /* Post-siteverify validation parity with the M8 captcha-verify
     * handler (security review #1). Hostname + action binding stops
     * a token minted for a different scope/form on the same sitekey
     * from satisfying verification here. v3 score threshold caps
     * "valid token but signal is weak". Operator can opt out of
     * either binding by setting the directive to empty. */
    const char *expected_host =
        cfg->captcha_expected_hostname
            ? cfg->captcha_expected_hostname
            : (r->server && r->server->server_hostname
                   ? r->server->server_hostname : "");
    const char *expected_action =
        cfg->captcha_expected_action
            ? cfg->captcha_expected_action : "botshield";

    if (resp_hostname && *expected_host &&
        strcmp(resp_hostname, expected_host) != 0) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: embedded-verify(%s): hostname-mismatch "
            "(got=%s expected=%s)", provider_name,
            resp_hostname, expected_host);
        return OK;
    }
    if (resp_action && *expected_action &&
        strcmp(resp_action, expected_action) != 0) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: embedded-verify(%s): action-mismatch "
            "(got=%s expected=%s)", provider_name,
            resp_action, expected_action);
        return OK;
    }
    if (strcmp(provider_name, "recaptcha-v3") == 0) {
        double min_score = (cfg->recaptcha_v3_min_score >= 0.0)
            ? cfg->recaptcha_v3_min_score
            : BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE;
        if (score < 0.0) {
            /* Missing score on a v3 response is a protocol surprise
             * (v3 always returns one). Fail open with a warning —
             * matches the M8 path's behavior. */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: embedded-verify(recaptcha-v3): "
                "response missing score — failing open "
                "(http=%ld)", http_code);
        } else if (score < min_score) {
            r->status = HTTP_FORBIDDEN;
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: embedded-verify(recaptcha-v3): "
                "score below threshold (%.2f < %.2f)",
                score, min_score);
            return OK;
        }
    }

    /* Mint a captcha-<provider> cookie just like the M8 interstitial
     * path does. The only rep delta is passes_silent=1 vs
     * passes_captcha=1 — this was a silent-tier dispatch that
     * happened to use a captcha provider for the verification, not
     * a captcha-tier user-interactive solve. */
    int ttl        = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);
    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);
    const char *cookie_alg_name = apr_psprintf(r->pool, "captcha-%s",
                                               cfg->captcha_provider->name);
    const bs_pow_algorithm *captcha_alg = bs_find_algorithm(cookie_alg_name);
    if (!captcha_alg || !captcha_alg->implemented) {
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: embedded-verify(%s): cookie alg '%s' "
            "missing from registry", provider_name, cookie_alg_name);
        return OK;
    }

    bs_rep_state next_rep;
    memset(&next_rep, 0, sizeof(next_rep));
    next_rep.passes_silent = 1;

    bs_challenge ch;
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          /* auto_tier */ 1,
                                          captcha_alg, &next_rep, &ch);
    if (ierr) {
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: embedded-verify(%s): cookie issue failed: %s",
            provider_name, ierr);
        return OK;
    }

    const char *payload = bs_build_cookie_payload(r->pool, cfg, &ch,
                                                  "captcha");
    if (!payload) {
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        return OK;
    }
    apr_table_set(r->err_headers_out, "Set-Cookie",
                  bs_build_set_cookie(r, cfg, payload, ch.expires_at));

    r->status = HTTP_NO_CONTENT;
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
        "mod_botshield: embedded-verify(%s): cookie minted "
        "(siteverify ok)", provider_name);
    return OK;
}

/* POST /botshield/embedded-verify — dispatcher.
 *
 * Body shape (JSON):
 *   PoW path:
 *     {"provider":"pow","v":N, "alg":"sha256-zeros",
 *      "salt":"<hex>", "nonce":"<hex>", "difficulty":N,
 *      "expires_at":N, "challenged_at":N, "auto":N,
 *      "signature":"<hex>", "counter":N}
 *   Provider path (turnstile et al.):
 *     {"provider":"turnstile","token":"<token>"}
 *
 * On success: 204 + Set-Cookie: _bs_verified=...; ...
 * On failure: 4xx; no cookie. */
#define BS_EMBEDDED_BODY_MAX 8192   /* turnstile tokens are ~600 bytes */
static int bs_embedded_verify_handler(request_rec *r, bs_dir_cfg *cfg)
{
    if (r->method_number != M_POST) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "POST");
        return OK;
    }

    apr_size_t body_len = 0;
    const char *body = bs_read_form_body(r, BS_EMBEDDED_BODY_MAX, &body_len);
    if (!body || body_len == 0) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    enum json_tokener_error jerr = json_tokener_success;
    json_object *root = json_tokener_parse_verbose(body, &jerr);
    if (!root || jerr != json_tokener_success) {
        if (root) json_object_put(root);
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    const char *provider = bs_json_get_str(r->pool, root, "provider", 32);
    if (!provider) provider = "pow";   /* legacy compat */

    int rv;
    if (strcmp(provider, "pow") == 0) {
        rv = bs_embedded_verify_pow(r, cfg, root);
    } else {
        rv = bs_embedded_verify_provider(r, cfg, root, provider);
    }
    json_object_put(root);
    return rv;
}
/* end E17 PoC handlers */

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

    bs_m_emit_counter(r, "bot_allow_total",
        "Requests whose crawler UA matched the published IP ranges for "
        "that crawler (legit-bot bypass applied).",
        bs_mload(&m->bot_allow_total));
    bs_m_emit_counter(r, "bot_fake_total",
        "Requests with a known-crawler UA whose IP was NOT in that "
        "crawler's published ranges (penalty applied, routed to captcha tier).",
        bs_mload(&m->bot_fake_total));
    bs_m_emit_counter(r, "bot_unverified_total",
        "Requests whose crawler UA matched a known pattern but no ranges "
        "file is configured for that crawler (no score effect, logged).",
        bs_mload(&m->bot_unverified_total));

    /* --- E2.1 policy-enforcement counters --- */

    bs_m_emit_counter(r, "rate_limit_observed_total",
        "Rate-limit over-budget events that ran in observe mode "
        "(per-rule mode=observe or BotShieldShadowMode on); rule "
        "would have returned 429 but didn't.",
        bs_mload(&m->rate_limit_observed_total));
    bs_m_emit_counter(r, "block_path_observed_total",
        "Block-path matches that ran in observe mode; rule would "
        "have returned 403 but didn't.",
        bs_mload(&m->block_path_observed_total));
    bs_m_emit_counter(r, "trigger_observed_total",
        "Trigger matches (path/cookie/env/load) that ran in observe "
        "mode across all families.",
        bs_mload(&m->trigger_observed_total));
    bs_m_emit_counter(r, "rate_limit_exceeded_total",
        "Requests that tripped a BotShieldRateLimit cohort budget "
        "(response was 429 + Retry-After).",
        bs_mload(&m->rate_limit_exceeded_total));
    bs_m_emit_counter(r, "block_path_hit_total",
        "Requests that matched a BotShieldBlockPath cohort+path-glob "
        "(response was 403).",
        bs_mload(&m->block_path_hit_total));

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
    bs_m_emit_gauge(r, "shm_strike_used",
        "Strike-table slots physically occupied "
        "(rule_slot != BS_STRIKE_EMPTY).",
        bs_metrics_strike_used());
    bs_m_emit_gauge(r, "shm_strike_capacity",
        "Configured BotShieldRateLimitEscalateCapacity.",
        (apr_uint64_t)bs_shm.strike_capacity);
    bs_m_emit_gauge(r, "shm_safeguard_used",
        "Safeguard-table slots physically occupied (used != 0).",
        bs_metrics_safeguard_used());
    bs_m_emit_gauge(r, "shm_safeguard_capacity",
        "Configured BotShieldSafeguardCapacity.",
        (apr_uint64_t)bs_shm.safeguard_capacity);
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

    /* E11 — load-state observability. The gauge is the most useful
     * value to alert on; the counter lets operators graph state
     * transitions per minute. */
    bs_m_emit_gauge(r, "load_state",
        "Current cached load state (0=normal, 1=warm, 2=hot).",
        (apr_uint64_t)(bs_shm.header
                       ? bs_shm.header->load_state : 0));
    bs_m_emit_counter(r, "load_state_changes_total",
        "Number of load-state transitions since the SHM was created.",
        (apr_uint64_t)(bs_shm.header
                       ? bs_shm.header->load_state_changes : 0));

    return OK;
}

/* ======================================================================
 * E2.2.3 — /botshield/policy-status
 *
 * Plain-text dump of the rules currently being enforced:
 *   - BotShieldRateLimit directives (directive rate_limits array).
 *   - BotShieldBlockPath directives (directive block_paths array).
 *   - robots.txt-derived groups (if BotShieldRobotsTxt is set) —
 *     source file path, mtime, every group's UA tokens + rules +
 *     Crawl-delay.
 *
 * Goal is operator-visibility: when E2.2.2 hot-swaps a freshly-edited
 * robots.txt, operators can curl this page to confirm what the module
 * is actually enforcing, rather than guessing. Also useful for
 * verifying that `BotShieldAllow` overrides have landed.
 *
 * No authentication / no rate limit built in. Treat like mod_status —
 * operators wrap it in `<Location>` with their own ACL. The page
 * doesn't reveal cookie secrets or client IPs; the most sensitive
 * content is the operator's own directive config, which is already
 * on disk in /etc/apache2/.
 *
 * Format is plain text (not Prometheus) — this is meant to be read
 * by humans over curl; structured consumers use /botshield/metrics.
 * ====================================================================== */

static void bs_psh_cohort_ipspec(request_rec *r, const bs_cohort *c)
{
    if (c->ip_any) { ap_rputs("*", r); return; }
    if (c->inline_cidrs) {
        ap_rprintf(r, "inline(%s)", c->inline_cidrs);
        return;
    }
    if (c->path) {
        ap_rprintf(r, "file(%s)", c->path);
        return;
    }
    ap_rprintf(r, "<%d ranges>", c->ranges ? c->ranges->nelts : 0);
}

static void bs_psh_render_counter(request_rec *r, int slot_idx,
                                  apr_uint32_t budget)
{
    bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
    if (slot_idx < 0 || !counters) {
        ap_rputs("-/-", r);
        return;
    }
    apr_uint32_t cnt = __atomic_load_n(&counters[slot_idx].count,
                                       __ATOMIC_RELAXED);
    ap_rprintf(r, "%u/%u", cnt, budget);
}

static int bs_policy_status_handler(request_rec *r, bs_dir_cfg *cfg)
{
    (void)cfg;
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }
    ap_set_content_type(r, "text/plain; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    if (!scfg) {
        ap_rputs("# scfg unavailable\n", r);
        return OK;
    }

    char tbuf[APR_RFC822_DATE_LEN + 1] = { 0 };
    apr_rfc822_date(tbuf, apr_time_now());
    ap_rprintf(r, "# mod_botshield policy status\n"
                  "# vhost:       %s\n"
                  "# server_time: %s\n\n",
        r->server->server_hostname ? r->server->server_hostname : "-",
        tbuf);

    /* --- directive rate limits --- */
    ap_rputs("## BotShieldRateLimit (directive)\n", r);
    if (!scfg->rate_limits || scfg->rate_limits->nelts == 0) {
        ap_rputs("# (none)\n\n", r);
    } else {
        ap_rputs("# name               budget  window  ua                          "
                 "ipspec                slot  count/budget\n", r);
        for (int i = 0; i < scfg->rate_limits->nelts; i++) {
            bs_rate_limit_entry *e = APR_ARRAY_IDX(
                scfg->rate_limits, i, bs_rate_limit_entry *);
            ap_rprintf(r, "%-18s  %6u  %4us   %-26s  ",
                e->name, e->budget, e->window_sec,
                e->cohort.ua_any ? "*"
                    : apr_psprintf(r->pool, "\"%s\"", e->cohort.ua_pattern));
            bs_psh_cohort_ipspec(r, &e->cohort);
            ap_rprintf(r, "%*s  %4d  ",
                       (int)(22 - (e->cohort.ip_any ? 1
                          : (int)(strlen("file()") + (e->cohort.path ? strlen(e->cohort.path) : 0)
                                  + (e->cohort.inline_cidrs ? strlen(e->cohort.inline_cidrs) : 0)))),
                       "", e->shm_slot);
            bs_psh_render_counter(r, e->shm_slot, e->budget);
            ap_rputs("\n", r);
        }
        ap_rputs("\n", r);
    }

    /* --- directive block paths --- */
    ap_rputs("## BotShieldBlockPath (directive)\n", r);
    if (!scfg->block_paths || scfg->block_paths->nelts == 0) {
        ap_rputs("# (none)\n\n", r);
    } else {
        ap_rputs("# name               path-glob                     "
                 "ua                          ipspec\n", r);
        for (int i = 0; i < scfg->block_paths->nelts; i++) {
            bs_block_path_entry *e = APR_ARRAY_IDX(
                scfg->block_paths, i, bs_block_path_entry *);
            ap_rprintf(r, "%-18s  %-28s  %-26s  ",
                e->name, e->path_pattern,
                e->cohort.ua_any ? "*"
                    : apr_psprintf(r->pool, "\"%s\"", e->cohort.ua_pattern));
            bs_psh_cohort_ipspec(r, &e->cohort);
            ap_rputs("\n", r);
        }
        ap_rputs("\n", r);
    }

    /* --- robots.txt --- */
    ap_rputs("## robots.txt (BotShieldRobotsTxt)\n", r);
    if (!scfg->robots_txt_path) {
        ap_rputs("# (not configured)\n", r);
        return OK;
    }
    bs_robots_state *rs =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    ap_rprintf(r, "# path:                %s\n", scfg->robots_txt_path);
    if (!rs) {
        ap_rputs("# status:              not loaded (parse failed or "
                 "file missing at post_config)\n", r);
        return OK;
    }
    char mbuf[APR_RFC822_DATE_LEN + 1] = { 0 };
    apr_rfc822_date(mbuf, rs->mtime);
    ap_rprintf(r, "# mtime:               %s\n"
                  "# groups:              %d\n"
                  "# slot pool:           %d/%d used\n"
                  "# wildcard scope:      %s\n"
                  "# refresh interval:    %d s%s\n",
        mbuf,
        robots_group_count(rs->doc),
        scfg->robots_slot_pool_used, scfg->robots_slot_pool_size,
        scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_STRICT ? "strict"
          : scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_OFF ? "off"
          : "heuristic",
        scfg->robots_refresh_interval,
        scfg->robots_refresh_interval == 0 ? " (live-refresh disabled)" : "");

    int n = robots_group_count(rs->doc);
    for (int i = 0; i < n; i++) {
        ap_rprintf(r, "\n### group[%d] \"%s\"  wildcard=%s\n", i,
            robots_group_name_at(rs->doc, i),
            robots_group_is_wildcard_at(rs->doc, i) ? "yes" : "no");
        int n_ua = robots_group_ua_count_at(rs->doc, i);
        for (int u = 0; u < n_ua; u++) {
            ap_rprintf(r, "  user-agent: %s\n",
                robots_group_ua_at(rs->doc, i, u));
        }
        int n_rules = robots_group_rule_count_at(rs->doc, i);
        for (int k = 0; k < n_rules; k++) {
            const char *pat = NULL;
            int allow = 0;
            if (robots_group_rule_at(rs->doc, i, k, &pat, &allow)) {
                ap_rprintf(r, "  %-9s %s\n",
                    allow ? "Allow:" : "Disallow:", pat ? pat : "");
            }
        }
        int cd = robots_group_crawl_delay_at(rs->doc, i);
        if (cd > 0) {
            int slot = (rs->slot_by_group_idx && i < n)
                     ? rs->slot_by_group_idx[i] : -1;
            ap_rprintf(r, "  Crawl-delay: %ds  slot=%d  ", cd, slot);
            bs_psh_render_counter(r, slot, 1);
            ap_rputs("\n", r);
        }
    }
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
        /* E15 — clamp forgiveness against the per-cookie
         * hourly cap. Window state lives in the cookie rep; a fresh
         * cookie starts with window_start=0 which the helper treats
         * as "open new window now." */
        bs_server_cfg *scfg_fc = ap_get_module_config(
            r->server->module_config, &botshield_module);
        int cap = scfg_fc && scfg_fc->forgive_cap_per_hour > 0
                ? scfg_fc->forgive_cap_per_hour
                : BS_DEFAULT_FORGIVE_CAP_PER_HOUR;
        apr_uint32_t now_sec = (apr_uint32_t)apr_time_sec(apr_time_now());
        next_rep = prior_ch.rep;
        forgive = bs_forgiveness_apply_cap(forgive, cap, now_sec,
                    &next_rep.forgive_window_start,
                    &next_rep.forgive_consumed);
        int floor   = bs_flag_penalty(prior_ch.rep.flags);
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < floor) new_score = floor;
        if (new_score < 0)     new_score = 0;
        next_rep.score          = new_score;
        next_rep.passes_captcha = prior_ch.rep.passes_captcha + 1;
    } else {
        next_rep.score          = 0;
        next_rep.flags          = 0;
        next_rep.passes_silent  = 0;
        next_rep.passes_form    = 0;
        next_rep.passes_captcha = 1;
        next_rep.challenged_at  = 0;   /* overwritten by issue() */
        next_rep.forgive_window_start = 0;
        next_rep.forgive_consumed     = 0;
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

    const char *payload = bs_build_cookie_payload(r->pool, cfg, &ch, "captcha");
    if (!payload) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: failed to build cookie payload "
            "(cookie_format=0x%x)", bs_effective_cookie_format(cfg));
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Service error: could not issue cookie.\n", r);
        return OK;
    }
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
    bs_check_allow(r, dcfg);

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
    /* E16 — graceful secret rotation. */
    AP_INIT_TAKE1("BotShieldSecondarySecretFile",
                 bs_set_secondary_secret_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to a verify-only secondary HMAC/GCM key for "
                 "graceful secret rotation. Issue path always uses "
                 "BotShieldSecretFile; verify tries primary then "
                 "secondary, so cookies signed under the OLD key keep "
                 "validating during the rotation window. Same mode-0600 "
                 "+ >= 16-byte hygiene as the primary. Remove the "
                 "directive after one BotShieldCookieTTL window has "
                 "elapsed and every active cookie is back on the new "
                 "key."),
    AP_INIT_TAKE1("BotShieldAlgorithm",  bs_set_algorithm,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Proof-of-work algorithm name. Only 'sha256-zeros' is built "
                 "into this module today; 'sha384-zeros' / 'sha512-zeros' / "
                 "'pbkdf2-sha256' / 'argon2id' are registry slots reserved "
                 "for future opt-in builds."),
    AP_INIT_TAKE1("BotShieldCookieFormat", bs_set_cookie_format, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Cookie wire format: hmac (legacy cleartext+HMAC; "
                 "default), gcm (AES-256-GCM; rep block confidential), "
                 "or a comma-separated list (e.g., 'gcm,hmac' for "
                 "migration: issue GCM, accept either). AES key is "
                 "SHA-256(BotShieldSecretFile bytes); same secret file "
                 "for both primitives."),
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
    /* E17 PoC — silent-tier dispatch flavor. */
    AP_INIT_TAKE1("BotShieldSilentMode", bs_set_silent_mode, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "How to dispatch silent-tier (low-friction) "
                 "challenges. 'interstitial' (default) = legacy M7 "
                 "auto-submit splash. 'embedded' = serve real page "
                 "(DECLINED) and rely on the operator-included "
                 "/botshield/embedded.js wrapper to do PoW in a Web "
                 "Worker and POST the result back to "
                 "/botshield/embedded-verify. The verified cookie "
                 "may not arrive in time for the very first request, "
                 "but it lands within a few page-views — see PLAN "
                 "E17 for the timing model."),
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
                 "fake_bot, pow_fail_streak. Optional second argument "
                 "is the TTL in seconds (default 3600). Use inside a "
                 "<Location> for honeypot paths."),
    /* E1 — Allow family */
    AP_INIT_FLAG("BotShieldAllow", bs_set_allow_enabled,
                 NULL, RSRC_CONF,
                 "Enable the Allow family (verified-bot first member). "
                 "Default off. When on, classified bot UAs are matched "
                 "against loaded IP ranges: in-range gets a large "
                 "negative credit (tier=pass bypass); out-of-range "
                 "gets a fake-<name> penalty routing to captcha tier."),
    AP_INIT_TAKE23("BotShieldAllowBot",
                 bs_set_allow_bot, NULL, RSRC_CONF,
                 "Register a bot for the Allow family. Args: "
                 "<name> <ua-pattern> [<target>]. Name is a [a-z0-9-] "
                 "token used as the decision-log identifier and "
                 "default ranges-file basename. UA-pattern is the "
                 "case-insensitive substring looked for in the "
                 "User-Agent header. Optional target: '*' for UA-only "
                 "trust (logs allow-bot-ua:<name>), an absolute file "
                 "path, a single CIDR, or a comma-separated CIDR "
                 "list. Omit the target to use the default file path "
                 "/var/lib/botshield/bots/<name>.txt."),
    /* E2.1 — policy enforcement. TAKE_ARGV because Apache has no
     * TAKE4/TAKE5 macros; the setters enforce argc themselves. */
    AP_INIT_TAKE_ARGV("BotShieldRateLimit",
                 bs_set_rate_limit, NULL, RSRC_CONF,
                 "Rate-limit a named cohort. Args: <name> <budget> "
                 "<per> <ua> <ipspec>. Per is sec/min/hour (or "
                 "s/m/h). UA is a substring (case-insensitive) or "
                 "'*' for any UA. Ipspec is '*', an absolute file "
                 "path, or a single / comma-separated CIDR list. "
                 "Both-'*' is rejected. Over-budget requests return "
                 "429 + Retry-After and get a +50 score penalty "
                 "under reason rate-limit-exceeded:<name>."),
    /* E9 — repeated-429 escalation. Sits on top of BotShieldRateLimit;
     * does not apply to robots.txt Crawl-delay 429s in v1 (no operator
     * handle for them). */
    AP_INIT_TAKE_ARGV("BotShieldRateLimitEscalate",
                 bs_set_rate_limit_escalate, NULL, RSRC_CONF,
                 "Promote repeated 429s on a named BotShieldRateLimit "
                 "into a stricter status. Args: <rate-name> <strikes> "
                 "<per> [status=<code>] [ttl=<sec>] [log=<tag>]. "
                 "Per accepts sec/min/hour. Once <strikes> rejected "
                 "requests accumulate within <per>, subsequent "
                 "requests against the same rule return status= "
                 "(default 403) for ttl= seconds (default 1800). The "
                 "ttl slides on each additional strike; log=<tag> "
                 "rides the decision line on threshold crossing for "
                 "fail2ban handoff. Reason rate-limit-abuse:<name>."),
    AP_INIT_TAKE1("BotShieldRateLimitEscalateCapacity",
                 bs_set_rate_escalate_capacity, NULL, RSRC_CONF,
                 "SHM strike-table slot count (default 50000). Sized "
                 "for (concurrent-misbehaving-IPs * named-rate-rules) "
                 "headroom; same eviction discipline as the flagged-"
                 "IP table when the probe window saturates. Read at "
                 "post_config from the main server's value."),
    /* E10 — challenge safeguard / anti-loop hysteresis. */
    AP_INIT_FLAG("BotShieldSafeguard",
                 bs_set_safeguard, NULL, RSRC_CONF,
                 "Enable anti-loop hysteresis (default off). When on, "
                 "a client that gets challenged N times within W "
                 "seconds without solving any challenge is passed "
                 "through for a TTL window instead of being re-"
                 "challenged. Decision log shows reason "
                 "challenge-safeguard. Doesn't mint _bs_verified; "
                 "doesn't override 403/429 blocks."),
    AP_INIT_TAKE1("BotShieldSafeguardThreshold",
                 bs_set_safeguard_threshold, NULL, RSRC_CONF,
                 "Presentations-without-solve inside the window "
                 "before safeguard trips (default 5; range 1..1000)."),
    AP_INIT_TAKE1("BotShieldSafeguardWindow",
                 bs_set_safeguard_window, NULL, RSRC_CONF,
                 "Counting window in seconds for the threshold "
                 "(default 600; range 1..86400)."),
    AP_INIT_TAKE1("BotShieldSafeguardTTL",
                 bs_set_safeguard_ttl, NULL, RSRC_CONF,
                 "How long safeguard stays active after the last "
                 "presentation (default 900 seconds; range "
                 "1..604800). Slides on each fresh presentation "
                 "during active safeguard."),
    AP_INIT_TAKE1("BotShieldSafeguardCapacity",
                 bs_set_safeguard_capacity, NULL, RSRC_CONF,
                 "SHM safeguard-table slot count (default 50000). "
                 "Per-server-scope but only the main server's value "
                 "is consulted at post_config since the table is "
                 "module-global."),
    /* E11 — load-aware throttling. Sampling + cached state. */
    AP_INIT_TAKE1("BotShieldLoadStateFile",
                 bs_set_load_state_file, NULL, RSRC_CONF,
                 "Optional file the operator's monitoring system "
                 "writes to push a load-state override into the "
                 "module. Body is one of normal/warm/hot. Watchdog "
                 "stat-polls mtime; only re-reads on change. "
                 "Most-severe-wins merging with internal sensing."),
    AP_INIT_TAKE1("BotShieldLoadRefreshInterval",
                 bs_set_load_refresh, NULL, RSRC_CONF,
                 "Watchdog tick period in seconds (default 1; "
                 "1..60). Lower = faster brownout response; higher "
                 "= less work in mod_watchdog."),
    AP_INIT_TAKE1("BotShieldLoadWarmThreshold",
                 bs_set_load_warm_pct, NULL, RSRC_CONF,
                 "Busy-worker percentage at which a tick samples "
                 "as 'warm' (default 65; range 1..99). Hysteresis "
                 "still applies — promotion takes 3 consecutive "
                 "warm-or-hot samples."),
    AP_INIT_TAKE1("BotShieldLoadHotThreshold",
                 bs_set_load_hot_pct, NULL, RSRC_CONF,
                 "Busy-worker percentage at which a tick samples "
                 "as 'hot' (default 85; range 1..99). Must be "
                 "greater than the warm threshold."),
    /* E13 — per-vhost reputation namespacing. */
    AP_INIT_TAKE1("BotShieldShareScope",
                 bs_set_share_scope, NULL, RSRC_CONF,
                 "Reputation-namespace override token. By default, "
                 "each vhost gets an isolated SHM namespace derived "
                 "from siphash(ServerName), so flagged-IP / Bloom / "
                 "strike / safeguard tables don't share rows across "
                 "unrelated sites. Set this directive to the same "
                 "token on two or more vhosts to force them to share "
                 "(e.g., dev+prod for one logical app, or api+www "
                 "subdomains). Strings up to 128 chars; hashed to a "
                 "32-bit ns_id and stored in each SHM slot."),
    /* E12 — shadow / dry-run enforcement. */
    AP_INIT_FLAG("BotShieldShadowMode",
                 bs_set_shadow_mode, NULL, RSRC_CONF,
                 "Master switch for dry-run enforcement. When on, "
                 "all trigger / rate-limit / block-path rules log "
                 "matches with a :observe suffix instead of taking "
                 "their action — useful for staging a whole policy "
                 "revision before flipping enforcement on. Default "
                 "off; per-rule mode=observe is the finer-grained "
                 "alternative."),
    /* E14 — adaptive challenge intensity. */
    AP_INIT_TAKE_ARGV("BotShieldFlag",
                 bs_set_flag, NULL, RSRC_CONF,
                 "Override metadata for a registered flag bit. "
                 "Args: <name> [penalty=N] [next_difficulty=±N] "
                 "[next_tier=pass|silent|form|captcha]. The flag "
                 "name picks the existing bit (honeypot_hit, "
                 "scanner_probe, fake_bot, pow_fail_streak, "
                 "app_verified_human, app_verified_session, "
                 "app_trust_signal); penalty replaces the built-in "
                 "score contribution; next_difficulty sums into the "
                 "PoW difficulty when the bit is set on the request "
                 "(IP- or cookie-derived); next_tier acts as a tier "
                 "FLOOR — score-derived tier is taken if higher, "
                 "but never lower."),
    AP_INIT_TAKE1("BotShieldMaxDifficulty",
                 bs_set_max_difficulty, NULL, RSRC_CONF,
                 "Server-scope ceiling on the effective PoW "
                 "difficulty after BotShieldFlag adaptive bumps. "
                 "Default 8 (matches BotShieldDifficulty's max); "
                 "raise up to 16 if operator-side adaptive policy "
                 "needs more headroom. Adaptive bumps that would "
                 "exceed this ceiling are silently clamped."),
    /* E15 — forgiveness farming defense. */
    AP_INIT_TAKE1("BotShieldForgivenessCapPerHour",
                 bs_set_forgive_cap, NULL, RSRC_CONF,
                 "Per-cookie cap on accumulated forgiveness points "
                 "inside a rolling 1-hour window. Default 200 — "
                 "enough for a real user pinned at borderline-"
                 "suspicious to keep transacting; tight enough that "
                 "a patient bot solving every few minutes stops "
                 "earning forgiveness past the cap. 0 disables the "
                 "cap (legacy behavior). Range 0..1000."),
    AP_INIT_TAKE_ARGV("BotShieldBlockPath",
                 bs_set_block_path, NULL, RSRC_CONF,
                 "Block a named cohort from a path glob. Args: "
                 "<name> <path-glob> <ua> <ipspec>. Path-glob must "
                 "begin with '/'; trailing '*' = prefix match, "
                 "trailing '$' = exact match. Hits return 403 with "
                 "a +100 score penalty under reason "
                 "block-path:<name>."),
    /* E4 — cookie triggers */
    AP_INIT_TAKE_ARGV("BotShieldCookieTrigger",
                 bs_set_cookie_trigger, NULL, RSRC_CONF,
                 "Cookie-based trigger. Args: <name> <cookie-match> "
                 "[key=value ...]. cookie-match is one of: "
                 "cookie=<n>, cookie=<n>=<v>, cookie=<n>~<substr>, "
                 "cookie=<n>!<v>, !cookie=<n>, cookies=<none|any|"
                 "session>, bs-cookie=<verified|missing|invalid>. "
                 "Keys: status=<code|pass> (default pass; diverges "
                 "from E3 — credit/penalty here ALWAYS apply, even "
                 "under pass), redirect=<url>, log=<tag>, flag=<bit>, "
                 "ttl=<sec>, penalty=<n>, credit=<n>. Declaration "
                 "order; pass triggers accumulate credit/penalty "
                 "(layered reputation signals), first non-pass "
                 "trigger short-circuits the response. Upsert-by-"
                 "name."),
    AP_INIT_TAKE1("BotShieldSessionCookieName",
                 bs_set_session_cookie_name, NULL, RSRC_CONF,
                 "Add a cookie name to the list matched by the "
                 "cookies=session predicate. Curated defaults: "
                 "PHPSESSID, JSESSIONID, ASP.NET_SessionId, "
                 "session_id, connect.sid, laravel_session. Each "
                 "invocation appends one name; case-insensitive."),
    /* E6 — env-var triggers */
    AP_INIT_TAKE_ARGV("BotShieldEnvTrigger",
                 bs_set_env_trigger, NULL, RSRC_CONF,
                 "Env-var-based trigger, reads r->subprocess_env. "
                 "Args: <name> <env-match> [key=value ...]. "
                 "env-match is one of: env=<var> (present), "
                 "env=<var>=<value> (exact match, case-sensitive), "
                 "!env=<var> (absent). Keys: status=<code|pass> "
                 "(default pass; credit/penalty apply under pass "
                 "like E4), log=<tag>, flag=<bit>, ttl=<sec>, "
                 "penalty=<n>, credit=<n>. No redirect= (env "
                 "signals are scoring/flagging only). Declaration "
                 "order, first match wins; upsert-by-name. Main "
                 "requests only — subrequests are no-ops."),
    /* E7.3 — feedback triggers (response-path mapping for E5) */
    AP_INIT_TAKE_ARGV("BotShieldFeedbackTrigger",
                 bs_set_feedback_trigger, NULL, RSRC_CONF,
                 "Map an app-signed event (via X-BotShield-Feedback "
                 "header) to module memory. Args: <event> "
                 "[key=value ...]. Required keys: flag=<bit>, "
                 "ttl=<sec>. Optional: log=<tag>. The app signs "
                 "event=<name>;sig=<hex>; the module looks up <name> "
                 "here and applies flag+ttl to the flagged-IP table. "
                 "No status/redirect/penalty/credit (response is "
                 "already served)."),
    /* E11.2 — load-aware throttling triggers */
    AP_INIT_TAKE_ARGV("BotShieldLoadTrigger",
                 bs_set_load_trigger, NULL, RSRC_CONF,
                 "Trigger that fires based on the cached load state "
                 "(see BotShieldLoadStateFile / E11). Args: <name> "
                 "<load-match> [key=value ...]. load-match is one of "
                 "state=<level> or state>=<level> where <level> is "
                 "normal|warm|hot. Keys: status=<code|pass>, "
                 "log=<tag>, penalty=<n>, credit=<n>. flag/ttl/"
                 "redirect rejected — load is global state, not "
                 "per-IP behavior. First-match-wins."),
    /* E3 — path-based triggers */
    AP_INIT_TAKE_ARGV("BotShieldPathTrigger",
                 bs_set_path_trigger, NULL, RSRC_CONF,
                 "Path-based trigger. Args: <name> <path-glob> "
                 "[key=value ...]. Keys: status=<code|pass> (default "
                 "403; 'pass' means the real handler runs), "
                 "redirect=<url> (implies 302 unless status=3xx "
                 "explicit), log=<tag> (emitted as tag=\"<x>\" on "
                 "the decision log), flag=<bit> (M5.1 flag name; "
                 "default scanner_probe), ttl=<sec> (flagged-IP "
                 "TTL; default 3600; 0 = don't flag), penalty=<n> "
                 "(score_add amount on this request; default 0; "
                 "ignored under status=pass). Declaration order, "
                 "first match wins; upsert-by-name."),
    /* E2.2 — robots.txt enforcement */
    AP_INIT_TAKE1("BotShieldRobotsTxt", bs_set_robots_txt,
                 NULL, RSRC_CONF,
                 "Path to a robots.txt file whose Disallow and "
                 "Crawl-delay rules mod_botshield will enforce "
                 "server-side. Parsed at post_config; RFC 9309 "
                 "semantics (prefix + '*' + '$' wildcards, longest-"
                 "match-wins, case-insensitive UA prefix). Blocked "
                 "paths return 403 (reason robots-block:<group>); "
                 "Crawl-delay trips return 429 + Retry-After "
                 "(reason robots-rate:<group>)."),
    AP_INIT_TAKE1("BotShieldRobotsRefreshInterval",
                 bs_set_robots_refresh_interval, NULL, RSRC_CONF,
                 "Seconds between mod_watchdog-driven re-checks of "
                 "the BotShieldRobotsTxt file. On mtime change the "
                 "file is re-parsed and the active rule set is "
                 "atomically swapped — no Apache reload needed. "
                 "Default 60. Set 0 to disable live-refresh and "
                 "require an explicit reload after editing."),
    AP_INIT_TAKE1("BotShieldRobotsWildcardScope",
                 bs_set_robots_wildcard_scope, NULL, RSRC_CONF,
                 "How to apply User-agent: * rules: 'heuristic' "
                 "(default — apply only to UAs that look like "
                 "crawlers), 'strict' (apply to every UA), or "
                 "'off' (ignore * groups entirely). Heuristic mode "
                 "uses a real-browser-prefix denylist (Mozilla/, "
                 "Opera/, Firefox/, Edge/, Safari/) combined with a "
                 "bot-token allowlist (bot/crawl/spider/fetch/"
                 "slurp)."),
    /* E5 — app-to-module reputation feedback */
    AP_INIT_FLAG("BotShieldAppFeedback",
                 bs_set_app_feedback, NULL, RSRC_CONF,
                 "Enable app-to-module reputation feedback via the "
                 "response header set by BotShieldAppFeedbackHeader. "
                 "Default off. When off, the header is still stripped "
                 "from outgoing responses so a misconfigured app can't "
                 "leak it to clients."),
    AP_INIT_TAKE1("BotShieldAppFeedbackHeader",
                 bs_set_app_feedback_header, NULL, RSRC_CONF,
                 "Header name the module reads feedback from. "
                 "Default X-BotShield-Feedback. App sets "
                 "`<header>: flag=<name>;ttl=<sec>[;kid=<id>];sig=<hex>`; "
                 "module validates the HMAC, applies the flag to the "
                 "flagged-IP table, and strips the header before the "
                 "response leaves Apache."),
    AP_INIT_TAKE1("BotShieldAppFeedbackSecretFile",
                 bs_set_app_feedback_secret_file, NULL, RSRC_CONF,
                 "Absolute path to the HMAC key used for validating "
                 "app-feedback signatures. Mode 600, root-owned. "
                 "Separate from BotShieldSecretFile so a compromise of "
                 "one key doesn't affect the other."),
    /* E8.2 — module-to-app reputation export. */
    AP_INIT_FLAG("BotShieldAppClaims",
                 bs_set_app_claims, NULL, RSRC_CONF,
                 "Enable module-to-app reputation export. When on, "
                 "the module strips any client-supplied X-Botshield-* "
                 "from the request and sets a single signed "
                 "X-Botshield-Claims header before the backend handler "
                 "runs. Default off."),
    AP_INIT_TAKE1("BotShieldAppClaimsSecretFile",
                 bs_set_app_claims_secret_file, NULL, RSRC_CONF,
                 "Absolute path to the HMAC key used to sign the "
                 "outbound X-Botshield-Claims header. Mode 600, "
                 "root-owned. Deliberately separate from "
                 "BotShieldAppFeedbackSecretFile: leaking the inbound "
                 "key shouldn't let an attacker forge module-originated "
                 "claims, and vice versa."),
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
"   var payload;\n"
"   if (CH.cookie_prefix) {\n"
"    /* E8.1 GCM cookie shape. Server gave us an opaque encrypted\n"
"       envelope; we append '.' + counter and the server splits on\n"
"       the last dot to decrypt + PoW-verify. */\n"
"    payload = CH.cookie_prefix + '.' + counterVal;\n"
"   } else {\n"
"    /* Legacy HMAC shape. Cleartext canonical fields + sig + counter\n"
"       pipe-joined and base64-encoded as a single blob. */\n"
"    var fields = [CH.v, CH.alg, CH.salt, CH.nonce, CH.difficulty,\n"
"                  CH.expires_at,\n"
"                  CH.score, CH.flags,\n"
"                  CH.passes_silent, CH.passes_form, CH.passes_captcha,\n"
"                  CH.challenged_at, CH.auto,\n"
"                  CH.forgive_window_start, CH.forgive_consumed,\n"
"                  CH.signature, counterVal];\n"
"    payload = btoa(fields.join('|'));\n"
"   }\n"
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
        if (strcmp(sub, "/policy-status") == 0) {
            return bs_policy_status_handler(r, cfg);
        }
        /* E17 PoC — embedded silent-verify endpoints. */
        if (strcmp(sub, "/embedded.js") == 0) {
            return bs_embedded_js_handler(r);
        }
        if (strcmp(sub, "/embedded-bootstrap") == 0) {
            return bs_embedded_bootstrap_handler(r, cfg);
        }
        if (strcmp(sub, "/embedded-verify") == 0) {
            return bs_embedded_verify_handler(r, cfg);
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
            /* E10 — safeguard clear on solve. A successful verify
             * proves this client CAN complete a challenge, so any
             * accumulated presentation history was transient noise
             * (mid-session CSP moment, browser cookie glitch). Reset
             * the slot so a later failed solve counts from zero. */
            {
                bs_server_cfg *scfg_sg = ap_get_module_config(
                    r->server->module_config, &botshield_module);
                if (scfg_sg && scfg_sg->safeguard_enabled == 1) {
                    unsigned char sg_ip[16];
                    if (bs_parse_client_ip(r->useragent_ip, sg_ip)) {
                        bs_mask_ipv6_prefix(sg_ip,
                                            scfg_sg->ipv6_prefix_bits);
                        bs_safeguard_clear(sg_ip, scfg_sg->ns_id);
                    }
                }
            }
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

    /* E4 — publish the `_bs_verified` verification verdict as a
     * request note so bs_check_policy's cookie-trigger evaluator
     * can surface it via bs-cookie=<state> predicates. Three-state
     * mapping matches the directive surface. */
    {
        const char *bs_state;
        if (!cookie_had_val)           bs_state = BS_CK_STATE_MISSING;
        else if (!cookie_verify_reason) bs_state = BS_CK_STATE_VERIFIED;
        else                           bs_state = BS_CK_STATE_INVALID;
        apr_table_setn(r->notes, BS_CK_STATE_NOTE, bs_state);
    }

    /* E2.1 + E2.2 + E3 policy enforcement. Runs before scoring
     * heuristics so a block / rate / trigger short-circuits cleanly.
     * Applies to cookie-valid requests too — operator policy
     * (including robots.txt and path-based triggers) is independent
     * of bot-ness. */
    int policy_rv = bs_check_policy(r);
    if (policy_rv == DECLINED) {
        /* E3 trigger with status=pass: log + let the real handler
         * respond. No score, no BotShield interstitial. Flag-IP +
         * tag side effects already applied in bs_check_policy. */
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        bs_decision_log(r, "pass", "declined", cookie_status, "-", "-",
                        reasons, s ? s->total : 0);
        return DECLINED;
    }
    if (policy_rv != OK) {
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        const char *outcome;
        if (policy_rv == HTTP_TOO_MANY_REQUESTS)      outcome = "rate_limited";
        else                                          outcome = "rejected";
        bs_decision_log(r, "pass", outcome, cookie_status, "-", "-",
                        reasons, s ? s->total : 0);
        return policy_rv;
    }

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
    bs_server_cfg *scfg_h = ap_get_module_config(
        r->server->module_config, &botshield_module);
    if (have_client_ip) {
        bs_mask_ipv6_prefix(client_ip, scfg_h->ipv6_prefix_bits);
    }
    apr_uint32_t ip_flags = 0;
    int ip_flag_penalty = 0;
    if (have_client_ip &&
        bs_flagged_ip_lookup(client_ip, &ip_flags, scfg_h->ns_id)) {
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
        !bs_bloom_seen(client_ip, scfg_h->ns_id)) {
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
    bs_tier score_tier  = bs_decide_tier(cfg, effective);

    /* E14 — adaptive intensity. Walk both flag sources (IP-side and
     * cookie-side) through the registry; difficulty deltas SUM, tier
     * floor takes MAX. The score-derived tier wins when it's already
     * higher than the floor (never silently downgrade). Difficulty
     * delta is applied later, just before bs_issue_challenge, so it
     * gets clamped against BotShieldMaxDifficulty alongside the rest
     * of the issue-time bounds checks. */
    bs_flag_adaptive adaptive_ip     = bs_flag_adaptive_for(ip_flags);
    bs_flag_adaptive adaptive_cookie = have_prior_rep
        ? bs_flag_adaptive_for(prior_ch.rep.flags)
        : (bs_flag_adaptive){0, BS_TIER_PASS, 0, 0};
    bs_flag_adaptive adaptive = {
        .difficulty_delta = adaptive_ip.difficulty_delta
                          + adaptive_cookie.difficulty_delta,
        .tier_floor = (adaptive_ip.tier_floor > adaptive_cookie.tier_floor)
                    ? adaptive_ip.tier_floor : adaptive_cookie.tier_floor,
        .bits_with_difficulty = adaptive_ip.bits_with_difficulty
                              | adaptive_cookie.bits_with_difficulty,
        .bits_with_tier = (adaptive_ip.tier_floor == adaptive_cookie.tier_floor)
                        ? (adaptive_ip.bits_with_tier
                           | adaptive_cookie.bits_with_tier)
                        : (adaptive_ip.tier_floor > adaptive_cookie.tier_floor
                           ? adaptive_ip.bits_with_tier
                           : adaptive_cookie.bits_with_tier),
    };
    bs_tier tier = score_tier;
    if (adaptive.tier_floor > tier) {
        tier = adaptive.tier_floor;
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "adaptive-tier:%s",
                         bs_tier_name(adaptive.tier_floor)));
    }

    /* BotShieldFlagIP: if any scope the request matched sets flag bits,
     * land them in the flagged-IP table now. Fires on every hit to the
     * scope, so honeypot paths and scanner-trap paths should be reached
     * only by actors that deserve the flag. */
    if (cfg->flag_on_match && have_client_ip) {
        bs_flagged_ip_add(r, client_ip, cfg->flag_on_match,
                          cfg->flag_on_match_ttl
                            ? cfg->flag_on_match_ttl : 3600,
                          scfg_h->ns_id);
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
        /* E8.2 — module-to-app reputation export. Strip incoming
         * X-Botshield-* and set a single signed claim envelope so
         * the backend handler reads sanctioned BotShield state
         * without poking at the (encrypted post-E8.1) cookie. */
        {
            bs_server_cfg *scfg2 = ap_get_module_config(
                r->server->module_config, &botshield_module);
            apr_uint32_t composite_flags = ip_flags
                | (have_prior_rep ? prior_ch.rep.flags : 0);
            const char *cerr = bs_app_claims_set(r, scfg2,
                effective, tier, cookie_status, composite_flags,
                have_prior_rep ? prior_ch.rep.passes_silent  : 0,
                have_prior_rep ? prior_ch.rep.passes_form    : 0,
                have_prior_rep ? prior_ch.rep.passes_captcha : 0);
            if (cerr) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                    "mod_botshield: app claims not emitted: %s", cerr);
            }
        }
        bs_decision_log(r, "pass", "declined", cookie_status,
                        "-", "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

    /* Not pass tier — we will issue a challenge. Feed the Bloom filter
     * now that we've committed to challenging this client; that keeps
     * writes off the ~99% happy path. */
    if (have_client_ip) bs_bloom_add(client_ip, scfg_h->ns_id);

    /* E10 — challenge safeguard. Before actually issuing the
     * challenge, check whether this IP has been presented N times
     * within the window without solving. If so, flip to a pass-
     * through with reason=challenge-safeguard so a broken client
     * (JS blocked, CSP-stripped, cookie handling buggy) stops
     * being looped on the same challenge. Otherwise record this
     * presentation and proceed. Safeguard runs AFTER bs_check_policy
     * by construction (we're already past the policy short-circuit
     * returns), so 403/429 blocks still win. */
    {
        bs_server_cfg *scfg_sg = ap_get_module_config(
            r->server->module_config, &botshield_module);
        if (scfg_sg && scfg_sg->safeguard_enabled == 1
            && have_client_ip) {
            apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
            if (bs_safeguard_check(client_ip, now_t, scfg_sg->ns_id)) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "mod_botshield: challenge-safeguard active for "
                    "%s; skipping challenge-issue and passing "
                    "through (until=%" APR_INT64_T_FMT ")",
                    r->useragent_ip, (apr_int64_t)now_t);
                bs_score_add(r, 0, 0, "challenge-safeguard");
                bs_decision_log(r, "safeguard", "declined",
                                cookie_status, "-", "-",
                                bs_decision_reason_names(r->pool, score),
                                effective);
                return DECLINED;
            }
            bs_safeguard_record_presentation(r, scfg_sg,
                                             client_ip, now_t,
                                             scfg_sg->ns_id);
        }
    }

    /* E17 PoC — if silent-tier dispatch lands here AND the scope is
     * in `embedded` mode, skip the M7 interstitial entirely. Serve
     * the real page (DECLINED). The operator-included
     * /botshield/embedded.js wrapper runs on page-load, fetches a
     * challenge from /botshield/embedded-bootstrap, solves PoW in a
     * Web Worker, and POSTs back to /botshield/embedded-verify which
     * mints _bs_verified. The cookie may not arrive in time for the
     * very first request, but subsequent page-loads in the session
     * carry it — see PLAN E17 for the "kicks in eventually"
     * timing model. */
    if (tier == BS_TIER_SILENT &&
        cfg->silent_mode == BS_SILENT_MODE_EMBEDDED) {
        bs_decision_log(r, "silent", "declined", cookie_status,
                        "-", "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

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
        /* E15 — clamp against the per-cookie hourly cap
         * and surface the granted vs requested via reason chain when
         * the cap kicks in. */
        int cap = scfg_h && scfg_h->forgive_cap_per_hour > 0
                ? scfg_h->forgive_cap_per_hour
                : BS_DEFAULT_FORGIVE_CAP_PER_HOUR;
        apr_uint32_t now_sec = (apr_uint32_t)apr_time_sec(apr_time_now());
        next_rep = prior_ch.rep;
        int requested = forgive;
        forgive = bs_forgiveness_apply_cap(forgive, cap, now_sec,
                    &next_rep.forgive_window_start,
                    &next_rep.forgive_consumed);
        if (forgive < requested) {
            bs_score_add(r, 0, 0,
                apr_psprintf(r->pool,
                    "forgive-capped:%d/%d",
                    forgive, requested));
        }
        int floor   = bs_flag_penalty(prior_ch.rep.flags);
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < floor) new_score = floor;
        if (new_score < 0)     new_score = 0;
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
        next_rep.forgive_window_start = 0;
        next_rep.forgive_consumed     = 0;
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
    /* Log line above prints the BASE difficulty; E14's adaptive
     * difficulty bump is logged via the reason chain
     * (adaptive-difficulty:+N) and the effective issue_difficulty
     * is what bs_issue_challenge actually uses. */

    /* E14 — apply adaptive difficulty bump and clamp against the
     * server-scope ceiling. Negative deltas (from credit flags like
     * app_verified_human) compose, then clamp at 1 (BotShieldDifficulty
     * minimum). Positive deltas clamp at the operator-set max
     * (BotShieldMaxDifficulty, default 8). The reason chain logs the
     * effective bump for traceability. */
    int issue_difficulty = difficulty;
    if (adaptive.difficulty_delta != 0) {
        int max_diff = (scfg_h && scfg_h->max_difficulty > 0)
                     ? scfg_h->max_difficulty
                     : BS_DEFAULT_MAX_DIFFICULTY;
        int requested = difficulty + adaptive.difficulty_delta;
        if (requested < 1)         issue_difficulty = 1;
        else if (requested > max_diff) issue_difficulty = max_diff;
        else                       issue_difficulty = requested;
        int applied_delta = issue_difficulty - difficulty;
        if (applied_delta != 0) {
            bs_score_add(r, 0, 0,
                apr_psprintf(r->pool, "adaptive-difficulty:%+d",
                             applied_delta));
        }
    }

    /* Issue a fresh signed challenge; the worker reads it from the page.
     * The next_rep struct carries forgiveness-adjusted rep from any
     * sig-verified prior cookie. */
    bs_challenge challenge;
    const char *ierr = bs_issue_challenge(r->pool, cfg, issue_difficulty, ttl,
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
    /* E5 — response-phase filter for the app-feedback header. Filter
     * runs once per request (self-removes), strips the configured
     * header from r->headers_out, and — when the feature is enabled
     * and the header is well-formed — HMAC-verifies and applies the
     * flag to the flagged-IP table. Registered here (filter + the
     * insert hook) so every request has it in the chain; cheap
     * until a real header appears. AP_FTYPE_CONTENT_SET puts us
     * before the network filters so headers modifications land
     * before the protocol flush. */
    /* Filter type picked to run AFTER mod_headers. mod_headers has
     * several stages and its late filter re-applies the "always"
     * directive even after we've stripped. Running at
     * AP_FTYPE_PROTOCOL - 1 (just past mod_headers' FIXUP_HEADERS_OUT
     * at CONTENT_SET but before the protocol serializer) gives the
     * widest window for the normal response chain. */
    bs_app_feedback_filter_handle = ap_register_output_filter(
        "BOTSHIELD_APP_FEEDBACK", bs_app_feedback_filter, NULL,
        AP_FTYPE_PROTOCOL - 1);
    /* Register on BOTH the normal-response chain and the error-
     * response chain. Apache builds a separate filter chain when
     * `ap_die` runs for a 4xx/5xx response (including 404 from a
     * missing file, error-from-handler, and ErrorDocument
     * redirects); the insert_filter hook doesn't fire there, so
     * without the error-filter registration the header would leak
     * to clients on any error response that mod_headers decorated.
     * Same handle, same callback — the filter is idempotent and
     * one-shot per request, so double-registration is safe. */
    ap_hook_insert_filter      (bs_app_feedback_insert_filter,
                                NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_error_filter(bs_app_feedback_insert_filter,
                                NULL, NULL, APR_HOOK_MIDDLE);
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
    bs_merge_server_cfg,  /* per-server config merger     */
    bs_cmds,              /* config directives            */
    bs_register_hooks,    /* hook registration            */
    AP_MODULE_FLAG_NONE   /* flags                        */
};
#endif
