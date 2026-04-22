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

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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

/* Challenge protocol (M4a) —
 *   Wire format (embedded inline in the interstitial, JSON):
 *     { v, alg, salt, nonce, difficulty, expires_at,
 *       score, flags, passes_silent, passes_form, passes_captcha,
 *       challenged_at, signature }
 *   Canonical HMAC input (deterministic, pipe-delimited ASCII):
 *     "v|alg|salthex|noncehex|difficulty|expires_at
 *      |score|flags|pass_s|pass_f|pass_c|challenged_at"
 *   Cookie payload = base64( canonical || "|" || sighex || "|" || counter )
 *   — a single base64 blob the server can parse by splitting on '|',
 *     no JSON parser required.
 *
 * Keep in sync with the JS worker when the template ships the wire bits. */
#define BS_PROTOCOL_VERSION   1
#define BS_SALT_BYTES         16
#define BS_NONCE_BYTES        8
#define BS_SIG_BYTES          32  /* HMAC-SHA-256 output */
#define BS_COOKIE_FIELDS      14  /* full cookie payload; canonical is 12 */

/* Forward declarations for the PoW algorithm dispatch table. */
typedef struct bs_dir_cfg bs_dir_cfg;

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
 * contiguously: fixed header, flagged-IP table, then (reserved for M5b)
 * two Bloom filter buffers. Workers access the segment through bs_shm,
 * a module-global runtime struct populated in post-config. */
#define BS_SHM_MAGIC              0x42534844  /* 'BSHD' */
#define BS_SHM_FORMAT_VERSION     1
#define BS_DEFAULT_SHM_SIZE       (8 * 1024 * 1024)
#define BS_DEFAULT_FLAGGED_SLOTS  50000
#define BS_FLAGGED_MIN_SLOTS      1024
#define BS_FLAGGED_MAX_SLOTS      1000000
#define BS_FLAGGED_PROBE_LIMIT    10   /* linear probe depth */
#define BS_FLAGGED_MAX_READ_SPINS 3    /* seqlock retry budget */

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
    /* Reserved for M5b (kept here so layout stabilizes now): */
    apr_uint32_t  bloom_active;     /* 0 or 1 */
    apr_uint32_t  bloom_buf_bytes;  /* per-buffer size in bytes */
    apr_int64_t   bloom_next_rotate;
    apr_int64_t   _pad1;
} bs_shm_header;

/* Module-global runtime pointer struct. Populated once in post-config;
 * children inherit via fork. M5b just fills in bloom_bufs[] and
 * bloom_buf_bytes — no re-plumbing. */
typedef struct {
    apr_shm_t           *shm;
    apr_global_mutex_t  *mutex;
    const char          *mutex_filename;   /* for attaches in child_init */
    bs_shm_header       *header;
    bs_flagged_ip_slot  *flagged_table;
    apr_size_t           flagged_capacity;
    unsigned char       *bloom_bufs[2];    /* reserved for M5b */
    apr_size_t           bloom_buf_bytes;  /* reserved for M5b */
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
    int         ttl_seconds;   /* reserved for M5 flagged-IP table entries */
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
};

/* Per-server config — holds SHM sizing before post-config runs. Only the
 * main server's values are consulted; vhost-level overrides are logged
 * and ignored because the SHM segment is global. */
typedef struct {
    apr_size_t shm_size;
    int        flagged_capacity;
    int        ipv6_prefix_bits;  /* 0..128; 64 = per-subscriber v6 key */
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
    return cfg;
}

static void *bs_create_server_cfg(apr_pool_t *p, server_rec *s)
{
    (void)s;
    bs_server_cfg *scfg = apr_pcalloc(p, sizeof(*scfg));
    scfg->shm_size          = BS_DEFAULT_SHM_SIZE;
    scfg->flagged_capacity  = BS_DEFAULT_FLAGGED_SLOTS;
    scfg->ipv6_prefix_bits  = 64;   /* /64 aggregation by default */
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
    int n = atoi(arg);
    if (n < 1 || n > 86400) {
        return "BotShieldCookieTTL must be between 1 and 86400 seconds";
    }
    ((bs_dir_cfg *)cfg_v)->cookie_ttl = n;
    return NULL;
}

static const char *bs_set_difficulty(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    int n = atoi(arg);
    if (n < 1 || n > 8) {
        return "BotShieldDifficulty must be between 1 and 8";
    }
    ((bs_dir_cfg *)cfg_v)->difficulty = n;
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
    char *end = NULL;
    apr_int64_t n = apr_strtoi64(arg, &end, 10);
    if (end == arg || n <= 0) {
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
    apr_int64_t bytes = n * mult;
    if (bytes < 128 * 1024 || bytes > 256LL * 1024 * 1024) {
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
    int n = atoi(arg);
    if (n < BS_FLAGGED_MIN_SLOTS || n > BS_FLAGGED_MAX_SLOTS) {
        return apr_psprintf(cmd->pool,
            "BotShieldFlaggedIPCapacity: must be between %d and %d",
            BS_FLAGGED_MIN_SLOTS, BS_FLAGGED_MAX_SLOTS);
    }
    scfg->flagged_capacity = n;
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
        ttl = atoi(ttl_str);
        if (ttl < 60 || ttl > 30 * 86400) {
            return "BotShieldFlagIP: ttl must be 60..2592000 seconds";
        }
    }
    cfg->flag_on_match     = bits;
    cfg->flag_on_match_ttl = ttl;
    return NULL;
}

/* Accept ".example.com" (leading dot for cross-subdomain) or "example.com"
 * (host-only). Empty string clears the directive, reverting to host-only. */
static const char *bs_set_cookie_domain(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg) return "BotShieldCookieDomain requires an argument";
    if (!*arg) { cfg->cookie_domain = NULL; return NULL; }
    /* Very light validation: no whitespace, no semicolons (would break the
     * Set-Cookie serialization). Trust the admin otherwise. */
    for (const char *p = arg; *p; p++) {
        if (*p == ';' || *p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            return apr_psprintf(cmd->pool,
                "BotShieldCookieDomain: '%s' contains an unsafe character", arg);
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
 *  |score|flags|pass_s|pass_f|pass_c|challenged_at"   (12 fields)
 *
 * Deterministic, ASCII, field-delimited. Both sign and verify produce this
 * exact string from the challenge struct — if a byte changes, the HMAC
 * changes, and tampering is detected. The rep fields follow the challenge
 * fields so existing M2 code reading positions 0..5 still lines up. */
static const char *bs_challenge_canonical(apr_pool_t *p,
                                          const bs_challenge *ch)
{
    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    bs_to_hex(ch->salt,  BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch->nonce, BS_NONCE_BYTES, nonce_hex);
    return apr_psprintf(p,
        "%d|%s|%s|%s|%d|%" APR_TIME_T_FMT
        "|%d|%u|%d|%d|%d|%" APR_TIME_T_FMT,
        ch->version, ch->alg_name, salt_hex, nonce_hex,
        ch->difficulty, ch->expires_at,
        ch->rep.score, (unsigned)ch->rep.flags,
        ch->rep.passes_silent, ch->rep.passes_form, ch->rep.passes_captcha,
        ch->rep.challenged_at);
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

/* --- Algorithm registry ---
 *
 * Static dispatch table. Only sha256-zeros is implemented today. Flipping
 * a 0 to 1 + providing the two functions is how new algorithms get added;
 * no changes to the protocol or the verify code path. */
static const bs_pow_algorithm bs_algorithms[] = {
    { "sha256-zeros",  1, bs_sha256_zeros_issue, bs_sha256_zeros_verify },
    { "sha384-zeros",  0, NULL, NULL },
    { "sha512-zeros",  0, NULL, NULL },
    { "pbkdf2-sha256", 0, NULL, NULL },
    { "argon2id",      0, NULL, NULL },
    { NULL,            0, NULL, NULL }
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

/* ======================================================================
 * Shared memory: flagged-IP table (M5a) + Bloom reservations (M5b).
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

    bs_server_cfg *scfg = ap_get_module_config(s->module_config,
                                               &botshield_module);

    /* Compute layout: header + flagged table. Bloom buffers are reserved
     * by leaving the remainder of the segment untouched; M5b will claim
     * it without a re-allocation. */
    apr_size_t header_bytes = sizeof(bs_shm_header);
    apr_size_t table_bytes  = (apr_size_t)scfg->flagged_capacity
                              * sizeof(bs_flagged_ip_slot);
    apr_size_t min_bytes    = header_bytes + table_bytes;
    if (scfg->shm_size < min_bytes) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: BotShieldShmSize %" APR_SIZE_T_FMT
            " is too small; needs at least %" APR_SIZE_T_FMT " bytes "
            "for header + %d flagged-IP slots",
            scfg->shm_size, min_bytes, scfg->flagged_capacity);
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
    bs_shm.bloom_bufs[0]    = NULL;
    bs_shm.bloom_bufs[1]    = NULL;
    bs_shm.bloom_buf_bytes  = 0;

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
        "flagged-IP capacity %d",
        scfg->shm_size, scfg->flagged_capacity);
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

/* Translate a flag bitmap (from the cookie's flags field OR the flagged-
 * IP table) into an additive score. M5a wires real numbers; bits are
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
        "\"challenged_at\":%" APR_TIME_T_FMT ","
        "\"signature\":\"%s\"%s}",
        ch->version, ch->alg_name, salt_hex, nonce_hex,
        ch->difficulty, ch->expires_at,
        ch->rep.score, (unsigned)ch->rep.flags,
        ch->rep.passes_silent, ch->rep.passes_form, ch->rep.passes_captcha,
        ch->rep.challenged_at,
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
 * issued. If `rep_in` is NULL, rep starts at zero (first-ever challenge). */
static const char *bs_issue_challenge(apr_pool_t *p, const bs_dir_cfg *cfg,
                                      int difficulty, int cookie_ttl,
                                      const bs_rep_state *rep_in,
                                      bs_challenge *out)
{
    if (!cfg->secret || !cfg->algorithm) {
        return "BotShieldSecretFile and BotShieldAlgorithm must be set";
    }
    apr_time_t now = apr_time_sec(apr_time_now());
    out->version     = BS_PROTOCOL_VERSION;
    out->alg_name    = cfg->algorithm->name;
    out->difficulty  = difficulty;
    out->expires_at  = now + cookie_ttl;
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

    const char *err = cfg->algorithm->issue(cfg, out);
    if (err) return err;

    const char *canon = bs_challenge_canonical(p, out);
    bs_hmac_sha256(cfg->secret, cfg->secret_len,
                   (const unsigned char *)canon, strlen(canon),
                   out->signature);
    return NULL;
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

    /* Expect 14 pipe-delimited fields (M4a):
     *   0..5  : v, alg, salt, nonce, difficulty, expires_at
     *   6..11 : score, flags, passes_silent, passes_form, passes_captcha,
     *           challenged_at
     *   12    : sighex
     *   13    : counter
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

    /* Parse + validate each field with a strict shape check. */
    int version = atoi(fields[0]);
    if (version != BS_PROTOCOL_VERSION) return "bad protocol version";

    const bs_pow_algorithm *alg = bs_find_algorithm(fields[1]);
    if (!alg || !alg->implemented) return "unknown algorithm";

    bs_challenge ch;
    ch.version    = version;
    ch.alg_name   = alg->name;
    ch.difficulty = atoi(fields[4]);
    if (ch.difficulty < 1 || ch.difficulty > 8) return "bad difficulty";

    if (strlen(fields[2]) != BS_SALT_BYTES * 2 ||
        !bs_from_hex(fields[2], BS_SALT_BYTES, ch.salt)) return "bad salt";
    if (strlen(fields[3]) != BS_NONCE_BYTES * 2 ||
        !bs_from_hex(fields[3], BS_NONCE_BYTES, ch.nonce)) return "bad nonce";

    ch.expires_at = (apr_time_t)apr_atoi64(fields[5]);

    /* Rep fields — each already string-safe thanks to strtok-in-place. */
    ch.rep.score          = atoi(fields[6]);
    ch.rep.flags          = (apr_uint32_t)strtoul(fields[7], NULL, 10);
    ch.rep.passes_silent  = atoi(fields[8]);
    ch.rep.passes_form    = atoi(fields[9]);
    ch.rep.passes_captcha = atoi(fields[10]);
    ch.rep.challenged_at  = (apr_time_t)apr_atoi64(fields[11]);

    unsigned char sig_from_client[BS_SIG_BYTES];
    if (strlen(fields[12]) != BS_SIG_BYTES * 2 ||
        !bs_from_hex(fields[12], BS_SIG_BYTES, sig_from_client)) {
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
    return alg->verify(&ch, fields[13]);
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

/* ======================================================================
 * Per-request scoring.
 *
 * Every feature that wants to nudge a request's risk upward (rate-limit
 * exceeded, honeypot hit, scanner probe, fake-Googlebot, failed captcha)
 * calls bs_score_add(). Today the score lives in r->request_config and
 * dies with the request; M4 will back the same API with SHM so penalties
 * outlive the request.
 * ====================================================================== */

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

/* Pick a tier from the running score. Today the tier is computed and
 * logged but not acted on — every challenged request still gets the
 * form-PoW interstitial. M7/M8 will route the silent and captcha tiers
 * to their own flows. */
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
        case BS_TIER_HARD:    return "hard";
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
                 "(default: 20). Logged only until M7 ships."),
    AP_INIT_TAKE1("BotShieldScoreHard",    bs_set_score_hard,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the form-PoW tier is picked "
                 "(default: 50). This is the only tier currently served."),
    AP_INIT_TAKE1("BotShieldScoreCaptcha", bs_set_score_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the captcha tier is picked "
                 "(default: 80). Logged only until M8 ships."),
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
    AP_INIT_TAKE12("BotShieldFlagIP", bs_set_flag_ip, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Flag the client IP with one or more bits when a request "
                 "hits this scope. Flag names: honeypot_hit, scanner_probe, "
                 "fake_crawler, pow_fail_streak. Optional second argument "
                 "is the TTL in seconds (default 3600). Use inside a "
                 "<Location> for honeypot paths."),
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
" btn.addEventListener('click', function h(e){\n"
"  if(!e.isTrusted) return;\n"
"  btn.removeEventListener('click', h);\n"
"  box.className = 'bs-widget bs-working';\n"
"  btn.setAttribute('aria-disabled', 'true');\n"
"  startChallenge();\n"
" });\n"
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
"   box.className = 'bs-widget bs-done';\n"
"   msg.textContent = 'Verified \\u2014 reloading\\u2026';\n"
"   var fields = [CH.v, CH.alg, CH.salt, CH.nonce, CH.difficulty,\n"
"                 CH.expires_at,\n"
"                 CH.score, CH.flags,\n"
"                 CH.passes_silent, CH.passes_form, CH.passes_captcha,\n"
"                 CH.challenged_at,\n"
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
        return OK;
    }

    /* Static assets pass through — a cookieless first page load must still
     * render its CSS/images so the PoW page is usable. */
    if (bs_is_asset_uri(r->uri)) {
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
    bs_challenge prior_ch;
    int have_prior_rep   = 0;
    int cookie_fully_ok  = 0;
    if (cookie_val && *cookie_val) {
        const char *reason = bs_verify_cookie(r, cfg, cookie_val, &prior_ch);
        if (!reason) {
            cookie_fully_ok = 1;
            have_prior_rep  = 1;
        } else {
            if (strcmp(reason, "signature mismatch") != 0) {
                have_prior_rep = 1;
            }
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_botshield: " BS_COOKIE_NAME " rejected: %s",
                          reason);
        }
    }

    /* Score the request. Heuristics always run — a fully-valid cookie
     * doesn't exempt you from fresh request-level signals that might
     * have pushed you into a tier that requires a re-challenge. */
    bs_run_builtin_heuristics(r);

    /* Flagged-IP table (M5a): look up the client IP. Hits add the
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
        return DECLINED;
    }

    /* Not pass tier — we will issue a challenge. Build the rep state
     * to carry into the new cookie. Today M4b serves form-PoW for every
     * non-pass tier; silent (M7) and captcha (M8) will ship later with
     * their own forgiveness rates. Until then, form forgiveness is
     * applied whenever we re-issue, matching what the user actually
     * solves. */
    bs_rep_state next_rep;
    if (have_prior_rep) {
        int forgive = bs_effective_int(cfg->forgive_form,
                                       BS_DEFAULT_FORGIVE_FORM);
        int floor   = bs_flag_penalty(prior_ch.rep.flags);
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < floor) new_score = floor;
        if (new_score < 0)     new_score = 0;
        next_rep = prior_ch.rep;
        next_rep.score       = new_score;
        next_rep.passes_form = prior_ch.rep.passes_form + 1;
    } else {
        next_rep.score          = 0;
        next_rep.flags          = 0;
        next_rep.passes_silent  = 0;
        next_rep.passes_form    = 1;   /* this pass counts as the first */
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
                                          &next_rep, &challenge);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_botshield: issue failed: %s", ierr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Service error: could not issue challenge.\n", r);
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
    const char *widget_mod = show_box ? "" : " bs-bare";
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
     * or our built-in default — same splice code path either way. */
    char *widget = apr_psprintf(r->pool, BS_WIDGET_TEMPLATE,
                                widget_mod,
                                aria_attr,
                                prompt_span,
                                brand_div,
                                help_html,
                                challenge_js);

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
    return OK;
}

/* --- Hook registration --- */

static void bs_register_hooks(apr_pool_t *p)
{
    (void)p;
    ap_hook_post_config(bs_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init (bs_child_init,  NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler    (bs_handler,     NULL, NULL, APR_HOOK_FIRST);
}

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
