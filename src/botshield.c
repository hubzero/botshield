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
#include <openssl/kdf.h>
#include <openssl/params.h>
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

#include "robots.h"    /* E2.2 — robots.txt parser/matcher */
#include "shm.h"       /* SHM tables, state save/load, headroom watchdog */
#include "crypto.h"    /* SHA-256, HMAC, AES-256-GCM, HKDF, hex codec */
#include "allowlist.h" /* E1 — UA classifier, CIDR list loader, builtin bots */
#include "metrics.h"   /* M9 — decision log, counters, Prometheus, mod_status */
#include "botshield.h" /* module-wide types: bs_dir_cfg, bs_server_cfg, ... */
#include "cookie.h"    /* GCM cookie envelope mint/verify, Cookie-header parser */
#include "challenge.h" /* M7 — challenge issuance, alg registry, bootstrap-sig */
#include "silent.h"    /* E17 — silent-tier embedded handlers */
#include "captcha.h"   /* M8 — provider registry, siteverify, pending cookie */
#include "bridge.h"    /* E5 + E8.2 — module ↔ app feedback / claims bridge */

/* Cross-cutting config defaults (BS_DEFAULT_*, BS_MAX_*, BS_UNSET,
 * cookie name strings, etc.) live in botshield.h so every TU that
 * needs them gets them via the umbrella include. */

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
/* BS_PROTOCOL_VERSION, BS_SALT_BYTES, BS_NONCE_BYTES, BS_GCM_COUNTER_SEP
 * live in botshield.h with the bs_challenge / bs_rep_state types they
 * frame.  BS_SIG_BYTES, BS_COOKIE_ALG_GCM, BS_GCM_NONCE_LEN, BS_GCM_TAG_LEN
 * live in crypto.h alongside the primitives that produce them. */

/* bs_parse_int_bounded / bs_parse_uint32_bounded / bs_parse_int64_bounded
 * forward decls live in botshield.h (cross-TU — cookie.c uses them in
 * the canonical-form parser). Defined later in this file alongside the
 * other bounded numeric helpers. */

/* Forward decl for bs_score_add — called from the E1 block, which
 * lives before the scoring section so its data structures are
 * available at post_config time. */
static void bs_score_add(request_rec *r, int penalty,
                         int ttl_seconds, const char *reason);



/* --- Flagged-IP bitmap and scoring ---
 *
 * Each bit represents a *serious* event we want to remember about an IP
 * even if its cookie is rolled back. Bits are additive: an IP that
 * triggered both a honeypot and a scanner probe carries both. Score
 * effects per bit live in scfg->flag_triggers — see
 * bs_default_flag_triggers and bs_apply_flag_triggers. */
#define BS_FLAG_HONEYPOT_HIT      (1U << 0)
#define BS_FLAG_SCANNER_PROBE     (1U << 1)
#define BS_FLAG_FAKE_BOT          (1U << 2)
#define BS_FLAG_POW_FAIL_STREAK   (1U << 3)
/* E5 — credit-carrying bits. Default flag-trigger entries assign a
 * negative score adjustment to these bits so the app can push score
 * down as well as up via the app-feedback channel. Compose additively
 * with penalty bits: an IP that tripped a honeypot and later had the
 * app verify the human carries +60 + -80 = -20 worth of flag-trigger
 * score effect until the shorter-TTL bit expires. */
#define BS_FLAG_APP_VERIFIED_HUMAN   (1U << 4)
#define BS_FLAG_APP_VERIFIED_SESSION (1U << 5)
#define BS_FLAG_APP_TRUST_SIGNAL     (1U << 6)


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
    cfg->score_silent  = BS_UNSET;
    cfg->score_hard    = BS_UNSET;
    cfg->score_captcha = BS_UNSET;
    cfg->silent_mode   = BS_SILENT_MODE_UNSET;
    cfg->form_captcha  = BS_UNSET;
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
    cfg->captcha_connect_timeout_ms = BS_UNSET;
    cfg->recaptcha_v3_min_score = -1.0;
    cfg->captcha_rate_limit  = BS_UNSET;
    cfg->captcha_expected_hostname = NULL;
    cfg->captcha_expected_action   = NULL;
    cfg->captcha_ca_bundle         = NULL;
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
    out->nonce_capacity = (add->nonce_capacity > 0)
                        ? add->nonce_capacity : base->nonce_capacity;
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
    /* E15 — child-set value wins; 0 means "inherit". */
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
    out->flag_triggers     = bs_merge_rule_array(p, base->flag_triggers,
                                                 add->flag_triggers);
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

    /* App integration server-scope inheritance. */
    if (add->app_feedback_enabled == BS_APP_FEEDBACK_UNSET) {
        out->app_feedback_enabled = base->app_feedback_enabled;
    }
    if (!add->app_feedback_header && base->app_feedback_header) {
        out->app_feedback_header = base->app_feedback_header;
    }
    if (add->app_claims_enabled == BS_APP_FEEDBACK_UNSET) {
        out->app_claims_enabled = base->app_claims_enabled;
    }
    if (!add->app_integration_secret_file && base->app_integration_secret_file) {
        out->app_integration_secret_file = base->app_integration_secret_file;
        out->app_integration_secret      = base->app_integration_secret;
        out->app_integration_secret_len  = base->app_integration_secret_len;
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
    scfg->nonce_capacity      = 0;   /* 0 = inherit/default */
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
    /* E15 — 0 means "inherit / use default". */
    scfg->forgive_cap_per_hour  = 0;
    scfg->block_paths      = apr_array_make(p, 4, sizeof(void *));
    scfg->path_triggers         = apr_array_make(p, 4, sizeof(void *));
    scfg->cookie_triggers  = apr_array_make(p, 4, sizeof(void *));
    scfg->env_triggers     = apr_array_make(p, 4, sizeof(void *));
    scfg->feedback_triggers = apr_array_make(p, 4, sizeof(void *));
    scfg->load_triggers     = apr_array_make(p, 4, sizeof(void *));
    scfg->flag_triggers     = apr_array_make(p, 8, sizeof(void *));
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
    /* App integration defaults — UNSET sentinel so the server-scope
     * merge can tell "unset at this scope" from explicit off. */
    scfg->app_feedback_enabled        = BS_APP_FEEDBACK_UNSET;
    scfg->app_feedback_header         = NULL;
    scfg->app_claims_enabled          = BS_APP_FEEDBACK_UNSET;
    scfg->app_integration_secret_file = NULL;
    scfg->app_integration_secret      = NULL;
    scfg->app_integration_secret_len  = 0;
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
    /* LOW #3 — derived per-purpose keys ride alongside the master.
     * If add has its own master secret, take its derived keys too;
     * otherwise inherit base's. */
    if (add->secret) {
        out->secret     = add->secret;
        out->secret_len = add->secret_len;
        memcpy(out->derived_gcm_cookie,
               add->derived_gcm_cookie,     32);
        memcpy(out->derived_hmac_pending,
               add->derived_hmac_pending,   32);
        memcpy(out->derived_hmac_bootstrap,
               add->derived_hmac_bootstrap, 32);
        out->derived_keys_set = add->derived_keys_set;
    } else {
        out->secret     = base->secret;
        out->secret_len = base->secret_len;
        memcpy(out->derived_gcm_cookie,
               base->derived_gcm_cookie,     32);
        memcpy(out->derived_hmac_pending,
               base->derived_hmac_pending,   32);
        memcpy(out->derived_hmac_bootstrap,
               base->derived_hmac_bootstrap, 32);
        out->derived_keys_set = base->derived_keys_set;
    }
    /* E16 — same merge shape for the verify-only
     * secondary key. Independent of primary so an operator can
     * stage a rotation by setting just the secondary on a child
     * scope. */
    if (add->secret_secondary) {
        out->secret_secondary     = add->secret_secondary;
        out->secret_secondary_len = add->secret_secondary_len;
        memcpy(out->derived_gcm_cookie_2,
               add->derived_gcm_cookie_2,     32);
        memcpy(out->derived_hmac_pending_2,
               add->derived_hmac_pending_2,   32);
        memcpy(out->derived_hmac_bootstrap_2,
               add->derived_hmac_bootstrap_2, 32);
        out->derived_keys_set_2 = add->derived_keys_set_2;
    } else {
        out->secret_secondary     = base->secret_secondary;
        out->secret_secondary_len = base->secret_secondary_len;
        memcpy(out->derived_gcm_cookie_2,
               base->derived_gcm_cookie_2,     32);
        memcpy(out->derived_hmac_pending_2,
               base->derived_hmac_pending_2,   32);
        memcpy(out->derived_hmac_bootstrap_2,
               base->derived_hmac_bootstrap_2, 32);
        out->derived_keys_set_2 = base->derived_keys_set_2;
    }
    out->score_silent  = (add->score_silent  == BS_UNSET) ? base->score_silent  : add->score_silent;
    out->score_hard    = (add->score_hard    == BS_UNSET) ? base->score_hard    : add->score_hard;
    out->score_captcha = (add->score_captcha == BS_UNSET) ? base->score_captcha : add->score_captcha;
    out->silent_mode   = (add->silent_mode   == BS_SILENT_MODE_UNSET)
                       ? base->silent_mode : add->silent_mode;
    out->form_captcha  = (add->form_captcha  == BS_UNSET)
                       ? base->form_captcha : add->form_captcha;
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
    out->captcha_connect_timeout_ms =
        (add->captcha_connect_timeout_ms == BS_UNSET)
            ? base->captcha_connect_timeout_ms
            : add->captcha_connect_timeout_ms;
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
    out->captcha_ca_bundle         = add->captcha_ca_bundle
                                     ? add->captcha_ca_bundle
                                     : base->captcha_ca_bundle;
    return out;
}

int bs_effective_int(int value, int fallback)
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

/* E18 — `BotShieldFormCaptcha on|off`. Per-scope opt-in for inline
 * form captcha verification on POST submit. When on, BotShield
 * inspects the request body for the configured captcha provider's
 * response field, siteverifies via the existing M8 client, mints
 * _bs_verified on success, and replays the body back via input
 * filter so the downstream app handler still sees its original
 * POST. Supports application/x-www-form-urlencoded and
 * application/json. multipart/form-data (file uploads) is out of
 * scope — operators with file-upload forms put the captcha on a
 * separate non-upload form. */
static const char *bs_set_form_captcha(cmd_parms *cmd, void *cfg_v, int flag)
{
    bs_dir_cfg *cfg = cfg_v;
    cfg->form_captcha = flag ? 1 : 0;
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
/* Loads up to max_bytes from path into a pool-allocated buffer.
 * The buffer is always NUL-terminated at byte n (one extra byte
 * past the file content). When out_len is non-NULL, it receives
 * the actual byte count read — callers handling binary content
 * (HMAC keys) MUST use this rather than strlen(out_content) since
 * binary keys can legitimately contain embedded NULs that
 * strlen would silently truncate at. Callers handling text
 * content (logo/help/challenge files) can pass NULL. */
static const char *bs_load_config_file(cmd_parms *cmd,
                                       const char *directive,
                                       const char *path,
                                       apr_size_t max_bytes,
                                       const char **out_content,
                                       apr_size_t *out_len)
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
    if (out_len) *out_len = n;
    return NULL;
}

/* Security review LOW #3 — derive the per-purpose keys for a master
 * secret. Called from the secret-file directive setters AFTER the
 * key bytes have been validated. Returns NULL on success; on
 * (vanishingly unlikely) HKDF failure returns a diagnostic string
 * the directive setter surfaces as a fatal config error so the
 * module refuses to start with a broken key derivation. The purpose
 * tags map 1:1 to derived_gcm_cookie / derived_hmac_pending /
 * derived_hmac_bootstrap in the dir_cfg. Bumping any tag (e.g.
 * "bs:cookie:gcm:v2") is the rotation knob if the underlying
 * crypto contract ever changes. */
static const char *bs_derive_purpose_keys(apr_pool_t *p,
                                          const unsigned char *master,
                                          apr_size_t master_len,
                                          unsigned char *out_gcm,
                                          unsigned char *out_pending,
                                          unsigned char *out_bootstrap)
{
    if (!bs_hkdf_derive_key(master, master_len,
                            "bs:cookie:gcm:v1", out_gcm)) {
        return apr_psprintf(p, "HKDF(bs:cookie:gcm:v1) failed");
    }
    if (!bs_hkdf_derive_key(master, master_len,
                            "bs:cookie:pending:v1", out_pending)) {
        return apr_psprintf(p, "HKDF(bs:cookie:pending:v1) failed");
    }
    if (!bs_hkdf_derive_key(master, master_len,
                            "bs:cookie:bootstrap:v1", out_bootstrap)) {
        return apr_psprintf(p, "HKDF(bs:cookie:bootstrap:v1) failed");
    }
    return NULL;
}

/* Security review HIGH #2 — validate a binary-capable secret loaded via
 * bs_load_config_file. Trims one trailing newline (common with
 * `echo`-style key generation), rejects embedded NUL bytes (would
 * silently truncate keys generated with `dd if=/dev/urandom` or
 * similar — P(NUL in N random bytes) = 1 − (255/256)^N, ≈12% for
 * 32-byte keys and ≈22% for 64-byte keys), and enforces the
 * minimum-bytes floor. Returns NULL on success with *out_len set
 * to the effective key length, or an error string. */
static const char *bs_validate_secret_key(cmd_parms *cmd,
                                          const char *directive,
                                          const char *path,
                                          const char *buf,
                                          apr_size_t buf_len,
                                          apr_size_t *out_len)
{
    apr_size_t len = buf_len;
    if (len > 0 && buf[len-1] == '\n') len--;
    if (memchr(buf, '\0', len) != NULL) {
        return apr_psprintf(cmd->pool,
            "%s: '%s' contains an embedded NUL byte. Random binary "
            "key files (e.g. `dd if=/dev/urandom` or `openssl rand`) "
            "hit a NUL with probability 1 − (255/256)^N — about 12%% "
            "for 32-byte keys, 22%% for 64-byte keys. Earlier versions "
            "of this loader silently truncated at the first NUL via "
            "strlen, yielding a shorter, weaker effective key with no "
            "log warning. Generate the key with hex "
            "(`openssl rand -hex 32`) or base64 "
            "(`openssl rand -base64 48`) encoding instead, or "
            "pre-strip NULs.",
            directive, path);
    }
    if (len < BS_MIN_SECRET_BYTES) {
        return apr_psprintf(cmd->pool,
            "%s: '%s' contains only %" APR_SIZE_T_FMT
            " bytes (minimum %d)",
            directive, path, len, BS_MIN_SECRET_BYTES);
    }
    *out_len = len;
    return NULL;
}

static const char *bs_set_logo_file(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    return bs_load_config_file(cmd, "BotShieldLogoFile", arg,
                               BS_MAX_LOGO_BYTES, &cfg->logo_svg, NULL);
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
                               BS_MAX_HELP_BYTES, &cfg->help_html, NULL);
}

static const char *bs_set_challenge_file(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    const char *err = bs_load_config_file(cmd, "BotShieldChallengeFile", arg,
                                          BS_MAX_PAGE_BYTES, &cfg->challenge_html, NULL);
    if (err) return err;
    if (!strstr(cfg->challenge_html, BS_WIDGET_MARKER)) {
        return apr_psprintf(cmd->pool,
            "BotShieldChallengeFile: '%s' contains no '%s' marker where the "
            "verification widget should be inserted", arg, BS_WIDGET_MARKER);
    }
    return NULL;
}

/* ======================================================================
 * Challenge struct, algorithm registry, issue/verify.
 * ====================================================================== */

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
int bs_parse_int_bounded(const char *s,
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
int bs_parse_uint32_bounded(const char *s,
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
int bs_parse_int64_bounded(const char *s,
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

/* Challenge issuance (bs_issue_challenge), the canonical-form HMAC
 * input (bs_challenge_canonical), the PoW algorithm registry, the
 * challenge-as-JSON serializer for the M7 interstitial, and the
 * MEDIUM #2 bootstrap-binding helpers all live in challenge.c
 * (see challenge.h). */

/* Captcha provider registry + libcurl-backed siteverify shim live
 * in captcha.c (see captcha.h). bs_find_provider, bs_captcha_siteverify,
 * the M8.1 pending-cookie pair, and the captcha-verify request
 * handler are all reachable through that header. */

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
static apr_status_t  bs_watchdog_save_cb(int state, void *data,
                                         apr_pool_t *pool);
/* The cookie envelope (mint/verify), the Cookie-header parser, and
 * the cross-file getters now live in cookie.h. The bootstrap-sig
 * pair lives in challenge.h. bs_verify_bootstrap_sig is private to
 * silent.c. */

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

/* Forward declarations — bs_check_policy (E3 path) calls these; they
 * live alongside their primary users further down the file.
 * (bs_parse_client_ip is now declared in botshield.h.) */
/* bs_mask_ipv6_prefix is now declared cross-file in botshield.h. */
/* E11 — load-state read used by bs_check_policy's load-trigger
 * walk. Declaration here so the walk compiles before the body. */
static bs_load_state bs_load_current(void);
/* SHM-table flagged-IP / strike / safeguard helpers all live in
 * shm.h. */
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

/* bs_feedback_trigger_entry now declared in botshield.h alongside
 * bs_trigger_action so bridge.c (E5) can use it without dragging the
 * full trigger system. */

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

/* Flag-trigger entry. Predicate is "flag_bit is set on this
 * request's IP-side or cookie-side flag bitmap"; the union of both
 * is computed once per request and triggers walk it.
 *
 * Two action verbs, kept separate from the shared bs_trigger_action
 * engine because they don't fit its penalty/status/redirect shape:
 *
 *   BS_FLAG_ACT_SCORE       — add `score_add` (signed, -1000..1000)
 *                             to the request score via bs_score_add.
 *                             Multiple matching score triggers SUM.
 *   BS_FLAG_ACT_TIER_FLOOR  — push the decided tier up to at least
 *                             `tier_min`. Multiple tier-floor
 *                             triggers MAX (strictest wins). */
typedef enum {
    BS_FLAG_ACT_SCORE = 0,
    BS_FLAG_ACT_TIER_FLOOR,
    /* Special-purpose entry: not a runtime action. The directive
     * `BotShieldFlagTrigger <flag> reset` inserts one of these as
     * a sentinel; post_config processing removes all earlier
     * entries targeting the same flag (defaults AND prior operator
     * declarations) along with the sentinel itself. The walker
     * never sees BS_FLAG_ACT_RESET entries — they're consumed
     * before the request path runs. */
    BS_FLAG_ACT_RESET,
} bs_flag_action_kind;

typedef struct {
    const char         *flag_name;    /* "honeypot_hit" etc. (display only) */
    apr_uint32_t        flag_bit;     /* resolved at parse time */
    bs_flag_action_kind action;
    int                 score_add;    /* used when action == SCORE */
    bs_tier             tier_min;     /* used when action == TIER_FLOOR */
    int                 mode;         /* bs_trigger_mode — observe vs enforce */
    int                 from_default; /* 1 if compiled-in default; 0 if operator */
} bs_flag_trigger_entry;

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

/* Path-pattern matching for BotShieldPathTrigger and BotShieldBlockPath
 * is the RFC 9309 matcher promoted from src/robots.c (bs_path_match).
 * The earlier v1 placeholder here that only handled <literal>,
 * <literal>*, and <literal>$ shapes was retired once the RFC 9309
 * matcher landed — its own comment flagged itself as temporary. One
 * path matcher across the codebase now. */

/* Surface a NOTICE at config-load when a pattern contains a non-
 * trailing '*'. Under the retired v1 matcher those characters were
 * treated as literal bytes (which essentially never matched any
 * URI). Under the RFC 9309 matcher they're proper wildcards. The
 * behavior change is desired for operators who intended wildcards;
 * for operators who fat-fingered a '*' the warning gives them a
 * heads-up so the new match doesn't surprise them. The trailing '*'
 * (or '*' followed only by '$') is the documented v1 shape and
 * stays silent — its behavior didn't change. */
static void bs_path_pattern_warn_middle_star(cmd_parms *cmd,
                                              const char *directive,
                                              const char *name,
                                              const char *pattern)
{
    const char *star = strchr(pattern, '*');
    if (!star) return;
    /* Find the last '*'. Anything past the last '*' that isn't
     * empty or "$" means there's content after a wildcard, i.e.
     * the wildcard is non-trailing. */
    const char *last_star = star;
    for (const char *q = star + 1; *q; q++) {
        if (*q == '*') last_star = q;
    }
    const char *tail = last_star + 1;
    if (*tail == '\0') return;        /* trailing '*' — v1 shape */
    if (tail[0] == '$' && tail[1] == '\0') return; /* '*$' — v1 shape */
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server,
        "mod_botshield: %s '%s' pattern '%s' contains a non-trailing "
        "'*'; interpreted per RFC 9309 (matches any byte sequence at "
        "this position). The retired v1 matcher treated middle '*' "
        "as a literal byte. If the literal was intended, this rule "
        "will no longer match.",
        directive, name, pattern);
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
 * count and err on admitting rather than emitting spurious 429s.
 *
 * Security review MEDIUM #4 — the prior shape did the window-roll
 * via two separate stores (CAS window_start_sec, then plain
 * __atomic_store_n on count = 1). Between those two operations,
 * another thread could land an increment via the bottom-of-loop
 * count-CAS path; the count=1 store then wiped that increment,
 * yielding a slightly-larger-than-budget window straddling the
 * rollover. Pack window_start_sec and count into a single u64 and
 * CAS them together — same shape as bs_cv_counter_bump. The
 * struct is already laid out 8-byte-packed for this. Each CAS
 * either rolls the window AND sets count atomically, or
 * increments count alone — no torn intermediate visible to
 * other threads. */
static int bs_rate_counter_admit(bs_rate_counter *slot,
                                 apr_uint32_t budget,
                                 apr_uint32_t window_sec)
{
    _Static_assert(sizeof(bs_rate_counter) == sizeof(apr_uint64_t),
                   "bs_rate_counter must be 8 bytes for u64 CAS");
    apr_uint64_t *p64 = (apr_uint64_t *)slot;
    apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
    for (int i = 0; i < 32; i++) {
        apr_uint64_t observed = __atomic_load_n(p64, __ATOMIC_RELAXED);
        bs_rate_counter snap;
        memcpy(&snap, &observed, sizeof(snap));
        apr_uint64_t next;
        bs_rate_counter cand;
        if (now < snap.window_start_sec ||
            now - snap.window_start_sec >= window_sec) {
            cand.count            = 1;
            cand.window_start_sec = now;
        } else {
            if (snap.count >= budget) return 0;
            cand.count            = snap.count + 1;
            cand.window_start_sec = snap.window_start_sec;
        }
        memcpy(&next, &cand, sizeof(next));
        if (__atomic_compare_exchange_n(p64, &observed, next,
                0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            return 1;
        }
        /* CAS lost — re-read */
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
            if (!bs_path_match(t->path_pattern, r->uri)) continue;
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
            if (!bs_path_match(e->path_pattern, r->uri)) continue;
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
                    (apr_uint32_t)e->shm_slot,
                    e->escalate->per_sec, e->escalate->strikes,
                    e->escalate->ttl_sec,
                    now_t, scfg->ns_id);
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

    /* Security review LOW #6 — surface truncated lines (the parser
     * silently caps any line > BOTSHIELD_ROBOTS_MAX_LINE). The
     * documented contract said operators "see a warning through
     * the summary log"; this emits that warning. */
    int n_truncated = robots_doc_truncated_lines(doc);
    if (n_truncated > 0) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: robots.txt %s: %d line(s) exceeded the "
            "parser line limit and were truncated during parse",
            scfg->robots_txt_path, n_truncated);
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



/* Flag-bit registry. Maps the BS_FLAG_* defines to the canonical
 * names that appear in directives (BotShieldFlagTrigger, BotShieldFlagIP),
 * wire formats (X-Botshield-Claims `flags=`), and the decision log.
 * Hoisted up the file so E8.2's claim-emit path can render the bitmap
 * without a forward-decl dance over an anonymous-struct array
 * (forward-declaring such arrays in C is awkward).
 *
 * E14 (rework) — registry trimmed to (name, bit). The prior penalty /
 * next_difficulty_delta / next_tier_floor fields were retired when
 * adaptive intensity moved into the unified BotShieldFlagTrigger
 * mechanism (see bs_default_flag_triggers below). */
typedef struct {
    const char     *name;
    apr_uint32_t    bit;
} bs_flag_meta;

static const bs_flag_meta bs_flag_metadata[] = {
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT         },
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE        },
    { "fake_bot",             BS_FLAG_FAKE_BOT             },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK      },
    { "app_verified_human",   BS_FLAG_APP_VERIFIED_HUMAN   },
    { "app_verified_session", BS_FLAG_APP_VERIFIED_SESSION },
    { "app_trust_signal",     BS_FLAG_APP_TRUST_SIGNAL     },
};
#define BS_FLAG_META_COUNT \
    (sizeof(bs_flag_metadata) / sizeof(bs_flag_metadata[0]))

/* NULL-terminated name+bit projection for the legacy parse sites
 * (bs_parse_flag_names, bs_app_claims_flag_names) that iterate via
 * a sentinel rather than a count. Struct is named (`bs_flag_name`)
 * so botshield.h can `extern`-declare the array. */
const struct bs_flag_name bs_flag_names[] = {
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT         },
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE        },
    { "fake_bot",             BS_FLAG_FAKE_BOT             },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK      },
    { "app_verified_human",   BS_FLAG_APP_VERIFIED_HUMAN   },
    { "app_verified_session", BS_FLAG_APP_VERIFIED_SESSION },
    { "app_trust_signal",     BS_FLAG_APP_TRUST_SIGNAL     },
    { NULL, 0 }
};

static const bs_flag_meta *bs_flag_meta_for_name(const char *name)
{
    for (size_t i = 0; i < BS_FLAG_META_COUNT; i++) {
        if (strcmp(bs_flag_metadata[i].name, name) == 0) {
            return &bs_flag_metadata[i];
        }
    }
    return NULL;
}

/* Compiled-in default flag-trigger rule set.
 *
 * Seeded into every server scope's scfg->flag_triggers at post_config
 * time so the module Just Works with zero config — operators don't
 * have to discover the abstraction to get sensible flag-driven
 * tier-bumping behavior. Operators tune by adding their own
 * BotShieldFlagTrigger directives (which append after these defaults
 * and accumulate per the SUM-score / MAX-tier_floor rules) or by
 * declaring `BotShieldFlagTrigger <flag> reset` to clear defaults
 * for that flag before declaring their own.
 *
 * Detection signals get both a score adjustment (for cumulative
 * effective-score math) and a tier_floor (for "this signal is
 * definitive enough that the response should be at least this
 * intense, regardless of cumulative score"). Trust signals get
 * score-only — a credit shouldn't force a tier UP.
 *
 * The score values match the prior bs_flag_meta.penalty fields the
 * E14 rework retired; behavior on a flagged IP is unchanged at the
 * effective-score level. The tier_floor entries are new: previously
 * E14 stayed dormant (every flag had next_tier_floor=PASS), so
 * flag-driven tier escalation only fired if an operator wrote a
 * BotShieldFlag directive — which Hubzero's 10 deployments never
 * did. Now the definitive signals (honeypot, fake-bot) escalate
 * to captcha automatically. */
static const struct {
    const char         *flag_name;
    apr_uint32_t        flag_bit;
    bs_flag_action_kind action;
    int                 score_add;
    bs_tier             tier_min;
} bs_default_flag_triggers[] = {
    /* Detection signals — definitive */
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT,
                              BS_FLAG_ACT_SCORE,        60, BS_TIER_PASS },
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT,
                              BS_FLAG_ACT_TIER_FLOOR,    0, BS_TIER_CAPTCHA },
    { "fake_bot",             BS_FLAG_FAKE_BOT,
                              BS_FLAG_ACT_SCORE,        80, BS_TIER_PASS },
    { "fake_bot",             BS_FLAG_FAKE_BOT,
                              BS_FLAG_ACT_TIER_FLOOR,    0, BS_TIER_CAPTCHA },
    /* Detection signals — probable */
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE,
                              BS_FLAG_ACT_SCORE,        50, BS_TIER_PASS },
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE,
                              BS_FLAG_ACT_TIER_FLOOR,    0, BS_TIER_HARD },
    /* Detection signals — accumulating */
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK,
                              BS_FLAG_ACT_SCORE,        30, BS_TIER_PASS },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK,
                              BS_FLAG_ACT_TIER_FLOOR,    0, BS_TIER_SILENT },
    /* Trust signals (credits) — score-only; never force tier up. */
    { "app_verified_human",   BS_FLAG_APP_VERIFIED_HUMAN,
                              BS_FLAG_ACT_SCORE,       -80, BS_TIER_PASS },
    { "app_verified_session", BS_FLAG_APP_VERIFIED_SESSION,
                              BS_FLAG_ACT_SCORE,       -40, BS_TIER_PASS },
    { "app_trust_signal",     BS_FLAG_APP_TRUST_SIGNAL,
                              BS_FLAG_ACT_SCORE,       -20, BS_TIER_PASS },
};
#define BS_DEFAULT_FLAG_TRIGGER_COUNT \
    (sizeof(bs_default_flag_triggers) / sizeof(bs_default_flag_triggers[0]))


static int bs_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                          apr_pool_t *ptemp, server_rec *s)
{
    (void)plog; (void)ptemp;

    /* Apache calls post-config twice on cold boot (syntax-check pass,
     * then the real one). Skip the first pass so we don't create the
     * SHM segment and then immediately discard it.
     *
     * Security review LOW #11 — the userdata key lives on
     * s->process->pool, which survives `apachectl graceful`. On
     * graceful, the previous boot's userdata is still set, so the
     * FIRST post_config call after graceful runs init directly
     * (correct — graceful only invokes post_config once). This
     * relies on Apache's documented post_config-runs-twice-on-cold-
     * boot, post_config-runs-once-on-graceful behavior. If that
     * ever changes (cold-boot single pass, or graceful double pass),
     * this skip would either suppress the only init opportunity
     * or skip the real one. Behavior is stable on Apache 2.4 today;
     * a more defensive pattern would key the userdata on a pconf-
     * scoped marker but Apache doesn't expose a stable one across
     * post_config invocations. */
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

    /* App integration: warn loudly at startup if a feature is on but
     * the shared secret is missing. Per-request paths fall through
     * with their own warning + skip (see bs_app_feedback_verify_filter
     * / bs_app_claims_set_header), but a single startup notice is
     * easier for operators to spot than a stream of per-request
     * warnings. We don't refuse to start: the rest of the module
     * still works (cookie tier, captcha tier, etc.). */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;
        int needs_secret = (vcfg->app_feedback_enabled == 1) ||
                           (vcfg->app_claims_enabled   == 1);
        if (needs_secret && !vcfg->app_integration_secret) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
                "mod_botshield: BotShieldAppFeedback or "
                "BotShieldAppClaims is enabled but "
                "BotShieldAppIntegrationSecretFile is not configured "
                "on this scope; the feature will be silently skipped "
                "at request time.");
        }
    }

    /* E14 (rework) — flag-trigger registration.
     *
     * For each server scope: prepend the compiled-in defaults to
     * the operator-declared trigger list (so defaults are earliest
     * and reset entries clear them), then walk the combined array
     * and process reset sentinels. A `reset` for a flag removes
     * every prior entry targeting that flag (defaults + operator)
     * along with the reset sentinel itself; entries declared after
     * the reset for the same flag are kept.
     *
     * Result is a final, request-time-ready scfg->flag_triggers
     * containing only BS_FLAG_ACT_SCORE / BS_FLAG_ACT_TIER_FLOOR
     * entries — no resets to dispatch on the hot path. */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;
        apr_array_header_t *operator_decls = vcfg->flag_triggers;
        apr_array_header_t *combined = apr_array_make(pconf,
            BS_DEFAULT_FLAG_TRIGGER_COUNT
              + (operator_decls ? operator_decls->nelts : 0),
            sizeof(void *));
        /* Defaults first. */
        for (size_t i = 0; i < BS_DEFAULT_FLAG_TRIGGER_COUNT; i++) {
            const typeof(bs_default_flag_triggers[0]) *d =
                &bs_default_flag_triggers[i];
            bs_flag_trigger_entry *e = apr_pcalloc(pconf, sizeof(*e));
            e->flag_name    = d->flag_name;
            e->flag_bit     = d->flag_bit;
            e->action       = d->action;
            e->score_add    = d->score_add;
            e->tier_min     = d->tier_min;
            e->mode         = BS_TMODE_ENFORCE;
            e->from_default = 1;
            *(bs_flag_trigger_entry **)apr_array_push(combined) = e;
        }
        /* Operator declarations next, in declaration order. */
        if (operator_decls) {
            for (int i = 0; i < operator_decls->nelts; i++) {
                bs_flag_trigger_entry *e =
                    APR_ARRAY_IDX(operator_decls, i, bs_flag_trigger_entry *);
                *(bs_flag_trigger_entry **)apr_array_push(combined) = e;
            }
        }
        /* Resolve reset sentinels: walk combined; when a reset is
         * found, drop every earlier entry for the same flag and the
         * reset itself. Build the final array in one pass. */
        apr_array_header_t *resolved = apr_array_make(pconf,
            combined->nelts, sizeof(void *));
        for (int i = 0; i < combined->nelts; i++) {
            bs_flag_trigger_entry *e =
                APR_ARRAY_IDX(combined, i, bs_flag_trigger_entry *);
            if (e->action == BS_FLAG_ACT_RESET) {
                /* Remove prior entries for this flag. */
                int w = 0;
                for (int j = 0; j < resolved->nelts; j++) {
                    bs_flag_trigger_entry *k =
                        APR_ARRAY_IDX(resolved, j, bs_flag_trigger_entry *);
                    if (k->flag_bit != e->flag_bit) {
                        APR_ARRAY_IDX(resolved, w, bs_flag_trigger_entry *) = k;
                        w++;
                    }
                }
                resolved->nelts = w;
                /* Sentinel itself is consumed — don't append. */
                continue;
            }
            *(bs_flag_trigger_entry **)apr_array_push(resolved) = e;
        }
        vcfg->flag_triggers = resolved;
    }

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
    /* MEDIUM #2 (Phase 2) — nonce table. */
    apr_size_t nonce_slots = (scfg->nonce_capacity > 0)
                           ? (apr_size_t)scfg->nonce_capacity
                           : (apr_size_t)BS_DEFAULT_NONCE_SLOTS;
    apr_size_t nonce_bytes = nonce_slots * sizeof(bs_nonce_slot);
    apr_size_t total_bytes  = header_bytes + table_bytes + 2 * bloom_bytes
                              + cv_rate_bytes + cv_log_bytes
                              + metrics_bytes + e21_rate_bytes
                              + strike_bytes + safeguard_bytes
                              + nonce_bytes;

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

    /* Graceful-restart hand-off. If a previous generation's SHM is
     * still live (bs_shm.shm != NULL means we're inside `apachectl
     * graceful` rather than a cold boot), force a synchronous save
     * of THAT generation's state to disk before we allocate the new
     * SHM and overwrite bs_shm. Without this, the new generation's
     * bs_state_load (called shortly below) would read a state.bin
     * up to BotShieldStateSaveInterval seconds stale — the old
     * generation's accumulated reputation since the last periodic
     * save would be lost. The old pconf's bs_state_cleanup will
     * also fire, but asynchronously AFTER this post_config
     * completes — too late to influence the new generation's load.
     * ptemp is the right pool here: scratch memory that dies with
     * this post_config invocation. */
    if (bs_shm.shm && scfg->state_file) {
        bs_shm_runtime old_rt = bs_shm;
        bs_state_save(ptemp, s, scfg->state_file, &old_rt);
    }

    /* Security review HIGH #4 — snapshot bs_shm before any failable
     * step that mutates the global. If RAND_bytes /
     * apr_global_mutex_create / ap_unixd_set_global_mutex_perms
     * fail, the new pconf gets destroyed by APR (which frees the
     * apr_shm_t), but the global bs_shm.shm / header /
     * flagged_table / bloom_bufs[*] would still hold dangling
     * pointers. On graceful restart with a botched new config the
     * old workers continue using the dangling state until the old
     * pconf finally tears down. Restore the snapshot on every
     * error path below so bs_shm either stays at the OLD
     * generation's pointers (graceful) or stays NULL (cold boot). */
    bs_shm_runtime saved_bs_shm = bs_shm;
    apr_status_t rv = apr_shm_create(&bs_shm.shm, scfg->shm_size,
                                     NULL, pconf);
    if (rv != APR_SUCCESS) {
        char errbuf[128];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: apr_shm_create failed: %s", errbuf);
        bs_shm = saved_bs_shm;
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
        bs_shm = saved_bs_shm;
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
    /* All slot types now share the same empty-marker convention
     * (apr_uint32_t used == 0); apr_shm_create zeroes the segment so
     * no explicit per-table init pass is needed. */
    bs_shm.safeguard_table = (bs_safeguard_slot *)
        ((unsigned char *)bs_shm.strike_table + strike_bytes);
    bs_shm.safeguard_capacity = safeguard_slots;
    /* MEDIUM #2 (Phase 2): nonce table follows safeguard. memset(base,0)
     * leaves every expires_at == 0 (empty sentinel) — no explicit
     * zero pass needed. */
    bs_shm.nonce_table = (bs_nonce_slot *)
        ((unsigned char *)bs_shm.safeguard_table + safeguard_bytes);
    bs_shm.nonce_capacity = nonce_slots;

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
        bs_shm = saved_bs_shm;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#ifdef AP_NEED_SET_MUTEX_PERMS
    rv = ap_unixd_set_global_mutex_perms(bs_shm.mutex);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: set_global_mutex_perms failed");
        bs_shm = saved_bs_shm;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif

    /* Pass bs_shm.shm as cleanup data so bs_shm_cleanup can verify
     * the global bs_shm still belongs to OUR generation before
     * zeroing it. Prevents the segfault where an old pconf's
     * cleanup zeros the global struct after the new generation has
     * already taken it over. */
    apr_pool_cleanup_register(pconf, bs_shm.shm, bs_shm_cleanup,
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
        /* Snapshot bs_shm at registration time so the cleanup save
         * (and the watchdog periodic save) operates on OUR
         * generation's SHM, not whatever a future graceful restart
         * has overwritten the global with. */
        ctx->shm_rt = bs_shm;
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
         * get rejected on format mismatch.
         *
         * Operator-facing documentation lives in the README's
         * "Multi-vhost deployments" section: every vhost gets
         * isolated reputation by default, and operators opt into
         * sharing reputation across sibling vhosts by setting the
         * same BotShieldShareScope token on each. Hundreds of
         * vhosts on one Apache instance share one SHM segment;
         * the per-slot ns_id is what makes that work. */
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
                /* Hysteresis fields too — bs_load_apply_tick reads
                 * these off main_scfg via the watchdog callback. If
                 * an operator sets BotShieldLoadWarmRise inside a
                 * <VirtualHost>, the directive parses fine but
                 * silently has no effect unless we propagate. */
                if (main_scfg->load_warm_rise <= 0
                    && vc->load_warm_rise > 0)
                    main_scfg->load_warm_rise = vc->load_warm_rise;
                if (main_scfg->load_hot_rise <= 0
                    && vc->load_hot_rise > 0)
                    main_scfg->load_hot_rise = vc->load_hot_rise;
                if (main_scfg->load_normal_fall <= 0
                    && vc->load_normal_fall > 0)
                    main_scfg->load_normal_fall = vc->load_normal_fall;
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


static const char *bs_set_state_file(cmd_parms *cmd, void *dconf,
                                     const char *arg)
{
    (void)dconf;
    bs_warn_if_virtual_scope(cmd, "BotShieldStateFile");
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
    bs_warn_if_virtual_scope(cmd, "BotShieldStateSaveInterval");
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

/* MEDIUM #2 (Phase 2) — BotShieldEmbeddedNonceCapacity <n>. SHM
 * slot count for the embedded-bootstrap nonce table. Sized to
 * comfortably hold all in-flight bootstrap challenges within their
 * 120-second expiry window: at 100 bootstraps/sec sustained that's
 * 12K nonces; the 32K default has ~60% headroom. */
static const char *bs_set_nonce_capacity(cmd_parms *cmd,
                                         void *dconf,
                                         const char *arg)
{
    (void)dconf;
    bs_warn_if_virtual_scope(cmd, "BotShieldEmbeddedNonceCapacity");
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end ||
        n < BS_NONCE_MIN_SLOTS || n > BS_NONCE_MAX_SLOTS) {
        return apr_psprintf(cmd->pool,
            "BotShieldEmbeddedNonceCapacity: '%s' must be %d..%d",
            arg, BS_NONCE_MIN_SLOTS, BS_NONCE_MAX_SLOTS);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->nonce_capacity = (int)n;
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

/* E14 (rework) — BotShieldFlagTrigger <flag> [reset] [action=<verb> args...]
 *
 * One unified config language for "when this flag fires, do X." Replaces
 * the prior BotShieldFlag directive (which mutated bs_flag_meta entries
 * to attach penalty/next_difficulty/next_tier metadata) with the same
 * shape as the existing BotShieldPathTrigger / BotShieldFeedbackTrigger /
 * BotShieldLoadTrigger family.
 *
 * Two action verbs:
 *   action=score add=N           — add signed N (-1000..1000) to the
 *                                  request score. SUM accumulates across
 *                                  triggers.
 *   action=tier_floor min=<tier> — set a minimum tier; <tier> is
 *                                  pass|silent|form|captcha. MAX
 *                                  accumulates (strictest wins).
 *
 * Reset keyword: `BotShieldFlagTrigger <flag> reset` clears all earlier
 * triggers (compiled-in defaults + prior operator declarations) for that
 * flag at post_config time. Three accepted forms:
 *
 *   BotShieldFlagTrigger pow_fail_streak reset
 *   BotShieldFlagTrigger honeypot_hit reset action=tier_floor min=form
 *   BotShieldFlagTrigger honeypot_hit reset
 *   BotShieldFlagTrigger honeypot_hit action=score add=60
 *
 * Form 2 is sugar for the first two of form 3. Reset is a directive-
 * level keyword, not an action verb — keeping the two concerns
 * syntactically distinct prevents conflict with future runtime verbs.
 *
 * Storage: each parsed line appends a bs_flag_trigger_entry to
 * scfg->flag_triggers. Reset entries appear inline as sentinels
 * (action=BS_FLAG_ACT_RESET); post_config consumes them. */
static const char *bs_set_flag_trigger(cmd_parms *cmd, void *dconf,
                                       int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 1) {
        return "BotShieldFlagTrigger: expects <flag> "
               "[reset] [action=<verb> args...]";
    }
    const char *flag_name = argv[0];
    const bs_flag_meta *fm = bs_flag_meta_for_name(flag_name);
    if (!fm) {
        return apr_psprintf(cmd->pool,
            "BotShieldFlagTrigger: unknown flag '%s'. Known flags: "
            "honeypot_hit, scanner_probe, fake_bot, pow_fail_streak, "
            "app_verified_human, app_verified_session, "
            "app_trust_signal", flag_name);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);

    int idx = 1;
    int saw_reset = 0;
    if (idx < argc && strcasecmp(argv[idx], "reset") == 0) {
        saw_reset = 1;
        idx++;
        bs_flag_trigger_entry *r = apr_pcalloc(cmd->pool, sizeof(*r));
        r->flag_name    = apr_pstrdup(cmd->pool, flag_name);
        r->flag_bit     = fm->bit;
        r->action       = BS_FLAG_ACT_RESET;
        r->mode         = BS_TMODE_ENFORCE;
        r->from_default = 0;
        *(bs_flag_trigger_entry **)apr_array_push(scfg->flag_triggers) = r;
    }
    /* Bare `reset` with nothing after — done. */
    if (idx >= argc) return NULL;

    /* Otherwise the next token must be `action=<verb>`. */
    if (strncasecmp(argv[idx], "action=", 7) != 0) {
        if (saw_reset) {
            return apr_psprintf(cmd->pool,
                "BotShieldFlagTrigger '%s' reset: extra arg '%s' must "
                "begin with 'action=' (or omit it for a bare reset)",
                flag_name, argv[idx]);
        }
        return apr_psprintf(cmd->pool,
            "BotShieldFlagTrigger '%s': expected 'reset' or 'action=' "
            "as the second token; got '%s'", flag_name, argv[idx]);
    }
    const char *verb = argv[idx] + 7;
    idx++;

    bs_flag_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->flag_name    = apr_pstrdup(cmd->pool, flag_name);
    e->flag_bit     = fm->bit;
    e->mode         = BS_TMODE_ENFORCE;
    e->from_default = 0;

    if (strcasecmp(verb, "score") == 0) {
        e->action = BS_FLAG_ACT_SCORE;
        int saw_add = 0;
        for (; idx < argc; idx++) {
            const char *arg = argv[idx];
            if (strncasecmp(arg, "add=", 4) == 0) {
                char *e2 = NULL;
                long n = strtol(arg + 4, &e2, 10);
                if (!e2 || *e2 || n < -1000 || n > 1000) {
                    return apr_psprintf(cmd->pool,
                        "BotShieldFlagTrigger '%s' action=score: "
                        "add='%s' must be an integer in -1000..1000",
                        flag_name, arg + 4);
                }
                e->score_add = (int)n;
                saw_add = 1;
            } else if (strcasecmp(arg, "mode=observe") == 0) {
                e->mode = BS_TMODE_OBSERVE;
            } else if (strcasecmp(arg, "mode=enforce") == 0) {
                e->mode = BS_TMODE_ENFORCE;
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlagTrigger '%s' action=score: "
                    "unknown arg '%s' (want add=N or mode=observe)",
                    flag_name, arg);
            }
        }
        if (!saw_add) {
            return apr_psprintf(cmd->pool,
                "BotShieldFlagTrigger '%s' action=score: missing "
                "required 'add=N'", flag_name);
        }
    } else if (strcasecmp(verb, "tier_floor") == 0) {
        e->action = BS_FLAG_ACT_TIER_FLOOR;
        int saw_min = 0;
        for (; idx < argc; idx++) {
            const char *arg = argv[idx];
            if (strncasecmp(arg, "min=", 4) == 0) {
                const char *t = arg + 4;
                if      (strcasecmp(t, "pass")    == 0) e->tier_min = BS_TIER_PASS;
                else if (strcasecmp(t, "silent")  == 0) e->tier_min = BS_TIER_SILENT;
                else if (strcasecmp(t, "form")    == 0) e->tier_min = BS_TIER_HARD;
                else if (strcasecmp(t, "captcha") == 0) e->tier_min = BS_TIER_CAPTCHA;
                else {
                    return apr_psprintf(cmd->pool,
                        "BotShieldFlagTrigger '%s' action=tier_floor: "
                        "min='%s' must be one of pass/silent/form/captcha",
                        flag_name, t);
                }
                saw_min = 1;
            } else if (strcasecmp(arg, "mode=observe") == 0) {
                e->mode = BS_TMODE_OBSERVE;
            } else if (strcasecmp(arg, "mode=enforce") == 0) {
                e->mode = BS_TMODE_ENFORCE;
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlagTrigger '%s' action=tier_floor: "
                    "unknown arg '%s' (want min=<tier> or mode=observe)",
                    flag_name, arg);
            }
        }
        if (!saw_min) {
            return apr_psprintf(cmd->pool,
                "BotShieldFlagTrigger '%s' action=tier_floor: missing "
                "required 'min=<tier>'", flag_name);
        }
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldFlagTrigger '%s': unknown action verb '%s' "
            "(want score or tier_floor)", flag_name, verb);
    }

    *(bs_flag_trigger_entry **)apr_array_push(scfg->flag_triggers) = e;
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
    bs_path_pattern_warn_middle_star(cmd, "BotShieldBlockPath",
                                      name, pattern);

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
    case BS_TFAMILY_FLAG:     return "BotShieldFlagTrigger";
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
    case BS_TFAMILY_FLAG:
        /* Flag triggers do not use bs_trigger_action — they have
         * their own bs_flag_trigger_entry shape with different
         * verbs. This case exists only to keep the switch
         * exhaustive across the enum; reaching it means a
         * caller mis-routed a flag trigger through the shared
         * engine. */
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
    case BS_TFAMILY_FLAG:
        /* Flag triggers use a separate parser. This entry exists
         * for switch-exhaustiveness; the flag setter prints its
         * own allowed-keys list at error time. */
        return "score, tier_floor, mode";
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
    bs_path_pattern_warn_middle_star(cmd, "BotShieldPathTrigger",
                                      name, pattern);

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
        if (!strcasecmp(cname, BS_COOKIE_NAME) ||
            !strcasecmp(cname, BS_COOKIE_NAME_HOST)) {
            return "BotShieldCookieTrigger: declaring a predicate "
                   "against the module's own " BS_COOKIE_NAME
                   " (or " BS_COOKIE_NAME_HOST ") cookie is not "
                   "supported — use bs-cookie=verified / "
                   "bs-cookie=missing / bs-cookie=invalid instead";
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

/* BotShieldAppIntegrationSecretFile <path>. HMAC key for both
 * directions of app integration: validates inbound feedback envelopes
 * and signs outbound X-Botshield-Claims headers. The two protocols'
 * canonical forms are structurally distinct (feedback HMACs
 * `event=<name>` only; claims HMAC seven semicolon-fields with a
 * fixed `v=1` lead) so cross-replay is not possible. Mode-600-or-
 * tighter + absolute path; loaded at parse time so the bytes are in
 * memory before the first request hits the hook. */
static const char *bs_set_app_integration_secret_file(cmd_parms *cmd,
                                                       void *dconf,
                                                       const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldAppIntegrationSecretFile: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldAppIntegrationSecretFile: path must be absolute";
    }

    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppIntegrationSecretFile: cannot stat '%s'", arg);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppIntegrationSecretFile: '%s' is group- or "
            "world-accessible (mode %04o); chmod 600 it",
            arg, st.st_mode & 07777);
    }

    const char *buf = NULL;
    apr_size_t buf_len = 0;
    const char *err = bs_load_config_file(cmd,
        "BotShieldAppIntegrationSecretFile", arg,
        BS_MAX_SECRET_BYTES, &buf, &buf_len);
    if (err) return err;

    apr_size_t len = 0;
    err = bs_validate_secret_key(cmd, "BotShieldAppIntegrationSecretFile",
                                 arg, buf, buf_len, &len);
    if (err) return err;

    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_integration_secret_file = apr_pstrdup(cmd->pool, arg);
    scfg->app_integration_secret      = (const unsigned char *)buf;
    scfg->app_integration_secret_len  = len;
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
    if (!ctx->shm_rt.shm || !ctx->shm_rt.flagged_table ||
        !ctx->shm_rt.bloom_bufs[0]) {
        return APR_SUCCESS;   /* SHM not up yet; nothing to save */
    }
    /* Use the callback's own pool so temporaries die with this tick. */
    bs_state_save(pool, ctx->server, ctx->path, &ctx->shm_rt);
    return APR_SUCCESS;
}

/* E14 (rework) — flag-trigger walker.
 *
 * Runs in bs_handler after flag bits are known (after
 * bs_flagged_ip_lookup and after the cookie verify decides
 * have_prior_rep) but BEFORE the tier decision. For each entry in
 * scfg->flag_triggers whose flag_bit is set in `all_flags`:
 *   - SCORE actions accumulate via bs_score_add (which already
 *     SUMs into the per-request score struct)
 *   - TIER_FLOOR actions MAX into *out_tier_floor; the caller
 *     applies the MAX(score_tier, *out_tier_floor) after
 *     bs_decide_tier returns.
 *
 * Observe-mode (mode=observe) entries log
 * `would-flag-trigger:<flag>:observe` and skip the side effect.
 *
 * Returns the count of triggers that fired (informational; the
 * walker's effects are applied via bs_score_add and
 * *out_tier_floor). */
static int bs_apply_flag_triggers(request_rec *r,
                                   const bs_server_cfg *scfg,
                                   apr_uint32_t all_flags,
                                   bs_tier *out_tier_floor)
{
    if (out_tier_floor) *out_tier_floor = BS_TIER_PASS;
    if (!scfg || !scfg->flag_triggers || all_flags == 0) return 0;
    int fired = 0;
    for (int i = 0; i < scfg->flag_triggers->nelts; i++) {
        bs_flag_trigger_entry *e =
            APR_ARRAY_IDX(scfg->flag_triggers, i, bs_flag_trigger_entry *);
        if (!(all_flags & e->flag_bit)) continue;
        fired++;
        if (e->mode == BS_TMODE_OBSERVE) {
            bs_score_add(r, 0, 0,
                apr_psprintf(r->pool,
                    "would-flag-trigger:%s:observe", e->flag_name));
            continue;
        }
        if (e->action == BS_FLAG_ACT_SCORE) {
            bs_score_add(r, e->score_add, 0,
                apr_psprintf(r->pool,
                    "flag-trigger:%s", e->flag_name));
        } else if (e->action == BS_FLAG_ACT_TIER_FLOOR) {
            if (out_tier_floor && e->tier_min > *out_tier_floor) {
                *out_tier_floor = e->tier_min;
            }
        }
        /* BS_FLAG_ACT_RESET entries are consumed at post_config —
         * the request path never sees them. */
    }
    return fired;
}

/* Decide whether the rep block in *prior_ch can be carried into a
 * freshly-minted cookie, given the cverr that bs_verify_cookie just
 * returned.
 *
 * Reject when:
 *   - cverr == "signature mismatch"  (rep bytes can't be trusted)
 *   - cverr == "expired"  ── Security review MEDIUM #1: TTL is the
 *     only mechanism preventing indefinite reputation transfer
 *     across cookie generations. A leaked or stolen cookie that has
 *     aged past TTL must NOT be allowed to transplant good-standing
 *     rep into a fresh _bs_verified via any solve path.
 *   - cverr is some other pre-auth failure (decode errors, wrong
 *     field count, "no secret configured", etc.) — bs_verify_cookie
 *     leaves *prior_ch unwritten in those branches, so
 *     prior_ch->alg_name is NULL and we reject.
 *
 * Accept when:
 *   - cverr == NULL  (cookie fully validated)
 *   - cverr names a post-tag-verification failure (PoW counter
 *     check, etc.) — bs_verify_cookie wrote authenticated rep into
 *     *prior_ch and prior_ch->alg_name is non-NULL.
 *
 * This is the load-bearing carry-forward gate. Both the issuance-
 * side helper (bs_carry_forward_eligible) and the render-side
 * predicate in bs_handler share this single source of truth so a
 * change to the rule only has to land here. The original review
 * (MEDIUM #1) was a four-site fix that the issuance-side
 * consolidation collapsed to one site; reusing this predicate from
 * bs_handler closes the same drift gap on the render side. */
static int bs_should_carry_prior_rep(const char *cverr,
                                      const bs_challenge *prior_ch)
{
    if (cverr == NULL) return 1;
    if (strcmp(cverr, "signature mismatch") == 0) return 0;
    if (strcmp(cverr, "expired") == 0) return 0;          /* MEDIUM #1 */
    return prior_ch->alg_name ? 1 : 0;
}

/* Carry-forward eligibility predicate for issuance call sites. Reads
 * the request's __Host-bs_verified cookie, verifies it, and applies
 * bs_should_carry_prior_rep to the result. Returns 1 with *out_prior_ch
 * populated when carry-forward is allowed; 0 (and leaves *out_prior_ch
 * untouched beyond what bs_verify_cookie wrote) when not.
 *
 * Used by bs_embedded_verify_pow_gcm, bs_embedded_verify_provider,
 * bs_captcha_verify_handler, and bs_form_captcha_replay. */
int bs_carry_forward_eligible(request_rec *r,
                                      const bs_dir_cfg *cfg,
                                      bs_challenge *out_prior_ch)
{
    const char *prior_val = bs_get_verified_cookie_value(r);
    if (!prior_val || !*prior_val) return 0;
    const char *cverr = bs_verify_cookie(r, cfg, prior_val, out_prior_ch);
    return bs_should_carry_prior_rep(cverr, out_prior_ch);
}

/* Apply the rep-carry-forward computation to *target.
 *
 * The caller has chosen forgive_amount based on the issuance tier
 * (cfg->forgive_silent / forgive_captcha / etc.) — that knowledge
 * stays at the call site because forgive bands are per-tier policy.
 *
 * This helper does the deterministic math:
 *   - clamp the requested forgive against the per-cookie hourly cap
 *     (writes target->forgive_window_start + forgive_consumed)
 *   - compute new score = prior.score - forgive, clamped against
 *     the flag-penalty floor and zero
 *
 * The caller bumps the appropriate passes_X afterward (the LOW #7
 * "ever passed" clamp). Tier knowledge for that decision also stays
 * at the call site. */
void bs_apply_rep_carry(request_rec *r,
                                const bs_dir_cfg *cfg,
                                const bs_challenge *prior_ch,
                                bs_rep_state *target,
                                int forgive_amount)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    int cap = (scfg && scfg->forgive_cap_per_hour > 0)
            ? scfg->forgive_cap_per_hour
            : BS_DEFAULT_FORGIVE_CAP_PER_HOUR;
    apr_uint32_t now_sec = (apr_uint32_t)apr_time_sec(apr_time_now());
    int forgive = bs_forgiveness_apply_cap(forgive_amount, cap, now_sec,
                                           &target->forgive_window_start,
                                           &target->forgive_consumed);
    /* E14 (rework) — the prior bs_flag_penalty floor here was tied
     * to the retired bs_flag_meta.penalty field. Under the new
     * design flag effects are re-applied at request time via
     * bs_apply_flag_triggers, so the carry-forward floor became
     * redundant: a forgiven-to-zero score on a flagged cookie is
     * simply re-raised on the next request when the trigger fires.
     * Carry-forward now clamps only at zero. */
    int new_score = prior_ch->rep.score - forgive;
    if (new_score < 0) new_score = 0;
    target->score = new_score;
}

/* E14 (rework) — the prior bs_flag_adaptive accumulator that walked
 * bs_flag_meta.next_difficulty_delta and next_tier_floor was retired.
 * Adaptive effects are now expressed as BotShieldFlagTrigger entries
 * and applied via bs_apply_flag_triggers above. */

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
    apr_size_t buf_len = 0;
    const char *err = bs_load_config_file(cmd, "BotShieldSecretFile", arg,
                                          BS_MAX_SECRET_BYTES, &buf, &buf_len);
    if (err) return err;

    apr_size_t len = 0;
    err = bs_validate_secret_key(cmd, "BotShieldSecretFile",
                                 arg, buf, buf_len, &len);
    if (err) return err;

    cfg->secret     = (const unsigned char *)buf;
    cfg->secret_len = len;

    /* Security review LOW #3 — derive per-purpose keys once. */
    err = bs_derive_purpose_keys(cmd->pool,
                                  cfg->secret, cfg->secret_len,
                                  cfg->derived_gcm_cookie,
                                  cfg->derived_hmac_pending,
                                  cfg->derived_hmac_bootstrap);
    if (err) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecretFile: key derivation failed: %s", err);
    }
    cfg->derived_keys_set = 1;
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
    apr_size_t buf_len = 0;
    const char *err = bs_load_config_file(cmd,
                                          "BotShieldSecondarySecretFile",
                                          arg, BS_MAX_SECRET_BYTES,
                                          &buf, &buf_len);
    if (err) return err;

    apr_size_t len = 0;
    err = bs_validate_secret_key(cmd, "BotShieldSecondarySecretFile",
                                 arg, buf, buf_len, &len);
    if (err) return err;

    cfg->secret_secondary     = (const unsigned char *)buf;
    cfg->secret_secondary_len = len;

    /* Security review LOW #3 — derive per-purpose keys for the
     * secondary master too. */
    err = bs_derive_purpose_keys(cmd->pool,
                                  cfg->secret_secondary,
                                  cfg->secret_secondary_len,
                                  cfg->derived_gcm_cookie_2,
                                  cfg->derived_hmac_pending_2,
                                  cfg->derived_hmac_bootstrap_2);
    if (err) {
        return apr_psprintf(cmd->pool,
            "BotShieldSecondarySecretFile: key derivation failed: %s",
            err);
    }
    cfg->derived_keys_set_2 = 1;
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
    apr_size_t buf_len = 0;
    const char *err = bs_load_config_file(cmd, "BotShieldCaptchaSecretFile",
                                          arg, BS_MAX_SECRET_BYTES,
                                          &buf, &buf_len);
    if (err) return err;

    apr_size_t len = 0;
    err = bs_validate_secret_key(cmd, "BotShieldCaptchaSecretFile",
                                 arg, buf, buf_len, &len);
    if (err) return err;
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

/* Security review LOW #13 — operator-tunable connect-phase timeout.
 * Default BS_CAPTCHA_CONNECT_TIMEOUT (250 ms) is tight for healthy
 * networks; operators on transient-loss links can bump it to avoid
 * fail-open on momentary connect blips. Same overall bound as the
 * full siteverify timeout. */
static const char *bs_set_captcha_connect_timeout(cmd_parms *cmd,
                                                  void *cfg_v,
                                                  const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < 50 || v > BS_MAX_CAPTCHA_TIMEOUT) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaConnectTimeout: '%s' must be an integer in "
            "50..%d ms", arg, BS_MAX_CAPTCHA_TIMEOUT);
    }
    cfg->captcha_connect_timeout_ms = (int)v;
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

/* `BotShieldCaptchaCABundle <path>` — absolute path to a PEM
 * certificate bundle that libcurl will use when validating the
 * captcha-provider TLS certificate. Optional. When unset, libcurl
 * falls back to its compiled-in default (typically the system
 * `ca-certificates` bundle on Debian/Ubuntu/RHEL).
 *
 * Why this exists: stripped-down container images that omit the
 * `ca-certificates` package have no system CA store, so every
 * captcha siteverify hits CURLE_PEER_FAILED_VERIFICATION and the
 * captcha tier silently fails-open (occasional permissive better
 * than locking everyone out — but a permanent state of fail-open
 * is bad). Pointing this at the bundle the operator's image ships
 * fixes that without a config-time policy change. */
static const char *bs_set_captcha_ca_bundle(cmd_parms *cmd,
                                            void *cfg_v,
                                            const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg || !*arg) {
        return "BotShieldCaptchaCABundle: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldCaptchaCABundle: path must be absolute";
    }
    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaCABundle: cannot stat '%s'", arg);
    }
    if (!S_ISREG(st.st_mode)) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaCABundle: '%s' is not a regular file", arg);
    }
    cfg->captcha_ca_bundle = apr_pstrdup(cmd->pool, arg);
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




bs_request_score *bs_get_score(request_rec *r, int create)
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
/* Operator-facing documentation: README "Understanding scoring"
 * (rendered into docs/guide/index.html) explains the score
 * composition, threshold ladder, and tuning workflow. */
static void bs_score_add(request_rec *r, int penalty,
                         int ttl_seconds, const char *reason)
{
    bs_request_score *s = bs_get_score(r, 1);
    if (s->entries->nelts >= BS_SCORE_MAX_REASONS) {
        /* Silent drop on cap could mask a runaway loop or a
         * misconfigured rule fanout. Log once at DEBUG so the
         * diagnostic surfaces under verbose-logging without
         * spamming production. The total still accumulates from
         * the entries we kept; it's only the per-reason audit trail
         * that's truncated past this point. */
        if (!s->cap_warned) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: score-reason cap (%d) reached for %s; "
                "further bs_score_add calls drop their reason silently",
                BS_SCORE_MAX_REASONS, r->uri);
            s->cap_warned = 1;
        }
        return;
    }
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
    /* Same O(N) join shape as bs_decision_reason_names + commit
     * d939a72: pre-format each "reason:penalty" pair into a
     * pointer-array, single apr_array_pstrcat for the comma join,
     * then one apr_pstrcat to wrap with brackets. */
    int n = s->entries->nelts;
    apr_array_header_t *arr = apr_array_make(p, n, sizeof(const char *));
    for (int i = 0; i < n; i++) {
        bs_score_entry *e = &APR_ARRAY_IDX(s->entries, i, bs_score_entry);
        *(const char **)apr_array_push(arr) =
            apr_psprintf(p, "%s:%d", e->reason, e->penalty);
    }
    return apr_pstrcat(p, "[", apr_array_pstrcat(p, arr, ','), "]", NULL);
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
/* Score-to-tier threshold ladder. Three configurable cut-points
 * (BotShieldScoreSilent / Hard / Captcha) gate four tiers. See the
 * README "Understanding scoring" section for the operator-facing
 * tuning workflow. */
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

const char *bs_tier_name(bs_tier t)
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
    /* E18 — inline form captcha. */
    AP_INIT_FLAG("BotShieldFormCaptcha", bs_set_form_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "When on, this scope validates a configured captcha "
                 "provider's response token in the POST body of form "
                 "submissions. Requires BotShieldCaptchaProvider + "
                 "SiteKey + SecretFile in the same scope (or "
                 "inherited). On valid token: mints _bs_verified, "
                 "DECLINED so the app handler runs with the original "
                 "body intact. On bad/missing token: 403, app handler "
                 "never runs. Supports application/x-www-form-"
                 "urlencoded and application/json bodies; "
                 "multipart/form-data (file uploads) is out of scope."),
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
    AP_INIT_TAKE1("BotShieldCaptchaConnectTimeout",
                 bs_set_captcha_connect_timeout, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Connect-phase timeout for siteverify in milliseconds "
                 "(default: 250, range 50..5000). Tighter than the full "
                 "siteverify timeout; bump on links with transient packet "
                 "loss to avoid fail-open on momentary connect blips."),
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
    AP_INIT_TAKE1("BotShieldCaptchaCABundle", bs_set_captcha_ca_bundle,
                 NULL, RSRC_CONF | ACCESS_CONF,
                 "Absolute path to a PEM CA bundle libcurl will use to "
                 "validate the captcha-provider TLS certificate. "
                 "Optional; defaults to libcurl's compiled-in system "
                 "bundle. Set this on stripped container images that "
                 "lack /etc/ssl/certs to avoid silent fail-open from "
                 "every siteverify hitting "
                 "CURLE_PEER_FAILED_VERIFICATION."),
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
    AP_INIT_TAKE1("BotShieldEmbeddedNonceCapacity",
                 bs_set_nonce_capacity, NULL, RSRC_CONF,
                 "SHM slot count for the embedded-bootstrap nonce "
                 "table (default 32768, range 1024..1048576). "
                 "Bound the in-flight + recently-redeemed challenge "
                 "set within the 120s bootstrap expiry. Each slot "
                 "is 24 bytes."),
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
                 "alternative for staging a single rule. Typical "
                 "workflow: add new rules with mode=observe, watch "
                 "the decision log, flip to enforce when matches "
                 "look right."),
    /* E14 (rework) — flag-driven trigger family. */
    AP_INIT_TAKE_ARGV("BotShieldFlagTrigger",
                 bs_set_flag_trigger, NULL, RSRC_CONF,
                 "Apply an action when a flag bit fires on the IP- "
                 "or cookie-side bitmap of a request. Args: <flag> "
                 "[reset] [action=<verb> args...]. Flag names: "
                 "honeypot_hit, scanner_probe, fake_bot, "
                 "pow_fail_streak, app_verified_human, "
                 "app_verified_session, app_trust_signal. Action "
                 "verbs: 'score add=N' (signed, -1000..1000; SUMs "
                 "across triggers) or 'tier_floor min=<tier>' "
                 "(pass|silent|form|captcha; MAXes across triggers). "
                 "'reset' clears compiled-in defaults + prior "
                 "operator declarations for the named flag before "
                 "this directive's effect is added. mode=observe "
                 "logs would-flag-trigger:<flag>:observe instead of "
                 "applying. Compiled-in defaults cover the common "
                 "cases — see example/flag-triggers.conf.example."),
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
    /* E8.2 — module-to-app reputation export. */
    AP_INIT_FLAG("BotShieldAppClaims",
                 bs_set_app_claims, NULL, RSRC_CONF,
                 "Enable module-to-app reputation export. When on, "
                 "the module strips any client-supplied X-Botshield-* "
                 "from the request and sets a single signed "
                 "X-Botshield-Claims header before the backend handler "
                 "runs. Default off."),
    AP_INIT_TAKE1("BotShieldAppIntegrationSecretFile",
                 bs_set_app_integration_secret_file, NULL, RSRC_CONF,
                 "Absolute path to the HMAC key used for both inbound "
                 "feedback envelopes and outbound X-Botshield-Claims "
                 "headers. Mode 600, root-owned. The two protocols' "
                 "canonical forms are structurally distinct, so one key "
                 "is safe — cross-replay is blocked by parser shape, "
                 "not key separation. Required only when at least one "
                 "of BotShieldAppFeedback or BotShieldAppClaims is on."),
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
" /* The cookie is now server-minted via /botshield/embedded-verify,\n"
"    so the JS never references the name (LOW #1, #2). */\n"
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
"   /* Security review LOW #1 — POST the solution to the server\n"
"      and let it mint the cookie via Set-Cookie + HttpOnly,\n"
"      instead of setting document.cookie locally. JS can't read\n"
"      the cookie back, but it doesn't need to: server validates\n"
"      and the next request's bs_handler accepts the new cookie.\n"
"      MEDIUM #2 — round-trip bound_ip + bootstrap_sig for\n"
"      IP-binding. */\n"
"   var body = JSON.stringify({\n"
"    provider: 'pow-gcm',\n"
"    cookie_prefix: CH.cookie_prefix,\n"
"    bound_ip: CH.bound_ip,\n"
"    bootstrap_sig: CH.bootstrap_sig,\n"
"    counter: counterVal\n"
"   });\n"
"   fetch('/botshield/embedded-verify', {\n"
"    method: 'POST',\n"
"    credentials: 'same-origin',\n"
"    headers: {'Content-Type':'application/json'},\n"
"    body: body\n"
"   }).then(function(resp){\n"
"    if (resp.ok || resp.status === 204) {\n"
"     setTimeout(function(){ location.reload(); }, 250);\n"
"    } else {\n"
"     msg.textContent = 'Verification failed (' + resp.status + ')';\n"
"    }\n"
"   }).catch(function(err){\n"
"    msg.textContent = 'Verification failed: ' +\n"
"                       (err && err.message || err);\n"
"   });\n"
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
            return bs_metrics_handler(r);
        }
        if (strcmp(sub, "/policy-status") == 0) {
            return bs_policy_status_handler(r, cfg);
        }
        /* E17 PoC — embedded silent-verify endpoints. */
        if (strcmp(sub, "/embedded.js") == 0) {
            return bs_embedded_js_handler(r);
        }
        if (strcmp(sub, "/embedded-worker.js") == 0) {
            return bs_embedded_worker_handler(r);
        }
        if (strcmp(sub, "/embedded-bootstrap") == 0) {
            return bs_embedded_bootstrap_handler(r, cfg);
        }
        if (strcmp(sub, "/embedded-verify") == 0) {
            return bs_embedded_verify_handler(r, cfg);
        }
        /* E18.4 — form-widget shell. */
        if (strcmp(sub, "/form-widget.js") == 0) {
            return bs_form_widget_handler(r);
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
    const char *cookie_val = bs_get_verified_cookie_value(r);
    bs_challenge prior_ch = { 0 };
    int have_prior_rep   = 0;
    int cookie_fully_ok  = 0;
    const char *cookie_verify_reason = NULL;
    int cookie_had_val = (cookie_val && *cookie_val);
    if (cookie_had_val) {
        cookie_verify_reason = bs_verify_cookie(r, cfg, cookie_val, &prior_ch);
        /* MEDIUM #1: render-side carry-forward must reject the same
         * cverrs the issuance-side carry-forward rejects, otherwise
         * an expired cookie's rep can be transplanted via the
         * interstitial-render path (next_rep is baked into the
         * challenge envelope and round-tripped through the JS,
         * arriving at /embedded-verify before the issuance-side
         * predicate sees it). Sharing bs_should_carry_prior_rep
         * keeps the two predicates from drifting. */
        have_prior_rep = bs_should_carry_prior_rep(cookie_verify_reason,
                                                    &prior_ch);
        if (!cookie_verify_reason) {
            cookie_fully_ok = 1;
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
                        bs_safeguard_clear(r, sg_ip, scfg_sg->ns_id);
                    }
                }
            }
        } else {
            /* Security review LOW #2 — log the cookie name actually
             * present so a sed-renamed test can grep for the right
             * literal. The dual-name helper hides which variant was
             * found; rediscover here for the log line only. */
            const char *which = bs_get_cookie_value(r, BS_COOKIE_NAME_HOST)
                                ? BS_COOKIE_NAME_HOST : BS_COOKIE_NAME;
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_botshield: %s rejected: %s",
                          which, cookie_verify_reason);
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
    if (have_client_ip) {
        bs_flagged_ip_lookup(client_ip, &ip_flags, scfg_h->ns_id);
    }
    /* E14 (rework) — score adjustments for IP-side flags now flow
     * through bs_apply_flag_triggers below (which also covers
     * cookie-side flags via the union, and emits per-flag
     * `flag-trigger:<name>` reasons). Keep a coarse 0-weight
     * "flagged-ip" reason here so operators (and tests) reading
     * decision logs still see at a glance "this IP is in the
     * flagged-IP table" without parsing every trigger name. */
    if (ip_flags != 0) {
        bs_score_add(r, 0, 0, "flagged-ip");
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

    /* E14 (rework) — flag-trigger walker. Walks scfg->flag_triggers
     * over the union of IP-side and cookie-side flag bits, applying
     * `score add=N` actions via bs_score_add (which SUMs into the
     * per-request score) and accumulating MAX into a tier_floor that
     * we apply after bs_decide_tier. Built-in defaults are seeded at
     * post_config; operators tune via BotShieldFlagTrigger. */
    apr_uint32_t all_flags = ip_flags
        | (have_prior_rep ? prior_ch.rep.flags : 0);
    bs_tier tier_floor_from_flags = BS_TIER_PASS;
    bs_apply_flag_triggers(r, scfg_h, all_flags, &tier_floor_from_flags);

    /* Fetch the score struct *after* all per-request adds. Using create=1
     * so a request with zero hits still gets a valid (empty) pointer and
     * the log line prints reasons=[] consistently. */
    bs_request_score *score = bs_get_score(r, 1);
    int heuristic_total = score->total;

    /* effective_score = per-request heuristic total (already inclusive
     * of any flag-trigger SCORE actions applied above) + the cookie's
     * accumulated rep score. Operator-facing tuning workflow lives
     * in the README "Understanding scoring" section. */
    int cookie_score = have_prior_rep ? prior_ch.rep.score : 0;
    int effective    = heuristic_total + cookie_score;
    bs_tier score_tier = bs_decide_tier(cfg, effective);

    /* Apply the tier floor accumulated by the flag-trigger walker
     * (MAX of any TIER_FLOOR actions across the union of flags).
     * The score-derived tier wins when it's already at-or-above the
     * floor — we never silently downgrade. */
    bs_tier tier = (tier_floor_from_flags > score_tier)
                 ? tier_floor_from_flags : score_tier;
    if (tier_floor_from_flags > score_tier) {
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "flag-tier-floor:%s",
                         bs_tier_name(tier_floor_from_flags)));
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
                      "(heuristic=%d cookie_score=%d "
                      "ip_flags=0x%x cookie_flags=0x%x) cookie_ok=%d",
                      r->uri, effective, heuristic_total, cookie_score,
                      (unsigned)ip_flags,
                      have_prior_rep ? (unsigned)prior_ch.rep.flags : 0,
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
        if (scfg_sg && have_client_ip) {
            apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
            /* Active-state behavior is gated on safeguard_enabled —
             * an operator who hasn't opted into safeguard doesn't
             * want pass-through-after-N. */
            if (scfg_sg->safeguard_enabled == 1 &&
                bs_safeguard_check(client_ip, now_t, scfg_sg->ns_id)) {
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
            /* Record the presentation regardless of safeguard_enabled.
             * E17's embedded → M7 fallback reads the same count to
             * decide when to bypass the embedded short-circuit. The
             * write itself is cheap (one mutex + a few SHM stores);
             * the only side-effect when safeguard is "off" is that
             * embedded mode gets the count it needs. */
            int sg_threshold = bs_safeguard_effective_int(
                scfg_sg->safeguard_threshold,
                BS_DEFAULT_SAFEGUARD_THRESHOLD);
            int sg_window = bs_safeguard_effective_int(
                scfg_sg->safeguard_window,
                BS_DEFAULT_SAFEGUARD_WINDOW);
            int sg_ttl = bs_safeguard_effective_int(
                scfg_sg->safeguard_ttl,
                BS_DEFAULT_SAFEGUARD_TTL);
            bs_safeguard_record_presentation(r, client_ip,
                                             sg_threshold, sg_window,
                                             sg_ttl,
                                             now_t,
                                             scfg_sg->ns_id);
        }
    }

    /* E17 — silent-tier dispatch with embedded mode. Default behavior:
     * skip the M7 interstitial, serve the real page (DECLINED), let
     * the wrapper handle verification in the background. Timing model:
     * "kicks in eventually" — see PLAN E17.
     *
     * E17 fallback: if this client has had N consecutive silent-tier
     * dispatches without _bs_verified arriving (count tracked via
     * bs_safeguard_present_count), the wrapper isn't doing its job
     * (CSP-blocked, no JS, no Worker support, etc.). Bypass the
     * embedded short-circuit so the M7 form-PoW path runs. M7's own
     * safeguard threshold catches the case where M7 also fails. */
    if (tier == BS_TIER_SILENT &&
        cfg->silent_mode == BS_SILENT_MODE_EMBEDDED) {
        int fall_back = 0;
        if (have_client_ip) {
            apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
            apr_uint32_t cnt = bs_safeguard_present_count(client_ip,
                                                          now_t,
                                                          scfg_h->ns_id);
            if (cnt >= BS_DEFAULT_EMBEDDED_FALLBACK_THRESHOLD) {
                fall_back = 1;
            }
        }
        if (!fall_back) {
            bs_decision_log(r, "silent", "declined", cookie_status,
                            "-", "-",
                            bs_decision_reason_names(r->pool, score),
                            effective);
            return DECLINED;
        }
        /* Fall through to M7 — the embedded path has had its
         * chances. Surface the decision in the reason chain so
         * operators can spot clients stuck in this state. */
        bs_score_add(r, 0, 0, "embedded-fallback-m7");
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
        /* E14 (rework) — bs_flag_penalty floor retired. Flag effects
         * are re-applied at request time via bs_apply_flag_triggers,
         * so a forgiven-to-zero score on a flagged cookie is simply
         * re-raised on the next request when the trigger fires. */
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < 0) new_score = 0;
        next_rep.score = new_score;
        if (prior_ch.auto_tier) {
            next_rep.passes_silent = 1;  /* LOW #7 clamp */
        } else {
            next_rep.passes_form = 1;  /* LOW #7 clamp */
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
    /* E14 (rework) — difficulty bumps are no longer derived from
     * flags. The reworked design promoted tier (silent / form /
     * captcha) to the primary lever via BotShieldFlagTrigger
     * action=tier_floor; difficulty stays at the operator-configured
     * BotShieldDifficulty. If a real future need for "harder PoW for
     * this signal" surfaces, add a difficulty action verb at that
     * time; do not pre-emptively reintroduce one. */

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
    const char *challenge_js = bs_challenge_json(r, r->pool, cfg, &challenge);
    if (!challenge_js) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: GCM cookie-prefix encryption failed; "
            "cannot render interstitial");
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        bs_decision_log(r, bs_tier_name(tier), "misconfigured",
                        cookie_status, "-", "-", "issue_failed", effective);
        return OK;
    }

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

/* --- E18 — inline form captcha ----------------------------------
 *
 * Operator opts a scope into form-captcha validation via
 * `BotShieldFormCaptcha on`. On POST to that scope, BotShield's
 * fixup hook reads the request body (url-encoded only in v1),
 * extracts the configured provider's response field, calls
 * siteverify, and either:
 *   - mints _bs_verified, installs an input replay filter so the
 *     downstream app handler still sees the original body, returns
 *     DECLINED → app's handler runs normally
 *   - returns 403 → app's handler never sees the bad request
 *
 * The replay-filter pattern handles "BotShield consumed the body
 * for inspection but the app handler still needs to read it." We
 * buffer the body in r->pool and emit it as a synthetic input
 * brigade when downstream asks. Apache's ap_add_input_filter puts
 * the filter at the top of r->input_filters, so the very first
 * read by the app handler hits our buffered copy and never touches
 * the drained protocol filters below.
 */

#define BS_FORM_CAPTCHA_BODY_MAX  (256 * 1024)   /* 256 KB body cap */

typedef struct {
    const char *body;
    apr_size_t  len;
    apr_size_t  offset;   /* bytes already emitted to downstream */
} bs_form_replay_ctx;

static ap_filter_rec_t *bs_form_replay_filter_handle = NULL;

static apr_status_t bs_form_replay_filter(ap_filter_t *f,
                                          apr_bucket_brigade *bb,
                                          ap_input_mode_t mode,
                                          apr_read_type_e block,
                                          apr_off_t readbytes)
{
    bs_form_replay_ctx *ctx = f->ctx;
    if (!ctx) {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    if (mode == AP_MODE_INIT) return APR_SUCCESS;

    /* E18 review fix — honor readbytes. Emitting the whole body in a
     * single bucket regardless of what the downstream handler asked
     * for is an API-conformance violation (a strictly-conformant
     * caller is allowed to discard excess past readbytes). Stream it
     * one chunk at a time, capped at readbytes when the caller is in
     * READBYTES mode. The body buffer is allocated in r->pool and
     * outlives any bucket the framework derives from it, so
     * apr_bucket_immortal_create is safe and avoids the deferred
     * pool-bucket copy on pool cleanup. */
    if (ctx->offset < ctx->len) {
        apr_size_t remain = ctx->len - ctx->offset;
        apr_size_t emit = remain;
        if (mode == AP_MODE_READBYTES && readbytes > 0 &&
            (apr_off_t)remain > readbytes) {
            emit = (apr_size_t)readbytes;
        } else if (mode == AP_MODE_GETLINE) {
            /* Honor line-mode reads. Some legacy CGI / custom
             * downstream handlers pull request bodies one line at
             * a time; emitting the whole remainder in one bucket
             * lets the caller discard everything past the first
             * newline (since they only consume one line). Emit up
             * to and including the first '\n' if present; if not,
             * fall through and emit the whole remainder (caller
             * keeps reading until EOS). */
            const char *start = ctx->body + ctx->offset;
            const void *nl = memchr(start, '\n', remain);
            if (nl) {
                emit = (apr_size_t)((const char *)nl - start) + 1;
            }
        }
        apr_bucket *b = apr_bucket_immortal_create(
            ctx->body + ctx->offset, emit, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        ctx->offset += emit;
        if (ctx->offset == ctx->len) {
            APR_BRIGADE_INSERT_TAIL(bb,
                apr_bucket_eos_create(f->c->bucket_alloc));
            ap_remove_input_filter(f);
        }
        return APR_SUCCESS;
    }

    /* Body fully drained but caller is reading again. Emit EOS and
     * self-remove. */
    APR_BRIGADE_INSERT_TAIL(bb,
        apr_bucket_eos_create(f->c->bucket_alloc));
    ap_remove_input_filter(f);
    return APR_SUCCESS;
}

/* Read the whole request body via the input filter chain into a
 * pool-allocated buffer. After this, the upstream filters are
 * drained — caller is expected to install bs_form_replay_filter to
 * satisfy downstream readers. Returns APR_SUCCESS + sets *out_body
 * + *out_len; APR_ENOSPC if body exceeds BS_FORM_CAPTCHA_BODY_MAX;
 * other apr_status_t on transport errors. */
static apr_status_t bs_form_captcha_read_body(request_rec *r,
                                              const char **out_body,
                                              apr_size_t *out_len)
{
    apr_bucket_brigade *bb = apr_brigade_create(r->pool,
        r->connection->bucket_alloc);
    /* E18 review fix — allocate one extra byte so a body of exactly
     * BS_FORM_CAPTCHA_BODY_MAX bytes (the read-loop guard is `>`,
     * not `>=`, so this size is accepted) can be NUL-terminated
     * without overwriting the last valid body byte. */
    char *buf = apr_palloc(r->pool, BS_FORM_CAPTCHA_BODY_MAX + 1);
    apr_size_t total = 0;
    int saw_eos = 0;
    apr_status_t rv = APR_SUCCESS;

    while (!saw_eos) {
        rv = ap_get_brigade(r->input_filters, bb,
                            AP_MODE_READBYTES, APR_BLOCK_READ,
                            HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            apr_brigade_destroy(bb);
            return rv;
        }
        apr_bucket *e;
        while ((e = APR_BRIGADE_FIRST(bb)) != APR_BRIGADE_SENTINEL(bb)) {
            if (APR_BUCKET_IS_EOS(e)) { saw_eos = 1; break; }
            const char *data;
            apr_size_t len;
            apr_status_t br = apr_bucket_read(e, &data, &len,
                                              APR_BLOCK_READ);
            if (br != APR_SUCCESS) {
                apr_brigade_destroy(bb);
                return br;
            }
            /* Security review MEDIUM — overflow-safe shape. The
             * naive `total + len > MAX` form can wrap on a maliciously
             * large `len` even though both operands are size_t, since
             * BS_FORM_CAPTCHA_BODY_MAX is well below SIZE_MAX. Rewrite
             * as `len > MAX - total` so the subtraction stays in range
             * and we never compute the overflowing sum at all. */
            if (len > BS_FORM_CAPTCHA_BODY_MAX - total) {
                apr_brigade_destroy(bb);
                return APR_ENOSPC;
            }
            memcpy(buf + total, data, len);
            total += len;
            apr_bucket_delete(e);
        }
        apr_brigade_cleanup(bb);
    }
    apr_brigade_destroy(bb);
    buf[total] = '\0';
    *out_body = buf;
    *out_len  = total;
    return APR_SUCCESS;
}

/* E18 fixup hook. Runs before content handlers. For POST to scopes
 * with BotShieldFormCaptcha on, validates the captcha and decides
 * whether to let the downstream handler see the request. */
static int bs_form_captcha_fixup(request_rec *r)
{
    if (r->method_number != M_POST) return DECLINED;
    if (!ap_is_initial_req(r)) return DECLINED;

    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    if (!cfg || cfg->form_captcha != 1) return DECLINED;

    if (!cfg->captcha_provider || !cfg->captcha_provider->implemented ||
        !cfg->captcha_secret || !cfg->captcha_site_key) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: BotShieldFormCaptcha on but scope is "
            "missing BotShieldCaptchaProvider/SiteKey/SecretFile; "
            "rejecting POST as misconfigured");
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Body content-type dispatch. Supports url-encoded and JSON.
     * multipart/form-data is deliberately out of scope — file
     * uploads need streaming-parser machinery this module isn't
     * the right home for. Anything else gets 415 with diagnostic
     * so operators notice the gap rather than silently allow
     * unverified submits. */
    /* Security review MEDIUM — Content-Type prefix match must check
     * the next byte is a recognized separator (`;` for parameters,
     * whitespace, or end-of-string). Without it,
     * `application/x-www-form-urlencoded-evil` and
     * `application/json-something` would match the prefix and slip
     * through with the wrong handler choice. */
    const char *ct = apr_table_get(r->headers_in, "Content-Type");
    #define BS_CT_TERMINATOR(c) ((c) == '\0' || (c) == ';' || \
                                  (c) == ' '  || (c) == '\t')
    int ct_form = (ct &&
        strncasecmp(ct, "application/x-www-form-urlencoded", 33) == 0 &&
        BS_CT_TERMINATOR(ct[33]));
    int ct_json = (ct &&
        strncasecmp(ct, "application/json", 16) == 0 &&
        BS_CT_TERMINATOR(ct[16]));
    #undef BS_CT_TERMINATOR
    if (!ct_form && !ct_json) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: BotShieldFormCaptcha supports "
            "application/x-www-form-urlencoded or application/json; "
            "got Content-Type=%s",
            ct ? ct : "(missing)");
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    /* Read the body. */
    const char *body = NULL;
    apr_size_t  body_len = 0;
    apr_status_t rv = bs_form_captcha_read_body(r, &body, &body_len);
    if (rv == APR_ENOSPC) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha body exceeds %d bytes",
            BS_FORM_CAPTCHA_BODY_MAX);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: form-captcha body read failed");
        return HTTP_BAD_REQUEST;
    }

    /* Security review HIGH #1 — NUL-byte parser-confusion smuggling.
     * Body is read as raw bytes (memcpy + length), but downstream
     * validators treat it as a C string: bs_form_get uses strchr,
     * json_tokener_parse_verbose stops at the first '\0'. The full
     * byte buffer (including post-NUL bytes) is then replayed to
     * the app handler via the replay filter. An attacker can hide
     * a separate request shape past a NUL — BotShield validates
     * the prefix, the app handler sees the full body. Reject any
     * body containing an embedded NUL with 400 before validation. */
    if (memchr(body, '\0', body_len) != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: form-captcha body contains embedded NUL "
            "byte (rejected to prevent parser-confusion smuggling)");
        return HTTP_BAD_REQUEST;
    }

    /* E12 — shadow / observe mode for E18. If global BotShieldShadowMode
     * is on, skip siteverify + cookie-mint, log a :observe reason, and
     * pass the request through. The body is still read (we already did
     * it — needed for the replay filter so the app handler sees its
     * original POST). Transport-level errors (415/413/400/503) above
     * this point intentionally still fire even under shadow mode —
     * those represent misconfiguration or genuinely-malformed requests,
     * not policy decisions an operator is staging. */
    {
        bs_server_cfg *scfg_sh = ap_get_module_config(
            r->server->module_config, &botshield_module);
        if (scfg_sh && scfg_sh->shadow_mode == 1) {
            bs_form_replay_ctx *ctx = apr_pcalloc(r->pool, sizeof(*ctx));
            ctx->body   = body;
            ctx->len    = body_len;
            ctx->offset = 0;
            ap_add_input_filter_handle(bs_form_replay_filter_handle,
                                       ctx, r, r->connection);
            /* The body has been consumed through ap_http_filter, which
             * silently de-chunks Transfer-Encoding: chunked into raw
             * bytes. r->headers_in still says "Transfer-Encoding:
             * chunked" though, so a downstream mod_proxy / mod_cgi
             * would try to re-chunk a body that no longer has
             * chunks — protocol error or dropped body. Strip the TE
             * header and set an explicit Content-Length so the
             * downstream sees a clean Content-Length-framed request. */
            apr_table_unset(r->headers_in, "Transfer-Encoding");
            apr_table_setn(r->headers_in, "Content-Length",
                apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, body_len));
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: form-captcha:observe (shadow mode; "
                "body replayed, no siteverify, no cookie mint)");
            return DECLINED;
        }
    }

    /* Extract the captcha-response field by provider-known name.
     * URL-encoded → bs_form_get (existing M8 helper).
     * JSON → json-c parse, look up the same key at top level. */
    const char *token = NULL;
    if (ct_form) {
        token = bs_form_get(r->pool, body,
                            cfg->captcha_provider->token_field);
    } else { /* ct_json */
        enum json_tokener_error jerr = json_tokener_success;
        json_object *root = json_tokener_parse_verbose(body, &jerr);
        if (!root || jerr != json_tokener_success) {
            if (root) json_object_put(root);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: form-captcha: JSON parse failed");
            return HTTP_BAD_REQUEST;
        }
        json_object *tok_v = NULL;
        if (json_object_object_get_ex(root,
                cfg->captcha_provider->token_field, &tok_v) &&
            tok_v && json_object_is_type(tok_v, json_type_string)) {
            const char *s = json_object_get_string(tok_v);
            if (s) token = apr_pstrdup(r->pool, s);
        }
        json_object_put(root);
    }
    if (!token || !*token) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha: missing token field '%s'",
            cfg->captcha_provider->token_field);
        return HTTP_FORBIDDEN;
    }

    /* siteverify via the existing M8 client. */
    int timeout_ms = cfg->captcha_timeout_ms > 0
        ? cfg->captcha_timeout_ms : BS_DEFAULT_CAPTCHA_TIMEOUT;
    const char *details = NULL;
    long http_code = 0;
    double score = -1.0;
    const char *resp_hostname = NULL, *resp_action = NULL;
    bs_captcha_result res = bs_captcha_siteverify(r,
        cfg->captcha_provider, cfg->captcha_secret,
        cfg->captcha_secret_len, token, timeout_ms,
        cfg->captcha_ca_bundle,
        &details, &http_code, &score, &resp_hostname, &resp_action);

    if (res != BS_CAPTCHA_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha siteverify rejected "
            "(http=%ld details=\"%s\")", http_code,
            details ? details : "");
        return HTTP_FORBIDDEN;
    }

    /* Hostname binding (security-review #1 parity with M8 path).
     * Action binding deliberately skipped here — the form's action
     * value is operator-defined and varies per form; enforcing a
     * single expected_action cross-form would be wrong. Operators
     * who want strict action checks can configure
     * BotShieldCaptchaExpectedAction explicitly. */
    const char *expected_host =
        cfg->captcha_expected_hostname
            ? cfg->captcha_expected_hostname
            : (r->server && r->server->server_hostname
                   ? r->server->server_hostname : "");
    if (resp_hostname && *expected_host &&
        strcmp(resp_hostname, expected_host) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha hostname-mismatch "
            "(got=%s expected=%s)", resp_hostname, expected_host);
        return HTTP_FORBIDDEN;
    }
    if (cfg->captcha_expected_action && *cfg->captcha_expected_action &&
        resp_action &&
        strcmp(resp_action, cfg->captcha_expected_action) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha action-mismatch "
            "(got=%s expected=%s)",
            resp_action, cfg->captcha_expected_action);
        return HTTP_FORBIDDEN;
    }
    if (strcmp(cfg->captcha_provider->name, "recaptcha-v3") == 0) {
        double min_score = (cfg->recaptcha_v3_min_score >= 0.0)
            ? cfg->recaptcha_v3_min_score
            : BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE;
        if (score >= 0.0 && score < min_score) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: form-captcha v3 score below "
                "threshold (%.2f < %.2f)", score, min_score);
            return HTTP_FORBIDDEN;
        }
    }

    /* Mint _bs_verified — same captcha-<provider> alg the M8
     * interstitial path uses. passes_captcha=1 (this WAS a captcha-
     * tier solve, just inline rather than interstitial). */
    int ttl        = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);
    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);
    const char *cookie_alg_name = apr_psprintf(r->pool, "captcha-%s",
                                               cfg->captcha_provider->name);
    const bs_pow_algorithm *captcha_alg = bs_find_algorithm(cookie_alg_name);
    if (!captcha_alg || !captcha_alg->implemented) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: form-captcha cookie alg '%s' missing "
            "from registry", cookie_alg_name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* E15 review fix — carry forward prior cookie state if present,
     * mirroring M8's captcha-verify path. Without this, an existing
     * client whose cookie has forgive_consumed close to the cap
     * could "wash" their budget by submitting a form-captcha — the
     * fresh memset zeroed the rolling-window state and gave them a
     * full new budget. Eligibility and rep-math live in
     * bs_carry_forward_eligible / bs_apply_rep_carry. */
    bs_rep_state next_rep;
    memset(&next_rep, 0, sizeof(next_rep));
    {
        bs_challenge prior_ch = { 0 };
        if (bs_carry_forward_eligible(r, cfg, &prior_ch)) {
            next_rep = prior_ch.rep;
            bs_apply_rep_carry(r, cfg, &prior_ch, &next_rep,
                               bs_effective_int(cfg->forgive_captcha,
                                                BS_DEFAULT_FORGIVE_CAPTCHA));
        }
        next_rep.passes_captcha = 1;  /* LOW #7 clamp */
    }

    bs_challenge ch;
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          /* auto_tier */ 0,
                                          captcha_alg, &next_rep, &ch);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: form-captcha cookie issue failed: %s", ierr);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* Best-effort install: if the cookie mint fails (GCM encrypt
     * error — vanishingly unlikely with a valid key) we still let
     * the replay filter run. The user just won't get a cookie this
     * time and will re-challenge on the next request. The other
     * three issuance paths 500 on the same condition — preserved
     * here as-is to keep this refactor behavior-neutral. */
    (void)bs_install_verified_cookie(r, cfg, &ch, "captcha");

    /* Install the replay filter so the downstream handler sees the
     * original POST body. Filter buffers in r->pool memory; lifetime
     * is the request, plenty for any handler that wants it. */
    bs_form_replay_ctx *ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    ctx->body   = body;
    ctx->len    = body_len;
    ctx->offset = 0;
    ap_add_input_filter_handle(bs_form_replay_filter_handle,
                               ctx, r, r->connection);
    /* See shadow-mode branch above for the rationale: ap_http_filter
     * de-chunked the body for us, so r->headers_in's
     * Transfer-Encoding: chunked is now a lie. Strip it and set
     * Content-Length to body_len so downstream mod_proxy / mod_cgi
     * / PHP-FPM see a coherent framed request. */
    apr_table_unset(r->headers_in, "Transfer-Encoding");
    apr_table_setn(r->headers_in, "Content-Length",
        apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, body_len));

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
        "mod_botshield: form-captcha verified (provider=%s, "
        "body_len=%" APR_SIZE_T_FMT ")",
        cfg->captcha_provider->name, body_len);
    /* DECLINED so the app's regular handler runs. */
    return DECLINED;
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
    /* E18 — inline form captcha. Fixup runs before content handlers
     * but after auth/header processing, so the request body is still
     * readable from the input filter chain. The hook reads + validates
     * + decides whether to let the downstream handler proceed. */
    ap_hook_fixups      (bs_form_captcha_fixup,
                         NULL, NULL, APR_HOOK_MIDDLE);
    bs_form_replay_filter_handle = ap_register_input_filter(
        "BS_FORM_REPLAY", bs_form_replay_filter, NULL,
        AP_FTYPE_RESOURCE);
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
/* The .so is compiled with -fvisibility=hidden so internal cross-file
 * symbols (bs_flagged_ip_lookup, bs_state_save, etc.) don't leak into
 * the dynamic-linker symbol table. Apache's LoadModule resolves the
 * module entry via dlsym, though, so this one symbol must stay
 * exported with default visibility. */
#pragma GCC visibility push(default)
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
#pragma GCC visibility pop
#endif
