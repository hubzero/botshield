/* config.c — module-config lifecycle hooks.
 *
 * Owns the four standard Apache module-config hooks (create/merge
 * for both dir and server scope) plus post_config and child_init.
 * The directive setters that parse individual BotShield* directives
 * live in their feature files (load.c, captcha.c, triggers.c, etc.)
 * or in botshield.c — this file is strictly the module-lifecycle
 * surface.
 *
 * post_config is the heaviest function in the module: it sizes and
 * creates the SHM segment, registers the load / headroom / state-
 * save watchdogs, runs libcurl_global_init, seeds the default flag-
 * trigger rule set into every server scope, and validates cross-
 * vhost invariants. It runs in the parent process pre-fork, so
 * single-threaded init (curl_global_init, OpenSSL state) is safe
 * here. */
#include <string.h>
#include <stdlib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <ap_config.h>
#include <ap_mpm.h>
#include <scoreboard.h>
#include <mod_watchdog.h>
#include <unixd.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_atomic.h>
#include <apr_global_mutex.h>
#include <apr_shm.h>

#include <curl/curl.h>
#include <openssl/rand.h>

#include "botshield.h"
#include "config.h"
#include "allowlist.h"
#include "load.h"
#include "metrics.h"
#include "robots.h"
#include "shm.h"

/* --- Config lifecycle --- */

void *bs_create_dir_cfg(apr_pool_t *p, char *path)
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

void *bs_merge_server_cfg(apr_pool_t *p, void *base_v, void *add_v)
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

void *bs_create_server_cfg(apr_pool_t *p, server_rec *s)
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

void *bs_merge_dir_cfg(apr_pool_t *p, void *base_v, void *add_v)
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


int bs_post_config(apr_pool_t *pconf, apr_pool_t *plog,
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
            int refresh = (main_scfg->load_refresh_sec > 0)
                ? main_scfg->load_refresh_sec
                : BS_DEFAULT_LOAD_REFRESH_SEC;
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

void bs_child_init(apr_pool_t *p, server_rec *s)
{
    if (!bs_shm.mutex) return;
    apr_status_t rv = apr_global_mutex_child_init(&bs_shm.mutex,
                                                  bs_shm.mutex_filename, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: global_mutex_child_init failed");
    }
}
