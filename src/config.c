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
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include <apr_file_io.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>   /* ap_exists_config_define */
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

#include "policy.h"   /* bs_policy_dump */
#include "botshield.h"
#include "config.h"
#include "allowlist.h"
#include "bot_directory.h"
#include "bot_rate.h"
#include "browser_classifier.h"
#include "challenge.h"
#include "heuristics.h"
#include "load.h"
#include "metrics.h"
#include "robots.h"
#include "shm.h"

/* --- Config lifecycle --- */

void *bs_create_dir_cfg(apr_pool_t *p, char *path)
{
    (void)path;
    bs_dir_cfg *cfg = apr_pcalloc(p, sizeof(*cfg));
    cfg->enabled           = BS_UNSET;
    cfg->challenge_enabled = BS_UNSET;
    cfg->accesslog_suppress = BS_UNSET;
    cfg->debug      = BS_UNSET;
    cfg->cookie_ttl = BS_UNSET;
    cfg->difficulty = BS_UNSET;
    cfg->interactive_min_ms = BS_UNSET;
    cfg->interactive_arm_ms = BS_UNSET;
    cfg->help_mode  = BS_UNSET;
    cfg->show_logo  = BS_UNSET;
    cfg->show_label = BS_UNSET;
    cfg->show_box   = BS_UNSET;
    cfg->algorithm  = NULL;
    cfg->secret     = NULL;
    cfg->secret_len = 0;
    cfg->secret_secondary     = NULL;
    cfg->secret_secondary_len = 0;
    cfg->score_non_interactive  = BS_UNSET;
    cfg->score_interactive    = BS_UNSET;
    cfg->score_captcha = BS_UNSET;
    cfg->non_interactive_mode   = BS_NON_INTERACTIVE_MODE_UNSET;
    cfg->form_captcha  = BS_UNSET;
    cfg->forgive_non_interactive  = BS_UNSET;
    cfg->forgive_interactive    = BS_UNSET;
    cfg->forgive_captcha = BS_UNSET;
    cfg->cookie_domain   = NULL;
    cfg->scope_triggers       = NULL;
    cfg->scope_triggers_reset = 0;
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
     * Every entry type stored here (bs_rate_limit_entry,
     * bs_request_trigger_entry, etc.) shares a const char *name as its
     * first field, so we can key the dedup by the leading pointer
     * word without branching per-type. */
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
    out->safeguard_redirect_url = add->safeguard_redirect_url
                                ? add->safeguard_redirect_url
                                : base->safeguard_redirect_url;
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
    out->request_triggers = bs_merge_rule_array(p, base->request_triggers,
                                             add->request_triggers);
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
    out->heuristic_triggers = bs_merge_rule_array(p,
                                                  base->heuristic_triggers,
                                                  add->heuristic_triggers);
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
    if (add->robots_mode == BS_ROBOTS_MODE_UNSET) {
        out->robots_mode = base->robots_mode;
    }
    /* Bot-directory runtime override inherits unless explicitly set. */
    if (!add->bot_directory_path && base->bot_directory_path) {
        out->bot_directory_path = base->bot_directory_path;
    }
    if (add->bot_directory_refresh_interval == 0) {
        out->bot_directory_refresh_interval = base->bot_directory_refresh_interval;
    }
    /* Browser-templates runtime override — same inheritance shape. */
    if (!add->browser_templates_path && base->browser_templates_path) {
        out->browser_templates_path = base->browser_templates_path;
    }
    if (add->browser_templates_refresh_interval == 0) {
        out->browser_templates_refresh_interval =
            base->browser_templates_refresh_interval;
    }

    /* App integration server-scope inheritance. */
    if (add->app_feedback_enabled == BS_APP_FEEDBACK_UNSET) {
        out->app_feedback_enabled = base->app_feedback_enabled;
    }
    if (!add->app_feedback_header && base->app_feedback_header) {
        out->app_feedback_header = base->app_feedback_header;
    }
    /* Inherit the decision-log path, but never the open fd: each vhost
     * that resolves to a path gets its own descriptor at post_config,
     * so two vhosts sharing a path still each hold an O_APPEND fd
     * rather than aliasing one struct. */
    if (!add->decision_log_path && base->decision_log_path) {
        out->decision_log_path = base->decision_log_path;
        out->decision_log_outcomes = base->decision_log_outcomes;
    }
    /* Sticky: enabling anywhere in the tree makes the vhost endpoint-
     * serving, so a vhost inherits a server-level enable. */
    out->any_enabled = base->any_enabled | add->any_enabled;
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
    scfg->vhost_idx         = -1;   /* until post_config assigns */
    scfg->flagged_capacity  = BS_DEFAULT_FLAGGED_SLOTS;
    scfg->ipv6_prefix_bits  = 64;   /* /64 aggregation by default */
    scfg->bloom_ips             = BS_DEFAULT_BLOOM_IPS;
    scfg->bloom_window_secs     = BS_DEFAULT_BLOOM_WINDOW;
    scfg->state_file            = NULL;
    scfg->state_save_interval   = 300;   /* 5 min default when state file set */
    scfg->captcha_max_inflight  = BS_DEFAULT_CAPTCHA_MAX_INFLIGHT;
    /* E1 Allow-family defaults. bot_classifier / bot_ranges are
     * built at post_config from the bundled bs_builtin_bots[] (set
     * via vendor/verified-bots.json) plus any operator-declared
     * BotShieldAllowBot entries. allow_bots collects directive-
     * declared entries keyed by name. */
    scfg->classify         = BS_CLASSIFY_FLAGS_ALL;
    scfg->bot_classifier   = NULL;
    scfg->bot_ranges       = NULL;
    scfg->bot_ranges_manifest = NULL;
    scfg->allow_ranges_refresh_interval = 0;   /* opt-in via directive */
    scfg->allow_bots       = apr_hash_make(p);
    /* E2.1 — rate-limit ordered arrays; populated by directives in
     * declaration order, post_config resolves cohort ipspecs and
     * assigns SHM slots. */
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
    scfg->safeguard_redirect_url = NULL;   /* NULL = use built-in */
    scfg->nonce_capacity      = 0;   /* 0 = inherit/default */
    /* E11 — load-state defaults. NULL state file = no external
     * override path; all numeric thresholds default to 0 (request-
     * time + post_config substitute the compile-time defaults). */
    scfg->load_state_file       = NULL;
    scfg->load_refresh_sec      = 0;
    scfg->load_warm_pct         = 0;
    scfg->loadavg_warm          = 0;
    scfg->loadavg_hot           = 0;
    scfg->load_hot_pct          = 0;
    scfg->load_warm_rise        = 0;
    scfg->load_hot_rise         = 0;
    scfg->load_normal_fall      = 0;
    scfg->load_external_cached  = BS_LOAD_NORMAL;
    scfg->load_external_mtime   = 0;
    /* E13 — namespace defaults. ns_id is filled in at post_config
     * once ServerName is final; here we just zero the field and
     * leave the explicit-token slot NULL. */
    scfg->ns_id                 = 0;
    scfg->share_scope_token     = NULL;
    /* E15 — 0 means "inherit / use default". */
    scfg->forgive_cap_per_hour  = 0;
    scfg->request_triggers         = apr_array_make(p, 4, sizeof(void *));
    scfg->cookie_triggers  = apr_array_make(p, 4, sizeof(void *));
    scfg->env_triggers     = apr_array_make(p, 4, sizeof(void *));
    scfg->feedback_triggers = apr_array_make(p, 4, sizeof(void *));
    scfg->load_triggers     = apr_array_make(p, 4, sizeof(void *));
    scfg->flag_triggers     = apr_array_make(p, 8, sizeof(void *));
    scfg->heuristic_triggers = apr_array_make(p, 4, sizeof(void *));
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
    scfg->robots_mode             = BS_ROBOTS_MODE_UNSET;
    /* Bot-directory runtime override. NULL path = no override
     * (compiled-in baseline stays active). Refresh interval 0 =
     * use compile-time default at post_config. */
    scfg->bot_directory_path             = NULL;
    scfg->bot_directory_refresh_interval = 0;
    /* Browser-templates runtime override defaults. NULL path =
     * compiled-in baseline stays active. Refresh interval 0 = use
     * compile-time default at post_config. */
    scfg->browser_templates_path             = NULL;
    scfg->browser_templates_refresh_interval = 0;
    /* App integration defaults — UNSET sentinel so the server-scope
     * merge can tell "unset at this scope" from explicit off. */
    scfg->app_feedback_enabled        = BS_APP_FEEDBACK_UNSET;
    scfg->app_feedback_header         = NULL;
    scfg->app_claims_enabled          = BS_APP_FEEDBACK_UNSET;
    scfg->app_integration_secret_file = NULL;
    scfg->app_integration_secret      = NULL;
    scfg->app_integration_secret_len  = 0;
    /* Module-owned decision log — opened in post_config, not here. */
    scfg->decision_log_path           = NULL;
    scfg->decision_log_fd             = NULL;
    scfg->decision_log_outcomes       = -1;   /* all */
    scfg->any_enabled                 = 0;
    return scfg;
}

void *bs_merge_dir_cfg(apr_pool_t *p, void *base_v, void *add_v)
{
    bs_dir_cfg *base = base_v;
    bs_dir_cfg *add  = add_v;
    bs_dir_cfg *out  = apr_pcalloc(p, sizeof(*out));
    out->enabled    = (add->enabled    == BS_UNSET) ? base->enabled    : add->enabled;
    out->challenge_enabled = (add->challenge_enabled == BS_UNSET)
                           ? base->challenge_enabled : add->challenge_enabled;
    out->accesslog_suppress = (add->accesslog_suppress == BS_UNSET)
                            ? base->accesslog_suppress
                            : add->accesslog_suppress;
    out->debug      = (add->debug      == BS_UNSET) ? base->debug      : add->debug;
    out->cookie_ttl = (add->cookie_ttl == BS_UNSET) ? base->cookie_ttl : add->cookie_ttl;
    out->difficulty = (add->difficulty == BS_UNSET) ? base->difficulty : add->difficulty;
    out->interactive_min_ms = (add->interactive_min_ms == BS_UNSET)
        ? base->interactive_min_ms : add->interactive_min_ms;
    out->interactive_arm_ms = (add->interactive_arm_ms == BS_UNSET)
        ? base->interactive_arm_ms : add->interactive_arm_ms;
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
    /* derived per-purpose keys ride alongside the master.
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
    out->score_non_interactive  = (add->score_non_interactive  == BS_UNSET) ? base->score_non_interactive  : add->score_non_interactive;
    out->score_interactive    = (add->score_interactive    == BS_UNSET) ? base->score_interactive    : add->score_interactive;
    out->score_captcha = (add->score_captcha == BS_UNSET) ? base->score_captcha : add->score_captcha;
    out->non_interactive_mode   = (add->non_interactive_mode   == BS_NON_INTERACTIVE_MODE_UNSET)
                       ? base->non_interactive_mode : add->non_interactive_mode;
    out->form_captcha  = (add->form_captcha  == BS_UNSET)
                       ? base->form_captcha : add->form_captcha;
    out->forgive_non_interactive  = (add->forgive_non_interactive  == BS_UNSET) ? base->forgive_non_interactive  : add->forgive_non_interactive;
    out->forgive_interactive    = (add->forgive_interactive    == BS_UNSET) ? base->forgive_interactive    : add->forgive_interactive;
    out->forgive_captcha = (add->forgive_captcha == BS_UNSET) ? base->forgive_captcha : add->forgive_captcha;
    out->cookie_domain   = add->cookie_domain ? add->cookie_domain : base->cookie_domain;
    /* Flag-on-match is additive: a more-specific scope that adds a flag
     * is merged with any broader-scope flag, so an inner <Location> adds
     * its flag without losing the outer. */
    /* Per-scope BotShieldTrigger merge. Default: concatenate
     * parent + child. Reset flag on the child drops the inherited
     * list and uses only the child's entries. The reset flag also
     * propagates to the merged output so deeper scopes see the
     * effect (a reset at vhost level holds through every nested
     * <Location>). */
    out->scope_triggers_reset = base->scope_triggers_reset
                              | add->scope_triggers_reset;
    if (add->scope_triggers_reset) {
        out->scope_triggers = add->scope_triggers;
    } else if (!base->scope_triggers || base->scope_triggers->nelts == 0) {
        out->scope_triggers = add->scope_triggers;
    } else if (!add->scope_triggers || add->scope_triggers->nelts == 0) {
        out->scope_triggers = base->scope_triggers;
    } else {
        out->scope_triggers = apr_array_append(p, base->scope_triggers,
                                               add->scope_triggers);
    }
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
/* Default rule sets ship EMPTY.
 *
 * The tables below are kept as documentation of a sensible starter
 * slate, not as behaviour. Nothing is seeded, so BotShieldEnabled On
 * with no rules does nothing at all: the module acts only where an
 * operator wrote a rule saying so.
 *
 * This reverses the E14 decision recorded above ("flag-driven tier
 * escalation only fired if an operator wrote a BotShieldFlag directive
 * -- which Hubzero's 10 deployments never did. Now the definitive
 * signals escalate to captcha automatically"). That automatic
 * escalation is what caused the harm it was meant to prevent: the
 * scanner_probe tier_floor behind incident #1, and honeypot_hit's
 * captcha floor overriding the -985 verified-bot credit, which
 * challenged Googlebot 248 times over ten hours on 2026-09-01. A
 * tier_floor is defined as "at least this intense regardless of
 * cumulative score", and regardless of score includes regardless of
 * every credit that says this client is fine.
 *
 * The evidence that these were never wanted is in the deployments
 * themselves: qubeshub's config carried four lines whose only purpose
 * was to switch them back off. A default every real deployment has to
 * disable is not a default.
 *
 * Set to 1 to restore the historical slate. */
#define BS_SEED_DEFAULT_RULES 0

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
                              BS_FLAG_ACT_TIER_FLOOR,    0, BS_TIER_INTERACTIVE },
    /* Detection signals — accumulating */
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK,
                              BS_FLAG_ACT_SCORE,        30, BS_TIER_PASS },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK,
                              BS_FLAG_ACT_TIER_FLOOR,    0, BS_TIER_NONINTERACTIVE },
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


/* --- post_config phase helpers ---
 *
 * bs_post_config used to be one ~900-line function — startup
 * sequence inline. The phases are independent and order-explicit,
 * so each phase lives in its own static helper here and the
 * orchestrator at the bottom reads as a checklist.
 *
 * Helpers are file-local; behavior is identical to the old inline
 * sequence. None of them are reentrant. */

/* Apache calls post-config twice on cold boot (syntax-check pass,
 * then the real one). Skip the first pass so we don't create the
 * SHM segment and then immediately discard it.
 *
 * The userdata key lives on s->process->pool, which survives
 * `apachectl graceful`. On graceful, the previous boot's userdata
 * is still set, so the FIRST post_config call after graceful runs
 * init directly (correct — graceful only invokes post_config
 * once). This relies on Apache's documented post_config-runs-
 * twice-on-cold-boot, post_config-runs-once-on-graceful behavior.
 * If that ever changes (cold-boot single pass, or graceful double
 * pass), this skip would either suppress the only init opportunity
 * or skip the real one. Behavior is stable on Apache 2.4 today;
 * a more defensive pattern would key the userdata on a pconf-scoped
 * marker but Apache doesn't expose a stable one across post_config
 * invocations.
 *
 * Returns 1 if this is the first (syntax-check) pass and the caller
 * should bail out with OK; 0 otherwise. */
static int bs_post_config_first_pass_skip(server_rec *s)
{
    void *already;
    apr_pool_userdata_get(&already, "bs_post_config_done",
                          s->process->pool);
    if (!already) {
        apr_pool_userdata_set((const void *)1, "bs_post_config_done",
                              apr_pool_cleanup_null,
                              s->process->pool);
        return 1;
    }
    return 0;
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
static int bs_init_curl_global(server_rec *s)
{
    CURLcode curl_rv = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_rv != CURLE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: curl_global_init failed: %s (CURLcode=%d). "
            "Refusing to start - the captcha tier needs working libcurl.",
            curl_easy_strerror(curl_rv), (int)curl_rv);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    return OK;
}

/* App integration: warn loudly at startup if a feature is on but
 * the shared secret is missing. Per-request paths fall through
 * with their own warning + skip (see bs_app_feedback_verify_filter
 * / bs_app_claims_set_header), but a single startup notice is
 * easier for operators to spot than a stream of per-request
 * warnings. We don't refuse to start: the rest of the module
 * still works (cookie tier, captcha tier, etc.). */
static void bs_warn_app_integration_secrets(server_rec *s)
{
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
}

/* Flag-trigger registration.
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
static void bs_resolve_flag_triggers(apr_pool_t *pconf, server_rec *s)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;
        /* Aliased server configs are reachable more than once in
         * this walk; resolving twice would re-seed the defaults on
         * top of the previous result. See bs_server_cfg. */
        if (vcfg->flag_triggers_resolved) continue;
        apr_array_header_t *operator_decls = vcfg->flag_triggers;
        apr_array_header_t *combined = apr_array_make(pconf,
            BS_DEFAULT_FLAG_TRIGGER_COUNT
              + (operator_decls ? operator_decls->nelts : 0),
            sizeof(void *));
        /* Defaults first -- none, unless BS_SEED_DEFAULT_RULES. */
        for (size_t i = 0;
             BS_SEED_DEFAULT_RULES && i < BS_DEFAULT_FLAG_TRIGGER_COUNT;
             i++) {
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
        vcfg->flag_triggers_resolved = 1;
    }
}

/* Compiled-in default heuristic-trigger rule set. Same shape as
 * bs_default_flag_triggers: each entry is one (id, action) row, and
 * post_config seeds these into scfg->heuristic_triggers ahead of any
 * operator declarations. Score values match the prior hardcoded
 * BS_PENALTY_* defines so behavior is unchanged from a fresh install
 * with no BotShieldHeuristicTrigger directives.
 *
 * Operators tune via additional BotShieldHeuristicTrigger directives
 * (which append after these defaults), or wipe via `<name> reset` for
 * a single heuristic, or `all reset` for the whole slate. */
static const struct {
    bs_heuristic_id           id;
    bs_heuristic_action_kind  action;
    int                       score_add;
    bs_tier                   tier_min;
} bs_default_heuristic_triggers[] = {
    { BS_H_MISSING_UA,     BS_HEUR_ACT_SCORE,
      BS_PENALTY_MISSING_UA,     BS_TIER_PASS },
    { BS_H_MISSING_AL,     BS_HEUR_ACT_SCORE,
      BS_PENALTY_MISSING_AL,     BS_TIER_PASS },
    { BS_H_SCRAPER_UA,     BS_HEUR_ACT_SCORE,
      BS_PENALTY_SCRAPER_UA,     BS_TIER_PASS },
    /* == BS_DEFAULT_SCORE_NON_INTERACTIVE. Both post-cookie heuristics fire only
     * when the request carries no usable cookie, so together they mean
     * "no session context"; at the non-interactive threshold an enabled scope
     * challenges that by default, with no rule for the operator to
     * write. */
    { BS_H_FIRST_SIGHT_IP, BS_HEUR_ACT_SCORE,
      BS_PENALTY_FIRST_SIGHT_IP, BS_TIER_PASS },
    { BS_H_DROPPED_COOKIE, BS_HEUR_ACT_SCORE,
      BS_PENALTY_DROPPED_COOKIE, BS_TIER_PASS },
};
#define BS_DEFAULT_HEURISTIC_TRIGGER_COUNT \
    (sizeof(bs_default_heuristic_triggers) / \
     sizeof(bs_default_heuristic_triggers[0]))

/* Seed defaults, append operator decls, then walk consuming reset
 * sentinels. Mirror of bs_resolve_flag_triggers with one extra
 * sentinel kind: BS_HEUR_ACT_RESET_ALL clears every prior entry
 * (defaults included) before continuing — operator's clean-slate
 * starting point. */
static void bs_resolve_heuristic_triggers(apr_pool_t *pconf,
                                          server_rec *s)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;
        /* Aliased server configs are reachable more than once in
         * this walk; resolving twice would re-seed the defaults on
         * top of the previous result. See bs_server_cfg. */
        if (vcfg->heuristic_triggers_resolved) continue;
        apr_array_header_t *operator_decls = vcfg->heuristic_triggers;
        apr_array_header_t *combined = apr_array_make(pconf,
            BS_DEFAULT_HEURISTIC_TRIGGER_COUNT
              + (operator_decls ? operator_decls->nelts : 0),
            sizeof(void *));
        for (size_t i = 0;
             BS_SEED_DEFAULT_RULES && i < BS_DEFAULT_HEURISTIC_TRIGGER_COUNT;
             i++) {
            const typeof(bs_default_heuristic_triggers[0]) *d =
                &bs_default_heuristic_triggers[i];
            bs_heuristic_trigger_entry *e = apr_pcalloc(pconf,
                sizeof(*e));
            e->id           = d->id;
            e->action       = d->action;
            e->score_add    = d->score_add;
            e->tier_min     = d->tier_min;
            e->mode         = BS_TMODE_ENFORCE;
            e->from_default = 1;
            *(bs_heuristic_trigger_entry **)apr_array_push(combined) = e;
        }
        if (operator_decls) {
            for (int i = 0; i < operator_decls->nelts; i++) {
                bs_heuristic_trigger_entry *e = APR_ARRAY_IDX(
                    operator_decls, i, bs_heuristic_trigger_entry *);
                *(bs_heuristic_trigger_entry **)apr_array_push(combined)
                    = e;
            }
        }
        apr_array_header_t *resolved = apr_array_make(pconf,
            combined->nelts, sizeof(void *));
        for (int i = 0; i < combined->nelts; i++) {
            bs_heuristic_trigger_entry *e = APR_ARRAY_IDX(
                combined, i, bs_heuristic_trigger_entry *);
            if (e->action == BS_HEUR_ACT_RESET_ALL) {
                /* Wipe everything accumulated so far. */
                resolved->nelts = 0;
                continue;
            }
            if (e->action == BS_HEUR_ACT_RESET) {
                /* Drop earlier entries with this id. */
                int w = 0;
                for (int j = 0; j < resolved->nelts; j++) {
                    bs_heuristic_trigger_entry *k = APR_ARRAY_IDX(
                        resolved, j, bs_heuristic_trigger_entry *);
                    if (k->id != e->id) {
                        APR_ARRAY_IDX(resolved, w,
                            bs_heuristic_trigger_entry *) = k;
                        w++;
                    }
                }
                resolved->nelts = w;
                continue;
            }
            *(bs_heuristic_trigger_entry **)apr_array_push(resolved) = e;
        }
        vcfg->heuristic_triggers = resolved;
        vcfg->heuristic_triggers_resolved = 1;
    }
}

/* Normalise a server_rec into a vhost directory key.
 *
 * ServerName, lowercased. Vhosts that share a name -- the usual :80
 * and :443 pair -- deliberately collapse onto one block: an operator
 * reading the dashboard thinks in sites, not listeners, and splitting
 * geodynamics.org across two tabs by port would obscure more than it
 * reveals. A server with no ServerName falls back to a stable literal
 * so it still gets counted somewhere nameable. */
static const char *bs_vhost_key(server_rec *s)
{
    if (s && s->server_hostname && *s->server_hostname) {
        return s->server_hostname;
    }
    return "(unnamed)";
}

/* Distinct ServerNames across the main server and every vhost, capped
 * at BS_M_MAX_VHOSTS. When the cap is hit the count includes the
 * catch-all slot, so callers can size for exactly what will be used. */
/* Does this vhost run BotShield at all?
 *
 * scfg->any_enabled is set by bs_set_enabled wherever BotShieldEnabled
 * On|LogOnly appears, so it is true for a vhost that only turns the
 * module on inside a <Location> -- which the vhost-scope lookup_defaults
 * would have missed. It already exists for bs_handler's endpoint
 * routing; this reuses it rather than inventing a second answer to the
 * same question.
 *
 * The main-server fallback covers config set outside any <VirtualHost>:
 * cmd->server is the main server there, so only its scfg is flagged,
 * but every vhost inherits the per-dir config and so really does run
 * the module. */
static int bs_vhost_runs_botshield(server_rec *sv, server_rec *base)
{
    bs_server_cfg *sc = ap_get_module_config(sv->module_config,
                                             &botshield_module);
    if (sc && sc->any_enabled) return 1;
    bs_server_cfg *mc = ap_get_module_config(base->module_config,
                                             &botshield_module);
    return (mc && mc->any_enabled) ? 1 : 0;
}

static apr_uint32_t bs_vhost_count(server_rec *base)
{
    const char *seen[BS_M_MAX_VHOSTS];
    apr_uint32_t n = 0;
    for (server_rec *s = base; s; s = s->next) {
        /* Only vhosts that actually run the module. A block is 86 KB
         * -- a full copy of every counter plus the minute and hour
         * rings -- and a vhost that never evaluates a request would
         * spend all of it on zeros. This host serves ~100 namevhosts,
         * of which all but a couple are a ServerName, a certificate
         * and a RedirectMatch; before this filter they consumed 31 of
         * the 32 slots and 2.7 MB of shared memory holding nothing,
         * while the directory read 100% full. */
        if (!bs_vhost_runs_botshield(s, base)) continue;
        const char *key = bs_vhost_key(s);
        int dup = 0;
        for (apr_uint32_t i = 0; i < n; i++) {
            if (strcasecmp(seen[i], key) == 0) { dup = 1; break; }
        }
        if (dup) continue;
        if (n >= BS_M_MAX_VHOSTS) return BS_M_MAX_VHOSTS;
        seen[n++] = key;
    }
    return n ? n : 1;
}

/* Fill the SHM directory and stamp each server's block index into its
 * config, so the per-request path is a deref rather than a lookup.
 * Runs after the segment is carved and zeroed. */
static void bs_vhost_dir_init(server_rec *base, apr_uint32_t n)
{
    bs_vhost_dir *dir = bs_shm.vhost_dir;
    if (!dir) return;
    dir->count = n;
    dir->overflowed = 0;
    apr_uint32_t skipped = 0;

    for (server_rec *s = base; s; s = s->next) {
        bs_server_cfg *sc = ap_get_module_config(s->module_config,
                                                 &botshield_module);
        if (!sc) continue;
        /* Same filter as bs_vhost_count, or the two would disagree
         * about which vhost owns which index. A skipped vhost keeps
         * vhost_idx 0 and its traffic lands in the global block only,
         * which is where a redirect-only vhost belongs. */
        if (!bs_vhost_runs_botshield(s, base)) {
            sc->vhost_idx = 0;
            skipped++;
            continue;
        }
        const char *key = bs_vhost_key(s);
        int idx = -1;
        for (apr_uint32_t i = 0; i < dir->count; i++) {
            if (dir->name[i][0]
                && strcasecmp(dir->name[i], key) == 0) {
                idx = (int)i;
                break;
            }
        }
        if (idx < 0) {
            for (apr_uint32_t i = 0; i < dir->count; i++) {
                if (!dir->name[i][0]) {
                    apr_cpystrn(dir->name[i], key, BS_M_VHOST_NAME_MAX);
                    idx = (int)i;
                    break;
                }
            }
        }
        if (idx < 0) {
            /* Directory full: everything else shares the last slot,
             * relabelled so the dashboard says so instead of
             * attributing the overflow to whoever got there first. */
            idx = (int)dir->count - 1;
            dir->overflowed = 1;
            apr_cpystrn(dir->name[idx], "(other vhosts)",
                        BS_M_VHOST_NAME_MAX);
        }
        sc->vhost_idx = idx;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, base,
        "mod_botshield: per-vhost metrics: %u of %d slot(s) assigned, "
        "%u vhost(s) skipped as not running the module (%" APR_SIZE_T_FMT
        " KB each). A skipped vhost still counts toward the site-wide "
        "totals; only its separate breakdown is dropped.",
        n, BS_M_MAX_VHOSTS, skipped,
        (apr_size_t)(BS_M_VHOST_NAME_MAX + sizeof(bs_metrics)) / 1024);

    if (dir->overflowed) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, base,
            "mod_botshield: more than %d distinct ServerNames RUNNING "
            "the module; the extras share one per-vhost metrics slot "
            "labelled \"(other vhosts)\". Raise BS_M_MAX_VHOSTS and "
            "BotShieldShmSize together if the breakdown matters.",
            BS_M_MAX_VHOSTS);
    }
}

/* SHM layout, allocation, header init, mutex creation.
 *
 * Computes total size from the configured capacities (header +
 * flagged-IP table + two Bloom buffers + captcha rate / log
 * rings + metrics + per-rule rate counters + strike/safeguard/
 * nonce tables), allocates the segment via apr_shm_create,
 * sets up every bs_shm.* table pointer, randomizes the SipHash
 * key, creates the global mutex, and registers the cleanup that
 * tears down the segment on pool destruction.
 *
 * Returns OK or HTTP_INTERNAL_SERVER_ERROR. On error the global
 * bs_shm is restored to its pre-call snapshot so a botched
 * graceful-restart attempt can't leave dangling pointers. */
static int bs_init_shm_layout(apr_pool_t *pconf, apr_pool_t *ptemp,
                              server_rec *s, bs_server_cfg *scfg)
{
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
    /* Per-vhost blocks. Counted here so the segment is sized for the
     * config actually loaded rather than for BS_M_MAX_VHOSTS worth of
     * worst case. */
    apr_uint32_t vhost_n = bs_vhost_count(s);
    apr_size_t vhost_bytes = sizeof(bs_vhost_dir)
                           + (apr_size_t)vhost_n * sizeof(bs_metrics);
    /* E2.1 — fixed-size table of rate-limit counter slots. Sized to
     * fit the bot-directory (~640 known-bot slugs + verified-bots,
     * each pre-allocated one slot when BotShieldBotRateLimit is
     * configured) plus directive rate-limits + robots.txt group
     * counters + generous headroom for directory growth between
     * graceful-restarts. 2048 slots × 8 bytes = 16 KB SHM —
     * trivial cost; leaves ~1400 slots free above today's directory.
     * Mid-run directory growth via watchdog refresh (vendor/bot-
     * directory.json updates) currently does NOT allocate new rate-
     * limit slots — operators graceful-restart for major directory
     * drops. Dynamic watchdog-driven slot allocation is a future
     * enhancement; new slugs in the meantime fall through to the
     * unknown-bot / fake-bot aggregate slots (graceful degradation,
     * no request failures). */
    #define BS_E21_RATE_SLOTS 2048
    apr_size_t e21_rate_bytes = BS_E21_RATE_SLOTS * sizeof(bs_rate_counter);
    /* Cumulative companion to the fixed-window counters. Lives at the
     * very end of the segment so every offset above stays put. */
    apr_size_t e21_total_bytes = BS_E21_RATE_SLOTS * sizeof(apr_uint64_t);
    apr_size_t e21_ua_bytes    = BS_E21_RATE_SLOTS * BS_RATE_UA_MAX;
    apr_size_t gen_bytes       = sizeof(bs_gen_counters);
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
    /* Embedded-bootstrap nonce table. */
    apr_size_t nonce_slots = (scfg->nonce_capacity > 0)
                           ? (apr_size_t)scfg->nonce_capacity
                           : (apr_size_t)BS_DEFAULT_NONCE_SLOTS;
    apr_size_t nonce_bytes = nonce_slots * sizeof(bs_nonce_slot);
    apr_size_t total_bytes  = header_bytes + table_bytes + 2 * bloom_bytes
                              + cv_rate_bytes + cv_log_bytes
                              + metrics_bytes + e21_rate_bytes
                              + strike_bytes + safeguard_bytes
                              + nonce_bytes + vhost_bytes
                              + e21_total_bytes + e21_ua_bytes
                              + gen_bytes;

    bs_shm.segment_used  = total_bytes;
    bs_shm.segment_total = scfg->shm_size;

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

    /* Snapshot bs_shm before any failable
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
    /* Nonce table follows safeguard. memset(base,0) leaves every
     * expires_at == 0 (empty sentinel) — no explicit zero pass
     * needed. */
    bs_shm.nonce_table = (bs_nonce_slot *)
        ((unsigned char *)bs_shm.safeguard_table + safeguard_bytes);
    bs_shm.nonce_capacity = nonce_slots;
    /* Per-vhost metrics last, so adding them leaves every offset above
     * unchanged. Directory first, then the blocks it indexes. */
    bs_shm.vhost_dir = (bs_vhost_dir *)
        ((unsigned char *)bs_shm.nonce_table + nonce_bytes);
    bs_shm.vmetrics  = (bs_metrics *)
        ((unsigned char *)bs_shm.vhost_dir + sizeof(bs_vhost_dir));
    /* Last block in the segment, so introducing it moved nothing. */
    bs_shm.rate_totals = (apr_uint64_t *)
        ((unsigned char *)bs_shm.vhost_dir + vhost_bytes);
    bs_shm.rate_ua = (char *)
        ((unsigned char *)bs_shm.rate_totals + e21_total_bytes);
    bs_shm.gen = (bs_gen_counters *)
        ((unsigned char *)bs_shm.rate_ua + e21_ua_bytes);
    /* The segment arrives zeroed, and zero is a legitimate load value.
     * Mark every history slot empty so a freshly started server draws
     * a short line from now rather than an hour of flat 0.00 that
     * never happened. */
    if (bs_shm.metrics) {
        for (int i = 0; i < BS_M_LA_SLOTS; i++) {
            bs_shm.metrics->la_ring[i] = BS_M_LA_EMPTY;
        }
        for (int i = 0; i < BS_M_DB_SLOTS; i++) {
            bs_shm.metrics->db_ring[i] = BS_M_DB_EMPTY;
        }
        for (int i = 0; i < BS_M_AP_SLOTS; i++) {
            bs_shm.metrics->ap_ring[i] = BS_M_AP_EMPTY;
        }
        for (int i = 0; i < BS_M_FPM_SLOTS; i++) {
            bs_shm.metrics->fpm_ring[i] = BS_M_FPM_EMPTY;
        }
    }

    bs_vhost_dir_init(s, vhost_n);

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

    return OK;
}

/* State persistence: load the previous generation's snapshot if
 * the operator pointed BotShieldStateFile at one, register the
 * graceful-shutdown save, and (if mod_watchdog is loaded and an
 * interval is set) register periodic saves. A missing or malformed
 * state file is non-fatal — bs_state_load logs NOTICE and returns
 * without touching SHM. */
static void bs_init_state_persistence(apr_pool_t *pconf, server_rec *s,
                                      bs_server_cfg *scfg)
{
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
                    wrv = fn_reg(wd, ival, ctx, bs_state_save_watchdog_cb);
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
}

/* Allow-family wiring: build the UA classifier + ranges hash for
 * each server that enabled the Allow family. Walks s, s->next,
 * s->next->next, ... so a vhost-scope `BotShieldAllow on` fires.
 * Each vhost gets its own classifier + ranges hash; per-request
 * check reads from r->server's scfg so scoping matches.
 *
 * Per-bot input shape:
 *   - Built-in bots (bs_builtin_bots[]) seed the Allow set
 *     unless an operator `BotShieldAllowBot` entry overrides
 *     by name.
 *   - Third-arg semantics inspected here, not at directive
 *     parse time, because we need pconf's allocator for the
 *     resulting apr_ipsubnet_t objects:
 *       - ua_only==1 (operator said `*`): no ranges loaded;
 *         request-time match gives known-bot:<name> (score 0,
 *         no verified-bot credit since no IP check happened).
 *       - inline_cidrs set: parse via
 *         bs_allow_load_ranges_from_string.
 *       - path set: load from that file.
 *       - neither: load from the default path. */
static void bs_wire_allowlist(apr_pool_t *pconf, server_rec *s)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;

        vcfg->bot_classifier = bs_ua_classifier_create(pconf);

        /* Seed the Allow set with the bundled built-ins
         * (vendor/verified-bots.json → bs_builtin_bots[]). Operator-
         * declared entries are overlaid on top; same-name operator
         * entries replace the built-in (last-writer-wins). The
         * runtime BotShieldClassify -verified-bots flag controls
         * whether the IP cross-check runs at request time, not
         * whether the allowlist is loaded — keeping the allowlist
         * loaded means operators can flip the flag at any time
         * without a reload-with-rebuild cycle. */
        apr_hash_t *working = apr_hash_make(pconf);
        for (const bs_allow_bot_entry *b = bs_builtin_bots;
             b->name; b++) {
            apr_hash_set(working, b->name, APR_HASH_KEY_STRING, b);
        }
        apr_hash_index_t *hi;
        for (hi = apr_hash_first(pconf, vcfg->allow_bots);
             hi; hi = apr_hash_next(hi)) {
            const void *k; void *v;
            apr_hash_this(hi, &k, NULL, &v);
            apr_hash_set(working, k, APR_HASH_KEY_STRING, v);
        }

        /* Build the live-reloadable manifest. The ranges machinery
         * is split between the manifest (what to load — owned by
         * pconf, immutable across watchdog ticks) and the state
         * (loaded ranges + observed mtimes — owned by a per-
         * generation subpool, atomic-swapped on file change). */
        bs_bot_ranges_manifest *manifest =
            apr_pcalloc(pconf, sizeof(*manifest));
        manifest->s           = sv;
        manifest->pool        = pconf;
        manifest->file_bots   = apr_array_make(pconf, 4,
                                  sizeof(bs_bot_file_manifest_entry));
        manifest->inline_bots = apr_array_make(pconf, 4,
                                  sizeof(bs_bot_inline_manifest_entry));

        int n_bots = 0, ua_only = 0;
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

            if (e->inline_cidrs) {
                bs_bot_inline_manifest_entry *me =
                    apr_array_push(manifest->inline_bots);
                me->name         = apr_pstrdup(pconf, e->name);
                me->inline_cidrs = apr_pstrdup(pconf, e->inline_cidrs);
                continue;
            }

            const char *path = e->path
                ? e->path
                : apr_psprintf(pconf,
                    "/var/lib/botshield/bots/%s.txt", e->name);

            bs_bot_file_manifest_entry *me =
                apr_array_push(manifest->file_bots);
            me->name           = apr_pstrdup(pconf, e->name);
            me->canonical_path = apr_pstrdup(pconf, path);
            me->sidecar_path   = bs_allow_sidecar_path(pconf, path);
        }

        vcfg->bot_ranges_manifest = manifest;

        /* Build + publish the initial state. publish() reads the
         * vcfg->bot_ranges_manifest pointer, so the assignment above
         * must precede this. */
        bs_bot_ranges_state *initial = bs_allow_ranges_build(manifest);
        if (initial) {
            bs_allow_ranges_publish(sv, initial);
        }

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: Allow enabled; %d bots "
            "(%d file-backed, %d inline, %d ua-only)",
            n_bots, manifest->file_bots->nelts,
            manifest->inline_bots->nelts, ua_only);
    }
}

/* Resolve cohort ipspecs for every rate_limit / path_trigger entry
 * across main + vhost scopes, link rate-limit-escalate directives
 * to their target rate-limit by name, and assign SHM slot indices
 * to rate_limit entries. Shared counter pool across all vhosts;
 * slot indices are global, handed out in declaration order. If
 * operators ever exceed BS_E21_RATE_SLOTS, the overflow entries
 * stay at shm_slot=-1 and are silently skipped at request time
 * (log warning surfaces the condition).
 *
 * The robots-init phase appends to *next_slot too, so it's an
 * out-param threaded between the two helpers. */
static void bs_wire_rate_and_block_cohorts(apr_pool_t *pconf,
                                           server_rec *s,
                                           int *next_slot)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;

        /* Resolve a cohort's ipspec (path or inline CIDRs) into the
         * ranges array. Shared between rate_limits and request_triggers. */
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
                    "mod_botshield: %s '%s' ipspec load failed (%s) - "      \
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
                    if (*next_slot < (int)bs_shm.rate_counter_count) {
                        e->shm_slot = (*next_slot)++;
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

        /* Path triggers with ua=/ipspec= keys carry a populated
         * cohort; resolve its ipspec the same way rate-limit cohorts
         * are resolved. Path triggers without those keys leave
         * has_cohort=0 and are skipped here. */
        if (vcfg->request_triggers && vcfg->request_triggers->nelts > 0) {
            int wired = 0;
            for (int i = 0; i < vcfg->request_triggers->nelts; i++) {
                bs_request_trigger_entry *e = APR_ARRAY_IDX(
                    vcfg->request_triggers, i, bs_request_trigger_entry *);
                if (!e->has_cohort) continue;
                BS_E21_RESOLVE_COHORT(&e->cohort,
                    "BotShieldRequestTrigger", e->name);
                wired++;
            }
            if (wired > 0) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                    "mod_botshield: %d path-trigger cohorts wired",
                    wired);
            }
        }
        #undef BS_E21_RESOLVE_COHORT
    }
}

/* Resolve sentinel defaults for any vhost where the directive
 * wasn't given (either at the vhost or at main scope that got
 * merged down). After this every vhost's scfg has concrete values;
 * downstream code can read them as-is. */
static void bs_resolve_robots_defaults(server_rec *s)
{
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
        if (vcfg->robots_mode == BS_ROBOTS_MODE_UNSET) {
            vcfg->robots_mode = BS_ROBOTS_MODE_ENFORCE;
        }
    }
}

/* Derive the per-vhost reputation namespace ID. */
static void bs_assign_namespace_ids(server_rec *s)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg) continue;

        /* Per-vhost reputation namespace ID.
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
}

#define BS_E22_ROBOTS_SLOT_POOL 16

/* Reserve an SHM rate-counter slot pool for each vhost's
 * robots.txt, then do the initial parse and register a per-vhost
 * watchdog for live refresh. The SHM slot pool is sized once at
 * post_config (cannot grow after); refresh reuses slots by group
 * name so rate-counter state survives across refreshes.
 * BS_E22_ROBOTS_SLOT_POOL is a deliberate overshoot — most hand-
 * maintained robots.txt files have <10 Crawl-delay groups.
 *
 * next_slot is consumed (mutated) for slot allocation; the rate-
 * limit phase already advanced it past the BotShieldRateLimit
 * cohorts. */
static void bs_init_robots(apr_pool_t *pconf, server_rec *s,
                           int *next_slot)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg || !vcfg->robots_txt_path) continue;

        /* Reserve the pool from the global rate-counter table. */
        int pool_base = *next_slot;
        int pool_size = BS_E22_ROBOTS_SLOT_POOL;
        if (pool_base + pool_size > (int)bs_shm.rate_counter_count) {
            pool_size = (int)bs_shm.rate_counter_count - pool_base;
            if (pool_size < 0) pool_size = 0;
        }
        vcfg->robots_slot_pool_base = pool_base;
        vcfg->robots_slot_pool_size = pool_size;
        vcfg->robots_slot_pool_used = 0;
        *next_slot += pool_size;

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
}

/* Bot-directory runtime override loader + watchdog.
 *
 * The bot-directory active state is module-global (one
 * classification table for the whole module), but the
 * BotShieldBotDirectory directive is server-scope and operators
 * commonly place it inside a <VirtualHost> block — so we have to
 * walk the vhost list to find the configured path. First non-NULL
 * wins; cross-vhost competing paths aren't a supported shape (the
 * data file is module-global, not per-vhost). Soft dep on
 * mod_watchdog — absence falls back to post_config-only load.
 *
 * Always publishes a state at startup so the lookup hot path can
 * use the Aho-Corasick fast path even when no override is
 * configured. The baseline state wraps the compiled-in
 * bs_known_bots[] rodata table in a fresh pool with its own AC
 * trie. */
static void bs_init_bot_directory(apr_pool_t *pconf, server_rec *s)
{
    /* Find any vhost (including the main server) that set the
     * directive. */
    server_rec       *src_sv   = NULL;
    bs_server_cfg    *src_scfg = NULL;
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (vcfg && vcfg->bot_directory_path) {
            src_sv   = sv;
            src_scfg = vcfg;
            break;
        }
    }

    /* Always publish a baseline state so the AC fast path is
     * active from request 1, regardless of operator config. If a
     * runtime override is configured below, it'll replace this. */
    bs_known_bots_state *baseline = bs_known_bots_build_baseline(s, pconf);
    if (baseline) {
        bs_known_bots_publish(s, baseline);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
            "mod_botshield: bot-directory baseline AC build failed; "
            "request-time lookup will fall back to sequential "
            "strcasestr (slow but correct)");
    }

    if (!src_scfg) {
        /* No runtime override configured — baseline stays active. */
        return;
    }

    /* Initial load of runtime override — failure here is non-fatal;
     * the baseline (just published above) stays active. */
    bs_known_bots_state *initial = bs_known_bots_load(
        src_sv, src_scfg->bot_directory_path, pconf);
    if (initial) {
        bs_known_bots_publish(src_sv, initial);
    } else {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, src_sv,
            "mod_botshield: bot-directory %s not loaded at "
            "post_config; compiled-in baseline (~%" APR_SIZE_T_FMT
            " entries) stays active. Watchdog will retry on file "
            "change if a refresh interval is set.",
            src_scfg->bot_directory_path, bs_known_bots_count);
    }

    /* Default refresh interval if operator didn't override and
     * watchdog is desired. 0 = leave watchdog unregistered. */
    int refresh = src_scfg->bot_directory_refresh_interval;
    if (refresh == 0) refresh = 300;   /* default 5 min */
    if (refresh < 0) return;

    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *fn_get =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *fn_reg =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!fn_get || !fn_reg) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, src_sv,
            "mod_botshield: mod_watchdog not loaded; "
            "bot-directory live-refresh disabled "
            "(post_config load still in effect)");
        return;
    }

    /* Per-worker watchdog (singleton=0 means each child process
     * registers and runs its own tick). Required because the bot-
     * directory active pointer is process-local — a single
     * singleton tick would only update one worker's view, leaving
     * other workers serving requests against stale state. Cost is
     * low: each tick is one apr_stat + early-out on unchanged
     * mtime, and the parser only runs when the file actually
     * changed. */
    const char *wd_name = "mod_botshield_bot_directory";
    ap_watchdog_t *wd = NULL;
    apr_status_t wrv = fn_get(&wd, wd_name, 0, 0, pconf);
    if (wrv == APR_SUCCESS && wd) {
        wrv = fn_reg(wd, apr_time_from_sec(refresh), src_sv,
                     bs_bot_directory_watchdog_cb);
    } else if (wrv == APR_SUCCESS) {
        wrv = APR_EGENERAL;
    }
    if (wrv == APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, src_sv,
            "mod_botshield: bot-directory live-refresh enabled "
            "every %d s (path=%s)",
            refresh, src_scfg->bot_directory_path);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, wrv, src_sv,
            "mod_botshield: bot-directory watchdog registration "
            "failed; live-refresh disabled (post_config load still "
            "in effect)");
    }
}


/* Browser-templates runtime override loader + watchdog.
 *
 * Same shape as bs_init_bot_directory — walk vhosts to find the
 * configured path, do an initial load, register a per-worker
 * watchdog (singleton=0) so all worker processes pick up file
 * changes within one refresh interval. Soft dep on mod_watchdog. */
static void bs_init_browser_templates(apr_pool_t *pconf, server_rec *s)
{
    server_rec    *src_sv   = NULL;
    bs_server_cfg *src_scfg = NULL;
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (vcfg && vcfg->browser_templates_path) {
            src_sv   = sv;
            src_scfg = vcfg;
            break;
        }
    }
    if (!src_scfg) return;

    bs_browser_templates_state *initial = bs_browser_templates_load(
        src_sv, src_scfg->browser_templates_path, pconf);
    if (initial) {
        bs_browser_templates_publish(src_sv, initial);
    } else {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, src_sv,
            "mod_botshield: browser-templates %s not loaded at "
            "post_config; compiled-in baseline (~%" APR_SIZE_T_FMT
            " templates) stays active. Watchdog will retry on file "
            "change.",
            src_scfg->browser_templates_path,
            bs_browser_templates_count);
    }

    int refresh = src_scfg->browser_templates_refresh_interval;
    if (refresh == 0) refresh = 300;
    if (refresh < 0) return;

    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *fn_get =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *fn_reg =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!fn_get || !fn_reg) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, src_sv,
            "mod_botshield: mod_watchdog not loaded; "
            "browser-templates live-refresh disabled "
            "(post_config load still in effect)");
        return;
    }

    const char *wd_name = "mod_botshield_browser_templates";
    ap_watchdog_t *wd = NULL;
    apr_status_t wrv = fn_get(&wd, wd_name, 0, 0, pconf);
    if (wrv == APR_SUCCESS && wd) {
        wrv = fn_reg(wd, apr_time_from_sec(refresh), src_sv,
                     bs_browser_templates_watchdog_cb);
    } else if (wrv == APR_SUCCESS) {
        wrv = APR_EGENERAL;
    }
    if (wrv == APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, src_sv,
            "mod_botshield: browser-templates live-refresh enabled "
            "every %d s (path=%s)",
            refresh, src_scfg->browser_templates_path);
    } else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, wrv, src_sv,
            "mod_botshield: browser-templates watchdog "
            "registration failed; live-refresh disabled");
    }
}


/* Allow-list ranges live-refresh watchdog.
 *
 * Iterates every vhost that wired a bot-ranges manifest and
 * registers a per-worker (singleton=0) watchdog tick that
 * stat()s canonical + sidecar files and rebuilds + atomic-swaps
 * the active state on mtime change. Per-vhost registration
 * because the ranges configuration can vary between vhosts.
 *
 * The interval comes from BotShieldAllowRangesRefreshInterval.
 * If unset (0), live-refresh is disabled — operators get the
 * post_config load only and must `apachectl graceful` to pick
 * up sidecar edits. */
static void bs_init_allow_ranges(apr_pool_t *pconf, server_rec *s)
{
    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *fn_get =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *fn_reg =
        APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);

    /* Each vhost manifest gets its own watchdog instance. ap_
     * watchdog_get_instance is keyed by name; we mint one per
     * vhost so each registration is independent. */
    int vhost_idx = 0;
    int registrations = 0;
    for (server_rec *sv = s; sv; sv = sv->next, vhost_idx++) {
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!vcfg || !vcfg->bot_ranges_manifest) continue;

        int refresh = vcfg->allow_ranges_refresh_interval;
        if (refresh <= 0) continue;   /* opt-in via directive */

        if (!fn_get || !fn_reg) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: mod_watchdog not loaded; "
                "allow-ranges live-refresh disabled "
                "(post_config load still in effect)");
            return;
        }

        const char *wd_name = apr_psprintf(pconf,
            "mod_botshield_allow_ranges_%d", vhost_idx);
        ap_watchdog_t *wd = NULL;
        apr_status_t wrv = fn_get(&wd, wd_name, 0, 0, pconf);
        if (wrv == APR_SUCCESS && wd) {
            wrv = fn_reg(wd, apr_time_from_sec(refresh), sv,
                         bs_allow_ranges_watchdog_cb);
        } else if (wrv == APR_SUCCESS) {
            wrv = APR_EGENERAL;
        }
        if (wrv == APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: allow-ranges live-refresh enabled "
                "every %d s (%d file-backed bots, sidecars at "
                "<base>.local.txt)",
                refresh, vcfg->bot_ranges_manifest->file_bots->nelts);
            registrations++;
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, wrv, sv,
                "mod_botshield: allow-ranges watchdog registration "
                "failed; live-refresh disabled for this vhost");
        }
    }
    (void)registrations;
}


/* Data-source staleness check at post_config.
 *
 * Each classifier pass depends on data files that age at different
 * rates: the bot directory adds new bots monthly, browser templates
 * cycle every few weeks (Chrome's release cadence), verified-bot
 * IP ranges churn quarterly. If an operator's deployment sits long
 * enough between refreshes, the data drifts and the relevant
 * classifier silently misclassifies — most damagingly, real bots
 * from new IPs get fake-bot penalties, and real users on current
 * Chrome versions get treated as bot-candidates.
 *
 * This emits a NOTICE per stale file at startup so operators see
 * the staleness in their reload logs. The threshold is hardcoded
 * at 180 days — generous enough that healthy deployments never see
 * the message, tight enough that drift is flagged before accuracy
 * degrades materially. The fix-hint points operators at either the
 * refresh tool or the matching BotShieldClassify flag for graceful
 * degradation. */
#define BS_STALE_AGE_DAYS 180

static void bs_check_one_file_staleness(server_rec *s,
                                        const char *path,
                                        const char *which,
                                        const char *fix_hint)
{
    apr_finfo_t fi;
    if (apr_stat(&fi, path, APR_FINFO_MTIME,
                 s->process->pconf) != APR_SUCCESS) {
        return;   /* file missing or unstattable — not our problem here */
    }
    apr_time_t now = apr_time_now();
    apr_int64_t age_us = (apr_int64_t)now - (apr_int64_t)fi.mtime;
    if (age_us <= 0) return;
    apr_int64_t age_days =
        age_us / ((apr_int64_t)1000 * 1000 * 60 * 60 * 24);
    if (age_days < BS_STALE_AGE_DAYS) return;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: %s data is stale: %s mtime is %" APR_INT64_T_FMT
        " days old (threshold %d). %s",
        which, path, age_days, BS_STALE_AGE_DAYS, fix_hint);
}

static void bs_check_staleness(apr_pool_t *pconf, server_rec *s)
{
    (void)pconf;

    /* Bot-directory runtime override (if configured). */
    bs_server_cfg *main_scfg = ap_get_module_config(
        s->module_config, &botshield_module);
    if (main_scfg && main_scfg->bot_directory_path) {
        bs_check_one_file_staleness(s,
            main_scfg->bot_directory_path,
            "bot-directory",
            "Refresh via tools/refresh-bot-directory.py, or skip the "
            "pass with 'BotShieldClassify -known-bots'.");
    }

    /* Browser-templates runtime override (if configured). */
    if (main_scfg && main_scfg->browser_templates_path) {
        bs_check_one_file_staleness(s,
            main_scfg->browser_templates_path,
            "browser-templates",
            "Refresh via tools/refresh-top-user-agents.py, or skip "
            "the pass with 'BotShieldClassify -browsers'.");
    }

    /* Verified-bot CIDR ranges files — one per built-in / declared
     * bot. Walk every vhost's manifest. Same canonical path can
     * appear in multiple vhosts; check each anyway since the cost
     * is cheap and the per-vhost log line is operator-useful. */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *vcfg = ap_get_module_config(
            sv->module_config, &botshield_module);
        if (!vcfg || !vcfg->bot_ranges_manifest) continue;
        bs_bot_ranges_manifest *m = vcfg->bot_ranges_manifest;
        if (!m->file_bots) continue;
        for (int i = 0; i < m->file_bots->nelts; i++) {
            const bs_bot_file_manifest_entry *e =
                &APR_ARRAY_IDX(m->file_bots, i,
                               bs_bot_file_manifest_entry);
            char which[128];
            apr_snprintf(which, sizeof(which),
                "verified-bot ranges (%s)", e->name);
            bs_check_one_file_staleness(sv,
                e->canonical_path, which,
                "Refresh via tools/refresh-bot-ranges.sh, or skip "
                "the IP cross-check with "
                "'BotShieldClassify -verified-bots' (degrades to "
                "UA-only verify).");
        }
    }
}


/* Load-state sampler watchdog. One registration on the main
 * server only — the cached state is module-global, so per-vhost
 * registrations would just multiply the work for no gain. The
 * sampler reads scoreboard + (optional) external state file once
 * per tick and updates SHM. Soft dep on mod_watchdog. */
static void bs_register_load_watchdog(apr_pool_t *pconf, server_rec *s)
{
    bs_server_cfg *main_scfg = ap_get_module_config(
        s->module_config, &botshield_module);
    {
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
}

/* Capacity headroom watchdog. Independent of load-state config;
 * runs whenever mod_watchdog is available. 60s tick is generous —
 * table populations move on minute-to-hour timescales and the
 * rewarn cooldown is 5 min anyway. */
static void bs_register_headroom_watchdog(apr_pool_t *pconf,
                                          server_rec *s)
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

/* Auto-managed master secret. If no BotShieldSecretFile is configured at
 * vhost scope, populate the server's lookup_defaults dir_cfg with a
 * 32-byte secret loaded from BS_DEFAULT_SECRET_PATH (generating the
 * file on first run). The existing dir_cfg merge logic propagates
 * the master + derived keys down to every <Location> that didn't
 * override.
 *
 * Multi-host caveat: each host auto-generates its own file, so cookies
 * issued by one host won't validate at another. Operators running
 * BotShield behind a load balancer must distribute one shared file or
 * configure BotShieldSecretFile pointing at shared storage. The startup
 * log line below names the path so this isn't silent.
 *
 * Idempotent across post_config's two-pass cold-boot behavior — the
 * first_pass_skip guard means this only runs on the second pass; on
 * graceful restart it runs once and the file is read, not regenerated. */
static apr_status_t bs_load_or_generate_default_secret(
    apr_pool_t *p, apr_pool_t *ptemp, server_rec *s,
    unsigned char out[BS_AUTO_SECRET_BYTES])
{
    const char *path = BS_DEFAULT_SECRET_PATH;
    const char *dir  = "/var/lib/botshield";

    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, path,
        APR_FOPEN_READ | APR_FOPEN_BINARY, APR_FPROT_OS_DEFAULT, ptemp);
    if (rv == APR_SUCCESS) {
        apr_size_t n = BS_AUTO_SECRET_BYTES;
        rv = apr_file_read_full(f, out, n, NULL);
        apr_file_close(f);
        if (rv == APR_SUCCESS) return APR_SUCCESS;
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: failed to read auto-secret %s; refusing "
            "to overwrite - inspect or remove the file", path);
        return rv;
    }
    if (!APR_STATUS_IS_ENOENT(rv)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: cannot open %s for read", path);
        return rv;
    }

    /* File missing — first run on this host. Create dir + file. */
    rv = apr_dir_make_recursive(dir,
        APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_UEXECUTE, p);
    if (rv != APR_SUCCESS && !APR_STATUS_IS_EEXIST(rv)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: cannot create %s for auto-secret", dir);
        return rv;
    }

    if (RAND_bytes(out, BS_AUTO_SECRET_BYTES) != 1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: RAND_bytes failed for auto-secret");
        return APR_EGENERAL;
    }

    /* Atomic write: tmp + rename. EXCL on the tmp open prevents two
     * concurrent post_config passes (or a botched prior run) from
     * stepping on each other; if the tmp already exists, fail loud. */
    const char *tmp = apr_pstrcat(ptemp, path, ".tmp", NULL);
    rv = apr_file_open(&f, tmp,
        APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE
            | APR_FOPEN_BINARY | APR_FOPEN_EXCL,
        APR_FPROT_UREAD | APR_FPROT_UWRITE, ptemp);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: cannot create tmp file %s", tmp);
        return rv;
    }
    apr_size_t n = BS_AUTO_SECRET_BYTES;
    rv = apr_file_write_full(f, out, n, NULL);
    apr_file_close(f);
    if (rv != APR_SUCCESS) {
        apr_file_remove(tmp, ptemp);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: write failed for %s", tmp);
        return rv;
    }

    /* chown so workers (running as ap_unixd_config.user_id) can read.
     * Best-effort — if we're not root the chown fails but the file is
     * still mode 0600 owned by whoever ran post_config; the operator
     * will see "could not read auto-secret" at next start and can fix
     * ownership manually. */
    if (chown(tmp, ap_unixd_config.user_id,
              ap_unixd_config.group_id) != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, s,
            "mod_botshield: chown(%s) failed; auto-secret may not be "
            "readable by Apache workers", tmp);
    }
    /* Same for the parent dir, in case we just created it. Ignore
     * failures — the dir may pre-exist with an intentional ownership. */
    if (chown(dir, ap_unixd_config.user_id,
              ap_unixd_config.group_id) != 0) {
        /* deliberately ignored */
    }

    rv = apr_file_rename(tmp, path, ptemp);
    if (rv != APR_SUCCESS) {
        apr_file_remove(tmp, ptemp);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
            "mod_botshield: rename(%s -> %s) failed", tmp, path);
        return rv;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: generated auto-managed master secret at %s. "
        "For multi-host deployments, distribute this file across hosts "
        "or configure BotShieldSecretFile to point at shared storage so "
        "every host validates cookies issued by every other host.",
        path);
    return APR_SUCCESS;
}

/* For each server_rec, populate its lookup_defaults dir_cfg's secret +
 * derived keys with the auto-managed master if no explicit
 * BotShieldSecretFile was configured at server scope. Run once with a
 * shared 32-byte key — every vhost that didn't override gets the same
 * derived keys, so cookies issued under "<VirtualHost A>" still validate
 * under "<VirtualHost B>" on the same host. */
static void bs_populate_auto_secret(apr_pool_t *pconf, apr_pool_t *ptemp,
                                    server_rec *s)
{
    /* Skip if every server has an explicit secret already. */
    int need = 0;
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_dir_cfg *dcfg = ap_get_module_config(
            sv->lookup_defaults, &botshield_module);
        if (dcfg && !dcfg->secret) { need = 1; break; }
    }
    if (!need) return;

    unsigned char master[BS_AUTO_SECRET_BYTES];
    if (bs_load_or_generate_default_secret(pconf, ptemp, s, master)
        != APR_SUCCESS) {
        return;
    }

    /* Stash a pconf-lifetime copy so dir_cfg->secret points at memory
     * that outlives ptemp. */
    unsigned char *master_p = apr_palloc(pconf, BS_AUTO_SECRET_BYTES);
    memcpy(master_p, master, BS_AUTO_SECRET_BYTES);

    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_dir_cfg *dcfg = ap_get_module_config(
            sv->lookup_defaults, &botshield_module);
        if (!dcfg || dcfg->secret) continue;
        const char *err = bs_derive_purpose_keys(pconf,
            master_p, BS_AUTO_SECRET_BYTES,
            dcfg->derived_gcm_cookie,
            dcfg->derived_hmac_pending,
            dcfg->derived_hmac_bootstrap);
        if (err) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv,
                "mod_botshield: HKDF for auto-secret failed: %s", err);
            continue;
        }
        dcfg->secret           = master_p;
        dcfg->secret_len       = BS_AUTO_SECRET_BYTES;
        dcfg->derived_keys_set = 1;
    }
}

/* When any server scope's root dir_cfg has BotShieldEnabled LogOnly,
 * log a one-time hint at startup pointing at the per-module LogLevel
 * knob. Decision log lines emit at APLOG_INFO; the default vhost
 * LogLevel is warn, so without this nudge the operator turns on
 * log-only mode and sees nothing in their logs.
 *
 * Per-Location LogOnly overrides aren't surfaced here — too noisy at
 * startup and the operator who wrote one already knows to look. */
static void bs_log_logonly_hint(server_rec *s)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_dir_cfg *dcfg = ap_get_module_config(sv->lookup_defaults,
                                                &botshield_module);
        if (dcfg && dcfg->enabled == BS_ENABLED_LOGONLY) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: BotShieldEnabled LogOnly - "
                "raise 'LogLevel botshield:info' to see decision logs.");
            return;   /* one notice is enough */
        }
    }
}

/* Default the PoW algorithm to sha256-zeros when no BotShieldAlgorithm
 * directive was provided. Same lookup_defaults mechanism as the
 * auto-secret: populate the server-scope dir_cfg, let the existing
 * merge fall through into every <Location> that didn't override.
 *
 * sha256-zeros is the only standalone-meaningful PoW algorithm; the
 * captcha-* slots in the registry require provider-specific directives
 * (BotShieldCaptchaProvider + SiteKey + SecretFile) before they're
 * useful, so they're never something an operator would land on
 * by accident. Defaulting here means "BotShieldEnabled On" suffices
 * for the common case (non-interactive + interactive PoW tiers); captcha tier still
 * needs its provider config but the cookie-alg side is auto-populated
 * by bs_captcha_set_provider. */
static void bs_populate_default_algorithm(server_rec *s)
{
    const bs_pow_algorithm *alg = bs_find_algorithm("sha256-zeros");
    if (!alg) return;   /* registry slot unexpectedly missing */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_dir_cfg *dcfg = ap_get_module_config(
            sv->lookup_defaults, &botshield_module);
        if (dcfg && !dcfg->algorithm) {
            dcfg->algorithm = alg;
        }
    }
}

/* --- config-test dump -------------------------------------------------
 *
 * `httpd -t -D DUMP_BOTSHIELD_POLICY` prints the effective policy for
 * every enabled vhost, the way -S prints vhosts. This lives in the
 * test_config hook rather than post_config for two reasons: post_config
 * is not called at all on a -t run, and test_config is the hook core
 * itself uses for DUMP_VHOSTS / DUMP_MODULES, so the flag composes with
 * those. The trigger resolvers run first because the dump reports
 * resolved triggers, and on a -t run nothing else has resolved them. */
void bs_test_config(apr_pool_t *pconf, server_rec *s)
{
    if (!ap_exists_config_define("DUMP_BOTSHIELD_POLICY")) return;

    bs_resolve_flag_triggers(pconf, s);
    bs_resolve_heuristic_triggers(pconf, s);

    for (server_rec *sv = s; sv; sv = sv->next) {
        if (!bs_vhost_runs_botshield(sv, s)) continue;

        /* Parse robots.txt here too. bs_init_robots does this in
         * post_config, so on a -t run the dump would otherwise report
         * every configured robots.txt as "not loaded" -- and "does my
         * robots.txt parse?" is one of the questions a config-test
         * dump is most useful for answering, before deploying rather
         * than after. The parse is pure: file in, struct out.
         *
         * The nominal slot pool is reserved so the parse does not warn
         * that Crawl-delay groups will not enforce -- true of this
         * configtest process, which attaches no SHM, and false of the
         * server it is testing the config for. The slot numbers
         * themselves are SHM bookkeeping and the dump does not print
         * them. */
        bs_server_cfg *vcfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (vcfg && vcfg->robots_txt_path && !vcfg->robots) {
            vcfg->robots_slot_pool_base = 0;
            vcfg->robots_slot_pool_size = BS_E22_ROBOTS_SLOT_POOL;
            vcfg->robots_slot_pool_used = 0;
            bs_robots_load(sv, vcfg, pconf);
        }
        bs_dir_cfg *dcfg = ap_get_module_config(sv->lookup_defaults,
                                                &botshield_module);
        bs_policy_dump(sv, pconf, dcfg);
    }
    fflush(stdout);
}

/* --- post_config orchestrator ---
 *
 * Each phase is its own static helper above; this function reads
 * as a checklist. Phases that can fail (curl global init, SHM
 * layout) return non-OK and short-circuit the rest. The remaining
 * phases are logging-only and keep going on best-effort. */
int bs_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                   apr_pool_t *ptemp, server_rec *s)
{
    (void)plog;

    if (bs_post_config_first_pass_skip(s)) return OK;

    int rv = bs_init_curl_global(s);
    if (rv != OK) return rv;

    bs_warn_app_integration_secrets(s);
    bs_resolve_flag_triggers(pconf, s);
    bs_resolve_heuristic_triggers(pconf, s);

    bs_server_cfg *scfg = ap_get_module_config(s->module_config,
                                               &botshield_module);

    rv = bs_init_shm_layout(pconf, ptemp, s, scfg);
    if (rv != OK) return rv;

    /* Owned decision logs: opened here, as root and before the child
     * processes fork, so every worker inherits the descriptor. Fatal on
     * failure — see bs_open_decision_logs. */
    rv = bs_open_decision_logs(pconf, s);
    if (rv != OK) return rv;

    /* Announce the access-log default. Suppressing lines by default is
     * a deliberate incompleteness in a file operators treat as a
     * system of record, so it gets said out loud once per start rather
     * than discovered by someone wondering where their requests went.
     * Only for servers that actually have BotShield enabled somewhere;
     * a loaded-but-unused module stays quiet. */
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *sc = ap_get_module_config(sv->module_config,
                                                 &botshield_module);
        if (!sc || !sc->any_enabled) continue;
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: access-log lines are suppressed by default "
            "for responses BotShield generated (challenged, block, "
            "rate_limited, redirect) - those requests never reached the "
            "application. They are still counted in "
            "botshield_requests_total and on the dashboard. "
            "'BotShieldAccessLog on' restores full logging; "
            "'suppress=<outcomes>' selects a different set.");
        break;
    }
    if (rv != OK) return rv;

    bs_init_state_persistence(pconf, s, scfg);
    bs_populate_auto_secret(pconf, ptemp, s);
    bs_populate_default_algorithm(s);
    bs_log_logonly_hint(s);
    bs_wire_allowlist(pconf, s);

    int next_slot = 0;
    bs_wire_rate_and_block_cohorts(pconf, s, &next_slot);
    bs_resolve_robots_defaults(s);
    bs_assign_namespace_ids(s);
    bs_init_robots(pconf, s, &next_slot);
    bs_init_bot_directory(pconf, s);
    bs_init_browser_templates(pconf, s);
    bs_init_allow_ranges(pconf, s);
    /* Slug-keyed bot rate limit needs the directory loaded (above)
     * and shares the rate-counter pool with directives + robots.txt. */
    bs_bot_rate_init(pconf, s, &next_slot);
    /* Cursor after every allocator has run -- see rate_slots_used. */
    bs_shm.rate_slots_used = (apr_size_t)(next_slot > 0 ? next_slot : 0);
    bs_check_staleness(pconf, s);
    bs_register_load_watchdog(pconf, s);
    bs_register_headroom_watchdog(pconf, s);

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

/* --- Directive setters --- *
 *
 * The remaining ~40 setters that don't have a feature home: top-
 * level / UI, score thresholds, SHM sizing, rate-limit family,
 * state-save, endpoint-prefix, plus the four config-time helpers
 * (bs_load_config_file / bs_validate_secret_key / bs_cohort_resolve
 * / bs_warn_if_virtual_scope) reused by feature-file setters via
 * cross-file decls in botshield.h. */

/* --- Directive setters --- */

const char *bs_set_enabled(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg || !*arg) {
        return "BotShieldEnabled requires an argument: On, Off, or LogOnly";
    }
    if (strcasecmp(arg, "on") == 0) {
        cfg->enabled = BS_ENABLED_ON;
    } else if (strcasecmp(arg, "off") == 0) {
        cfg->enabled = BS_ENABLED_OFF;
    } else if (strcasecmp(arg, "logonly") == 0
            || strcasecmp(arg, "log-only") == 0
            || strcasecmp(arg, "log_only") == 0) {
        cfg->enabled = BS_ENABLED_LOGONLY;
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldEnabled: unknown mode '%s' (expected On, Off, "
            "or LogOnly)", arg);
    }
    /* Record on the server config that this vhost has the module live
     * somewhere, so bs_handler will serve the module-owned endpoints
     * even when the enable is scoped to a <Location>. */
    if (cfg->enabled == BS_ENABLED_ON || cfg->enabled == BS_ENABLED_LOGONLY) {
        bs_server_cfg *scfg = ap_get_module_config(
            cmd->server->module_config, &botshield_module);
        if (scfg) scfg->any_enabled = 1;
    }
    return NULL;
}

const char *bs_set_challenge(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->challenge_enabled = flag ? 1 : 0;
    return NULL;
}

const char *bs_set_debug(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->debug = flag ? 1 : 0;
    return NULL;
}

const char *bs_set_show_logo(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->show_logo = flag ? 1 : 0;
    return NULL;
}

const char *bs_set_show_label(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->show_label = flag ? 1 : 0;
    return NULL;
}

const char *bs_set_show_box(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    ((bs_dir_cfg *)cfg_v)->show_box = flag ? 1 : 0;
    return NULL;
}

const char *bs_set_cookie_ttl(cmd_parms *cmd, void *cfg_v, const char *arg)
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

const char *bs_set_interactive_min_ms(cmd_parms *cmd, void *cfg_v,
                                      const char *arg)
{
    (void)cmd;
    long n;
    /* Upper bound is a usability guard, not a security one: past a few
     * seconds the floor stops rejecting bots and starts rejecting
     * people who clicked promptly. */
    if (!bs_parse_int_bounded(arg, 0, 5000, 4, &n)) {
        return "BotShieldInteractiveMinSolveMs: must be an integer "
               "0..5000 (0 disables the floor)";
    }
    ((bs_dir_cfg *)cfg_v)->interactive_min_ms = (int)n;
    return NULL;
}

const char *bs_set_interactive_arm_ms(cmd_parms *cmd, void *cfg_v,
                                      const char *arg)
{
    (void)cmd;
    long n;
    /* Capped at 2000: past that the widget is visibly broken to the
     * person waiting on it, and the signal it buys stops improving. */
    if (!bs_parse_int_bounded(arg, 0, 2000, 4, &n)) {
        return "BotShieldInteractiveArmMs: must be an integer 0..2000 "
               "(0 shows the checkbox immediately)";
    }
    ((bs_dir_cfg *)cfg_v)->interactive_arm_ms = (int)n;
    return NULL;
}

const char *bs_set_difficulty(cmd_parms *cmd, void *cfg_v, const char *arg)
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

/* BotShieldAccessLog on|off|suppress=<outcome[,outcome...]>
 *
 * Decouples access-log control from the trigger families. It used to be
 * reachable only as a trigger action key, which meant an operator whose
 * challenges came from the scoring defaults had to invent a rule whose
 * only purpose was logging -- and any request the rule's predicate
 * missed silently kept logging. Outcome-keyed and scope-level, so it
 * follows the decision rather than the rule that produced it. */
const char *bs_set_robots_mode(cmd_parms *cmd, void *cfg_v,
                               const char *arg)
{
    (void)cfg_v;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!strcasecmp(arg, "enforce"))      scfg->robots_mode = BS_ROBOTS_MODE_ENFORCE;
    else if (!strcasecmp(arg, "observe")) scfg->robots_mode = BS_ROBOTS_MODE_OBSERVE;
    else return apr_psprintf(cmd->pool,
        "BotShieldRobotsMode: '%s' must be enforce or observe", arg);
    return NULL;
}

const char *bs_set_access_log(cmd_parms *cmd, void *cfg_v, int argc,
                              char *const argv[])
{
    bs_dir_cfg *cfg = (bs_dir_cfg *)cfg_v;
    if (argc != 1) {
        return "BotShieldAccessLog: takes exactly one argument: "
               "on, off, or suppress=<outcome[,outcome...]>";
    }
    const char *v = argv[0];

    if (!strcasecmp(v, "on")) {
        cfg->accesslog_suppress = 0;
        return NULL;
    }
    if (!strcasecmp(v, "off")) {
        /* "off" means every outcome BotShield reaches a decision on.
         * Requests it never evaluated are outside its reach and keep
         * logging -- this directive cannot silence the whole site. */
        cfg->accesslog_suppress = (int)((1U << BS_M_OUTCOME_COUNT) - 1U);
        return NULL;
    }
    if (strncasecmp(v, "suppress=", 9) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldAccessLog: '%s' must be on, off, or "
            "suppress=<outcome[,outcome...]>", v);
    }

    unsigned mask = 0;
    char *list = apr_pstrdup(cmd->pool, v + 9);
    char *save = NULL;
    for (char *tok = apr_strtok(list, ",", &save); tok;
         tok = apr_strtok(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        if (!*tok) continue;
        int oi = bs_outcome_index(tok);
        if (oi < 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldAccessLog: unknown outcome '%s'. Valid: "
                "allow, challenged, verified, block, failopen, "
                "rate_limited, inflight_capped, pending_missing, "
                "misconfigured, debug, redirect", tok);
        }
        mask |= (1U << (unsigned)oi);
    }
    if (!mask) {
        return "BotShieldAccessLog: suppress= needs at least one outcome";
    }
    cfg->accesslog_suppress = (int)mask;
    return NULL;
}

const char *bs_set_score_non_interactive(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldScoreNonInteractive",
        &((bs_dir_cfg *)cfg_v)->score_non_interactive, arg, cmd->pool);
}

const char *bs_set_score_interactive(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldScoreInteractive",
        &((bs_dir_cfg *)cfg_v)->score_interactive, arg, cmd->pool);
}

const char *bs_set_score_captcha(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldScoreCaptcha",
        &((bs_dir_cfg *)cfg_v)->score_captcha, arg, cmd->pool);
}

const char *bs_set_forgive_non_interactive(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldForgivenessNonInteractive",
        &((bs_dir_cfg *)cfg_v)->forgive_non_interactive, arg, cmd->pool);
}

const char *bs_set_forgive_interactive(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldForgivenessInteractive",
        &((bs_dir_cfg *)cfg_v)->forgive_interactive, arg, cmd->pool);
}

const char *bs_set_forgive_captcha(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    return bs_set_score_int("BotShieldForgivenessCaptcha",
        &((bs_dir_cfg *)cfg_v)->forgive_captcha, arg, cmd->pool);
}


/* E18 — `BotShieldFormCaptcha on|off`. Per-scope opt-in for inline
 * form captcha verification on POST submit. When on, BotShield
 * inspects the request body for the configured captcha provider's
 * response field, siteverifies via the existing M8 client, mints
 * _bs_session on success, and replays the body back via input
 * filter so the downstream app handler still sees its original
 * POST. Supports application/x-www-form-urlencoded and
 * application/json. multipart/form-data (file uploads) is out of
 * scope — operators with file-upload forms put the captcha on a
 * separate non-upload form. */
const char *bs_set_form_captcha(cmd_parms *cmd, void *cfg_v, int flag)
{
    bs_dir_cfg *cfg = cfg_v;
    cfg->form_captcha = flag ? 1 : 0;
    return NULL;
}

/* E13 — log a NOTICE if an SHM-sizing directive is placed inside
 * <VirtualHost>. The single SHM segment is sized once at post_config
 * from the main server's scfg; per-vhost values for capacity directives
 * are silently ignored. The footgun was hard to spot in operator
 * configs — surface it explicitly so they don't think their override
 * took effect. */
void bs_warn_if_virtual_scope(cmd_parms *cmd, const char *name)
{
    if (cmd->server && cmd->server->is_virtual) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server,
            "mod_botshield: %s placed inside <VirtualHost> at %s:%d "
            "is ignored - SHM is sized once from the main server "
            "scope. Move this directive outside <VirtualHost>.",
            name,
            cmd->directive && cmd->directive->filename
                ? cmd->directive->filename : "(unknown)",
            cmd->directive ? cmd->directive->line_num : 0);
    }
}

const char *bs_set_shm_size(cmd_parms *cmd, void *dconf, const char *arg)
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
    /* Guard the suffix multiply. The explicit
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

const char *bs_set_flagged_capacity(cmd_parms *cmd, void *dconf,
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


/* Accept ".example.com" (leading dot for cross-subdomain) or "example.com"
 * (host-only). Empty string clears the directive, reverting to host-only.
 *
 * the value is embedded into both the Set-Cookie
 * header and (via bs_challenge_json) inline JSON in the interstitial
 * script. The previous check only rejected whitespace + semicolons,
 * which would have let quotes/backslashes through and given a
 * config-time script-injection footgun to any templating system
 * that ever hands this directive a non-human-typed value. Tighten
 * to DNS hostname charset only: [a-zA-Z0-9.-], max 253 chars per
 * RFC 1035. Leading dot permitted (cookie-domain convention). */
const char *bs_set_cookie_domain(cmd_parms *cmd, void *cfg_v, const char *arg)
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

const char *bs_set_prompt(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    if (!arg || !*arg) return "BotShieldPromptText cannot be empty";
    ((bs_dir_cfg *)cfg_v)->prompt = arg;
    return NULL;
}

const char *bs_set_logo_label(cmd_parms *cmd, void *cfg_v, const char *arg)
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
const char *bs_load_config_file(cmd_parms *cmd,
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


/* Validate a binary-capable secret loaded via
 * bs_load_config_file. Trims one trailing newline (common with
 * `echo`-style key generation), rejects embedded NUL bytes (would
 * silently truncate keys generated with `dd if=/dev/urandom` or
 * similar — P(NUL in N random bytes) = 1 − (255/256)^N, ≈12% for
 * 32-byte keys and ≈22% for 64-byte keys), and enforces the
 * minimum-bytes floor. Returns NULL on success with *out_len set
 * to the effective key length, or an error string. */
const char *bs_validate_secret_key(cmd_parms *cmd,
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

/* End-to-end secret-file loader: stat + mode check (refuse group-
 * or world-accessible) + bs_load_config_file + bs_validate_secret_key.
 *
 * Used by every directive that loads an HMAC / GCM master key
 * (BotShieldSecretFile, BotShieldSecondarySecretFile,
 * BotShieldCaptchaSecretFile, BotShieldAppIntegrationSecretFile).
 * Consolidating the four sites into one helper means the
 * mode-600 discipline, the size cap, the NUL-byte check, and the
 * minimum-key-length floor all change in one place if the
 * threat model evolves.
 *
 * Returns NULL on success with *out_buf and *out_len populated.
 * On any failure returns an Apache error string keyed on the
 * caller's `directive` so the operator sees the directive that
 * actually failed, not a generic message. */
const char *bs_load_secret_file(cmd_parms *cmd,
                                const char *directive,
                                const char *path,
                                const char **out_buf,
                                apr_size_t *out_len)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "%s: cannot stat '%s'", directive, path);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "%s: '%s' is group- or world-accessible "
            "(mode %04o); chmod 600 it",
            directive, path, st.st_mode & 07777);
    }

    const char *raw_buf = NULL;
    apr_size_t raw_len = 0;
    const char *err = bs_load_config_file(cmd, directive, path,
                                          BS_MAX_SECRET_BYTES,
                                          &raw_buf, &raw_len);
    if (err) return err;

    apr_size_t valid_len = 0;
    err = bs_validate_secret_key(cmd, directive, path,
                                 raw_buf, raw_len, &valid_len);
    if (err) return err;

    *out_buf = raw_buf;
    *out_len = valid_len;
    return NULL;
}

const char *bs_set_logo_file(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    return bs_load_config_file(cmd, "BotShieldLogoFile", arg,
                               BS_MAX_LOGO_BYTES, &cfg->logo_svg, NULL);
}

const char *bs_set_help(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    (void)cmd;
    bs_dir_cfg *cfg = cfg_v;
    if (strcasecmp(arg, "off") == 0)         cfg->help_mode = BS_HELP_OFF;
    else if (strcasecmp(arg, "on") == 0)     cfg->help_mode = BS_HELP_ON;
    else if (strcasecmp(arg, "button") == 0) cfg->help_mode = BS_HELP_BUTTON;
    else return "BotShieldHelp must be one of: off, on, button";
    return NULL;
}

const char *bs_set_help_file(cmd_parms *cmd, void *cfg_v, const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    return bs_load_config_file(cmd, "BotShieldHelpFile", arg,
                               BS_MAX_HELP_BYTES, &cfg->help_html, NULL);
}

const char *bs_set_challenge_file(cmd_parms *cmd, void *cfg_v, const char *arg)
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

const char *bs_set_bloom_ips(cmd_parms *cmd, void *dconf,
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

const char *bs_set_bloom_window(cmd_parms *cmd, void *dconf,
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

const char *bs_set_ipv6_prefix(cmd_parms *cmd, void *dconf,
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
const char *bs_set_state_file(cmd_parms *cmd, void *dconf,
                                     const char *arg)
{
    (void)dconf;
    bs_warn_if_virtual_scope(cmd, "BotShieldStateFile");
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!arg || !*arg) return "BotShieldStateFile requires a path";
    /* The state file carries mutable reputation state and the keyed-
     * hash collision keys; treat it as sensitive. Apache's CWD is
     * undefined for relative paths (depends on how Apache was
     * launched), so a relative `state.bin` could land in a world-
     * writable directory by accident. Require an absolute path so
     * operators are forced to think about the parent directory. The
     * recommended convention is /var/lib/mod_botshield/state.bin
     * with mode 0700 on the parent. */
    if (arg[0] != '/') {
        return apr_psprintf(cmd->pool,
            "BotShieldStateFile: '%s' must be an absolute path. "
            "The file holds reputation state and keyed-hash collision "
            "keys — pin it to a non-world-writable parent (the "
            "convention is /var/lib/mod_botshield/state.bin).", arg);
    }
    scfg->state_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

const char *bs_set_state_save_interval(cmd_parms *cmd, void *dconf,
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

/* BotShieldRateLimit <name> [budget=N] [per=U] [ua=...] [ipspec=...]
 * [mode=...] — cohort rate-limit. Legacy positional form
 * `<name> <budget> <per> <ua> <ipspec> [mode=...]` is also accepted
 * and parses the same way internally; the form is detected by
 * sniffing the args (every arg after <name> contains '=' → new
 * shape; any positional arg without '=' → legacy).
 *
 * Cohort semantics mirror BotShieldRequestTrigger ua=/ipspec= (UA
 * substring, @botgroup, polymorphic ipspec, '*' for "any" on either
 * axis). Both-'*' (or both keys omitted in the new form) is rejected
 * because that would rate-limit every request on the server. Budget
 * + window are stored as-is; SHM slot assignment happens in
 * post_config.
 *
 * Apache doesn't ship AP_INIT_TAKE4/5, so this uses TAKE_ARGV and
 * enforces argc itself. */
/* E12 — parse the optional trailing `mode=enforce|observe` argv
 * token used by BotShieldRateLimit. The directive grammar is
 * positional (5 args for rate-limit), so this is strict: the
 * token must be the LAST argument and it must be `mode=...`.
 * Returns the parsed mode in *out_mode and shrinks *argc by 1 if
 * the token was consumed. */
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

const char *bs_set_rate_limit(cmd_parms *cmd, void *dconf,
                                     int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 1) {
        return "BotShieldRateLimit: expects at least <name>";
    }
    const char *name = argv[0];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldRateLimit: name '%s' must be [a-z0-9-]{1,32}", name);
    }

    /* Form detection — every arg after <name> is key=value (contains
     * '=') in the new shape; the legacy positional shape has at most
     * a single trailing `mode=...` token. If any non-trailing arg
     * lacks '=', fall through to the legacy parser. */
    int new_form = (argc > 1);
    for (int i = 1; i < argc; i++) {
        if (!strchr(argv[i], '=')) { new_form = 0; break; }
    }

    const char *budget_s = NULL, *per_s = NULL;
    const char *ua_arg = NULL, *ipspec_arg = NULL;
    int mode = BS_TMODE_ENFORCE;

    if (new_form) {
        for (int i = 1; i < argc; i++) {
            const char *arg = argv[i];
            const char *eq  = strchr(arg, '=');
            apr_size_t klen = (apr_size_t)(eq - arg);
            const char *val = eq + 1;
            if (klen == 6 && strncasecmp(arg, "budget", 6) == 0) {
                budget_s = val;
            } else if (klen == 3 && strncasecmp(arg, "per", 3) == 0) {
                per_s = val;
            } else if (klen == 2 && strncasecmp(arg, "ua", 2) == 0) {
                ua_arg = val;
            } else if (klen == 6 && strncasecmp(arg, "ipspec", 6) == 0) {
                ipspec_arg = val;
            } else if (klen == 4 && strncasecmp(arg, "mode", 4) == 0) {
                if (!strcasecmp(val, "enforce")) {
                    mode = BS_TMODE_ENFORCE;
                } else if (!strcasecmp(val, "observe")) {
                    mode = BS_TMODE_OBSERVE;
                } else {
                    return apr_psprintf(cmd->pool,
                        "BotShieldRateLimit: mode='%s' must be 'enforce' "
                        "or 'observe'", val);
                }
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldRateLimit: unknown key '%.*s' (known: "
                    "budget, per, ua, ipspec, mode)", (int)klen, arg);
            }
        }
        if (!budget_s) {
            return "BotShieldRateLimit: budget=<N> is required";
        }
        if (!per_s) {
            return "BotShieldRateLimit: per=<sec|min|hour> is required";
        }
    } else {
        /* Legacy positional: <name> <budget> <per> <ua> <ipspec>
         * [mode=enforce|observe]. Strip optional trailing mode=
         * before counting. */
        const char *merr = bs_parse_optional_mode(cmd->pool,
            "BotShieldRateLimit", &argc, argv, &mode);
        if (merr) return merr;
        if (argc != 5) {
            return "BotShieldRateLimit: expects either "
                   "<name> [budget=N] [per=U] [ua=...] [ipspec=...] "
                   "[mode=...]  or legacy "
                   "<name> <budget> <per> <ua> <ipspec> [mode=...]";
        }
        budget_s   = argv[1];
        per_s      = argv[2];
        ua_arg     = argv[3];
        ipspec_arg = argv[4];
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
    e->mode       = mode;
    /* In the new form an omitted ua=/ipspec= defaults to "*" (any).
     * bs_cohort_resolve enforces the both-* rejection so a
     * key=value form with neither set still errors at config time. */
    const char *ua_eff     = ua_arg     ? ua_arg     : "*";
    const char *ipspec_eff = ipspec_arg ? ipspec_arg : "*";
    const char *err = bs_cohort_resolve(cmd, &e->cohort, ua_eff, ipspec_eff);
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
const char *bs_set_rate_limit_escalate(cmd_parms *cmd, void *dconf,
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
    e->status_code = 403;       /* default per CHANGELOG.md E9 */
    e->ttl_sec     = 1800;      /* default per CHANGELOG.md E9 */
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
const char *bs_set_rate_escalate_capacity(cmd_parms *cmd,
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
const char *bs_set_safeguard(cmd_parms *cmd, void *dconf, int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->safeguard_enabled = flag ? 1 : 0;
    return NULL;
}

/* E10 — BotShieldSafeguardThreshold <N>. Number of presentations
 * within the window before safeguard trips. */
const char *bs_set_safeguard_threshold(cmd_parms *cmd,
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
const char *bs_set_safeguard_window(cmd_parms *cmd,
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
const char *bs_set_safeguard_ttl(cmd_parms *cmd,
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

/* E10 — BotShieldSafeguardRedirectURL <url>. Where to send a client
 * that trips the safeguard threshold. NULL (unset) → use the built-
 * in explainer at <BotShieldEndpointPrefix>/safeguard-info. The
 * built-in endpoint is auto-routed by the module so operators don't
 * need a Location carve-out. The original URI is appended as
 * ?return=<urlencoded path> so the explainer (or operator's own
 * page) can offer a continue link. URL must start with '/' (same-
 * origin path) to avoid open-redirect risk. */
const char *bs_set_safeguard_redirect_url(cmd_parms *cmd,
                                          void *dconf,
                                          const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldSafeguardRedirectURL requires a path";
    }
    if (arg[0] != '/' || (arg[0] == '/' && arg[1] == '/')) {
        return apr_psprintf(cmd->pool,
            "BotShieldSafeguardRedirectURL: '%s' must be a same-origin "
            "absolute path starting with a single '/'", arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->safeguard_redirect_url = apr_pstrdup(cmd->pool, arg);
    return NULL;
}


/* E10 — BotShieldSafeguardCapacity <n>. SHM slot count. Same
 * per-server-scope convention as the other SHM-sizing directives:
 * only the main server's value is consulted at post_config. */
const char *bs_set_safeguard_capacity(cmd_parms *cmd,
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

/* BotShieldEmbeddedNonceCapacity <n>. SHM slot count for the
 * embedded-bootstrap nonce table. Sized to comfortably hold all
 * in-flight bootstrap challenges within their 120-second expiry
 * window: at 100 bootstraps/sec sustained that's 12K nonces; the
 * 32K default has ~60% headroom. */
const char *bs_set_nonce_capacity(cmd_parms *cmd,
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
const char *bs_set_share_scope(cmd_parms *cmd, void *dconf,
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

/* The BotShieldFlagTrigger directive setter lives in triggers.c. */

/* E15 — BotShieldForgivenessCapPerHour <N>. Server-
 * scope cap on the points of forgiveness any one cookie can earn
 * inside a rolling 1-hour window. 0 disables the cap (legacy
 * behavior). Range 1..1000 — beyond that the cap is effectively
 * absent anyway. */
const char *bs_set_forgive_cap(cmd_parms *cmd, void *dconf,
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
int bs_forgiveness_apply_cap(int requested,
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

const char *bs_set_endpoint_prefix(cmd_parms *cmd, void *cfg_v,
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
const char *bs_cohort_resolve(cmd_parms *cmd, bs_cohort *out,
                                     const char *ua, const char *ipspec)
{
    memset(out, 0, sizeof(*out));
    if (!ua || strcmp(ua, "*") == 0) {
        /* NULL is "the caller supplied no UA axis at all" — the
         * key-form parser normalises an omitted ua= to "*" before it
         * gets here (see the ua_eff default), so this is the
         * positional/internal path. */
        out->ua_any = 1;
    } else if (!*ua) {
        /* ua="" (or a bare ua=) — no User-Agent header, or one present
         * but empty. Absence is not a substring of anything, so the
         * substring form below could never express it; before this the
         * only way to write "challenge requests with no UA" was to wrap
         * a scope in an Apache <If "-z %{HTTP_USER_AGENT}">, which
         * works but puts half the policy outside the module and out of
         * the decision log's reach.
         *
         * This used to fold into "any" alongside "*". Nothing shipped
         * wrote it — an empty value was a redundant second spelling of
         * a meaning "*" and omission already covered — so the slot was
         * free to carry the useful meaning instead. "*" remains the
         * spelling for "any", and it has to: the legacy positional form
         * cannot omit the UA argument, so it needs a placeholder. */
        out->ua_none = 1;
    } else if (ua[0] == '@') {
        /* @botgroup selector — match by the request's classified
         * botgroup instead of UA-substring. Recognized botgroups:
         * search, ai-input, ai-train, monitor (mod_botshield
         * extension; the others are IETF aipref vocabulary).
         *
         * @bot and @fake-bot are class selectors rather than botgroups:
         * they match the classifier's verdict directly. A botgroup can
         * only name a bot the UA directory already knows, so before
         * these existed class=unknown-bot could not be named in a rule
         * at all, and "act on every bot" had to be spelled as one rule
         * per botgroup -- which silently missed that class. */
        if (!ua[1]) {
            return "UA selector '@' must be followed by a botgroup "
                   "name (search, ai-input, ai-train, monitor) or a "
                   "class (bot, fake-bot)";
        }
        if (strcasecmp(ua + 1, "bot") == 0) {
            out->ua_class_bot = 1;
        } else if (strcasecmp(ua + 1, "fake-bot") == 0) {
            out->ua_class_fake = 1;
        } else {
            out->ua_botgroup = apr_pstrdup(cmd->pool, ua + 1);
        }
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
