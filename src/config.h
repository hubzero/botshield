/* config.h — module-config lifecycle hooks.
 *
 * Apache's module loading model invokes four config hooks per
 * configured scope (server, vhost, <Directory>, .htaccess):
 *
 *   create_dir_config   per <Directory>/<Location>; allocate dconf
 *   merge_dir_config    when scopes nest; combine parent + child
 *   create_server_config  per server/vhost; allocate scfg
 *   merge_server_config   when vhosts inherit from main
 *
 * Plus two lifecycle hooks invoked once per server lifetime:
 *
 *   post_config    after all directives parsed; runs in parent
 *                  (single-threaded, pre-fork). HKDF derivation,
 *                  SHM segment sizing, watchdog registration,
 *                  cross-vhost validation, defaults seeding.
 *   child_init     in each worker process at startup. Currently
 *                  just attaches to the SHM mutex.
 *
 * Apache 2.4 invokes post_config TWICE on cold boot (syntax-check
 * pass, then the real init). Implementation skips the first via a
 * userdata sentinel keyed on s->process->pool. See comments in
 * bs_post_config for the graceful-restart corollary. */
#ifndef BOTSHIELD_CONFIG_H
#define BOTSHIELD_CONFIG_H

#include <httpd.h>
#include <http_config.h>
#include <ap_config.h>
#include <apr_pools.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Per-<Directory>/<Location> dconf allocator + merger. */
void *bs_create_dir_cfg(apr_pool_t *p, char *path);
void *bs_merge_dir_cfg(apr_pool_t *p, void *base_v, void *add_v);

/* Per-server/<VirtualHost> scfg allocator + merger. */
void *bs_create_server_cfg(apr_pool_t *p, server_rec *s);
void *bs_merge_server_cfg(apr_pool_t *p, void *base_v, void *add_v);

/* Post-config hook: runs once after all directives parsed (in
 * parent, pre-fork). Returns OK on success, an HTTP_* code on
 * fatal init failure. Apache 2.4 invokes this twice on cold boot
 * — the first invocation is the syntax-check pass and is skipped
 * here. */
int bs_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                   apr_pool_t *ptemp, server_rec *s);

/* Per-worker init: attaches the worker to the SHM mutex inherited
 * from the parent. Idempotent (safe under graceful restart). */
void bs_child_init(apr_pool_t *p, server_rec *s);

/* mod_watchdog tick callbacks registered by post_config:
 *   - bs_state_save_watchdog_cb     → shm.h (pairs with bs_state_save)
 *   - bs_robots_watchdog_cb   → robots.h (pairs with bs_robots_load) */

/* --- Directive setters (feature-homeless) ---
 *
 * Setters whose configured fields aren't owned by a single feature
 * file. Top-level / UI / score / forgiveness / SHM-sizing / state-
 * save / rate-limit family / endpoint-prefix. Wired into the cmds[]
 * table in botshield.c. */

/* Top-level + UI */
const char *bs_set_enabled       (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_debug         (cmd_parms *cmd, void *cfg_v, int flag);
const char *bs_set_show_logo     (cmd_parms *cmd, void *cfg_v, int flag);
const char *bs_set_show_label    (cmd_parms *cmd, void *cfg_v, int flag);
const char *bs_set_show_box      (cmd_parms *cmd, void *cfg_v, int flag);
const char *bs_set_cookie_ttl    (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_difficulty    (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_form_captcha  (cmd_parms *cmd, void *cfg_v, int flag);
const char *bs_set_cookie_domain (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_prompt        (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_logo_label    (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_logo_file     (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_help          (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_help_file     (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_challenge(cmd_parms *cmd, void *cfg_v, int flag);
const char *bs_set_challenge_file(cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_endpoint_prefix(cmd_parms *cmd, void *cfg_v, const char *arg);

/* Score thresholds + forgiveness */
const char *bs_set_robots_mode   (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_access_log    (cmd_parms *cmd, void *cfg_v, int argc,
                                  char *const argv[]);
const char *bs_set_score_silent  (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_score_hard    (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_score_captcha (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_forgive_silent(cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_forgive_form  (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_forgive_captcha(cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_forgive_cap   (cmd_parms *cmd, void *dconf,  const char *arg);

/* SHM sizing + capacity + scoping */
const char *bs_set_shm_size           (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_flagged_capacity   (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_bloom_ips          (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_bloom_window       (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_ipv6_prefix        (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_share_scope        (cmd_parms *cmd, void *dconf, const char *arg);

/* State-save */
const char *bs_set_state_file         (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_state_save_interval(cmd_parms *cmd, void *dconf, const char *arg);

/* Rate-limit / safeguard family */
const char *bs_set_rate_limit            (cmd_parms *cmd, void *dconf,
                                          int argc, char *const argv[]);
const char *bs_set_rate_limit_escalate   (cmd_parms *cmd, void *dconf,
                                          int argc, char *const argv[]);
const char *bs_set_rate_escalate_capacity(cmd_parms *cmd, void *dconf,
                                          const char *arg);
const char *bs_set_scoring            (cmd_parms *cmd, void *dconf, int flag);
const char *bs_set_safeguard          (cmd_parms *cmd, void *dconf, int flag);
const char *bs_set_safeguard_threshold(cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_safeguard_window   (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_safeguard_ttl      (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_safeguard_redirect_url(cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_safeguard_capacity (cmd_parms *cmd, void *dconf, const char *arg);
const char *bs_set_nonce_capacity     (cmd_parms *cmd, void *dconf, const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_CONFIG_H */
