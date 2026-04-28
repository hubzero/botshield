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

/* mod_watchdog callbacks registered by post_config. Defined in
 * botshield.c (where the rest of the request-path SHM machinery
 * they touch lives) and exposed here so post_config can pass them
 * to ap_watchdog_register_callback. */
apr_status_t bs_robots_watchdog_cb(int state, void *data,
                                   apr_pool_t *pool);
apr_status_t bs_watchdog_save_cb(int state, void *data,
                                 apr_pool_t *pool);

/* Stat + (conditionally) parse + atomic-publish the robots.txt
 * pointed to by scfg->robots_txt_path. Called both at post_config
 * (initial load) and from the watchdog callback (refresh). When
 * the source file's mtime is unchanged, it's a cheap no-op. */
apr_status_t bs_robots_load(server_rec *sv, struct bs_server_cfg *scfg,
                            apr_pool_t *pconf);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_CONFIG_H */
