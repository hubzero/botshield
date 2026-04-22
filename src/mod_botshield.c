/*
 * mod_botshield — tiered bot detection and challenge module for Apache 2.4.
 *
 * This is the skeleton: module registration, per-directory config, and a
 * request handler that — when BotShieldDebug is set — short-circuits every
 * request with a 403 "Hello World" response. The scoring engine, PoW
 * challenges, SHM scoreboard, and Bloom filter all layer on top later.
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

module AP_MODULE_DECLARE_DATA botshield_module;

/* Tri-state for flag directives: -1 = unset (inherit), 0 = off, 1 = on. */
#define BS_UNSET (-1)

typedef struct {
    int enabled;
    int debug;
} bs_dir_cfg;

/* --- Config lifecycle --- */

static void *bs_create_dir_cfg(apr_pool_t *p, char *path)
{
    (void)path;
    bs_dir_cfg *cfg = apr_pcalloc(p, sizeof(*cfg));
    cfg->enabled = BS_UNSET;
    cfg->debug   = BS_UNSET;
    return cfg;
}

static void *bs_merge_dir_cfg(apr_pool_t *p, void *base_v, void *add_v)
{
    bs_dir_cfg *base = base_v;
    bs_dir_cfg *add  = add_v;
    bs_dir_cfg *out  = apr_pcalloc(p, sizeof(*out));
    out->enabled = (add->enabled == BS_UNSET) ? base->enabled : add->enabled;
    out->debug   = (add->debug   == BS_UNSET) ? base->debug   : add->debug;
    return out;
}

/* --- Directive setters --- */

static const char *bs_set_enabled(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    bs_dir_cfg *cfg = cfg_v;
    cfg->enabled = flag ? 1 : 0;
    return NULL;
}

static const char *bs_set_debug(cmd_parms *cmd, void *cfg_v, int flag)
{
    (void)cmd;
    bs_dir_cfg *cfg = cfg_v;
    cfg->debug = flag ? 1 : 0;
    return NULL;
}

static const command_rec bs_cmds[] = {
    AP_INIT_FLAG("BotShieldEnabled", bs_set_enabled, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Turn mod_botshield on/off for the enclosing scope "
                 "(default: off)"),
    AP_INIT_FLAG("BotShieldDebug",   bs_set_debug,   NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "If on, return 403 'Hello World' for every request in "
                 "the enclosing scope (default: off)"),
    { NULL }
};

/* --- Request handler ---
 *
 * Registered at APR_HOOK_FIRST so we run before the default static-file
 * handler. When debug mode is active we emit our own body and set
 * r->status; returning OK tells Apache to use our response as-is rather
 * than substitute its stock 403 ErrorDocument.
 */

static int bs_handler(request_rec *r)
{
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    if (!cfg || cfg->enabled != 1 || cfg->debug != 1) {
        return DECLINED;
    }

    /* Let sub-requests (ErrorDocument, SSI includes, etc.) pass through
     * untouched — otherwise a 403 here could recurse into another 403. */
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "mod_botshield: debug mode — forcing 403 for %s",
                  r->unparsed_uri);

    r->status = HTTP_FORBIDDEN;
    ap_set_content_type(r, "text/plain; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->err_headers_out, "X-Botshield", "debug-403");
    ap_rputs("Hello World\n", r);
    return OK;
}

/* --- Hook registration --- */

static void bs_register_hooks(apr_pool_t *p)
{
    (void)p;
    ap_hook_handler(bs_handler, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(botshield) = {
    STANDARD20_MODULE_STUFF,
    bs_create_dir_cfg,    /* per-directory config creator */
    bs_merge_dir_cfg,     /* per-directory config merger  */
    NULL,                 /* per-server config creator    */
    NULL,                 /* per-server config merger     */
    bs_cmds,              /* config directives            */
    bs_register_hooks,    /* hook registration            */
    AP_MODULE_FLAG_NONE   /* flags                        */
};
