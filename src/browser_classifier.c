/* browser_classifier.c — strict-template browser UA classifier.
 *
 * normalize-and-compare:
 *   1. Walk the UA byte-by-byte into a stack buffer, copying each
 *      byte verbatim except runs of [0-9._]+ collapse to a single
 *      'X'. ~200-char UA in a few hundred ns.
 *   2. Test the normalized form for exact match against the active
 *      template set (compiled-in baseline or runtime override).
 *      Sequential strcmp at N≈23 templates is sub-microsecond.
 *
 * Anchored full-string match: a UA with anything appended fails to
 * match (extra bytes after Safari/X don't normalize away). This is
 * the explicit design property — "won't get tricked by additional
 * things being added."
 *
 * Same atomic-swap-with-one-tick-drain lifecycle as bot_directory.
 * Per-worker mod_watchdog ticks (singleton=0) so all worker
 * processes see the same active template set within one refresh
 * interval. */
#include "browser_classifier.h"
#include "botshield.h"

#include <string.h>

#include <apr_atomic.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <http_log.h>
#include <mod_watchdog.h>


/* --- Module-global active/pending state -------------------------- */

static bs_browser_templates_state *bs_browser_active  = NULL;
static bs_browser_templates_state *bs_browser_pending = NULL;


/* --- UA normalization -------------------------------------------- */

/* Replace runs of [0-9._]+ with a single 'X'. Writes into out
 * up to out_cap-1 bytes plus NUL. Returns 1 on success, 0 if the
 * normalized form would overflow out (in practice this means the
 * UA was unreasonably long; caller treats as "not a browser"). */
static int bs_browser_normalize(const char *ua, char *out, apr_size_t out_cap)
{
    if (!out_cap) return 0;
    apr_size_t w = 0;
    int in_version = 0;
    for (const char *p = ua; *p; p++) {
        unsigned char c = (unsigned char)*p;
        int is_version_byte = (c >= '0' && c <= '9') || c == '.' || c == '_';
        if (is_version_byte) {
            if (!in_version) {
                if (w + 1 >= out_cap) return 0;
                out[w++] = 'X';
                in_version = 1;
            }
            /* skip subsequent version bytes — collapsed into one X */
        } else {
            if (w + 1 >= out_cap) return 0;
            out[w++] = (char)c;
            in_version = 0;
        }
    }
    out[w] = '\0';
    return 1;
}


/* --- Lookup ------------------------------------------------------ */

int bs_ua_is_browser(const char *ua)
{
    if (!ua || !*ua) return 0;

    /* Stack buffer: 1024 covers every real-world browser UA
     * comfortably (top-100 max is ~210 chars). Anything longer is
     * almost certainly not a real browser; treating it as
     * "not-a-browser" is the right outcome. */
    char buf[1024];
    if (!bs_browser_normalize(ua, buf, sizeof(buf))) return 0;

    /* Atomic-load the active runtime override; fall back to baseline. */
    bs_browser_templates_state *st =
        __atomic_load_n(&bs_browser_active, __ATOMIC_ACQUIRE);

    const char *const *entries = st ? st->entries : bs_browser_templates;
    if (!entries) return 0;

    /* Sorted alphabetically — could bsearch, but at N≈23 sequential
     * strcmp wins on simplicity and is still sub-microsecond. */
    for (const char *const *e = entries; *e != NULL; e++) {
        if (strcmp(buf, *e) == 0) return 1;
    }
    return 0;
}


/* --- Templates file parser --------------------------------------- */

static char *bs_trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t'
                    || end[-1] == '\r' || end[-1] == '\n')) {
        end--;
    }
    *end = '\0';
    return s;
}

bs_browser_templates_state *bs_browser_templates_load(
    server_rec *s, const char *path, apr_pool_t *parent_pool)
{
    if (!path || !*path) return NULL;

    apr_pool_t *pool = NULL;
    if (apr_pool_create(&pool, parent_pool) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
            "mod_botshield: browser-templates: pool create failed");
        return NULL;
    }

    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, path,
                                    APR_READ | APR_BUFFERED,
                                    APR_OS_DEFAULT, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, s,
            "mod_botshield: browser-templates: cannot open %s "
            "(falling back to compiled-in baseline)", path);
        apr_pool_destroy(pool);
        return NULL;
    }

    apr_finfo_t finfo;
    apr_file_info_get(&finfo, APR_FINFO_MTIME, f);

    apr_array_header_t *rows = apr_array_make(pool, 32, sizeof(char *));

    char line[2048];
    while (apr_file_gets(line, sizeof(line), f) == APR_SUCCESS) {
        char *trimmed = bs_trim(line);
        if (!*trimmed || *trimmed == '#') continue;
        *(char **)apr_array_push(rows) = apr_pstrdup(pool, trimmed);
    }
    apr_file_close(f);

    if (rows->nelts == 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
            "mod_botshield: browser-templates %s parsed to zero "
            "entries; ignoring (compiled-in baseline stays active)",
            path);
        apr_pool_destroy(pool);
        return NULL;
    }

    /* Append NULL sentinel for the lookup loop. */
    *(char **)apr_array_push(rows) = NULL;

    bs_browser_templates_state *st = apr_pcalloc(pool, sizeof(*st));
    st->pool         = pool;
    st->entries      = (const char *const *)rows->elts;
    st->count        = (apr_size_t)(rows->nelts - 1);
    st->source_mtime = finfo.mtime;
    st->source_path  = apr_pstrdup(pool, path);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
        "mod_botshield: browser-templates loaded %s "
        "(%" APR_SIZE_T_FMT " templates)", path, st->count);
    return st;
}


/* --- Atomic publish + drain -------------------------------------- */

void bs_browser_templates_publish(server_rec *s,
                                  bs_browser_templates_state *new_state)
{
    bs_browser_templates_state *to_destroy = bs_browser_pending;
    bs_browser_pending = NULL;

    bs_browser_templates_state *prior = __atomic_exchange_n(
        &bs_browser_active, new_state, __ATOMIC_ACQ_REL);

    bs_browser_pending = prior;

    if (to_destroy) {
        apr_pool_destroy(to_destroy->pool);
    }

    if (s) {
        if (new_state) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                "mod_botshield: browser-templates active: %s "
                "(%" APR_SIZE_T_FMT " templates)",
                new_state->source_path, new_state->count);
        } else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                "mod_botshield: browser-templates: reverted to "
                "compiled-in baseline");
        }
    }
}


/* --- Watchdog ---------------------------------------------------- */

apr_status_t bs_browser_templates_watchdog_cb(int state, void *data,
                                              apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;

    server_rec *s = data;
    if (!s) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(s->module_config, &botshield_module);
    if (!scfg || !scfg->browser_templates_path) return APR_SUCCESS;

    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, scfg->browser_templates_path,
                               APR_FINFO_MTIME, s->process->pconf);
    if (rv != APR_SUCCESS) return APR_SUCCESS;

    bs_browser_templates_state *active =
        __atomic_load_n(&bs_browser_active, __ATOMIC_ACQUIRE);
    if (active && active->source_mtime == finfo.mtime) return APR_SUCCESS;

    bs_browser_templates_state *fresh = bs_browser_templates_load(
        s, scfg->browser_templates_path, s->process->pconf);
    if (!fresh) return APR_SUCCESS;

    bs_browser_templates_publish(s, fresh);
    return APR_SUCCESS;
}


/* --- Directive setters ------------------------------------------- */

const char *bs_set_browser_templates(cmd_parms *cmd, void *dconf,
                                     const char *path)
{
    (void)dconf;
    if (!path || !*path) {
        return "BotShieldBrowserTemplates: path required";
    }
    if (path[0] != '/') {
        return "BotShieldBrowserTemplates: path must be absolute";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->browser_templates_path = apr_pstrdup(cmd->pool, path);
    return NULL;
}

const char *bs_set_browser_templates_refresh_interval(cmd_parms *cmd,
                                                      void *dconf,
                                                      const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end || v < 0 || v > 86400) {
        return apr_psprintf(cmd->pool,
            "BotShieldBrowserTemplatesRefreshInterval: '%s' must be "
            "an integer 0..86400 seconds (0 = disable live refresh)",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->browser_templates_refresh_interval = (int)v;
    return NULL;
}
