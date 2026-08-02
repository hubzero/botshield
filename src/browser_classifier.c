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
/* In-place collapse of device-varying tokens. See the call site in
 * bs_browser_normalize for why. Both rewrites shrink the string, so
 * they can never overflow. */
static void bs_browser_collapse_device(char *s, apr_size_t cap)
{
    (void)cap;
    /* "Android X; <device>)" -> "Android X; D)" */
    char *a = strstr(s, "Android X; ");
    if (a) {
        char *dev = a + sizeof("Android X; ") - 1;
        char *close = strchr(dev, ')');
        if (close && close > dev) {
            *dev++ = 'D';
            memmove(dev, close, strlen(close) + 1);
        }
    }
    /* "Mobile/<build>" -> "Mobile/B"  (build is the alnum run) */
    char *m = strstr(s, "Mobile/");
    if (m) {
        char *b = m + sizeof("Mobile/") - 1;
        char *e = b;
        while (*e && (((*e >= '0' && *e <= '9')
                    || (*e >= 'A' && *e <= 'Z')
                    || (*e >= 'a' && *e <= 'z')))) e++;
        if (e > b) {
            *b++ = 'B';
            memmove(b, e, strlen(e) + 1);
        }
    }
}

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

    /* Second pass: collapse two tokens that vary per *device* rather
     * than per browser build. Digit-masking alone cannot reach them
     * because they are alphabetic.
     *
     *   "Android X; SM-SXB)"  ->  "Android X; D)"
     *   "Mobile/XEX"          ->  "Mobile/B"
     *
     * Android device models are effectively unbounded -- thousands of
     * model strings -- so no template list can enumerate them, and a
     * genuine phone that sends a real model (rather than Chrome's
     * frozen "K") would never match. Same for the iOS build token,
     * which carries a letter and so survives digit-masking.
     *
     * Deliberately biased toward over-matching. A scraper that
     * hand-builds a browser-shaped UA now classifies as a browser and
     * gets challenged -- which it cannot solve. A real phone that
     * failed to classify got treated as a crawler candidate and, with
     * robots.txt wildcard rules on, was refused outright with no
     * challenge to solve. The first error costs nothing; the second
     * locks a user out.
     *
     * Kept narrow on purpose: both rewrites are anchored to a literal
     * prefix, so a UA without that prefix is untouched. In particular
     * bot UAs that append "(compatible; <bot>/X; +url)" after the
     * browser-shaped part still fail the exact-match and fall through
     * to the bot-directory pass. */
    bs_browser_collapse_device(out, out_cap);
    return 1;
}


/* --- Family slug detection ---------------------------------------- *
 *
 * The codegen pre-computes the family slug for every compile-time
 * template (gen-browser-templates.py runs the same priority-ordered
 * substring detection in Python at build time). At request time the
 * lookup just returns entry->slug — zero strstr.
 *
 * This function exists for the runtime-override loader: the override
 * file ships normalized templates only, so the loader runs this once
 * per entry at load time and stashes the result on the struct.
 *
 * Order matters: Chromium derivatives (Edge, Opera, Brave, Samsung,
 * etc.) carry "Chrome/" in their UA, so they must be detected by
 * their distinguishing token first. Most-specific tokens win.
 *
 * Operates on either the raw UA or the normalized template — the
 * family-identifying tokens (Edg/, OPR/, Chrome/, etc.) don't contain
 * digits/dots/underscores, so they survive normalization unchanged. */
const char *bs_browser_family(const char *s)
{
    if (!s) return "browser";

    /* Chromium derivatives identified by their distinctive token. */
    if (strstr(s, "EdgA/"))             return "edge-mobile";
    if (strstr(s, "EdgiOS/"))           return "edge-ios";
    if (strstr(s, "Edg/"))              return "edge";
    if (strstr(s, "OPiOS/"))            return "opera-ios";
    if (strstr(s, "OPR/"))              return "opera";
    if (strstr(s, "SamsungBrowser/"))   return "samsung";
    if (strstr(s, "Brave"))             return "brave";
    if (strstr(s, "YaBrowser/"))        return "yandex";
    if (strstr(s, "Ddg/"))              return "duckduckgo";
    if (strstr(s, "AVG/"))              return "avg";
    if (strstr(s, "Avast/"))            return "avast";
    if (strstr(s, "ADG/"))              return "adguard";
    if (strstr(s, "median"))            return "median";
    if (strstr(s, "obsidian"))          return "obsidian";
    if (strstr(s, "ScalboostBrowser/")) return "scalboost";
    if (strstr(s, "CriOS/"))            return "chrome-ios";
    if (strstr(s, "FxiOS/"))            return "firefox-ios";

    /* Engine-based identification — Firefox before Chrome since
     * Gecko UAs don't carry "Chrome/" but the reverse isn't true. */
    if (strstr(s, "Firefox/"))          return "firefox";

    if (strstr(s, "Chrome/")) {
        return strstr(s, "Mobile") ? "chrome-mobile" : "chrome";
    }

    /* Safari: Version/+Safari/ token combo. iOS variants carry Mobile/. */
    if (strstr(s, "Safari/")) {
        return strstr(s, "Mobile/") ? "safari-mobile" : "safari";
    }

    /* iOS WebView — Mobile/ token without Safari/. */
    if (strstr(s, "Mobile/"))           return "ios-webview";

    /* Template matched but didn't fit any family bucket. Generic. */
    return "browser";
}


/* --- Lookup ------------------------------------------------------ */

const char *bs_ua_browser_slug(const char *ua)
{
    if (!ua || !*ua) return NULL;

    /* Stack buffer: 1024 covers every real-world browser UA
     * comfortably (top-100 max is ~210 chars). Anything longer is
     * almost certainly not a real browser; treating it as
     * "not-a-browser" is the right outcome. */
    char buf[1024];
    if (!bs_browser_normalize(ua, buf, sizeof(buf))) return NULL;

    /* Atomic-load the active runtime override; fall back to baseline. */
    bs_browser_templates_state *st =
        __atomic_load_n(&bs_browser_active, __ATOMIC_ACQUIRE);

    const bs_browser_template *entries = st ? st->entries : bs_browser_templates;
    if (!entries) return NULL;

    /* Sorted alphabetically — could bsearch, but at N≈23 sequential
     * strcmp wins on simplicity and is still sub-microsecond. */
    for (const bs_browser_template *e = entries; e->normalized != NULL; e++) {
        if (strcmp(buf, e->normalized) == 0) return e->slug;
    }
    return NULL;
}

int bs_ua_is_browser(const char *ua)
{
    return bs_ua_browser_slug(ua) != NULL;
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

    apr_array_header_t *rows =
        apr_array_make(pool, 32, sizeof(bs_browser_template));

    char line[2048];
    while (apr_file_gets(line, sizeof(line), f) == APR_SUCCESS) {
        char *trimmed = bs_trim(line);
        if (!*trimmed || *trimmed == '#') continue;
        /* Format: <normalized template>\t<slug>. The slug column is
         * optional for backward compatibility — older files (and any
         * hand-written entries) get auto-slugged via the family
         * function at load time. The family-identifying tokens
         * (Edg/, OPR/, Chrome/, ...) don't contain digits/dots/
         * underscores so they survive normalization unchanged. */
        bs_browser_template *e = apr_array_push(rows);
        char *tab = strchr(trimmed, '\t');
        if (tab) {
            *tab = '\0';
            e->normalized = apr_pstrdup(pool, trimmed);
            char *slug = bs_trim(tab + 1);
            e->slug = (slug && *slug)
                    ? apr_pstrdup(pool, slug)
                    : bs_browser_family(e->normalized);
        } else {
            e->normalized = apr_pstrdup(pool, trimmed);
            e->slug       = bs_browser_family(e->normalized);
        }
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

    /* Append NULL-normalized sentinel for the lookup loop. */
    bs_browser_template *sentinel = apr_array_push(rows);
    sentinel->normalized = NULL;
    sentinel->slug       = NULL;

    bs_browser_templates_state *st = apr_pcalloc(pool, sizeof(*st));
    st->pool         = pool;
    st->entries      = (const bs_browser_template *)rows->elts;
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
