/* browser_classifier.h — strict-template browser UA classifier.
 *
 * Returns 1 if a UA matches one of a curated set of "real browser"
 * templates (compiled-in baseline from data/top-user-agents.json,
 * optionally overridden at runtime by an operator-managed text file).
 * Returns 0 otherwise — used to flag UAs that look browser-shaped
 * but have extra trailing/inserted content (Mozilla-prefixed
 * scrapers, in-house tools, brand-new browsers not yet in the
 * top-100 list).
 *
 * Algorithm: normalize the UA by replacing runs of [0-9._]+ with a
 * single 'X', then test for exact match against the deduped set of
 * normalized templates from the top-100 list. Anchored full-string
 * match — appended tokens fail by design (the user explicitly wants
 * "won't get tricked by additional things being added").
 *
 * Trade-off: a brand-new browser entering the top-100 won't match
 * until the runtime templates file is refreshed. This is the
 * intentional consequence of strict matching; the runtime-refresh
 * shape (BotShieldBrowserTemplates + watchdog) bounds the
 * misclassification window to one refresh interval.
 *
 * Two-tier storage (mirrors bot_directory):
 *
 *   Compile-time baseline: src/generated_browser_templates.c
 *     (codegenned from data/top-user-agents.json at build).
 *     Always available; used when no runtime override is loaded.
 *
 *   Runtime override: text file at the path given by
 *     BotShieldBrowserTemplates. Re-parsed by a per-worker
 *     mod_watchdog tick on mtime change. Refresh via
 *     tools/refresh-top-user-agents.py without rebuilding the .so.
 */
#ifndef BOTSHIELD_BROWSER_CLASSIFIER_H
#define BOTSHIELD_BROWSER_CLASSIFIER_H

#include <apr.h>
#include <apr_pools.h>
#include <apr_time.h>
#include <httpd.h>
#include <http_config.h>   /* cmd_parms */

#ifdef __cplusplus
extern "C" {
#endif

/* One entry in the active template set: the normalized UA template
 * plus the browser-family slug ("chrome", "firefox", "edge", ...).
 * Both pointers are immutable for the entry's lifetime. */
typedef struct bs_browser_template {
    const char *normalized;
    const char *slug;
} bs_browser_template;

/* Generated baseline: NULL-terminated (entry with normalized==NULL)
 * array of templates, sorted alphabetically by `normalized`. Lifetime
 * is process. */
extern const bs_browser_template bs_browser_templates[];
extern const apr_size_t          bs_browser_templates_count;

/* Runtime override state. Loaded from a text file, owned by a
 * private pool whose lifetime extends one watchdog tick beyond
 * the swap. */
typedef struct bs_browser_templates_state {
    apr_pool_t                *pool;
    const bs_browser_template *entries;   /* NULL-normalized terminator */
    apr_size_t                 count;
    apr_time_t                 source_mtime;
    const char                *source_path;
} bs_browser_templates_state;

/* Internal: identify the browser family from a raw UA or a normalized
 * template. The family-identifying tokens (Edg/, OPR/, Chrome/,
 * Firefox/, etc.) don't contain digits/dots/underscores, so they
 * survive normalization unchanged — same call works for either input.
 * Used by the runtime-override loader to slug each parsed entry once
 * at load time. The codegen runs the same priority-ordered logic in
 * Python so compile-time templates carry their slug at link time
 * without needing this call. Returns a static-storage slug; never
 * returns NULL (falls back to "browser" generic). */
const char *bs_browser_family(const char *s);

/* Returns 1 if the UA matches a known browser template, 0
 * otherwise. NULL UA returns 0. Atomically loads the active
 * runtime-override state, falling back to the compiled-in baseline
 * if no override is loaded. Thin wrapper around bs_ua_browser_slug. */
int bs_ua_is_browser(const char *ua);

/* Returns a browser-family slug if the UA matches a curated template,
 * NULL otherwise. The slug is identified from distinctive tokens in
 * the UA (Chromium derivatives carry "Chrome/" but each ships its own
 * marker — Edg/, OPR/, EdgA/, SamsungBrowser/, Brave, YaBrowser/,
 * etc.) so we can tell Chrome-derived browsers apart from bare Chrome.
 *
 * Possible return values (static rodata; safe to store): "chrome",
 * "chrome-mobile", "chrome-ios", "firefox", "firefox-ios", "edge",
 * "edge-mobile", "edge-ios", "safari", "safari-mobile", "opera",
 * "opera-ios", "samsung", "brave", "duckduckgo", "yandex", "avg",
 * "avast", "adguard", "median", "obsidian", "scalboost",
 * "ios-webview", "browser" (fallback when template matched but no
 * family token recognized). NULL means "no template match" — caller
 * should treat as not-a-browser. */
const char *bs_ua_browser_slug(const char *ua);

/* Parse a templates file at `path` into a fresh state allocated
 * from a subpool of `parent_pool`. Returns NULL on any failure
 * (open, no usable templates) — caller leaves the current active
 * state in place.
 *
 * File format: one normalized template per line; blank lines and
 * comments (starting with '#') skipped. The refresh script writes
 * this format. */
bs_browser_templates_state *bs_browser_templates_load(
    server_rec *s,
    const char *path,
    apr_pool_t *parent_pool);

/* Atomically swap `new_state` in as the active runtime override.
 * Previously-active state is held one watchdog tick before its
 * pool is destroyed. Pass NULL to revert to the compiled-in
 * baseline. */
void bs_browser_templates_publish(server_rec *s,
                                  bs_browser_templates_state *new_state);

/* Watchdog tick callback. Registered with singleton=0 so each
 * worker child gets its own tick — the active pointer is process-
 * local, so per-worker ticks are required for updates to reach all
 * workers within one refresh interval. */
apr_status_t bs_browser_templates_watchdog_cb(int state, void *data,
                                              apr_pool_t *pool);

/* Setters wired into bs_cmds[]. */
const char *bs_set_browser_templates(cmd_parms *cmd, void *dconf,
                                     const char *path);
const char *bs_set_browser_templates_refresh_interval(cmd_parms *cmd,
                                                      void *dconf,
                                                      const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_BROWSER_CLASSIFIER_H */
