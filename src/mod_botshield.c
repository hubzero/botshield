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

#include <ctype.h>
#include <stdlib.h>

module AP_MODULE_DECLARE_DATA botshield_module;

/* Tri-state for flag directives: -1 = unset (inherit), 0 = off, 1 = on.
 * Integer directives use -1 to mean "inherit" too. */
#define BS_UNSET              (-1)
#define BS_DEFAULT_COOKIE_TTL 300   /* seconds a verified cookie is good for */
#define BS_DEFAULT_DIFFICULTY 4     /* leading hex zeros */
#define BS_CLOCK_SKEW_AHEAD   60    /* grace if client clock runs ahead */
#define BS_COOKIE_NAME        "_bs_verified"
#define BS_DEFAULT_PROMPT     "I\xe2\x80\x99m not a robot"   /* U+2019 */
#define BS_DEFAULT_LOGO_LABEL "botshield"
#define BS_MAX_LOGO_BYTES     (64 * 1024)
#define BS_MAX_HELP_BYTES     (64 * 1024)
#define BS_MAX_PAGE_BYTES     (256 * 1024)
#define BS_WIDGET_MARKER      "<!-- BOTSHIELD -->"

/* Help visibility modes (values are stored in bs_dir_cfg.help_mode). */
enum bs_help_mode {
    BS_HELP_OFF    = 0,  /* emit nothing */
    BS_HELP_ON     = 1,  /* always visible below the widget */
    BS_HELP_BUTTON = 2,  /* "?" link below widget; click to expand */
};
#define BS_DEFAULT_HELP_MODE BS_HELP_BUTTON

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

typedef struct {
    int enabled;
    int debug;
    int cookie_ttl;
    int difficulty;
    int help_mode;              /* BS_HELP_* or BS_UNSET */
    const char *prompt;         /* e.g. "I'm not a robot" */
    const char *logo_svg;       /* full SVG content, loaded at config time */
    const char *logo_label;     /* small caption under the logo */
    const char *help_html;      /* panel content, loaded at config time */
    const char *challenge_html; /* full HTML page template with marker */
} bs_dir_cfg;

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
    return cfg;
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
    out->prompt         = add->prompt         ? add->prompt         : base->prompt;
    out->logo_svg       = add->logo_svg       ? add->logo_svg       : base->logo_svg;
    out->logo_label     = add->logo_label     ? add->logo_label     : base->logo_label;
    out->help_html      = add->help_html      ? add->help_html      : base->help_html;
    out->challenge_html = add->challenge_html ? add->challenge_html : base->challenge_html;
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
                 "Seconds a verified cookie stays valid (default: 60)"),
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

/* --- Cookie parsing ---
 *
 * Scan the Cookie header for `_bs_verified=<digits>:<16-hex>` at a
 * name-boundary (so `other_bs_verified=` won't false-match). Returns 1 if a
 * well-formed cookie with a timestamp within the TTL window is found.
 *
 * When a cookie is present but invalid, logs an APLOG_INFO with the reason
 * so we can distinguish "no cookie" from "expired cookie" from "malformed
 * cookie" in live traffic — a necessity while the baseline is shaking out. */
static int bs_has_valid_cookie(request_rec *r, int ttl)
{
    const char *cookies = apr_table_get(r->headers_in, "Cookie");
    if (!cookies) return 0;

    static const char NAME[] = BS_COOKIE_NAME "=";
    const apr_size_t NLEN = sizeof(NAME) - 1;
    const char *p = cookies;
    const char *reject_reason = NULL;

    while ((p = strstr(p, NAME)) != NULL) {
        int at_boundary = (p == cookies) ||
                          (p[-1] == ';')  ||
                          (p[-1] == ' ')  ||
                          (p[-1] == '\t');
        if (!at_boundary) { p += NLEN; continue; }

        const char *v = p + NLEN;

        char *end = NULL;
        long ts = strtol(v, &end, 10);
        if (end == v || *end != ':' || ts <= 0) {
            reject_reason = "malformed timestamp"; p += NLEN; continue;
        }

        const char *hex = end + 1;
        int i;
        for (i = 0; i < 16; i++) {
            if (!isxdigit((unsigned char)hex[i])) break;
        }
        if (i != 16) {
            reject_reason = "hash not 16 hex chars"; p += NLEN; continue;
        }

        char term = hex[16];
        if (term != '\0' && term != ';' && term != ' ' && term != '\t') {
            reject_reason = "unexpected trailing char"; p += NLEN; continue;
        }

        apr_time_t now_sec = apr_time_sec(apr_time_now());
        long delta = (long)now_sec - ts;
        if (delta > ttl) {
            reject_reason = apr_psprintf(r->pool,
                "expired (cookie is %lds old, ttl=%ds)", delta, ttl);
            p += NLEN; continue;
        }
        if (delta < -BS_CLOCK_SKEW_AHEAD) {
            reject_reason = apr_psprintf(r->pool,
                "timestamp from the future (%lds ahead)", -delta);
            p += NLEN; continue;
        }

        return 1;
    }

    if (reject_reason) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_botshield: " BS_COOKIE_NAME
                      " rejected: %s", reject_reason);
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
"<div class=\"bs-widget\" id=\"c\">\n"
" <button type=\"button\" class=\"bs-btn\" id=\"btn\"\n"
"         aria-describedby=\"msg\">\n"
"  <span class=\"bs-check\" id=\"cb\" aria-hidden=\"true\"></span>\n"
"  <span class=\"bs-label\">%s</span>\n"
" </button>\n"
" <div class=\"bs-brand\" aria-hidden=\"true\">\n"
"  %s\n"
"  <span class=\"nm\">%s</span>\n"
" </div>\n"
"</div>\n"
"%s"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script>\n"
"(function(){\n"
" var DIFFICULTY = %d;\n"
" var COOKIE_TTL = %d;\n"
" var COOKIE_NAME = '" BS_COOKIE_NAME "';\n"
" var box = document.getElementById('c');\n"
" var msg = document.getElementById('msg');\n"
" var btn = document.getElementById('btn');\n"
" btn.addEventListener('click', function h(e){\n"
"  if(!e.isTrusted) return;\n"
"  btn.removeEventListener('click', h);\n"
"  box.className = 'bs-widget bs-working';\n"
"  btn.setAttribute('aria-disabled', 'true');\n"
"  startChallenge();\n"
" });\n"
" function startChallenge(){\n"
"  var prefix = new Array(DIFFICULTY+1).join('0');\n"
"  var enc = new TextEncoder();\n"
"  var fp = [screen.width,screen.height,screen.colorDepth,\n"
"            navigator.language,new Date().getTimezoneOffset(),\n"
"            navigator.hardwareConcurrency||0].join('|');\n"
"  var salt = Math.floor(Date.now()/1000) + ':' + fp;\n"
"  var nonce = 0;\n"
"  var BATCH = 2048;\n"
"  var t0 = Date.now();\n"
"  msg.textContent = 'Verifying\\u2026';\n"
"  function doBatch(){\n"
"   var promises = [];\n"
"   var start = nonce;\n"
"   for (var i=0; i<BATCH; i++){\n"
"    promises.push(crypto.subtle.digest('SHA-256',\n"
"                   enc.encode(salt + ':' + (start+i))));\n"
"   }\n"
"   Promise.all(promises).then(function(results){\n"
"    for (var i=0; i<results.length; i++){\n"
"     var a = new Uint8Array(results[i]);\n"
"     var hex = '';\n"
"     for (var j=0; j<8; j++){\n"
"      hex += ('0'+a[j].toString(16)).slice(-2);\n"
"     }\n"
"     if (hex.substring(0, DIFFICULTY) === prefix){\n"
"      finish(hex); return;\n"
"     }\n"
"    }\n"
"    nonce = start + BATCH;\n"
"    var elapsed = ((Date.now()-t0)/1000).toFixed(1);\n"
"    msg.textContent = 'Verifying\\u2026 (' + nonce.toLocaleString() +\n"
"                      ' hashes, ' + elapsed + 's)';\n"
"    setTimeout(doBatch, 0);\n"
"   }).catch(function(err){\n"
"    msg.textContent = 'Verification failed: ' + (err && err.message || err);\n"
"   });\n"
"  }\n"
"  function finish(hex){\n"
"   box.className = 'bs-widget bs-done';\n"
"   msg.textContent = 'Verified \\u2014 reloading\\u2026';\n"
"   var tsNow = Math.floor(Date.now()/1000);\n"
"   var exp = new Date(Date.now() + COOKIE_TTL*1000).toUTCString();\n"
"   var secure = (location.protocol === 'https:') ? '; Secure' : '';\n"
"   document.cookie = COOKIE_NAME + '=' + tsNow + ':' + hex +\n"
"                     '; Path=/; Expires=' + exp +\n"
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

    if (bs_has_valid_cookie(r, ttl)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_botshield: verified cookie, passing %s", r->uri);
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "mod_botshield: challenging %s (difficulty=%d, ttl=%d)",
                  r->unparsed_uri, difficulty, ttl);

    const char *prompt     = cfg->prompt     ? cfg->prompt     : BS_DEFAULT_PROMPT;
    const char *logo_svg   = cfg->logo_svg   ? cfg->logo_svg   : BS_DEFAULT_LOGO_SVG;
    const char *logo_label = cfg->logo_label ? cfg->logo_label : BS_DEFAULT_LOGO_LABEL;
    int help_mode = bs_effective_int(cfg->help_mode, BS_DEFAULT_HELP_MODE);
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

    /* Render the widget block once, then splice it into the page shell at
     * BS_WIDGET_MARKER. The shell is either the admin's BotShieldChallengeFile
     * or our built-in default — same splice code path either way. */
    char *widget = apr_psprintf(r->pool, BS_WIDGET_TEMPLATE,
                                ap_escape_html(r->pool, prompt),
                                logo_svg,
                                ap_escape_html(r->pool, logo_label),
                                help_html,
                                difficulty, ttl);

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
