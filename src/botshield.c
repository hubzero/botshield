/*
 * mod_botshield — tiered bot detection and challenge module for Apache 2.4.
 *
 * Module entry surface. This file hosts:
 *   - bs_handler              : the ap_hook_handler request entry
 *   - cmds[]                  : the directive table Apache reads at config
 *   - bs_register_hooks       : ap_hook_post_config / child_init / handler /
 *                               fixups + input-filter registrations
 *   - botshield_module        : the apr module struct (extern symbol Apache
 *                               resolves via dlsym at LoadModule time)
 *   - bs_robots_load          : the robots.txt loader called both from
 *                               post_config and the mod_watchdog tick
 *   - policy dump             : httpd -t -D DUMP_BOTSHIELD_POLICY
 *                               text dump
 *
 * Everything else fans out through the per-feature .h includes below.
 * Each subsystem owns its runtime, its directive setters, and its tests.
 *
 * Operator model. Four tiers, decided per request from a running score:
 *   pass     no challenge, real handler runs
 *   noninteractive  embedded noninteractive tier verification (E17) or auto-submit splash
 *   form     visible interactive PoW interstitial — a checkbox the JS solves
 *   captcha  third-party provider widget (Turnstile, hCaptcha, reCAPTCHA,
 *            Friendly, GeeTest) on the M8 verify endpoint
 *
 * The tier-earned cookie (_bs_session or __Host-bs_session, AES-GCM
 * envelope) carries forward across requests, with a forgiveness-window
 * cap so a one-time solve doesn't whitewash a flagged client forever.
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
#include "bot_directory.h" /* knownbot UA classifier (Cloudflare directory) */
#include "bot_rate.h" /* slug-keyed bot rate limit */
#include "browser_classifier.h" /* strict-template browser UA classifier */
#include "ua_class.h"     /* unified UA classifier (browser/known/verified/fake) */
#include "metrics.h"   /* M9 — decision log, counters, Prometheus, mod_status */
#include "botshield.h" /* module-wide types: bs_dir_cfg, bs_server_cfg, ... */
#include "config.h"    /* module-config lifecycle (create/merge/post/child) */
#include "cookie.h"    /* GCM cookie envelope mint/verify, Cookie-header parser */
#include "challenge.h" /* M7 — challenge issuance, alg registry, bootstrap-sig */
#include "load.h"      /* E11 — load-aware throttling watchdog + state read */
#include "triggers.h"  /* E3/E4/E6/E7.3/E11.2 — trigger families */
#include "non_interactive.h"    /* E17 — noninteractive tier embedded handlers */
#include "captcha.h"   /* M8 — provider registry, siteverify, pending cookie */
#include "bridge.h"    /* E5 + E8.2 — module ↔ app feedback / claims bridge */
#include "templates.h" /* challenge page widget + shell rendering */
#include "formcaptcha.h" /* E18 — inline form-captcha tier */
#include "score.h"     /* per-request score + flagtrigger walker */
#include "policy.h"    /* request-time policy walker */
#include "heuristics.h" /* cheap built-in score signals */

/* This file is the module's hooks-table spine: bs_handler (the
 * request entry hook), the cmds[] directive table, bs_register_hooks,
 * and the botshield_module struct. Plus a few thin helpers that
 * bs_handler calls directly (bs_tier_name, the
 * bounded numeric parsers). Every other concern fans out through the
 * per-feature includes above. */

/* Character policy for bot-name tokens: lowercase letters, digits,
 * hyphen. Used as the hash key and the default ranges-file basename.
 * Rejects anything that could create path-traversal surprises or
 * cross-host confusion. Lives here because the rate-limit, block-
 * path, allowlist, and triggers setters scattered across other
 * files all reuse it via the cross-file decl in botshield.h. */
int bs_bot_name_valid(const char *s)
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

















/* Container entry points. Each is three lines because bs_open_trigger
 * carries the work; what differs between families is only which setter
 * receives the tokens it builds. */

static const char *bs_open_trigger(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldTrigger", bs_set_trigger);
}

static const char *bs_open_flagtrigger(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldFlagTrigger", bs_set_flag_trigger);
}

static const char *bs_open_cookietrigger(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldCookieTrigger", bs_set_cookie_trigger);
}

static const char *bs_open_envtrigger(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldEnvTrigger", bs_set_env_trigger);
}

static const char *bs_open_feedbacktrigger(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldFeedbackTrigger", bs_set_feedback_trigger);
}

static const char *bs_open_loadtrigger(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldLoadTrigger", bs_set_load_trigger);
}

static const char *bs_open_match(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldMatch", bs_set_match_set);
}

static const char *bs_open_rule(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    return bs_section_trigger(cmd, dconf, arg, "BotShieldRule", bs_set_request_trigger);
}

static const char *bs_open_requesttrigger(cmd_parms *cmd, void *dconf,
                                          const char *arg)
{
    /* Deprecated spelling of <BotShieldRule>. Same setter, same parser,
     * same entry type -- the family stopped being about
     * requests-versus-something-else once it grew ua=, ipspec=, query=,
     * cookies=, exists=, solved= and minload=.
     *
     * Warns rather than fails, and will fail later. A config error is
     * fatal to httpd, and this name is still in live configs; taking a
     * site down at the next restart is not an acceptable way to
     * announce a rename. BotShieldPathTrigger got the same treatment --
     * renamed 2026-08-01, removed 2026-08-10 -- and that is the
     * sequence being followed here. */
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
        "mod_botshield: <BotShieldRequestTrigger> is deprecated and "
        "will be removed; rename these blocks to <BotShieldRule>. "
        "Same directive and same behaviour -- only the spelling "
        "differs.");
    return bs_section_trigger(cmd, dconf, arg, "BotShieldRequestTrigger", bs_set_request_trigger);
}

static const command_rec bs_cmds[] = {
    AP_INIT_TAKE1("BotShieldEnabled",   bs_set_enabled,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Mode for the enclosing scope: On (enforce), Off (disabled), "
                 "or LogOnly (observe-only — log decisions without acting). "
                 "Default: Off"),
    AP_INIT_FLAG("BotShieldChallenge", bs_set_challenge, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Whether this scope may render a challenge. Default On. "
                 "Off collapses any selected tier back to pass: triggers, "
                 "rate limits and scoring all still run and still log, but "
                 "no interstitial, form or captcha is ever served. Use it "
                 "for a block-only scope, where an explicit respond=4xx "
                 "trigger is meant to be the only action. Parking "
                 "BotShieldScoreNonInteractive/Hard/Captcha at 10000 is NOT "
                 "equivalent: a flag tier_floor is MAXed in after the "
                 "score-to-tier decision and ignores thresholds entirely, "
                 "so an IP carrying honeypot_hit, fake_bot, scanner_probe "
                 "or pow_fail_streak would still be challenged. This is "
                 "applied after the floor, so it holds. Suppression shows "
                 "in the decision log as challengeoff:<tier>."),
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
    AP_INIT_TAKE1("BotShieldInteractiveArmMs",
                 bs_set_interactive_arm_ms, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Withhold the interactive tier's checkbox for this "
                 "many milliseconds after the page loads (default: "
                 "300; 0 shows it immediately). The widget renders at "
                 "full size with a spinner meanwhile, so nothing "
                 "shifts and there is no dead control to click. Two "
                 "effects: the earliest legitimate submit becomes "
                 "window+reaction as a fact rather than a guess, and a "
                 "click landing within a few ms of the reveal is "
                 "reported as an attestation failure -- a person's "
                 "click scatters, a poller's does not. 100 is a good "
                 "production value: below the threshold where a delay "
                 "is perceived, while the gap signal is unaffected."),
    AP_INIT_TAKE1("BotShieldInteractiveMinSolveMs",
                 bs_set_interactive_min_ms, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Reject an interactive-tier solve that returns sooner "
                 "than this many milliseconds after the challenge was "
                 "issued (default: 400; 0 disables). The clock is the "
                 "server's -- the issue stamp is covered by the "
                 "bootstrap HMAC -- so a client cannot shorten it. "
                 "Measured, not guessed: a warmed headless browser "
                 "needed 177ms to load, render and land a trusted "
                 "click, and a person needs several hundred more to "
                 "notice the widget and reach it. Does not stop a bot "
                 "that sleeps; makes sleeping cost real wall time per "
                 "request. Raise it if your pages are heavy, lower or "
                 "disable it if legitimate clients are being refused "
                 "(look for reason=solve_too_fast)."),
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
                 "Proof-of-work algorithm name. Only 'sha256zeros' is built "
                 "into this module today; 'sha384-zeros' / 'sha512-zeros' / "
                 "'pbkdf2-sha256' / 'argon2id' are registry slots reserved "
                 "for future opt-in builds."),
    /* One directive per observability endpoint. The directive name
     * says which endpoint it opens, so there is no first-token-is-
     * sometimes-a-surface rule to learn, and a new surface added later
     * cannot inherit a grant written before it existed. */
    AP_INIT_TAKE_ARGV("BotShieldDashboardAccess", bs_set_dashboard_access,
                 NULL, RSRC_CONF,
                 "Who may read the dashboard pages. Closed until this "
                 "names someone; refused requests get 404. Arguments are "
                 "IPv4/IPv6 addresses or CIDR blocks, or the single "
                 "keyword 'all' (serve to everyone) or 'none' (close, "
                 "and refuse a grant inherited from server scope). "
                 "Directives accumulate. Matches the same client address "
                 "the module scores, so mod_remoteip applies. For "
                 "passwords or anything richer, wrap the path in a "
                 "<Location> as well -- this only decides whether the "
                 "endpoint is served at all."),
    AP_INIT_TAKE_ARGV("BotShieldMetricsAccess", bs_set_metrics_access,
                 NULL, RSRC_CONF,
                 "Who may read /metrics. Closed until this names "
                 "someone; refused requests get 404. Same argument form "
                 "as BotShieldDashboardAccess."),
    AP_INIT_TAKE_ARGV("BotShieldChallengeAtLeast", bs_set_challenge_at_least,
                 NULL, RSRC_CONF | ACCESS_CONF,
                 "<name> <n> <tier> -- floor the tier at <tier> when the "
                 "named per-request accumulator (BotShieldScore) has "
                 "reached <n>. Evaluated with the score-to-tier decision, "
                 "after robots and rate limiting, so a request refused "
                 "there is never challenged instead. Rows MAX against "
                 "each other and against flag and rule tier floors."),
    AP_INIT_TAKE_ARGV("BotShieldAdminAccess", bs_set_admin_access,
                 NULL, RSRC_CONF,
                 "Who may clear flagged addresses via POST to "
                 "<prefix>/admin/unflag. Closed until this names "
                 "someone; refused requests get 404. Same argument form "
                 "as BotShieldDashboardAccess. Unlike the other two "
                 "this grants a write, so it is deliberately not "
                 "covered by either read grant."),
    AP_INIT_TAKE_ARGV("BotShieldAccessLog", bs_set_access_log, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Control the Apache access-log line for requests "
                 "BotShield decided on. 'on' (default) logs normally; "
                 "'off' suppresses every decided outcome; "
                 "'suppress=<outcome[,outcome...]>' suppresses only "
                 "those, e.g. suppress=challenged,block. Outcome names "
                 "are the decision-log vocabulary: allow, challenged, "
                 "verified, block, failopen, rate_limited, "
                 "inflight_capped, pending_missing, misconfigured, "
                 "debug, redirect. Scope-level and keyed on the "
                 "decision, so it covers challenges raised by the "
                 "scoring defaults - unlike the per-rule "
                 "accesslog=on|off action key, which only covers "
                 "requests that rule's predicate matched. Under "
                 "LogOnly a counterfactual (~block) is NOT suppressed: "
                 "nothing was enforced and the origin answered, so it "
                 "is ordinary traffic. Requests BotShield never "
                 "evaluated always log."),
    /* E18 — inline form captcha. */
    AP_INIT_FLAG("BotShieldFormCaptcha", bs_set_form_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "When on, this scope validates a configured captcha "
                 "provider's response token in the POST body of form "
                 "submissions. Requires BotShieldCaptchaProvider + "
                 "SiteKey + SecretFile in the same scope (or "
                 "inherited). On valid token: mints _bs_session, "
                 "DECLINED so the app handler runs with the original "
                 "body intact. On bad/missing token: 403, app handler "
                 "never runs. Supports application/x-www-form-"
                 "urlencoded and application/json bodies; "
                 "multipart/form-data (file uploads) is out of scope."),
    /* Silent-tier dispatch flavor. */
    AP_INIT_TAKE1("BotShieldNonInteractiveMode", bs_set_non_interactive_mode, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "How to dispatch noninteractive tier (low-friction) "
                 "challenges. 'interstitial' (default) = legacy M7 "
                 "auto-submit splash. 'embedded' = serve real page "
                 "(DECLINED) and rely on the operator-included "
                 "/botshield/embedded.js wrapper to do PoW in a Web "
                 "Worker and POST the result back to "
                 "/botshield/embedded-verify. The verified cookie "
                 "may not arrive in time for the very first request, "
                 "but it lands within a few page-views — see CHANGELOG "
                 "E17 for the timing model."),
    AP_INIT_TAKE1("BotShieldForgivenessNonInteractive", bs_set_forgive_non_interactive, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful noninteractive PoW pass "
                 "(default: 10). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessInteractive",   bs_set_forgive_interactive,   NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful interactive PoW pass "
                 "(default: 25). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessCaptcha",bs_set_forgive_captcha,NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful captcha pass "
                 "(default: 50). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldCookieDomain", bs_set_cookie_domain, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "If set, Set-Cookie for _bs_session includes a Domain= "
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
                 "Total shared-memory budget for the flagged-IP / strike "
                 "/ safeguard tables and the Bloom filter. Accepts "
                 "K/M/G suffixes. Default: 16M. Range: 128K..256M."),
    AP_INIT_TAKE1("BotShieldForgetIPAfter", bs_set_forget_ip_after, NULL,
                 RSRC_CONF,
                 "Seconds an address stays flagged, counted from its "
                 "LAST flagging rather than its first -- so an address "
                 "that keeps tripping rules stays flagged, and one that "
                 "stops is forgotten this long afterwards. Server scope "
                 "because the address slot holds a single expiry shared "
                 "by every flag on it. Flags are advisory: the table "
                 "evicts under pressure, so one may lapse early. "
                 "Default: 3600. Range: 1..2592000."),
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
    AP_INIT_TAKE1("BotShieldDataDir", bs_set_data_dir, NULL,
                 RSRC_CONF,
                 "Directory holding this instance's own files: the "
                 "auto-generated cookie secret and the persistent "
                 "state. Absolute path; default /var/lib/botshield. "
                 "Created at startup and owned by the Apache user. Give "
                 "each httpd instance on a host its own, or they share "
                 "both files -- and a shared cookie secret means one "
                 "instance invalidates the other's cookies."),
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
    AP_INIT_RAW_ARGS("<BotShieldTrigger", bs_open_trigger, NULL, RSRC_CONF | ACCESS_CONF,
                 "Open a BotShieldTrigger block. Takes the rule name; every "
                 "setting is a BotShield directive on its own line "
                 "until </BotShieldTrigger>."),
    AP_INIT_RAW_ARGS("<BotShieldFlagTrigger", bs_open_flagtrigger, NULL, RSRC_CONF,
                 "Open a BotShieldFlagTrigger block. Takes the rule name; every "
                 "setting is a BotShield directive on its own line "
                 "until </BotShieldFlagTrigger>."),
    AP_INIT_RAW_ARGS("<BotShieldCookieTrigger", bs_open_cookietrigger, NULL, RSRC_CONF,
                 "Open a BotShieldCookieTrigger block. Takes the rule name; every "
                 "setting is a BotShield directive on its own line "
                 "until </BotShieldCookieTrigger>."),
    AP_INIT_RAW_ARGS("<BotShieldEnvTrigger", bs_open_envtrigger, NULL, RSRC_CONF,
                 "Open a BotShieldEnvTrigger block. Takes the rule name; every "
                 "setting is a BotShield directive on its own line "
                 "until </BotShieldEnvTrigger>."),
    AP_INIT_RAW_ARGS("<BotShieldFeedbackTrigger", bs_open_feedbacktrigger, NULL, RSRC_CONF,
                 "Open a BotShieldFeedbackTrigger block. Takes the rule name; every "
                 "setting is a BotShield directive on its own line "
                 "until </BotShieldFeedbackTrigger>."),
    AP_INIT_RAW_ARGS("<BotShieldLoadTrigger", bs_open_loadtrigger, NULL, RSRC_CONF,
                 "Open a BotShieldLoadTrigger block. Takes the rule name; every "
                 "setting is a BotShield directive on its own line "
                 "until </BotShieldLoadTrigger>."),
    AP_INIT_RAW_ARGS("<BotShieldRule", bs_open_rule, NULL, RSRC_CONF,
                 "Open a BotShieldRule block. Takes the rule name; every "
                 "setting is a BotShield directive on its own line "
                 "until </BotShieldRule>."),
    AP_INIT_RAW_ARGS("<BotShieldMatch", bs_open_match, NULL, RSRC_CONF,
                 "Open a BotShieldMatch block: a named set of match "
                 "conditions that rules reuse with 'BotShieldMatches "
                 "<name>'. Takes the set's name; every condition is a "
                 "BotShield directive on its own line inside, until "
                 "</BotShieldMatch>. Conditions only -- actions belong "
                 "on the rules that name the set. Define a set above "
                 "the rules that use it."),
    AP_INIT_RAW_ARGS("<BotShieldRequestTrigger", bs_open_requesttrigger, NULL, RSRC_CONF,
                 "DEPRECATED spelling of <BotShieldRule>; warns at config "
                 "time and will be removed. Identical behaviour -- rename "
                 "the block and its closing tag."),
    AP_INIT_TAKE_ARGV("BotShieldTrigger", bs_flat_trigger_retired, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Per-scope trigger: the Apache scope (server / "
                 "<VirtualHost> / <Directory> / <Location> / "
                 "<LocationMatch> / <Files> / <If>) the directive "
                 "lives in IS the predicate. Action keys: "
                 "respond=<code|nochallenge>, redirect=<url>, log=<tag>, "
                 "accesslog=on|off, "
                 "flag=<name>, ttl=<sec>, penalty=<N>, credit=<N>, "
                 "mode=enforce|observe. The literal 'reset' as the "
                 "first arg drops triggers inherited from outer "
                 "scopes (and earlier same-scope BotShieldTrigger "
                 "directives). Multiple BotShieldTrigger directives "
                 "in one scope each append a separate action. "
                 "Replaces the legacy BotShieldFlagIP — the "
                 "equivalent today is `BotShieldTrigger flag=<name> "
                 "ttl=<sec>`."),
    /* E1 — Allow family */
    AP_INIT_TAKE_ARGV("BotShieldClassify", bs_set_classify, NULL,
                 RSRC_CONF,
                 "Per-pass enable/disable for the unified UA "
                 "classifier. Two grammars: standalone form "
                 "'BotShieldClassify On|Off' (one token, exclusive); "
                 "compositional form 'BotShieldClassify [All|None] "
                 "[+/-flag]...' where flag is one of: browsers, "
                 "known-bots, verified-bots, unknown-bots. Default "
                 "is all four passes enabled. Mixing On/Off with "
                 "deltas is a config-time error; use All/None for "
                 "the compositional form. Each disabled pass has a "
                 "fail-safe: -browsers treats all UAs as browsers "
                 "for robots.txt wildcard purposes; -known-bots "
                 "skips the AC directory (no log slug); "
                 "-verified-bots skips the IP cross-check (matched "
                 "UAs degrade to knownbot, neither verified-bot "
                 "credit nor fake-bot penalty — the natural response "
                 "to stale CIDR data); -unknown-bots skips "
                 "the heuristic substring scan."),
    AP_INIT_TAKE23("BotShieldAllowBot",
                 bs_set_allow_bot, NULL, RSRC_CONF,
                 "Register a verified-bot entry. Args: <name> "
                 "<ua-pattern> [<target>]. Name is a [a-z0-9-] token "
                 "used as the decision-log identifier and default "
                 "ranges-file basename; same-name as a bundled "
                 "built-in (googlebot, bingbot, applebot, "
                 "googleother, siteimprove from "
                 "data/verified-bots.json) replaces the built-in. "
                 "UA-pattern is the case-insensitive substring "
                 "looked for in the User-Agent header. Optional "
                 "target: '*' opts out of IP verification (UA "
                 "match alone, logged as knownbot:<name> with "
                 "score 0); an absolute file path; a single CIDR; "
                 "or a comma-separated CIDR list. Omit "
                 "the target to use the default file path "
                 "/var/lib/botshield/bots/<name>.txt. Whether the "
                 "verified-bot pass actually runs is controlled by "
                 "BotShieldClassify."),
    AP_INIT_TAKE1("BotShieldAllowRangesRefreshInterval",
                 bs_set_allow_ranges_refresh_interval, NULL, RSRC_CONF,
                 "Seconds between watchdog ticks that re-stat the "
                 "verified-bot CIDR files (canonical "
                 "/var/lib/botshield/bots/<name>.txt and operator "
                 "sidecar <base>.local.txt). On any mtime change the "
                 "module rebuilds the active range set in a private "
                 "subpool and atomic-swaps it into place; previous "
                 "state is held one tick before destruction so in-"
                 "flight readers can't deref freed memory. The "
                 "sidecar is the supported seam for adding custom "
                 "scanner IPs that aren't in a vendor's public feed "
                 "(e.g. dedicated Siteimprove enterprise scans). "
                 "0 disables (default; post_config load remains in "
                 "effect, reload via graceful restart). Range "
                 "0..86400; recommended 60-300."),
    /* E2.1 — policy enforcement. TAKE_ARGV because Apache has no
     * TAKE4/TAKE5 macros; the setters enforce argc themselves. */
    AP_INIT_TAKE_ARGV("BotShieldRateLimit",
                 bs_set_rate_limit, NULL, RSRC_CONF,
                 "Rate-limit a named cohort. Two forms:\n"
                 "  <name> [budget=N] [per=U] [ua=...] [ipspec=...] "
                 "[mode=enforce|observe]   (key=value form)\n"
                 "  <name> <budget> <per> <ua> <ipspec> "
                 "[mode=enforce|observe]   (legacy positional)\n"
                 "Per is sec/min/hour (or s/m/h). UA is a substring "
                 "(case-insensitive), `@<botgroup>`, or '*' for any "
                 "UA. Ipspec is '*', an absolute file path, or a "
                 "single / comma-separated CIDR list. Both-'*' (or "
                 "both keys omitted in the key=value form) is "
                 "rejected. Over-budget requests return 429 + "
                 "Retry-After and get a +50 score penalty under "
                 "reason ratelimitexceeded:<name>."),
    AP_INIT_TAKE_ARGV("BotShieldBotRateLimit",
                 bs_set_bot_rate_limit, NULL, RSRC_CONF,
                 "Per-bot-slug rate limit. Three forms:\n"
                 "  Off                                    decline "
                 "robots.txt Crawl-delay groups (explicit entries "
                 "still apply)\n"
                 "  <slug-or-pattern-or-@bg-or-*> <delay-sec>    1 "
                 "req per <delay> seconds (Crawl-delay style); 0 "
                 "admits all\n"
                 "  <slug-or-pattern-or-@bg-or-*> <budget> <per>  "
                 "<budget> requests per <per> period (sec/min/hour).\n"
                 "Any form may be followed by mode=enforce|observe "
                 "(default enforce); observe counts and logs "
                 "bot-rate:<slug>:observe with outcome=~rate_limited "
                 "but never returns 429. "
                 "Slug-or-pattern is matched (case-insensitive "
                 "substring) against the bot directory; resolves to "
                 "all matching slugs which share one counter. '*' is "
                 "the wildcard fallback — pre-allocates one counter "
                 "PER directory slug not covered by a specific rule. "
                 "'@<botgroup>' selects all directory slugs in that "
                 "botgroup (search, ai-input, ai-train, monitor) "
                 "with per-slug allocation — the precedence ladder "
                 "is specific > @botgroup > * wildcard. Three "
                 "reserved aggregate slots back the wildcard "
                 "(unknownbot, fake-bot, wildcard-fallback). "
                 "No default: with no directive and no robots.txt "
                 "Crawl-delay, nothing is rate limited. Over-budget "
                 "returns 429 + Retry-After + reason bot-rate:<slug>."),
    /* E9 — repeated-429 escalation. Sits on top of BotShieldRateLimit;
     * does not apply to robots.txt Crawl-delay 429s in v1 (no operator
     * handle for them). */
    AP_INIT_TAKE_ARGV("BotShieldRateLimitEscalate",
                 bs_set_rate_limit_escalate, NULL, RSRC_CONF,
                 "Promote repeated 429s on a named BotShieldRateLimit "
                 "into a stricter status. Args: <rate-name> <strikes> "
                 "<per> [respond=<code>] [ttl=<sec>] [log=<tag>]. "
                 "Per accepts sec/min/hour. Once <strikes> rejected "
                 "requests accumulate within <per>, subsequent "
                 "requests against the same rule return respond= "
                 "(default 403) for ttl= seconds (default 1800). The "
                 "ttl slides on each additional strike; log=<tag> "
                 "rides the decision line on threshold crossing for "
                 "fail2ban handoff. Reason ratelimitabuse:<name>."),
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
                 "Anti-loop hysteresis. Default ON - only an explicit Off "
                 "disables it. When on, a client challenged N times "
                 "within W seconds without solving any of them is "
                 "redirected ONCE to the explainer page and its "
                 "counter is cleared; the next request is challenged "
                 "again normally. It does NOT grant a pass window -- "
                 "an earlier version of this text said it did, which "
                 "would describe a bot buying access by failing on "
                 "purpose. Decision log shows reason "
                 "challengesafeguard. Doesn't mint _bs_session; "
                 "doesn't override 403/429 blocks. Default-on because a client that cannot solve the challenge - JS disabled, a "
                 "privacy extension, an old browser - would otherwise be re-challenged forever with no way out, and nothing in the "
                 "logs shouts about it. The tripped client is redirected to an explainer, NOT admitted: it never reaches protected "
                 "content, and its flagged-IP entry survives."),
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
    AP_INIT_TAKE1("BotShieldSafeguardRedirectURL",
                 bs_set_safeguard_redirect_url, NULL, RSRC_CONF,
                 "Where to redirect (302) a client that trips the "
                 "safeguard threshold. Original URI is appended as "
                 "?return=<urlencoded path>. Unset (default) uses the "
                 "built-in explainer at "
                 "<BotShieldEndpointPrefix>/safeguard-info, which is "
                 "auto-routed by the module so no Location carve-out "
                 "is needed. Must be a same-origin absolute path."),
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
    /* Load-average thresholds, per CPU. The worker-ratio thresholds
     * below cannot see this deployment's failure mode: with 1024
     * MaxRequestWorkers on 6 cores the box is CPU-saturated at a busy
     * ratio of 2-3%, which is where four outages actually ran. */
    AP_INIT_TAKE1("BotShieldLatencyWarm", bs_set_latency_warm, NULL,
                 RSRC_CONF,
                 "Apache mean request latency in ms at which load is "
                 "'warm' (default 250). Measured as a delta between "
                 "watchdog ticks, not since restart."),
    AP_INIT_TAKE1("BotShieldLatencyHot", bs_set_latency_hot, NULL,
                 RSRC_CONF,
                 "Apache mean request latency in ms at which load is "
                 "'hot' (default 1000). Must exceed BotShieldLatencyWarm."),
    AP_INIT_TAKE1("BotShieldFpmStatsFile",
                 bs_set_fpm_stats_file, NULL, RSRC_CONF,
                 "Path to the external PHP-FPM monitor's key=value "
                 "telemetry file. Dashboard display only; PHP-FPM load "
                 "reaches policy via BotShieldLoadStateFile."),
    AP_INIT_TAKE1("BotShieldDbStatsFile",
                 bs_set_db_stats_file, NULL, RSRC_CONF,
                 "Path to the external database monitor's key=value "
                 "telemetry file. Dashboard display only; database load "
                 "reaches policy via BotShieldLoadStateFile."),
    AP_INIT_TAKE1("BotShieldLoadAvgWarm", bs_set_loadavg_warm, NULL,
                 RSRC_CONF,
                 "1-minute load average PER CPU at which the load state "
                 "samples as 'warm', as a ratio (default 1.0). Same unit "
                 "as a host shedding script whose HIGH is 2x cores; keep "
                 "this under that so policy can shed selectively before "
                 "a blunt site-wide 503 engages."),
    AP_INIT_TAKE1("BotShieldLoadAvgHot", bs_set_loadavg_hot, NULL,
                 RSRC_CONF,
                 "Per-CPU load average at which the state samples as "
                 "'hot' (default 1.5). Must exceed BotShieldLoadAvgWarm."),
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
    /* Flag-driven trigger family. */
    AP_INIT_TAKE_ARGV("BotShieldFlagTrigger",
                 bs_flat_trigger_retired, NULL, RSRC_CONF,
                 "Apply an action when a flag bit fires on the IP- "
                 "or cookie-side bitmap of a request. Args: <flag> "
                 "[reset] [action=<verb> args...]. Flag names: "
                 "honeypot_hit, scanner_probe, fake_bot, "
                 "pow_fail_streak, app_verified_human, "
                 "app_verified_session, app_trust_signal. Action "
                 "verbs: 'score add=N' (signed, -1000..1000; SUMs "
                 "across triggers) or 'tier_floor min=<tier>' "
                 "(pass|noninteractive|interactive|captcha; MAXes across triggers). "
                 "'reset' clears prior operator declarations for "
                 "the named flag before this directive's effect is "
                 "added. mode=observe logs "
                 "would-flagtrigger:<flag>:observe instead of "
                 "applying. NOTHING IS SEEDED: a flag with no "
                 "BotShieldFlagTrigger is recorded and acts on "
                 "nothing, so every consequence is a line in this "
                 "config. See docs/examples/flag-triggers.conf.example "
                 "for a slate to start from."),
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
    /* E4 — cookie triggers */
    AP_INIT_TAKE_ARGV("BotShieldCookieTrigger",
                 bs_flat_trigger_retired, NULL, RSRC_CONF,
                 "Cookie-based trigger. Args: <name> <cookie-match> "
                 "[key=value ...]. cookie-match is one of: "
                 "cookie=<n>, cookie=<n>=<v>, cookie=<n>~<substr>, "
                 "cookie=<n>!<v>, !cookie=<n>, cookies=<none|any|"
                 "session>, bs-cookie=<verified|missing|invalid>. "
                 "Keys: respond=<code|nochallenge> (default pass; diverges "
                 "from E3 — credit/penalty here ALWAYS apply, even "
                 "under pass), redirect=<url>, log=<tag>, accesslog=on|off, "
                 "flag=<bit>, "
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
                 bs_flat_trigger_retired, NULL, RSRC_CONF,
                 "Env-var-based trigger, reads r->subprocess_env. "
                 "Args: <name> <env-match> [key=value ...]. "
                 "env-match is one of: env=<var> (present), "
                 "env=<var>=<value> (exact match, case-sensitive), "
                 "!env=<var> (absent). Keys: respond=<code|nochallenge> "
                 "(default pass; credit/penalty apply under pass "
                 "like E4), log=<tag>, accesslog=on|off, flag=<bit>, ttl=<sec>, "
                 "penalty=<n>, credit=<n>. No redirect= (env "
                 "signals are scoring/flagging only). Declaration "
                 "order, first match wins; upsert-by-name. Main "
                 "requests only — subrequests are no-ops."),
    /* E7.3 — feedback triggers (response-path mapping for E5) */
    AP_INIT_TAKE_ARGV("BotShieldFeedbackTrigger",
                 bs_flat_trigger_retired, NULL, RSRC_CONF,
                 "Map an app-signed event (via X-BotShield-Feedback "
                 "header) to module memory. Args: <event> "
                 "[key=value ...]. Required keys: flag=<bit>, "
                 "ttl=<sec>. Optional: log=<tag>, accesslog=on|off. The app signs "
                 "event=<name>;sig=<hex>; the module looks up <name> "
                 "here and applies flag+ttl to the flagged-IP table. "
                 "No status/redirect/penalty/credit (response is "
                 "already served)."),
    /* E11.2 — load-aware throttling triggers */
    AP_INIT_TAKE_ARGV("BotShieldLoadTrigger",
                 bs_flat_trigger_retired, NULL, RSRC_CONF,
                 "Trigger that fires based on the cached load state "
                 "(see BotShieldLoadStateFile / E11). Args: <name> "
                 "<load-match> [key=value ...]. load-match is one of "
                 "state=<level> or state>=<level> where <level> is "
                 "normal|warm|hot. Keys: respond=<code|nochallenge>, "
                 "log=<tag>, accesslog=on|off, penalty=<n>, credit=<n>. flag/ttl/"
                 "redirect rejected — load is global state, not "
                 "per-IP behavior. First-match-wins."),
    /* E3 — path-based triggers */
    /* BotShieldRule — the name this family should have had.
     *
     * Same setter, same parser, same entry type as
     * BotShieldRequestTrigger; only the spelling differs. The family
     * stopped being about requests-versus-something-else once it grew
     * ua=, ipspec=, query=, cookies=, exists=, solved= and minload=:
     * it is simply "match a request on any combination of its
     * properties and act", which is what a rule is.
     *
     * Both names stay registered. An existing config keeps working,
     * and the docs lead with BotShieldRule.
     *
     * The two match keys that make a load-shed ladder expressible
     * without arithmetic:
     *   solved=yes|no        did this client pass a challenge
     *   minload=normal|warm|hot   fires at that load state or above
     * Combined with ua=@bot / @search / @ai-train / @fake-bot, a shed
     * ladder reads as one line per rung with no score to reason about.
     */
    AP_INIT_TAKE_ARGV("BotShieldRule",
                 bs_flat_trigger_retired, NULL, RSRC_CONF,
                 "Match a request on any combination of its properties "
                 "and act once. Args: <name> [key=value ...]. Match "
                 "keys, all optional and ANDed, at least one required: "
                 "path=<glob>, query=<glob>, cookies=none|any|session, "
                 "exists=yes|no, solved=yes|no (client holds a cookie "
                 "proving it passed a challenge), "
                 "minload=normal|warm|hot (fires at that load state or "
                 "above), ua=<substring>|@<botgroup>|@bot|@fake-bot, "
                 "ipspec=*|<file>|<cidr[,cidr]>. Action keys: "
                 "respond=<code|nochallenge>, redirect=<url>, tier=<t>, "
                 "penalty=<n>, log=<tag>, accesslog=on|off, flag=<bit>, "
                 "ttl=<sec>, mode=enforce|observe."),
    AP_INIT_TAKE_ARGV("BotShieldRequestTrigger",
                 bs_flat_trigger_retired, NULL, RSRC_CONF,
                 "DEPRECATED spelling of BotShieldRule, and the flat "
                 "one-line form is retired besides. Write "
                 "<BotShieldRule name> ... </BotShieldRule>; see that "
                 "directive for the match and action keys. This text "
                 "used to restate them and drifted: it still advertised "
                 "flag= and ttl= defaults that no longer exist, and "
                 "tier= values that were renamed. One directive should "
                 "document itself once."),
    AP_INIT_TAKE_ARGV("BotShieldDecisionLog", bs_set_decision_log,
                 NULL, RSRC_CONF,
                 "Module-owned decision log. Defaults to "
                 "logs/botshield.log for any server with "
                 "BotShieldEnabled somewhere in it; a loaded but "
                 "unused module writes nothing. Value is a "
                 "server-root-relative path, an "
                 "absolute path, or a piped-log spec "
                 "(\"|/usr/bin/rotatelogs /var/log/bs.%Y%m%d 86400\"). "
                 "With rotatelogs -n, add -L so a fixed path always "
                 "links to the file currently open -- -n cycles the "
                 "live file between logfile and logfile.N, and anything "
                 "reading the base name silently goes stale. "
                 "Written directly from the decision path rather than "
                 "through mod_log_config, so it is independent of the "
                 "access log: `accesslog=off` can suppress access logging "
                 "while this log still records, which is what lets you "
                 "rapid-rotate the detection log and archive the access "
                 "log separately. One descriptor per vhost, opened at "
                 "post_config and inherited by every child; single "
                 "O_APPEND write per line, no request-path locking. "
                 "Optional - without it the authoritative record is the "
                 "error-log `mod_botshield: decision ...` line (boring "
                 "passes demoted to DEBUG) plus whatever CustomLog the "
                 "operator wires up. Failure to open is fatal at "
                 "startup: a decision log you asked for and did not get "
                 "is a silent blind spot."),
    /* E2.2 — robots.txt enforcement */
    AP_INIT_TAKE1("BotShieldRobotsTxt", bs_set_robots_txt,
                 NULL, RSRC_CONF,
                 "Path to a robots.txt file whose Disallow and "
                 "Crawl-delay rules mod_botshield will enforce "
                 "server-side. Parsed at post_config; RFC 9309 "
                 "semantics (prefix + '*' + '$' wildcards, longest-"
                 "match-wins, case-insensitive UA prefix). Blocked "
                 "paths return 403 (reason robotsblock:<group>); "
                 "Crawl-delay trips return 429 + Retry-After "
                 "(reason robots-rate:<group>)."),
    AP_INIT_TAKE1("BotShieldRobotsMode", bs_set_robots_mode,
                 NULL, RSRC_CONF,
                 "Whether robots.txt Disallow rules enforce or only "
                 "record. 'enforce' (default) returns 403 with reason "
                 "robotsblock:<group>; 'observe' logs "
                 "robotsblock:<group>:observe with outcome=~block and "
                 "lets the request through, suppressing the score bump "
                 "and the flag as well so nothing leaks into later "
                 "requests. Use observe to find out who actually "
                 "ignores a robots.txt before starting to refuse them "
                 "- independent of BotShieldEnabled, so a scope can "
                 "enforce its scoring while robots stays advisory."),
    AP_INIT_TAKE1("BotShieldRobotsRefreshInterval",
                 bs_set_robots_refresh_interval, NULL, RSRC_CONF,
                 "Seconds between mod_watchdog-driven re-checks of "
                 "the BotShieldRobotsTxt file. On mtime change the "
                 "file is re-parsed and the active rule set is "
                 "atomically swapped — no Apache reload needed. "
                 "Default 60. Set 0 to disable live-refresh and "
                 "require an explicit reload after editing."),
    AP_INIT_TAKE1("BotShieldBotDirectory",
                 bs_set_bot_directory, NULL, RSRC_CONF,
                 "Path to a TSV file overriding the compiled-in "
                 "bot-directory baseline. Format: pattern|slug|"
                 "category|followsRobotsTxt, one record per line, "
                 "comments with '#'. Refresh via "
                 "services/refresh/botshield-refresh.py directory; the watchdog re-"
                 "parses on mtime change so updates take effect "
                 "without Apache reload. Optional; if unset the "
                 "compiled-in baseline (~600 entries from the "
                 "bundled Cloudflare directory at build time) "
                 "stays active."),
    AP_INIT_TAKE1("BotShieldBotDirectoryRefreshInterval",
                 bs_set_bot_directory_refresh_interval, NULL, RSRC_CONF,
                 "Seconds between mod_watchdog re-checks of the "
                 "BotShieldBotDirectory file. Default 300. Set 0 to "
                 "disable live-refresh; the post_config-time load "
                 "still happens once."),
    AP_INIT_TAKE1("BotShieldBrowserTemplates",
                 bs_set_browser_templates, NULL, RSRC_CONF,
                 "Path to a text file overriding the compiled-in "
                 "browser-template baseline. Each non-comment line "
                 "is a normalized UA template (runs of [0-9._]+ "
                 "replaced by 'X'). Refresh via "
                 "services/refresh/botshield-refresh.py user-agents; the watchdog "
                 "re-loads on mtime change. Optional; if unset the "
                 "compiled-in baseline (~23 templates from the "
                 "build-time bundled top-100 list) stays active."),
    AP_INIT_TAKE1("BotShieldBrowserTemplatesRefreshInterval",
                 bs_set_browser_templates_refresh_interval, NULL,
                 RSRC_CONF,
                 "Seconds between mod_watchdog re-checks of the "
                 "BotShieldBrowserTemplates file. Default 300. Set "
                 "0 to disable live-refresh."),
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
    ".css", ".js", ".mjs", ".map", ".wasm", ".webmanifest",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif",
    ".svg", ".ico", ".bmp", ".heic", ".heif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".opus", ".ogg",
    ".mp4", ".webm", ".mov", ".m4v", ".ogv",
    ".vtt",
    ".m3u8", ".mpd", ".m4s",
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



/* --- Request-handler helpers --- */

/* Always-mint: install a presence-only session cookie if no valid
 * cookie was carried into the request. Called once from bs_handler
 * right after cookie verify. Every terminal outcome below it
 * (pass-tier short-circuit, LogOnly decline, challenge-tier
 * interstitial render, block 403, safeguard 302) ships the response
 * with this Set-Cookie already installed on r->err_headers_out, so
 * none of those outcomes need their own mint logic.
 *
 * The cookie carries trust=0 (passes_non_interactive = passes_interactive =
 * passes_captcha = 0) and uses the "session" passthrough algorithm
 * — no PoW solution to verify, just an authenticated envelope
 * marking "you've been here." When the user later solves a real
 * challenge at /botshield/embedded-verify or /captcha-verify, those
 * endpoints mint a higher-trust cookie that replaces this one
 * (apr_table_add stacks Set-Cookies; browser uses the latest for
 * the same name).
 *
 * No-op on these requests:
 *   - Cookie verify already accepted a valid existing cookie
 *   - Module is BS_ENABLED_OFF for this scope (defensive — caller
 *     already gated on this, but cheap to repeat)
 *   - Mint failed (typically: no secret configured yet). The next
 *     request gets another attempt.
 *
 * Mint-on-pass design notes:
 *   - bs_safeguard_clear is gated on solve evidence
 *     (passes_*) at its call site, so trust=0 cookies don't reset
 *     safeguard counters. Bots that harvest a fresh cookie can't
 *     use it to bypass safeguard.
 *   - The cookie is a session cookie (no Expires/Max-Age), so
 *     browser drops it at session end. The envelope's server-side
 *     expires_at still bounds acceptance regardless of browser
 *     behavior. */
static int bs_maybe_mint_session(request_rec *r, bs_dir_cfg *cfg,
                                 int cookie_fully_ok)
{
    if (cookie_fully_ok) return 0;
    if (!cfg || cfg->enabled == BS_ENABLED_OFF) return 0;
    if (!cfg->secret) return 0;

    const bs_pow_algorithm *session_alg = bs_find_algorithm("session");
    if (!session_alg) return 0;

    int ttl = (cfg->cookie_ttl > 0) ? cfg->cookie_ttl : BS_DEFAULT_COOKIE_TTL;
    int difficulty = (cfg->difficulty > 0) ? cfg->difficulty
                                           : BS_DEFAULT_DIFFICULTY;
    /* Session flags a rule asked for on this request. They ride a note
     * to this single mint rather than each rule minting its own cookie
     * -- which is what the removed burn= did, and why it had to unset
     * both Set-Cookie tables to stop the ordinary mint overwriting
     * it. */
    bs_rep_state seed;
    memset(&seed, 0, sizeof(seed));
    const char *pending = apr_table_get(r->notes, "bs-session-flags");
    if (pending) {
        unsigned padd = 0, pdel = 0, prep = 0;
        if (sscanf(pending, "%x:%x:%u", &padd, &pdel, &prep) == 3) {
            /* A fresh cookie carries nothing, so a removal has nothing
             * to remove and "=" and "+" agree: the set is what was
             * added. */
            seed.flags_active = (apr_uint32_t)padd;
        }
    }
    bs_challenge fresh = { 0 };
    const char *ierr = bs_issue_challenge(r->pool, cfg,
                                          difficulty, ttl,
                                          /*auto_tier*/0,
                                          /*alg_override*/session_alg,
                                          pending ? &seed : NULL,
                                          &fresh);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_botshield: session mint deferred: %s",
                      ierr);
        return 0;
    }
    /* counter slot is required by the wire format but its content
     * is ignored by the session passthrough verify. "session" reads
     * cleanly when anyone debugs the wire form. */
    if (bs_install_verified_cookie(r, cfg, &fresh, "session") != NULL) {
        return 0;
    }
    return 1;
}

/* Challenge safeguard: before issuing a challenge, check whether
 * this IP has been presented N times within the window without
 * solving. If so, redirect (302) to the configured safeguard URL
 * (or built-in explainer) with the original URI as `?return=`, and
 * clear the per-IP counter so the user gets a fresh challenge cycle
 * after they engage with the redirect target.
 *
 * Pre-2026 behavior was a silent pass-through (return DECLINED),
 * which gave determined bots free access to content for the TTL
 * window without informing real-but-broken users about what was
 * happening. The redirect-with-explainer model makes the failure
 * mode visible to legitimate clients and gives bots nothing useful
 * (the explainer page has no scrapable content; redirect followers
 * land on it but don't reach the protected URL).
 *
 * Recording the presentation runs unconditionally on safeguard-
 * eligible paths (have_client_ip + scfg present), regardless of
 * safeguard_enabled — the embedded → M7 fallback in noninteractive tier
 * dispatch reads the same count to decide when to bypass the
 * embedded short-circuit. The write is cheap (one mutex + a few
 * SHM stores); the only side-effect when safeguard is "off" is
 * that embedded mode gets the count it needs.
 *
 * Runs AFTER bs_check_policy by construction (caller is already
 * past the policy short-circuit returns), so 403/429 blocks still
 * win.
 *
 * Returns OK with r->status set to 302 if safeguard redirected the
 * request, OK if the caller should continue to challenge issuance. */
static int bs_apply_safeguard(request_rec *r, int have_client_ip,
                              const unsigned char *client_ip,
                              const char *cookie_status,
                              bs_request_score *score, int effective)
{
    bs_server_cfg *scfg_sg = ap_get_module_config(
        r->server->module_config, &botshield_module);
    if (!scfg_sg || !have_client_ip) return OK;

    apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
    /* Default-on: -1 is "operator said nothing", and the anti-loop
     * valve is not something you want to have to remember. Only an
     * explicit BotShieldSafeguard Off disables it. */
    if (scfg_sg->safeguard_enabled != 0 &&
        bs_safeguard_check(client_ip, now_t, scfg_sg->ns_id)) {
        /* Resolve the redirect target. Operator override via
         * BotShieldSafeguardRedirectURL, otherwise the built-in
         * explainer at <endpoint_prefix>/safeguard-info. */
        bs_dir_cfg *dcfg_sg = ap_get_module_config(
            r->per_dir_config, &botshield_module);
        const char *prefix = (dcfg_sg && dcfg_sg->endpoint_prefix)
            ? dcfg_sg->endpoint_prefix
            : BS_DEFAULT_ENDPOINT_PREFIX;
        const char *base = scfg_sg->safeguard_redirect_url
            ? scfg_sg->safeguard_redirect_url
            : apr_pstrcat(r->pool, prefix, "/safeguard-info", NULL);

        /* Build Location: <base>?return=<urlencoded original URI>.
         * unparsed_uri preserves the query string so the user comes
         * back to where they were. */
        const char *orig = (r->unparsed_uri && *r->unparsed_uri)
                         ? r->unparsed_uri : "/";
        const char *orig_enc = ap_escape_uri(r->pool, orig);
        char sep = strchr(base, '?') ? '&' : '?';
        const char *location = apr_psprintf(r->pool,
            "%s%creturn=%s", base, sep, orig_enc);

        /* Clear the counter so the next failure cycle starts fresh.
         * This is the operational equivalent of "the safeguard fired,
         * stop accumulating against this IP" — without it, the next
         * request would just trigger the redirect again immediately. */
        bs_safeguard_clear(r, client_ip, scfg_sg->ns_id);

        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: challengesafeguard tripped for "
            "%s; redirecting to %s", r->useragent_ip, location);
        bs_score_add(r, 0, 0, "challengesafeguard");
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->safeguard_fired_total,
                               1, __ATOMIC_RELAXED);
        }
        bs_decision_log(r, "safeguard", "redirect",
                        cookie_status, "-", "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);

        /* Apache's redirect idiom: set Location, return the 3xx
         * status. ap_die builds the small "click here" body. The
         * caller propagates this rv up through bs_handler.
         *
         * Use err_headers_out for our supplementary headers because
         * ap_die clears r->headers_out on error/redirect responses
         * but preserves err_headers_out (Apache's contract for
         * "headers I want on the error response too"). Location is
         * special-cased and goes through either way, but explicit
         * is clearer. */
        apr_table_setn(r->err_headers_out, "Location", location);
        apr_table_setn(r->err_headers_out, "Cache-Control", "no-store");
        apr_table_setn(r->err_headers_out, "X-Botshield", "safeguardredirect");
        return HTTP_MOVED_TEMPORARILY;
    }

    int sg_threshold = bs_safeguard_effective_int(
        scfg_sg->safeguard_threshold, BS_DEFAULT_SAFEGUARD_THRESHOLD);
    int sg_window = bs_safeguard_effective_int(
        scfg_sg->safeguard_window, BS_DEFAULT_SAFEGUARD_WINDOW);
    int sg_ttl = bs_safeguard_effective_int(
        scfg_sg->safeguard_ttl, BS_DEFAULT_SAFEGUARD_TTL);
    bs_safeguard_record_presentation(r, client_ip,
                                     sg_threshold, sg_window, sg_ttl,
                                     now_t, scfg_sg->ns_id);
    return OK;
}

/* Is this client allowed to read this observability surface?
 *
 * Matches r->useragent_ip via bs_allow_ip_in_ranges, the same address
 * the module scores on, so mod_remoteip applies exactly as it does to
 * Apache's own `Require ip`. An operator who has already reasoned about
 * their proxy chain for one gets the same answer from the other, which
 * matters more here than picking the connection peer would: behind a
 * reverse proxy the peer is the proxy, and an admin-IP list matched
 * against it would never match anybody. */
static int bs_observe_permitted(request_rec *r, const bs_observe_acl *acl)
{
    if (!acl) return 0;
    if (acl->allow_all) return 1;
    return bs_allow_ip_in_ranges(acl->ranges, r);
}

/* 404, not 403.
 *
 * 403 confirms the surface exists and that this module is installed,
 * which is a free hint to anyone scanning for a dashboard to come back
 * to from a better address. 404 is also what the operator sees if they
 * forget the directive, and "the page is not there" sends them to the
 * documentation, where a 403 sends them to their own <Location> hunting
 * for a Require they never wrote.
 *
 * Logged to the decision log as outcome=observe with a reason that says
 * it was refused, rather than as a new outcome: a grep for
 * outcome=observe should still find every request that reached these
 * surfaces, served or not. Like the served case, this deliberately
 * bypasses the decision counters -- traffic to the measuring instrument
 * is not a decision about site traffic. */
static int bs_observe_denied(request_rec *r, const char *surface)
{
    bs_log_observability_denied(r, surface);
    return HTTP_NOT_FOUND;
}

/* POST <prefix>/admin/unflag -- clear flags from an address or range.
 *
 * Form body:
 *   addr=<ip|cidr>          required
 *   flags=<name[,name...]>  optional; omitted means drop the entry
 *                           whatever it holds
 *
 * Deliberately POST. A GET would be fetched by a link checker, a
 * browser prefetch, or an operator's own history, and this changes
 * state.
 *
 * Deliberately requires an X-BotShield-Unflag header, whose value is
 * ignored. The ACL matches on address, and an operator's browser sits
 * at an allowed address: without this, any page that browser visits
 * could POST a form here and have it accepted. A cross-origin form
 * cannot set a header, so requiring one that no form can produce means
 * the request had to come from something deliberately constructed --
 * curl, a script, the operator's own tooling.
 *
 * There is no `ns` parameter, though the plan proposed one. The ACL is
 * per-server and namespaces are per-vhost, so honouring a
 * client-supplied namespace would let a host granted admin on one
 * vhost clear another vhost's reputation -- a grant the operator never
 * wrote. The namespace is the one this request arrived in. */
/* Reply with our own text and our own status.
 *
 * Returning the status code from a handler lets Apache substitute its
 * error document, so a caller asking why their request was refused got
 * "Your browser sent a request that this server could not understand"
 * instead of the flag name they mistyped. Setting r->status and
 * returning OK keeps the body we wrote. */
static int bs_admin_reply(request_rec *r, int status, const char *msg)
{
    r->status = status;
    ap_set_content_type(r, "text/plain; charset=utf-8");
    ap_rprintf(r, "%s\n", msg);
    return OK;
}

static int bs_admin_unflag_handler(request_rec *r)
{
    if (r->method_number != M_POST) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "botshield: admin/unflag refused: %s, want POST",
                      r->method ? r->method : "-");
        return bs_admin_reply(r, HTTP_METHOD_NOT_ALLOWED,
                              "POST only: this clears state");
    }
    if (!apr_table_get(r->headers_in, "X-BotShield-Unflag")) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "botshield: admin/unflag refused: no "
                      "X-BotShield-Unflag header");
        return bs_admin_reply(r, HTTP_BAD_REQUEST,
                              "missing X-BotShield-Unflag header");
    }

    const char *body = NULL;
    apr_size_t body_len = 0;
    apr_status_t bsr = bs_read_form_body(r, 4 * 1024, &body, &body_len);
    if (bsr == APR_ENOSPC)
        return bs_admin_reply(r, HTTP_REQUEST_ENTITY_TOO_LARGE,
                              "body too large");
    if (bsr != APR_SUCCESS)
        return bs_admin_reply(r, HTTP_BAD_REQUEST, "unreadable body");

    char *addr_spec = bs_form_get(r->pool, body, "addr");
    if (!addr_spec || !*addr_spec)
        return bs_admin_reply(r, HTTP_BAD_REQUEST, "addr is required");

    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg) return HTTP_INTERNAL_SERVER_ERROR;

    /* Split the optional prefix length off before parsing the
     * address: bs_parse_client_ip wants a bare address. */
    int want_bits = -1;
    char *slash = strchr(addr_spec, '/');
    if (slash) {
        *slash = '\0';
        const char *lenstr = slash + 1;
        if (!*lenstr)
            return bs_admin_reply(r, HTTP_BAD_REQUEST,
                                  "empty prefix length");
        char *end = NULL;
        long v = strtol(lenstr, &end, 10);
        if (!end || *end || v < 0 || v > 128)
            return bs_admin_reply(r, HTTP_BAD_REQUEST,
                                  "bad prefix length");
        want_bits = (int)v;
    }

    unsigned char net[16];
    if (!bs_parse_client_ip(addr_spec, net))
        return bs_admin_reply(r, HTTP_BAD_REQUEST, "bad address");

    /* v4 arrives v4-mapped, so a v4 /24 is 120 bits of the 16-byte
     * key. Detect the mapping rather than re-reading the string: that
     * is the form the table stores and the form we have to match. */
    static const unsigned char V4MAP[12] = {
        0,0,0,0, 0,0,0,0, 0,0,0xFF,0xFF
    };
    int is_v4 = (memcmp(net, V4MAP, sizeof(V4MAP)) == 0);

    int bits;
    if (is_v4) {
        if (want_bits < 0) want_bits = 32;
        if (want_bits > 32)
            return bs_admin_reply(r, HTTP_BAD_REQUEST,
                "prefix length above /32 for an IPv4 address");
        bits = 96 + want_bits;
    } else {
        /* v6 entries are stored masked to ipv6_prefix_bits, so a /128
         * would match nothing that granularity coarser than /128 ever
         * wrote. Clamp to the storage granularity and report the
         * prefix actually acted on, because it is wider than what was
         * asked for and the operator has to see that. */
        int gran = scfg->ipv6_prefix_bits > 0 ? scfg->ipv6_prefix_bits : 128;
        if (want_bits < 0) want_bits = 128;
        bits = want_bits > gran ? gran : want_bits;
        bs_mask_ipv6_prefix(net, gran);
    }

    apr_uint32_t del_bits = 0;
    char *flags_spec = bs_form_get(r->pool, body, "flags");
    if (flags_spec && *flags_spec) {
        const char *ferr = NULL;
        del_bits = bs_parse_flag_names(r->pool, flags_spec, &ferr);
        if (ferr) return bs_admin_reply(r, HTTP_BAD_REQUEST, ferr);
    }

    apr_uint32_t cleared = 0;
    bs_flagged_ip_clear_range(r, net, bits, del_bits, scfg->ns_id, &cleared);

    /* NOTICE, not INFO: clearing reputation state is the kind of thing
     * someone asks about afterwards, and it should be in the log of a
     * server that is not running at debug level. Names who asked as
     * well as what changed -- the ACL is the gate, but the log is the
     * record of who walked through it. */
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                  "botshield: admin/unflag by %s: addr=%s bits=%d "
                  "flags=%s ns=%u slots=%u",
                  r->useragent_ip ? r->useragent_ip : "-",
                  addr_spec, bits,
                  (flags_spec && *flags_spec) ? flags_spec : "(all)",
                  (unsigned)scfg->ns_id, (unsigned)cleared);

    return bs_admin_reply(r, HTTP_OK,
                          apr_psprintf(r->pool, "cleared %u",
                                       (unsigned)cleared));
}

/* Bloom membership for this request, computed at most once.
 *
 * Hoisted out of the heuristic block below so a rule predicate can
 * consult it: bs_check_policy walks the rules well before that block
 * runs, and a predicate cannot read a value that has not been computed.
 *
 * Reading earlier is safe because the only writer for this address is
 * the bs_bloom_add below, which still runs once and after everything
 * that reads. Memoized for two reasons: two rules naming the predicate
 * must not see different answers, and the lookup should stay one
 * lookup.
 *
 * 1 = first sight (Bloom miss), 0 = seen before, -1 = no usable client
 * address. The -1 is a real case -- a rule asking about an address that
 * does not exist should not match either way. */
int bs_request_first_sight(request_rec *r)
{
    const char *cached = apr_table_get(r->notes, "bs-first-sight");
    if (cached) return atoi(cached);

    int result = -1;
    unsigned char ip[16];
    if (bs_parse_client_ip(r->useragent_ip, ip)) {
        bs_server_cfg *scfg = ap_get_module_config(
            r->server->module_config, &botshield_module);
        if (scfg) {
            bs_mask_ipv6_prefix(ip, scfg->ipv6_prefix_bits);
            result = bs_bloom_seen(ip, scfg->ns_id) ? 0 : 1;
        }
    }
    apr_table_setn(r->notes, "bs-first-sight",
                   apr_psprintf(r->pool, "%d", result));
    return result;
}

/* Module-owned endpoint routing. URLs under BotShieldEndpointPrefix
 * (default /botshield) are served by this module's own handlers, not
 * the tier dispatch. Today:
 *   <prefix>/captcha-verify             — single-provider vhost
 *   <prefix>/captcha-verify/<name>      — per-provider cohabitation
 *   <prefix>/metrics                    — mod_status-style export
 *   <prefix>/embedded{.js,-worker.js,-bootstrap,-verify}
 *                                       — noninteractive tier embedded path
 *   <prefix>/form-widget.js             — interactive PoW widget shell
 * The bare /captcha-verify form still works for the single-provider
 * case so the old dev config and the first-provider-on-a-vhost case
 * keep working. Called before the debug / asset / cookie paths so
 * operators can hit the verify endpoint regardless of surrounding
 * scope.
 *
 * Returns the Apache return code if the URI matched a module
 * endpoint (including 404 OK for unknownendpoint-under-prefix);
 * returns -1 if the URI is outside the prefix and the caller should
 * fall through to the tier dispatch. */
static int bs_route_module_endpoint(request_rec *r, bs_dir_cfg *cfg)
{
    const char *prefix = cfg->endpoint_prefix
        ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    apr_size_t prefix_len = strlen(prefix);
    if (!r->uri || strncmp(r->uri, prefix, prefix_len) != 0 ||
        r->uri[prefix_len] != '/') {
        return -1;
    }

    const char *sub = r->uri + prefix_len;

    /* Observability ACL, checked before dispatch.
     *
     * Prefix-matched on /dashboard/ rather than enumerated so a
     * dashboard page added later is gated by existing config instead of
     * shipping open until someone remembers to add it to a list. The
     * preview pages are deliberately outside this: they reveal nothing
     * a challenged visitor does not already see. */
    {
        int is_metrics = (strcmp(sub, "/metrics") == 0);
        int is_dash    = (strcmp(sub, "/dashboard") == 0
                          || strncmp(sub, "/dashboard/", 11) == 0);
        /* Prefix-matched like /dashboard/, so a second admin action
         * added later is gated by the directive that already exists
         * rather than shipping open until someone lists it. */
        int is_admin   = (strncmp(sub, "/admin/", 7) == 0);
        if (is_metrics || is_dash || is_admin) {
            bs_server_cfg *scfg =
                ap_get_module_config(r->server->module_config,
                                     &botshield_module);
            const bs_observe_acl *acl = !scfg ? NULL
                : (is_admin   ? &scfg->observe_admin
                 : is_metrics ? &scfg->observe_metrics
                              : &scfg->observe_dashboard);
            if (!bs_observe_permitted(r, acl)) {
                return bs_observe_denied(r,
                    is_admin ? "admin" : is_metrics ? "metrics"
                                                    : "dashboard");
            }
        }
    }

    if (strcmp(sub, "/captcha-verify") == 0 ||
        strncmp(sub, "/captcha-verify/", 16) == 0) {
        return bs_captcha_verify_handler(r, cfg);
    }
    if (strcmp(sub, "/metrics") == 0) {
        return bs_metrics_handler(r);
    }
    if (strcmp(sub, "/admin/unflag") == 0) {
        return bs_admin_unflag_handler(r);
    }
    if (strcmp(sub, "/dashboard") == 0) {
        return bs_dashboard_handler(r);
    }
    /* Bot detail page. Same observability class as /dashboard -- it is
     * listed alongside it in the world-readable scope in the shipped
     * config, so an operator who exposes one has exposed both. */
    if (strcmp(sub, "/dashboard/bots") == 0) {
        return bs_dashboard_bots_handler(r);
    }
    if (strcmp(sub, "/dashboard/responses") == 0) {
        return bs_dashboard_responses_handler(r);
    }
    if (strcmp(sub, "/dashboard/internals") == 0) {
        return bs_dashboard_internals_handler(r);
    }
    /* Interstitial previews. Reveal nothing a challenged visitor does
     * not already see, so they are not gated with the dashboard -- but
     * an operator who wants them behind the same ACL just adds
     * |preview to that LocationMatch. */
    if (strcmp(sub, "/preview") == 0 || strcmp(sub, "/preview/") == 0) {
        return bs_preview_index_handler(r);
    }
    if (strcmp(sub, "/preview/noninteractive") == 0) {
        return bs_preview_handler(r, 1);
    }
    if (strcmp(sub, "/preview/interactive") == 0) {
        return bs_preview_handler(r, 0);
    }
    /* The explainer is already served at /safeguard-info, but it lives
     * here too so all three pages an operator might want to look at
     * are under one prefix. Same handler, so there is one page and not
     * a copy that drifts. */
    if (strcmp(sub, "/preview/safeguard") == 0) {
        return bs_safeguard_info_handler(r);
    }
    if (strcmp(sub, "/dashboard/app-bots") == 0) {
        return bs_dashboard_app_bots_handler(r);
    }
    if (strcmp(sub, "/dashboard/app-users") == 0) {
        return bs_dashboard_app_users_handler(r);
    }
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
    if (strcmp(sub, "/form-widget.js") == 0) {
        return bs_form_widget_handler(r);
    }
    if (strcmp(sub, "/safeguard-info") == 0) {
        /* Built-in explainer page served on safeguard redirect.
         * Renders unconditionally (counter reset already happened
         * upstream when the safeguard tripped). */
        return bs_safeguard_info_handler(r);
    }

    /* Unknown module endpoint under the prefix → 404, so a typo in
     * an operator's template fails loudly instead of falling through
     * to Apache and serving some unrelated file. */
    r->status = HTTP_NOT_FOUND;
    ap_set_content_type(r, "text/plain; charset=utf-8");
    apr_table_setn(r->err_headers_out, "X-Botshield", "unknownendpoint");
    ap_rputs("Not found.\n", r);
    bs_decision_log(r, "none", "block", "-", "-", "-",
                    "unknown_endpoint", 0);
    return OK;
}

/* --- Request handler ---
 *
 * Registered at APR_HOOK_FIRST so we run before Apache's default
 * static-file handler. The body is a top-down state machine; each
 * step either short-circuits with a decision_log line or falls
 * through to the next:
 *
 *   1. Module-config / initial-req gate (cheap drops).
 *   2. Module-owned endpoint dispatch — /captcha-verify, /metrics,
 *      /embedded*, /form-widget.js. Returns Apache
 *      rv directly; never reaches the tier dispatch below.
 *   3. Debug + asset short-circuits + secret-presence sanity.
 *   4. Cookie verify — bs_verify_cookie + safeguard-clear-on-solve
 *      + bs-cookie-state note for cookietrigger predicates.
 *   5. Policy check — bs_check_policy (cookie/env/load/scope/path
 *      triggers + robots + rate_limits). DECLINED or
 *      HTTP_* short-circuits return here.
 *   6. Heuristics + flagged-IP + first-sight + flagtrigger walker
 *      → effective score, score_tier, tier_floor.
 *   7. Pass-tier short-circuit + app_claims emission.
 *   8. Bloom-add + safeguard presentation accounting.
 *   9. Embedded noninteractive tier dispatch with embedded-→-interactive PoW
 *      fallback when the wrapper has had its chances.
 *   10. Build next_rep (forgiveness + cap), issue challenge, render
 *       interstitial (noninteractive / interactive PoW / captcha widget). */
static int bs_handler(request_rec *r)
{
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    /* enabled is a tristate: BS_ENABLED_ON enforces, BS_ENABLED_LOGONLY
     * runs the handler for observation, BS_ENABLED_OFF (or BS_UNSET
     * meaning "no setting inherited") declines. */
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    /* Module-owned endpoints are dispatched on whether the module is
     * live ANYWHERE on this vhost, not on the per-directory enabled
     * state of the requested URL. They belong to the vhost.
     *
     * Gating them on the per-directory state was wrong in a way that
     * only shows up once an operator scopes the enable: with
     * `BotShieldEnabled On` inside a <Location>, the /botshield prefix is
     * outside that scope, so every endpoint 404s. That silently breaks
     * the captcha tier (captcha-verify unreachable) and embedded mode
     * (embedded-verify, embedded.js), and points the safeguard redirect
     * at a 404 — the anti-lockout valve landing on a broken page is
     * worse than either not redirecting or not challenging.
     *
     * An explicit `BotShieldEnabled Off` on the endpoint path still
     * wins, so operators keep a way to switch them off. Access control
     * remains Apache's job: wrap the prefix in <Location> with
     * Require ip / AuthType to restrict. */
    bs_server_cfg *scfg_ep = ap_get_module_config(r->server->module_config,
                                                  &botshield_module);
    if (scfg_ep && scfg_ep->any_enabled
        && !(cfg && cfg->enabled == BS_ENABLED_OFF)) {
        int endpoint_rv = bs_route_module_endpoint(r, cfg);
        if (endpoint_rv != -1) {
            /* Marker for the response breakout: these never reach the
             * decision path, so BS_OUTCOME is absent and they would
             * otherwise be attributed to the origin. */
            if (!apr_table_get(r->subprocess_env, "BS_ENDPOINT")) {
                apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "1");
            }
            return endpoint_rv;
        }
    }

    /* enabled is a tristate: BS_ENABLED_ON enforces, BS_ENABLED_LOGONLY
     * runs the handler for observation, BS_ENABLED_OFF (or BS_UNSET
     * meaning "no setting inherited") declines. */
    if (!cfg
        || cfg->enabled == BS_ENABLED_OFF
        || cfg->enabled == BS_UNSET) {
        return DECLINED;
    }

    /* Debug override keeps the first-commit behavior available for tests. */
    if (cfg->debug == 1) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_botshield: debug mode - forcing 403 for %s",
                      r->unparsed_uri);
        r->status = HTTP_FORBIDDEN;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->headers_out,    "Cache-Control", "no-store");
        apr_table_setn(r->err_headers_out, "X-Botshield",  "debug403");
        ap_rputs("Hello World\n", r);
        bs_decision_log(r, "none", "debug", "-", "-", "-", "-", 0);
        return OK;
    }

    /* Static assets pass through — a cookieless first page load must still
     * render its CSS/images so the PoW page is usable. */
    if (bs_is_asset_uri(r->uri)) {
        bs_decision_log(r, "nochallenge", "allow", "-", "-", "-", "asset", 0);
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
    /* Does the presented cookie carry proof that a challenge was
     * actually solved, as opposed to merely being a cookie we once
     * handed out? Under always-mint the two are very different things,
     * and several call sites below must not confuse them. */
    int have_solve_proof = 0;
    const char *cookie_verify_reason = NULL;
    int cookie_had_val = (cookie_val && *cookie_val);
    if (cookie_had_val) {
        cookie_verify_reason = bs_verify_cookie(r, cfg, cookie_val, &prior_ch);
        /* : render-side carry-forward must reject the same
         * cverrs the issuance-side carry-forward rejects, otherwise
         * an expired cookie's rep can be transplanted via the
         * interstitial-render path (next_rep is baked into the
         * challenge envelope and round-tripped through the JS,
         * arriving at /embedded-verify before the issuance-side
         * predicate sees it). Sharing bs_should_carry_prior_rep
         * keeps the two predicates from drifting. */
        have_prior_rep = bs_should_carry_prior_rep(cookie_verify_reason,
                                                    &prior_ch);
        /* Record the cookie the client already holds as the base an
         * output filter would amend. A mint later in this request
         * overwrites it; if none happens -- which is the ordinary case
         * for a client whose cookie is still good -- this is what app
         * feedback has to work with. Without it, trust asserted about
         * a returning visitor would land nowhere, which is precisely
         * the visitor it is usually asserted about. */
        if (have_prior_rep) {
            bs_record_outgoing_cookie(r, &prior_ch, cfg);
        }
        /* Solve proof is read off the AUTHENTICATED rep block, so it
         * is gated on have_prior_rep rather than on full cookie
         * validity: a cookie that failed only a post-tag check (PoW
         * counter, etc.) still has trustworthy pass counters, while a
         * signature-mismatched or expired one has none we may believe. */
        if (have_prior_rep) {
            have_solve_proof = prior_ch.rep.passes_non_interactive
                            || prior_ch.rep.passes_interactive
                            || prior_ch.rep.passes_captcha;
        }
        if (!cookie_verify_reason) {
            cookie_fully_ok = 1;
            /* E10 — safeguard clear on solve. Gated on actual solve
             * evidence (passes_non_interactive / passes_interactive / passes_captcha)
             * rather than just cookie validity. Under always-mint,
             * trust=0 presence cookies authenticate cleanly via the
             * GCM tag but represent no challenge solve — they must
             * NOT clear the safeguard counter or a bot would harvest
             * a fresh cookie on its first request and bypass safeguard
             * for every subsequent failed challenge. Only cookies that
             * carry actual solve proof get to clear. */
            if (have_solve_proof) {
                bs_server_cfg *scfg_sg = ap_get_module_config(
                    r->server->module_config, &botshield_module);
                if (scfg_sg && scfg_sg->safeguard_enabled != 0) {
                    unsigned char sg_ip[16];
                    if (bs_parse_client_ip(r->useragent_ip, sg_ip)) {
                        bs_mask_ipv6_prefix(sg_ip,
                                            scfg_sg->ipv6_prefix_bits);
                        bs_safeguard_clear(r, sg_ip, scfg_sg->ns_id);
                    }
                }
            }
        } else {
            /* Log the cookie name actually
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
    /* Split the "ok" bucket on solve proof. Under always-mint a valid
     * cookie is the normal state of every returning client, so "ok"
     * alone answered a question nobody was asking; what an operator
     * needs to see is whether the holder ever passed a challenge.
     * "solved" means verified AND carrying passes_non_interactive/form/captcha;
     * "ok" now means verified with no such proof -- a presence cookie,
     * which is exactly what a cookie-harvesting bot holds. */
    if (have_solve_proof && strcmp(cookie_status, "ok") == 0) {
        cookie_status = "solved";
    }

    /* E4 — publish the `_bs_session` verification verdict as a
     * request note so bs_check_policy's cookietrigger evaluator
     * can surface it via bs-cookie=<state> predicates. Three-state
     * mapping matches the directive surface. */
    {
        const char *bs_state;
        if (!cookie_had_val)           bs_state = BS_CK_STATE_MISSING;
        else if (!cookie_verify_reason) bs_state = BS_CK_STATE_VERIFIED;
        else                           bs_state = BS_CK_STATE_INVALID;
        apr_table_setn(r->notes, BS_CK_STATE_NOTE, bs_state);
        /* Solve proof is a different question from cookie validity --
         * under always-mint every returning client has a valid cookie --
         * so it gets its own note rather than a fourth state. */
        apr_table_setn(r->notes, BS_CK_SOLVED_NOTE,
                       have_solve_proof ? "1" : "0");
    }

    /* Always-mint: install a presence-only session cookie when the
     * request didn't carry a valid one. Centralized here so every
     * terminal outcome below (pass / challenge / block / safeguard
     * redirect / LogOnly decline) ships its response with the
     * Set-Cookie already in err_headers_out. The verify endpoints
     * (/botshield/embedded-verify etc.) don't reach this code —
     * they're routed earlier via bs_route_module_endpoint and do
     * their own higher-trust mints (apr_table_add stacks Set-Cookie;
     * browser uses the latest for the same name).
     *
     * On successful mint, override cookie_status from "absent" to
     * "minted" so the decision-log line distinguishes "request
     * carried no cookie and we did nothing" (cookie=absent, can
     * happen when module is off or secret isn't configured) from
     * "request carried no cookie and we issued one" (cookie=minted,
     * the always-mint case). */
    if (bs_maybe_mint_session(r, cfg, cookie_fully_ok)) {
        cookie_status = "minted";
    }

    /* Attach the UA classification result as a zero-impact score
     * reason so it surfaces in the decision-log line. Reads the
     * unified classification cached on r->pool by
     * bs_classify_request_hook — no extra trie walk here.
     *
     * Every request gets exactly one UA-class tag:
     *   verified-bot:name  (UA + IP confirmed; emitted from allowlist.c)
     *   fake-bot:name      (UA + IP failed;    emitted from allowlist.c)
     *   knownbot:name     (directory match OR allowlist UA pattern without IP check)
     *   unknownbot:token  (heuristic substring hit, no other signal)
     *   browser:slug       (top-100 real-browser template match)
     *   unknownua         (UA present but didn't classify anywhere)
     *   emptyua           (no User-Agent header)
     *
     * Skip emission entirely when allowlist already speaks
     * (is_verified_bot/is_fake_bot) to avoid double-tagging. */
    {
        const bs_ua_class *cls = bs_classify_request_ua(r);
        if (cls && !cls->is_verified_bot && !cls->is_fake_bot) {
            if (cls->is_browser) {
                const char *slug = cls->browser_slug
                                 ? cls->browser_slug : "browser";
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "browser:", slug, NULL));
            } else if (cls->known_slug && *cls->known_slug) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "knownbot:", cls->known_slug, NULL));
            } else if (cls->verified_name && *cls->verified_name) {
                /* Allowlist UA pattern matched but no IP check ran
                 * (UA-only target or ranges not loaded). The
                 * operator-declared name lands in the knownbot pool. */
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "knownbot:", cls->verified_name, NULL));
            } else if (cls->is_unknown_bot && cls->unknown_bot_token) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "unknownbot:", cls->unknown_bot_token, NULL));
            } else {
                /* No classifier signal. Distinguish empty UA (header
                 * missing or empty) from unknown UA (header present
                 * but didn't match templates/directory/heuristic). */
                const char *ua = apr_table_get(r->headers_in, "User-Agent");
                bs_score_add(r, 0, 0,
                    (!ua || !*ua) ? "emptyua" : "unknownua");
            }
        }
    }

    /* E2.1 + E2.2 + E3 policy enforcement. Runs before scoring
     * heuristics so a block / rate / trigger short-circuits cleanly.
     * Applies to cookie-valid requests too — operator policy
     * (including robots.txt and path-based triggers) is independent
     * of bot-ness. */
    int policy_rv = bs_check_policy(r);
    if (policy_rv == DECLINED) {
        /* E3 trigger with respond=nochallenge: log + let the real handler
         * respond. No score, no BotShield interstitial. Flag-IP +
         * tag side effects already applied in bs_check_policy. */
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        bs_decision_log(r, "nochallenge", "allow", cookie_status, "-",
                        "-",
                        reasons, s ? s->total : 0);
        return DECLINED;
    }
    if (policy_rv != OK) {
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        const char *outcome;
        if (policy_rv == HTTP_TOO_MANY_REQUESTS)      outcome = "rate_limited";
        else                                          outcome = "block";
        bs_decision_log(r, "nochallenge", outcome, cookie_status, "-",
                        "-",
                        reasons, s ? s->total : 0);
        return policy_rv;
    }

    /* Score the request. Heuristics always run — a fully-valid cookie
     * doesn't exempt you from fresh request-level signals that might
     * have pushed you into a tier that requires a re-challenge. */
    /* Scoring always runs, and BotShieldScoring is gone.
     *
     * It existed to stop the module acting on rules nobody wrote. That
     * is now handled where the rules are: the default flag slate ships
     * empty, and there are no score thresholds to leave unset. With
     * nothing implicit left to gate, the switch could only do harm --
     * an operator who writes a rule and sees it silently ignored
     * because a second control is off is exactly the
     * silent-misconfiguration shape it was added to prevent. */

    /* Crawler classification: verified against the published ranges,
     * or claiming a crawler from outside them. Tags the decision with
     * verifiedbot:/fakebot: and decides nothing -- ua=@verified-bot
     * and ua=@fake-bot are how a config acts on it.
     *
     * This used to be the first thing bs_run_builtin_heuristics did,
     * which is where it ended up rather than where it belongs: it is
     * not a heuristic, and that function is gone. */
    bs_check_allow(r, cfg);

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
    /* Coarse 0-weight "flaggedip" reason so operators (and tests)
     * reading decision logs see at a glance that this IP is in the
     * flagged-IP table, without having to parse every trigger name.
     * The actual score adjustments flow through bs_apply_flag_triggers
     * below — that walker covers both IP-side and cookie-side flags
     * via the union and emits per-flag `flagtrigger:<name>` reasons. */
    if (ip_flags != 0) {
        bs_score_add(r, 0, 0, "flaggedip");
    }

    /* Bloom-based reputation signals (M5.2). Only fire on cookieless
     * or signature-mismatched requests; sig-verified cookies (even if
     * expired) mean we've already transacted with this browser via
     * cookie state, so neither first-sight nor droppedcookie carry
     * useful signal there.
     *
     * Two heuristics, mutually exclusive based on Bloom membership:
     *   - Bloom miss → firstsightip (truly first visit)
     *   - Bloom hit  → droppedcookie (we know this IP, but they
     *                  arrived without a usable cookie - reset,
     *                  cleared, or evasion)
     *
     * Bloom is populated EAGERLY below — every request with a
     * client IP gets added, regardless of tier outcome. Without
     * eager population, IPs that always pass-tier would never enter
     * Bloom, and "firstsightip" would degrade into "this IP hasn't
     * been challenge-tier-bumped yet" — wrong semantics. */
    /* Not for declared crawlers. Both heuristics detect "no session
     * context", which is suspicious for a browser and simply normal for
     * a crawler -- they do not carry cookies, and penalising them for
     * it made every known bot cross the noninteractive threshold on arrival
     * (semrush-bl measured 40: missingacceptlanguage 15 +
     * droppedcookie 25). Known bots are meant to be admitted and
     * governed by robots.txt and rate limits, not challenged for being
     * stateless.
     *
     * Deliberately keyed on is_known_bot, so it does NOT cover
     * is_fake_bot: a UA claiming a crawler whose IP failed the ranges
     * cross-check keeps every penalty, including these. The other
     * bot-shaped signals -- missingua, scraperua, the fake-bot
     * penalty itself -- are untouched.
     *
     * UA-only trust is spoofable, and the answer to that is the rate
     * limit, not a challenge: a spoofer claiming a crawler UA inherits
     * that crawler's declared budget. */
    const bs_ua_class *uac_h = bs_classify_request_ua(r);
    /* LIBRARY_OR_TOOL is NOT a declared crawler. The exemption below
     * exists because a real crawler -- one with a published identity,
     * an operator, and verifiable IP ranges -- is legitimately
     * stateless, and penalising it for carrying no cookie made every
     * known bot cross the noninteractive threshold on arrival.
     *
     * None of that applies to a generic HTTP client library. The
     * directory lists python-requests, python-httpx, Go-http-client,
     * okhttp, GuzzleHttp, PycURL and Scrapy under this category --
     * Scrapy being a scraping framework by name. Granting them the
     * stateless exemption waived firstsightip (20) and
     * droppedcookie (25), which put the most common scraper
     * transports BELOW an anonymous browser: measured at score 15 and
     * admitted, where the same request from an unknown UA scored 20
     * and was challenged. A library string is evidence about the
     * transport, not about who is driving it. */
    int declared_crawler = bs_ua_is_declared_crawler(uac_h);
    if (declared_crawler) {
        bs_score_add(r, 0, 0, "knownbotstatelessok");
    }
    /* Gated on have_solve_proof, NOT have_prior_rep. A cookie only
     * earns the waiver by proving a challenge was solved; merely
     * holding one we handed out proves nothing but that the client
     * keeps a cookie jar.
     *
     * Under always-mint, every client gets a signature-valid cookie on
     * its first request. Waiving on validity alone let a bot mint one,
     * store it, and permanently suppress a 25-point penalty it had
     * never earned -- measured on this hub as no-UA scanners sitting
     * at score 45 (noninteractive tier) instead of 70 (interactive tier), i.e. using
     * cookie persistence to hold themselves in the CHEAPER challenge
     * tier. Same reasoning the safeguard-clear path above already
     * applies; these two call sites had drifted apart.
     *
     * Cost to real browsers is one noninteractive challenge: they arrive with
     * no proof, get scored 25 (droppedcookie) into the noninteractive tier,
     * solve it transparently, and every later request carries
     * passes_non_interactive and lands back here clean. */
    /* The firstsightip / droppedcookie scores were applied here, under
     * this same guard. They are rules now -- firstsight=yes solved=no
     * crawler=no, and its negation -- and the guard reads as those
     * three conditions because that is what it always was. */
    /* Population sits here, after policy, and that placement is
     * load-bearing rather than incidental.
     *
     * A request a rule refused never reaches this line, so a refused
     * address does not enter the filter. That reads like a bug against
     * the old comment here -- which claimed every request with a client
     * IP feeds the filter -- and moving it earlier was tried. Four
     * tests caught why it is wrong: droppedcookie means "known address
     * arriving without a usable cookie", and its suspicion is that the
     * client was given a cookie and is not presenting it. A refused
     * request never reached a mint, so that client has no cookie to
     * present. Recording it turns droppedcookie into a 25-point penalty
     * for having been blocked once, against a threshold of 20.
     *
     * So this filter answers "was this address given a chance to hold a
     * cookie", not "has this address been seen". BotShieldFirstSight
     * reads the same filter and inherits the same meaning, which is the
     * consistency that matters: a rule and the heuristics must not
     * disagree about the same address. */
    if (have_client_ip) bs_bloom_add(client_ip, scfg_h->ns_id);

    /* Flag-trigger walker. Walks scfg->flag_triggers over the union
     * of IP-side and cookie-side flag bits, applying `score add=N`
     * actions via bs_score_add or a named accumulator, and
     * accumulating MAX into a tier_floor. Nothing is seeded; operators
     * declare what they want via BotShieldFlagTrigger. */
    /* The union this walker has always advertised. cookie_flags is
     * gated on have_prior_rep for the same reason the solve proof
     * below is: the GCM tag is what makes the rep block trustworthy,
     * and an unauthenticated cookie must not be able to assert a flag
     * about its own bearer -- in either direction. */
    apr_uint32_t cookie_flags = have_prior_rep ? prior_ch.rep.flags_active : 0;
    apr_uint32_t all_flags = ip_flags | cookie_flags;
    /* Skip flags this client already answered for. Solving does not
     * clear a flag and flag scores re-apply every request, so without
     * this a flag worth more than BotShieldScoreNonInteractive is an unbreakable
     * loop: solve, get re-flagged, get re-challenged, forever. Observed
     * in production as pow_ok succeeding once a second, each success
     * followed immediately by another challenge carrying cookie=solved.
     *
     * Only genuine solve proof excuses anything -- a presence cookie
     * ("ok", which is what a cookie-harvesting bot holds) does not.
     * Flags acquired after the solve are not in the excused set and
     * still fire, so this forgives the debt that existed at solve time
     * rather than granting blanket immunity. The cookie's own lifetime
     * bounds it; no separate TTL. */
    apr_uint32_t excused = (have_solve_proof && have_prior_rep)
                         ? prior_ch.rep.flags_excused : 0;
    apr_uint32_t firing_flags = all_flags & ~excused;
    if (all_flags & excused) {
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "flags-excused:0x%x",
                         (unsigned)(all_flags & excused)));
    }
    bs_tier tier_floor_from_flags = BS_TIER_PASS;
    int flag_block_status = 0;
    const char *flag_block_name = NULL;
    /* Flag score AND tier_floor actions are both implicit, so both are
     * gated. Leaving tier_floor on with scoring off would keep the
     * exact hazard this directive exists to remove: a floor that
     * ignores the verified-bot credit. */
    bs_apply_flag_triggers(r, scfg_h, firing_flags, all_flags,
                           &tier_floor_from_flags,
                           &flag_block_status, &flag_block_name);

    /* A block ends the request here, before any tier is chosen.
     *
     * Read from the un-excused set on purpose: solving a challenge
     * pays off the flags that were live at solve time, and a refusal
     * is not a debt a client can work off. The inverse -- letting a
     * solve clear a block -- would make "blocked" mean "solve a
     * challenge to continue", which is what a challenge tier already
     * says and not what an operator writing block asked for.
     *
     * Safe to leave un-excusable only because it terminates. A flag
     * that forces a challenge and cannot be excused is the loop that
     * reached production twice. */
    if (flag_block_status) {
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "flagblock:%s", flag_block_name));
        bs_decision_log(r, "nochallenge", "block", cookie_status,
                        "-", "-",
                        apr_psprintf(r->pool, "flagblock:%s",
                                     flag_block_name), 0);
        return flag_block_status;
    }

    /* Fetch the score struct *after* all per-request adds. Using create=1
     * so a request with zero hits still gets a valid (empty) pointer and
     * the log line prints reasons=[] consistently. */
    bs_request_score *score = bs_get_score(r, 1);
    int heuristic_total = score->total;

    /* effective_score = per-request heuristic total (already inclusive
     * of any flagtrigger SCORE actions applied above) + the cookie's
     * accumulated rep score. Operator-facing tuning workflow lives
     * in the README "Understanding scoring" section. */
    int cookie_score = have_prior_rep ? prior_ch.rep.score : 0;
    int effective    = heuristic_total + cookie_score;
    /* The cumulative score decides nothing. It is still computed and
     * still logged -- what it cost and what it caught are worth
     * reading -- but the three cut-points that turned it into a tier
     * are gone, and a named accumulator plus BotShieldChallengeAtLeast
     * says the same thing where an operator can see which signal paid
     * for which challenge. */
    bs_tier score_tier = BS_TIER_PASS;

    /* Apply the tier floor accumulated by the flagtrigger walker
     * (MAX of any TIER_FLOOR actions across the union of flags).
     * The score-derived tier wins when it's already at-or-above the
     * floor — we never silently downgrade. */
    /* A trigger tier= floor composes with the flag floor and the
     * score-derived tier by MAX, same as everything else here. */
    /* Named accumulators -> tier floor. Evaluated here, beside
     * the tier decision, because this is after robots and the rate
     * limiter: a request those refused never reaches this line, and so
     * is never challenged in place of being refused. */
    if (cfg->challenge_at_least && !cfg->challenge_at_least_reset) {
        for (int i = 0; i < cfg->challenge_at_least->nelts; i++) {
            const bs_challenge_min *row = APR_ARRAY_IDX(
                cfg->challenge_at_least, i, const bs_challenge_min *);
            if (bs_request_named_score(r, row->name) < row->min) continue;
            /* Into score_tier, not the flag floor. This IS the
             * score-to-tier mapping -- reading a named accumulator
             * rather than the ambient total -- and attributing it to
             * flags would put flagtierfloor: in the reason trace for a
             * tier no flag chose. */
            if ((bs_tier)row->tier > score_tier) {
                score_tier = (bs_tier)row->tier;
            }
            bs_score_add(r, 0, 0,
                apr_psprintf(r->pool, "score:%s>=%d:%s",
                             row->name, row->min,
                             bs_tier_name((bs_tier)row->tier)));
        }
    }

    bs_tier trig_floor = (bs_tier)bs_get_request_tier_floor(r);
    if (trig_floor > tier_floor_from_flags) {
        tier_floor_from_flags = trig_floor;
    }
    bs_tier tier = (tier_floor_from_flags > score_tier)
                 ? tier_floor_from_flags : score_tier;
    if (tier_floor_from_flags > score_tier) {
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "flagtierfloor:%s",
                         bs_tier_name(tier_floor_from_flags)));
    }

    /* BotShieldChallenge Off — collapse any challenge tier back to pass
     * for this scope. Deliberately applied AFTER the floor MAX above: a
     * flag tier_floor ignores the score thresholds entirely, so parking
     * BotShieldScoreNonInteractive/Hard/Captcha cannot express "never challenge
     * here" on its own. This can.
     *
     * Everything else still runs — triggers act, rate limits act, score
     * accumulates, the decision is logged. Only the rendering is
     * suppressed, and the suppression is visible in the reason chain
     * rather than quietly, in the same spirit as :observe and the
     * ~counterfactual outcomes. */
    if (cfg->challenge_enabled == 0 && tier != BS_TIER_PASS) {
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "challengeoff:%s", bs_tier_name(tier)));
        tier = BS_TIER_PASS;
    }

    /* Per-scope flag/TTL writes happen inside bs_check_policy via
     * the BotShieldTrigger walker (BS_TFAMILY_SCOPE). The legacy
     * BotShieldFlagIP directive that used to live here was
     * superseded by `BotShieldTrigger flag=<name> ttl=<sec>`. */

    /* Happy path: score below the noninteractive threshold → pass through.
     * If there's no cookie this means no cookie is ever issued —
     * legitimate users experience mod_botshield as invisible. */
    if (tier == BS_TIER_PASS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_botshield: pass %s effective=%d "
                      "(heuristic=%d cookie_score=%d "
                      "ip_flags=0x%x excused=0x%x) cookie_ok=%d",
                      r->uri, effective, heuristic_total, cookie_score,
                      (unsigned)ip_flags,
                      have_prior_rep ? (unsigned)prior_ch.rep.flags_excused : 0,
                      cookie_fully_ok);
        /* E8.2 — module-to-app reputation export. Strip incoming
         * X-Botshield-* and set a single signed claim envelope so
         * the backend handler reads sanctioned BotShield state
         * without poking at the (encrypted post-E8.1) cookie. */
        {
            bs_server_cfg *scfg2 = ap_get_module_config(
                r->server->module_config, &botshield_module);
            /* Deliberately the raw IP-side set, not the post-excusal
             * firing set: the app is being told what BotShield knows
             * about this client, and a flag that was excused from
             * scoring is still a fact about it. Excusal governs whether
             * we re-challenge, not what we report. */
            apr_uint32_t composite_flags = ip_flags;
            const char *cerr = bs_app_claims_set(r, scfg2,
                effective, tier, cookie_status, composite_flags,
                have_prior_rep ? prior_ch.rep.passes_non_interactive  : 0,
                have_prior_rep ? prior_ch.rep.passes_interactive    : 0,
                have_prior_rep ? prior_ch.rep.passes_captcha : 0);
            if (cerr) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                    "mod_botshield: app claims not emitted: %s", cerr);
            }
        }
        bs_decision_log(r, "nochallenge", "allow", cookie_status,
                        "-",
                        "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

    /* BotShieldEnabled LogOnly — dry-run mode. Log what the tier
     * decision would have produced and DECLINE instead of issuing
     * a challenge. Skips Bloom / safeguard / IP-flag side effects so
     * the dry-run is purely observational; the operator gets a
     * per-request decision log without any client seeing an
     * interstitial or failed challenge. The trigger / rate-limit
     * machinery has its own observe paths (honored elsewhere); this
     * branch is the tier-dispatch counterpart. */
    if (cfg && cfg->enabled == BS_ENABLED_LOGONLY) {
        bs_set_would_outcome(r, "~challenge");
        bs_decision_log(r, bs_tier_name(tier), "allow",
                        cookie_status, "-",
                        cfg->algorithm ? cfg->algorithm->name : "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

    /* Bloom is populated eagerly above (right after first-sight /
     * droppedcookie dispatch), so by this point the IP is already
     * recorded for future requests regardless of tier. The pre-eager
     * implementation populated only here, which created the misleading
     * firstsightip semantics this code path used to live with. */

    int safeguard_rv = bs_apply_safeguard(r, have_client_ip, client_ip,
                                          cookie_status, score, effective);
    if (safeguard_rv != OK) return safeguard_rv;

    /* E17 — noninteractive tier dispatch with embedded mode. Default behavior:
     * skip the M7 interstitial, serve the real page (DECLINED), let
     * the wrapper handle verification in the background. Timing model:
     * "kicks in eventually" — see CHANGELOG.
     *
     * Embedded → interactive PoW fallback: if this client has had N
     * consecutive noninteractive tier dispatches without _bs_session
     * arriving (count tracked via bs_safeguard_present_count), the
     * wrapper isn't doing its job (CSP-blocked, no JS, no Worker
     * support, etc.). Bypass the embedded short-circuit so the
     * interactive PoW path runs. The interactive PoW path's own safeguard
     * threshold catches the case where it also fails. */
    if (tier == BS_TIER_NONINTERACTIVE &&
        cfg->non_interactive_mode == BS_NON_INTERACTIVE_MODE_EMBEDDED) {
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
            bs_decision_log(r, "noninteractive", "allow", cookie_status,
                            "-",
                            "-",
                            bs_decision_reason_names(r->pool, score),
                            effective);
            return DECLINED;
        }
        /* Fall through to M7 — the embedded path has had its
         * chances. Surface the decision in the reason chain so
         * operators can spot clients stuck in this state. */
        bs_score_add(r, 0, 0, "embeddedfallbackm7");
    }

    /* `issue_auto` picks the interactive PoW interstitial style: the
     * noninteractive tier auto-submit splash (issue_auto=1) for low-friction
     * challenges, the visible form interstitial (issue_auto=0) for
     * the harder tier. Captcha tier is rendered separately by
     * bs_render_challenge_page when cfg->captcha_provider is set;
     * if the operator selected captcha tier without configuring a
     * provider, render falls through to the interactive PoW interstitial
     * with reason "captcha_fallback" on the decision log. */
    int issue_auto = (tier == BS_TIER_NONINTERACTIVE);

    /* Build the rep state to carry into the new cookie. Forgiveness +
     * pass-counter bump are picked from the tier the *prior* cookie was
     * served under (prior_ch.auto_tier), because that records what the
     * user actually just solved. First-time challenges have no prior
     * tier, so they increment whichever counter matches the tier we're
     * about to issue. */
    bs_rep_state next_rep;
    /* Zeroed up front so a field added to bs_rep_state later cannot
     * reach a client as stack garbage. The else branch below assigns
     * every field it knows about, and that was a complete list right up
     * until rep gained burned_until (since removed) -- at which point
     * a first-time client was handed a cookie carrying whatever the
     * stack held, GCM-signed so it read back as authentic, and was
     * refused with burnedcookie on its very next request. Nothing in
     * the config said burn, and no amount of reading the trigger code
     * would have shown why. The field is gone; the next one added
     * would land the same way, which is what this memset is for. */
    memset(&next_rep, 0, sizeof(next_rep));
    if (have_prior_rep) {
        int forgive = prior_ch.auto_tier
            ? bs_effective_int(cfg->forgive_non_interactive, BS_DEFAULT_FORGIVE_NON_INTERACTIVE)
            : bs_effective_int(cfg->forgive_interactive,   BS_DEFAULT_FORGIVE_INTERACTIVE);
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
        /* The forgiven score has no flag-derived floor. Flag effects
         * re-apply at request time, so forgiveness alone never breaks
         * a flagged client out of a challenge loop -- that is what
         * flags_excused below is for. */
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < 0) new_score = 0;
        next_rep.score = new_score;
        if (prior_ch.auto_tier) {
            next_rep.passes_non_interactive = 1;  /* clamp */
        } else {
            next_rep.passes_interactive = 1;  /* clamp */
        }
    } else {
        next_rep.score          = 0;
        next_rep.flags_excused  = 0;
        next_rep.passes_non_interactive  = issue_auto ? 1 : 0;
        next_rep.passes_interactive    = issue_auto ? 0 : 1;
        next_rep.passes_captcha = 0;
        next_rep.challenged_at  = 0;   /* overwritten by issue() */
        next_rep.forgive_window_start = 0;
        next_rep.forgive_consumed     = 0;
    }

    /* Stamp the flags this client is being challenged over into the
     * cookie we are about to issue.
     *
     * Needed because the M7 form path never re-mints: the client
     * assembles its cookie as <envelope>.<counter> from the envelope
     * issued right here, and no server-side mint follows the solve. The
     * verify endpoints DO re-mint and stamp this themselves, so this is
     * the same excusal arriving by the only route the interactive tier has.
     *
     * Safe to record before the work is done, because the envelope is
     * inert without a valid PoW counter -- a client that never solves
     * can never present this cookie, so "excused at issue" and "excused
     * on solve" are the same event from the server's side.
     *
     * OR'd so re-challenges accumulate rather than resetting what an
     * earlier solve already settled. */
    next_rep.flags_excused |= all_flags;

    /* Same pending set as the session mint. A challenge response is
     * still a response, and a rule that flagged this request must not
     * lose its mark just because the request also happened to earn a
     * challenge. */
    {
        const char *pending = apr_table_get(r->notes, "bs-session-flags");
        if (pending) {
            unsigned padd = 0, pdel = 0, prep = 0;
            if (sscanf(pending, "%x:%x:%u", &padd, &pdel, &prep) == 3) {
                next_rep.flags_active = prep
                    ? (apr_uint32_t)padd
                    : ((next_rep.flags_active | (apr_uint32_t)padd)
                       & ~(apr_uint32_t)pdel);
            }
        }
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
                  have_prior_rep ? (unsigned)prior_ch.rep.flags_excused : 0,
                  cookie_fully_ok,
                  next_rep.passes_non_interactive, next_rep.passes_interactive,
                  next_rep.passes_captcha);
    /* Difficulty stays at the operator-configured BotShieldDifficulty.
     * Tier (noninteractive / interactive / captcha) is the primary lever for "this
     * signal needs harder verification" via BotShieldFlagTrigger
     * action=tier_floor. If a real future need for "harder PoW for
     * this signal" surfaces, add a difficulty action verb at that
     * time; don't pre-emptively reintroduce one. */

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

    int use_captcha_widget = bs_render_challenge_page(r, cfg, tier,
                                                     challenge_js,
                                                     issue_auto);

    /* Decision log for the challenge we just served. For non-captcha
     * tiers the provider/alg are the PoW algorithm the cookie will be
     * signed under; captcha tier names the configured provider and its
     * cookie alg. When captcha tier falls through to interactive PoW (no
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
         * scope — interstitial we actually served is interactive PoW. Label
         * honestly. */
        served_tier_name = "interactive";
        served_reason    = (!score || !score->entries ||
                            score->entries->nelts == 0)
            ? "captcha_fallback"
            : apr_pstrcat(r->pool, "captcha_fallback,", served_reason, NULL);
    }
    bs_decision_log(r, served_tier_name, "challenged", cookie_status,
                    served_provider, served_alg, served_reason, effective);
    return OK;
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
    ap_hook_test_config (bs_test_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init  (bs_child_init,  NULL, NULL, APR_HOOK_MIDDLE);
    /* REALLY_FIRST, not FIRST. mod_proxy also registers its content
     * handler at APR_HOOK_FIRST; ties there break on module load order,
     * and mod_proxy loads first -- so it answered every ProxyPass'd
     * request before this module ran, and no policy could reach those
     * paths. On one production hub that silently exempted /index.php
     * (the homepage target and the OAuth callback),
     * /administrator/index.php and /api/index.php: the three most
     * sensitive entry points on the site.
     *
     * Diagnosed rather than guessed. A fixups probe showed the request
     * arriving with proxyreq=2, handler=proxy-server AND enabled=2
     * (LogOnly) -- the phases ran and the per-directory config merged
     * correctly; only this module's handler never fired. That ruled out
     * the phase-ordering theories and left handler precedence.
     *
     * Declining still hands the request back: mod_proxy serves anything
     * this module passes on, so a proxied path is now evaluated exactly
     * like any other and proxied exactly as before. */
    ap_hook_handler     (bs_handler,     NULL, NULL, APR_HOOK_REALLY_FIRST);
    /* Unified UA classifier — runs late in post_read_request so
     * mod_remoteip's earlier hook (default APR_HOOK_FIRST) has
     * rewritten r->useragent_ip into the real client address before
     * we do the verified-bot IP cross-check. The result is cached on
     * r->pool so every downstream consumer reads the same answer. */
    ap_hook_post_read_request(bs_classify_request_hook,
                              NULL, NULL, APR_HOOK_LAST);
    {
        extern int bs_propagate_decision_env(request_rec *r);
        ap_hook_log_transaction(bs_propagate_decision_env,
                                NULL, NULL, APR_HOOK_FIRST);
    }
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
