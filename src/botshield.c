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
 *   - policy-status handler   : the admin-visible /botshield/policy-status
 *                               text dump
 *   - bs_decide_tier          : score → (pass | silent | form | captcha)
 *
 * Everything else fans out through the per-feature .h includes below.
 * Each subsystem owns its runtime, its directive setters, and its tests.
 *
 * Operator model. Four tiers, decided per request from a running score:
 *   pass     no challenge, real handler runs
 *   silent   embedded silent-tier verification (E17) or auto-submit splash
 *   form     visible form-PoW interstitial — a checkbox the JS solves
 *   captcha  third-party provider widget (Turnstile, hCaptcha, reCAPTCHA,
 *            Friendly, GeeTest) on the M8 verify endpoint
 *
 * The tier-earned cookie (_bs_verified or __Host-bs_verified, AES-GCM
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
#include "metrics.h"   /* M9 — decision log, counters, Prometheus, mod_status */
#include "botshield.h" /* module-wide types: bs_dir_cfg, bs_server_cfg, ... */
#include "config.h"    /* module-config lifecycle (create/merge/post/child) */
#include "cookie.h"    /* GCM cookie envelope mint/verify, Cookie-header parser */
#include "challenge.h" /* M7 — challenge issuance, alg registry, bootstrap-sig */
#include "load.h"      /* E11 — load-aware throttling watchdog + state read */
#include "triggers.h"  /* E3/E4/E6/E7.3/E11.2 — trigger families */
#include "silent.h"    /* E17 — silent-tier embedded handlers */
#include "captcha.h"   /* M8 — provider registry, siteverify, pending cookie */
#include "bridge.h"    /* E5 + E8.2 — module ↔ app feedback / claims bridge */
#include "templates.h" /* challenge page widget + shell rendering */
#include "formcaptcha.h" /* E18 — inline form-captcha tier */
#include "score.h"     /* per-request score + flag-trigger walker */
#include "policy.h"    /* request-time policy walker */
#include "heuristics.h" /* cheap built-in score signals */

/* This file is the module's hooks-table spine: bs_handler (the
 * request entry hook), the cmds[] directive table, bs_register_hooks,
 * and the botshield_module struct. Plus a few thin helpers that
 * bs_handler calls directly (bs_decide_tier, bs_tier_name, the
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
                 "Seconds a verified cookie stays valid (default: 3600, "
                 "range 1..86400)"),
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
                 "Proof-of-work algorithm name. Only 'sha256-zeros' is built "
                 "into this module today; 'sha384-zeros' / 'sha512-zeros' / "
                 "'pbkdf2-sha256' / 'argon2id' are registry slots reserved "
                 "for future opt-in builds."),
    AP_INIT_TAKE1("BotShieldScoreSilent",  bs_set_score_silent,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the silent-PoW tier is picked "
                 "(default: 20). Serves a no-click auto-submit splash."),
    AP_INIT_TAKE1("BotShieldScoreHard",    bs_set_score_hard,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the form-PoW tier is picked "
                 "(default: 50). Serves the checkbox interstitial."),
    AP_INIT_TAKE1("BotShieldScoreCaptcha", bs_set_score_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the captcha tier is picked "
                 "(default: 80). Serves the configured third-party "
                 "provider's widget; falls through to form-PoW if no "
                 "BotShieldCaptchaProvider is set on the scope."),
    /* E18 — inline form captcha. */
    AP_INIT_FLAG("BotShieldFormCaptcha", bs_set_form_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "When on, this scope validates a configured captcha "
                 "provider's response token in the POST body of form "
                 "submissions. Requires BotShieldCaptchaProvider + "
                 "SiteKey + SecretFile in the same scope (or "
                 "inherited). On valid token: mints _bs_verified, "
                 "DECLINED so the app handler runs with the original "
                 "body intact. On bad/missing token: 403, app handler "
                 "never runs. Supports application/x-www-form-"
                 "urlencoded and application/json bodies; "
                 "multipart/form-data (file uploads) is out of scope."),
    /* Silent-tier dispatch flavor. */
    AP_INIT_TAKE1("BotShieldSilentMode", bs_set_silent_mode, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "How to dispatch silent-tier (low-friction) "
                 "challenges. 'interstitial' (default) = legacy M7 "
                 "auto-submit splash. 'embedded' = serve real page "
                 "(DECLINED) and rely on the operator-included "
                 "/botshield/embedded.js wrapper to do PoW in a Web "
                 "Worker and POST the result back to "
                 "/botshield/embedded-verify. The verified cookie "
                 "may not arrive in time for the very first request, "
                 "but it lands within a few page-views — see CHANGELOG "
                 "E17 for the timing model."),
    AP_INIT_TAKE1("BotShieldForgivenessSilent", bs_set_forgive_silent, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful silent-PoW pass "
                 "(default: 10). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessForm",   bs_set_forgive_form,   NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful form-PoW pass "
                 "(default: 25). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessCaptcha",bs_set_forgive_captcha,NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful captcha pass "
                 "(default: 50). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldCookieDomain", bs_set_cookie_domain, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "If set, Set-Cookie for _bs_verified includes a Domain= "
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
    AP_INIT_TAKE_ARGV("BotShieldTrigger", bs_set_trigger, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Per-scope trigger: the Apache scope (server / "
                 "<VirtualHost> / <Directory> / <Location> / "
                 "<LocationMatch> / <Files> / <If>) the directive "
                 "lives in IS the predicate. Action keys: "
                 "status=<code|pass>, redirect=<url>, log=<tag>, "
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
    AP_INIT_FLAG("BotShieldAllow", bs_set_allow_enabled,
                 NULL, RSRC_CONF,
                 "Enable the Allow family (verified-bot first member). "
                 "Default off. When on, classified bot UAs are matched "
                 "against loaded IP ranges: in-range gets a large "
                 "negative credit (tier=pass bypass); out-of-range "
                 "gets a fake-<name> penalty routing to captcha tier."),
    AP_INIT_TAKE23("BotShieldAllowBot",
                 bs_set_allow_bot, NULL, RSRC_CONF,
                 "Register a bot for the Allow family. Args: "
                 "<name> <ua-pattern> [<target>]. Name is a [a-z0-9-] "
                 "token used as the decision-log identifier and "
                 "default ranges-file basename. UA-pattern is the "
                 "case-insensitive substring looked for in the "
                 "User-Agent header. Optional target: '*' for UA-only "
                 "trust (logs allow-bot-ua:<name>), an absolute file "
                 "path, a single CIDR, or a comma-separated CIDR "
                 "list. Omit the target to use the default file path "
                 "/var/lib/botshield/bots/<name>.txt."),
    /* E2.1 — policy enforcement. TAKE_ARGV because Apache has no
     * TAKE4/TAKE5 macros; the setters enforce argc themselves. */
    AP_INIT_TAKE_ARGV("BotShieldRateLimit",
                 bs_set_rate_limit, NULL, RSRC_CONF,
                 "Rate-limit a named cohort. Args: <name> <budget> "
                 "<per> <ua> <ipspec>. Per is sec/min/hour (or "
                 "s/m/h). UA is a substring (case-insensitive) or "
                 "'*' for any UA. Ipspec is '*', an absolute file "
                 "path, or a single / comma-separated CIDR list. "
                 "Both-'*' is rejected. Over-budget requests return "
                 "429 + Retry-After and get a +50 score penalty "
                 "under reason rate-limit-exceeded:<name>."),
    /* E9 — repeated-429 escalation. Sits on top of BotShieldRateLimit;
     * does not apply to robots.txt Crawl-delay 429s in v1 (no operator
     * handle for them). */
    AP_INIT_TAKE_ARGV("BotShieldRateLimitEscalate",
                 bs_set_rate_limit_escalate, NULL, RSRC_CONF,
                 "Promote repeated 429s on a named BotShieldRateLimit "
                 "into a stricter status. Args: <rate-name> <strikes> "
                 "<per> [status=<code>] [ttl=<sec>] [log=<tag>]. "
                 "Per accepts sec/min/hour. Once <strikes> rejected "
                 "requests accumulate within <per>, subsequent "
                 "requests against the same rule return status= "
                 "(default 403) for ttl= seconds (default 1800). The "
                 "ttl slides on each additional strike; log=<tag> "
                 "rides the decision line on threshold crossing for "
                 "fail2ban handoff. Reason rate-limit-abuse:<name>."),
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
                 "Enable anti-loop hysteresis (default off). When on, "
                 "a client that gets challenged N times within W "
                 "seconds without solving any challenge is passed "
                 "through for a TTL window instead of being re-"
                 "challenged. Decision log shows reason "
                 "challenge-safeguard. Doesn't mint _bs_verified; "
                 "doesn't override 403/429 blocks."),
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
    /* E12 — log-only / dry-run enforcement. */
    AP_INIT_FLAG("BotShieldLogOnly",
                 bs_set_log_only, NULL, RSRC_CONF,
                 "Master switch for dry-run enforcement. When on, all "
                 "client-visible enforcement is suppressed and logged "
                 "instead: trigger / rate-limit / block-path rules log "
                 "matches with a :observe suffix, AND tier decisions "
                 "(silent / hard / captcha) emit a 'would-challenge' "
                 "decision log line and decline rather than serving an "
                 "interstitial. Useful for staging a whole policy "
                 "revision — including bare 'BotShieldEnabled On' on a "
                 "fresh vhost — and watching what the module would do "
                 "before any real client sees a challenge. Default "
                 "off; per-rule mode=observe is the finer-grained "
                 "alternative for staging a single rule. Typical "
                 "workflow: turn on at vhost scope, raise LogLevel "
                 "(e.g. 'LogLevel botshield:info'), watch the decision "
                 "log, flip off when matches look right."),
    /* Flag-driven trigger family. */
    AP_INIT_TAKE_ARGV("BotShieldFlagTrigger",
                 bs_set_flag_trigger, NULL, RSRC_CONF,
                 "Apply an action when a flag bit fires on the IP- "
                 "or cookie-side bitmap of a request. Args: <flag> "
                 "[reset] [action=<verb> args...]. Flag names: "
                 "honeypot_hit, scanner_probe, fake_bot, "
                 "pow_fail_streak, app_verified_human, "
                 "app_verified_session, app_trust_signal. Action "
                 "verbs: 'score add=N' (signed, -1000..1000; SUMs "
                 "across triggers) or 'tier_floor min=<tier>' "
                 "(pass|silent|form|captcha; MAXes across triggers). "
                 "'reset' clears compiled-in defaults + prior "
                 "operator declarations for the named flag before "
                 "this directive's effect is added. mode=observe "
                 "logs would-flag-trigger:<flag>:observe instead of "
                 "applying. Compiled-in defaults cover the common "
                 "cases — see example/flag-triggers.conf.example."),
    /* Heuristic-driven trigger family. Same shape as the flag family
     * but the predicate is a compile-time named heuristic on the
     * request itself rather than a flag bit. */
    AP_INIT_TAKE_ARGV("BotShieldHeuristicTrigger",
                 bs_set_heuristic_trigger, NULL, RSRC_CONF,
                 "Bind an action to one of the built-in request "
                 "heuristics. Args: <name>|all [reset] [action=<verb> "
                 "args...]. Names: missing-ua (UA absent or empty), "
                 "missing-al (Accept-Language absent), scraper-ua "
                 "(UA contains a known HTTP-library token), "
                 "first-sight-ip (Bloom-filter miss for the client "
                 "IP). Action verbs: 'score add=N' (signed, "
                 "-1000..1000) or 'tier_floor min=<tier>'. "
                 "'<name> reset' clears defaults + prior declarations "
                 "for that name; 'all reset' wipes every entry "
                 "(defaults included) so the operator can build the "
                 "slate up from zero. mode=observe logs the match "
                 "with a :observe suffix instead of applying. "
                 "Compiled-in defaults: missing-ua=40, missing-al=15, "
                 "scraper-ua=50, first-sight-ip=5."),
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
    AP_INIT_TAKE_ARGV("BotShieldBlockPath",
                 bs_set_block_path, NULL, RSRC_CONF,
                 "Block a named cohort from a path glob. Args: "
                 "<name> <path-glob> <ua> <ipspec>. Path-glob must "
                 "begin with '/'; trailing '*' = prefix match, "
                 "trailing '$' = exact match. Hits return 403 with "
                 "a +100 score penalty under reason "
                 "block-path:<name>."),
    /* E4 — cookie triggers */
    AP_INIT_TAKE_ARGV("BotShieldCookieTrigger",
                 bs_set_cookie_trigger, NULL, RSRC_CONF,
                 "Cookie-based trigger. Args: <name> <cookie-match> "
                 "[key=value ...]. cookie-match is one of: "
                 "cookie=<n>, cookie=<n>=<v>, cookie=<n>~<substr>, "
                 "cookie=<n>!<v>, !cookie=<n>, cookies=<none|any|"
                 "session>, bs-cookie=<verified|missing|invalid>. "
                 "Keys: status=<code|pass> (default pass; diverges "
                 "from E3 — credit/penalty here ALWAYS apply, even "
                 "under pass), redirect=<url>, log=<tag>, flag=<bit>, "
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
                 bs_set_env_trigger, NULL, RSRC_CONF,
                 "Env-var-based trigger, reads r->subprocess_env. "
                 "Args: <name> <env-match> [key=value ...]. "
                 "env-match is one of: env=<var> (present), "
                 "env=<var>=<value> (exact match, case-sensitive), "
                 "!env=<var> (absent). Keys: status=<code|pass> "
                 "(default pass; credit/penalty apply under pass "
                 "like E4), log=<tag>, flag=<bit>, ttl=<sec>, "
                 "penalty=<n>, credit=<n>. No redirect= (env "
                 "signals are scoring/flagging only). Declaration "
                 "order, first match wins; upsert-by-name. Main "
                 "requests only — subrequests are no-ops."),
    /* E7.3 — feedback triggers (response-path mapping for E5) */
    AP_INIT_TAKE_ARGV("BotShieldFeedbackTrigger",
                 bs_set_feedback_trigger, NULL, RSRC_CONF,
                 "Map an app-signed event (via X-BotShield-Feedback "
                 "header) to module memory. Args: <event> "
                 "[key=value ...]. Required keys: flag=<bit>, "
                 "ttl=<sec>. Optional: log=<tag>. The app signs "
                 "event=<name>;sig=<hex>; the module looks up <name> "
                 "here and applies flag+ttl to the flagged-IP table. "
                 "No status/redirect/penalty/credit (response is "
                 "already served)."),
    /* E11.2 — load-aware throttling triggers */
    AP_INIT_TAKE_ARGV("BotShieldLoadTrigger",
                 bs_set_load_trigger, NULL, RSRC_CONF,
                 "Trigger that fires based on the cached load state "
                 "(see BotShieldLoadStateFile / E11). Args: <name> "
                 "<load-match> [key=value ...]. load-match is one of "
                 "state=<level> or state>=<level> where <level> is "
                 "normal|warm|hot. Keys: status=<code|pass>, "
                 "log=<tag>, penalty=<n>, credit=<n>. flag/ttl/"
                 "redirect rejected — load is global state, not "
                 "per-IP behavior. First-match-wins."),
    /* E3 — path-based triggers */
    AP_INIT_TAKE_ARGV("BotShieldPathTrigger",
                 bs_set_path_trigger, NULL, RSRC_CONF,
                 "Path-based trigger. Args: <name> <path-glob> "
                 "[key=value ...]. Keys: status=<code|pass> (default "
                 "403; 'pass' means the real handler runs), "
                 "redirect=<url> (implies 302 unless status=3xx "
                 "explicit), log=<tag> (emitted as tag=\"<x>\" on "
                 "the decision log), flag=<bit> (M5.1 flag name; "
                 "default scanner_probe), ttl=<sec> (flagged-IP "
                 "TTL; default 3600; 0 = don't flag), penalty=<n> "
                 "(score_add amount on this request; default 0; "
                 "ignored under status=pass). Declaration order, "
                 "first match wins; upsert-by-name."),
    /* E2.2 — robots.txt enforcement */
    AP_INIT_TAKE1("BotShieldRobotsTxt", bs_set_robots_txt,
                 NULL, RSRC_CONF,
                 "Path to a robots.txt file whose Disallow and "
                 "Crawl-delay rules mod_botshield will enforce "
                 "server-side. Parsed at post_config; RFC 9309 "
                 "semantics (prefix + '*' + '$' wildcards, longest-"
                 "match-wins, case-insensitive UA prefix). Blocked "
                 "paths return 403 (reason robots-block:<group>); "
                 "Crawl-delay trips return 429 + Retry-After "
                 "(reason robots-rate:<group>)."),
    AP_INIT_TAKE1("BotShieldRobotsRefreshInterval",
                 bs_set_robots_refresh_interval, NULL, RSRC_CONF,
                 "Seconds between mod_watchdog-driven re-checks of "
                 "the BotShieldRobotsTxt file. On mtime change the "
                 "file is re-parsed and the active rule set is "
                 "atomically swapped — no Apache reload needed. "
                 "Default 60. Set 0 to disable live-refresh and "
                 "require an explicit reload after editing."),
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



/* --- Request-handler helpers --- */

/* Challenge safeguard: before issuing a challenge, check whether
 * this IP has been presented N times within the window without
 * solving. If so, flip to a pass-through (return DECLINED) with
 * reason=challenge-safeguard so a broken client (JS blocked, CSP-
 * stripped, cookie handling buggy) stops being looped on the same
 * challenge. Otherwise record this presentation and proceed.
 *
 * Recording the presentation runs unconditionally on safeguard-
 * eligible paths (have_client_ip + scfg present), regardless of
 * safeguard_enabled — the embedded → M7 fallback in silent-tier
 * dispatch reads the same count to decide when to bypass the
 * embedded short-circuit. The write is cheap (one mutex + a few
 * SHM stores); the only side-effect when safeguard is "off" is
 * that embedded mode gets the count it needs.
 *
 * Runs AFTER bs_check_policy by construction (caller is already
 * past the policy short-circuit returns), so 403/429 blocks still
 * win.
 *
 * Returns DECLINED if safeguard short-circuited the request, OK
 * if the caller should continue to challenge issuance. */
static int bs_apply_safeguard(request_rec *r, int have_client_ip,
                              const unsigned char *client_ip,
                              const char *cookie_status,
                              bs_request_score *score, int effective)
{
    bs_server_cfg *scfg_sg = ap_get_module_config(
        r->server->module_config, &botshield_module);
    if (!scfg_sg || !have_client_ip) return OK;

    apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
    if (scfg_sg->safeguard_enabled == 1 &&
        bs_safeguard_check(client_ip, now_t, scfg_sg->ns_id)) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: challenge-safeguard active for "
            "%s; skipping challenge-issue and passing "
            "through (until=%" APR_INT64_T_FMT ")",
            r->useragent_ip, (apr_int64_t)now_t);
        bs_score_add(r, 0, 0, "challenge-safeguard");
        bs_decision_log(r, "safeguard", "allow",
                        cookie_status, "-", "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
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

/* Module-owned endpoint routing. URLs under BotShieldEndpointPrefix
 * (default /botshield) are served by this module's own handlers, not
 * the tier dispatch. Today:
 *   <prefix>/captcha-verify             — single-provider vhost
 *   <prefix>/captcha-verify/<name>      — per-provider cohabitation
 *   <prefix>/metrics                    — mod_status-style export
 *   <prefix>/policy-status              — operator readback
 *   <prefix>/embedded{.js,-worker.js,-bootstrap,-verify}
 *                                       — silent-tier embedded path
 *   <prefix>/form-widget.js             — form-PoW widget shell
 * The bare /captcha-verify form still works for the single-provider
 * case so the old dev config and the first-provider-on-a-vhost case
 * keep working. Called before the debug / asset / cookie paths so
 * operators can hit the verify endpoint regardless of surrounding
 * scope.
 *
 * Returns the Apache return code if the URI matched a module
 * endpoint (including 404 OK for unknown-endpoint-under-prefix);
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
    if (strcmp(sub, "/captcha-verify") == 0 ||
        strncmp(sub, "/captcha-verify/", 16) == 0) {
        return bs_captcha_verify_handler(r, cfg);
    }
    if (strcmp(sub, "/metrics") == 0) {
        return bs_metrics_handler(r);
    }
    if (strcmp(sub, "/policy-status") == 0) {
        return bs_policy_status_handler(r, cfg);
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

    /* Unknown module endpoint under the prefix → 404, so a typo in
     * an operator's template fails loudly instead of falling through
     * to Apache and serving some unrelated file. */
    r->status = HTTP_NOT_FOUND;
    ap_set_content_type(r, "text/plain; charset=utf-8");
    apr_table_setn(r->err_headers_out, "X-Botshield", "unknown-endpoint");
    ap_rputs("Not found.\n", r);
    bs_decision_log(r, "none", "block", "skipped", "-", "skipped",
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
 *      /embedded*, /form-widget.js, /policy-status. Returns Apache
 *      rv directly; never reaches the tier dispatch below.
 *   3. Debug + asset short-circuits + secret-presence sanity.
 *   4. Cookie verify — bs_verify_cookie + safeguard-clear-on-solve
 *      + bs-cookie-state note for cookie-trigger predicates.
 *   5. Policy check — bs_check_policy (cookie/env/load/scope/path
 *      triggers + block_paths + robots + rate_limits). DECLINED or
 *      HTTP_* short-circuits return here.
 *   6. Heuristics + flagged-IP + first-sight + flag-trigger walker
 *      → effective score, score_tier, tier_floor.
 *   7. Pass-tier short-circuit + app_claims emission.
 *   8. Bloom-add + safeguard presentation accounting.
 *   9. Embedded silent-tier dispatch with embedded-→-form-PoW
 *      fallback when the wrapper has had its chances.
 *   10. Build next_rep (forgiveness + cap), issue challenge, render
 *       interstitial (silent / form-PoW / captcha widget). */
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

    int endpoint_rv = bs_route_module_endpoint(r, cfg);
    if (endpoint_rv != -1) {
        return endpoint_rv;
    }

    /* Debug override keeps the first-commit behavior available for tests. */
    if (cfg->debug == 1) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_botshield: debug mode - forcing 403 for %s",
                      r->unparsed_uri);
        r->status = HTTP_FORBIDDEN;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->headers_out,    "Cache-Control", "no-store");
        apr_table_setn(r->err_headers_out, "X-Botshield",  "debug-403");
        ap_rputs("Hello World\n", r);
        bs_decision_log(r, "none", "debug", "skipped", "-", "skipped", "-", 0);
        return OK;
    }

    /* Static assets pass through — a cookieless first page load must still
     * render its CSS/images so the PoW page is usable. */
    if (bs_is_asset_uri(r->uri)) {
        bs_decision_log(r, "pass", "allow", "skipped", "-", "skipped", "asset", 0);
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
        bs_decision_log(r, "none", "misconfigured", "skipped", "-", "skipped", "-", 0);
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
        if (!cookie_verify_reason) {
            cookie_fully_ok = 1;
            /* E10 — safeguard clear on solve. A successful verify
             * proves this client CAN complete a challenge, so any
             * accumulated presentation history was transient noise
             * (mid-session CSP moment, browser cookie glitch). Reset
             * the slot so a later failed solve counts from zero. */
            {
                bs_server_cfg *scfg_sg = ap_get_module_config(
                    r->server->module_config, &botshield_module);
                if (scfg_sg && scfg_sg->safeguard_enabled == 1) {
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

    /* E4 — publish the `_bs_verified` verification verdict as a
     * request note so bs_check_policy's cookie-trigger evaluator
     * can surface it via bs-cookie=<state> predicates. Three-state
     * mapping matches the directive surface. */
    {
        const char *bs_state;
        if (!cookie_had_val)           bs_state = BS_CK_STATE_MISSING;
        else if (!cookie_verify_reason) bs_state = BS_CK_STATE_VERIFIED;
        else                           bs_state = BS_CK_STATE_INVALID;
        apr_table_setn(r->notes, BS_CK_STATE_NOTE, bs_state);
    }

    /* E2.1 + E2.2 + E3 policy enforcement. Runs before scoring
     * heuristics so a block / rate / trigger short-circuits cleanly.
     * Applies to cookie-valid requests too — operator policy
     * (including robots.txt and path-based triggers) is independent
     * of bot-ness. */
    int policy_rv = bs_check_policy(r);
    if (policy_rv == DECLINED) {
        /* E3 trigger with status=pass: log + let the real handler
         * respond. No score, no BotShield interstitial. Flag-IP +
         * tag side effects already applied in bs_check_policy. */
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        bs_decision_log(r, "pass", "allow", cookie_status, "-",
                        cfg->algorithm ? cfg->algorithm->name : "skipped",
                        reasons, s ? s->total : 0);
        return DECLINED;
    }
    if (policy_rv != OK) {
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        const char *outcome;
        if (policy_rv == HTTP_TOO_MANY_REQUESTS)      outcome = "rate_limited";
        else                                          outcome = "block";
        bs_decision_log(r, "pass", outcome, cookie_status, "-",
                        cfg->algorithm ? cfg->algorithm->name : "skipped",
                        reasons, s ? s->total : 0);
        return policy_rv;
    }

    /* Score the request. Heuristics always run — a fully-valid cookie
     * doesn't exempt you from fresh request-level signals that might
     * have pushed you into a tier that requires a re-challenge. */
    bs_run_builtin_heuristics(r);

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
    /* Coarse 0-weight "flagged-ip" reason so operators (and tests)
     * reading decision logs see at a glance that this IP is in the
     * flagged-IP table, without having to parse every trigger name.
     * The actual score adjustments flow through bs_apply_flag_triggers
     * below — that walker covers both IP-side and cookie-side flags
     * via the union and emits per-flag `flag-trigger:<name>` reasons. */
    if (ip_flags != 0) {
        bs_score_add(r, 0, 0, "flagged-ip");
    }

    /* First-sight Bloom lookup (M5.2). Policy: only on cookieless or
     * signature-mismatched requests. Sig-verified cookies (even if
     * expired) mean we've already transacted with this browser, so
     * the first-sight signal would just be noise. A valid cookie
     * likewise skips this.
     *
     * Action is bound by the BotShieldHeuristicTrigger
     * 'first-sight-ip' entry — defaulted to score add=5 at
     * post_config, operator-tunable or `all reset`-able. */
    if (have_client_ip && !have_prior_rep &&
        !bs_bloom_seen(client_ip, scfg_h->ns_id)) {
        bs_apply_heuristic(r, BS_H_FIRST_SIGHT_IP);
    }

    /* Flag-trigger walker. Walks scfg->flag_triggers over the union
     * of IP-side and cookie-side flag bits, applying `score add=N`
     * actions via bs_score_add (which SUMs into the per-request
     * score) and accumulating MAX into a tier_floor that we apply
     * after bs_decide_tier. Built-in defaults are seeded at
     * post_config; operators tune via BotShieldFlagTrigger. */
    apr_uint32_t all_flags = ip_flags
        | (have_prior_rep ? prior_ch.rep.flags : 0);
    bs_tier tier_floor_from_flags = BS_TIER_PASS;
    bs_apply_flag_triggers(r, scfg_h, all_flags, &tier_floor_from_flags);

    /* Fetch the score struct *after* all per-request adds. Using create=1
     * so a request with zero hits still gets a valid (empty) pointer and
     * the log line prints reasons=[] consistently. */
    bs_request_score *score = bs_get_score(r, 1);
    int heuristic_total = score->total;

    /* effective_score = per-request heuristic total (already inclusive
     * of any flag-trigger SCORE actions applied above) + the cookie's
     * accumulated rep score. Operator-facing tuning workflow lives
     * in the README "Understanding scoring" section. */
    int cookie_score = have_prior_rep ? prior_ch.rep.score : 0;
    int effective    = heuristic_total + cookie_score;
    bs_tier score_tier = bs_decide_tier(cfg, effective);

    /* Apply the tier floor accumulated by the flag-trigger walker
     * (MAX of any TIER_FLOOR actions across the union of flags).
     * The score-derived tier wins when it's already at-or-above the
     * floor — we never silently downgrade. */
    bs_tier tier = (tier_floor_from_flags > score_tier)
                 ? tier_floor_from_flags : score_tier;
    if (tier_floor_from_flags > score_tier) {
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "flag-tier-floor:%s",
                         bs_tier_name(tier_floor_from_flags)));
    }

    /* Per-scope flag/TTL writes happen inside bs_check_policy via
     * the BotShieldTrigger walker (BS_TFAMILY_SCOPE). The legacy
     * BotShieldFlagIP directive that used to live here was
     * superseded by `BotShieldTrigger flag=<name> ttl=<sec>`. */

    /* Happy path: score below the silent threshold → pass through.
     * If there's no cookie this means no cookie is ever issued —
     * legitimate users experience mod_botshield as invisible. */
    if (tier == BS_TIER_PASS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_botshield: pass %s effective=%d "
                      "(heuristic=%d cookie_score=%d "
                      "ip_flags=0x%x cookie_flags=0x%x) cookie_ok=%d",
                      r->uri, effective, heuristic_total, cookie_score,
                      (unsigned)ip_flags,
                      have_prior_rep ? (unsigned)prior_ch.rep.flags : 0,
                      cookie_fully_ok);
        /* E8.2 — module-to-app reputation export. Strip incoming
         * X-Botshield-* and set a single signed claim envelope so
         * the backend handler reads sanctioned BotShield state
         * without poking at the (encrypted post-E8.1) cookie. */
        {
            bs_server_cfg *scfg2 = ap_get_module_config(
                r->server->module_config, &botshield_module);
            apr_uint32_t composite_flags = ip_flags
                | (have_prior_rep ? prior_ch.rep.flags : 0);
            const char *cerr = bs_app_claims_set(r, scfg2,
                effective, tier, cookie_status, composite_flags,
                have_prior_rep ? prior_ch.rep.passes_silent  : 0,
                have_prior_rep ? prior_ch.rep.passes_form    : 0,
                have_prior_rep ? prior_ch.rep.passes_captcha : 0);
            if (cerr) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                    "mod_botshield: app claims not emitted: %s", cerr);
            }
        }
        bs_decision_log(r, "pass", "allow", cookie_status,
                        "-",
                        cfg->algorithm ? cfg->algorithm->name : "skipped",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

    /* E12 — global log-only / dry-run mode. Log what the tier
     * decision would have produced and DECLINE instead of issuing
     * a challenge. Skips Bloom / safeguard / IP-flag side effects so
     * the dry-run is purely observational; the operator gets a
     * per-request decision log without any client seeing an
     * interstitial or failed challenge. The trigger / rate-limit
     * machinery has its own observe paths (honored elsewhere); this
     * branch is the tier-dispatch counterpart. */
    if (scfg_h && scfg_h->log_only == 1) {
        bs_decision_log(r, bs_tier_name(tier), "would-challenge",
                        cookie_status, "-",
                        cfg->algorithm ? cfg->algorithm->name : "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

    /* Not pass tier — we will issue a challenge. Feed the Bloom filter
     * now that we've committed to challenging this client; that keeps
     * writes off the ~99% happy path. */
    if (have_client_ip) bs_bloom_add(client_ip, scfg_h->ns_id);

    int safeguard_rv = bs_apply_safeguard(r, have_client_ip, client_ip,
                                          cookie_status, score, effective);
    if (safeguard_rv != OK) return safeguard_rv;

    /* E17 — silent-tier dispatch with embedded mode. Default behavior:
     * skip the M7 interstitial, serve the real page (DECLINED), let
     * the wrapper handle verification in the background. Timing model:
     * "kicks in eventually" — see CHANGELOG.
     *
     * Embedded → form-PoW fallback: if this client has had N
     * consecutive silent-tier dispatches without _bs_verified
     * arriving (count tracked via bs_safeguard_present_count), the
     * wrapper isn't doing its job (CSP-blocked, no JS, no Worker
     * support, etc.). Bypass the embedded short-circuit so the
     * form-PoW path runs. The form-PoW path's own safeguard
     * threshold catches the case where it also fails. */
    if (tier == BS_TIER_SILENT &&
        cfg->silent_mode == BS_SILENT_MODE_EMBEDDED) {
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
            bs_decision_log(r, "silent", "allow", cookie_status,
                            "-",
                            cfg->algorithm ? cfg->algorithm->name : "skipped",
                            bs_decision_reason_names(r->pool, score),
                            effective);
            return DECLINED;
        }
        /* Fall through to M7 — the embedded path has had its
         * chances. Surface the decision in the reason chain so
         * operators can spot clients stuck in this state. */
        bs_score_add(r, 0, 0, "embedded-fallback-m7");
    }

    /* `issue_auto` picks the form-PoW interstitial style: the
     * silent-tier auto-submit splash (issue_auto=1) for low-friction
     * challenges, the visible form interstitial (issue_auto=0) for
     * the harder tier. Captcha tier is rendered separately by
     * bs_render_challenge_page when cfg->captcha_provider is set;
     * if the operator selected captcha tier without configuring a
     * provider, render falls through to the form-PoW interstitial
     * with reason "captcha_fallback" on the decision log. */
    int issue_auto = (tier == BS_TIER_SILENT);

    /* Build the rep state to carry into the new cookie. Forgiveness +
     * pass-counter bump are picked from the tier the *prior* cookie was
     * served under (prior_ch.auto_tier), because that records what the
     * user actually just solved. First-time challenges have no prior
     * tier, so they increment whichever counter matches the tier we're
     * about to issue. */
    bs_rep_state next_rep;
    if (have_prior_rep) {
        int forgive = prior_ch.auto_tier
            ? bs_effective_int(cfg->forgive_silent, BS_DEFAULT_FORGIVE_SILENT)
            : bs_effective_int(cfg->forgive_form,   BS_DEFAULT_FORGIVE_FORM);
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
        /* No floor on the forgiven score even on flagged cookies.
         * Flag effects are re-applied at request time by
         * bs_apply_flag_triggers, so a forgiven-to-zero score on a
         * flagged cookie is simply re-raised on the next request
         * when the trigger fires. */
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < 0) new_score = 0;
        next_rep.score = new_score;
        if (prior_ch.auto_tier) {
            next_rep.passes_silent = 1;  /* clamp */
        } else {
            next_rep.passes_form = 1;  /* clamp */
        }
    } else {
        next_rep.score          = 0;
        next_rep.flags          = 0;
        next_rep.passes_silent  = issue_auto ? 1 : 0;
        next_rep.passes_form    = issue_auto ? 0 : 1;
        next_rep.passes_captcha = 0;
        next_rep.challenged_at  = 0;   /* overwritten by issue() */
        next_rep.forgive_window_start = 0;
        next_rep.forgive_consumed     = 0;
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
                  have_prior_rep ? (unsigned)prior_ch.rep.flags : 0,
                  cookie_fully_ok,
                  next_rep.passes_silent, next_rep.passes_form,
                  next_rep.passes_captcha);
    /* Difficulty stays at the operator-configured BotShieldDifficulty.
     * Tier (silent / form / captcha) is the primary lever for "this
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
     * cookie alg. When captcha tier falls through to form-PoW (no
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
         * scope — interstitial we actually served is form-PoW. Label
         * honestly. */
        served_tier_name = "form";
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
    ap_hook_child_init  (bs_child_init,  NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler     (bs_handler,     NULL, NULL, APR_HOOK_FIRST);
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
