/* botshield.h — module-wide private header.
 *
 * Cross-file type definitions, enums, and a small handful of
 * function declarations that the request handler shares across
 * the file split. Every TU in the module includes this header.
 *
 * NOT a public API — the .so is built with -fvisibility=hidden so
 * none of this leaks outside the module. The single externally-
 * visible symbol is `botshield_module` (the AP_DECLARE_MODULE
 * struct), which is annotated with default visibility at its
 * definition site in botshield.c.
 *
 * Layered headers:
 *   crypto.h     — small primitives (HMAC, GCM, hex, HKDF)
 *   shm.h        — SHM tables, state save/load, headroom watchdog
 *   robots.h     — robots.txt parser
 *   allowlist.h  — verified-crawler classifier + CIDR loader
 *   metrics.h    — decision log, M9 counters, Prometheus, mod_status
 *   botshield.h  — THIS file: bs_dir_cfg, bs_server_cfg, request-
 *                  flow types, cross-file function declarations
 *   botshield.c — the request handler + glue. Includes all of
 *                     the above plus the per-feature headers as
 *                     more extractions land. */
#ifndef BOTSHIELD_H
#define BOTSHIELD_H

#include <apr.h>
#include <apr_hash.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <httpd.h>
#include <http_config.h>

#include "captcha.h"  /* M8 captcha provider registry */
#include "challenge.h"/* bs_challenge, bs_rep_state, PoW algorithm registry */
#include "crypto.h"
#include "robots.h"
#include "score.h"    /* bs_tier, bs_silent_mode, score system */
#include "shm.h"      /* bs_load_state, bs_metrics typedefs */
#include "triggers.h" /* trigger + policy family types */

#ifdef __cplusplus
extern "C" {
#endif

/* Wire-format constants live next to the types they parameterize:
 * challenge envelope (BS_PROTOCOL_VERSION, BS_SALT_BYTES,
 * BS_NONCE_BYTES) in challenge.h; cookie wire (BS_GCM_COUNTER_SEP)
 * in cookie.h. */

/* ======================================================================
 * Config defaults (operator-tunable; tri-state directives use -1
 * for "unset / inherit")
 * ====================================================================== */

#define BS_UNSET              (-1)
#define BS_DEFAULT_COOKIE_TTL 3600  /* seconds a verified cookie is good for */
#define BS_DEFAULT_DIFFICULTY 4     /* leading hex zeros */
#define BS_CLOCK_SKEW_AHEAD   60    /* grace if client clock runs ahead */
#define BS_DEFAULT_FORGIVE_SILENT   10
#define BS_DEFAULT_FORGIVE_FORM     25
#define BS_DEFAULT_FORGIVE_CAPTCHA  50
/* E15 — per-cookie hourly cap on accumulated forgiveness. 200
 * points/hour ≈ 4-8 challenge-passes worth of credit. */
#define BS_DEFAULT_FORGIVE_CAP_PER_HOUR  200
#define BS_FORGIVE_WINDOW_SEC            3600
#define BS_COOKIE_NAME        "_bs_verified"
/*  `__Host-` prefix variant. We emit
 * this when the request is HTTPS AND no operator cookie_domain is
 * in play. Verify path checks both (host-prefix first). */
#define BS_COOKIE_NAME_HOST   "__Host-bs_verified"
#define BS_DEFAULT_PROMPT     "I\xe2\x80\x99m not a robot"  /* U+2019 */
#define BS_DEFAULT_LOGO_LABEL "botshield"
#define BS_MAX_LOGO_BYTES     (64 * 1024)
#define BS_MAX_HELP_BYTES     (64 * 1024)
#define BS_MAX_PAGE_BYTES     (256 * 1024)
#define BS_MAX_SECRET_BYTES   1024
#define BS_MIN_SECRET_BYTES   16
/* Auto-generated when no BotShieldSecretFile is configured;
 * see bs_ensure_default_secret. Distribute across hosts for shared
 * cookie validation, or override with BotShieldSecretFile. */
#define BS_DEFAULT_SECRET_PATH "/var/lib/botshield/secret"
#define BS_AUTO_SECRET_BYTES   32
#define BS_WIDGET_MARKER      "<!-- BOTSHIELD -->"

/* E4 — BotShield-cookie-state note. Set by bs_handler after the
 * `_bs_verified` verification pass so the cookie-trigger predicate
 * matcher (and other consumers) can surface the verdict without
 * re-running the HMAC check. Values: "verified" / "missing" /
 * "invalid". */
#define BS_CK_STATE_NOTE      "botshield-cookie-state"
#define BS_CK_STATE_VERIFIED  "verified"
#define BS_CK_STATE_MISSING   "missing"
#define BS_CK_STATE_INVALID   "invalid"

/* Score thresholds and heuristic-penalty constants live in score.h
 * (BS_DEFAULT_SCORE_*, BS_SCORE_MAX_REASONS, BS_PENALTY_*). */

/* Help visibility modes (values are stored in bs_dir_cfg.help_mode).
 * Used by the help/help-file directive setters in config.c and by
 * the splash-page renderer in botshield.c. */
enum bs_help_mode {
    BS_HELP_OFF    = 0,
    BS_HELP_ON     = 1,
    BS_HELP_BUTTON = 2,
};
#define BS_DEFAULT_HELP_MODE BS_HELP_BUTTON

/* BotShieldEnabled tri-state. Stored in bs_dir_cfg.enabled.
 * BS_UNSET (-1) means "inherit from parent scope" so the dir-merge
 * picks the right value. Operators write On/Off/LogOnly; the setter
 * maps the strings to these constants. */
enum bs_enabled_state {
    BS_ENABLED_OFF     = 0,
    BS_ENABLED_ON      = 1,   /* enforce: tier decisions act */
    BS_ENABLED_LOGONLY = 2,   /* observe: log decisions, decline */
};

/* --- Flag-bit registry ----------------------------------------
 *
 * Each bit represents a *serious* event we want to remember about
 * an IP even if its cookie is rolled back. Bits are additive — an
 * IP that tripped both a honeypot and a scanner probe carries both.
 * Score effects per bit live in scfg->flag_triggers (see
 * bs_default_flag_triggers + bs_apply_flag_triggers in botshield.c).
 *
 * BS_FLAG_APP_* are credit-carrying bits set by the app via the E5
 * X-BotShield-Feedback bridge — the app can push score down as well
 * as up. Compose additively with the penalty bits. */
#define BS_FLAG_HONEYPOT_HIT          (1U << 0)
#define BS_FLAG_SCANNER_PROBE         (1U << 1)
#define BS_FLAG_FAKE_BOT              (1U << 2)
#define BS_FLAG_POW_FAIL_STREAK       (1U << 3)
#define BS_FLAG_APP_VERIFIED_HUMAN    (1U << 4)
#define BS_FLAG_APP_VERIFIED_SESSION  (1U << 5)
#define BS_FLAG_APP_TRUST_SIGNAL      (1U << 6)

/* Captcha tier (M8) defaults — small and boring: a 1 s HTTP verify
 * budget is enough for Cloudflare / hCaptcha / Google normally, and
 * short enough that a provider outage doesn't stall real users. */
#define BS_DEFAULT_ENDPOINT_PREFIX  "/botshield"
#define BS_DEFAULT_CAPTCHA_TIMEOUT  1000   /* milliseconds */
#define BS_MIN_CAPTCHA_TIMEOUT      100
#define BS_MAX_CAPTCHA_TIMEOUT      5000
#define BS_CAPTCHA_CONNECT_TIMEOUT  250    /* milliseconds */
#define BS_MAX_CAPTCHA_TOKEN        4096   /* Turnstile tokens ≤ ~2 KB */
#define BS_MAX_CAPTCHA_BODY         8192   /* siteverify response cap */
#define BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE 0.5  /* Google's suggested baseline */

/* Tier + silent-mode enums (bs_tier, bs_silent_mode) and the per-
 * request score system (bs_score_entry, bs_request_score) live in
 * score.h. */

/* Reputation state (bs_rep_state), challenge envelope (bs_challenge),
 * and the PoW algorithm registry (bs_pow_algorithm, bs_alg_issue_fn,
 * bs_alg_verify_fn) live in challenge.h. */

/* M8 captcha provider registry (bs_captcha_provider, bs_captcha_result,
 * bs_captcha_siteverify_fn) lives in captcha.h. */

/* Robots.txt active-state bundle (bs_robots_state, robots_doc forward
 * decl, bs_robots_wildcard_scope enum) lives in robots.h. */

/* ======================================================================
 * Per-directory configuration
 * ====================================================================== */

struct bs_dir_cfg {
    int enabled;
    int debug;
    int cookie_ttl;
    int difficulty;
    int help_mode;              /* BS_HELP_* or BS_UNSET */
    int show_logo;              /* 0 = hide, 1 = show, -1 = inherit */
    int show_label;             /* 0 = hide prompt, 1 = show, -1 = inherit */
    int show_box;               /* 0 = no box, 1 = boxed, -1 = inherit */
    const char *prompt;         /* e.g. "I'm not a robot" */
    const char *logo_svg;       /* full SVG content, loaded at config time */
    const char *logo_label;     /* small caption under the logo */
    const char *help_html;      /* panel content, loaded at config time */
    const char *challenge_html; /* full HTML page template with marker */
    const bs_pow_algorithm *algorithm;      /* chosen issue algorithm */
    const unsigned char    *secret;         /* master key bytes */
    apr_size_t              secret_len;     /* master key length */
    /* E16 — verify-only secondary secret for graceful rotation. */
    const unsigned char    *secret_secondary;
    apr_size_t              secret_secondary_len;
    /*  HKDF-Expand'd per-purpose keys
     * derived once at config-load time. Each purpose tag yields a
     * cryptographically-independent key: leaking one tells an
     * attacker nothing about the others. */
    unsigned char    derived_gcm_cookie     [32];
    unsigned char    derived_hmac_pending   [32];
    /* separate purpose key for the bootstrap → verify
     * IP-binding HMAC. Distinct from the cookie key so the
     * bound-ip signature can't be repurposed against the cookie. */
    unsigned char    derived_hmac_bootstrap [32];
    int              derived_keys_set;
    /* Same for the secondary key, populated when
     * BotShieldSecondarySecretFile is configured. */
    unsigned char    derived_gcm_cookie_2   [32];
    unsigned char    derived_hmac_pending_2 [32];
    unsigned char    derived_hmac_bootstrap_2[32];
    int              derived_keys_set_2;
    int score_silent;           /* score >= this → silent tier */
    int score_hard;             /* score >= this → hard form-PoW tier */
    int score_captcha;          /* score >= this → captcha tier */
    /* E17 — silent-tier dispatch flavor, tri-state with UNSET so the
     * merge picks the right scope's value. */
    int silent_mode;            /* bs_silent_mode; UNSET inherits */
    /* E18 — inline form captcha. -1 inherit, 0 off, 1 on. */
    int form_captcha;
    int forgive_silent;         /* score credit on silent-tier pass */
    int forgive_form;           /* score credit on form-tier pass */
    int forgive_captcha;        /* score credit on captcha pass */
    const char *cookie_domain;  /* if set, Set-Cookie Domain= attribute */
    /* BotShieldTrigger — per-Apache-scope trigger list. Each entry
     * is a bs_trigger_action *; the request-time walker iterates
     * the merged list and applies each via bs_apply_trigger_action.
     * `scope_triggers_reset` means "this scope drops inherited
     * triggers" — the merge skips base->scope_triggers when set. */
    apr_array_header_t *scope_triggers;
    int                 scope_triggers_reset;
    /* --- Captcha tier (M8) --- */
    const char *endpoint_prefix;            /* default "/botshield" */
    const bs_captcha_provider *captcha_provider;  /* NULL = tier unused */
    const char *captcha_site_key;           /* provider-public */
    const unsigned char *captcha_secret;    /* file bytes, mode-600 */
    apr_size_t  captcha_secret_len;
    int         captcha_timeout_ms;         /* siteverify HTTP timeout */
    /* Connect-phase timeout. */
    int         captcha_connect_timeout_ms;
    /* reCAPTCHA v3: minimum score in [0.0, 1.0]. -1.0 = unset. */
    double      recaptcha_v3_min_score;
    /* M8.1 per-scope verify-endpoint rate limit. -1 unset, 0 disables. */
    int         captcha_rate_limit;
    /* Binding-metadata validation on the siteverify response. NULL =
     * runtime default (server_hostname, "botshield"); empty string =
     * skip the check. */
    const char *captcha_expected_hostname;
    const char *captcha_expected_action;
    /* Optional CA bundle for siteverify TLS. NULL = libcurl's
     * compiled-in default. */
    const char *captcha_ca_bundle;
};

/* ======================================================================
 * Per-server configuration
 * ====================================================================== */

#define BS_APP_FEEDBACK_UNSET           (-1)
#define BS_APP_FEEDBACK_DEFAULT_HEADER  "X-BotShield-Feedback"

typedef struct bs_server_cfg {
    apr_size_t  shm_size;
    int         flagged_capacity;
    int         ipv6_prefix_bits;   /* 0..128; 64 = per-subscriber v6 key */
    int         bloom_ips;          /* expected working-set size */
    int         bloom_window_secs;  /* full window; rotation at window/2 */
    const char *state_file;         /* NULL = persistence off */
    int         state_save_interval;/* seconds; 0 = shutdown-only */
    int         captcha_max_inflight;  /* M8.1: cap on outstanding siteverifies */
    /* E1 — verified legit-crawler allow-list. State loaded in
     * post_config and read-only thereafter; lives at server scope
     * because the UA classifier + CIDR lists are global, not per-
     * directory. */
    /* BotShieldAllowVerifiedBots flag: opt in to the bundled set of
     * built-in crawlers (bs_builtin_bots[]). Default 0. The allowlist
     * machinery activates if this is on OR if any BotShieldAllowBot
     * has been declared (apr_hash_count(allow_bots) > 0); both off =
     * machinery never wires up. */
    int         verified_bots_enabled;
    void       *bot_classifier;       /* bs_ua_classifier *, opaque here */
    apr_hash_t *bot_ranges;           /* name → apr_array_header_t of apr_ipsubnet_t* */
    apr_hash_t *allow_bots;           /* name → bs_allow_bot_entry * (directive-defined) */
    /* E2.1 — policy enforcement (rate limit + path block). Ordered
     * arrays of entry pointers. */
    apr_array_header_t *rate_limits;
    /* E9 — repeated-429 escalation. */
    apr_array_header_t *rate_escalates;
    int                 strike_capacity;
    /* E10 — safeguard config. -1 unset sentinel. */
    int                 safeguard_enabled;
    int                 safeguard_threshold;
    int                 safeguard_window;
    int                 safeguard_ttl;
    int                 safeguard_capacity;
    /* Embedded-bootstrap nonce table sizing. 0 = default. */
    int                 nonce_capacity;
    /* E11 — load-aware throttling. */
    const char         *load_state_file;
    int                 load_refresh_sec;
    int                 load_warm_pct;
    int                 load_hot_pct;
    int                 load_warm_rise;
    int                 load_hot_rise;
    int                 load_normal_fall;
    bs_load_state       load_external_cached;
    apr_time_t          load_external_mtime;
    /* E13 — reputation namespace for SHM-backed state. */
    apr_uint32_t        ns_id;            /* effective; resolved post_config */
    const char         *share_scope_token; /* explicit override; NULL = default */
    /* E15 — per-cookie hourly forgiveness cap. */
    int                 forgive_cap_per_hour;
    apr_array_header_t *block_paths;
    /* E3 — path-based triggers. */
    apr_array_header_t *path_triggers;
    /* E4 — cookie triggers. */
    apr_array_header_t *cookie_triggers;
    /* E6 — env-var triggers. */
    apr_array_header_t *env_triggers;
    /* E7.3 — feedback triggers. */
    apr_array_header_t *feedback_triggers;
    /* E11.2 — load triggers. */
    apr_array_header_t *load_triggers;
    /* Flag triggers. */
    apr_array_header_t *flag_triggers;
    /* Heuristic triggers (BotShieldHeuristicTrigger).
     * Holds bs_heuristic_trigger_entry*; resolved at post_config from
     * defaults + operator declarations + reset sentinels. */
    apr_array_header_t *heuristic_triggers;
    apr_array_header_t *session_names;
    /* E2.2 — robots.txt enforcement. */
    const char         *robots_txt_path;
    int                 robots_wildcard_scope;
    bs_robots_state    *robots;                      /* active bundle, atomic */
    bs_robots_state    *robots_pending;              /* awaits destruction */
    apr_hash_t         *robots_slot_by_name;
    int                 robots_slot_pool_base;
    int                 robots_slot_pool_size;
    int                 robots_slot_pool_used;
    int                 robots_refresh_interval;
    /* E5 — app-to-module reputation feedback. */
    int                 app_feedback_enabled;
    const char         *app_feedback_header;
    /* E8.2 — module-to-app reputation export. */
    int                 app_claims_enabled;
    /* Single shared HMAC key for both directions of app integration. */
    const char         *app_integration_secret_file;
    const unsigned char *app_integration_secret;
    apr_size_t          app_integration_secret_len;
} bs_server_cfg;

/* Trigger and policy family types (bs_trigger_*, bs_*_trigger_entry,
 * bs_cohort, bs_rate_limit_entry, bs_block_path_entry, bs_rate_counter,
 * bs_flag_trigger_entry, BS_TFAMILY_*, BS_TMODE_*, BS_TEXEC_*,
 * BS_FLAG_ACT_*, BS_PENALTY_RATE_LIMIT/BLOCK_PATH) live in triggers.h. */

/* ======================================================================
 * Module symbol — extern so other TUs can pass &botshield_module to
 * ap_get_module_config. The definition (and its visibility-default
 * pragma) lives in botshield.c.
 * ====================================================================== */

extern module AP_MODULE_DECLARE_DATA botshield_module;

/* ======================================================================
 * Transitional cross-file function declarations.
 *
 * Functions defined in botshield.c that newly-extracted TUs need to
 * call. As future phases extract their own .c/.h pairs, declarations
 * migrate from this section to the per-feature header (cookie.h,
 * challenge.h, captcha.h, ...). Anything left in this section is a
 * pending future-extraction. */

/* Resolve a tri-state int (BS_UNSET = -1 sentinel, otherwise the
 * operator-set value) to its runtime fallback. Used by every code
 * path that reads a per-scope cfg int. Inline because it's tiny
 * and the pattern shows up dozens of times per request. */
static inline int bs_effective_int(int value, int fallback)
{
    return (value == BS_UNSET) ? fallback : value;
}

/* IP parsing (bs_parse_client_ip) and IPv6-prefix masking
 * (bs_mask_ipv6_prefix) live in allowlist.h. Bounded integer parsers
 * (bs_parse_int_bounded, bs_parse_uint32_bounded, bs_parse_int64_bounded)
 * live in crypto.h. */

/* Flag-bit name registry — NULL-terminated table of (name, bit)
 * pairs used by the parse path (operator declares
 * `flag=honeypot_hit`) and the wire-format renderers
 * (X-Botshield-Claims `flags=`). Will move to triggers.h or stay
 * a long-term botshield.h citizen since the bit-meaning vocabulary
 * is genuinely cross-cutting. */
extern const struct bs_flag_name { const char *name; apr_uint32_t bit; }
       bs_flag_names[];

/* Form-body reader — slurps a POST body up to `max_len` and writes
 * it as a NUL-terminated string. Returns APR_SUCCESS or an APR
 * error. Used by the verify handlers (silent + M8). */
apr_status_t bs_read_form_body(request_rec *r, apr_size_t max_len,
                               const char **out_body,
                               apr_size_t *out_len);

/* Challenge issuance, PoW algorithm registry, the canonical-form
 * HMAC input, and the bootstrap-binding helpers all live
 * in challenge.h (see src/challenge.{c,h}). */

/* Cookie format / mint / verify (E11.4 GCM cookie path), the
 * Cookie-header parse-once tokenizer, AND the rep carry-forward
 * helpers (bs_carry_forward_eligible, bs_apply_rep_carry) all
 * live in cookie.h. */

/* M8 captcha siteverify, provider registry, M8.1 pending cookie,
 * and the captcha-verify request handler all live in captcha.h. */

/* Validate an operator-supplied bot/rule name token (lowercase
 * letters, digits, hyphen; max 32 chars). Returns 1 on accept, 0
 * on reject. Used by E1 BotShieldAllowBot setters and by triggers
 * directive setters. */
int bs_bot_name_valid(const char *s);

/* --- Config-time helpers (callable from any feature's directive
 * setters). All four currently live in botshield.c; they may
 * migrate to config.c in a later phase as more setters relocate. */

/* Log a NOTICE if the directive is being set inside a <VirtualHost>
 * scope — used for SHM-sizing directives that the post_config hook
 * only reads off the main server's scfg. */
void bs_warn_if_virtual_scope(cmd_parms *cmd, const char *name);

/* Slurp a file into pool memory with a max-size cap. Used for the
 * secret/secondary-secret/captcha-secret keys and for the operator-
 * customizable HTML / SVG templates (challenge page, logo, help). */
const char *bs_load_config_file(cmd_parms *cmd,
                                const char *directive,
                                const char *path,
                                apr_size_t max_bytes,
                                const char **out_content,
                                apr_size_t *out_len);

/* Validate the contents of a secret-key file (BotShieldSecretFile
 * et al.). Trims one trailing newline, rejects embedded NULs,
 * enforces BS_MIN_SECRET_BYTES <= len. */
const char *bs_validate_secret_key(cmd_parms *cmd,
                                   const char *directive,
                                   const char *path,
                                   const char *buf,
                                   apr_size_t buf_len,
                                   apr_size_t *out_len);

/* End-to-end secret-file loader. stat + mode-600 check +
 * bs_load_config_file (with BS_MAX_SECRET_BYTES) +
 * bs_validate_secret_key. Used by every directive that loads an
 * HMAC / GCM master key. Single point of change for the
 * mode-600 discipline, the size cap, and the validation rules. */
const char *bs_load_secret_file(cmd_parms *cmd,
                                const char *directive,
                                const char *path,
                                const char **out_buf,
                                apr_size_t *out_len);

/* Resolve a directive's (ua, ipspec) arg pair into a bs_cohort.
 * Range parsing for ipspec is deferred to post_config — the cohort
 * stores the raw spec strings here. Returns NULL on success or an
 * Apache directive-error string. */
const char *bs_cohort_resolve(cmd_parms *cmd, bs_cohort *out,
                              const char *ua, const char *ipspec);

/* RFC 9309 path-pattern warning — log a NOTICE when a directive's
 * path pattern contains a non-trailing '*' that the retired v1
 * matcher would have treated as a literal byte. Used by E2.1
 * BotShieldBlockPath and by E3 BotShieldPathTrigger. */
void bs_path_pattern_warn_middle_star(cmd_parms *cmd,
                                      const char *directive,
                                      const char *name,
                                      const char *pattern);

/* Score system (bs_get_score, bs_score_add, bs_decision_reason_names,
 * bs_score_reasons_joined, bs_apply_flag_triggers) lives in score.h. */

/* Apply the per-cookie forgiveness cap. Modifies *consumed and
 * *window_start in place; returns the points actually granted.
 * Window rolls if more than BS_FORGIVE_WINDOW_SEC has passed since
 * window_start. Defined in config.c next to bs_set_forgive_cap. */
int bs_forgiveness_apply_cap(int requested, int cap,
                             apr_uint32_t now_sec,
                             apr_uint32_t *window_start,
                             apr_uint32_t *consumed);

/* Parse a comma-separated list of flag-bit names ("honeypot_hit,
 * scanner_probe") into a bit mask. Sets *err to a pool-allocated
 * diagnostic on unknown names. Used by triggers.c to validate the
 * flag= action key and by bridge.c to parse claims-flag lists. */
apr_uint32_t bs_parse_flag_names(apr_pool_t *p, const char *s,
                                 const char **err);

/* bs_tier_name and bs_decide_tier (the score-to-tier picker) live
 * in score.h alongside the score system they consume. */

/* E7.3 feedback-trigger lookup. */
const bs_feedback_trigger_entry *bs_feedback_trigger_find(
    const struct bs_server_cfg *scfg, const char *event);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_H */
