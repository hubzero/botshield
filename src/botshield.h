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
#include "score.h"    /* bs_tier, bs_non_interactive_mode, score system */
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
/* Leading hex zeros, so expected work is 2^(4*d) hashes: d=4 is
 * 65,536, d=3 is 4,096. Lowered 4 -> 3 on measurement, not taste.
 *
 * 905 real solves overnight at d=4 cost a median 329ms of client CPU,
 * p90 1019ms, p99 5188ms, and 34% of solvers spent over half a
 * second. Android solvers were worst: median 733ms and 22% over two
 * seconds, against 2.8% on Windows.
 *
 * That cost buys nothing defensively. Of those 905 solves only 2
 * carried any failed attestation probe -- the population that runs
 * this JS at all is already clean, because the automation hitting
 * this site does not execute the challenge. The proof-of-work is a
 * capability test (did a real engine run?), not an economic barrier;
 * a bot farm that can afford 4,096 hashes can afford 65,536. So the
 * right value is the smallest that still proves capability. */
#define BS_DEFAULT_DIFFICULTY 3
#define BS_CLOCK_SKEW_AHEAD   60    /* grace if client clock runs ahead */
#define BS_DEFAULT_FORGIVE_NON_INTERACTIVE   10
#define BS_DEFAULT_FORGIVE_INTERACTIVE     25
#define BS_DEFAULT_FORGIVE_CAPTCHA  50
/* E15 — per-cookie hourly cap on accumulated forgiveness. 200
 * points/hour ≈ 4-8 nochallenge outcomes worth of credit. */
#define BS_DEFAULT_FORGIVE_CAP_PER_HOUR  200
#define BS_FORGIVE_WINDOW_SEC            3600
#define BS_COOKIE_NAME        "_bs_session"
/*  `__Host-` prefix variant. We emit
 * this when the request is HTTPS AND no operator cookie_domain is
 * in play. Verify path checks both (host-prefix first). */
#define BS_COOKIE_NAME_HOST   "__Host-bs_session"
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
/* Basenames inside BotShieldDataDir. */
#define BS_DATA_SECRET_NAME "secret"
#define BS_DATA_STATE_NAME  "state.bin"
#define BS_AUTO_SECRET_BYTES   32
#define BS_WIDGET_MARKER      "<!-- BOTSHIELD -->"

/* E4 — BotShield-cookie-state note. Set by bs_handler after the
 * `_bs_session` verification pass so the cookietrigger predicate
 * matcher (and other consumers) can surface the verdict without
 * re-running the HMAC check. Values: "verified" / "missing" /
 * "invalid". */
#define BS_CK_STATE_NOTE      "botshield-cookie-state"
/* Whether the presented cookie carries proof that a challenge was
 * actually solved, as opposed to merely verifying. Published as a note
 * so the policy walk can match on it -- the walk runs after cookie
 * verification, so the answer is known by then. "1" or "0". */
#define BS_CK_SOLVED_NOTE     "botshield-cookie-solved"
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

/* Tier + noninteractive-mode enums (bs_tier, bs_non_interactive_mode) and the per-
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
    /* BotShieldChallenge — On (default) or Off. Off means no tier
     * above pass is ever selected in this scope: triggers, rate
     * limits and scoring all still run, but nothing is rendered.
     * Applied AFTER the flag tier-floor MAX, which is the point --
     * parking the score thresholds does not stop a floor, so it
     * cannot express "never challenge here" on its own. */
    int challenge_enabled;
    /* BotShieldAccessLog: bitmask over BS_M_OUTCOME_*, suppress the
     * Apache access-log line when the decision lands on a set bit.
     * BS_UNSET = inherit / no suppression. An int mask rather than a
     * bool because the two logs answer different questions: the access
     * log is the traffic record, the decision log is the security
     * record, and a flood should be able to leave the second while
     * staying out of the first. */
    int accesslog_suppress;
    int debug;
    int cookie_ttl;
    int difficulty;
    int interactive_min_ms;  /* solve-time floor, ms; 0 = off */
    int interactive_arm_ms;  /* checkbox withheld this long, ms */
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
    int score_non_interactive;           /* score >= this → noninteractive tier */
    int score_interactive;             /* score >= this → hard interactive PoW tier */
    int score_captcha;          /* score >= this → captcha tier */
    /* E17 — noninteractive tier dispatch flavor, tri-state with UNSET so the
     * merge picks the right scope's value. */
    int non_interactive_mode;            /* bs_non_interactive_mode; UNSET inherits */
    /* E18 — inline form captcha. -1 inherit, 0 off, 1 on. */
    int form_captcha;
    int forgive_non_interactive;         /* score credit on noninteractive tier pass */
    int forgive_interactive;           /* score credit on form-tier pass */
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

/* Per-pass enable/disable for the unified UA classifier. Wired
 * through BotShieldClassify. Defaults to all four passes on; the
 * struct is read by bs_classify_request_ua to gate each pass and
 * by bs_ua_is_crawler_candidate for the browsers fail-safe.
 *
 * Fail-safe semantics when a flag is 0:
 *   browsers      → treat all UAs as if browser=1 for robots.txt
 *                   wildcard gating (no real users punished by
 *                   stale templates). Other passes still run.
 *   known_bots    → AC directory walk skipped; directory-only
 *                   matches won't surface knownbot:<slug> tags.
 *   verified_bots → UA-classifier match still happens; IP cross-
 *                   check skipped; matched UAs degrade to knownbot:
 *                   <name> (score 0). Neither verified-bot credit nor
 *                   fake-bot penalty fires. The natural response to
 *                   stale CIDR data without losing the directory tag.
 *   unknown_bots  → heuristic substring scan skipped; would-be
 *                   unknownbot UAs fall to unknownua. */
typedef struct bs_classify_flags {
    unsigned int browsers      : 1;
    unsigned int known_bots    : 1;
    unsigned int verified_bots : 1;
    unsigned int unknown_bots  : 1;
} bs_classify_flags;

#define BS_CLASSIFY_FLAGS_ALL  ((bs_classify_flags){1, 1, 1, 1})
#define BS_CLASSIFY_FLAGS_NONE ((bs_classify_flags){0, 0, 0, 0})
/* Access control for the observability surfaces (the /dashboard family
 * and /metrics). One of these per surface per vhost.
 *
 * Deny by default: an unconfigured surface is not served at all. These
 * pages reveal internal vhost names, traffic volumes, challenge and
 * solve rates and SHM capacities, and the module used to serve them to
 * anyone who asked, relying on the operator to write a <Location> the
 * shipped config could only recommend. A default that is safe only if
 * you read the comment is not a default.
 *
 * `allow_all` is the explicit opt-in to the old behaviour. `ranges`
 * holds apr_ipsubnet_t * and is NULL while the surface is unconfigured
 * in this scope, which is what the merge reads to decide whether to
 * inherit. A configured-but-empty array means "explicitly denied here"
 * and blocks inheritance. */
typedef struct {
    apr_array_header_t *ranges;
    /* The literal tokens as written, const char *. apr_ipsubnet_t does
     * not retain the text it was parsed from, and "3 ranges" is not an
     * answer to "did my allowlist come out the way I meant" -- which is
     * the question an operator asks right before a wrong list locks
     * them out of their own dashboard. */
    apr_array_header_t *specs;
    int                 allow_all;
} bs_observe_acl;


typedef struct bs_server_cfg {
    apr_size_t  shm_size;
    int         flagged_capacity;
    int         ipv6_prefix_bits;   /* 0..128; 64 = per-subscriber v6 key */
    int         bloom_ips;          /* expected working-set size */
    int         bloom_window_secs;  /* full window; rotation at window/2 */
    const char *state_file;         /* NULL = persistence off */
    /* BotShieldDataDir: where this instance's own files live -- the
     * auto-secret and the state file. NULL means BS_DEFAULT_DATA_DIR. */
    const char *data_dir;
    int         state_save_interval;/* seconds; 0 = shutdown-only */
    int         captcha_max_inflight;  /* M8.1: cap on outstanding siteverifies */
    /* E1 — verified legit-crawler allow-list. State loaded in
     * post_config and read-only thereafter; lives at server scope
     * because the UA classifier + CIDR lists are global, not per-
     * directory. */
    /* Per-pass classifier on/off, set by BotShieldClassify. Default
     * is all four passes enabled. Read at request time by
     * bs_classify_request_ua + bs_ua_is_crawler_candidate to gate
     * each pass with its fail-safe semantic. */
    bs_classify_flags classify;
    void       *bot_classifier;       /* bs_ua_classifier *, opaque here */
    /* Live-reloadable per-vhost CIDR state. Concrete struct lives in
     * allowlist.h; opaque here to avoid pulling that header. The
     * watchdog rebuilds + atomic-swaps this pointer when source
     * files change on disk. NULL until bs_wire_allowlist runs. */
    struct bs_bot_ranges_state    *bot_ranges;
    /* Manifest of file-backed and inline bots, retained for the
     * watchdog rebuilder. Built once in post_config; immutable. */
    struct bs_bot_ranges_manifest *bot_ranges_manifest;
    /* BotShieldAllowRangesRefreshInterval — seconds between watchdog
     * ticks that re-stat the canonical + sidecar files. 0 disables
     * (post_config load remains in effect; reload via graceful
     * restart). Default 0 (off). */
    int         allow_ranges_refresh_interval;
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
    /* On safeguard trip, redirect the client here (302 with original
     * URI as ?return=). NULL → use the built-in explainer page at
     * <endpoint_prefix>/safeguard-info. The built-in page is auto-
     * routed by bs_route_module_endpoint so operators don't need a
     * Location carve-out. */
    const char         *safeguard_redirect_url;
    /* Embedded-bootstrap nonce table sizing. 0 = default. */
    int                 nonce_capacity;
    /* E11 — load-aware throttling. */
    const char         *load_state_file;
    /* BotShieldDbStatsFile -- telemetry published by the external
     * database monitor. Read for the dashboard only; the database's
     * effect on policy travels through load_state_file above, so a
     * malformed stats line can make a graph wrong but cannot make the
     * module shed. */
    const char         *db_stats_file;
    apr_time_t          db_stats_mtime;
    const char         *fpm_stats_file;
    apr_time_t          fpm_stats_mtime;
    int                 load_refresh_sec;
    int                 load_warm_pct;
    int                 loadavg_warm;   /* per-CPU hundredths; 0 = default */
    int                 loadavg_hot;
    int                 latency_warm_ms;  /* 0 = default */
    int                 latency_hot_ms;
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
    /* E3 — path-based triggers. */
    apr_array_header_t *request_triggers;
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
    /* Idempotence guards for the two post_config resolvers.
     *
     * bs_resolve_flag_triggers and bs_resolve_heuristic_triggers each
     * read and write the SAME field: it carries operator declarations on
     * input and the fully resolved list on output. That is only safe if
     * every bs_server_cfg is visited exactly once. It is not guaranteed
     * -- these configs are shared between server_recs, because
     * bs_merge_rule_array returns the caller's array object unchanged
     * when one side is empty (`if (nadd == 0) return base;`). A second
     * visit then treats the first visit's output, compiled-in defaults
     * included, as operator input and seeds the defaults again.
     *
     * Observed on a HubZero hub with 102 namevhosts and the config at
     * main scope: every heuristic fired 107 times. firstsightip (20)
     * scored 2140, droppedcookie (25) scored 2675,
     * missingacceptlanguage (5) scored 535 -- all exactly x107, which
     * pushed ordinary browsers into the captcha tier. */
    int                 flag_triggers_resolved;
    int                 heuristic_triggers_resolved;
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
    int                 robots_mode;   /* bs_robots_mode */
    /* Cloudflare bot directory runtime override.
     *
     * The compiled-in bs_known_bots[] table is the baseline. If
     * BotShieldBotDirectory points at a TSV file, post_config parses
     * it into a fresh bs_known_bots_state and atomic-swaps the active
     * pointer. A periodic watchdog re-parses on file mtime change so
     * operators can refresh the directory (via services/refresh/botshield-refresh.py directory)
     * without rebuilding the .so or reloading httpd.
     *
     * Path / refresh interval are server-scope; the active state
     * pointer is module-global (bot_directory.c owns it). NULL path
     * leaves the compiled-in baseline in effect. */
    const char         *bot_directory_path;
    int                 bot_directory_refresh_interval;
    /* Top-user-agents browser-templates runtime override.
     * Same shape as bot_directory: NULL path = compiled-in baseline
     * stays active; non-NULL path = parse + atomic-swap, refreshed
     * by per-worker watchdog on file mtime change. The classifier
     * is consumed by bs_ua_is_crawler_candidate (policy.c) to
     * distinguish real-browser UAs from everything else when
     * applying robots.txt User-agent: * rules. */
    const char         *browser_templates_path;
    int                 browser_templates_refresh_interval;
    /* E5 — app-to-module reputation feedback. */
    int                 app_feedback_enabled;
    const char         *app_feedback_header;
    /* E8.2 — module-to-app reputation export. */
    int                 app_claims_enabled;
    /* Single shared HMAC key for both directions of app integration. */
    const char         *app_integration_secret_file;
    const unsigned char *app_integration_secret;
    apr_size_t          app_integration_secret_len;

    /* Slug-keyed bot rate limit (BotShieldBotRateLimit + robots.txt
     * Crawl-delay slug-rekey). State is opaque here; bot_rate.c owns
     * the struct definition + lifecycle. NULL when no rules are
     * configured for this vhost. */
    struct bs_bot_rate_state *bot_rate_state;

    /* Module-owned decision log (BotShieldDecisionLog). Written
     * directly from bs_decision_log at decision time, so it does not
     * depend on mod_log_config and survives `accesslog=off`. `path` is the
     * operator string ("logs/x.log", "/abs/path", or "|program");
     * `fd` is opened once at post_config and inherited by every child.
     * Both NULL when the directive is absent — the operator is then
     * relying on the error log and/or their own CustomLog. */
    const char         *decision_log_path;
    apr_file_t         *decision_log_fd;
    /* outcomes= filter: bitmask over BS_M_OUTCOME_*, -1 = record
     * everything (the default and the historical behaviour). Under a
     * flood the log is dominated by one repeated outcome -- 5,000
     * near-identical challenged lines a minute measured live -- which
     * rotates the interesting rarities out of retention.
     *
     * Filtering is all-or-nothing per outcome, with no sample rate on
     * purpose. Whatever is named is kept whole: in a security log an
     * absent line must mean "it did not happen", and sampling destroys
     * that property for every outcome it touches. Volume and shape of
     * what is not logged live on /botshield/dashboard, which counts
     * every outcome exactly. */
    int                 decision_log_outcomes;
    /* Index of this server's per-vhost metrics block, assigned once at
     * post_config. -1 until then (and for any server that somehow
     * misses the pass), which the metric writers read as "global
     * only". Resolved here rather than looked up per request: the
     * decision path should pay a pointer deref, not a string compare. */
    int                 vhost_idx;

    /* Set when any scope on this vhost turns the module on (On or
     * LogOnly). Module-owned endpoints under BotShieldEndpointPrefix
     * are dispatched on this, NOT on the per-directory enabled state of
     * the requested URL: the endpoints belong to the vhost, not to
     * whichever <Location> happens to enable scoring. Without that,
     * scoping `BotShieldEnabled On` to a <Location> silently 404s
     * captcha-verify, embedded-verify, embedded.js, form-widget.js,
     * safeguard-info and metrics — which breaks the
     * captcha and embedded tiers outright, and leaves the safeguard
     * redirect pointing at a 404. */
    int                 any_enabled;

    /* Who may read the dashboard pages and /metrics. Separate
     * per surface: a
     * Prometheus scraper and an admin browser are rarely the same
     * host, and unioning them grants the scraper the dashboard. */
    bs_observe_acl      observe_dashboard;
    bs_observe_acl      observe_metrics;
} bs_server_cfg;

/* Trigger and policy family types (bs_trigger_*, bs_*_trigger_entry,
 * bs_cohort, bs_rate_limit_entry, bs_rate_counter,
 * bs_flag_trigger_entry, BS_TFAMILY_*, BS_TMODE_*, BS_TEXEC_*,
 * BS_FLAG_ACT_*, BS_PENALTY_RATE_LIMIT) live in triggers.h. */

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
 * error. Used by the verify handlers (noninteractive + M8). */
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
/* Default BotShieldStateFile: <dir>/<instance>.state.bin
 *
 * Absolute, not ServerRoot-relative like BS_DEFAULT_DECISION_LOG: the
 * file carries mutable reputation state and the keyed-hash collision
 * keys, so it belongs under /var/lib rather than beside the logs, and
 * the setter refuses relative paths for that reason.
 *
 * Defaulted at all because without it every restart -- including a
 * logrotate one -- silently empties the flagged-IP table, the Bloom
 * filters and every dashboard counter. That is a policy-free default:
 * it enables no enforcement and changes no decision, it only stops the
 * module forgetting what it already learned. Contrast the synthesised
 * rate limit, which invents enforcement nobody asked for.
 *
 * Everything the module owns per instance lives in one directory, so
 * a second httpd on the same host needs one directive rather than one
 * per file. The directory already held two colliding files before this
 * was a directive at all: the state file and the auto-secret. The
 * secret is the worse of the two -- two instances sharing a cookie
 * HMAC key means whichever wrote last invalidates the other's issued
 * cookies.
 *
 * Deriving a per-instance name instead was tried and rejected.
 * ServerRoot and DefaultRuntimeDir are both unusable: instances
 * routinely share a ServerRoot, and the runtime dir is ephemeral and
 * reset at boot. The listen set does work, being the one thing the OS
 * forces to differ, but it changes whenever an operator edits Listen,
 * which would rename the files and start that instance cold. A default
 * that quietly moves is worse than one you have to declare.
 *
 * bs_init_state_dir creates the parent as root during post_config and
 * hands it to the Apache user, because the periodic save runs in a
 * child. Everything about it is best-effort: a state file that cannot
 * be written degrades to "starts cold", never to a failed start. */
#define BS_DEFAULT_DATA_DIR "/var/lib/botshield"

/* Load telemetry published by the sidecars in tools/. The paths are
 * not a guess: botshield-dbmon.service passes
 * --state-file /run/botshield/db-load.state, and the monitor derives
 * its .stats companion from that name, so these are the two halves of
 * one shipped convention. Defaulted so installing the units is enough
 * to light up the dashboard's load graph.
 *
 * A missing file is the normal case and costs one failed open per
 * watchdog tick -- the reader no-ops and the graph stays empty, which
 * is what a deployment without the sidecars should see. Unlike the
 * data dir these are read-only and operator-published, so two
 * instances sharing them is fine: they are reading the same host's
 * telemetry. */
#define BS_DEFAULT_DB_STATS_FILE  "/run/botshield/db-load.stats"
#define BS_DEFAULT_FPM_STATS_FILE "/run/botshield/fpm-load.stats"

/* Refuse a server-scope-only directive written inside <VirtualHost>.
 * Returns an error string for the setter to return, or NULL. */
const char *bs_require_server_scope(cmd_parms *cmd, const char *name);

/* BotShieldDataDir: the directory holding this instance's own files. */
const char *bs_set_data_dir(cmd_parms *cmd, void *dconf, const char *arg);

/* <data dir>/<name>, using the configured dir or the default. */
const char *bs_data_path(apr_pool_t *p, struct bs_server_cfg *scfg,
                         const char *name);

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
 * matcher would have treated as a literal byte. Used by E3
 * BotShieldRequestTrigger. */
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
