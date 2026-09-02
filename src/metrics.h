/* metrics.h — decision log, M9.2 SHM-resident counters, M9.3
 * Prometheus exposition handler, and the mod_status contribution.
 *
 * The hot decision path emits one structured log line per terminal
 * decision (bs_decision_log) and bumps tier / outcome / cookie /
 * provider counter dimensions in the SHM metrics block. Operators
 * scrape the Prometheus endpoint or read /server-status to inspect
 * those counters; both readers live here.
 *
 * Cross-file callers reach this module via the four public functions
 * below. Everything else (enum-string lookups, gauge cache, atomic
 * load helpers, Prometheus HELP/TYPE rendering) is file-local. */
#ifndef BOTSHIELD_METRICS_H
#define BOTSHIELD_METRICS_H

#include <httpd.h>
#include <http_config.h>   /* cmd_parms for the directive setter */
#include <apr_pools.h>

#include "shm.h"       /* BS_M_*_COUNT enum sizes, bs_metrics_slot */

#ifdef __cplusplus
extern "C" {
#endif

/* Emit one M9.1 decision log line and bump the matching M9.2 counter
 * dimensions. Caller composes the reason string (typically via
 * bs_decision_reason_names — still in botshield.c since it
 * walks the request-scoped score struct). All string args may be NULL
 * or "-"; renderer substitutes "-" for NULL and skips counter dimensions
 * that don't map. */
void bs_decision_log(request_rec *r,
                     const char *tier,
                     const char *outcome,
                     const char *cookie,
                     const char *provider,
                     const char *alg,
                     const char *reason,
                     int score);

/* Map a bs_verify_cookie diagnostic to the M9.1 cookie enum string.
 * NULL reason (accept) → "ok"; expired / signature mismatch /
 * everything else map per the M9.1 spec. `had_cookie` distinguishes
 * "no cookie present" (→ "absent") from cookie present but failed
 * verify. */
const char *bs_decision_cookie_status(const char *verify_reason,
                                      int had_cookie);

/* Stash an operator-defined trigger log-tag on r->notes. The tag is
 * picked up by bs_decision_log and emitted as an extra `tag="..."`
 * field on the decision line; absent tag means a normal decision
 * line shape, byte-for-byte unchanged. Called from the trigger
 * walks when a matching rule's action carries a log_tag. */
void bs_set_trigger_tag(request_rec *r, const char *tag);

/* Stash a "would-X" counterfactual outcome on r->notes. Called from
 * suppression sites (RateLimit observe, Trigger observe with a
 * status side-effect, FormCaptcha observe, tier-dispatch under
 * BotShieldEnabled LogOnly). bs_decision_log reads this note
 * and renders it in the outcome field with a leading `~` prefix
 * (e.g. `~block`, `~rate_limited`, `~challenge`) instead of plain
 * `allow`, so the operator-facing decision log shows what the policy
 * would have done if not suppressed. Severity-aware: a more-severe
 * stash (~block) wins over a less-severe one (~challenge) when
 * multiple suppressions fire on the same request. */
void bs_set_would_outcome(request_rec *r, const char *would);

/* BotShieldDecisionLog setter. Accepts a server-root-relative path
 * ("logs/botshield.log"), an absolute path, or a piped-log spec
 * ("|/usr/bin/rotatelogs ..."). Config-time only stores the string;
 * bs_open_decision_logs does the opening. */
const char *bs_set_decision_log(cmd_parms *cmd, void *cfg_v,
                                int argc, char *const argv[]);

/* Open every configured BotShieldDecisionLog. Called from post_config
 * (as root, before privilege drop) so the descriptor is inherited by
 * every child process. Piped specs go through ap_open_piped_log, the
 * same path mod_log_config uses, which is what makes
 * `|/usr/bin/rotatelogs` work. Returns OK, or HTTP_INTERNAL_SERVER_ERROR
 * if a configured log cannot be opened — a decision log the operator
 * asked for and did not get is a silent blind spot, so we refuse to
 * start rather than pretend. */
int bs_open_decision_logs(apr_pool_t *pconf, server_rec *s);

/* subprocess_env marker for `accesslog=off`. Env (not notes) because it has
 * to survive mod_rewrite's internal_redirect the same way the BS_*
 * decision fields do — see bs_propagate_decision_env. */
#define BS_NOLOG_ENV "BS_NOLOG"

/* Suppress ALL access logging for this request.
 *
 * Set from the trigger action engine when a matching rule carries
 * `accesslog=off`. bs_propagate_decision_env — registered on
 * ap_hook_log_transaction at APR_HOOK_FIRST — sees the marker and
 * returns DONE. log_transaction is a RUN_ALL hook declared with
 * (OK, DECLINED), so any other return value breaks the chain and every
 * later-ordered logger is skipped, mod_log_config included. No
 * CustomLog line is formatted or written.
 *
 * Consequences the operator is buying, deliberately:
 *   - A CustomLog-based decision log is suppressed too: mod_log_config
 *     services every CustomLog directive from one hook function, so
 *     there is no way to keep one and starve another. BotShieldDecisionLog
 *     is written by the module itself and is unaffected, as is the
 *     error-log line bs_decision_log emits. That is the intended split —
 *     access log off, detection record intact.
 *   - Any third-party module with a log_transaction hook ordered after
 *     ours (audit logging, analytics) is also skipped.
 * Pair it with BotShieldDecisionLog and you get the useful combination:
 * flood traffic kept out of an archived access log while every decision
 * is still recorded in a separately-rotated detection log. Without an
 * owned decision log the only surviving record is the error-log line
 * (and boring passes there are demoted to DEBUG).
 *
 * If you want to drop a line from one specific CustomLog while keeping
 * the others, this is the wrong tool — use mod_log_config's own
 * conditional form, which can key off what we already published:
 *   CustomLog logs/access.log combined "expr=%{reqenv:BS_OUTCOME} != 'block'"
 *
 * Never applies under observe / LogOnly: bs_apply_trigger_action
 * returns before any side effect in that path, so a dry run still
 * produces its evidence. */
void bs_suppress_access_log(request_rec *r);

/* Outcome name -> BS_M_OUTCOME_* index, or -1. Exposed so the
 * BotShieldAccessLog parser validates against the SAME vocabulary the
 * decision log and metrics use, rather than a second copy of the list
 * that would drift the first time an outcome is added. */
/* Access-log suppression applied when the operator sets no
 * BotShieldAccessLog. These four are the outcomes where BotShield
 * generated the response itself and the application never ran, so the
 * line records something the site did not serve. `allow` and the
 * verify-endpoint outcomes are NOT in here: those either reached the
 * origin or are the module answering its own endpoint, and both are
 * real traffic.
 *
 * This is a deliberate incompleteness in the access log and is
 * announced at startup rather than left to be discovered. Every
 * suppressed request is still counted in requests_total, still on the
 * dashboard, and still eligible for the decision log.
 * `BotShieldAccessLog on` restores full logging. */
/* Outcomes the decision log records when the operator sets no
 * outcomes= key: the rare, actionable ones, UNION whatever the access
 * log is suppressing for that request.
 *
 * The union is the point. Suppressing a line from the access log and
 * omitting it from the decision log makes the request vanish from every
 * log on the box -- it happened, the server answered it, and nothing
 * says so. Deriving the default from the access-log mask makes
 * "recorded somewhere" a property of the module rather than of the
 * operator remembering to keep two directives in step.
 *
 * Computed per request, because BotShieldAccessLog is per-directory
 * while BotShieldDecisionLog is per-server: there is no single
 * suppression set at config time to union with. */
#define BS_DEFAULT_DECISIONLOG_OUTCOMES \
    ((1U << BS_M_OUTCOME_BLOCK)         | \
     (1U << BS_M_OUTCOME_VERIFIED)      | \
     (1U << BS_M_OUTCOME_RATE_LIMITED)  | \
     (1U << BS_M_OUTCOME_MISCONFIGURED) | \
     (1U << BS_M_OUTCOME_FAILOPEN)      | \
     (1U << BS_M_OUTCOME_REDIRECT))

#define BS_DEFAULT_ACCESSLOG_SUPPRESS \
    ((1U << BS_M_OUTCOME_CHALLENGED)   | \
     (1U << BS_M_OUTCOME_BLOCK)        | \
     (1U << BS_M_OUTCOME_RATE_LIMITED) | \
     (1U << BS_M_OUTCOME_REDIRECT))

/* Path the decision log takes when BotShieldDecisionLog is absent.
 * Server-root relative, so logs/ resolves the same way Apache's own
 * ErrorLog and CustomLog do.
 *
 * Only opened for a server with BotShieldEnabled somewhere in it. A
 * module that is loaded but never switched on writes nothing -- same
 * reasoning as the shipped drop-in not carrying a CustomLog, which
 * would otherwise leave an empty file on every host that installed the
 * RPM. */
#define BS_DEFAULT_DECISION_LOG "logs/botshield.log"

int bs_outcome_index(const char *name);

/* Inverse of bs_outcome_index. Returns "?" out of range. */
const char *bs_m_outcome_name(int idx);

/* Classification index -> display name ("browser", "verified-bot", ...). */
const char *bs_m_class_name(int idx);

/* Log an observability-endpoint hit to the decision log and suppress
 * its access-log line. Does not touch the decision counters. */
void bs_log_observability_request(request_rec *r);


/* ----------------------------------------------------------------------
 * Windowed counter reads (dashboard)
 * -------------------------------------------------------------------- */

/* One window's worth of tier/outcome totals. */
typedef struct {
    apr_uint64_t tier   [BS_M_TIER_COUNT];
    apr_uint64_t outcome[BS_M_OUTCOME_COUNT];
    apr_uint64_t cookie [BS_M_COOKIE_COUNT];
    apr_uint64_t req_total;      /* every request, evaluated or not */
    apr_uint64_t req_cookie;
    apr_uint64_t req_status[BS_M_STATUS_COUNT];
    apr_uint64_t req_code[BS_M_CODE_COUNT];
    apr_uint64_t req_resp[BS_M_RESP_COUNT];
    apr_uint64_t req_class[BS_M_CLASS_COUNT];
    /* Same three decision dimensions split by audience (bot / user),
     * backing the dashboard's two tabs. */
    apr_uint64_t g_resp   [BS_M_GROUP_COUNT][BS_M_RESP_COUNT];
    apr_uint64_t g_tier   [BS_M_GROUP_COUNT][BS_M_TIER_COUNT];
    apr_uint64_t g_outcome[BS_M_GROUP_COUNT][BS_M_OUTCOME_COUNT];
    apr_uint64_t g_cookie [BS_M_GROUP_COUNT][BS_M_COOKIE_COUNT];
    apr_uint64_t decisions;      /* sum of outcome[] — every decision logs one */
} bs_metrics_window;

/* Sum the buckets covering the last `span_minutes`.
 *   15 / 60  -> the minute ring
 *   1440     -> the hour ring
 *   0        -> all-time cumulative counters (no ring)
 * Any other span is rounded up onto whichever ring can serve it.
 * Slots outside the window are skipped, so a quiet period reads as
 * zero rather than as stale data. */
/* vhost_idx -1 reads the global aggregate; 0..count-1 reads that
 * vhost's block. */
void bs_metrics_read_window(int span_minutes, int vhost_idx,
                            bs_metrics_window *out);

/* Record one decision into both rings. Called from bs_decision_log
 * alongside the cumulative bumps; indices are the same bs_m_*_idx
 * values, and -1 means "no counter for this dimension". */
void bs_metrics_bucket_add(int vhost_idx, int tier_idx,
                           int outcome_idx, int cookie_idx,
                           int group_idx);

/* Record one request into the site-wide traffic counters. Called from
 * the log_transaction hook, which runs for every request on every
 * vhost — including requests BotShield never evaluated, which is the
 * whole point: it supplies the denominator for coverage. */
void bs_metrics_traffic_add(int vhost_idx, int status_idx, int code_idx,
                            int has_cookie, int resp_idx, int class_idx);

/* /botshield/metrics handler — Prometheus exposition format 0.0.4.
 * Mounted via the request dispatcher in botshield.c. Apache's
 * <Location> + Require* gates access; this module emits to anyone
 * who reaches the handler. */
int bs_metrics_handler(request_rec *r);

/* /botshield/dashboard — operator-facing HTML view of the same
 * counters /metrics exposes, with 15min / 1h / 24h / all-time
 * windows from the bucket rings. Self-contained: inline CSS and
 * inline SVG, no scripts or external assets, so a strict site CSP
 * cannot break it. Same access-control story as /metrics — wrap it
 * in <Location> with Require ip if it should not be public. */
int bs_dashboard_handler(request_rec *r);

/* /dashboard/bots — per-bot detail: every slug the rate limiter has
 * allocated a counter for, with its budget, origin, mode and current
 * window usage, plus a breakdown by botgroup. Rendered from the live
 * bot-rate state and the bot directory; adds no counters of its own. */
int bs_dashboard_bots_handler(request_rec *r);

/* /dashboard/internals — module health: SHM table occupancy, hot-swap
 * generation accounting (the only leak-shaped risk here), and a
 * point-in-time read of the machine. Separate from /dashboard/responses
 * because "is my policy right" and "is the module working" are
 * different questions asked at different moments. */
int bs_dashboard_internals_handler(request_rec *r);

/* The remaining dashboard pages. Each renders one coherent view over
 * the same window data; they were sections and tabs on one long page
 * until the page outgrew a single scroll. */
int bs_dashboard_responses_handler(request_rec *r);
int bs_dashboard_app_bots_handler(request_rec *r);
int bs_dashboard_app_users_handler(request_rec *r);

/* mod_status contribution — registered via APR_OPTIONAL_HOOK in
 * bs_register_hooks. Renders the same top-line counters in either
 * AP_STATUS_SHORT (one "Key: value" per line) or compact-HTML mode
 * for /server-status. */
int bs_status_hook(request_rec *r, int flags);

/* Site-wide automated share over the last hour, whole percent, or -1
 * when there is not enough traffic for it to mean anything. */
int bs_bot_share_pct(void);

/* Bump attestation_fail_total. Called from the verify path when a
 * solve reports one or more failed probes. */
void bs_metrics_note_attestation_fail(void);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_METRICS_H */
