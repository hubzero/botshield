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

/* /botshield/metrics handler — Prometheus exposition format 0.0.4.
 * Mounted via the request dispatcher in botshield.c. Apache's
 * <Location> + Require* gates access; this module emits to anyone
 * who reaches the handler. */
int bs_metrics_handler(request_rec *r);

/* mod_status contribution — registered via APR_OPTIONAL_HOOK in
 * bs_register_hooks. Renders the same top-line counters in either
 * AP_STATUS_SHORT (one "Key: value" per line) or compact-HTML mode
 * for /server-status. */
int bs_status_hook(request_rec *r, int flags);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_METRICS_H */
