/* bridge.h — module ↔ app reputation bridge.
 *
 * Two halves of one signed wire-format integration:
 *
 *   E5  inbound  (app → module via X-BotShield-Feedback):
 *       app emits a signed `event=<name>;sig=<hex>` header on its
 *       responses. The module's output filter HMAC-verifies, looks
 *       the event up in scfg->feedback_triggers, and applies the
 *       configured flag-bit + TTL + log-tag.
 *
 *   E8.2 outbound (module → app via X-Botshield-Claims):
 *       on the request path, the module strips any incoming
 *       X-Botshield-* and emits a single signed X-Botshield-Claims
 *       on the request to the backend handler. The backend reads
 *       BotShield's verdict (request risk score, cookie state,
 *       tier, flag bitmap) without poking at the encrypted cookie.
 *
 * Why both halves share one file: same HMAC infrastructure, same
 * ap-table-based wire format. The two protocols' canonical bytes
 * are structurally distinct (feedback HMACs `event=<name>` only;
 * claims HMACs seven semicolon-fields with a fixed `v=1` lead) so
 * cross-replay between the two directions is impossible — one key
 * with parser-provided domain separation is sufficient. */
#ifndef BOTSHIELD_BRIDGE_H
#define BOTSHIELD_BRIDGE_H

#include <httpd.h>
#include <http_config.h>
#include <util_filter.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* E5 output-filter registration. The filter handle is set in
 * post_config (bs_register_hooks) by ap_register_output_filter
 * passing bs_app_feedback_filter as the callback, and inserted on
 * every initial request via bs_app_feedback_insert_filter. */
extern ap_filter_rec_t *bs_app_feedback_filter_handle;
apr_status_t bs_app_feedback_filter(ap_filter_t *f,
                                    apr_bucket_brigade *bb);
void bs_app_feedback_insert_filter(request_rec *r);

/* E8.2 — strip any client-supplied X-Botshield-* and emit a fresh
 * signed X-Botshield-Claims request header. Called from the
 * request-handler "nochallenge" decision after the score+tier are
 * resolved. Returns NULL on success or a pool-allocated diagnostic
 * string on failure (e.g. no key configured). */
const char *bs_app_claims_set(request_rec *r,
                              struct bs_server_cfg *scfg,
                              int score, bs_tier tier,
                              const char *cookie_status,
                              apr_uint32_t flags,
                              int passes_non_interactive,
                              int passes_interactive,
                              int passes_captcha);

/* --- E5 + E8.2 directive setters --- *
 *
 * BotShieldAppFeedback / BotShieldAppFeedbackHeader configure the
 * inbound (E5) channel; BotShieldAppClaims gates the outbound (E8.2)
 * channel; BotShieldAppIntegrationSecretFile loads the HMAC key
 * shared by both. */
const char *bs_set_app_feedback(cmd_parms *cmd, void *dconf, int flag);
const char *bs_set_app_feedback_header(cmd_parms *cmd, void *dconf,
                                       const char *name);
const char *bs_set_app_claims(cmd_parms *cmd, void *dconf, int flag);
const char *bs_set_app_integration_secret_file(cmd_parms *cmd,
                                               void *dconf,
                                               const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_BRIDGE_H */
