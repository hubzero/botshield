/* formcaptcha.h — E18 inline form-captcha tier.
 *
 * Operator opts a scope into form-captcha validation via
 * `BotShieldFormCaptcha on`. On POST to that scope, BotShield's
 * fixup hook reads the request body (url-encoded or JSON), extracts
 * the configured captcha provider's response field, calls
 * siteverify, and either:
 *   - mints _bs_session, installs an input replay filter so the
 *     downstream app handler still sees the original body, returns
 *     DECLINED → app's handler runs normally
 *   - returns 403 → app's handler never sees the bad request
 *
 * The replay-filter pattern handles "BotShield consumed the body
 * for inspection but the app handler still needs to read it." We
 * buffer the body in r->pool and emit it as a synthetic input
 * brigade when downstream asks. ap_add_input_filter puts the filter
 * at the top of r->input_filters, so the very first read by the
 * app handler hits our buffered copy and never touches the drained
 * protocol filters below.
 *
 * Multipart/form-data is deliberately out of scope — file uploads
 * need streaming-parser machinery this module isn't the right home
 * for. Operators with file-upload forms put the captcha on a
 * separate non-upload form. */
#ifndef BOTSHIELD_FORMCAPTCHA_H
#define BOTSHIELD_FORMCAPTCHA_H

#include <httpd.h>
#include <util_filter.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The fixup hook registered against ap_hook_fixups in
 * bs_register_hooks. Returns DECLINED to let the request through
 * (either because form-captcha isn't enabled on this scope or
 * because the captcha verified), or an HTTP status code to short-
 * circuit. */
int bs_form_captcha_fixup(request_rec *r);

/* Input-filter callback. Registered via ap_register_input_filter at
 * post_config time (see bs_register_hooks). The fixup hook installs
 * the filter on a per-request basis after siteverify succeeds; the
 * filter then replays the buffered body to the downstream handler. */
extern ap_filter_rec_t *bs_form_replay_filter_handle;
apr_status_t bs_form_replay_filter(ap_filter_t *f,
                                   apr_bucket_brigade *bb,
                                   ap_input_mode_t mode,
                                   apr_read_type_e block,
                                   apr_off_t readbytes);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_FORMCAPTCHA_H */
