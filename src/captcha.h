/* captcha.h — M8 captcha tier: provider registry, libcurl-backed
 * siteverify, M8.1 pending-cookie machinery, and the verify endpoint
 * handler.
 *
 * Public surface:
 *   - bs_find_provider          → provider-name lookup
 *   - bs_captcha_siteverify     → libcurl POST + json-c parse;
 *                                 dispatches to provider-specific
 *                                 fn when the registry row sets one
 *                                 (GeeTest), shared default path
 *                                 otherwise (Turnstile / hCaptcha /
 *                                 reCAPTCHA v2/v3 / Friendly)
 *   - bs_mint_pending_cookie    → M8.1: HMAC-signed origin cookie
 *                                 minted at interstitial render time
 *   - bs_clear_pending_cookie   → emits Max-Age=0 to drop the
 *                                 pending cookie after a successful
 *                                 siteverify so a stale cookie can't
 *                                 be reused
 *   - bs_captcha_verify_handler → POST handler at
 *                                 <prefix>/captcha-verify
 *   - bs_form_get               → URL-encoded form-body field
 *                                 lookup; small helper that lives
 *                                 here because the captcha verify
 *                                 endpoint is its primary user (the
 *                                 E18 form-captcha replay path also
 *                                 calls it). */
#ifndef BOTSHIELD_CAPTCHA_H
#define BOTSHIELD_CAPTCHA_H

#include <httpd.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

const bs_captcha_provider *bs_find_provider(const char *name);

bs_captcha_result bs_captcha_siteverify(request_rec *r,
                                        const bs_captcha_provider *prov,
                                        const unsigned char *secret,
                                        apr_size_t secret_len,
                                        const char *token,
                                        int timeout_ms,
                                        const char *ca_bundle,
                                        const char **out_details,
                                        long *out_http_code,
                                        double *out_score,
                                        const char **out_hostname,
                                        const char **out_action);

const char *bs_mint_pending_cookie(request_rec *r,
                                   const bs_dir_cfg *cfg);
const char *bs_clear_pending_cookie(request_rec *r,
                                    const bs_dir_cfg *cfg);

int bs_captcha_verify_handler(request_rec *r, bs_dir_cfg *cfg);

/* URL-encoded form-body field lookup. Returns a pool-allocated copy
 * of the value (URL-decoded), or NULL if the key isn't present.
 * `body` is a NUL-terminated `key=val&key=val…` string; use the
 * pre-existing bs_read_form_body to slurp it. */
char *bs_form_get(apr_pool_t *p, const char *body, const char *key);

/* --- M8 captcha directive setters --- *
 *
 * Eleven directive setters that configure the captcha tier — provider
 * choice, site/secret keys, network timeouts, expected hostname /
 * action, CA bundle, and the rate-limit / max-inflight DoS guards.
 * Wired into the cmds[] table in botshield.c. */
const char *bs_set_captcha_provider     (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_site_key     (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_secret_file  (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_timeout      (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_connect_timeout(cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_recaptcha_v3_min_score(cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_expected_hostname(cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_expected_action  (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_ca_bundle    (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_rate_limit   (cmd_parms *cmd, void *cfg_v, const char *arg);
const char *bs_set_captcha_max_inflight (cmd_parms *cmd, void *cfg_v, const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_CAPTCHA_H */
