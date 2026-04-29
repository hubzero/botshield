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
#include <http_config.h>
#include <apr.h>

#include "challenge.h"   /* bs_challenge (out-param of carry_and_mint) */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — bs_dir_cfg is defined in botshield.h.
 * Declared here so this header is self-contained. */
struct bs_dir_cfg;
typedef struct bs_dir_cfg bs_dir_cfg;

/* ======================================================================
 * M8 captcha provider registry
 * ====================================================================== */

typedef struct bs_captcha_provider bs_captcha_provider;

typedef enum {
    BS_CAPTCHA_OK              = 0,
    BS_CAPTCHA_REJECTED        = 1,
    BS_CAPTCHA_TIMEOUT         = 2,
    BS_CAPTCHA_ERROR           = 3,
    /* Guard short-circuits emitted by bs_captcha_siteverify_guarded.
     * Caller maps to HTTP status (typically 429 / 503) and emits its
     * own decision_log line so the tier label matches the call site
     * (captcha / silent / form). */
    BS_CAPTCHA_RATE_LIMITED    = 4,
    BS_CAPTCHA_INFLIGHT_CAPPED = 5
} bs_captcha_result;

/* Provider-specific siteverify function. NULL on the provider row
 * means "use the shared secret/response/remoteip POST + json-c parse
 * path." Providers whose verify protocol diverges materially from
 * the Google-family contract (GeeTest: HMAC-signed fields, non-bool
 * result semantics, JSON blob as the client-side token) set this to
 * their own function instead. */
typedef bs_captcha_result (*bs_captcha_siteverify_fn)(
    request_rec *r,
    const bs_captcha_provider *prov,
    const unsigned char *secret, apr_size_t secret_len,
    const char *token, int timeout_ms,
    /* Optional operator-supplied CA bundle path. NULL = libcurl
     * default. */
    const char *ca_bundle,
    const char **out_details,
    long *out_http_code,
    double *out_score,
    /* Binding-metadata out-params. NULL is a legal value and means
     * "provider didn't return this field" — a valid signal (e.g.
     * GeeTest doesn't expose hostname/action over the wire because
     * its binding is HMAC-signed at request time). Callers only
     * compare when non-NULL. */
    const char **out_hostname,
    const char **out_action);

/* For the Google-family providers (Turnstile, hCaptcha, reCAPTCHA
 * v2/v3, Friendly Captcha), `siteverify_fn` is NULL and the shared
 * default path POSTs a body of the form
 *   secret=<secret>&<siteverify_field>=<token>&remoteip=<ip>
 * where `siteverify_field` defaults to "response" or is set to e.g.
 * "solution" (Friendly Captcha).
 *
 * For providers whose verify protocol doesn't fit that shape
 * (GeeTest), `siteverify_fn` is set to a provider-specific function
 * and the rest of the registry row is informational — the fn decides
 * how to use it.
 *
 * `token_field` is the name of the hidden form input the
 * interstitial emits to carry the client's token to our verify
 * endpoint. `widget_script_url` is the async script tag the
 * interstitial embeds; `widget_class` is the CSS class on the
 * container div the provider's script looks for (empty for providers
 * with programmatic init). */
struct bs_captcha_provider {
    const char *name;
    int         implemented;
    const char *siteverify_url;
    const char *token_field;
    const char *widget_script_url;
    const char *widget_class;
    const char *siteverify_field;          /* NULL → "response" */
    bs_captcha_siteverify_fn siteverify_fn; /* NULL → shared path */
};

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

/* Centralized siteverify wrapper. Applies the M8.1 guard rail
 * (per-IP rate limit + global in-flight semaphore) before
 * dispatching to the provider-specific or shared siteverify path.
 * Used by /captcha-verify, /embedded-verify-provider (E17), and
 * bs_form_captcha_fixup (E18) so all three paths get the same
 * provider-quota and worker-occupancy DoS protection that the
 * /captcha-verify handler had inline.
 *
 * Returns the same bs_captcha_result enum plus two new variants
 * (BS_CAPTCHA_RATE_LIMITED, BS_CAPTCHA_INFLIGHT_CAPPED). Caller
 * maps to HTTP status (typically 429 / 503) and emits its own
 * decision_log line.
 *
 * `log_tag` is a short identifier for the call site
 * ("captcha-verify", "embedded-verify", "form-captcha") woven into
 * the rate-limit / in-flight log lines. The token must already be
 * non-NULL, non-empty, and length-bounded by the caller (each call
 * site has its own body shape). Resolves the provider verify_fn
 * (provider-specific override or shared bs_captcha_siteverify) and
 * dispatches once the guards pass. */
bs_captcha_result bs_captcha_siteverify_guarded(
    request_rec *r,
    const bs_dir_cfg *cfg,
    const char *token,
    int timeout_ms,
    const char *log_tag,
    const char **out_details,
    long *out_http_code,
    double *out_score,
    const char **out_hostname,
    const char **out_action);

const char *bs_mint_pending_cookie(request_rec *r,
                                   const bs_dir_cfg *cfg);
const char *bs_clear_pending_cookie(request_rec *r,
                                    const bs_dir_cfg *cfg);

/* Carry-forward + mint + install for the three captcha-result
 * sites that all need the same cookie minting after a successful
 * provider verify (or a fail-open on TIMEOUT/ERROR): the M8
 * /captcha-verify handler, the embedded-verify-provider path in
 * silent.c, and the inline form-captcha fixup in formcaptcha.c.
 *
 * The shared logic — read prior `_bs_verified` if sig-verifies-or-
 * just-expired, apply forgive_amount through the per-cookie hourly
 * cap, increment the matching passes_* counter, derive the
 * captcha-<provider> alg row, issue a fresh challenge, install the
 * cookie via Set-Cookie — used to live in three copies. Both the
 * forgive-cap regression caught in the E15 review and the
 * fresh-rep regression caught in the E17 review were drift in
 * exactly this section. One helper; one place to update.
 *
 * passes_kind picks which counter to bump: PASSES_CAPTCHA for the
 * captcha-tier callers, PASSES_SILENT for the embedded-silent path.
 * forgive_amount is the per-tier policy the caller picks
 * (cfg->forgive_captcha vs cfg->forgive_silent). auto_tier is the
 * silent-tier marker the silent.c caller sets to 1; the captcha-
 * tier callers leave it 0.
 *
 * Returns NULL on success with `*out_ch` populated and the
 * Set-Cookie row already added to r->err_headers_out. On failure
 * returns an error-string the caller may log; the caller is
 * responsible for the HTTP status and decision-log emission. */
typedef enum {
    BS_CAPTCHA_PASSES_CAPTCHA = 0,
    BS_CAPTCHA_PASSES_SILENT  = 1,
} bs_captcha_passes_kind;

const char *bs_captcha_carry_and_mint(
    request_rec *r,
    const bs_dir_cfg *cfg,
    bs_captcha_passes_kind passes_kind,
    int forgive_amount,
    int auto_tier,
    bs_challenge *out_ch,
    const char **out_alg_name);

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
