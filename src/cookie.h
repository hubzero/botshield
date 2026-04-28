/* cookie.h — _bs_verified GCM cookie envelope + Cookie-header parser.
 *
 * Two halves of the cookie surface meet here:
 *
 *   read  — bs_parse_cookies_once tokenizes the inbound Cookie header
 *           into a per-request memoized name→value map; the two
 *           getters (bs_get_cookie_value, bs_get_verified_cookie_value)
 *           sit on top.
 *
 *   mint/verify — bs_build_cookie_prefix_gcm builds the AES-GCM-
 *           encrypted opaque cookie envelope; bs_build_cookie_payload
 *           appends the counter; bs_build_set_cookie assembles the
 *           Set-Cookie header line; bs_install_verified_cookie ties
 *           those together for the four issuance call sites
 *           (silent embedded-verify, M8 captcha-verify, form-captcha-
 *           replay, and the immediate post-PoW path). bs_verify_cookie
 *           is the inverse — base64-decode, GCM-decrypt, parse into a
 *           bs_challenge struct, dispatch to the alg's verify fn.
 *
 * The wire format is documented in mod_botshield.md. Briefly:
 *     base64(alg_id || nonce || ciphertext || tag) "." counter_str
 * The counter is "captcha" for server-issued captcha cookies, the
 * decimal PoW counter for client-solved sha256-zeros cookies. */
#ifndef BOTSHIELD_COOKIE_H
#define BOTSHIELD_COOKIE_H

#include <httpd.h>
#include <apr_tables.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AES-256-GCM cookie wire format separator: base64-envelope + '.' +
 * plaintext counter. '.' is outside the standard base64 alphabet so
 * the split point is unambiguous. */
#define BS_GCM_COUNTER_SEP    '.'

/* --- Read side ------------------------------------------------- */

/* Parse-once tokenizer for the request's Cookie header. Returns a
 * pool-allocated apr_table_t (name → value, RFC 6265 in practice).
 * The result is memoized on r->notes so subsequent calls within the
 * same request return the same map. Used by bs_get_cookie_value and
 * by the cookie-trigger predicate evaluator. Never returns NULL —
 * an absent Cookie header yields an empty table. */
apr_table_t *bs_parse_cookies_once(request_rec *r);

/* Look up `name` in the parsed cookie map. Returns NULL on miss. */
const char *bs_get_cookie_value(request_rec *r, const char *name);

/* verified-cookie lookup. Prefers __Host-bs_verified
 * (modern HTTPS deployments) and falls back to legacy _bs_verified
 * (cross-subdomain SSO via Domain=). */
const char *bs_get_verified_cookie_value(request_rec *r);

/* --- Mint side ------------------------------------------------- */

/* GCM cookie prefix — base64(alg_id || nonce || ct || tag). The JS
 * interstitial appends ".<counter>" client-side; the captcha and
 * embedded-verify paths build the full payload via bs_build_cookie_
 * payload below. Returns NULL on success, an error-string diagnostic
 * on GCM-encrypt failure or missing key. */
const char *bs_build_cookie_prefix_gcm(apr_pool_t *p,
                                       const bs_dir_cfg *cfg,
                                       const bs_challenge *ch,
                                       const char **out_b64);

/* Full base64-encoded cookie payload — prefix '.' counter. */
const char *bs_build_cookie_payload(apr_pool_t *p,
                                    const bs_dir_cfg *cfg,
                                    const bs_challenge *ch,
                                    const char *counter_str);

/* Render the Set-Cookie header line (name=value; Path=/; Expires=…;
 * SameSite=Lax; HttpOnly; Secure on HTTPS; Domain when configured).
 * emits __Host-bs_verified when prefix preconditions hold. */
const char *bs_build_set_cookie(request_rec *r, const bs_dir_cfg *cfg,
                                const char *payload_b64,
                                apr_time_t expires_at);

/* Build the payload from `ch` + counter_str and add a Set-Cookie row
 * to r->err_headers_out (so it reaches the client even on non-2xx
 * responses). Returns NULL on success, error-string on failure. */
const char *bs_install_verified_cookie(request_rec *r,
                                       const bs_dir_cfg *cfg,
                                       const bs_challenge *ch,
                                       const char *counter_str);

/* --- Verify side ----------------------------------------------- */

/* Verify a GCM-format cookie. Base64-decodes the prefix, GCM-decrypts
 * (primary key, then secondary if E16 rotation is in progress),
 * parses canonical fields into *out_ch, checks expiry, dispatches the
 * counter check to the alg's verify fn. `dot` points at the '.' that
 * separates prefix from counter. Returns NULL on accept. */
const char *bs_verify_cookie_gcm(request_rec *r,
                                 const bs_dir_cfg *cfg,
                                 const char *cookie_value,
                                 const char *dot,
                                 bs_challenge *out_ch);

/* Verify any cookie format. Locates the '.' and dispatches to
 * bs_verify_cookie_gcm. Pre-auth errors (no key, oversize, missing
 * '.') leave *out_ch untouched; post-auth rejections (expired, bad
 * counter) populate *out_ch so callers can carry rep state forward. */
const char *bs_verify_cookie(request_rec *r, const bs_dir_cfg *cfg,
                             const char *cookie_value,
                             bs_challenge *out_ch);

/* --- Carry-forward: rep state across cookie generations ------- *
 *
 * Issuance call sites (silent embedded-verify, M8 captcha-verify,
 * E18 form-captcha) read the prior cookie via bs_carry_forward_eligible,
 * then bs_apply_rep_carry computes the carried score with the
 * forgive-band the call site picks per tier policy. */

/* The shared carry-forward predicate. Both bs_carry_forward_eligible
 * (issuance-side) and bs_handler (render-side) call this so the two
 * paths reject the same cverrs and don't drift. Reject when:
 *   - cverr == "signature mismatch" (rep bytes can't be trusted)
 *   - cverr == "expired"           (indefinite rep transfer)
 *   - cverr is some other pre-auth error and *prior_ch is unwritten. */
int bs_should_carry_prior_rep(const char *cverr,
                              const bs_challenge *prior_ch);

/* Returns 1 with *out_prior_ch populated if the caller may carry
 * the prior cookie's rep block into a freshly-minted cookie; 0 if
 * the prior cookie is missing/invalid/expired. TTL is the only
 * mechanism preventing indefinite reputation transfer across
 * cookie generations. */
int bs_carry_forward_eligible(request_rec *r, const bs_dir_cfg *cfg,
                              bs_challenge *out_prior_ch);

/* Apply rep-carry math: clamp forgive_amount against the per-cookie
 * hourly cap, compute new score = prior.score - forgive, clamp at
 * zero. forgive_amount is per-tier policy, picked by the caller
 * (cfg->forgive_silent / forgive_form / forgive_captcha). The
 * caller bumps target->passes_X afterward (the "ever
 * passed" clamp). */
void bs_apply_rep_carry(request_rec *r, const bs_dir_cfg *cfg,
                        const bs_challenge *prior_ch,
                        bs_rep_state *target,
                        int forgive_amount);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_COOKIE_H */
