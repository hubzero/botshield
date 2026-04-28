/* challenge.h — challenge issuance, PoW algorithm registry, and
 * the bootstrap-sig helpers shared between M7 (interstitial) and
 * E17 (silent-tier embedded mode).
 *
 * The "challenge" abstraction is a pre-shared opaque envelope the
 * server signs once and the client returns having proved possession
 * of a small bit of work (PoW counter) or a third-party attestation
 * (captcha siteverify response). Both interstitial and silent paths
 * use the same bs_challenge struct + algorithm registry.
 *
 * Wire format (embedded inline in the interstitial, JSON):
 *     { v, alg, salt, nonce, difficulty, expires_at,
 *       score, flags, passes_silent, passes_form, passes_captcha,
 *       challenged_at, auto, signature }
 *
 * Canonical HMAC input (deterministic, pipe-delimited ASCII):
 *     "v|alg|salthex|noncehex|difficulty|expires_at
 *      |score|flags|pass_s|pass_f|pass_c|challenged_at|auto"
 *
 * Cookie payload = base64( canonical || "|" || sighex || "|" || counter )
 * — a single base64 blob the server can parse by splitting on '|',
 * no JSON parser required.
 *
 * `auto` is the silent-tier (M7) marker: 1 means the challenge was
 * served as a no-click auto-submit splash, 0 means the form-PoW
 * interstitial. HMAC-covered so an accepted cookie tells the server
 * which tier actually served it — used to pick passes_silent vs
 * passes_form and the matching forgiveness amount on verify.
 *
 * Keep in sync with the JS worker (silent.c) when the template
 * ships the wire bits. */
#ifndef BOTSHIELD_CHALLENGE_H
#define BOTSHIELD_CHALLENGE_H

#include <httpd.h>
#include <http_config.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PoW algorithm registry lookup. Returns NULL on no match. */
const bs_pow_algorithm *bs_find_algorithm(const char *name);

/* Build the canonical pipe-delimited HMAC input string for a
 * challenge. Both the issue path (signs this string) and the verify
 * path (recomputes and compares HMACs) produce the exact same
 * canonical bytes for a given challenge struct — that's the
 * tamper-detection contract. Returned string is pool-allocated. */
const char *bs_challenge_canonical(apr_pool_t *p, const bs_challenge *ch);

/* Issue a fresh challenge: fills `*out` with version, alg, salt,
 * nonce, difficulty, expires_at, auto_tier, and the alg-specific
 * signature. `rep_in` carries forward reputation across re-issues
 * (NULL = first-time challenge with zero rep). `alg_override` lets
 * the captcha-tier path pin a specific alg row regardless of
 * cfg->algorithm; pass NULL to use the configured algorithm. */
const char *bs_issue_challenge(apr_pool_t *p, const bs_dir_cfg *cfg,
                               int difficulty, int cookie_ttl,
                               int auto_tier,
                               const bs_pow_algorithm *alg_override,
                               const bs_rep_state *rep_in,
                               bs_challenge *out);

/* Render a challenge as the inline JSON the M7 interstitial JS
 * consumes. Includes the encrypted cookie prefix, salt/nonce/
 * difficulty/expires, and (for embedded silent-tier mode) the
 * bound-IP HMAC pair. */
const char *bs_challenge_json(request_rec *r, apr_pool_t *p,
                              const bs_dir_cfg *cfg,
                              const bs_challenge *ch);

/* MEDIUM #2 bootstrap-binding helpers — bind the silent-tier
 * embedded-bootstrap to the originating client IP via an HMAC over
 * (nonce, bound_ip_hex, expires_at). Issued at bootstrap time,
 * verified at /embedded-verify time. */
int  bs_format_bound_ip_hex(const char *useragent_ip,
                            char out_hex[33]);
void bs_compute_bootstrap_sig(apr_pool_t *p,
                              const unsigned char key[32],
                              const char *nonce_hex,
                              const char *bound_ip_hex,
                              apr_time_t expires_at,
                              char out_sig_hex[BS_SIG_BYTES * 2 + 1]);

/* `BotShieldAlgorithm <name>` — pin the PoW algorithm for cookie
 * minting from this scope. Validates against the registry and the
 * implemented flag. */
const char *bs_set_algorithm(cmd_parms *cmd, void *cfg_v,
                             const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_CHALLENGE_H */
