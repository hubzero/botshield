/* challenge.h — challenge issuance, PoW algorithm registry,
 * reputation state envelope, and the bootstrap-sig helpers shared
 * between M7 (interstitial) and E17 (silent-tier embedded mode).
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
#include <apr.h>
#include <apr_pools.h>
#include <apr_time.h>

#include "crypto.h"   /* BS_SIG_BYTES, primitives */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — bs_dir_cfg is defined in botshield.h.
 * Declared here so this header is self-contained. */
struct bs_dir_cfg;
typedef struct bs_dir_cfg bs_dir_cfg;

/* ======================================================================
 * Challenge wire-format constants
 * ====================================================================== */

/* Bumped 1->2 for E15: rep envelope grew two fields
 * (forgive_window_start, forgive_consumed). Old (v1) cookies fail the
 * version check and trigger a fresh challenge — one-time disruption
 * per client on upgrade. */
#define BS_PROTOCOL_VERSION   2
#define BS_SALT_BYTES         16
#define BS_NONCE_BYTES        8

/* ======================================================================
 * Reputation state and challenge envelope
 * ====================================================================== */

/* Reputation state carried in the cookie. Populated fresh on a first-
 * time challenge (all zeros), and merged forward with forgiveness on
 * re-issues.
 *
 * E15 — forgiveness cap per window. `forgive_window_start` marks the
 * start of the current rolling hour (unix sec); on every verify-
 * success we either roll the window if the prior one is over an hour
 * old, or clamp the new forgiveness so the running consumed total
 * stays at or below BotShieldForgivenessCapPerHour. */
typedef struct {
    int          score;
    apr_uint32_t flags;
    int          passes_silent;
    int          passes_form;
    int          passes_captcha;
    apr_time_t   challenged_at;        /* unix sec */
    apr_uint32_t forgive_window_start; /* unix sec; 0 = no window yet */
    apr_uint32_t forgive_consumed;     /* points used inside current window */
} bs_rep_state;

typedef struct {
    int           version;
    const char   *alg_name;              /* points into registry */
    unsigned char salt [BS_SALT_BYTES];
    unsigned char nonce[BS_NONCE_BYTES];
    int           difficulty;
    apr_time_t    expires_at;            /* unix seconds */
    bs_rep_state  rep;                   /* carried forward across re-issues */
    int           auto_tier;             /* 1 = silent M7 auto-submit; 0 = form */
    unsigned char signature[BS_SIG_BYTES];
} bs_challenge;

/* ======================================================================
 * PoW algorithm registry
 * ====================================================================== */

typedef const char *(*bs_alg_issue_fn)(const bs_dir_cfg *cfg,
                                       bs_challenge *out);
typedef const char *(*bs_alg_verify_fn)(const bs_challenge *ch,
                                        const char *counter_str);

typedef struct {
    const char       *name;
    int               implemented;   /* 1 = callable, 0 = reserved */
    bs_alg_issue_fn   issue;
    bs_alg_verify_fn  verify;
} bs_pow_algorithm;

/* ======================================================================
 * Challenge API
 * ====================================================================== */

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

/* bootstrap-binding helpers — bind the silent-tier
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
