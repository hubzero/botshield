/* crypto.h — small primitives for mod_botshield: SHA-256, HMAC,
 * AES-256-GCM envelope, HKDF key derivation, hex codec.
 *
 * Pure-OpenSSL wrappers, no per-request state. The HKDF helper is
 * called once per secret/purpose at config-load time; the rest run
 * on the request hot path. Constant-time equality (bs_ct_equal)
 * lives here too — it's small, security-critical, and naturally
 * paired with the HMAC verifier callers.
 *
 * Symbol-namespacing rule (Apache modules share dynamic-linker
 * symbol space): every cross-file function declared here uses the
 * `bs_` / `BS_` prefix; the .so is linked with -fvisibility=hidden
 * so only `botshield_module` itself escapes the .so. */
#ifndef BOTSHIELD_CRYPTO_H
#define BOTSHIELD_CRYPTO_H

#include <apr.h>
#include <apr_errno.h>

#include <httpd.h>
#include <http_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hash output sizes. Both equal 32 (SHA-256 digest length); the two
 * names exist because the call sites mean different things — one is
 * "raw SHA-256 of arbitrary bytes," the other is "HMAC-SHA-256
 * authentication tag." Operationally indistinguishable, but the
 * intent at the call site is clearer with the right name. */
#define BS_SHA256_LEN  32
#define BS_SIG_BYTES   32     /* HMAC-SHA-256 output (cookies, bootstrap_sig, …) */

/* AES-256-GCM envelope wire format (used by the GCM cookie path):
 *     alg_id(1) || nonce(BS_GCM_NONCE_LEN) || ct || tag(BS_GCM_TAG_LEN)
 *
 * The single AAD byte is the alg_id, so an attacker can't swap
 * 0x01 for some future 0x02 and drive the verifier into a
 * different parse. */
#define BS_COOKIE_ALG_GCM   0x01
#define BS_GCM_NONCE_LEN    12
#define BS_GCM_TAG_LEN      16

/* SHA-256 over `len` bytes. Writes BS_SHA256_LEN bytes to `out`. */
void bs_sha256(const unsigned char *data, apr_size_t len,
               unsigned char out[BS_SHA256_LEN]);

/* HMAC-SHA-256. Writes BS_SIG_BYTES bytes to `out`. */
void bs_hmac_sha256(const unsigned char *key, apr_size_t keylen,
                    const unsigned char *data, apr_size_t datalen,
                    unsigned char out[BS_SIG_BYTES]);

/* Constant-time equality. Returns 1 on equal, 0 on not. Use this
 * for any HMAC / nonce / tag comparison so a length-correlated
 * timing attack can't extract bytes by measuring response time. */
int bs_ct_equal(const unsigned char *a, const unsigned char *b,
                apr_size_t len);

/*  HKDF-Expand for per-purpose key
 * derivation. RFC 5869. Replaces the prior `SHA256(secret)` ad-hoc
 * derivation with a cryptographically clean per-purpose model:
 *
 *   key_for_X = HKDF(secret, info="bs:X:v1")
 *
 * Each purpose gets its own derived key. Leaking one (cryptanalysis,
 * side-channel, key extraction from memory) tells an attacker
 * nothing about the others — the HMAC-based extract+expand
 * construction is one-way per purpose-tag.
 *
 * Called once at config-load time per secret/purpose; the derived
 * keys live in dir_cfg and the request path uses them directly
 * with zero per-request HKDF cost. Returns 0 on OpenSSL failure
 * (treated as fatal by the caller — module won't start). */
int bs_hkdf_derive_key(const unsigned char *master,
                       apr_size_t master_len,
                       const char *info,
                       unsigned char out_key[32]);

/* AES-256-GCM encrypt. On success: writes the full envelope
 * (1 + BS_GCM_NONCE_LEN + pt_len + BS_GCM_TAG_LEN bytes) into
 * `out_buf`, sets *out_len, returns NULL. On failure: returns an
 * error string; *out_len untouched. Caller's `out_buf` must be
 * pre-sized to at least 1 + BS_GCM_NONCE_LEN + pt_len + BS_GCM_TAG_LEN. */
const char *bs_gcm_encrypt(const unsigned char aes_key[32],
                           const unsigned char *pt,
                           apr_size_t pt_len,
                           unsigned char *out_buf,
                           apr_size_t *out_len);

/* AES-256-GCM decrypt. Verifies the GCM tag (constant-time inside
 * OpenSSL). On success: writes plaintext to `out_pt`, sets
 * *out_pt_len, returns NULL. On any failure including tag mismatch:
 * returns an error string; *out_pt and *out_pt_len untouched.
 * Caller's `out_pt` must be at least env_len - 1 - BS_GCM_NONCE_LEN
 * - BS_GCM_TAG_LEN bytes. */
const char *bs_gcm_decrypt(const unsigned char aes_key[32],
                           const unsigned char *env,
                           apr_size_t env_len,
                           unsigned char *out_pt,
                           apr_size_t *out_pt_len);

/* Hex codec. bs_to_hex writes 2*len lowercase chars + NUL into `out`.
 * bs_from_hex decodes the first 2*out_len characters of `in` into
 * `out`; returns 1 on success, 0 if `in_len` is too short or any
 * non-hex byte is in the consumed prefix. The defensive `in_len`
 * parameter prevents OOB reads if a future caller forgets the
 * length check upstream. */
void bs_to_hex(const unsigned char *in, apr_size_t len, char *out);
int  bs_from_hex(const char *in, apr_size_t in_len,
                 apr_size_t out_len, unsigned char *out);

/* Bounded integer parsers for pre-HMAC cookie / form-body fields.
 * Each returns 1 on a clean parse within [min, max]; 0 otherwise.
 * Caller's *out is left untouched on failure. max_len is a hard cap
 * on the digit-string length — rejects gigantic inputs before they
 * reach strtol. Used by directive setters and by the canonical-form
 * cookie parser in cookie.c. */
int bs_parse_int_bounded(const char *s,
                         long min_val, long max_val,
                         apr_size_t max_len,
                         long *out);
int bs_parse_uint32_bounded(const char *s,
                            apr_size_t max_len,
                            apr_uint32_t *out);
int bs_parse_int64_bounded(const char *s,
                           apr_int64_t min_val,
                           apr_int64_t max_val,
                           apr_int64_t *out);

/* --- Cookie/secret directive setters --- *
 *
 * BotShieldSecretFile / BotShieldSecondarySecretFile load the master
 * HMAC keys for the GCM cookie envelope and derive per-purpose keys
 * (HKDF) at config time. Both verify the file is mode-600. */
const char *bs_set_secret_file(cmd_parms *cmd, void *cfg_v,
                               const char *arg);
const char *bs_set_secondary_secret_file(cmd_parms *cmd, void *cfg_v,
                                         const char *arg);

/* HKDF-derive the three per-purpose 32-byte keys
 * (cookie GCM, pending HMAC, bootstrap HMAC) from a master secret.
 * Used by the secret-file directive setters and by the auto-secret
 * post_config path. Returns NULL on success; on (vanishingly unlikely)
 * HKDF failure returns a diagnostic string allocated from p. */
const char *bs_derive_purpose_keys(apr_pool_t *p,
                                   const unsigned char *master,
                                   apr_size_t master_len,
                                   unsigned char *out_gcm,
                                   unsigned char *out_pending,
                                   unsigned char *out_bootstrap);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_CRYPTO_H */
