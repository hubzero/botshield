/* crypto.c — implementations behind crypto.h. Pure-OpenSSL wrappers
 * with no per-request state. */

#include "crypto.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

void bs_sha256(const unsigned char *data, apr_size_t len,
               unsigned char out[BS_SHA256_LEN])
{
    unsigned int outlen = BS_SHA256_LEN;
    EVP_Digest(data, (size_t)len, out, &outlen, EVP_sha256(), NULL);
}

void bs_hmac_sha256(const unsigned char *key, apr_size_t keylen,
                    const unsigned char *data, apr_size_t datalen,
                    unsigned char out[BS_SIG_BYTES])
{
    unsigned int outlen = BS_SIG_BYTES;
    HMAC(EVP_sha256(), key, (int)keylen, data, datalen, out, &outlen);
}

int bs_ct_equal(const unsigned char *a, const unsigned char *b,
                apr_size_t len)
{
    unsigned char diff = 0;
    for (apr_size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

int bs_hkdf_derive_key(const unsigned char *master,
                       apr_size_t master_len,
                       const char *info,
                       unsigned char out_key[32])
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return 0;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return 0;
    OSSL_PARAM params[5];
    int i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string("digest",
                                                   "SHA256", 0);
    params[i++] = OSSL_PARAM_construct_octet_string("key",
                                                    (void *)master,
                                                    master_len);
    /* Empty salt: HKDF-Extract degenerates to HMAC(zeros, secret).
     * The per-purpose info tag below provides domain separation. */
    params[i++] = OSSL_PARAM_construct_octet_string("salt",
                                                    (void *)"", 0);
    params[i++] = OSSL_PARAM_construct_octet_string("info",
                                                    (void *)info,
                                                    strlen(info));
    params[i] = OSSL_PARAM_construct_end();
    int rc = EVP_KDF_derive(ctx, out_key, 32, params);
    EVP_KDF_CTX_free(ctx);
    return rc == 1;
}

const char *bs_gcm_encrypt(const unsigned char aes_key[32],
                           const unsigned char *pt,
                           apr_size_t pt_len,
                           unsigned char *out_buf,
                           apr_size_t *out_len)
{
    /* LOW #3 — caller passes the HKDF-derived AES key directly;
     * we no longer derive per-call. */
    const unsigned char *key = aes_key;

    out_buf[0] = BS_COOKIE_ALG_GCM;
    if (RAND_bytes(out_buf + 1, BS_GCM_NONCE_LEN) != 1) {
        return "RAND_bytes(gcm_nonce)";
    }
    unsigned char *nonce = out_buf + 1;
    unsigned char *ct    = out_buf + 1 + BS_GCM_NONCE_LEN;
    unsigned char *tag   = ct + pt_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "EVP_CIPHER_CTX_new";
    const char *err = NULL;
    int outlen = 0, finallen = 0, aadlen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        err = "EVP_EncryptInit_ex(aes_256_gcm)"; goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            BS_GCM_NONCE_LEN, NULL) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(SET_IVLEN)"; goto done;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        err = "EVP_EncryptInit_ex(key+nonce)"; goto done;
    }
    if (EVP_EncryptUpdate(ctx, NULL, &aadlen, out_buf, 1) != 1) {
        err = "EVP_EncryptUpdate(AAD)"; goto done;
    }
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &outlen, pt, (int)pt_len) != 1) {
            err = "EVP_EncryptUpdate(pt)"; goto done;
        }
    }
    if (EVP_EncryptFinal_ex(ctx, ct + outlen, &finallen) != 1) {
        err = "EVP_EncryptFinal_ex"; goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            BS_GCM_TAG_LEN, tag) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(GET_TAG)"; goto done;
    }
    *out_len = 1 + BS_GCM_NONCE_LEN + pt_len + BS_GCM_TAG_LEN;

done:
    EVP_CIPHER_CTX_free(ctx);
    /* LOW #3 — `key` now points at caller-owned memory (cfg-cached
     * derived key); the caller's pool cleanup will OPENSSL_cleanse
     * when the cfg is destroyed. Don't cleanse a borrowed buffer. */
    return err;
}

const char *bs_gcm_decrypt(const unsigned char aes_key[32],
                           const unsigned char *env,
                           apr_size_t env_len,
                           unsigned char *out_pt,
                           apr_size_t *out_pt_len)
{
    if (env_len < (apr_size_t)(1 + BS_GCM_NONCE_LEN + BS_GCM_TAG_LEN)) {
        return "envelope too short";
    }
    if (env[0] != BS_COOKIE_ALG_GCM) return "unknown alg_id";

    apr_size_t ct_len = env_len - 1 - BS_GCM_NONCE_LEN - BS_GCM_TAG_LEN;
    const unsigned char *nonce = env + 1;
    const unsigned char *ct    = env + 1 + BS_GCM_NONCE_LEN;
    const unsigned char *tag   = ct + ct_len;

    /* LOW #3 — caller passes the HKDF-derived AES key directly. */
    const unsigned char *key = aes_key;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "EVP_CIPHER_CTX_new";
    const char *err = NULL;
    int outlen = 0, finallen = 0, aadlen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        err = "EVP_DecryptInit_ex(aes_256_gcm)"; goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            BS_GCM_NONCE_LEN, NULL) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(SET_IVLEN)"; goto done;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        err = "EVP_DecryptInit_ex(key+nonce)"; goto done;
    }
    if (EVP_DecryptUpdate(ctx, NULL, &aadlen, env, 1) != 1) {
        err = "EVP_DecryptUpdate(AAD)"; goto done;
    }
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, out_pt, &outlen, ct, (int)ct_len) != 1) {
            err = "EVP_DecryptUpdate(ct)"; goto done;
        }
    }
    /* Set expected tag BEFORE Final — required by EVP's GCM contract. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            BS_GCM_TAG_LEN, (void *)tag) != 1) {
        err = "EVP_CIPHER_CTX_ctrl(SET_TAG)"; goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, out_pt + outlen, &finallen) != 1) {
        err = "gcm tag verification failed"; goto done;
    }
    *out_pt_len = (apr_size_t)(outlen + finallen);

done:
    EVP_CIPHER_CTX_free(ctx);
    /* LOW #3 — borrowed key, see encrypt path comment. */
    return err;
}

void bs_to_hex(const unsigned char *in, apr_size_t len, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (apr_size_t i = 0; i < len; i++) {
        out[i*2]   = H[(in[i] >> 4) & 0xF];
        out[i*2+1] = H[in[i] & 0xF];
    }
    out[len*2] = '\0';
}

int bs_from_hex(const char *in, apr_size_t in_len,
                apr_size_t out_len, unsigned char *out)
{
    if (in_len < out_len * 2) return 0;
    for (apr_size_t i = 0; i < out_len; i++) {
        int hi = -1, lo = -1;
        char c = in[i*2];
        if      (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        c = in[i*2+1];
        if      (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}
