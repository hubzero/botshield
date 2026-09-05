/* challenge.c — challenge issuance, PoW algorithm registry, and the
 *  bootstrap-binding helpers shared by the M7 (interstitial)
 * and E17 (noninteractive tier) paths.
 *
 * Two abstractions live here:
 *
 *   bs_pow_algorithm registry — a static dispatch table mapping
 *     algorithm names ("sha256zeros", "captcha-turnstile", …) to
 *     issue/verify fn pointers. The verify fn is what runs at cookie-
 *     redemption time; the issue fn just fills salt+nonce on a fresh
 *     bs_challenge. Reserved-but-disabled rows (sha384-zeros, argon2id,
 *     …) keep the wire-format namespace stable for future algorithms.
 *
 *   bs_issue_challenge / bs_challenge_canonical / bs_challenge_json —
 *     the top-level "mint a fresh challenge" entry point, the canonical
 *     pipe-delimited form HMAC'd into the cookie, and the JSON
 *     serialization the M7 interstitial JS consumes.
 *
 * Plus the bootstrap-sig pair (bs_format_bound_ip_hex /
 * bs_compute_bootstrap_sig). They originally lived next to the
 * noninteractive tier verify handler, but they're computed at challenge-
 * issuance time too — so they belong with the rest of the challenge
 * minting code, not the verifier.
 *
 * No state of its own. All inputs come from the caller's bs_dir_cfg
 * (keys, algorithm pin) plus the request (client IP, pool). */
#include <string.h>

#include <openssl/rand.h>

#include <httpd.h>
#include <apr_strings.h>

#include "botshield.h"
#include "allowlist.h" /* bs_parse_client_ip, bs_mask_ipv6_prefix */
#include "challenge.h"
#include "cookie.h"
#include "crypto.h"

/* --- Canonical form for HMAC input ---
 *
 * "v|alg|salthex|noncehex|difficulty|expires_at
 *  |score|flags|pass_s|pass_f|pass_c|challenged_at|auto
 *  |forgive_window_start|forgive_consumed"                  (15 fields)
 *
 * Deterministic, ASCII, field-delimited. Both sign and verify produce this
 * exact string from the challenge struct — if a byte changes, the HMAC
 * changes, and tampering is detected. The rep fields follow the challenge
 * fields so existing M2 code reading positions 0..5 still lines up; the
 * M7 `auto` marker is appended at position 12 after challenged_at; the
 * E15 forgiveness-window pair is appended at 13..14. */
const char *bs_challenge_canonical(apr_pool_t *p,
                                   const bs_challenge *ch)
{
    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    bs_to_hex(ch->salt,  BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch->nonce, BS_NONCE_BYTES, nonce_hex);
    /* v2 canonical = v1 canonical + forgive_window_start +
     * forgive_consumed (E15). v3 appends burned_until for 16 fields;
     * v4 appends flags_active for 17. The HMAC cookie body adds 2 more
     * (sig_hex, counter), so 19 on the wire. Older bodies are still
     * accepted on the way in: v2 reads as unburned, v2/v3 as carrying
     * no session flags. */
    return apr_psprintf(p,
        "%d|%s|%s|%s|%d|%" APR_TIME_T_FMT
        "|%d|%u|%d|%d|%d|%" APR_TIME_T_FMT "|%d|%u|%u|%u|%u",
        ch->version, ch->alg_name, salt_hex, nonce_hex,
        ch->difficulty, ch->expires_at,
        ch->rep.score, (unsigned)ch->rep.flags_excused,
        ch->rep.passes_non_interactive, ch->rep.passes_interactive, ch->rep.passes_captcha,
        ch->rep.challenged_at,
        ch->auto_tier ? 1 : 0,
        (unsigned)ch->rep.forgive_window_start,
        (unsigned)ch->rep.forgive_consumed,
        (unsigned)ch->rep.burned_until,
        (unsigned)ch->rep.flags_active);
}

/* --- Algorithm: sha256zeros ---
 *
 * The PoW our M1 widget already uses, now wrapped in the registry.
 * issue: pick salt+nonce, record in the challenge. (HMAC signing is done
 *   by the top-level issuer, not the per-alg callback.)
 * verify: check that SHA-256(salt || nonce || counter) has `difficulty`
 *   leading hex zero digits. */
static const char *bs_sha256_zeros_issue(const bs_dir_cfg *cfg,
                                         bs_challenge *out)
{
    (void)cfg;
    if (RAND_bytes(out->salt,  BS_SALT_BYTES)  != 1) return "RAND_bytes(salt)";
    if (RAND_bytes(out->nonce, BS_NONCE_BYTES) != 1) return "RAND_bytes(nonce)";
    return NULL;
}

static const char *bs_sha256_zeros_verify(const bs_challenge *ch,
                                          const char *counter_str)
{
    if (!counter_str || !*counter_str) return "empty counter";

    /* Accumulate salt || nonce || counter into a stack buffer. Salt+nonce
     * is 24 bytes; counter is a decimal ASCII integer, capped well below
     * 32 bytes by the cookie-size limit. */
    unsigned char buf[BS_SALT_BYTES + BS_NONCE_BYTES + 64];
    apr_size_t n = 0;
    memcpy(buf + n, ch->salt,  BS_SALT_BYTES);  n += BS_SALT_BYTES;
    memcpy(buf + n, ch->nonce, BS_NONCE_BYTES); n += BS_NONCE_BYTES;
    apr_size_t cslen = strlen(counter_str);
    if (cslen > sizeof(buf) - n) return "counter too long";
    memcpy(buf + n, counter_str, cslen); n += cslen;

    unsigned char digest[BS_SHA256_LEN];
    bs_sha256(buf, n, digest);

    /* Leading `difficulty` hex zero digits = first `difficulty`/2 bytes are
     * 0x00, and if difficulty is odd the high nibble of the next byte is 0. */
    int full_bytes = ch->difficulty / 2;
    int need_half  = ch->difficulty & 1;
    for (int i = 0; i < full_bytes; i++) {
        if (digest[i] != 0) return "insufficient leading zeros";
    }
    if (need_half && (digest[full_bytes] >> 4) != 0) {
        return "insufficient leading zeros";
    }
    return NULL;
}

/* --- Algorithm: captcha passthrough (M8) ---
 *
 * Captcha-earned cookies use the same signed envelope as PoW-earned
 * cookies, but there's no client-side PoW counter to check — provider
 * siteverify already confirmed the solve before the cookie was issued,
 * and the HMAC on the envelope protects every field. The verify fn is
 * a noop: counter presence is required (to keep the 15-field cookie
 * shape), but its contents are ignored. */
static const char *bs_captcha_issue(const bs_dir_cfg *cfg,
                                    bs_challenge *out)
{
    (void)cfg;
    /* Random salt/nonce so two captcha cookies issued to the same user
     * at the same second don't collide in logs or caches. Difficulty
     * is unused but valid (kept at whatever the handler passed in). */
    if (RAND_bytes(out->salt,  BS_SALT_BYTES)  != 1) return "RAND_bytes(salt)";
    if (RAND_bytes(out->nonce, BS_NONCE_BYTES) != 1) return "RAND_bytes(nonce)";
    return NULL;
}

static const char *bs_captcha_verify_noop(const bs_challenge *ch,
                                          const char *counter_str)
{
    (void)ch;
    if (!counter_str || !*counter_str) return "empty counter";
    /* Anything non-empty passes — the captcha provider already did the
     * real work. */
    return NULL;
}

/* --- Algorithm: session passthrough -------------------------------
 *
 * Used by the always-mint path that issues a presence-only session
 * cookie when a request arrives without a valid one. The cookie's
 * envelope carries the same canonical fields as a solve-issued
 * cookie, but with passes_non_interactive=passes_interactive=passes_captcha=0 — no
 * trust is claimed, so there is no PoW solution to verify. The HMAC
 * (GCM tag) on the envelope authenticates every field against
 * tampering, which is the only integrity check that's meaningful for
 * a trust=0 cookie. The verify fn is a noop, mirroring the captcha
 * passthrough; the issue fn is a trivial salt/nonce randomizer. */
static const char *bs_session_issue(const bs_dir_cfg *cfg,
                                    bs_challenge *out)
{
    (void)cfg;
    if (RAND_bytes(out->salt,  BS_SALT_BYTES)  != 1) return "RAND_bytes(salt)";
    if (RAND_bytes(out->nonce, BS_NONCE_BYTES) != 1) return "RAND_bytes(nonce)";
    return NULL;
}

static const char *bs_session_verify_noop(const bs_challenge *ch,
                                          const char *counter_str)
{
    (void)ch;
    /* counter slot must be non-empty (wire shape requires the dot-
     * separated tail) but its contents are ignored. */
    if (!counter_str || !*counter_str) return "empty counter";
    return NULL;
}

/* --- Algorithm registry ---
 *
 * Static dispatch table. sha256zeros is the PoW tier; captcha-turnstile
 * is the captcha tier's cookie alg — same signed envelope, provider
 * already did the client-side work. Reserved slots flip from 0→1 by
 * providing the two callbacks; no changes to the protocol or verify
 * code path. */
static const bs_pow_algorithm bs_algorithms[] = {
    { "sha256zeros",          1, bs_sha256_zeros_issue, bs_sha256_zeros_verify },
    { "session",               1, bs_session_issue,      bs_session_verify_noop },
    { "captcha-turnstile",     1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-hcaptcha",      1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-recaptcha-v2",  1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-recaptcha-v3",  1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-friendly",      1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "captcha-geetest",       1, bs_captcha_issue,      bs_captcha_verify_noop },
    { "sha384-zeros",          0, NULL, NULL },
    { "sha512-zeros",          0, NULL, NULL },
    { "pbkdf2-sha256",         0, NULL, NULL },
    { "argon2id",              0, NULL, NULL },
    { NULL,                    0, NULL, NULL }
};

const bs_pow_algorithm *bs_find_algorithm(const char *name)
{
    for (int i = 0; bs_algorithms[i].name; i++) {
        if (strcmp(bs_algorithms[i].name, name) == 0) {
            return &bs_algorithms[i];
        }
    }
    return NULL;
}

/* --- JSON inline blob for the M7 interstitial ---
 *
 * Emits the small JSON object the M7 splash page consumes inline:
 * salt/nonce/difficulty/expires/auto + the encrypted cookie_prefix the
 * JS appends a counter to. For noninteractive tier embedded mode the
 *  IP-binding pair (bound_ip + bootstrap_sig) is included so
 * the round-trip /embedded-verify can match the issuing IP.
 *
 * Also carries the cookie_domain (if configured) so the JS can include
 * a Domain= attribute when needed.
 *
 * The rep block is omitted (that's the whole point of GCM: the client
 * shouldn't see score/flags/passes_*). The JSON carries an opaque
 * cookie_prefix base64 blob that the JS appends `.<counter>` to. */
const char *bs_challenge_json(request_rec *r, apr_pool_t *p,
                              const bs_dir_cfg *cfg,
                              const bs_challenge *ch)
{
    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    bs_to_hex(ch->salt,  BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch->nonce, BS_NONCE_BYTES, nonce_hex);
    const char *domain_json = cfg->cookie_domain
        ? apr_psprintf(p, ",\"cookie_domain\":\"%s\"", cfg->cookie_domain)
        : "";
    /* IP-binding round-trip. Compute bound_ip from
     * the request's client IP and bootstrap_sig over the
     * (nonce, bound_ip, expires_at) tuple under the per-purpose
     * derived bootstrap key. Both fields ride along in the JSON
     * for the JS to round-trip back to /embedded-verify. */
    char bound_ip_hex[33];
    char bootstrap_sig_hex[BS_SIG_BYTES * 2 + 1];
    /* Millisecond issue stamp, signed alongside the IP binding so the
     * verify side can measure issue -> solve without trusting the
     * client's clock. See BS_MIN_INTERACTIVE_SOLVE_MS. */
    apr_int64_t issued_ms = (apr_int64_t)(apr_time_now() / 1000);
    int have_bound_ip = bs_format_bound_ip_hex(
        r ? r->useragent_ip : NULL, bound_ip_hex);
    if (have_bound_ip) {
        bs_compute_bootstrap_sig(p, cfg->derived_hmac_bootstrap,
                                  nonce_hex, bound_ip_hex,
                                  ch->expires_at, issued_ms,
                                  bootstrap_sig_hex);
    }
    const char *bind_json = have_bound_ip
        ? apr_psprintf(p,
            ",\"bound_ip\":\"%s\",\"bootstrap_sig\":\"%s\","
            "\"issued_ms\":%" APR_INT64_T_FMT,
            bound_ip_hex, bootstrap_sig_hex, issued_ms)
        : "";
    const char *prefix_b64 = NULL;
    const char *err = bs_build_cookie_prefix_gcm(p, cfg, ch, &prefix_b64);
    if (err) return NULL;
    return apr_psprintf(p,
        "{\"salt\":\"%s\",\"nonce\":\"%s\",\"difficulty\":%d,"
        "\"expires_at\":%" APR_TIME_T_FMT ",\"auto\":%d,"
        "\"arm_ms\":%d,"
        "\"cookie_prefix\":\"%s\"%s%s}",
        salt_hex, nonce_hex, ch->difficulty, ch->expires_at,
        ch->auto_tier ? 1 : 0,
        ch->auto_tier ? 0
                      : bs_effective_int(cfg->interactive_arm_ms,
                                         BS_DEFAULT_INTERACTIVE_ARM_MS),
        prefix_b64, domain_json,
        bind_json);
}

/* --- Top-level issue / verify ---
 *
 * bs_issue_challenge fills the `ch` struct (salt, nonce, signature) from
 * config; the handler serializes to JSON for inline embedding. Stateless.
 *
 * bs_verify_cookie parses a base64-encoded cookie payload into a challenge
 * + counter, checks HMAC + expiry, dispatches the PoW check to the alg.
 * Returns NULL on accept, else a diagnostic string. */

/* Issue a fresh challenge. If `rep_in` is non-NULL its fields are copied
 * into the issued challenge verbatim — the handler has already applied
 * whatever forgiveness / increments are appropriate for the tier being
 * issued. If `rep_in` is NULL, rep starts at zero (first-ever challenge).
 * `auto_tier` controls the M7 noninteractive tier variant: 1 renders the interstitial
 * as an auto-submitting splash, 0 renders the interactive PoW checkbox.
 * `alg_override` lets callers issue cookies under a non-default algorithm
 * (M8 uses this for captcha-turnstile). NULL = use cfg->algorithm. */
const char *bs_issue_challenge(apr_pool_t *p, const bs_dir_cfg *cfg,
                               int difficulty, int cookie_ttl,
                               int auto_tier,
                               const bs_pow_algorithm *alg_override,
                               const bs_rep_state *rep_in,
                               bs_challenge *out)
{
    if (!cfg->secret) {
        return "BotShieldSecretFile must be set";
    }
    const bs_pow_algorithm *alg = alg_override ? alg_override : cfg->algorithm;
    if (!alg) {
        return "BotShieldAlgorithm must be set (or alg_override provided)";
    }
    apr_time_t now = apr_time_sec(apr_time_now());
    out->version     = BS_PROTOCOL_VERSION;
    out->alg_name    = alg->name;
    out->difficulty  = difficulty;
    out->expires_at  = now + cookie_ttl;
    out->auto_tier   = auto_tier ? 1 : 0;
    if (rep_in) {
        out->rep = *rep_in;
    } else {
        /* Whole-struct rather than field by field, for the same reason
         * the caller memsets: the list form is complete only until rep
         * gains a field, and nothing warns when it stops being so. */
        memset(&out->rep, 0, sizeof(out->rep));
    }
    /* The challenged_at stamp records "when this cookie earned its
     * current PoW proof" — set unconditionally since an issued challenge
     * always implies a fresh PoW solve on acceptance. */
    out->rep.challenged_at = now;

    const char *err = alg->issue(cfg, out);
    if (err) return err;

    /* GCM-only — the canonical bytes are authenticated by the GCM tag
     * inside the cookie envelope; ch.signature is unused on the wire. */
    return NULL;
}

/* ---  bootstrap-binding helpers ---
 *
 *  IP-binding for the bootstrap → verify
 * pathway. At bootstrap time we sign (nonce, bound_ip, expires_at)
 * with a per-purpose HKDF-derived key (`derived_hmac_bootstrap`).
 * At verify time we recompute the HMAC and also compare bound_ip
 * against the verifying request's IP. A challenge issued from one
 * IP cannot be redeemed from another — closes the distributed-
 * redemption attack where one IP solves the PoW and many others
 * redeem the result.
 *
 * bound_ip is rendered as a 32-char lowercase hex string of the
 * 16 raw bytes (IPv4 maps to ::ffff:V.V.V.V already in the parser).
 * Format-stable across IPv4 / IPv6.
 *
 * Output: 32-byte hex string + NUL into out_hex (33 bytes). */
int bs_format_bound_ip_hex(const char *useragent_ip, char out_hex[33])
{
    unsigned char ip_bytes[16];
    if (!useragent_ip || !*useragent_ip) return 0;
    if (!bs_parse_client_ip(useragent_ip, ip_bytes)) return 0;
    bs_to_hex(ip_bytes, 16, out_hex);
    return 1;
}

/* Compute the bootstrap-binding HMAC over
 *   "bs:bootstrap:v2:" || nonce_hex || ":" || bound_ip_hex || ":"
 *   || expires_at || ":" || issued_ms   (both decimal ASCII)
 * using the dir_cfg's derived bootstrap key. Output is hex-encoded
 * into out_sig_hex (65 bytes).
 *
 * v2 adds issued_ms so the verify side has a millisecond issue stamp
 * it can trust. Bumping the version invalidates only signatures for
 * challenges still in flight -- a bootstrap sig lives for one page
 * load, unlike the session cookie -- so the cost is that clients
 * mid-solve at the moment of a deploy solve once more. */
void bs_compute_bootstrap_sig(apr_pool_t *p,
                              const unsigned char key[32],
                              const char *nonce_hex,
                              const char *bound_ip_hex,
                              apr_time_t expires_at,
                              apr_int64_t issued_ms,
                              char out_sig_hex[BS_SIG_BYTES * 2 + 1])
{
    const char *canon = apr_psprintf(p,
        "bs:bootstrap:v2:%s:%s:%" APR_TIME_T_FMT ":%" APR_INT64_T_FMT,
        nonce_hex, bound_ip_hex, expires_at, issued_ms);
    unsigned char mac[BS_SIG_BYTES];
    bs_hmac_sha256(key, 32, (const unsigned char *)canon,
                   strlen(canon), mac);
    bs_to_hex(mac, BS_SIG_BYTES, out_sig_hex);
}

/* --- M7 algorithm directive setter --- */

const char *bs_set_algorithm(cmd_parms *cmd, void *cfg_v,
                                    const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    const bs_pow_algorithm *alg = bs_find_algorithm(arg);
    if (!alg) {
        return apr_psprintf(cmd->pool,
            "BotShieldAlgorithm: '%s' is not a recognized algorithm name",
            arg);
    }
    if (!alg->implemented) {
        return apr_psprintf(cmd->pool,
            "BotShieldAlgorithm: '%s' is reserved in the registry but not "
            "built into this module", arg);
    }
    cfg->algorithm = alg;
    return NULL;
}
