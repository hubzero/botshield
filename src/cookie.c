/* cookie.c — _bs_session GCM cookie envelope + Cookie-header parser.
 *
 * Two halves of cookie handling, both small and tightly coupled to
 * the GCM envelope format:
 *
 *   read   — bs_parse_cookies_once tokenizes the inbound Cookie
 *            header into a per-request memoized name→value map,
 *            and the two getters layer on top.
 *
 *   mint/  — bs_build_cookie_prefix_gcm AES-GCM-encrypts the
 *   verify   canonical pipe-delimited challenge form, base64-encodes
 *            alg_id||nonce||ct||tag, and the JS interstitial appends
 *            "."<counter> client-side. bs_build_cookie_payload does
 *            that join server-side for captcha cookies.
 *            bs_verify_cookie_gcm is the inverse: base64-decode,
 *            GCM-decrypt (primary then secondary key for E16
 *            rotation), parse canonical fields, dispatch to the
 *            alg's verify fn.
 *
 * No state of its own; everything reads from cfg or the per-request
 * pool. */
#include <string.h>
#include <limits.h>
#include <stdio.h>

#include <httpd.h>
#include <http_protocol.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_base64.h>

#include "botshield.h"
#include "allowlist.h" /* bs_parse_client_ip, bs_mask_ipv6_prefix */
#include "challenge.h"
#include "cookie.h"
#include "crypto.h"

/* --- Read side: Cookie-header parsing ------------------------- */

/* Parse-once tokenizer for the Cookie request header. Returns a
 * pool-allocated apr_table_t (name → value, case-insensitive on the
 * name per RFC 6265 in practice). Empty values are stored as ""
 * (matching `cookie=<name>` / `cookie=<name>=`). Duplicate names
 * take the first occurrence; subsequent ones are ignored. Cached on
 * r->notes as a hex-encoded pointer so the same map survives across
 * multiple cookietrigger evaluations within the same request. */
#define BS_COOKIEMAP_NOTE  "botshield-parsed-cookies"
apr_table_t *bs_parse_cookies_once(request_rec *r)
{
    const char *cached_hex = apr_table_get(r->notes, BS_COOKIEMAP_NOTE);
    if (cached_hex && *cached_hex) {
        apr_table_t *prev;
        if (sscanf(cached_hex, "%p", (void **)&prev) == 1 && prev) {
            return prev;
        }
    }

    apr_table_t *map = apr_table_make(r->pool, 8);
    const char *raw = apr_table_get(r->headers_in, "Cookie");
    if (raw && *raw) {
        char *buf = apr_pstrdup(r->pool, raw);
        char *state = NULL;
        for (char *tok = apr_strtok(buf, ";", &state); tok;
             tok = apr_strtok(NULL, ";", &state)) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (!*tok) continue;
            char *eq = strchr(tok, '=');
            const char *name;
            const char *value;
            if (eq) {
                *eq = '\0';
                name  = tok;
                value = eq + 1;
            } else {
                name  = tok;
                value = "";
            }
            /* Trim trailing whitespace from name (values are taken
             * as-is; cookie values are allowed to include leading
             * whitespace per RFC 6265 in practice, but we strip a
             * common one anyway). */
            apr_size_t nlen = strlen(name);
            while (nlen && (name[nlen-1] == ' ' || name[nlen-1] == '\t')) {
                ((char *)name)[--nlen] = '\0';
            }
            if (nlen == 0) continue;
            if (apr_table_get(map, name) != NULL) continue;  /* first wins */
            apr_table_setn(map, name, value);
        }
    }
    apr_table_setn(r->notes, BS_COOKIEMAP_NOTE,
                   apr_psprintf(r->pool, "%p", (void *)map));
    return map;
}

/* Find the value of a named cookie in the request's Cookie header.
 * Returns NULL if the cookie isn't present. The value isn't validated
 * here — callers decode and verify. Routes through the
 * bs_parse_cookies_once tokenizer (RFC 6265 separator handling, name-
 * boundary correctness) and benefits from its r->notes memoization
 * so per-request cost stays a single parse. */
const char *bs_get_cookie_value(request_rec *r, const char *name)
{
    apr_table_t *map = bs_parse_cookies_once(r);
    if (!map) return NULL;
    return apr_table_get(map, name);
}

/* Session-cookie lookup that prefers `__Host-bs_session` and falls
 * back to the unprefixed `_bs_session`.
 * Both can be valid in some operator setups: HTTPS-only deployment
 * always sees the prefixed variant; a Domain-configured (cross-
 * subdomain SSO) deployment can't use the __Host- prefix at all and
 * so only ever presents the unprefixed name. */
const char *bs_get_verified_cookie_value(request_rec *r)
{
    const char *v = bs_get_cookie_value(r, BS_COOKIE_NAME_HOST);
    if (v && *v) return v;
    return bs_get_cookie_value(r, BS_COOKIE_NAME);
}

/* --- Mint side: GCM envelope + Set-Cookie line --------------- */

/* GCM cookie prefix builder. Encrypts the canonical pipe-delimited
 * challenge form, base64-encodes
 *     alg_id(1) || nonce(12) || ciphertext || tag(16)
 * for the JS interstitial to append '.<counter>' to when the PoW
 * worker completes. Also used by the server-built captcha cookie
 * path, which appends '.captcha' on the module side. */
const char *bs_build_cookie_prefix_gcm(apr_pool_t *p,
                                       const bs_dir_cfg *cfg,
                                       const bs_challenge *ch,
                                       const char **out_b64)
{
    if (!cfg->derived_keys_set) return "no secret";
    const char *canon = bs_challenge_canonical(p, ch);
    apr_size_t pt_len = strlen(canon);
    apr_size_t env_cap = 1 + BS_GCM_NONCE_LEN + pt_len + BS_GCM_TAG_LEN;
    unsigned char *env = apr_palloc(p, env_cap);
    apr_size_t env_len = 0;
    /* derived GCM key, not raw secret. */
    const char *err = bs_gcm_encrypt(cfg->derived_gcm_cookie,
                                     (const unsigned char *)canon, pt_len,
                                     env, &env_len);
    if (err) return err;
    char *b64 = apr_palloc(p, apr_base64_encode_len((int)env_len) + 1);
    apr_base64_encode(b64, (const char *)env, (int)env_len);
    *out_b64 = b64;
    return NULL;
}

/* Build the base64-encoded cookie payload for a challenge + counter.
 * Wire form: base64(alg_id || nonce || ct || tag) + "." + counter.
 * The server builds this when issuing captcha cookies (counter =
 * "captcha"); the JS builds the same shape from the cookie_prefix
 * exposed in bs_challenge_json. */
const char *bs_build_cookie_payload(apr_pool_t *p,
                                    const bs_dir_cfg *cfg,
                                    const bs_challenge *ch,
                                    const char *counter_str)
{
    const char *prefix_b64 = NULL;
    const char *err = bs_build_cookie_prefix_gcm(p, cfg, ch, &prefix_b64);
    if (err) return NULL;
    return apr_psprintf(p, "%s%c%s", prefix_b64,
                        BS_GCM_COUNTER_SEP, counter_str);
}

/* Set-Cookie string for a server-issued bs_session cookie. The cookie
 * is a session cookie (no Expires/Max-Age) — the browser drops it on
 * session end, which matches the per-browsing-session semantic of the
 * always-mint design. The server-side TTL still exists in the
 * envelope's expires_at field, so a misbehaving browser that keeps
 * a session cookie past its server-side TTL still gets rejected at
 * verify. The expires_at parameter is now used only to set that
 * server-side bound; it does not appear on the wire. */
const char *bs_build_set_cookie(request_rec *r, const bs_dir_cfg *cfg,
                                const char *payload_b64,
                                apr_time_t expires_at)
{
    (void)expires_at;   /* server-side bound, not wire attribute */
    const char *secure = "";
    /* Apache exposes the scheme via ap_run_http_scheme or r->server's
     * SSL config; simplest portable check is ap_is_https if mod_ssl is
     * loaded, else fall through. mod_ssl registers ssl_is_https as an
     * optional function; here we take the belt-and-suspenders route and
     * check the r->parsed_uri / r->server / request scheme via
     * ap_http_scheme(r). */
    const char *scheme = ap_http_scheme(r);
    int is_https = (scheme && strcmp(scheme, "https") == 0);
    if (is_https) {
        secure = "; Secure";
    }
    const char *domain = "";
    int has_domain = (cfg->cookie_domain && *cfg->cookie_domain);
    if (has_domain) {
        domain = apr_psprintf(r->pool, "; Domain=%s", cfg->cookie_domain);
    }
    /* Emit __Host-bs_session when the
     * RFC 6265bis preconditions hold (HTTPS + no Domain). Browsers
     * reject the prefix when those invariants fail, so we only use
     * it where we can. Operators on plain HTTP or with a configured
     * cookie_domain (cross-subdomain SSO) get the unprefixed
     * name; the verify path checks both. */
    const char *name = (is_https && !has_domain)
        ? BS_COOKIE_NAME_HOST : BS_COOKIE_NAME;
    /* HttpOnly closes the XSS theft path. SameSite=Lax matches what
     * the historical M1 widget JS set via document.cookie before the
     * mint moved server-side, so cookies issued via either path are
     * indistinguishable on subsequent requests. */
    return apr_psprintf(r->pool,
        "%s=%s; Path=/%s%s; SameSite=Lax; HttpOnly",
        name, payload_b64, domain, secure);
}

/* Build a _bs_session cookie payload from ch and install the
 * resulting Set-Cookie header on the request's err_headers_out
 * (so it reaches the client even on non-2xx responses). Returns
 * NULL on success, an error-string diagnostic on failure (the only
 * realistic failure is GCM encrypt; callers map this to 500).
 *
 * counter_str is the payload's tail token: "captcha" for server-
 * issued captcha cookies, the decimal PoW counter for embedded
 * PoW-verify, etc. ch must already carry the rep state the caller
 * wants — call bs_apply_rep_carry first if doing carry-forward.
 *
 * The four issuance call sites (embedded-verify-powgcm, embedded-
 * verify-provider, M8 captcha-verify, form-captcha-replay) all
 * funnel through here. apr_table_add (not setn) is required so we
 * append rather than clobber any prior Set-Cookie rows that other
 * modules (mod_session etc.) may have added earlier in the chain. */
const char *bs_install_verified_cookie(request_rec *r,
                                       const bs_dir_cfg *cfg,
                                       const bs_challenge *ch,
                                       const char *counter_str)
{
    const char *payload = bs_build_cookie_payload(r->pool, cfg, ch,
                                                   counter_str);
    if (!payload) return "GCM cookie payload build failed";
    apr_table_add(r->err_headers_out, "Set-Cookie",
                  bs_build_set_cookie(r, cfg, payload, ch->expires_at));
    return NULL;
}

/* --- Verify side: parse + decrypt + dispatch ----------------- */

/* Parse the 15 pipe-delimited canonical-form fields (same shape
 * emitted by bs_challenge_canonical, after GCM-decrypt) into *ch.
 * Returns NULL on success or a diagnostic on parse failure. Caller
 * has already split the canonical string at '|' into fields[0..14].
 *
 * Field count grew from 13 to 15 with BS_PROTOCOL_VERSION 1->2 to
 * carry forgiveness-window state. The version check rejects v1
 * cookies before we read the new fields, so a malformed v1 won't
 * misalign reads. */
/* Strict surface-form check for the
 * cookie's canonical integer fields. The lenient bs_parse_int_bounded
 * (used elsewhere for directive parsing where operators write loose
 * input) accepts strtol's full grammar: leading whitespace, optional
 * `+` sign, leading zeros. That makes the canonical form malleable —
 * `5`, `+5`, ` 5`, `005` all parse to the same value, and the
 * verify path would HMAC the RECONSTRUCTED canonical and accept any
 * of those surface forms even though the server only ever emits `5`.
 *
 * Not exploitable today (HMAC is over the reconstructed bytes, and
 * all variants reconstruct identically). But canonical-form
 * unambiguity is cheap to enforce and removes a future-footgun
 * risk: any code that ever uses raw cookie bytes for replay-
 * tracking or fingerprinting would otherwise have a free surface-
 * form bypass.
 *
 * Strict canonical: ASCII digit string, optional leading `-` only
 * when allow_negative, no whitespace, no `+`, no leading zeros
 * (single `0` fine; `00` / `01` / `010` rejected). */
static int bs_strict_int_form(const char *s, int allow_negative)
{
    if (!s || !*s) return 0;
    if (*s == '-') {
        if (!allow_negative) return 0;
        s++;
        if (!*s) return 0;
    }
    /* Leading digit: must be a digit. */
    if (*s < '0' || *s > '9') return 0;
    /* Reject leading-zero ambiguity: "0" is fine, "00"/"01" not. */
    if (*s == '0' && s[1] != '\0') return 0;
    for (const char *p = s + 1; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
    }
    return 1;
}

static const char *bs_parse_canonical_fields(char *const fields[],
                                              bs_challenge *ch)
{
    long v;
    apr_int64_t v64;
    /* Strict surface-form gate. Score is the only signed
     * field; everything else is non-negative. */
    static const struct {
        int idx;
        int allow_neg;
    } strict_int_fields[] = {
        { 0,  0 },   /* version */
        { 4,  0 },   /* difficulty */
        { 5,  0 },   /* expires_at */
        { 6,  1 },   /* score (signed) */
        { 7,  0 },   /* flags */
        { 8,  0 },   /* passes_non_interactive */
        { 9,  0 },   /* passes_interactive */
        { 10, 0 },   /* passes_captcha */
        { 11, 0 },   /* challenged_at */
        { 12, 0 },   /* auto */
        { 13, 0 },   /* forgive_window_start */
        { 14, 0 },   /* forgive_consumed */
    };
    for (size_t i = 0;
         i < sizeof(strict_int_fields)/sizeof(strict_int_fields[0]);
         i++) {
        int fi = strict_int_fields[i].idx;
        if (!bs_strict_int_form(fields[fi],
                                 strict_int_fields[i].allow_neg)) {
            return "non-canonical integer surface form";
        }
    }
    if (!bs_parse_int_bounded(fields[0], 0, INT_MAX, 10, &v)) return "bad version";
    ch->version = (int)v;
    if (ch->version != BS_PROTOCOL_VERSION) return "bad protocol version";

    const bs_pow_algorithm *alg = bs_find_algorithm(fields[1]);
    if (!alg || !alg->implemented) return "unknown algorithm";
    ch->alg_name = alg->name;

    if (strlen(fields[2]) != BS_SALT_BYTES * 2 ||
        !bs_from_hex(fields[2], BS_SALT_BYTES * 2,
                     BS_SALT_BYTES, ch->salt)) return "bad salt";
    if (strlen(fields[3]) != BS_NONCE_BYTES * 2 ||
        !bs_from_hex(fields[3], BS_NONCE_BYTES * 2,
                     BS_NONCE_BYTES, ch->nonce)) return "bad nonce";
    if (!bs_parse_int_bounded(fields[4], 1, 16, 2, &v)) return "bad difficulty";
    ch->difficulty = (int)v;
    if (!bs_parse_int64_bounded(fields[5], 0, APR_INT64_MAX, &v64)) return "bad expires_at";
    ch->expires_at = (apr_time_t)v64;

    if (!bs_parse_int_bounded(fields[6], INT_MIN, INT_MAX, 11, &v)) return "bad score";
    ch->rep.score = (int)v;
    if (!bs_parse_uint32_bounded(fields[7], 10, &ch->rep.flags_excused))
        return "bad flags";
    if (!bs_parse_int_bounded(fields[8],  0, 1, 1, &v)) return "bad passes_non_interactive";
    ch->rep.passes_non_interactive  = (int)v;
    if (!bs_parse_int_bounded(fields[9],  0, 1, 1, &v)) return "bad passes_interactive";
    ch->rep.passes_interactive    = (int)v;
    if (!bs_parse_int_bounded(fields[10], 0, 1, 1, &v)) return "bad passes_captcha";
    ch->rep.passes_captcha = (int)v;
    if (!bs_parse_int64_bounded(fields[11], 0, APR_INT64_MAX, &v64)) return "bad challenged_at";
    ch->rep.challenged_at  = (apr_time_t)v64;
    if (!bs_parse_int_bounded(fields[12], 0, 1, 1, &v)) return "bad auto";
    ch->auto_tier = (int)v;
    if (!bs_parse_uint32_bounded(fields[13], 10, &ch->rep.forgive_window_start))
        return "bad forgive_window_start";
    if (!bs_parse_uint32_bounded(fields[14], 10, &ch->rep.forgive_consumed))
        return "bad forgive_consumed";
    return NULL;
}

/* Verify a GCM-format cookie. `dot` points at the '.' that
 * separates the base64 envelope from the counter portion. */
const char *bs_verify_cookie_gcm(request_rec *r,
                                 const bs_dir_cfg *cfg,
                                 const char *cookie_value,
                                 const char *dot,
                                 bs_challenge *out_ch)
{
    apr_size_t prefix_len = (apr_size_t)(dot - cookie_value);
    const char *counter = dot + 1;
    char *prefix_b64 = apr_pstrmemdup(r->pool, cookie_value, prefix_len);
    unsigned char *env = apr_palloc(r->pool,
                                    apr_base64_decode_len(prefix_b64));
    int env_len = apr_base64_decode((char *)env, prefix_b64);
    if (env_len < 1 + BS_GCM_NONCE_LEN + BS_GCM_TAG_LEN) {
        return "base64 decode failed";
    }

    apr_size_t pt_cap = (apr_size_t)env_len - 1 - BS_GCM_NONCE_LEN
                      - BS_GCM_TAG_LEN;
    unsigned char *pt = apr_palloc(r->pool, pt_cap + 1);
    apr_size_t pt_len = 0;
    /* E16 — try primary key first, then secondary if
     * configured. AES-GCM decrypt is authenticated; a wrong key
     * fails the tag check and bs_gcm_decrypt returns an error
     * without leaking plaintext. The retry is safe and the success
     * path is unchanged. */
    /* derived GCM keys, primary then secondary. */
    const char *derr = bs_gcm_decrypt(cfg->derived_gcm_cookie,
                                      env, (apr_size_t)env_len,
                                      pt, &pt_len);
    if (derr && cfg->derived_keys_set_2) {
        derr = bs_gcm_decrypt(cfg->derived_gcm_cookie_2,
                              env, (apr_size_t)env_len,
                              pt, &pt_len);
    }
    if (derr) {
        /* "signature mismatch" is the canonical reason string for any
         * authenticator failure (here: GCM tag); callers treat it as
         * "don't carry rep forward". */
        return "signature mismatch";
    }
    pt[pt_len] = '\0';

    /* pt is canonical form (15 pipe-delimited fields after E14 +
     * E15 — the count grew with BS_PROTOCOL_VERSION 1->2). */
    char *fields[15];
    int nf = 0;
    char *p = (char *)pt;
    fields[nf++] = p;
    while (*p && nf < 15) {
        if (*p == '|') { *p = '\0'; fields[nf++] = p + 1; }
        p++;
    }
    if (nf != 15) return "wrong field count";

    bs_challenge ch;
    memset(&ch, 0, sizeof(ch));
    const char *perr = bs_parse_canonical_fields(fields, &ch);
    if (perr) return perr;
    /* The GCM tag above already authenticated every canonical byte.
     * Expose ch so callers can carry rep state forward. */
    if (out_ch) *out_ch = ch;

    apr_time_t now = apr_time_sec(apr_time_now());
    if (now > ch.expires_at) return "expired";
    const bs_pow_algorithm *alg = bs_find_algorithm(fields[1]);
    return alg->verify(&ch, counter);
}

/* Verify a cookie. Writes to *out_ch once the GCM tag has
 * authenticated the envelope bytes; later semantic rejections
 * (expiry, bad counter) leave the struct populated for rep
 * carry-forward. On pre-auth error *out_ch stays untouched. */
const char *bs_verify_cookie(request_rec *r, const bs_dir_cfg *cfg,
                             const char *cookie_value,
                             bs_challenge *out_ch)
{
    if (!cfg->secret) return "no secret configured";
    apr_size_t val_len = strlen(cookie_value);
    if (val_len > BS_MAX_PAGE_BYTES) return "cookie absurdly long";

    /* Wire form is always base64(envelope) '.' counter. The '.' is
     * outside the standard base64 alphabet, so it's an unambiguous
     * split point. A cookie that's missing it is from the retired
     * HMAC format (or arbitrary garbage) — reject. */
    const char *dot = strrchr(cookie_value, BS_GCM_COUNTER_SEP);
    if (!dot) return "unsupported cookie format";
    return bs_verify_cookie_gcm(r, cfg, cookie_value, dot, out_ch);
}

/* --- Carry-forward: rep state across cookie generations --- */

/* Decide whether the rep block in *prior_ch can be carried into a
 * freshly-minted cookie, given the cverr that bs_verify_cookie just
 * returned.
 *
 * Reject when:
 *   - cverr == "signature mismatch"  (rep bytes can't be trusted —
 *     the GCM tag didn't authenticate, so the canonical fields might
 *     be attacker-chosen).
 *   - cverr == "expired"  (TTL is the only mechanism preventing
 *     indefinite reputation transfer across cookie generations. A
 *     leaked or stolen cookie that has aged past TTL must not be
 *     allowed to transplant good-standing rep into a fresh
 *     _bs_session via any solve path).
 *   - cverr is some other pre-auth failure (decode errors, wrong
 *     field count, "no secret configured", etc.) — bs_verify_cookie
 *     leaves *prior_ch unwritten in those branches, so
 *     prior_ch->alg_name is NULL and we reject.
 *
 * Accept when:
 *   - cverr == NULL  (cookie fully validated)
 *   - cverr names a post-tag-verification failure (PoW counter
 *     check, etc.) — bs_verify_cookie wrote authenticated rep into
 *     *prior_ch and prior_ch->alg_name is non-NULL.
 *
 * Single source of truth for the carry-forward rule. Both the
 * issuance-side helper (bs_carry_forward_eligible) and the render-
 * side predicate in bs_handler call through here so a change to the
 * rule only has to land in one place. */
int bs_should_carry_prior_rep(const char *cverr,
                              const bs_challenge *prior_ch)
{
    if (cverr == NULL) return 1;
    if (strcmp(cverr, "signature mismatch") == 0) return 0;
    if (strcmp(cverr, "expired") == 0) return 0;
    return prior_ch->alg_name ? 1 : 0;
}

/* Carry-forward eligibility predicate for issuance call sites. Reads
 * the request's __Host-bs_session cookie, verifies it, and applies
 * bs_should_carry_prior_rep to the result. Returns 1 with *out_prior_ch
 * populated when carry-forward is allowed; 0 (and leaves *out_prior_ch
 * untouched beyond what bs_verify_cookie wrote) when not.
 *
 * Used by bs_embedded_verify_pow_gcm, bs_embedded_verify_provider,
 * bs_captcha_verify_handler, and bs_form_captcha_replay. */
int bs_carry_forward_eligible(request_rec *r,
                                      const bs_dir_cfg *cfg,
                                      bs_challenge *out_prior_ch)
{
    const char *prior_val = bs_get_verified_cookie_value(r);
    if (!prior_val || !*prior_val) return 0;
    const char *cverr = bs_verify_cookie(r, cfg, prior_val, out_prior_ch);
    return bs_should_carry_prior_rep(cverr, out_prior_ch);
}

/* Apply the rep-carry-forward computation to *target.
 *
 * The caller has chosen forgive_amount based on the issuance tier
 * (cfg->forgive_non_interactive / forgive_captcha / etc.) — that knowledge
 * stays at the call site because forgive bands are per-tier policy.
 *
 * This helper does the deterministic math:
 *   - clamp the requested forgive against the per-cookie hourly cap
 *     (writes target->forgive_window_start + forgive_consumed)
 *   - compute new score = max(0, prior.score - forgive). No flag-
 *     derived floor: flag effects re-apply at request time via
 *     bs_apply_flag_triggers, so a forgiven-to-zero score on a
 *     flagged cookie is simply re-raised on the next request.
 *
 * The caller bumps the appropriate passes_X afterward (the
 * "ever passed" clamp). Tier knowledge for that decision also stays
 * at the call site. */
/* Record the client's currently-flagged bits as answered-for.
 *
 * Called at every point a challenge is successfully solved, because
 * solving does not clear a flag and flag scores re-apply on every
 * request: without this, any flag scoring at or above
 * BotShieldScoreNonInteractive is an unbreakable challenge loop. Seen in
 * production as pow_ok succeeding roughly once a second, each success
 * followed immediately by another challenge carrying cookie=solved.
 *
 * Only flags live at THIS moment are excused. Anything flagged later is
 * new evidence and still fires, so a solve settles the debt it was
 * challenged for without buying immunity. OR'd rather than assigned so
 * a client solving twice keeps what it already earned.
 *
 * Reads the IP table directly: the verify endpoints are routed before
 * the decision path runs, so there is no ip_flags in scope to pass in. */
void bs_rep_excuse_current_flags(request_rec *r, bs_rep_state *rep)
{
    if (!rep) return;
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg) return;
    unsigned char ip[16];
    apr_uint32_t  flags = 0;
    if (!bs_parse_client_ip(r->useragent_ip, ip)) return;
    bs_mask_ipv6_prefix(ip, scfg->ipv6_prefix_bits);
    bs_flagged_ip_lookup(ip, &flags, scfg->ns_id);
    rep->flags_excused |= flags;
}

void bs_apply_rep_carry(request_rec *r,
                                const bs_dir_cfg *cfg,
                                const bs_challenge *prior_ch,
                                bs_rep_state *target,
                                int forgive_amount)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    int cap = (scfg && scfg->forgive_cap_per_hour > 0)
            ? scfg->forgive_cap_per_hour
            : BS_DEFAULT_FORGIVE_CAP_PER_HOUR;
    apr_uint32_t now_sec = (apr_uint32_t)apr_time_sec(apr_time_now());
    int forgive = bs_forgiveness_apply_cap(forgive_amount, cap, now_sec,
                                           &target->forgive_window_start,
                                           &target->forgive_consumed);
    /* Carry-forward clamps only at zero — no flag-derived floor.
     * Flag effects are re-applied at request time by
     * bs_apply_flag_triggers, so a forgiven-to-zero score on a
     * flagged cookie is simply re-raised on the next request when
     * the trigger fires. */
    int new_score = prior_ch->rep.score - forgive;
    if (new_score < 0) new_score = 0;
    target->score = new_score;
}
