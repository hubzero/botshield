/* formcaptcha.c — E18 inline form-captcha tier.
 *
 * See formcaptcha.h for the operator-level model. This file owns:
 *   - bs_form_replay_filter   input-filter callback + handle
 *   - bs_form_captcha_read_body  body-buffering helper
 *   - bs_form_captcha_fixup   the ap_hook_fixups entry point
 *
 * The fixup hook is the meat: dispatches by Content-Type, reads
 * the body, extracts the provider's token field, calls the M8
 * siteverify client, validates hostname / action / v3 score, mints
 * _bs_verified, and installs the replay filter. */
#include <string.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_strings.h>
#include <apr_tables.h>

#include <json-c/json.h>

#include "botshield.h"
#include "captcha.h"     /* bs_form_get, bs_captcha_siteverify, bs_captcha_result */
#include "challenge.h"   /* bs_find_algorithm, bs_issue_challenge */
#include "cookie.h"      /* bs_install_verified_cookie */
#include "formcaptcha.h"

#define BS_FORM_CAPTCHA_BODY_MAX  (256 * 1024)   /* 256 KB body cap */

typedef struct {
    const char *body;
    apr_size_t  len;
    apr_size_t  offset;   /* bytes already emitted to downstream */
} bs_form_replay_ctx;

ap_filter_rec_t *bs_form_replay_filter_handle = NULL;

apr_status_t bs_form_replay_filter(ap_filter_t *f,
                                   apr_bucket_brigade *bb,
                                   ap_input_mode_t mode,
                                   apr_read_type_e block,
                                   apr_off_t readbytes)
{
    bs_form_replay_ctx *ctx = f->ctx;
    if (!ctx) {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    if (mode == AP_MODE_INIT) return APR_SUCCESS;

    /* E18 review fix — honor readbytes. Emitting the whole body in a
     * single bucket regardless of what the downstream handler asked
     * for is an API-conformance violation (a strictly-conformant
     * caller is allowed to discard excess past readbytes). Stream it
     * one chunk at a time, capped at readbytes when the caller is in
     * READBYTES mode. The body buffer is allocated in r->pool and
     * outlives any bucket the framework derives from it, so
     * apr_bucket_immortal_create is safe and avoids the deferred
     * pool-bucket copy on pool cleanup. */
    if (ctx->offset < ctx->len) {
        apr_size_t remain = ctx->len - ctx->offset;
        apr_size_t emit = remain;
        if (mode == AP_MODE_READBYTES && readbytes > 0 &&
            (apr_off_t)remain > readbytes) {
            emit = (apr_size_t)readbytes;
        } else if (mode == AP_MODE_GETLINE) {
            /* Honor line-mode reads. Some legacy CGI / custom
             * downstream handlers pull request bodies one line at
             * a time; emitting the whole remainder in one bucket
             * lets the caller discard everything past the first
             * newline (since they only consume one line). Emit up
             * to and including the first '\n' if present; if not,
             * fall through and emit the whole remainder (caller
             * keeps reading until EOS). */
            const char *start = ctx->body + ctx->offset;
            const void *nl = memchr(start, '\n', remain);
            if (nl) {
                emit = (apr_size_t)((const char *)nl - start) + 1;
            }
        }
        apr_bucket *b = apr_bucket_immortal_create(
            ctx->body + ctx->offset, emit, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        ctx->offset += emit;
        if (ctx->offset == ctx->len) {
            APR_BRIGADE_INSERT_TAIL(bb,
                apr_bucket_eos_create(f->c->bucket_alloc));
            ap_remove_input_filter(f);
        }
        return APR_SUCCESS;
    }

    /* Body fully drained but caller is reading again. Emit EOS and
     * self-remove. */
    APR_BRIGADE_INSERT_TAIL(bb,
        apr_bucket_eos_create(f->c->bucket_alloc));
    ap_remove_input_filter(f);
    return APR_SUCCESS;
}

/* Read the whole request body via the input filter chain into a
 * pool-allocated buffer. After this, the upstream filters are
 * drained — caller is expected to install bs_form_replay_filter to
 * satisfy downstream readers. Returns APR_SUCCESS + sets *out_body
 * + *out_len; APR_ENOSPC if body exceeds BS_FORM_CAPTCHA_BODY_MAX;
 * other apr_status_t on transport errors. */
static apr_status_t bs_form_captcha_read_body(request_rec *r,
                                              const char **out_body,
                                              apr_size_t *out_len)
{
    apr_bucket_brigade *bb = apr_brigade_create(r->pool,
        r->connection->bucket_alloc);
    /* E18 review fix — allocate one extra byte so a body of exactly
     * BS_FORM_CAPTCHA_BODY_MAX bytes (the read-loop guard is `>`,
     * not `>=`, so this size is accepted) can be NUL-terminated
     * without overwriting the last valid body byte. */
    char *buf = apr_palloc(r->pool, BS_FORM_CAPTCHA_BODY_MAX + 1);
    apr_size_t total = 0;
    int saw_eos = 0;
    apr_status_t rv = APR_SUCCESS;

    while (!saw_eos) {
        rv = ap_get_brigade(r->input_filters, bb,
                            AP_MODE_READBYTES, APR_BLOCK_READ,
                            HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            apr_brigade_destroy(bb);
            return rv;
        }
        apr_bucket *e;
        while ((e = APR_BRIGADE_FIRST(bb)) != APR_BRIGADE_SENTINEL(bb)) {
            if (APR_BUCKET_IS_EOS(e)) { saw_eos = 1; break; }
            const char *data;
            apr_size_t len;
            apr_status_t br = apr_bucket_read(e, &data, &len,
                                              APR_BLOCK_READ);
            if (br != APR_SUCCESS) {
                apr_brigade_destroy(bb);
                return br;
            }
            /* Security review MEDIUM — overflow-safe shape. The
             * naive `total + len > MAX` form can wrap on a maliciously
             * large `len` even though both operands are size_t, since
             * BS_FORM_CAPTCHA_BODY_MAX is well below SIZE_MAX. Rewrite
             * as `len > MAX - total` so the subtraction stays in range
             * and we never compute the overflowing sum at all. */
            if (len > BS_FORM_CAPTCHA_BODY_MAX - total) {
                apr_brigade_destroy(bb);
                return APR_ENOSPC;
            }
            memcpy(buf + total, data, len);
            total += len;
            apr_bucket_delete(e);
        }
        apr_brigade_cleanup(bb);
    }
    apr_brigade_destroy(bb);
    buf[total] = '\0';
    *out_body = buf;
    *out_len  = total;
    return APR_SUCCESS;
}

/* E18 fixup hook. Runs before content handlers. For POST to scopes
 * with BotShieldFormCaptcha on, validates the captcha and decides
 * whether to let the downstream handler see the request. */
int bs_form_captcha_fixup(request_rec *r)
{
    if (r->method_number != M_POST) return DECLINED;
    if (!ap_is_initial_req(r)) return DECLINED;

    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    if (!cfg || cfg->form_captcha != 1) return DECLINED;

    if (!cfg->captcha_provider || !cfg->captcha_provider->implemented ||
        !cfg->captcha_secret || !cfg->captcha_site_key) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: BotShieldFormCaptcha on but scope is "
            "missing BotShieldCaptchaProvider/SiteKey/SecretFile; "
            "rejecting POST as misconfigured");
        return HTTP_SERVICE_UNAVAILABLE;
    }

    /* Body content-type dispatch. Supports url-encoded and JSON.
     * multipart/form-data is deliberately out of scope — file
     * uploads need streaming-parser machinery this module isn't
     * the right home for. Anything else gets 415 with diagnostic
     * so operators notice the gap rather than silently allow
     * unverified submits. */
    /* Security review MEDIUM — Content-Type prefix match must check
     * the next byte is a recognized separator (`;` for parameters,
     * whitespace, or end-of-string). Without it,
     * `application/x-www-form-urlencoded-evil` and
     * `application/json-something` would match the prefix and slip
     * through with the wrong handler choice. */
    const char *ct = apr_table_get(r->headers_in, "Content-Type");
    #define BS_CT_TERMINATOR(c) ((c) == '\0' || (c) == ';' || \
                                  (c) == ' '  || (c) == '\t')
    int ct_form = (ct &&
        strncasecmp(ct, "application/x-www-form-urlencoded", 33) == 0 &&
        BS_CT_TERMINATOR(ct[33]));
    int ct_json = (ct &&
        strncasecmp(ct, "application/json", 16) == 0 &&
        BS_CT_TERMINATOR(ct[16]));
    #undef BS_CT_TERMINATOR
    if (!ct_form && !ct_json) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: BotShieldFormCaptcha supports "
            "application/x-www-form-urlencoded or application/json; "
            "got Content-Type=%s",
            ct ? ct : "(missing)");
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    /* Read the body. */
    const char *body = NULL;
    apr_size_t  body_len = 0;
    apr_status_t rv = bs_form_captcha_read_body(r, &body, &body_len);
    if (rv == APR_ENOSPC) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha body exceeds %d bytes",
            BS_FORM_CAPTCHA_BODY_MAX);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: form-captcha body read failed");
        return HTTP_BAD_REQUEST;
    }

    /* Security review HIGH #1 — NUL-byte parser-confusion smuggling.
     * Body is read as raw bytes (memcpy + length), but downstream
     * validators treat it as a C string: bs_form_get uses strchr,
     * json_tokener_parse_verbose stops at the first '\0'. The full
     * byte buffer (including post-NUL bytes) is then replayed to
     * the app handler via the replay filter. An attacker can hide
     * a separate request shape past a NUL — BotShield validates
     * the prefix, the app handler sees the full body. Reject any
     * body containing an embedded NUL with 400 before validation. */
    if (memchr(body, '\0', body_len) != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: form-captcha body contains embedded NUL "
            "byte (rejected to prevent parser-confusion smuggling)");
        return HTTP_BAD_REQUEST;
    }

    /* E12 — shadow / observe mode for E18. If global BotShieldShadowMode
     * is on, skip siteverify + cookie-mint, log a :observe reason, and
     * pass the request through. The body is still read (we already did
     * it — needed for the replay filter so the app handler sees its
     * original POST). Transport-level errors (415/413/400/503) above
     * this point intentionally still fire even under shadow mode —
     * those represent misconfiguration or genuinely-malformed requests,
     * not policy decisions an operator is staging. */
    {
        bs_server_cfg *scfg_sh = ap_get_module_config(
            r->server->module_config, &botshield_module);
        if (scfg_sh && scfg_sh->shadow_mode == 1) {
            bs_form_replay_ctx *ctx = apr_pcalloc(r->pool, sizeof(*ctx));
            ctx->body   = body;
            ctx->len    = body_len;
            ctx->offset = 0;
            ap_add_input_filter_handle(bs_form_replay_filter_handle,
                                       ctx, r, r->connection);
            /* The body has been consumed through ap_http_filter, which
             * silently de-chunks Transfer-Encoding: chunked into raw
             * bytes. r->headers_in still says "Transfer-Encoding:
             * chunked" though, so a downstream mod_proxy / mod_cgi
             * would try to re-chunk a body that no longer has
             * chunks — protocol error or dropped body. Strip the TE
             * header and set an explicit Content-Length so the
             * downstream sees a clean Content-Length-framed request. */
            apr_table_unset(r->headers_in, "Transfer-Encoding");
            apr_table_setn(r->headers_in, "Content-Length",
                apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, body_len));
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: form-captcha:observe (shadow mode; "
                "body replayed, no siteverify, no cookie mint)");
            return DECLINED;
        }
    }

    /* Extract the captcha-response field by provider-known name.
     * URL-encoded → bs_form_get (existing M8 helper).
     * JSON → json-c parse, look up the same key at top level. */
    const char *token = NULL;
    if (ct_form) {
        token = bs_form_get(r->pool, body,
                            cfg->captcha_provider->token_field);
    } else { /* ct_json */
        enum json_tokener_error jerr = json_tokener_success;
        json_object *root = json_tokener_parse_verbose(body, &jerr);
        if (!root || jerr != json_tokener_success) {
            if (root) json_object_put(root);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: form-captcha: JSON parse failed");
            return HTTP_BAD_REQUEST;
        }
        json_object *tok_v = NULL;
        if (json_object_object_get_ex(root,
                cfg->captcha_provider->token_field, &tok_v) &&
            tok_v && json_object_is_type(tok_v, json_type_string)) {
            const char *s = json_object_get_string(tok_v);
            if (s) token = apr_pstrdup(r->pool, s);
        }
        json_object_put(root);
    }
    if (!token || !*token) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha: missing token field '%s'",
            cfg->captcha_provider->token_field);
        return HTTP_FORBIDDEN;
    }

    /* siteverify via the existing M8 client. */
    int timeout_ms = cfg->captcha_timeout_ms > 0
        ? cfg->captcha_timeout_ms : BS_DEFAULT_CAPTCHA_TIMEOUT;
    const char *details = NULL;
    long http_code = 0;
    double score = -1.0;
    const char *resp_hostname = NULL, *resp_action = NULL;
    bs_captcha_result res = bs_captcha_siteverify(r,
        cfg->captcha_provider, cfg->captcha_secret,
        cfg->captcha_secret_len, token, timeout_ms,
        cfg->captcha_ca_bundle,
        &details, &http_code, &score, &resp_hostname, &resp_action);

    if (res != BS_CAPTCHA_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha siteverify rejected "
            "(http=%ld details=\"%s\")", http_code,
            details ? details : "");
        return HTTP_FORBIDDEN;
    }

    /* Hostname binding (security-review #1 parity with M8 path).
     * Action binding deliberately skipped here — the form's action
     * value is operator-defined and varies per form; enforcing a
     * single expected_action cross-form would be wrong. Operators
     * who want strict action checks can configure
     * BotShieldCaptchaExpectedAction explicitly. */
    const char *expected_host =
        cfg->captcha_expected_hostname
            ? cfg->captcha_expected_hostname
            : (r->server && r->server->server_hostname
                   ? r->server->server_hostname : "");
    if (resp_hostname && *expected_host &&
        strcmp(resp_hostname, expected_host) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha hostname-mismatch "
            "(got=%s expected=%s)", resp_hostname, expected_host);
        return HTTP_FORBIDDEN;
    }
    if (cfg->captcha_expected_action && *cfg->captcha_expected_action &&
        resp_action &&
        strcmp(resp_action, cfg->captcha_expected_action) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: form-captcha action-mismatch "
            "(got=%s expected=%s)",
            resp_action, cfg->captcha_expected_action);
        return HTTP_FORBIDDEN;
    }
    if (strcmp(cfg->captcha_provider->name, "recaptcha-v3") == 0) {
        double min_score = (cfg->recaptcha_v3_min_score >= 0.0)
            ? cfg->recaptcha_v3_min_score
            : BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE;
        if (score >= 0.0 && score < min_score) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: form-captcha v3 score below "
                "threshold (%.2f < %.2f)", score, min_score);
            return HTTP_FORBIDDEN;
        }
    }

    /* Mint _bs_verified — same captcha-<provider> alg the M8
     * interstitial path uses. passes_captcha=1 (this WAS a captcha-
     * tier solve, just inline rather than interstitial). */
    int ttl        = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);
    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);
    const char *cookie_alg_name = apr_psprintf(r->pool, "captcha-%s",
                                               cfg->captcha_provider->name);
    const bs_pow_algorithm *captcha_alg = bs_find_algorithm(cookie_alg_name);
    if (!captcha_alg || !captcha_alg->implemented) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: form-captcha cookie alg '%s' missing "
            "from registry", cookie_alg_name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* E15 review fix — carry forward prior cookie state if present,
     * mirroring M8's captcha-verify path. Without this, an existing
     * client whose cookie has forgive_consumed close to the cap
     * could "wash" their budget by submitting a form-captcha — the
     * fresh memset zeroed the rolling-window state and gave them a
     * full new budget. Eligibility and rep-math live in
     * bs_carry_forward_eligible / bs_apply_rep_carry. */
    bs_rep_state next_rep;
    memset(&next_rep, 0, sizeof(next_rep));
    {
        bs_challenge prior_ch = { 0 };
        if (bs_carry_forward_eligible(r, cfg, &prior_ch)) {
            next_rep = prior_ch.rep;
            bs_apply_rep_carry(r, cfg, &prior_ch, &next_rep,
                               bs_effective_int(cfg->forgive_captcha,
                                                BS_DEFAULT_FORGIVE_CAPTCHA));
        }
        next_rep.passes_captcha = 1;  /* LOW #7 clamp */
    }

    bs_challenge ch;
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          /* auto_tier */ 0,
                                          captcha_alg, &next_rep, &ch);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: form-captcha cookie issue failed: %s", ierr);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* Best-effort install: if the cookie mint fails (GCM encrypt
     * error — vanishingly unlikely with a valid key) we still let
     * the replay filter run. The user just won't get a cookie this
     * time and will re-challenge on the next request. The other
     * three issuance paths 500 on the same condition — preserved
     * here as-is to keep this refactor behavior-neutral. */
    (void)bs_install_verified_cookie(r, cfg, &ch, "captcha");

    /* Install the replay filter so the downstream handler sees the
     * original POST body. Filter buffers in r->pool memory; lifetime
     * is the request, plenty for any handler that wants it. */
    bs_form_replay_ctx *ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    ctx->body   = body;
    ctx->len    = body_len;
    ctx->offset = 0;
    ap_add_input_filter_handle(bs_form_replay_filter_handle,
                               ctx, r, r->connection);
    /* See shadow-mode branch above for the rationale: ap_http_filter
     * de-chunked the body for us, so r->headers_in's
     * Transfer-Encoding: chunked is now a lie. Strip it and set
     * Content-Length to body_len so downstream mod_proxy / mod_cgi
     * / PHP-FPM see a coherent framed request. */
    apr_table_unset(r->headers_in, "Transfer-Encoding");
    apr_table_setn(r->headers_in, "Content-Length",
        apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, body_len));

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
        "mod_botshield: form-captcha verified (provider=%s, "
        "body_len=%" APR_SIZE_T_FMT ")",
        cfg->captcha_provider->name, body_len);
    /* DECLINED so the app's regular handler runs. */
    return DECLINED;
}
