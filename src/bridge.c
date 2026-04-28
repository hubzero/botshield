/* bridge.c — implementations behind bridge.h. E5 app→module
 * feedback (inbound output filter) + E8.2 module→app claims
 * (outbound request header). */

#include "bridge.h"

#include <ctype.h>
#include <string.h>
#include <sys/stat.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>
#include <apr_atomic.h>

#include <httpd.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include "botshield.h"
#include "crypto.h"
#include "shm.h"
#include "metrics.h"

/* ======================================================================
 * E5 — App-to-module reputation feedback.
 *
 * App emits `X-BotShield-Feedback: event=<name>[;kid=<id>];sig=<hex>` on
 * its response. Module reads, HMAC-verifies, parses, strips the header,
 * looks up `<name>` in scfg->feedback_triggers (see E7.3's
 * BotShieldFeedbackTrigger directive), and applies the configured
 * flag+ttl+log. The wire carries *event names*, not raw flag/ttl
 * policy — operators control the mapping from event → module memory
 * in their Apache config, so an app compromise can't poke arbitrary
 * flag bits.
 *
 * Flag bits can be penalty (honeypot_hit, scanner_probe, fake_bot,
 * pow_fail_streak) or credit (app_verified_human, app_verified_session,
 * app_trust_signal); same wire format, different bit semantics on the
 * config side of the event-name indirection.
 *
 * Implementation rules (see PLAN.md E5):
 *   1. Run as an output filter so stripping happens before the
 *      response reaches the client. log_transaction would be too late.
 *   2. Always strip when the header is present, even if the feature
 *      is off — a misconfigured app must not leak the header to clients.
 *   3. Duplicate headers → reject + strip all instances.
 *   4. Main request only (ap_is_initial_req).
 *   5. One-shot per request: the filter removes itself after processing.
 *
 * Wire-format change (E7.3): pre-E7.3 apps signed
 * `flag=<name>;ttl=<sec>;sig=<hex>` directly. The body now carries
 * `event=<name>;sig=<hex>` and the flag/ttl come from config. Apps
 * must migrate their signer; the old body shape is rejected at
 * HMAC-verify time (the `flag=` / `ttl=` tokens are no longer HMAC-
 * covered under the new wire format, so signatures won't match).
 * ====================================================================== */

ap_filter_rec_t *bs_app_feedback_filter_handle;

/* Count how many header entries match `name` (case-insensitive)
 * across both headers_out tables. apr_table_get only returns the
 * first; we need the count to catch duplicates up front, before
 * calling apr_table_unset (which removes all of them). Check both
 * r->headers_out AND r->err_headers_out — mod_headers' "Header
 * set" writes to the former; "Header always set" writes to the
 * latter (which Apache still merges into the on-wire response
 * regardless of status). If we only looked at one, a conditional
 * `Header set` from a 404 handler would miss the strip. */
static int bs_count_header_in_table(apr_table_t *t, const char *name)
{
    if (!t) return 0;
    const apr_array_header_t *arr = apr_table_elts(t);
    int count = 0;
    for (int i = 0; i < arr->nelts; i++) {
        apr_table_entry_t *e = &((apr_table_entry_t *)arr->elts)[i];
        if (e->key && strcasecmp(e->key, name) == 0) count++;
    }
    return count;
}
static int bs_count_header(request_rec *r, const char *name)
{
    return bs_count_header_in_table(r->headers_out, name)
         + bs_count_header_in_table(r->err_headers_out, name);
}

/* Parse + HMAC-verify a single X-BotShield-Feedback value under the
 * E7.3 wire format (`event=<name>[;...];sig=<hex>`). On success the
 * pool-allocated event name lands in *out_event and NULL is returned.
 * On failure returns an error string for logging and leaves
 * *out_event untouched. Caller looks up the event in
 * scfg->feedback_triggers to decide what the event means. */
static const char *bs_app_feedback_verify(apr_pool_t *p,
                                          const unsigned char *key,
                                          apr_size_t key_len,
                                          const char *value,
                                          const char **out_event)
{
    if (!key || key_len == 0) return "no secret configured";
    if (!value || !*value) return "empty header value";

    /* Find ";sig=" — everything before it is HMAC-covered. */
    const char *sig_marker = strstr(value, ";sig=");
    if (!sig_marker) return "missing sig= field";
    apr_size_t signed_len = (apr_size_t)(sig_marker - value);
    const char *sig_hex = sig_marker + 5;
    if (strlen(sig_hex) != 64) return "sig must be 64 hex chars";

    unsigned char expected[32];
    bs_hmac_sha256(key, key_len,
                   (const unsigned char *)value, signed_len,
                   expected);
    unsigned char given[32];
    if (!bs_from_hex(sig_hex, 64, 32, given)) return "sig not hex";
    if (!bs_ct_equal(expected, given, 32)) return "signature mismatch";

    /* Parse key=value pairs up to (but not including) ;sig=. The
     * only semantic key is event=; everything else (kid, tid, etc.)
     * is tolerated so apps can include their own correlation IDs
     * under the HMAC without churning this parser. */
    char *body = apr_pstrmemdup(p, value, signed_len);
    char *state = NULL;
    const char *event_name = NULL;
    for (char *tok = apr_strtok(body, ";", &state); tok;
         tok = apr_strtok(NULL, ";", &state)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = tok;
        const char *v = eq + 1;
        if (!strcasecmp(k, "event")) {
            event_name = v;
        }
        /* Pre-E7.3 bodies carried flag= / ttl= directly. Those
         * tokens would now be ignored here, but they were part of
         * the HMAC-covered bytes under the OLD key layout. Under
         * the new format the signer covers only event=<name>, so
         * an old body would fail HMAC verification above before
         * reaching this parse. No explicit "reject pre-E7.3"
         * branch is needed — the crypto catches it. */
    }

    if (!event_name || !*event_name) return "missing event= field";
    /* Event names follow the same constrained shape as trigger
     * names so operators can always reason about what a signed
     * body means. Enforced here so an injected ';' or '=' inside
     * the value can't confuse the upcoming lookup. */
    apr_size_t elen = strlen(event_name);
    if (elen == 0 || elen > 32) {
        return "event name must be 1..32 chars";
    }
    for (apr_size_t i = 0; i < elen; i++) {
        unsigned char c = (unsigned char)event_name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
              || c == '-';
        if (!ok) return "event name must be [a-z0-9-]";
    }

    *out_event = apr_pstrdup(p, event_name);
    return NULL;
}

/* Look up an event name in scfg->feedback_triggers. Returns the
 * matching entry or NULL. Declaration order, first match wins (no
 * accumulation — an event is a discrete app-originated signal). */
const bs_feedback_trigger_entry *bs_feedback_trigger_find(
    const struct bs_server_cfg *scfg, const char *event)
{
    if (!scfg || !scfg->feedback_triggers || !event) return NULL;
    for (int i = 0; i < scfg->feedback_triggers->nelts; i++) {
        bs_feedback_trigger_entry *e = APR_ARRAY_IDX(
            scfg->feedback_triggers, i, bs_feedback_trigger_entry *);
        if (strcmp(e->event, event) == 0) return e;
    }
    return NULL;
}

/* Output-filter callback. Runs once per initial request: reads
 * r->headers_out for the configured feedback header, strips every
 * occurrence, and (if the feature is enabled and exactly one copy
 * was found) validates the HMAC and updates the flagged-IP table. */
apr_status_t bs_app_feedback_filter(ap_filter_t *f,
                                           apr_bucket_brigade *bb)
{
    request_rec *r = f->r;

    /* One-shot: remove before processing to avoid re-entry on
     * subsequent brigade passes. */
    ap_remove_output_filter(f);

    if (!ap_is_initial_req(r)) {
        return ap_pass_brigade(f->next, bb);
    }

    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    if (!scfg) return ap_pass_brigade(f->next, bb);

    const char *hname = scfg->app_feedback_header
                      ? scfg->app_feedback_header
                      : BS_APP_FEEDBACK_DEFAULT_HEADER;

    int n = bs_count_header(r, hname);
    if (n == 0) return ap_pass_brigade(f->next, bb);

    /* Snapshot the first value BEFORE we strip — we still want to
     * verify and apply it if there's exactly one. Check both tables
     * since mod_headers' `Header set` and `Header always set` go
     * to different ones. */
    const char *first_val = apr_table_get(r->headers_out, hname);
    if (!first_val) first_val = apr_table_get(r->err_headers_out, hname);
    char *snapshot = first_val ? apr_pstrdup(r->pool, first_val) : NULL;

    /* Always strip — see PLAN.md E5 rule 2. Removes every copy at
     * once (from both tables) so duplicates don't leak even when
     * we reject them. */
    apr_table_unset(r->headers_out, hname);
    apr_table_unset(r->err_headers_out, hname);

    int enabled = (scfg->app_feedback_enabled == 1);
    if (!enabled) {
        return ap_pass_brigade(f->next, bb);
    }

    if (n > 1) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: app feedback rejected: %d copies of "
            "'%s' on response (expected exactly 1)", n, hname);
        return ap_pass_brigade(f->next, bb);
    }

    if (!scfg->app_integration_secret ||
        scfg->app_integration_secret_len == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: app feedback received but "
            "BotShieldAppIntegrationSecretFile not configured");
        return ap_pass_brigade(f->next, bb);
    }

    const char *event = NULL;
    const char *err = bs_app_feedback_verify(r->pool,
        scfg->app_integration_secret, scfg->app_integration_secret_len,
        snapshot, &event);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: app feedback rejected: %s", err);
        return ap_pass_brigade(f->next, bb);
    }

    /* Map event → action via BotShieldFeedbackTrigger. Unknown
     * events are a config-side miss, not an app-side attack — log
     * at info and skip. This is the indirection that keeps flag
     * names out of the wire format: a compromised app can emit any
     * event name, but only configured mappings have effect. */
    const bs_feedback_trigger_entry *ft =
        bs_feedback_trigger_find(scfg, event);
    if (!ft) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: app feedback event=%s unmapped "
            "(no BotShieldFeedbackTrigger entry); ignored", event);
        return ap_pass_brigade(f->next, bb);
    }

    unsigned char client_ip[16];
    if (bs_parse_client_ip(r->useragent_ip, client_ip)) {
        bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
        bs_flagged_ip_add(r, client_ip,
                          ft->action.flag_bit, ft->action.ttl_sec,
                          scfg->ns_id);
        if (ft->action.log_tag) {
            /* Feedback has no decision-log emission of its own, but
             * the tag belongs in r->notes so any subsequent access
             * log or custom format can pick it up via %{BS-...}n. */
            bs_set_trigger_tag(r, ft->action.log_tag);
        }
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: app feedback event=%s applied "
            "flag=0x%x ttl=%d", event,
            ft->action.flag_bit, ft->action.ttl_sec);
    }

    return ap_pass_brigade(f->next, bb);
}

/* Adds the one-shot filter to the chain for every request. Called
 * from ap_hook_insert_filter. Cheap — just appends to the filter
 * list; the real work is gated inside the filter on
 * ap_is_initial_req + the header being present. */
void bs_app_feedback_insert_filter(request_rec *r)
{
    if (!ap_is_initial_req(r)) return;
    ap_add_output_filter_handle(bs_app_feedback_filter_handle,
                                NULL, r, r->connection);
}

/* ======================================================================
 * E8.2 — Module-to-app reputation export.
 *
 * On the request path: strip any client-supplied X-Botshield-*, then
 * set a single signed X-Botshield-Claims header that the backend
 * handler reads to drive whatever app-side policy cares about
 * BotShield's verdict (request-by-request risk score, cookie state,
 * accumulated flag bitmap, etc.).
 *
 * Symmetric to E5 in shape:
 *   - signed envelope, key=value;...;sig=<hex>, HMAC-SHA-256
 *   - separate secret file (defense-in-depth vs. E5's inbound key)
 *   - unknown body keys tolerated (forward compat)
 *
 * Symmetric to E5 in trust posture: the strip-before-set is the
 * trust anchor for apps that don't bother to verify the HMAC. The
 * signed envelope is for apps that want value-integrity even across
 * an untrusted Apache→backend hop.
 * ====================================================================== */

/* Walk r->headers_in and unset every header whose name begins with
 * "X-Botshield-" (case-insensitive). apr_table_unset takes a key, so
 * we collect names first (snapshotting because table mutation during
 * iteration is undefined) then drop them all in a second pass. */
static void bs_app_claims_strip_incoming(request_rec *r)
{
    const apr_array_header_t *arr = apr_table_elts(r->headers_in);
    apr_array_header_t *to_unset =
        apr_array_make(r->pool, 4, sizeof(const char *));
    for (int i = 0; i < arr->nelts; i++) {
        apr_table_entry_t *e = &((apr_table_entry_t *)arr->elts)[i];
        if (e->key && strncasecmp(e->key, "X-Botshield-", 12) == 0) {
            *(const char **)apr_array_push(to_unset) = e->key;
        }
    }
    for (int i = 0; i < to_unset->nelts; i++) {
        apr_table_unset(r->headers_in,
                        APR_ARRAY_IDX(to_unset, i, const char *));
    }
}

/* Render the flag bitmap as a space-separated list of registry names
 * for the X-Botshield-Claims body. Empty string when no bits set —
 * apps see `flags=` (empty value) which the parser treats the same
 * as absent. */
static const char *bs_app_claims_flag_names(apr_pool_t *p,
                                            apr_uint32_t flags)
{
    if (!flags) return "";
    char *buf = apr_palloc(p, 256);
    apr_size_t off = 0;
    for (int i = 0; bs_flag_names[i].name; i++) {
        if (!(flags & bs_flag_names[i].bit)) continue;
        const char *n = bs_flag_names[i].name;
        apr_size_t nlen = strlen(n);
        if (off + nlen + 2 > 256) break;   /* defensive cap */
        if (off > 0) buf[off++] = ' ';
        memcpy(buf + off, n, nlen);
        off += nlen;
    }
    buf[off] = '\0';
    return buf;
}

/* Emit X-Botshield-Claims on the request to the backend. Called from
 * bs_handler's PASS leg — every value is finalized at that point.
 * Returns NULL on success or an error string the caller can log. */
const char *bs_app_claims_set(request_rec *r,
                                     bs_server_cfg *scfg,
                                     int score,
                                     bs_tier tier,
                                     const char *cookie_status,
                                     apr_uint32_t flags,
                                     int passes_silent,
                                     int passes_form,
                                     int passes_captcha)
{
    if (!scfg || scfg->app_claims_enabled != 1) return NULL;
    if (!scfg->app_integration_secret ||
        scfg->app_integration_secret_len == 0) {
        return "BotShieldAppIntegrationSecretFile not configured";
    }

    bs_app_claims_strip_incoming(r);

    apr_time_t now = apr_time_sec(apr_time_now());
    const char *flag_names = bs_app_claims_flag_names(r->pool, flags);
    const char *body = apr_psprintf(r->pool,
        "v=1;score=%d;tier=%s;cookie=%s;flags=%s;"
        "passes=s=%d,f=%d,c=%d;ts=%" APR_TIME_T_FMT,
        score, bs_tier_name(tier), cookie_status, flag_names,
        passes_silent, passes_form, passes_captcha, now);

    unsigned char mac[BS_SIG_BYTES];
    bs_hmac_sha256(scfg->app_integration_secret,
                   scfg->app_integration_secret_len,
                   (const unsigned char *)body, strlen(body), mac);
    char sig_hex[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(mac, BS_SIG_BYTES, sig_hex);

    const char *header_val = apr_psprintf(r->pool, "%s;sig=%s",
                                          body, sig_hex);
    apr_table_setn(r->headers_in, "X-Botshield-Claims", header_val);
    return NULL;
}

/* --- E5 + E8.2 directive setters --- */

/* E5 — BotShieldAppFeedback on|off. Master gate for the
 * app-to-module reputation-feedback channel. Default off. Even
 * under off we still strip the feedback header from outgoing
 * responses (see bs_app_feedback_fixup), so a misconfigured app
 * can't leak it to clients during a staged rollout. */
const char *bs_set_app_feedback(cmd_parms *cmd, void *dconf,
                                        int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_feedback_enabled = flag ? 1 : 0;
    return NULL;
}

/* E5 — BotShieldAppFeedbackHeader <name>. Header name the module
 * reads feedback from (and strips on its way out). Default
 * X-BotShield-Feedback. */
const char *bs_set_app_feedback_header(cmd_parms *cmd, void *dconf,
                                               const char *name)
{
    (void)dconf;
    if (!name || !*name) {
        return "BotShieldAppFeedbackHeader: header name required";
    }
    apr_size_t nlen = strlen(name);
    if (nlen > 64) {
        return "BotShieldAppFeedbackHeader: name over 64 chars";
    }
    for (apr_size_t i = 0; i < nlen; i++) {
        unsigned char c = (unsigned char)name[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok) {
            return apr_psprintf(cmd->pool,
                "BotShieldAppFeedbackHeader: '%s' contains invalid "
                "char '%c'", name, (char)c);
        }
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_feedback_header = apr_pstrdup(cmd->pool, name);
    return NULL;
}

/* E8.2 — BotShieldAppClaims on|off. Master gate for the module-to-
 * app reputation-export channel. Default off. When on, the module
 * sets a single signed X-Botshield-Claims header on the request to
 * the backend handler, having first stripped any client-supplied
 * X-Botshield-* (the strip is what makes the signed envelope safe
 * to trust on app reads — even if an app skips HMAC verification,
 * forged claim values can't survive the strip + set sequence). */
const char *bs_set_app_claims(cmd_parms *cmd, void *dconf, int flag)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_claims_enabled = flag ? 1 : 0;
    return NULL;
}

/* BotShieldAppIntegrationSecretFile <path>. HMAC key for both
 * directions of app integration: validates inbound feedback envelopes
 * and signs outbound X-Botshield-Claims headers. The two protocols'
 * canonical forms are structurally distinct (feedback HMACs
 * `event=<name>` only; claims HMAC seven semicolon-fields with a
 * fixed `v=1` lead) so cross-replay is not possible. Mode-600-or-
 * tighter + absolute path; loaded at parse time so the bytes are in
 * memory before the first request hits the hook. */
const char *bs_set_app_integration_secret_file(cmd_parms *cmd,
                                                       void *dconf,
                                                       const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldAppIntegrationSecretFile: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldAppIntegrationSecretFile: path must be absolute";
    }

    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppIntegrationSecretFile: cannot stat '%s'", arg);
    }
    if (st.st_mode & (S_IRGRP | S_IROTH | S_IWGRP | S_IWOTH)) {
        return apr_psprintf(cmd->pool,
            "BotShieldAppIntegrationSecretFile: '%s' is group- or "
            "world-accessible (mode %04o); chmod 600 it",
            arg, st.st_mode & 07777);
    }

    const char *buf = NULL;
    apr_size_t buf_len = 0;
    const char *err = bs_load_config_file(cmd,
        "BotShieldAppIntegrationSecretFile", arg,
        BS_MAX_SECRET_BYTES, &buf, &buf_len);
    if (err) return err;

    apr_size_t len = 0;
    err = bs_validate_secret_key(cmd, "BotShieldAppIntegrationSecretFile",
                                 arg, buf, buf_len, &len);
    if (err) return err;

    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->app_integration_secret_file = apr_pstrdup(cmd->pool, arg);
    scfg->app_integration_secret      = (const unsigned char *)buf;
    scfg->app_integration_secret_len  = len;
    return NULL;
}
