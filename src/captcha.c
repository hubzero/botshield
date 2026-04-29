/* captcha.c — implementations behind captcha.h. M8 captcha tier:
 * libcurl-backed siteverify shim, provider registry, M8.1
 * pending-cookie machinery, and the verify endpoint handler. */

#include "captcha.h"
#include "allowlist.h" /* bs_parse_client_ip */

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
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

#include <openssl/rand.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "botshield.h"
#include "challenge.h"
#include "cookie.h"
#include "crypto.h"
#include "shm.h"
#include "metrics.h"

static bs_captcha_result bs_geetest_siteverify(request_rec *r,
    const bs_captcha_provider *prov, const unsigned char *secret,
    apr_size_t secret_len, const char *token, int timeout_ms,
    const char *ca_bundle,
    const char **out_details, long *out_http_code, double *out_score,
    const char **out_hostname, const char **out_action);

static const bs_captcha_provider bs_providers[] = {
    { "turnstile",    1,
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      "cf-turnstile-response",
      "https://challenges.cloudflare.com/turnstile/v0/api.js",
      "cf-turnstile",
      NULL, NULL },
    { "hcaptcha",     1,
      "https://api.hcaptcha.com/siteverify",
      "h-captcha-response",
      "https://js.hcaptcha.com/1/api.js",
      "h-captcha",
      NULL, NULL },
    { "recaptcha-v2", 1,
      "https://www.google.com/recaptcha/api/siteverify",
      "g-recaptcha-response",
      "https://www.google.com/recaptcha/api.js",
      "g-recaptcha",
      NULL, NULL },
    { "recaptcha-v3", 1,
      "https://www.google.com/recaptcha/api/siteverify",
      "g-recaptcha-response",
      "https://www.google.com/recaptcha/api.js",
      "" /* no widget class — v3 uses grecaptcha.execute(), not a div */,
      NULL, NULL },
    { "friendly",     1,
      "https://api.friendlycaptcha.com/api/v1/siteverify",
      "frc-captcha-solution",
      "https://cdn.jsdelivr.net/npm/friendly-challenge/widget.min.js",
      "frc-captcha",
      "solution" /* Friendly Captcha's POST field name is `solution` */,
      NULL },
    { "geetest",      1,
      "https://gcaptcha4.geetest.com/validate",
      "geetest-token" /* the hidden form input carrying a JSON blob */,
      "https://static.geetest.com/v4/gt4.js",
      "" /* programmatic init via initGeetest4() */,
      NULL /* shared body shape not used — custom fn handles signing */,
      bs_geetest_siteverify },
    { NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL }
};

const bs_captcha_provider *bs_find_provider(const char *name)
{
    for (int i = 0; bs_providers[i].name; i++) {
        if (strcmp(bs_providers[i].name, name) == 0) {
            return &bs_providers[i];
        }
    }
    return NULL;
}
/* ======================================================================
 * Captcha tier (M8) — libcurl siteverify shim.
 *
 * Deliberately boring: one POST per verify, short timeouts, small
 * response buffer capped at BS_MAX_CAPTCHA_BODY, no JSON dependency
 * (the one field we need is "success", and we look for the explicit
 * `"success":false` / `"success":true` forms Cloudflare documents).
 *
 * Fail policy:
 *   - OK        → cookie issued, user redirected to return_to.
 *   - REJECTED  → 403 logged at INFO with a short body snippet.
 *   - TIMEOUT   → cookie issued anyway (fail-open), WARNING logged.
 *   - ERROR     → same as TIMEOUT for request flow; logged at WARNING.
 *     The alternative (fail-closed) locks users out during a Cloudflare
 *     blip, which the plan rejected as worse than occasional permissive
 *     behavior.
 * ====================================================================== */

/* bs_captcha_result is defined near the provider struct so the provider-
 * specific siteverify fn pointer can reference it. */

typedef struct {
    char      *buf;      /* r->pool-allocated */
    apr_size_t cap;
    apr_size_t len;
    int        truncated;
} bs_curl_buffer;

/* curl_easy_setopt return codes used to be
 * silently ignored. Wrapping every call with this macro accumulates
 * the first failure into setopt_rc, which the caller checks once
 * before curl_easy_perform. CURLE_OK is the common path; checking
 * the accumulator at the end avoids cluttering 16 lines per
 * siteverify with explicit if-blocks. Caller must declare
 * `CURLcode setopt_rc = CURLE_OK;` in scope. */
#define BS_SETOPT(h, opt, val) do { \
    CURLcode _bs_rc = curl_easy_setopt((h), (opt), (val)); \
    if (_bs_rc != CURLE_OK && setopt_rc == CURLE_OK) setopt_rc = _bs_rc; \
} while (0)

static size_t bs_curl_write_cb(char *ptr, size_t size, size_t nmemb,
                               void *userdata)
{
    bs_curl_buffer *b = userdata;
    /* Overflow-guard the size*nmemb multiply (
     * hardening point). libcurl's documented contract keeps `size`
     * at 1 in practice, and BS_MAX_CAPTCHA_BODY caps the target
     * buffer anyway, so a realistic overrun is vanishingly unlikely.
     * But the guard is two cheap comparisons and closes the class
     * entirely: an overflow would wrap `incoming` to a small value,
     * make our truncation accounting think we took the whole chunk
     * when we really dropped a mountain of bytes, and return a
     * mis-stated byte count to libcurl. Treat overflow as "drop
     * this chunk" same as the already-truncated branch.*/
    if (size > 0 && nmemb > SIZE_MAX / size) {
        b->truncated = 1;
        /* Return 0 to tell libcurl we consumed nothing — it will
         * abort the transfer with CURLE_WRITE_ERROR, which the
         * caller maps to BS_CAPTCHA_ERROR + fail-open. That's the
         * right behavior for an obviously-malformed provider
         * response: don't silently drop it. */
        return 0;
    }
    size_t incoming = size * nmemb;
    /* Abort the transfer once truncation
     * is detected, instead of draining the rest of the body
     * silently. A slow-trickle malicious provider was previously
     * able to hold an in-flight captcha slot for the full timeout
     * (BS_DEFAULT_CAPTCHA_MAX_INFLIGHT defaults to 64 — exhausting
     * the pool with 64 slow trickles starves real verifies).
     * Returning 0 yields CURLE_WRITE_ERROR; the caller maps that
     * to BS_CAPTCHA_ERROR (fail-open by policy on transport
     * failures, same path as a timeout). */
    if (b->truncated) return 0;
    size_t room = (b->len < b->cap) ? (b->cap - b->len) : 0;
    size_t take = (incoming < room) ? incoming : room;
    if (take > 0) {
        memcpy(b->buf + b->len, ptr, take);
        b->len += take;
    }
    if (take < incoming) {
        b->truncated = 1;
        return 0;   /* abort transfer */
    }
    return incoming;
}

/* libcurl global state is initialized once in bs_post_config (see the
 * comment there). No per-request init guard here — curl_global_init is
 * not thread-safe, and doing it lazily from the request path would
 * race under mpm_event. */

/*  CURLOPT_OPENSOCKETFUNCTION callback
 * that rejects connections to RFC1918 / loopback / link-local
 * addresses. Defense-in-depth:  already pinned protocol to
 * https, but if a provider's NS were ever compromised to return an
 * internal IP for the provider hostname (challenges.cloudflare.com,
 * etc.), libcurl would still happily connect to that address and
 * we'd POST our captcha-secret bytes to whoever's listening. This
 * callback inspects the resolved address right before socket()
 * and refuses the connection by returning CURL_SOCKET_BAD if the
 * target is in any of:
 *   IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
 *         127.0.0.0/8, 169.254.0.0/16, 0.0.0.0/8
 *   IPv6: ::1/128, fc00::/7 (ULA), fe80::/10 (link-local),
 *         IPv4-mapped equivalents of the above. */
static curl_socket_t bs_curl_open_socket_cb(void *clientp,
                                            curlsocktype purpose,
                                            struct curl_sockaddr *addr)
{
    (void)clientp; (void)purpose;
    int reject = 0;
    if (addr->family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&addr->addr;
        apr_uint32_t ip = ntohl(sin->sin_addr.s_addr);
        unsigned char o1 = (ip >> 24) & 0xFF;
        unsigned char o2 = (ip >> 16) & 0xFF;
        if (o1 == 10) reject = 1;                              /* 10/8 */
        else if (o1 == 172 && (o2 & 0xF0) == 16) reject = 1;   /* 172.16/12 */
        else if (o1 == 192 && o2 == 168) reject = 1;           /* 192.168/16 */
        else if (o1 == 127) reject = 1;                        /* loopback */
        else if (o1 == 169 && o2 == 254) reject = 1;           /* link-local */
        else if (o1 == 0) reject = 1;                          /* 0/8 */
    } else if (addr->family == AF_INET6) {
        const struct sockaddr_in6 *sin6 =
            (const struct sockaddr_in6 *)&addr->addr;
        const unsigned char *b = sin6->sin6_addr.s6_addr;
        /* ::1 loopback */
        if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
            b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
            b[8]==0 && b[9]==0 && b[10]==0 && b[11]==0 &&
            b[12]==0 && b[13]==0 && b[14]==0 && b[15]==1) reject = 1;
        /* fc00::/7 — ULA */
        else if ((b[0] & 0xFE) == 0xFC) reject = 1;
        /* fe80::/10 — link-local */
        else if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) reject = 1;
        /* ::ffff:0:0/96 — IPv4-mapped; recheck the embedded v4 */
        else if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
                 b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
                 b[8]==0 && b[9]==0 && b[10]==0xFF && b[11]==0xFF) {
            unsigned char o1 = b[12], o2 = b[13];
            if (o1 == 10) reject = 1;
            else if (o1 == 172 && (o2 & 0xF0) == 16) reject = 1;
            else if (o1 == 192 && o2 == 168) reject = 1;
            else if (o1 == 127) reject = 1;
            else if (o1 == 169 && o2 == 254) reject = 1;
            else if (o1 == 0) reject = 1;
        }
    }
    if (reject) return CURL_SOCKET_BAD;
    return socket(addr->family, addr->socktype, addr->protocol);
}

/* URL-encode via libcurl and copy into the request pool so the caller
 * can free the libcurl buffer right away. */
static const char *bs_curl_escape_pool(apr_pool_t *p, CURL *curl,
                                       const char *in, apr_size_t in_len)
{
    /* Curl_easy_escape takes int. Casting
     * size_t > INT_MAX wraps to a negative length and curl_easy_escape
     * misinterprets it. None of our callers exceed INT_MAX in
     * practice (secret bytes capped at 1024, tokens at ~600), but
     * rejecting explicitly is cheap and closes the class. */
    if (in_len > (apr_size_t)INT_MAX) return NULL;
    char *esc = curl_easy_escape(curl, in, (int)in_len);
    if (!esc) return NULL;
    const char *dup = apr_pstrdup(p, esc);
    curl_free(esc);
    return dup;
}

/* Append a header line to a curl_slist, handling the alloc-failure
 * edge correctly. libcurl's curl_slist_append returns NULL on
 * allocation failure and leaves the input list unchanged — naive
 * `list = curl_slist_append(list, s)` overwrites the variable with
 * NULL on failure and leaks the prior list. Returns 1 on success
 * with *list updated; 0 on failure with *list unchanged. */
static int bs_curl_slist_append(struct curl_slist **list, const char *s)
{
    struct curl_slist *next = curl_slist_append(*list, s);
    if (!next) return 0;
    *list = next;
    return 1;
}

/* Shared hardened-HTTPS-POST helper for siteverify.
 *
 * Both the Google-family path (`bs_captcha_siteverify`) and the
 * GeeTest path (`bs_geetest_siteverify`) need an identical
 * libcurl setup: TLS 1.2 floor, peer + host verify, no redirects,
 * HTTPS-only protocol allowlist, private-IP block via the
 * opensocket callback, response capped at BS_MAX_CAPTCHA_BODY,
 * Content-Type: x-www-form-urlencoded, Accept: application/json,
 * connect-timeout from cfg, total-timeout from caller. The two
 * functions used to maintain this 70-line block in lockstep; one
 * helper means future TLS/protocol/proxy hardening lands in
 * exactly one place.
 *
 * Caller supplies URL + URL-encoded body + a pre-allocated
 * response buffer (BS_MAX_CAPTCHA_BODY + 1 bytes for the NUL
 * terminator). Returns BS_CAPTCHA_OK with the response NUL-
 * terminated and *out_http_code populated; caller parses the
 * body. Returns BS_CAPTCHA_TIMEOUT / BS_CAPTCHA_ERROR for
 * transport failure; *out_details is set to a libcurl-string
 * description on error.
 *
 * `log_tag` is the short string woven into the curl_easy_setopt
 * failure log so an operator grep'ing the error log sees which
 * call site failed. */
static bs_captcha_result bs_captcha_https_post(
    request_rec *r,
    const char *url,
    const char *body,
    int total_timeout_ms,
    const char *ca_bundle,
    bs_curl_buffer *resp,
    long *out_http_code,
    const char **out_details,
    const char *log_tag)
{
    *out_http_code = 0;
    *out_details   = "";

    CURL *curl = curl_easy_init();
    if (!curl) return BS_CAPTCHA_ERROR;

    CURLcode setopt_rc = CURLE_OK;
    BS_SETOPT(curl, CURLOPT_URL, url);
    BS_SETOPT(curl, CURLOPT_POST, 1L);
    BS_SETOPT(curl, CURLOPT_POSTFIELDS, body);
    BS_SETOPT(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    {
        bs_dir_cfg *_dcfg = ap_get_module_config(r->per_dir_config,
                                                 &botshield_module);
        long _ct = (_dcfg && _dcfg->captcha_connect_timeout_ms > 0)
                   ? _dcfg->captcha_connect_timeout_ms
                   : BS_CAPTCHA_CONNECT_TIMEOUT;
        BS_SETOPT(curl, CURLOPT_CONNECTTIMEOUT_MS, _ct);
    }
    BS_SETOPT(curl, CURLOPT_TIMEOUT_MS, (long)total_timeout_ms);
    BS_SETOPT(curl, CURLOPT_NOSIGNAL, 1L);
    BS_SETOPT(curl, CURLOPT_NOPROGRESS, 1L);
    BS_SETOPT(curl, CURLOPT_USERAGENT, "mod_botshield/0.1");
    BS_SETOPT(curl, CURLOPT_WRITEFUNCTION, bs_curl_write_cb);
    BS_SETOPT(curl, CURLOPT_WRITEDATA, resp);
    BS_SETOPT(curl, CURLOPT_FOLLOWLOCATION, 0L);
    BS_SETOPT(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    BS_SETOPT(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    /* Pin TLS floor at 1.2. Modern libcurl already excludes
     * earlier versions by default; explicit-is-better-than-
     * implicit locks the policy across libcurl version drift. */
    BS_SETOPT(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (ca_bundle) {
        BS_SETOPT(curl, CURLOPT_CAINFO, ca_bundle);
    }
    /* Allowlist HTTPS only. Provider URLs are hard-coded today,
     * but a future operator-tunable URL would become an immediate
     * SSRF vector via file:// / gopher:// / etc. REDIR_PROTOCOLS
     * mirrors the policy in case FOLLOWLOCATION is ever flipped. */
    BS_SETOPT(curl, CURLOPT_PROTOCOLS_STR, "https");
    BS_SETOPT(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    /* Defense-in-depth against a compromised-DNS scenario: the
     * opensocket callback rejects RFC1918 / loopback / link-local
     * before connect(). */
    BS_SETOPT(curl, CURLOPT_OPENSOCKETFUNCTION, bs_curl_open_socket_cb);
    /* Server-declared response size cap. Streaming-trickle
     * providers without a declared length still terminate via
     * bs_curl_write_cb returning 0 on overflow. */
    BS_SETOPT(curl, CURLOPT_MAXFILESIZE, (long)BS_MAX_CAPTCHA_BODY);
    /* Pin Content-Type and Accept so a future provider
     * content-negotiation change can't quietly shift the wire
     * format. */
    struct curl_slist *bs_hdrs = NULL;
    if (!bs_curl_slist_append(&bs_hdrs,
            "Content-Type: application/x-www-form-urlencoded") ||
        !bs_curl_slist_append(&bs_hdrs,
            "Accept: application/json")) {
        curl_slist_free_all(bs_hdrs);
        curl_easy_cleanup(curl);
        return BS_CAPTCHA_ERROR;
    }
    BS_SETOPT(curl, CURLOPT_HTTPHEADER, bs_hdrs);
    if (setopt_rc != CURLE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: %s: curl_easy_setopt failed: %s "
            "(CURLcode=%d)",
            log_tag, curl_easy_strerror(setopt_rc),
            (int)setopt_rc);
        curl_slist_free_all(bs_hdrs);
        curl_easy_cleanup(curl);
        return BS_CAPTCHA_ERROR;
    }

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    curl_slist_free_all(bs_hdrs);
    *out_http_code = http_code;

    if (rc == CURLE_OPERATION_TIMEDOUT) return BS_CAPTCHA_TIMEOUT;
    if (rc != CURLE_OK) {
        *out_details = curl_easy_strerror(rc);
        return BS_CAPTCHA_ERROR;
    }
    if (http_code < 200 || http_code >= 300) {
        *out_details = apr_psprintf(r->pool, "http-status-%ld",
                                    http_code);
        return BS_CAPTCHA_ERROR;
    }
    /* NUL-terminate. The buffer was allocated with one extra
     * byte for exactly this. */
    resp->buf[resp->len] = '\0';
    return BS_CAPTCHA_OK;
}

/* Parse the siteverify response body with json-c. Returns:
 *   BS_CAPTCHA_OK        — explicit "success":true
 *   BS_CAPTCHA_REJECTED  — explicit "success":false; *out_details is set
 *                          to a comma-joined "error-codes" list, or the
 *                          empty string if the provider didn't send any.
 *   BS_CAPTCHA_ERROR     — malformed JSON, wrong shape, or "success" of
 *                          a non-boolean type. *out_details is a snippet
 *                          of the raw body for the log.
 * The Google-family providers (Turnstile, hCaptcha, reCAPTCHA v2/v3,
 * Friendly Captcha) all use the same {"success":bool,...} contract,
 * so one parser covers all of them. Friendly Captcha v1 writes its
 * error list under the key "errors" instead of "error-codes"; both
 * keys are accepted, preferring "error-codes" when present. GeeTest
 * uses a different response shape entirely and bypasses this parser
 * via its own siteverify_fn on the provider row.
 *
 * `out_score` is optional; when non-NULL it receives the numeric
 * "score" field if present (reCAPTCHA v3), or -1.0 if the response
 * didn't carry a score (other Google-family providers). The
 * handler uses it to apply BotShieldRecaptchaV3MinScore *after* the
 * success:true check — v3 threshold failures look the same as any
 * other REJECTED outcome to downstream code. */
static bs_captcha_result bs_captcha_parse_response(apr_pool_t *p,
                                                   const char *body,
                                                   apr_size_t body_len,
                                                   const char **out_details,
                                                   double *out_score,
                                                   const char **out_hostname,
                                                   const char **out_action)
{
    *out_details = "";
    if (out_score) *out_score = -1.0;
    if (out_hostname) *out_hostname = NULL;
    if (out_action)   *out_action   = NULL;
    if (!body || body_len == 0) return BS_CAPTCHA_ERROR;

    enum json_tokener_error jerr = json_tokener_success;
    json_object *root = json_tokener_parse_verbose(body, &jerr);
    if (!root || jerr != json_tokener_success) {
        if (root) json_object_put(root);
        /* 120-char snippet of whatever came back for the log. */
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(p, body, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
        return BS_CAPTCHA_ERROR;
    }

    /* Shape must be an object with a boolean `success` field. Anything
     * else (missing field, wrong type) is a protocol surprise. */
    bs_captcha_result out = BS_CAPTCHA_ERROR;
    if (json_object_is_type(root, json_type_object)) {
        json_object *succ = NULL;
        if (json_object_object_get_ex(root, "success", &succ) &&
            succ && json_object_is_type(succ, json_type_boolean)) {
            if (json_object_get_boolean(succ)) {
                out = BS_CAPTCHA_OK;
                /* v3 carries a numeric score field. Extract if present;
                 * providers that don't carry it leave out_score at -1.0. */
                json_object *sc = NULL;
                if (out_score &&
                    json_object_object_get_ex(root, "score", &sc) &&
                    sc && (json_object_is_type(sc, json_type_double) ||
                           json_object_is_type(sc, json_type_int))) {
                    *out_score = json_object_get_double(sc);
                }
                /* Binding metadata. Turnstile +
                 * hCaptcha + reCAPTCHA v2 + v3 all return `hostname`.
                 * reCAPTCHA v3 + Turnstile also return `action`. Copy
                 * into the caller's pool so the original json_object
                 * can be freed without dangling the strings. */
                json_object *hn = NULL;
                if (out_hostname &&
                    json_object_object_get_ex(root, "hostname", &hn) &&
                    hn && json_object_is_type(hn, json_type_string)) {
                    const char *s = json_object_get_string(hn);
                    if (s) *out_hostname = apr_pstrdup(p, s);
                }
                json_object *act = NULL;
                if (out_action &&
                    json_object_object_get_ex(root, "action", &act) &&
                    act && json_object_is_type(act, json_type_string)) {
                    const char *s = json_object_get_string(act);
                    if (s) *out_action = apr_pstrdup(p, s);
                }
            } else {
                out = BS_CAPTCHA_REJECTED;
                /* Join the error-codes array into a compact string for
                 * the log. Most providers use "error-codes"; Friendly
                 * Captcha v1 uses "errors". Check both, preferring the
                 * standard name when both are present. */
                json_object *ec = NULL;
                if (!json_object_object_get_ex(root, "error-codes", &ec)) {
                    json_object_object_get_ex(root, "errors", &ec);
                }
                if (ec && json_object_is_type(ec, json_type_array)) {
                    /* apr_pstrcat in a loop is O(N²) — each call
                     * allocates a fresh buffer sized to the
                     * cumulative length and copies the prior result
                     * forward. Push into an array and join in one
                     * allocation via apr_array_pstrcat (O(N)). The
                     * 8 KB body cap (BS_MAX_CAPTCHA_BODY) bounds N,
                     * but a misconfigured-secret response returning
                     * many "invalid-input-*" error codes hits this
                     * path on every request — worth the tidier
                     * shape. */
                    int n = (int)json_object_array_length(ec);
                    apr_array_header_t *arr = apr_array_make(p,
                        n > 0 ? n : 1, sizeof(const char *));
                    for (int i = 0; i < n; i++) {
                        json_object *e = json_object_array_get_idx(ec, i);
                        if (!e) continue;
                        const char *s = json_object_get_string(e);
                        if (!s) continue;
                        /* Borrowed pointer into root — root is
                         * json_object_put'd at the end of this
                         * function, AFTER apr_array_pstrcat copies
                         * the strings into its joined output. Safe. */
                        *(const char **)apr_array_push(arr) = s;
                    }
                    *out_details = apr_array_pstrcat(p, arr, ',');
                }
            }
        }
    }

    if (out == BS_CAPTCHA_ERROR) {
        /* Couldn't find or interpret "success". Log a snippet. */
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(p, body, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
    }

    json_object_put(root);
    return out;
}

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
                                               const char **out_action)
{
    *out_details  = "";
    *out_http_code = 0;
    if (out_score) *out_score = -1.0;
    if (out_hostname) *out_hostname = NULL;
    if (out_action)   *out_action   = NULL;

    CURL *curl = curl_easy_init();
    if (!curl) return BS_CAPTCHA_ERROR;

    /* Build URL-encoded body: secret=...&response=...&remoteip=... */
    const char *esc_secret = bs_curl_escape_pool(r->pool, curl,
        (const char *)secret, secret_len);
    const char *esc_token  = bs_curl_escape_pool(r->pool, curl,
        token, strlen(token));
    const char *esc_ip     = bs_curl_escape_pool(r->pool, curl,
        r->useragent_ip ? r->useragent_ip : "",
        r->useragent_ip ? strlen(r->useragent_ip) : 0);
    if (!esc_secret || !esc_token || !esc_ip) {
        curl_easy_cleanup(curl);
        return BS_CAPTCHA_ERROR;
    }
    const char *field = prov->siteverify_field ? prov->siteverify_field
                                               : "response";
    const char *body = apr_psprintf(r->pool,
        "secret=%s&%s=%s&remoteip=%s",
        esc_secret, field, esc_token, esc_ip);

    /* allocate one extra byte so a
     * full-cap response (resp.len == BS_MAX_CAPTCHA_BODY, which
     * the write callback caps at via the room calculation) can
     * receive its NUL terminator at resp.buf[resp.len] without
     * overwriting the last valid byte. Symmetric with the
     * BS_FORM_CAPTCHA_BODY_MAX+1 fix applied to the form-captcha
     * body buffer. */
    bs_curl_buffer resp = {
        .buf = apr_palloc(r->pool, BS_MAX_CAPTCHA_BODY + 1),
        .cap = BS_MAX_CAPTCHA_BODY,
        .len = 0, .truncated = 0,
    };

    bs_captcha_result xport = bs_captcha_https_post(
        r, prov->siteverify_url, body, timeout_ms, ca_bundle,
        &resp, out_http_code, out_details, "captcha siteverify");
    /* curl_escape outputs are still owned by the curl handle that
     * bs_captcha_https_post just freed via curl_easy_cleanup. apr
     * already copied the strings into r->pool via bs_curl_escape_pool,
     * so the body string remains valid through perform and after. */
    if (xport != BS_CAPTCHA_OK) return xport;

    return bs_captcha_parse_response(r->pool, resp.buf, resp.len,
                                     out_details, out_score,
                                     out_hostname, out_action);
}

/* ----------------------------------------------------------------------
 * GeeTest v4 siteverify. Not the "Google family" shape:
 *
 *   client → server:  JSON blob of {lot_number, pass_token, gen_time,
 *                                   captcha_output} submitted as the
 *                                   `geetest-token` form field.
 *
 *   server → GeeTest: POST {siteverify_url}?captcha_id=<sitekey>
 *                     Content-Type: application/x-www-form-urlencoded
 *                     body: lot_number=...&captcha_output=...
 *                           &pass_token=...&gen_time=...&sign_token=...
 *                     where sign_token = HMAC-SHA256(captcha_key=secret,
 *                                                    lot_number) as hex.
 *
 *   GeeTest → server: {"result":"success"|"fail","reason":"...",...}
 *                     — "result" is a string, not a bool; "reason" is
 *                     the human-readable explanation.
 *
 * We map GeeTest's "success" / "fail" onto BS_CAPTCHA_OK /
 * BS_CAPTCHA_REJECTED the same way the shared path maps the boolean
 * from Google-family providers. Everything else (libcurl buffer,
 * timeouts, write callback, fail-open policy) is shared via the same
 * helpers the default shim uses. */
static apr_status_t bs_geetest_parse_client_token(apr_pool_t *p,
                                                  const char *token,
                                                  const char **out_lot_number,
                                                  const char **out_captcha_output,
                                                  const char **out_pass_token,
                                                  const char **out_gen_time,
                                                  const char **out_err)
{
    *out_lot_number    = NULL;
    *out_captcha_output = NULL;
    *out_pass_token    = NULL;
    *out_gen_time      = NULL;
    *out_err           = NULL;

    if (!token || !*token) {
        *out_err = "empty token";
        return APR_EINVAL;
    }
    json_object *root = json_tokener_parse(token);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root) json_object_put(root);
        *out_err = "token not a JSON object";
        return APR_EINVAL;
    }

    struct { const char *key; const char **out; } fields[] = {
        { "lot_number",     out_lot_number     },
        { "captcha_output", out_captcha_output },
        { "pass_token",     out_pass_token     },
        { "gen_time",       out_gen_time       },
        { NULL, NULL }
    };

    for (int i = 0; fields[i].key; i++) {
        json_object *v = NULL;
        if (!json_object_object_get_ex(root, fields[i].key, &v) || !v) {
            *out_err = apr_psprintf(p, "missing field '%s'", fields[i].key);
            json_object_put(root);
            return APR_EINVAL;
        }
        const char *s = json_object_get_string(v);
        if (!s) {
            *out_err = apr_psprintf(p, "non-string field '%s'", fields[i].key);
            json_object_put(root);
            return APR_EINVAL;
        }
        *fields[i].out = apr_pstrdup(p, s);
    }
    json_object_put(root);
    return APR_SUCCESS;
}

static bs_captcha_result bs_geetest_siteverify(request_rec *r,
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
                                               const char **out_action)
{
    *out_details   = "";
    *out_http_code = 0;
    if (out_score) *out_score = -1.0;
    /* GeeTest's binding is HMAC-signed over the request side (sign_token
     * covers lot_number), not a string echoed back in the response.
     * Leave the binding out-params NULL — the handler's shared check
     * will see NULL and skip hostname/action comparison for this
     * provider (intended behavior). */
    if (out_hostname) *out_hostname = NULL;
    if (out_action)   *out_action   = NULL;

    /* Need the sitekey (captcha_id) from per-dir cfg. Walk up from r. */
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    if (!cfg || !cfg->captcha_site_key) {
        *out_details = "captcha_id missing from scope";
        return BS_CAPTCHA_ERROR;
    }

    const char *lot_number, *captcha_output, *pass_token, *gen_time;
    const char *perr = NULL;
    if (bs_geetest_parse_client_token(r->pool, token,
            &lot_number, &captcha_output, &pass_token, &gen_time,
            &perr) != APR_SUCCESS) {
        *out_details = perr ? perr : "bad token";
        return BS_CAPTCHA_REJECTED;
    }

    /* sign_token = HMAC-SHA256(captcha_key=secret, lot_number) hex. */
    unsigned char sig[BS_SIG_BYTES];
    bs_hmac_sha256(secret, secret_len,
                   (const unsigned char *)lot_number, strlen(lot_number),
                   sig);
    char sign_token[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(sig, BS_SIG_BYTES, sign_token);

    CURL *curl = curl_easy_init();
    if (!curl) return BS_CAPTCHA_ERROR;

    const char *e_lot    = bs_curl_escape_pool(r->pool, curl, lot_number,     strlen(lot_number));
    const char *e_output = bs_curl_escape_pool(r->pool, curl, captcha_output, strlen(captcha_output));
    const char *e_pass   = bs_curl_escape_pool(r->pool, curl, pass_token,     strlen(pass_token));
    const char *e_time   = bs_curl_escape_pool(r->pool, curl, gen_time,       strlen(gen_time));
    const char *e_id     = bs_curl_escape_pool(r->pool, curl, cfg->captcha_site_key,
                                               strlen(cfg->captcha_site_key));
    if (!e_lot || !e_output || !e_pass || !e_time || !e_id) {
        curl_easy_cleanup(curl);
        return BS_CAPTCHA_ERROR;
    }
    const char *url = apr_psprintf(r->pool,
        "%s?captcha_id=%s", prov->siteverify_url, e_id);
    const char *body = apr_psprintf(r->pool,
        "lot_number=%s&captcha_output=%s&pass_token=%s"
        "&gen_time=%s&sign_token=%s",
        e_lot, e_output, e_pass, e_time, sign_token);

    bs_curl_buffer resp = {
        .buf = apr_palloc(r->pool, BS_MAX_CAPTCHA_BODY + 1),
        .cap = BS_MAX_CAPTCHA_BODY,
        .len = 0, .truncated = 0,
    };

    /* The shared helper takes ownership of curl_easy_cleanup. The
     * curl_escape outputs above are owned by `curl` (via libcurl's
     * own internals); bs_curl_escape_pool already copied them into
     * r->pool, so the body string survives the cleanup. */
    curl_easy_cleanup(curl);
    bs_captcha_result xport = bs_captcha_https_post(
        r, url, body, timeout_ms, ca_bundle,
        &resp, out_http_code, out_details, "GeeTest siteverify");
    if (xport != BS_CAPTCHA_OK) return xport;

    /* Parse GeeTest response: {"result":"success"/"fail","reason":"..."}. */
    apr_size_t body_len = resp.len;
    json_object *root = json_tokener_parse(resp.buf);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root) json_object_put(root);
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(r->pool, resp.buf, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
        return BS_CAPTCHA_ERROR;
    }

    bs_captcha_result out = BS_CAPTCHA_ERROR;
    json_object *res_o = NULL, *reason_o = NULL;
    if (json_object_object_get_ex(root, "result", &res_o) && res_o &&
        json_object_is_type(res_o, json_type_string)) {
        const char *res = json_object_get_string(res_o);
        if (res && strcmp(res, "success") == 0) {
            out = BS_CAPTCHA_OK;
        } else if (res && strcmp(res, "fail") == 0) {
            out = BS_CAPTCHA_REJECTED;
        }
    }
    if (json_object_object_get_ex(root, "reason", &reason_o) && reason_o &&
        json_object_is_type(reason_o, json_type_string)) {
        const char *reason = json_object_get_string(reason_o);
        if (reason) *out_details = apr_pstrdup(r->pool, reason);
    }
    if (out == BS_CAPTCHA_ERROR && (!*out_details || !**out_details)) {
        apr_size_t n = body_len < 120 ? body_len : 120;
        char *snip = apr_pstrndup(r->pool, resp.buf, n);
        for (char *q = snip; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
        *out_details = snip;
    }
    json_object_put(root);
    return out;
}

/* ----------------------------------------------------------------------
 * M8.1 verify-endpoint guardrails: per-IP rate limit, global in-flight
 * semaphore, per-IP log-throttle. All three live in SHM and use the
 * same "epoch-minute << 20 | count" slot encoding (bs_cv_slot). Reads
 * are torn-tolerant (a CAS loop corrects any bad read); writes are CAS.
 * ---------------------------------------------------------------------- */

/* Hash an IP to a slot index in a power-of-two table. Reuses the SHM
 * SipHash key so precomputed collisions are blocked. */
static apr_uint32_t bs_cv_slot_index(const unsigned char ip[16],
                                     apr_size_t slot_count)
{
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key, ip, 16);
    /* slot_count is a power of two at configuration time. */
    return (apr_uint32_t)(h & (apr_uint64_t)(slot_count - 1));
}

/* Try to increment a window counter at [slots[idx]] under `limit`.
 * Returns 1 on "accepted" (slot incremented, under cap) or 0 on
 * "rejected" (slot at or above cap in the current window). `cur_min`
 * is the current unix-minute. Uses CAS to roll a stale window and to
 * increment. */
static int bs_cv_counter_bump(bs_cv_slot *slots, apr_size_t idx,
                              apr_uint64_t cur_min, int limit)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        /* Relaxed atomic load makes the torn-tolerant observation
         * explicit to the compiler and TSAN; the CAS below will
         * either succeed (so what we read was consistent) or retry. */
        bs_cv_slot observed = __atomic_load_n(&slots[idx],
                                              __ATOMIC_RELAXED);
        bs_cv_slot next;
        if (BS_CV_WINDOW(observed) != cur_min) {
            next = BS_CV_SLOT(cur_min, 1);
        } else {
            apr_uint32_t count = BS_CV_COUNT(observed);
            if ((int)count >= limit) return 0;
            next = BS_CV_SLOT(cur_min, count + 1);
        }
        /* apr_atomic_cas64 isn't universally available; fall back to a
         * 32-bit CAS on the lower half since that's where the count
         * lives. The window rollover is idempotent — a concurrent
         * rollover just re-initializes to (cur_min, 1), which is
         * indistinguishable from our own rollover. */
        if (__sync_bool_compare_and_swap(&slots[idx], observed, next)) {
            return 1;
        }
    }
    /* Contention gave up — fail-open on rate (accept) rather than
     * flap-reject legitimate traffic. Alternate choice would be
     * fail-closed; either is defensible. */
    return 1;
}

/* Per-IP rate limit on the verify endpoint. Returns 1 if the request
 * is within the cap (allow through), 0 if over cap (reject with 429).
 * limit <= 0 disables the check. */
static int bs_captcha_rate_allowed(const unsigned char ip[16], int limit)
{
    if (limit <= 0 || !bs_shm.cv_rate_slots) return 1;
    apr_uint64_t cur_min =
        (apr_uint64_t)(apr_time_sec(apr_time_now()) / 60);
    apr_uint32_t idx =
        bs_cv_slot_index(ip, bs_shm.cv_rate_slot_count);
    return bs_cv_counter_bump(bs_shm.cv_rate_slots, idx, cur_min, limit);
}

/* Global in-flight siteverify semaphore. Returns 1 on acquire, 0 if
 * the cap was already reached (caller must return 503 without calling
 * libcurl). Every successful acquire MUST be paired with a release on
 * every return path. */
static int bs_captcha_inflight_acquire(int max_inflight)
{
    if (!bs_shm.cv_inflight || max_inflight <= 0) return 1;
    for (int attempt = 0; attempt < 8; attempt++) {
        apr_uint32_t cur = apr_atomic_read32(bs_shm.cv_inflight);
        if ((int)cur >= max_inflight) return 0;
        if (apr_atomic_cas32(bs_shm.cv_inflight, cur + 1, cur) == cur) {
            return 1;
        }
    }
    /* Heavy contention — fail-closed here so we don't overshoot the
     * cap under load. Cheap: contention at this level already means
     * we're near the cap. */
    return 0;
}

static void bs_captcha_inflight_release(void)
{
    if (!bs_shm.cv_inflight) return;
    apr_atomic_dec32(bs_shm.cv_inflight);
}

/* Per-IP log-throttle for verify-endpoint lines. Returns 1 if the
 * caller should emit the log, 0 if it should suppress. When emitting
 * after a rollover, *out_prev_count carries the number of events
 * suppressed during the previous window (0 if none or if this is the
 * first event for this slot). Callers typically format the log as
 * `... (×N in last 60s)` when out_prev_count > 1.
 *
 * Each IP gets one log per BS_CAPTCHA_LOG_WINDOW_SEC regardless of
 * how many events fired in between; the count tells the operator
 * how many were collapsed. */
static int bs_captcha_log_throttle(const unsigned char ip[16],
                                   apr_uint32_t *out_prev_count)
{
    if (out_prev_count) *out_prev_count = 0;
    if (!bs_shm.cv_log_slots) return 1;
    apr_uint64_t cur_min =
        (apr_uint64_t)(apr_time_sec(apr_time_now()) /
                       BS_CAPTCHA_LOG_WINDOW_SEC);
    apr_uint32_t idx =
        bs_cv_slot_index(ip, bs_shm.cv_log_slot_count);

    for (int attempt = 0; attempt < 4; attempt++) {
        bs_cv_slot observed = __atomic_load_n(&bs_shm.cv_log_slots[idx],
                                              __ATOMIC_RELAXED);
        if (BS_CV_WINDOW(observed) != cur_min) {
            /* Stale window → this is the first log in a new window.
             * Roll to (cur_min, 1); report how many were suppressed in
             * the old window (if any) so the caller can tell the
             * operator "N events collapsed since the last line". */
            apr_uint32_t prev = BS_CV_COUNT(observed);
            bs_cv_slot next = BS_CV_SLOT(cur_min, 1);
            if (__sync_bool_compare_and_swap(&bs_shm.cv_log_slots[idx],
                                              observed, next)) {
                if (out_prev_count) *out_prev_count = prev;
                return 1;
            }
        } else {
            /* Same window → bump the suppressed count, but don't log. */
            apr_uint32_t count = BS_CV_COUNT(observed);
            bs_cv_slot next = BS_CV_SLOT(cur_min, count + 1);
            if (__sync_bool_compare_and_swap(&bs_shm.cv_log_slots[idx],
                                              observed, next)) {
                return 0;   /* suppressed */
            }
        }
    }
    /* Contention → log (better to have the line than silently drop). */
    return 1;
}

/* Small helper: return " (×N in last 60s)" or "" for prepending to a
 * throttled log line. Allocated on r->pool. */
static const char *bs_log_suppress_suffix(apr_pool_t *p, apr_uint32_t n)
{
    if (n <= 1) return "";
    return apr_psprintf(p, " (×%u in last %ds)",
                        n, BS_CAPTCHA_LOG_WINDOW_SEC);
}

/* See captcha.h for the contract. The wrapper exists so embedded-
 * verify (silent.c) and form-captcha (formcaptcha.c) get the same
 * provider-quota / worker-occupancy DoS protection that the
 * /captcha-verify handler had inline — without this, those two
 * paths reach bs_captcha_siteverify with no rate cap and no
 * in-flight semaphore. */
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
    const char **out_action)
{
    if (!log_tag) log_tag = "captcha";

    /* Per-IP rate limit. 0 disables; default 30/min. */
    unsigned char client_ip[16];
    int have_ip = bs_parse_client_ip(r->useragent_ip, client_ip);
    if (have_ip) {
        int rate_limit = bs_effective_int(cfg->captcha_rate_limit,
                                          BS_DEFAULT_CAPTCHA_RATE_LIMIT);
        if (!bs_captcha_rate_allowed(client_ip, rate_limit)) {
            apr_uint32_t prev = 0;
            int emit = bs_captcha_log_throttle(client_ip, &prev);
            if (emit) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "mod_botshield: %s rate limit%s "
                    "(ip=%s, limit=%d/min)",
                    log_tag, bs_log_suppress_suffix(r->pool, prev),
                    r->useragent_ip ? r->useragent_ip : "?", rate_limit);
            }
            return BS_CAPTCHA_RATE_LIMITED;
        }
    }

    /* Global in-flight semaphore. Acquire-then-release; every return
     * path past the acquire MUST release. */
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                                &botshield_module);
    int max_inflight = scfg ? scfg->captcha_max_inflight
                            : BS_DEFAULT_CAPTCHA_MAX_INFLIGHT;
    if (!bs_captcha_inflight_acquire(max_inflight)) {
        apr_uint32_t prev = 0;
        int emit = have_ip
            ? bs_captcha_log_throttle(client_ip, &prev) : 1;
        if (emit) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: %s in-flight cap reached%s "
                "(max=%d) — provider likely slow",
                log_tag, bs_log_suppress_suffix(r->pool, prev),
                max_inflight);
        }
        return BS_CAPTCHA_INFLIGHT_CAPPED;
    }

    /* Provider-specific verify path overrides the shared shim when
     * set. GeeTest is the current user; the other five providers
     * leave siteverify_fn NULL. */
    bs_captcha_siteverify_fn verify_fn =
        cfg->captcha_provider->siteverify_fn
        ? cfg->captcha_provider->siteverify_fn
        : bs_captcha_siteverify;
    bs_captcha_result result = verify_fn(
        r, cfg->captcha_provider,
        cfg->captcha_secret, cfg->captcha_secret_len,
        token, timeout_ms, cfg->captcha_ca_bundle,
        out_details, out_http_code, out_score,
        out_hostname, out_action);

    bs_captcha_inflight_release();
    return result;
}



/* URL-decode an x-www-form-urlencoded value in place: '+' → ' ',
 * %XX → byte. Unrecognized sequences are left untouched; a value that
 * survives partial decoding will simply fail siteverify downstream. */
static void bs_urldecode_inplace(char *s)
{
    char *w = s;
    char *rp = s;
    while (*rp) {
        if (*rp == '+') { *w++ = ' '; rp++; continue; }
        if (*rp == '%' && rp[1] && rp[2]) {
            int hi = -1, lo = -1;
            char c = rp[1];
            if      (c >= '0' && c <= '9') hi = c - '0';
            else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
            c = rp[2];
            if      (c >= '0' && c <= '9') lo = c - '0';
            else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
            if (hi >= 0 && lo >= 0) {
                /* Refuse to decode %00.
                 * Otherwise the embedded NUL truncates every C-string
                 * consumer downstream (strlen, strchr, snprintf %s).
                 * Pass the literal '%','0','0' through; downstream
                 * validators that care can flag the percent sequence
                 * explicitly. */
                if (hi == 0 && lo == 0) {
                    *w++ = *rp++;   /* '%' */
                    continue;
                }
                *w++ = (char)((hi << 4) | lo);
                rp += 3;
                continue;
            }
        }
        *w++ = *rp++;
    }
    *w = '\0';
}

/* Read the POST body into an r->pool buffer. Caps length at max_len to
 * prevent a malicious client from forcing us to buffer unbounded bytes
 * during captcha-verify. Returns NULL on error (already responded to
 * the client via ap_setup_client_block) or a pool-allocated NUL-
 * terminated buffer otherwise. */
/* Read the whole request body via ap_get_client_block into a
 * pool-allocated buffer.
 *
 * Returns:
 *   APR_SUCCESS  — *out_body / *out_len populated; body may be empty.
 *   APR_ENOSPC   — body exceeded max_len; caller should emit 413.
 *   APR_EGENERAL — ap_get_client_block returned a transport error;
 *                  caller should emit 400.
 *   APR_EINIT    — ap_setup_client_block rejected; caller emits 400.
 *
 *  was returning a pointer-or-NULL with
 * silent truncation when the body exceeded max_len: the loop
 * `break`'d at `total >= max_len` without consuming the rest, so
 * callers couldn't tell the difference between "body fit cleanly"
 * and "body was twice the cap and we threw the tail away." Now
 * the function reads one extra byte past max_len; if any data
 * remains, we return APR_ENOSPC so the caller can 413 instead
 * of accepting a quietly-truncated body. */
apr_status_t bs_read_form_body(request_rec *r, apr_size_t max_len,
                                      const char **out_body,
                                      apr_size_t *out_len)
{
    *out_body = NULL;
    *out_len = 0;
    int rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if (rc != OK) return APR_EINIT;
    if (!ap_should_client_block(r)) {
        char *empty = apr_pcalloc(r->pool, 1);
        *out_body = empty;
        return APR_SUCCESS;
    }
    char *buf = apr_palloc(r->pool, max_len + 1);
    apr_size_t total = 0;
    long n;
    char chunk[4096];
    while ((n = ap_get_client_block(r, chunk, sizeof(chunk))) > 0) {
        if ((apr_size_t)n > max_len - total) {
            /* This chunk would overflow. Body is too big. Mark the
             * connection close-on-response so the unread tail of the
             * body doesn't desync framing on the next keepalive
             * request — Apache otherwise leaves the unconsumed
             * remainder on the socket and the next request gets
             * garbled. */
            r->connection->keepalive = AP_CONN_CLOSE;
            return APR_ENOSPC;
        }
        memcpy(buf + total, chunk, (apr_size_t)n);
        total += (apr_size_t)n;
    }
    if (n < 0) return APR_EGENERAL;
    buf[total] = '\0';
    *out_body = buf;
    *out_len = total;
    return APR_SUCCESS;
}

/* Pick a single field value from a URL-encoded body. Returns a fresh
 * pool-allocated, URL-decoded copy, or NULL if the field is absent —
 * safe to call repeatedly on the same buffer. */
char *bs_form_get(apr_pool_t *p, const char *body, const char *key)
{
    apr_size_t klen = strlen(key);
    const char *cur = body;
    while (cur && *cur) {
        const char *eq  = strchr(cur, '=');
        const char *amp = strchr(cur, '&');
        if (!eq || (amp && eq > amp)) {
            if (!amp) break;
            cur = amp + 1;
            continue;
        }
        apr_size_t this_klen = (apr_size_t)(eq - cur);
        const char *val     = eq + 1;
        const char *val_end = amp ? amp : (body + strlen(body));
        if (this_klen == klen && strncmp(cur, key, klen) == 0) {
            char *dup = apr_pstrmemdup(p, val, (apr_size_t)(val_end - val));
            bs_urldecode_inplace(dup);
            return dup;
        }
        if (!amp) break;
        cur = amp + 1;
    }
    return NULL;
}

/* Sanity-check a client-supplied return_to for use as a redirect target.
 * Accept only same-origin relative paths: must start with '/', must not
 * start with '//' (protocol-relative), no CR/LF (header injection), and
 * reasonable length. Returns NULL on reject, else the same pointer for
 * caller convenience. */
static const char *bs_sanitize_return_to(const char *s)
{
    if (!s || !*s) return NULL;
    apr_size_t len = strlen(s);
    if (len > 2048) return NULL;
    if (s[0] != '/') return NULL;
    if (s[1] == '/' || s[1] == '\\') return NULL;   /* //host, /\host */
    for (apr_size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n' || c == 0) return NULL;
    }
    return s;
}


/* ---- M8.1 challenge-origin "pending" cookie ----
 *
 * Name:  _bs_captcha_pending
 * Value: <nonce_hex>|<expiry_unix_sec>|<hmac_hex>
 *        hmac = HMAC-SHA256(derived_hmac_pending,
 *                           "bs:pending:v1:" || nonce_hex || ":"
 *                           || expiry_unix_sec_ascii)
 * Attrs: HttpOnly, Secure (on HTTPS), SameSite=Lax, Max-Age=300,
 *        Path=<endpoint_prefix>/captcha-verify (so it's only sent on
 *        verify POSTs, not every request).
 *
 * Why this exists — DoS protection for /captcha-verify:
 *
 * Without this cookie, an attacker could POST garbage tokens directly
 * to /captcha-verify. Each request triggers an outbound libcurl call
 * to the captcha provider's siteverify endpoint, holding one of
 * BS_DEFAULT_CAPTCHA_MAX_INFLIGHT (=64) in-flight slots for the call
 * duration. Saturating that semaphore yields:
 *   - 503 to legitimate users hitting /captcha-verify
 *   - Burned API quota with the captcha provider
 *   - Possible provider-side rate-limiting against the operator
 *
 * The pending cookie short-circuits the attack:
 *   - Minted only at captcha-interstitial render time (one mint per
 *     legitimate challenge presentation)
 *   - Required at /captcha-verify; absent / forged / expired → 403 in
 *     microseconds via HMAC verify, no libcurl call made
 *   - Path-scoped to /captcha-verify so it's not sent on regular
 *     requests (zero per-request cookie-size cost in normal traffic)
 *   - HttpOnly + HMAC-signed so it can't be forged client-side
 *
 * Net effect: only clients that actually saw the challenge page can
 * reach the libcurl call. The verify endpoint's effective attack
 * surface shrinks from "anyone with a TCP connection" to "rate of
 * legitimate captcha presentations" — a much smaller number.
 *
 * Why this is a separate cookie from _bs_verified, not state inside it:
 *   - _bs_verified           Path=/, hour-scale TTL, sent every request
 *   - _bs_captcha_pending    Path=<prefix>/captcha-verify, 5-min TTL,
 *                            sent only at the verify endpoint
 * Folding pending-state into _bs_verified would either mix state-
 * machine concerns into the long-lived trust cookie or carry pending
 * state on every request — both worse than the current split. */
#define BS_PENDING_COOKIE_NAME  "_bs_captcha_pending"
#define BS_PENDING_COOKIE_TTL   300   /* seconds */

const char *bs_mint_pending_cookie(request_rec *r,
                                          const bs_dir_cfg *cfg)
{
    if (!cfg->secret) return NULL;
    unsigned char nonce[16];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return NULL;
    char nonce_hex[sizeof(nonce) * 2 + 1];
    bs_to_hex(nonce, sizeof(nonce), nonce_hex);

    apr_time_t expiry = apr_time_sec(apr_time_now()) + BS_PENDING_COOKIE_TTL;
    /* Explicit module + purpose + version
     * context tag for domain separation. SHA-256 HMAC is collision-
     * resistant on its own, but a longer, more specific tag makes
     * it impossible for any FUTURE HMAC use to accidentally share
     * a canonical-bytes prefix with this one. Versioning the tag
     * lets us bump the protocol later without revalidating that
     * the new bytes are disjoint from the old. */
    const char *canon = apr_psprintf(r->pool,
        "bs:pending:v1:%s:%" APR_TIME_T_FMT, nonce_hex, expiry);
    unsigned char mac[BS_SIG_BYTES];
    /* derived pending-HMAC key. */
    bs_hmac_sha256(cfg->derived_hmac_pending, 32,
                   (const unsigned char *)canon, strlen(canon), mac);
    char mac_hex[BS_SIG_BYTES * 2 + 1];
    bs_to_hex(mac, BS_SIG_BYTES, mac_hex);

    const char *value = apr_psprintf(r->pool,
        "%s|%" APR_TIME_T_FMT "|%s", nonce_hex, expiry, mac_hex);
    const char *prefix = cfg->endpoint_prefix
        ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    const char *scheme = ap_http_scheme(r);
    const char *secure = (scheme && strcmp(scheme, "https") == 0)
        ? "; Secure" : "";
    return apr_psprintf(r->pool,
        BS_PENDING_COOKIE_NAME "=%s; Path=%s/captcha-verify; "
        "HttpOnly%s; SameSite=Lax; Max-Age=%d",
        value, prefix, secure, BS_PENDING_COOKIE_TTL);
}

/* Returns NULL on accept; else a short diagnostic string. On accept,
 * the cookie stays on the request (the handler should emit a
 * Max-Age=0 clear after a successful siteverify so a stale cookie
 * isn't reused). Every failure reason returns to the caller the same
 * way — don't differentiate in the 403 response body, both to avoid
 * leaking validation details and to keep the response constant-time. */
static const char *bs_verify_pending_cookie(request_rec *r,
                                            const bs_dir_cfg *cfg)
{
    if (!cfg->secret) return "no server secret";
    const char *raw = bs_get_cookie_value(r, BS_PENDING_COOKIE_NAME);
    if (!raw || !*raw) return "missing";
    if (strlen(raw) > 256) return "too long";

    char *mut = apr_pstrdup(r->pool, raw);
    char *nonce_hex = mut;
    char *bar1 = strchr(mut, '|');
    if (!bar1) return "bad format";
    *bar1++ = '\0';
    char *expiry_str = bar1;
    char *bar2 = strchr(expiry_str, '|');
    if (!bar2) return "bad format";
    *bar2++ = '\0';
    char *mac_hex = bar2;
    if (strlen(nonce_hex) != 32) return "bad nonce";
    if (strlen(mac_hex)   != BS_SIG_BYTES * 2) return "bad mac length";
    /* nonce must be valid hex — quick check. */
    unsigned char scratch[16];
    if (!bs_from_hex(nonce_hex, 32, sizeof(scratch), scratch)) return "bad nonce hex";

    /* Bounded parse before HMAC. apr_atoi64
     * silently clamps/wraps on overflow without signalling; use the
     * bounded helper so gigantic junk is rejected cleanly instead
     * of feeding a nonsense timestamp into the freshness check. */
    apr_int64_t expiry_raw;
    if (!bs_parse_int64_bounded(expiry_str, 1, APR_INT64_MAX, &expiry_raw)) {
        return "bad expiry";
    }
    apr_time_t expiry = (apr_time_t)expiry_raw;
    /* Was `expiry + BS_CLOCK_SKEW_AHEAD <
     * now` with the comment "grace if client clock runs ahead", but
     * the expiry stamped into the pending cookie comes from
     * apr_time_now() at mint time — server-side, never a client
     * stamp. The clock-skew grace was therefore mis-justified and
     * just extended the effective TTL by 60s, giving a stolen-
     * and-expired pending cookie an extra minute of replay
     * window for no defensive value. Drop the grace. */
    if (expiry < apr_time_sec(apr_time_now())) {
        return "expired";
    }

    /* Must match the mint side's canon
     * shape exactly. See comment above the mint site for the
     * domain-separation rationale. */
    const char *canon = apr_psprintf(r->pool,
        "bs:pending:v1:%s:%" APR_TIME_T_FMT, nonce_hex, expiry);
    unsigned char expect[BS_SIG_BYTES];
    /* derived pending-HMAC key (primary). */
    bs_hmac_sha256(cfg->derived_hmac_pending, 32,
                   (const unsigned char *)canon, strlen(canon), expect);
    unsigned char got[BS_SIG_BYTES];
    if (!bs_from_hex(mac_hex, BS_SIG_BYTES * 2,
                     BS_SIG_BYTES, got)) return "bad mac hex";
    if (!bs_ct_equal(expect, got, BS_SIG_BYTES)) {
        /* Secondary-key fallback for the pending cookie. During a
         * BotShieldSecondarySecretFile rotation reload, any user
         * with an in-flight pending cookie (TTL 300s) would 403 on
         * captcha submit if we only checked the primary key — even
         * though the secondary key would validate. Same retry
         * pattern as the _bs_verified and embedded-verify paths. */
        if (!cfg->derived_keys_set_2) return "sig mismatch";
        bs_hmac_sha256(cfg->derived_hmac_pending_2, 32,
                       (const unsigned char *)canon, strlen(canon),
                       expect);
        if (!bs_ct_equal(expect, got, BS_SIG_BYTES)) {
            return "sig mismatch";
        }
    }
    return NULL;
}

/* Set-Cookie clearing the pending cookie (Max-Age=0). Called after a
 * successful verify so a captured cookie can't be replayed. */
const char *bs_clear_pending_cookie(request_rec *r,
                                           const bs_dir_cfg *cfg)
{
    const char *prefix = cfg->endpoint_prefix
        ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    const char *scheme = ap_http_scheme(r);
    const char *secure = (scheme && strcmp(scheme, "https") == 0)
        ? "; Secure" : "";
    return apr_psprintf(r->pool,
        BS_PENDING_COOKIE_NAME "=; Path=%s/captcha-verify; "
        "HttpOnly%s; SameSite=Lax; Max-Age=0",
        prefix, secure);
}

/* See captcha.h for the contract. Single-source-of-truth for
 * "successful provider verify → mint a fresh _bs_verified". The
 * three call sites (captcha verify handler, embedded-verify-provider,
 * form-captcha fixup) used to maintain this in lockstep; both the
 * forgive-cap regression caught in E15 and the fresh-rep regression
 * caught in E17 were drift in exactly this code. */
const char *bs_captcha_carry_and_mint(
    request_rec *r,
    const bs_dir_cfg *cfg,
    bs_captcha_passes_kind passes_kind,
    int forgive_amount,
    int auto_tier,
    bs_challenge *out_ch,
    const char **out_alg_name)
{
    if (!cfg || !cfg->captcha_provider) {
        return "no captcha provider configured on scope";
    }

    /* Carry forward prior cookie's rep block when the prior cookie
     * sig-verifies (or sig-verified-but-just-expired). bs_carry_
     * forward_eligible handles the gating; bs_apply_rep_carry does
     * the rep math + per-cookie hourly forgive cap clamp. */
    bs_rep_state next_rep;
    memset(&next_rep, 0, sizeof(next_rep));
    {
        bs_challenge prior_ch = { 0 };
        if (bs_carry_forward_eligible(r, cfg, &prior_ch)) {
            next_rep = prior_ch.rep;
            bs_apply_rep_carry(r, cfg, &prior_ch, &next_rep,
                               forgive_amount);
        }
        if (passes_kind == BS_CAPTCHA_PASSES_SILENT) {
            next_rep.passes_silent = 1;   /* clamp */
        } else {
            next_rep.passes_captcha = 1;  /* clamp */
        }
    }

    /* Cookie alg name is derived from provider name by convention so
     * adding a provider doesn't require touching this helper — just the
     * two registries. */
    const char *cookie_alg_name = apr_psprintf(r->pool, "captcha-%s",
                                               cfg->captcha_provider->name);
    const bs_pow_algorithm *alg = bs_find_algorithm(cookie_alg_name);
    if (!alg || !alg->implemented) {
        return apr_psprintf(r->pool,
            "cookie alg '%s' missing from registry — provider '%s' "
            "is wired up but its cookie-alg row isn't",
            cookie_alg_name, cfg->captcha_provider->name);
    }
    if (out_alg_name) *out_alg_name = cookie_alg_name;

    int ttl        = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);
    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);

    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          auto_tier, alg,
                                          &next_rep, out_ch);
    if (ierr) return apr_psprintf(r->pool, "challenge issue: %s", ierr);

    if (bs_install_verified_cookie(r, cfg, out_ch, "captcha") != NULL) {
        return "cookie payload build failed (GCM encrypt)";
    }
    return NULL;
}

/* M8 verify handler. Mounted at <prefix>/captcha-verify; POSTed to by
 * the interstitial's form submit when the provider's widget callback
 * fires. On success, server-issues a signed captcha-turnstile cookie
 * and 302s back to the page the user tried to reach. */
int bs_captcha_verify_handler(request_rec *r, bs_dir_cfg *cfg)
{
    /* Response from this endpoint must never be cached by any
     * intermediary — verify is stateful (issues a cookie) and the body
     * only ever contains status text. Set the header early so every
     * return path inherits it. */
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    /* For consistency in the decision log, resolve a provider name up
     * front even if config is partial — misconfigured paths still want
     * a defensible value to emit. */
    const char *prov_name = (cfg->captcha_provider
                             && cfg->captcha_provider->name)
                            ? cfg->captcha_provider->name : "-";

    if (r->method_number != M_POST) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "POST");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("POST required.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "method_not_allowed", 0);
        return OK;
    }

    /* M8.1 cheap prefilter: Content-Type must be form-urlencoded. Reject
     * anything else (JSON bodies, multipart, unset, etc.) immediately —
     * we only parse form bodies downstream and a mismatched type is
     * either a misconfigured client or junk traffic. */
    const char *ctype = apr_table_get(r->headers_in, "Content-Type");
    if (!ctype || strncmp(ctype, "application/x-www-form-urlencoded",
                          sizeof("application/x-www-form-urlencoded") - 1) != 0) {
        r->status = HTTP_UNSUPPORTED_MEDIA_TYPE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-bad-content-type");
        ap_rputs("application/x-www-form-urlencoded required.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "bad_content_type", 0);
        return OK;
    }

    if (!cfg->captcha_provider || !cfg->captcha_site_key ||
        !cfg->captcha_secret || !cfg->secret) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: captcha-verify called on a scope without full "
            "captcha config (provider=%s, sitekey=%s, secret=%s)",
            cfg->captcha_provider ? "set" : "unset",
            cfg->captcha_site_key ? "set" : "unset",
            cfg->captcha_secret   ? "set" : "unset");
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Captcha verification is not configured on this scope.\n", r);
        bs_decision_log(r, "captcha", "misconfigured", "-",
                        prov_name, "-", "-", 0);
        return OK;
    }

    /* M8.1 pending-cookie check MUST run BEFORE the libcurl siteverify
     * call below. See the M8.1 block comment at bs_mint_pending_cookie
     * for the full threat model — without this gate, blind POST spray
     * at /captcha-verify can saturate BS_DEFAULT_CAPTCHA_MAX_INFLIGHT
     * (=64) and DoS legitimate users (plus burn provider quota). A
     * valid cookie proves the client hit our interstitial within the
     * last 5 minutes; missing or tampered short-circuits to 403 in
     * microseconds before any rate slot or body parse. */
    const char *pend_err = bs_verify_pending_cookie(r, cfg);
    if (pend_err) {
        /* Log throttled — a flood of blind POSTs must not drown the log. */
        unsigned char ip_for_log[16];
        int have_ip_for_log =
            bs_parse_client_ip(r->useragent_ip, ip_for_log);
        apr_uint32_t prev = 0;
        int emit = have_ip_for_log
            ? bs_captcha_log_throttle(ip_for_log, &prev) : 1;
        if (emit) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: captcha-verify pending cookie %s%s — 403",
                pend_err, bs_log_suppress_suffix(r->pool, prev));
        }
        r->status = HTTP_FORBIDDEN;
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-pending-missing");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Challenge session missing or expired.\n", r);
        bs_decision_log(r, "captcha", "pending_missing", "-",
                        prov_name, "-", pend_err, 0);
        return OK;
    }

    /* M8.1 body size tightened to 8 KB total (was BS_MAX_CAPTCHA_TOKEN
     * + 4096 ~= 12 KB). The largest legitimate body is a GeeTest JSON
     * blob of ~2 KB + return_to ~= 3 KB; 8 KB is comfortable headroom
     * and caps the work a hostile client can force us to buffer. */
    apr_size_t body_len = 0;
    const char *body = NULL;
    apr_status_t bsr = bs_read_form_body(r, 8 * 1024, &body, &body_len);
    if (bsr == APR_ENOSPC) {
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "body_too_large", 0);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    if (bsr != APR_SUCCESS || !body) {
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "body_read_failed", 0);
        return HTTP_BAD_REQUEST;
    }
    char *token     = bs_form_get(r->pool, body,
                                  cfg->captcha_provider->token_field);
    char *return_to = bs_form_get(r->pool, body, "return_to");

    const char *safe_return = bs_sanitize_return_to(return_to);
    if (!safe_return) safe_return = "/";

    if (!token || !*token) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: captcha-verify: missing token field '%s'",
            cfg->captcha_provider->token_field);
        r->status = HTTP_BAD_REQUEST;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Missing captcha token.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "no_token", 0);
        return OK;
    }
    if (strlen(token) > BS_MAX_CAPTCHA_TOKEN) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: captcha-verify: token longer than %d bytes",
            BS_MAX_CAPTCHA_TOKEN);
        r->status = HTTP_BAD_REQUEST;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Captcha token too long.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        prov_name, "-", "token_too_long", 0);
        return OK;
    }

    int timeout = bs_effective_int(cfg->captcha_timeout_ms,
                                   BS_DEFAULT_CAPTCHA_TIMEOUT);

    /* Re-extract client IP for log-throttle calls in the result-
     * handling code below. The guard rail does its own IP parse
     * internally; this copy is for the post-verify log lines. */
    unsigned char client_ip[16];
    int have_ip = bs_parse_client_ip(r->useragent_ip, client_ip);

    const char *details = NULL;
    long http_code = 0;
    double score = -1.0;
    const char *resp_hostname = NULL;
    const char *resp_action   = NULL;
    /* Centralized guarded siteverify — applies the per-IP rate limit
     * + global in-flight semaphore + provider dispatch. Two new
     * result variants (RATE_LIMITED, INFLIGHT_CAPPED) signal a guard
     * short-circuit; map to 429 / 503. */
    bs_captcha_result result = bs_captcha_siteverify_guarded(
        r, cfg, token, timeout, "captcha-verify",
        &details, &http_code, &score,
        &resp_hostname, &resp_action);

    if (result == BS_CAPTCHA_RATE_LIMITED) {
        r->status = HTTP_TOO_MANY_REQUESTS;
        apr_table_setn(r->err_headers_out, "Retry-After", "60");
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-rate-limited");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Too many captcha verification attempts.\n", r);
        bs_decision_log(r, "captcha", "rate_limited", "-",
                        prov_name, "-", "-", 0);
        return OK;
    }
    if (result == BS_CAPTCHA_INFLIGHT_CAPPED) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        apr_table_setn(r->err_headers_out, "Retry-After", "2");
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-saturated");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Captcha verification busy, try again shortly.\n", r);
        bs_decision_log(r, "captcha", "inflight_capped", "-",
                        prov_name, "-", "-", 0);
        return OK;
    }

    /* bind the token to this origin + flow.
     *   - hostname: provider-echoed domain of the site where the
     *     challenge was solved. Check against the configured expected
     *     hostname (default = r->server->server_hostname) so a token
     *     minted on another origin but sharing the same sitekey can't
     *     satisfy verification here.
     *   - action (reCAPTCHA v3, Turnstile): the string the client
     *     widget tagged the token with. We embed `action: 'botshield'`
     *     in the interstitial JS, so a token from a different form on
     *     the same sitekey will carry a different action. Without this
     *     check, reCAPTCHA v3 in particular is score-threshold-only,
     *     which a stolen-from-elsewhere token with a high score would
     *     sail through.
     *
     * Mismatch flips OK → REJECTED with a descriptive details string
     * so the prose + decision log both carry the "why". An operator
     * can opt out of either check by setting the directive value to
     * the empty string. */
    if (result == BS_CAPTCHA_OK) {
        const char *expected_host =
            cfg->captcha_expected_hostname
                ? cfg->captcha_expected_hostname
                : (r->server && r->server->server_hostname
                       ? r->server->server_hostname : "");
        const char *expected_action =
            cfg->captcha_expected_action
                ? cfg->captcha_expected_action
                : "botshield";

        if (resp_hostname && *expected_host &&
            strcmp(resp_hostname, expected_host) != 0) {
            details = apr_psprintf(r->pool,
                "hostname-mismatch:got=%s,expected=%s",
                resp_hostname, expected_host);
            result = BS_CAPTCHA_REJECTED;
        } else if (resp_action && *expected_action &&
                   strcmp(resp_action, expected_action) != 0) {
            details = apr_psprintf(r->pool,
                "action-mismatch:got=%s,expected=%s",
                resp_action, expected_action);
            result = BS_CAPTCHA_REJECTED;
        }
    }

    /* reCAPTCHA v3 score threshold. Applied *after* success:true — the
     * provider said the token is valid; we still reject if the signal
     * is too weak. A missing score on a v3 response is a protocol
     * surprise (v3 always returns one); treat that as ERROR so the
     * fail-open path runs rather than silently accepting or rejecting.
     * The plain REJECTED path above stays exactly as it was. */
    /* Log-throttle is only invoked from failure branches so a flood of
     * happy-path OKs doesn't bump the slot counter and starve later
     * REJECTED/WARNING emissions. OK paths log unconditionally — the
     * throttle exists to protect against hostile/broken traffic. */
    int is_v3 = (strcmp(cfg->captcha_provider->name, "recaptcha-v3") == 0);
    if (result == BS_CAPTCHA_OK && is_v3) {
        double min_score = (cfg->recaptcha_v3_min_score >= 0.0)
            ? cfg->recaptcha_v3_min_score
            : BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE;
        if (score < 0.0) {
            apr_uint32_t prev = 0;
            int emit = have_ip
                ? bs_captcha_log_throttle(client_ip, &prev) : 1;
            if (emit) ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: reCAPTCHA v3 response missing score%s — "
                "failing open (provider=%s http=%ld)",
                bs_log_suppress_suffix(r->pool, prev),
                cfg->captcha_provider->name, http_code);
            /* fall through to success path (fail-open) */
        } else if (score < min_score) {
            apr_uint32_t prev = 0;
            int emit = have_ip
                ? bs_captcha_log_throttle(client_ip, &prev) : 1;
            if (emit) ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: captcha REJECTED%s "
                "(provider=%s http=%ld score=%.2f min=%.2f)",
                bs_log_suppress_suffix(r->pool, prev),
                cfg->captcha_provider->name, http_code,
                score, min_score);
            r->status = HTTP_FORBIDDEN;
            ap_set_content_type(r, "text/plain; charset=utf-8");
            apr_table_setn(r->err_headers_out, "X-Botshield", "captcha-rejected");
            ap_rputs("Verification score too low. Go back and try again.\n", r);
            bs_decision_log(r, "captcha", "rejected", "-",
                            cfg->captcha_provider->name, "-",
                            apr_psprintf(r->pool, "low_score:%.2f", score),
                            0);
            return OK;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                "mod_botshield: captcha OK (provider=%s http=%ld "
                "score=%.2f min=%.2f return_to=%s)",
                cfg->captcha_provider->name, http_code,
                score, min_score, safe_return);
        }
    } else if (result == BS_CAPTCHA_REJECTED) {
        apr_uint32_t prev = 0;
        int emit = have_ip
            ? bs_captcha_log_throttle(client_ip, &prev) : 1;
        if (emit) ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: captcha REJECTED%s "
            "(provider=%s http=%ld error-codes=[%s])",
            bs_log_suppress_suffix(r->pool, prev),
            cfg->captcha_provider->name, http_code,
            details ? details : "");
        r->status = HTTP_FORBIDDEN;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->err_headers_out, "X-Botshield", "captcha-rejected");
        ap_rputs("Captcha verification failed. Go back and try again.\n", r);
        bs_decision_log(r, "captcha", "rejected", "-",
                        cfg->captcha_provider->name, "-",
                        (details && *details) ? details : "-", 0);
        return OK;
    } else if (result == BS_CAPTCHA_TIMEOUT || result == BS_CAPTCHA_ERROR) {
        /* Fail-open is an attack surface while a provider is unavailable.
         * The WARNING-level log line carries the literal string
         * "failing open" so operators can grep/alert on it; M9.2 counts
         * these as outcome=failopen. */
        apr_uint32_t prev = 0;
        int emit = have_ip
            ? bs_captcha_log_throttle(client_ip, &prev) : 1;
        if (emit) ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: captcha %s — failing open%s "
            "(provider=%s http=%ld detail=\"%s\")",
            result == BS_CAPTCHA_TIMEOUT ? "TIMEOUT" : "ERROR",
            bs_log_suppress_suffix(r->pool, prev),
            cfg->captcha_provider->name, http_code,
            details ? details : "");
        /* fall through to success path */
    } else {
        /* Plain OK, non-v3 provider. */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: captcha OK (provider=%s http=%ld return_to=%s)",
            cfg->captcha_provider->name, http_code, safe_return);
    }

    /* Carry-forward + mint + install — see bs_captcha_carry_and_mint
     * in captcha.h. Single source of truth for the forgive cap +
     * passes counter + cookie installation across the captcha-verify
     * handler, embedded-verify-provider, and form-captcha fixup. */
    bs_challenge ch;
    const char *cookie_alg_name = NULL;
    const char *merr = bs_captcha_carry_and_mint(r, cfg,
        BS_CAPTCHA_PASSES_CAPTCHA,
        bs_effective_int(cfg->forgive_captcha, BS_DEFAULT_FORGIVE_CAPTCHA),
        /* auto_tier */ 0,
        &ch, &cookie_alg_name);
    if (merr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: captcha cookie issue: %s", merr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Service error: could not issue cookie.\n", r);
        bs_decision_log(r, "captcha", "misconfigured", "-",
                        cfg->captcha_provider->name,
                        cookie_alg_name ? cookie_alg_name : "-",
                        "mint_failed", 0);
        return OK;
    }
    /* Second Set-Cookie: Max-Age=0 clear for the pending cookie so
     * the solved challenge can't be replayed. apr_table_add (not
     * setn) preserves the verified-cookie row from the install
     * helper above. */
    apr_table_add(r->err_headers_out, "Set-Cookie",
                  bs_clear_pending_cookie(r, cfg));
    apr_table_setn(r->headers_out, "Location",      safe_return);
    apr_table_setn(r->headers_out, "X-Botshield",   "captcha-ok");
    r->status = HTTP_SEE_OTHER;   /* 303 — POST→GET redirect */
    /* Decision log: verified = real OK, failopen = provider was
     * unavailable but we issued anyway. The v3 missing-score branch
     * also falls through here — detect via details carrying an ERROR/
     * TIMEOUT marker stored earlier. Simplest: re-check `result`. */
    const char *d_outcome = (result == BS_CAPTCHA_OK) ? "verified" : "failopen";
    const char *d_reason  = "-";
    if (result == BS_CAPTCHA_TIMEOUT) d_reason = "provider_timeout";
    else if (result == BS_CAPTCHA_ERROR) d_reason = "provider_error";
    bs_decision_log(r, "captcha", d_outcome, "-",
                    cfg->captcha_provider->name, cookie_alg_name,
                    d_reason, 0);
    return OK;
}


/* --- M8 captcha directive setters --- */

const char *bs_set_captcha_provider(cmd_parms *cmd, void *cfg_v,
                                           const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    const bs_captcha_provider *p = bs_find_provider(arg);
    if (!p) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaProvider: '%s' is not a recognized provider "
            "(known: turnstile, hcaptcha, recaptcha-v2, recaptcha-v3, "
            "friendly, geetest)", arg);
    }
    if (!p->implemented) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaProvider: '%s' is reserved in the registry "
            "but not built into this module", arg);
    }
    cfg->captcha_provider = p;
    return NULL;
}

const char *bs_set_captcha_site_key(cmd_parms *cmd, void *cfg_v,
                                           const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg || !*arg) {
        return "BotShieldCaptchaSiteKey: empty value";
    }
    /* Site keys are public; cap length so a misconfigured directive
     * can't wedge the interstitial. */
    if (strlen(arg) > 256) {
        return "BotShieldCaptchaSiteKey: value longer than 256 bytes";
    }
    /* Defense-in-depth: real provider site keys are alphanumerics
     * plus `_`, `-`, `.` (Turnstile, hCaptcha, reCAPTCHA, Friendly,
     * GeeTest all conform). The value gets embedded into JS string
     * literals, HTML attributes, and JSON in the interstitial render
     * paths (templates.c, silent.c). Charset-restricting it at
     * config time makes the embed sites trivially safe even though
     * the value is operator-controlled. */
    for (const char *p = arg; *p; p++) {
        unsigned char c = (unsigned char)*p;
        int ok = (c >= 'a' && c <= 'z')
              || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9')
              || c == '_' || c == '-' || c == '.';
        if (!ok) {
            return apr_psprintf(cmd->pool,
                "BotShieldCaptchaSiteKey: illegal character 0x%02x at "
                "offset %td. Allowed: alphanumerics, '_', '-', '.'.",
                c, p - arg);
        }
    }
    cfg->captcha_site_key = arg;
    return NULL;
}

/* Reuse the same mode-600 discipline as BotShieldSecretFile. */
const char *bs_set_captcha_secret_file(cmd_parms *cmd, void *cfg_v,
                                              const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;

    const char *buf = NULL;
    apr_size_t len = 0;
    const char *err = bs_load_secret_file(cmd, "BotShieldCaptchaSecretFile",
                                          arg, &buf, &len);
    if (err) return err;
    cfg->captcha_secret     = (const unsigned char *)buf;
    cfg->captcha_secret_len = len;
    return NULL;
}

const char *bs_set_captcha_timeout(cmd_parms *cmd, void *cfg_v,
                                          const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < BS_MIN_CAPTCHA_TIMEOUT ||
        v > BS_MAX_CAPTCHA_TIMEOUT) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaTimeout: '%s' must be an integer in %d..%d ms",
            arg, BS_MIN_CAPTCHA_TIMEOUT, BS_MAX_CAPTCHA_TIMEOUT);
    }
    cfg->captcha_timeout_ms = (int)v;
    return NULL;
}

/* Operator-tunable connect-phase timeout.
 * Default BS_CAPTCHA_CONNECT_TIMEOUT (250 ms) is tight for healthy
 * networks; operators on transient-loss links can bump it to avoid
 * fail-open on momentary connect blips. Same overall bound as the
 * full siteverify timeout. */
const char *bs_set_captcha_connect_timeout(cmd_parms *cmd,
                                                  void *cfg_v,
                                                  const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < 50 || v > BS_MAX_CAPTCHA_TIMEOUT) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaConnectTimeout: '%s' must be an integer in "
            "50..%d ms", arg, BS_MAX_CAPTCHA_TIMEOUT);
    }
    cfg->captcha_connect_timeout_ms = (int)v;
    return NULL;
}

/* `BotShieldRecaptchaV3MinScore 0.0..1.0` — threshold below which a
 * successful-but-low-score reCAPTCHA v3 verification is treated as a
 * rejection. Google's documented baseline is 0.5; operators tune down
 * (more permissive, fewer false rejections) or up (more strict) based
 * on observed traffic. */
const char *bs_set_recaptcha_v3_min_score(cmd_parms *cmd,
                                                 void *cfg_v,
                                                 const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    double v = strtod(arg, &end);
    if (!end || *end != '\0' || v < 0.0 || v > 1.0) {
        return apr_psprintf(cmd->pool,
            "BotShieldRecaptchaV3MinScore: '%s' must be a number in 0.0..1.0",
            arg);
    }
    cfg->recaptcha_v3_min_score = v;
    return NULL;
}

/* `BotShieldCaptchaExpectedHostname <host|off>` — hostname the
 * captcha provider echoed back in the siteverify response must
 * equal this value. Default = r->server->server_hostname (the
 * vhost name). The literal value `off` (case-insensitive) disables
 * the check — stored internally as an empty string — for
 * multi-origin deployments where the operator enforces binding
 * elsewhere. Apache's directive parser rejects bare "" as zero
 * args so the sentinel is the ergonomic escape.
 *
 * DNS hostname charset only — matches the cookie-domain setter's
 * policy. Rejects quotes / backslashes / whitespace / anything that
 * could confuse later string comparison or logging. */
const char *bs_set_captcha_expected_hostname(cmd_parms *cmd,
                                                    void *cfg_v,
                                                    const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg) return "BotShieldCaptchaExpectedHostname requires an argument";
    if (strcasecmp(arg, "off") == 0) {
        cfg->captcha_expected_hostname = "";
        return NULL;
    }
    if (strlen(arg) > 253) {
        return "BotShieldCaptchaExpectedHostname: longer than RFC 1035 limit";
    }
    for (const char *p = arg; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-')) {
            return apr_psprintf(cmd->pool,
                "BotShieldCaptchaExpectedHostname: '%s' contains "
                "a character outside [a-zA-Z0-9.-]", arg);
        }
    }
    cfg->captcha_expected_hostname = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* `BotShieldCaptchaExpectedAction <action|off>` — the action string
 * the client-side widget tagged the token with. Default =
 * "botshield" (matches the action embedded in the interstitial JS
 * for reCAPTCHA v3 and the Turnstile data-action attribute). The
 * literal value `off` disables the check. Restricted to printable
 * ASCII without whitespace or shell/quote metacharacters. */
const char *bs_set_captcha_expected_action(cmd_parms *cmd,
                                                  void *cfg_v,
                                                  const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg) return "BotShieldCaptchaExpectedAction requires an argument";
    if (strcasecmp(arg, "off") == 0) {
        cfg->captcha_expected_action = "";
        return NULL;
    }
    if (strlen(arg) > 64) {
        return "BotShieldCaptchaExpectedAction: max 64 characters";
    }
    for (const char *p = arg; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20 || c >= 0x7f || c == '"' || c == '\'' ||
            c == '\\' || c == ';' || c == '&') {
            return apr_psprintf(cmd->pool,
                "BotShieldCaptchaExpectedAction: '%s' contains "
                "an unsafe character", arg);
        }
    }
    cfg->captcha_expected_action = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* `BotShieldCaptchaCABundle <path>` — absolute path to a PEM
 * certificate bundle that libcurl will use when validating the
 * captcha-provider TLS certificate. Optional. When unset, libcurl
 * falls back to its compiled-in default (typically the system
 * `ca-certificates` bundle on Debian/Ubuntu/RHEL).
 *
 * Why this exists: stripped-down container images that omit the
 * `ca-certificates` package have no system CA store, so every
 * captcha siteverify hits CURLE_PEER_FAILED_VERIFICATION and the
 * captcha tier silently fails-open (occasional permissive better
 * than locking everyone out — but a permanent state of fail-open
 * is bad). Pointing this at the bundle the operator's image ships
 * fixes that without a config-time policy change. */
const char *bs_set_captcha_ca_bundle(cmd_parms *cmd,
                                            void *cfg_v,
                                            const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if (!arg || !*arg) {
        return "BotShieldCaptchaCABundle: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldCaptchaCABundle: path must be absolute";
    }
    struct stat st;
    if (stat(arg, &st) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaCABundle: cannot stat '%s'", arg);
    }
    if (!S_ISREG(st.st_mode)) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaCABundle: '%s' is not a regular file", arg);
    }
    cfg->captcha_ca_bundle = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* `BotShieldCaptchaRateLimit N` — verify-endpoint attempts per IP per
 * minute. 0 disables the rate limiter entirely (not recommended);
 * default BS_DEFAULT_CAPTCHA_RATE_LIMIT = 30. */
const char *bs_set_captcha_rate_limit(cmd_parms *cmd, void *cfg_v,
                                             const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < 0 || v > 1000) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaRateLimit: '%s' must be an integer 0..1000 "
            "(0 disables)", arg);
    }
    cfg->captcha_rate_limit = (int)v;
    return NULL;
}

/* `BotShieldCaptchaMaxInFlight N` — global cap on outstanding siteverify
 * calls. The underlying SHM counter is module-global, so if the
 * directive appears in more than one server_rec the last-parsed value
 * wins at runtime. Allowed anywhere (RSRC_CONF) so operators who only
 * have a vhost config can still set it; we don't pretend otherwise. */
const char *bs_set_captcha_max_inflight(cmd_parms *cmd, void *cfg_v,
                                               const char *arg)
{
    (void)cfg_v;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 1024) {
        return apr_psprintf(cmd->pool,
            "BotShieldCaptchaMaxInFlight: '%s' must be an integer 1..1024",
            arg);
    }
    scfg->captcha_max_inflight = (int)v;
    return NULL;
}
