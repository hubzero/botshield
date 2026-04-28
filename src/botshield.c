/*
 * mod_botshield — tiered bot detection and challenge module for Apache 2.4.
 *
 * Baseline tier: if the request has no valid _bs_verified cookie, return a
 * self-contained HTML interstitial with a proof-of-work challenge in inline
 * JavaScript. The client solves the PoW (SHA-256 with N leading hex zeros),
 * sets the cookie, and reloads — the same URL now passes through to the
 * real content.
 *
 * Security note on this baseline: the cookie is set client-side and the
 * server only matches it by format + timestamp window. A motivated attacker
 * can forge a cookie matching the regex; this is the "static verify page"
 * tier from hubzero/c-site-verify. Server-side HMAC signing (milestone M1)
 * closes that gap. The tier is still useful because it filters every bot
 * that can't run JS (most of them, in practice).
 *
 * Scope: directives are valid in server config, <VirtualHost>, <Directory>,
 * <Location>, <Files>, and their regex/match variants. Not .htaccess.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_file_io.h"
#include "apr_base64.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_thread_mutex.h"
#include "apr_atomic.h"
#include "unixd.h"
#include "mod_watchdog.h"
#include "mod_status.h"
#include "scoreboard.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "robots.h"    /* E2.2 — robots.txt parser/matcher */
#include "shm.h"       /* SHM tables, state save/load, headroom watchdog */
#include "crypto.h"    /* SHA-256, HMAC, AES-256-GCM, HKDF, hex codec */
#include "allowlist.h" /* E1 — UA classifier, CIDR list loader, builtin bots */
#include "metrics.h"   /* M9 — decision log, counters, Prometheus, mod_status */
#include "botshield.h" /* module-wide types: bs_dir_cfg, bs_server_cfg, ... */
#include "config.h"    /* module-config lifecycle (create/merge/post/child) */
#include "cookie.h"    /* GCM cookie envelope mint/verify, Cookie-header parser */
#include "challenge.h" /* M7 — challenge issuance, alg registry, bootstrap-sig */
#include "load.h"      /* E11 — load-aware throttling watchdog + state read */
#include "triggers.h"  /* E3/E4/E6/E7.3/E11.2 — trigger families */
#include "silent.h"    /* E17 — silent-tier embedded handlers */
#include "captcha.h"   /* M8 — provider registry, siteverify, pending cookie */
#include "bridge.h"    /* E5 + E8.2 — module ↔ app feedback / claims bridge */
#include "templates.h" /* challenge page widget + shell rendering */
#include "formcaptcha.h" /* E18 — inline form-captcha tier */
#include "score.h"     /* per-request score + flag-trigger walker */

/* Cross-cutting config defaults (BS_DEFAULT_*, BS_MAX_*, BS_UNSET,
 * cookie name strings, etc.) live in botshield.h so every TU that
 * needs them gets them via the umbrella include. */

/* Challenge protocol (M4.1 + M7) —
 *   Wire format (embedded inline in the interstitial, JSON):
 *     { v, alg, salt, nonce, difficulty, expires_at,
 *       score, flags, passes_silent, passes_form, passes_captcha,
 *       challenged_at, auto, signature }
 *   Canonical HMAC input (deterministic, pipe-delimited ASCII):
 *     "v|alg|salthex|noncehex|difficulty|expires_at
 *      |score|flags|pass_s|pass_f|pass_c|challenged_at|auto"
 *   Cookie payload = base64( canonical || "|" || sighex || "|" || counter )
 *   — a single base64 blob the server can parse by splitting on '|',
 *     no JSON parser required.
 *
 *   `auto` is the silent-tier (M7) marker: 1 means the challenge was served
 *   as a no-click auto-submit splash, 0 means the form-PoW interstitial.
 *   HMAC-covered so an accepted cookie tells the server which tier actually
 *   served it — used to pick passes_silent vs passes_form and the matching
 *   forgiveness amount on verify.
 *
 * Keep in sync with the JS worker when the template ships the wire bits. */
/* BS_PROTOCOL_VERSION, BS_SALT_BYTES, BS_NONCE_BYTES, BS_GCM_COUNTER_SEP
 * live in botshield.h with the bs_challenge / bs_rep_state types they
 * frame.  BS_SIG_BYTES, BS_COOKIE_ALG_GCM, BS_GCM_NONCE_LEN, BS_GCM_TAG_LEN
 * live in crypto.h alongside the primitives that produce them. */

/* bs_parse_int_bounded / bs_parse_uint32_bounded / bs_parse_int64_bounded
 * forward decls live in botshield.h (cross-TU — cookie.c uses them in
 * the canonical-form parser). Defined later in this file alongside the
 * other bounded numeric helpers. */

/* bs_score_add is now declared cross-file in botshield.h. The
 * definition lives later in this file alongside bs_get_score. */



/* BS_FLAG_* bit definitions live in botshield.h alongside the other
 * cross-cutting types. Used here, in triggers.c (default path-trigger
 * action), and in bridge.c (app-feedback flag mapping). */


/* enum bs_help_mode + BS_DEFAULT_HELP_MODE now in botshield.h. */

/* BS_DEFAULT_SCORE_*, BS_SCORE_MAX_REASONS, BS_PENALTY_* are now in
 * botshield.h since multiple files (config.c, score.c, bs_handler)
 * reference them. */





/* BS_ROBOTS_REFRESH_UNSET / _DEFAULT now declared in botshield.h. */


int bs_effective_int(int value, int fallback)
{
    return (value == BS_UNSET) ? fallback : value;
}

/* ======================================================================
 * Challenge struct, algorithm registry, issue/verify.
 * ====================================================================== */

/* Bounded integer parser for pre-HMAC cookie fields (security review
 * #2). atoi() and strtoul(..., NULL, 10) both invoke undefined
 * behavior on overflow per C11 §7.22.1 — atoi because the result
 * doesn't fit in int, strtoul because we never check errno. Our
 * ASan/UBSan fuzz can't reliably catch that because the dangerous
 * work happens inside libc, not in instrumented project code.
 *
 * Returns 1 on a clean parse within [min_val, max_val]; 0 otherwise.
 * The out pointer is left untouched on failure so callers can treat
 * 0-returns as "reject this cookie" without dancing around partial
 * state. Accepts optional leading + only; negative values must fall
 * within min_val to be accepted (no underflow tricks).
 *
 * max_len is a hard cap on the digit-string length — rejects gigantic
 * inputs before they reach strtol. A 64-bit long can hold up to 19
 * decimal digits, so any cookie field longer than that is obviously
 * junk and we bail without invoking libc at all. */
int bs_parse_int_bounded(const char *s,
                         long min_val, long max_val,
                         apr_size_t max_len,
                         long *out)
{
    if (!s || !*s) return 0;
    apr_size_t len = strlen(s);
    if (len > max_len) return 0;

    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0)        return 0;  /* ERANGE or other libc complaint */
    if (!end || *end != '\0') return 0;  /* trailing junk */
    if (v < min_val || v > max_val) return 0;
    *out = v;
    return 1;
}

/* 32-bit unsigned variant for the flags field. strtoul also invokes
 * UB on overflow if errno isn't checked — same hardening. */
int bs_parse_uint32_bounded(const char *s,
                            apr_size_t max_len,
                            apr_uint32_t *out)
{
    if (!s || !*s) return 0;
    if (strlen(s) > max_len) return 0;

    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0)        return 0;
    if (!end || *end != '\0') return 0;
    if (v > UINT32_MAX)    return 0;
    *out = (apr_uint32_t)v;
    return 1;
}

/* int64 variant for expires_at / challenged_at (apr_time_t seconds).
 * Same shape; max_len caps at 19 (largest int64 decimal expansion). */
int bs_parse_int64_bounded(const char *s,
                           apr_int64_t min_val,
                           apr_int64_t max_val,
                           apr_int64_t *out)
{
    if (!s || !*s) return 0;
    if (strlen(s) > 19) return 0;

    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno != 0)        return 0;
    if (!end || *end != '\0') return 0;
    if ((apr_int64_t)v < min_val || (apr_int64_t)v > max_val) return 0;
    *out = (apr_int64_t)v;
    return 1;
}

/* Challenge issuance (bs_issue_challenge), the canonical-form HMAC
 * input (bs_challenge_canonical), the PoW algorithm registry, the
 * challenge-as-JSON serializer for the M7 interstitial, and the
 * MEDIUM #2 bootstrap-binding helpers all live in challenge.c
 * (see challenge.h). */

/* Captcha provider registry + libcurl-backed siteverify shim live
 * in captcha.c (see captcha.h). bs_find_provider, bs_captcha_siteverify,
 * the M8.1 pending-cookie pair, and the captcha-verify request
 * handler are all reachable through that header. */

/* Parse r->useragent_ip into a 16-byte network-order buffer. IPv4
 * becomes v6-mapped (::ffff:a.b.c.d) so the table is keyed uniformly.
 * Returns 1 on success, 0 if the string is unparseable. */
int bs_parse_client_ip(const char *ip_str, unsigned char out[16])
{
    if (!ip_str || !*ip_str) return 0;
    struct in_addr v4;
    if (inet_pton(AF_INET, ip_str, &v4) == 1) {
        memset(out, 0, 10);
        out[10] = 0xff; out[11] = 0xff;
        memcpy(out + 12, &v4, 4);
        return 1;
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip_str, &v6) == 1) {
        memcpy(out, &v6, 16);
        return 1;
    }
    return 0;
}

/* Apply an IPv6 prefix mask in-place so same-subnet v6 clients collapse
 * to one key in the flagged-IP table. This bounds the attacker's ability
 * to rotate through a /64 allocation to shed flags.
 *
 * IPv4 (carried as v6-mapped, ::ffff:a.b.c.d) is never masked: the v4
 * economy is per-/32, not per-/24.
 *
 * prefix_bits == 128 or prefix_bits <= 0 → no-op. */
void bs_mask_ipv6_prefix(unsigned char ip[16], int prefix_bits)
{
    static const unsigned char v4mapped[12] =
        { 0,0,0,0, 0,0,0,0, 0,0, 0xff,0xff };
    if (memcmp(ip, v4mapped, 12) == 0) return;       /* v4-in-v6: leave alone */
    if (prefix_bits <= 0 || prefix_bits >= 128) return;

    int full_bytes  = prefix_bits / 8;
    int extra_bits  = prefix_bits % 8;
    if (extra_bits) {
        unsigned char keep = (unsigned char)(0xff << (8 - extra_bits));
        ip[full_bytes] &= keep;
        full_bytes++;
    }
    for (int i = full_bytes; i < 16; i++) ip[i] = 0;
}

/* bs_watchdog_save_cb forward decl now lives in config.h. */
/* The cookie envelope (mint/verify), the Cookie-header parser, and
 * the cross-file getters now live in cookie.h. The bootstrap-sig
 * pair lives in challenge.h. bs_verify_bootstrap_sig is private to
 * silent.c. */


/* ======================================================================
 * E2.1 — Policy enforcement: rate limiting + path-based blocks
 *
 * Two feature families sharing one cohort definition:
 *
 *   BotShieldRateLimit <name> <budget> <per> <ua> <ipspec>
 *   BotShieldBlockPath <name> <path-glob> <ua> <ipspec>
 *
 * A "cohort" is a (ua-substring?, ipspec?) predicate pair. The ipspec
 * reuses E1's polymorphic shape — omitted / explicit path / '*' / inline
 * CIDRs — via bs_allow_push_cidr + bs_allow_load_ranges{,_from_string}.
 * Cohort matching at request time is UA-match AND IP-match, with '*'
 * as "any" on either axis (but not both — that would rate-limit or
 * block every request, which is almost always a mistake and the setter
 * rejects it at config time).
 *
 * Storage:
 *  - Config: scfg->rate_limits / scfg->block_paths hashes, keyed by
 *    name. Merged across main/vhost scope via bs_merge_server_cfg.
 *  - Runtime: rate counters live in SHM as a flat slot array
 *    (bs_shm.rate_counters[]). Each bs_rate_limit_entry's shm_slot
 *    is an index assigned in post_config. Fixed-window counter model
 *    with atomic CAS updates — approximate rather than exact sliding
 *    window, but that's the right trade for a rate limiter (smaller
 *    code, no per-bucket mutex, burst-at-boundary is harmless here
 *    because the downstream score_add hook still records it).
 *
 * On trip:
 *  - Block-path hit → 403 + bs_score_add(+100, "block-path:<name>").
 *  - Rate-limit exceeded → 429 + Retry-After: <seconds remaining in
 *    window> + bs_score_add(+50, "rate-limit-exceeded:<name>").
 * ====================================================================== */


/* Inspect a directive's (ua, ipspec) arg pair and populate a
 * bs_cohort. Returns NULL on success, or an Apache directive-error
 * string. Ranges resolution is deferred to post_config so we can
 * use pconf rather than cmd->temp_pool. */

/* Path-pattern matching for BotShieldPathTrigger and BotShieldBlockPath
 * is the RFC 9309 matcher promoted from src/robots.c (bs_path_match).
 * The earlier v1 placeholder here that only handled <literal>,
 * <literal>*, and <literal>$ shapes was retired once the RFC 9309
 * matcher landed — its own comment flagged itself as temporary. One
 * path matcher across the codebase now. */

/* Surface a NOTICE at config-load when a pattern contains a non-
 * trailing '*'. Under the retired v1 matcher those characters were
 * treated as literal bytes (which essentially never matched any
 * URI). Under the RFC 9309 matcher they're proper wildcards. The
 * behavior change is desired for operators who intended wildcards;
 * for operators who fat-fingered a '*' the warning gives them a
 * heads-up so the new match doesn't surprise them. The trailing '*'
 * (or '*' followed only by '$') is the documented v1 shape and
 * stays silent — its behavior didn't change. */
void bs_path_pattern_warn_middle_star(cmd_parms *cmd,
                                      const char *directive,
                                      const char *name,
                                      const char *pattern)
{
    const char *star = strchr(pattern, '*');
    if (!star) return;
    /* Find the last '*'. Anything past the last '*' that isn't
     * empty or "$" means there's content after a wildcard, i.e.
     * the wildcard is non-trailing. */
    const char *last_star = star;
    for (const char *q = star + 1; *q; q++) {
        if (*q == '*') last_star = q;
    }
    const char *tail = last_star + 1;
    if (*tail == '\0') return;        /* trailing '*' — v1 shape */
    if (tail[0] == '$' && tail[1] == '\0') return; /* '*$' — v1 shape */
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, cmd->server,
        "mod_botshield: %s '%s' pattern '%s' contains a non-trailing "
        "'*'; interpreted per RFC 9309 (matches any byte sequence at "
        "this position). The retired v1 matcher treated middle '*' "
        "as a literal byte. If the literal was intended, this rule "
        "will no longer match.",
        directive, name, pattern);
}

/* Cohort match at request time. Returns 1 when this request belongs
 * to the cohort. UA match is case-insensitive via strcasestr to
 * match the directive's documented contract. strcasestr is a GNU
 * extension, already relied on elsewhere in the module on the
 * platforms we target (Linux/FreeBSD/macOS). */
static int bs_cohort_matches(const bs_cohort *c,
                             const char *ua, request_rec *r)
{
    if (!c->ua_any) {
        if (!ua || !c->ua_pattern || !strcasestr(ua, c->ua_pattern)) return 0;
    }
    if (!c->ip_any) {
        if (!c->ranges || !bs_allow_ip_in_ranges(c->ranges, r)) return 0;
    }
    return 1;
}

/* Fixed-window admission test. Returns 1 if the request fits under
 * budget (count was incremented), 0 if the window is full.
 *
 * Under pathological contention the CAS loop bounces; cap the retry
 * count and err on admitting rather than emitting spurious 429s.
 *
 * Security review MEDIUM #4 — the prior shape did the window-roll
 * via two separate stores (CAS window_start_sec, then plain
 * __atomic_store_n on count = 1). Between those two operations,
 * another thread could land an increment via the bottom-of-loop
 * count-CAS path; the count=1 store then wiped that increment,
 * yielding a slightly-larger-than-budget window straddling the
 * rollover. Pack window_start_sec and count into a single u64 and
 * CAS them together — same shape as bs_cv_counter_bump. The
 * struct is already laid out 8-byte-packed for this. Each CAS
 * either rolls the window AND sets count atomically, or
 * increments count alone — no torn intermediate visible to
 * other threads. */
static int bs_rate_counter_admit(bs_rate_counter *slot,
                                 apr_uint32_t budget,
                                 apr_uint32_t window_sec)
{
    _Static_assert(sizeof(bs_rate_counter) == sizeof(apr_uint64_t),
                   "bs_rate_counter must be 8 bytes for u64 CAS");
    apr_uint64_t *p64 = (apr_uint64_t *)slot;
    apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
    for (int i = 0; i < 32; i++) {
        apr_uint64_t observed = __atomic_load_n(p64, __ATOMIC_RELAXED);
        bs_rate_counter snap;
        memcpy(&snap, &observed, sizeof(snap));
        apr_uint64_t next;
        bs_rate_counter cand;
        if (now < snap.window_start_sec ||
            now - snap.window_start_sec >= window_sec) {
            cand.count            = 1;
            cand.window_start_sec = now;
        } else {
            if (snap.count >= budget) return 0;
            cand.count            = snap.count + 1;
            cand.window_start_sec = snap.window_start_sec;
        }
        memcpy(&next, &cand, sizeof(next));
        if (__atomic_compare_exchange_n(p64, &observed, next,
                0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            return 1;
        }
        /* CAS lost — re-read */
    }
    return 1;
}

/* Is this UA a plausible crawler for the purpose of applying
 * robots.txt User-agent: * rules in heuristic mode? See PLAN.md for
 * the rationale — the point is to avoid rate-limiting or blocking
 * real users' browsers, which never read robots.txt and so should
 * never be subject to its rules. */
static int bs_ua_is_crawler_candidate(const char *ua)
{
    if (!ua || !*ua) return 0;

    int has_bot_token =
           strcasestr(ua, "bot")    != NULL
        || strcasestr(ua, "crawl")  != NULL
        || strcasestr(ua, "spider") != NULL
        || strcasestr(ua, "fetch")  != NULL
        || strcasestr(ua, "slurp")  != NULL;
    if (has_bot_token) return 1;

    /* Bot-less UA that starts with a real-browser prefix: skip.
     * Everything else (curl/python/etc.) defaults to candidate —
     * those tools are used by scrapers and rarely by humans. */
    static const char *const browser_prefixes[] = {
        "Mozilla/", "Opera/", "Firefox/", "Edge/", "Safari/", NULL
    };
    for (int i = 0; browser_prefixes[i]; i++) {
        apr_size_t plen = strlen(browser_prefixes[i]);
        if (strncasecmp(ua, browser_prefixes[i], plen) == 0) return 0;
    }
    return 1;
}

/* BS_CK_STATE_NOTE / _VERIFIED / _MISSING / _INVALID are now
 * declared cross-file in botshield.h — set by bs_handler after the
 * `_bs_verified` verification pass; consumed by triggers.c's
 * cookie-trigger evaluator and by bs_check_policy below. */


/* Request-time E2.1 + E2.2 + E3 + E4 + E6 check. Return values:
 *   OK                     — no rule fired; continue to heuristics.
 *   DECLINED               — a trigger with status=pass fired; the
 *                            bs_handler short-circuits to DECLINED
 *                            so the real handler runs, with the
 *                            flag-IP / log side effects already
 *                            applied.
 *   any other HTTP_* code  — short-circuit with that status. The
 *                            handler returns it directly so Apache's
 *                            ErrorDocument machinery can render the
 *                            response body.
 *
 * Order:
 *   1. E4 cookie triggers (declaration order; pass accumulates,
 *      first non-pass short-circuits).
 *   2. E6 env-var triggers (declaration order, first match wins).
 *   3. E3 path triggers (declaration order, first match wins).
 *   4. Directive block_paths (declaration order, first match wins).
 *   5. robots.txt Disallow (if configured).
 *   6. Directive rate_limits.
 *   7. robots.txt Crawl-delay (if configured).
 *
 * Cookie triggers run first so reputation signals always land on
 * the decision log, even when a later rule short-circuits. Env
 * triggers run next — another reputation/policy shape driven by
 * upstream Apache modules (SetEnvIf / ModSecurity / etc.). Path
 * triggers are the most specific per-path intent the operator
 * can write — a trigger on `/.env` should win against any
 * cohort-scoped block-path that also happens to match. Operator
 * directives always get first say in each family after that;
 * robots.txt fills in where the operator hasn't declared
 * explicit rules.
 *
 * Precedence divergences from E3 (strict first-match-wins, no
 * accumulation) worth keeping straight:
 *  - E4 cookies: credit/penalty always apply (even under
 *    status=pass); pass matches accumulate across triggers;
 *    first non-pass trigger short-circuits the walk.
 *  - E6 env: credit/penalty always apply (E4-style), but the
 *    family uses strict first-match-wins — a pass match ends
 *    the env-trigger loop without considering later entries. */
static int bs_check_policy(request_rec *r)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg) return OK;

    /* E4 — cookie triggers. Declaration order; **pass triggers
     * accumulate, first non-pass trigger short-circuits the walk**.
     * That split exists to make the canonical layered-reputation
     * pattern work — `app-session credit=15` + `app-auth
     * credit=40` should stack to a 55-point credit when both
     * cookies are present, not lose the second credit to first-
     * match-wins. Contrast E3 path triggers, which are strict
     * first-match-wins with no accumulation: paths are one-off
     * matches, cookies are ongoing-state signals that naturally
     * compose.
     *
     * Runs before E3 path triggers so reputation signals land on
     * the decision log even when a later rule short-circuits.
     *
     * Divergences from E3 to keep straight while reading this loop:
     *  1. credit/penalty apply regardless of status (even under
     *     status=pass, because the cookie IS this request's state).
     *  2. pass matches don't end the walk — they accumulate. */
    if (scfg->cookie_triggers && scfg->cookie_triggers->nelts > 0) {
        apr_table_t *cmap = bs_parse_cookies_once(r);
        const char *bs_state = apr_table_get(r->notes, BS_CK_STATE_NOTE);
        for (int i = 0; i < scfg->cookie_triggers->nelts; i++) {
            bs_cookie_trigger_entry *c = APR_ARRAY_IDX(
                scfg->cookie_triggers, i, bs_cookie_trigger_entry *);
            if (!bs_cookie_pred_match(c, cmap, scfg->session_names,
                                      bs_state)) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_COOKIE, &c->action,
                "cookie-trigger", c->name);
            /* Cookie family: BS_TEXEC_PASS_CONTINUE keeps accumulating
             * credits; BS_TEXEC_STATUS short-circuits. PASS_BREAK /
             * PASS_DECLINE aren't produced for this family. */
            if (o == BS_TEXEC_STATUS) return c->action.status_code;
        }
    }

    /* E6 — env-var triggers. Declaration order, first match wins.
     * Gate: once per client-visible request. `ap_is_initial_req` is
     * (r->main == NULL && r->prev == NULL) per httpd's protocol.c,
     * which both excludes subrequests (where producer env
     * propagation differs) and blocks re-application on internal-
     * redirect legs (ErrorDocument, RewriteRule-without-R) where
     * the env producer would fire a second time and double-count
     * score/flag. The header docs only advertise the main-vs-
     * subrequest distinction, so we restate the full intent here.
     * Reads r->subprocess_env, the table SetEnvIf / RewriteRule
     * [E=...] / BrowserMatch / ModSecurity v2 setenv all populate
     * at phases that run before the handler. */
    if (ap_is_initial_req(r)
        && scfg->env_triggers && scfg->env_triggers->nelts > 0) {
        for (int i = 0; i < scfg->env_triggers->nelts; i++) {
            bs_env_trigger_entry *t = APR_ARRAY_IDX(
                scfg->env_triggers, i, bs_env_trigger_entry *);
            const char *v = apr_table_get(r->subprocess_env,
                                          t->env_name);
            int matched = 0;
            switch (t->pred_kind) {
            case BS_EP_NAMED_PRESENT:
                matched = (v != NULL);
                break;
            case BS_EP_NAMED_ABSENT:
                matched = (v == NULL);
                break;
            case BS_EP_NAMED_EQ:
                matched = (v != NULL
                        && t->env_value != NULL
                        && strcmp(v, t->env_value) == 0);
                break;
            }
            if (!matched) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_ENV, &t->action,
                "env-trigger", t->name);
            /* Env family: BS_TEXEC_PASS_BREAK ends the loop (env
             * signals are discrete; no accumulation). STATUS
             * short-circuits. */
            if (o == BS_TEXEC_STATUS) return t->action.status_code;
            if (o == BS_TEXEC_PASS_BREAK) break;
        }
    }

    /* E11.2 — load triggers. Match on the global cached load state
     * (BS_LOAD_NORMAL/WARM/HOT). First-match-wins; alternative-
     * specificity rules (state>=warm vs state=hot) are stacked by
     * declaration order with the more specific one declared first. */
    if (scfg->load_triggers && scfg->load_triggers->nelts > 0) {
        bs_load_state cur = bs_load_current();
        for (int i = 0; i < scfg->load_triggers->nelts; i++) {
            bs_load_trigger_entry *t = APR_ARRAY_IDX(
                scfg->load_triggers, i, bs_load_trigger_entry *);
            int matched = 0;
            switch (t->pred_kind) {
            case BS_LP_EQ: matched = (cur == t->target_state); break;
            case BS_LP_GE: matched = (cur >= t->target_state); break;
            }
            if (!matched) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_LOAD, &t->action,
                "load-trigger", t->name);
            if (o == BS_TEXEC_STATUS) return t->action.status_code;
            if (o == BS_TEXEC_PASS_BREAK) break;
        }
    }

    /* E3 — path triggers. First match wins; no accumulation. */
    if (scfg->path_triggers && scfg->path_triggers->nelts > 0) {
        for (int i = 0; i < scfg->path_triggers->nelts; i++) {
            bs_path_trigger_entry *t = APR_ARRAY_IDX(
                scfg->path_triggers, i, bs_path_trigger_entry *);
            if (!bs_path_match(t->path_pattern, r->uri)) continue;
            bs_trigger_exec_outcome o = bs_apply_trigger_action(
                r, scfg, BS_TFAMILY_PATH, &t->action,
                "path-trigger", t->name);
            /* Path family: PASS decays to DECLINED (handler lets
             * the real Apache response through); STATUS emits
             * Location/code short-circuit. CONTINUE/BREAK aren't
             * produced for this family. */
            if (o == BS_TEXEC_PASS_DECLINE) return DECLINED;
            if (o == BS_TEXEC_STATUS)       return t->action.status_code;
        }
    }

    const char *ua = apr_table_get(r->headers_in, "User-Agent");

    /* Block paths first: if the request would be 403ed anyway there's
     * no point charging it a token from a rate bucket it's also in.
     * Ordered-array iteration — first match wins; declaration order
     * is the precedence. E12: a matched rule in observe mode (or
     * any matched rule when global shadow_mode is on) logs
     * `would-block-path:<name>` instead of returning 403, and the
     * walk continues so subsequent rules still get their say. */
    int global_shadow = (scfg->shadow_mode == 1);
    if (scfg->block_paths && scfg->block_paths->nelts > 0) {
        for (int i = 0; i < scfg->block_paths->nelts; i++) {
            bs_block_path_entry *e = APR_ARRAY_IDX(
                scfg->block_paths, i, bs_block_path_entry *);
            if (!bs_path_match(e->path_pattern, r->uri)) continue;
            if (!bs_cohort_matches(&e->cohort, ua, r)) continue;
            int observe = global_shadow || (e->mode == BS_TMODE_OBSERVE);
            if (observe) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "block-path:", e->name,
                                ":observe", NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->block_path_observed_total,
                        1, __ATOMIC_RELAXED);
                }
                continue;
            }
            bs_score_add(r, BS_PENALTY_BLOCK_PATH, 3600,
                apr_pstrcat(r->pool, "block-path:", e->name, NULL));
            if (bs_shm.metrics) {
                __atomic_fetch_add(&bs_shm.metrics->block_path_hit_total,
                                   1, __ATOMIC_RELAXED);
            }
            return HTTP_FORBIDDEN;
        }
    }

    /* E2.2 — robots.txt Disallow enforcement. Queried once for
     * (ua, path); the result also carries the Crawl-delay we'll use
     * below, so stash it.
     *
     * Atomic load of scfg->robots so we never see a half-swapped
     * state bundle. The bundle's fields are immutable after publish,
     * and the previous bundle is held one refresh cycle before its
     * pool is reclaimed — see bs_robots_refresh. */
    bs_robots_state *rstate =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    robots_match rmatch = { -1, 0, 1, 0, NULL };
    int robots_apply = 0;
    if (rstate && rstate->doc && ua) {
        robots_query(rstate->doc, ua, r->uri, &rmatch);
        if (rmatch.group_idx >= 0) {
            robots_apply = 1;
            if (rmatch.is_wildcard) {
                switch (scfg->robots_wildcard_scope) {
                case BS_ROBOTS_WILDCARD_OFF:
                    robots_apply = 0;
                    break;
                case BS_ROBOTS_WILDCARD_HEURISTIC:
                    if (!bs_ua_is_crawler_candidate(ua)) robots_apply = 0;
                    break;
                case BS_ROBOTS_WILDCARD_STRICT:
                default:
                    /* apply regardless */
                    break;
                }
            }
        }
    }
    if (robots_apply && !rmatch.allowed) {
        bs_score_add(r, BS_PENALTY_BLOCK_PATH, 3600,
            apr_pstrcat(r->pool, "robots-block:",
                        rmatch.group_name ? rmatch.group_name : "?", NULL));
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->block_path_hit_total,
                               1, __ATOMIC_RELAXED);
        }
        return HTTP_FORBIDDEN;
    }

    /* A directive rate-limit cohort that MATCHES this request is
     * authoritative for it — operator policy overrides robots.txt in
     * the rate-limit family. If a directive matched, we skip the
     * robots.txt crawl-delay check below regardless of whether the
     * directive admitted or tripped. */
    int directive_rate_matched = 0;
    if (scfg->rate_limits && scfg->rate_limits->nelts > 0) {
        bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
        unsigned char client_ip[16];
        int have_ip = bs_parse_client_ip(r->useragent_ip, client_ip);
        if (have_ip) bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
        apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
        for (int i = 0; i < scfg->rate_limits->nelts; i++) {
            bs_rate_limit_entry *e = APR_ARRAY_IDX(
                scfg->rate_limits, i, bs_rate_limit_entry *);
            if (!bs_cohort_matches(&e->cohort, ua, r)) continue;
            directive_rate_matched = 1;
            if (e->shm_slot < 0 || !counters) continue;

            /* E12 — observe mode (per-rule or global shadow_mode).
             * The counter still ticks (so `would-rate-limit` volume
             * answers the operator's "what would this fire?"
             * question accurately), but over-budget hits log
             * `rate-limit-exceeded:<name>:observe` instead of
             * returning 429. E9 escalation is also fully suppressed
             * — we don't bump strikes, and any pre-existing
             * escalation state is ignored for this rule under
             * observe. */
            int observe = global_shadow || (e->mode == BS_TMODE_OBSERVE);

            if (!observe && e->escalate && have_ip
                && bs_strike_check_escalated(client_ip,
                                             (apr_uint32_t)e->shm_slot,
                                             now_t, scfg->ns_id)) {
                /* E9 — escalation gate. Active only outside observe
                 * mode; observe must not enforce. */
                bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                    apr_pstrcat(r->pool, "rate-limit-abuse:",
                                e->name, NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_exceeded_total,
                        1, __ATOMIC_RELAXED);
                }
                return e->escalate->status_code;
            }

            if (bs_rate_counter_admit(&counters[e->shm_slot],
                                      e->budget, e->window_sec)) {
                continue;
            }
            /* Over budget. */
            if (observe) {
                bs_score_add(r, 0, 0,
                    apr_pstrcat(r->pool, "rate-limit-exceeded:",
                                e->name, ":observe", NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_observed_total,
                        1, __ATOMIC_RELAXED);
                }
                continue;
            }
            /* Enforce: Retry-After = seconds remaining in window. */
            apr_uint32_t win = __atomic_load_n(
                &counters[e->shm_slot].window_start_sec, __ATOMIC_RELAXED);
            apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
            apr_uint32_t retry = (now >= win && now - win < e->window_sec)
                                  ? e->window_sec - (now - win) : 1;
            apr_table_setn(r->err_headers_out, "Retry-After",
                apr_psprintf(r->pool, "%u", retry));
            bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                apr_pstrcat(r->pool, "rate-limit-exceeded:",
                            e->name, NULL));
            if (bs_shm.metrics) {
                __atomic_fetch_add(&bs_shm.metrics->rate_limit_exceeded_total,
                                   1, __ATOMIC_RELAXED);
            }
            /* E9 — strike accounting. Record this 429 under the
             * (ip, rule) entry; if the strike count crosses the
             * threshold inside the per-window, log the operator's
             * tag once for fail2ban handoff. The threshold-crossing
             * request itself returns 429; subsequent ones promote
             * to status_code via bs_strike_check_escalated above. */
            if (e->escalate && have_ip) {
                int crossed = bs_strike_record_429(r, client_ip,
                    (apr_uint32_t)e->shm_slot,
                    e->escalate->per_sec, e->escalate->strikes,
                    e->escalate->ttl_sec,
                    now_t, scfg->ns_id);
                if (crossed) {
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                        "mod_botshield: rate-limit-abuse threshold "
                        "crossed for '%s' from ip=%s; escalating to "
                        "status=%d for %ds%s%s%s",
                        e->name, r->useragent_ip,
                        e->escalate->status_code, e->escalate->ttl_sec,
                        e->escalate->log_tag ? " tag=\"" : "",
                        e->escalate->log_tag ? e->escalate->log_tag : "",
                        e->escalate->log_tag ? "\"" : "");
                    bs_set_trigger_tag(r, e->escalate->log_tag);
                }
            }
            return HTTP_TOO_MANY_REQUESTS;
        }
    }

    /* E2.2 — robots.txt Crawl-delay enforcement. Budget=1 per
     * Crawl-delay seconds; slot assignment is held inside rstate's
     * bundle (allocated at post_config + preserved by name across
     * refreshes). Skipped when a directive rate-limit already
     * matched this request: operator policy is authoritative in the
     * rate family. */
    if (robots_apply && rmatch.crawl_delay_sec > 0
        && !directive_rate_matched
        && rstate && rstate->slot_by_group_idx
        && rmatch.group_idx < robots_group_count(rstate->doc)) {
        int slot_idx = rstate->slot_by_group_idx[rmatch.group_idx];
        bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
        if (slot_idx >= 0 && counters) {
            bs_rate_counter *slot = &counters[slot_idx];
            if (!bs_rate_counter_admit(slot, 1,
                    (apr_uint32_t)rmatch.crawl_delay_sec)) {
                apr_uint32_t win = __atomic_load_n(
                    &slot->window_start_sec, __ATOMIC_RELAXED);
                apr_uint32_t now =
                    (apr_uint32_t)apr_time_sec(apr_time_now());
                apr_uint32_t wsec =
                    (apr_uint32_t)rmatch.crawl_delay_sec;
                apr_uint32_t retry = (now >= win && now - win < wsec)
                                      ? wsec - (now - win) : 1;
                apr_table_setn(r->err_headers_out, "Retry-After",
                    apr_psprintf(r->pool, "%u", retry));
                bs_score_add(r, BS_PENALTY_RATE_LIMIT, 3600,
                    apr_pstrcat(r->pool, "robots-rate:",
                        rmatch.group_name ? rmatch.group_name : "?",
                        NULL));
                if (bs_shm.metrics) {
                    __atomic_fetch_add(
                        &bs_shm.metrics->rate_limit_exceeded_total,
                        1, __ATOMIC_RELAXED);
                }
                return HTTP_TOO_MANY_REQUESTS;
            }
        }
    }

    return OK;
}

/* ======================================================================
 * E2.2.2 — live-refresh of robots.txt via mod_watchdog
 *
 * bs_robots_load(): stat + (conditionally) parse + publish. Runs both
 * at post_config (initial load) and at each watchdog tick (refresh).
 * When the source file's mtime is unchanged, it's a cheap no-op.
 *
 * Atomic-swap model: active state lives in scfg->robots (read with
 * __atomic_load_n on the request path). When a fresh doc is built,
 * we atomically publish it, push the outgoing state into
 * scfg->robots_pending, and destroy whatever pool was in the
 * previous pending slot. That gives each displaced doc at least one
 * refresh interval of grace — more than enough for any in-flight
 * request to finish reading pointers into its pool.
 *
 * Slot stability: SHM rate-counter slots are keyed by group name via
 * scfg->robots_slot_by_name, which lives in pconf and survives
 * refresh. A group whose name reappears in the new doc keeps its
 * existing slot (and its in-flight Crawl-delay window); a genuinely
 * new group gets a fresh slot from the reserved pool. The map never
 * shrinks — operators who delete a crawler from robots.txt leave a
 * stale entry, which is harmless (no lookup targets it). If they
 * re-add it, the old slot is reused.
 * ====================================================================== */
apr_status_t bs_robots_load(server_rec *sv, bs_server_cfg *scfg,
                            apr_pool_t *pconf)
{
    if (!scfg || !scfg->robots_txt_path) return APR_EINVAL;

    /* Stat first — if mtime is unchanged since the active doc was
     * parsed, there's nothing to do. This is the common case on
     * every refresh tick. */
    apr_finfo_t fi;
    apr_status_t rv = apr_stat(&fi, scfg->robots_txt_path,
                               APR_FINFO_MTIME | APR_FINFO_SIZE, pconf);
    if (rv != APR_SUCCESS) {
        char errbuf[128];
        apr_strerror(rv, errbuf, sizeof(errbuf));
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, sv,
            "mod_botshield: robots.txt %s stat failed (%s); "
            "keeping previous state",
            scfg->robots_txt_path, errbuf);
        return rv;
    }

    bs_robots_state *cur =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    if (cur && cur->mtime == fi.mtime) {
        return APR_SUCCESS;
    }

    /* Build the new state in a fresh subpool we control. Destroying
     * this subpool later frees the doc and its slot map in one go,
     * without touching anything else in pconf. */
    apr_pool_t *npool = NULL;
    apr_pool_create(&npool, pconf);

    robots_doc *doc = NULL;
    const char *parse_err = NULL;
    rv = robots_parse_file(npool, scfg->robots_txt_path,
                           &doc, &parse_err);
    if (rv != APR_SUCCESS || !doc) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, sv,
            "mod_botshield: robots.txt %s parse failed (%s); "
            "keeping previous state",
            scfg->robots_txt_path,
            parse_err ? parse_err : "unknown error");
        apr_pool_destroy(npool);
        return rv;
    }

    /* Security review LOW #6 — surface truncated lines (the parser
     * silently caps any line > BOTSHIELD_ROBOTS_MAX_LINE). The
     * documented contract said operators "see a warning through
     * the summary log"; this emits that warning. */
    int n_truncated = robots_doc_truncated_lines(doc);
    if (n_truncated > 0) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: robots.txt %s: %d line(s) exceeded the "
            "parser line limit and were truncated during parse",
            scfg->robots_txt_path, n_truncated);
    }
    int n_groups = robots_group_count(doc);
    bs_robots_state *ns = apr_pcalloc(npool, sizeof(*ns));
    ns->doc   = doc;
    ns->pool  = npool;
    ns->mtime = fi.mtime;
    ns->slot_by_group_idx = apr_pcalloc(npool,
        (n_groups > 0 ? n_groups : 1) * sizeof(int));

    int delay_count = 0, slot_reused = 0, slot_new = 0, slot_exhausted = 0;
    for (int i = 0; i < n_groups; i++) {
        ns->slot_by_group_idx[i] = -1;
        int cd = robots_group_crawl_delay_at(doc, i);
        if (cd <= 0) continue;
        delay_count++;
        const char *name = robots_group_name_at(doc, i);
        int *slot_ptr = apr_hash_get(scfg->robots_slot_by_name,
                                     name, APR_HASH_KEY_STRING);
        if (slot_ptr) {
            ns->slot_by_group_idx[i] = *slot_ptr;
            slot_reused++;
            continue;
        }
        if (scfg->robots_slot_pool_used < scfg->robots_slot_pool_size) {
            int slot = scfg->robots_slot_pool_base
                     + scfg->robots_slot_pool_used++;
            ns->slot_by_group_idx[i] = slot;
            /* Persist the mapping in pconf so future refreshes see
             * it. Copy name into pconf too — the doc's pool will be
             * destroyed on replacement and its name string with it. */
            int *persist = apr_palloc(pconf, sizeof(int));
            *persist = slot;
            apr_hash_set(scfg->robots_slot_by_name,
                         apr_pstrdup(pconf, name),
                         APR_HASH_KEY_STRING, persist);
            slot_new++;
        } else {
            slot_exhausted++;
        }
    }

    /* Publish the new state. scfg->robots_pending currently holds
     * the bundle displaced one refresh ago (or NULL at first load);
     * destroy its pool now — more than one refresh interval has
     * passed since any request took a pointer to it. */
    bs_robots_state *to_destroy = scfg->robots_pending;
    bs_robots_state *displaced  = cur;
    __atomic_store_n(&scfg->robots, ns, __ATOMIC_RELEASE);
    scfg->robots_pending = displaced;
    if (to_destroy && to_destroy->pool) {
        apr_pool_destroy(to_destroy->pool);
    }

    if (slot_exhausted > 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
            "mod_botshield: robots.txt slot pool exhausted "
            "(%d/%d used); %d Crawl-delay groups will not enforce "
            "until an Apache reload resizes the pool",
            scfg->robots_slot_pool_used, scfg->robots_slot_pool_size,
            slot_exhausted);
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
        "mod_botshield: robots.txt %s %sloaded — %d groups, "
        "%d with Crawl-delay (%d slots reused, %d new)",
        scfg->robots_txt_path, cur ? "re" : "",
        n_groups, delay_count, slot_reused, slot_new);
    return APR_SUCCESS;
}

/* mod_watchdog tick callback — one registration per vhost with a
 * BotShieldRobotsTxt directive. State-transition events (STARTING,
 * STOPPING) do nothing; RUNNING calls bs_robots_load which returns
 * fast when mtime hasn't changed. */
apr_status_t bs_robots_watchdog_cb(int state, void *data,
                                          apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    /* data was passed as the server_rec at registration; retrieve
     * scfg from it so we always see the live pointer. pconf is
     * reachable through sv->process->pconf. */
    server_rec *sv = data;
    if (!sv) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(sv->module_config, &botshield_module);
    if (!scfg || !scfg->robots_txt_path) return APR_SUCCESS;
    bs_robots_load(sv, scfg, sv->process->pconf);
    return APR_SUCCESS;
}




/* NULL-terminated name+bit projection for the legacy parse sites
 * (bs_parse_flag_names, bs_app_claims_flag_names) that iterate via
 * a sentinel rather than a count. Struct is named (`bs_flag_name`)
 * so botshield.h can `extern`-declare the array. */
const struct bs_flag_name bs_flag_names[] = {
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT         },
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE        },
    { "fake_bot",             BS_FLAG_FAKE_BOT             },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK      },
    { "app_verified_human",   BS_FLAG_APP_VERIFIED_HUMAN   },
    { "app_verified_session", BS_FLAG_APP_VERIFIED_SESSION },
    { "app_trust_signal",     BS_FLAG_APP_TRUST_SIGNAL     },
    { NULL, 0 }
};





/* The E1 BotShieldAllow / BotShieldAllowBot directive setters live
 * in allowlist.c. */

/* Character policy for bot-name tokens: lowercase letters, digits,
 * hyphen. Used as the hash key and the default ranges-file basename.
 * Rejects anything that could create path-traversal surprises or
 * cross-host confusion. Stays here because the rate-limit, block-
 * path, and triggers setters scattered across other files all reuse
 * it via the cross-file decl in botshield.h. */
int bs_bot_name_valid(const char *s)
{
    if (!s || !*s) return 0;
    apr_size_t len = strlen(s);
    if (len > 32) return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
            return 0;
        }
    }
    return 1;
}


/* The directive setters for BotShieldRateLimit, the rate-limit
 * helpers (parse_optional_mode, rate_unit_seconds), and the rest
 * of the rate-limit / safeguard / block-path family live in
 * config.c. */



/* mod_watchdog periodic-save callback. Runs in the parent/watchdog
 * process context with a short-lived pool. AP_WATCHDOG_STATE_RUNNING
 * fires at the configured interval. STARTING/STOPPING we ignore; the
 * graceful-shutdown save still happens via pool cleanup. */
apr_status_t bs_watchdog_save_cb(int state, void *data,
                                        apr_pool_t *pool)
{
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    bs_state_cleanup_ctx *ctx = data;
    if (!ctx || !ctx->path) return APR_SUCCESS;
    if (!ctx->shm_rt.shm || !ctx->shm_rt.flagged_table ||
        !ctx->shm_rt.bloom_bufs[0]) {
        return APR_SUCCESS;   /* SHM not up yet; nothing to save */
    }
    /* Use the callback's own pool so temporaries die with this tick. */
    bs_state_save(pool, ctx->server, ctx->path, &ctx->shm_rt);
    return APR_SUCCESS;
}

/* E14 (rework) — flag-trigger walker.
 *
 * Runs in bs_handler after flag bits are known (after
 * bs_flagged_ip_lookup and after the cookie verify decides
 * have_prior_rep) but BEFORE the tier decision. For each entry in
 * scfg->flag_triggers whose flag_bit is set in `all_flags`:
 *   - SCORE actions accumulate via bs_score_add (which already
 *     SUMs into the per-request score struct)
 *   - TIER_FLOOR actions MAX into *out_tier_floor; the caller
 *     applies the MAX(score_tier, *out_tier_floor) after
 *     bs_decide_tier returns.
 *
 * Observe-mode (mode=observe) entries log
 * `would-flag-trigger:<flag>:observe` and skip the side effect.
 *
 * Returns the count of triggers that fired (informational; the
 * walker's effects are applied via bs_score_add and
 * *out_tier_floor). */

/* Decide whether the rep block in *prior_ch can be carried into a
 * freshly-minted cookie, given the cverr that bs_verify_cookie just
 * returned.
 *
 * Reject when:
 *   - cverr == "signature mismatch"  (rep bytes can't be trusted)
 *   - cverr == "expired"  ── Security review MEDIUM #1: TTL is the
 *     only mechanism preventing indefinite reputation transfer
 *     across cookie generations. A leaked or stolen cookie that has
 *     aged past TTL must NOT be allowed to transplant good-standing
 *     rep into a fresh _bs_verified via any solve path.
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
 * This is the load-bearing carry-forward gate. Both the issuance-
 * side helper (bs_carry_forward_eligible) and the render-side
 * predicate in bs_handler share this single source of truth so a
 * change to the rule only has to land here. The original review
 * (MEDIUM #1) was a four-site fix that the issuance-side
 * consolidation collapsed to one site; reusing this predicate from
 * bs_handler closes the same drift gap on the render side. */
static int bs_should_carry_prior_rep(const char *cverr,
                                      const bs_challenge *prior_ch)
{
    if (cverr == NULL) return 1;
    if (strcmp(cverr, "signature mismatch") == 0) return 0;
    if (strcmp(cverr, "expired") == 0) return 0;          /* MEDIUM #1 */
    return prior_ch->alg_name ? 1 : 0;
}

/* Carry-forward eligibility predicate for issuance call sites. Reads
 * the request's __Host-bs_verified cookie, verifies it, and applies
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
 * (cfg->forgive_silent / forgive_captcha / etc.) — that knowledge
 * stays at the call site because forgive bands are per-tier policy.
 *
 * This helper does the deterministic math:
 *   - clamp the requested forgive against the per-cookie hourly cap
 *     (writes target->forgive_window_start + forgive_consumed)
 *   - compute new score = prior.score - forgive, clamped against
 *     the flag-penalty floor and zero
 *
 * The caller bumps the appropriate passes_X afterward (the LOW #7
 * "ever passed" clamp). Tier knowledge for that decision also stays
 * at the call site. */
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
    /* E14 (rework) — the prior bs_flag_penalty floor here was tied
     * to the retired bs_flag_meta.penalty field. Under the new
     * design flag effects are re-applied at request time via
     * bs_apply_flag_triggers, so the carry-forward floor became
     * redundant: a forgiven-to-zero score on a flagged cookie is
     * simply re-raised on the next request when the trigger fires.
     * Carry-forward now clamps only at zero. */
    int new_score = prior_ch->rep.score - forgive;
    if (new_score < 0) new_score = 0;
    target->score = new_score;
}

/* E14 (rework) — the prior bs_flag_adaptive accumulator that walked
 * bs_flag_meta.next_difficulty_delta and next_tier_floor was retired.
 * Adaptive effects are now expressed as BotShieldFlagTrigger entries
 * and applied via bs_apply_flag_triggers above. */

/* Flag-name registry moved up the file (near the early request-path
 * helpers) so E8.2's bs_app_claims_flag_names can render the bitmap
 * without a forward-declaration dance. Definition lives further up;
 * leave a placeholder comment here so a reader scanning E5/E6 still
 * sees where the table conceptually belongs. */

apr_uint32_t bs_parse_flag_names(apr_pool_t *p, const char *s,
                                 const char **err)
{
    apr_uint32_t bits = 0;
    *err = NULL;
    const char *cur = s;
    while (cur && *cur) {
        const char *comma = strchr(cur, ',');
        apr_size_t len = comma ? (apr_size_t)(comma - cur) : strlen(cur);
        while (len && (*cur == ' ' || *cur == '\t')) { cur++; len--; }
        while (len && (cur[len-1] == ' ' || cur[len-1] == '\t')) { len--; }

        int matched = 0;
        for (int i = 0; bs_flag_names[i].name; i++) {
            apr_size_t nlen = strlen(bs_flag_names[i].name);
            if (nlen == len &&
                strncasecmp(cur, bs_flag_names[i].name, nlen) == 0) {
                bits |= bs_flag_names[i].bit;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            *err = apr_psprintf(p, "unknown flag name '%.*s' "
                "(known penalty bits: honeypot_hit, scanner_probe, "
                "fake_bot, pow_fail_streak; credit bits: "
                "app_verified_human, app_verified_session, "
                "app_trust_signal)", (int)len, cur);
            return 0;
        }
        cur = comma ? comma + 1 : NULL;
    }
    return bits;
}


/* --- New directive setters --- */



/* The M8 captcha-tier directive setters (provider, site_key,
 * secret_file, timeouts, expected hostname/action, ca_bundle,
 * rate_limit, max_inflight) live in captcha.c. */

/* `BotShieldEndpointPrefix /path` — URL prefix the module's own
 * handlers live under. Today: /captcha-verify[/<provider>] (M8),
 * /metrics (M9.3). Future: E7's /solver.js. Must start with '/' and
 * not end with '/'. */


/* ======================================================================
 * E2.2.3 — /botshield/policy-status
 *
 * Plain-text dump of the rules currently being enforced:
 *   - BotShieldRateLimit directives (directive rate_limits array).
 *   - BotShieldBlockPath directives (directive block_paths array).
 *   - robots.txt-derived groups (if BotShieldRobotsTxt is set) —
 *     source file path, mtime, every group's UA tokens + rules +
 *     Crawl-delay.
 *
 * Goal is operator-visibility: when E2.2.2 hot-swaps a freshly-edited
 * robots.txt, operators can curl this page to confirm what the module
 * is actually enforcing, rather than guessing. Also useful for
 * verifying that `BotShieldAllow` overrides have landed.
 *
 * No authentication / no rate limit built in. Treat like mod_status —
 * operators wrap it in `<Location>` with their own ACL. The page
 * doesn't reveal cookie secrets or client IPs; the most sensitive
 * content is the operator's own directive config, which is already
 * on disk in /etc/apache2/.
 *
 * Format is plain text (not Prometheus) — this is meant to be read
 * by humans over curl; structured consumers use /botshield/metrics.
 * ====================================================================== */

static void bs_psh_cohort_ipspec(request_rec *r, const bs_cohort *c)
{
    if (c->ip_any) { ap_rputs("*", r); return; }
    if (c->inline_cidrs) {
        ap_rprintf(r, "inline(%s)", c->inline_cidrs);
        return;
    }
    if (c->path) {
        ap_rprintf(r, "file(%s)", c->path);
        return;
    }
    ap_rprintf(r, "<%d ranges>", c->ranges ? c->ranges->nelts : 0);
}

static void bs_psh_render_counter(request_rec *r, int slot_idx,
                                  apr_uint32_t budget)
{
    bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
    if (slot_idx < 0 || !counters) {
        ap_rputs("-/-", r);
        return;
    }
    apr_uint32_t cnt = __atomic_load_n(&counters[slot_idx].count,
                                       __ATOMIC_RELAXED);
    ap_rprintf(r, "%u/%u", cnt, budget);
}

static int bs_policy_status_handler(request_rec *r, bs_dir_cfg *cfg)
{
    (void)cfg;
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }
    ap_set_content_type(r, "text/plain; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    if (!scfg) {
        ap_rputs("# scfg unavailable\n", r);
        return OK;
    }

    char tbuf[APR_RFC822_DATE_LEN + 1] = { 0 };
    apr_rfc822_date(tbuf, apr_time_now());
    ap_rprintf(r, "# mod_botshield policy status\n"
                  "# vhost:       %s\n"
                  "# server_time: %s\n\n",
        r->server->server_hostname ? r->server->server_hostname : "-",
        tbuf);

    /* --- directive rate limits --- */
    ap_rputs("## BotShieldRateLimit (directive)\n", r);
    if (!scfg->rate_limits || scfg->rate_limits->nelts == 0) {
        ap_rputs("# (none)\n\n", r);
    } else {
        ap_rputs("# name               budget  window  ua                          "
                 "ipspec                slot  count/budget\n", r);
        for (int i = 0; i < scfg->rate_limits->nelts; i++) {
            bs_rate_limit_entry *e = APR_ARRAY_IDX(
                scfg->rate_limits, i, bs_rate_limit_entry *);
            ap_rprintf(r, "%-18s  %6u  %4us   %-26s  ",
                e->name, e->budget, e->window_sec,
                e->cohort.ua_any ? "*"
                    : apr_psprintf(r->pool, "\"%s\"", e->cohort.ua_pattern));
            bs_psh_cohort_ipspec(r, &e->cohort);
            ap_rprintf(r, "%*s  %4d  ",
                       (int)(22 - (e->cohort.ip_any ? 1
                          : (int)(strlen("file()") + (e->cohort.path ? strlen(e->cohort.path) : 0)
                                  + (e->cohort.inline_cidrs ? strlen(e->cohort.inline_cidrs) : 0)))),
                       "", e->shm_slot);
            bs_psh_render_counter(r, e->shm_slot, e->budget);
            ap_rputs("\n", r);
        }
        ap_rputs("\n", r);
    }

    /* --- directive block paths --- */
    ap_rputs("## BotShieldBlockPath (directive)\n", r);
    if (!scfg->block_paths || scfg->block_paths->nelts == 0) {
        ap_rputs("# (none)\n\n", r);
    } else {
        ap_rputs("# name               path-glob                     "
                 "ua                          ipspec\n", r);
        for (int i = 0; i < scfg->block_paths->nelts; i++) {
            bs_block_path_entry *e = APR_ARRAY_IDX(
                scfg->block_paths, i, bs_block_path_entry *);
            ap_rprintf(r, "%-18s  %-28s  %-26s  ",
                e->name, e->path_pattern,
                e->cohort.ua_any ? "*"
                    : apr_psprintf(r->pool, "\"%s\"", e->cohort.ua_pattern));
            bs_psh_cohort_ipspec(r, &e->cohort);
            ap_rputs("\n", r);
        }
        ap_rputs("\n", r);
    }

    /* --- robots.txt --- */
    ap_rputs("## robots.txt (BotShieldRobotsTxt)\n", r);
    if (!scfg->robots_txt_path) {
        ap_rputs("# (not configured)\n", r);
        return OK;
    }
    bs_robots_state *rs =
        __atomic_load_n(&scfg->robots, __ATOMIC_ACQUIRE);
    ap_rprintf(r, "# path:                %s\n", scfg->robots_txt_path);
    if (!rs) {
        ap_rputs("# status:              not loaded (parse failed or "
                 "file missing at post_config)\n", r);
        return OK;
    }
    char mbuf[APR_RFC822_DATE_LEN + 1] = { 0 };
    apr_rfc822_date(mbuf, rs->mtime);
    ap_rprintf(r, "# mtime:               %s\n"
                  "# groups:              %d\n"
                  "# slot pool:           %d/%d used\n"
                  "# wildcard scope:      %s\n"
                  "# refresh interval:    %d s%s\n",
        mbuf,
        robots_group_count(rs->doc),
        scfg->robots_slot_pool_used, scfg->robots_slot_pool_size,
        scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_STRICT ? "strict"
          : scfg->robots_wildcard_scope == BS_ROBOTS_WILDCARD_OFF ? "off"
          : "heuristic",
        scfg->robots_refresh_interval,
        scfg->robots_refresh_interval == 0 ? " (live-refresh disabled)" : "");

    int n = robots_group_count(rs->doc);
    for (int i = 0; i < n; i++) {
        ap_rprintf(r, "\n### group[%d] \"%s\"  wildcard=%s\n", i,
            robots_group_name_at(rs->doc, i),
            robots_group_is_wildcard_at(rs->doc, i) ? "yes" : "no");
        int n_ua = robots_group_ua_count_at(rs->doc, i);
        for (int u = 0; u < n_ua; u++) {
            ap_rprintf(r, "  user-agent: %s\n",
                robots_group_ua_at(rs->doc, i, u));
        }
        int n_rules = robots_group_rule_count_at(rs->doc, i);
        for (int k = 0; k < n_rules; k++) {
            const char *pat = NULL;
            int allow = 0;
            if (robots_group_rule_at(rs->doc, i, k, &pat, &allow)) {
                ap_rprintf(r, "  %-9s %s\n",
                    allow ? "Allow:" : "Disallow:", pat ? pat : "");
            }
        }
        int cd = robots_group_crawl_delay_at(rs->doc, i);
        if (cd > 0) {
            int slot = (rs->slot_by_group_idx && i < n)
                     ? rs->slot_by_group_idx[i] : -1;
            ap_rprintf(r, "  Crawl-delay: %ds  slot=%d  ", cd, slot);
            bs_psh_render_counter(r, slot, 1);
            ap_rputs("\n", r);
        }
    }
    return OK;
}






/* Cheap built-in signals, run on requests we're about to challenge. Called
 * after the cookie check — a verified cookie skips scoring entirely. */
static void bs_run_builtin_heuristics(request_rec *r)
{
    /* E1: crawler allow-list runs first. A verified crawler adds a
     * large negative penalty that dominates anything else scoring
     * might pile on (scraper UA tokens in "Googlebot" etc.) and
     * collapses tier dispatch to pass. */
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    bs_check_allow(r, dcfg);

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (!ua || !*ua) {
        bs_score_add(r, BS_PENALTY_MISSING_UA, 3600, "missing-user-agent");
    }
    const char *al = apr_table_get(r->headers_in, "Accept-Language");
    if (!al || !*al) {
        bs_score_add(r, BS_PENALTY_MISSING_AL, 3600, "missing-accept-language");
    }

    /* Obvious scraper / HTTP-library UA fragments. Case-sensitive on
     * purpose — we pick both casings where both actually appear in the
     * wild. Matches are flagged, not blocked, so false positives only
     * cost a tier bump. */
    if (ua && *ua) {
        static const char *const scraper_tokens[] = {
            "curl", "Wget", "wget",
            "python", "Python", "python-requests",
            "urllib", "httpx", "aiohttp",
            "Go-http-client", "okhttp", "axios", "scrapy",
            "java", "Java", "libwww", "lwp-request",
            NULL
        };
        for (int i = 0; scraper_tokens[i]; i++) {
            if (strstr(ua, scraper_tokens[i])) {
                bs_score_add(r, BS_PENALTY_SCRAPER_UA, 3600,
                    apr_psprintf(r->pool, "scraper-ua-%s", scraper_tokens[i]));
                break;
            }
        }
    }
}

/* Pick a tier from the running score. Each tier has its own
 * interstitial: silent → auto-submit splash; form → reCAPTCHA-shaped
 * checkbox; captcha → configured third-party provider's widget. When
 * captcha tier is selected but no provider is configured on the scope,
 * the render code falls through to form-PoW (documented in the
 * decision log as reason="captcha_fallback"). */
/* Score-to-tier threshold ladder. Three configurable cut-points
 * (BotShieldScoreSilent / Hard / Captcha) gate four tiers. See the
 * README "Understanding scoring" section for the operator-facing
 * tuning workflow. */
static bs_tier bs_decide_tier(const bs_dir_cfg *cfg, int score)
{
    int silent  = bs_effective_int(cfg->score_silent,  BS_DEFAULT_SCORE_SILENT);
    int hard    = bs_effective_int(cfg->score_hard,    BS_DEFAULT_SCORE_HARD);
    int captcha = bs_effective_int(cfg->score_captcha, BS_DEFAULT_SCORE_CAPTCHA);
    if (score >= captcha) return BS_TIER_CAPTCHA;
    if (score >= hard)    return BS_TIER_HARD;
    if (score >= silent)  return BS_TIER_SILENT;
    return BS_TIER_PASS;
}

const char *bs_tier_name(bs_tier t)
{
    switch (t) {
        case BS_TIER_PASS:    return "pass";
        case BS_TIER_SILENT:  return "silent";
        case BS_TIER_HARD:    return "form";
        case BS_TIER_CAPTCHA: return "captcha";
    }
    return "?";
}

static const command_rec bs_cmds[] = {
    AP_INIT_FLAG("BotShieldEnabled",    bs_set_enabled,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Turn mod_botshield on/off for the enclosing scope (default: off)"),
    AP_INIT_FLAG("BotShieldDebug",      bs_set_debug,      NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "If on, return 403 'Hello World' for every request in the "
                 "enclosing scope (default: off)"),
    AP_INIT_TAKE1("BotShieldCookieTTL", bs_set_cookie_ttl, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Seconds a verified cookie stays valid (default: 3600, "
                 "range 1..86400)"),
    AP_INIT_TAKE1("BotShieldDifficulty",bs_set_difficulty, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Number of leading hex zeros the PoW must produce (default: 4)"),
    AP_INIT_TAKE1("BotShieldPromptText", bs_set_prompt,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Label shown next to the checkbox (default: \"I'm not a robot\"). "
                 "HTML-escaped at render time."),
    AP_INIT_TAKE1("BotShieldLogoFile",   bs_set_logo_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to an SVG file served inline as the widget logo. "
                 "Read once at startup; must be <= 64 KB. "
                 "Default: embedded Guardian shield."),
    AP_INIT_TAKE1("BotShieldLogoLabel",  bs_set_logo_label,NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Small caption under the logo (default: \"botshield\"). "
                 "Empty string hides it."),
    AP_INIT_FLAG("BotShieldShowLogo",   bs_set_show_logo,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Show the brand column — logo + caption (default: on). "
                 "Off removes the whole column from the widget."),
    AP_INIT_FLAG("BotShieldShowLabel",  bs_set_show_label, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Show the prompt text next to the checkbox (default: on). "
                 "Off hides the text and moves it to the button's aria-label "
                 "so screen readers still hear it."),
    AP_INIT_FLAG("BotShieldShowBox",    bs_set_show_box,   NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Show the widget's outer box — border, background, shadow "
                 "(default: on). Off leaves just the controls for the admin's "
                 "page to style around."),
    AP_INIT_TAKE1("BotShieldHelp",       bs_set_help,      NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Help visibility: off | on | button (default: button). "
                 "'button' shows a '?' link under the widget that toggles "
                 "an explainer panel."),
    AP_INIT_TAKE1("BotShieldHelpFile",   bs_set_help_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to an HTML fragment used as the help panel content. "
                 "Read once at startup; must be <= 64 KB. Contents are "
                 "trusted (no escaping). Default: a built-in explanation."),
    AP_INIT_TAKE1("BotShieldChallengeFile", bs_set_challenge_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to a full HTML page that wraps the verification "
                 "widget. Must contain the marker '" BS_WIDGET_MARKER "' "
                 "where the widget should be inserted. Read once at startup; "
                 "must be <= 256 KB. Other BotShield* directives still apply "
                 "to the widget block."),
    AP_INIT_TAKE1("BotShieldSecretFile", bs_set_secret_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to the HMAC key used to sign challenge cookies. "
                 "Must be mode 0600 (not group- or world-accessible) and "
                 ">= 16 bytes. Read once at startup."),
    /* E16 — graceful secret rotation. */
    AP_INIT_TAKE1("BotShieldSecondarySecretFile",
                 bs_set_secondary_secret_file, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Path to a verify-only secondary HMAC/GCM key for "
                 "graceful secret rotation. Issue path always uses "
                 "BotShieldSecretFile; verify tries primary then "
                 "secondary, so cookies signed under the OLD key keep "
                 "validating during the rotation window. Same mode-0600 "
                 "+ >= 16-byte hygiene as the primary. Remove the "
                 "directive after one BotShieldCookieTTL window has "
                 "elapsed and every active cookie is back on the new "
                 "key."),
    AP_INIT_TAKE1("BotShieldAlgorithm",  bs_set_algorithm,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Proof-of-work algorithm name. Only 'sha256-zeros' is built "
                 "into this module today; 'sha384-zeros' / 'sha512-zeros' / "
                 "'pbkdf2-sha256' / 'argon2id' are registry slots reserved "
                 "for future opt-in builds."),
    AP_INIT_TAKE1("BotShieldScoreSilent",  bs_set_score_silent,  NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the silent-PoW tier is picked "
                 "(default: 20). Serves a no-click auto-submit splash."),
    AP_INIT_TAKE1("BotShieldScoreHard",    bs_set_score_hard,    NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the form-PoW tier is picked "
                 "(default: 50). Serves the checkbox interstitial."),
    AP_INIT_TAKE1("BotShieldScoreCaptcha", bs_set_score_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score at or above which the captcha tier is picked "
                 "(default: 80). Serves the configured third-party "
                 "provider's widget; falls through to form-PoW if no "
                 "BotShieldCaptchaProvider is set on the scope."),
    /* E18 — inline form captcha. */
    AP_INIT_FLAG("BotShieldFormCaptcha", bs_set_form_captcha, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "When on, this scope validates a configured captcha "
                 "provider's response token in the POST body of form "
                 "submissions. Requires BotShieldCaptchaProvider + "
                 "SiteKey + SecretFile in the same scope (or "
                 "inherited). On valid token: mints _bs_verified, "
                 "DECLINED so the app handler runs with the original "
                 "body intact. On bad/missing token: 403, app handler "
                 "never runs. Supports application/x-www-form-"
                 "urlencoded and application/json bodies; "
                 "multipart/form-data (file uploads) is out of scope."),
    /* E17 PoC — silent-tier dispatch flavor. */
    AP_INIT_TAKE1("BotShieldSilentMode", bs_set_silent_mode, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "How to dispatch silent-tier (low-friction) "
                 "challenges. 'interstitial' (default) = legacy M7 "
                 "auto-submit splash. 'embedded' = serve real page "
                 "(DECLINED) and rely on the operator-included "
                 "/botshield/embedded.js wrapper to do PoW in a Web "
                 "Worker and POST the result back to "
                 "/botshield/embedded-verify. The verified cookie "
                 "may not arrive in time for the very first request, "
                 "but it lands within a few page-views — see PLAN "
                 "E17 for the timing model."),
    AP_INIT_TAKE1("BotShieldForgivenessSilent", bs_set_forgive_silent, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful silent-PoW pass "
                 "(default: 10). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessForm",   bs_set_forgive_form,   NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful form-PoW pass "
                 "(default: 25). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldForgivenessCaptcha",bs_set_forgive_captcha,NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Score credit applied on a successful captcha pass "
                 "(default: 50). Clamped at max(0, flag_penalty)."),
    AP_INIT_TAKE1("BotShieldCookieDomain", bs_set_cookie_domain, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "If set, Set-Cookie for _bs_verified includes a Domain= "
                 "attribute so reputation follows users across subdomains. "
                 "Use '.example.com' for subdomain sharing. Default: host-only."),
    AP_INIT_TAKE1("BotShieldEndpointPrefix", bs_set_endpoint_prefix, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "URL prefix for module-owned handlers (default: /botshield). "
                 "Must start with '/' and not end with '/'. Change it if this "
                 "collides with real app routes."),
    AP_INIT_TAKE1("BotShieldCaptchaProvider", bs_set_captcha_provider, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Third-party captcha provider for the captcha tier. Built "
                 "in: 'turnstile' (Cloudflare), 'hcaptcha', 'recaptcha-v2', "
                 "'recaptcha-v3' (with BotShieldRecaptchaV3MinScore), "
                 "'friendly' (Friendly Captcha), 'geetest' (GeeTest v4). "
                 "Unrecognized names fail at configtest time."),
    AP_INIT_TAKE1("BotShieldCaptchaSiteKey", bs_set_captcha_site_key, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Provider-public site key embedded in the captcha widget."),
    AP_INIT_TAKE1("BotShieldCaptchaSecretFile", bs_set_captcha_secret_file,
                 NULL, RSRC_CONF | ACCESS_CONF,
                 "Path to the captcha provider's secret key, used in "
                 "server-side siteverify calls. Must be mode 0600 (not "
                 "group- or world-accessible). Read once at startup."),
    AP_INIT_TAKE1("BotShieldCaptchaTimeout", bs_set_captcha_timeout, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Siteverify HTTP call timeout in milliseconds "
                 "(default: 1000, range 100..5000). On timeout the module "
                 "fails open — issues the cookie and logs a WARNING."),
    AP_INIT_TAKE1("BotShieldCaptchaConnectTimeout",
                 bs_set_captcha_connect_timeout, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Connect-phase timeout for siteverify in milliseconds "
                 "(default: 250, range 50..5000). Tighter than the full "
                 "siteverify timeout; bump on links with transient packet "
                 "loss to avoid fail-open on momentary connect blips."),
    AP_INIT_TAKE1("BotShieldRecaptchaV3MinScore",
                 bs_set_recaptcha_v3_min_score, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Minimum score (0.0..1.0) to accept a reCAPTCHA v3 "
                 "verification (default: 0.5). Scores below this are "
                 "logged as REJECTED with the numeric score."),
    AP_INIT_TAKE1("BotShieldCaptchaExpectedHostname",
                 bs_set_captcha_expected_hostname, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Hostname the captcha provider must echo back in the "
                 "siteverify response for the token to be accepted. "
                 "Default: the vhost's server_hostname. Empty string "
                 "disables the check (for multi-origin deployments)."),
    AP_INIT_TAKE1("BotShieldCaptchaExpectedAction",
                 bs_set_captcha_expected_action, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Action string the client widget must tag the captcha "
                 "token with (reCAPTCHA v3 + Turnstile). Default: "
                 "'botshield'. Empty string disables the check. "
                 "Mismatch rejects the token."),
    AP_INIT_TAKE1("BotShieldCaptchaCABundle", bs_set_captcha_ca_bundle,
                 NULL, RSRC_CONF | ACCESS_CONF,
                 "Absolute path to a PEM CA bundle libcurl will use to "
                 "validate the captcha-provider TLS certificate. "
                 "Optional; defaults to libcurl's compiled-in system "
                 "bundle. Set this on stripped container images that "
                 "lack /etc/ssl/certs to avoid silent fail-open from "
                 "every siteverify hitting "
                 "CURLE_PEER_FAILED_VERIFICATION."),
    AP_INIT_TAKE1("BotShieldCaptchaRateLimit", bs_set_captcha_rate_limit,
                 NULL, RSRC_CONF | ACCESS_CONF,
                 "Max captcha-verify POSTs per IP per minute (default: 30, "
                 "range 0..1000; 0 disables). Over cap returns 429 Retry-"
                 "After without calling the provider. Scope: per-dir."),
    AP_INIT_TAKE1("BotShieldCaptchaMaxInFlight", bs_set_captcha_max_inflight,
                 NULL, RSRC_CONF,
                 "Global cap on concurrent outbound siteverify calls "
                 "(default: 64, range 1..1024). Over cap returns 503 "
                 "with WARNING. Server-scope only."),
    AP_INIT_TAKE1("BotShieldShmSize", bs_set_shm_size, NULL,
                 RSRC_CONF,
                 "Total shared-memory budget for flagged-IP table and "
                 "(future) Bloom filter. Accepts K/M/G suffixes. "
                 "Default: 8M. Range: 128K..256M."),
    AP_INIT_TAKE1("BotShieldFlaggedIPCapacity", bs_set_flagged_capacity, NULL,
                 RSRC_CONF,
                 "Slot count in the flagged-IP hash table. Each slot is "
                 "32 bytes. Default: 50000 (≈ 1.6 MB). "
                 "Range: 1024..1000000."),
    AP_INIT_TAKE1("BotShieldIPv6PrefixLen", bs_set_ipv6_prefix, NULL,
                 RSRC_CONF,
                 "Native-IPv6 clients are keyed on this prefix length in "
                 "the flagged-IP table. Default 64 — one subscriber "
                 "allocation is one identity, so an attacker with a /64 "
                 "can't rotate addresses to shed a flag. 128 disables "
                 "aggregation. IPv4 (v6-mapped) keys are never masked."),
    AP_INIT_TAKE1("BotShieldBloomIPs", bs_set_bloom_ips, NULL,
                 RSRC_CONF,
                 "Expected working-set size for the first-sight Bloom "
                 "filter. Drives buffer size at ~10 bits/IP (1% FP). "
                 "Default 1000000 (2.4 MB total for the two buffers). "
                 "Range 1000..10000000."),
    AP_INIT_TAKE1("BotShieldBloomWindow", bs_set_bloom_window, NULL,
                 RSRC_CONF,
                 "Full lifetime window for Bloom entries, in seconds. "
                 "Rotation happens at half-window. Default 604800 (1 week) "
                 "→ 3.5 day guaranteed minimum lifetime, 7 day max. "
                 "Range 3600..2592000."),
    AP_INIT_TAKE1("BotShieldStateFile", bs_set_state_file, NULL,
                 RSRC_CONF,
                 "Path to a binary file used to persist flagged-IP and "
                 "Bloom state across graceful restarts. Written atomically "
                 "at clean shutdown; loaded (with checksum and dimension "
                 "checks) at startup. Any problem at load time is treated "
                 "as 'start fresh'. Unset (default) disables persistence."),
    AP_INIT_TAKE1("BotShieldStateSaveInterval", bs_set_state_save_interval, NULL,
                 RSRC_CONF,
                 "Seconds between periodic state snapshots via mod_watchdog. "
                 "Default 300 (5 min). 0 disables periodic saves (only the "
                 "graceful-shutdown save runs). Range when non-zero: "
                 "30..86400. Requires mod_watchdog to be loaded; otherwise "
                 "degrades to shutdown-only with a NOTICE."),
    AP_INIT_TAKE12("BotShieldFlagIP", bs_set_flag_ip, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Flag the client IP with one or more bits when a request "
                 "hits this scope. Flag names: honeypot_hit, scanner_probe, "
                 "fake_bot, pow_fail_streak. Optional second argument "
                 "is the TTL in seconds (default 3600). Use inside a "
                 "<Location> for honeypot paths."),
    /* E1 — Allow family */
    AP_INIT_FLAG("BotShieldAllow", bs_set_allow_enabled,
                 NULL, RSRC_CONF,
                 "Enable the Allow family (verified-bot first member). "
                 "Default off. When on, classified bot UAs are matched "
                 "against loaded IP ranges: in-range gets a large "
                 "negative credit (tier=pass bypass); out-of-range "
                 "gets a fake-<name> penalty routing to captcha tier."),
    AP_INIT_TAKE23("BotShieldAllowBot",
                 bs_set_allow_bot, NULL, RSRC_CONF,
                 "Register a bot for the Allow family. Args: "
                 "<name> <ua-pattern> [<target>]. Name is a [a-z0-9-] "
                 "token used as the decision-log identifier and "
                 "default ranges-file basename. UA-pattern is the "
                 "case-insensitive substring looked for in the "
                 "User-Agent header. Optional target: '*' for UA-only "
                 "trust (logs allow-bot-ua:<name>), an absolute file "
                 "path, a single CIDR, or a comma-separated CIDR "
                 "list. Omit the target to use the default file path "
                 "/var/lib/botshield/bots/<name>.txt."),
    /* E2.1 — policy enforcement. TAKE_ARGV because Apache has no
     * TAKE4/TAKE5 macros; the setters enforce argc themselves. */
    AP_INIT_TAKE_ARGV("BotShieldRateLimit",
                 bs_set_rate_limit, NULL, RSRC_CONF,
                 "Rate-limit a named cohort. Args: <name> <budget> "
                 "<per> <ua> <ipspec>. Per is sec/min/hour (or "
                 "s/m/h). UA is a substring (case-insensitive) or "
                 "'*' for any UA. Ipspec is '*', an absolute file "
                 "path, or a single / comma-separated CIDR list. "
                 "Both-'*' is rejected. Over-budget requests return "
                 "429 + Retry-After and get a +50 score penalty "
                 "under reason rate-limit-exceeded:<name>."),
    /* E9 — repeated-429 escalation. Sits on top of BotShieldRateLimit;
     * does not apply to robots.txt Crawl-delay 429s in v1 (no operator
     * handle for them). */
    AP_INIT_TAKE_ARGV("BotShieldRateLimitEscalate",
                 bs_set_rate_limit_escalate, NULL, RSRC_CONF,
                 "Promote repeated 429s on a named BotShieldRateLimit "
                 "into a stricter status. Args: <rate-name> <strikes> "
                 "<per> [status=<code>] [ttl=<sec>] [log=<tag>]. "
                 "Per accepts sec/min/hour. Once <strikes> rejected "
                 "requests accumulate within <per>, subsequent "
                 "requests against the same rule return status= "
                 "(default 403) for ttl= seconds (default 1800). The "
                 "ttl slides on each additional strike; log=<tag> "
                 "rides the decision line on threshold crossing for "
                 "fail2ban handoff. Reason rate-limit-abuse:<name>."),
    AP_INIT_TAKE1("BotShieldRateLimitEscalateCapacity",
                 bs_set_rate_escalate_capacity, NULL, RSRC_CONF,
                 "SHM strike-table slot count (default 50000). Sized "
                 "for (concurrent-misbehaving-IPs * named-rate-rules) "
                 "headroom; same eviction discipline as the flagged-"
                 "IP table when the probe window saturates. Read at "
                 "post_config from the main server's value."),
    /* E10 — challenge safeguard / anti-loop hysteresis. */
    AP_INIT_FLAG("BotShieldSafeguard",
                 bs_set_safeguard, NULL, RSRC_CONF,
                 "Enable anti-loop hysteresis (default off). When on, "
                 "a client that gets challenged N times within W "
                 "seconds without solving any challenge is passed "
                 "through for a TTL window instead of being re-"
                 "challenged. Decision log shows reason "
                 "challenge-safeguard. Doesn't mint _bs_verified; "
                 "doesn't override 403/429 blocks."),
    AP_INIT_TAKE1("BotShieldSafeguardThreshold",
                 bs_set_safeguard_threshold, NULL, RSRC_CONF,
                 "Presentations-without-solve inside the window "
                 "before safeguard trips (default 5; range 1..1000)."),
    AP_INIT_TAKE1("BotShieldSafeguardWindow",
                 bs_set_safeguard_window, NULL, RSRC_CONF,
                 "Counting window in seconds for the threshold "
                 "(default 600; range 1..86400)."),
    AP_INIT_TAKE1("BotShieldSafeguardTTL",
                 bs_set_safeguard_ttl, NULL, RSRC_CONF,
                 "How long safeguard stays active after the last "
                 "presentation (default 900 seconds; range "
                 "1..604800). Slides on each fresh presentation "
                 "during active safeguard."),
    AP_INIT_TAKE1("BotShieldSafeguardCapacity",
                 bs_set_safeguard_capacity, NULL, RSRC_CONF,
                 "SHM safeguard-table slot count (default 50000). "
                 "Per-server-scope but only the main server's value "
                 "is consulted at post_config since the table is "
                 "module-global."),
    AP_INIT_TAKE1("BotShieldEmbeddedNonceCapacity",
                 bs_set_nonce_capacity, NULL, RSRC_CONF,
                 "SHM slot count for the embedded-bootstrap nonce "
                 "table (default 32768, range 1024..1048576). "
                 "Bound the in-flight + recently-redeemed challenge "
                 "set within the 120s bootstrap expiry. Each slot "
                 "is 24 bytes."),
    /* E11 — load-aware throttling. Sampling + cached state. */
    AP_INIT_TAKE1("BotShieldLoadStateFile",
                 bs_set_load_state_file, NULL, RSRC_CONF,
                 "Optional file the operator's monitoring system "
                 "writes to push a load-state override into the "
                 "module. Body is one of normal/warm/hot. Watchdog "
                 "stat-polls mtime; only re-reads on change. "
                 "Most-severe-wins merging with internal sensing."),
    AP_INIT_TAKE1("BotShieldLoadRefreshInterval",
                 bs_set_load_refresh, NULL, RSRC_CONF,
                 "Watchdog tick period in seconds (default 1; "
                 "1..60). Lower = faster brownout response; higher "
                 "= less work in mod_watchdog."),
    AP_INIT_TAKE1("BotShieldLoadWarmThreshold",
                 bs_set_load_warm_pct, NULL, RSRC_CONF,
                 "Busy-worker percentage at which a tick samples "
                 "as 'warm' (default 65; range 1..99). Hysteresis "
                 "still applies — promotion takes 3 consecutive "
                 "warm-or-hot samples."),
    AP_INIT_TAKE1("BotShieldLoadHotThreshold",
                 bs_set_load_hot_pct, NULL, RSRC_CONF,
                 "Busy-worker percentage at which a tick samples "
                 "as 'hot' (default 85; range 1..99). Must be "
                 "greater than the warm threshold."),
    /* E13 — per-vhost reputation namespacing. */
    AP_INIT_TAKE1("BotShieldShareScope",
                 bs_set_share_scope, NULL, RSRC_CONF,
                 "Reputation-namespace override token. By default, "
                 "each vhost gets an isolated SHM namespace derived "
                 "from siphash(ServerName), so flagged-IP / Bloom / "
                 "strike / safeguard tables don't share rows across "
                 "unrelated sites. Set this directive to the same "
                 "token on two or more vhosts to force them to share "
                 "(e.g., dev+prod for one logical app, or api+www "
                 "subdomains). Strings up to 128 chars; hashed to a "
                 "32-bit ns_id and stored in each SHM slot."),
    /* E12 — shadow / dry-run enforcement. */
    AP_INIT_FLAG("BotShieldShadowMode",
                 bs_set_shadow_mode, NULL, RSRC_CONF,
                 "Master switch for dry-run enforcement. When on, "
                 "all trigger / rate-limit / block-path rules log "
                 "matches with a :observe suffix instead of taking "
                 "their action — useful for staging a whole policy "
                 "revision before flipping enforcement on. Default "
                 "off; per-rule mode=observe is the finer-grained "
                 "alternative for staging a single rule. Typical "
                 "workflow: add new rules with mode=observe, watch "
                 "the decision log, flip to enforce when matches "
                 "look right."),
    /* E14 (rework) — flag-driven trigger family. */
    AP_INIT_TAKE_ARGV("BotShieldFlagTrigger",
                 bs_set_flag_trigger, NULL, RSRC_CONF,
                 "Apply an action when a flag bit fires on the IP- "
                 "or cookie-side bitmap of a request. Args: <flag> "
                 "[reset] [action=<verb> args...]. Flag names: "
                 "honeypot_hit, scanner_probe, fake_bot, "
                 "pow_fail_streak, app_verified_human, "
                 "app_verified_session, app_trust_signal. Action "
                 "verbs: 'score add=N' (signed, -1000..1000; SUMs "
                 "across triggers) or 'tier_floor min=<tier>' "
                 "(pass|silent|form|captcha; MAXes across triggers). "
                 "'reset' clears compiled-in defaults + prior "
                 "operator declarations for the named flag before "
                 "this directive's effect is added. mode=observe "
                 "logs would-flag-trigger:<flag>:observe instead of "
                 "applying. Compiled-in defaults cover the common "
                 "cases — see example/flag-triggers.conf.example."),
    /* E15 — forgiveness farming defense. */
    AP_INIT_TAKE1("BotShieldForgivenessCapPerHour",
                 bs_set_forgive_cap, NULL, RSRC_CONF,
                 "Per-cookie cap on accumulated forgiveness points "
                 "inside a rolling 1-hour window. Default 200 — "
                 "enough for a real user pinned at borderline-"
                 "suspicious to keep transacting; tight enough that "
                 "a patient bot solving every few minutes stops "
                 "earning forgiveness past the cap. 0 disables the "
                 "cap (legacy behavior). Range 0..1000."),
    AP_INIT_TAKE_ARGV("BotShieldBlockPath",
                 bs_set_block_path, NULL, RSRC_CONF,
                 "Block a named cohort from a path glob. Args: "
                 "<name> <path-glob> <ua> <ipspec>. Path-glob must "
                 "begin with '/'; trailing '*' = prefix match, "
                 "trailing '$' = exact match. Hits return 403 with "
                 "a +100 score penalty under reason "
                 "block-path:<name>."),
    /* E4 — cookie triggers */
    AP_INIT_TAKE_ARGV("BotShieldCookieTrigger",
                 bs_set_cookie_trigger, NULL, RSRC_CONF,
                 "Cookie-based trigger. Args: <name> <cookie-match> "
                 "[key=value ...]. cookie-match is one of: "
                 "cookie=<n>, cookie=<n>=<v>, cookie=<n>~<substr>, "
                 "cookie=<n>!<v>, !cookie=<n>, cookies=<none|any|"
                 "session>, bs-cookie=<verified|missing|invalid>. "
                 "Keys: status=<code|pass> (default pass; diverges "
                 "from E3 — credit/penalty here ALWAYS apply, even "
                 "under pass), redirect=<url>, log=<tag>, flag=<bit>, "
                 "ttl=<sec>, penalty=<n>, credit=<n>. Declaration "
                 "order; pass triggers accumulate credit/penalty "
                 "(layered reputation signals), first non-pass "
                 "trigger short-circuits the response. Upsert-by-"
                 "name."),
    AP_INIT_TAKE1("BotShieldSessionCookieName",
                 bs_set_session_cookie_name, NULL, RSRC_CONF,
                 "Add a cookie name to the list matched by the "
                 "cookies=session predicate. Curated defaults: "
                 "PHPSESSID, JSESSIONID, ASP.NET_SessionId, "
                 "session_id, connect.sid, laravel_session. Each "
                 "invocation appends one name; case-insensitive."),
    /* E6 — env-var triggers */
    AP_INIT_TAKE_ARGV("BotShieldEnvTrigger",
                 bs_set_env_trigger, NULL, RSRC_CONF,
                 "Env-var-based trigger, reads r->subprocess_env. "
                 "Args: <name> <env-match> [key=value ...]. "
                 "env-match is one of: env=<var> (present), "
                 "env=<var>=<value> (exact match, case-sensitive), "
                 "!env=<var> (absent). Keys: status=<code|pass> "
                 "(default pass; credit/penalty apply under pass "
                 "like E4), log=<tag>, flag=<bit>, ttl=<sec>, "
                 "penalty=<n>, credit=<n>. No redirect= (env "
                 "signals are scoring/flagging only). Declaration "
                 "order, first match wins; upsert-by-name. Main "
                 "requests only — subrequests are no-ops."),
    /* E7.3 — feedback triggers (response-path mapping for E5) */
    AP_INIT_TAKE_ARGV("BotShieldFeedbackTrigger",
                 bs_set_feedback_trigger, NULL, RSRC_CONF,
                 "Map an app-signed event (via X-BotShield-Feedback "
                 "header) to module memory. Args: <event> "
                 "[key=value ...]. Required keys: flag=<bit>, "
                 "ttl=<sec>. Optional: log=<tag>. The app signs "
                 "event=<name>;sig=<hex>; the module looks up <name> "
                 "here and applies flag+ttl to the flagged-IP table. "
                 "No status/redirect/penalty/credit (response is "
                 "already served)."),
    /* E11.2 — load-aware throttling triggers */
    AP_INIT_TAKE_ARGV("BotShieldLoadTrigger",
                 bs_set_load_trigger, NULL, RSRC_CONF,
                 "Trigger that fires based on the cached load state "
                 "(see BotShieldLoadStateFile / E11). Args: <name> "
                 "<load-match> [key=value ...]. load-match is one of "
                 "state=<level> or state>=<level> where <level> is "
                 "normal|warm|hot. Keys: status=<code|pass>, "
                 "log=<tag>, penalty=<n>, credit=<n>. flag/ttl/"
                 "redirect rejected — load is global state, not "
                 "per-IP behavior. First-match-wins."),
    /* E3 — path-based triggers */
    AP_INIT_TAKE_ARGV("BotShieldPathTrigger",
                 bs_set_path_trigger, NULL, RSRC_CONF,
                 "Path-based trigger. Args: <name> <path-glob> "
                 "[key=value ...]. Keys: status=<code|pass> (default "
                 "403; 'pass' means the real handler runs), "
                 "redirect=<url> (implies 302 unless status=3xx "
                 "explicit), log=<tag> (emitted as tag=\"<x>\" on "
                 "the decision log), flag=<bit> (M5.1 flag name; "
                 "default scanner_probe), ttl=<sec> (flagged-IP "
                 "TTL; default 3600; 0 = don't flag), penalty=<n> "
                 "(score_add amount on this request; default 0; "
                 "ignored under status=pass). Declaration order, "
                 "first match wins; upsert-by-name."),
    /* E2.2 — robots.txt enforcement */
    AP_INIT_TAKE1("BotShieldRobotsTxt", bs_set_robots_txt,
                 NULL, RSRC_CONF,
                 "Path to a robots.txt file whose Disallow and "
                 "Crawl-delay rules mod_botshield will enforce "
                 "server-side. Parsed at post_config; RFC 9309 "
                 "semantics (prefix + '*' + '$' wildcards, longest-"
                 "match-wins, case-insensitive UA prefix). Blocked "
                 "paths return 403 (reason robots-block:<group>); "
                 "Crawl-delay trips return 429 + Retry-After "
                 "(reason robots-rate:<group>)."),
    AP_INIT_TAKE1("BotShieldRobotsRefreshInterval",
                 bs_set_robots_refresh_interval, NULL, RSRC_CONF,
                 "Seconds between mod_watchdog-driven re-checks of "
                 "the BotShieldRobotsTxt file. On mtime change the "
                 "file is re-parsed and the active rule set is "
                 "atomically swapped — no Apache reload needed. "
                 "Default 60. Set 0 to disable live-refresh and "
                 "require an explicit reload after editing."),
    AP_INIT_TAKE1("BotShieldRobotsWildcardScope",
                 bs_set_robots_wildcard_scope, NULL, RSRC_CONF,
                 "How to apply User-agent: * rules: 'heuristic' "
                 "(default — apply only to UAs that look like "
                 "crawlers), 'strict' (apply to every UA), or "
                 "'off' (ignore * groups entirely). Heuristic mode "
                 "uses a real-browser-prefix denylist (Mozilla/, "
                 "Opera/, Firefox/, Edge/, Safari/) combined with a "
                 "bot-token allowlist (bot/crawl/spider/fetch/"
                 "slurp)."),
    /* E5 — app-to-module reputation feedback */
    AP_INIT_FLAG("BotShieldAppFeedback",
                 bs_set_app_feedback, NULL, RSRC_CONF,
                 "Enable app-to-module reputation feedback via the "
                 "response header set by BotShieldAppFeedbackHeader. "
                 "Default off. When off, the header is still stripped "
                 "from outgoing responses so a misconfigured app can't "
                 "leak it to clients."),
    AP_INIT_TAKE1("BotShieldAppFeedbackHeader",
                 bs_set_app_feedback_header, NULL, RSRC_CONF,
                 "Header name the module reads feedback from. "
                 "Default X-BotShield-Feedback. App sets "
                 "`<header>: flag=<name>;ttl=<sec>[;kid=<id>];sig=<hex>`; "
                 "module validates the HMAC, applies the flag to the "
                 "flagged-IP table, and strips the header before the "
                 "response leaves Apache."),
    /* E8.2 — module-to-app reputation export. */
    AP_INIT_FLAG("BotShieldAppClaims",
                 bs_set_app_claims, NULL, RSRC_CONF,
                 "Enable module-to-app reputation export. When on, "
                 "the module strips any client-supplied X-Botshield-* "
                 "from the request and sets a single signed "
                 "X-Botshield-Claims header before the backend handler "
                 "runs. Default off."),
    AP_INIT_TAKE1("BotShieldAppIntegrationSecretFile",
                 bs_set_app_integration_secret_file, NULL, RSRC_CONF,
                 "Absolute path to the HMAC key used for both inbound "
                 "feedback envelopes and outbound X-Botshield-Claims "
                 "headers. Mode 600, root-owned. The two protocols' "
                 "canonical forms are structurally distinct, so one key "
                 "is safe — cross-replay is blocked by parser shape, "
                 "not key separation. Required only when at least one "
                 "of BotShieldAppFeedback or BotShieldAppClaims is on."),
    { NULL }
};

/* --- Asset-extension skip list ---
 *
 * Requests whose URI ends in one of these suffixes pass through without a
 * challenge. This keeps CSS/JS/images/fonts on the real page from being
 * replaced by the interstitial on first load. Anything not in this list —
 * including JSON, XML, paths with no extension — is subject to the gate. */
static const char *const BS_ASSET_EXTS[] = {
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".ogg",
    NULL
};

static int bs_is_asset_uri(const char *uri)
{
    if (!uri) return 0;
    const char *q = strchr(uri, '?');
    apr_size_t len = q ? (apr_size_t)(q - uri) : strlen(uri);
    for (int i = 0; BS_ASSET_EXTS[i]; i++) {
        apr_size_t elen = strlen(BS_ASSET_EXTS[i]);
        if (len >= elen &&
            strncasecmp(uri + len - elen, BS_ASSET_EXTS[i], elen) == 0) {
            return 1;
        }
    }
    return 0;
}



/* --- Request handler ---
 *
 * Registered at APR_HOOK_FIRST so we run before the default static-file
 * handler. */
static int bs_handler(request_rec *r)
{
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    if (!cfg || cfg->enabled != 1) {
        return DECLINED;
    }
    if (!ap_is_initial_req(r)) {
        return DECLINED;
    }

    /* Module-owned endpoint routing (M8). URLs under BotShieldEndpointPrefix
     * (default /botshield) are served by this module's own handlers, not
     * the tier dispatch. Today:
     *   <prefix>/captcha-verify             — single-provider vhost
     *   <prefix>/captcha-verify/<name>      — per-provider cohabitation
     * The bare form still works for the single-provider case so the old
     * dev config and the first-provider-on-a-vhost case keep working.
     * Done before the debug / asset / cookie paths so operators can hit
     * the verify endpoint regardless of surrounding scope. */
    const char *prefix = cfg->endpoint_prefix
        ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    apr_size_t prefix_len = strlen(prefix);
    if (r->uri && strncmp(r->uri, prefix, prefix_len) == 0 &&
        r->uri[prefix_len] == '/') {
        const char *sub = r->uri + prefix_len;
        if (strcmp(sub, "/captcha-verify") == 0 ||
            strncmp(sub, "/captcha-verify/", 16) == 0) {
            return bs_captcha_verify_handler(r, cfg);
        }
        if (strcmp(sub, "/metrics") == 0) {
            return bs_metrics_handler(r);
        }
        if (strcmp(sub, "/policy-status") == 0) {
            return bs_policy_status_handler(r, cfg);
        }
        /* E17 PoC — embedded silent-verify endpoints. */
        if (strcmp(sub, "/embedded.js") == 0) {
            return bs_embedded_js_handler(r);
        }
        if (strcmp(sub, "/embedded-worker.js") == 0) {
            return bs_embedded_worker_handler(r);
        }
        if (strcmp(sub, "/embedded-bootstrap") == 0) {
            return bs_embedded_bootstrap_handler(r, cfg);
        }
        if (strcmp(sub, "/embedded-verify") == 0) {
            return bs_embedded_verify_handler(r, cfg);
        }
        /* E18.4 — form-widget shell. */
        if (strcmp(sub, "/form-widget.js") == 0) {
            return bs_form_widget_handler(r);
        }
        /* Unknown module endpoint under the prefix → 404, so a typo in
         * an operator's template fails loudly instead of falling through
         * to Apache and serving some unrelated file. */
        r->status = HTTP_NOT_FOUND;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->err_headers_out, "X-Botshield", "unknown-endpoint");
        ap_rputs("Not found.\n", r);
        bs_decision_log(r, "none", "rejected", "-", "-", "-",
                        "unknown_endpoint", 0);
        return OK;
    }

    /* Debug override keeps the first-commit behavior available for tests. */
    if (cfg->debug == 1) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_botshield: debug mode — forcing 403 for %s",
                      r->unparsed_uri);
        r->status = HTTP_FORBIDDEN;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->headers_out,    "Cache-Control", "no-store");
        apr_table_setn(r->err_headers_out, "X-Botshield",  "debug-403");
        ap_rputs("Hello World\n", r);
        bs_decision_log(r, "none", "debug", "-", "-", "-", "-", 0);
        return OK;
    }

    /* Static assets pass through — a cookieless first page load must still
     * render its CSS/images so the PoW page is usable. */
    if (bs_is_asset_uri(r->uri)) {
        bs_decision_log(r, "pass", "declined", "-", "-", "-", "asset", 0);
        return DECLINED;
    }

    int ttl        = bs_effective_int(cfg->cookie_ttl, BS_DEFAULT_COOKIE_TTL);
    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);

    /* Without a secret+algorithm we can't sign challenges or verify cookies.
     * Refuse the scope with a 503 so misconfiguration is immediately visible
     * rather than silently weaker. */
    if (!cfg->secret || !cfg->algorithm) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_botshield: BotShieldEnabled On requires both "
                      "BotShieldSecretFile and BotShieldAlgorithm in scope "
                      "(for %s)", r->uri);
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        apr_table_setn(r->headers_out, "Cache-Control", "no-store");
        apr_table_setn(r->err_headers_out, "X-Botshield", "misconfigured");
        ap_rputs("Service unavailable: mod_botshield misconfigured.\n", r);
        bs_decision_log(r, "none", "misconfigured", "-", "-", "-", "-", 0);
        return OK;
    }

    /* Parse the cookie if present. Three outcomes from bs_verify_cookie:
     *   - NULL reason                  — cookie fully valid; rep is
     *     trustworthy and the holder has solved their PoW. We still
     *     compute effective score so a fresh signal can force a
     *     re-challenge.
     *   - non-NULL, sig did verify     — cookie failed a later check
     *     (expired, PoW counter doesn't satisfy difficulty, etc.).
     *     Rep was server-signed so it's still safe to carry forward.
     *   - non-NULL, "signature mismatch" — HMAC didn't verify; bytes
     *     in the cookie can't be trusted. Discard entirely.
     */
    const char *cookie_val = bs_get_verified_cookie_value(r);
    bs_challenge prior_ch = { 0 };
    int have_prior_rep   = 0;
    int cookie_fully_ok  = 0;
    const char *cookie_verify_reason = NULL;
    int cookie_had_val = (cookie_val && *cookie_val);
    if (cookie_had_val) {
        cookie_verify_reason = bs_verify_cookie(r, cfg, cookie_val, &prior_ch);
        /* MEDIUM #1: render-side carry-forward must reject the same
         * cverrs the issuance-side carry-forward rejects, otherwise
         * an expired cookie's rep can be transplanted via the
         * interstitial-render path (next_rep is baked into the
         * challenge envelope and round-tripped through the JS,
         * arriving at /embedded-verify before the issuance-side
         * predicate sees it). Sharing bs_should_carry_prior_rep
         * keeps the two predicates from drifting. */
        have_prior_rep = bs_should_carry_prior_rep(cookie_verify_reason,
                                                    &prior_ch);
        if (!cookie_verify_reason) {
            cookie_fully_ok = 1;
            /* E10 — safeguard clear on solve. A successful verify
             * proves this client CAN complete a challenge, so any
             * accumulated presentation history was transient noise
             * (mid-session CSP moment, browser cookie glitch). Reset
             * the slot so a later failed solve counts from zero. */
            {
                bs_server_cfg *scfg_sg = ap_get_module_config(
                    r->server->module_config, &botshield_module);
                if (scfg_sg && scfg_sg->safeguard_enabled == 1) {
                    unsigned char sg_ip[16];
                    if (bs_parse_client_ip(r->useragent_ip, sg_ip)) {
                        bs_mask_ipv6_prefix(sg_ip,
                                            scfg_sg->ipv6_prefix_bits);
                        bs_safeguard_clear(r, sg_ip, scfg_sg->ns_id);
                    }
                }
            }
        } else {
            /* Security review LOW #2 — log the cookie name actually
             * present so a sed-renamed test can grep for the right
             * literal. The dual-name helper hides which variant was
             * found; rediscover here for the log line only. */
            const char *which = bs_get_cookie_value(r, BS_COOKIE_NAME_HOST)
                                ? BS_COOKIE_NAME_HOST : BS_COOKIE_NAME;
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_botshield: %s rejected: %s",
                          which, cookie_verify_reason);
        }
    }
    const char *cookie_status =
        bs_decision_cookie_status(cookie_verify_reason, cookie_had_val);

    /* E4 — publish the `_bs_verified` verification verdict as a
     * request note so bs_check_policy's cookie-trigger evaluator
     * can surface it via bs-cookie=<state> predicates. Three-state
     * mapping matches the directive surface. */
    {
        const char *bs_state;
        if (!cookie_had_val)           bs_state = BS_CK_STATE_MISSING;
        else if (!cookie_verify_reason) bs_state = BS_CK_STATE_VERIFIED;
        else                           bs_state = BS_CK_STATE_INVALID;
        apr_table_setn(r->notes, BS_CK_STATE_NOTE, bs_state);
    }

    /* E2.1 + E2.2 + E3 policy enforcement. Runs before scoring
     * heuristics so a block / rate / trigger short-circuits cleanly.
     * Applies to cookie-valid requests too — operator policy
     * (including robots.txt and path-based triggers) is independent
     * of bot-ness. */
    int policy_rv = bs_check_policy(r);
    if (policy_rv == DECLINED) {
        /* E3 trigger with status=pass: log + let the real handler
         * respond. No score, no BotShield interstitial. Flag-IP +
         * tag side effects already applied in bs_check_policy. */
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        bs_decision_log(r, "pass", "declined", cookie_status, "-", "-",
                        reasons, s ? s->total : 0);
        return DECLINED;
    }
    if (policy_rv != OK) {
        bs_request_score *s = bs_get_score(r, 0);
        const char *reasons = bs_score_reasons_joined(r->pool, s);
        const char *outcome;
        if (policy_rv == HTTP_TOO_MANY_REQUESTS)      outcome = "rate_limited";
        else                                          outcome = "rejected";
        bs_decision_log(r, "pass", outcome, cookie_status, "-", "-",
                        reasons, s ? s->total : 0);
        return policy_rv;
    }

    /* Score the request. Heuristics always run — a fully-valid cookie
     * doesn't exempt you from fresh request-level signals that might
     * have pushed you into a tier that requires a re-challenge. */
    bs_run_builtin_heuristics(r);

    /* Flagged-IP table (M5.1): look up the client IP. Hits add the
     * serious-event bitmap's penalty to effective_score, rollback-proof
     * because the flag lives in SHM, not in the cookie.
     *
     * IPv6 native addresses are masked to the operator-configured prefix
     * (default /64) so an attacker can't trivially rotate within their
     * ISP allocation to shed a flag. v4-mapped addresses are left at /32. */
    unsigned char client_ip[16];
    int have_client_ip =
        bs_parse_client_ip(r->useragent_ip, client_ip);
    bs_server_cfg *scfg_h = ap_get_module_config(
        r->server->module_config, &botshield_module);
    if (have_client_ip) {
        bs_mask_ipv6_prefix(client_ip, scfg_h->ipv6_prefix_bits);
    }
    apr_uint32_t ip_flags = 0;
    if (have_client_ip) {
        bs_flagged_ip_lookup(client_ip, &ip_flags, scfg_h->ns_id);
    }
    /* E14 (rework) — score adjustments for IP-side flags now flow
     * through bs_apply_flag_triggers below (which also covers
     * cookie-side flags via the union, and emits per-flag
     * `flag-trigger:<name>` reasons). Keep a coarse 0-weight
     * "flagged-ip" reason here so operators (and tests) reading
     * decision logs still see at a glance "this IP is in the
     * flagged-IP table" without parsing every trigger name. */
    if (ip_flags != 0) {
        bs_score_add(r, 0, 0, "flagged-ip");
    }

    /* First-sight Bloom lookup (M5.2). Policy: only on cookieless or
     * signature-mismatched requests. Sig-verified cookies (even if
     * expired) mean we've already transacted with this browser, so
     * the first-sight signal would just be noise. A valid cookie
     * likewise skips this. */
    if (have_client_ip && !have_prior_rep &&
        !bs_bloom_seen(client_ip, scfg_h->ns_id)) {
        bs_score_add(r, BS_FIRST_SIGHT_PENALTY, 0, "first-sight-ip");
    }

    /* E14 (rework) — flag-trigger walker. Walks scfg->flag_triggers
     * over the union of IP-side and cookie-side flag bits, applying
     * `score add=N` actions via bs_score_add (which SUMs into the
     * per-request score) and accumulating MAX into a tier_floor that
     * we apply after bs_decide_tier. Built-in defaults are seeded at
     * post_config; operators tune via BotShieldFlagTrigger. */
    apr_uint32_t all_flags = ip_flags
        | (have_prior_rep ? prior_ch.rep.flags : 0);
    bs_tier tier_floor_from_flags = BS_TIER_PASS;
    bs_apply_flag_triggers(r, scfg_h, all_flags, &tier_floor_from_flags);

    /* Fetch the score struct *after* all per-request adds. Using create=1
     * so a request with zero hits still gets a valid (empty) pointer and
     * the log line prints reasons=[] consistently. */
    bs_request_score *score = bs_get_score(r, 1);
    int heuristic_total = score->total;

    /* effective_score = per-request heuristic total (already inclusive
     * of any flag-trigger SCORE actions applied above) + the cookie's
     * accumulated rep score. Operator-facing tuning workflow lives
     * in the README "Understanding scoring" section. */
    int cookie_score = have_prior_rep ? prior_ch.rep.score : 0;
    int effective    = heuristic_total + cookie_score;
    bs_tier score_tier = bs_decide_tier(cfg, effective);

    /* Apply the tier floor accumulated by the flag-trigger walker
     * (MAX of any TIER_FLOOR actions across the union of flags).
     * The score-derived tier wins when it's already at-or-above the
     * floor — we never silently downgrade. */
    bs_tier tier = (tier_floor_from_flags > score_tier)
                 ? tier_floor_from_flags : score_tier;
    if (tier_floor_from_flags > score_tier) {
        bs_score_add(r, 0, 0,
            apr_psprintf(r->pool, "flag-tier-floor:%s",
                         bs_tier_name(tier_floor_from_flags)));
    }

    /* BotShieldFlagIP: if any scope the request matched sets flag bits,
     * land them in the flagged-IP table now. Fires on every hit to the
     * scope, so honeypot paths and scanner-trap paths should be reached
     * only by actors that deserve the flag. */
    if (cfg->flag_on_match && have_client_ip) {
        bs_flagged_ip_add(r, client_ip, cfg->flag_on_match,
                          cfg->flag_on_match_ttl
                            ? cfg->flag_on_match_ttl : 3600,
                          scfg_h->ns_id);
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
            "mod_botshield: flagged IP %s bits=0x%x ttl=%d scope=%s",
            r->useragent_ip, (unsigned)cfg->flag_on_match,
            cfg->flag_on_match_ttl ? cfg->flag_on_match_ttl : 3600,
            r->uri);
    }

    /* Happy path: score below the silent threshold → pass through.
     * If there's no cookie this means no cookie is ever issued —
     * legitimate users experience mod_botshield as invisible. */
    if (tier == BS_TIER_PASS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_botshield: pass %s effective=%d "
                      "(heuristic=%d cookie_score=%d "
                      "ip_flags=0x%x cookie_flags=0x%x) cookie_ok=%d",
                      r->uri, effective, heuristic_total, cookie_score,
                      (unsigned)ip_flags,
                      have_prior_rep ? (unsigned)prior_ch.rep.flags : 0,
                      cookie_fully_ok);
        /* E8.2 — module-to-app reputation export. Strip incoming
         * X-Botshield-* and set a single signed claim envelope so
         * the backend handler reads sanctioned BotShield state
         * without poking at the (encrypted post-E8.1) cookie. */
        {
            bs_server_cfg *scfg2 = ap_get_module_config(
                r->server->module_config, &botshield_module);
            apr_uint32_t composite_flags = ip_flags
                | (have_prior_rep ? prior_ch.rep.flags : 0);
            const char *cerr = bs_app_claims_set(r, scfg2,
                effective, tier, cookie_status, composite_flags,
                have_prior_rep ? prior_ch.rep.passes_silent  : 0,
                have_prior_rep ? prior_ch.rep.passes_form    : 0,
                have_prior_rep ? prior_ch.rep.passes_captcha : 0);
            if (cerr) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                    "mod_botshield: app claims not emitted: %s", cerr);
            }
        }
        bs_decision_log(r, "pass", "declined", cookie_status,
                        "-", "-",
                        bs_decision_reason_names(r->pool, score),
                        effective);
        return DECLINED;
    }

    /* Not pass tier — we will issue a challenge. Feed the Bloom filter
     * now that we've committed to challenging this client; that keeps
     * writes off the ~99% happy path. */
    if (have_client_ip) bs_bloom_add(client_ip, scfg_h->ns_id);

    /* E10 — challenge safeguard. Before actually issuing the
     * challenge, check whether this IP has been presented N times
     * within the window without solving. If so, flip to a pass-
     * through with reason=challenge-safeguard so a broken client
     * (JS blocked, CSP-stripped, cookie handling buggy) stops
     * being looped on the same challenge. Otherwise record this
     * presentation and proceed. Safeguard runs AFTER bs_check_policy
     * by construction (we're already past the policy short-circuit
     * returns), so 403/429 blocks still win. */
    {
        bs_server_cfg *scfg_sg = ap_get_module_config(
            r->server->module_config, &botshield_module);
        if (scfg_sg && have_client_ip) {
            apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
            /* Active-state behavior is gated on safeguard_enabled —
             * an operator who hasn't opted into safeguard doesn't
             * want pass-through-after-N. */
            if (scfg_sg->safeguard_enabled == 1 &&
                bs_safeguard_check(client_ip, now_t, scfg_sg->ns_id)) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                    "mod_botshield: challenge-safeguard active for "
                    "%s; skipping challenge-issue and passing "
                    "through (until=%" APR_INT64_T_FMT ")",
                    r->useragent_ip, (apr_int64_t)now_t);
                bs_score_add(r, 0, 0, "challenge-safeguard");
                bs_decision_log(r, "safeguard", "declined",
                                cookie_status, "-", "-",
                                bs_decision_reason_names(r->pool, score),
                                effective);
                return DECLINED;
            }
            /* Record the presentation regardless of safeguard_enabled.
             * E17's embedded → M7 fallback reads the same count to
             * decide when to bypass the embedded short-circuit. The
             * write itself is cheap (one mutex + a few SHM stores);
             * the only side-effect when safeguard is "off" is that
             * embedded mode gets the count it needs. */
            int sg_threshold = bs_safeguard_effective_int(
                scfg_sg->safeguard_threshold,
                BS_DEFAULT_SAFEGUARD_THRESHOLD);
            int sg_window = bs_safeguard_effective_int(
                scfg_sg->safeguard_window,
                BS_DEFAULT_SAFEGUARD_WINDOW);
            int sg_ttl = bs_safeguard_effective_int(
                scfg_sg->safeguard_ttl,
                BS_DEFAULT_SAFEGUARD_TTL);
            bs_safeguard_record_presentation(r, client_ip,
                                             sg_threshold, sg_window,
                                             sg_ttl,
                                             now_t,
                                             scfg_sg->ns_id);
        }
    }

    /* E17 — silent-tier dispatch with embedded mode. Default behavior:
     * skip the M7 interstitial, serve the real page (DECLINED), let
     * the wrapper handle verification in the background. Timing model:
     * "kicks in eventually" — see PLAN E17.
     *
     * E17 fallback: if this client has had N consecutive silent-tier
     * dispatches without _bs_verified arriving (count tracked via
     * bs_safeguard_present_count), the wrapper isn't doing its job
     * (CSP-blocked, no JS, no Worker support, etc.). Bypass the
     * embedded short-circuit so the M7 form-PoW path runs. M7's own
     * safeguard threshold catches the case where M7 also fails. */
    if (tier == BS_TIER_SILENT &&
        cfg->silent_mode == BS_SILENT_MODE_EMBEDDED) {
        int fall_back = 0;
        if (have_client_ip) {
            apr_int64_t now_t = (apr_int64_t)apr_time_sec(apr_time_now());
            apr_uint32_t cnt = bs_safeguard_present_count(client_ip,
                                                          now_t,
                                                          scfg_h->ns_id);
            if (cnt >= BS_DEFAULT_EMBEDDED_FALLBACK_THRESHOLD) {
                fall_back = 1;
            }
        }
        if (!fall_back) {
            bs_decision_log(r, "silent", "declined", cookie_status,
                            "-", "-",
                            bs_decision_reason_names(r->pool, score),
                            effective);
            return DECLINED;
        }
        /* Fall through to M7 — the embedded path has had its
         * chances. Surface the decision in the reason chain so
         * operators can spot clients stuck in this state. */
        bs_score_add(r, 0, 0, "embedded-fallback-m7");
    }

    /* Decide whether this challenge will be served as the M7 silent-tier
     * auto-submit splash or as the form-PoW interstitial. Captcha tier
     * (M8) still stubs to form until that ships. */
    int issue_auto = (tier == BS_TIER_SILENT);

    /* Build the rep state to carry into the new cookie. Forgiveness +
     * pass-counter bump are picked from the tier the *prior* cookie was
     * served under (prior_ch.auto_tier), because that records what the
     * user actually just solved. First-time challenges have no prior
     * tier, so they increment whichever counter matches the tier we're
     * about to issue. */
    bs_rep_state next_rep;
    if (have_prior_rep) {
        int forgive = prior_ch.auto_tier
            ? bs_effective_int(cfg->forgive_silent, BS_DEFAULT_FORGIVE_SILENT)
            : bs_effective_int(cfg->forgive_form,   BS_DEFAULT_FORGIVE_FORM);
        /* E15 — clamp against the per-cookie hourly cap
         * and surface the granted vs requested via reason chain when
         * the cap kicks in. */
        int cap = scfg_h && scfg_h->forgive_cap_per_hour > 0
                ? scfg_h->forgive_cap_per_hour
                : BS_DEFAULT_FORGIVE_CAP_PER_HOUR;
        apr_uint32_t now_sec = (apr_uint32_t)apr_time_sec(apr_time_now());
        next_rep = prior_ch.rep;
        int requested = forgive;
        forgive = bs_forgiveness_apply_cap(forgive, cap, now_sec,
                    &next_rep.forgive_window_start,
                    &next_rep.forgive_consumed);
        if (forgive < requested) {
            bs_score_add(r, 0, 0,
                apr_psprintf(r->pool,
                    "forgive-capped:%d/%d",
                    forgive, requested));
        }
        /* E14 (rework) — bs_flag_penalty floor retired. Flag effects
         * are re-applied at request time via bs_apply_flag_triggers,
         * so a forgiven-to-zero score on a flagged cookie is simply
         * re-raised on the next request when the trigger fires. */
        int new_score = prior_ch.rep.score - forgive;
        if (new_score < 0) new_score = 0;
        next_rep.score = new_score;
        if (prior_ch.auto_tier) {
            next_rep.passes_silent = 1;  /* LOW #7 clamp */
        } else {
            next_rep.passes_form = 1;  /* LOW #7 clamp */
        }
    } else {
        next_rep.score          = 0;
        next_rep.flags          = 0;
        next_rep.passes_silent  = issue_auto ? 1 : 0;
        next_rep.passes_form    = issue_auto ? 0 : 1;
        next_rep.passes_captcha = 0;
        next_rep.challenged_at  = 0;   /* overwritten by issue() */
        next_rep.forgive_window_start = 0;
        next_rep.forgive_consumed     = 0;
    }

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                  "mod_botshield: challenging %s (alg=%s, difficulty=%d, "
                  "ttl=%d) effective=%d tier=%s heuristic=%d reasons=%s "
                  "cookie_score=%d cookie_flags=0x%x cookie_ok=%d "
                  "passes=[s:%d f:%d c:%d]",
                  r->unparsed_uri, cfg->algorithm->name, difficulty, ttl,
                  effective, bs_tier_name(tier), heuristic_total,
                  bs_score_reasons_joined(r->pool, score),
                  have_prior_rep ? cookie_score : -1,
                  have_prior_rep ? (unsigned)prior_ch.rep.flags : 0,
                  cookie_fully_ok,
                  next_rep.passes_silent, next_rep.passes_form,
                  next_rep.passes_captcha);
    /* E14 (rework) — difficulty bumps are no longer derived from
     * flags. The reworked design promoted tier (silent / form /
     * captcha) to the primary lever via BotShieldFlagTrigger
     * action=tier_floor; difficulty stays at the operator-configured
     * BotShieldDifficulty. If a real future need for "harder PoW for
     * this signal" surfaces, add a difficulty action verb at that
     * time; do not pre-emptively reintroduce one. */

    /* Issue a fresh signed challenge; the worker reads it from the page.
     * The next_rep struct carries forgiveness-adjusted rep from any
     * sig-verified prior cookie. */
    bs_challenge challenge;
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          issue_auto, NULL,
                                          &next_rep, &challenge);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_botshield: issue failed: %s", ierr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("Service error: could not issue challenge.\n", r);
        bs_decision_log(r, bs_tier_name(tier), "misconfigured",
                        cookie_status, "-", "-", "issue_failed", effective);
        return OK;
    }
    const char *challenge_js = bs_challenge_json(r, r->pool, cfg, &challenge);
    if (!challenge_js) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: GCM cookie-prefix encryption failed; "
            "cannot render interstitial");
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        bs_decision_log(r, bs_tier_name(tier), "misconfigured",
                        cookie_status, "-", "-", "issue_failed", effective);
        return OK;
    }

    int use_captcha_widget = bs_render_challenge_page(r, cfg, tier,
                                                     challenge_js,
                                                     issue_auto);

    /* Decision log for the challenge we just served. For non-captcha
     * tiers the provider/alg are the PoW algorithm the cookie will be
     * signed under; captcha tier names the configured provider and its
     * cookie alg. When captcha tier falls through to form-PoW (no
     * provider configured), report the actual served tier (form) with
     * reason "captcha_fallback". */
    const char *served_tier_name = bs_tier_name(tier);
    const char *served_provider  = "-";
    const char *served_alg       = cfg->algorithm
                                   ? cfg->algorithm->name : "-";
    const char *served_reason    = bs_decision_reason_names(r->pool, score);
    if (use_captcha_widget) {
        served_provider = cfg->captcha_provider->name;
        served_alg      = apr_psprintf(r->pool, "captcha-%s",
                                       cfg->captcha_provider->name);
    } else if (tier == BS_TIER_CAPTCHA) {
        /* Captcha tier asked for but no provider configured on this
         * scope — interstitial we actually served is form-PoW. Label
         * honestly. */
        served_tier_name = "form";
        served_reason    = (!score || !score->entries ||
                            score->entries->nelts == 0)
            ? "captcha_fallback"
            : apr_pstrcat(r->pool, "captcha_fallback,", served_reason, NULL);
    }
    bs_decision_log(r, served_tier_name, "challenged", cookie_status,
                    served_provider, served_alg, served_reason, effective);
    return OK;
}


/* --- Hook registration --- */

/* Gated under the same BS_FUZZ_HARNESS flag as the module
 * declaration below: the hook-registration calls (ap_hook_*,
 * APR_OPTIONAL_HOOK) reference Apache symbols the fuzz harness
 * doesn't link against, and the fuzz target never invokes this
 * function. No effect on the normal apxs build. */
#ifndef BS_FUZZ_HARNESS
static void bs_register_hooks(apr_pool_t *p)
{
    (void)p;
    ap_hook_post_config (bs_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init  (bs_child_init,  NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler     (bs_handler,     NULL, NULL, APR_HOOK_FIRST);
    /* E18 — inline form captcha. Fixup runs before content handlers
     * but after auth/header processing, so the request body is still
     * readable from the input filter chain. The hook reads + validates
     * + decides whether to let the downstream handler proceed. */
    ap_hook_fixups      (bs_form_captcha_fixup,
                         NULL, NULL, APR_HOOK_MIDDLE);
    bs_form_replay_filter_handle = ap_register_input_filter(
        "BS_FORM_REPLAY", bs_form_replay_filter, NULL,
        AP_FTYPE_RESOURCE);
    /* E5 — response-phase filter for the app-feedback header. Filter
     * runs once per request (self-removes), strips the configured
     * header from r->headers_out, and — when the feature is enabled
     * and the header is well-formed — HMAC-verifies and applies the
     * flag to the flagged-IP table. Registered here (filter + the
     * insert hook) so every request has it in the chain; cheap
     * until a real header appears. AP_FTYPE_CONTENT_SET puts us
     * before the network filters so headers modifications land
     * before the protocol flush. */
    /* Filter type picked to run AFTER mod_headers. mod_headers has
     * several stages and its late filter re-applies the "always"
     * directive even after we've stripped. Running at
     * AP_FTYPE_PROTOCOL - 1 (just past mod_headers' FIXUP_HEADERS_OUT
     * at CONTENT_SET but before the protocol serializer) gives the
     * widest window for the normal response chain. */
    bs_app_feedback_filter_handle = ap_register_output_filter(
        "BOTSHIELD_APP_FEEDBACK", bs_app_feedback_filter, NULL,
        AP_FTYPE_PROTOCOL - 1);
    /* Register on BOTH the normal-response chain and the error-
     * response chain. Apache builds a separate filter chain when
     * `ap_die` runs for a 4xx/5xx response (including 404 from a
     * missing file, error-from-handler, and ErrorDocument
     * redirects); the insert_filter hook doesn't fire there, so
     * without the error-filter registration the header would leak
     * to clients on any error response that mod_headers decorated.
     * Same handle, same callback — the filter is idempotent and
     * one-shot per request, so double-registration is safe. */
    ap_hook_insert_filter      (bs_app_feedback_insert_filter,
                                NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_error_filter(bs_app_feedback_insert_filter,
                                NULL, NULL, APR_HOOK_MIDDLE);
    /* mod_status optional hook: fires only when mod_status is loaded.
     * If it isn't, APR_OPTIONAL_HOOK silently registers nothing — no
     * hot-path cost and no hard linkage to mod_status. */
    APR_OPTIONAL_HOOK(ap, status_hook, bs_status_hook,
                      NULL, NULL, APR_HOOK_MIDDLE);
}
#endif

/* The module declaration pulls in Apache's core runtime symbols
 * (hooks, module registration) that the LibFuzzer harness in
 * tests/fuzz/ doesn't link against. Wrap it so the fuzz target can
 * #include this file verbatim without fighting the linker. No
 * effect on the normal apxs build. */
#ifndef BS_FUZZ_HARNESS
/* The .so is compiled with -fvisibility=hidden so internal cross-file
 * symbols (bs_flagged_ip_lookup, bs_state_save, etc.) don't leak into
 * the dynamic-linker symbol table. Apache's LoadModule resolves the
 * module entry via dlsym, though, so this one symbol must stay
 * exported with default visibility. */
#pragma GCC visibility push(default)
AP_DECLARE_MODULE(botshield) = {
    STANDARD20_MODULE_STUFF,
    bs_create_dir_cfg,    /* per-directory config creator */
    bs_merge_dir_cfg,     /* per-directory config merger  */
    bs_create_server_cfg, /* per-server config creator    */
    bs_merge_server_cfg,  /* per-server config merger     */
    bs_cmds,              /* config directives            */
    bs_register_hooks,    /* hook registration            */
    AP_MODULE_FLAG_NONE   /* flags                        */
};
#pragma GCC visibility pop
#endif
