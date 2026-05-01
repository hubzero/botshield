/* metrics.c — implementations behind metrics.h. Decision log,
 * M9.2 counter increments, M9.2 SHM gauge readers (with thread-
 * local 1s cache), M9.3 Prometheus exposition handler, and the
 * mod_status contribution. */

#include "metrics.h"
#include "shm.h"

#include <string.h>

#include <apr_atomic.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>

#include <http_log.h>
#include <http_protocol.h>
#include <mod_status.h>

/* ======================================================================
 * M9.2 string → counter index lookups
 *
 * Values mirror the M9.1 enum strings verbatim. Unknown strings
 * return -1; the caller logs one WARNING and skips the increment
 * rather than silently corrupt counters (the validator should catch
 * drift at the M9.1 gate, this is defense-in-depth).
 * ====================================================================== */

static int bs_m_tier_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "none")    == 0) return BS_M_TIER_NONE;
    if (strcmp(s, "pass")    == 0) return BS_M_TIER_PASS;
    if (strcmp(s, "silent")  == 0) return BS_M_TIER_SILENT;
    if (strcmp(s, "form")    == 0) return BS_M_TIER_FORM;
    if (strcmp(s, "captcha") == 0) return BS_M_TIER_CAPTCHA;
    /* E10 — safeguard activations land in the decision log as
     * tier="safeguard" so operators can grep/filter for them
     * (semantically distinct from a regular pass). For metrics we
     * bin them into the pass counter — they are functionally
     * pass-through (no challenge issued, request reaches origin).
     * Operators wanting to dashboard safeguard rate scrape the
     * decision log for reason="challenge-safeguard". */
    if (strcmp(s, "safeguard") == 0) return BS_M_TIER_PASS;
    return -1;
}

static int bs_m_outcome_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "allow")            == 0) return BS_M_OUTCOME_ALLOW;
    if (strcmp(s, "challenged")       == 0) return BS_M_OUTCOME_CHALLENGED;
    if (strcmp(s, "verified")         == 0) return BS_M_OUTCOME_VERIFIED;
    if (strcmp(s, "block")            == 0) return BS_M_OUTCOME_BLOCK;
    if (strcmp(s, "failopen")         == 0) return BS_M_OUTCOME_FAILOPEN;
    if (strcmp(s, "rate_limited")     == 0) return BS_M_OUTCOME_RATE_LIMITED;
    if (strcmp(s, "inflight_capped")  == 0) return BS_M_OUTCOME_INFLIGHT_CAPPED;
    if (strcmp(s, "pending_missing")  == 0) return BS_M_OUTCOME_PENDING_MISSING;
    if (strcmp(s, "misconfigured")    == 0) return BS_M_OUTCOME_MISCONFIGURED;
    if (strcmp(s, "debug")            == 0) return BS_M_OUTCOME_DEBUG;
    if (strcmp(s, "redirect")         == 0) return BS_M_OUTCOME_REDIRECT;
    return -1;
}

static int bs_m_cookie_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "ok")         == 0) return BS_M_COOKIE_OK;
    if (strcmp(s, "expired")    == 0) return BS_M_COOKIE_EXPIRED;
    if (strcmp(s, "bad_sig")    == 0) return BS_M_COOKIE_BAD_SIG;
    if (strcmp(s, "bad_format") == 0) return BS_M_COOKIE_BAD_FORMAT;
    if (strcmp(s, "absent")     == 0) return BS_M_COOKIE_ABSENT;
    if (strcmp(s, "minted")     == 0) return BS_M_COOKIE_MINTED;
    return -1;
}

static int bs_m_provider_idx(const char *s)
{
    if (!s) return -1;
    if (strcmp(s, "turnstile")    == 0) return BS_M_PROV_TURNSTILE;
    if (strcmp(s, "hcaptcha")     == 0) return BS_M_PROV_HCAPTCHA;
    if (strcmp(s, "recaptcha-v2") == 0) return BS_M_PROV_RECAPTCHA_V2;
    if (strcmp(s, "recaptcha-v3") == 0) return BS_M_PROV_RECAPTCHA_V3;
    if (strcmp(s, "friendly")     == 0) return BS_M_PROV_FRIENDLY;
    if (strcmp(s, "geetest")      == 0) return BS_M_PROV_GEETEST;
    return -1;
}

/* ======================================================================
 * M9.2 on-demand gauge readers
 *
 * Called by the metrics export handler when a scraper GETs
 * /botshield/metrics. Not called on the hot decision path. Results
 * cached for 1 second via a thread-local struct so concurrent
 * scrapes don't each walk the flagged-IP table or popcount the
 * Bloom buffers.
 *
 * The cache is deliberately process-local (not SHM) so a read by
 * one worker doesn't stale the value for another — if two workers
 * answer two concurrent scrapes they each do their own computation,
 * but each is still bounded at 1 Hz per worker.
 * ====================================================================== */

typedef struct {
    apr_time_t   expires_at;
    apr_uint64_t flagged_used;
    apr_uint64_t strike_used;
    apr_uint64_t safeguard_used;
    apr_uint64_t bloom_bits_active;
    apr_uint64_t bloom_bits_warming;
} bs_gauge_cache;

static __thread bs_gauge_cache bs_gauges = {0, 0, 0, 0, 0, 0};
#define BS_GAUGE_CACHE_TTL_US (1000 * 1000)  /* 1 second */

static void bs_gauges_refresh(void)
{
    apr_time_t now = apr_time_now();
    if (now < bs_gauges.expires_at) return;

    apr_int64_t now_sec = (apr_int64_t)apr_time_sec(now);
    apr_uint64_t flagged_used = 0;
    /* Relaxed atomic loads on slot->version
     * make TSAN happy with the concurrent read. Estimate is fine
     * (already documented). */
    if (bs_shm.flagged_table) {
        for (apr_size_t i = 0; i < bs_shm.flagged_capacity; i++) {
            const bs_flagged_ip_slot *slot = &bs_shm.flagged_table[i];
            apr_uint32_t v = __atomic_load_n(&slot->version,
                                              __ATOMIC_RELAXED);
            if ((v & 1U) == 0 &&
                slot->used != 0 &&
                slot->expires_at > now_sec) {
                flagged_used++;
            }
        }
    }
    /* E13.1 — strike + safeguard occupancy. "Used" here means the
     * slot would force a probe walk (used != 0), regardless of
     * whether the entry is still TTL-active. That's the right view
     * for load-factor-based probe-saturation warnings. */
    apr_uint64_t strike_used = 0;
    if (bs_shm.strike_table) {
        for (apr_size_t i = 0; i < bs_shm.strike_capacity; i++) {
            const bs_strike_slot *slot = &bs_shm.strike_table[i];
            apr_uint32_t v = __atomic_load_n(&slot->version,
                                              __ATOMIC_RELAXED);
            if ((v & 1U) == 0 && slot->used != 0) {
                strike_used++;
            }
        }
    }
    apr_uint64_t safeguard_used = 0;
    if (bs_shm.safeguard_table) {
        for (apr_size_t i = 0; i < bs_shm.safeguard_capacity; i++) {
            const bs_safeguard_slot *slot = &bs_shm.safeguard_table[i];
            apr_uint32_t v = __atomic_load_n(&slot->version,
                                              __ATOMIC_RELAXED);
            if ((v & 1U) == 0 && slot->used != 0) {
                safeguard_used++;
            }
        }
    }
    apr_uint64_t bloom_active = 0, bloom_warming = 0;
    if (bs_shm.bloom_bufs[0] && bs_shm.bloom_buf_bytes) {
        apr_uint32_t act = apr_atomic_read32(&bs_shm.header->bloom_active);
        apr_size_t bb = bs_shm.bloom_buf_bytes;
        bloom_active  = bs_popcount_buffer(bs_shm.bloom_bufs[act & 1U], bb);
        bloom_warming = bs_popcount_buffer(bs_shm.bloom_bufs[(act & 1U) ^ 1], bb);
    }

    bs_gauges.flagged_used       = flagged_used;
    bs_gauges.strike_used        = strike_used;
    bs_gauges.safeguard_used     = safeguard_used;
    bs_gauges.bloom_bits_active  = bloom_active;
    bs_gauges.bloom_bits_warming = bloom_warming;
    bs_gauges.expires_at         = now + BS_GAUGE_CACHE_TTL_US;
}

static apr_uint64_t bs_metrics_flagged_used(void)
{
    bs_gauges_refresh();
    return bs_gauges.flagged_used;
}

static apr_uint64_t bs_metrics_strike_used(void)
{
    bs_gauges_refresh();
    return bs_gauges.strike_used;
}

static apr_uint64_t bs_metrics_safeguard_used(void)
{
    bs_gauges_refresh();
    return bs_gauges.safeguard_used;
}

static apr_uint64_t bs_metrics_bloom_bits(int active_buf)
{
    bs_gauges_refresh();
    return active_buf ? bs_gauges.bloom_bits_active
                      : bs_gauges.bloom_bits_warming;
}

static apr_uint32_t bs_metrics_inflight_cur(void)
{
    if (!bs_shm.cv_inflight) return 0;
    return apr_atomic_read32(bs_shm.cv_inflight);
}

/* ======================================================================
 * M9.2 counter bump
 * ====================================================================== */

/* Bump the M9.2 counters for one decision emission. `cookie` and
 * `provider` may be "-" (not applicable); those dimensions skip.
 * Unknown enum strings log one WARNING and skip that dimension — a
 * loud signal that the producer/consumer drifted out of sync. */
static void bs_metrics_bump(request_rec *r,
                            const char *tier, const char *outcome,
                            const char *cookie, const char *provider)
{
    if (!bs_shm.metrics) return;

    int ti = bs_m_tier_idx(tier);
    int oi = bs_m_outcome_idx(outcome);
    int ci = (cookie && strcmp(cookie, "-") != 0)
             ? bs_m_cookie_idx(cookie) : -1;
    int pi = (provider && strcmp(provider, "-") != 0)
             ? bs_m_provider_idx(provider) : -1;

    if (ti >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->tier[ti], 1, __ATOMIC_RELAXED);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown tier=\"%s\" - skipped",
            tier ? tier : "(null)");
    }
    if (oi >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->outcome[oi], 1, __ATOMIC_RELAXED);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown outcome=\"%s\" - skipped",
            outcome ? outcome : "(null)");
    }
    if (ci >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->cookie[ci], 1, __ATOMIC_RELAXED);
    } else if (cookie && strcmp(cookie, "-") != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown cookie=\"%s\" - skipped",
            cookie);
    }
    if (pi >= 0) {
        __atomic_fetch_add(&bs_shm.metrics->provider[pi], 1, __ATOMIC_RELAXED);
    } else if (provider && strcmp(provider, "-") != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: metrics: unknown provider=\"%s\" - skipped",
            provider);
    }
}

/* ======================================================================
 * Cookie-status enum mapper
 * ====================================================================== */

const char *bs_decision_cookie_status(const char *verify_reason,
                                      int had_cookie)
{
    if (!had_cookie) return "absent";
    if (!verify_reason) return "ok";
    if (strcmp(verify_reason, "expired") == 0) return "expired";
    if (strcmp(verify_reason, "signature mismatch") == 0) return "bad_sig";
    return "bad_format";
}

/* ======================================================================
 * Trigger-tag stash on r->notes
 *
 * Set by trigger walks when a matching rule carries an operator
 * `log_tag`. Read by bs_decision_log so the tag rides on the
 * decision line as an extra `tag="..."` field without changing the
 * 30-call-site signature.
 * ====================================================================== */

#define BS_TRIGGER_TAG_NOTE   "botshield-trigger-tag"

void bs_set_trigger_tag(request_rec *r, const char *tag)
{
    if (!tag || !*tag) return;
    apr_table_setn(r->notes, BS_TRIGGER_TAG_NOTE,
                   apr_pstrdup(r->pool, tag));
}

static const char *bs_get_trigger_tag(request_rec *r)
{
    return apr_table_get(r->notes, BS_TRIGGER_TAG_NOTE);
}

#define BS_WOULD_OUTCOME_NOTE "botshield-would-outcome"

/* Severity ordering for would-outcomes. When multiple suppression
 * sites fire on the same request (e.g. a BlockPath observed AND
 * tier-dispatch suppressed), the most-severe stashed value wins for
 * the outcome field — operators want the strongest action the
 * policy wanted, not the last-evaluated. */
static int bs_would_severity(const char *would)
{
    if (!would) return 0;
    if (strcmp(would, "~block")        == 0) return 4;
    if (strcmp(would, "~rate_limited") == 0) return 3;
    if (strcmp(would, "~challenge")    == 0) return 2;
    return 1;
}

void bs_set_would_outcome(request_rec *r, const char *would)
{
    if (!would || !*would) return;
    const char *cur = apr_table_get(r->notes, BS_WOULD_OUTCOME_NOTE);
    if (bs_would_severity(would) > bs_would_severity(cur)) {
        apr_table_setn(r->notes, BS_WOULD_OUTCOME_NOTE,
                       apr_pstrdup(r->pool, would));
    }
}

static const char *bs_get_would_outcome(request_rec *r)
{
    return apr_table_get(r->notes, BS_WOULD_OUTCOME_NOTE);
}

/* ======================================================================
 * Decision log
 * ====================================================================== */

/* Sanitize a string for inclusion inside the `key="value"` quoted
 * fields of the decision log.
 *
 * Browsers always %22-encode '"' in URIs but a hand-rolled HTTP
 * client can send a literal '"' raw; without sanitization it would
 * close the quoting and mis-tokenize the rest of the line for
 * downstream log parsers.
 *
 * Why URL-encoding instead of backslash-escaping: Apache's error-
 * log writer escapes embedded '\' bytes (each '\' becomes "\\" in
 * the log file) but does NOT escape '"'. A naive '"'→'\"' approach
 * therefore lands in the log as '\\"' — three characters that a
 * standard string-literal parser reads as escaped-backslash +
 * close-quote, which still mis-tokenizes. Percent-encoding the
 * troublesome bytes ('"' → "%22", '\' → "%5C") survives Apache's
 * pass-through unchanged and remains operator-readable since the
 * surrounding URI context is already URL-shaped.
 *
 * Fast path: if the input contains no '"' or '\', returns the
 * input pointer unchanged — zero copy, zero pool allocation.
 * Common case for typical request URIs and reason names. */
static const char *bs_log_quote(apr_pool_t *p, const char *s)
{
    if (!s) return "-";
    apr_size_t extra = 0;
    for (const char *q = s; *q; q++) {
        if (*q == '"' || *q == '\\') extra += 2;  /* '"' → "%22"; '\' → "%5C" */
    }
    if (extra == 0) return s;
    apr_size_t in_len = strlen(s);
    char *out = apr_palloc(p, in_len + extra + 1);
    char *w = out;
    for (const char *q = s; *q; q++) {
        if (*q == '"') {
            *w++ = '%'; *w++ = '2'; *w++ = '2';
        } else if (*q == '\\') {
            *w++ = '%'; *w++ = '5'; *w++ = 'C';
        } else {
            *w++ = *q;
        }
    }
    *w = '\0';
    return out;
}

/* mod_log_config's config_log_transaction evaluates the env=NAME
 * conditional against the original request_rec passed to
 * log_transaction, then walks r->next forward to find the last
 * request in the chain and renders %{NAME}e tokens against THAT
 * request_rec. For requests that hit an internal_redirect (e.g.
 * mod_rewrite's per-Directory `RewriteRule (.*) index.php`, used
 * by HUBzero/Joomla/Drupal/WordPress and friends), the forward
 * request_rec's subprocess_env was deep-copied from the original
 * but every key was prefixed with "REDIRECT_" by the
 * rename_original_env transformation in
 * server/protocol.c::internal_internal_redirect. Our un-prefixed
 * BS_* and BOTSHIELD env vars don't survive on the forward request_rec,
 * so the env=BOTSHIELD conditional matches against the original
 * (BOTSHIELD set there) but the format render — running on the
 * forward — sees only REDIRECT_BOTSHIELD and renders every
 * %{BS_NAME}e as "-".
 *
 * Fix: at ap_hook_log_transaction APR_HOOK_FIRST (running
 * immediately before mod_log_config's APR_HOOK_MIDDLE hook on the
 * same request), walk r->next forward and copy our
 * BS_* and BOTSHIELD env vars from the origin to whatever the last
 * request_rec in the chain is. mod_log_config then renders against
 * a request_rec where the un-prefixed names exist with the right
 * values. No-op when there's no chain. */
int bs_propagate_decision_env(request_rec *r)
{
    if (!r->next) return DECLINED;
    request_rec *fwd = r;
    while (fwd->next) fwd = fwd->next;
    if (fwd == r) return DECLINED;
    const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
    apr_table_entry_t *elts = (apr_table_entry_t *)arr->elts;
    for (int i = 0; i < arr->nelts; i++) {
        if (!elts[i].key || !elts[i].val) continue;
        if (strncmp(elts[i].key, "BS_", 3) == 0
            || strcmp(elts[i].key, "BOTSHIELD") == 0) {
            apr_table_setn(fwd->subprocess_env,
                           elts[i].key, elts[i].val);
        }
    }
    return DECLINED;
}

void bs_decision_log(request_rec *r,
                     const char *tier,
                     const char *outcome,
                     const char *cookie,
                     const char *provider,
                     const char *alg,
                     const char *reason,
                     int score)
{
    const char *ip       = (r->useragent_ip && *r->useragent_ip)
                           ? r->useragent_ip : "-";
    const char *path     = (r->unparsed_uri && *r->unparsed_uri)
                           ? r->unparsed_uri : "-";
    const char *tag      = bs_get_trigger_tag(r);
    const char *reason_q = bs_log_quote(r->pool,
                                         reason ? reason : "-");
    const char *path_q   = bs_log_quote(r->pool, path);

    /* Override outcome with the would-X stash if a suppression site
     * recorded one and the call site passed the natural "allow"
     * (i.e. nothing else more specific). Most-severe stashed
     * counterfactual wins. Lets BlockPath / RateLimit / Trigger
     * observe / FormCaptcha observe / tier-dispatch under
     * BotShieldEnabled LogOnly all surface as `outcome=~block`,
     * `~rate_limited`, `~challenge` etc. instead of plain `allow`
     * with the policy intent buried in the reason chain.
     *
     * Important: the override applies to the operator-facing
     * surfaces only — decision-log line and BS_OUTCOME env var.
     * The metrics counter (`outcome_for_metrics`) keeps the
     * original "allow" because that is what actually happened
     * (under LogOnly we declined and the request reached origin).
     * Operators wanting staging-volume metrics use the per-family
     * *_observed_total counters and the tier counter, both of which
     * are independent of LogOnly. Conflating ~challenge with real
     * served challenges in `outcome[challenged]` would corrupt the
     * production "% served" dashboards. */
    const char *outcome_for_metrics = outcome;
    const char *would = bs_get_would_outcome(r);
    if (would && outcome && strcmp(outcome, "allow") == 0) {
        outcome = would;
    }

    /* Demote the "boring pass" — tier=pass, outcome=allow,
     * score=0, no reasons, no trigger tag — to DEBUG so an
     * operator running at 'LogLevel botshield:info' for staging /
     * tuning sees only decisions where something actually
     * contributed. Pass-with-credits (score=0 but reasons non-
     * empty), tagged pass (asset bypass, etc.), any non-pass
     * tier, and any tilde-prefixed counterfactual all stay at
     * INFO. */
    int level = APLOG_INFO;
    int boring = (tier && strcmp(tier, "pass") == 0)
              && (outcome && strcmp(outcome, "allow") == 0)
              && score == 0
              && (!tag || !*tag)
              && (!reason || !*reason || strcmp(reason, "-") == 0);
    if (boring) level = APLOG_DEBUG;

    /* Stash the same fields as subprocess_env + flip the BOTSHIELD
     * env var, so an operator can route a dedicated decision log via
     * mod_log_config:
     *
     *   LogFormat "%{cu}t %a %>s tier=%{BS_TIER}e ..." botshield
     *   CustomLog logs/botshield-decisions.log botshield env=BOTSHIELD
     *
     * subprocess_env (not r->notes) is the right vehicle because
     * Apache's internal_internal_redirect deep-copies subprocess_env
     * into the redirect-target request_rec but creates a fresh empty
     * notes table. mod_rewrite's per-Directory `RewriteRule (.*)
     * index.php` style rules — used heavily by HUBzero / Joomla /
     * Drupal / WordPress and friends — trigger exactly that path,
     * so notes wouldn't survive into the request_rec that
     * log_transaction logs. Env vars do.
     *
     * BS_TIME is the ISO-8601 UTC timestamp of the decision (same
     * format Apache 2.4.13+ emits via %{cu}t in mod_log_config, but
     * with millisecond precision instead of microsecond, formatted
     * here so the LogFormat doesn't have to fight strftime's local-
     * time-only %t).
     *
     * env values are populated unconditionally — including for the
     * boring-pass case — so an operator's CustomLog conditional sees
     * a consistent BOTSHIELD=1 marker on every decision. The
     * formatter pulls fields by name; missing values render as "-"
     * (mod_log_config's standard for absent %{e}). */
    {
        apr_time_exp_t tm;
        apr_time_exp_gmt(&tm, apr_time_now());
        apr_table_setn(r->subprocess_env, "BS_TIME",
            apr_psprintf(r->pool,
                "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                tm.tm_usec / 1000));
    }
    apr_table_setn(r->subprocess_env, "BS_TIER",
                   tier     ? tier     : "-");
    apr_table_setn(r->subprocess_env, "BS_OUTCOME",
                   outcome  ? outcome  : "-");
    apr_table_setn(r->subprocess_env, "BS_COOKIE",
                   cookie   ? cookie   : "-");
    apr_table_setn(r->subprocess_env, "BS_PROVIDER",
                   provider ? provider : "-");
    apr_table_setn(r->subprocess_env, "BS_ALG",
                   alg      ? alg      : "-");
    apr_table_setn(r->subprocess_env, "BS_REASON",
                   reason   ? reason   : "-");
    apr_table_setn(r->subprocess_env, "BS_SCORE",
                   apr_psprintf(r->pool, "%d", score));
    if (tag && *tag) {
        apr_table_setn(r->subprocess_env, "BS_TAG", tag);
    }
    apr_table_setn(r->subprocess_env, "BOTSHIELD", "1");

    /* tag= suffix only when a trigger set it; normal decision lines
     * stay byte-identical so existing log parsers don't break. */
    if (tag && *tag) {
        const char *tag_q = bs_log_quote(r->pool, tag);
        ap_log_rerror(APLOG_MARK, level, 0, r,
            "mod_botshield: decision tier=%s outcome=%s ip=%s score=%d "
            "cookie=%s provider=%s alg=%s reason=\"%s\" path=\"%s\" "
            "tag=\"%s\"",
            tier, outcome, ip, score,
            cookie   ? cookie   : "-",
            provider ? provider : "-",
            alg      ? alg      : "-",
            reason_q, path_q, tag_q);
    } else {
        ap_log_rerror(APLOG_MARK, level, 0, r,
            "mod_botshield: decision tier=%s outcome=%s ip=%s score=%d "
            "cookie=%s provider=%s alg=%s reason=\"%s\" path=\"%s\"",
            tier, outcome, ip, score,
            cookie   ? cookie   : "-",
            provider ? provider : "-",
            alg      ? alg      : "-",
            reason_q, path_q);
    }
    /* M9.2: counters derived from the same enum vocabulary. One log
     * line, up to four counter increments (tier, outcome, cookie when
     * applicable, provider when applicable). */
    bs_metrics_bump(r, tier, outcome_for_metrics, cookie, provider);
}

/* ======================================================================
 * M9.3 Prometheus exposition handler
 *
 * Mounted at <prefix>/metrics. Emits counters + gauges in a fixed
 * deterministic order with hardcoded metric names (no runtime name
 * construction → no apr_psprintf on the scrape path). Each counter
 * read uses __atomic_load_n with RELAXED; on x86_64 64-bit aligned
 * reads are already atomic, but the intrinsic keeps the compiler
 * from reordering across concurrent writers.
 *
 * Access control is deliberately delegated to Apache: operators
 * gate this endpoint with `<Location /botshield/metrics>` +
 * Require ip / AuthType Basic / etc. The module emits everything to
 * anyone who reaches the handler.
 * ====================================================================== */

#define BS_M_PREFIX "botshield_"

static apr_uint64_t bs_mload(const apr_uint64_t *p)
{
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

/* Emit one Prometheus metric: HELP, TYPE, value. Single ap_rprintf
 * per line keeps the scrape path free of intermediate buffers. */
static void bs_m_emit_counter(request_rec *r, const char *name,
                              const char *help, apr_uint64_t val)
{
    ap_rprintf(r, "# HELP %s%s %s\n", BS_M_PREFIX, name, help);
    ap_rprintf(r, "# TYPE %s%s counter\n", BS_M_PREFIX, name);
    ap_rprintf(r, "%s%s %" APR_UINT64_T_FMT "\n", BS_M_PREFIX, name, val);
}

static void bs_m_emit_gauge(request_rec *r, const char *name,
                            const char *help, apr_uint64_t val)
{
    ap_rprintf(r, "# HELP %s%s %s\n", BS_M_PREFIX, name, help);
    ap_rprintf(r, "# TYPE %s%s gauge\n", BS_M_PREFIX, name);
    ap_rprintf(r, "%s%s %" APR_UINT64_T_FMT "\n", BS_M_PREFIX, name, val);
}

int bs_metrics_handler(request_rec *r)
{
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }
    if (!bs_shm.metrics) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("# metrics not initialized\n", r);
        return OK;
    }

    /* Prometheus exposition format 0.0.4. Content-Type per the spec. */
    ap_set_content_type(r,
        "text/plain; version=0.0.4; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    bs_metrics *m = bs_shm.metrics;

    /* --- Decision counters (ordered tier → outcome → cookie → provider) --- */

    bs_m_emit_counter(r, "tier_none_total",
        "Decisions reaching no tier (pre-tier terminations like debug/asset/misconfig).",
        bs_mload(&m->tier[BS_M_TIER_NONE]));
    bs_m_emit_counter(r, "tier_pass_total",
        "Decisions at tier=pass (no challenge served, request DECLINED).",
        bs_mload(&m->tier[BS_M_TIER_PASS]));
    bs_m_emit_counter(r, "tier_silent_total",
        "Decisions at tier=silent (auto-submit splash interstitial served).",
        bs_mload(&m->tier[BS_M_TIER_SILENT]));
    bs_m_emit_counter(r, "tier_form_total",
        "Decisions at tier=form (checkbox PoW interstitial served).",
        bs_mload(&m->tier[BS_M_TIER_FORM]));
    bs_m_emit_counter(r, "tier_captcha_total",
        "Decisions at tier=captcha (third-party provider widget served or verified).",
        bs_mload(&m->tier[BS_M_TIER_CAPTCHA]));

    bs_m_emit_counter(r, "outcome_allow_total",
        "Decisions that let the request through (pass tier, asset bypass, "
        "silent embedded pass-through, safeguard pass).",
        bs_mload(&m->outcome[BS_M_OUTCOME_ALLOW]));
    bs_m_emit_counter(r, "outcome_challenged_total",
        "Decisions that served an interstitial.",
        bs_mload(&m->outcome[BS_M_OUTCOME_CHALLENGED]));
    bs_m_emit_counter(r, "outcome_verified_total",
        "Captcha verifications that passed siteverify.",
        bs_mload(&m->outcome[BS_M_OUTCOME_VERIFIED]));
    bs_m_emit_counter(r, "outcome_block_total",
        "Requests blocked: invalid cookie, failed captcha verify, "
        "rate-limit-exceeded, etc.",
        bs_mload(&m->outcome[BS_M_OUTCOME_BLOCK]));
    bs_m_emit_counter(r, "outcome_failopen_total",
        "Siteverify calls that failed open (timeout, network error, provider 5xx).",
        bs_mload(&m->outcome[BS_M_OUTCOME_FAILOPEN]));
    bs_m_emit_counter(r, "outcome_rate_limited_total",
        "Verify requests rejected by per-IP rate limit.",
        bs_mload(&m->outcome[BS_M_OUTCOME_RATE_LIMITED]));
    bs_m_emit_counter(r, "outcome_inflight_capped_total",
        "Verify requests rejected by global in-flight semaphore.",
        bs_mload(&m->outcome[BS_M_OUTCOME_INFLIGHT_CAPPED]));
    bs_m_emit_counter(r, "outcome_pending_missing_total",
        "Verify POSTs missing or with tampered pending cookie.",
        bs_mload(&m->outcome[BS_M_OUTCOME_PENDING_MISSING]));
    bs_m_emit_counter(r, "outcome_misconfigured_total",
        "Terminations due to missing scope config or internal state.",
        bs_mload(&m->outcome[BS_M_OUTCOME_MISCONFIGURED]));
    bs_m_emit_counter(r, "outcome_debug_total",
        "BotShieldDebug-forced 403 responses.",
        bs_mload(&m->outcome[BS_M_OUTCOME_DEBUG]));
    bs_m_emit_counter(r, "outcome_redirect_total",
        "Decisions that issued a 302 redirect (e.g., safeguard "
        "explainer).",
        bs_mload(&m->outcome[BS_M_OUTCOME_REDIRECT]));

    bs_m_emit_counter(r, "cookie_ok_total",
        "Rep cookies that verified fully (signature + freshness + PoW).",
        bs_mload(&m->cookie[BS_M_COOKIE_OK]));
    bs_m_emit_counter(r, "cookie_expired_total",
        "Rep cookies with valid signature but past expires_at.",
        bs_mload(&m->cookie[BS_M_COOKIE_EXPIRED]));
    bs_m_emit_counter(r, "cookie_bad_sig_total",
        "Rep cookies with HMAC signature mismatch.",
        bs_mload(&m->cookie[BS_M_COOKIE_BAD_SIG]));
    bs_m_emit_counter(r, "cookie_bad_format_total",
        "Rep cookies that failed structural parsing (field count, hex, etc).",
        bs_mload(&m->cookie[BS_M_COOKIE_BAD_FORMAT]));
    bs_m_emit_counter(r, "cookie_absent_total",
        "Requests with no rep cookie.",
        bs_mload(&m->cookie[BS_M_COOKIE_ABSENT]));
    bs_m_emit_counter(r, "cookie_minted_total",
        "Decisions where the response carried a freshly-minted "
        "presence cookie (always-mint path).",
        bs_mload(&m->cookie[BS_M_COOKIE_MINTED]));

    bs_m_emit_counter(r, "provider_turnstile_total",
        "Decisions tagged with provider=turnstile.",
        bs_mload(&m->provider[BS_M_PROV_TURNSTILE]));
    bs_m_emit_counter(r, "provider_hcaptcha_total",
        "Decisions tagged with provider=hcaptcha.",
        bs_mload(&m->provider[BS_M_PROV_HCAPTCHA]));
    bs_m_emit_counter(r, "provider_recaptcha_v2_total",
        "Decisions tagged with provider=recaptcha-v2.",
        bs_mload(&m->provider[BS_M_PROV_RECAPTCHA_V2]));
    bs_m_emit_counter(r, "provider_recaptcha_v3_total",
        "Decisions tagged with provider=recaptcha-v3.",
        bs_mload(&m->provider[BS_M_PROV_RECAPTCHA_V3]));
    bs_m_emit_counter(r, "provider_friendly_total",
        "Decisions tagged with provider=friendly.",
        bs_mload(&m->provider[BS_M_PROV_FRIENDLY]));
    bs_m_emit_counter(r, "provider_geetest_total",
        "Decisions tagged with provider=geetest.",
        bs_mload(&m->provider[BS_M_PROV_GEETEST]));

    /* --- Persistence counters + gauges --- */

    bs_m_emit_counter(r, "state_saves_total",
        "Successful state-file saves (shutdown + periodic).",
        bs_mload(&m->state_saves_total));
    bs_m_emit_counter(r, "state_loads_total",
        "Successful state-file loads at post-config.",
        bs_mload(&m->state_loads_total));
    bs_m_emit_gauge(r, "state_save_last_unix",
        "Unix seconds of the last successful state save.",
        bs_mload(&m->state_save_last_unix));
    bs_m_emit_gauge(r, "state_save_last_bytes",
        "Byte length of the last successful state save.",
        bs_mload(&m->state_save_last_bytes));
    bs_m_emit_gauge(r, "state_save_last_duration_microseconds",
        "Wall-clock microseconds the last save took (build + fsync + rename + dir fsync).",
        bs_mload(&m->state_save_last_duration_us));
    bs_m_emit_gauge(r, "state_load_last_kept",
        "Flagged-IP entries kept across the last state load.",
        bs_mload(&m->state_load_last_kept));
    bs_m_emit_gauge(r, "state_load_last_dropped",
        "Flagged-IP entries dropped as stale during the last state load.",
        bs_mload(&m->state_load_last_dropped));

    /* --- E1 crawler-verification counters --- */

    bs_m_emit_counter(r, "bot_allow_total",
        "Requests whose crawler UA matched the published IP ranges for "
        "that crawler (legit-bot bypass applied).",
        bs_mload(&m->bot_allow_total));
    bs_m_emit_counter(r, "bot_fake_total",
        "Requests with a known-crawler UA whose IP was NOT in that "
        "crawler's published ranges (penalty applied, routed to captcha tier).",
        bs_mload(&m->bot_fake_total));
    bs_m_emit_counter(r, "bot_unverified_total",
        "Requests whose crawler UA matched a known pattern but no ranges "
        "file is configured for that crawler (no score effect, logged).",
        bs_mload(&m->bot_unverified_total));

    /* --- E2.1 policy-enforcement counters --- */

    bs_m_emit_counter(r, "rate_limit_observed_total",
        "Rate-limit over-budget events that ran in observe mode "
        "(per-rule mode=observe or BotShieldEnabled LogOnly); rule "
        "would have returned 429 but didn't.",
        bs_mload(&m->rate_limit_observed_total));
    bs_m_emit_counter(r, "block_path_observed_total",
        "Block-path matches that ran in observe mode; rule would "
        "have returned 403 but didn't.",
        bs_mload(&m->block_path_observed_total));
    bs_m_emit_counter(r, "trigger_observed_total",
        "Trigger matches (path/cookie/env/load) that ran in observe "
        "mode across all families.",
        bs_mload(&m->trigger_observed_total));
    bs_m_emit_counter(r, "rate_limit_exceeded_total",
        "Requests that tripped a BotShieldRateLimit cohort budget "
        "(response was 429 + Retry-After).",
        bs_mload(&m->rate_limit_exceeded_total));
    bs_m_emit_counter(r, "block_path_hit_total",
        "Requests that matched a BotShieldBlockPath cohort+path-glob "
        "(response was 403).",
        bs_mload(&m->block_path_hit_total));

    /* --- On-demand gauges (may refresh a 1-second cache) --- */

    bs_m_emit_gauge(r, "captcha_inflight_current",
        "Current in-flight captcha siteverify calls.",
        (apr_uint64_t)bs_metrics_inflight_cur());
    bs_m_emit_gauge(r, "shm_flagged_used",
        "Flagged-IP slots currently populated with non-expired entries.",
        bs_metrics_flagged_used());
    bs_m_emit_gauge(r, "shm_flagged_capacity",
        "Configured BotShieldFlaggedIPCapacity.",
        (apr_uint64_t)bs_shm.flagged_capacity);
    bs_m_emit_gauge(r, "shm_strike_used",
        "Strike-table slots physically occupied (used != 0).",
        bs_metrics_strike_used());
    bs_m_emit_gauge(r, "shm_strike_capacity",
        "Configured BotShieldRateLimitEscalateCapacity.",
        (apr_uint64_t)bs_shm.strike_capacity);
    bs_m_emit_gauge(r, "shm_safeguard_used",
        "Safeguard-table slots physically occupied (used != 0).",
        bs_metrics_safeguard_used());
    bs_m_emit_gauge(r, "shm_safeguard_capacity",
        "Configured BotShieldSafeguardCapacity.",
        (apr_uint64_t)bs_shm.safeguard_capacity);
    bs_m_emit_gauge(r, "bloom_bits_set_active",
        "Set bits in the active Bloom buffer (popcount; ~population proxy).",
        bs_metrics_bloom_bits(1));
    bs_m_emit_gauge(r, "bloom_bits_set_warming",
        "Set bits in the warming Bloom buffer.",
        bs_metrics_bloom_bits(0));
    bs_m_emit_gauge(r, "bloom_window_seconds",
        "Configured BotShieldBloomWindow (full window; rotation at half).",
        (apr_uint64_t)(bs_shm.header
                       ? bs_shm.header->bloom_window_secs : 0));
    bs_m_emit_gauge(r, "cv_rate_slot_capacity",
        "Fixed size of the verify-endpoint rate-limit ring (slots).",
        (apr_uint64_t)bs_shm.cv_rate_slot_count);
    bs_m_emit_gauge(r, "cv_log_slot_capacity",
        "Fixed size of the verify-endpoint log-suppress ring (slots).",
        (apr_uint64_t)bs_shm.cv_log_slot_count);

    /* E11 — load-state observability. The gauge is the most useful
     * value to alert on; the counter lets operators graph state
     * transitions per minute. */
    bs_m_emit_gauge(r, "load_state",
        "Current cached load state (0=normal, 1=warm, 2=hot).",
        (apr_uint64_t)(bs_shm.header
                       ? bs_shm.header->load_state : 0));
    bs_m_emit_counter(r, "load_state_changes_total",
        "Number of load-state transitions since the SHM was created.",
        (apr_uint64_t)(bs_shm.header
                       ? bs_shm.header->load_state_changes : 0));

    return OK;
}

/* ======================================================================
 * M9.3 mod_status contribution
 * ====================================================================== */

int bs_status_hook(request_rec *r, int flags)
{
    if (!bs_shm.metrics) return DECLINED;
    bs_metrics *m = bs_shm.metrics;

    if (flags & AP_STATUS_SHORT) {
        ap_rprintf(r,
            "BotShieldTierPass: %" APR_UINT64_T_FMT "\n"
            "BotShieldTierSilent: %" APR_UINT64_T_FMT "\n"
            "BotShieldTierForm: %" APR_UINT64_T_FMT "\n"
            "BotShieldTierCaptcha: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeVerified: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeRejected: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeFailopen: %" APR_UINT64_T_FMT "\n"
            "BotShieldOutcomeRateLimited: %" APR_UINT64_T_FMT "\n"
            "BotShieldCaptchaInflightCurrent: %u\n"
            "BotShieldFlaggedUsed: %" APR_UINT64_T_FMT "\n"
            "BotShieldFlaggedCapacity: %" APR_SIZE_T_FMT "\n",
            bs_mload(&m->tier[BS_M_TIER_PASS]),
            bs_mload(&m->tier[BS_M_TIER_SILENT]),
            bs_mload(&m->tier[BS_M_TIER_FORM]),
            bs_mload(&m->tier[BS_M_TIER_CAPTCHA]),
            bs_mload(&m->outcome[BS_M_OUTCOME_VERIFIED]),
            bs_mload(&m->outcome[BS_M_OUTCOME_BLOCK]),
            bs_mload(&m->outcome[BS_M_OUTCOME_FAILOPEN]),
            bs_mload(&m->outcome[BS_M_OUTCOME_RATE_LIMITED]),
            bs_metrics_inflight_cur(),
            bs_metrics_flagged_used(),
            bs_shm.flagged_capacity);
        return OK;
    }

    ap_rputs("<hr />\n<h2>mod_botshield</h2>\n", r);
    ap_rputs("<table border=\"0\" cellspacing=\"0\" cellpadding=\"3\">\n",
             r);
    ap_rputs("<tr><th>tier</th><th>total</th>"
             "<th></th><th>outcome</th><th>total</th></tr>\n", r);
    /* Two parallel columns: tier distribution on the left, outcome
     * highlights on the right. Keeps the row count tight. */
    const struct { const char *label; apr_uint64_t val; } rows[] = {
        { "pass",    bs_mload(&m->tier[BS_M_TIER_PASS])    },
        { "silent",  bs_mload(&m->tier[BS_M_TIER_SILENT])  },
        { "form",    bs_mload(&m->tier[BS_M_TIER_FORM])    },
        { "captcha", bs_mload(&m->tier[BS_M_TIER_CAPTCHA]) },
        { "none",    bs_mload(&m->tier[BS_M_TIER_NONE])    },
    };
    const struct { const char *label; apr_uint64_t val; } out_rows[] = {
        { "verified",        bs_mload(&m->outcome[BS_M_OUTCOME_VERIFIED])        },
        { "block",           bs_mload(&m->outcome[BS_M_OUTCOME_BLOCK])           },
        { "failopen",        bs_mload(&m->outcome[BS_M_OUTCOME_FAILOPEN])        },
        { "rate_limited",    bs_mload(&m->outcome[BS_M_OUTCOME_RATE_LIMITED])    },
        { "pending_missing", bs_mload(&m->outcome[BS_M_OUTCOME_PENDING_MISSING]) },
    };
    for (int i = 0; i < 5; i++) {
        ap_rprintf(r,
            "<tr><td>%s</td><td align=\"right\">%" APR_UINT64_T_FMT "</td>"
            "<td>&nbsp;&nbsp;</td>"
            "<td>%s</td><td align=\"right\">%" APR_UINT64_T_FMT "</td></tr>\n",
            rows[i].label, rows[i].val,
            out_rows[i].label, out_rows[i].val);
    }
    ap_rputs("</table>\n", r);
    ap_rprintf(r,
        "<p>captcha in-flight: %u &nbsp;&nbsp; "
        "flagged IPs: %" APR_UINT64_T_FMT " / %" APR_SIZE_T_FMT " &nbsp;&nbsp; "
        "last state save: %" APR_UINT64_T_FMT " bytes in %" APR_UINT64_T_FMT " \xc2\xb5s "
        "&nbsp;&nbsp;"
        "<a href=\"/botshield/metrics\">full metrics</a></p>\n",
        bs_metrics_inflight_cur(),
        bs_metrics_flagged_used(),
        bs_shm.flagged_capacity,
        bs_mload(&m->state_save_last_bytes),
        bs_mload(&m->state_save_last_duration_us));

    return OK;
}
