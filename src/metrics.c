/* metrics.c — implementations behind metrics.h. Decision log,
 * M9.2 counter increments, M9.2 SHM gauge readers (with thread-
 * local 1s cache), M9.3 Prometheus exposition handler, and the
 * mod_status contribution. */

#include "metrics.h"
#include "botshield.h"  /* bs_server_cfg, botshield_module */
#include "shm.h"
#include "ua_class.h"

#include <string.h>

#include <apr_atomic.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>

#include <http_config.h>
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

/* Outcome index -> name. Paired with bs_m_outcome_idx below and kept
 * adjacent to it on purpose: these are inverses, and the one thing this
 * file must not grow is a third place where the outcome vocabulary is
 * spelled out. */
static const char *const bs_m_outcome_names[BS_M_OUTCOME_COUNT] = {
    "allow", "challenged", "verified", "block", "failopen",
    "rate_limited", "inflight_capped", "pending_missing",
    "misconfigured", "debug", "redirect"
};

const char *bs_m_outcome_name(int idx)
{
    if (idx < 0 || idx >= BS_M_OUTCOME_COUNT) return "?";
    return bs_m_outcome_names[idx];
}

static const char *const bs_m_class_names[BS_M_CLASS_COUNT] = {
    "browser", "verified-bot", "known-bot",
    "unknown-bot", "fake-bot", "unknown"
};

const char *bs_m_class_name(int idx)
{
    if (idx < 0 || idx >= BS_M_CLASS_COUNT) return "?";
    return bs_m_class_names[idx];
}

/* ua_class label -> persisted metrics index. Explicit switch rather
 * than a cast: the two enums are ordered differently on purpose, so the
 * on-disk numbering stays stable if the classifier's is reordered. A
 * new label added there without a case here fails the build. */
static int bs_m_class_idx(bs_ua_class_label l)
{
    switch (l) {
    case BS_UA_CLASS_BROWSER:      return BS_M_CLASS_BROWSER;
    case BS_UA_CLASS_VERIFIED_BOT: return BS_M_CLASS_VERIFIED_BOT;
    case BS_UA_CLASS_KNOWN_BOT:    return BS_M_CLASS_KNOWN_BOT;
    case BS_UA_CLASS_UNKNOWN_BOT:  return BS_M_CLASS_UNKNOWN_BOT;
    case BS_UA_CLASS_FAKE_BOT:     return BS_M_CLASS_FAKE_BOT;
    case BS_UA_CLASS_UNKNOWN:      return BS_M_CLASS_UNKNOWN;
    }
    return BS_M_CLASS_UNKNOWN;
}

/* Audience split for the dashboard tabs. Switch rather than a range
 * test on the class enum, for the same reason bs_m_class_idx is: a new
 * class must fail the build here and force a decision about which side
 * it belongs on, instead of silently landing in whichever half the
 * numbering puts it.
 *
 * FAKE_BOT is USER on purpose. It is a UA claiming to be a crawler
 * whose IP failed the cross-check -- filing it under bots would let a
 * spoofer hide inside exactly the population the bot tab exempts from
 * scrutiny. UNKNOWN is USER for the same reason: unclassified traffic
 * belongs with the population we still challenge, not with the one we
 * pass on sight. */
static int bs_m_group_of_class(int class_idx)
{
    switch (class_idx) {
    case BS_M_CLASS_VERIFIED_BOT:
    case BS_M_CLASS_KNOWN_BOT:
    case BS_M_CLASS_UNKNOWN_BOT:
        return BS_M_GROUP_BOT;
    case BS_M_CLASS_BROWSER:
    case BS_M_CLASS_FAKE_BOT:
    case BS_M_CLASS_UNKNOWN:
        return BS_M_GROUP_USER;
    }
    return BS_M_GROUP_USER;
}

/* Group for the request in hand, from the shared UA classifier. */
static int bs_m_request_group(request_rec *r)
{
    const bs_ua_class *uac = bs_classify_request_ua(r);
    return bs_m_group_of_class(uac ? bs_m_class_idx(uac->label)
                                   : BS_M_CLASS_UNKNOWN);
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
    if (strcmp(s, "solved")     == 0) return BS_M_COOKIE_SOLVED;
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

static bs_metrics *bs_vhost_block(int idx);   /* defined with the rings */

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

    /* Same indices feed the windowed rings that back the dashboard. */
    bs_server_cfg *scfg_v = ap_get_module_config(r->server->module_config,
                                                 &botshield_module);
    int vidx = scfg_v ? scfg_v->vhost_idx : -1;
    int gi   = bs_m_request_group(r);
    bs_metrics_bucket_add(vidx, ti, oi, ci, gi);

    /* Cumulative side of the same event, mirrored into the vhost
     * block. The global block keeps being written directly so the
     * Prometheus and mod_status surfaces are unchanged. */
    bs_metrics *vm = bs_vhost_block(vidx);
    if (vm) {
        if (ti >= 0) __atomic_fetch_add(&vm->tier[ti], 1, __ATOMIC_RELAXED);
        if (oi >= 0) __atomic_fetch_add(&vm->outcome[oi], 1, __ATOMIC_RELAXED);
        if (ci >= 0) __atomic_fetch_add(&vm->cookie[ci], 1, __ATOMIC_RELAXED);
        if (gi >= 0) {
            if (ti >= 0) __atomic_fetch_add(&vm->g_tier[gi][ti],
                                            1, __ATOMIC_RELAXED);
            if (oi >= 0) __atomic_fetch_add(&vm->g_outcome[gi][oi],
                                            1, __ATOMIC_RELAXED);
            if (ci >= 0) __atomic_fetch_add(&vm->g_cookie[gi][ci],
                                            1, __ATOMIC_RELAXED);
        }
    }

    /* Cumulative audience-split mirrors, alongside the flat counters. */
    if (gi >= 0) {
        if (ti >= 0) __atomic_fetch_add(&bs_shm.metrics->g_tier[gi][ti],
                                        1, __ATOMIC_RELAXED);
        if (oi >= 0) __atomic_fetch_add(&bs_shm.metrics->g_outcome[gi][oi],
                                        1, __ATOMIC_RELAXED);
        if (ci >= 0) __atomic_fetch_add(&bs_shm.metrics->g_cookie[gi][ci],
                                        1, __ATOMIC_RELAXED);
    }

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
 * sites fire on the same request (e.g. a path-trigger observed AND
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

/* ======================================================================
 * Time-bucketed counters — see bs_metrics_slot in shm.h for the design
 * ====================================================================== */

/* Claim a slot for `epoch` if it still holds an older wrap, then add.
 * The CAS means exactly one writer zeroes the slot; a concurrent writer
 * that already read the stale epoch may add into the freshly-zeroed slot
 * (its count survives) or lose a single increment. Advisory by design. */
/* The per-vhost block for `idx`, or NULL when there is none (index not
 * yet assigned, directory absent, or index out of range). Callers write
 * the global block unconditionally and this one additionally, so a NULL
 * here degrades to "aggregate only" rather than losing the event. */
static bs_metrics *bs_vhost_block(int idx)
{
    if (idx < 0 || !bs_shm.vmetrics || !bs_shm.vhost_dir) return NULL;
    if ((apr_uint32_t)idx >= bs_shm.vhost_dir->count) return NULL;
    return &bs_shm.vmetrics[idx];
}

/* Claim `slot` for `epoch`, zeroing it if it still holds an older wrap.
 * Split out from the adders because two independent writers land in the
 * same slot — the decision path and the per-request traffic path — and
 * both must be able to trigger the rollover. */
static void bs_m_slot_claim(bs_metrics_slot *slot, apr_uint64_t epoch)
{
    apr_uint64_t seen = __atomic_load_n(&slot->epoch, __ATOMIC_RELAXED);
    if (seen == epoch) return;
    if (__atomic_compare_exchange_n(&slot->epoch, &seen, epoch, 0,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        for (int i = 0; i < BS_M_TIER_COUNT; i++) {
            __atomic_store_n(&slot->tier[i], 0, __ATOMIC_RELAXED);
        }
        for (int i = 0; i < BS_M_OUTCOME_COUNT; i++) {
            __atomic_store_n(&slot->outcome[i], 0, __ATOMIC_RELAXED);
        }
        for (int i = 0; i < BS_M_COOKIE_COUNT; i++) {
            __atomic_store_n(&slot->cookie[i], 0, __ATOMIC_RELAXED);
        }
        __atomic_store_n(&slot->req_total,  0, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->req_cookie, 0, __ATOMIC_RELAXED);
        for (int i = 0; i < BS_M_STATUS_COUNT; i++) {
            __atomic_store_n(&slot->req_status[i], 0, __ATOMIC_RELAXED);
        }
        for (int i = 0; i < BS_M_RESP_COUNT; i++) {
            __atomic_store_n(&slot->req_resp[i], 0, __ATOMIC_RELAXED);
        }
        for (int i = 0; i < BS_M_CLASS_COUNT; i++) {
            __atomic_store_n(&slot->req_class[i], 0, __ATOMIC_RELAXED);
        }
        /* Audience-split mirrors must be reset with the slot they live
         * in; a missed reset here would let a recycled slot carry a
         * previous window's bot counts into the current one. */
        for (int g = 0; g < BS_M_GROUP_COUNT; g++) {
            for (int i = 0; i < BS_M_TIER_COUNT; i++) {
                __atomic_store_n(&slot->g_tier[g][i], 0, __ATOMIC_RELAXED);
            }
            for (int i = 0; i < BS_M_OUTCOME_COUNT; i++) {
                __atomic_store_n(&slot->g_outcome[g][i], 0, __ATOMIC_RELAXED);
            }
            for (int i = 0; i < BS_M_COOKIE_COUNT; i++) {
                __atomic_store_n(&slot->g_cookie[g][i], 0, __ATOMIC_RELAXED);
            }
        }
    }
}

static void bs_m_slot_add(bs_metrics_slot *slot, apr_uint64_t epoch,
                          int tier_idx, int outcome_idx, int cookie_idx,
                          int group_idx)
{
    bs_m_slot_claim(slot, epoch);
    if (tier_idx >= 0) {
        __atomic_fetch_add(&slot->tier[tier_idx], 1, __ATOMIC_RELAXED);
        if (group_idx >= 0) {
            __atomic_fetch_add(&slot->g_tier[group_idx][tier_idx],
                               1, __ATOMIC_RELAXED);
        }
    }
    if (outcome_idx >= 0) {
        __atomic_fetch_add(&slot->outcome[outcome_idx], 1, __ATOMIC_RELAXED);
        if (group_idx >= 0) {
            __atomic_fetch_add(&slot->g_outcome[group_idx][outcome_idx],
                               1, __ATOMIC_RELAXED);
        }
    }
    if (cookie_idx >= 0) {
        __atomic_fetch_add(&slot->cookie[cookie_idx], 1, __ATOMIC_RELAXED);
        if (group_idx >= 0) {
            __atomic_fetch_add(&slot->g_cookie[group_idx][cookie_idx],
                               1, __ATOMIC_RELAXED);
        }
    }
}

void bs_metrics_bucket_add(int vhost_idx, int tier_idx,
                           int outcome_idx, int cookie_idx,
                           int group_idx)
{
    if (!bs_shm.metrics) return;
    apr_uint64_t minute = (apr_uint64_t)(apr_time_sec(apr_time_now()) / 60);
    apr_uint64_t hour   = minute / 60;
    bs_metrics *vm = bs_vhost_block(vhost_idx);
    bs_metrics *blocks[2] = { bs_shm.metrics, vm };
    for (int b = 0; b < 2; b++) {
        if (!blocks[b]) continue;
        bs_m_slot_add(&blocks[b]->min_slots[minute % BS_M_MIN_SLOTS],
                      minute, tier_idx, outcome_idx, cookie_idx, group_idx);
        bs_m_slot_add(&blocks[b]->hour_slots[hour % BS_M_HOUR_SLOTS],
                      hour, tier_idx, outcome_idx, cookie_idx, group_idx);
    }
}

/* Per-request traffic. Deliberately cheap: one epoch load plus at most
 * three relaxed adds per ring. This runs on every request the server
 * handles — static assets included — so anything more expensive would
 * be a tax on the whole site, not just the protected scopes. */
static void bs_m_slot_traffic(bs_metrics_slot *slot, apr_uint64_t epoch,
                              int status_idx, int has_cookie, int resp_idx,
                              int class_idx)
{
    bs_m_slot_claim(slot, epoch);
    __atomic_fetch_add(&slot->req_total, 1, __ATOMIC_RELAXED);
    if (has_cookie) {
        __atomic_fetch_add(&slot->req_cookie, 1, __ATOMIC_RELAXED);
    }
    if (status_idx >= 0) {
        __atomic_fetch_add(&slot->req_status[status_idx], 1,
                           __ATOMIC_RELAXED);
    }
    if (resp_idx >= 0) {
        __atomic_fetch_add(&slot->req_resp[resp_idx], 1, __ATOMIC_RELAXED);
    }
    if (class_idx >= 0) {
        __atomic_fetch_add(&slot->req_class[class_idx], 1, __ATOMIC_RELAXED);
    }
}

void bs_metrics_traffic_add(int vhost_idx, int status_idx, int has_cookie,
                            int resp_idx, int class_idx)
{
    if (!bs_shm.metrics) return;
    apr_uint64_t minute = (apr_uint64_t)(apr_time_sec(apr_time_now()) / 60);
    apr_uint64_t hour   = minute / 60;
    bs_metrics *vm = bs_vhost_block(vhost_idx);
    bs_metrics *blocks[2] = { bs_shm.metrics, vm };
    for (int b = 0; b < 2; b++) {
        bs_metrics *m = blocks[b];
        if (!m) continue;
        bs_m_slot_traffic(&m->min_slots[minute % BS_M_MIN_SLOTS],
                          minute, status_idx, has_cookie, resp_idx, class_idx);
        bs_m_slot_traffic(&m->hour_slots[hour % BS_M_HOUR_SLOTS],
                          hour, status_idx, has_cookie, resp_idx, class_idx);
        __atomic_fetch_add(&m->req_total, 1, __ATOMIC_RELAXED);
        if (has_cookie) {
            __atomic_fetch_add(&m->req_cookie, 1, __ATOMIC_RELAXED);
        }
        if (status_idx >= 0) {
            __atomic_fetch_add(&m->req_status[status_idx], 1,
                               __ATOMIC_RELAXED);
        }
        if (resp_idx >= 0) {
            __atomic_fetch_add(&m->req_resp[resp_idx], 1, __ATOMIC_RELAXED);
        }
        if (class_idx >= 0) {
            __atomic_fetch_add(&m->req_class[class_idx], 1, __ATOMIC_RELAXED);
        }
    }
}

/* Sum every slot of `ring` whose epoch lies in (now - span, now]. */
static void bs_m_sum_ring(const bs_metrics_slot *ring, int nslots,
                          apr_uint64_t now_epoch, apr_uint64_t span,
                          bs_metrics_window *out)
{
    apr_uint64_t oldest = (now_epoch >= span - 1) ? now_epoch - (span - 1) : 0;
    for (int i = 0; i < nslots; i++) {
        apr_uint64_t e = __atomic_load_n(&ring[i].epoch, __ATOMIC_RELAXED);
        if (e == 0 || e < oldest || e > now_epoch) continue;
        for (int t = 0; t < BS_M_TIER_COUNT; t++) {
            out->tier[t] += __atomic_load_n(&ring[i].tier[t], __ATOMIC_RELAXED);
        }
        for (int o = 0; o < BS_M_OUTCOME_COUNT; o++) {
            out->outcome[o] += __atomic_load_n(&ring[i].outcome[o],
                                               __ATOMIC_RELAXED);
        }
        for (int c = 0; c < BS_M_COOKIE_COUNT; c++) {
            out->cookie[c] += __atomic_load_n(&ring[i].cookie[c],
                                              __ATOMIC_RELAXED);
        }
        out->req_total  += __atomic_load_n(&ring[i].req_total,
                                           __ATOMIC_RELAXED);
        out->req_cookie += __atomic_load_n(&ring[i].req_cookie,
                                           __ATOMIC_RELAXED);
        for (int st = 0; st < BS_M_STATUS_COUNT; st++) {
            out->req_status[st] += __atomic_load_n(&ring[i].req_status[st],
                                                   __ATOMIC_RELAXED);
        }
        for (int rk = 0; rk < BS_M_RESP_COUNT; rk++) {
            out->req_resp[rk] += __atomic_load_n(&ring[i].req_resp[rk],
                                                 __ATOMIC_RELAXED);
        }
        for (int ck = 0; ck < BS_M_CLASS_COUNT; ck++) {
            out->req_class[ck] += __atomic_load_n(&ring[i].req_class[ck],
                                                  __ATOMIC_RELAXED);
        }
        for (int g = 0; g < BS_M_GROUP_COUNT; g++) {
            for (int t = 0; t < BS_M_TIER_COUNT; t++) {
                out->g_tier[g][t] += __atomic_load_n(&ring[i].g_tier[g][t],
                                                     __ATOMIC_RELAXED);
            }
            for (int o = 0; o < BS_M_OUTCOME_COUNT; o++) {
                out->g_outcome[g][o] +=
                    __atomic_load_n(&ring[i].g_outcome[g][o],
                                    __ATOMIC_RELAXED);
            }
            for (int c = 0; c < BS_M_COOKIE_COUNT; c++) {
                out->g_cookie[g][c] +=
                    __atomic_load_n(&ring[i].g_cookie[g][c],
                                    __ATOMIC_RELAXED);
            }
        }
    }
}

void bs_metrics_read_window(int span_minutes, int vhost_idx,
                            bs_metrics_window *out)
{
    memset(out, 0, sizeof(*out));
    if (!bs_shm.metrics) return;
    const bs_metrics *m = (vhost_idx < 0) ? bs_shm.metrics
                                          : bs_vhost_block(vhost_idx);
    if (!m) return;

    if (span_minutes <= 0) {
        /* All-time: the plain cumulative counters. */
        for (int t = 0; t < BS_M_TIER_COUNT; t++) {
            out->tier[t] = __atomic_load_n(&m->tier[t],
                                           __ATOMIC_RELAXED);
        }
        for (int o = 0; o < BS_M_OUTCOME_COUNT; o++) {
            out->outcome[o] = __atomic_load_n(&m->outcome[o],
                                              __ATOMIC_RELAXED);
        }
        for (int c = 0; c < BS_M_COOKIE_COUNT; c++) {
            out->cookie[c] = __atomic_load_n(&m->cookie[c],
                                             __ATOMIC_RELAXED);
        }
        out->req_total  = __atomic_load_n(&m->req_total,
                                          __ATOMIC_RELAXED);
        out->req_cookie = __atomic_load_n(&m->req_cookie,
                                          __ATOMIC_RELAXED);
        for (int st = 0; st < BS_M_STATUS_COUNT; st++) {
            out->req_status[st] =
                __atomic_load_n(&m->req_status[st],
                                __ATOMIC_RELAXED);
        }
        for (int rk = 0; rk < BS_M_RESP_COUNT; rk++) {
            out->req_resp[rk] = __atomic_load_n(&m->req_resp[rk],
                                                __ATOMIC_RELAXED);
        }
        for (int ck = 0; ck < BS_M_CLASS_COUNT; ck++) {
            out->req_class[ck] = __atomic_load_n(&m->req_class[ck],
                                                 __ATOMIC_RELAXED);
        }
        for (int g = 0; g < BS_M_GROUP_COUNT; g++) {
            for (int t = 0; t < BS_M_TIER_COUNT; t++) {
                out->g_tier[g][t] = __atomic_load_n(&m->g_tier[g][t],
                                                    __ATOMIC_RELAXED);
            }
            for (int o = 0; o < BS_M_OUTCOME_COUNT; o++) {
                out->g_outcome[g][o] = __atomic_load_n(&m->g_outcome[g][o],
                                                       __ATOMIC_RELAXED);
            }
            for (int c = 0; c < BS_M_COOKIE_COUNT; c++) {
                out->g_cookie[g][c] = __atomic_load_n(&m->g_cookie[g][c],
                                                      __ATOMIC_RELAXED);
            }
        }
    } else {
        apr_uint64_t minute = (apr_uint64_t)(apr_time_sec(apr_time_now()) / 60);
        if (span_minutes <= BS_M_MIN_SLOTS) {
            bs_m_sum_ring(m->min_slots, BS_M_MIN_SLOTS,
                          minute, (apr_uint64_t)span_minutes, out);
        } else {
            /* Round up onto whole hours — the hour ring is the only
             * thing that reaches past 60 minutes. */
            apr_uint64_t hours = (apr_uint64_t)((span_minutes + 59) / 60);
            if (hours > BS_M_HOUR_SLOTS) hours = BS_M_HOUR_SLOTS;
            bs_m_sum_ring(m->hour_slots, BS_M_HOUR_SLOTS,
                          minute / 60, hours, out);
        }
    }
    for (int o = 0; o < BS_M_OUTCOME_COUNT; o++) out->decisions += out->outcome[o];
}

void bs_suppress_access_log(request_rec *r)
{
    apr_table_setn(r->subprocess_env, BS_NOLOG_ENV, "1");
}

int bs_outcome_index(const char *name)
{
    return bs_m_outcome_idx(name);
}

/* ======================================================================
 * Module-owned decision log (BotShieldDecisionLog)
 *
 * Why this exists alongside the CustomLog route: mod_log_config serves
 * every CustomLog from one log_transaction hook, so `accesslog=off` — which
 * breaks that chain — cannot suppress the access log while keeping a
 * decision record. Writing our own line at decision time decouples the
 * two, which is the whole point: rapid-rotate the detection log,
 * archive the access log, and keep flood traffic out of the latter.
 *
 * Concurrency: one descriptor per vhost, opened at post_config and
 * inherited by every mpm_event child. Every write is a single
 * apr_file_write of a fully pre-formatted line onto an O_APPEND
 * descriptor. Decision lines run ~200-900 bytes, under PIPE_BUF (4096),
 * so concurrent appends from multiple processes do not interleave —
 * the same guarantee mod_log_config relies on. No mutex is taken on
 * the request path.
 *
 * Rotation: an O_APPEND descriptor survives logrotate's copytruncate
 * (the inode is reused). A move-and-create rotation would strand this
 * fd on the old inode until the next graceful restart re-runs
 * post_config, so operators wanting that style should use a piped
 * spec ("|/usr/bin/rotatelogs ...") instead, which owns its own
 * rotation.
 * ====================================================================== */

const char *bs_set_decision_log(cmd_parms *cmd, void *cfg_v,
                                int argc, char *const argv[])
{
    (void)cfg_v;
    if (argc < 1 || !argv[0] || !*argv[0]) {
        return "BotShieldDecisionLog requires a path or a |program spec";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->decision_log_path = apr_pstrdup(cmd->pool, argv[0]);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strncasecmp(a, "outcomes=", 9) != 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldDecisionLog: unknown key '%s' (want "
                "outcomes=<outcome[,outcome...]>)", a);
        }
        unsigned mask = 0;
        char *list = apr_pstrdup(cmd->pool, a + 9);
        char *save = NULL;
        for (char *tok = apr_strtok(list, ",", &save); tok;
             tok = apr_strtok(NULL, ",", &save)) {
            while (*tok == ' ') tok++;
            if (!*tok) continue;
            if (!strcasecmp(tok, "all")) {
                mask = (1U << BS_M_OUTCOME_COUNT) - 1U;
                continue;
            }
            int oi = bs_m_outcome_idx(tok);
            if (oi < 0) {
                return apr_psprintf(cmd->pool,
                    "BotShieldDecisionLog: unknown outcome '%s'. Valid: "
                    "all, allow, challenged, verified, block, failopen, "
                    "rate_limited, inflight_capped, pending_missing, "
                    "misconfigured, debug, redirect", tok);
            }
            mask |= (1U << (unsigned)oi);
        }
        if (!mask) {
            return "BotShieldDecisionLog: outcomes= needs at least one "
                   "outcome (omit the key entirely to record all)";
        }
        scfg->decision_log_outcomes = (int)mask;
    }
    return NULL;
}

int bs_open_decision_logs(apr_pool_t *pconf, server_rec *s)
{
    for (server_rec *sv = s; sv; sv = sv->next) {
        bs_server_cfg *scfg = ap_get_module_config(sv->module_config,
                                                   &botshield_module);
        if (!scfg || scfg->decision_log_fd) continue;
        /* No directive: fall back to the default path, but only where
         * BotShield is actually enabled. The decision log is the only
         * record of a suppressed request, so defaulting it on is what
         * makes "recorded somewhere" hold without configuration --
         * see BS_DEFAULT_ACCESSLOG_SUPPRESS. */
        if (!scfg->decision_log_path) {
            if (!scfg->any_enabled) continue;
            scfg->decision_log_path = BS_DEFAULT_DECISION_LOG;
        }

        const char *spec = scfg->decision_log_path;

        if (*spec == '|') {
            /* Piped log. Skip the '|' and any leading space, then hand
             * off to Apache's own helper so restart/respawn semantics
             * match mod_log_config exactly. */
            const char *program = spec + 1;
            while (*program == ' ' || *program == '\t') program++;
            if (!*program) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv,
                    "mod_botshield: BotShieldDecisionLog '%s' names no "
                    "program after the pipe", spec);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            piped_log *pl = ap_open_piped_log(pconf, program);
            if (!pl) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv,
                    "mod_botshield: BotShieldDecisionLog could not start "
                    "piped-log program '%s'", program);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            scfg->decision_log_fd = ap_piped_log_write_fd(pl);
        }
        else {
            const char *path = ap_server_root_relative(pconf, spec);
            if (!path) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv,
                    "mod_botshield: BotShieldDecisionLog path '%s' does "
                    "not resolve", spec);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            apr_file_t *fd = NULL;
            apr_status_t rv = apr_file_open(&fd, path,
                APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_APPEND,
                APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_GREAD,
                pconf);
            if (rv != APR_SUCCESS) {
                char errbuf[120];
                apr_strerror(rv, errbuf, sizeof(errbuf));
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, sv,
                    "mod_botshield: BotShieldDecisionLog cannot open "
                    "'%s': %s. Refusing to start - a decision log the "
                    "operator asked for and did not get is a silent "
                    "blind spot.", path, errbuf);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            scfg->decision_log_fd = fd;
        }

        /* Say what is being recorded, not just that recording is on.
         * A filtered log looks identical to a complete one from the
         * outside, and "the log says nothing happened" is a very
         * expensive thing to get wrong during an incident. */
        if (scfg->decision_log_outcomes == -1) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: decision log active: %s (default set: "
                "block, verified, rate_limited, misconfigured, failopen, "
                "redirect, plus whatever BotShieldAccessLog suppresses "
                "for the request - so nothing the server answered is "
                "absent from both logs). Name outcomes= to override.",
                spec);
        } else {
            const char *kept = "", *sep = "";
            for (int oi = 0; oi < BS_M_OUTCOME_COUNT; oi++) {
                if (scfg->decision_log_outcomes & (1U << (unsigned)oi)) {
                    kept = apr_pstrcat(pconf, kept, sep,
                                       bs_m_outcome_name(oi), NULL);
                    sep = ",";
                }
            }
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                "mod_botshield: decision log active: %s (outcomes=%s "
                "only, each logged in full; other outcomes get no "
                "per-request line but are still counted exactly in "
                "/botshield/metrics and the dashboard)", spec, kept);
        }
    }
    return OK;
}

/* Emit one pre-formatted decision line to the owned log, if any.
 * Single write, no locking — see the concurrency note above.
 *
 * Line shape:  <iso8601-utc> <payload> ua="<user-agent>"
 *
 * Deliberately NOT carrying an HTTP status field. This runs at decision
 * time, before the response is finalized, so r->status is not yet the
 * code the client will receive (a block logs 200 here while the handler
 * goes on to return 403). The CustomLog route could use %>s because it
 * ran at log_transaction; we cannot, and printing a number we know to be
 * unreliable is worse than omitting it. `outcome=` in the payload is the
 * authoritative decision, and unlike a status code it distinguishes
 * block from rate_limited from challenged.
 *
 * The client IP is not repeated positionally either — the payload
 * already carries ip=. */
static void bs_decision_log_write(request_rec *r, const char *payload,
                                  int outcome_idx, unsigned al_suppress)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    if (!scfg || !scfg->decision_log_fd) return;

    /* outcomes= filter. Only the module-owned log is filtered; the
     * error-log line is gated by LogLevel and is not where the volume
     * lives (measured at 0 B/min against 265 MB/hr here), and the
     * metrics counters are bumped by the caller regardless -- so a
     * filtered-out outcome is still counted, still on the dashboard,
     * still in Prometheus. What is dropped is the per-request detail. */
    /* Explicit outcomes= is taken literally -- an operator who names a
     * set has accepted responsibility for what falls outside it. With
     * no key, default to the actionable set UNION whatever the access
     * log is dropping, so nothing the server answered goes unrecorded
     * in both places. */
    unsigned dl_mask = (scfg->decision_log_outcomes != -1)
                     ? (unsigned)scfg->decision_log_outcomes
                     : (BS_DEFAULT_DECISIONLOG_OUTCOMES | al_suppress);

    /* A counterfactual always gets a line, whatever the filter says.
     * Under observe mode the real outcome is `allow` -- the request was
     * declined and the origin answered -- so the outcome filter drops
     * it, which silently discards the one record observation exists to
     * produce. An operator running LogOnly to find out who ignores
     * their robots.txt would have seen nothing at all.
     *
     * Safe to exempt: a would-outcome is only stashed when a rule
     * actually would have acted, so this is bounded by policy matches,
     * not by traffic. */
    if (!bs_get_would_outcome(r)) {
        if (outcome_idx < 0) return;
        if (!(dl_mask & (1U << (unsigned)outcome_idx))) {
            /* Not a kept outcome: no line. Deliberately not sampled --
             * a partial record would mean an absent line no longer
             * proves the event did not happen, which is the one thing
             * a security log has to be able to say. The count is exact
             * on /botshield/metrics and the dashboard regardless. */
            return;
        }
    }

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    const char *ts = apr_table_get(r->subprocess_env, "BS_TIME");
    const char *line = apr_psprintf(r->pool, "%s %s ua=\"%s\"\n",
        ts ? ts : "-",
        payload,
        ua ? bs_log_quote(r->pool, ua) : "-");
    apr_size_t len = strlen(line);
    apr_file_write(scfg->decision_log_fd, line, &len);
}

/* `accesslog=off` verdict for the log_transaction chain. DONE breaks a
 * RUN_ALL hook declared with (OK, DECLINED), so returning it here means
 * mod_log_config never runs and nothing is written for this request.
 * Checked on both ends of an internal-redirect chain: the trigger fires
 * on the origin request, but a later hook may be handed either. */
static int bs_nolog_verdict(request_rec *origin, request_rec *fwd)
{
    if (apr_table_get(origin->subprocess_env, BS_NOLOG_ENV)
        || (fwd != origin
            && apr_table_get(fwd->subprocess_env, BS_NOLOG_ENV))) {
        return DONE;
    }
    return DECLINED;
}

/* Is `name` present as a cookie name in `hdr`? Token-aware: matches at
 * the header start or after a "; " separator and requires the '=', so
 * a cookie merely *ending* in the name does not count. */
static int bs_cookie_named(const char *hdr, const char *name)
{
    apr_size_t nlen = strlen(name);
    for (const char *p = hdr; (p = strstr(p, name)) != NULL; p += nlen) {
        if (p != hdr) {
            const char *prev = p - 1;
            /* Walk back over spaces to find the real separator. */
            while (prev > hdr && *prev == ' ') prev--;
            if (*prev != ';' && *prev != ',') continue;
        }
        const char *q = p + nlen;
        while (*q == ' ') q++;
        if (*q == '=') return 1;
    }
    return 0;
}

/* Which response did BotShield produce, if any?
 *
 * Read from the env the decision path already stashes, so this costs
 * two table lookups and no new bookkeeping. Three cases bin as ORIGIN
 * even though a decision was recorded:
 *
 *   - allow / verified: the request went on to the application.
 *   - a ~-prefixed counterfactual: under LogOnly the log says ~block
 *     but nothing was blocked, and counting it as ours would overstate
 *     enforcement in exactly the mode chosen to avoid enforcing.
 *   - no BS_OUTCOME at all: the scope was never evaluated.
 *
 * misconfigured and debug do terminate the request, but they are
 * failure modes rather than a policy response; they bin as BLOCK so a
 * refusal is never invisible. */
/* Did the application answer, or did the core hand back a file?
 *
 * Keyed on how the response was produced, not on the URI. An extension
 * test would be guesswork -- .php can be static and an extensionless
 * URL is usually the app -- while this reads what actually happened:
 * anything handed to a proxied backend is the application, anything
 * else that resolved to a regular file on disk was served off disk.
 *
 * r->finfo is filled in by map_to_storage, and r->proxyreq / r->handler
 * are set by the time log_transaction runs, so this is struct reads on
 * a path that executes for every request on the server. */
static int bs_origin_or_static(request_rec *r)
{
    if (r->proxyreq != PROXYREQ_NONE) return BS_M_RESP_ORIGIN;
    if (r->handler && strncmp(r->handler, "proxy:", 6) == 0) {
        return BS_M_RESP_ORIGIN;
    }
    if (r->finfo.filetype == APR_REG) return BS_M_RESP_STATIC;
    return BS_M_RESP_ORIGIN;
}

static int bs_resp_kind_idx(request_rec *r)
{
    const char *ep = apr_table_get(r->subprocess_env, "BS_ENDPOINT");
    if (ep) {
        return (strcmp(ep, "obs") == 0) ? BS_M_RESP_OBSERVE
                                        : BS_M_RESP_ENDPOINT;
    }
    const char *o = apr_table_get(r->subprocess_env, "BS_OUTCOME");
    if (!o || !*o || *o == '~') return bs_origin_or_static(r);

    if (strcmp(o, "challenged")      == 0) return BS_M_RESP_CHALLENGE;
    if (strcmp(o, "block")           == 0) return BS_M_RESP_BLOCK;
    if (strcmp(o, "misconfigured")   == 0) return BS_M_RESP_BLOCK;
    if (strcmp(o, "debug")           == 0) return BS_M_RESP_BLOCK;
    if (strcmp(o, "rate_limited")    == 0) return BS_M_RESP_RATE_LIMITED;
    if (strcmp(o, "inflight_capped") == 0) return BS_M_RESP_RATE_LIMITED;
    if (strcmp(o, "redirect")        == 0) return BS_M_RESP_REDIRECT;
    if (strcmp(o, "pending_missing") == 0) return BS_M_RESP_ENDPOINT;
    return bs_origin_or_static(r);
}

/* The invariant: if BotShield produced the response, the application did
 * not, so the client cannot have received a 2xx.
 *
 * Only the four kinds that mean "refused or intercepted" are asserted.
 * The exclusions are not oversights:
 *   ORIGIN    — the application answering is the correct outcome.
 *   ENDPOINT  — verify, embedded.js, assets: 200 is their success case.
 *   OBSERVE   — dashboard / metrics / policy-status, likewise.
 * `~`-prefixed counterfactuals and allow/verified already bin as ORIGIN
 * inside bs_resp_kind_idx, so LogOnly never trips this.
 *
 * `status` is the end of the internal-redirect chain — what the client
 * actually received — while the response kind comes from the origin
 * request, which is where the decision was recorded. Comparing across
 * the chain is the entire point: a rewrite re-dispatching to the
 * application after BotShield answered is precisely the fault this
 * catches.
 *
 * Counter first, log second, and the log throttled to one line a minute
 * across all workers: this runs on every request, so a systematic fault
 * would otherwise write one line per request into a decision log that
 * already measured 258 MB/hour under flood. The counter is the
 * monitorable signal; the log line just tells you where to look. */
static void bs_check_resp_status_invariant(request_rec *r, int resp_idx,
                                           int status_idx, int status)
{
    if (status_idx != BS_M_STATUS_2XX)   return;
    if (resp_idx != BS_M_RESP_CHALLENGE
        && resp_idx != BS_M_RESP_BLOCK
        && resp_idx != BS_M_RESP_RATE_LIMITED
        && resp_idx != BS_M_RESP_REDIRECT) return;
    if (!bs_shm.metrics) return;

    __atomic_fetch_add(&bs_shm.metrics->resp_status_mismatch_total, 1,
                       __ATOMIC_RELAXED);

    if (!bs_shm.header) return;
    apr_time_t now_t = apr_time_now();
    apr_int64_t prev = __atomic_load_n(&bs_shm.header->resp_mismatch_warn_us,
                                       __ATOMIC_RELAXED);
    if (now_t - (apr_time_t)prev > apr_time_from_sec(60)
        && __atomic_compare_exchange_n(&bs_shm.header->resp_mismatch_warn_us,
                                       &prev, (apr_int64_t)now_t, 0,
                                       __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        const char *o = apr_table_get(r->subprocess_env, "BS_OUTCOME");
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: response-kind/status mismatch: recorded "
            "outcome=%s but the client received %d -- the application "
            "answered a request BotShield reported as handled. "
            "Enforcement is being overstated; check for an ErrorDocument "
            "or a rewrite re-dispatching after the handler. uri=%s "
            "(botshield_resp_status_mismatch_total is the running count; "
            "further lines throttled to one per minute)",
            o ? o : "-", status, r->uri ? r->uri : "-");
    }
}

static int bs_status_class_idx(int status)
{
    if (status >= 200 && status < 300) return BS_M_STATUS_2XX;
    if (status >= 300 && status < 400) return BS_M_STATUS_3XX;
    if (status >= 400 && status < 500) return BS_M_STATUS_4XX;
    if (status >= 500 && status < 600) return BS_M_STATUS_5XX;
    return BS_M_STATUS_OTHER;
}

int bs_propagate_decision_env(request_rec *r)
{
    request_rec *fwd = r;
    while (fwd->next) fwd = fwd->next;

    /* Site-wide traffic. This hook runs once per client request on
     * every vhost regardless of BotShieldEnabled scope, and
     * subrequests never reach it — so this is one count per request,
     * and it includes everything BotShield never evaluated. That is
     * deliberate: decisions/req_total is the coverage figure, which is
     * only meaningful if the denominator is the whole site.
     *
     * Status comes from the end of the internal-redirect chain, which
     * is what the client actually received; cookies come from the
     * origin, which is what the client actually sent. */
    {
        const char *ck = apr_table_get(r->headers_in, "Cookie");
        int has_cookie = ck && (bs_cookie_named(ck, BS_COOKIE_NAME)
                                || bs_cookie_named(ck, BS_COOKIE_NAME_HOST));
        bs_server_cfg *scfg_t =
            ap_get_module_config(r->server->module_config, &botshield_module);
        /* Classification is computed once at post_read_request and
         * cached on r->pool, so reading it here is a pointer deref. */
        const bs_ua_class *uac = bs_classify_request_ua(r);
        int status_idx = bs_status_class_idx(fwd->status);
        int resp_idx   = bs_resp_kind_idx(r);
        bs_metrics_traffic_add(scfg_t ? scfg_t->vhost_idx : -1,
                               status_idx, has_cookie, resp_idx,
                               uac ? bs_m_class_idx(uac->label)
                                   : BS_M_CLASS_UNKNOWN);
        bs_check_resp_status_invariant(r, resp_idx, status_idx,
                                       fwd->status);
    }

    if (fwd != r) {
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
    }

    return bs_nolog_verdict(r, fwd);
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
     * counterfactual wins. Lets RateLimit / Trigger observe /
     * FormCaptcha observe / tier-dispatch under BotShieldEnabled
     * LogOnly all surface as `outcome=~block`, `~rate_limited`,
     * `~challenge` etc. instead of plain `allow` with the policy
     * intent buried in the reason chain.
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
     *   CustomLog logs/botshield.log botshield env=BOTSHIELD
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
    {
        const bs_ua_class *uac_e = bs_classify_request_ua(r);
        apr_table_setn(r->subprocess_env, "BS_CLASS",
                       uac_e ? bs_ua_class_label_str(uac_e->label) : "-");
    }

    /* Build the key=value payload once, then feed it to both sinks:
     * Apache's error log (always) and the module-owned decision log
     * (when BotShieldDecisionLog is configured). Passing the assembled
     * string through a single %s keeps the error-log line byte-identical
     * to what the previous two-branch printf produced, so existing
     * parsers — including the pytest framework, which slices decisions
     * out of the error log — are unaffected.
     *
     * tag= suffix only when a trigger set it. */
    /* class= is the UA classifier's verdict, the same one the dashboard
     * splits its bot/user tabs on. Without it the log cannot be sliced
     * the way the dashboard is, so a question like "why is the user
     * challenge rate only 50%" could be posed on the dashboard and not
     * answered from the log -- the two disagreed about who was a bot
     * because the log never said. Cached on the request by the
     * post_read_request hook, so this is a pointer read.
     *
     * Appended last, after tag=, so every existing prefix stays byte
     * identical. Parsers that slice fields positionally from the front
     * -- the pytest framework reads decisions out of the error log --
     * see exactly what they saw before, and key=value greps pick the
     * new field up for free. */
    const bs_ua_class *uac_l = bs_classify_request_ua(r);
    const char *cls = uac_l ? bs_ua_class_label_str(uac_l->label) : "-";

    const char *payload;
    if (tag && *tag) {
        payload = apr_psprintf(r->pool,
            "tier=%s outcome=%s ip=%s score=%d "
            "cookie=%s provider=%s alg=%s reason=\"%s\" path=\"%s\" "
            "tag=\"%s\" class=%s",
            tier, outcome, ip, score,
            cookie   ? cookie   : "-",
            provider ? provider : "-",
            alg      ? alg      : "-",
            reason_q, path_q, bs_log_quote(r->pool, tag), cls);
    } else {
        payload = apr_psprintf(r->pool,
            "tier=%s outcome=%s ip=%s score=%d "
            "cookie=%s provider=%s alg=%s reason=\"%s\" path=\"%s\" "
            "class=%s",
            tier, outcome, ip, score,
            cookie   ? cookie   : "-",
            provider ? provider : "-",
            alg      ? alg      : "-",
            reason_q, path_q, cls);
    }
    ap_log_rerror(APLOG_MARK, level, 0, r,
                  "mod_botshield: decision %s", payload);

    /* BotShieldAccessLog suppress=<outcomes>. Applied here because
     * bs_decision_log is the one funnel every outcome passes through,
     * and it runs before log_transaction, which is where the
     * suppression is read.
     *
     * Keyed on outcome_for_metrics, not the possibly ~-prefixed log
     * outcome: under LogOnly a "~block" did not block, the origin
     * answered, and that request belongs in the access log like any
     * other. Suppressing it would hide real traffic on the strength of
     * a decision that was never enforced. */
    unsigned al_mask = 0;
    {
        bs_dir_cfg *dc = ap_get_module_config(r->per_dir_config,
                                              &botshield_module);
        if (outcome_for_metrics) {
            /* Unset means "operator expressed no opinion", which takes
             * the compiled-in default rather than "log everything" --
             * the common case should not need a directive. An explicit
             * `BotShieldAccessLog on` sets the mask to 0 and is
             * therefore distinguishable from unset. */
            al_mask = (dc && dc->accesslog_suppress != BS_UNSET)
                    ? (unsigned)dc->accesslog_suppress
                    : BS_DEFAULT_ACCESSLOG_SUPPRESS;
            int oi = bs_m_outcome_idx(outcome_for_metrics);
            if (oi >= 0 && (al_mask & (1U << (unsigned)oi))) {
                bs_suppress_access_log(r);
            }
        }
    }

    bs_decision_log_write(r, payload,
                          bs_m_outcome_idx(outcome_for_metrics), al_mask);
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

/* ======================================================================
 * /botshield/dashboard — operator-facing view of the same counters the
 * Prometheus endpoint exposes.
 *
 * Self-contained: inline CSS and inline SVG, no scripts, no external
 * fonts or images. A strict site CSP would block a CDN, and an
 * operational page should not depend on the network being healthy.
 * Hover detail rides on SVG <title>, which browsers render natively —
 * an interaction layer that costs no JavaScript.
 *
 * Form choices follow from what each number is for, not from what looks
 * busy. Part-to-whole is a stacked bar rather than a pie: the slices
 * that matter here (block, rate_limited) are the small ones, and those
 * are exactly what a pie renders unreadable. Ratios against a limit are
 * meters. Eleven outcome classes are a table, because past ~7 classes a
 * chart stops adding anything. The tier ladder is an ORDINAL ramp (one
 * hue, light→dark) rather than categorical hues, because pass → silent
 * → form → captcha is an ordered escalation, not four unrelated
 * identities.
 *
 * Both ramps below were machine-validated (monotone lightness, adjacent
 * ΔL ≥ 0.06, light end ≥ 2:1 against its own surface, single hue). The
 * dark ramp is a separate selection, not an inversion of the light one —
 * an inverted ramp fails the contrast check against #1a1a19.
 * ====================================================================== */

/* Ordinal tier ramp — validated light: 2.06:1 at the pale end. */
/* Cookie state is categorical — distinct states, not a scale — so it
 * takes the categorical theme's fixed slot order rather than the tier
 * ramp. Slots 1-6 in order; their adjacent pairs (the pairlist a
 * stacked bar uses) are a strict subset of the reference theme's
 * validated eight, worst adjacent CVD dE 9.1 light / 8.4 dark against
 * these exact surfaces. Three light slots sit under 3:1 on #fcfcfb, so
 * the relief rule applies — bs_d_stacked direct-labels every series
 * with its value, and identity never rides on colour alone. */
#define BS_D_C1 "#2a78d6"
#define BS_D_C2 "#eb6834"
#define BS_D_C3 "#1baf7a"
#define BS_D_C4 "#eda100"
#define BS_D_C5 "#e87ba4"
#define BS_D_C6 "#008300"
/* C7 carries the cookie `solved` slice. Violet, chosen to sit apart
 * from C1's blue and C3/C6's greens so the one state that means "this
 * client actually passed a challenge" is not read as another shade of
 * the states that only mean "this client has a cookie". */
#define BS_D_C7 "#7a4fd0"

#define BS_D_T1 "#86b6ef"
#define BS_D_T2 "#5598e7"
#define BS_D_T3 "#256abf"
#define BS_D_T4 "#104281"

/* Value of `key` in a query string, or NULL. Token-aware: matches at
 * the start or after '&', so vh=1 cannot be read out of a parameter
 * that merely contains "vh=". Replaces a chain of strstr() probes that
 * worked only because no two parameter values could collide -- an
 * invariant that stops holding the moment a parameter is added. */
static const char *bs_d_qparam(apr_pool_t *pool, const char *args,
                               const char *key)
{
    if (!args || !key) return NULL;
    apr_size_t klen = strlen(key);
    for (const char *p = args; *p; ) {
        const char *amp = strchr(p, '&');
        apr_size_t seglen = amp ? (apr_size_t)(amp - p) : strlen(p);
        if (seglen > klen && p[klen] == '=' 
            && strncasecmp(p, key, klen) == 0) {
            return apr_pstrndup(pool, p + klen + 1, seglen - klen - 1);
        }
        if (!amp) break;
        p = amp + 1;
    }
    return NULL;
}

static const char *bs_d_window_label(int span)
{
    switch (span) {
    case 15:   return "last 15 min";
    case 60:   return "last hour";
    case 1440: return "last 24 h";
    default:   return "since restart";
    }
}

/* Percentage with one decimal, guarding the zero-denominator case that
 * a quiet window makes routine rather than exceptional. */
static const char *bs_d_pct(apr_pool_t *p, apr_uint64_t num, apr_uint64_t den)
{
    if (!den) return "—";
    return apr_psprintf(p, "%.1f%%", (double)num * 100.0 / (double)den);
}

/* One segment of a horizontal stacked bar. Segments are drawn inside a
 * rounded clip so the outer ends are 4px-rounded while internal joins
 * stay square, and each is inset by a 2px surface gap. */
static void bs_d_seg(request_rec *r, double x, double w, const char *fill,
                     const char *label, apr_uint64_t v, const char *pct)
{
    if (w <= 0) return;
    ap_rprintf(r,
        "<rect x='%.2f' y='0' width='%.2f' height='34' fill='%s'>"
        "<title>%s: %" APR_UINT64_T_FMT " (%s)</title></rect>",
        x, w > 2 ? w - 2 : w, fill, label, v, pct);
}

static void bs_d_stacked(request_rec *r, const char *id, const char *title,
                         const char **labels, const apr_uint64_t *vals,
                         const char **fills, int n, apr_uint64_t total)
{
    ap_rprintf(r, "<section><h2>%s</h2>", title);
    if (!total) {
        ap_rputs("<p class='empty'>No decisions in this window.</p></section>", r);
        return;
    }
    /* Unique clip id per chart: two elements sharing an id is invalid
     * markup, and browsers resolve every reference to the first one. */
    ap_rprintf(r,
        "<svg viewBox='0 0 600 34' width='100%%' height='34' "
        "role='img' preserveAspectRatio='none'>"
        "<clipPath id='clip-%s'>"
        "<rect x='0' y='0' width='600' height='34' rx='4'/></clipPath>"
        "<g clip-path='url(#clip-%s)'>", id, id);
    double x = 0;
    for (int i = 0; i < n; i++) {
        double w = 600.0 * (double)vals[i] / (double)total;
        bs_d_seg(r, x, w, fills[i], labels[i], vals[i],
                 bs_d_pct(r->pool, vals[i], total));
        x += w;
    }
    ap_rputs("</g></svg><ul class='legend'>", r);
    for (int i = 0; i < n; i++) {
        /* Legend always present for >= 2 series, and every series is
         * also direct-labelled with its value — identity is never
         * carried by colour alone. Text stays in ink tokens; only the
         * swatch wears the series colour. */
        ap_rprintf(r, "<li><i style='background:%s'></i>%s "
                      "<b>%" APR_UINT64_T_FMT "</b> <span>%s</span></li>",
                   fills[i], labels[i], vals[i],
                   bs_d_pct(r->pool, vals[i], total));
    }
    ap_rputs("</ul></section>", r);
}

/* Ratio against a limit — a meter on a same-hue track, not a two-slice pie. */
/* One audience tab's worth of decision stats. Same four KPIs and three
 * bars as the untabbed section used to show, read out of the
 * audience-split mirrors instead of the flat arrays.
 *
 * `idp` prefixes every bar's element id: the two panels render the same
 * charts and the ids have to stay unique across the document.
 *
 * The per-class strip at the bottom comes from the flat req_class[],
 * which counts REQUESTS (log_transaction, every request on the vhost),
 * while everything above it counts DECISIONS (only requests an enabled
 * scope evaluated). The two are different denominators on purpose --
 * the gap between them is how much of the site the policy actually
 * covers -- so they are labelled separately rather than summed. */
static void bs_d_audience_panel(request_rec *r, const bs_metrics_window *w,
                                int g, const char *idp,
                                const int *classes, const char **class_labels,
                                int nclasses)
{
    apr_uint64_t decisions = 0;
    for (int o = 0; o < BS_M_OUTCOME_COUNT; o++) decisions += w->g_outcome[g][o];
    apr_uint64_t challenged = w->g_outcome[g][BS_M_OUTCOME_CHALLENGED];
    apr_uint64_t verified   = w->g_outcome[g][BS_M_OUTCOME_VERIFIED];
    apr_uint64_t blocked    = w->g_outcome[g][BS_M_OUTCOME_BLOCK]
                            + w->g_outcome[g][BS_M_OUTCOME_RATE_LIMITED];
    apr_uint64_t unsolved   = (challenged > verified) ? challenged - verified : 0;

    ap_rputs("<div class='kpis'>", r);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Decisions</div>"
                  "<div class='v'>%" APR_UINT64_T_FMT "</div></div>", decisions);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Challenge rate</div>"
                  "<div class='v'>%s</div><div class='n'>%" APR_UINT64_T_FMT
                  " issued</div></div>",
               bs_d_pct(r->pool, challenged, decisions), challenged);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Solve rate</div>"
                  "<div class='v'>%s</div><div class='n'>%" APR_UINT64_T_FMT
                  " solved</div></div>",
               bs_d_pct(r->pool, verified, challenged), verified);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Blocked</div>"
                  "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                  "<div class='n'>%s of decisions</div></div>",
               blocked, bs_d_pct(r->pool, blocked, decisions));
    ap_rputs("</div>", r);

    {
        const char *labels[] = { "Solved", "Unsolved (left)" };
        const char *fills[]  = { "var(--t4)", "var(--t1)" };
        apr_uint64_t vals[]  = { verified, unsolved };
        bs_d_stacked(r, apr_pstrcat(r->pool, idp, "res", NULL),
                     "Challenge resolution", labels, vals, fills, 2,
                     challenged);
    }
    {
        const char *labels[] = { "solved", "ok (no solve)", "minted",
                                 "absent", "expired", "bad sig",
                                 "bad format" };
        const char *fills[]  = { "var(--c7)", "var(--c1)", "var(--c2)",
                                 "var(--c3)", "var(--c4)", "var(--c5)",
                                 "var(--c6)" };
        apr_uint64_t vals[]  = { w->g_cookie[g][BS_M_COOKIE_SOLVED],
                                 w->g_cookie[g][BS_M_COOKIE_OK],
                                 w->g_cookie[g][BS_M_COOKIE_MINTED],
                                 w->g_cookie[g][BS_M_COOKIE_ABSENT],
                                 w->g_cookie[g][BS_M_COOKIE_EXPIRED],
                                 w->g_cookie[g][BS_M_COOKIE_BAD_SIG],
                                 w->g_cookie[g][BS_M_COOKIE_BAD_FORMAT] };
        apr_uint64_t tot = 0;
        for (int i = 0; i < 7; i++) tot += vals[i];
        bs_d_stacked(r, apr_pstrcat(r->pool, idp, "ck", NULL),
                     "Reputation cookie state", labels, vals, fills, 7, tot);
    }
    {
        const char *labels[] = { "pass", "silent", "form", "captcha" };
        const char *fills[]  = { "var(--t1)", "var(--t2)",
                                 "var(--t3)", "var(--t4)" };
        apr_uint64_t vals[]  = { w->g_tier[g][BS_M_TIER_PASS],
                                 w->g_tier[g][BS_M_TIER_SILENT],
                                 w->g_tier[g][BS_M_TIER_FORM],
                                 w->g_tier[g][BS_M_TIER_CAPTCHA] };
        apr_uint64_t tot = vals[0] + vals[1] + vals[2] + vals[3];
        bs_d_stacked(r, apr_pstrcat(r->pool, idp, "tier", NULL),
                     "Tier mix", labels, vals, fills, 4, tot);
    }
    {
        const char *fills[] = { "var(--c1)", "var(--c2)", "var(--c3)",
                                "var(--c4)", "var(--c5)", "var(--c6)" };
        apr_uint64_t vals[BS_M_CLASS_COUNT];
        apr_uint64_t tot = 0;
        for (int i = 0; i < nclasses; i++) {
            vals[i] = w->req_class[classes[i]];
            tot += vals[i];
        }
        bs_d_stacked(r, apr_pstrcat(r->pool, idp, "cls", NULL),
                     "Requests by classification", class_labels, vals,
                     fills, nclasses, tot);
    }
}

static void bs_d_meter(request_rec *r, const char *label,
                       apr_uint64_t used, apr_uint64_t cap)
{
    double frac = cap ? (double)used / (double)cap : 0.0;
    if (frac > 1.0) frac = 1.0;
    ap_rprintf(r,
        "<div class='meter'><div class='mrow'><span>%s</span>"
        "<span class='mval'>%" APR_UINT64_T_FMT " / %" APR_UINT64_T_FMT
        " <b>%s</b></span></div>"
        "<div class='track'><div class='fill' style='width:%.1f%%'></div></div></div>",
        label, used, cap, bs_d_pct(r->pool, used, cap), frac * 100.0);
}

/* Record an observability-endpoint request in the decision log and keep
 * it out of the access log.
 *
 * These are the measuring instrument, not site traffic: a dashboard left
 * open on a 10s refresh was 8.1% of all requests on this deployment and
 * the source of 3,023 of 4,347 request timeouts. In the access log that
 * distorts every traffic figure derived from it.
 *
 * Suppressing without recording would break the rule the rest of the
 * module keeps -- anything hidden from the access log appears in the
 * decision log -- so the line is written here, deliberately NOT through
 * bs_decision_log: that would call bs_metrics_bump and count viewing the
 * dashboard as a decision, inflating the very numbers the page shows.
 * The counters already track these separately as
 * botshield_responses_observe_total. */
void bs_log_observability_request(request_rec *r)
{
    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    bs_suppress_access_log(r);
    if (!scfg || !scfg->decision_log_fd) return;

    const char *ua   = apr_table_get(r->headers_in, "User-Agent");
    const char *path = (r->unparsed_uri && *r->unparsed_uri)
                       ? r->unparsed_uri : "-";
    /* Format the stamp here rather than reading BS_TIME: that env var is
     * set by bs_decision_log, which this function deliberately does not
     * call, so it is absent on this path. Same format so the two line
     * kinds sort together. */
    apr_time_exp_t tm;
    apr_time_exp_gmt(&tm, apr_time_now());
    const char *ts = apr_psprintf(r->pool,
        "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_usec / 1000);
    const char *line = apr_psprintf(r->pool,
        "%s tier=none outcome=observe ip=%s score=0 cookie=- provider=- "
        "alg=- reason=\"observability-endpoint\" path=\"%s\" ua=\"%s\"\n",
        ts,
        (r->useragent_ip && *r->useragent_ip) ? r->useragent_ip : "-",
        bs_log_quote(r->pool, path),
        ua ? bs_log_quote(r->pool, ua) : "-");
    apr_size_t len = strlen(line);
    apr_file_write(scfg->decision_log_fd, line, &len);
}

int bs_dashboard_handler(request_rec *r)
{
    apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "obs");
    bs_log_observability_request(r);
    int span = 60;
    /* Auto-refresh seconds. Defaults to 30 because the common use is a
     * page left open while watching traffic; r=0 turns it off. Offering
     * the off switch is not optional politeness — WCAG 2.2.1 wants
     * auto-updating content to be pausable or adjustable. */
    int refresh = 30;
    if (r->args) {
        const char *wv = bs_d_qparam(r->pool, r->args, "w");
        if (wv) {
            if      (strcmp(wv, "15")   == 0) span = 15;
            else if (strcmp(wv, "60")   == 0) span = 60;
            else if (strcmp(wv, "1440") == 0) span = 1440;
            else if (strcmp(wv, "all")  == 0) span = 0;
        }
        const char *rv = bs_d_qparam(r->pool, r->args, "r");
        if (rv) {
            if      (strcmp(rv, "0")  == 0) refresh = 0;
            else if (strcmp(rv, "10") == 0) refresh = 10;
            else if (strcmp(rv, "30") == 0) refresh = 30;
            else if (strcmp(rv, "60") == 0) refresh = 60;
        }
    }
    const char *wq = (span == 15) ? "15" : (span == 1440) ? "1440"
                   : (span == 0)  ? "all" : "60";

    /* Vhost tab. -1 is the aggregate and stays the default: the
     * whole-server view is what an operator wants first, and it is the
     * one guaranteed to agree with /botshield/metrics. */
    int vsel = -1;
    const bs_vhost_dir *vdir = bs_shm.vhost_dir;
    {
        const char *v = bs_d_qparam(r->pool, r->args, "vh");
        if (v && strcmp(v, "all") != 0 && vdir) {
            char *end = NULL;
            long n = strtol(v, &end, 10);
            if (end && *end == '\0' && n >= 0
                && (apr_uint32_t)n < vdir->count) {
                vsel = (int)n;
            }
        }
    }
    const char *vq = (vsel < 0) ? "all"
                                : apr_psprintf(r->pool, "%d", vsel);

    /* Audience tab. In the query string for the same reason w/r/vh are:
     * the page auto-refreshes, and any selection the URL does not carry
     * snaps back to its default every interval. That ruled out the
     * CSS-only :checked approach this started as -- a radio resets on
     * every load, so the tab would flip back to Bots under anyone
     * watching the page. Carrying it here also makes a tab linkable,
     * which the radio version was not. */
    int aud = BS_M_GROUP_BOT;
    {
        const char *t = bs_d_qparam(r->pool, r->args, "tab");
        if (t && strcmp(t, "usr") == 0) aud = BS_M_GROUP_USER;
    }
    const char *tq = (aud == BS_M_GROUP_USER) ? "usr" : "bot";

    bs_metrics_window w;
    bs_metrics_read_window(span, vsel, &w);
    bs_gauges_refresh();

    /* The site-wide decisions/challenged/verified/blocked/unsolved
     * locals that used to live here fed the single decisions section.
     * That section is now split by audience, and bs_d_audience_panel
     * derives each figure from g_outcome[] for its own group -- summing
     * the two tabs reproduces the old totals. Solve counts still come
     * from outcome[verified] rather than cookie[], since one human
     * browsing 50 pages carries a cookie on all 50 but solved once. */

    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Robots-Tag", "noindex, nofollow");

    ap_rputs(
      "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
      "<meta name='viewport' content='width=device-width,initial-scale=1'>", r);
    if (refresh > 0) {
        /* Carry the current window through the refresh, or the page
         * would silently snap back to the default every interval. */
        ap_rprintf(r,
            "<meta http-equiv='refresh' "
            "content='%d;url=?w=%s&amp;r=%d&amp;vh=%s&amp;tab=%s'>",
            refresh, wq, refresh, vq, tq);
    }
    ap_rputs(
      "<title>mod_botshield dashboard</title><style>"
      ":root{--surface:#fcfcfb;--ink:#1a1a19;--ink2:#5c5c58;--muted:#8a8a84;"
      "--line:#e4e4e0;--t1:" BS_D_T1 ";--t2:" BS_D_T2 ";--t3:" BS_D_T3 ";--t4:" BS_D_T4 ";"
      "--c1:" BS_D_C1 ";--c2:" BS_D_C2 ";--c3:" BS_D_C3 ";"
      "--c4:" BS_D_C4 ";--c5:" BS_D_C5 ";--c6:" BS_D_C6 ";"
      "--c7:" BS_D_C7 ";"
      "--track:#eef2f7;--good:#0ca30c;--warn:#fab219;--crit:#d03b3b;"
      "--neutral:#8a8a84}"
      "@media(prefers-color-scheme:dark){:root{--surface:#1a1a19;--ink:#f2f2ef;"
      "--ink2:#b9b9b2;--muted:#8a8a84;--line:#33332f;"
      /* Separate dark selection, validated against #1a1a19 — not a flip. */
      "--t1:#3987e5;--t2:#6da7ec;--t3:#9ec5f4;--t4:#cde2fb;"
      "--c1:#3987e5;--c2:#d95926;--c3:#199e70;--c4:#c98500;"
      "--c5:#d55181;--c6:#008300;--c7:#9d86e0;--track:#26262340}}"
      "*{box-sizing:border-box}"
      "body{margin:0;padding:28px 24px 56px;background:var(--surface);color:var(--ink);"
      "font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
      "main{max-width:860px;margin:0 auto}"
      "h1{font-size:19px;margin:0 0 2px;font-weight:600}"
      "h2{font-size:13px;font-weight:600;color:var(--ink2);margin:0 0 10px;"
      "text-transform:uppercase;letter-spacing:.04em}"
      ".sub{color:var(--muted);font-size:13px;margin:0 0 20px}"
      "nav{display:flex;gap:6px;margin:0 0 26px;flex-wrap:wrap}"
      "nav a{padding:5px 12px;border:1px solid var(--line);border-radius:999px;"
      "text-decoration:none;color:var(--ink2);font-size:13px}"
      "nav a.on{background:var(--t3);border-color:var(--t3);color:#fff}"
      "nav.rf{align-items:center;margin-top:-16px;margin-bottom:26px}"
      "nav.rf span{font-size:12px;color:var(--muted)}"
      "nav.rf a{padding:3px 9px;font-size:12px}"
      "nav.rf .ts{margin-left:auto;font-variant-numeric:tabular-nums}"
      "section{margin:0 0 28px}"
      ".kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}"
      /* Audience tabs. Plain links, because the selection lives in the
       * query string -- see the `tab` parse -- so it survives the
       * auto-refresh. Ordinary anchors are keyboard-operable and
       * linkable for free. */
      ".tabbar{display:flex;gap:2px;border-bottom:1px solid var(--line);"
      "margin:0 0 16px}"
      ".tabbar a{padding:8px 14px;font-size:13px;font-weight:600;"
      "letter-spacing:.02em;color:var(--muted);text-decoration:none;"
      "border-bottom:2px solid transparent;margin-bottom:-1px;"
      "white-space:nowrap}"
      ".tabbar a span{font-weight:400;color:var(--muted);margin-left:6px;"
      "font-variant-numeric:tabular-nums}"
      ".tabbar a:hover{color:var(--ink2)}"
      ".tabbar a.on{color:var(--ink);border-bottom-color:var(--t2)}"
      ".tabbar a.on span{color:var(--ink2)}"
      ".note{margin:0 0 16px;font-size:13px;line-height:1.45;"
      "color:var(--ink2);max-width:62ch}"
      ".kpi{border:1px solid var(--line);border-radius:8px;padding:12px 14px}"
      ".kpi .k{font-size:12px;color:var(--muted);margin-bottom:4px}"
      ".kpi .v{font-size:27px;font-weight:600;letter-spacing:-.02em;line-height:1.1}"
      ".kpi .n{font-size:12px;color:var(--muted);margin-top:2px}"
      ".legend{list-style:none;display:flex;flex-wrap:wrap;gap:14px;padding:8px 0 0;margin:0}"
      ".legend li{font-size:13px;color:var(--ink2);display:flex;align-items:center;gap:6px}"
      ".legend i{width:10px;height:10px;border-radius:2px;display:inline-block}"
      ".legend b{color:var(--ink);font-weight:600}"
      ".legend span{color:var(--muted)}"
      ".meter{margin:0 0 12px}"
      ".mrow{display:flex;justify-content:space-between;font-size:13px;color:var(--ink2)}"
      ".mval b{color:var(--ink)}"
      ".track{height:8px;border-radius:4px;background:var(--track);margin-top:5px;overflow:hidden}"
      ".fill{height:100%;background:var(--t3);border-radius:4px}"
      "table{border-collapse:collapse;width:100%;font-size:14px}"
      "th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}"
      "th{font-size:12px;color:var(--muted);font-weight:600}"
      "td.n{text-align:right;font-variant-numeric:tabular-nums}"
      ".empty{color:var(--muted);font-size:14px;margin:0}"
      "nav.vh{margin:-10px 0 18px;flex-wrap:wrap}"
      "nav.vh a{font-size:12px}"
      "footer{color:var(--muted);font-size:12px;margin-top:34px;border-top:1px solid var(--line);padding-top:12px}"
      "</style></head><body><main>", r);

    {
        const char *scope = (vsel < 0)
            ? "all vhosts"
            : ap_escape_html(r->pool, vdir->name[vsel]);
        ap_rprintf(r,
            "<h1>mod_botshield</h1><p class='sub'>%s &middot; %s</p>",
            bs_d_window_label(span), scope);
    }

    ap_rputs("<nav>", r);
    const struct { const char *q, *t; int s; } wins[] = {
        {"15", "15 min", 15}, {"60", "1 hour", 60},
        {"1440", "24 hours", 1440}, {"all", "All time", 0} };
    for (int i = 0; i < 4; i++) {
        ap_rprintf(r,
                   "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%s&amp;tab=%s'>%s</a>",
                   span == wins[i].s ? "on" : "", wins[i].q, refresh,
                   vq, tq, wins[i].t);
    }
    ap_rputs("</nav>", r);

    /* Vhost tabs. Only worth drawing when there is more than one site
     * to choose between; a single-vhost server gets no row rather than
     * a row with one inert tab in it. */
    if (vdir && vdir->count > 1) {
        ap_rputs("<nav class='vh'>", r);
        ap_rprintf(r, "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=all"
                      "&amp;tab=%s'>All vhosts</a>",
                   vsel < 0 ? "on" : "", wq, refresh, tq);
        for (apr_uint32_t i = 0; i < vdir->count; i++) {
            if (!vdir->name[i][0]) continue;
            ap_rprintf(r,
                "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%u"
                "&amp;tab=%s'>%s</a>",
                vsel == (int)i ? "on" : "", wq, refresh, i, tq,
                ap_escape_html(r->pool, vdir->name[i]));
        }
        ap_rputs("</nav>", r);
    }

    /* Refresh control, and a rendered-at stamp so a stale tab is
     * obvious at a glance rather than quietly wrong. */
    {
        char ts[32];
        apr_time_exp_t tm;
        apr_time_exp_lt(&tm, apr_time_now());
        apr_snprintf(ts, sizeof(ts), "%02d:%02d:%02d",
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        ap_rputs("<nav class='rf'><span>Auto-refresh</span>", r);
        static const int opts[4] = { 0, 10, 30, 60 };
        for (int i = 0; i < 4; i++) {
            char lbl[8];
            if (opts[i] == 0) apr_snprintf(lbl, sizeof(lbl), "Off");
            else              apr_snprintf(lbl, sizeof(lbl), "%ds", opts[i]);
            ap_rprintf(r,
                       "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%s"
                       "&amp;tab=%s'>%s</a>",
                       refresh == opts[i] ? "on" : "", wq, opts[i], vq,
                       tq, lbl);
        }
        ap_rprintf(r, "<span class='ts'>rendered %s</span></nav>", ts);
    }

    /* Site traffic first: it is the denominator everything below is a
     * share of, and with the enable scoped to a <Location> the gap
     * between requests and decisions is the single most important
     * thing an operator can misread. */
    ap_rputs("<section><h2>Site traffic (all vhosts)</h2><div class='kpis'>", r);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Requests</div>"
                  "<div class='v'>%" APR_UINT64_T_FMT "</div></div>",
               w.req_total);
    ap_rprintf(r, "<div class='kpi'><div class='k'>With BS cookie</div>"
                  "<div class='v'>%s</div><div class='n'>%" APR_UINT64_T_FMT
                  " requests</div></div>",
               bs_d_pct(r->pool, w.req_cookie, w.req_total), w.req_cookie);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Evaluated</div>"
                  "<div class='v'>%s</div><div class='n'>%" APR_UINT64_T_FMT
                  " reached a decision</div></div>",
               bs_d_pct(r->pool, w.decisions, w.req_total), w.decisions);
    ap_rputs("</div></section>", r);

    /* Who is visiting. Categorical: these are kinds of client, not a
     * scale -- a known bot is not "worse" than a browser. fake-bot is
     * the one with a verdict in it, and it still takes a categorical
     * slot rather than the critical status token, because mixing the
     * two vocabularies in one chart makes the other five look like
     * severity levels. The label carries the meaning; the hue only
     * carries identity. */
    {
        const char *labels[] = { "browser", "verified bot", "known bot",
                                 "unknown bot", "fake bot", "unclassified" };
        const char *fills[]  = { "var(--c1)", "var(--c2)", "var(--c3)",
                                 "var(--c4)", "var(--c5)", "var(--neutral)" };
        apr_uint64_t vals[]  = { w.req_class[BS_M_CLASS_BROWSER],
                                 w.req_class[BS_M_CLASS_VERIFIED_BOT],
                                 w.req_class[BS_M_CLASS_KNOWN_BOT],
                                 w.req_class[BS_M_CLASS_UNKNOWN_BOT],
                                 w.req_class[BS_M_CLASS_FAKE_BOT],
                                 w.req_class[BS_M_CLASS_UNKNOWN] };
        apr_uint64_t tot = 0;
        for (int i = 0; i < 6; i++) tot += vals[i];
        bs_d_stacked(r, "cls", "Client classification", labels, vals,
                     fills, 6, tot);
    }

    /* Status class carries polarity (good -> bad), so it wears the
     * reserved status tokens rather than categorical slots. 3xx takes a
     * neutral: a redirect is not a warning, and saying so in colour
     * would be a lie. Every segment is direct-labelled, which is also
     * the required mitigation for the sub-3:1 light-surface steps. */
    {
        const char *labels[] = { "2xx", "3xx", "4xx", "5xx", "other" };
        /* HTTP status classes follow the convention every devtools and
         * log viewer already uses -- green / blue / orange / red -- so
         * the chart reads without consulting a legend. Blue is not in
         * the reserved status palette, which only has
         * good/warning/serious/critical, so 3xx and 4xx take
         * categorical slots 1 and 2. Mixing the two vocabularies in one
         * chart is normally wrong; here the convention is strong enough
         * that following it beats internal purity, and every segment is
         * direct-labelled with its value and share so identity never
         * rides on colour alone. */
        const char *fills[]  = { "var(--good)", "var(--c1)",
                                 "var(--c2)", "var(--crit)",
                                 "var(--muted)" };
        apr_uint64_t vals[]  = { w.req_status[BS_M_STATUS_2XX],
                                 w.req_status[BS_M_STATUS_3XX],
                                 w.req_status[BS_M_STATUS_4XX],
                                 w.req_status[BS_M_STATUS_5XX],
                                 w.req_status[BS_M_STATUS_OTHER] };
        apr_uint64_t tot = 0;
        for (int i = 0; i < 5; i++) tot += vals[i];
        bs_d_stacked(r, "st", "Response status", labels, vals, fills, 5, tot);
    }

    /* What BotShield itself answered. Deliberately NOT a segment inside
     * the status chart: on a healthy site the origin is ~99% of the
     * bar, which would squeeze every BotShield response into an
     * unreadable sliver. The share goes in a KPI, and the breakdown
     * gets its own bar scaled to BotShield's own responses. */
    {
        /* Three-way: BotShield / static files / the application.
         *
         * `ours` must skip BOTH non-BotShield kinds. ORIGIN was already
         * excluded; STATIC has to be too, or every stylesheet and image
         * counts as something this module answered.
         *
         * The split exists because two of these three answer different
         * questions and used to be one number. A page pulls in twenty
         * sub-resources, so static volume dwarfs application volume:
         * with them merged, "how much reached the app" was really "how
         * many files did Apache hand back", and the comparison anyone
         * actually wants -- BotShield versus the application -- was
         * buried under asset traffic that no policy will ever touch. */
        apr_uint64_t ours = 0;
        for (int i = 1; i < BS_M_RESP_COUNT; i++) {
            if (i == BS_M_RESP_STATIC) continue;
            ours += w.req_resp[i];
        }
        apr_uint64_t stat_n = w.req_resp[BS_M_RESP_STATIC];
        apr_uint64_t app_n  = w.req_resp[BS_M_RESP_ORIGIN];

        ap_rputs("<section><h2>Who answered</h2>"
                 "<div class='kpis'>", r);
        ap_rprintf(r, "<div class='kpi'><div class='k'>BotShield"
                      "</div><div class='v'>%s</div>"
                      "<div class='n'>%" APR_UINT64_T_FMT " of %"
                      APR_UINT64_T_FMT " requests</div></div>",
                   bs_d_pct(r->pool, ours, w.req_total), ours, w.req_total);
        ap_rprintf(r, "<div class='kpi'><div class='k'>Static files</div>"
                      "<div class='v'>%s</div><div class='n'>%"
                      APR_UINT64_T_FMT " served off disk</div></div>",
                   bs_d_pct(r->pool, stat_n, w.req_total), stat_n);
        ap_rprintf(r, "<div class='kpi'><div class='k'>Application</div>"
                      "<div class='v'>%s</div><div class='n'>%"
                      APR_UINT64_T_FMT " reached the app</div></div>",
                   bs_d_pct(r->pool, app_n, w.req_total), app_n);
        ap_rputs("</div>", r);

        {
            const char *wlabels[] = { "BotShield", "static files",
                                      "application" };
            const char *wfills[]  = { "var(--t2)", "var(--neutral)",
                                      "var(--c3)" };
            apr_uint64_t wvals[]  = { ours, stat_n, app_n };
            bs_d_stacked(r, "who", "Requests by responder", wlabels, wvals,
                         wfills, 3, ours + stat_n + app_n);
        }
        ap_rputs("</section>", r);

        /* Kinds of response, not a good-to-bad scale: a block is
         * BotShield working, not a failure. So categorical slots
         * rather than status tokens. Scaled to `ours`, so this reads
         * as "of what we answered, what was it". */
        const char *labels[] = { "challenge", "block", "rate limited",
                                 "redirect", "endpoint", "dashboard" };
        const char *fills[]  = { "var(--c1)", "var(--c2)", "var(--c3)",
                                 "var(--c4)", "var(--c5)", "var(--neutral)" };
        apr_uint64_t vals[]  = { w.req_resp[BS_M_RESP_CHALLENGE],
                                 w.req_resp[BS_M_RESP_BLOCK],
                                 w.req_resp[BS_M_RESP_RATE_LIMITED],
                                 w.req_resp[BS_M_RESP_REDIRECT],
                                 w.req_resp[BS_M_RESP_ENDPOINT],
                                 w.req_resp[BS_M_RESP_OBSERVE] };
        /* The instrument wears the neutral, not a categorical slot: it
         * is not one of the policy responses, it is you looking. */
        bs_d_stacked(r, "rk", "BotShield response breakdown", labels, vals,
                     fills, 6, ours);
    }

    /* Rate limiting, broken out of the response bar above.
     *
     * It earns its own section for a display reason and a semantic one.
     * Display: rate-limited is routinely a fraction of a percent of
     * BotShield's responses, which is around a pixel of a 600px bar —
     * the <title> is there but the segment is too narrow to hover, so
     * the bar cannot answer "is the rate limit doing anything".
     * Semantic: the others are per-request verdicts on a client, while
     * this is a budget decision about a crawler across all its IPs. It
     * is tuned with different directives and read on a different
     * cadence.
     *
     * MIND THE TIME BASES — they are deliberately not the same, and
     * mixing them silently is how a dashboard starts lying:
     *   - "429s in this window" is windowed, from req_resp[], and moves
     *     with the w= selector like everything else on the page.
     *   - enforced/observed totals are plain bs_metrics fields, so they
     *     are cumulative SINCE RESTART regardless of w=. They are
     *     labelled as such rather than being quietly rescaled.
     *   - and they are read from the GLOBAL block, not the per-vhost
     *     one, because bot_rate.c and policy.c only ever increment
     *     bs_shm.metrics->. There is no per-vhost copy to select, so
     *     with vh= set these two do not narrow with the rest of the
     *     page. Labelled "all vhosts" for that reason; do not "fix" it
     *     by pointing them at bs_vhost_block(), which would read a
     *     field nothing writes and render a confident zero.
     * Both totals also span BOTH families — BotShieldBotRateLimit
     * (slug-keyed) and BotShieldRateLimit (cohort) — because
     * bot_rate.c and policy.c increment the same pair. On a host with
     * only one family configured that is the same number; on a host
     * with both it is a sum, and the split is not recoverable here.
     *
     * Not shown, because the counters do not exist: which bot slugs are
     * being limited. That is per-holder state and needs a cumulative
     * counter on bs_bot_rate_slot; until then the decision log is the
     * only place to get it:
     *   grep -oE 'bot-rate:[a-z0-9-]+' botshield.log | sort | uniq -c
     */
    {
        /* Recomputed, not borrowed: `ours` above is scoped to the
         * response-breakdown block. */
        apr_uint64_t rl_total = 0;
        for (int i = 1; i < BS_M_RESP_COUNT; i++) rl_total += w.req_resp[i];

        apr_uint64_t rl_win = w.req_resp[BS_M_RESP_RATE_LIMITED];
        apr_uint64_t enforced = 0, observed = 0;
        if (bs_shm.metrics) {
            enforced = bs_mload(&bs_shm.metrics->rate_limit_exceeded_total);
            observed = bs_mload(&bs_shm.metrics->rate_limit_observed_total);
        }

        ap_rputs("<section><h2>Rate limiting</h2><div class='kpis'>", r);
        ap_rprintf(r, "<div class='kpi'><div class='k'>429s issued</div>"
                      "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                      "<div class='n'>%s of BotShield responses, %s</div>"
                      "</div>",
                   rl_win, bs_d_pct(r->pool, rl_win, rl_total),
                   bs_d_window_label(span));
        ap_rprintf(r, "<div class='kpi'><div class='k'>Enforced</div>"
                      "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                      "<div class='n'>all vhosts, since restart</div></div>",
                   enforced);
        ap_rprintf(r, "<div class='kpi'><div class='k'>Observed</div>"
                      "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                      "<div class='n'>would have 429'd, all vhosts</div>"
                      "</div>", observed);
        ap_rputs("</div>", r);

        /* Enforced vs observed is the tuning question — how much of the
         * configured limit is actually acting. Only drawn when there is
         * something to draw; a site with rate limiting off should show
         * the KPIs reading zero, not an empty chart frame. */
        if (enforced || observed) {
            const char *rl_labels[] = { "enforced", "observed" };
            const char *rl_fills[]  = { "var(--c3)", "var(--neutral)" };
            apr_uint64_t rl_vals[]  = { enforced, observed };
            bs_d_stacked(r, "rl", "Rate limit: enforced vs observed",
                         rl_labels, rl_vals, rl_fills, 2,
                         enforced + observed);
        }
        ap_rputs("</section>", r);
    }

    /* KPI row — a handful of headline numbers is a stat row, not a chart. */
    /* Decisions, split by audience into two tabs.
     *
     * Mixing bots and humans in one set of numbers made both unreadable.
     * On this hub the majority of evaluated traffic is declared crawlers
     * that BotShield passes ON PURPOSE -- they cannot solve a JS
     * challenge and are governed by rate limits instead -- so they drag
     * the aggregate challenge rate down and hide what is actually
     * happening to visitors. Separating them means each tab's challenge
     * and solve rates are answerable questions.
     *
     * CSS-only tabs: two radios and sibling :checked selectors. The
     * dashboard ships no JavaScript and this does not change that. The
     * radios stay in the tab order (opacity, not display:none) so the
     * tabs remain keyboard-reachable.
     *
     * Both panels are always rendered; the tab only chooses which is
     * visible. That keeps the page a single request with no state, and
     * costs one extra set of bars in the HTML. */
    {
        apr_uint64_t bot_dec = 0, usr_dec = 0;
        for (int o = 0; o < BS_M_OUTCOME_COUNT; o++) {
            bot_dec += w.g_outcome[BS_M_GROUP_BOT][o];
            usr_dec += w.g_outcome[BS_M_GROUP_USER][o];
        }
        static const int bot_cls[] = { BS_M_CLASS_VERIFIED_BOT,
                                       BS_M_CLASS_KNOWN_BOT,
                                       BS_M_CLASS_UNKNOWN_BOT };
        static const char *bot_lbl[] = { "verified bot", "known bot",
                                         "unknown bot" };
        static const int usr_cls[] = { BS_M_CLASS_BROWSER,
                                       BS_M_CLASS_FAKE_BOT,
                                       BS_M_CLASS_UNKNOWN };
        static const char *usr_lbl[] = { "browser", "fake bot", "unknown" };

        ap_rputs("<section><h2>BotShield decisions</h2>", r);
        ap_rprintf(r,
            "<nav class='tabbar'>"
            "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%s&amp;tab=bot'>"
            "Bots <span>%" APR_UINT64_T_FMT "</span></a>"
            "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%s&amp;tab=usr'>"
            "Users &amp; unknown <span>%" APR_UINT64_T_FMT "</span></a>"
            "</nav>",
            aud == BS_M_GROUP_BOT ? "on" : "", wq, refresh, vq, bot_dec,
            aud == BS_M_GROUP_USER ? "on" : "", wq, refresh, vq, usr_dec);

        if (aud == BS_M_GROUP_BOT) {
            ap_rputs("<p class='note'>Declared crawlers. Most are passed "
                     "deliberately and governed by BotShieldBotRateLimit "
                     "rather than by challenges, so a low challenge rate "
                     "here is the policy working, not a gap.</p>", r);
            bs_d_audience_panel(r, &w, BS_M_GROUP_BOT, "b",
                                bot_cls, bot_lbl, 3);
        } else {
            ap_rputs("<p class='note'>Browsers, unclassified clients, and "
                     "UAs claiming to be crawlers whose IP failed the "
                     "cross-check. This is the population challenges are "
                     "aimed at, so challenge and solve rates here are the "
                     "ones to read.</p>", r);
            bs_d_audience_panel(r, &w, BS_M_GROUP_USER, "u",
                                usr_cls, usr_lbl, 3);
        }
        ap_rputs("</section>", r);
    }

    /* Live capacity — ratios against a limit, so meters. These are
     * point-in-time gauges and ignore the window selector; labelled as
     * such rather than left to imply they follow it. */
    ap_rputs("<section><h2>Capacity now <span style='text-transform:none;"
             "font-weight:400'>(live, not windowed)</span></h2>", r);
    bs_d_meter(r, "Flagged IPs", bs_gauges.flagged_used,
               (apr_uint64_t)bs_shm.flagged_capacity);
    bs_d_meter(r, "Safeguard entries", bs_gauges.safeguard_used,
               (apr_uint64_t)bs_shm.safeguard_capacity);
    bs_d_meter(r, "Rate-limit strikes", bs_gauges.strike_used,
               (apr_uint64_t)bs_shm.strike_capacity);
    ap_rputs("</section>", r);

    /* Eleven outcome classes is a table, not eleven hues. */
    ap_rputs("<section><h2>Outcomes</h2><table><thead><tr><th>Outcome</th>"
             "<th class='n'>Count</th><th class='n'>Share</th></tr></thead><tbody>", r);
    {
        const char *const *onames = bs_m_outcome_names;
        int shown = 0;
        for (int i = 0; i < BS_M_OUTCOME_COUNT; i++) {
            if (!w.outcome[i]) continue;
            ap_rprintf(r, "<tr><td>%s</td><td class='n'>%" APR_UINT64_T_FMT
                          "</td><td class='n'>%s</td></tr>",
                       onames[i], w.outcome[i],
                       bs_d_pct(r->pool, w.outcome[i], w.decisions));
            shown++;
        }
        if (!shown) ap_rputs("<tr><td colspan='3' class='empty'>"
                             "Nothing recorded in this window.</td></tr>", r);
    }
    ap_rputs("</tbody></table></section>", r);

    ap_rputs("<footer>Counters reset when the SHM segment is recreated, which "
             "a graceful restart does. Windowed views are bucketed and "
             "advisory: a writer crossing a bucket boundary can lose an "
             "increment. &ldquo;Unsolved&rdquo; means a challenge was issued "
             "and the client never came back &mdash; they are gone, not "
             "queued.</footer></main></body></html>", r);
    return OK;
}

int bs_metrics_handler(request_rec *r)
{
    apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "obs");
    bs_log_observability_request(r);
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

    bs_m_emit_counter(r, "requests_total",
        "Every request the server logged, on every vhost, whether or "
        "not BotShield evaluated it. Denominator for coverage.",
        bs_mload(&m->req_total));
    bs_m_emit_counter(r, "requests_with_cookie_total",
        "Requests that arrived carrying a BotShield session cookie.",
        bs_mload(&m->req_cookie));
    bs_m_emit_counter(r, "requests_status_2xx_total",
        "Requests answered 2xx.", bs_mload(&m->req_status[BS_M_STATUS_2XX]));
    bs_m_emit_counter(r, "requests_status_3xx_total",
        "Requests answered 3xx.", bs_mload(&m->req_status[BS_M_STATUS_3XX]));
    bs_m_emit_counter(r, "requests_status_4xx_total",
        "Requests answered 4xx (includes BotShield blocks).",
        bs_mload(&m->req_status[BS_M_STATUS_4XX]));
    bs_m_emit_counter(r, "requests_status_5xx_total",
        "Requests answered 5xx.", bs_mload(&m->req_status[BS_M_STATUS_5XX]));
    bs_m_emit_counter(r, "requests_status_other_total",
        "Requests answered outside 2xx-5xx (1xx, or no status recorded).",
        bs_mload(&m->req_status[BS_M_STATUS_OTHER]));

    bs_m_emit_counter(r, "clients_browser_total",
        "Requests from a UA matching a real-browser template.",
        bs_mload(&m->req_class[BS_M_CLASS_BROWSER]));
    bs_m_emit_counter(r, "clients_verified_bot_total",
        "Requests from a crawler whose UA matched the allow list AND "
        "whose IP is in that crawler's published ranges.",
        bs_mload(&m->req_class[BS_M_CLASS_VERIFIED_BOT]));
    bs_m_emit_counter(r, "clients_known_bot_total",
        "Requests from a UA in the bot directory, not IP-verified.",
        bs_mload(&m->req_class[BS_M_CLASS_KNOWN_BOT]));
    bs_m_emit_counter(r, "clients_unknown_bot_total",
        "Requests from a UA with bot-shaped tokens but no directory "
        "entry.", bs_mload(&m->req_class[BS_M_CLASS_UNKNOWN_BOT]));
    bs_m_emit_counter(r, "clients_fake_bot_total",
        "Requests claiming a crawler UA from an IP outside that "
        "crawler's published ranges - spoofed.",
        bs_mload(&m->req_class[BS_M_CLASS_FAKE_BOT]));
    bs_m_emit_counter(r, "clients_unknown_total",
        "Requests matching no classifier.",
        bs_mload(&m->req_class[BS_M_CLASS_UNKNOWN]));

    bs_m_emit_counter(r, "responses_origin_total",
        "Requests the application answered (BotShield did not respond).",
        bs_mload(&m->req_resp[BS_M_RESP_ORIGIN]));
    bs_m_emit_counter(r, "responses_static_total",
        "Requests answered off disk by the core handler (CSS, JS, "
        "images, uploads). Split out of responses_origin_total, which "
        "now counts application responses only.",
        bs_mload(&m->req_resp[BS_M_RESP_STATIC]));
    bs_m_emit_counter(r, "responses_challenge_total",
        "Responses where BotShield served an interstitial.",
        bs_mload(&m->req_resp[BS_M_RESP_CHALLENGE]));
    bs_m_emit_counter(r, "responses_block_total",
        "Responses where BotShield refused the request.",
        bs_mload(&m->req_resp[BS_M_RESP_BLOCK]));
    bs_m_emit_counter(r, "responses_rate_limited_total",
        "Responses where BotShield rate-limited or shed the request.",
        bs_mload(&m->req_resp[BS_M_RESP_RATE_LIMITED]));
    bs_m_emit_counter(r, "responses_redirect_total",
        "Responses where BotShield issued a safeguard redirect.",
        bs_mload(&m->req_resp[BS_M_RESP_REDIRECT]));
    bs_m_emit_counter(r, "responses_endpoint_total",
        "Responses served by a functional BotShield endpoint "
        "(verify, bootstrap, assets).",
        bs_mload(&m->req_resp[BS_M_RESP_ENDPOINT]));
    bs_m_emit_counter(r, "responses_observe_total",
        "Responses served by an observability endpoint (dashboard, "
        "metrics, policy-status) -- the measuring instrument, counted "
        "so it can be discounted.",
        bs_mload(&m->req_resp[BS_M_RESP_OBSERVE]));

    bs_m_emit_counter(r, "outcome_allow_total",
        "Decisions that let the request through (pass tier, asset bypass, "
        "silent embedded pass-through, safeguard pass).",
        bs_mload(&m->outcome[BS_M_OUTCOME_ALLOW]));
    bs_m_emit_counter(r, "outcome_challenged_total",
        "Decisions that served an interstitial.",
        bs_mload(&m->outcome[BS_M_OUTCOME_CHALLENGED]));
    bs_m_emit_counter(r, "outcome_verified_total",
        "Challenges completed successfully: captcha siteverify OK, or "
        "an embedded-verify PoW accepted. One per solve.",
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
        "Rep cookies that verified fully (signature + freshness + PoW) "
        "but carry NO challenge-solve proof -- presence cookies. Under "
        "always-mint this is what a cookie-harvesting bot holds.",
        bs_mload(&m->cookie[BS_M_COOKIE_OK]));
    bs_m_emit_counter(r, "cookie_solved_total",
        "Rep cookies that verified fully AND carry solve proof "
        "(passes_silent/form/captcha). The only cookie state that "
        "waives first-sight-ip / dropped-cookie.",
        bs_mload(&m->cookie[BS_M_COOKIE_SOLVED]));
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
    bs_m_emit_counter(r, "resp_status_mismatch_total",
        "Requests recorded as answered BY BotShield (challenge, block, "
        "rate-limit, safeguard redirect) where the client nevertheless "
        "received a 2xx, i.e. the application answered. Mutually "
        "exclusive by construction: ALERT ON ANY NON-ZERO VALUE. A "
        "non-zero count means the decision log is overstating "
        "enforcement -- typically an ErrorDocument or a rewrite "
        "re-dispatching after the handler ran.",
        bs_mload(&m->resp_status_mismatch_total));
    bs_m_emit_counter(r, "trigger_observed_total",
        "Trigger matches (path/cookie/env/load) that ran in observe "
        "mode across all families.",
        bs_mload(&m->trigger_observed_total));
    bs_m_emit_counter(r, "rate_limit_exceeded_total",
        "Requests that tripped a BotShieldRateLimit cohort budget "
        "(response was 429 + Retry-After).",
        bs_mload(&m->rate_limit_exceeded_total));

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
