/* metrics.c — implementations behind metrics.h. Decision log,
 * M9.2 counter increments, M9.2 SHM gauge readers (with thread-
 * local 1s cache), M9.3 Prometheus exposition handler, and the
 * mod_status contribution. */

#include "metrics.h"
#include "botshield.h"  /* bs_server_cfg, botshield_module */
#include "shm.h"
#include "ua_class.h"
#include "load.h"        /* bs_load_current, bs_loadavg_current */
#include "bot_directory.h"  /* bs_bot_dir_lookup_slug for /dashboard/bots */
#include "bot_rate.h"       /* bs_bot_rate_slot / state, same page */

#include <string.h>
#include <unistd.h>   /* sysconf(_SC_PAGESIZE) for the RSS sample */

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
    if (strcmp(s, "non-interactive") == 0) return BS_M_TIER_NONINTERACTIVE;
    if (strcmp(s, "interactive") == 0) return BS_M_TIER_INTERACTIVE;
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
            for (int i = 0; i < BS_M_RESP_COUNT; i++) {
                __atomic_store_n(&slot->g_resp[g][i], 0, __ATOMIC_RELAXED);
            }
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
                              int status_idx, int code_idx, int has_cookie,
                              int resp_idx, int group_idx,
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
    if (code_idx >= 0) {
        __atomic_fetch_add(&slot->req_code[code_idx], 1, __ATOMIC_RELAXED);
    }
    if (resp_idx >= 0) {
        __atomic_fetch_add(&slot->req_resp[resp_idx], 1, __ATOMIC_RELAXED);
        if (group_idx >= 0) {
            __atomic_fetch_add(&slot->g_resp[group_idx][resp_idx],
                               1, __ATOMIC_RELAXED);
        }
    }
    if (class_idx >= 0) {
        __atomic_fetch_add(&slot->req_class[class_idx], 1, __ATOMIC_RELAXED);
    }
}

void bs_metrics_traffic_add(int vhost_idx, int status_idx, int code_idx,
                            int has_cookie, int resp_idx, int class_idx)
{
    if (!bs_shm.metrics) return;
    apr_uint64_t minute = (apr_uint64_t)(apr_time_sec(apr_time_now()) / 60);
    apr_uint64_t hour   = minute / 60;
    /* Derived here rather than passed in: the caller already resolved
     * the class, and the group is a pure function of it. */
    int group_idx = (class_idx >= 0) ? bs_m_group_of_class(class_idx) : -1;
    bs_metrics *vm = bs_vhost_block(vhost_idx);
    bs_metrics *blocks[2] = { bs_shm.metrics, vm };
    for (int b = 0; b < 2; b++) {
        bs_metrics *m = blocks[b];
        if (!m) continue;
        bs_m_slot_traffic(&m->min_slots[minute % BS_M_MIN_SLOTS],
                          minute, status_idx, code_idx, has_cookie,
                          resp_idx, group_idx, class_idx);
        bs_m_slot_traffic(&m->hour_slots[hour % BS_M_HOUR_SLOTS],
                          hour, status_idx, code_idx, has_cookie,
                          resp_idx, group_idx, class_idx);
        __atomic_fetch_add(&m->req_total, 1, __ATOMIC_RELAXED);
        if (has_cookie) {
            __atomic_fetch_add(&m->req_cookie, 1, __ATOMIC_RELAXED);
        }
        if (status_idx >= 0) {
            __atomic_fetch_add(&m->req_status[status_idx], 1,
                               __ATOMIC_RELAXED);
        }
        if (code_idx >= 0) {
            __atomic_fetch_add(&m->req_code[code_idx], 1, __ATOMIC_RELAXED);
        }
        if (resp_idx >= 0) {
            __atomic_fetch_add(&m->req_resp[resp_idx], 1, __ATOMIC_RELAXED);
        }
        if (resp_idx >= 0 && group_idx >= 0) {
            __atomic_fetch_add(&m->g_resp[group_idx][resp_idx],
                               1, __ATOMIC_RELAXED);
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
        for (int cd = 0; cd < BS_M_CODE_COUNT; cd++) {
            out->req_code[cd] += __atomic_load_n(&ring[i].req_code[cd],
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
            for (int k = 0; k < BS_M_RESP_COUNT; k++) {
                out->g_resp[g][k] += __atomic_load_n(&ring[i].g_resp[g][k],
                                                     __ATOMIC_RELAXED);
            }
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

/* Share of site traffic that is automated, as a whole percent over the
 * last hour, or -1 when the sample is too thin for the number to say
 * anything. Counted at log_transaction, so the denominator is every
 * request on every vhost rather than only the ones BotShield decided
 * on -- which is the honest denominator for "how much of what arrives
 * here is a bot".
 *
 * Rendered on the non-interactive interstitial. Only the percentage leaves the
 * module: absolute volumes are operational data, and a public page
 * reachable by anyone who trips a challenge is not where they belong.
 */
int bs_bot_share_pct(void)
{
    bs_metrics_window w;
    bs_metrics_read_window(60, -1, &w);

    apr_uint64_t total = 0;
    for (int i = 0; i < BS_M_CLASS_COUNT; i++) {
        total += w.req_class[i];
    }
    /* Below this the figure is an artefact of a restart, not a
     * property of the site, and a wrong number on a page a stranger is
     * reading is worse than no number. */
    if (total < 500) return -1;

    apr_uint64_t bots = w.req_class[BS_M_CLASS_VERIFIED_BOT]
                      + w.req_class[BS_M_CLASS_KNOWN_BOT]
                      + w.req_class[BS_M_CLASS_UNKNOWN_BOT]
                      + w.req_class[BS_M_CLASS_FAKE_BOT];
    return (int)((bots * 100 + total / 2) / total);
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
        for (int cd = 0; cd < BS_M_CODE_COUNT; cd++) {
            out->req_code[cd] =
                __atomic_load_n(&m->req_code[cd], __ATOMIC_RELAXED);
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
            for (int k = 0; k < BS_M_RESP_COUNT; k++) {
                out->g_resp[g][k] = __atomic_load_n(&m->g_resp[g][k],
                                                    __ATOMIC_RELAXED);
            }
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

/* Exact status code to counter index, or -1 for codes we do not track
 * individually. Those still reach their class counter, so the
 * per-code breakdown is always a subset of the class it decomposes
 * and can be presented as "the rest" without a second lookup. */
static int bs_status_code_idx(int status)
{
    switch (status) {
    case 200: return BS_M_CODE_200;  case 204: return BS_M_CODE_204;
    case 206: return BS_M_CODE_206;  case 301: return BS_M_CODE_301;
    case 302: return BS_M_CODE_302;  case 304: return BS_M_CODE_304;
    case 400: return BS_M_CODE_400;  case 401: return BS_M_CODE_401;
    case 403: return BS_M_CODE_403;  case 404: return BS_M_CODE_404;
    case 408: return BS_M_CODE_408;  case 426: return BS_M_CODE_426;
    case 429: return BS_M_CODE_429;  case 500: return BS_M_CODE_500;
    case 502: return BS_M_CODE_502;  case 503: return BS_M_CODE_503;
    default:  return -1;
    }
}

/* Numeric label for each tracked index, for rendering. */
static const int bs_m_code_values[BS_M_CODE_COUNT] = {
    200,204,206, 301,302,304, 400,401,403,404,408,426,429, 500,502,503
};

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
        int code_idx   = bs_status_code_idx(fwd->status);
        int resp_idx   = bs_resp_kind_idx(r);
        bs_metrics_traffic_add(scfg_t ? scfg_t->vhost_idx : -1,
                               status_idx, code_idx, has_cookie, resp_idx,
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
 * hue, light→dark) rather than categorical hues, because pass -> non-interactive
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

/* Load-average chart: one hour of per-CPU load, sized to sit beside the
 * number in its KPI box.
 *
 * COLOUR BY VALUE, not by series. A single stroke gradient in user
 * space maps blue -> amber -> orange -> red onto the y axis, so the
 * line changes colour as it climbs and the band boundaries are the
 * warm and hot thresholds themselves. One <linearGradient> and one
 * <polyline> does what per-segment colouring would need up to 719
 * separate elements to do, and it gradates instead of stepping.
 *
 * Newest on the right. Reading stops at the first BS_M_LA_EMPTY slot,
 * so a partly-filled ring draws a short line rather than a cliff down
 * to an hour of idle that never happened.
 *
 * The y axis scales to whichever is larger, the observed peak or the
 * hot threshold, so the thresholds are always on screen: a quiet hour
 * that hid where "hot" sits would show the level without showing
 * whether it matters. */
/* Both graphs are the same picture of different numbers, so they share
 * one renderer rather than two copies that drift apart. What varies is
 * the ring, its cadence, the thresholds, and how a value prints -- the
 * load average is hundredths-per-CPU and wants "1.50", the database
 * series is a thread count and wants "12". */
typedef struct {
    const apr_uint16_t *ring;
    int          slots;
    int          period;      /* seconds per slot */
    apr_uint16_t empty;
    apr_uint32_t pos;
    int          warm, hot;   /* thresholds, in the series' own units */
    int          hundredths;  /* print values as x.yy rather than as an int */
    const char  *grad_id;     /* must be unique per page: two SVGs, one DOM */
    const char  *aria;
} bs_spark_spec;

static void bs_d_spark(request_rec *r, const bs_spark_spec *sp)
{
    const int aw = sp->warm, ah = sp->hot;
    int vals[BS_M_LA_SLOTS], n = 0, peak = ah;   /* LA is the larger ring */
    for (int i = 0; i < sp->slots; i++) {
        apr_uint32_t idx =
            (sp->pos + (apr_uint32_t)sp->slots - (apr_uint32_t)i)
            % (apr_uint32_t)sp->slots;
        apr_uint16_t v = sp->ring[idx];
        if (v == sp->empty) break;
        vals[n++] = v;
        if (v > peak) peak = v;
    }
    if (n < 2) return;
    /* A tenth of headroom above whatever tops the axis. Without it the
     * quiet case -- where the peak IS the hot threshold -- squeezes the
     * red band to zero width and runs the line along the top edge, so
     * the chart shows neither where "too high" is nor that today was
     * nowhere near it. */
    int seen_peak = peak;          /* before headroom: a real observation */
    peak = peak + peak / 10;

    /* Plot box inside the viewBox; the margins hold the tick labels. */
    const int W = 360, H = 96;
    const int X0 = 34, X1 = 356, Y0 = 6, Y1 = 72;
    const int PH = Y1 - Y0;
    #define BS_LA_Y(v) (Y1 - ((v) * PH) / peak)
    #define BS_LA_X(i) (X1 - ((i) * (X1 - X0)) / (sp->slots - 1))

    ap_rprintf(r, "<svg class='spark' viewBox='0 0 %d %d' role='img' "
                  "aria-label='%s'>", W, H, sp->aria);

    /* Gradient stops are the thresholds, expressed as a fraction of the
     * axis. gradientUnits='userSpaceOnUse' so the stops track the plot
     * box rather than the path's own bounding box -- otherwise the
     * colours would rescale with whatever the line happens to span. */
    ap_rprintf(r,
        "<defs><linearGradient id='%s' gradientUnits='userSpaceOnUse' "
        "x1='0' y1='%d' x2='0' y2='%d'>"
        "<stop offset='0' stop-color='var(--c1)'/>"
        "<stop offset='%d%%' stop-color='var(--c1)'/>"
        "<stop offset='%d%%' stop-color='var(--warn)'/>"
        "<stop offset='%d%%' stop-color='var(--c2)'/>"
        "<stop offset='100%%' stop-color='var(--crit)'/>"
        "</linearGradient></defs>",
        sp->grad_id, Y1, Y0,
        (aw * 50) / peak,      /* still calm below half of warm */
        (aw * 100) / peak,     /* amber from warm */
        (ah * 100) / peak);    /* orange from hot, red above */

    /* Threshold guides. */
    ap_rprintf(r, "<line x1='%d' y1='%d' x2='%d' y2='%d' "
                  "stroke='var(--warn)' stroke-width='1' "
                  "stroke-dasharray='3 3' opacity='.55'/>",
               X0, BS_LA_Y(aw), X1, BS_LA_Y(aw));
    ap_rprintf(r, "<line x1='%d' y1='%d' x2='%d' y2='%d' "
                  "stroke='var(--crit)' stroke-width='1' "
                  "stroke-dasharray='3 3' opacity='.55'/>",
               X0, BS_LA_Y(ah), X1, BS_LA_Y(ah));

    /* Axes. */
    ap_rprintf(r, "<line x1='%d' y1='%d' x2='%d' y2='%d' "
                  "stroke='var(--line)' stroke-width='1'/>",
               X0, Y1, X1, Y1);
    ap_rprintf(r, "<line x1='%d' y1='%d' x2='%d' y2='%d' "
                  "stroke='var(--line)' stroke-width='1'/>",
               X0, Y0, X0, Y1);

    /* Y ticks: baseline, the two thresholds, and the peak when it rises
     * above hot -- four labels at most, which is all that fits. */
    {
        int yv[4]; int yn = 0;
        yv[yn++] = 0; yv[yn++] = aw; yv[yn++] = ah;
        /* Label the observed peak only when load actually rose above
         * hot. Labelling the headroom-inflated axis top would claim a
         * reading that never happened. */
        if (seen_peak > ah) yv[yn++] = seen_peak;
        for (int i = 0; i < yn; i++) {
            int y = BS_LA_Y(yv[i]);
            ap_rprintf(r, "<line x1='%d' y1='%d' x2='%d' y2='%d' "
                          "stroke='var(--line)'/>", X0 - 3, y, X0, y);
            if (sp->hundredths) {
                ap_rprintf(r, "<text x='%d' y='%d' text-anchor='end' "
                              "font-size='8' fill='var(--muted)'>"
                              "%d.%02d</text>",
                           X0 - 5, y + 3, yv[i] / 100, yv[i] % 100);
            } else {
                ap_rprintf(r, "<text x='%d' y='%d' text-anchor='end' "
                              "font-size='8' fill='var(--muted)'>%d</text>",
                           X0 - 5, y + 3, yv[i]);
            }
        }
    }

    /* X ticks every 15 minutes, labelled with wall-clock time.
     *
     * Absolute rather than "-30m": these charts sit beside an error log
     * and an access log, and correlating a bump against either means
     * reading a clock. A relative label forces that arithmetic on every
     * glance, and gets it wrong the moment the page has been open a
     * while without refreshing -- the labels stay put while the data
     * scrolls under them.
     *
     * Local time, matching the rendered-at stamp below the controls and
     * the access log's own timestamps. */
    {
        apr_time_t base = apr_time_now();
        for (int mins = 0; mins <= 60; mins += 15) {
            int i = (mins * 60) / sp->period;
            /* A ring of N slots holds N-1 intervals, so a full hour
             * lands one slot past the end; clamp so the leftmost tick
             * sits on the edge instead of being dropped. */
            if (i > sp->slots - 1) i = sp->slots - 1;
            int x = BS_LA_X(i);
            apr_time_exp_t tm;
            apr_time_exp_lt(&tm, base - apr_time_from_sec(mins * 60));
            ap_rprintf(r, "<line x1='%d' y1='%d' x2='%d' y2='%d' "
                          "stroke='var(--line)'/>", x, Y1, x, Y1 + 3);
            ap_rprintf(r, "<text x='%d' y='%d' text-anchor='%s' "
                          "font-size='8' fill='var(--muted)'>%02d:%02d</text>",
                       x, Y1 + 13, mins == 0 ? "end" : "middle",
                       tm.tm_hour, tm.tm_min);
        }
    }

    ap_rprintf(r, "<polyline fill='none' stroke='url(#%s)' "
                  "stroke-width='1.6' stroke-linejoin='round' points='",
               sp->grad_id);
    for (int i = n - 1; i >= 0; i--) {
        ap_rprintf(r, "%d,%d ", BS_LA_X(i), BS_LA_Y(vals[i]));
    }
    ap_rputs("'/></svg>", r);
    #undef BS_LA_Y
    #undef BS_LA_X
}

/* Today's date, for the chart captions. A screenshot of one of these
 * boxes should carry enough to place it in time: the x axis gives the
 * clock, this gives the day. */
static const char *bs_d_today(request_rec *r)
{
    apr_time_exp_t tm;
    apr_time_exp_lt(&tm, apr_time_now());
    return apr_psprintf(r->pool, "%04d-%02d-%02d",
                        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

/* Open a load-monitor box whose chart expands when clicked.
 *
 * CSS-only, because this dashboard ships no JavaScript. A hidden
 * checkbox before the box holds the state and a <label> covering the
 * chart toggles it; the :checked sibling selector then lets the box
 * span the full grid width and grow the chart. Clicking again
 * collapses it.
 *
 * The label wraps only the chart, not the whole tile, so selecting the
 * headline number with the mouse still works.
 *
 * `id` must be unique per page -- four of these render on the overview
 * and a duplicate id would make every label drive the first box. */
static void bs_d_chartbox_open(request_rec *r, const char *id,
                               const char *title,
                               const char *state, const char *tone)
{
    /* Filled pill. Ink is chosen against the fill rather than fixed to
     * white: --warn is a mid amber (#fab219) and white on it is around
     * 1.9:1, which fails badly. Dark ink on amber clears 4.5:1; white
     * clears it on the green, red and grey. */
    const char *ink = strstr(tone, "warn") ? "#231f11" : "#fff";
    ap_rprintf(r,
        "<input type='checkbox' class='zoomcb' id='zoom-%s'>"
        "<div class='kpi kpi-load' id='box-%s'>"
        "<span class='pill' style='background:%s;color:%s'>%s</span>"
        "<div class='k'>%s</div><div class='loadrow'>",
        id, id, tone, ink, state, title);
}

/* Close the box, wrapping the chart just emitted in the toggle label.
 * Split from _open so the caller can emit its number and chart between
 * them without this helper needing to know either. */
static void bs_d_chartbox_close(request_rec *r, const char *id,
                                const char *caption)
{
    ap_rprintf(r,
        "<label class='zoomlab' for='zoom-%s' title='Click to enlarge'>"
        "</label></div>", id);
    if (caption && *caption) {
        ap_rprintf(r, "<div class='n'>%s</div>", caption);
    }
    ap_rputs("</div>", r);
}

/* Per-CPU load average over the last hour. */
static void bs_d_load_spark(request_rec *r)
{
    bs_metrics *m = bs_shm.metrics;
    if (!m) return;
    int aw, ah;
    bs_loadavg_thresholds(r->server, &aw, &ah);
    bs_spark_spec sp = {
        m->la_ring, BS_M_LA_SLOTS, BS_M_LA_PERIOD, BS_M_LA_EMPTY,
        apr_atomic_read32(&m->la_pos), aw, ah, 1, "lag",
        "per-CPU load average over the last hour"
    };
    bs_d_spark(r, &sp);
}

/* Apache mean request latency over the last hour. */
static void bs_d_apache_spark(request_rec *r)
{
    bs_metrics *m = bs_shm.metrics;
    if (!m) return;
    int lw, lh;
    bs_latency_thresholds(r->server, &lw, &lh);
    bs_spark_spec sp = {
        m->ap_ring, BS_M_AP_SLOTS, BS_M_AP_PERIOD, BS_M_AP_EMPTY,
        apr_atomic_read32(&m->ap_pos), lw, lh, 0, "apg",
        "Apache mean request latency over the last hour"
    };
    bs_d_spark(r, &sp);
}

/* PHP-FPM saturation, percent of pm.max_children, over the last hour. */
static void bs_d_fpm_spark(request_rec *r)
{
    bs_metrics *m = bs_shm.metrics;
    if (!m) return;
    int warm = (int)apr_atomic_read32(&m->fpm_warm_pct);
    int hot  = (int)apr_atomic_read32(&m->fpm_hot_pct);
    if (hot <= 0) return;           /* no monitor has ever reported */
    bs_spark_spec sp = {
        m->fpm_ring, BS_M_FPM_SLOTS, BS_M_FPM_PERIOD, BS_M_FPM_EMPTY,
        apr_atomic_read32(&m->fpm_pos), warm, hot, 0, "fpg",
        "PHP-FPM workers busy, percent of the pool ceiling, last hour"
    };
    bs_d_spark(r, &sp);
}

/* Database threads-running over the last hour. Thresholds come from the
 * monitor's own stats file rather than from module config: they are the
 * numbers it actually classified against, so the graph's bands cannot
 * disagree with the state it published. */
static void bs_d_db_spark(request_rec *r)
{
    bs_metrics *m = bs_shm.metrics;
    if (!m) return;
    int warm = (int)apr_atomic_read32(&bs_shm.header->db_warm_threads);
    int hot  = (int)apr_atomic_read32(&bs_shm.header->db_hot_threads);
    if (hot <= 0) return;           /* no monitor has ever reported */
    bs_spark_spec sp = {
        m->db_ring, BS_M_DB_SLOTS, BS_M_DB_PERIOD, BS_M_DB_EMPTY,
        apr_atomic_read32(&m->db_pos), warm, hot, 0, "dbg",
        "database threads running over the last hour"
    };
    bs_d_spark(r, &sp);
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

/* Percentage at which a segment is wide enough to hold its own label.
 *
 * Decided server-side from the share, because CSS cannot measure text
 * and there is no JavaScript here. A label like "12.3%" needs roughly
 * 42px; the bar is commonly 600-900px wide in this layout, so 8% is
 * the smallest share that reliably clears it with air on both sides.
 * Below that the number goes to the legend only rather than being
 * squeezed into a sliver or spilling over its neighbour. */
#define BS_D_INBAR_MIN_PCT 8.0

/* As bs_d_stacked, but each series may carry a `detail` string that is
 * appended to the hover text on both the bar segment and the legend
 * row. Used to break a status class down into the individual codes
 * inside it -- "4xx" is a poor answer when the question is whether
 * those are 403s or 404s. NULL detail renders exactly as before. */
static void bs_d_stacked_detail(request_rec *r, const char *id,
                                const char *title,
                                const char **labels,
                                const apr_uint64_t *vals,
                                const char **fills,
                                const char **detail,
                                int n, apr_uint64_t total)
{
    ap_rprintf(r, "<section><h2>%s</h2>", title);
    if (!total) {
        ap_rputs("<p class='empty'>No decisions in this window.</p></section>", r);
        return;
    }
    /* Flex divs rather than an SVG.
     *
     * The SVG this replaces used preserveAspectRatio='none' to stretch a
     * 600-unit viewBox across the container, which is fine for plain
     * rectangles and ruinous for text: every glyph would be scaled
     * horizontally by whatever the container happened to be. Percentage
     * flex-basis gives the same proportional widths with labels that
     * render at their natural shape.
     *
     * (void)id now -- the clip-path it disambiguated is gone, replaced
     * by overflow:hidden on the rounded track. */
    (void)id;
    ap_rputs("<div class='stack'>", r);
    for (int i = 0; i < n; i++) {
        if (!vals[i]) continue;      /* no zero-width slivers */
        double pct = 100.0 * (double)vals[i] / (double)total;
        const char *pcts = bs_d_pct(r->pool, vals[i], total);
        /* data-tip drives a CSS tooltip rather than title=, because the
         * native one has a browser-controlled delay of about a second
         * that no markup can shorten. aria-label carries the same text
         * for screen readers; it is deliberately not title=, which
         * would put the slow native tooltip back alongside this one.
         *
         * When a breakdown exists the tooltip is ONLY the breakdown --
         * the class total and its share are already on the bar and in
         * the legend, so repeating them just pushes the useful lines
         * further from the cursor. */
        const char *tip = (detail && detail[i] && *detail[i])
            ? detail[i]
            : apr_psprintf(r->pool, "%s: %" APR_UINT64_T_FMT " (%s)",
                           labels[i], vals[i], pcts);
        ap_rprintf(r,
            "<div class='seg' style='flex:0 0 %.4f%%;background:%s' "
            "data-tip='%s' aria-label='%s: %" APR_UINT64_T_FMT " (%s)'>",
            pct, fills[i], tip, labels[i], vals[i], pcts);
        if (pct >= BS_D_INBAR_MIN_PCT) {
            ap_rprintf(r, "<span>%s</span>", pcts);
        }
        ap_rputs("</div>", r);
    }
    ap_rputs("</div><ul class='legend'>", r);
    for (int i = 0; i < n; i++) {
        /* Legend always present for >= 2 series, and every series is
         * also direct-labelled with its value — identity is never
         * carried by colour alone. Text stays in ink tokens; only the
         * swatch wears the series colour. */
        const char *ltip = (detail && detail[i] && *detail[i])
            ? detail[i]
            : apr_psprintf(r->pool, "%s: %" APR_UINT64_T_FMT,
                           labels[i], vals[i]);
        ap_rprintf(r, "<li data-tip='%s'>"
                      "<i style='background:%s'></i>%s "
                      "<b>%" APR_UINT64_T_FMT "</b> <span>%s</span></li>",
                   ltip, fills[i], labels[i], vals[i],
                   bs_d_pct(r->pool, vals[i], total));
    }
    ap_rputs("</ul></section>", r);
}

static void bs_d_stacked(request_rec *r, const char *id, const char *title,
                         const char **labels, const apr_uint64_t *vals,
                         const char **fills, int n, apr_uint64_t total)
{
    bs_d_stacked_detail(r, id, title, labels, vals, fills, NULL, n, total);
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
        const char *labels[] = { "pass", "non-interactive", "interactive",
                                 "captcha" };
        const char *fills[]  = { "var(--t1)", "var(--t2)",
                                 "var(--t3)", "var(--t4)" };
        apr_uint64_t vals[]  = { w->g_tier[g][BS_M_TIER_PASS],
                                 w->g_tier[g][BS_M_TIER_NONINTERACTIVE],
                                 w->g_tier[g][BS_M_TIER_INTERACTIVE],
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

/* The <meta refresh> that makes a left-open page keep itself current.
 * Query-only URL, so it re-requests the page it is on. Every parameter
 * is carried or the refresh would reset the view the operator chose --
 * the failure the old tab= param was fixed for. */
static void bs_d_meta_refresh(request_rec *r, int span, int refresh,
                              const char *vq)
{
    if (refresh <= 0) return;
    const char *wq = span == 0 ? "all"
                   : (span == 15 ? "15" : (span == 1440 ? "1440" : "60"));
    ap_rprintf(r, "<meta http-equiv='refresh' "
                  "content='%d;url=?w=%s&amp;r=%d&amp;vh=%s'>",
               refresh, wq, refresh, vq);
}

/* Shared page chrome for the dashboard family.
 *
 * Extracted when /dashboard/bots arrived: the stylesheet is ~70
 * lines and a second copy would drift the moment either page gained
 * a rule. Title is the only parameter; everything else is identical
 * on purpose, because the two pages are one tool and should not look
 * like two.
 *
 * Emits through the opening <main>; the caller emits its own body. */
static void bs_d_page_open(request_rec *r, const char *title,
                           int span, int refresh, const char *vq)
{
    /* Prologue lives here, not in a caller. It used to be emitted by
     * bs_dashboard_handler alone, so every page split off it shipped
     * with no doctype, no charset and no viewport -- quirks mode on a
     * desktop and an unscaled layout on a phone. Sharing the chrome
     * means sharing all of it.
     *
     * The meta refresh is emitted here too, for ordering: it has to be
     * inside <head>, and a separate call left that to each caller to
     * remember. */
    ap_rputs("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             "<meta name='viewport' "
             "content='width=device-width,initial-scale=1'>", r);
    bs_d_meta_refresh(r, span, refresh, vq);
    ap_rprintf(r, "<title>%s</title>", title);
    ap_rputs(
      "<style>"
      ":root{--surface:#fcfcfb;--ink:#1a1a19;--ink2:#5c5c58;--muted:#8a8a84;"
      "--line:#e4e4e0;--t1:" BS_D_T1 ";--t2:" BS_D_T2 ";--t3:" BS_D_T3 ";--t4:" BS_D_T4 ";"
      "--c1:" BS_D_C1 ";--c2:" BS_D_C2 ";--c3:" BS_D_C3 ";"
      "--c4:" BS_D_C4 ";--c5:" BS_D_C5 ";--c6:" BS_D_C6 ";"
      "--c7:" BS_D_C7 ";"
      "--track:#eef2f7;--good:#0ca30c;--warn:#fab219;--crit:#d03b3b;"
      /* Rail is its own surface, a shade off the content so the eye
       * reads two regions without needing a hard divider. */
      "--rail:#f4f3ef;--hov:#00000008;--act:#0000000f;"
      "--neutral:#8a8a84}"
      "@media(prefers-color-scheme:dark){:root{--surface:#1a1a19;--ink:#f2f2ef;"
      "--ink2:#b9b9b2;--muted:#8a8a84;--line:#33332f;"
      /* Separate dark selection, validated against #1a1a19 — not a flip. */
      "--t1:#3987e5;--t2:#6da7ec;--t3:#9ec5f4;--t4:#cde2fb;"
      "--c1:#3987e5;--c2:#d95926;--c3:#199e70;--c4:#c98500;"
      "--c5:#d55181;--c6:#008300;--c7:#9d86e0;--track:#26262340;"
      "--rail:#141413;--hov:#ffffff0d;--act:#ffffff17}}"
      "*{box-sizing:border-box}"
      /* App shell: a full-height rail on its own surface, flush to the
       * left edge, beside the content. The controls used to be four
       * stacked rows above the first chart -- a wall to scroll past
       * before reaching any number.
       *
       * Single column under 900px, where a fixed rail plus charts does
       * not fit and a sticky sidebar would eat the viewport. */
      ".shell{display:grid;grid-template-columns:248px minmax(0,1fr);"
      /* 100vh MINUS the body padding, or the document is always taller
       * than the viewport by exactly that padding and the page scrolls
       * even when nothing overflows. */
      "min-height:calc(100vh - 24px);transition:grid-template-columns .2s ease}"
      /* No horizontal padding: nav rows span the full rail width so the
       * selected one can reach the border and bleed past it. Children
       * that should stay inset carry their own margin.
       *
       * overflow is visible so that bleed is not clipped, and is only
       * switched to hidden while collapsed, where the rail's content
       * would otherwise spill out of a zero-width column. */
      /* The rail's own background is the CONTENT surface, and each
       * section carries the rail tone. Inverted from the obvious way
       * round on purpose: the gaps between sections then read as the
       * page showing through, which is what separates them, and the
       * selected tab -- painted in the content surface -- reads as a
       * hole cut through its section straight into the page. */
      "aside{background:var(--surface);border-right:1px solid var(--line);"
      "padding:0 0 24px;min-height:calc(100vh - 24px);position:sticky;top:0;"
      "overflow:visible;display:flex;flex-direction:column;gap:0}"
      "main{padding:6px 26px 18px;max-width:1000px;min-width:0}"
      /* Rail header: product name and the collapse control on one line,
       * the way a sidebar you can put away usually reads. */
      ".railhead{display:flex;align-items:center;justify-content:space-"
      "between;gap:8px;margin:0 10px 2px}"
      "aside h1{font-size:14px;margin:0;font-weight:600}"
      "aside .sub{font-size:11px;margin:0 14px 12px;color:var(--muted)}"
      /* Nav rows: full-width rounded targets with a hover fill, rather
       * than outlined pills. Pills were fine as a horizontal strip and
       * look like scattered buttons stacked in a column. */
      "aside nav{display:flex;flex-direction:column;gap:1px;margin:0 0 14px}"
      /* Page nav and filters are different kinds of control -- one moves
       * you, the others reshape what you are looking at -- so they get a
       * rule between them rather than running together as one list. */
      "aside nav.pages{margin:0}"
      "aside nav a{display:block;padding:7px 14px;border:0;border-radius:0;"
      "font-size:13px;color:var(--ink2);text-decoration:none;"
      "background:none;text-align:left}"
      "aside nav a:hover{background:var(--hov);color:var(--ink)}"
      /* Selected page: painted in the CONTENT background and run one
       * pixel past the rail's right border, so it reads as the tab whose
       * page you are on rather than a highlighted list row. The border
       * is drawn on the aside, so covering it takes the extra pixel --
       * a background match alone still leaves a hairline cutting across
       * the selected row and breaks the join. */
      "aside nav.pages a.on{background:var(--surface);color:var(--ink);"
      "font-weight:600;margin-right:-1px;position:relative;z-index:1;"
      /* Inset, not a real border: a 3px border-left would push the
       * label 3px right on selection and make the list twitch as you
       * move between pages. */
      "box-shadow:inset 3px 0 0 var(--t2)}"
      /* Filter rows stay list-like; only page nav is a tab. */
      "aside nav:not(.pages) a.on{background:var(--act);color:var(--ink);"
      "font-weight:600}"
      "aside .flabel{font-size:10px;text-transform:uppercase;"
      "letter-spacing:.07em;color:var(--muted);margin:0 16px 7px;"
      "font-weight:600}"
      /* Each filter is its own panel, sitting on the content surface so
       * the rail tone shows through between them. Three unseparated
       * rows read as one long list of unrelated buttons; boxed, each
       * label clearly owns the control beneath it. */
      /* Every section is the same full width. They are bands across the
       * rail separated by horizontal gutters of page colour, not cards
       * floating in it -- and the navigation section has to be full
       * width regardless, since the selected tab must reach the right
       * border to join the content. Uniform width keeps the rail from
       * looking like two different systems stacked. */
      "aside .fgroup{background:var(--rail);border-radius:0;"
      "margin:0 0 9px;padding:10px 0 9px}"
      "aside .navsec{padding:14px 0 10px}"
      "aside .fgroup nav{margin:0}"
      "aside .fgroup nav a{border-radius:6px;margin:0 8px;padding:5px 12px}"
      /* Disclosure picker. The summary is the current selection and the
       * panel is a plain link list, so no submit button is needed. */
      ".vhpick{margin:0 12px}"
      ".vhpick summary{cursor:pointer;list-style:none;padding:6px 10px;"
      "border:1px solid var(--line);border-radius:7px;font-size:12px;"
      "background:var(--surface);color:var(--ink);display:flex;"
      "align-items:center;justify-content:space-between;gap:6px;"
      "overflow:hidden;white-space:nowrap;text-overflow:ellipsis}"
      ".vhpick summary::-webkit-details-marker{display:none}"
      ".vhpick summary:hover{border-color:var(--t2)}"
      ".vhpick .cv{color:var(--muted);flex:none}"
      /* Capped and scrollable: 32 vhosts would otherwise push the rest
       * of the rail off the bottom of the screen when opened. */
      ".vhpick .vhlist{max-height:210px;overflow-y:auto;margin:5px 0 0;"
      "border:1px solid var(--line);border-radius:7px;"
      "background:var(--surface)}"
      ".vhpick .vhlist a{display:block;padding:5px 10px;font-size:12px;"
      "color:var(--ink2);text-decoration:none;white-space:nowrap;"
      "overflow:hidden;text-overflow:ellipsis}"
      ".vhpick .vhlist a:hover{background:var(--hov);color:var(--ink)}"
      ".vhpick .vhlist a.on{font-weight:600;color:var(--ink);"
      "background:var(--act)}"
      /* Off / 10s / 30s / 60s are short enough to sit on one line, and
       * a row of four reads as a single choice rather than four
       * unrelated rows. */
      "aside nav.rf{flex-direction:row;flex-wrap:wrap;gap:4px;"
      "margin:0 12px}"
      "aside nav.rf a{padding:4px 9px;border-radius:6px;margin:0;"
      "font-size:12px}"
      /* Directly under the refresh section, outside its box. The
       * section's own bottom margin supplies the gap above. */
      "aside>.ts{margin:0 16px;font-size:11px;color:var(--muted)}"
      /* Collapse, CSS only: a checkbox and sibling selectors, so no
       * JavaScript and no page load. The rail's column animates to zero
       * and its content is clipped by overflow:hidden.
       *
       * Two toggles for one checkbox: one in the rail header, one at the
       * top of the content. Exactly one is ever visible, so the control
       * is always where you would reach for it and never both places at
       * once. A control that hides itself is a control you cannot get
       * back.
       *
       * KNOWN LIMIT: in-page state, so the auto-refresh resets it. Set
       * Auto-refresh to Off to make it stick. A URL parameter would
       * survive the refresh but could not animate, since each toggle
       * would become a page load. */
      "#rail{position:absolute;opacity:0;width:0;height:0}"
      "#rail:checked~.shell{grid-template-columns:0 minmax(0,1fr)}"
      "#rail:checked~.shell aside{border-right:0;overflow:hidden}"
      /* Sized to be seen. At 28px with muted ink the chevron was
       * legible only if you already knew it was there. */
      ".icontog{display:inline-flex;align-items:center;justify-content:"
      "center;width:34px;height:34px;flex:none;cursor:pointer;"
      "border-radius:8px;color:var(--ink2);font-size:22px;line-height:1;"
      "font-weight:600;user-select:none;border:1px solid transparent}"
      ".icontog:hover{background:var(--hov);color:var(--ink);"
      "border-color:var(--line)}"
      "#rail:focus-visible~.shell .icontog{outline:2px solid var(--t2);"
      "outline-offset:1px}"
      /* The content-side toggle only exists while the rail is away. */
      "main>.icontog{display:none;margin:0 0 14px}"
      "#rail:checked~.shell main>.icontog{display:inline-flex}"
      "#rail:checked~.shell aside .icontog{display:none}"
      "@media(max-width:900px){.shell,#rail:checked~.shell"
      "{grid-template-columns:1fr}"
      "aside{position:static;height:auto;border-right:0;"
      "border-bottom:1px solid var(--line)}"
      "#rail:checked~.shell aside{display:none}"
      "#rail:checked~.shell main>.icontog{display:inline-flex}}"
      "@media(max-width:900px){.shell{grid-template-columns:1fr;gap:8px}"
      "aside{position:static}}"
      "body{margin:0;padding:10px 24px 14px;background:var(--surface);color:var(--ink);"
      "font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
      "main{min-width:0}"
      "h1{font-size:19px;margin:0 0 2px;font-weight:600}"
      "h2{font-size:13px;font-weight:600;color:var(--ink2);margin:0 0 10px;"
      "text-transform:uppercase;letter-spacing:.04em}"
      ".sub{color:var(--muted);font-size:13px;margin:0 0 20px}"
      "nav{display:flex;gap:6px;margin:0 0 18px;flex-wrap:wrap}"
      /* Inside the rail every control stacks and fills the width, so
       * the eye runs down one column instead of wrapping through
       * three. Outside it (nothing does today) the flex row above
       * still applies. */
      "aside nav{flex-direction:column;gap:2px;margin:0 0 20px}"
      "aside nav a{text-align:left;border-color:transparent}"
      "aside nav a:hover{border-color:var(--line)}"
      "aside .flabel{font-size:11px;text-transform:uppercase;"
      "letter-spacing:.06em;color:var(--muted);margin:0 0 6px;"
      "font-weight:600}"
      "margin:0 0 20px}"
      "aside nav.rf{flex-direction:column}"
      "aside nav.rf .ts{margin:6px 0 0;font-size:11px}"
      "nav a{padding:5px 12px;border:1px solid var(--line);border-radius:999px;"
      "text-decoration:none;color:var(--ink2);font-size:13px}"
      "nav a.on{background:var(--t3);border-color:var(--t3);color:#fff}"
      "nav.rf{align-items:center;margin-top:-16px;margin-bottom:26px}"
      "nav.rf span{font-size:12px;color:var(--muted)}"
      "nav.rf a{padding:3px 9px;font-size:12px}"
      "nav.rf .ts{margin-left:auto;font-variant-numeric:tabular-nums}"
      "section{margin:0 0 28px}"
      ".shell main>section:last-of-type{margin-bottom:0}"
      ".kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}"
      /* The load box holds a number and a sparkline side by side, so
       * it needs roughly twice the width of a plain stat tile. */
      ".kpi-load{grid-column:span 2;min-width:390px}"
      ".loadrow{display:flex;align-items:center;gap:14px}"
      ".loadrow .v{flex:none}"
      /* Taller than a sparkline: tick labels need the room. Still
       * inside the KPI box, just a chart rather than a squiggle. */
      ".spark{flex:1;min-width:0;height:96px;display:block}"
      /* Fixed 2x2 for the four load monitors. Explicit columns rather
       * than auto-fit so the charts line up column-for-column and share
       * a visual x-axis; auto-fit sizes by content and would leave the
       * time axes offset from each other, which defeats the reason for
       * showing them together. */
      ".loadpair{grid-template-columns:repeat(2,minmax(0,1fr))}"
      /* Compact: four boxes is a lot of vertical space at the full
       * chart height, and these are a glanceable header for the page,
       * not the subject of it. */
      /* span 1, explicitly. .kpi-load carries grid-column:span 2 from
       * the wide auto-fit KPI row it was designed for; inherited into
       * a 2-column grid that makes every box full-width and stacks
       * the four monitors into four rows instead of a 2x2. */
      ".loadpair .kpi-load{grid-column:span 1;min-width:0;padding:10px 12px}"
      ".loadpair .spark{height:68px}"
      ".loadpair .v{font-size:22px}"
      ".loadpair .loadrow{gap:10px}"
      /* Click-to-enlarge, CSS only -- this dashboard ships no
       * JavaScript. The checkbox lives immediately before its box so
       * the :checked + .kpi sibling selector can reach it; the label
       * sits over the chart and toggles it. */
      ".zoomcb{position:absolute;opacity:0;pointer-events:none}"
      ".loadrow{position:relative}"
      ".zoomlab{position:absolute;inset:0;cursor:zoom-in}"
      ".zoomcb:checked + .kpi .zoomlab{cursor:zoom-out}"
      /* Expanded: span the full grid width and give the chart real
       * height. 240px is enough for the tick labels to breathe, which
       * is the actual reason to enlarge one of these. */
      ".zoomcb:checked + .kpi{grid-column:1/-1}"
      ".zoomcb:checked + .kpi .spark{height:240px}"
      ".zoomcb:checked + .kpi .v{font-size:30px}"
      /* Keyboard: the checkbox is off-screen but still focusable, so
       * show a ring on the box when it has focus. */
      ".zoomcb:focus-visible + .kpi{outline:2px solid var(--c1);"
      "outline-offset:2px}"
      /* Instant tooltips. title= is unusable here: browsers hold it for
       * roughly a second before showing anything, which is longer than
       * it takes to move the pointer along a stacked bar. This appears
       * on hover with no delay.
       *
       * white-space:pre so the newlines in data-tip render as lines --
       * the whole point is a per-code list, not one long run-on. */
      /* Generic hoverable term. The bar/legend tooltips above use
       * white-space:pre because their content is short pre-formatted
       * lines; this one carries sentences, so it wraps and takes a
       * max-width. The dotted underline is the affordance -- an
       * explanation nobody knows to hover for is not an explanation. */
      ".tip{border-bottom:1px dotted var(--muted);cursor:help}"
      ".tip[data-tip]{position:relative}"
      ".tip[data-tip]:hover::after{content:attr(data-tip);"
      "white-space:pre-wrap;width:max-content;max-width:300px;"
      "position:absolute;left:0;bottom:calc(100% + 6px);"
      "background:var(--ink);color:var(--surface);font-size:11px;"
      "font-weight:400;line-height:1.5;padding:7px 10px;border-radius:6px;"
      "box-shadow:0 2px 10px rgba(0,0,0,.28);z-index:60;"
      "pointer-events:none;text-align:left}"
      "th .tip{border-bottom-color:var(--line)}"
      ".seg[data-tip],.legend li[data-tip]{position:relative}"
      ".seg[data-tip]:hover::after,.legend li[data-tip]:hover::after{"
      "content:attr(data-tip);white-space:pre;position:absolute;"
      "left:50%;bottom:calc(100% + 6px);transform:translateX(-50%);"
      "background:var(--ink);color:var(--surface);font-size:11px;"
      "font-weight:500;line-height:1.45;padding:6px 9px;border-radius:6px;"
      "box-shadow:0 2px 10px rgba(0,0,0,.28);z-index:50;"
      "pointer-events:none;text-align:left}"
      ".seg:first-child{border-top-left-radius:4px;"
      "border-bottom-left-radius:4px}"
      ".seg:last-child{border-top-right-radius:4px;"
      "border-bottom-right-radius:4px}"
      /* Composite verdict strip above the pair. */
      /* Stacked share bar. overflow:hidden on the rounded track gives
       * the 4px outer corners the old SVG clip-path provided, while
       * internal joins stay square. */
      /* overflow stays VISIBLE on both the track and the segments so a
       * segment's tooltip can escape the bar. The rounded ends that
       * overflow:hidden used to provide now come from border-radius on
       * the first and last segment, and the only thing that genuinely
       * needed clipping -- the in-bar percentage label -- clips
       * itself. */
      ".stack{display:flex;width:100%;height:34px;border-radius:4px;"
      "overflow:visible;background:var(--track)}"
      ".seg{position:relative;display:flex;align-items:center;"
      "justify-content:center;min-width:0;overflow:visible;"
      "box-shadow:inset -2px 0 0 var(--surface)}"
      ".seg:last-child{box-shadow:none}"
      /* White on the saturated series fills, with a soft dark halo so
       * it stays legible on the lighter ones (amber especially) in
       * both themes without hard-coding a per-series text colour. */
      ".seg span{font-size:11px;font-weight:600;color:#fff;"
      "text-shadow:0 0 3px rgba(0,0,0,.55);white-space:nowrap;"
      "padding:0 4px;max-width:100%;overflow:hidden}"
      /* State pill, top-right of each monitor box. Replaces the
       * composite strip that used to sit above the grid: the merged
       * verdict is the worst of these four, which reads at a glance
       * without spending a row on it. Colour is doubled by the word,
       * so the state never rides on hue alone. */
      ".kpi-load{position:relative}"
      /* The 5/15-minute pair rides alongside the 1-minute headline at
       * a smaller size: present for context, never competing with the
       * number the chart and the pill are about. */
      ".la2{font-size:13px;font-weight:500;color:var(--muted);"
      "margin-left:7px;letter-spacing:.01em;white-space:nowrap;"
      "font-variant-numeric:tabular-nums}"
      ".capline{margin:0;font-size:13px;color:var(--ink2)}"
      ".capline span{color:var(--muted)}"
      ".pill{position:absolute;top:10px;right:12px;font-size:11px;"
      "font-weight:700;letter-spacing:.03em;text-transform:uppercase;"
      "border-radius:999px;padding:3px 9px;white-space:nowrap}"
      "@media(max-width:600px){.kpi-load{grid-column:span 1;"
      "min-width:0}.spark{display:none}"
      ".loadpair{grid-template-columns:1fr}}"
      /* Audience tabs. Plain links, because the selection lives in the
       * query string -- see the `tab` parse -- so it survives the
       * auto-refresh. Ordinary anchors are keyboard-operable and
       * linkable for free. */
      /* Page nav: same pill vocabulary as the window/vhost navs so it
       * reads as navigation, with extra space beneath to separate
       * "which page" from "which view of it". */
      "nav.pages{margin-bottom:14px}"
      "nav.pages a{font-weight:600}"
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
      ".muted{color:var(--muted)}"
      "text-transform:uppercase;letter-spacing:.04em}"
      "border:1px solid var(--line);border-radius:999px;"
      "background:var(--surface);color:var(--ink);max-width:22rem}"
      "border:1px solid var(--line);border-radius:999px;cursor:pointer;"
      "background:var(--surface);color:var(--ink2)}"
      "footer{color:var(--muted);font-size:12px;margin-top:34px;border-top:1px solid var(--line);padding-top:12px}"
      "</style></head><body>"
      /* Checkbox before the shell so the sibling selectors reach it. */
      "<input type='checkbox' id='rail'>"
      "<div class='shell'>", r);
}

/* Parse the view controls every dashboard page shares: window, refresh
 * interval, vhost. One parser rather than a copy per page -- the first
 * cut of the extra pages duplicated the w= parsing three times and
 * silently supported a different subset of values on each.
 *
 * Out params are left untouched when the corresponding arg is absent,
 * so callers set their defaults before calling. */
static void bs_d_view_params(request_rec *r, int *span, int *refresh,
                             int *vsel)
{
    if (!r->args) return;
    const char *v;
    if ((v = bs_d_qparam(r->pool, r->args, "w")) != NULL) {
        if      (!strcmp(v, "15"))   *span = 15;
        else if (!strcmp(v, "60"))   *span = 60;
        else if (!strcmp(v, "1440")) *span = 1440;
        else if (!strcmp(v, "all"))  *span = 0;
    }
    if ((v = bs_d_qparam(r->pool, r->args, "r")) != NULL) {
        if      (!strcmp(v, "0"))  *refresh = 0;
        else if (!strcmp(v, "10")) *refresh = 10;
        else if (!strcmp(v, "30")) *refresh = 30;
        else if (!strcmp(v, "60")) *refresh = 60;
    }
    if (vsel && (v = bs_d_qparam(r->pool, r->args, "vh")) != NULL) {
        const bs_vhost_dir *vd = bs_shm.vhost_dir;
        if (strcmp(v, "all") != 0 && vd) {
            char *end = NULL;
            long n = strtol(v, &end, 10);
            if (end && *end == '\0' && n >= 0 && (apr_uint32_t)n < vd->count) {
                *vsel = (int)n;
            }
        }
    }
}

/* Window / vhost / refresh selectors, shared by every dashboard page.
 *
 * Links are query-only ("?w=..."), so they resolve against whichever
 * page is rendering and each page keeps its own path. Every link
 * carries all three parameters: dropping one would silently reset it as
 * a side effect of changing another, which is the bug the tab= plumbing
 * used to have.
 *
 * Emitted on every page because "what am I looking at" and "over what
 * period" are the same question. A page that shows numbers without
 * saying which window they cover is a page you have to guess at. */
static void bs_d_view_controls(request_rec *r, int span, int refresh,
                               int vsel, const char *vq)
{
    ap_rputs("<div class='fgroup'><p class='flabel'>Time range</p><nav>", r);
    const struct { const char *q, *t; int s; } wins[] = {
        {"15", "15 min", 15}, {"60", "1 hour", 60},
        {"1440", "24 hours", 1440}, {"all", "All time", 0} };
    for (int i = 0; i < 4; i++) {
        ap_rprintf(r, "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%s'>%s</a>",
                   span == wins[i].s ? "on" : "", wins[i].q, refresh,
                   vq, wins[i].t);
    }
    ap_rputs("</nav></div>", r);

    /* Vhost picker: a <details> disclosure of plain links.
     *
     * It was a <select> in a GET form, which needed an Apply button --
     * without JavaScript a select navigates nowhere on its own, so
     * something had to submit it. A disclosure has no such problem:
     * every entry is an ordinary link that carries w and r along, so
     * choosing one IS the navigation and the extra button disappears.
     * Still no JavaScript.
     *
     * Capped height with its own scroll: this hub has 32 vhosts and a
     * list that long would otherwise push the rest of the rail off the
     * bottom of the screen when opened.
     *
     * Only drawn when there is a choice to make. */
    const bs_vhost_dir *vdir = bs_shm.vhost_dir;
    if (vdir && vdir->count > 1) {
        const char *wq = span == 0 ? "all"
                       : (span == 15 ? "15"
                       : (span == 1440 ? "1440" : "60"));
        const char *cur = (vsel < 0 || !vdir->name[vsel][0])
                        ? "All vhosts"
                        : ap_escape_html(r->pool, vdir->name[vsel]);
        ap_rputs("<div class='fgroup'><p class='flabel'>Vhost</p>"
                 "<details class='vhpick'><summary>", r);
        ap_rprintf(r, "%s<span class='cv'>&#9662;</span></summary>", cur);
        ap_rputs("<div class='vhlist'>", r);
        ap_rprintf(r, "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=all'>"
                      "All vhosts</a>", vsel < 0 ? "on" : "", wq, refresh);
        for (apr_uint32_t i = 0; i < vdir->count; i++) {
            if (!vdir->name[i][0]) continue;
            ap_rprintf(r, "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%u'>"
                          "%s</a>", vsel == (int)i ? "on" : "", wq, refresh,
                       i, ap_escape_html(r->pool, vdir->name[i]));
        }
        ap_rputs("</div></details></div>", r);
    }

    /* Refresh control plus a rendered-at stamp, so a stale tab is
     * obvious at a glance rather than quietly wrong. Off is offered
     * because WCAG 2.2.1 wants auto-updating content adjustable. */
    {
        char ts[32];
        apr_time_exp_t tm;
        char wq[8];
        apr_snprintf(wq, sizeof(wq), "%s",
                     span == 0 ? "all" : (span == 15 ? "15"
                                : (span == 1440 ? "1440" : "60")));
        apr_time_exp_lt(&tm, apr_time_now());
        apr_snprintf(ts, sizeof(ts), "%02d:%02d:%02d",
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        ap_rputs("<div class='fgroup'><p class='flabel'>Auto-refresh</p>"
                 "<nav class='rf'>", r);
        static const int opts[4] = { 0, 10, 30, 60 };
        for (int i = 0; i < 4; i++) {
            char lbl[8];
            if (opts[i] == 0) apr_snprintf(lbl, sizeof(lbl), "Off");
            else              apr_snprintf(lbl, sizeof(lbl), "%ds", opts[i]);
            ap_rprintf(r, "<a class='%s' href='?w=%s&amp;r=%d&amp;vh=%s'>"
                          "%s</a>", refresh == opts[i] ? "on" : "", wq,
                       opts[i], vq, lbl);
        }
        /* Stamp lives outside the group, as the rail's last child, so
         * margin-top:auto parks it at the bottom of the sidebar. It is
         * provenance rather than a control -- when this view was drawn,
         * which is what makes a forgotten tab obviously stale -- so it
         * belongs out of the way at the foot of the page, not wedged
         * between two sets of buttons. */
        /* Stamp sits OUTSIDE the refresh box, just below it. It labels
         * the page, not the control -- when this view was drawn -- so
         * enclosing it in the auto-refresh panel implied it was one of
         * that panel's settings. */
        ap_rprintf(r, "</nav></div><p class='ts'>rendered %s</p>", ts);
    }
}

/* Dashboard page navigation.
 *
 * Absolute hrefs built from BotShieldEndpointPrefix, not relative ones.
 * The pages sit at two depths (/dashboard and /dashboard/<page>), so
 * relative links would need different spellings per page -- and the
 * first attempt at that shipped an href='.' that resolved to the
 * prefix root instead of the dashboard. Absolute is one spelling that
 * is correct from anywhere.
 *
 * `active` is matched against the page slug; "" means the overview. */
static void bs_d_nav(request_rec *r, const char *active)
{
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    const char *px = (dcfg && dcfg->endpoint_prefix)
                   ? dcfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    static const char *slug[]  = { "", "responses", "app-bots",
                                   "app-users", "bots", "internals" };
    static const char *label[] = { "Overview", "BotShield responses",
                                   "App &rarr; bots", "App &rarr; users",
                                   "Bots", "Internals" };
    ap_rputs("<nav class='pages'>", r);
    for (int i = 0; i < 6; i++) {
        int on = strcmp(active, slug[i]) == 0;
        if (!*slug[i]) {
            ap_rprintf(r, "<a class='%s' href='%s/dashboard'>%s</a>",
                       on ? "on" : "", px, label[i]);
        } else {
            ap_rprintf(r, "<a class='%s' href='%s/dashboard/%s'>%s</a>",
                       on ? "on" : "", px, slug[i], label[i]);
        }
    }
    /* Closes the navigation section opened alongside <aside>. */
    ap_rputs("</nav></div>", r);
}

/* Head + nav + heading, shared by every dashboard page so they cannot
 * drift into looking like separate tools. */
/* Open the rail, emit brand + page nav, and leave it open for the
 * caller's filter controls. bs_d_page_body then closes the rail and
 * opens <main>.
 *
 * Split in two rather than taking the filters as a callback: the
 * controls need span/refresh/vsel that only the handler has, and
 * threading six parameters through here to hand them straight back
 * would be worse than two calls that read in order. */
static void bs_d_page_start(request_rec *r, const char *title,
                            const char *sub, const char *active,
                            int span, int refresh, const char *vq)
{
    bs_d_page_open(r, title, span, refresh, vq);
    ap_rputs("<aside><div class='fgroup navsec'>"
             "<div class='railhead'><h1>mod_botshield</h1>"
             "<label class='icontog' for='rail' title='Hide sidebar' "
             "aria-label='Hide sidebar'>&laquo;</label></div>", r);
    ap_rprintf(r, "<p class='sub'>%s</p>", sub ? sub : "");
    bs_d_nav(r, active);
}

/* Close the rail, open the content column, and put the collapse toggle
 * at the top of it -- inside <main> so it stays reachable when the rail
 * is hidden. */
static void bs_d_page_body(request_rec *r)
{
    ap_rputs("</aside><main>"
             "<label class='icontog' for='rail' title='Show sidebar' "
             "aria-label='Show sidebar'>&raquo;</label>", r);
}

/* ======================================================================
 * /dashboard/bots — per-bot detail
 *
 * Rendered entirely from state that already exists: the rate limiter's
 * per-slug holders (budget, window, origin, mode, live counter) and the
 * bot directory (category, botgroup).
 *
 * It used to show only the limiter's fixed-window counter, on the
 * argument that a second cumulative table was storage nobody asked
 * for. That was wrong in a way worth recording: at the default
 * 1-second window the snapshot is empty essentially always -- 723 bots
 * allocated, one row rendered -- so the page could not answer "which
 * crawlers are hitting this site", which is the only question anyone
 * opens it to ask. Cheap to store, and the absence was not neutral.
 *
 * So there are two numbers per row and they mean different things:
 *   Requests     cumulative since restart. Who is actually here.
 *   Window use   the limiter's live counter. Pressure right now, and
 *                0 for any bot idle longer than its own window.
 * ====================================================================== */

typedef struct {
    const char *slug;
    const char *category;
    const char *botgroup;
    apr_uint32_t used;
    apr_uint64_t seen;
    apr_uint32_t budget;
    apr_uint32_t window_sec;
    const char *origin;
    const char *ua;          /* last agent seen on this slot, or NULL */
    int observe;
    /* Not one bot: a catch-all holder whose contents are defined by
     * what missed everything else. Rendered plainly rather than made
     * to look like a directory entry. */
    int aggregate;
    /* How many slugs share this row's counter slot. >1 means the
     * numbers are the group's, not this bot's -- a multi-slug
     * BotShieldBotRateLimit directive resolves to one shared holder.
     * Left unflagged, identical totals repeated down the table read as
     * a rendering bug. */
    int shared;
} bs_d_botrow;

/* ap_escape_html covers & < > and the double quote, but leaves the
 * apostrophe -- and every attribute this dashboard emits is
 * single-quoted, so a User-Agent carrying one would close the
 * attribute and start writing markup. Every other data-tip on these
 * pages is a module-generated label; this is the first one built from
 * request input, so it gets its own pass. */
static const char *bs_d_attr(apr_pool_t *pool, const char *s)
{
    const char *esc = ap_escape_html(pool, s ? s : "");
    if (!strchr(esc, '\'')) return esc;
    apr_size_t n = 0;
    for (const char *p = esc; *p; p++) n += (*p == '\'') ? 5 : 1;
    char *out = apr_palloc(pool, n + 1), *w = out;
    for (const char *p = esc; *p; p++) {
        if (*p == '\'') { memcpy(w, "&#39;", 5); w += 5; }
        else             { *w++ = *p; }
    }
    *w = '\0';
    return out;
}

/* Cumulative first: the table's job is "who is here", and the live
 * window is the tiebreak among bots that are here right now. */
static int bs_d_botrow_cmp(const void *a, const void *b)
{
    const bs_d_botrow *x = a, *y = b;
    if (x->seen != y->seen) return (x->seen < y->seen) ? 1 : -1;
    /* Groups lead their tier, which is what keeps an idle one visible:
     * at zero traffic it would otherwise sort in among ~700 idle bots
     * and fall off the end of the table. An absent group row is
     * ambiguous in a way a zero is not -- it could mean the bucket is
     * empty or that no wildcard rule allocated the holder at all. */
    if (x->aggregate != y->aggregate) return y->aggregate - x->aggregate;
    if (x->used != y->used) return (x->used < y->used) ? 1 : -1;
    return strcmp(x->slug ? x->slug : "", y->slug ? y->slug : "");
}

int bs_dashboard_bots_handler(request_rec *r)
{
    apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "obs");
    bs_log_observability_request(r);

    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Robots-Tag", "noindex, nofollow");

    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    /* The bots page is a live snapshot, so the window selector does not
     * change its table -- the rate limiter keeps one current-window
     * counter and nothing historical. The controls are still drawn, and
     * the refresh is what makes the page useful: leave it open and the
     * table repopulates as crawlers arrive. */
    int span = 60, refresh = 30, vsel = -1;
    bs_d_view_params(r, &span, &refresh, &vsel);
    const char *vq = (vsel < 0) ? "all"
                                : apr_psprintf(r->pool, "%d", vsel);
    /* The per-bot table is a live snapshot, but the counters beside it
     * are windowed like every other page. */
    bs_metrics_window w;
    bs_metrics_read_window(span, vsel, &w);
    bs_d_page_open(r, "mod_botshield bots", span, refresh, vq);
    ap_rputs("<aside><div class='fgroup navsec'>"
             "<div class='railhead'><h1>mod_botshield</h1>"
             "<label class='icontog' for='rail' title='Hide sidebar' "
             "aria-label='Hide sidebar'>&laquo;</label></div>", r);

    /* Subtitle only -- the rail header above already carries the h1.
     * This line kept its own when the header was introduced, so the
     * bots page shipped the product name twice. */
    ap_rprintf(r, "<p class='sub'>%s &middot; per-bot state</p>",
               bs_d_window_label(span));
    bs_d_nav(r, "bots");
    bs_d_view_controls(r, span, refresh, vsel, vq);
    bs_d_page_body(r);

    /* Collect rows from the rate limiter's slug table. */
    apr_array_header_t *rows =
        apr_array_make(r->pool, 64, sizeof(bs_d_botrow));
    bs_rate_counter *counters = (bs_rate_counter *)bs_shm.rate_counters;
    apr_uint64_t now_sec = (apr_uint64_t)apr_time_sec(apr_time_now());

    if (scfg && scfg->bot_rate_state && scfg->bot_rate_state->by_slug) {
        apr_hash_index_t *hi;
        for (hi = apr_hash_first(r->pool, scfg->bot_rate_state->by_slug);
             hi; hi = apr_hash_next(hi)) {
            const void *k; void *v;
            apr_hash_this(hi, &k, NULL, &v);
            bs_bot_rate_slot *h = v;
            if (!h) continue;
            bs_d_botrow row;
            memset(&row, 0, sizeof(row));
            row.slug       = (const char *)k;
            row.budget     = h->budget;
            row.window_sec = h->window_sec;
            row.origin     = h->origin ? h->origin : "-";
            row.observe    = h->observe;
            /* Live window count. A slot whose window has already rolled
             * reads as 0 rather than a stale figure -- showing the old
             * count would imply current pressure that is gone. */
            if (counters && h->shm_slot >= 0) {
                bs_rate_counter *c = &counters[h->shm_slot];
                apr_uint32_t ws = __atomic_load_n(&c->window_start_sec,
                                                  __ATOMIC_RELAXED);
                apr_uint32_t n  = __atomic_load_n(&c->count,
                                                  __ATOMIC_RELAXED);
                if (h->window_sec && now_sec < (apr_uint64_t)ws + h->window_sec) {
                    row.used = n;
                }
            }
            if (bs_shm.rate_totals && h->shm_slot >= 0 &&
                (apr_size_t)h->shm_slot < bs_shm.rate_counter_count) {
                row.seen = __atomic_load_n(
                    &bs_shm.rate_totals[h->shm_slot], __ATOMIC_RELAXED);
            }
            if (bs_shm.rate_ua && h->shm_slot >= 0 &&
                (apr_size_t)h->shm_slot < bs_shm.rate_counter_count) {
                const char *ua = bs_shm.rate_ua
                               + (apr_size_t)h->shm_slot * BS_RATE_UA_MAX;
                /* Copied out of SHM before rendering: another child can
                 * overwrite it mid-page, and half of one agent followed
                 * by half of another is not worth the sharper number. */
                if (*ua) row.ua = apr_pstrndup(r->pool, ua,
                                               BS_RATE_UA_MAX - 1);
            }
            row.shared = h->shm_slot;   /* resolved to a count below */
            bs_bot_dir_lookup_slug(row.slug, &row.category, &row.botgroup);
            *(bs_d_botrow *)apr_array_push(rows) = row;
        }
    }

    /* The four aggregate holders live in their own fields, not in
     * by_slug, so this table has never shown them -- and on this
     * deployment they carry the single largest share of bot traffic
     * (no-ua alone was ~39k requests/day when it was split out). A
     * page titled "per-bot state" that silently omits the biggest
     * buckets is worse than one that admits they are buckets. */
    if (scfg && scfg->bot_rate_state) {
        bs_bot_rate_state *st = scfg->bot_rate_state;
        struct { const char *name; bs_bot_rate_slot *h; const char *what; }
        agg[] = {
            { "unknown-bot", st->unknown_bot_holder,
              "bot-like UA that matches no directory entry" },
            { "no-ua", st->no_ua_holder,
              "no User-Agent header at all" },
            { "fake-bot", st->fake_bot_holder,
              "UA claimed a crawler, IP failed the cross-check" },
            { "wildcard-fallback", st->wildcard_fallback_holder,
              "known slug with no counter of its own, usually one the "
              "directory gained since startup" },
        };
        for (unsigned a = 0; a < sizeof(agg) / sizeof(agg[0]); a++) {
            bs_bot_rate_slot *h = agg[a].h;
            if (!h) continue;
            bs_d_botrow row;
            memset(&row, 0, sizeof(row));
            row.slug       = agg[a].name;
            row.category   = agg[a].what;
            row.budget     = h->budget;
            row.window_sec = h->window_sec;
            row.origin     = h->origin ? h->origin : "-";
            row.observe    = h->observe;
            row.aggregate  = 1;
            if (counters && h->shm_slot >= 0) {
                bs_rate_counter *c = &counters[h->shm_slot];
                apr_uint32_t ws = __atomic_load_n(&c->window_start_sec,
                                                  __ATOMIC_RELAXED);
                apr_uint32_t n  = __atomic_load_n(&c->count,
                                                  __ATOMIC_RELAXED);
                if (h->window_sec && now_sec < (apr_uint64_t)ws + h->window_sec) {
                    row.used = n;
                }
            }
            if (bs_shm.rate_totals && h->shm_slot >= 0 &&
                (apr_size_t)h->shm_slot < bs_shm.rate_counter_count) {
                row.seen = __atomic_load_n(
                    &bs_shm.rate_totals[h->shm_slot], __ATOMIC_RELAXED);
            }
            if (bs_shm.rate_ua && h->shm_slot >= 0 &&
                (apr_size_t)h->shm_slot < bs_shm.rate_counter_count) {
                const char *ua = bs_shm.rate_ua
                               + (apr_size_t)h->shm_slot * BS_RATE_UA_MAX;
                if (*ua) row.ua = apr_pstrndup(r->pool, ua,
                                               BS_RATE_UA_MAX - 1);
            }
            row.shared = h->shm_slot;
            *(bs_d_botrow *)apr_array_push(rows) = row;
        }
    }

    if (rows->nelts == 0) {
        ap_rputs("<section><p class='empty'>No per-bot rate-limit slots "
                 "are allocated. That means either no BotShieldBotRateLimit "
                 "rule is in effect, or the module has not been enabled in "
                 "a scope on this vhost.</p></section>"
                 "</main></div></body></html>", r);
        return OK;
    }

    /* Turn each row's stashed slot index into "how many slugs land on
     * this slot". Two passes over an array this size is nothing, and it
     * avoids a second hash walk. */
    {
        apr_size_t nslots = bs_shm.rate_counter_count;
        int *per_slot = nslots ? apr_pcalloc(r->pool, nslots * sizeof(int))
                               : NULL;
        for (int i = 0; per_slot && i < rows->nelts; i++) {
            int sl = ((bs_d_botrow *)rows->elts)[i].shared;
            if (sl >= 0 && (apr_size_t)sl < nslots) per_slot[sl]++;
        }
        for (int i = 0; i < rows->nelts; i++) {
            bs_d_botrow *b = &((bs_d_botrow *)rows->elts)[i];
            int sl = b->shared;
            b->shared = (per_slot && sl >= 0 && (apr_size_t)sl < nslots)
                      ? per_slot[sl] : 1;
        }
    }

    qsort(rows->elts, rows->nelts, sizeof(bs_d_botrow), bs_d_botrow_cmp);

    /* Botgroup breakdown across every allocated slug. */
    {
        static const char *names[] = { "search", "ai-input", "ai-train",
                                       "monitor", "(ungrouped)" };
        apr_uint64_t vals[5] = { 0, 0, 0, 0, 0 };
        const char *fills[] = { "var(--c1)", "var(--c2)", "var(--c3)",
                                "var(--c4)", "var(--neutral)" };
        for (int i = 0; i < rows->nelts; i++) {
            bs_d_botrow *b = &((bs_d_botrow *)rows->elts)[i];
            int slot = 4;
            if (b->botgroup) {
                for (int g = 0; g < 4; g++) {
                    if (strcmp(b->botgroup, names[g]) == 0) { slot = g; break; }
                }
            }
            vals[slot]++;
        }
        apr_uint64_t tot = 0;
        for (int i = 0; i < 5; i++) tot += vals[i];
        ap_rputs("<section><h2>Bot types</h2>", r);
        bs_d_stacked(r, "bg", "Known bots by group", names, vals,
                     fills, 5, tot);
        ap_rputs("<p class='note'>Counts BOTS, not requests: one row per "
                 "slug the limiter tracks. Groups come from the IETF "
                 "aipref content-signal vocabulary, plus monitor as a "
                 "mod_botshield extension. Ungrouped means the directory "
                 "category does not map to a group -- libraries and tools "
                 "mostly land there.</p></section>", r);
    }

    /* Global bot-facing counters, moved off the main dashboard. */
    {
        /* Windowed, not cumulative. These KPIs read all-time totals
         * while the page carried a time-range selector, so choosing
         * "last hour" changed the label and not the numbers -- the
         * worst kind of wrong, because it looks like it worked.
         *
         * Three have faithful windowed equivalents. The fourth,
         * observed-but-not-enforced rate limits, exists only as a
         * cumulative counter, so it says "since restart" on its face
         * rather than pretending to honour the selector. */
        apr_uint64_t rl_win = w.outcome[BS_M_OUTCOME_RATE_LIMITED];
        apr_uint64_t bots_win = w.req_class[BS_M_CLASS_VERIFIED_BOT]
                              + w.req_class[BS_M_CLASS_KNOWN_BOT];
        apr_uint64_t fake_win = w.req_class[BS_M_CLASS_FAKE_BOT];
        apr_uint64_t obs_all = bs_shm.metrics
            ? bs_mload(&bs_shm.metrics->rate_limit_observed_total) : 0;

        ap_rputs("<section><h2>Rate limiting &amp; blocks</h2>"
                 "<div class='kpis'>", r);
        ap_rprintf(r, "<div class='kpi'><div class='k'>429s issued</div>"
                      "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                      "<div class='n'>enforced</div></div>", rl_win);
        ap_rprintf(r, "<div class='kpi'><div class='k'>Bots seen</div>"
                      "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                      "<div class='n'>verified + known</div></div>",
                   bots_win);
        ap_rprintf(r, "<div class='kpi'><div class='k'>Fake bots</div>"
                      "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                      "<div class='n'>UA claimed a crawler, IP failed"
                      "</div></div>", fake_win);
        ap_rprintf(r, "<div class='kpi'><div class='k'>Would-429</div>"
                      "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                      "<div class='n'>observe mode, since restart</div>"
                      "</div>", obs_all);
        ap_rputs("</div></section>", r);
    }

    /* The table. Top 50 by current-window usage. */
    {
        /* Only bots with live usage, per the ">0 traffic" ask. The
         * fixed-window counter is the only per-bot number that exists,
         * and at the default 1-second window it has almost always
         * rolled by the time anyone loads this page -- so an unfiltered
         * table is 700 rows of zeros with the interesting ones buried.
         * Filtering makes the emptiness honest instead of hiding it in
         * noise, and the empty case says why. */
        int seen_n = 0, active = 0, nbots = 0, idle_groups = 0;
        apr_uint64_t seen_sum = 0;
        for (int i = 0; i < rows->nelts; i++) {
            bs_d_botrow *b = &((bs_d_botrow *)rows->elts)[i];
            if (!b->aggregate) nbots++;
            if (b->seen > 0) { seen_n++; seen_sum += b->seen; }
            else if (b->aggregate) idle_groups++;
            if (b->used > 0) active++;
        }
        /* The sort puts every seen row first, then the idle groups, so
         * one count covers both. */
        int listed = seen_n + idle_groups;
        int shown = listed < 100 ? listed : 100;
        ap_rprintf(r, "<section><h2>Per-bot state</h2>"
                      "<p class='note'>%d bot%s allocated a counter, %d "
                      "seen since restart (%" APR_UINT64_T_FMT " requests"
                      "), %d with traffic in the current window%s. Bots "
                      "never seen are not listed &mdash; the directory is "
                      "the full roster, this is who turned up. "
                      "&ldquo;Requests&rdquo; is cumulative and counts "
                      "refusals as well as admissions; &ldquo;window "
                      "use&rdquo; is the limiter's live counter, which "
                      "reads 0 for any bot idle longer than its own "
                      "window. Budget 0 means unlimited. Hover a bot "
                      "name for the last User-Agent seen on it &mdash; "
                      "on the rows marked (group) that sample is the "
                      "only view of what is in the bucket, since those "
                      "are catch-alls rather than one bot.</p>",
                   nbots, nbots == 1 ? "" : "s", seen_n,
                   seen_sum, active,
                   shown < listed ? ", top 100 shown" : "");
        ap_rputs("<table><thead><tr><th>Bot</th><th>Group</th>"
                 "<th>Category</th><th class='n'>Requests</th>"
                 "<th class='n'>Window use</th>"
                 "<th class='n'>Budget</th><th>Origin</th><th>Mode</th>"
                 "</tr></thead><tbody>", r);
        if (listed == 0) {
            ap_rputs("<tr><td colspan='8' class='empty'>No bot has been "
                     "seen since the last restart. If this persists, the "
                     "module is classifying nothing as a known bot on "
                     "this vhost &mdash; check that a scope has it "
                     "enabled.</td></tr>", r);
        }
        for (int i = 0; i < shown; i++) {
            bs_d_botrow *b = &((bs_d_botrow *)rows->elts)[i];
            char budget[64];
            if (b->budget == 0) {
                apr_snprintf(budget, sizeof(budget), "unlimited");
            } else {
                apr_snprintf(budget, sizeof(budget),
                             "%u / %us", b->budget, b->window_sec);
            }
            /* The agent hangs off the bot name, which is the cell a
             * reader is already pointing at to ask "who is this". A
             * slot seen only before the last restart has no sample. */
            const char *uacell = b->ua
                ? apr_psprintf(r->pool, "<span data-tip='%s'>%s</span>",
                               bs_d_attr(r->pool, b->ua),
                               ap_escape_html(r->pool, b->slug))
                : ap_escape_html(r->pool, b->slug);
            ap_rprintf(r,
                "<tr><td>%s%s</td><td>%s</td><td>%s</td>"
                "<td class='n'>%" APR_UINT64_T_FMT "%s</td>"
                "<td class='n'>%u</td><td class='n'>%s</td>"
                "<td>%s</td><td>%s</td></tr>",
                uacell,
                b->aggregate ? " <span class='muted'>(group)</span>" : "",
                b->botgroup ? ap_escape_html(r->pool, b->botgroup) : "&mdash;",
                b->category ? ap_escape_html(r->pool, b->category) : "&mdash;",
                b->seen,
                /* Marked, not hidden: the number is real, it just
                 * belongs to every slug on the shared holder. */
                b->shared > 1 ? "<span class='muted'>&#8225;</span>" : "",
                b->used, budget,
                ap_escape_html(r->pool, b->origin),
                b->observe ? "observe" : "enforce");
        }
        ap_rputs("</tbody></table>", r);
        {
            int any_shared = 0;
            for (int i = 0; i < shown; i++) {
                if (((bs_d_botrow *)rows->elts)[i].shared > 1) {
                    any_shared = 1; break;
                }
            }
            if (any_shared) {
                ap_rputs("<p class='note'>&#8225; counter is shared by "
                         "every slug on one multi-slug rule, so the "
                         "request total is the group's, not this bot's."
                         "</p>", r);
            }
        }
        ap_rputs("</section>", r);
    }

    ap_rputs("</main></div></body></html>", r);
    return OK;
}

/* ======================================================================
 * /dashboard/internals — is the module itself healthy?
 *
 * Deliberately separate from /dashboard/responses. That page answers
 * "what did BotShield do to traffic", which is a question about
 * policy; this one answers "is BotShield working", which is a question
 * about the tool. Same screen, different job, different reader.
 *
 * Everything here is read at render time. Nothing is sampled into a
 * ring, because none of it is a rate: these are levels, and a level you
 * can re-read on demand does not need a history to be useful. The load
 * charts on the overview already cover the things that do.
 * ====================================================================== */

typedef struct {
    int      have_mem, have_stat, have_uptime, have_fd, have_self;
    apr_uint64_t mem_total, mem_avail, mem_free, cached, buffers;
    apr_uint64_t swap_total, swap_free, dirty, committed;   /* kB */
    apr_uint64_t procs_running, procs_blocked;
    apr_uint64_t uptime_sec;
    apr_uint64_t fd_used, fd_max;
    apr_uint64_t self_rss_kb;
} bs_os_snap;

/* Pull one "Key: value kB" out of a /proc/meminfo-shaped buffer. */
static apr_uint64_t bs_meminfo_kb(const char *buf, const char *key)
{
    apr_size_t klen = strlen(key);
    for (const char *p = buf; p && *p; ) {
        if (strncmp(p, key, klen) == 0 && p[klen] == ':') {
            return (apr_uint64_t)apr_atoi64(p + klen + 1);
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return 0;
}

static int bs_slurp(apr_pool_t *pool, const char *path,
                    char *buf, apr_size_t cap)
{
    apr_file_t *f = NULL;
    if (apr_file_open(&f, path, APR_READ | APR_BINARY, 0, pool)
        != APR_SUCCESS) {
        return 0;
    }
    apr_size_t got = cap - 1;
    apr_status_t rv = apr_file_read(f, buf, &got);
    apr_file_close(f);
    if (rv != APR_SUCCESS && rv != APR_EOF) return 0;
    buf[got] = '\0';
    return 1;
}

/* Every field is optional. A container or a hardened kernel can hide
 * any of these, and a dashboard that renders "0" for "could not read"
 * is worse than one that says so. */
static void bs_os_read(apr_pool_t *pool, bs_os_snap *o)
{
    char buf[8192];
    memset(o, 0, sizeof(*o));

    if (bs_slurp(pool, "/proc/meminfo", buf, sizeof(buf))) {
        o->have_mem   = 1;
        o->mem_total  = bs_meminfo_kb(buf, "MemTotal");
        o->mem_avail  = bs_meminfo_kb(buf, "MemAvailable");
        o->mem_free   = bs_meminfo_kb(buf, "MemFree");
        o->cached     = bs_meminfo_kb(buf, "Cached");
        o->buffers    = bs_meminfo_kb(buf, "Buffers");
        o->swap_total = bs_meminfo_kb(buf, "SwapTotal");
        o->swap_free  = bs_meminfo_kb(buf, "SwapFree");
        o->dirty      = bs_meminfo_kb(buf, "Dirty");
        o->committed  = bs_meminfo_kb(buf, "Committed_AS");
    }
    if (bs_slurp(pool, "/proc/stat", buf, sizeof(buf))) {
        const char *p;
        o->have_stat = 1;
        if ((p = strstr(buf, "procs_running")))
            o->procs_running = (apr_uint64_t)apr_atoi64(p + 13);
        if ((p = strstr(buf, "procs_blocked")))
            o->procs_blocked = (apr_uint64_t)apr_atoi64(p + 13);
    }
    if (bs_slurp(pool, "/proc/uptime", buf, sizeof(buf))) {
        o->have_uptime = 1;
        o->uptime_sec  = (apr_uint64_t)apr_atoi64(buf);
    }
    if (bs_slurp(pool, "/proc/sys/fs/file-nr", buf, sizeof(buf))) {
        char *end = NULL;
        o->have_fd  = 1;
        o->fd_used  = (apr_uint64_t)apr_strtoi64(buf, &end, 10);
        if (end) {
            /* field 2 is the (always-0 since 2.6) free count; max is 3rd */
            (void)apr_strtoi64(end, &end, 10);
            o->fd_max = (apr_uint64_t)apr_strtoi64(end, &end, 10);
        }
    }
    /* statm field 2 is resident pages. Only this child -- a module
     * cannot see its siblings, so this is a sample of the fleet, not
     * the fleet. */
    if (bs_slurp(pool, "/proc/self/statm", buf, sizeof(buf))) {
        char *end = NULL;
        (void)apr_strtoi64(buf, &end, 10);
        apr_int64_t rss_pages = apr_strtoi64(end, &end, 10);
        long pg = sysconf(_SC_PAGESIZE);
        if (rss_pages > 0 && pg > 0) {
            o->have_self    = 1;
            o->self_rss_kb  = (apr_uint64_t)rss_pages * (apr_uint64_t)pg / 1024;
        }
    }
}

static const char *bs_d_kb(apr_pool_t *pool, apr_uint64_t kb);

/* One capacity row. `used` past `cap` is impossible for the tables and
 * merely alarming for the pools, so the bar is clamped and the number
 * is not -- an operator needs to see 102 against 32, not a full bar. */
/* `alloc` is how many slots the segment actually reserved, which for
 * every table equals cap -- except the per-vhost directory, where only
 * the vhosts running the module get a block. Reporting cap * per_slot
 * there would bill 32 blocks' worth of memory that was never carved. */
static void bs_d_cap_row(request_rec *r, const char *name,
                         apr_uint64_t used, apr_uint64_t cap,
                         apr_uint64_t alloc, apr_uint64_t per_slot,
                         const char *note)
{
    double pct = cap ? (100.0 * (double)used / (double)cap) : 0.0;
    double bar = pct > 100.0 ? 100.0 : pct;
    const char *fill = (pct >= 90.0) ? "var(--crit)"
                     : (pct >= 70.0) ? "var(--warn)" : "var(--good)";
    /* The overflow consequence rides on the table name rather than
     * occupying a column: it is the same sentence for the life of the
     * deployment, and six rows of static prose crowd out the numbers
     * that actually change. */
    ap_rprintf(r,
        "<tr><td><span class='tip' data-tip='%s'>%s</span></td>"
        "<td class='n'>%" APR_UINT64_T_FMT "</td>"
        "<td class='n'>%" APR_UINT64_T_FMT "</td>"
        "<td class='n'>%.1f%%</td>"
        "<td><div class='stack' style='height:8px'>"
        "<div class='seg' style='flex:0 0 %.2f%%;background:%s'></div>"
        "<div class='seg' style='flex:1 1 auto;background:var(--track)'></div>"
        "</div></td>"
        "<td class='n'>%s</td></tr>",
        note ? note : "", name, used, cap, pct, bar, fill,
        bs_d_kb(r->pool, alloc * per_slot / 1024));
}

static const char *bs_d_kb(apr_pool_t *pool, apr_uint64_t kb)
{
    if (kb >= 1024ULL * 1024ULL) {
        return apr_psprintf(pool, "%.1f GB", (double)kb / 1048576.0);
    }
    if (kb >= 1024ULL) {
        return apr_psprintf(pool, "%.0f MB", (double)kb / 1024.0);
    }
    return apr_psprintf(pool, "%" APR_UINT64_T_FMT " kB", kb);
}

static const char *bs_d_dur(apr_pool_t *pool, apr_uint64_t sec)
{
    if (sec >= 86400) return apr_psprintf(pool, "%" APR_UINT64_T_FMT "d %" APR_UINT64_T_FMT "h",
                                          sec / 86400, (sec % 86400) / 3600);
    if (sec >= 3600)  return apr_psprintf(pool, "%" APR_UINT64_T_FMT "h %" APR_UINT64_T_FMT "m",
                                          sec / 3600, (sec % 3600) / 60);
    if (sec >= 60)    return apr_psprintf(pool, "%" APR_UINT64_T_FMT "m", sec / 60);
    return apr_psprintf(pool, "%" APR_UINT64_T_FMT "s", sec);
}

/* --- Per-device I/O -----------------------------------------------
 * /proc/diskstats and /proc/net/dev are counters since boot, and a
 * total since boot answers a question nobody asks: an average over
 * fourteen days goes numb to whatever is happening now. So both are
 * read twice a fraction of a second apart and reported as rates.
 *
 * That costs the request one short sleep. It is paid on an operator
 * page that is already doing table scans, never on the decision path,
 * and it is the difference between a number you can act on and a
 * number you can only file.
 * ------------------------------------------------------------------ */
#define BS_IO_MAX_DEV   24
#define BS_IO_NAME_MAX  20
/* The window costs a parked worker thread, not CPU: 20 concurrent
 * renders measured 0.34s wall and no measurable CPU at all, where
 * serialized work would have taken 5s. So the only thing a short
 * window buys is a faster page, and the only thing it costs is
 * precision -- at 250ms a single 4 KB I/O reads as 16 KB/s. 500ms
 * halves that quantization and still feels immediate. */
#define BS_IO_SAMPLE_US 500000

typedef struct {
    char         name[BS_IO_NAME_MAX];
    apr_uint64_t a, b, c, d, e;   /* meaning depends on the source */
} bs_io_dev;

typedef struct {
    int        n;
    bs_io_dev  dev[BS_IO_MAX_DEV];
} bs_io_set;

static bs_io_dev *bs_io_find(bs_io_set *set, const char *name)
{
    for (int i = 0; i < set->n; i++) {
        if (strcmp(set->dev[i].name, name) == 0) return &set->dev[i];
    }
    return NULL;
}

/* diskstats: name, reads, sectors read, writes, sectors written, ms
 * doing I/O. Sectors are 512 bytes on this interface regardless of the
 * device's real sector size -- the kernel normalises them. */
static void bs_io_read_disks(apr_pool_t *pool, bs_io_set *set)
{
    char buf[16384];
    set->n = 0;
    if (!bs_slurp(pool, "/proc/diskstats", buf, sizeof(buf))) return;
    for (char *line = buf, *save = NULL;
         (line = apr_strtok(line ? line : NULL, "\n", &save)) != NULL;
         line = NULL) {
        char nm[BS_IO_NAME_MAX];
        unsigned long long rd, rdsec, wr, wrsec, ioms;
        if (sscanf(line,
                   " %*u %*u %19s %llu %*u %llu %*u %llu %*u %llu %*u %*u %llu",
                   nm, &rd, &rdsec, &wr, &wrsec, &ioms) != 6) {
            continue;
        }
        if (rd == 0 && wr == 0) continue;              /* never used */
        if (strncmp(nm, "loop", 4) == 0) continue;
        if (strncmp(nm, "ram", 3) == 0)  continue;
        if (set->n >= BS_IO_MAX_DEV) break;
        bs_io_dev *d = &set->dev[set->n++];
        apr_cpystrn(d->name, nm, sizeof(d->name));
        d->a = rd; d->b = rdsec; d->c = wr; d->d = wrsec; d->e = ioms;
    }
}

/* Drop partitions, keeping whole devices. A name is a partition when
 * stripping its trailing digits leaves a device that is also present
 * -- vda5 against vda. Done by lookup rather than by assuming a naming
 * scheme, so nvme0n1 (whose parent nvme0 is not a device) survives. */
static void bs_io_drop_partitions(bs_io_set *set)
{
    bs_io_set kept;
    kept.n = 0;
    for (int i = 0; i < set->n; i++) {
        char parent[BS_IO_NAME_MAX];
        apr_cpystrn(parent, set->dev[i].name, sizeof(parent));
        apr_size_t L = strlen(parent);
        while (L > 0 && parent[L - 1] >= '0' && parent[L - 1] <= '9') {
            parent[--L] = '\0';
        }
        if (L > 0 && L != strlen(set->dev[i].name)
            && bs_io_find(set, parent)) {
            continue;   /* it is a slice of something we already list */
        }
        if (kept.n < BS_IO_MAX_DEV) kept.dev[kept.n++] = set->dev[i];
    }
    *set = kept;
}

/* net/dev: rx bytes, rx errs+drop, tx bytes, tx errs+drop. */
static void bs_io_read_nics(apr_pool_t *pool, bs_io_set *set)
{
    char buf[16384];
    set->n = 0;
    if (!bs_slurp(pool, "/proc/net/dev", buf, sizeof(buf))) return;
    for (char *line = buf, *save = NULL;
         (line = apr_strtok(line ? line : NULL, "\n", &save)) != NULL;
         line = NULL) {
        char *colon = strchr(line, ':');
        if (!colon) continue;                 /* the two header rows */
        *colon = '\0';
        char *nm = line;
        while (*nm == ' ' || *nm == '\t') nm++;
        unsigned long long rxb, rxe, rxd, txb, txe, txd;
        if (sscanf(colon + 1,
                   " %llu %*u %llu %llu %*u %*u %*u %*u %llu %*u %llu %llu",
                   &rxb, &rxe, &rxd, &txb, &txe, &txd) != 6) {
            continue;
        }
        if (set->n >= BS_IO_MAX_DEV) break;
        bs_io_dev *d = &set->dev[set->n++];
        apr_cpystrn(d->name, nm, sizeof(d->name));
        d->a = rxb; d->b = txb; d->c = rxe + rxd; d->d = txe + txd; d->e = 0;
    }
}

static const char *bs_d_rate(apr_pool_t *pool, double bytes_per_sec)
{
    if (bytes_per_sec >= 1048576.0)
        return apr_psprintf(pool, "%.1f MB/s", bytes_per_sec / 1048576.0);
    if (bytes_per_sec >= 1024.0)
        return apr_psprintf(pool, "%.0f kB/s", bytes_per_sec / 1024.0);
    if (bytes_per_sec >= 1.0)
        return apr_psprintf(pool, "%.0f B/s", bytes_per_sec);
    return "&mdash;";
}

int bs_dashboard_internals_handler(request_rec *r)
{
    apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "obs");
    bs_log_observability_request(r);
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Robots-Tag", "noindex, nofollow");

    bs_server_cfg *scfg = ap_get_module_config(r->server->module_config,
                                               &botshield_module);
    int span = 60, refresh = 30, vsel = -1;
    bs_d_view_params(r, &span, &refresh, &vsel);
    const char *vq = (vsel < 0) ? "all" : apr_psprintf(r->pool, "%d", vsel);

    bs_d_page_open(r, "mod_botshield internals", span, refresh, vq);
    ap_rputs("<aside><div class='fgroup navsec'>"
             "<div class='railhead'><h1>mod_botshield</h1>"
             "<label class='icontog' for='rail' title='Hide sidebar' "
             "aria-label='Hide sidebar'>&laquo;</label></div>", r);
    ap_rputs("<p class='sub'>live snapshot &middot; module health</p>", r);
    bs_d_nav(r, "internals");
    bs_d_view_controls(r, span, refresh, vsel, vq);
    bs_d_page_body(r);

    bs_gauges_refresh();

    /* --- Shared memory ------------------------------------------- */
    {
        ap_rputs("<section><h2>Shared memory</h2>"
                 "<p class='note'>Carved once at startup, never grows "
                 "&middot; every table <span class='tip' data-tip='"
                 "Nothing errors when a table fills. Flagged IPs, "
                 "strikes and safeguard entries evict the oldest; the "
                 "rate-counter pool stops handing out slots and the "
                 "bots that missed one are no longer limited at all."
                 "'>degrades silently when full</span></p>", r);
        ap_rputs("<table><thead><tr><th>Table</th><th class='n'>Used</th>"
                 "<th class='n'>Capacity</th><th class='n'>Full</th>"
                 "<th>&nbsp;</th><th class='n'>Costs</th>"
                 "</tr></thead><tbody>", r);

        bs_d_cap_row(r, "Flagged IPs", bs_gauges.flagged_used,
                     (apr_uint64_t)bs_shm.flagged_capacity,
                     (apr_uint64_t)bs_shm.flagged_capacity,
                     sizeof(bs_flagged_ip_slot),
                     "evicts oldest; a flagged client escapes early");
        bs_d_cap_row(r, "Strikes", bs_gauges.strike_used,
                     (apr_uint64_t)bs_shm.strike_capacity,
                     (apr_uint64_t)bs_shm.strike_capacity,
                     sizeof(bs_strike_slot),
                     "evicts; escalation forgets repeat offenders");
        bs_d_cap_row(r, "Safeguard", bs_gauges.safeguard_used,
                     (apr_uint64_t)bs_shm.safeguard_capacity,
                     (apr_uint64_t)bs_shm.safeguard_capacity,
                     sizeof(bs_safeguard_slot),
                     "evicts; loop detection misses a looping client");
        /* Occupancy answers "how many clients are being watched".
         * The number an operator actually needs is how many TRIPPED
         * it, because an abused safeguard and an idle one look
         * identical in the gauge above. */
        {
            apr_uint64_t fired = bs_shm.metrics
                ? bs_mload(&bs_shm.metrics->safeguard_fired_total) : 0;
            ap_rprintf(r,
                "<tr><td><span class='tip' data-tip='Each firing is one "
                "redirect to the explainer, after which the counter is "
                "cleared and the client is challenged normally again. "
                "It grants no pass window, so a rising number is cost "
                "rather than bypass -- roughly one 302 in place of one "
                "interstitial.'>Safeguard fired</span></td>"
                "<td class='n'>%" APR_UINT64_T_FMT "</td>"
                "<td class='n'>&mdash;</td><td class='n'>&mdash;</td>"
                "<td>&nbsp;</td><td class='n'>&mdash;</td></tr>",
                fired);
        }
        bs_d_cap_row(r, "Nonces", 0,
                     (apr_uint64_t)bs_shm.nonce_capacity,
                     (apr_uint64_t)bs_shm.nonce_capacity,
                     sizeof(bs_nonce_slot),
                     "oldest binding drops; a challenge must be reissued");
        bs_d_cap_row(r, "Rate counters", (apr_uint64_t)bs_shm.rate_slots_used,
                     (apr_uint64_t)bs_shm.rate_counter_count,
                     (apr_uint64_t)bs_shm.rate_counter_count,
                     sizeof(bs_rate_counter) + sizeof(apr_uint64_t)
                       + BS_RATE_UA_MAX,
                     "unallocated bots are NOT rate limited");
        {
            apr_uint32_t vused = bs_shm.vhost_dir
                ? __atomic_load_n(&bs_shm.vhost_dir->count, __ATOMIC_RELAXED)
                : 0;
            /* Only vhosts running the module get a block, so the
             * allocation is vused, not the cap. */
            bs_d_cap_row(r, "Per-vhost metric blocks", vused,
                         (apr_uint64_t)BS_M_MAX_VHOSTS, vused,
                         BS_M_VHOST_NAME_MAX + sizeof(bs_metrics),
                         "further vhosts RUNNING the module share the "
                         "last slot; ones that do not are not counted "
                         "here at all");
        }
        ap_rputs("</tbody></table>", r);
        if (bs_shm.segment_total) {
            double pct = 100.0 * (double)bs_shm.segment_used
                                / (double)bs_shm.segment_total;
            ap_rprintf(r,
                "<p class='note'>Segment <strong>%s of %s</strong> "
                "(%.0f%%) &middot; <span class='tip' data-tip='Set by "
                "BotShieldShmSize. The unused part is reserved at "
                "startup, not grown into, so it is headroom for raising "
                "a capacity at the next restart rather than room the "
                "module will take on its own.'>BotShieldShmSize</span> "
                "&middot; per-vhost block <span class='tip' data-tip='"
                "A full copy of every counter plus the minute and hour "
                "rings; the 84 windowed slots are 82 KB of it. Only "
                "vhosts that actually run the module get one.'>%s each"
                "</span></p>",
                bs_d_kb(r->pool, (apr_uint64_t)bs_shm.segment_used / 1024),
                bs_d_kb(r->pool, (apr_uint64_t)bs_shm.segment_total / 1024),
                pct,
                bs_d_kb(r->pool,
                        (apr_uint64_t)(BS_M_VHOST_NAME_MAX
                                       + sizeof(bs_metrics)) / 1024));
        }
        ap_rputs("</section>", r);
    }

    /* --- Hot-swap generations ------------------------------------ */
    {
        static const char *gname[BS_GEN_COUNT] = {
            "Bot directory (AC trie)", "robots.txt",
            "Verified-bot IP ranges", "Browser templates"
        };
        /* Scope decides what a healthy Live number looks like, so it
         * has to be on the page. The directory and the templates are
         * process-global (one live generation); robots and the IP
         * ranges hang off bs_server_cfg and so have one generation per
         * configured vhost. Reading a per-vhost row against a global
         * expectation is how a fine number gets read as a leak. */
        static const char *gscope[BS_GEN_COUNT] = {
            "global", "per-vhost", "per-vhost", "global"
        };
        apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
        ap_rputs("<section><h2>Hot-swap generations</h2>"
                 "<p class='note'>The only place this module can leak. "
                 "<span class='tip' data-tip='Each subsystem builds new "
                 "state into a private pool, swaps it in, and destroys "
                 "the one retired on the previous tick, so a reader "
                 "holding a pointer across the swap never reads freed "
                 "memory. Counted directly rather than inferred from "
                 "process RSS, which belongs to every module in the "
                 "child and can attribute growth to none of them."
                 "'>Leak shape: Built climbing while Freed stays flat."
                 "</span></p>", r);
        ap_rputs("<table><thead><tr><th>Subsystem</th>"
                 "<th><span class='tip' data-tip='Global subsystems have "
                 "one publisher. Per-vhost ones have a generation per "
                 "configured vhost, so a larger Live there is the shape "
                 "of the deployment, not a fault.'>Scope</span></th>"
                 "<th class='n'>Built</th>"
                 "<th class='n'><span class='tip' data-tip='Lags Built "
                 "by one generation per publisher by design: a "
                 "generation is retired on the NEXT rebuild, not its "
                 "own. Where sources never change this rests at 0, "
                 "which is healthy.'>Freed</span></th>"
                 "<th class='n'><span class='tip' data-tip='Built minus "
                 "Freed. Uncoloured on purpose -- the healthy value "
                 "depends on publisher count and refresh rate, and a "
                 "guessed threshold would cry wolf on a normal server."
                 "'>Live</span></th>"
                 "<th>Last rebuild</th></tr></thead><tbody>", r);
        for (int i = 0; i < BS_GEN_COUNT; i++) {
            apr_uint64_t b = 0, f = 0; apr_uint32_t t = 0;
            if (bs_shm.gen) {
                b = __atomic_load_n(&bs_shm.gen->built[i], __ATOMIC_RELAXED);
                f = __atomic_load_n(&bs_shm.gen->freed[i], __ATOMIC_RELAXED);
                t = __atomic_load_n(&bs_shm.gen->last_sec[i], __ATOMIC_RELAXED);
            }
            apr_uint64_t live = (b > f) ? b - f : 0;
            /* Uncoloured on purpose. The resting value is publishers
             * x 1, and publishers depends on vhost count and on which
             * subsystems have file-backed sources at all -- neither of
             * which this row knows. A threshold invented here would
             * paint a correct number red on an ordinary server, which
             * is how an operator learns to ignore a dashboard. */
            const char *tone = "var(--ink)";
            ap_rprintf(r,
                "<tr><td>%s</td><td class='muted'>%s</td>"
                "<td class='n'>%" APR_UINT64_T_FMT "</td>"
                "<td class='n'>%" APR_UINT64_T_FMT "</td>"
                "<td class='n' style='color:%s;font-weight:600'>%"
                APR_UINT64_T_FMT "</td><td>%s</td></tr>",
                gname[i], gscope[i], b, f, tone, live,
                t ? apr_psprintf(r->pool, "%s ago",
                                 bs_d_dur(r->pool, (apr_uint64_t)(now - t)))
                  : "<span class='muted'>never (compiled-in only)</span>");
        }
        ap_rputs("</tbody></table></section>", r);
    }

    /* --- Machine ------------------------------------------------- */
    {
        bs_os_snap o;
        bs_os_read(r->pool, &o);
        ap_rputs("<section><h2>Machine</h2>"
                 "<div class='kpis'>", r);

        if (bs_shm.header) {
            apr_uint32_t l1 = __atomic_load_n(&bs_shm.header->loadavg_pct, __ATOMIC_RELAXED);
            apr_uint32_t l5 = __atomic_load_n(&bs_shm.header->loadavg5_pct, __ATOMIC_RELAXED);
            apr_uint32_t l15 = __atomic_load_n(&bs_shm.header->loadavg15_pct, __ATOMIC_RELAXED);
            ap_rprintf(r, "<div class='kpi'><div class='k'>Load average</div>"
                          "<div class='v'>%.2f</div><div class='n'>%.2f / %.2f "
                          "(5m / 15m)</div></div>",
                       l1 / 100.0, l5 / 100.0, l15 / 100.0);
        }
        if (o.have_mem) {
            double used_pct = o.mem_total
                ? 100.0 * (double)(o.mem_total - o.mem_avail) / (double)o.mem_total
                : 0.0;
            ap_rprintf(r, "<div class='kpi'><div class='k'>Memory in use</div>"
                          "<div class='v'>%.0f%%</div><div class='n'>%s "
                          "available of %s</div></div>",
                       used_pct, bs_d_kb(r->pool, o.mem_avail),
                       bs_d_kb(r->pool, o.mem_total));
            /* Swap absent is a real operational fact, not a missing
             * reading: with none configured the kernel has no way to
             * relieve pressure short of the OOM killer. */
            if (o.swap_total == 0) {
                ap_rputs("<div class='kpi'><div class='k'>Swap</div>"
                         "<div class='v'>none</div><div class='n'>pressure "
                         "ends at the OOM killer</div></div>", r);
            } else {
                ap_rprintf(r, "<div class='kpi'><div class='k'>Swap free</div>"
                              "<div class='v'>%s</div><div class='n'>of %s"
                              "</div></div>",
                           bs_d_kb(r->pool, o.swap_free),
                           bs_d_kb(r->pool, o.swap_total));
            }
            if (o.committed && o.mem_total) {
                double ov = 100.0 * (double)o.committed / (double)o.mem_total;
                ap_rprintf(r, "<div class='kpi'><div class='k'>Committed</div>"
                              "<div class='v'>%.0f%%</div><div class='n'>%s "
                              "promised vs RAM</div></div>",
                           ov, bs_d_kb(r->pool, o.committed));
            }
        }
        if (o.have_stat) {
            /* procs_blocked is uninterruptible sleep -- almost always
             * storage. It is the one number here that says "the disk is
             * the problem" rather than "the CPU is". */
            ap_rprintf(r, "<div class='kpi'><div class='k'>Runnable</div>"
                          "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                          "<div class='n'>%" APR_UINT64_T_FMT " blocked on I/O"
                          "</div></div>", o.procs_running, o.procs_blocked);
        }
        if (o.have_fd && o.fd_max) {
            ap_rprintf(r, "<div class='kpi'><div class='k'>Open files</div>"
                          "<div class='v'>%.1f%%</div><div class='n'>%"
                          APR_UINT64_T_FMT " of %" APR_UINT64_T_FMT
                          "</div></div>",
                       100.0 * (double)o.fd_used / (double)o.fd_max,
                       o.fd_used, o.fd_max);
        }
        if (o.have_uptime) {
            ap_rprintf(r, "<div class='kpi'><div class='k'>Host uptime</div>"
                          "<div class='v'>%s</div><div class='n'>since last "
                          "boot</div></div>", bs_d_dur(r->pool, o.uptime_sec));
        }
        if (o.have_self) {
            ap_rprintf(r, "<div class='kpi'><div class='k'>This worker RSS</div>"
                          "<div class='v'>%s</div><div class='n'>one child, "
                          "all modules</div></div>",
                       bs_d_kb(r->pool, o.self_rss_kb));
        }
        ap_rputs("</div>", r);
        ap_rputs("<p class='note'>Point-in-time from /proc &middot; "
                 "<span class='tip' data-tip='One httpd child, covering "
                 "every module in it. A sample of the fleet, not the "
                 "fleet, and it cannot attribute growth to BotShield -- "
                 "the generations table does that.'>RSS caveat</span>"
                 "</p></section>", r);
    }

    /* --- Per-device I/O ------------------------------------------ */
    {
        bs_io_set d0, d1, n0, n1;
        apr_time_t t0 = apr_time_now();
        bs_io_read_disks(r->pool, &d0);
        bs_io_read_nics(r->pool, &n0);
        apr_sleep(BS_IO_SAMPLE_US);
        apr_time_t t1 = apr_time_now();
        bs_io_read_disks(r->pool, &d1);
        bs_io_read_nics(r->pool, &n1);
        double secs = (double)(t1 - t0) / (double)APR_USEC_PER_SEC;
        if (secs <= 0.0) secs = (double)BS_IO_SAMPLE_US / 1000000.0;
        bs_io_drop_partitions(&d0);
        bs_io_drop_partitions(&d1);

        ap_rprintf(r, "<section><h2>Disks</h2>"
                      "<p class='note'>Sampled over %.2fs at page load "
                      "&middot; <span class='tip' data-tip='Counters in "
                      "/proc are totals since boot, and an average "
                      "across the whole uptime goes numb to whatever is "
                      "happening now. Two reads a fraction of a second "
                      "apart give a rate instead. The wait parks one "
                      "worker thread and uses no measurable CPU."
                      "'>why sampled</span> &middot; <span class='tip' "
                      "data-tip='Partitions fold into their whole "
                      "device. Stacked ones do not: a dm-* or md* "
                      "volume reports the same I/O as the disk beneath "
                      "it, so those rows overlap rather than add."
                      "'>device rollup</span></p>", secs);
        ap_rputs("<table><thead><tr><th>Device</th>"
                 "<th class='n'>Read</th><th class='n'>Write</th>"
                 "<th class='n'>IOPS</th>"
                 "<th class='n'><span class='tip' data-tip='Share of the "
                 "interval the device had at least one request in "
                 "flight -- what iostat calls %%util. Near 100%% means "
                 "saturated. Pairs with the I/O-blocked process count "
                 "under Machine: high busy at low throughput is "
                 "seek-bound random I/O.'>Busy</span></th>"
                 "<th>&nbsp;</th></tr></thead><tbody>", r);
        int shown = 0;
        for (int i = 0; i < d1.n; i++) {
            bs_io_dev *b = &d1.dev[i];
            bs_io_dev *a = bs_io_find(&d0, b->name);
            if (!a) continue;
            double rd  = (double)(b->b - a->b) * 512.0 / secs;
            double wr  = (double)(b->d - a->d) * 512.0 / secs;
            double ops = (double)((b->a - a->a) + (b->c - a->c)) / secs;
            double busy = (double)(b->e - a->e) / (secs * 1000.0) * 100.0;
            if (busy > 100.0) busy = 100.0;   /* parallel queues can exceed */
            if (rd < 1.0 && wr < 1.0 && ops < 0.5) continue;  /* idle */
            const char *fill = (busy >= 80.0) ? "var(--crit)"
                             : (busy >= 40.0) ? "var(--warn)" : "var(--good)";
            ap_rprintf(r,
                "<tr><td>%s</td><td class='n'>%s</td><td class='n'>%s</td>"
                "<td class='n'>%.0f</td><td class='n'>%.0f%%</td>"
                "<td><div class='stack' style='height:8px'>"
                "<div class='seg' style='flex:0 0 %.2f%%;background:%s'></div>"
                "<div class='seg' style='flex:1 1 auto;background:var(--track)'>"
                "</div></div></td></tr>",
                ap_escape_html(r->pool, b->name),
                bs_d_rate(r->pool, rd), bs_d_rate(r->pool, wr),
                ops, busy, busy, fill);
            shown++;
        }
        if (!shown) {
            ap_rputs("<tr><td colspan='6' class='empty'>No device moved "
                     "during the sample. On a quiet server that is the "
                     "normal reading, not a missing one.</td></tr>", r);
        }
        ap_rputs("</tbody></table></section>", r);

        ap_rputs("<section><h2>Network</h2>"
                 "<p class='note'>Same sample &middot; <span class='tip' "
                 "data-tip='Loopback is kept rather than filtered as "
                 "noise: PHP-FPM is reached over 127.0.0.1, so lo "
                 "carries the application traffic this server generates "
                 "for itself.'>lo included</span></p>", r);
        ap_rputs("<table><thead><tr><th>Interface</th>"
                 "<th class='n'>In</th><th class='n'>Out</th>"
                 "<th class='n'><span class='tip' data-tip='Cumulative "
                 "since boot, not a rate -- for errors the total is the "
                 "interesting number, and a rate would hide a problem "
                 "that has stopped growing.'>Errors / drops</span></th>"
                 "</tr></thead><tbody>", r);
        for (int i = 0; i < n1.n; i++) {
            bs_io_dev *b = &n1.dev[i];
            bs_io_dev *a = bs_io_find(&n0, b->name);
            if (!a) continue;
            double rx = (double)(b->a - a->a) / secs;
            double tx = (double)(b->b - a->b) / secs;
            apr_uint64_t bad = b->c + b->d;
            ap_rprintf(r,
                "<tr><td>%s</td><td class='n'>%s</td><td class='n'>%s</td>"
                "<td class='n'%s>%" APR_UINT64_T_FMT "</td></tr>",
                ap_escape_html(r->pool, b->name),
                bs_d_rate(r->pool, rx), bs_d_rate(r->pool, tx),
                bad ? " style='color:var(--warn);font-weight:600'" : "",
                bad);
        }
        ap_rputs("</tbody></table></section>", r);
    }

    /* --- Build / config ------------------------------------------ */
    {
        ap_rputs("<section><h2>Build</h2><table><tbody>", r);
        ap_rprintf(r, "<tr><td>SHM format</td><td class='n'>v%d</td></tr>",
                   BS_SHM_FORMAT_VERSION);
        ap_rprintf(r, "<tr><td>State-file format</td><td class='n'>v%d</td></tr>",
                   BS_STATE_FORMAT_VERSION);
        ap_rprintf(r, "<tr><td>Segment size</td><td class='n'>%s</td></tr>",
                   scfg ? bs_d_kb(r->pool, (apr_uint64_t)scfg->shm_size / 1024)
                        : "&mdash;");
        ap_rprintf(r, "<tr><td>Built</td><td class='n'>%s %s</td></tr>",
                   __DATE__, __TIME__);
        ap_rputs("</tbody></table></section>", r);
    }

    ap_rputs("</main></div></body></html>", r);
    return OK;
}

/* ======================================================================
 * Audience pages: /dashboard/app-bots and /dashboard/app-users
 *
 * These were tabs on the overview. A tab is a page in disguise when the
 * two halves share no numbers, and these share none: one is crawl
 * budget, the other is readership. As pages they also drop the tab CSS,
 * the tab= query param, and the plumbing that carried that param
 * through the auto-refresh.
 * ====================================================================== */
static int bs_d_audience_page(request_rec *r, int group)
{
    apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "obs");
    bs_log_observability_request(r);
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Robots-Tag", "noindex, nofollow");

    int span = 60, refresh = 30, vsel = -1;
    bs_d_view_params(r, &span, &refresh, &vsel);
    const char *vq = (vsel < 0) ? "all"
                                : apr_psprintf(r->pool, "%d", vsel);
    bs_metrics_window w;
    bs_metrics_read_window(span, vsel, &w);

    int is_bot = (group == BS_M_GROUP_BOT);
    bs_d_page_start(r,
        is_bot ? "mod_botshield app to bots" : "mod_botshield app to users",
        bs_d_window_label(span),
        is_bot ? "app-bots" : "app-users", span, refresh, vq);
    bs_d_view_controls(r, span, refresh, vsel, vq);
    bs_d_page_body(r);

    static const int bot_cls[] = { BS_M_CLASS_VERIFIED_BOT,
                                   BS_M_CLASS_KNOWN_BOT,
                                   BS_M_CLASS_UNKNOWN_BOT };
    static const char *bot_lbl[] = { "verified bot", "known bot",
                                     "unknown bot" };
    static const int usr_cls[] = { BS_M_CLASS_BROWSER,
                                   BS_M_CLASS_FAKE_BOT,
                                   BS_M_CLASS_UNKNOWN };
    static const char *usr_lbl[] = { "browser", "fake bot", "unknown" };

    ap_rprintf(r, "<section><h2>%s</h2>",
               is_bot ? "Application served to bots"
                      : "Application served to users");
    if (is_bot) {
        ap_rputs("<p class='note'>Declared crawlers. Most are passed "
                 "deliberately and governed by BotShieldBotRateLimit "
                 "rather than by challenges, so a low challenge rate "
                 "here is the policy working, not a gap.</p>", r);
        bs_d_audience_panel(r, &w, BS_M_GROUP_BOT, "b", bot_cls, bot_lbl, 3);
    } else {
        ap_rputs("<p class='note'>Browsers, unclassified clients, and UAs "
                 "claiming to be crawlers whose IP failed the cross-check. "
                 "This is the population challenges are aimed at, so "
                 "challenge and solve rates here are the ones to read.</p>",
                 r);
        bs_d_audience_panel(r, &w, BS_M_GROUP_USER, "u", usr_cls, usr_lbl, 3);
    }
    ap_rputs("</section></main></div></body></html>", r);
    return OK;
}

int bs_dashboard_app_bots_handler(request_rec *r)
{
    return bs_d_audience_page(r, BS_M_GROUP_BOT);
}

int bs_dashboard_app_users_handler(request_rec *r)
{
    return bs_d_audience_page(r, BS_M_GROUP_USER);
}

/* ======================================================================
 * /dashboard/responses — what BotShield itself answered
 * ====================================================================== */
int bs_dashboard_responses_handler(request_rec *r)
{
    apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "obs");
    bs_log_observability_request(r);
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Robots-Tag", "noindex, nofollow");

    int span = 60, refresh = 30, vsel = -1;
    bs_d_view_params(r, &span, &refresh, &vsel);
    const char *vq = (vsel < 0) ? "all"
                                : apr_psprintf(r->pool, "%d", vsel);
    bs_metrics_window w;
    bs_metrics_read_window(span, vsel, &w);

    bs_d_page_start(r, "mod_botshield responses",
                    bs_d_window_label(span), "responses", span, refresh, vq);
    bs_d_view_controls(r, span, refresh, vsel, vq);
    bs_d_page_body(r);

    apr_uint64_t ours = 0;
    for (int i = 1; i < BS_M_RESP_COUNT; i++) {
        if (i == BS_M_RESP_STATIC) continue;
        ours += w.req_resp[i];
    }

    ap_rputs("<section><h2>Answered by BotShield</h2><div class='kpis'>", r);
    ap_rprintf(r, "<div class='kpi'><div class='k'>BotShield responses</div>"
                  "<div class='v'>%s</div><div class='n'>%" APR_UINT64_T_FMT
                  " of %" APR_UINT64_T_FMT " requests</div></div>",
               bs_d_pct(r->pool, ours, w.req_total), ours, w.req_total);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Challenges</div>"
                  "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                  "<div class='n'>interstitials served</div></div>",
               w.req_resp[BS_M_RESP_CHALLENGE]);
    ap_rprintf(r, "<div class='kpi'><div class='k'>Solved</div>"
                  "<div class='v'>%" APR_UINT64_T_FMT "</div>"
                  "<div class='n'>challenge passed</div></div>",
               w.outcome[BS_M_OUTCOME_VERIFIED]);
    ap_rputs("</div>", r);

    {
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
        bs_d_stacked(r, "rk", "BotShield response breakdown", labels, vals,
                     fills, 6, ours);
        ap_rputs("<p class='note'>Scaled to what BotShield answered, not "
                 "to all traffic: on a healthy site the origin is most of "
                 "the bar and would squeeze these into slivers. "
                 "\"dashboard\" is this page and its siblings -- the "
                 "measuring instrument, counted so it can be discounted."
                 "</p>", r);
    }

    ap_rputs("</section>", r);

    /* Which tier was selected.
     *
     * Recorded since M9.2 and never rendered, so the only way to learn
     * that the form and captcha tiers have never fired on this
     * deployment was to grep the decision log -- which is exactly what
     * had to be done during two incidents. It is also the fastest
     * check that a threshold change did what was intended. */
    {
        const char *tl[] = { "none", "pass", "non-interactive",
                             "interactive", "captcha" };
        /* pass is the good outcome and wears it; the three challenge
         * tiers escalate through the categorical slots rather than the
         * status palette, because a captcha is not a "worse" outcome
         * than a non-interactive challenge, it is a costlier one. */
        const char *tf[] = { "var(--neutral)", "var(--good)", "var(--c1)",
                             "var(--c4)", "var(--c2)" };
        apr_uint64_t tv[BS_M_TIER_COUNT], tt = 0;
        for (int i = 0; i < BS_M_TIER_COUNT; i++) {
            tv[i] = w.tier[i]; tt += tv[i];
        }
        bs_d_stacked(r, "tier", "Tier selected", tl, tv, tf,
                     BS_M_TIER_COUNT, tt);
        ap_rputs("<section><p class='note'>A tier that never appears is a "
                 "tier that has never run. Both form and captcha are "
                 "untested on this deployment and the score thresholds "
                 "are parked to keep them unreachable &mdash; this is "
                 "where that shows.</p></section>", r);
    }

    /* Cookie state on arrival.
     *
     * The distinction that matters is solved vs ok. Under always-mint
     * every returning client holds a signature-valid cookie, so "valid"
     * says nothing about whether a challenge was ever passed -- and a
     * cookie-harvesting bot looks identical to a real visitor until you
     * separate the two.
     *
     * It is also the challenge-loop signature. The lockout in ticket
     * #5168 looked exactly like this: solved cookies arriving
     * repeatedly alongside challenges, once per second. On a bar it is
     * one glance rather than a log query. */
    {
        const char *cl[] = { "ok", "expired", "bad sig", "bad format",
                             "absent", "minted", "solved" };
        const char *cf[] = { "var(--c1)", "var(--c4)", "var(--crit)",
                             "var(--c2)", "var(--neutral)", "var(--c5)",
                             "var(--good)" };
        apr_uint64_t cv[BS_M_COOKIE_COUNT], ct = 0;
        for (int i = 0; i < BS_M_COOKIE_COUNT; i++) {
            cv[i] = w.cookie[i]; ct += cv[i];
        }
        bs_d_stacked(r, "ck", "Cookie state on arrival", cl, cv, cf,
                     BS_M_COOKIE_COUNT, ct);
        ap_rputs("<section><p class='note'>&ldquo;solved&rdquo; carries "
                 "proof a challenge was passed; &ldquo;ok&rdquo; is a "
                 "valid cookie with no such proof, which is what a "
                 "cookie-harvesting bot holds. Solved cookies arriving in "
                 "quantity beside a high challenge count is the shape of "
                 "a challenge loop.</p></section>", r);
    }

    /* Outcome table: the full vocabulary, including the rare ones. */
    {
        const char *const *onames = bs_m_outcome_names;
        int shown = 0;
        ap_rputs("<section><h2>Outcomes</h2><table><thead><tr>"
                 "<th>Outcome</th><th class='n'>Count</th>"
                 "<th class='n'>Share</th></tr></thead><tbody>", r);
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
        ap_rputs("</tbody></table></section>", r);
    }

    ap_rputs("</main></div></body></html>", r);
    return OK;
}

int bs_dashboard_handler(request_rec *r)
{
    apr_table_setn(r->subprocess_env, "BS_ENDPOINT", "obs");
    bs_log_observability_request(r);
    /* Same parser and defaults as every other dashboard page. This
     * block used to be ~45 lines of inline w/r/vh parsing duplicated
     * in spirit on each new page; one parser means one set of accepted
     * values. */
    int span = 60, refresh = 30, vsel = -1;
    bs_d_view_params(r, &span, &refresh, &vsel);
    const char *vq = (vsel < 0) ? "all"
                                : apr_psprintf(r->pool, "%d", vsel);
    const bs_vhost_dir *vdir = bs_shm.vhost_dir;


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

    bs_d_page_open(r, "mod_botshield dashboard", span, refresh, vq);

    /* Opens the rail. The overview builds its own subtitle rather than
     * going through bs_d_page_start because it names the selected vhost
     * as well as the window; the rest of the sequence is identical. */
    ap_rputs("<aside><div class='fgroup navsec'>"
             "<div class='railhead'><h1>mod_botshield</h1>"
             "<label class='icontog' for='rail' title='Hide sidebar' "
             "aria-label='Hide sidebar'>&laquo;</label></div>", r);
    {
        const char *scope = (vsel < 0)
            ? "all vhosts"
            : ap_escape_html(r->pool, vdir->name[vsel]);
        ap_rprintf(r,
            "<p class='sub'>%s &middot; %s</p>",
            bs_d_window_label(span), scope);
    }

    /* Page nav first. A second page needs a navigation affordance, not
     * a sentence in the body: the link lived in a 13px muted <p> in the
     * middle of a long page and was reported as "I don't see any new
     * links", which is a fair verdict on that placement. Order matters
     * too -- which page you are on reads before which window. */
    bs_d_nav(r, "");
    bs_d_view_controls(r, span, refresh, vsel, vq);
    bs_d_page_body(r);

    /* Server load. Point-in-time like the capacity gauges further down,
     * not a windowed figure -- a load average carries its own window.
     *
     * Both signals are shown because they disagree in the way that
     * matters here: with 1024 MaxRequestWorkers on 6 cores, four
     * outages ran at 2-3% busy workers while the per-CPU load average
     * was well past 2.0. A dashboard showing only the worker ratio
     * would have reported those incidents as an idle server. */
    {
        apr_uint32_t la = bs_loadavg_current();
        /* The merged state is no longer rendered here -- it is the
         * worst of the four pills below, and printing it again cost a
         * row. It is still what policy matches on; see bs_load_current
         * and the minload= predicate. */
        apr_uint32_t dbst  = bs_shm.header
            ? apr_atomic_read32(&bs_shm.header->db_state) : 0;
        apr_uint32_t dbthr = bs_shm.header
            ? apr_atomic_read32(&bs_shm.header->db_threads_run) : 0;
        apr_uint32_t dbqps = bs_shm.header
            ? apr_atomic_read32(&bs_shm.header->db_qps) : 0;
        apr_uint32_t dblck = bs_shm.header
            ? apr_atomic_read32(&bs_shm.header->db_lock_pct_x100) : 0;
        apr_uint32_t dbsec = bs_shm.header
            ? apr_atomic_read32(&bs_shm.header->db_sample_sec) : 0;
        apr_uint32_t nowsec = (apr_uint32_t)apr_time_sec(apr_time_now());
        /* A monitor that died an hour ago reads exactly like a database
         * that is perfectly calm. Age is the only thing that separates
         * them, so it decides whether these numbers are shown at all. */
        int db_have  = (dbsec > 0);
        int db_stale = db_have && (nowsec > dbsec + 120);

        /* No section heading and no composite status bar. The four
         * boxes below each carry their own state pill, so a strip that
         * repeated all four states above them was a second copy that
         * cost a whole row of vertical space. The merged verdict is
         * still what policy matches on -- it is simply the worst of the
         * four pills, which is legible at a glance without a caption
         * saying so.
         *
         * Each state is computed here and handed to the box that owns
         * it; the pill markup lives in bs_d_chartbox_open. */
        const char *cpu_s, *cpu_t;
        {
            int aw, ah;
            bs_loadavg_thresholds(r->server, &aw, &ah);
            cpu_s = ((int)la >= ah) ? "hot" : ((int)la >= aw) ? "warm" : "normal";
            cpu_t = ((int)la >= ah) ? "var(--crit)"
                  : ((int)la >= aw) ? "var(--warn)" : "var(--good)";
        }
        const char *ap_s, *ap_t;
        {
            apr_uint32_t lat_us = bs_latency_current_us();
            if (lat_us == BS_M_AP_NO_STATUS) {
                ap_s = "no status"; ap_t = "var(--muted)";
            } else {
                int lat = (int)(lat_us / 1000), lw, lh;
                bs_latency_thresholds(r->server, &lw, &lh);
                ap_s = (lat >= lh) ? "hot" : (lat >= lw) ? "warm" : "normal";
                ap_t = (lat >= lh) ? "var(--crit)"
                     : (lat >= lw) ? "var(--warn)" : "var(--good)";
            }
        }
        const char *db_s, *db_t;
        if (!db_have)       { db_s = "no monitor"; db_t = "var(--muted)"; }
        else if (db_stale)  { db_s = apr_psprintf(r->pool, "stale %us",
                                                  nowsec - dbsec);
                              db_t = "var(--warn)"; }
        else {
            db_s = (dbst == BS_LOAD_HOT) ? "hot"
                 : (dbst == BS_LOAD_WARM) ? "warm" : "normal";
            db_t = (dbst == BS_LOAD_HOT) ? "var(--crit)"
                 : (dbst == BS_LOAD_WARM) ? "var(--warn)" : "var(--good)";
        }
        const char *fpm_s, *fpm_t;
        {
            bs_metrics *fm = bs_shm.metrics;
            apr_uint32_t fsec = fm ? apr_atomic_read32(&fm->fpm_sample_sec) : 0;
            apr_uint32_t fst  = fm ? apr_atomic_read32(&fm->fpm_state) : 0;
            if (!fsec)                    { fpm_s = "no monitor";
                                            fpm_t = "var(--muted)"; }
            else if (nowsec > fsec + 120) { fpm_s = apr_psprintf(r->pool,
                                                "stale %us", nowsec - fsec);
                                            fpm_t = "var(--warn)"; }
            else {
                fpm_s = (fst == BS_LOAD_HOT) ? "hot"
                      : (fst == BS_LOAD_WARM) ? "warm" : "normal";
                fpm_t = (fst == BS_LOAD_HOT) ? "var(--crit)"
                      : (fst == BS_LOAD_WARM) ? "var(--warn)" : "var(--good)";
            }
        }
        ap_rputs("<section>", r);

        ap_rputs("<div class='kpis loadpair'>", r);
        /* Number and sparkline share one box: the value says where you
         * are, the line says how you got here, and reading one without
         * the other is what made four overnight spikes look like
         * unrelated events. */
        bs_d_chartbox_open(r, "cpu", "Load per CPU", cpu_s, cpu_t);
        {
            /* All three averages, as every other load readout on a unix
             * box shows them. The 1-minute stays the headline because
             * it is the one policy matches on and the one the chart
             * plots; the 5 and 15 are what distinguish a spike that is
             * passing from a plateau that is not, which is the first
             * thing anyone wants to know from a load average. */
            apr_uint32_t la5 = 0, la15 = 0;
            bs_loadavg_current_all(&la5, &la15);
            ap_rprintf(r, "<div class='v'>%u.%02u"
                          "<span class='la2'>%u.%02u %u.%02u</span></div>",
                       la / 100, la % 100,
                       la5 / 100, la5 % 100, la15 / 100, la15 % 100);
        }
        bs_d_load_spark(r);
        bs_d_chartbox_close(r, "cpu", apr_psprintf(r->pool,
            "1-minute average, last hour &middot; %s", bs_d_today(r)));

        /* Apache request latency. Deliberately NOT the busy-worker
         * ratio: with 1024 slots on 6 cores that reads 2-3% while the
         * site is unusable, which is how four overnight outages looked
         * like an idle server. */
        {
            apr_uint32_t lat_us = bs_latency_current_us();
            bs_d_chartbox_open(r, "apache", "Apache request latency", ap_s, ap_t);
            ap_rputs("<div class='v'>", r);
            if (lat_us == BS_M_AP_NO_STATUS) {
                /* No number at all rather than a zero. Zero here would
                 * read as an instantaneous server, which is the exact
                 * opposite of what an absent measurement means. */
                ap_rputs("<span style='color:var(--muted)'>&mdash;</span>"
                         "</div></div><div class='n'>unavailable: this "
                         "metric is derived from Apache's per-worker "
                         "counters, which are only maintained under "
                         "<code>ExtendedStatus On</code></div></div>", r);
            } else {
                /* Three scales, because this number legitimately spans
                 * five orders of magnitude: sub-millisecond on a static
                 * hit, tens of ms normally, tens of SECONDS during the
                 * outages. Printing everything in ms would show "0ms"
                 * for a fast server and "36000ms" for a dying one. */
                if (lat_us >= 1000000) {
                    ap_rprintf(r, "%u.%us</div>", lat_us / 1000000,
                               (lat_us % 1000000) / 100000);
                } else if (lat_us >= 1000) {
                    ap_rprintf(r, "%ums</div>", lat_us / 1000);
                } else {
                    ap_rprintf(r, "0.%ums</div>", lat_us / 100);
                }
                bs_d_apache_spark(r);
                bs_d_chartbox_close(r, "apache", apr_psprintf(r->pool,
                    "mean per request, last hour &middot; %s",
                    bs_d_today(r)));
            }
        }

        /* Database, same shape so the two read against each other. */
        if (db_have && !db_stale) {
            /* Threads-running stays the plotted and headline metric,
             * with queries/s alongside it.
             *
             * QPS is the more interesting number to watch and the worse
             * one to chart: it has no ceiling to draw bands against --
             * every other chart here normalises to a real limit (cores,
             * pm.max_children, a saturation point) and 500 q/s is
             * neither high nor low without context. It also inverts
             * under the failure we care about, because a pool stuck on
             * lock waits serves FEWER queries per second, so a QPS line
             * goes quiet exactly when the database is in trouble. */
            bs_d_chartbox_open(r, "db", "Database threads running", db_s, db_t);
            ap_rprintf(r, "<div class='v'>%u<span class='la2'>%u q/s</span>"
                          "</div>", dbthr, dbqps);
            bs_d_db_spark(r);
            bs_d_chartbox_close(r, "db",
                apr_psprintf(r->pool,
                    "%u.%02u%% lock contention, last hour &middot; %s",
                    dblck / 100, dblck % 100, bs_d_today(r)));
        } else {
            ap_rprintf(r, "<div class='kpi kpi-load'><div class='k'>Database "
                          "threads running</div><div class='loadrow'>"
                          "<div class='v' style='color:var(--muted)'>—</div>"
                          "</div><div class='n'>%s</div></div>",
                       db_have
                         ? "monitor stopped reporting; the last reading is "
                           "not shown because a dead monitor looks calm"
                         : "no monitor configured "
                           "(BotShieldDbStatsFile)");
        }
        /* PHP-FPM. pm.max_children is a real ceiling, which is what
         * makes a percentage here meaningful in a way the Apache
         * busy-worker ratio is not. */
        {
            bs_metrics *fm = bs_shm.metrics;
            apr_uint32_t fsec = fm ? apr_atomic_read32(&fm->fpm_sample_sec) : 0;
            int fstale = fsec && (nowsec > fsec + 120);
            bs_d_chartbox_open(r, "fpm", "PHP-FPM workers busy", fpm_s, fpm_t);
            if (fsec && !fstale) {
                ap_rprintf(r, "<div class='v'>%u%%</div>",
                           apr_atomic_read32(&fm->fpm_pct));
                bs_d_fpm_spark(r);
                bs_d_chartbox_close(r, "fpm", apr_psprintf(r->pool,
                    "%u of %u children, %u queued, last hour &middot; %s",
                    apr_atomic_read32(&fm->fpm_active),
                    apr_atomic_read32(&fm->fpm_max_children),
                    apr_atomic_read32(&fm->fpm_queue), bs_d_today(r)));
            } else {
                ap_rprintf(r, "<div class='v' style='color:var(--muted)'>"
                              "&mdash;</div></div><div class='n'>%s</div>"
                              "</div>",
                           fsec ? "monitor stopped reporting; the last "
                                  "reading is not shown because a dead "
                                  "monitor looks calm"
                                : "no monitor configured "
                                  "(BotShieldFpmStatsFile)");
            }
        }
        ap_rputs("</div>", r);   /* closes the KPI row */
        ap_rputs("</section>", r);
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
    /* Solve rate against challenges issued, not against all decisions.
     * A challenge nobody answers is a client that left, so this is the
     * one number that says whether the challenge is working -- and it
     * is what separates a real browser population from a scraper farm
     * or a broken interstitial. */
    ap_rprintf(r, "<div class='kpi'><div class='k'>Solved</div>"
                  "<div class='v'>%s</div><div class='n'>%" APR_UINT64_T_FMT
                  " of %" APR_UINT64_T_FMT " challenges</div></div>",
               bs_d_pct(r->pool, w.outcome[BS_M_OUTCOME_VERIFIED],
                        w.outcome[BS_M_OUTCOME_CHALLENGED]),
               w.outcome[BS_M_OUTCOME_VERIFIED],
               w.outcome[BS_M_OUTCOME_CHALLENGED]);
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

        /* Break each class into the codes actually seen inside it, for
         * the hover. Only tracked codes appear; whatever is left over
         * is reported as "other" rather than silently dropped, so the
         * parts always reconcile with the class total the user is
         * looking at. */
        const char *detail[5] = { NULL, NULL, NULL, NULL, NULL };
        {
            static const int lo[5] = { 200, 300, 400, 500, 0 };
            static const int hi[5] = { 299, 399, 499, 599, 0 };
            for (int c = 0; c < 4; c++) {
                char *d = apr_pstrdup(r->pool, "");
                apr_uint64_t named = 0;
                for (int k = 0; k < BS_M_CODE_COUNT; k++) {
                    int code = bs_m_code_values[k];
                    if (code < lo[c] || code > hi[c]) continue;
                    if (!w.req_code[k]) continue;
                    named += w.req_code[k];
                    d = apr_psprintf(r->pool, "%s%s%d: %" APR_UINT64_T_FMT,
                                     d, *d ? "\n" : "", code, w.req_code[k]);
                }
                if (vals[c] > named) {
                    d = apr_psprintf(r->pool, "%s%sother: %" APR_UINT64_T_FMT,
                                     d, *d ? "\n" : "", vals[c] - named);
                }
                if (*d) detail[c] = d;
            }
        }
        bs_d_stacked_detail(r, "st", "Response status", labels, vals,
                            fills, detail, 5, tot);
    }

    /* What BotShield itself answered. Deliberately NOT a segment inside
     * the status chart: on a healthy site the origin is ~99% of the
     * bar, which would squeeze every BotShield response into an
     * unreadable sliver. The share goes in a KPI, and the breakdown
     * gets its own bar scaled to BotShield's own responses. */
    {
        /* Four-way: BotShield / static / app-to-bot / app-to-user.
         *
         * `ours` must skip BOTH non-BotShield kinds. ORIGIN was already
         * excluded; STATIC has to be too, or every stylesheet counts as
         * something this module answered.
         *
         * Splitting the application row by audience is the point of the
         * arrangement. "The app answered a crawler" and "the app
         * answered a person" are the same row in req_resp[] and
         * completely different facts -- the first is crawl budget spent
         * on machines that will never convert, the second is the site
         * doing its job. Merged, a hub whose application load is mostly
         * search bots looks identical to one serving readers, and the
         * only lever that moves the first (rate limits) is invisible.
         *
         * Static is NOT split by audience on purpose: bots rarely fetch
         * sub-resources, so that row is almost entirely human by
         * construction and splitting it would add a slice that is
         * always ~0 while making the bar harder to read. */
        apr_uint64_t ours = 0;
        for (int i = 1; i < BS_M_RESP_COUNT; i++) {
            if (i == BS_M_RESP_STATIC) continue;
            ours += w.req_resp[i];
        }
        apr_uint64_t stat_n   = w.req_resp[BS_M_RESP_STATIC];
        apr_uint64_t app_bot  = w.g_resp[BS_M_GROUP_BOT][BS_M_RESP_ORIGIN];
        apr_uint64_t app_usr  = w.g_resp[BS_M_GROUP_USER][BS_M_RESP_ORIGIN];
        apr_uint64_t app_all  = w.req_resp[BS_M_RESP_ORIGIN];
        /* Anything the classifier could not place lands in neither
         * group; show it rather than let the slices silently under-sum. */
        apr_uint64_t app_unk  = (app_all > app_bot + app_usr)
                              ? app_all - app_bot - app_usr : 0;

        ap_rputs("<section><h2>Who answered</h2><div class='kpis'>", r);
        ap_rprintf(r, "<div class='kpi'><div class='k'>BotShield</div>"
                      "<div class='v'>%s</div><div class='n'>%"
                      APR_UINT64_T_FMT " of %" APR_UINT64_T_FMT
                      " requests</div></div>",
                   bs_d_pct(r->pool, ours, w.req_total), ours, w.req_total);
        ap_rprintf(r, "<div class='kpi'><div class='k'>Static files</div>"
                      "<div class='v'>%s</div><div class='n'>%"
                      APR_UINT64_T_FMT " served off disk</div></div>",
                   bs_d_pct(r->pool, stat_n, w.req_total), stat_n);
        ap_rprintf(r, "<div class='kpi'><div class='k'>App &rarr; bot</div>"
                      "<div class='v'>%s</div><div class='n'>%"
                      APR_UINT64_T_FMT " crawler requests</div></div>",
                   bs_d_pct(r->pool, app_bot, w.req_total), app_bot);
        ap_rprintf(r, "<div class='kpi'><div class='k'>App &rarr; user</div>"
                      "<div class='v'>%s</div><div class='n'>%"
                      APR_UINT64_T_FMT " human requests</div></div>",
                   bs_d_pct(r->pool, app_usr, w.req_total), app_usr);
        ap_rputs("</div>", r);

        {
            const char *wl[] = { "BotShield", "static files",
                                 "app &rarr; bot", "app &rarr; user",
                                 "app (unclassified)" };
            const char *wf[] = { "var(--t2)", "var(--neutral)",
                                 "var(--c2)", "var(--c3)", "var(--muted)" };
            apr_uint64_t wv[] = { ours, stat_n, app_bot, app_usr, app_unk };
            apr_uint64_t tot = ours + stat_n + app_all;
            bs_d_stacked(r, "who", "Requests by responder", wl, wv,
                         wf, app_unk ? 5 : 4, tot);
        }
        ap_rputs("</section>", r);

        /* The response breakdown that used to sit here lives on
         * /dashboard/responses, which is the page about exactly this
         * and shows the same bar plus the outcome vocabulary. Two
         * copies of one chart is one chart too many, and the overview
         * already answers "how much did BotShield answer" in the
         * responder bar above -- the split of that share is the
         * responses page's whole subject. */
    }

    /* Rate limiting and the per-bot view moved to /dashboard/bots.
     *
     * They never belonged beside the per-request verdicts here. Those
     * judge one client; a rate limit is a budget decision about a
     * crawler across all of its IPs, tuned with different directives
     * and read on a different cadence. On the bots page they sit with
     * the per-bot state they describe.
     *
     * That page also answers what the old comment here said was
     * unanswerable -- WHICH slugs are being limited -- by reading the
     * rate limiter's own per-slug holders. It reports live window
     * usage rather than a lifetime total, because the fixed-window
     * counter is the only per-bot number that exists and adding a
     * cumulative one was not worth the storage. */
    /* No mid-page teaser section: the page nav at the top is the
     * affordance now. */

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
    /* Audience split moved to its own pages (app-bots / app-users).
     * It was a tabbed section here; a tab is a page in disguise when the
     * two halves share no numbers, and making them real pages removed
     * the tab CSS, the tab= query param and the "keep the tab through
     * the refresh" plumbing that param needed. */

    /* Live capacity — ratios against a limit, so meters. These are
     * point-in-time gauges and ignore the window selector; labelled as
     * such rather than left to imply they follow it. */

    /* SHM table occupancy. This is NOT a load signal -- it measures
     * BotShield's own memory, not the machine's -- so it does not
     * overlap the four monitors above. But it is inert in normal
     * operation: measured here at 0.06%, 0.03% and 0.00% of 50,000,
     * which is three meters drawing zero and a section's worth of
     * height to do it.
     *
     * It still has to be visible, because filling one of these tables
     * is a real failure mode: probe saturation starts evicting entries
     * and the module logs about it. So it is quiet while quiet and
     * expands the moment anything approaches its ceiling.
     *
     * 25% is the trip point rather than something higher because these
     * are open-addressed tables -- probe cost climbs well before the
     * table is full, so "getting busy" matters earlier than "nearly
     * out of room". */
    {
        struct { const char *label; apr_uint64_t used, cap; } tab[3] = {
            { "Flagged IPs",        bs_gauges.flagged_used,
              (apr_uint64_t)bs_shm.flagged_capacity },
            { "Safeguard entries",  bs_gauges.safeguard_used,
              (apr_uint64_t)bs_shm.safeguard_capacity },
            { "Rate-limit strikes", bs_gauges.strike_used,
              (apr_uint64_t)bs_shm.strike_capacity },
        };
        int busy = 0;
        for (int i = 0; i < 3; i++) {
            if (tab[i].cap && tab[i].used * 4 >= tab[i].cap) busy = 1;
        }
        ap_rputs("<section><h2>Capacity now <span style='text-transform:none;"
                 "font-weight:400'>(live, not windowed)</span></h2>", r);
        if (busy) {
            for (int i = 0; i < 3; i++) {
                bs_d_meter(r, tab[i].label, tab[i].used, tab[i].cap);
            }
        } else {
            ap_rputs("<p class='capline'>", r);
            for (int i = 0; i < 3; i++) {
                ap_rprintf(r, "%s<span>%s</span> %" APR_UINT64_T_FMT
                              " <span>of %" APR_UINT64_T_FMT "</span>",
                           i ? " &middot; " : "", tab[i].label,
                           tab[i].used, tab[i].cap);
            }
            ap_rputs("</p>", r);
        }
        ap_rputs("</section>", r);
    }

    /* The Outcomes table that used to sit here is gone. Five of its
     * rows were already on the page: challenged, block and rate_limited
     * are the same numbers the "BotShield response breakdown" bar
     * shows, and allow is just decisions minus those. Only `verified`
     * -- the count of challenges actually solved -- appeared nowhere
     * else, and burying the single most diagnostic number on the page
     * in the last row of the last table was the wrong place for it. It
     * is now a KPI in the traffic row, expressed against challenges
     * issued rather than against all decisions, because "what fraction
     * of the clients we challenged came back and solved it" is the
     * question that number answers. */
    ap_rputs("</main></div></body></html>", r);
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
    bs_m_emit_counter(r, "tier_non_interactive_total",
        "Decisions at tier=non-interactive (self-solving widget served).",
        bs_mload(&m->tier[BS_M_TIER_NONINTERACTIVE]));
    bs_m_emit_counter(r, "tier_interactive_total",
        "Decisions at tier=interactive (checkbox PoW interstitial served).",
        bs_mload(&m->tier[BS_M_TIER_INTERACTIVE]));
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
    bs_m_emit_counter(r, "responses_app_bot_total",
        "Application responses served to a classified bot (verified, "
        "known or unknown bot). Crawl budget rather than readership.",
        bs_mload(&m->g_resp[BS_M_GROUP_BOT][BS_M_RESP_ORIGIN]));
    bs_m_emit_counter(r, "responses_app_user_total",
        "Application responses served to a browser, spoofed bot or "
        "unclassified client -- everything not a real crawler.",
        bs_mload(&m->g_resp[BS_M_GROUP_USER][BS_M_RESP_ORIGIN]));
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
        "non-interactive embedded pass-through, safeguard pass).",
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
        "(passes_non_interactive/form/captcha). The only cookie state that "
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
    bs_m_emit_counter(r, "safeguard_fired_total",
        "Times the anti-loop safeguard redirected a client to the "
        "explainer after N unsolved challenges. Distinct from "
        "shm_safeguard_used, which counts clients being watched rather "
        "than clients that tripped it.",
        bs_mload(&m->safeguard_fired_total));

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
    /* The other three load signals. Without these the dashboard shows
     * data that nothing can retain: the in-module rings hold exactly
     * one hour and then overwrite, so anything longer has to be
     * scraped. Apache latency and the merged state were already here;
     * these complete the set.
     *
     * Flat names rather than a labelled series, matching every other
     * metric this endpoint emits. */
    {
        apr_uint32_t la5 = 0, la15 = 0;
        bs_loadavg_current_all(&la5, &la15);
        bs_m_emit_gauge(r, "loadavg_1m_pct",
            "1-minute load average per CPU, in hundredths (1.50 per core "
            "-> 150). Per-CPU so one threshold means the same thing on a "
            "6-core host and a 64-core one.", bs_loadavg_current());
        bs_m_emit_gauge(r, "loadavg_5m_pct",
            "5-minute load average per CPU, in hundredths.", la5);
        bs_m_emit_gauge(r, "loadavg_15m_pct",
            "15-minute load average per CPU, in hundredths.", la15);
    }
    if (bs_shm.header) {
        bs_m_emit_gauge(r, "db_threads_running",
            "MariaDB threads actively executing, from the external "
            "monitor. Saturation, not throughput: a pool stuck on lock "
            "waits shows high threads and LOW queries per second.",
            apr_atomic_read32(&bs_shm.header->db_threads_run));
        bs_m_emit_gauge(r, "db_queries_per_sec",
            "MariaDB queries per second over the monitor's sample "
            "window. A delta, not the since-boot average.",
            apr_atomic_read32(&bs_shm.header->db_qps));
        bs_m_emit_gauge(r, "db_lock_contention_pct_x100",
            "Share of table-lock acquisitions that had to wait, percent "
            "x100 (1.25% -> 125), over the sample window.",
            apr_atomic_read32(&bs_shm.header->db_lock_pct_x100));
        bs_m_emit_gauge(r, "db_sample_unix",
            "Unix time of the database monitor's last sample. Compare "
            "against scrape time to detect a dead monitor: a stopped "
            "monitor otherwise reads exactly like a calm database.",
            apr_atomic_read32(&bs_shm.header->db_sample_sec));
        bs_m_emit_gauge(r, "db_load_state",
            "Database load state as the monitor classified it: "
            "0 normal, 1 warm, 2 hot.",
            apr_atomic_read32(&bs_shm.header->db_state));
    }
    if (bs_shm.metrics) {
        bs_metrics *fm = bs_shm.metrics;
        bs_m_emit_gauge(r, "fpm_active_processes",
            "PHP-FPM children currently serving a request.",
            apr_atomic_read32(&fm->fpm_active));
        bs_m_emit_gauge(r, "fpm_max_children",
            "pm.max_children, read from the pool config. The real "
            "ceiling for dynamic content, unlike MaxRequestWorkers.",
            apr_atomic_read32(&fm->fpm_max_children));
        bs_m_emit_gauge(r, "fpm_listen_queue",
            "Requests waiting for a free PHP-FPM child. Any non-zero "
            "value means users are already queueing.",
            apr_atomic_read32(&fm->fpm_queue));
        bs_m_emit_gauge(r, "fpm_sample_unix",
            "Unix time of the PHP-FPM monitor's last sample; same "
            "staleness check as db_sample_unix.",
            apr_atomic_read32(&fm->fpm_sample_sec));
        bs_m_emit_gauge(r, "fpm_load_state",
            "PHP-FPM load state as the monitor classified it: "
            "0 normal, 1 warm, 2 hot.",
            apr_atomic_read32(&fm->fpm_state));
    }
    {
        /* -1, not the sentinel and not 0: a scrape must be able to tell
         * "not measured" from "measured as instant". */
        apr_uint32_t lat_us = bs_latency_current_us();
        bs_m_emit_gauge(r, "apache_latency_us",
            "Mean Apache request latency over the last sample window, "
            "microseconds. A delta between watchdog ticks, not an "
            "average since restart. -1 when unavailable (requires "
            "ExtendedStatus On).",
            lat_us == BS_M_AP_NO_STATUS ? -1.0 : (double)lat_us);
    }
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
            bs_mload(&m->tier[BS_M_TIER_NONINTERACTIVE]),
            bs_mload(&m->tier[BS_M_TIER_INTERACTIVE]),
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
        { "non-interactive", bs_mload(&m->tier[BS_M_TIER_NONINTERACTIVE]) },
        { "interactive", bs_mload(&m->tier[BS_M_TIER_INTERACTIVE]) },
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
