/* score.c — per-request scoring + flag-trigger walker.
 *
 * Owns the tiny request-scoped score-aggregation surface plus the
 * E14 flag-trigger runtime walker that mutates the score from flag
 * bits resolved earlier in the request path. See score.h for the
 * public API. */
#include <string.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include "botshield.h"
#include "score.h"

bs_request_score *bs_get_score(request_rec *r, int create)
{
    bs_request_score *s = ap_get_module_config(r->request_config,
                                               &botshield_module);
    if (!s && create) {
        s = apr_pcalloc(r->pool, sizeof(*s));
        s->entries = apr_array_make(r->pool, 4, sizeof(bs_score_entry));
        ap_set_module_config(r->request_config, &botshield_module, s);
    }
    return s;
}

/* `reason` must outlive the request — static string or r->pool-allocated.
 * `ttl_seconds` is accepted for API stability but ignored in M3 (the
 * request-scoped struct dies with the request). The long-term stores
 * are narrower than the API implies: M4 puts accumulated rep in the
 * user's cookie (per-user, server-stateless); M5 puts serious-event
 * flags in an SHM flagged-IP table (sparse, per-IP). `ttl_seconds`
 * feeds the latter when the caller is a serious-event source. */
/* Operator-facing documentation: README "Understanding scoring"
 * (rendered into docs/guide/index.html) explains the score
 * composition, threshold ladder, and tuning workflow. */
void bs_score_add(request_rec *r, int penalty,
                  int ttl_seconds, const char *reason)
{
    bs_request_score *s = bs_get_score(r, 1);
    if (s->entries->nelts >= BS_SCORE_MAX_REASONS) {
        /* Silent drop on cap could mask a runaway loop or a
         * misconfigured rule fanout. Log once at DEBUG so the
         * diagnostic surfaces under verbose-logging without
         * spamming production. The total still accumulates from
         * the entries we kept; it's only the per-reason audit trail
         * that's truncated past this point. */
        if (!s->cap_warned) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: score-reason cap (%d) reached for %s; "
                "further bs_score_add calls drop their reason silently",
                BS_SCORE_MAX_REASONS, r->uri);
            s->cap_warned = 1;
        }
        return;
    }
    bs_score_entry *e = apr_array_push(s->entries);
    e->penalty     = penalty;
    e->ttl_seconds = ttl_seconds;
    e->reason      = reason;
    s->total      += penalty;
}

/* Join the request's score-reason names (no penalties) into a single
 * comma-separated string for the decision line. Returns "-" when no
 * heuristic signal fired. */
const char *bs_decision_reason_names(apr_pool_t *p,
                                     const bs_request_score *s)
{
    if (!s || !s->entries || s->entries->nelts == 0) return "-";
    /* O(N) join: push borrowed reason pointers into an array,
     * single allocation via apr_array_pstrcat. The
     * BS_SCORE_MAX_REASONS=16 cap bounds N tightly, but the join
     * fires on every request that emits a decision line, so the
     * tidier shape pays back on the hot path. The reason strings
     * outlive p (string literals or strings already in p), so
     * apr_array_pstrcat's copy is safe. */
    int n = s->entries->nelts;
    apr_array_header_t *arr = apr_array_make(p, n, sizeof(const char *));
    for (int i = 0; i < n; i++) {
        bs_score_entry *e = &APR_ARRAY_IDX(s->entries, i, bs_score_entry);
        *(const char **)apr_array_push(arr) = e->reason;
    }
    return apr_array_pstrcat(p, arr, ',');
}

/* Build a compact "[reason:penalty,reason:penalty,...]" string for logs. */
const char *bs_score_reasons_joined(apr_pool_t *p,
                                    const bs_request_score *s)
{
    if (!s || !s->entries || s->entries->nelts == 0) return "[]";
    /* Same O(N) join shape as bs_decision_reason_names: pre-format
     * each "reason:penalty" pair into a pointer-array, single
     * apr_array_pstrcat for the comma join, then one apr_pstrcat
     * to wrap with brackets. */
    int n = s->entries->nelts;
    apr_array_header_t *arr = apr_array_make(p, n, sizeof(const char *));
    for (int i = 0; i < n; i++) {
        bs_score_entry *e = &APR_ARRAY_IDX(s->entries, i, bs_score_entry);
        *(const char **)apr_array_push(arr) =
            apr_psprintf(p, "%s:%d", e->reason, e->penalty);
    }
    return apr_pstrcat(p, "[", apr_array_pstrcat(p, arr, ','), "]", NULL);
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
int bs_apply_flag_triggers(request_rec *r,
                           const struct bs_server_cfg *scfg,
                           apr_uint32_t all_flags,
                           bs_tier *out_tier_floor)
{
    if (out_tier_floor) *out_tier_floor = BS_TIER_PASS;
    if (!scfg || !scfg->flag_triggers || all_flags == 0) return 0;
    int fired = 0;
    for (int i = 0; i < scfg->flag_triggers->nelts; i++) {
        bs_flag_trigger_entry *e =
            APR_ARRAY_IDX(scfg->flag_triggers, i, bs_flag_trigger_entry *);
        if (!(all_flags & e->flag_bit)) continue;
        fired++;
        if (e->mode == BS_TMODE_OBSERVE) {
            bs_score_add(r, 0, 0,
                apr_psprintf(r->pool,
                    "would-flag-trigger:%s:observe", e->flag_name));
            continue;
        }
        if (e->action == BS_FLAG_ACT_SCORE) {
            bs_score_add(r, e->score_add, 0,
                apr_psprintf(r->pool,
                    "flag-trigger:%s", e->flag_name));
        } else if (e->action == BS_FLAG_ACT_TIER_FLOOR) {
            if (out_tier_floor && e->tier_min > *out_tier_floor) {
                *out_tier_floor = e->tier_min;
            }
        }
        /* BS_FLAG_ACT_RESET entries are consumed at post_config —
         * the request path never sees them. */
    }
    return fired;
}
