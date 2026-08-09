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

    /* Score total accumulates regardless of the per-reason cap. The
     * cap only truncates the audit trail; dropping the penalty too
     * would let a noisy stream of low-value reasons silently mask a
     * later high-value signal that lands past the 16th call. */
    s->total += penalty;

    if (s->entries->nelts >= BS_SCORE_MAX_REASONS) {
        /* Silent drop on cap could mask a runaway loop or a
         * misconfigured rule fanout. Log once at DEBUG so the
         * diagnostic surfaces under verbose-logging without
         * spamming production. */
        if (!s->cap_warned) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: score-reason cap (%d) reached for %s; "
                "further bs_score_add calls drop their reason silently "
                "(score total still accumulates)",
                BS_SCORE_MAX_REASONS, r->uri);
            s->cap_warned = 1;
        }
        return;
    }
    bs_score_entry *e = apr_array_push(s->entries);
    e->penalty     = penalty;
    e->ttl_seconds = ttl_seconds;
    e->reason      = reason;
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

/* Flag-trigger walker.
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

/* The E14 flag-trigger walker (bs_apply_flag_triggers) lives in
 * score.c. bs_flag_names[] is defined further up this file (the
 * NULL-terminated name+bit array bs_parse_flag_names iterates). */

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

/* Score → tier picker. Three configurable cut-points
 * (BotShieldScoreSilent / Hard / Captcha) gate four tiers. The
 * README "Understanding scoring" section covers the operator-facing
 * tuning workflow; templates.h documents the per-tier interstitial
 * rendering. */
bs_tier bs_decide_tier(const bs_dir_cfg *cfg, int score)
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

/* ----------------------------------------------------------------------
 * Per-request tier floor (trigger tier= action)
 * -------------------------------------------------------------------- */

#define BS_TIER_FLOOR_NOTE "bs-tier-floor"

void bs_set_request_tier_floor(request_rec *r, int tier)
{
    if (!r || tier < BS_TIER_PASS || tier > BS_TIER_CAPTCHA) return;
    /* MAX rather than overwrite: two rules can match one request and
     * the stronger demand should win, matching how flag tier_floors
     * compose. */
    if (bs_get_request_tier_floor(r) >= tier) return;
    apr_table_setn(r->notes, BS_TIER_FLOOR_NOTE,
                   apr_psprintf(r->pool, "%d", tier));
}

int bs_get_request_tier_floor(request_rec *r)
{
    if (!r) return BS_TIER_PASS;
    const char *v = apr_table_get(r->notes, BS_TIER_FLOOR_NOTE);
    if (!v) return BS_TIER_PASS;
    int t = atoi(v);
    if (t < BS_TIER_PASS || t > BS_TIER_CAPTCHA) return BS_TIER_PASS;
    return t;
}
