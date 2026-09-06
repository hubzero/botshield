/* triggers.c — E3/E4/E6/E7.3/E11.2 trigger families.
 *
 * Five trigger families share one config-time action engine and one
 * request-time executor:
 *
 *   E3   BotShieldRequestTrigger      path glob       request-path
 *   E4   BotShieldCookieTrigger    cookie name/val request-path
 *   E6   BotShieldEnvTrigger       env var         request-path
 *   E7.3 BotShieldFeedbackTrigger  event name      response-path
 *   E11.2 BotShieldLoadTrigger     load state      request-path
 *
 * Engine: bs_trigger_action_init seeds family defaults; one
 * bs_parse_trigger_action_key call per key=value argv element walks
 * the action keys (status, redirect, log, flag, ttl, penalty,
 * credit, mode); bs_finalize_trigger_action does cross-key
 * validation (e.g. redirect= requires 3xx status). At request time
 * bs_apply_trigger_action emits the action's side effects (score,
 * flag-IP, log tag, redirect Location) and returns an outcome code
 * the family's walker uses to decide between continue / break /
 * short-circuit.
 *
 * Predicates are family-specific and live with the rest of the
 * setter — except bs_cookie_pred_match, which the request-path
 * walker in botshield.c calls directly to consume an already-parsed
 * cookie map. */
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_lib.h>    /* apr_isspace, apr_tolower */

#include "botshield.h"
#include "allowlist.h" /* bs_parse_client_ip, bs_mask_ipv6_prefix */
#include "metrics.h"   /* bs_set_trigger_tag, bs_shm.metrics */
#include "challenge.h" /* bs_issue_challenge, bs_rep_state */
#include "cookie.h"    /* bs_install_verified_cookie */
#include "score.h"     /* bs_score_add */
#include "shm.h"       /* bs_flagged_ip_add */
#include "triggers.h"

/* Is this cookie-name on the operator-curated session-name list?
 * Linear scan — list is short (typically <10 entries) so an O(n)
 * scan is faster than building a hash map. */
static int bs_is_session_cookie_name(const apr_array_header_t *names,
                                     const char *name)
{
    if (!names) return 0;
    for (int i = 0; i < names->nelts; i++) {
        if (strcasecmp(APR_ARRAY_IDX(names, i, const char *), name) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Evaluate a single cookietrigger predicate against the parsed
 * cookie map + BS-cookie state. Returns 1 on match, 0 on no match. */
int bs_cookie_pred_match(const bs_cookie_trigger_entry *e,
                         apr_table_t *cmap,
                         const apr_array_header_t *session_names,
                         const char *bs_state)
{
    switch (e->pred_kind) {
    case BS_CP_NAMED_PRESENT:
        return apr_table_get(cmap, e->cname) != NULL;
    case BS_CP_NAMED_ABSENT:
        return apr_table_get(cmap, e->cname) == NULL;
    case BS_CP_NAMED_EQ: {
        const char *v = apr_table_get(cmap, e->cname);
        return v && strcmp(v, e->cvalue) == 0;
    }
    case BS_CP_NAMED_NE: {
        const char *v = apr_table_get(cmap, e->cname);
        return v && strcmp(v, e->cvalue) != 0;
    }
    case BS_CP_NAMED_CONTAINS: {
        const char *v = apr_table_get(cmap, e->cname);
        return v && strstr(v, e->cvalue) != NULL;
    }
    case BS_CP_BULK_NONE:
        return apr_is_empty_table(cmap);
    case BS_CP_BULK_ANY:
        return !apr_is_empty_table(cmap);
    case BS_CP_BULK_SESSION: {
        const apr_array_header_t *arr = apr_table_elts(cmap);
        for (int i = 0; i < arr->nelts; i++) {
            apr_table_entry_t *te = &((apr_table_entry_t *)arr->elts)[i];
            if (bs_is_session_cookie_name(session_names, te->key)) {
                return 1;
            }
        }
        return 0;
    }
    case BS_CP_BS_VERIFIED:
        return bs_state && strcmp(bs_state, BS_CK_STATE_VERIFIED) == 0;
    case BS_CP_BS_MISSING:
        return !bs_state
            || strcmp(bs_state, BS_CK_STATE_MISSING) == 0;
    case BS_CP_BS_INVALID:
        return bs_state && strcmp(bs_state, BS_CK_STATE_INVALID) == 0;
    }
    return 0;
}


/* Strip one layer of matching surrounding quotes from a key's value.
 *
 * Apache's TAKE_ARGV tokenizer only honours quotes that begin a token,
 * so `key="value"` arrives with the quotes still attached to the value
 * while a bare positional `"value"` arrives clean. Operators reasonably
 * write the quoted form — the CHANGELOG's own examples do
 * (`ua="GPTBot"`) — and without this the stored pattern is `"GPTBot"`,
 * which can never match a real User-Agent. Silent non-match, no
 * diagnostic. Strip here so both spellings behave the same. */
static const char *bs_unquote(apr_pool_t *pool, const char *v)
{
    if (!v) return v;
    apr_size_t n = strlen(v);
    if (n >= 2 && (v[0] == '"' || v[0] == '\'') && v[n - 1] == v[0]) {
        return apr_pstrndup(pool, v + 1, n - 2);
    }
    return v;
}

static const char *bs_trigger_family_dname(bs_trigger_family fam)
{
    switch (fam) {
    case BS_TFAMILY_REQUEST:  return "BotShieldRequestTrigger";
    case BS_TFAMILY_COOKIE:   return "BotShieldCookieTrigger";
    case BS_TFAMILY_ENV:      return "BotShieldEnvTrigger";
    case BS_TFAMILY_FEEDBACK: return "BotShieldFeedbackTrigger";
    case BS_TFAMILY_LOAD:     return "BotShieldLoadTrigger";
    case BS_TFAMILY_FLAG:     return "BotShieldFlagTrigger";
    case BS_TFAMILY_SCOPE:    return "BotShieldTrigger";
    }
    return "BotShieldTrigger";      /* unreachable */
}

static void bs_trigger_action_init(bs_trigger_family fam,
                                   bs_trigger_action *a)
{
    memset(a, 0, sizeof(*a));
    switch (fam) {
    case BS_TFAMILY_REQUEST:
        /* Immediate 403, and no memory of the client at all.
         *
         * This family used to flag the IP with scanner_probe for an
         * hour by default. That suited the original use -- a handful of
         * scanners probing /.env -- and was actively wrong for a
         * high-cardinality flood, where at roughly one request per
         * address the flag is never read again and 50k slots of table
         * churn buy nothing. And where an operator has declared a
         * tier_floor for scanner_probe -- as the historical compiled-in
         * slate did, before 36494af shipped no default rules -- a rule
         * written to block quietly starts rendering interstitials to
         * whoever shared that address next.
         *
         * A rule that remembers a client is a decision with a blast
         * radius, and a default is the wrong place for it: the operator
         * who wanted a plain 404 on /wp-admin got an hour of forced
         * challenges for every NAT behind it, and nothing in the config
         * said so. Both kinds of memory are opt-in now -- flag= plus
         * BotShieldFlagIP for the address, BotShieldFlagSession
         * for the cookie session. */
        a->status_code = 403;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    case BS_TFAMILY_COOKIE:
    case BS_TFAMILY_ENV:
        /* Cookie/env default is pass-with-score-shaping. No flag
         * unless operator asks; no short-circuit unless they do. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    case BS_TFAMILY_FEEDBACK:
        /* Feedback runs on the response path; status/redirect/
         * penalty/credit don't apply. status_code left at PASS as
         * a harmless sentinel — the executor path for this family
         * doesn't consult it. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    case BS_TFAMILY_LOAD:
        /* Load triggers default to pass-with-score-shaping. The
         * common case is "add some penalty/credit when warm/hot";
         * less common is "outright 403 expensive paths under hot."
         * Both are explicit operator decisions via status=. No
         * flag — load is a global state, not per-IP behavior. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    case BS_TFAMILY_FLAG:
        /* Flag triggers do not use bs_trigger_action — they have
         * their own bs_flag_trigger_entry shape with different
         * verbs. This case exists only to keep the switch
         * exhaustive across the enum; reaching it means a
         * caller mis-routed a flag trigger through the shared
         * engine. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    case BS_TFAMILY_SCOPE:
        /* Per-scope triggers default to pass-with-score-shaping —
         * the scope match itself is the predicate, so the typical
         * use is "everything reaching this <Location> gets +N
         * penalty / -N credit / a flag bit set." Operators flip
         * status= explicitly when they want the scope to short-
         * circuit with a status code or redirect. */
        a->status_code = BS_TRIGGER_STATUS_PASS;
        a->flag_bit    = 0;
        a->ttl_sec     = 0;
        break;
    }
    a->penalty         = 0;
    a->credit          = 0;
    a->tier_floor      = -1;
    a->redirect_url    = NULL;
    a->log_tag         = NULL;
    a->status_explicit = 0;
}

static const char *bs_trigger_known_keys(bs_trigger_family fam)
{
    switch (fam) {
    case BS_TFAMILY_REQUEST:
        return "respond, nochallenge, challenge, redirect, logas, "
               "accesslog, flagip, flagsession, penalty, mode";
    case BS_TFAMILY_COOKIE:
        return "respond, nochallenge, challenge, redirect, logas, "
               "accesslog, flagip, flagsession, penalty, credit, "
               "mode";
    case BS_TFAMILY_ENV:
        return "respond, nochallenge, challenge, logas, accesslog, flagip, "
               "flagsession, penalty, credit, mode";
    case BS_TFAMILY_FEEDBACK:
        /* mode=observe means "log :observe but skip the flagged-IP
         * write" — meaningful for staging a feedback rule before
         * mutating server state. */
        return "flagip, flagsession, logas, accesslog, mode";
    case BS_TFAMILY_LOAD:
        return "respond, logas, accesslog, penalty, credit, mode";
    case BS_TFAMILY_SCOPE:
        return "respond, nochallenge, challenge, redirect, logas, "
               "accesslog, flagip, flagsession, penalty, credit, "
               "mode";
    case BS_TFAMILY_FLAG:
        /* Flag triggers use a separate parser. This entry exists
         * for switch-exhaustiveness; the flag setter prints its
         * own allowed-keys list at error time. */
        return "score, tier_floor, mode";
    }
    return "";
}

/* Feedback-specific: status/redirect/penalty/credit make no sense
 * on the response path — all four are rejected at parse time with
 * a pointed error. Centralized so the messages stay consistent and
 * future keys are easier to vet per family. */
static int bs_trigger_key_is_response_only(const char *arg,
                                           apr_size_t klen)
{
    #define BS_KMATCH(n) (klen == sizeof(n)-1 && \
                          strncasecmp(arg, n, sizeof(n)-1) == 0)
    if (BS_KMATCH("respond"))  return 1;
    if (BS_KMATCH("status"))   return 1;   /* deprecated spelling */
    if (BS_KMATCH("redirect")) return 1;
    if (BS_KMATCH("penalty"))  return 1;
    if (BS_KMATCH("credit"))   return 1;
    #undef BS_KMATCH
    return 0;
}

/* Flags that describe a session and must never be written to an
 * address. Suspicion may be shared across an address -- a penalty on a
 * NAT costs strangers a challenge, which is the trade this module
 * already makes. A credit on an address is different in kind: it hands
 * every stranger behind that NAT an exemption one client earned, and
 * the shared sliding expiry means unrelated traffic keeps renewing it. */
#define BS_FLAGS_SESSION_ONLY  (BS_FLAG_APP_VERIFIED_HUMAN   | \
                                BS_FLAG_APP_VERIFIED_SESSION | \
                                BS_FLAG_APP_TRUST_SIGNAL)

/* `+name` adds, `-name` removes, `=name` makes the named set the whole
 * set. `+` is the default and may be omitted, so an unprefixed list
 * behaves exactly as it did before prefixes existed.
 *
 * The grammar is not new here: BotShieldClassify already takes
 * `[All|None] [+/-flag]...`, and states that mixing its reset token
 * with deltas is a config-time error. Same rule, same reason -- "=a,+b"
 * has no reading that is not a guess about what the operator meant. */
static const char *bs_parse_flag_ops(apr_pool_t *p, const char *s,
                                     apr_uint32_t *add, apr_uint32_t *del,
                                     int *replace)
{
    *add = *del = 0;
    *replace = 0;
    int saw_delta = 0, saw_replace = 0, saw_any = 0;

    char *copy = apr_pstrdup(p, s);
    char *save = NULL;
    for (char *tok = apr_strtok(copy, ",", &save); tok;
         tok = apr_strtok(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char op = '+';
        if (*tok == '+' || *tok == '-' || *tok == '=') { op = *tok; tok++; }
        while (*tok == ' ' || *tok == '\t') tok++;
        apr_size_t l = strlen(tok);
        while (l && (tok[l-1] == ' ' || tok[l-1] == '\t')) tok[--l] = '\0';
        if (!*tok) return "empty flag name";

        /* One name at a time through the shared parser: it is
         * case-insensitive, and its unknown-name error already lists
         * the vocabulary split into penalty and credit bits. Also
         * defined above this point, which the metadata table is not. */
        const char *ferr = NULL;
        apr_uint32_t bit = bs_parse_flag_names(p, tok, &ferr);
        if (ferr) return ferr;
        saw_any = 1;
        if (op == '=')      { saw_replace = 1; *add |= bit; }
        else if (op == '-') { saw_delta   = 1; *del |= bit; }
        else                { saw_delta   = 1; *add |= bit; }
    }
    if (!saw_any) return "names no flag";
    if (saw_replace && saw_delta) {
        return "cannot mix '=' with '+' or '-' -- '=' names the whole "
               "resulting set, so a delta alongside it has no meaning";
    }
    if (saw_replace) *replace = 1;
    return NULL;
}

static const char *bs_parse_trigger_action_key(apr_pool_t *pool,
                                               bs_trigger_family fam,
                                               const char *arg,
                                               bs_trigger_action *a)
{
    const char *dname = bs_trigger_family_dname(fam);
    const char *eq = strchr(arg, '=');
    if (!eq) {
        /* BotShieldNoChallenge: this rule produces no response of its
         * own and no challenge decision is made for the request.
         *
         * Named for what it waives rather than what it grants. The
         * request still meets rate limiting and robots.txt, and the
         * rule's own flag writes still happen -- so "exempt" would
         * claim more than it does. `pass` was retired for precisely
         * that overclaim; this is the name that replaced it, and the
         * directive borrows it rather than inventing a third word.
         *
         * Valueless, the way BotShieldReset is: the block walker
         * passes a directive with no argument through as a bare
         * token. */
        if (strcasecmp(arg, "nochallenge") == 0) {
            a->status_code = BS_TRIGGER_STATUS_PASS;
            a->status_explicit = 1;
            return NULL;
        }
        return apr_psprintf(pool,
            "%s: extra arg '%s' must be key=value", dname, arg);
    }
    apr_size_t klen = (apr_size_t)(eq - arg);
    const char *val = bs_unquote(pool, eq + 1);

    /* Feedback family: reject the request-path-only keys up front
     * with a pointed error message so operators don't confuse this
     * family with the cookie/env surface. */
    if (fam == BS_TFAMILY_FEEDBACK
        && bs_trigger_key_is_response_only(arg, klen)) {
        return apr_psprintf(pool,
            "%s: %.*s= is not supported on feedback triggers "
            "(the response has already been served; feedback maps "
            "a signed event to flag/ttl only — use a cookie or path "
            "trigger for status/redirect/penalty/credit)",
            dname, (int)klen, arg);
    }

    #define BS_AK(n) (klen == sizeof(n)-1 && \
                      strncasecmp(arg, n, sizeof(n)-1) == 0)

    if (BS_AK("score")) {
        /* BotShieldScore <name> +N|-N|=N
         *
         * A named accumulator that lives for this request only. The
         * ambient score this replaces persisted into the cookie, which
         * is what let a request refused for someone else's rate spike
         * bill the client toward a future challenge. Reputation that
         * must outlive a request is a flag.
         *
         * Names rather than one total so the coupling is scoped: every
         * contributor and reader of an accumulator is `grep <name>`,
         * and an unrelated one cannot perturb it. */
        const char *cur = val;
        while (*cur == ' ' || *cur == '\t') cur++;
        const char *nstart = cur;
        while (*cur && *cur != ' ' && *cur != '\t') cur++;
        apr_size_t nlen = (apr_size_t)(cur - nstart);
        if (!nlen || nlen > 32) {
            return apr_psprintf(pool,
                "%s: BotShieldScore needs a name then a movement, e.g. "
                "'BotShieldScore suspicion +10'", dname);
        }
        for (apr_size_t i = 0; i < nlen; i++) {
            char c = nstart[i];
            if (!apr_isalnum(c) && c != '_' && c != '-') {
                return apr_psprintf(pool,
                    "%s: BotShieldScore name '%.*s' -- letters, digits, "
                    "_ and - only", dname, (int)nlen, nstart);
            }
        }
        while (*cur == ' ' || *cur == '\t') cur++;
        char op = *cur;
        if (op != '+' && op != '-' && op != '=') {
            return apr_psprintf(pool,
                "%s: BotShieldScore %.*s -- the movement must start "
                "with + - or =, e.g. '+10'", dname, (int)nlen, nstart);
        }
        cur++;
        if (!*cur) {
            return apr_psprintf(pool,
                "%s: BotShieldScore %.*s %c -- no number after the "
                "operator", dname, (int)nlen, nstart, op);
        }
        char *end = NULL;
        long v = strtol(cur, &end, 10);
        if (!end || *end || v < 0 || v > BS_NAMED_SCORE_MAX) {
            return apr_psprintf(pool,
                "%s: BotShieldScore %.*s %c%s -- expected an integer "
                "in 0..%d", dname, (int)nlen, nstart, op, cur,
                BS_NAMED_SCORE_MAX);
        }
        if (!a->score_ops) {
            a->score_ops = apr_array_make(pool, 2, sizeof(bs_score_op *));
        }
        bs_score_op *sop = apr_pcalloc(pool, sizeof(*sop));
        sop->name  = apr_pstrmemdup(pool, nstart, nlen);
        sop->op    = op;
        sop->value = (int)v;
        *(bs_score_op **)apr_array_push(a->score_ops) = sop;
        /* Same rule BotShieldChallenge follows: a rule that only moves
         * a score has said nothing about a response, so it passes and
         * the walk carries on. Without this it would refuse with the
         * family default of 403, which is not what "score this" means. */
        if (!a->status_explicit) {
            a->status_code = BS_TRIGGER_STATUS_PASS;
            a->status_explicit = 1;
        }
        return NULL;
    }
    if (BS_AK("respond") || BS_AK("status")) {
        /* BotShieldRespond is the name; BotShieldStatus is the old
         * spelling and warns.
         *
         * "Status" is the word Apache already spends on mod_status and
         * server-status, and this module ships a dashboard and a
         * metrics endpoint of its own -- so in this config the old name
         * read as a monitoring surface rather than as the response a
         * rule produces. Nothing in Apache names a response code
         * "Status": Redirect and ErrorDocument take one as an argument,
         * and mod_rewrite spells it [R=404].
         *
         * Warns rather than fails, for the same reason the
         * BotShieldRequestTrigger rename does: a config error is fatal
         * to httpd and this spelling is in live configs. */
        const char *kspell = BS_AK("status") ? "status" : "respond";
        if (BS_AK("status")) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                "mod_botshield: %s: BotShieldStatus is deprecated and "
                "will be removed; rename it to BotShieldRespond. Same "
                "values, same behaviour.", dname);
        }
        /* 'nochallenge' is the name; 'pass' is the same thing spelled
         * the way it was before the name said what it meant. It waives
         * the challenge only -- rate limits and robots.txt still apply
         * to a request that took this branch -- and the shorter spelling
         * invited the opposite reading.
         *
         * 'pass' is no longer accepted. It was measurably ambiguous
         * rather than theoretically so: the decision log emitted
         * tier=pass on 14,066 lines of a single day here, meaning the
         * same thing, so an operator grepping for one sense got both
         * and had no way to separate them. */
        if (!strcasecmp(val, "nochallenge")) {
            a->status_code = BS_TRIGGER_STATUS_PASS;
        } else {
            char *end = NULL;
            long code = strtol(val, &end, 10);
            if (!end || *end || code < 100 || code > 599) {
                return apr_psprintf(pool,
                    "%s: %s='%s' must be an HTTP code 100..599 "
                    "or 'nochallenge'",
                    dname, kspell, val);
            }
            a->status_code = (int)code;
        }
        a->status_explicit = 1;
    } else if (BS_AK("challenge")) {
        /* BotShieldChallenge <tier> -- what BotShieldTier said, plus
         * the thing it always needed alongside it.
         *
         * `tier=` required `status=nochallenge` as a companion, because
         * a concrete status short-circuits before any tier is chosen.
         * That companion carried no meaning of its own: you wrote it to
         * be allowed to write the line you actually wanted. Issuing a
         * challenge already implies producing no other response, so
         * this sets both and the companion disappears.
         *
         * Also names an act rather than a taxonomy. "Tier" is what the
         * levels are called internally; "challenge" is what the rule
         * does. */
        if      (!strcasecmp(val, "noninteractive"))
            a->tier_floor = BS_TIER_NONINTERACTIVE;
        else if (!strcasecmp(val, "interactive"))
            a->tier_floor = BS_TIER_INTERACTIVE;
        else if (!strcasecmp(val, "captcha"))
            a->tier_floor = BS_TIER_CAPTCHA;
        else return apr_psprintf(pool,
            "%s: BotShieldChallenge '%s' must be noninteractive, "
            "interactive or captcha. To make a rule decide nothing, "
            "write BotShieldNoChallenge instead.", dname, val);
        if (!a->status_explicit) {
            a->status_code = BS_TRIGGER_STATUS_PASS;
            a->status_explicit = 1;
        }
    } else if (BS_AK("tier")) {
        if      (!strcasecmp(val, "nochallenge")) a->tier_floor = BS_TIER_PASS;
        else if (!strcasecmp(val, "noninteractive"))
            a->tier_floor = BS_TIER_NONINTERACTIVE;
        /* The form/hard alias this used to carry is gone. It existed
         * because the wire string said "form" while the threshold
         * directive said Hard, so an operator could not guess which
         * surface they were on. One name on every surface now. */
        else if (!strcasecmp(val, "interactive"))
            a->tier_floor = BS_TIER_INTERACTIVE;
        else if (!strcasecmp(val, "captcha")) a->tier_floor = BS_TIER_CAPTCHA;
        else return apr_psprintf(pool,
            "%s: tier='%s' must be nochallenge/noninteractive/interactive/"
            "captcha", dname, val);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
            "mod_botshield: %s: BotShieldTier is deprecated and will be "
            "removed; write BotShieldChallenge <tier>, which needs no "
            "BotShieldRespond nochallenge alongside it.", dname);
    } else if (BS_AK("redirect")) {
        if (fam == BS_TFAMILY_ENV || fam == BS_TFAMILY_LOAD) {
            return apr_psprintf(pool,
                "%s: redirect= is not supported on this family "
                "(scoring/flagging only; use the path or cookie "
                "family for response-shaping redirects)", dname);
        }
        if (!*val) {
            return apr_psprintf(pool,
                "%s: redirect= requires a URL", dname);
        }
        a->redirect_url = apr_pstrdup(pool, val);
    } else if (BS_AK("logas") || BS_AK("log")) {
        /* BotShieldLogAs sets the tag embedded on the decision-log
         * line this request was going to emit anyway. It does not
         * cause logging, which is what the old name implied -- an
         * operator could reasonably read BotShieldLog as the thing
         * that produces the log entry, and removing it as a way to
         * stop one. "As" says the value is a name. */
        if (BS_AK("log")) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                "mod_botshield: %s: BotShieldLog is deprecated and will "
                "be removed; write BotShieldLogAs. It labels the "
                "decision line, it does not cause it.", dname);
        }
        if (!*val) {
            return apr_psprintf(pool,
                "%s: a log tag cannot be empty", dname);
        }
        /* Reject the shape that briefly meant "suppress" during
         * development. Silently treating it as a tag named "off" would
         * strip suppression from a config that depended on it; failing
         * loudly costs nothing and names the replacement. */
        if (strcasecmp(val, "off") == 0) {
            return apr_psprintf(pool,
                "%s: log=off is not a tag and no longer suppresses "
                "logging - use accesslog=off, which composes with "
                "log=<tag> so a rule can carry a fail2ban tag AND "
                "keep its request out of the access log", dname);
        }
        a->log_tag = apr_pstrdup(pool, val);
    } else if (BS_AK("accesslog")) {
        /* Independent of log= on purpose: the canonical use is a
         * scanner probe that wants BOTH a tag for fail2ban handoff and
         * no access-log line. Overloading log= made those mutually
         * exclusive, which cost the tag on exactly the traffic most
         * worth tagging. */
        if (strcasecmp(val, "off") == 0) {
            a->suppress_access_log = 1;
        } else if (strcasecmp(val, "on") == 0) {
            a->suppress_access_log = 0;
        } else {
            return apr_psprintf(pool,
                "%s: accesslog=%s must be 'on' or 'off' ('off' drops "
                "the access-log line for a matching request; the "
                "module's own decision record is unaffected)",
                dname, val);
        }
    } else if (BS_AK("flag")) {
        if (fam == BS_TFAMILY_LOAD) {
            return apr_psprintf(pool,
                "%s: flag= is not supported on load triggers "
                "(load is global state; flagging individual IPs "
                "because the host is hot doesn't fit the model — "
                "use a cookie or env trigger if you want per-IP "
                "memory tied to a load condition)", dname);
        }
        const char *perr = NULL;
        apr_uint32_t bits = bs_parse_flag_names(pool, val, &perr);
        if (perr) return apr_psprintf(pool,
            "%s: flag=%s: %s", dname, val, perr);
        if (bits == 0 || (bits & (bits - 1)) != 0) {
            return apr_psprintf(pool,
                "%s: flag=%s must name exactly one bit",
                dname, val);
        }
        a->flag_bit = bits;
        /* BotShieldFlag names no subject, and the subject is the whole
         * question: an address is shared and a cookie is not. It also
         * cannot express the credit flags safely, since those describe
         * a session. BotShieldFlagIP and BotShieldFlagSession say
         * which, and refuse the combinations that do not make sense. */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
            "mod_botshield: %s: BotShieldFlag is deprecated and will be "
            "removed; write BotShieldFlagIP or BotShieldFlagSession, "
            "which name the subject the mark is written to.", dname);
    } else if (BS_AK("flagip") || BS_AK("flagsession")) {
        int to_session = BS_AK("flagsession");
        const char *dirname = to_session ? "BotShieldFlagSession"
                                         : "BotShieldFlagIP";
        apr_uint32_t add = 0, del = 0;
        int replace = 0;
        const char *perr = bs_parse_flag_ops(pool, val, &add, &del, &replace);
        if (perr) {
            return apr_psprintf(pool, "%s: %s %s", dname, dirname, perr);
        }
        /* Clearing is available only where the assertion is
         * authenticated. Every other family fires on request properties
         * the client controls, so '-' or '=' there would be a
         * reputation-laundering primitive: fetch the matching URL,
         * shed your own record. Feedback fires on an app-signed header,
         * where the application asserts it and the requester cannot. */
        if ((del || replace) && fam != BS_TFAMILY_FEEDBACK) {
            return apr_psprintf(pool,
                "%s: %s: '-' and '=' are only allowed on "
                "BotShieldFeedbackTrigger. A rule matches on request "
                "properties the client controls, so clearing here would "
                "let any client clear its own record by fetching the "
                "matching URL.", dname, dirname);
        }
        apr_uint32_t bits = add;
        if (!to_session && ((add | del) & BS_FLAGS_SESSION_ONLY)) {
            return apr_psprintf(pool,
                "%s: BotShieldFlagIP cannot set app_verified_human, "
                "app_verified_session or app_trust_signal -- those "
                "describe one session, and on an address every client "
                "sharing it inherits the credit. Use "
                "BotShieldFlagSession.", dname);
        }
        if (to_session) {
            a->flag_session         = add;
            a->flag_session_clear   = del;
            a->flag_session_replace = replace;
        } else {
            a->flag_ip         = add;
            a->flag_ip_clear   = del;
            a->flag_ip_replace = replace;
        }
        (void)bits;
    } else if (BS_AK("ttl")) {
        if (fam == BS_TFAMILY_LOAD) {
            return apr_psprintf(pool,
                "%s: ttl= has no effect on load triggers (no flag "
                "is written, so there's nothing for ttl to govern)",
                dname);
        }
        char *end = NULL;
        long t = strtol(val, &end, 10);
        if (!end || *end || t < 0 || t > 86400 * 30) {
            return apr_psprintf(pool,
                "%s: ttl='%s' must be 0..2592000 (0 = don't flag)",
                dname, val);
        }
        a->ttl_sec = (int)t;
        /* A per-rule duration cannot be honoured: the address slot
         * holds one expiry shared by every flag on it, extended to
         * whichever rule wrote last. BotShieldForgetIPAfter is that
         * one window, said once, at the scope where it is true. */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
            "mod_botshield: %s: BotShieldTTL is deprecated and will be "
            "removed; the address window is BotShieldForgetIPAfter at "
            "server scope. A per-rule duration was never honoured -- "
            "one address slot holds one expiry for all its flags.",
            dname);
    } else if (BS_AK("penalty")) {
        char *end = NULL;
        long pn = strtol(val, &end, 10);
        if (!end || *end || pn < 0 || pn > 1000) {
            return apr_psprintf(pool,
                "%s: penalty='%s' must be 0..1000", dname, val);
        }
        a->penalty = (int)pn;
    } else if (BS_AK("mode")) {
        /* observe vs enforce. Default enforce; observe makes the
         * rule log a :observe match without applying side effects.
         * For feedback triggers the side effect is the flagged-IP
         * write; observe-mode means "log would-have-flagged but
         * skip the SHM mutation", which is the same staging gate
         * operators get for the other families. The bridge.c
         * filter already honors a->mode == BS_TMODE_OBSERVE. */
        if (!strcasecmp(val, "enforce")) {
            a->mode = BS_TMODE_ENFORCE;
        } else if (!strcasecmp(val, "observe")) {
            a->mode = BS_TMODE_OBSERVE;
        } else {
            return apr_psprintf(pool,
                "%s: mode='%s' must be 'enforce' or 'observe'",
                dname, val);
        }
    } else if (BS_AK("credit")) {
        if (fam == BS_TFAMILY_REQUEST) {
            return apr_psprintf(pool,
                "%s: credit= is not supported on path triggers "
                "(path matches are discrete events; running "
                "reputation belongs on cookie or env triggers)",
                dname);
        }
        char *end = NULL;
        long cn = strtol(val, &end, 10);
        if (!end || *end || cn < 0 || cn > 1000) {
            return apr_psprintf(pool,
                "%s: credit='%s' must be 0..1000", dname, val);
        }
        a->credit = (int)cn;
    } else {
        return apr_psprintf(pool,
            "%s: unknown key '%.*s' (known: %s)",
            dname, (int)klen, arg, bs_trigger_known_keys(fam));
    }
    #undef BS_AK
    return NULL;
}

static const char *bs_finalize_trigger_action(apr_pool_t *pool,
                                              bs_trigger_family fam,
                                              bs_trigger_action *a)
{
    const char *dname = bs_trigger_family_dname(fam);
    /* No flag without a TTL — clear the bit so the request-time
     * walk skips the flag_ip call and the decision log stays
     * honest about what persisted. */
    if (a->ttl_sec == 0) a->flag_bit = 0;

    /* Feedback triggers without an actionable flag are dead config —
     * the mapping has nowhere to land. Reject at parse time so
     * operators see it via configtest rather than as silent no-ops
     * at runtime. */
    if (fam == BS_TFAMILY_FEEDBACK) {
        /* The deprecated pair still needs its own ttl; the new
         * directives use the server-scope window, so naming a flag is
         * enough. Either way an event with nowhere to land is dead
         * config and is refused at parse time. */
        if (!a->flag_bit && !a->flag_ip && !a->flag_session
            && !a->flag_ip_clear && !a->flag_session_clear
            && !a->flag_ip_replace && !a->flag_session_replace) {
            return apr_psprintf(pool,
                "%s: feedback triggers must set BotShieldFlagIP or "
                "BotShieldFlagSession; the event mapping has no "
                "request-time surface otherwise", dname);
        }
        return NULL;   /* status/redirect checks don't apply here */
    }

    if (a->redirect_url) {
        if (a->status_code == BS_TRIGGER_STATUS_PASS) {
            return apr_psprintf(pool,
                "%s: status=pass and redirect= are mutually exclusive "
                "— a redirect IS the response", dname);
        }
        if (!a->status_explicit) {
            /* Default 302 when redirect is set without an explicit
             * status; lets operators write `redirect=<url>` without
             * also spelling out status=302. */
            a->status_code = 302;
            a->status_explicit = 1;
        }
        if (a->status_code < 300 || a->status_code >= 400) {
            return apr_psprintf(pool,
                "%s: redirect= requires a 3xx status (got %d)",
                dname, a->status_code);
        }
    }
    return NULL;
}

bs_trigger_exec_outcome bs_apply_trigger_action(
    request_rec *r,
    struct bs_server_cfg *scfg,
    bs_trigger_family fam,
    const bs_trigger_action *a,
    const char *family_tag,
    const char *trigger_name)
{
    /* Log-only / observe-mode short-circuit. If the rule is
     * observe-only, OR the dir scope is in LogOnly mode, log the match
     * with a :observe suffix and return without applying any side
     * effect (no flag-IP, no score, no status, no redirect, no log
     * tag — observe is a "what would have happened" probe).
     * Caller's loop treats BS_TEXEC_OBSERVE as `continue` so the
     * next rule still gets a chance — observed rules never shadow
     * enforced ones. */
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    int global_log_only = (dcfg && dcfg->enabled == BS_ENABLED_LOGONLY);
    int observe = global_log_only || (a->mode == BS_TMODE_OBSERVE);
    if (observe) {
        bs_score_add(r, 0, 0,
            apr_pstrcat(r->pool, family_tag, ":", trigger_name,
                        ":observe", NULL));
        /* If the rule's action carried a client-visible status
         * (block / rate-limit), surface that as a ~ counterfactual
         * on the outcome field. Pure flag-write or score-only
         * triggers don't change the outcome under observe. */
        if (a->status_code == HTTP_TOO_MANY_REQUESTS) {
            bs_set_would_outcome(r, "~rate_limited");
        } else if (a->status_code >= 400) {
            bs_set_would_outcome(r, "~block");
        }
        /* Named accumulators still move, but only when the
         * suppression is scope-wide LogOnly rather than this rule's
         * own mode=observe.
         *
         * The two are different requests. mode=observe is one rule its
         * author asked to contribute nothing, so it contributes
         * nothing. LogOnly is "do not act, and tell me what you would
         * have done" -- and a decision computed without its inputs is
         * not the decision that would have been made. It is a
         * different, quieter one, reported as if it were the same.
         *
         * The line this splits on is per-request evidence against
         * side effects that outlive the request. A named score lives
         * for one request and feeds only this request's decision. The
         * flag-IP write above is the other kind: it is state for
         * future requests, LogOnly must not write it, and it stays
         * above this point deliberately. */
        if (global_log_only && a->mode != BS_TMODE_OBSERVE
         && a->score_ops) {
            for (int i = 0; i < a->score_ops->nelts; i++) {
                const bs_score_op *sop =
                    APR_ARRAY_IDX(a->score_ops, i, const bs_score_op *);
                bs_request_named_score_apply(r, sop->name, sop->op,
                                             sop->value);
            }
        }
        if (bs_shm.metrics) {
            __atomic_fetch_add(&bs_shm.metrics->trigger_observed_total,
                               1, __ATOMIC_RELAXED);
        }
        return BS_TEXEC_OBSERVE;
    }

    /* Flag-IP (future-request memory). Applies to all families
     * uniformly — flag_bit is already 0 when ttl_sec==0, so the
     * guard below is belt-and-suspenders. */
    {
        /* Two spellings converge here. The deprecated flag=/ttl= pair
         * carries its own duration; BotShieldFlagIP uses the
         * server-scope window, because one address slot holds a single
         * expires_at shared by all its flags. */
        apr_uint32_t ip_bits = a->flag_ip;
        int ip_ttl = scfg->forget_ip_after > 0
                   ? scfg->forget_ip_after : BS_DEFAULT_FORGET_IP_AFTER;
        if (a->flag_bit && a->ttl_sec > 0) {
            ip_bits |= a->flag_bit;
            ip_ttl   = a->ttl_sec;
        }
        if (ip_bits || a->flag_ip_clear || a->flag_ip_replace) {
            unsigned char client_ip[16];
            if (bs_parse_client_ip(r->useragent_ip, client_ip)) {
                bs_mask_ipv6_prefix(client_ip, scfg->ipv6_prefix_bits);
                if (a->flag_ip_clear || a->flag_ip_replace) {
                    bs_flagged_ip_clear(r, client_ip, a->flag_ip_clear,
                                        a->flag_ip, a->flag_ip_replace,
                                        scfg->ns_id);
                } else {
                    bs_flagged_ip_add(r, client_ip, ip_bits, ip_ttl,
                                      scfg->ns_id);
                }
            }
        }
    }
    /* Session flags ride to the single mint point rather than minting a
     * cookie here. The removed burn= minted its own and had to unset
     * both Set-Cookie
     * tables to stop the ordinary mint overwriting it; accumulating in
     * a note means one cookie, no race, and several rules can
     * contribute to it. */
    if (a->flag_session || a->flag_session_clear
        || a->flag_session_replace) {
        /* add:del:replace, accumulated across every rule that fires on
         * this request and applied once at the mint. */
        apr_uint32_t add = 0, del = 0;
        int replace = 0;
        const char *prev = apr_table_get(r->notes, "bs-session-flags");
        if (prev) {
            unsigned a_, d_, rp_;
            if (sscanf(prev, "%x:%x:%u", &a_, &d_, &rp_) == 3) {
                add = a_; del = d_; replace = (int)rp_;
            }
        }
        if (a->flag_session_replace) {
            /* A later '=' is the whole set; earlier deltas are moot. */
            add = a->flag_session;
            del = 0;
            replace = 1;
        } else {
            add |= a->flag_session;
            del |= a->flag_session_clear;
            add &= ~a->flag_session_clear;
        }
        apr_table_setn(r->notes, "bs-session-flags",
                       apr_psprintf(r->pool, "%x:%x:%u", add, del,
                                    (unsigned)replace));
    }
    /* Named accumulators move as soon as the rule matches, before
     * any decision this rule makes -- a rule that scores and then
     * refuses still leaves the movement behind for the log to show. */
    if (a->score_ops) {
        for (int i = 0; i < a->score_ops->nelts; i++) {
            const bs_score_op *sop =
                APR_ARRAY_IDX(a->score_ops, i, const bs_score_op *);
            bs_request_named_score_apply(r, sop->name, sop->op,
                                         sop->value);
        }
    }

    bs_set_trigger_tag(r, a->log_tag);

    /* accesslog=off. Deliberately placed after the observe short-circuit
     * above, so a dry run still leaves its evidence in the log. */
    if (a->suppress_access_log) {
        bs_suppress_access_log(r);
    }

    int is_pass = (a->status_code == BS_TRIGGER_STATUS_PASS);

    if (is_pass) {
        if (fam == BS_TFAMILY_REQUEST) {
            if (a->tier_floor >= 0 || a->penalty || a->credit
             || a->score_ops) {
                /* tier= turns the match into "challenge this", not
                 * "ignore this". Score contribution and the floor
                 * both apply, and we return CONTINUE so the caller
                 * keeps walking into the scoring pipeline instead of
                 * declining out of the handler. */
                /* status=pass with score-shaping and/or a tier
                 * demand. Either way the request must reach the
                 * scoring pipeline, so CONTINUE rather than the bare
                 * pass's DECLINE. A bare status=pass with neither key
                 * keeps its original log-only meaning below. */
                int d = a->penalty - a->credit;
                const char *why = (a->tier_floor >= 0)
                    ? apr_pstrcat(r->pool, family_tag, ":", trigger_name,
                                  ":tier-", bs_tier_name(a->tier_floor),
                                  NULL)
                    : apr_pstrcat(r->pool, family_tag, ":", trigger_name,
                                  NULL);
                bs_score_add(r, d, 0, why);
                if (a->tier_floor >= 0) {
                    bs_set_request_tier_floor(r, a->tier_floor);
                }
                return BS_TEXEC_PASS_CONTINUE;
            }
            /* Path pass: record the match for the decision-log
             * reason trace but do NOT bump the score. "nochallenge" here
             * means "don't enforce anything on this request" — the
             * flag-IP side-effect above is the trigger's only
             * future-request surface. */
            bs_score_add(r, 0, 0,
                apr_pstrcat(r->pool, family_tag, ":", trigger_name,
                            ":pass", NULL));
            return BS_TEXEC_PASS_DECLINE;
        }
        /* Cookie/env/load/scope pass: apply penalty - credit on
         * THIS request's score. The signal is part of this
         * request's decision state (cookie carried, env set, host
         * hot, scope matched), so the score contribution belongs
         * here. */
        int delta = a->penalty - a->credit;
        bs_score_add(r, delta, 0,
            apr_pstrcat(r->pool, family_tag, ":", trigger_name, NULL));
        if (fam == BS_TFAMILY_COOKIE) return BS_TEXEC_PASS_CONTINUE;
        /* Scope: multiple BotShieldTrigger directives in the same
         * scope are independent declarations, all should fire on
         * a pass — caller's loop continues to the next entry. */
        if (fam == BS_TFAMILY_SCOPE)  return BS_TEXEC_PASS_CONTINUE;
        /* env + load: first-match-wins. Distinct load triggers
         * (state>=warm vs state=hot) are alternative-specificity
         * cases, not layered reputation — one match is enough. */
        return BS_TEXEC_PASS_BREAK;
    }

    /* Concrete status. Record reason; caller emits Location + the
     * status_code. Path family historically ignored `credit` — the
     * parser rejects credit= for path so a->credit is always 0 and
     * `penalty - credit` collapses to `penalty` for path too. */
    int delta = a->penalty - a->credit;
    bs_score_add(r, delta, 0,
        apr_pstrcat(r->pool, family_tag, ":", trigger_name, NULL));

    if (a->redirect_url) {
        apr_table_setn(r->headers_out, "Location", a->redirect_url);
    }
    return BS_TEXEC_STATUS;
}

/* BotShieldRequestTrigger <name> [key=value ...].
 *
 * The family matches on up to six dimensions -- path, query, cookies,
 * exists, ua and ipspec -- so no single one of them belongs in the
 * directive name or in a positional slot.
 *
 * Every match dimension is optional and they AND together. Making path
 * a key is what lets a rule match on query or cookie state at ANY path,
 * which the positional form could not express. A rule with no match
 * dimension at all is rejected: that is the per-scope BotShieldTrigger's
 * job, and silently matching every request is too sharp an edge. */
/* Is `ua` a comma list of @selectors, e.g. "@search,@ai-input"?
 *
 * Only @selectors split. A bare substring pattern is passed through
 * untouched, because a User-Agent legitimately contains commas
 * ("Mozilla/5.0 (X11; Linux x86_64)") and splitting those would
 * silently change what a rule matches. */
static int bs_ua_is_selector_list(const char *ua)
{
    if (!ua || ua[0] != '@' || !strchr(ua, ',')) return 0;
    for (const char *p = ua; *p; p++) {
        if (*p == ',' && p[1] != '@') return 0;
    }
    return 1;
}

/* A rule that demands a tier but never asks whether the client already
 * solved will challenge the same visitor on every request, forever.
 * Solving does not clear it, because nothing in the rule looks at the
 * solve proof.
 *
 * Diagnosed three times before this warning existed: /silent-demo and
 * /form-demo in the test config (which is why the browser suite could
 * not complete a challenge -> solve -> served round trip), and
 * admin-user on production, where 599 of 601 challenges in one day
 * went to clients already carrying cookie=solved -- an admin could not
 * reach the login page at all.
 *
 * Warned from the setter rather than post_config so `httpd -t` shows
 * it -- a warning an operator only sees after deploying is most of the
 * way to no warning. Apache does not run post_config on a -t
 * invocation at all (verified by probe; the first-pass guard is not
 * the mechanism). The hook -t does run is test_config, which is where
 * -D DUMP_BOTSHIELD_POLICY lives.
 *
 * A warning, not an error: challenging every time is legitimate for a
 * honeypot or a path no real client should reach. But it should be a
 * decision, and `tier=` reads like "challenge this" rather than
 * "challenge this forever", so the default reading is the wrong one. */
static void bs_warn_tier_without_solved(cmd_parms *cmd,
                                        const bs_request_trigger_entry *e)
{
    if (e->action.tier_floor < 0 || e->solved_pred >= 0) return;
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
        "mod_botshield: BotShieldRequestTrigger '%s' sets tier= but has "
        "no solved= condition, so it re-challenges clients that have "
        "already solved -- an endless loop for real visitors. Add "
        "solved=no to challenge once; ignore this if the path is meant "
        "to challenge every time.", e->name);
}

const char *bs_set_request_trigger(cmd_parms *cmd, void *dconf,
                                       int argc, char *const argv[])
{
    (void)dconf;
    /* Names the family in every message this setter emits. The
     * canonical spelling is BotShieldRule; <BotShieldRequestTrigger>
     * still parses but is deprecated, and an operator using it is
     * being pointed at the name to migrate to anyway. */
    static const char *D = "BotShieldRule";
    if (argc < 1) {
        return "BotShieldRequestTrigger: expects <name> [key=value ...] "
               "with at least one of path= query= cookies= ua= ipspec=";
    }
    const char *name = argv[0];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "%s: name '%s' must be [a-z0-9-]{1,32}", D, name);
    }
    /* Catch the retired positional form rather than let it fall through
     * to the action-key parser as an unknown key. */
    if (argc >= 2 && argv[1][0] == '/') {
        return apr_psprintf(cmd->pool,
            "%s: the path glob is now a key, not a positional argument - "
            "write path=\"%s\" instead of a bare %s", D, argv[1], argv[1]);
    }

    bs_request_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name        = apr_pstrdup(cmd->pool, name);
    e->cookie_pred = -1;              /* no cookie condition */
    e->exists_pred = -1;              /* no filesystem condition */
    e->solved_pred = -1;              /* no solve-proof condition */
    e->firstsight_pred = -1;          /* no Bloom-membership condition */
    e->acceptlang_pred = -1;          /* no Accept-Language condition */
    e->score_pred_name = NULL;        /* no accumulator condition */
    e->score_pred_min  = 0;
    e->bscookie_pred = -1;            /* no bs-cookie condition */
    e->crawler_pred  = -1;            /* no crawler condition */
    e->minload     = -1;              /* no load condition */
    bs_trigger_action_init(BS_TFAMILY_REQUEST, &e->action);

    const char *ua_arg = NULL, *ipspec_arg = NULL;
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq  = strchr(arg, '=');
        if (eq) {
            apr_size_t klen = (apr_size_t)(eq - arg);
            const char *val = bs_unquote(cmd->pool, eq + 1);
            if (klen == 4 && strncasecmp(arg, "path", 4) == 0) {
                /* Comma-separated list. Each element is validated on
                 * its own so the error names the offending path rather
                 * than the whole string. */
                if (!*val) {
                    return apr_psprintf(cmd->pool,
                        "%s: path= requires at least one path", D);
                }
                if (strlen(val) > 1024) {
                    return apr_psprintf(cmd->pool,
                        "%s: path= list longer than 1024 chars", D);
                }
                /* Accumulate: the block walker hands one token per
                 * BotShieldPath line, and each token is a whole path.
                 * It is not split on anything, because every delimiter
                 * worth using is legal inside a path -- comma by RFC
                 * 3986, and whitespace never survives Apache's own argv
                 * split to reach here. */
                if (!e->path_patterns) {
                    e->path_patterns = apr_array_make(cmd->pool, 4,
                                                      sizeof(const char *));
                }
                {
                    char *tok = apr_pstrdup(cmd->pool, val);
                    while (*tok == ' ' || *tok == '\t') tok++;
                    apr_size_t tl = strlen(tok);
                    while (tl && (tok[tl-1] == ' ' || tok[tl-1] == '\t')) {
                        tok[--tl] = '\0';
                    }
                    if (!*tok) {
                        return apr_psprintf(cmd->pool,
                            "%s: path= is empty", D);
                    }
                    if (tok[0] == '"' || strchr(tok, '"')) {
                        /* Apache splits argv on whitespace before we
                         * see it, so a space inside the list arrives
                         * as separate arguments with the quotes still
                         * attached. Say that, rather than leaving the
                         * operator staring at a stray quote in a
                         * "must start with /" message. */
                        return apr_psprintf(cmd->pool,
                            "%s: path must not contain spaces (got "
                            "'%s'). Apache splits the directive on "
                            "whitespace before the module sees it. Write "
                            "one BotShieldPath per path; a comma is a "
                            "legal path character and does not separate "
                            "a list.",
                            D, tok);
                    }
                    if (tok[0] != '/') {
                        return apr_psprintf(cmd->pool,
                            "%s: path= element '%s' must start with '/'",
                            D, tok);
                    }
                    if (tl > 256) {
                        return apr_psprintf(cmd->pool,
                            "%s: path= element '%s' longer than 256 chars",
                            D, tok);
                    }
                    bs_path_pattern_warn_middle_star(cmd, D, name, tok);
                    *(const char **)apr_array_push(e->path_patterns) =
                        apr_pstrdup(cmd->pool, tok);
                }
                if (e->path_patterns->nelts == 0) {
                    return apr_psprintf(cmd->pool,
                        "%s: path= contained no usable path", D);
                }
                continue;
            }
            if (klen == 5 && strncasecmp(arg, "query", 5) == 0) {
                if (!*val) {
                    return apr_psprintf(cmd->pool,
                        "%s: query= requires a glob (e.g. query=\"*return=*\")",
                        D);
                }
                if (strlen(val) > 256) {
                    return apr_psprintf(cmd->pool,
                        "%s: query= longer than 256 chars", D);
                }
                e->query_pattern = apr_pstrdup(cmd->pool, val);
                continue;
            }
            if (klen == 6 && strncasecmp(arg, "solved", 6) == 0) {
                if      (!strcasecmp(val, "yes")) e->solved_pred = 1;
                else if (!strcasecmp(val, "no"))  e->solved_pred = 0;
                else {
                    return apr_psprintf(cmd->pool,
                        "%s: solved='%s' not one of yes|no", D, val);
                }
                continue;
            }
            if (klen == 14
             && strncasecmp(arg, "acceptlanguage", 14) == 0) {
                if      (!*val)                 e->acceptlang_pred = 0;
                else if (!strcmp(val, "*"))     e->acceptlang_pred = 1;
                else {
                    return apr_psprintf(cmd->pool,
                        "%s: acceptlanguage='%s' -- only \"\" (absent "
                        "or empty) and * (present) are accepted; this "
                        "is the missingal signal as a condition, not a "
                        "header matcher", D, val);
                }
                continue;
            }
            if (klen == 12
             && strncasecmp(arg, "scoreatleast", 12) == 0) {
                const char *cur = val;
                while (*cur == ' ' || *cur == '\t') cur++;
                const char *nstart = cur;
                while (*cur && *cur != ' ' && *cur != '\t') cur++;
                apr_size_t nlen = (apr_size_t)(cur - nstart);
                while (*cur == ' ' || *cur == '\t') cur++;
                char *end = NULL;
                long v = strtol(cur, &end, 10);
                if (!nlen || !*cur || !end || *end
                 || v < -BS_NAMED_SCORE_MAX || v > BS_NAMED_SCORE_MAX) {
                    return apr_psprintf(cmd->pool,
                        "%s: BotShieldScoreAtLeast needs a name then a "
                        "number, e.g. 'BotShieldScoreAtLeast suspicion "
                        "15'", D);
                }
                e->score_pred_name = apr_pstrmemdup(cmd->pool, nstart, nlen);
                e->score_pred_min  = (int)v;
                continue;
            }
            if (klen == 10 && strncasecmp(arg, "firstsight", 10) == 0) {
                if      (!strcasecmp(val, "yes")) e->firstsight_pred = 1;
                else if (!strcasecmp(val, "no"))  e->firstsight_pred = 0;
                else {
                    return apr_psprintf(cmd->pool,
                        "%s: firstsight='%s' not one of yes|no", D, val);
                }
                continue;
            }
            if (klen == 7 && strncasecmp(arg, "minload", 7) == 0) {
                if      (!strcasecmp(val, "normal")) e->minload = BS_LOAD_NORMAL;
                else if (!strcasecmp(val, "warm"))   e->minload = BS_LOAD_WARM;
                else if (!strcasecmp(val, "hot"))    e->minload = BS_LOAD_HOT;
                else {
                    return apr_psprintf(cmd->pool,
                        "%s: minload='%s' not one of normal|warm|hot", D, val);
                }
                continue;
            }
            if (klen == 6 && strncasecmp(arg, "exists", 6) == 0) {
                if      (!strcasecmp(val, "yes")) e->exists_pred = 1;
                else if (!strcasecmp(val, "no"))  e->exists_pred = 0;
                else {
                    return apr_psprintf(cmd->pool,
                        "%s: exists='%s' not one of yes|no", D, val);
                }
                continue;
            }
            if (klen == 7 && strncasecmp(arg, "crawler", 7) == 0) {
                if      (!strcasecmp(val, "yes")) e->crawler_pred = 1;
                else if (!strcasecmp(val, "no"))  e->crawler_pred = 0;
                else {
                    return apr_psprintf(cmd->pool,
                        "%s: crawler='%s' not one of yes|no", D, val);
                }
                continue;
            }
            if (klen == 8 && strncasecmp(arg, "bscookie", 8) == 0) {
                if      (!strcasecmp(val, "verified")) e->bscookie_pred = BS_BSC_VERIFIED;
                else if (!strcasecmp(val, "missing"))  e->bscookie_pred = BS_BSC_MISSING;
                else if (!strcasecmp(val, "invalid"))  e->bscookie_pred = BS_BSC_INVALID;
                else if (!strcasecmp(val, "unproven")) e->bscookie_pred = BS_BSC_ANY_BAD;
                else {
                    return apr_psprintf(cmd->pool,
                        "%s: bscookie='%s' must be one of verified, "
                        "missing, invalid, unproven (= missing or "
                        "invalid)", D, val);
                }
                continue;
            }
            if (klen == 7 && strncasecmp(arg, "cookies", 7) == 0) {
                /* Bulk forms only. Named-cookie predicates
                 * (cookie=<n>, bs-cookie=<state>, ...) stay with
                 * BotShieldCookieTrigger, whose vocabulary does not
                 * compress into one key. */
                if (strcasecmp(val, "none") == 0) {
                    e->cookie_pred = BS_CP_BULK_NONE;
                } else if (strcasecmp(val, "any") == 0) {
                    e->cookie_pred = BS_CP_BULK_ANY;
                } else if (strcasecmp(val, "session") == 0) {
                    e->cookie_pred = BS_CP_BULK_SESSION;
                } else {
                    return apr_psprintf(cmd->pool,
                        "%s: cookies=%s must be none, any or session "
                        "(named-cookie predicates live on "
                        "BotShieldCookieTrigger)", D, val);
                }
                continue;
            }
            if (klen == 2 && strncasecmp(arg, "ua", 2) == 0) {
                ua_arg = val;
                continue;
            }
            if (klen == 6 && strncasecmp(arg, "ipspec", 6) == 0) {
                ipspec_arg = val;
                continue;
            }
        }
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_REQUEST, arg, &e->action);
        if (err) return err;
    }

    /* A bare `ua=*` / `ipspec=*` means "match any", which is the
     * default, so it is treated as if omitted.
     *
     * `ua=""` is NOT that: an empty value means "no User-Agent header,
     * or an empty one", which is a real restriction and must survive to
     * bs_cohort_resolve. Testing ua_arg[0] alone would drop it here and
     * then reject the whole rule below as having no match key — so the
     * emptiness test is deliberately absent on the ua axis.
     *
     * ipspec keeps its emptiness test: there is no equivalent "absent
     * client IP" to express, so an empty ipspec really is a no-op. */
    int ua_restricts     = ua_arg     && strcmp(ua_arg, "*") != 0;
    int ipspec_restricts = ipspec_arg && ipspec_arg[0] && strcmp(ipspec_arg, "*") != 0;
    if (ua_restricts || ipspec_restricts) {
        const char *ua_eff = ua_restricts     ? ua_arg     : "*";
        const char *ip_eff = ipspec_restricts ? ipspec_arg : "*";
        const char *cerr = bs_cohort_resolve(cmd, &e->cohort, ua_eff, ip_eff);
        if (cerr) return apr_pstrcat(cmd->pool, D, ": ", cerr, NULL);
        e->has_cohort = 1;
    }

    if (!e->path_patterns && !e->query_pattern
        && e->bscookie_pred < 0 && e->crawler_pred < 0
        && e->cookie_pred < 0 && e->exists_pred < 0
        && e->solved_pred < 0 && e->minload < 0
        && e->firstsight_pred < 0 && e->acceptlang_pred < 0
        && !e->score_pred_name
        && !e->has_cohort) {
        return apr_psprintf(cmd->pool,
            "%s '%s': needs at least one match key (path=, query=, "
            "cookies=, bscookie=, crawler=, exists=, solved=, firstsight=, "
            "acceptlanguage=, minload=, ua=, "
            "ipspec=). A rule "
            "with no condition "
            "matches every request - use BotShieldTrigger in the scope "
            "you mean instead", D, name);
    }

    const char *err = bs_finalize_trigger_action(cmd->pool,
        BS_TFAMILY_REQUEST, &e->action);
    if (err) return err;

    /* `ua=@a,@b` becomes one entry per alternative.
     *
     * Expanded here rather than by teaching the cohort to hold a list,
     * because this family is strict first-match-wins: N adjacent
     * entries differing only on the UA axis, carrying identical
     * actions, are exactly equivalent to one entry with an OR -- and
     * need no change to the struct or to the request-path matcher.
     *
     * That duplication is why four near-identical /api rules existed:
     * same path, same action, one token apart.
     *
     * Each copy takes a #N name so upsert-by-name stays exact. The
     * decision log is unaffected: it reports the action's log= tag,
     * which every copy shares. */
    if (bs_ua_is_selector_list(ua_arg)) {
        char *list = apr_pstrdup(cmd->pool, ua_arg);
        char *save = NULL, *tok = apr_strtok(list, ",", &save);
        int n = 0;
        while (tok) {
            while (*tok == ' ' || *tok == '\t') tok++;
            n++;
            bs_request_trigger_entry *c =
                apr_pmemdup(cmd->pool, e, sizeof(*e));
            memset(&c->cohort, 0, sizeof(c->cohort));
            const char *cerr = bs_cohort_resolve(cmd, &c->cohort, tok,
                ipspec_arg && ipspec_arg[0] ? ipspec_arg : "*");
            if (cerr) return apr_pstrcat(cmd->pool, D, ": ", cerr, NULL);
            c->has_cohort = 1;
            if (n > 1) {
                c->name = apr_psprintf(cmd->pool, "%s#%d", e->name, n);
            }
            *(bs_request_trigger_entry **)
                apr_array_push(scfg->request_triggers) = c;
            tok = apr_strtok(NULL, ",", &save);
        }
        return NULL;
    }

    /* Upsert-by-name; preserves declaration order. */
    for (int i = 0; i < scfg->request_triggers->nelts; i++) {
        bs_request_trigger_entry *ex =
            APR_ARRAY_IDX(scfg->request_triggers, i, bs_request_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->request_triggers, i, bs_request_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_request_trigger_entry **)apr_array_push(scfg->request_triggers) = e;
    bs_warn_tier_without_solved(cmd, e);
    return NULL;
}

/* E4 — BotShieldSessionCookieName <name>. Each invocation appends
 * one cookie name to scfg->session_names (lowercased, deduped).
 * The list seeds the `cookies=session` predicate — matches any
 * cookie on the request whose name is in this list. Curated
 * defaults ship (PHPSESSID, JSESSIONID, etc.); this directive lets
 * operators add framework-specific names without editing the
 * module. Short by design — long auto-lists turn `cookies=session`
 * into a loose any-cookie-with-a-suggestive-name matcher. */
const char *bs_set_session_cookie_name(cmd_parms *cmd, void *dconf,
                                              const char *name)
{
    (void)dconf;
    if (!name || !*name) {
        return "BotShieldSessionCookieName: name required";
    }
    apr_size_t nlen = strlen(name);
    if (nlen > 64) {
        return "BotShieldSessionCookieName: name over 64 chars";
    }
    for (apr_size_t i = 0; i < nlen; i++) {
        unsigned char c = (unsigned char)name[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_'
              || c == '.';
        if (!ok) return apr_psprintf(cmd->pool,
            "BotShieldSessionCookieName: '%s' contains invalid "
            "char '%c' (expect [A-Za-z0-9_-.])", name, (char)c);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    char *lower = apr_pstrdup(cmd->pool, name);
    for (char *p = lower; *p; p++) *p = (char)tolower((unsigned char)*p);
    /* Dedup — O(n) scan, list is tiny. */
    for (int i = 0; i < scfg->session_names->nelts; i++) {
        if (strcmp(APR_ARRAY_IDX(scfg->session_names, i,
                                 const char *), lower) == 0) {
            return NULL;
        }
    }
    *(const char **)apr_array_push(scfg->session_names) = lower;
    return NULL;
}

/* E4 — BotShieldCookieTrigger <name> <cookie-match> [key=value ...].
 *
 * Parses the cookie-match predicate (see CHANGELOG.md E4 for the full
 * predicate grammar) and the action keys, enforces cross-
 * validation (status=pass + redirect= is a config error;
 * _bs_session as cookie=name is redirected to bs-cookie=<state>),
 * and upserts by name. See bs_request_trigger_entry for the action-key
 * semantics shared with E3; the semantic divergences are:
 *
 *   - credit= always applies (even under status=pass), because a
 *     cookie is ongoing client state we want to shape this
 *     request's score for.
 *   - penalty= likewise always applies. Contrast E3 where it's
 *     ignored under pass.
 *   - status=pass is the DEFAULT; a credit trigger with no status
 *     set is pass-with-score-shaping. */
static int bs_ishex_or_alnum(char c)
{
    unsigned char u = (unsigned char)c;
    return (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z')
        || (u >= '0' && u <= '9') || u == '-' || u == '_' || u == '.';
}

const char *bs_set_cookie_trigger(cmd_parms *cmd, void *dconf,
                                         int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 2) {
        return "BotShieldCookieTrigger: expects <name> <cookie-match> "
               "[key=value ...]";
    }
    const char *name     = argv[0];
    const char *match    = argv[1];
    bs_server_cfg *scfg  = ap_get_module_config(cmd->server->module_config,
                                                &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldCookieTrigger: name '%s' must be [a-z0-9-]{1,32}",
            name);
    }

    bs_cookie_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name = apr_pstrdup(cmd->pool, name);
    bs_trigger_action_init(BS_TFAMILY_COOKIE, &e->action);

    /* --- Parse the cookie-match predicate. --- */
    const char *m = match;
    int negated = 0;
    if (m[0] == '!') { negated = 1; m++; }
    if (!strncasecmp(m, "cookie=", 7)) {
        const char *rest = m + 7;
        if (!*rest) {
            return "BotShieldCookieTrigger: cookie= needs a name";
        }
        /* Parse cookie name up to '=' / '~' / '!' / end. */
        const char *op = rest;
        while (*op && *op != '=' && *op != '~' && *op != '!') {
            if (!bs_ishex_or_alnum(*op)) {
                return apr_psprintf(cmd->pool,
                    "BotShieldCookieTrigger: cookie name may only "
                    "contain [A-Za-z0-9_-.] (got '%c')", *op);
            }
            op++;
        }
        apr_size_t nlen = (apr_size_t)(op - rest);
        if (nlen == 0 || nlen > 64) {
            return "BotShieldCookieTrigger: cookie name must be 1..64 chars";
        }
        char *cname = apr_pstrmemdup(cmd->pool, rest, nlen);
        /* Reject the module's own cookie at this predicate level;
         * redirect operators to bs-cookie=<state>. */
        if (!strcasecmp(cname, BS_COOKIE_NAME) ||
            !strcasecmp(cname, BS_COOKIE_NAME_HOST)) {
            return "BotShieldCookieTrigger: declaring a predicate "
                   "against the module's own " BS_COOKIE_NAME
                   " (or " BS_COOKIE_NAME_HOST ") cookie is not "
                   "supported — use bs-cookie=verified / "
                   "bs-cookie=missing / bs-cookie=invalid instead";
        }
        e->cname = cname;
        /* Dispatch on the operator chosen. */
        if (*op == '\0') {
            e->pred_kind = negated ? BS_CP_NAMED_ABSENT
                                   : BS_CP_NAMED_PRESENT;
        } else if (negated) {
            return "BotShieldCookieTrigger: '!' prefix may only be "
                   "combined with a bare cookie=<name> (absence "
                   "test); use cookie=<name>!<value> for value "
                   "mismatch";
        } else if (*op == '=') {
            e->pred_kind = BS_CP_NAMED_EQ;
            e->cvalue    = apr_pstrdup(cmd->pool, op + 1);
        } else if (*op == '~') {
            e->pred_kind = BS_CP_NAMED_CONTAINS;
            e->cvalue    = apr_pstrdup(cmd->pool, op + 1);
            if (!*e->cvalue) {
                return "BotShieldCookieTrigger: cookie=<name>~<substr> "
                       "needs a non-empty substring";
            }
        } else if (*op == '!') {
            e->pred_kind = BS_CP_NAMED_NE;
            e->cvalue    = apr_pstrdup(cmd->pool, op + 1);
        }
    } else if (!strncasecmp(m, "cookies=", 8)) {
        if (negated) {
            return "BotShieldCookieTrigger: '!' prefix cannot combine "
                   "with cookies=<state> — use the complementary "
                   "state (cookies=any is the complement of cookies=none)";
        }
        const char *state = m + 8;
        if      (!strcasecmp(state, "none"))    e->pred_kind = BS_CP_BULK_NONE;
        else if (!strcasecmp(state, "any"))     e->pred_kind = BS_CP_BULK_ANY;
        else if (!strcasecmp(state, "session")) e->pred_kind = BS_CP_BULK_SESSION;
        else {
            return apr_psprintf(cmd->pool,
                "BotShieldCookieTrigger: cookies='%s' not one of "
                "none|any|session", state);
        }
    } else if (!strncasecmp(m, "bs-cookie=", 10)
            || !strncasecmp(m, "bscookie=", 9)) {
        /* Both spellings accepted. The request family already called
         * this key `bscookie` while this family wanted `bs-cookie`.
         * Two names for one concept was survivable while each was
         * typed by hand; it stops being survivable once a block's
         * BotShieldBSCookie has to lower-case to one of them. */
        const int keylen = (m[2] == '-') ? 10 : 9;
        if (negated) {
            return "BotShieldCookieTrigger: '!' prefix cannot combine "
                   "with bs-cookie=<state> — use the complementary "
                   "state directly";
        }
        const char *state = m + keylen;
        if      (!strcasecmp(state, "verified")) e->pred_kind = BS_CP_BS_VERIFIED;
        else if (!strcasecmp(state, "missing"))  e->pred_kind = BS_CP_BS_MISSING;
        else if (!strcasecmp(state, "invalid"))  e->pred_kind = BS_CP_BS_INVALID;
        else {
            return apr_psprintf(cmd->pool,
                "BotShieldCookieTrigger: bs-cookie='%s' not one of "
                "verified|missing|invalid", state);
        }
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldCookieTrigger: unrecognized cookie-match '%s' "
            "(expected cookie=... / !cookie=... / cookies=... / "
            "bs-cookie=...)", match);
    }

    /* --- Parse action keys via shared engine (E7.2). --- */
    for (int i = 2; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_COOKIE, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_COOKIE, &e->action);
        if (err) return err;
    }

    /* Upsert-by-name. */
    for (int i = 0; i < scfg->cookie_triggers->nelts; i++) {
        bs_cookie_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->cookie_triggers, i, bs_cookie_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->cookie_triggers, i,
                          bs_cookie_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_cookie_trigger_entry **)apr_array_push(scfg->cookie_triggers) = e;
    return NULL;
}

/* E6 — BotShieldEnvTrigger <name> <env-match> [key=value ...].
 *
 * env-match shapes:
 *   env=<var>           present (any value, including empty)
 *   env=<var>=<value>   exact value match
 *   !env=<var>          absent
 *
 * Keys mirror E4's, minus `redirect` (E6 doesn't do response
 * shaping; scoring/flagging only). Predicate matching reads
 * `r->subprocess_env` at request time.
 *
 * Narrower by design than E3/E4: no substring/contains shape, no
 * cookie-bulk-state analog. Operators who need rich matching set
 * a coarse bucket upstream (SetEnvIfExpr, ModSecurity rule, etc.)
 * and consume the bucket here. */
const char *bs_set_env_trigger(cmd_parms *cmd, void *dconf,
                                      int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 2) {
        return "BotShieldEnvTrigger: expects <name> <env-match> "
               "[key=value ...]";
    }
    const char *name  = argv[0];
    const char *match = argv[1];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldEnvTrigger: name '%s' must be [a-z0-9-]{1,32}",
            name);
    }

    bs_env_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name = apr_pstrdup(cmd->pool, name);
    bs_trigger_action_init(BS_TFAMILY_ENV, &e->action);

    /* --- Parse env-match predicate. --- */
    const char *m = match;
    int negated = 0;
    if (m[0] == '!') { negated = 1; m++; }
    if (strncmp(m, "env=", 4) != 0) {
        return apr_psprintf(cmd->pool,
            "BotShieldEnvTrigger: unrecognized env-match '%s' "
            "(expected env=<var>, env=<var>=<value>, or "
            "!env=<var>)", match);
    }
    const char *rest = m + 4;
    if (!*rest) {
        return "BotShieldEnvTrigger: env= needs a variable name";
    }
    /* Env var name: POSIX-ish [A-Za-z_][A-Za-z0-9_]* but Apache is
     * liberal; we accept the same charset we allow on session-
     * cookie names and cookie-match names. Stored verbatim, but the
     * request-time lookup (`apr_table_get` on `r->subprocess_env`)
     * is case-insensitive per APR table semantics — two triggers
     * whose env names differ only in case will resolve to the same
     * stored value at runtime and shadow each other under
     * first-match-wins. */
    const char *op = rest;
    while (*op && *op != '=') {
        unsigned char c = (unsigned char)*op;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) {
            return apr_psprintf(cmd->pool,
                "BotShieldEnvTrigger: env var name contains "
                "invalid char '%c' (expect [A-Za-z0-9_-])", (char)c);
        }
        op++;
    }
    apr_size_t nlen = (apr_size_t)(op - rest);
    if (nlen == 0 || nlen > 128) {
        return "BotShieldEnvTrigger: env var name must be 1..128 chars";
    }
    e->env_name = apr_pstrmemdup(cmd->pool, rest, nlen);

    if (*op == '\0') {
        e->pred_kind = negated ? BS_EP_NAMED_ABSENT
                               : BS_EP_NAMED_PRESENT;
    } else if (negated) {
        return "BotShieldEnvTrigger: '!' prefix only combines with "
               "bare env=<var> (absence test); use env=<var>=<value> "
               "for value-mismatch semantics via a separate trigger";
    } else {
        /* *op == '=' */
        e->pred_kind  = BS_EP_NAMED_EQ;
        e->env_value  = apr_pstrdup(cmd->pool, op + 1);
        /* Empty expected-value is legitimate: SetEnvIf with no value
         * assigns "", so env=FOO= matches that case explicitly.
         * Distinct from env=FOO (matches empty OR non-empty). */
    }

    /* --- Parse action keys via shared engine (E7.2). --- */
    for (int i = 2; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_ENV, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_ENV, &e->action);
        if (err) return err;
    }

    /* Upsert-by-name (same as E3/E4). */
    for (int i = 0; i < scfg->env_triggers->nelts; i++) {
        bs_env_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->env_triggers, i, bs_env_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->env_triggers, i,
                          bs_env_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_env_trigger_entry **)apr_array_push(scfg->env_triggers) = e;
    return NULL;
}

/* E7.3 — BotShieldFeedbackTrigger <event> [key=value ...].
 *
 * Binds an app-signed event name (carried in E5's
 * X-BotShield-Feedback header body as `event=<name>;sig=<hex>`) to
 * a module-memory update. Required keys: flag=<bit> and ttl=<sec>
 * (the event has to land somewhere); optional log=<tag>. Response-
 * path only, so status/redirect/penalty/credit are rejected by the
 * shared parser. Upsert-by-event-name. */
const char *bs_set_feedback_trigger(cmd_parms *cmd, void *dconf,
                                           int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 1) {
        return "BotShieldFeedbackTrigger: expects <event> "
               "[key=value ...]";
    }
    const char *event = argv[0];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(event)) {
        return apr_psprintf(cmd->pool,
            "BotShieldFeedbackTrigger: event '%s' must be "
            "[a-z0-9-]{1,32}", event);
    }

    bs_feedback_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->event = apr_pstrdup(cmd->pool, event);
    bs_trigger_action_init(BS_TFAMILY_FEEDBACK, &e->action);

    for (int i = 1; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_FEEDBACK, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_FEEDBACK, &e->action);
        if (err) return err;
    }

    /* Upsert-by-event. Last declaration for a given event wins its
     * slot, same model as the other trigger families. */
    for (int i = 0; i < scfg->feedback_triggers->nelts; i++) {
        bs_feedback_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->feedback_triggers, i, bs_feedback_trigger_entry *);
        if (strcmp(ex->event, e->event) == 0) {
            APR_ARRAY_IDX(scfg->feedback_triggers, i,
                          bs_feedback_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_feedback_trigger_entry **)
        apr_array_push(scfg->feedback_triggers) = e;
    return NULL;
}

/* E11.2 — BotShieldLoadTrigger <name> <load-match> [key=value ...].
 *
 * load-match shapes:
 *   state=normal   (exact match — typically only for tests/docs)
 *   state=warm
 *   state=hot
 *   state>=warm    (matches warm OR hot)
 *   state>=hot     (matches hot only — equivalent to state=hot but
 *                   reads more naturally in operator config when
 *                   paired with state>=warm rules)
 *
 * First-match-wins within the family (load triggers are alternative-
 * specificity cases, not layered reputation). Action keys: status,
 * log, penalty, credit. flag/ttl/redirect rejected at parse time —
 * load is a global signal, not per-IP behavior to memorize. */
const char *bs_set_load_trigger(cmd_parms *cmd, void *dconf,
                                       int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 2) {
        return "BotShieldLoadTrigger: expects <name> <load-match> "
               "[key=value ...]";
    }
    const char *name  = argv[0];
    const char *match = argv[1];
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    if (!bs_bot_name_valid(name)) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadTrigger: name '%s' must be [a-z0-9-]{1,32}",
            name);
    }

    int pred_kind;
    const char *state_str;
    if (!strncmp(match, "state>=", 7)) {
        pred_kind = BS_LP_GE;
        state_str = match + 7;
    } else if (!strncmp(match, "state=", 6)) {
        pred_kind = BS_LP_EQ;
        state_str = match + 6;
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadTrigger: unrecognized load-match '%s' "
            "(expected state=<level> or state>=<level> where "
            "<level> is normal|warm|hot)", match);
    }
    bs_load_state target;
    if      (!strcasecmp(state_str, "normal")) target = BS_LOAD_NORMAL;
    else if (!strcasecmp(state_str, "warm"))   target = BS_LOAD_WARM;
    else if (!strcasecmp(state_str, "hot"))    target = BS_LOAD_HOT;
    else {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadTrigger: state '%s' must be one of "
            "normal|warm|hot", state_str);
    }

    bs_load_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->name         = apr_pstrdup(cmd->pool, name);
    e->pred_kind    = pred_kind;
    e->target_state = target;
    bs_trigger_action_init(BS_TFAMILY_LOAD, &e->action);

    for (int i = 2; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_LOAD, argv[i], &e->action);
        if (err) return err;
    }
    {
        const char *err = bs_finalize_trigger_action(cmd->pool,
            BS_TFAMILY_LOAD, &e->action);
        if (err) return err;
    }

    /* Upsert-by-name. */
    for (int i = 0; i < scfg->load_triggers->nelts; i++) {
        bs_load_trigger_entry *ex = APR_ARRAY_IDX(
            scfg->load_triggers, i, bs_load_trigger_entry *);
        if (strcmp(ex->name, e->name) == 0) {
            APR_ARRAY_IDX(scfg->load_triggers, i,
                          bs_load_trigger_entry *) = e;
            return NULL;
        }
    }
    *(bs_load_trigger_entry **)apr_array_push(scfg->load_triggers) = e;
    return NULL;
}

/* --- BotShieldTrigger setter --- *
 *
 * BotShieldTrigger [reset] [key=value ...]
 *
 * Per-scope trigger declaration; the Apache scope match is the
 * predicate. `reset` as the first arg drops inherited triggers
 * (and earlier same-scope entries) before any further triggers
 * in this scope are appended. Action keys mirror the cookie
 * family. Multiple BotShieldTrigger directives in one scope each
 * append a separate entry. */
const char *bs_set_trigger(cmd_parms *cmd, void *cfg_v,
                                  int argc, char *const argv[])
{
    bs_dir_cfg *cfg = cfg_v;
    int start_idx = 0;
    if (argc >= 1 && strcasecmp(argv[0], "reset") == 0) {
        /* Reset clears any same-scope entries pushed before this
         * directive and signals the merge to drop the inherited
         * base list. Subsequent args (if any) are action keys
         * for the remaining directive. */
        cfg->scope_triggers_reset = 1;
        if (cfg->scope_triggers) {
            cfg->scope_triggers->nelts = 0;
        }
        start_idx = 1;
        if (argc == 1) return NULL;
    }
    if (start_idx == argc) {
        return "BotShieldTrigger: expects [reset] [key=value ...]; "
               "got nothing actionable";
    }

    if (!cfg->scope_triggers) {
        cfg->scope_triggers = apr_array_make(cmd->pool, 2,
                                             sizeof(bs_trigger_action *));
    }

    bs_trigger_action *a = apr_pcalloc(cmd->pool, sizeof(*a));
    bs_trigger_action_init(BS_TFAMILY_SCOPE, a);

    for (int i = start_idx; i < argc; i++) {
        const char *err = bs_parse_trigger_action_key(cmd->pool,
            BS_TFAMILY_SCOPE, argv[i], a);
        if (err) return err;
    }
    const char *err = bs_finalize_trigger_action(cmd->pool,
        BS_TFAMILY_SCOPE, a);
    if (err) return err;

    *(bs_trigger_action **)apr_array_push(cfg->scope_triggers) = a;
    return NULL;
}

/* Flag-bit registry. Maps the BS_FLAG_* defines to the canonical
 * names that appear in directives (BotShieldFlagTrigger, BotShieldTrigger),
 * wire formats (X-Botshield-Claims `flags=`), and the decision log.
 * Hoisted up the file so E8.2's claim-emit path can render the bitmap
 * without a forward-decl dance over an anonymous-struct array
 * (forward-declaring such arrays in C is awkward).
 *
 * Registry is just (name, bit) — adaptive intensity (penalty,
 * difficulty delta, tier floor) lives in BotShieldFlagTrigger
 * entries instead, including the compiled-in defaults seeded by
 * bs_default_flag_triggers. */
typedef struct {
    const char     *name;
    apr_uint32_t    bit;
} bs_flag_meta;

static const bs_flag_meta bs_flag_metadata[] = {
    { "honeypot_hit",         BS_FLAG_HONEYPOT_HIT         },
    { "scanner_probe",        BS_FLAG_SCANNER_PROBE        },
    { "fake_bot",             BS_FLAG_FAKE_BOT             },
    { "pow_fail_streak",      BS_FLAG_POW_FAIL_STREAK      },
    { "app_verified_human",   BS_FLAG_APP_VERIFIED_HUMAN   },
    { "app_verified_session", BS_FLAG_APP_VERIFIED_SESSION },
    { "app_trust_signal",     BS_FLAG_APP_TRUST_SIGNAL     },
    { "blocked",              BS_FLAG_BLOCKED              },
};
#define BS_FLAG_META_COUNT \
    (sizeof(bs_flag_metadata) / sizeof(bs_flag_metadata[0]))

static const bs_flag_meta *bs_flag_meta_for_name(const char *name)
{
    for (size_t i = 0; i < BS_FLAG_META_COUNT; i++) {
        if (strcmp(bs_flag_metadata[i].name, name) == 0) {
            return &bs_flag_metadata[i];
        }
    }
    return NULL;
}
/* BotShieldFlagTrigger <flag> [reset] [action=<verb> args...]
 *
 * One unified config language for "when this flag fires, do X." Replaces
 * the prior BotShieldFlag directive (which mutated bs_flag_meta entries
 * to attach penalty/next_difficulty/next_tier metadata) with the same
 * shape as the existing BotShieldRequestTrigger / BotShieldFeedbackTrigger /
 * BotShieldLoadTrigger family.
 *
 * Two action verbs:
 *   action=score add=N           — add signed N (-1000..1000) to the
 *                                  request score. SUM accumulates across
 *                                  triggers.
 *   action=tier_floor min=<tier> — set a minimum tier; <tier> is
 *                                  pass|noninteractive|interactive|captcha. MAX
 *                                  accumulates (strictest wins).
 *
 * Reset keyword: `BotShieldFlagTrigger <flag> reset` clears all earlier
 * triggers (compiled-in defaults + prior operator declarations) for that
 * flag at post_config time. Three accepted forms:
 *
 *   BotShieldFlagTrigger pow_fail_streak reset
 *   BotShieldFlagTrigger honeypot_hit reset action=tier_floor min=form
 *   BotShieldFlagTrigger honeypot_hit reset
 *   BotShieldFlagTrigger honeypot_hit action=score add=60
 *
 * Form 2 is sugar for the first two of form 3. Reset is a directive-
 * level keyword, not an action verb — keeping the two concerns
 * syntactically distinct prevents conflict with future runtime verbs.
 *
 * Storage: each parsed line appends a bs_flag_trigger_entry to
 * scfg->flag_triggers. Reset entries appear inline as sentinels
 * (action=BS_FLAG_ACT_RESET); post_config consumes them. */
const char *bs_set_flag_trigger(cmd_parms *cmd, void *dconf,
                                       int argc, char *const argv[])
{
    (void)dconf;
    if (argc < 1) {
        return "BotShieldFlagTrigger: expects <flag> "
               "[reset] [action=<verb> args...]";
    }
    const char *flag_name = argv[0];
    const bs_flag_meta *fm = bs_flag_meta_for_name(flag_name);
    if (!fm) {
        return apr_psprintf(cmd->pool,
            "BotShieldFlagTrigger: unknown flag '%s'. Known flags: "
            "honeypot_hit, scanner_probe, fake_bot, pow_fail_streak, "
            "app_verified_human, app_verified_session, "
            "app_trust_signal", flag_name);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);

    int idx = 1;
    int saw_reset = 0;
    if (idx < argc && strcasecmp(argv[idx], "reset") == 0) {
        saw_reset = 1;
        idx++;
        bs_flag_trigger_entry *r = apr_pcalloc(cmd->pool, sizeof(*r));
        r->flag_name    = apr_pstrdup(cmd->pool, flag_name);
        r->flag_bit     = fm->bit;
        r->action       = BS_FLAG_ACT_RESET;
        r->mode         = BS_TMODE_ENFORCE;
        r->from_default = 0;
        *(bs_flag_trigger_entry **)apr_array_push(scfg->flag_triggers) = r;
    }
    /* Bare `reset` with nothing after — done. */
    if (idx >= argc) return NULL;

    /* Otherwise the next token must be `action=<verb>`. */
    if (strncasecmp(argv[idx], "action=", 7) != 0) {
        if (saw_reset) {
            return apr_psprintf(cmd->pool,
                "BotShieldFlagTrigger '%s' reset: extra arg '%s' must "
                "begin with 'action=' (or omit it for a bare reset)",
                flag_name, argv[idx]);
        }
        return apr_psprintf(cmd->pool,
            "BotShieldFlagTrigger '%s': expected 'reset' or 'action=' "
            "as the second token; got '%s'", flag_name, argv[idx]);
    }
    const char *verb = argv[idx] + 7;
    idx++;

    bs_flag_trigger_entry *e = apr_pcalloc(cmd->pool, sizeof(*e));
    e->flag_name    = apr_pstrdup(cmd->pool, flag_name);
    e->flag_bit     = fm->bit;
    e->mode         = BS_TMODE_ENFORCE;
    e->from_default = 0;

    if (strcasecmp(verb, "score") == 0) {
        e->action = BS_FLAG_ACT_SCORE;
        int saw_add = 0;
        for (; idx < argc; idx++) {
            const char *arg = argv[idx];
            if (strncasecmp(arg, "add=", 4) == 0) {
                char *e2 = NULL;
                long n = strtol(arg + 4, &e2, 10);
                if (!e2 || *e2 || n < -1000 || n > 1000) {
                    return apr_psprintf(cmd->pool,
                        "BotShieldFlagTrigger '%s' action=score: "
                        "add='%s' must be an integer in -1000..1000",
                        flag_name, arg + 4);
                }
                e->score_add = (int)n;
                saw_add = 1;
            } else if (strcasecmp(arg, "mode=observe") == 0) {
                e->mode = BS_TMODE_OBSERVE;
            } else if (strcasecmp(arg, "mode=enforce") == 0) {
                e->mode = BS_TMODE_ENFORCE;
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlagTrigger '%s' action=score: "
                    "unknown arg '%s' (want add=N or mode=observe)",
                    flag_name, arg);
            }
        }
        if (!saw_add) {
            return apr_psprintf(cmd->pool,
                "BotShieldFlagTrigger '%s' action=score: missing "
                "required 'add=N'", flag_name);
        }
    } else if (strcasecmp(verb, "tier_floor") == 0) {
        e->action = BS_FLAG_ACT_TIER_FLOOR;
        int saw_min = 0;
        for (; idx < argc; idx++) {
            const char *arg = argv[idx];
            if (strncasecmp(arg, "min=", 4) == 0) {
                const char *t = arg + 4;
                if      (strcasecmp(t, "nochallenge") == 0) e->tier_min = BS_TIER_PASS;
                else if (strcasecmp(t, "noninteractive") == 0)
                    e->tier_min = BS_TIER_NONINTERACTIVE;
                else if (strcasecmp(t, "interactive") == 0)
                    e->tier_min = BS_TIER_INTERACTIVE;
                else if (strcasecmp(t, "captcha") == 0) e->tier_min = BS_TIER_CAPTCHA;
                else {
                    return apr_psprintf(cmd->pool,
                        "BotShieldFlagTrigger '%s' action=tier_floor: "
                        "min='%s' must be one of nochallenge/noninteractive/interactive/captcha",
                        flag_name, t);
                }
                saw_min = 1;
            } else if (strcasecmp(arg, "mode=observe") == 0) {
                e->mode = BS_TMODE_OBSERVE;
            } else if (strcasecmp(arg, "mode=enforce") == 0) {
                e->mode = BS_TMODE_ENFORCE;
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlagTrigger '%s' action=tier_floor: "
                    "unknown arg '%s' (want min=<tier> or mode=observe)",
                    flag_name, arg);
            }
        }
        if (!saw_min) {
            return apr_psprintf(cmd->pool,
                "BotShieldFlagTrigger '%s' action=tier_floor: missing "
                "required 'min=<tier>'", flag_name);
        }
    } else if (strcasecmp(verb, "block") == 0) {
        e->action = BS_FLAG_ACT_BLOCK;
        e->block_status = HTTP_FORBIDDEN;
        for (; idx < argc; idx++) {
            const char *arg = argv[idx];
            if (strncasecmp(arg, "status=", 7) == 0) {
                char *e2 = NULL;
                long code = strtol(arg + 7, &e2, 10);
                if (!e2 || *e2 || code < 400 || code > 599) {
                    return apr_psprintf(cmd->pool,
                        "BotShieldFlagTrigger '%s' action=block: "
                        "status='%s' must be 400..599 -- a block is a "
                        "refusal, so a 2xx or 3xx has no meaning here",
                        flag_name, arg + 7);
                }
                e->block_status = (int)code;
            } else if (strcasecmp(arg, "mode=observe") == 0) {
                e->mode = BS_TMODE_OBSERVE;
            } else if (strcasecmp(arg, "mode=enforce") == 0) {
                e->mode = BS_TMODE_ENFORCE;
            } else {
                return apr_psprintf(cmd->pool,
                    "BotShieldFlagTrigger '%s' action=block: unknown "
                    "arg '%s' (want status=<4xx|5xx> or mode=observe)",
                    flag_name, arg);
            }
        }
    } else {
        return apr_psprintf(cmd->pool,
            "BotShieldFlagTrigger '%s': unknown action verb '%s' "
            "(want score or tier_floor)", flag_name, verb);
    }

    *(bs_flag_trigger_entry **)apr_array_push(scfg->flag_triggers) = e;
    return NULL;
}


/* ----------------------------------------------------------------------
 * Container syntax: <BotShieldRequestTrigger name> ... </...>
 *
 * The flat `key=value` form is retired. It packed a rule's six match
 * dimensions and eight action keys onto one logical line, which in
 * practice meant backslash continuations, and a continuation cannot be
 * commented, cannot be reordered, and cannot be diffed a line at a
 * time. One live rule here carried a 400-character path list on a line
 * that could not be broken at all, duplicated verbatim into a second
 * rule, with nothing checking that the two copies still agreed.
 *
 * These handlers do not re-implement any parsing. They read the lines
 * between the tags, turn each `BotShieldFoo value` into the `foo=value`
 * token the existing setter already understands, and hand the whole
 * thing to that setter. Semantics, validation and error text are the
 * same by construction rather than by maintenance, and the policy dump
 * needs no changes at all, because what lands in the config is the same
 * structure the flat form built.
 *
 * The inner names are deliberately NOT registered as directives. They
 * exist only inside a container, so `BotShieldPath` at top level is an
 * unknown directive, which Apache already reports clearly, and the
 * global directive table stays free of fifteen words like `Status` and
 * `Mode` that would otherwise have to be rejected by hand everywhere
 * else.
 * -------------------------------------------------------------------- */

/* Inner directive name -> the key the flat parser knows. The rule is
 * mechanical: drop the BotShield prefix and lowercase the rest. Only
 * one name does not survive that, because `ua` is not a word. */
static const char *bs_section_key(apr_pool_t *p, const char *directive)
{
    const apr_size_t plen = sizeof("BotShield") - 1;
    if (strncasecmp(directive, "BotShield", plen) != 0 || !directive[plen])
        return NULL;
    char *key = apr_pstrdup(p, directive + plen);
    for (char *c = key; *c; c++) *c = (char)apr_tolower(*c);
    if (strcmp(key, "useragent") == 0) return "ua";
    return key;
}

/* Keys whose flat form is already a comma-separated list. Repeating
 * one of these inside a container appends rather than replaces, so a
 * long path list can be written a line per entry with a comment on
 * each -- the thing the flat form made impossible. Repeating any other
 * key is a config error, because silently keeping the last value is
 * how you end up debugging a rule that does not do what it says. */
static int bs_section_key_repeats(const char *key)
{
    return strcmp(key, "path") == 0
        || strcmp(key, "ua") == 0
        || strcmp(key, "ipspec") == 0;
}

/* <BotShieldMatch name> -- store the block's conditions under a name.
 *
 * Refuses action keys. A set is the predicate half of a rule, and a set
 * that could carry respond= would add an action to every rule naming
 * it, from a block whose name says only what it matches. Rules stay the
 * only place an action is written.
 *
 * Refuses a redefinition rather than letting the last one win. Two
 * blocks with one name is a copy-paste, and silently keeping one of
 * them is how the crawler-pass / content-gate divergence would come
 * back wearing a name. */
const char *bs_set_match_set(cmd_parms *cmd, void *dconf,
                             int argc, char *const argv[])
{
    (void)dconf;
    apr_pool_t *p = cmd->pool;
    if (argc < 1 || !argv[0] || !*argv[0]) {
        return "<BotShieldMatch> needs a name: <BotShieldMatch gated>";
    }
    const char *name = argv[0];
    if (argc < 2) {
        return apr_psprintf(p,
            "<BotShieldMatch %s> is empty -- a set with no conditions "
            "matches nothing and reads as if it matched everything",
            name);
    }

    static const char *const action_keys[] = {
        "respond=", "status=", "challenge=", "tier=", "redirect=",
        "logas=", "log=", "accesslog=", "flagip=", "flagsession=",
        "flag=", "ttl=", "penalty=", "credit=", "mode=", NULL
    };

    bs_server_cfg *scfg = ap_get_module_config(
        cmd->server->module_config, &botshield_module);
    if (!scfg) return "<BotShieldMatch>: no server config";

    apr_array_header_t *kvs =
        apr_array_make(p, argc - 1, sizeof(char *));
    for (int i = 1; i < argc; i++) {
        const char *kv = argv[i];
        for (int a = 0; action_keys[a]; a++) {
            apr_size_t alen = strlen(action_keys[a]);
            if (strncasecmp(kv, action_keys[a], alen) == 0) {
                return apr_psprintf(p,
                    "<BotShieldMatch %s>: '%.*s' is an action, and a "
                    "match set holds conditions only. Put it on the "
                    "rules that use this set -- otherwise a block named "
                    "for what it matches would also decide what "
                    "happens.", name, (int)(alen - 1), action_keys[a]);
            }
        }
        if (strcasecmp(kv, "nochallenge") == 0) {
            return apr_psprintf(p,
                "<BotShieldMatch %s>: 'nochallenge' is an action, and a "
                "match set holds conditions only.", name);
        }
        *(const char **)apr_array_push(kvs) = apr_pstrdup(p, kv);
    }

    if (!scfg->match_sets) {
        scfg->match_sets = apr_hash_make(cmd->pool);
    }
    if (apr_hash_get(scfg->match_sets, name, APR_HASH_KEY_STRING)) {
        return apr_psprintf(p,
            "<BotShieldMatch %s> is defined twice in this scope. The "
            "second would silently replace the first, which is how two "
            "rules meant to share a set drift apart.", name);
    }
    apr_hash_set(scfg->match_sets, apr_pstrdup(cmd->pool, name),
                 APR_HASH_KEY_STRING, kvs);
    return NULL;
}

const char *bs_section_trigger(cmd_parms *cmd, void *dconf, const char *arg,
                              const char *dname, bs_trigger_setter setter)
{
    apr_pool_t *p = cmd->pool;

    /* Apache hands us everything after the directive word, closing
     * angle bracket included. */
    char *spec = apr_pstrdup(p, arg);
    apr_size_t slen = strlen(spec);
    while (slen && apr_isspace(spec[slen - 1])) spec[--slen] = '\0';
    if (!slen || spec[slen - 1] != '>') {
        return apr_psprintf(p, "<%s> is missing its closing '>'", dname);
    }
    spec[--slen] = '\0';
    while (slen && apr_isspace(spec[slen - 1])) spec[--slen] = '\0';

    /* A name is optional because one family does not take one:
     * BotShieldTrigger is scoped by its enclosing <Location> rather
     * than identified by a name, so <BotShieldTrigger> is the whole
     * opening tag. Families that do want a name still say so, from
     * their own setter, which is where that error belongs. */
    const char *name = ap_getword_conf(p, (const char **)&spec);
    const int named = (name && *name);
    if (*spec) {
        return apr_psprintf(p,
            "<%s %s>: unexpected '%s' after the name. Every other "
            "setting is a directive on its own line inside the block.",
            dname, named ? name : "", spec);
    }
    if (!named) name = "";

    /* Two lists, joined at the end. The flat parsers read a bare
     * positional flag at argv[1] specifically, so where the operator
     * happened to write it inside the block must not matter -- a block
     * whose meaning depends on line order would be the continuation
     * problem again wearing a different hat. */
    apr_array_header_t *flags = apr_array_make(p, 2, sizeof(char *));
    apr_array_header_t *kvs   = apr_array_make(p, 12, sizeof(char *));

    /* Remember where each key landed so a repeat can append to it. */
    apr_table_t *seen = apr_table_make(p, 12);

    /* The block body is already parsed. Apache builds a container's
     * children before it calls the section handler, and hangs them off
     * cmd->directive, so there is nothing to read here -- only a list
     * to walk.
     *
     * Two wrong turns preceded this. Reading the lines with
     * ap_cfg_getline consumed the closing tag out from under Apache's
     * own container tracking, which then reported the block as never
     * closed. Calling ap_build_cont_config asked for a body that had
     * already been consumed, and read off the end of the file, which
     * is a segfault rather than an error message. */
    for (ap_directive_t *d = cmd->directive->first_child; d; d = d->next) {
        const char *directive = d->directive;
        const char *key = bs_section_key(p, directive);
        if (!key) {
            return apr_psprintf(p,
                "<%s %s>: '%s' is not a BotShield setting", dname, name,
                directive);
        }

        /* d->args is the rest of the line, already stripped by the
         * config reader. Strip one layer of quoting so a value with
         * spaces -- a UA substring, say -- survives either spelling. */
        char *value = apr_pstrdup(p, d->args ? d->args : "");
        apr_size_t vlen = strlen(value);
        while (vlen && apr_isspace(value[vlen - 1])) value[--vlen] = '\0';
        /* An explicitly quoted empty string is a value, not an absent
         * one: ua="" matches a request whose User-Agent is missing or
         * empty, which is a real rule here and not a typo. Only a line
         * with nothing after the directive counts as valueless. */
        int quoted = (vlen >= 2 && (value[0] == '"' || value[0] == '\'')
                                && value[vlen - 1] == value[0]);
        if (quoted) {
            value[vlen - 1] = '\0';
            value++;
        }

        /* A valueless directive is a positional flag in the flat
         * form -- `reset` on the flag and heuristic families. It goes
         * through as a bare token, not as key=value, because that is
         * what those parsers read. */
        if (!*value && !quoted) {
            /* Valueless directives. `reset` clears inherited triggers;
             * `nochallenge` is BotShieldNoChallenge, which takes no
             * argument because there is nothing to parameterise -- the
             * rule decides nothing. Both pass through as bare tokens
             * for the family setters to read. */
            if (strcmp(key, "reset") != 0
                && strcmp(key, "nochallenge") != 0) {
                return apr_psprintf(p,
                    "<%s %s>: %s needs a value", dname, name, directive);
            }
            if (apr_table_get(seen, key)) {
                return apr_psprintf(p, "<%s %s>: %s given twice",
                                    dname, name, directive);
            }
            apr_table_set(seen, key, "1");
            *(const char **)apr_array_push(flags) = key;
            continue;
        }

        const char *prior = apr_table_get(seen, key);
        if (prior) {
            if (!bs_section_key_repeats(key)) {
                return apr_psprintf(p,
                    "<%s %s>: %s given twice. Only Path, UserAgent and "
                    "IPSpec accumulate; everything else would silently "
                    "keep one value.", dname, name, directive);
            }
            if (strcmp(key, "path") == 0) {
                /* Paths get a token each rather than a comma-joined
                 * list, because a comma is a legal character in a path
                 * (RFC 3986 sub-delims) and cannot also be the
                 * separator. Joining them here and splitting them apart
                 * in the setter turned `BotShieldPath /a,/b` into two
                 * patterns -- silently matching two prefixes instead of
                 * the one literal path asked for.
                 *
                 * UserAgent and IPSpec keep the joined form: a comma
                 * cannot appear in a CIDR, and @botgroup lists are
                 * written comma-separated on purpose. */
                *(const char **)apr_array_push(kvs) =
                    apr_psprintf(p, "%s=%s", key, value);
                continue;
            }
            /* Rewrite the token in place: the parser sees one list. */
            for (int i = 0; i < kvs->nelts; i++) {
                char **slot = &((char **)kvs->elts)[i];
                apr_size_t klen = strlen(key);
                if (strncmp(*slot, key, klen) == 0 && (*slot)[klen] == '=') {
                    *slot = apr_psprintf(p, "%s,%s", *slot, value);
                    break;
                }
            }
            continue;
        }
        apr_table_set(seen, key, "1");
        /* A leading '!' on the value negates the match. The flat form
         * put it on the key -- `!cookie=csrf_token` -- which cannot
         * survive becoming a directive name, and reads better on the
         * value anyway: BotShieldCookie !csrf_token. */
        if (value[0] == '!') {
            *(const char **)apr_array_push(kvs) =
                apr_psprintf(p, "!%s=%s", key, value + 1);
        } else if (value[0] == '>' || value[0] == '<') {
            /* A comparison, not an assignment: BotShieldState >=warm
             * is the load family's `state>=warm`. The operator rides
             * on the value because a directive name cannot hold it. */
            *(const char **)apr_array_push(kvs) =
                apr_psprintf(p, "%s%s", key, value);
        } else {
            *(const char **)apr_array_push(kvs) =
                apr_psprintf(p, "%s=%s", key, value);
        }
    }

    if (flags->nelts == 0 && kvs->nelts == 0) {
        return apr_psprintf(p, "<%s %s> is empty", dname, name);
    }

    /* Expand matches=<name> before the setter sees the block.
     *
     * Textual on purpose: the result is exactly the block the operator
     * would have written by hand, so no parser, evaluator or family
     * downstream learns that named sets exist. A set is read where it
     * is written -- resolution happens here, in definition order, which
     * is also why a set may name a set defined above it and why a cycle
     * cannot be built. */
    if (kvs->nelts) {
        bs_server_cfg *mscfg = ap_get_module_config(
            cmd->server->module_config, &botshield_module);
        apr_array_header_t *expanded =
            apr_array_make(p, kvs->nelts + 8, sizeof(char *));
        int any = 0;
        for (int i = 0; i < kvs->nelts; i++) {
            const char *kv = APR_ARRAY_IDX(kvs, i, const char *);
            if (strncasecmp(kv, "matches=", 8) != 0) {
                *(const char **)apr_array_push(expanded) = kv;
                continue;
            }
            any = 1;
            const char *sname = kv + 8;
            apr_array_header_t *set =
                (mscfg && mscfg->match_sets)
                ? apr_hash_get(mscfg->match_sets, sname,
                               APR_HASH_KEY_STRING)
                : NULL;
            if (!set) {
                return apr_psprintf(p,
                    "<%s %s>: BotShieldMatches '%s' names no "
                    "<BotShieldMatch> block in this scope. Define the "
                    "set above the rules that use it.",
                    dname, named ? name : "", sname);
            }
            apr_array_cat(expanded, set);
        }
        if (any) kvs = expanded;
    }

    apr_array_header_t *argv = apr_array_make(
        p, flags->nelts + kvs->nelts + 1, sizeof(char *));
    if (named) *(const char **)apr_array_push(argv) = name;
    apr_array_cat(argv, flags);
    apr_array_cat(argv, kvs);

    return setter(cmd, dconf, argv->nelts, (char *const *)argv->elts);
}

/* The retired flat form. Kept registered so it fails with a sentence
 * that says what to write, rather than "Invalid command", which sends
 * the reader looking for a typo or a missing LoadModule. */
const char *bs_flat_trigger_retired(cmd_parms *cmd, void *dconf,
                                    int argc, char *const argv[])
{
    (void)dconf; (void)argc;
    const char *dname = cmd->cmd->name;
    const char *name = argc > 0 ? argv[0] : "myrule";
    /* One line, because Apache prints a config error verbatim and a
     * literal \n comes out as the two characters. */
    return apr_psprintf(cmd->pool,
        "%s: the one-line key=value form is retired -- write "
        "<%s %s> ... </%s> with one BotShield directive per setting "
        "inside it (BotShieldPath, BotShieldStatus, and so on). "
        "See docs/directives.md.",
        dname, dname, name, dname);
}
