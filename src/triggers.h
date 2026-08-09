/* triggers.h — E2.1/E3/E4/E6/E7.3/E11.2/E14 trigger + policy families.
 *
 * Six trigger families share one config-time action engine and one
 * request-time executor. Five families differ in their predicate
 * shape (path glob, cookie name+value, env var, app-feedback event,
 * load tier) but funnel through the same bs_trigger_action struct
 * and the same bs_apply_trigger_action executor:
 *
 *   E3  BotShieldPathTrigger      path glob       request-path
 *   E4  BotShieldCookieTrigger    cookie name/val request-path
 *   E6  BotShieldEnvTrigger       env var         request-path
 *   E7.3 BotShieldFeedbackTrigger event name      response-path
 *   E11.2 BotShieldLoadTrigger    load state      request-path
 *
 * The sixth (E14 flag-trigger) uses a separate action surface
 * (score-add / tier_floor) whose entry type also lives here.
 *
 * The E2.1 rate-limit family and the E3 path-trigger family share
 * their (UA?, IP?) cohort predicate (bs_cohort), declared up front
 * so per-family entry types can embed it.
 *
 * Each family has its own directive setter (bs_set_*_trigger) that
 * parses family-specific predicate args, then delegates the shared
 * key=value action keys (status, redirect, log, flag, ttl, penalty,
 * credit, mode) to bs_parse_trigger_action_key + finalize.
 *
 * The request-path walker bs_check_policy in policy.c calls
 * bs_apply_trigger_action with the matched entry's action; the
 * response-path E5 filter in bridge.c calls it for feedback. Outcome
 * codes (BS_TEXEC_*) tell the caller whether to short-circuit, end
 * the family loop, or keep accumulating credits. */
#ifndef BOTSHIELD_TRIGGERS_H
#define BOTSHIELD_TRIGGERS_H

#include <httpd.h>
#include <http_config.h>
#include <apr.h>
#include <apr_tables.h>

#include "score.h"     /* bs_tier (used by bs_flag_trigger_entry) */
#include "shm.h"       /* bs_load_state (used by bs_load_trigger_entry) */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — bs_dir_cfg / bs_server_cfg are defined in
 * botshield.h. Declared here so this header is self-contained. */
struct bs_dir_cfg;
struct bs_server_cfg;

/* ======================================================================
 * Shared action engine — types
 * ====================================================================== */

#define BS_TRIGGER_STATUS_PASS   (-1)

typedef enum {
    BS_TFAMILY_REQUEST = 0,
    BS_TFAMILY_COOKIE,
    BS_TFAMILY_ENV,
    BS_TFAMILY_FEEDBACK,
    BS_TFAMILY_LOAD,
    BS_TFAMILY_FLAG,
    BS_TFAMILY_SCOPE,
} bs_trigger_family;

typedef enum {
    BS_TMODE_ENFORCE = 0,
    BS_TMODE_OBSERVE,
} bs_trigger_mode;

typedef enum {
    BS_TEXEC_PASS_CONTINUE = 0,
    BS_TEXEC_PASS_BREAK,
    BS_TEXEC_PASS_DECLINE,
    BS_TEXEC_STATUS,
    BS_TEXEC_OBSERVE,
} bs_trigger_exec_outcome;

typedef struct {
    int           status_code;    /* HTTP code or BS_TRIGGER_STATUS_PASS */
    const char   *redirect_url;   /* NULL unless explicitly set */
    const char   *log_tag;
    apr_uint32_t  flag_bit;       /* single BS_FLAG_* bit; 0 if ttl_sec==0 */
    int           ttl_sec;        /* 0 = don't flag the IP */
    int           penalty;        /* 0..1000 */
    int           credit;         /* 0..1000 (rejected on path family) */
    int           status_explicit; /* 1 if operator wrote status= */
    int           mode;           /* bs_trigger_mode */
    /* 1 if the operator wrote mode=enforce, as distinct from the mode
     * field merely defaulting to BS_TMODE_ENFORCE (which is 0, so the
     * two are otherwise indistinguishable).
     *
     * Explicit enforce overrides a LogOnly scope. Without that, a
     * site-wide "BotShieldEnabled LogOnly" forced every trigger to
     * observe, and there was no way to say "watch the whole site, but
     * act on THIS" short of switching the scope with an Apache
     * <If> — which moves half the policy outside the module, where the
     * decision log cannot see it.
     *
     * Defaulted enforce is deliberately NOT enough: a scope set to
     * LogOnly must keep its promise that nothing acts unless someone
     * said so on the rule itself. */
    int           mode_explicit_enforce;
    /* accesslog=off — suppress the access-log line for a matching
     * request by breaking the log_transaction hook chain. Independent
     * of log_tag: a rule can carry a fail2ban tag AND keep its request
     * out of the access log, which is the usual want for scanner
     * probes. The module's own decision record is unaffected. See
     * bs_suppress_access_log in metrics.h for what it costs. */
    int           suppress_access_log;
    /* tier=<t>: route the match into a challenge tier instead of
     * refusing it. -1 = unset. Distinct from flag= + a flag-trigger
     * tier_floor, which writes per-IP state with a TTL: this applies
     * to THIS request only, so a client that solves the challenge is
     * not re-challenged on its next request by a flag it cannot
     * clear. Only meaningful alongside status=pass -- a concrete
     * status short-circuits before any tier is chosen. */
    int          tier_floor;
} bs_trigger_action;

/* ======================================================================
 * Per-family entry types
 *
 * One entry per BotShield<family>Trigger directive. Each carries
 * its family-specific predicate plus a shared bs_trigger_action
 * (action keys parsed by bs_parse_trigger_action_key in triggers.c).
 * scfg holds parallel apr_arrays of these — bs_check_policy walks
 * each in declaration order.
 *
 * bs_cohort (the shared "(UA?, IP?) predicate" struct) is declared
 * up here so per-family entry types can embed it. The path-trigger
 * family uses it for optional ua=/ipspec= gating; the rate-limit
 * family further down reuses the same type. */

typedef struct {
    const char         *ua_pattern;
    int                 ua_any;
    /* ua="" — matches a request with NO User-Agent header, or one
     * present but empty. Absence is not a substring of anything, so
     * ua_pattern could never express it.
     *
     * The empty value used to mean "any", redundantly with "*" and with
     * omitting the key entirely. Nothing shipped used it, so it now
     * carries the meaning it reads as. "*" is still "any". */
    int                 ua_none;
    /* @botgroup selector — when non-NULL, the UA axis matches by
     * the request's classified botgroup instead of UA-substring.
     * Mutually exclusive with ua_pattern; setter rejects both. Set
     * by `BotShieldRateLimit @ai-train ...` or
     * `BotShieldPathTrigger ... ua=@search ...`. */
    const char         *ua_botgroup;
    int                 ip_any;
    const char         *path;
    const char         *inline_cidrs;
    apr_array_header_t *ranges;
} bs_cohort;

/* Request trigger (was BotShieldPathTrigger through 2026-07). Every
 * match dimension is optional and they AND together; the setter
 * rejects a rule with none, since that is what the per-scope
 * BotShieldTrigger is for. NULL / -1 means "this dimension does not
 * restrict". */
typedef struct {
    const char        *name;
    const char        *path_pattern;   /* path=  glob vs r->uri;  NULL = any */
    const char        *query_pattern;  /* query= glob vs r->args; NULL = any */
    /* cookies= bulk predicate: one of BS_CP_BULK_NONE / _ANY / _SESSION,
     * or -1 for no cookie condition. Named-cookie predicates stay with
     * BotShieldCookieTrigger, whose vocabulary is richer than one key. */
    int                cookie_pred;
    /* ua= / ipspec= cohort. has_cohort==0 means no UA/IP restriction. */
    bs_cohort          cohort;
    int                has_cohort;
    bs_trigger_action  action;
} bs_request_trigger_entry;

/* Cookie predicate kinds. Per-named lookups (NAMED_*) target a
 * specific cookie name; bulk variants (BULK_*) examine the cookie
 * map as a whole; BS_VERIFIED/MISSING/INVALID consume the
 * BS_CK_STATE_* note set by bs_handler. */
enum bs_cookie_pred_kind {
    BS_CP_NAMED_PRESENT = 0,
    BS_CP_NAMED_ABSENT,
    BS_CP_NAMED_EQ,
    BS_CP_NAMED_NE,
    BS_CP_NAMED_CONTAINS,
    BS_CP_BULK_NONE,
    BS_CP_BULK_ANY,
    BS_CP_BULK_SESSION,
    BS_CP_BS_VERIFIED,
    BS_CP_BS_MISSING,
    BS_CP_BS_INVALID,
};

typedef struct {
    const char        *name;
    int                pred_kind;     /* enum bs_cookie_pred_kind */
    const char        *cname;         /* NULL unless kind is NAMED_* */
    const char        *cvalue;        /* NULL unless kind is NAMED_{EQ,NE,CONTAINS} */
    bs_trigger_action  action;
} bs_cookie_trigger_entry;

/* Env predicate kinds — narrower than cookie (no contains/bulk) by
 * design; rich matching belongs in the upstream module that sets
 * the env var. */
enum bs_env_pred_kind {
    BS_EP_NAMED_PRESENT = 0,
    BS_EP_NAMED_ABSENT,
    BS_EP_NAMED_EQ,
};

typedef struct {
    const char        *name;
    int                pred_kind;     /* enum bs_env_pred_kind */
    const char        *env_name;
    const char        *env_value;     /* NULL unless NAMED_EQ */
    bs_trigger_action  action;
} bs_env_trigger_entry;

/* Load predicate: state==target (EQ) or state>=target (GE). */
enum bs_load_pred_kind {
    BS_LP_EQ = 0,
    BS_LP_GE,
};

typedef struct {
    const char        *name;
    int                pred_kind;     /* enum bs_load_pred_kind */
    bs_load_state      target_state;
    bs_trigger_action  action;
} bs_load_trigger_entry;

/* E7.3 — feedback trigger entry. One per BotShieldFeedbackTrigger
 * directive; lookup-by-event-name. */
typedef struct {
    const char        *event;
    bs_trigger_action  action;
} bs_feedback_trigger_entry;

/* ======================================================================
 * E2.1 rate-limit family
 *
 * bs_rate_limit_entry and bs_rate_escalate_entry are the per-directive
 * configs that consume the bs_cohort predicate declared above. Defined
 * here because config.c's post_config hook walks them at SHM-slot
 * assignment time.
 * ====================================================================== */

#define BS_PENALTY_RATE_LIMIT  50

typedef struct bs_rate_escalate_entry bs_rate_escalate_entry;

typedef struct {
    const char   *name;
    bs_cohort     cohort;
    apr_uint32_t  budget;
    apr_uint32_t  window_sec;
    int           shm_slot;
    const bs_rate_escalate_entry *escalate;
    int           mode;
} bs_rate_limit_entry;

struct bs_rate_escalate_entry {
    const char   *rule_name;
    apr_uint32_t  strikes;
    apr_uint32_t  per_sec;
    int           status_code;
    int           ttl_sec;
    const char   *log_tag;
};

/* SHM slot for the fixed-window counter. 8 bytes; CAS would target
 * the pair as a u64 on a 64-bit-atomic platform. v1 uses 32-bit
 * atomics on each field separately. */
typedef struct {
    apr_uint32_t count;
    apr_uint32_t window_start_sec;
} bs_rate_counter;

/* ======================================================================
 * E14 flag-trigger family
 *
 * Predicate is "flag_bit is set on this request's IP-side or cookie-
 * side flag bitmap". Two runtime action verbs (SCORE / TIER_FLOOR);
 * RESET is a config-time sentinel consumed before the request path
 * runs.
 * ====================================================================== */

typedef enum {
    BS_FLAG_ACT_SCORE = 0,
    BS_FLAG_ACT_TIER_FLOOR,
    BS_FLAG_ACT_RESET,
} bs_flag_action_kind;

typedef struct {
    const char         *flag_name;
    apr_uint32_t        flag_bit;
    bs_flag_action_kind action;
    int                 score_add;
    bs_tier             tier_min;
    int                 mode;
    int                 from_default;
} bs_flag_trigger_entry;

/* ======================================================================
 * Cookie-trigger predicate matcher
 *
 * Evaluate one BotShieldCookieTrigger entry's predicate against the
 * already-parsed cookie map and the BS-cookie-state note set by
 * bs_handler. Returns 1 on match, 0 on no match.
 * ====================================================================== */
int bs_cookie_pred_match(const bs_cookie_trigger_entry *e,
                         apr_table_t *cmap,
                         const apr_array_header_t *session_names,
                         const char *bs_state);

/* ======================================================================
 * Shared action engine: executor
 *
 * Apply a parsed bs_trigger_action against `r`. Records score, flags
 * the IP if the rule asks for it, sets the trigger-tag note for the
 * decision log, and emits any redirect Location. Returns one of:
 *
 *   BS_TEXEC_OBSERVE        — observe-mode match; caller continues
 *   BS_TEXEC_PASS_DECLINE   — path-family pass; caller returns DECLINED
 *   BS_TEXEC_PASS_CONTINUE  — cookie-family pass; caller keeps accumulating
 *   BS_TEXEC_PASS_BREAK     — env/load-family pass; caller ends the loop
 *   BS_TEXEC_STATUS         — concrete status; caller returns a->status_code
 *
 * `family_tag` is the decision-log prefix ("cookie-trigger" /
 * "env-trigger" / "load-trigger" / "path-trigger"); `trigger_name`
 * is the operator's per-rule label.
 * ====================================================================== */
bs_trigger_exec_outcome bs_apply_trigger_action(
    request_rec *r,
    struct bs_server_cfg *scfg,
    bs_trigger_family fam,
    const bs_trigger_action *a,
    const char *family_tag,
    const char *trigger_name);

/* ======================================================================
 * Directive setters
 *
 * Each family's setter parses its own predicate args (path glob /
 * cookie spec / env var / event name / load match) then runs the
 * remaining argv through the shared action-key parser. Setters
 * upsert by name so re-declaring a name updates rather than
 * appends.
 * ====================================================================== */

const char *bs_set_request_trigger    (cmd_parms *cmd, void *dconf,
                                    int argc, char *const argv[]);
const char *bs_set_cookie_trigger  (cmd_parms *cmd, void *dconf,
                                    int argc, char *const argv[]);
const char *bs_set_env_trigger     (cmd_parms *cmd, void *dconf,
                                    int argc, char *const argv[]);
const char *bs_set_feedback_trigger(cmd_parms *cmd, void *dconf,
                                    int argc, char *const argv[]);
const char *bs_set_load_trigger    (cmd_parms *cmd, void *dconf,
                                    int argc, char *const argv[]);

/* E4 — BotShieldSessionCookieName <name>. Each invocation appends a
 * new name to the session-cookie list. Lives next to the cookie-
 * trigger code because it feeds the BS_CP_BULK_SESSION predicate. */
const char *bs_set_session_cookie_name(cmd_parms *cmd, void *dconf,
                                       const char *name);

/* --- Flag-trigger family setter --- *
 *
 * BotShieldFlagTrigger — flag→action mapping registry. Per-scope
 * IP flagging that used to live in BotShieldFlagIP is now
 * expressed as `BotShieldTrigger flag=<name> ttl=<sec>` (see
 * below). */
const char *bs_set_flag_trigger(cmd_parms *cmd, void *dconf,
                                int argc, char *const argv[]);

/* --- BotShieldTrigger — per-Apache-scope trigger declaration --- *
 *
 * Lives in any Apache container the parser accepts (server,
 * <VirtualHost>, <Directory>, <Location>, <LocationMatch>,
 * <Files>, <If>, etc.). The Apache scope match IS the predicate;
 * the directive carries only the action keys. Multiple
 * BotShieldTrigger directives in one scope each append a separate
 * action entry. Action keys: status, redirect, log, flag, ttl,
 * penalty, credit, mode (same surface as the cookie family).
 *
 * Reset semantics: `BotShieldTrigger reset` (no other args) sets
 * a flag on the current dcfg that the merge consults — when a
 * deeper scope contains a reset, inherited triggers from outer
 * scopes are dropped before any further triggers in the current
 * scope are appended. The reset also clears any earlier
 * BotShieldTrigger directives that were appended in the same
 * scope before the reset directive. */
const char *bs_set_trigger(cmd_parms *cmd, void *dconf,
                           int argc, char *const argv[]);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_TRIGGERS_H */
