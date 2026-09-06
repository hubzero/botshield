/* triggers.h — E2.1/E3/E4/E6/E7.3/E11.2/E14 trigger + policy families.
 *
 * Six trigger families share one config-time action engine and one
 * request-time executor. Five families differ in their predicate
 * shape (path glob, cookie name+value, env var, app-feedback event,
 * load tier) but funnel through the same bs_trigger_action struct
 * and the same bs_apply_trigger_action executor:
 *
 *   E3  BotShieldRequestTrigger      path glob       request-path
 *   E4  BotShieldCookieTrigger    cookie name/val request-path
 *   E6  BotShieldEnvTrigger       env var         request-path
 *   E7.3 BotShieldFeedbackTrigger event name      response-path
 *   E11.2 BotShieldLoadTrigger    load state      request-path
 *
 * The sixth (E14 flagtrigger) uses a separate action surface
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

/* One BotShieldScore movement. '=' assigns, '+'/'-' accumulate.
 * Bounded like every other integer surface here. */
typedef struct {
    const char *name;
    char        op;      /* '+', '-' or '=' */
    int         value;
} bs_score_op;

typedef struct {
    int           status_code;    /* HTTP code or BS_TRIGGER_STATUS_PASS */
    const char   *redirect_url;   /* NULL unless explicitly set */
    const char   *log_tag;
    apr_uint32_t  flag_bit;       /* DEPRECATED flag=; 0 if ttl_sec==0 */
    int           ttl_sec;        /* DEPRECATED ttl=; 0 = don't flag the IP */
    /* BotShieldFlagIP / BotShieldFlagSession. Separate from flag_bit
     * because the deprecated pair carries its own per-rule TTL, while
     * these use the server-scope window: the address slot holds one
     * expires_at shared by every flag on it, so a per-rule duration
     * promises resolution the storage cannot deliver. */
    apr_uint32_t  flag_ip;            /* bits to set on the address */
    apr_uint32_t  flag_ip_clear;      /* bits to remove */
    int           flag_ip_replace;    /* 1 = flag_ip becomes the whole set */
    apr_uint32_t  flag_session;       /* bits to set on the cookie session */
    apr_uint32_t  flag_session_clear; /* bits to remove */
    int           flag_session_replace;
    /* BotShieldScore <name> +N|-N|=N -- named per-request
     * accumulators. An array because one rule may move more than one,
     * and because a rule that moves none is the common case and costs
     * a NULL. */
    apr_array_header_t *score_ops;   /* of bs_score_op * */
    int           status_explicit; /* 1 if operator wrote status= */
    int           mode;           /* bs_trigger_mode */
    /* accesslog=off — suppress the access-log line for a matching
     * request by breaking the log_transaction hook chain. Independent
     * of log_tag: a rule can carry a fail2ban tag AND keep its request
     * out of the access log, which is the usual want for scanner
     * probes. The module's own decision record is unaffected. See
     * bs_suppress_access_log in metrics.h for what it costs. */
    int           suppress_access_log;
    /* tier=<t>: route the match into a challenge tier instead of
     * refusing it. -1 = unset. Distinct from flag= + a flagtrigger
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
     * `BotShieldRequestTrigger ... ua=@search ...`. */
    const char         *ua_botgroup;
    /* @bot / @fake-bot — match on the classifier's verdict rather than
     * on a declared botgroup. @botgroup can only name a bot the UA
     * directory already knows, which leaves class=unknownbot (a
     * bot-shaped UA with no directory entry) impossible to name in a
     * rule at all.
     *
     * @bot deliberately means verified-bot + knownbot + unknownbot,
     * the same three the dashboard's Bots tab counts. A fake bot is a
     * UA claiming a crawler whose IP failed the cross-check -- it is
     * not a crawler, and folding it in here would put a spoofer inside
     * whatever exemption an operator grants "bots". It gets its own
     * selector so it stays nameable. 0 = axis unused. */
    int                 ua_class_bot;
    int                 ua_class_fake;
    /* @verified-bot -- the narrow half of @bot: the UA matched a
     * crawler pattern AND the client address checked out against that
     * crawler's published ranges. @bot is deliberately wide, which is
     * what "act on every bot" wants and the opposite of what "this one
     * is proven, leave it alone" wants. Before this the proven set had
     * no name in a rule, and the only way to say it was a credit large
     * enough to swamp every other term. 0 = axis unused. */
    int                 ua_class_verified;
    /* @scraper -- the UA carries a known HTTP-library token. Its own
     * selector rather than a botgroup because it is a classification
     * this module makes, not a bot the directory knows: curl and
     * python-requests are not crawlers with names, they are clients
     * that did not bother to claim one. */
    int                 ua_class_scraper;
    int                 ip_any;
    const char         *path;
    const char         *inline_cidrs;
    apr_array_header_t *ranges;
} bs_cohort;

/* Request trigger. Every
 * match dimension is optional and they AND together; the setter
 * rejects a rule with none, since that is what the per-scope
 * BotShieldTrigger is for. NULL / -1 means "this dimension does not
 * restrict". */
typedef struct {
    const char        *name;
    /* path= globs matched against r->uri; NULL = any path. A list
     * rather than one glob because the alternative is one rule per
     * path, and the paths that share an action usually share it
     * exactly -- seven near-identical probe rules differing only in a
     * string is the shape this avoids. Any element matching is a
     * match; order within the list is irrelevant. */
    apr_array_header_t *path_patterns;   /* const char * */
    /* bscookie= : the module's own session-cookie verdict, as published
     * to r->notes before the policy walk. -1 = unset.
     *
     * Exists because the two heuristics that gate almost all traffic --
     * firstsightip and droppedcookie -- are internal state, not
     * request properties, so a path= rule could not express what the
     * enclosing <Location> scope turned on. This is the larger of the
     * two: "no usable cookie" accounts for ~82% of challenges. The
     * bloom half (firstsight=) is not available here, because the bloom
     * lookup runs after bs_check_policy. */
    int                 bscookie_pred;   /* enum bs_bscookie_pred */
    /* crawler= : matches bs_ua_is_declared_crawler. -1 = unset.
     *
     * The exemption that keeps a tier= rule from challenging Googlebot.
     * It exists in the scoring path already, as !declared_crawler
     * guarding the unproven-client heuristics; this makes the same
     * exemption writable, so "crawlers pass" is a line in the config
     * instead of a conditional in C. */
    int                 crawler_pred;    /* 1 = yes, 0 = no, -1 = unset */
    const char        *query_pattern;  /* query= glob vs r->args; NULL = any */
    /* cookies= bulk predicate: one of BS_CP_BULK_NONE / _ANY / _SESSION,
     * or -1 for no cookie condition. Named-cookie predicates stay with
     * BotShieldCookieTrigger, whose vocabulary is richer than one key. */
    int                cookie_pred;
    /* exists=yes|no — does the request map to something on disk?
     * Read from r->finfo, which map_to_storage has already filled in by
     * the time the handler runs, so this costs no extra stat().
     *
     * The use it exists for: on an admin path, the real UI is files
     * that are there (templates, CSS, JS, images) while a scanner is
     * asking for thousands of paths that are not. "Challenge what does
     * not resolve, leave what does alone" separates the two without
     * enumerating either, and keeps a challenge off the sub-resources
     * that could not solve one anyway.
     *
     * -1 = no condition, 1 = must exist, 0 = must not exist. */
    int                exists_pred;
    /* solved=yes|no -- does the client hold a cookie proving it passed
     * a challenge? The single strongest predicate this module has: on a
     * production hub 100.0% of challenges carried "no solve proof", so
     * this one key reproduces what the whole scoring ladder decided.
     * -1 = no condition. */
    int                solved_pred;
    /* firstsight=yes|no -- was this address a Bloom miss?
     *
     * The address half of what the firstsightip / droppedcookie
     * heuristics measure, available here so a rule can scope it.
     * Globally those two fire everywhere or nowhere; as a predicate
     * "challenge newcomers on /login only" becomes writable.
     * Combined with solved=no it reproduces either heuristic exactly:
     * firstsight=yes is firstsightip, firstsight=no is droppedcookie.
     * -1 = no condition. */
    int                firstsight_pred;
    /* acceptlanguage="" | * -- absent-or-empty, or present.
     *
     * The missingal heuristic as a condition, spelled the way
     * BotShieldUserAgent already spells the same question: a quoted
     * empty string means the header is absent or empty, since absence
     * is not a substring and needs its own token. Deliberately not a
     * general header matcher -- that is a bigger surface with its own
     * escaping and case rules, and it is not what parity needs.
     * -1 = no condition. */
    int                acceptlang_pred;
    /* scoreatleast=<name> <n> -- match when the named accumulator has
     * reached n by the time this rule is reached. Reads what earlier
     * rules put there; NULL name = no condition. */
    const char        *score_pred_name;
    int                score_pred_min;
    /* minload=normal|warm|hot -- fires when the current load state is
     * AT OR ABOVE this level. Spelled as a minimum rather than an
     * operator so it parses as an ordinary key=value; "fires from warm
     * upwards" is the only comparison a shed ladder ever wants.
     * -1 = no condition. */
    int                minload;
    /* ua= / ipspec= cohort. has_cohort==0 means no UA/IP restriction. */
    bs_cohort          cohort;
    int                has_cohort;
    bs_trigger_action  action;
} bs_request_trigger_entry;

/* Cookie predicate kinds. Per-named lookups (NAMED_*) target a
 * specific cookie name; bulk variants (BULK_*) examine the cookie
 * map as a whole; BS_VERIFIED/MISSING/INVALID consume the
 * BS_CK_STATE_* note set by bs_handler. */
/* bscookie= values. ANY_BAD is the useful one -- missing and invalid
 * are the same thing to a policy that just wants proof, and making an
 * operator write two rules to say "unproven" would defeat the point. */
enum bs_bscookie_pred {
    BS_BSC_VERIFIED = 0,
    BS_BSC_MISSING,
    BS_BSC_INVALID,
    BS_BSC_ANY_BAD          /* missing OR invalid */
};

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
 * E14 flagtrigger family
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
    /* Refuse the request outright. Sits above every tier rather than
     * beside them: score SUMs, tier_floor MAXes, and any block wins.
     *
     * Unlike the other two this is NOT subject to excusal. A flag that
     * forces a challenge and cannot be excused is the unbreakable loop
     * that reached production twice -- solve, get re-flagged, get
     * re-challenged. A block has no loop to get stuck in: it ends the
     * request rather than asking the client for something. That is
     * what makes it safe to leave un-excusable, and why tier_floor
     * must not be. */
    BS_FLAG_ACT_BLOCK,
} bs_flag_action_kind;

typedef struct {
    const char         *flag_name;
    apr_uint32_t        flag_bit;
    bs_flag_action_kind action;
    int                 score_add;
    /* action=score accumulator=<name>. NULL means the ambient total,
     * which is what every flag trigger did before named accumulators
     * existed and what the compiled-in default slate still describes.
     *
     * A named movement dies with the request. That is the whole reason
     * to prefer it: the ambient total persists into the cookie, so a
     * flag's penalty could be billed to a client on a request that was
     * refused for something else entirely. */
    const char         *score_name;
    bs_tier             tier_min;
    int                 mode;
    int                 from_default;
    int                 block_status;   /* action=block status=N */
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
 * `family_tag` is the decision-log prefix ("cookietrigger" /
 * "envtrigger" / "loadtrigger" / "path-trigger"); `trigger_name`
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
/* Every trigger family's flat setter has this shape, which is what
 * lets one container implementation serve all of them. */
typedef const char *(*bs_trigger_setter)(cmd_parms *cmd, void *dconf,
                                         int argc, char *const argv[]);

/* Reads the lines of a <BotShieldXxx name> block, rewrites each inner
 * directive into the key=value token the flat parser already knows,
 * and calls `setter` with the result. `dname` is the family name
 * without the angle brackets. */
/* <BotShieldMatch name> -- store a named set of conditions that rules
 * splice in with BotShieldMatches. Conditions only; actions are
 * refused. */
const char *bs_set_match_set(cmd_parms *cmd, void *dconf,
                             int argc, char *const argv[]);

const char *bs_section_trigger(cmd_parms *cmd, void *dconf, const char *arg,
                               const char *dname, bs_trigger_setter setter);

/* Registered for the retired one-line form: errors with the block
 * spelling instead of Apache's bare "Invalid command". */
const char *bs_flat_trigger_retired(cmd_parms *cmd, void *dconf,
                                    int argc, char *const argv[]);

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
