/* triggers.h — E3/E4/E6/E7.3/E11.2 trigger families.
 *
 * Five trigger families share one config-time action engine and one
 * request-time executor. The families differ in their predicate
 * shape (path glob, cookie name+value, env var, app-feedback event,
 * load tier) but funnel through the same bs_trigger_action struct
 * and the same bs_apply_trigger_action executor.
 *
 *   E3  BotShieldPathTrigger      path glob       request-path
 *   E4  BotShieldCookieTrigger    cookie name/val request-path
 *   E6  BotShieldEnvTrigger       env var         request-path
 *   E7.3 BotShieldFeedbackTrigger event name      response-path
 *   E11.2 BotShieldLoadTrigger    load state      request-path
 *
 * Each family has its own directive setter (bs_set_*_trigger) that
 * parses family-specific predicate args, then delegates the shared
 * key=value action keys (status, redirect, log, flag, ttl, penalty,
 * credit, mode) to bs_parse_trigger_action_key + finalize.
 *
 * The request-path walker bs_check_policy in botshield.c calls
 * bs_apply_trigger_action with the matched entry's action; the
 * response-path E5 filter in bridge.c calls it for feedback. Outcome
 * codes (BS_TEXEC_*) tell the caller whether to short-circuit, end
 * the family loop, or keep accumulating credits. */
#ifndef BOTSHIELD_TRIGGERS_H
#define BOTSHIELD_TRIGGERS_H

#include <httpd.h>
#include <http_config.h>
#include <apr_tables.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- Per-family entry types --------------------------------- *
 *
 * One entry per BotShield<family>Trigger directive. Each carries
 * its family-specific predicate plus a shared bs_trigger_action
 * (action keys parsed by bs_parse_trigger_action_key in triggers.c).
 * scfg holds parallel apr_arrays of these — bs_check_policy walks
 * each in declaration order. */

typedef struct {
    const char        *name;
    const char        *path_pattern;
    bs_trigger_action  action;
} bs_path_trigger_entry;

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

/* --- Cookie-trigger predicate matcher ----------------------- *
 *
 * Evaluate one BotShieldCookieTrigger entry's predicate against the
 * already-parsed cookie map and the BS-cookie-state note set by
 * bs_handler. Returns 1 on match, 0 on no match. */
int bs_cookie_pred_match(const bs_cookie_trigger_entry *e,
                         apr_table_t *cmap,
                         const apr_array_header_t *session_names,
                         const char *bs_state);

/* --- Shared action engine: executor ------------------------- *
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
 * is the operator's per-rule label. */
bs_trigger_exec_outcome bs_apply_trigger_action(
    request_rec *r,
    struct bs_server_cfg *scfg,
    bs_trigger_family fam,
    const bs_trigger_action *a,
    const char *family_tag,
    const char *trigger_name);

/* --- Directive setters -------------------------------------- *
 *
 * Each family's setter parses its own predicate args (path glob /
 * cookie spec / env var / event name / load match) then runs the
 * remaining argv through the shared action-key parser. Setters
 * upsert by name so re-declaring a name updates rather than
 * appends. */

const char *bs_set_path_trigger    (cmd_parms *cmd, void *dconf,
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

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_TRIGGERS_H */
