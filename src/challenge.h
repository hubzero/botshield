/* challenge.h — challenge issuance, PoW algorithm registry,
 * reputation state envelope, and the bootstrap-sig helpers shared
 * between M7 (interstitial) and E17 (non-interactive tier embedded mode).
 *
 * The "challenge" abstraction is a pre-shared opaque envelope the
 * server signs once and the client returns having proved possession
 * of a small bit of work (PoW counter) or a third-party attestation
 * (captcha siteverify response). Both interstitial and non-interactive paths
 * use the same bs_challenge struct + algorithm registry.
 *
 * Wire format (embedded inline in the interstitial, JSON):
 *     { v, alg, salt, nonce, difficulty, expires_at,
 *       score, flags, passes_non_interactive, passes_interactive, passes_captcha,
 *       challenged_at, auto, signature }
 *
 * Canonical HMAC input (deterministic, pipe-delimited ASCII):
 *     "v|alg|salthex|noncehex|difficulty|expires_at
 *      |score|flags|pass_s|pass_f|pass_c|challenged_at|auto"
 *
 * Cookie payload = base64( canonical || "|" || sighex || "|" || counter )
 * — a single base64 blob the server can parse by splitting on '|',
 * no JSON parser required.
 *
 * `auto` is the non-interactive tier (M7) marker: 1 means the challenge was
 * served as a no-click auto-submit splash, 0 means the interactive PoW
 * interstitial. HMAC-covered so an accepted cookie tells the server
 * which tier actually served it — used to pick passes_non_interactive vs
 * passes_interactive and the matching forgiveness amount on verify.
 *
 * Keep in sync with the JS worker (non_interactive.c) when the template
 * ships the wire bits. */
#ifndef BOTSHIELD_CHALLENGE_H
#define BOTSHIELD_CHALLENGE_H

#include <httpd.h>
#include <http_config.h>
#include <apr.h>
#include <apr_pools.h>
#include <apr_time.h>

#include "crypto.h"   /* BS_SIG_BYTES, primitives */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — bs_dir_cfg is defined in botshield.h.
 * Declared here so this header is self-contained. */
struct bs_dir_cfg;
typedef struct bs_dir_cfg bs_dir_cfg;

/* ======================================================================
 * Challenge wire-format constants
 * ====================================================================== */

/* Bumped 1->2 for E15: rep envelope grew two fields
 * (forgive_window_start, forgive_consumed). Old (v1) cookies fail the
 * version check and trigger a fresh challenge — one-time disruption
 * per client on upgrade. */
#define BS_PROTOCOL_VERSION   2
#define BS_SALT_BYTES         16
#define BS_NONCE_BYTES        8

/* ======================================================================
 * Reputation state and challenge envelope
 * ====================================================================== */

/* Reputation state carried in the cookie. Populated fresh on a first-
 * time challenge (all zeros), and merged forward with forgiveness on
 * re-issues.
 *
 * E15 — forgiveness cap per window. `forgive_window_start` marks the
 * start of the current rolling hour (unix sec); on every verify-
 * success we either roll the window if the prior one is over an hour
 * old, or clamp the new forgiveness so the running consumed total
 * stays at or below BotShieldForgivenessCapPerHour. */
typedef struct {
    int          score;
    /* Flags the holder has already answered for.
     *
     * Wire field 7. It was originally "cookie-side flags", OR'd into the
     * IP-side set so a flag followed the cookie -- but nothing ever
     * wrote it, so it has always been zero on the wire. It now records
     * the flag set that was live at the moment this cookie's challenge
     * was solved, and those flags are skipped on later requests.
     *
     * This is what stops a flagged client looping forever. Solving does
     * not clear a flag, and flag scores are re-applied on every request,
     * so before this a flag worth more than BotShieldScoreNonInteractive meant
     * an unbreakable challenge loop no matter how many times the client
     * solved. Flags acquired AFTER the solve are absent from this set
     * and still fire, so the excusal pays off the debt that existed at
     * solve time without granting immunity to new evidence.
     *
     * No protocol bump: same slot, same width, and the old always-zero
     * value reads as "nothing excused", which is exactly the previous
     * behaviour until the client next solves. */
    apr_uint32_t flags_excused;
    int          passes_non_interactive;
    int          passes_interactive;
    int          passes_captcha;
    apr_time_t   challenged_at;        /* unix sec */
    apr_uint32_t forgive_window_start; /* unix sec; 0 = no window yet */
    apr_uint32_t forgive_consumed;     /* points used inside current window */
} bs_rep_state;

typedef struct {
    int           version;
    const char   *alg_name;              /* points into registry */
    unsigned char salt [BS_SALT_BYTES];
    unsigned char nonce[BS_NONCE_BYTES];
    int           difficulty;
    apr_time_t    expires_at;            /* unix seconds */
    bs_rep_state  rep;                   /* carried forward across re-issues */
    int           auto_tier;             /* 1 = non-interactive M7 auto-submit; 0 = form */
    unsigned char signature[BS_SIG_BYTES];
} bs_challenge;

/* ======================================================================
 * PoW algorithm registry
 * ====================================================================== */

typedef const char *(*bs_alg_issue_fn)(const bs_dir_cfg *cfg,
                                       bs_challenge *out);
typedef const char *(*bs_alg_verify_fn)(const bs_challenge *ch,
                                        const char *counter_str);

typedef struct {
    const char       *name;
    int               implemented;   /* 1 = callable, 0 = reserved */
    bs_alg_issue_fn   issue;
    bs_alg_verify_fn  verify;
} bs_pow_algorithm;

/* ======================================================================
 * Challenge API
 * ====================================================================== */

/* PoW algorithm registry lookup. Returns NULL on no match. */
const bs_pow_algorithm *bs_find_algorithm(const char *name);

/* Build the canonical pipe-delimited HMAC input string for a
 * challenge. Both the issue path (signs this string) and the verify
 * path (recomputes and compares HMACs) produce the exact same
 * canonical bytes for a given challenge struct — that's the
 * tamper-detection contract. Returned string is pool-allocated. */
const char *bs_challenge_canonical(apr_pool_t *p, const bs_challenge *ch);

/* Issue a fresh challenge: fills `*out` with version, alg, salt,
 * nonce, difficulty, expires_at, auto_tier, and the alg-specific
 * signature. `rep_in` carries forward reputation across re-issues
 * (NULL = first-time challenge with zero rep). `alg_override` lets
 * the captcha-tier path pin a specific alg row regardless of
 * cfg->algorithm; pass NULL to use the configured algorithm. */
const char *bs_issue_challenge(apr_pool_t *p, const bs_dir_cfg *cfg,
                               int difficulty, int cookie_ttl,
                               int auto_tier,
                               const bs_pow_algorithm *alg_override,
                               const bs_rep_state *rep_in,
                               bs_challenge *out);

/* Render a challenge as the inline JSON the M7 interstitial JS
 * consumes. Includes the encrypted cookie prefix, salt/nonce/
 * difficulty/expires, and (for embedded non-interactive tier mode) the
 * bound-IP HMAC pair. */
const char *bs_challenge_json(request_rec *r, apr_pool_t *p,
                              const bs_dir_cfg *cfg,
                              const bs_challenge *ch);

/* bootstrap-binding helpers — bind the non-interactive tier
 * embedded-bootstrap to the originating client IP via an HMAC over
 * (nonce, bound_ip_hex, expires_at). Issued at bootstrap time,
 * verified at /embedded-verify time. */
int  bs_format_bound_ip_hex(const char *useragent_ip,
                            char out_hex[33]);
void bs_compute_bootstrap_sig(apr_pool_t *p,
                              const unsigned char key[32],
                              const char *nonce_hex,
                              const char *bound_ip_hex,
                              apr_time_t expires_at,
                              apr_int64_t issued_ms,
                              char out_sig_hex[BS_SIG_BYTES * 2 + 1]);

/* Floor on issue -> verify wall time for the interactive tier, in
 * milliseconds.
 *
 * rep.challenged_at cannot serve here: it is unix SECONDS, so the
 * finest floor it could express is a whole second, which is longer
 * than a real click. issued_ms rides in the bootstrap signature
 * instead -- the same HMAC that already binds nonce and IP -- so the
 * client cannot move it, and the clock is entirely the server's.
 *
 * The 400ms default comes from measurement, not from reaction-time
 * literature. Driving this page with Playwright, the fastest a warmed
 * browser could load, render and land a trusted click was 177ms; cold
 * it was 239ms. The first cut of this floor was 150ms, which sat under
 * both -- it cost an attacker nothing, because rendering already
 * exceeds it. 400ms refuses every run of that harness while staying
 * well under a person noticing the widget and moving a mouse to it.
 *
 * Only the interactive tier is bounded: the non-interactive tier has
 * no human in the loop and its solve starts at DOMContentLoaded.
 *
 * This does not stop a bot that sleeps. It makes sleeping mandatory,
 * and because the clock is the server's the delay is real wall time
 * per request rather than a field the client can fill in.
 *
 * BotShieldInteractiveMinSolveMs overrides it, and 0 disables it. The
 * right value is deployment-specific -- a heavier page pushes humans
 * and bots alike later -- and an operator hitting false positives
 * needs an off switch that is not a recompile. */
#define BS_DEFAULT_INTERACTIVE_MIN_MS 400

/* How long the interactive widget withholds its checkbox.
 *
 * The point is not the delay, it is that the delay is OURS. A bare
 * floor is a guess about how fast people are, and it charges the
 * quick ones. Withholding the control makes the earliest legitimate
 * submit (window + reaction) a fact instead, and the server can floor
 * at least the window for free -- no legitimate client can beat it.
 *
 * The checkbox is absent during the window, not present-but-inert: a
 * visible control that swallows clicks trains people to think the
 * page is broken, and it is the confident fast clickers who hit it.
 *
 * 300 is a testing value. 100 is the better production one -- below
 * the threshold where a delay reads as a delay at all, so nobody
 * waits, while the sharper signal survives the shrink. That signal is
 * the GAP: a person clicks hundreds of ms after the reveal, a poller
 * within a few, and the gap does not care how long the window was. */
#define BS_DEFAULT_INTERACTIVE_ARM_MS 300

/* Bounds on the client's attestation array. Attacker-controlled
 * input reaching the decision log, so cap the count and the length
 * of each label; the alphabet is checked separately. */
#define BS_ATT_MAX_ITEMS     8
#define BS_ATT_MAX_ITEM_LEN 24

/* `BotShieldAlgorithm <name>` — pin the PoW algorithm for cookie
 * minting from this scope. Validates against the registry and the
 * implemented flag. */
const char *bs_set_algorithm(cmd_parms *cmd, void *cfg_v,
                             const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_CHALLENGE_H */
