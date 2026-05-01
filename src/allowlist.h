/* allowlist.h — verified-crawler building blocks for mod_botshield.
 *
 * E1's job: distinguish "real Googlebot" from "someone claiming to be
 * Googlebot." UA strings are forgeable, IP ranges aren't, so the
 * design is:
 *
 *   1. UA classifier (substring trie, case-insensitive) maps a UA to
 *      a known crawler name or NULL.
 *   2. CIDR-list lookup checks the client IP against the named
 *      crawler's published address ranges.
 *   3. Both match → verified-<name>; classifier hit but IP miss →
 *      fake-<name>; classifier miss → no-op.
 *
 * This file owns ONLY the building blocks: UA classifier, CIDR
 * loader, and the built-in bot table. The request-time orchestrator
 * (bs_check_allow) and the BotShieldAllowBot directive setters live
 * in botshield.c — they read bs_dir_cfg / bs_server_cfg and emit
 * bs_score_add, both of which are module-internal concerns. */
#ifndef BOTSHIELD_ALLOWLIST_H
#define BOTSHIELD_ALLOWLIST_H

#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_errno.h>
#include <httpd.h>
#include <http_config.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque to callers — the trie internals stay private to allowlist.c.
 * Pass the pointer around via this typedef; the only operations are
 * the four public functions below. */
typedef struct bs_ua_classifier bs_ua_classifier;

/* One declared (or built-in) crawler the operator wants the Allow
 * family to recognize. Held in scfg->allow_bots keyed on `name`.
 *
 *  pattern      — UA substring the classifier matches (case-insensitive,
 *                 longest-match wins across overlapping entries).
 *  path         — explicit ranges-file path, or NULL for the default
 *                 (/var/lib/botshield/bots/<name>.txt). Ignored when
 *                 ua_only is set or inline_cidrs is non-NULL.
 *  inline_cidrs — comma-separated CIDR list from the directive's third
 *                 arg, parsed at post_config; NULL if a path or
 *                 UA-only mode is in use instead.
 *  ua_only      — 1 when the directive's third arg was `*`; the bot is
 *                 allowed on UA match alone, no IP check. Logged with
 *                 reason "allow-bot-ua:<name>" instead of "allow-bot:". */
typedef struct {
    const char *name;
    const char *pattern;
    const char *path;
    const char *inline_cidrs;
    int         ua_only;
} bs_allow_bot_entry;

/* Built-in seed crawlers always added at post_config. NULL-name
 * sentinel terminates iteration. */
extern const bs_allow_bot_entry bs_builtin_bots[];

/* Hard cap on a CIDR-ranges file size. Real provider lists run a few
 * KB; anything past 1 MiB means an operator pointed the directive at
 * a JSON / log / wrong file. Reject loudly rather than slurp. */
#define BS_CRAWLER_MAX_RANGES_FILE  (1024 * 1024)

/* --- UA classifier ----------------------------------------------- */

/* Allocate an empty classifier on `p`. The classifier's lifetime is
 * tied to the pool's. */
bs_ua_classifier *bs_ua_classifier_create(apr_pool_t *p);

/* Register a UA substring pattern. `name` must outlive the classifier
 * — typically a static string or a string allocated on the same pool.
 * Last-writer-wins on duplicates. */
apr_status_t bs_ua_classifier_add(bs_ua_classifier *c,
                                  const char *name,
                                  const char *pattern);

/* Walk the trie at every position in `ua` and return the longest
 * terminal match across all start positions; NULL on no match.
 * Longest-match semantics matter when operators register overlapping
 * patterns — a more specific "CorpBot/Admin" must shadow a generic
 * "CorpBot" so explicit overrides do what operators expect. */
const char *bs_ua_classify(const bs_ua_classifier *c, const char *ua);

/* --- CIDR list loader ------------------------------------------- */

/* Parse a CIDR list file into an apr_array_header_t of
 * apr_ipsubnet_t *. One CIDR per line, # comments, blank lines OK,
 * IPv4 + IPv6 both accepted. Returns APR_SUCCESS with *out filled or
 * an APR error with *out_err set to a pool-allocated diagnostic. */
apr_status_t bs_allow_load_ranges(apr_pool_t *p,
                                  const char *path,
                                  apr_array_header_t **out,
                                  const char **out_err);

/* Parse a comma-separated CIDR list (BotShieldAllowBot's inline
 * mode). Same return contract as bs_allow_load_ranges. */
apr_status_t bs_allow_load_ranges_from_string(apr_pool_t *p,
                                              const char *csv,
                                              apr_array_header_t **out,
                                              const char **out_err);

/* Test r->useragent_ip against a loaded CIDR list. Returns 1 on hit,
 * 0 on miss or any parse problem with the client IP string. Defends
 * against blocking DNS via inet_pton-validate before handing the IP
 * to APR (a misconfigured / absent mod_remoteip could otherwise drop
 * a non-numeric value through to apr_sockaddr_info_get's resolver
 * timeout). */
int bs_allow_ip_in_ranges(const apr_array_header_t *ranges,
                          request_rec *r);

/* IP parsing — mirror of inet_pton with the IPv4-mapped-to-IPv6
 * normalization the SHM tables expect. Returns 1 on success. */
int bs_parse_client_ip(const char *ip_str, unsigned char out[16]);

/* IPv6-prefix mask in place — zero out the trailing (128 - prefix)
 * bits of an IPv6 address so the SHM tables key on a configured
 * subscriber prefix instead of the full address. v4-mapped addresses
 * are left untouched. */
void bs_mask_ipv6_prefix(unsigned char ip[16], int prefix_bits);

/* E1 request-time entry. Called from bs_run_builtin_heuristics when
 * BotShieldLegitCrawlers is on. Emits at most one bs_score_add call
 * per request (a dominant credit for verified crawlers, a strong
 * penalty for fakes claiming a crawler UA from the wrong IP, or a
 * neutral "bot-unverified" reason when ranges aren't loaded). */
void bs_check_allow(request_rec *r, const bs_dir_cfg *cfg);

/* --- E1 directive setters --- *
 *
 * BotShieldAllow on|off — master gate for the allow-list family.
 * BotShieldAllowBot <name> <ua-pattern> [<target>] — register a bot
 * with optional UA-only/file/inline-CIDR target. */
const char *bs_set_verified_bots(cmd_parms *cmd, void *dconf, int flag);
const char *bs_set_allow_bot(cmd_parms *cmd, void *dconf,
                             const char *name,
                             const char *pattern,
                             const char *target);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_ALLOWLIST_H */
