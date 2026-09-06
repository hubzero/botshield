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
 *  ua_only      — 1 when the directive's third arg was `*`; operator
 *                 opted out of IP verification for this bot. UA match
 *                 alone doesn't qualify for verified-bot credit, so
 *                 the entry just contributes its UA pattern to the
 *                 knownbot pool (logged as "knownbot:<name>", score 0). */
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

/* --- Live-reloadable bot-ranges state ---------------------------- *
 *
 * The set of CIDR lists that bs_check_allow reads at request time.
 * Allocated from a private subpool of pconf and atomic-swapped by
 * bs_allow_ranges_watchdog_cb when any of the source files change
 * on disk. The previously-active state is held one watchdog tick
 * before its pool is destroyed so concurrent readers can't deref
 * freed memory.
 *
 * Per-vhost: scfg->bot_ranges points at the active state; the
 * watchdog walks scfg->bot_ranges_manifest to know what to stat.
 *
 * Sidecar convention: each file-backed bot is loaded from
 *   <canonical>          (refreshed by services/refresh/botshield-refresh.py)
 *   <canonical-without-.txt>.local.txt   (operator-managed extras)
 * The sidecar is optional. If both exist, their CIDR sets are
 * concatenated. The sidecar is the seam for adding custom enterprise
 * scanner IPs that aren't published in the provider's public feed
 * (e.g. dedicated Siteimprove scans contracted for one site). */
typedef struct bs_bot_ranges_state {
    apr_pool_t *pool;          /* owns by_name + every contained array */
    apr_hash_t *by_name;       /* name (const char *) → apr_array_header_t * of apr_ipsubnet_t * */
    apr_hash_t *file_mtimes;   /* name → bs_bot_file_mtimes *; only file-backed bots */
} bs_bot_ranges_state;

typedef struct bs_bot_file_mtimes {
    apr_time_t canonical_mtime; /* 0 if file missing at last check */
    apr_time_t sidecar_mtime;   /* 0 if file missing at last check */
} bs_bot_file_mtimes;

/* Manifest: the set of bots configured for this vhost, retained
 * across watchdog ticks so the rebuilder knows what to load. Built
 * once in bs_wire_allowlist from pconf; immutable thereafter (apart
 * from `pending_drain`, the one-tick destroy-deferred slot used by
 * bs_allow_ranges_publish). */
typedef struct bs_bot_ranges_manifest {
    server_rec         *s;            /* for log context */
    apr_pool_t         *pool;         /* pconf — outlives all generations */
    apr_array_header_t *file_bots;    /* of bs_bot_file_manifest_entry */
    apr_array_header_t *inline_bots;  /* of bs_bot_inline_manifest_entry */
    /* Previously-active state, parked here so concurrent readers
     * still finishing apr_hash_get on the old hash can't deref freed
     * memory. Destroyed on the *next* publish, giving readers a
     * full watchdog tick of grace. Touched only by the watchdog
     * thread, no lock required. */
    bs_bot_ranges_state *pending_drain;
} bs_bot_ranges_manifest;

typedef struct bs_bot_file_manifest_entry {
    const char *name;             /* bot key */
    const char *canonical_path;   /* explicit path or default-derived */
    const char *sidecar_path;     /* derived: <base>.local.txt or <path>.local */
} bs_bot_file_manifest_entry;

typedef struct bs_bot_inline_manifest_entry {
    const char *name;             /* bot key */
    const char *inline_cidrs;     /* directive's inline list, re-parsed each rebuild */
} bs_bot_inline_manifest_entry;

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

/* Sidecar-aware loader. Reads `canonical_path` (required) and
 * `sidecar_path` (optional — missing file is fine, anything else is
 * a parse error). Returns the concatenation in *out. Sets
 * *out_canonical_mtime / *out_sidecar_mtime to the observed mtimes
 * (0 if a file was absent). On any failure of the canonical file,
 * returns the underlying APR error and *out stays NULL.
 *
 * Pass NULL for sidecar_path to skip the sidecar entirely. */
apr_status_t bs_allow_load_ranges_with_sidecar(
    apr_pool_t *p,
    const char *canonical_path,
    const char *sidecar_path,
    apr_array_header_t **out,
    apr_time_t *out_canonical_mtime,
    apr_time_t *out_sidecar_mtime,
    const char **out_err);

/* Derive a sidecar path from a canonical path. Convention: if the
 * canonical ends in ".txt", swap to "<base>.local.txt"; otherwise
 * append ".local". Result allocated on `p`. Stable across calls so
 * the watchdog can stat the same path it'll later load. */
const char *bs_allow_sidecar_path(apr_pool_t *p, const char *canonical);

/* --- Live-reloadable state machinery ---------------------------- *
 *
 * Build a fresh bs_bot_ranges_state from the manifest. Every entry
 * in `manifest` is loaded and its ranges populated into the new
 * state; missing file-backed bots are logged but don't fail the
 * whole rebuild (they just have no ranges this generation; the bot's
 * UA pattern still matches but lands in the knownbot pool with
 * score 0 instead of getting verified-bot credit). Returns NULL only
 * on subpool allocation failure. */
bs_bot_ranges_state *bs_allow_ranges_build(
    const bs_bot_ranges_manifest *manifest);

/* Atomically swap `new_state` in as the active per-vhost state.
 * Drains the previously-active state on the next swap (one-tick
 * grace). Pass NULL only at process teardown — request-time readers
 * tolerate it but the result is "no verification possible." */
void bs_allow_ranges_publish(server_rec *s,
                             bs_bot_ranges_state *new_state);

/* mod_watchdog tick callback. Registered with singleton=0 so each
 * worker child gets its own update — the active state pointer is
 * process-local. Stat()s every manifest file each tick; rebuilds +
 * publishes only on observed mtime change. */
apr_status_t bs_allow_ranges_watchdog_cb(int state, void *data,
                                         apr_pool_t *pool);

/* Setter for BotShieldAllowRangesRefreshInterval. */
const char *bs_set_allow_ranges_refresh_interval(cmd_parms *cmd,
                                                 void *dconf,
                                                 const char *arg);

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

/* E1 request-time entry, called from bs_handler.
 *
 * Emits at most one reason per request -- verifiedbot:<name> for an
 * IP-confirmed crawler, fakebot:<name> for one claiming a crawler UA
 * from outside its ranges -- and no score with either. What each means
 * is a rule: ua=@verified-bot, ua=@fake-bot. UA-only and
 * ranges-not-loaded states emit nothing here; bs_handler's knownbot
 * block tags them as knownbot:<name>. */
void bs_check_allow(request_rec *r, const bs_dir_cfg *cfg);

/* --- E1 directive setters --- *
 *
 * BotShieldAllowBot <name> <ua-pattern> [<target>] — register a
 * verified-bot entry with optional UA-only/file/inline-CIDR target.
 * The bundled built-in set (data/verified-bots.json) loads
 * automatically; operator-declared entries via this directive are
 * overlaid on top (same-name operator entries replace the built-in).
 * Whether the verified-bot pass actually runs at request time is
 * controlled by BotShieldClassify. */
const char *bs_set_allow_bot(cmd_parms *cmd, void *dconf,
                             const char *name,
                             const char *pattern,
                             const char *target);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_ALLOWLIST_H */
