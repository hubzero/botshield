/* load.h — E11 load-aware throttling.
 *
 * mod_watchdog samples the Apache scoreboard's busy-worker ratio
 * every BotShieldLoadRefreshInterval seconds, optionally merges in
 * an external operator-set state from BotShieldLoadStateFile, and
 * folds the result into a cached state in SHM with hysteresis.
 *
 * The request path reads bs_shm.header->load_state as a single
 * lockless u32 via bs_load_current() — no scoreboard scans on the
 * hot path. E11.2's BotShieldLoadTrigger predicate matcher consumes
 * that state.
 *
 * The state machine has three values (BS_LOAD_NORMAL/WARM/HOT
 * defined in shm.h) and asymmetric transition rules — fast to
 * escalate (3 escalating samples to warm; 2 more to hot), slow to
 * recover (5 normal samples to demote one level). Tuning constants
 * live in shm.h alongside the enum so the SHM header layout that
 * carries them is in one place. */
#ifndef BOTSHIELD_LOAD_H
#define BOTSHIELD_LOAD_H

#include <httpd.h>
#include <http_config.h>
#include <ap_config.h>
#include <apr_pools.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Lockless atomic read of the current load state. Used by E11.2's
 * BotShieldLoadTrigger predicate matcher in bs_check_policy. Returns
 * BS_LOAD_NORMAL when the SHM segment isn't attached yet. */
bs_load_state bs_load_current(void);

/* mod_watchdog tick callback. Registered in bs_post_config when
 * mod_watchdog is loaded. Samples the scoreboard, reads the
 * operator-set external file (if configured), merges most-severe-
 * wins, and folds the result into the SHM-resident load_state via
 * the hysteresis machine. Single-thread (one watchdog), so no
 * locking; readers see a consistent state because the final write
 * is to load_state itself. */
apr_status_t bs_load_watchdog_cb(int state, void *data,
                                 apr_pool_t *pool);

/* --- Directive setters --------------------------------------- */

/* BotShieldLoadStateFile <path> — operator-writable file whose body
 * is `normal`, `warm`, or `hot` (whitespace tolerated). The watchdog
 * stat-polls mtime once per refresh tick; only re-reads when mtime
 * changed. Most-severe-wins merging means an external `hot` overrides
 * any internal sensing decision. */
const char *bs_set_load_state_file(cmd_parms *cmd, void *dconf,
                                   const char *arg);

/* BotShieldLoadRefreshInterval <seconds> — watchdog tick cadence,
 * 1..60s, default BS_DEFAULT_LOAD_REFRESH_SEC. */
const char *bs_set_load_refresh(cmd_parms *cmd, void *dconf,
                                const char *arg);

/* BotShieldLoadWarmThreshold <percent> — busy-worker ratio at which
 * a sample is classified warm. 1..99, default
 * BS_DEFAULT_LOAD_WARM_RATIO_PCT. */
const char *bs_set_load_warm_pct(cmd_parms *cmd, void *dconf,
                                 const char *arg);

/* BotShieldLoadHotThreshold <percent> — same shape as warm, default
 * BS_DEFAULT_LOAD_HOT_RATIO_PCT. (Operators are responsible for
 * setting hot strictly greater than warm; the watchdog won't crash
 * if they don't but the warm tier becomes unreachable.) */
const char *bs_set_load_hot_pct(cmd_parms *cmd, void *dconf,
                                const char *arg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_LOAD_H */
