/* load.c — E11 load-aware throttling.
 *
 * Watchdog tick samples the Apache scoreboard's busy-worker ratio,
 * optionally merges in an external operator-set state from a watched
 * file, and folds the result into a cached state in SHM with
 * hysteresis. Request path reads bs_shm.header->load_state as a
 * single atomic u32 via bs_load_current — no scoreboard scans on the
 * hot path.
 *
 * State transitions write load_state last, after the streak counters
 * and the load_state_changes metric, so an unlucky reader sees a
 * self-consistent snapshot — at worst a slightly stale state for a
 * few microseconds. That's fine for a coarse 3-value brownout
 * signal.
 *
 * Tunables (BS_DEFAULT_LOAD_*) live in shm.h alongside the SHM-
 * resident state they describe. */
#include <string.h>
#include <stdlib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <ap_config.h>
#include <scoreboard.h>
#include <mod_watchdog.h>

#include <apr_atomic.h>
#include <apr_strings.h>
#include <apr_file_io.h>

#include "botshield.h"
#include "load.h"
#include "shm.h"

static int bs_load_effective_int(int v, int dflt)
{
    return (v > 0) ? v : dflt;
}

/* Map a sampled busy-worker ratio (percent of total slots) to a
 * candidate state via the operator's thresholds. */
static bs_load_state bs_load_state_from_pct(int busy_pct,
                                            int warm_pct, int hot_pct)
{
    if (busy_pct >= hot_pct)  return BS_LOAD_HOT;
    if (busy_pct >= warm_pct) return BS_LOAD_WARM;
    return BS_LOAD_NORMAL;
}

/* Read + parse the external load-state file. Caches by mtime so a
 * sampler that ticks every second only does an open()/read() when
 * the file actually changed (operator's monitor wrote a new value).
 * On any error: leave the cache untouched and return whatever the
 * last successful read produced (or NORMAL if never read). */
static bs_load_state bs_load_read_external(server_rec *sv,
                                           bs_server_cfg *scfg)
{
    if (!scfg->load_state_file) return BS_LOAD_NORMAL;
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, scfg->load_state_file,
                               APR_FINFO_MTIME, sv->process->pconf);
    if (rv != APR_SUCCESS) {
        /* File missing is normal if the operator hasn't written one
         * yet. Don't log per-tick or we'd spam. */
        return scfg->load_external_cached;
    }
    if (finfo.mtime == scfg->load_external_mtime) {
        return scfg->load_external_cached;   /* unchanged */
    }

    apr_file_t *f = NULL;
    rv = apr_file_open(&f, scfg->load_state_file,
                       APR_READ | APR_BINARY, 0, sv->process->pconf);
    if (rv != APR_SUCCESS) return scfg->load_external_cached;

    char buf[32];
    apr_size_t got = sizeof(buf) - 1;
    rv = apr_file_read(f, buf, &got);
    apr_file_close(f);
    if (rv != APR_SUCCESS && rv != APR_EOF) {
        return scfg->load_external_cached;
    }
    buf[got] = '\0';
    /* Trim trailing whitespace/newline so `echo hot > file` works. */
    while (got > 0 && (buf[got-1] == '\n' || buf[got-1] == '\r'
                       || buf[got-1] == ' '  || buf[got-1] == '\t')) {
        buf[--got] = '\0';
    }
    /* Trim leading whitespace too. */
    char *p = buf;
    while (*p == ' ' || *p == '\t') p++;

    bs_load_state parsed;
    if      (!strcasecmp(p, "normal")) parsed = BS_LOAD_NORMAL;
    else if (!strcasecmp(p, "warm"))   parsed = BS_LOAD_WARM;
    else if (!strcasecmp(p, "hot"))    parsed = BS_LOAD_HOT;
    else {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sv,
            "mod_botshield: BotShieldLoadStateFile '%s' contains "
            "unrecognized value '%s' (expected normal|warm|hot); "
            "treating as normal",
            scfg->load_state_file, p);
        parsed = BS_LOAD_NORMAL;
    }
    scfg->load_external_cached = parsed;
    scfg->load_external_mtime  = finfo.mtime;
    if (parsed != BS_LOAD_NORMAL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: external load state from '%s': %s",
            scfg->load_state_file, p);
    }
    return parsed;
}

/* Sample the Apache scoreboard. Returns busy_pct = 100 *
 * busy_workers / total_worker_slots. "Busy" = anything that's
 * actively servicing a request: BUSY_READ/WRITE/KEEPALIVE/LOG/DNS
 * + GRACEFUL (still serving its current request). READY and DEAD
 * slots don't count as busy. */
static int bs_load_sample_scoreboard(void)
{
    if (!ap_exists_scoreboard_image()) return 0;
    global_score *gs = ap_get_scoreboard_global();
    if (!gs) return 0;
    int total = gs->server_limit * gs->thread_limit;
    if (total <= 0) return 0;

    int busy = 0;
    for (int i = 0; i < gs->server_limit; i++) {
        for (int j = 0; j < gs->thread_limit; j++) {
            worker_score *ws =
                ap_get_scoreboard_worker_from_indexes(i, j);
            if (!ws) continue;
            switch (ws->status) {
            case SERVER_BUSY_READ:
            case SERVER_BUSY_WRITE:
            case SERVER_BUSY_KEEPALIVE:
            case SERVER_BUSY_LOG:
            case SERVER_BUSY_DNS:
            case SERVER_GRACEFUL:
                busy++;
                break;
            default:
                break;
            }
        }
    }
    return (busy * 100) / total;
}

/* Apply hysteresis. Given a candidate state from this tick's
 * sampling, decide whether to promote/demote the cached state.
 * Asymmetric: easy to enter (3 escalating samples to warm; 2 more
 * to hot), slow to exit (5 normal samples to demote one level).
 * Reset the opposite streak whenever the candidate changes
 * direction.
 *
 * Writes through the SHM header. Single-thread (watchdog), so no
 * locking; readers see a consistent state because the final write
 * is to load_state itself. */
static void bs_load_apply_tick(server_rec *sv, bs_server_cfg *scfg,
                               bs_load_state candidate)
{
    if (!bs_shm.header) return;
    int warm_rise = bs_load_effective_int(scfg->load_warm_rise,
                        BS_DEFAULT_LOAD_WARM_RISE);
    int hot_rise  = bs_load_effective_int(scfg->load_hot_rise,
                        BS_DEFAULT_LOAD_HOT_RISE);
    int fall      = bs_load_effective_int(scfg->load_normal_fall,
                        BS_DEFAULT_LOAD_NORMAL_FALL);

    bs_load_state current = (bs_load_state)bs_shm.header->load_state;
    bs_load_state next    = current;

    if (candidate > current) {
        bs_shm.header->load_recovery_streak = 0;
        bs_shm.header->load_escalation_streak++;
        int need = (current == BS_LOAD_NORMAL) ? warm_rise : hot_rise;
        if ((int)bs_shm.header->load_escalation_streak >= need) {
            next = (bs_load_state)(current + 1);
            bs_shm.header->load_escalation_streak = 0;
        }
    } else if (candidate < current) {
        bs_shm.header->load_escalation_streak = 0;
        bs_shm.header->load_recovery_streak++;
        if ((int)bs_shm.header->load_recovery_streak >= fall) {
            next = (bs_load_state)(current - 1);
            bs_shm.header->load_recovery_streak = 0;
        }
    } else {
        /* Steady-state: any drift toward edge resets. */
        bs_shm.header->load_escalation_streak = 0;
        bs_shm.header->load_recovery_streak   = 0;
    }

    if (next != current) {
        const char *names[] = { "normal", "warm", "hot" };
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
            "mod_botshield: load state %s -> %s",
            names[current], names[next]);
        bs_shm.header->load_state_since_sec =
            (apr_uint32_t)apr_time_sec(apr_time_now());
        bs_shm.header->load_state_changes++;
        /* Publish the new state last so a request reading the field
         * sees either the old or the new value, not torn metadata. */
        apr_atomic_set32(&bs_shm.header->load_state,
                         (apr_uint32_t)next);
    }
}

/* mod_watchdog tick. Sample, merge with external file, fold into
 * the cached state. Cheap enough to run every second per main
 * server. */
apr_status_t bs_load_watchdog_cb(int state, void *data,
                                 apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    server_rec *sv = data;
    if (!sv) return APR_SUCCESS;
    bs_server_cfg *scfg =
        ap_get_module_config(sv->module_config, &botshield_module);
    if (!scfg) return APR_SUCCESS;

    int warm_pct = bs_load_effective_int(scfg->load_warm_pct,
                       BS_DEFAULT_LOAD_WARM_RATIO_PCT);
    int hot_pct  = bs_load_effective_int(scfg->load_hot_pct,
                       BS_DEFAULT_LOAD_HOT_RATIO_PCT);
    int busy_pct = bs_load_sample_scoreboard();
    bs_load_state internal = bs_load_state_from_pct(busy_pct,
                                                    warm_pct, hot_pct);
    bs_load_state external = bs_load_read_external(sv, scfg);

    /* Most-severe-wins merge. */
    bs_load_state candidate = (internal > external) ? internal : external;
    bs_load_apply_tick(sv, scfg, candidate);
    return APR_SUCCESS;
}

/* Cheap request-path read of the cached state. Lockless atomic.
 * Used by E11.2's BotShieldLoadTrigger predicate matcher. */
bs_load_state bs_load_current(void)
{
    if (!bs_shm.header) return BS_LOAD_NORMAL;
    return (bs_load_state)apr_atomic_read32(&bs_shm.header->load_state);
}

/* --- Directive setters --------------------------------------- */

/* BotShieldLoadStateFile <path>. Operator-writable file whose body
 * is `normal`, `warm`, or `hot` (whitespace tolerated). Watchdog
 * stat-polls mtime once per refresh tick; only re-reads when mtime
 * changed. Most-severe-wins merging means an external `hot` overrides
 * any internal sensing decision. */
const char *bs_set_load_state_file(cmd_parms *cmd, void *dconf,
                                   const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) {
        return "BotShieldLoadStateFile: path required";
    }
    if (arg[0] != '/') {
        return "BotShieldLoadStateFile: path must be absolute";
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_state_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* BotShieldLoadRefreshInterval <seconds>. How often the watchdog
 * samples + reads the external file. Default 1s; the lockless cached
 * read on the request path keeps this from affecting hot-path cost. */
const char *bs_set_load_refresh(cmd_parms *cmd, void *dconf,
                                const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 60) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadRefreshInterval: '%s' must be 1..60 seconds",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_refresh_sec = (int)n;
    return NULL;
}

/* BotShieldLoadWarmThreshold <percent>. Busy-worker ratio (percent
 * of total worker slots) at which a sample is classified warm.
 * Default 65. */
const char *bs_set_load_warm_pct(cmd_parms *cmd, void *dconf,
                                 const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 99) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadWarmThreshold: '%s' must be 1..99 (percent)",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_warm_pct = (int)n;
    return NULL;
}

/* BotShieldLoadHotThreshold <percent>. Default 85; must be strictly
 * greater than the warm threshold. */
const char *bs_set_load_hot_pct(cmd_parms *cmd, void *dconf,
                                const char *arg)
{
    (void)dconf;
    char *end = NULL;
    long n = strtol(arg, &end, 10);
    if (!end || *end || n < 1 || n > 99) {
        return apr_psprintf(cmd->pool,
            "BotShieldLoadHotThreshold: '%s' must be 1..99 (percent)",
            arg);
    }
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->load_hot_pct = (int)n;
    return NULL;
}
