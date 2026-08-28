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
#include <stdio.h>      /* sscanf for /proc/loadavg */
#include <unistd.h>     /* sysconf(_SC_NPROCESSORS_ONLN) */

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

/* Sample the 1-minute load average, normalised per CPU, in hundredths
 * (loadavg 3.0 on 6 cores -> 50).
 *
 * The scoreboard ratio below cannot see this deployment's failure mode.
 * With MaxRequestWorkers 1024 on 6 cores, the box is CPU-saturated at a
 * busy ratio in the single digits: four separate outages ran at 25-30
 * busy workers -- 2-3% -- while the 1-minute load average was well past
 * the point where requests took thirty seconds. A worker-ratio trigger
 * calibrated to fire there would be indistinguishable from noise.
 *
 * Per-CPU normalisation so one threshold means the same thing on a
 * 6-core hub and a 64-core one. Read every tick: /proc/loadavg is a
 * kernel-computed value, so this is one small read, not a scan.
 *
 * Returns -1 when unavailable (non-Linux, /proc not mounted), which
 * the caller treats as "this signal has no opinion" rather than as
 * zero -- zero would be an active claim that the box is idle. */
static int bs_load_sample_loadavg(apr_pool_t *pool)
{
    apr_file_t *f = NULL;
    char buf[64];
    apr_size_t n = sizeof(buf) - 1;
    if (apr_file_open(&f, "/proc/loadavg", APR_READ | APR_BINARY, 0,
                      pool) != APR_SUCCESS) {
        return -1;
    }
    apr_status_t rv = apr_file_read(f, buf, &n);
    apr_file_close(f);
    if (rv != APR_SUCCESS || n == 0) return -1;
    buf[n] = '\0';

    /* "0.31 0.48 1.31 1/523 12345" -- first field only. */
    double one = 0.0;
    if (sscanf(buf, "%lf", &one) != 1) return -1;

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    return (int)((one * 100.0) / (double)ncpu);
}

/* Read one unsigned integer field out of a "k=v k=v" line. Returns -1
 * when the key is absent, which callers treat as "not reported" rather
 * than as zero -- a monitor that omits a field is not claiming it is 0.
 * Scaled by `scale` so a decimal like lock_pct=1.25 can be carried as
 * an integer 125 without a float parse in the watchdog. */
static int bs_kv_int(const char *line, const char *key, int scale)
{
    size_t klen = strlen(key);
    const char *p = line;
    while ((p = strstr(p, key)) != NULL) {
        /* Must be at a field boundary and followed by '=', or "state"
         * would match inside "warm_threads=..." style neighbours and
         * "threads_run" would match "threads_running". */
        int at_start = (p == line) || (p[-1] == ' ');
        if (at_start && p[klen] == '=') {
            const char *v = p + klen + 1;
            if (*v < '0' || *v > '9') return -1;
            int whole = 0;
            while (*v >= '0' && *v <= '9') whole = whole * 10 + (*v++ - '0');

            /* Fractional part, renormalised to exactly the number of
             * digits `scale` carries: scale=100 keeps two, scale=1
             * discards them. Done by padding or truncating rather than
             * by dividing at the end, so "1.5" reads as 150 and not 15. */
            int frac = 0, want = 0;
            for (int t = scale; t > 1; t /= 10) want++;
            if (*v == '.') {
                v++;
                int have = 0;
                while (*v >= '0' && *v <= '9') {
                    if (have < want) { frac = frac * 10 + (*v - '0'); have++; }
                    v++;
                }
                while (have < want) { frac *= 10; have++; }
            }
            return whole * scale + frac;
        }
        p += klen;
    }
    return -1;
}

/* Read the external monitor's telemetry file (BotShieldDbStatsFile).
 *
 * Publishes to SHM for the dashboard only -- the database's effect on
 * policy travels through BotShieldLoadStateFile, which the monitor
 * writes separately and which merges with every other signal. Keeping
 * telemetry off the policy path means a malformed stats line can make
 * the graph wrong but cannot make the module shed. */
static void bs_load_read_db_stats(server_rec *sv, bs_server_cfg *scfg)
{
    if (!scfg->db_stats_file || !bs_shm.header) return;

    apr_finfo_t finfo;
    if (apr_stat(&finfo, scfg->db_stats_file, APR_FINFO_MTIME,
                 sv->process->pconf) != APR_SUCCESS) {
        return;   /* monitor not installed or not running yet */
    }
    if (finfo.mtime == scfg->db_stats_mtime) return;   /* unchanged */
    scfg->db_stats_mtime = finfo.mtime;

    apr_file_t *f = NULL;
    if (apr_file_open(&f, scfg->db_stats_file, APR_READ | APR_BINARY, 0,
                      sv->process->pconf) != APR_SUCCESS) {
        return;
    }
    char buf[512];
    apr_size_t got = sizeof(buf) - 1;
    apr_status_t rv = apr_file_read(f, buf, &got);
    apr_file_close(f);
    if ((rv != APR_SUCCESS && rv != APR_EOF) || got == 0) return;
    buf[got] = '\0';
    for (apr_size_t i = 0; i < got; i++) {
        if (buf[i] == '\n' || buf[i] == '\r') { buf[i] = '\0'; break; }
    }

    int threads = bs_kv_int(buf, "threads_run", 1);
    if (threads < 0) return;          /* no usable reading; leave last */
    int qps     = bs_kv_int(buf, "qps", 1);
    int lockx   = bs_kv_int(buf, "lock_pct", 100);
    int ts      = bs_kv_int(buf, "ts", 1);
    int warm    = bs_kv_int(buf, "warm_threads", 1);
    int hot     = bs_kv_int(buf, "hot_threads", 1);

    if (threads > 65534) threads = 65534;
    apr_atomic_set32(&bs_shm.header->db_threads_run, (apr_uint32_t)threads);
    if (qps   >= 0) apr_atomic_set32(&bs_shm.header->db_qps, (apr_uint32_t)qps);
    if (lockx >= 0) apr_atomic_set32(&bs_shm.header->db_lock_pct_x100,
                                     (apr_uint32_t)lockx);
    if (ts    >= 0) apr_atomic_set32(&bs_shm.header->db_sample_sec,
                                     (apr_uint32_t)ts);
    if (warm  >  0) apr_atomic_set32(&bs_shm.header->db_warm_threads,
                                     (apr_uint32_t)warm);
    if (hot   >  0) apr_atomic_set32(&bs_shm.header->db_hot_threads,
                                     (apr_uint32_t)hot);

    /* History ring, gated on elapsed time like la_ring. The monitor and
     * the watchdog tick independently, so this stores whatever the
     * newest published reading is at each period boundary rather than
     * assuming a 1:1 correspondence between their cadences. */
    if (bs_shm.metrics) {
        bs_metrics *m = bs_shm.metrics;
        apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
        apr_uint32_t last = apr_atomic_read32(&m->db_last_sec);
        if (now >= last + BS_M_DB_PERIOD) {
            apr_uint32_t pos = apr_atomic_read32(&m->db_pos);
            pos = (pos + 1) % BS_M_DB_SLOTS;
            m->db_ring[pos] = (apr_uint16_t)threads;
            apr_atomic_set32(&m->db_pos, pos);
            apr_atomic_set32(&m->db_last_sec, now);
        }
    }
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
    bs_load_read_db_stats(sv, scfg);

    /* Load average, per CPU, in hundredths. Thresholds are expressed in
     * the same unit the site's own shedding script uses -- HIGH is
     * 2x cores, LOW is 1x cores -- so one number means the same thing
     * to both systems.
     *
     * Deliberately BELOW that script's HIGH. The script publishes a
     * marker at 2.0/core and the vhost answers /index.php and
     * /api/index.php with a flat 503 for everyone, logged-in humans
     * included. That is the right last rung and a poor first one. These
     * thresholds sit under it so the module can shed selectively --
     * crawlers, then clients with no solve proof -- while there is
     * still headroom, and the blunt rung only arrives if that failed. */
    bs_load_state avg = BS_LOAD_NORMAL;
    int la = bs_load_sample_loadavg(sv->process->pconf);
    if (la >= 0) {
        int aw = bs_load_effective_int(scfg->loadavg_warm,
                                       BS_DEFAULT_LOADAVG_WARM);
        int ah = bs_load_effective_int(scfg->loadavg_hot,
                                       BS_DEFAULT_LOADAVG_HOT);
        avg = bs_load_state_from_pct(la, aw, ah);
        apr_atomic_set32(&bs_shm.header->loadavg_pct, (apr_uint32_t)la);
        /* History ring, one sample per BS_M_LA_PERIOD seconds. Gated on
         * elapsed time rather than tick count so the cadence holds if
         * BotShieldLoadRefreshInterval is retuned. */
        if (bs_shm.metrics) {
            bs_metrics *m = bs_shm.metrics;
            apr_uint32_t now = (apr_uint32_t)apr_time_sec(apr_time_now());
            apr_uint32_t last = apr_atomic_read32(&m->la_last_sec);
            if (now >= last + BS_M_LA_PERIOD) {
                apr_uint32_t pos = apr_atomic_read32(&m->la_pos);
                pos = (pos + 1) % BS_M_LA_SLOTS;
                m->la_ring[pos] = (la > 65534) ? 65534 : (apr_uint16_t)la;
                apr_atomic_set32(&m->la_pos, pos);
                apr_atomic_set32(&m->la_last_sec, now);
            }
        }
    }

    /* Most-severe-wins merge across all three signals. */
    bs_load_state candidate = (internal > external) ? internal : external;
    if (avg > candidate) candidate = avg;
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

/* BotShieldDbStatsFile <path>. Written by the external monitor; read
 * for the dashboard only, never for policy. */
const char *bs_set_db_stats_file(cmd_parms *cmd, void *dconf,
                                 const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) return "BotShieldDbStatsFile: path required";
    if (arg[0] != '/') return "BotShieldDbStatsFile: path must be absolute";
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->db_stats_file = apr_pstrdup(cmd->pool, arg);
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

/* BotShieldLoadAvgWarm / …Hot <ratio>
 *
 * Per-CPU 1-minute load average, given as a decimal ratio: 1.0 means
 * "one runnable process per core". Stored in hundredths.
 *
 * A ratio rather than a raw load figure so one number carries across
 * machines -- and so it reads in the same unit the host's own shedding
 * script uses, whose defaults are HIGH = 2x cores and LOW = 1x cores.
 * Keep these under that HIGH; see BS_DEFAULT_LOADAVG_WARM. */
static const char *bs_set_loadavg_thr(cmd_parms *cmd, const char *arg,
                                      const char *dname, int *slot)
{
    char *end = NULL;
    double v = strtod(arg, &end);
    if (!end || *end || !(v > 0.0) || v > 100.0) {
        return apr_psprintf(cmd->pool,
            "%s: '%s' must be a ratio greater than 0 and at most 100 "
            "(1.0 = one runnable process per core)", dname, arg);
    }
    *slot = (int)(v * 100.0);
    return NULL;
}

const char *bs_set_loadavg_warm(cmd_parms *cmd, void *dconf, const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    return bs_set_loadavg_thr(cmd, arg, "BotShieldLoadAvgWarm",
                              &scfg->loadavg_warm);
}

const char *bs_set_loadavg_hot(cmd_parms *cmd, void *dconf, const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    const char *err = bs_set_loadavg_thr(cmd, arg, "BotShieldLoadAvgHot",
                                         &scfg->loadavg_hot);
    if (err) return err;
    if (scfg->loadavg_warm > 0 && scfg->loadavg_hot <= scfg->loadavg_warm) {
        return "BotShieldLoadAvgHot must be greater than "
               "BotShieldLoadAvgWarm";
    }
    return NULL;
}

/* Last sampled per-CPU load average, hundredths. Dashboard only. */
apr_uint32_t bs_loadavg_current(void)
{
    if (!bs_shm.header) return 0;
    return apr_atomic_read32(&bs_shm.header->loadavg_pct);
}

/* Effective load-average thresholds for this server, defaults applied.
 *
 * Exists so reporting surfaces do not have to duplicate the "0 means
 * default" convention -- and because bs_load_effective_int is static:
 * calling it from another translation unit built fine and then failed
 * at module load with an undefined symbol, which is a slower way to
 * find out. */
void bs_loadavg_thresholds(server_rec *s, int *warm, int *hot)
{
    int w = BS_DEFAULT_LOADAVG_WARM, h = BS_DEFAULT_LOADAVG_HOT;
    if (s) {
        bs_server_cfg *scfg =
            ap_get_module_config(s->module_config, &botshield_module);
        if (scfg) {
            w = bs_load_effective_int(scfg->loadavg_warm,
                                      BS_DEFAULT_LOADAVG_WARM);
            h = bs_load_effective_int(scfg->loadavg_hot,
                                      BS_DEFAULT_LOADAVG_HOT);
        }
    }
    if (warm) *warm = w;
    if (hot)  *hot  = h;
}
