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
static int bs_load_sample_loadavg(apr_pool_t *pool, int *out5, int *out15)
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

    /* "0.31 0.48 1.31 1/523 12345" -- all three averages. The kernel
     * computes them whether or not we read them, and they arrive in the
     * same read, so taking all three is free. */
    double one = 0.0, five = 0.0, fifteen = 0.0;
    int got = sscanf(buf, "%lf %lf %lf", &one, &five, &fifteen);
    if (got < 1) return -1;

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    if (out5)  *out5  = (got >= 2) ? (int)((five    * 100.0) / (double)ncpu) : -1;
    if (out15) *out15 = (got >= 3) ? (int)((fifteen * 100.0) / (double)ncpu) : -1;
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
/* Read one monitor's key=value line, mtime-gated so an unchanged file
 * costs a stat rather than an open+read. Returns 0 when there is
 * nothing new to parse -- missing file, unchanged mtime, or read
 * failure, all of which mean "keep whatever we last published" rather
 * than "the thing being monitored is fine". */
static int bs_load_read_stats_line(server_rec *sv, const char *path,
                                   apr_time_t *cached_mtime,
                                   char *buf, apr_size_t buflen)
{
    if (!path) return 0;
    apr_finfo_t finfo;
    if (apr_stat(&finfo, path, APR_FINFO_MTIME,
                 sv->process->pconf) != APR_SUCCESS) {
        return 0;   /* monitor not installed or not running yet */
    }
    if (finfo.mtime == *cached_mtime) return 0;
    *cached_mtime = finfo.mtime;

    apr_file_t *f = NULL;
    if (apr_file_open(&f, path, APR_READ | APR_BINARY, 0,
                      sv->process->pconf) != APR_SUCCESS) {
        return 0;
    }
    apr_size_t got = buflen - 1;
    apr_status_t rv = apr_file_read(f, buf, &got);
    apr_file_close(f);
    if ((rv != APR_SUCCESS && rv != APR_EOF) || got == 0) return 0;
    buf[got] = '\0';
    for (apr_size_t i = 0; i < got; i++) {
        if (buf[i] == '\n' || buf[i] == '\r') { buf[i] = '\0'; break; }
    }
    return 1;
}

/* Parse the state= token a monitor publishes. Its own verdict, not one
 * re-derived here: the monitors classify on dimensions the module never
 * sees (lock contention, listen queue), so recomputing from the numbers
 * alone could disagree with the state that is actually driving policy. */
static apr_uint32_t bs_load_parse_state_kv(const char *buf)
{
    const char *sp = strstr(buf, "state=");
    if (sp && (sp == buf || sp[-1] == ' ')) {
        sp += 6;
        if      (!strncmp(sp, "hot",  3)) return BS_LOAD_HOT;
        else if (!strncmp(sp, "warm", 4)) return BS_LOAD_WARM;
    }
    return BS_LOAD_NORMAL;
}

static void bs_load_read_db_stats(server_rec *sv, bs_server_cfg *scfg)
{
    if (!bs_shm.header) return;
    char buf[512];
    if (!bs_load_read_stats_line(sv, scfg->db_stats_file,
                                 &scfg->db_stats_mtime, buf, sizeof(buf))) {
        return;
    }

    int threads = bs_kv_int(buf, "threads_run", 1);
    if (threads < 0) return;          /* no usable reading; leave last */

    /* The monitor's own verdict, not one we re-derive. It classifies on
     * lock contention as well as thread count, so recomputing from
     * threads alone here would sometimes disagree with the state it
     * published -- and the state file is what actually drives policy. */
    apr_atomic_set32(&bs_shm.header->db_state,
                     bs_load_parse_state_kv(buf));
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

/* Read the PHP-FPM monitor's telemetry (BotShieldFpmStatsFile).
 *
 * Display only, exactly like the database path: PHP-FPM reaches policy
 * through BotShieldLoadStateFile, so a malformed stats line can make a
 * graph wrong but cannot make the module shed. */
static void bs_load_read_fpm_stats(server_rec *sv, bs_server_cfg *scfg)
{
    if (!bs_shm.metrics) return;
    char buf[512];
    if (!bs_load_read_stats_line(sv, scfg->fpm_stats_file,
                                 &scfg->fpm_stats_mtime, buf, sizeof(buf))) {
        return;
    }

    int pct = bs_kv_int(buf, "pct", 1);
    if (pct < 0) return;              /* no usable reading; leave last */
    bs_metrics *m = bs_shm.metrics;

    int active = bs_kv_int(buf, "active", 1);
    int maxc   = bs_kv_int(buf, "max_children", 1);
    int queue  = bs_kv_int(buf, "listen_queue", 1);
    int ts     = bs_kv_int(buf, "ts", 1);
    int wp     = bs_kv_int(buf, "warm_pct", 1);
    int hp     = bs_kv_int(buf, "hot_pct", 1);

    if (pct > 65534) pct = 65534;
    apr_atomic_set32(&m->fpm_pct,   (apr_uint32_t)pct);
    apr_atomic_set32(&m->fpm_state, bs_load_parse_state_kv(buf));
    if (active >= 0) apr_atomic_set32(&m->fpm_active, (apr_uint32_t)active);
    if (maxc   >  0) apr_atomic_set32(&m->fpm_max_children,
                                      (apr_uint32_t)maxc);
    if (queue  >= 0) apr_atomic_set32(&m->fpm_queue, (apr_uint32_t)queue);
    if (ts     >= 0) apr_atomic_set32(&m->fpm_sample_sec, (apr_uint32_t)ts);
    if (wp     >  0) apr_atomic_set32(&m->fpm_warm_pct, (apr_uint32_t)wp);
    if (hp     >  0) apr_atomic_set32(&m->fpm_hot_pct,  (apr_uint32_t)hp);

    apr_uint32_t now  = (apr_uint32_t)apr_time_sec(apr_time_now());
    apr_uint32_t last = apr_atomic_read32(&m->fpm_last_sec);
    if (now >= last + BS_M_FPM_PERIOD) {
        apr_uint32_t pos = apr_atomic_read32(&m->fpm_pos);
        pos = (pos + 1) % BS_M_FPM_SLOTS;
        m->fpm_ring[pos] = (apr_uint16_t)pct;
        apr_atomic_set32(&m->fpm_pos, pos);
        apr_atomic_set32(&m->fpm_last_sec, now);
    }
}

/* Sample the Apache scoreboard. Returns busy_pct = 100 *
 * busy_workers / total_worker_slots. "Busy" = anything that's
 * actively servicing a request: BUSY_READ/WRITE/KEEPALIVE/LOG/DNS
 * + GRACEFUL (still serving its current request). READY and DEAD
 * slots don't count as busy. */
static int bs_load_sample_scoreboard(apr_uint64_t *out_access,
                                    apr_uint64_t *out_duration)
{
    if (!ap_exists_scoreboard_image()) return 0;
    global_score *gs = ap_get_scoreboard_global();
    if (!gs) return 0;
    int total = gs->server_limit * gs->thread_limit;
    if (total <= 0) return 0;

    int busy = 0;
    apr_uint64_t acc = 0, dur = 0;
    for (int i = 0; i < gs->server_limit; i++) {
        for (int j = 0; j < gs->thread_limit; j++) {
            worker_score *ws =
                ap_get_scoreboard_worker_from_indexes(i, j);
            if (!ws) continue;
            /* Same two fields mod_status sums for Total Accesses and
             * Total Duration. Free to collect: this loop already walks
             * every slot for the busy count. */
            acc += ws->access_count;
            dur += (apr_uint64_t)ws->duration;
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
    if (out_access)   *out_access   = acc;
    if (out_duration) *out_duration = dur;
    return (busy * 100) / total;
}

/* Mean request latency in microseconds over the interval since the last
 * call, or -1 when there is no usable sample yet.
 *
 * A DELTA, because the cumulative figure is an average over the whole
 * uptime and goes numb exactly when it matters: measured on this host,
 * cumulative read 31.7ms while the live window read 52ms, and during
 * the overnight outages the homepage was taking 29-36 SECONDS while the
 * since-restart mean stayed in the tens of milliseconds.
 *
 * This is the one Apache-side number those outages moved. The
 * busy-worker ratio could not see them at all: MaxRequestWorkers is
 * 1024 on 6 cores, so 25-30 stuck workers -- the whole site
 * unusable -- reads as 2-3% utilisation.
 *
 * Counters live in SHM rather than in statics because the watchdog is
 * not guaranteed to stay in one process across a graceful restart.
 *
 * A child recycling (MaxConnectionsPerChild) resets its slots to zero,
 * which can make the summed delta negative. That is indistinguishable
 * here from a counter wrap, so the sample is dropped rather than
 * guessed at -- one missed tick against reporting a nonsense latency. */
static int bs_load_sample_latency(apr_uint64_t acc, apr_uint64_t dur)
{
    /* access_count and duration are only maintained when ExtendedStatus
     * is on; with it off they sit at zero forever. Reporting that as a
     * 0ms mean would be the worst possible failure -- a jammed server
     * would read as the fastest one imaginable, and the shed ladder
     * would see its calmest input. Report "no opinion" instead, and let
     * the dashboard say why. */
    if (!ap_extended_status) return -2;
    if (!bs_shm.metrics) return -1;
    bs_metrics *m = bs_shm.metrics;
    apr_uint64_t pa = m->ap_prev_access, pd = m->ap_prev_duration;
    m->ap_prev_access   = acc;
    m->ap_prev_duration = dur;
    if (pa == 0 && pd == 0) return -1;      /* first call: no baseline */
    if (acc < pa || dur < pd) return -1;    /* slots recycled */
    apr_uint64_t dn = acc - pa;
    if (dn == 0) return -1;                 /* idle window says nothing */
    return (int)((dur - pd) / dn);
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
    apr_uint64_t sb_access = 0, sb_duration = 0;
    int busy_pct = bs_load_sample_scoreboard(&sb_access, &sb_duration);
    bs_load_state internal = bs_load_state_from_pct(busy_pct,
                                                    warm_pct, hot_pct);
    bs_load_state external = bs_load_read_external(sv, scfg);
    bs_load_read_db_stats(sv, scfg);
    bs_load_read_fpm_stats(sv, scfg);

    /* Apache mean request latency. Same scoreboard walk, one delta.
     *
     * Sampled every tick so the accumulators stay current, but only
     * written to the history ring on the ring's own cadence -- the
     * delta must span a real interval to mean anything, and a
     * sub-second window on a quiet site is mostly noise. */
    bs_load_state lat_state = BS_LOAD_NORMAL;
    if (bs_shm.metrics) {
        bs_metrics *m = bs_shm.metrics;
        apr_uint32_t now  = (apr_uint32_t)apr_time_sec(apr_time_now());
        apr_uint32_t last = apr_atomic_read32(&m->ap_last_sec);
        if (now >= last + BS_M_AP_PERIOD) {
            int us = bs_load_sample_latency(sb_access, sb_duration);
            if (us == -2) {
                /* Distinct from "no sample yet": this one never
                 * resolves on its own and needs an operator. */
                apr_atomic_set32(&m->ap_latency_us, BS_M_AP_NO_STATUS);
            } else if (us >= 0) {
                /* The ring is milliseconds, which is the resolution the
                 * warm/hot thresholds work at. The headline number keeps
                 * microseconds: a server answering in 290us is not
                 * answering in 0ms, and rounding it to zero on the
                 * dashboard reads as a broken metric rather than a fast
                 * one. Caught on a dev box; production runs 31-52ms and
                 * would never have shown it. */
                int ms = us / 1000;
                if (ms > BS_M_AP_MAX_MS) ms = BS_M_AP_MAX_MS;
                apr_uint32_t pos = apr_atomic_read32(&m->ap_pos);
                pos = (pos + 1) % BS_M_AP_SLOTS;
                m->ap_ring[pos] = (apr_uint16_t)ms;
                apr_atomic_set32(&m->ap_pos, pos);
                apr_atomic_set32(&m->ap_latency_us, (apr_uint32_t)us);
            }
            apr_atomic_set32(&m->ap_last_sec, now);
        }
        /* State from the last published sample rather than only from a
         * fresh one, so the signal holds its value between ring writes
         * instead of collapsing to normal on four ticks out of five. */
        /* Compare in the sentinel's own type. Round-tripping it through
         * int made the comparison signed-vs-unsigned, which is exactly
         * the kind of thing that works until the value changes. */
        apr_uint32_t cur_us = apr_atomic_read32(&m->ap_latency_us);
        if (cur_us != BS_M_AP_NO_STATUS) {
            int cur = (int)(cur_us / 1000);
            int lw = bs_load_effective_int(scfg->latency_warm_ms,
                                           BS_DEFAULT_LATENCY_WARM_MS);
            int lh = bs_load_effective_int(scfg->latency_hot_ms,
                                           BS_DEFAULT_LATENCY_HOT_MS);
            lat_state = bs_load_state_from_pct(cur, lw, lh);
        }
    }

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
    int la5 = -1, la15 = -1;
    int la = bs_load_sample_loadavg(sv->process->pconf, &la5, &la15);
    if (la >= 0) {
        if (la5  >= 0) apr_atomic_set32(&bs_shm.header->loadavg5_pct,
                                        (apr_uint32_t)la5);
        if (la15 >= 0) apr_atomic_set32(&bs_shm.header->loadavg15_pct,
                                        (apr_uint32_t)la15);
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
    if (lat_state > candidate) candidate = lat_state;
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

/* BotShieldFpmStatsFile <path>. */
const char *bs_set_fpm_stats_file(cmd_parms *cmd, void *dconf,
                                  const char *arg)
{
    (void)dconf;
    if (!arg || !*arg) return "BotShieldFpmStatsFile: path required";
    if (arg[0] != '/') return "BotShieldFpmStatsFile: path must be absolute";
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    scfg->fpm_stats_file = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

/* BotShieldLatencyWarm / BotShieldLatencyHot <milliseconds>. Mean
 * request latency at which a sample is classified warm / hot. */
static const char *bs_set_latency_ms(cmd_parms *cmd, const char *arg,
                                     int *slot, const char *name)
{
    if (!arg || !*arg) return apr_psprintf(cmd->pool,
                                           "%s: milliseconds required", name);
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (end == arg || (end && *end) || v < 1 || v > BS_M_AP_MAX_MS) {
        return apr_psprintf(cmd->pool,
            "%s: expected 1..%d milliseconds, got '%s'",
            name, BS_M_AP_MAX_MS, arg);
    }
    *slot = (int)v;
    return NULL;
}

const char *bs_set_latency_warm(cmd_parms *cmd, void *dconf, const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    return bs_set_latency_ms(cmd, arg, &scfg->latency_warm_ms,
                             "BotShieldLatencyWarm");
}

const char *bs_set_latency_hot(cmd_parms *cmd, void *dconf, const char *arg)
{
    (void)dconf;
    bs_server_cfg *scfg = ap_get_module_config(cmd->server->module_config,
                                               &botshield_module);
    return bs_set_latency_ms(cmd, arg, &scfg->latency_hot_ms,
                             "BotShieldLatencyHot");
}

/* Effective latency thresholds, defaults applied. Exported for the
 * dashboard, which needs the same numbers to draw its bands. */
void bs_latency_thresholds(server_rec *sv, int *warm, int *hot)
{
    bs_server_cfg *scfg =
        ap_get_module_config(sv->module_config, &botshield_module);
    int w = scfg ? scfg->latency_warm_ms : 0;
    int h = scfg ? scfg->latency_hot_ms  : 0;
    if (warm) *warm = bs_load_effective_int(w, BS_DEFAULT_LATENCY_WARM_MS);
    if (hot)  *hot  = bs_load_effective_int(h, BS_DEFAULT_LATENCY_HOT_MS);
}

/* Most recent Apache mean-latency sample, milliseconds. */
/* Most recent Apache mean-latency sample, MICROSECONDS, or
 * BS_M_AP_NO_STATUS when the metric is unavailable. */
apr_uint32_t bs_latency_current_us(void)
{
    return bs_shm.metrics
         ? apr_atomic_read32(&bs_shm.metrics->ap_latency_us)
         : BS_M_AP_NO_STATUS;
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
/* The 5- and 15-minute averages, per-CPU hundredths. */
void bs_loadavg_current_all(apr_uint32_t *m5, apr_uint32_t *m15)
{
    if (m5)  *m5  = bs_shm.header
        ? apr_atomic_read32(&bs_shm.header->loadavg5_pct)  : 0;
    if (m15) *m15 = bs_shm.header
        ? apr_atomic_read32(&bs_shm.header->loadavg15_pct) : 0;
}

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
