/* shm.h — SHM table machinery for mod_botshield.
 *
 * mod_botshield holds five tables in a single APR shared-memory segment
 * plus a small fixed header with global counters. Workers read/write
 * the segment under a mix of seqlock (in-row) and global-mutex (probes
 * + bumps) discipline:
 *
 *   1. flagged-IP   — per-IP reputation flag bitmap (M5.1)
 *   2. strike       — per-(IP, rate-rule) repeated-429 escalation (E9)
 *   3. safeguard    — per-IP challenge-presented-N-times anti-loop (E10)
 *   4. nonce        — embedded-bootstrap challenge replay-defense
 *                    
 *   5. bloom (x2)   — rotating "have we ever seen this IP" filter (M5.2)
 *
 * Plus a captcha-verify rate-limit ring, a captcha-log-suppress ring,
 * a fixed-window rate-counter pool (E2.1), a Bloom rotation timestamp,
 * a load-state cell, and the M9.2 metrics counter block. All packed
 * into one segment so a single apr_shm_create + apr_global_mutex_create
 * carries the whole thing — and so cross-table state-save/load is one
 * transaction.
 *
 * Why three (now four) similarly-shaped tables instead of one unified
 * "row" type:
 *
 *   The tables look like minor variations of each other (seqlock + IP
 *   key + ns_id + a payload), but the payload semantics are mutually
 *   incompatible. flagged-IP carries an OR'd bitmap that compose
 *   across reasons; strike carries a windowed counter keyed on
 *   (IP, rule_slot) where the same IP can have different counts for
 *   different rules; safeguard carries presentation-counter +
 *   safeguard-until timestamp keyed on IP only. Unifying would force
 *   one synthetic key shape (IP + rule_slot + reason_kind) and a
 *   tagged-union payload that's bigger than any individual current
 *   slot — burning RAM and probe-cache locality for a refactor that
 *   doesn't simplify any caller. The tables are independent reads in
 *   bs_handler so cross-table consistency isn't a feature we'd gain
 *   either. Keep them separate; document that they LOOK alike for the
 *   same family of reasons (open-addressing + seqlock + ns_id) but
 *   mean different things.
 *
 * Symbol-namespacing rule (Apache modules share dynamic-linker symbol
 * space): every cross-file function/type/global declared here uses the
 * `bs_` / `BS_` prefix. File-local helpers in shm.c stay
 * `static`. The Apache module entry point `botshield_module` is the
 * one un-prefixed symbol — Apache's `LoadModule` requires that name. */
#ifndef BOTSHIELD_SHM_H
#define BOTSHIELD_SHM_H

#include <apr_pools.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <apr_errno.h>
#include <httpd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================
 * Capacity / size constants
 * ====================================================================== */

/* SHM segment header */
#define BS_SHM_MAGIC              0x42534844  /* 'BSHD' */
/* Format-version history:
 *   1 — initial; per-table empty markers (flags==0, rule_slot==EMPTY,
 *       expires_at==0, used==0).
 *   2 — every slot type now carries an explicit apr_uint32_t used
 *       field with 0 = empty as the unified convention. Slot
 *       layouts changed; no backward-compatible read of v1 segments. */
#define BS_SHM_FORMAT_VERSION     2
/* E13 — bumped from 8M to 16M to accommodate the per-slot ns_id+pad
 * fields (8 bytes/slot across flagged-IP / strike / safeguard tables
 * at default capacities). 8M no longer fits the default config. */
#define BS_DEFAULT_SHM_SIZE       (16 * 1024 * 1024)

/* Flagged-IP table */
#define BS_DEFAULT_FLAGGED_SLOTS  50000
#define BS_FLAGGED_MIN_SLOTS      1024
#define BS_FLAGGED_MAX_SLOTS      1000000
#define BS_FLAGGED_PROBE_LIMIT    10
#define BS_FLAGGED_MAX_READ_SPINS 3

/* Rotating Bloom filter (M5.2) */
#define BS_BLOOM_BITS_PER_IP      10
#define BS_BLOOM_K                7
#define BS_DEFAULT_BLOOM_IPS      1000000
#define BS_DEFAULT_BLOOM_WINDOW   604800
#define BS_BLOOM_MIN_IPS          1000
#define BS_BLOOM_MAX_IPS          10000000
#define BS_BLOOM_MIN_WINDOW       3600
#define BS_BLOOM_MAX_WINDOW       (30 * 86400)
#define BS_FIRST_SIGHT_PENALTY    5

/* Strike table (E9) */
#define BS_STRIKE_PROBE_LIMIT      8
#define BS_DEFAULT_STRIKE_SLOTS    50000
#define BS_STRIKE_MIN_SLOTS        1024
#define BS_STRIKE_MAX_SLOTS        1000000

/* Safeguard table (E10) */
#define BS_SAFEGUARD_PROBE_LIMIT   8
#define BS_DEFAULT_SAFEGUARD_SLOTS 50000
#define BS_SAFEGUARD_MIN_SLOTS     1024
#define BS_SAFEGUARD_MAX_SLOTS     1000000
#define BS_DEFAULT_SAFEGUARD_THRESHOLD 5
#define BS_DEFAULT_SAFEGUARD_WINDOW    600
#define BS_DEFAULT_SAFEGUARD_TTL       900

/* Embedded-bootstrap nonce table */
#define BS_NONCE_PROBE_LIMIT       8
#define BS_DEFAULT_NONCE_SLOTS     32768
#define BS_NONCE_MIN_SLOTS         1024
#define BS_NONCE_MAX_SLOTS         1048576
/* E17 — embedded → M7 fallback threshold. After N consecutive silent-
 * tier-embedded dispatches in the safeguard window without
 * _bs_session arriving, the embedded short-circuit is bypassed and
 * M7 issues. Set lower than safeguard threshold so M7 gets a chance
 * before pass-through fully kicks in. Reuses the safeguard table's
 * present_count to avoid a fourth SHM table just for this counter. */
#define BS_DEFAULT_EMBEDDED_FALLBACK_THRESHOLD 3

/* Captcha-verify rate-limit + log-suppress slots (M8.1) */
#define BS_CV_WINDOW_SHIFT  20
#define BS_CV_COUNT_MASK    ((apr_uint64_t)0xFFFFF)
#define BS_CV_SLOT(min, cnt) \
    (((apr_uint64_t)(min) << BS_CV_WINDOW_SHIFT) | \
     ((apr_uint64_t)(cnt) & BS_CV_COUNT_MASK))
#define BS_CV_WINDOW(slot) ((apr_uint64_t)(slot) >> BS_CV_WINDOW_SHIFT)
#define BS_CV_COUNT(slot)  ((apr_uint32_t)((slot) & BS_CV_COUNT_MASK))
#define BS_DEFAULT_CV_RATE_SLOTS  4096
#define BS_DEFAULT_CV_LOG_SLOTS   2048
#define BS_DEFAULT_CAPTCHA_RATE_LIMIT     30
#define BS_DEFAULT_CAPTCHA_MAX_INFLIGHT   64
#define BS_CAPTCHA_LOG_WINDOW_SEC         60

/* M6 state-file persistence */
#define BS_STATE_MAGIC            0x44485342U
/* Format-version history:
 *   1 — initial.
 *   2 — bs_flagged_ip_slot grew an `ns_id` field for per-vhost
 *       reputation namespacing.
 *   3 — bs_flagged_ip_slot grew an explicit `used` field and got
 *       its layout reordered as part of the empty-marker
 *       consistency cleanup. Slot bytes from v2 state files don't
 *       map cleanly into v3 layout, so older files are rejected
 *       with a NOTICE and the table starts fresh. */
/* v4 appends the M9.2 metrics block (cumulative counters plus the
 * dashboard bucket rings) so decision history survives a restart. The
 * rings carry their own epoch stamps, so slots that aged out while the
 * server was down are simply skipped by the window reader — no special
 * handling on reload. A version mismatch is already rejected with a
 * NOTICE and a fresh start, so old files degrade rather than break.
 *
 * v5 widens bs_metrics_slot with the cookie dimension; v6 adds the
 * site-wide traffic fields; v7 appends the per-vhost blocks, which are
 * restored by matching saved ServerName against the running directory
 * so adding or removing a vhost re-files history instead of
 * scrambling it. The block is length-prefixed and
 * size-checked on load, so an older file would be refused on size
 * alone even without the version bump; the bump makes the rejection
 * say why.
 *
 * v10 adds the `solved` cookie state, which widens both cookie[] arrays
 * (cumulative and per-slot) and so changes sizeof(bs_metrics). The
 * length check would refuse a v9 file anyway; the bump makes the NOTICE
 * explain itself instead of reporting a bare size mismatch. Cost of the
 * bump is one restart's worth of dashboard history. */
#define BS_STATE_FORMAT_VERSION   10
#define BS_STATE_MAX_AGE_SECS     (14 * 86400)
#define BS_FNV64_SEED             0xcbf29ce484222325ULL

/* E13.1 capacity-headroom watchdog */
#define BS_HEADROOM_NOTICE_PCT     50
#define BS_HEADROOM_WARN_PCT       70
#define BS_HEADROOM_REWARN_SEC     300

/* M9.2 metrics — enum fixed-arity counter blocks. Indices are 1:1
 * with the M9.1 decision-log enums. Reviewer guidance: keep counter
 * vocabulary identical to log vocabulary so a new outcome is a
 * visible build break, not silent metric drift. */
typedef enum {
    BS_M_TIER_NONE = 0,
    BS_M_TIER_PASS,
    BS_M_TIER_SILENT,
    BS_M_TIER_FORM,
    BS_M_TIER_CAPTCHA,
    BS_M_TIER_COUNT
} bs_m_tier;

typedef enum {
    BS_M_OUTCOME_ALLOW = 0,
    BS_M_OUTCOME_CHALLENGED,
    BS_M_OUTCOME_VERIFIED,
    BS_M_OUTCOME_BLOCK,
    BS_M_OUTCOME_FAILOPEN,
    BS_M_OUTCOME_RATE_LIMITED,
    BS_M_OUTCOME_INFLIGHT_CAPPED,
    BS_M_OUTCOME_PENDING_MISSING,
    BS_M_OUTCOME_MISCONFIGURED,
    BS_M_OUTCOME_DEBUG,
    BS_M_OUTCOME_REDIRECT,
    BS_M_OUTCOME_COUNT
} bs_m_outcome;

/* Who produced the response, and if it was us, what kind. Lets the
 * dashboard separate a BotShield 403 from an application 403, which are
 * indistinguishable in the status-class counters.
 *
 * Counterfactuals do not count as ours: under LogOnly the decision log
 * says ~block but the request was declined and the origin answered, so
 * it bins as ORIGIN.
 *
 * OBSERVE is split from ENDPOINT because the dashboard and the metrics
 * scrape are the measuring instrument, not traffic. A dashboard left
 * open on a 10s refresh is 360 requests an hour of self-inflicted load;
 * folded in with the verify endpoints it would quietly dominate the
 * breakdown. They are still counted in req_total -- that has to keep
 * matching the access logs -- just kept separable. */
typedef enum {
    BS_M_RESP_ORIGIN = 0,      /* the application answered */
    BS_M_RESP_CHALLENGE,       /* interstitial served */
    BS_M_RESP_BLOCK,           /* refused (403 and friends) */
    BS_M_RESP_RATE_LIMITED,    /* 429 */
    BS_M_RESP_REDIRECT,        /* safeguard 302 */
    BS_M_RESP_ENDPOINT,        /* module endpoint: verify, assets */
    BS_M_RESP_OBSERVE,         /* dashboard / metrics / policy-status */
    BS_M_RESP_COUNT
} bs_m_resp;

/* Client classification, mirroring bs_ua_class_label in ua_class.h.
 * Recorded per request alongside the status class, so the dashboard can
 * answer "who is visiting" and not only "what did we answer".
 *
 * Indices are a deliberate copy rather than a reuse of the ua_class
 * enum: this one is persisted in the state file, so its numbering is a
 * wire format that must not shift if the classifier's enum is
 * reordered. bs_m_class_idx() maps between them in one place. */
typedef enum {
    BS_M_CLASS_BROWSER = 0,
    BS_M_CLASS_VERIFIED_BOT,
    BS_M_CLASS_KNOWN_BOT,
    BS_M_CLASS_UNKNOWN_BOT,
    BS_M_CLASS_FAKE_BOT,
    BS_M_CLASS_UNKNOWN,
    BS_M_CLASS_COUNT
} bs_m_class;

/* HTTP status class for the site-wide traffic counters. Separate from
 * the decision vocabulary: these count every request the server logs,
 * including ones BotShield never evaluated. */
typedef enum {
    BS_M_STATUS_2XX = 0,
    BS_M_STATUS_3XX,
    BS_M_STATUS_4XX,
    BS_M_STATUS_5XX,
    BS_M_STATUS_OTHER,
    BS_M_STATUS_COUNT
} bs_m_status;

typedef enum {
    /* BS_M_COOKIE_OK is "verified but carries no solve proof" -- a
     * presence cookie. BS_M_COOKIE_SOLVED is the same verification
     * plus passes_silent/form/captcha in the authenticated rep block.
     * The two are disjoint, deliberately: under always-mint every
     * client holds a valid cookie after one request, so "valid" says
     * nothing about whether a challenge was ever passed, and the
     * dashboard needs to show the difference rather than hide it
     * inside a single ok bucket. */
    BS_M_COOKIE_OK = 0,
    BS_M_COOKIE_EXPIRED,
    BS_M_COOKIE_BAD_SIG,
    BS_M_COOKIE_BAD_FORMAT,
    BS_M_COOKIE_ABSENT,
    BS_M_COOKIE_MINTED,
    BS_M_COOKIE_SOLVED,
    BS_M_COOKIE_COUNT
} bs_m_cookie;

typedef enum {
    BS_M_PROV_TURNSTILE = 0,
    BS_M_PROV_HCAPTCHA,
    BS_M_PROV_RECAPTCHA_V2,
    BS_M_PROV_RECAPTCHA_V3,
    BS_M_PROV_FRIENDLY,
    BS_M_PROV_GEETEST,
    BS_M_PROV_COUNT
} bs_m_provider;

/* E11 load-aware throttling state — value lives in
 * bs_shm_header.load_state (as apr_uint32_t for atomic access). The
 * sampler watchdog + hysteresis logic lives in botshield.c; the
 * tunables below are exposed here because the enum is. */
typedef enum {
    BS_LOAD_NORMAL = 0,
    BS_LOAD_WARM   = 1,
    BS_LOAD_HOT    = 2,
} bs_load_state;

#define BS_DEFAULT_LOAD_REFRESH_SEC      1
#define BS_DEFAULT_LOAD_WARM_RATIO_PCT   65    /* busy_workers / total */
#define BS_DEFAULT_LOAD_HOT_RATIO_PCT    85
/* Hysteresis: asymmetric. Easy to enter (3 escalating samples to
 * warm, 2 more to hot), slow to exit (5 normal samples to demote
 * one level). Tunes the responsiveness vs. flap-resistance tradeoff. */
#define BS_DEFAULT_LOAD_WARM_RISE        3
#define BS_DEFAULT_LOAD_HOT_RISE         2
#define BS_DEFAULT_LOAD_WARM_FALL        5
#define BS_DEFAULT_LOAD_NORMAL_FALL      5

/* ======================================================================
 * Slot types
 * ====================================================================== */

/* Per-slot seqlock + payload. version bit 0 is "write in progress":
 * even = quiescent, odd = mid-write. Readers snapshot fields between
 * matching even versions.
 *
 * Empty-marker convention (unified across all SHM slot types as of
 * BS_SHM_FORMAT_VERSION 2): apr_uint32_t used == 0 means the slot is
 * unwritten; apr_shm_create zeroes the segment, so a fresh table
 * starts with every slot empty without any explicit init pass.
 *
 * E13 — `ns_id` field added so vhosts isolate flagged-IP reputation.
 * Lookups match (ip, ns_id); same physical table holds rows from many
 * namespaces without cross-pollution. */
typedef struct {
    apr_uint32_t  version;       /* seqlock counter */
    apr_uint32_t  used;          /* 0 = empty slot */
    unsigned char ip[16];        /* IPv6-mapped v4 or raw v6 */
    apr_uint32_t  flags;         /* OR'd flag bitmap */
    apr_uint32_t  ns_id;         /* E13 reputation namespace */
    apr_int64_t   expires_at;    /* unix seconds; past means stale */
} bs_flagged_ip_slot;

/* E9 — repeated-429 escalation. Per-(client_ip, rate_rule_slot) strike
 * accounting in SHM. Strike counter is windowed on `strike_window_start`
 * so an idle entry rolls over.
 *
 * `escalation_until == 0` → not yet crossed threshold. Non-zero → in
 * the escalated state until the timestamp passes. Each fresh strike
 * during escalation extends the timestamp (TTL slides on last strike). */
typedef struct {
    apr_uint32_t  version;             /* seqlock counter */
    apr_uint32_t  used;                /* 0 = empty slot */
    unsigned char ip[16];              /* masked per ipv6_prefix_bits */
    apr_uint32_t  rule_slot;           /* rate-rule index */
    apr_uint32_t  ns_id;               /* E13 reputation namespace */
    apr_uint32_t  strike_window_start; /* unix sec; 0 = no strikes yet */
    apr_uint32_t  strike_count;
    apr_int64_t   escalation_until;    /* unix sec; 0 = not escalated */
} bs_strike_slot;

/* E10 — challenge safeguard / anti-loop hysteresis.
 *
 *   `present_count` accumulates inside `present_window_start +
 *   window_sec`. Resets on bs_safeguard_clear (valid _bs_session
 *   arrived; client can solve, history was noise) or on window roll.
 *
 *   `safeguard_until == 0` → inactive; non-zero → request-time check
 *   returns "safeguard active" until timestamp passes. Each fresh
 *   presentation during active safeguard slides the TTL forward so a
 *   chronically broken client stays in safeguard rather than dropping
 *   in and out at every window boundary. */
typedef struct {
    apr_uint32_t  version;              /* seqlock */
    apr_uint32_t  used;                 /* 0 = empty slot */
    unsigned char ip[16];               /* masked per ipv6_prefix_bits */
    apr_uint32_t  present_window_start; /* unix sec */
    apr_uint32_t  present_count;
    apr_int64_t   safeguard_until;      /* unix sec; 0 = inactive */
    apr_uint32_t  ns_id;                /* E13 reputation namespace */
    apr_uint32_t  _pad;
} bs_safeguard_slot;

/* embedded-bootstrap nonce table. Records every
 * successfully-redeemed challenge nonce with its expiry so the verify
 * endpoint can reject replays. Keyed on a 64-bit SipHash of
 * (8-byte challenge nonce || 4-byte ns_id). Eviction on expiry. */
typedef struct {
    apr_uint32_t  version;        /* seqlock */
    apr_uint32_t  used;           /* 0 = empty slot */
    apr_uint64_t  nonce_hash;     /* siphash24(siphash_key, nonce||ns_id) */
    apr_int64_t   expires_at;     /* unix sec; past means stale */
    apr_uint32_t  ns_id;          /* E13 reputation namespace */
    apr_uint32_t  _pad;
} bs_nonce_slot;

/* M8.1 — captcha-verify rate-limit slot encoding. One uint64 per slot:
 *   bits 63..20  unix-minute window start
 *   bits 19..0   count within that window (0..1M)
 * Rolling to a new minute is a CAS of the whole slot. */
typedef apr_uint64_t bs_cv_slot;

/* SHM segment header. Three 64-byte cachelines — write-once config,
 * hot-read/rare-write, and write-frequently — segregated to prevent
 * false sharing between fields with very different read/write rates.
 * The layout is locked by static_assert below. */
typedef struct {
    /* === Cacheline 0: configuration (write-once) === */
    apr_uint32_t  magic;
    apr_uint32_t  format_version;
    apr_uint32_t  flagged_capacity;
    apr_uint32_t  bloom_buf_bytes;
    apr_uint32_t  bloom_window_secs;
    apr_uint32_t  cv_rate_slots;
    apr_uint32_t  cv_log_slots;
    apr_uint32_t  _pad_cl0_a;
    unsigned char siphash_key[16];
    apr_uint32_t  _pad_cl0[4];

    /* === Cacheline 1: hot-read, rare-write === */
    apr_uint32_t  bloom_active;
    apr_uint32_t  load_state;
    apr_uint32_t  load_state_since_sec;
    apr_uint32_t  load_escalation_streak;
    apr_uint32_t  load_recovery_streak;
    apr_uint32_t  load_state_changes;
    apr_uint32_t  _pad_cl1[10];

    /* === Cacheline 2: write-frequently === */
    apr_uint32_t  cv_inflight;
    apr_uint32_t  _pad_cl2_a;
    apr_int64_t   bloom_next_rotate;
    /* Probe-saturation log-throttle
     * timestamps shared across worker processes. */
    apr_int64_t   probe_warn_flagged_us;
    apr_int64_t   probe_warn_strike_us;
    apr_int64_t   probe_warn_safeguard_us;
    /* Log-throttle for the response-kind/status invariant (see
     * resp_status_mismatch_total). Same shared-across-workers shape as
     * the probe-saturation throttles above: this fires from
     * log_transaction, which runs on every request, so an unthrottled
     * warning would be one log line per request under a systematic
     * fault -- exactly when the log is least affordable. Carved from
     * the trailing pad so the header keeps its size. */
    apr_int64_t   resp_mismatch_warn_us;
    apr_uint32_t  _pad_cl2[4];
} bs_shm_header;


/* ----------------------------------------------------------------------
 * Per-vhost metrics
 *
 * Each distinct ServerName gets its own bs_metrics block, so the
 * dashboard can break the numbers down per site. Blocks are the same
 * type as the global one: a few hundred bytes per vhost are wasted on
 * the server-wide-only fields (persistence gauges and such, which stay
 * zero in a vhost block), and in exchange there is no second struct to
 * drift out of sync and no separate read path.
 *
 * The global block is still written directly and remains the
 * aggregate, so Prometheus and mod_status are untouched by any of this
 * and the "All" tab cannot disagree with them.
 *
 * Vhosts sharing a ServerName -- the usual :80 and :443 pair -- share
 * one block, because an operator thinks in sites, not in listeners.
 * Past BS_M_MAX_VHOSTS distinct names, the overflow all lands in the
 * last slot, which the dashboard labels as such rather than silently
 * dropping it.
 * -------------------------------------------------------------------- */
#define BS_M_MAX_VHOSTS      32
#define BS_M_VHOST_NAME_MAX  64

typedef struct {
    apr_uint32_t count;                 /* blocks actually allocated */
    apr_uint32_t overflowed;            /* 1 = last slot is the catch-all */
    char name[BS_M_MAX_VHOSTS][BS_M_VHOST_NAME_MAX];
} bs_vhost_dir;

/* ----------------------------------------------------------------------
 * Time-bucketed decision counters (dashboard windows)
 *
 * Two epoch-stamped rings give 15-minute, 1-hour and 24-hour views
 * without a time-series store. A slot records which epoch (minute
 * number, or hour number) it holds; a writer landing on a slot from an
 * older wrap claims it via CAS and zeroes it, and a reader simply skips
 * any slot whose epoch falls outside the window. Nothing sweeps.
 *
 * The minute ring is 60 slots so it serves both the 15-minute and the
 * 1-hour window; the hour ring covers a day. All-time stays the plain
 * cumulative counters below.
 *
 * Cost: (60 + 24) slots x ~240 bytes = ~20 KB of a 16 MB segment.
 * Three extra relaxed atomic adds per decision, and three per request
 * for the site-wide traffic fields (which run on every request, not
 * just evaluated ones).
 *
 * Accuracy: two writers crossing a bucket boundary can race, and the
 * loser's increment may land in the slot the winner just zeroed. These
 * counters are advisory — the same posture the gauges already take —
 * and a CAS-per-increment is not worth paying on the decision path.
 * -------------------------------------------------------------------- */
#define BS_M_MIN_SLOTS   60   /* 1-minute slots: serves 15min and 1h */
#define BS_M_HOUR_SLOTS  24   /* 1-hour slots: serves 24h */

typedef struct {
    apr_uint64_t epoch;                    /* minute or hour number; 0 = unused */
    apr_uint64_t tier   [BS_M_TIER_COUNT];
    apr_uint64_t outcome[BS_M_OUTCOME_COUNT];
    /* Cookie state is in the ring because it carries the only solve
     * signal the PoW tiers produce. outcome=verified comes solely from
     * captcha siteverify; a client that solves a silent/form
     * interstitial returns on a fresh request that reads cookie=ok, so
     * a windowed solve rate needs this dimension, not just outcome[]. */
    apr_uint64_t cookie [BS_M_COOKIE_COUNT];
    /* Site-wide traffic, counted at log_transaction — which runs for
     * every request on every vhost, regardless of BotShieldEnabled
     * scope. Decisions are a subset: with the enable scoped to a
     * <Location>, req_total is the denominator that makes "how much of
     * the site is actually covered" answerable. */
    apr_uint64_t req_total;
    apr_uint64_t req_cookie;               /* carried a session cookie */
    apr_uint64_t req_status[BS_M_STATUS_COUNT];
    apr_uint64_t req_resp[BS_M_RESP_COUNT];
    apr_uint64_t req_class[BS_M_CLASS_COUNT];
} bs_metrics_slot;

/* M9.2 metrics block. Lives in SHM next to the rate-counter pool. */
typedef struct {
    apr_uint64_t tier   [BS_M_TIER_COUNT];
    apr_uint64_t outcome[BS_M_OUTCOME_COUNT];
    apr_uint64_t cookie [BS_M_COOKIE_COUNT];
    apr_uint64_t provider[BS_M_PROV_COUNT];
    /* Site-wide traffic (see bs_metrics_slot). */
    apr_uint64_t req_total;
    apr_uint64_t req_cookie;
    apr_uint64_t req_status[BS_M_STATUS_COUNT];
    apr_uint64_t req_resp[BS_M_RESP_COUNT];
    apr_uint64_t req_class[BS_M_CLASS_COUNT];
    /* Persistence gauges. */
    apr_uint64_t state_saves_total;
    apr_uint64_t state_save_last_unix;
    apr_uint64_t state_save_last_bytes;
    apr_uint64_t state_save_last_duration_us;
    apr_uint64_t state_loads_total;
    apr_uint64_t state_load_last_kept;
    apr_uint64_t state_load_last_dropped;
    /* E1 — crawler verification aggregate counters. */
    apr_uint64_t bot_allow_total;
    apr_uint64_t bot_fake_total;
    apr_uint64_t bot_unverified_total;
    /* E2.1 — enforcement counters. */
    apr_uint64_t rate_limit_exceeded_total;
    /* E12 — log-only / observe-mode counters. */
    apr_uint64_t rate_limit_observed_total;
    apr_uint64_t trigger_observed_total;
    /* Requests where BotShield recorded that IT produced the response
     * -- challenge, block, rate-limit, safeguard redirect -- and the
     * client nevertheless received a 2xx, i.e. the application answered.
     * The two are mutually exclusive by construction, so this counter
     * should read zero forever.
     *
     * It exists because both halves of the comparison were already being
     * computed side by side in bs_propagate_decision_env and then filed
     * into separate marginal tallies (req_resp[] and req_status[]),
     * which cannot express "these two happened on the SAME request".
     * You could read 500 challenges and 40,000 2xx off /metrics and
     * never learn whether any single request was both.
     *
     * What a non-zero value means: something downstream overrode
     * BotShield's response -- an ErrorDocument, an internal redirect
     * re-dispatching to the handler -- and the decision log is
     * overstating enforcement. That is the silent-failure shape this
     * deployment has been bitten by: green configtest, running httpd,
     * nothing alerting, traffic unprotected. A counter that should be
     * zero is the cheapest way to make it loud. */
    apr_uint64_t resp_status_mismatch_total;
    /* Windowed views of tier/outcome — see bs_metrics_slot above. */
    bs_metrics_slot min_slots [BS_M_MIN_SLOTS];
    bs_metrics_slot hour_slots[BS_M_HOUR_SLOTS];
} bs_metrics;

/* Module-global runtime pointer struct. Populated once in post-config;
 * children inherit via fork. `rate_counters` stays opaque (`void *`)
 * because the bs_rate_counter struct is owned by the rate-limit
 * machinery, not the SHM layer — shm.c only stores the
 * pointer, never dereferences it. */
typedef struct {
    apr_shm_t           *shm;
    apr_global_mutex_t  *mutex;
    const char          *mutex_filename;
    bs_shm_header       *header;
    bs_flagged_ip_slot  *flagged_table;
    apr_size_t           flagged_capacity;
    unsigned char       *bloom_bufs[2];
    apr_size_t           bloom_buf_bytes;
    /* M8.1 */
    bs_cv_slot          *cv_rate_slots;
    apr_size_t           cv_rate_slot_count;
    bs_cv_slot          *cv_log_slots;
    apr_size_t           cv_log_slot_count;
    apr_uint32_t        *cv_inflight;
    /* M9.2 */
    bs_metrics          *metrics;
    /* Per-vhost blocks + the ServerName directory that indexes them. */
    bs_vhost_dir        *vhost_dir;
    bs_metrics          *vmetrics;
    /* E2.1 — fixed-window rate-limit counter pool, opaque from
     * the SHM layer's perspective. */
    void                *rate_counters;
    apr_size_t           rate_counter_count;
    /* E9 strike table */
    bs_strike_slot      *strike_table;
    apr_size_t           strike_capacity;
    /* E10 safeguard table */
    bs_safeguard_slot   *safeguard_table;
    apr_size_t           safeguard_capacity;
    /* Embedded-bootstrap nonce table — one-time-use binding for
     * silent-tier challenges; insert at issue, atomic-consume at
     * verify, second presentation rejected. */
    bs_nonce_slot       *nonce_table;
    apr_size_t           nonce_capacity;
} bs_shm_runtime;

/* Module-global. Defined in shm.c; botshield.c
 * (and its post_config in particular) writes the slot pointers
 * into this directly during SHM segment layout. */
extern bs_shm_runtime bs_shm;

/* M6 state-save snapshot context. Wraps a generation's bs_shm at
 * cleanup-registration time so a graceful restart's cleanup save
 * targets ITS OWN snapshot rather than whatever bs_shm now points
 * at after the new generation's post_config. */
typedef struct bs_state_cleanup_ctx {
    apr_pool_t      *pool;
    server_rec      *server;
    const char      *path;
    bs_shm_runtime   shm_rt;
} bs_state_cleanup_ctx;

/* ======================================================================
 * Public functions
 * ====================================================================== */

/* SipHash-2-4. Keyed bucket hash for the SHM open-addressed tables;
 * key lives in bs_shm.header->siphash_key, generated at post_config
 * via RAND_bytes so attackers can't precompute colliding inputs. */
apr_uint64_t bs_siphash24(const unsigned char key[16],
                          const unsigned char *data, apr_size_t len);

/* Bit-population count over a buffer. Used by Bloom-fill metrics
 * gauges (in botshield.c) and the headroom watchdog (here).
 * Uses relaxed atomic loads — Bloom buffers are concurrently
 * mutated; popcount is inherently an approximation. */
apr_uint64_t bs_popcount_buffer(const unsigned char *buf,
                                apr_size_t bytes);

/* --- Flagged-IP table ---------------------------------------------- */

void bs_flagged_ip_add(request_rec *r, const unsigned char ip[16],
                       apr_uint32_t flag_bits, int ttl_seconds,
                       apr_uint32_t ns_id);
int  bs_flagged_ip_lookup(const unsigned char ip[16],
                          apr_uint32_t *out_flags, apr_uint32_t ns_id);

/* --- Strike table (E9) --------------------------------------------- *
 *
 * bs_strike_record_429 takes the three rate-escalate policy ints
 * directly (per_sec window, strikes-to-cross, ttl_sec for the
 * escalated state) so this header doesn't need bs_rate_escalate_entry.
 * The caller resolves config defaults at the call site. */
int  bs_strike_check_escalated(const unsigned char ip[16],
                               apr_uint32_t rule_slot,
                               apr_int64_t now,
                               apr_uint32_t ns_id);
int  bs_strike_record_429(request_rec *r,
                          const unsigned char ip[16],
                          apr_uint32_t rule_slot,
                          apr_uint32_t per_sec,
                          apr_uint32_t strikes,
                          apr_int64_t  ttl_sec,
                          apr_int64_t  now,
                          apr_uint32_t ns_id);

/* --- Safeguard table (E10) ---------------------------------------- *
 *
 * bs_safeguard_record_presentation takes the three policy ints
 * (threshold, window-sec, ttl-sec) directly for the same reason —
 * the SHM header stays free of bs_server_cfg knowledge. */
int          bs_safeguard_check(const unsigned char ip[16],
                                apr_int64_t now, apr_uint32_t ns_id);
apr_uint32_t bs_safeguard_present_count(const unsigned char ip[16],
                                        apr_int64_t now,
                                        apr_uint32_t ns_id);
void bs_safeguard_record_presentation(request_rec *r,
                                      const unsigned char ip[16],
                                      int threshold, int window,
                                      int ttl,
                                      apr_int64_t now,
                                      apr_uint32_t ns_id);
void bs_safeguard_clear(request_rec *r, const unsigned char ip[16],
                        apr_uint32_t ns_id);
/* "If v is positive, return v; otherwise return dflt." Used by
 * callers translating BS_UNSET (-1) sentinels into hard defaults
 * when feeding the policy ints to bs_safeguard_record_presentation. */
int  bs_safeguard_effective_int(int v, int dflt);

/* --- Bloom filter (M5.2) ------------------------------------------ */

void bs_bloom_rotate_if_due(apr_int64_t now_sec);
void bs_bloom_add(const unsigned char ip[16], apr_uint32_t ns_id);
int  bs_bloom_seen(const unsigned char ip[16], apr_uint32_t ns_id);

/* --- Embedded-bootstrap nonce table ----------- */

/* Atomically claim a nonce. Returns 1 if the nonce was unused (and
 * has now been recorded with the given expiry); 0 if it was already
 * present (replay) or under saturation/lock-contention failure
 * (fail-closed). Caller passes the canonical 8-byte challenge nonce. */
int bs_embedded_nonce_consume(request_rec *r,
                              const unsigned char *nonce,
                              apr_size_t nonce_len,
                              apr_int64_t expires_at,
                              apr_uint32_t ns_id);

/* --- M6 state save / load ----------------------------------------- */

void         bs_state_load(apr_pool_t *p, server_rec *s, const char *path);
apr_status_t bs_state_save(apr_pool_t *p, server_rec *s,
                           const char *path,
                           const bs_shm_runtime *rt);
apr_status_t bs_state_cleanup(void *data);

/* mod_watchdog tick that calls bs_state_save at the configured
 * BotShieldStateSaveInterval. Registered against mod_watchdog by
 * post_config; ignores STARTING / STOPPING events. */
apr_status_t bs_state_save_watchdog_cb(int state, void *data,
                                 apr_pool_t *pool);

/* --- SHM lifecycle ------------------------------------------------ */

apr_status_t bs_shm_cleanup(void *data);

/* mod_watchdog tick: walks the four SHM tables + Bloom buffers and
 * NOTICEs / WARNINGs on capacity-headroom thresholds. Registered in
 * post_config alongside the load-sampler watchdog. */
apr_status_t bs_headroom_watchdog_cb(int state, void *data,
                                     apr_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_SHM_H */
