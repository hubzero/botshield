/* shm.c — SHM table machinery for mod_botshield.
 *
 * See shm.h for the design narrative on why five similarly-
 * shaped tables live here. This file owns:
 *
 *   - The bs_shm runtime global (struct definition: bs_shm_runtime in
 *     the header). botshield.c writes the slot pointers into it
 *     during the SHM segment layout pass in post_config; lookups and
 *     mutators read it through the public functions below.
 *
 *   - SipHash-2-4 over the SHM-resident key. Used both for the open-
 *     addressed bucket indices (DoS-resistant; key generated at
 *     post_config via RAND_bytes) and as a 64-bit fingerprint for the
 *     embedded-bootstrap nonce table.
 *
 *   - Per-table helpers (bucket, write-slot, read-slot loops) plus the
 *     public lookup/insert functions for flagged-IP, strike, safeguard,
 *     embedded-bootstrap nonce, and the rotating Bloom filter.
 *
 *   - The M6 state save/load envelope and its pool-cleanup trampoline
 *     plus parent-directory fsync helper.
 *
 *   - The capacity-headroom watchdog tick (mod_watchdog callback). One
 *     unified walker dispatches per-table predicates so the four-table
 *     scan shares a single rate-limited warning state. */

#include "shm.h"

#include <string.h>
#include <stddef.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <apr_atomic.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_file_io.h>
#include <apr_thread_mutex.h>

#include <http_log.h>
#include <ap_mpm.h>
#include <mod_watchdog.h>

/* ======================================================================
 * Module-global runtime state
 * ====================================================================== */

bs_shm_runtime bs_shm;

/* Lock the cacheline layout. If a future field addition slips one of
 * the three sections off its 64-byte boundary, this fires at compile
 * time so the false-sharing fix doesn't silently regress. */
_Static_assert(sizeof(bs_shm_header) == 192,
               "bs_shm_header must be exactly three 64-byte cachelines");
_Static_assert(offsetof(bs_shm_header, bloom_active) == 64,
               "cacheline 1 starts at offset 64");
_Static_assert(offsetof(bs_shm_header, cv_inflight) == 128,
               "cacheline 2 starts at offset 128");

/* ======================================================================
 * SipHash-2-4 (bucket hash + nonce fingerprint)
 *
 * Key lives in bs_shm.header->siphash_key, generated at post-config so
 * attackers can't precompute colliding inputs to evict stored entries.
 * ====================================================================== */

static inline apr_uint64_t bs_rotl64(apr_uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

#define BS_SIPROUND() do {                                                 \
    v0 += v1; v1 = bs_rotl64(v1,13); v1 ^= v0; v0 = bs_rotl64(v0,32);      \
    v2 += v3; v3 = bs_rotl64(v3,16); v3 ^= v2;                             \
    v0 += v3; v3 = bs_rotl64(v3,21); v3 ^= v0;                             \
    v2 += v1; v1 = bs_rotl64(v1,17); v1 ^= v2; v2 = bs_rotl64(v2,32);      \
} while (0)

apr_uint64_t bs_siphash24(const unsigned char key[16],
                          const unsigned char *data, apr_size_t len)
{
    apr_uint64_t k0, k1;
    memcpy(&k0, key,     8);
    memcpy(&k1, key + 8, 8);

    apr_uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    apr_uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    apr_uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    apr_uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const unsigned char *end = data + (len - (len & 7));
    for (; data != end; data += 8) {
        apr_uint64_t m;
        memcpy(&m, data, 8);
        v3 ^= m;
        BS_SIPROUND(); BS_SIPROUND();
        v0 ^= m;
    }

    apr_uint64_t b = ((apr_uint64_t)len) << 56;
    switch (len & 7) {
        case 7: b |= ((apr_uint64_t)data[6]) << 48; /* fallthrough */
        case 6: b |= ((apr_uint64_t)data[5]) << 40; /* fallthrough */
        case 5: b |= ((apr_uint64_t)data[4]) << 32; /* fallthrough */
        case 4: b |= ((apr_uint64_t)data[3]) << 24; /* fallthrough */
        case 3: b |= ((apr_uint64_t)data[2]) << 16; /* fallthrough */
        case 2: b |= ((apr_uint64_t)data[1]) <<  8; /* fallthrough */
        case 1: b |= ((apr_uint64_t)data[0]);       /* fallthrough */
        case 0: break;
    }
    v3 ^= b;
    BS_SIPROUND(); BS_SIPROUND();
    v0 ^= b;
    v2 ^= 0xff;
    BS_SIPROUND(); BS_SIPROUND(); BS_SIPROUND(); BS_SIPROUND();
    return v0 ^ v1 ^ v2 ^ v3;
}
#undef BS_SIPROUND

/* ======================================================================
 * Popcount helpers
 *
 * Used by bloom-fill metric gauges (in botshield.c via the public
 * bs_popcount_buffer) and the headroom watchdog (here).
 * ====================================================================== */

static apr_uint64_t bs_popcount_u64(apr_uint64_t x)
{
    return (apr_uint64_t)__builtin_popcountll(x);
}

apr_uint64_t bs_popcount_buffer(const unsigned char *buf, apr_size_t bytes)
{
    apr_uint64_t total = 0;
    apr_size_t aligned_end = (bytes / 8) * 8;
    const apr_uint64_t *p64 = (const apr_uint64_t *)buf;
    apr_size_t n64 = aligned_end / 8;
    /* Relaxed atomic loads: the Bloom buffer is concurrently mutated
     * via byte-level __atomic_or_fetch in the insert path, so plain
     * u64 loads here would be a data race per the C memory model
     * (even though the hardware on x86_64 gives us the same answer).
     * The popcount result is inherently an approximation of a live
     * counter, so acquire ordering isn't needed — we just need TSAN
     * to see this as a race-tolerant read. */
    for (apr_size_t i = 0; i < n64; i++) {
        total += bs_popcount_u64(
            __atomic_load_n(&p64[i], __ATOMIC_RELAXED));
    }
    /* Tail bytes (Bloom buffers are u64-aligned per the post_config
     * layout, so aligned_end == bytes in practice — keep the loop for
     * safety if that ever changes). */
    for (apr_size_t i = aligned_end; i < bytes; i++) {
        total += (apr_uint64_t)__builtin_popcount(
            __atomic_load_n(&buf[i], __ATOMIC_RELAXED));
    }
    return total;
}

/* ======================================================================
 * Flagged-IP table
 * ====================================================================== */

/* SipHash-keyed bucket index for the flagged-IP probe walk. ns_id is
 * folded into the hash input so different reputation namespaces
 * (E13) get disjoint bucket distributions on the same physical table —
 * the slot's ns_id field is the authoritative match check; mixing
 * ns_id into the hash is a load-balancing optimization, not a
 * correctness one. */
static apr_uint32_t bs_flagged_bucket(const unsigned char ip[16],
                                      apr_uint32_t ns_id)
{
    unsigned char buf[16 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)( ns_id        & 0xFF);
    buf[17] = (unsigned char)((ns_id >>  8) & 0xFF);
    buf[18] = (unsigned char)((ns_id >> 16) & 0xFF);
    buf[19] = (unsigned char)((ns_id >> 24) & 0xFF);
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key,
                                  buf, sizeof(buf));
    return (apr_uint32_t)(h % bs_shm.flagged_capacity);
}

/* Write into a slot under seqlock protection. Caller must hold the
 * global mutex.
 *
 * Security review HIGH #5 — version stores use C11 RELEASE semantics,
 * version loads use ACQUIRE. apr_atomic_set32 / read32 only happen to
 * emit full barriers on x86; on AArch64 / POWER the plain payload
 * stores between the two version bumps could be reordered relative
 * to the version stores, allowing a lockless reader to observe an
 * even (committed) version with stale or torn payload bytes. The
 * release/acquire pair locks the ordering down portably. */
static void bs_flagged_write_slot(bs_flagged_ip_slot *slot,
                                  const unsigned char ip[16],
                                  apr_uint32_t flags,
                                  apr_int64_t expires_at,
                                  apr_uint32_t ns_id)
{
    apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
    __atomic_store_n(&slot->version, v | 1U, __ATOMIC_RELEASE);   /* begin: odd */
    slot->used       = 1;
    memcpy(slot->ip, ip, 16);
    slot->flags      = flags;
    slot->ns_id      = ns_id;
    slot->expires_at = expires_at;
    /* Release-publish: payload stores above are now visible. */
    __atomic_store_n(&slot->version, (v | 1U) + 1U, __ATOMIC_RELEASE);
}

void bs_flagged_ip_add(request_rec *r, const unsigned char ip[16],
                       apr_uint32_t flag_bits, int ttl_seconds,
                       apr_uint32_t ns_id)
{
    if (!bs_shm.flagged_table || !bs_shm.mutex) return;
    if (!flag_bits) return;
    if (ttl_seconds <= 0) ttl_seconds = 3600;

    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_int64_t expires_at = now + ttl_seconds;
    apr_uint32_t base = bs_flagged_bucket(ip, ns_id);

    /* Load-shed under heavy contention. Under a volumetric DDoS,
     * every malicious request reaches this write path; a blocking
     * lock would queue every Apache worker behind whichever one
     * holds the mutex and starve legitimate traffic. trylock + drop
     * trades one missed flag-write for keeping workers flowing —
     * acceptable because (a) the next request from the same IP
     * will retry, (b) the table is already lossy under probe-limit
     * overflow, and (c) silent drop is preferable to disk-I/O log
     * spam during the same DDoS. */
    apr_status_t rv = apr_global_mutex_trylock(bs_shm.mutex);
    if (APR_STATUS_IS_EBUSY(rv)) return;
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: flagged-IP mutex_lock failed; dropping flag");
        return;
    }

    int victim = -1;
    for (unsigned i = 0; i < BS_FLAGGED_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.flagged_capacity;
        bs_flagged_ip_slot *slot = &bs_shm.flagged_table[idx];

        /* LOW #9 — defensive version-odd skip. We hold the mutex,
         * so any odd version was left by a writer that crashed
         * mid-write (SIGKILL / OOM / segfault) before
         * bs_flagged_write_slot could rebump the version even.
         * The slot bytes are partial garbage; don't try to identify
         * an entry from them. Treat as recoverable victim space and
         * let the eviction path overwrite cleanly. */
        apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
        if (v & 1U) {
            if (victim < 0) victim = (int)idx;
            continue;
        }

        if (slot->used && slot->ns_id == ns_id
            && memcmp(slot->ip, ip, 16) == 0) {
            /* Merge flags, refresh TTL to whichever is later. */
            apr_uint32_t merged = slot->flags | flag_bits;
            apr_int64_t later   = slot->expires_at > expires_at
                                  ? slot->expires_at : expires_at;
            bs_flagged_write_slot(slot, ip, merged, later, ns_id);
            apr_global_mutex_unlock(bs_shm.mutex);
            return;
        }
        if (!slot->used && victim < 0) {
            victim = (int)idx;
            /* Empty is good; keep looking only in case an exact-IP
             * match is further along — we want to merge, not duplicate. */
        }
        if (slot->used && slot->expires_at < now && victim < 0) {
            victim = (int)idx;
        }
    }

    if (victim < 0) {
        /* Probe window was fully occupied with live non-matching entries.
         * Overwrite the first slot we looked at. Rate-limit the warning
         * so a sustained attack doesn't flood logs.
         *
         * Security review LOW #10 — log-throttle timestamp lives in
         * SHM so all worker processes coordinate. CAS-claim wins the
         * right to log; losers skip (the winner already emitted). */
        apr_time_t now_t = apr_time_now();
        apr_int64_t prev = __atomic_load_n(
            &bs_shm.header->probe_warn_flagged_us, __ATOMIC_RELAXED);
        if (now_t - (apr_time_t)prev > apr_time_from_sec(60) &&
            __atomic_compare_exchange_n(
                &bs_shm.header->probe_warn_flagged_us, &prev,
                (apr_int64_t)now_t, 0, __ATOMIC_RELAXED,
                __ATOMIC_RELAXED)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: flagged-IP table probe saturated at bucket %u "
                "(capacity %" APR_SIZE_T_FMT "); overwriting — consider "
                "raising BotShieldFlaggedIPCapacity",
                base, bs_shm.flagged_capacity);
        }
        victim = (int)base;
    }

    bs_flagged_write_slot(&bs_shm.flagged_table[victim], ip,
                          flag_bits, expires_at, ns_id);
    apr_global_mutex_unlock(bs_shm.mutex);
}

/* Read under seqlock. Returns 1 if the IP has a live entry, writing
 * the merged flag bitmap into *out_flags. 0 on miss or all retries
 * skipped. Readers never block writers; a caught-mid-write slot is
 * skipped (probe continues to the next). */
int bs_flagged_ip_lookup(const unsigned char ip[16],
                         apr_uint32_t *out_flags, apr_uint32_t ns_id)
{
    if (!bs_shm.flagged_table) return 0;

    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_uint32_t base = bs_flagged_bucket(ip, ns_id);

    for (unsigned i = 0; i < BS_FLAGGED_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.flagged_capacity;
        bs_flagged_ip_slot *slot = &bs_shm.flagged_table[idx];

        apr_uint32_t v1, v2;
        apr_uint32_t   local_used;
        unsigned char  local_ip[16];
        apr_uint32_t   local_flags;
        apr_int64_t    local_expires;
        apr_uint32_t   local_ns;
        int spins = 0;
        for (;;) {
            v1 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 & 1U) {
                if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
                continue;
            }
            local_used    = slot->used;
            memcpy(local_ip, slot->ip, 16);
            local_flags   = slot->flags;
            local_expires = slot->expires_at;
            local_ns      = slot->ns_id;
            v2 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;            /* slot too contended */
        if (!local_used) continue;          /* empty */
        if (local_expires < now) continue;  /* stale */
        if (local_ns != ns_id) continue;    /* E13: different namespace */
        if (memcmp(local_ip, ip, 16) != 0) continue;

        *out_flags = local_flags;
        return 1;
    }
    return 0;
}

/* ======================================================================
 * Strike table (E9: repeated-429 escalation)
 *
 * Same open-addressing + per-slot seqlock idiom as flagged_table. Hash
 * key is (masked client_ip, rule_slot, ns_id); collisions across
 * different rules for the same IP are valid — they just probe to
 * different buckets via the rule_slot mixin.
 * ====================================================================== */

static apr_uint32_t bs_strike_bucket(const unsigned char ip[16],
                                     apr_uint32_t rule_slot,
                                     apr_uint32_t ns_id)
{
    unsigned char buf[16 + 4 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)( rule_slot        & 0xFF);
    buf[17] = (unsigned char)((rule_slot >> 8 ) & 0xFF);
    buf[18] = (unsigned char)((rule_slot >> 16) & 0xFF);
    buf[19] = (unsigned char)((rule_slot >> 24) & 0xFF);
    buf[20] = (unsigned char)( ns_id            & 0xFF);
    buf[21] = (unsigned char)((ns_id >> 8 )     & 0xFF);
    buf[22] = (unsigned char)((ns_id >> 16)     & 0xFF);
    buf[23] = (unsigned char)((ns_id >> 24)     & 0xFF);
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key,
                                  buf, sizeof(buf));
    return (apr_uint32_t)(h % bs_shm.strike_capacity);
}

int bs_strike_check_escalated(const unsigned char ip[16],
                              apr_uint32_t rule_slot, apr_int64_t now,
                              apr_uint32_t ns_id)
{
    if (!bs_shm.strike_table || bs_shm.strike_capacity == 0) return 0;
    apr_uint32_t base = bs_strike_bucket(ip, rule_slot, ns_id);

    for (unsigned i = 0; i < BS_STRIKE_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.strike_capacity;
        bs_strike_slot *slot = &bs_shm.strike_table[idx];

        apr_uint32_t v1, v2;
        apr_uint32_t  local_used;
        unsigned char local_ip[16];
        apr_uint32_t  local_rule;
        apr_int64_t   local_until;
        apr_uint32_t  local_ns;
        int spins = 0;
        for (;;) {
            v1 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 & 1U) {
                if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
                continue;
            }
            local_used  = slot->used;
            local_rule  = slot->rule_slot;
            memcpy(local_ip, slot->ip, 16);
            local_until = slot->escalation_until;
            local_ns    = slot->ns_id;
            v2 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;
        if (!local_used) continue;
        if (local_rule != rule_slot) continue;
        if (local_ns != ns_id) continue;
        if (memcmp(local_ip, ip, 16) != 0) continue;
        return local_until > now;
    }
    return 0;
}

/* Strike accounting under the shared mutex. Bumps the (ip, rule)
 * counter inside its `per_sec` window, sets escalation_until on
 * threshold crossing. Returns 1 if THIS call crossed the threshold
 * from "not escalated" to "escalated" (caller logs the operator's
 * tag exactly once); 0 otherwise. */
int bs_strike_record_429(request_rec *r, const unsigned char ip[16],
                         apr_uint32_t rule_slot,
                         apr_uint32_t per_sec, apr_uint32_t strikes,
                         apr_int64_t ttl_sec,
                         apr_int64_t now, apr_uint32_t ns_id)
{
    if (!bs_shm.strike_table || !bs_shm.mutex) return 0;
    apr_uint32_t base = bs_strike_bucket(ip, rule_slot, ns_id);

    /* Load-shed under heavy contention — same rationale as
     * bs_flagged_ip_add. A dropped strike just means the attacker
     * gets one extra 429 before the rate-limit-abuse escalation
     * kicks in; retrying from the same IP will hit the lock when
     * it's free. */
    apr_status_t rv = apr_global_mutex_trylock(bs_shm.mutex);
    if (APR_STATUS_IS_EBUSY(rv)) return 0;
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: strike-table mutex_lock failed; "
            "dropping strike");
        return 0;
    }

    int matched_idx = -1;
    int empty_idx   = -1;
    for (unsigned i = 0; i < BS_STRIKE_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.strike_capacity;
        bs_strike_slot *slot = &bs_shm.strike_table[idx];
        /* LOW #9 — defensive version-odd skip. ACQUIRE pairs with
         * the RELEASE bumps in the write path. */
        apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
        if (v & 1U) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (!slot->used) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (slot->rule_slot == rule_slot
            && slot->ns_id == ns_id
            && memcmp(slot->ip, ip, 16) == 0) {
            matched_idx = (int)idx;
            break;
        }
    }

    int target_idx;
    if (matched_idx >= 0) {
        target_idx = matched_idx;
    } else if (empty_idx >= 0) {
        target_idx = empty_idx;
    } else {
        /* Security review LOW #10 — SHM-shared log-throttle. */
        apr_time_t now_t = apr_time_now();
        apr_int64_t prev = __atomic_load_n(
            &bs_shm.header->probe_warn_strike_us, __ATOMIC_RELAXED);
        if (now_t - (apr_time_t)prev > apr_time_from_sec(60) &&
            __atomic_compare_exchange_n(
                &bs_shm.header->probe_warn_strike_us, &prev,
                (apr_int64_t)now_t, 0, __ATOMIC_RELAXED,
                __ATOMIC_RELAXED)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: strike-table probe saturated at "
                "bucket %u (capacity %" APR_SIZE_T_FMT "); "
                "overwriting — consider raising "
                "BotShieldRateLimitEscalateCapacity",
                base, bs_shm.strike_capacity);
        }
        target_idx = (int)base;
    }

    bs_strike_slot *slot = &bs_shm.strike_table[target_idx];
    apr_uint32_t v0 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
    __atomic_store_n(&slot->version, v0 | 1U, __ATOMIC_RELEASE);   /* begin write */

    int crossed = 0;
    apr_uint32_t now_sec = (apr_uint32_t)now;
    int fresh_slot = (matched_idx < 0);
    if (fresh_slot) {
        slot->used                = 1;
        memcpy(slot->ip, ip, 16);
        slot->rule_slot           = rule_slot;
        slot->ns_id               = ns_id;
        slot->strike_window_start = now_sec;
        slot->strike_count        = 1;
        slot->escalation_until    = 0;
    } else {
        /* Window roll: reset count when the per-window has passed. */
        if (slot->strike_window_start == 0
            || now_sec - slot->strike_window_start >= per_sec) {
            slot->strike_window_start = now_sec;
            slot->strike_count        = 1;
        } else {
            slot->strike_count++;
        }
    }
    if (slot->strike_count >= strikes) {
        apr_int64_t prev_until = slot->escalation_until;
        slot->escalation_until = now + ttl_sec;
        if (prev_until <= now) crossed = 1;
    }

    __atomic_store_n(&slot->version, (v0 | 1U) + 1U, __ATOMIC_RELEASE);
    apr_global_mutex_unlock(bs_shm.mutex);
    return crossed;
}

/* ======================================================================
 * Safeguard table (E10: anti-loop hysteresis on challenge presentation)
 * ====================================================================== */

int bs_safeguard_effective_int(int v, int dflt)
{
    return (v > 0) ? v : dflt;
}

static apr_uint32_t bs_safeguard_bucket(const unsigned char ip[16],
                                        apr_uint32_t ns_id)
{
    /* E13 — fold ns_id into the hash so vhosts with different
     * reputation namespaces get disjoint bucket distributions. */
    unsigned char buf[16 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)(ns_id      );
    buf[17] = (unsigned char)(ns_id >>  8);
    buf[18] = (unsigned char)(ns_id >> 16);
    buf[19] = (unsigned char)(ns_id >> 24);
    apr_uint64_t h = bs_siphash24(bs_shm.header->siphash_key,
                                  buf, sizeof(buf));
    /* Mix a distinct constant so this table's bucket distribution
     * isn't perfectly correlated with flagged_table / strike_table
     * for the same IP — reduces probe-window collisions across
     * tables under high saturation. */
    h ^= 0xC0FFEE00BA5EBA11ULL;
    return (apr_uint32_t)(h % bs_shm.safeguard_capacity);
}

int bs_safeguard_check(const unsigned char ip[16], apr_int64_t now,
                       apr_uint32_t ns_id)
{
    if (!bs_shm.safeguard_table || bs_shm.safeguard_capacity == 0) return 0;
    apr_uint32_t base = bs_safeguard_bucket(ip, ns_id);

    for (unsigned i = 0; i < BS_SAFEGUARD_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.safeguard_capacity;
        bs_safeguard_slot *slot = &bs_shm.safeguard_table[idx];

        apr_uint32_t v1, v2;
        apr_uint32_t  local_used;
        apr_uint32_t  local_ns_id;
        unsigned char local_ip[16];
        apr_int64_t   local_until;
        int spins = 0;
        for (;;) {
            v1 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 & 1U) {
                if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
                continue;
            }
            local_used  = slot->used;
            local_ns_id = slot->ns_id;
            memcpy(local_ip, slot->ip, 16);
            local_until = slot->safeguard_until;
            v2 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;
        if (!local_used) continue;
        if (local_ns_id != ns_id) continue;
        if (memcmp(local_ip, ip, 16) != 0) continue;
        return local_until > now;
    }
    return 0;
}

/* E17 — read present_count for this IP (lockless seqlock). Used by
 * the embedded → M7 fallback decision: after N consecutive silent-
 * tier-embedded dispatches without _bs_verified, the embedded short-
 * circuit is bypassed and M7 issues. */
apr_uint32_t bs_safeguard_present_count(const unsigned char ip[16],
                                        apr_int64_t now,
                                        apr_uint32_t ns_id)
{
    if (!bs_shm.safeguard_table || bs_shm.safeguard_capacity == 0) return 0;
    apr_uint32_t base = bs_safeguard_bucket(ip, ns_id);

    for (unsigned i = 0; i < BS_SAFEGUARD_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.safeguard_capacity;
        bs_safeguard_slot *slot = &bs_shm.safeguard_table[idx];

        apr_uint32_t v1, v2;
        apr_uint32_t  local_used;
        apr_uint32_t  local_ns_id;
        unsigned char local_ip[16];
        apr_uint32_t  local_window_start;
        apr_uint32_t  local_count;
        int spins = 0;
        for (;;) {
            v1 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 & 1U) {
                if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
                continue;
            }
            local_used         = slot->used;
            local_ns_id        = slot->ns_id;
            memcpy(local_ip, slot->ip, 16);
            local_window_start = slot->present_window_start;
            local_count        = slot->present_count;
            v2 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
            if (v1 == v2) break;
            if (++spins >= BS_FLAGGED_MAX_READ_SPINS) { v1 = ~0U; break; }
        }
        if (v1 == ~0U) continue;
        if (!local_used) continue;
        if (local_ns_id != ns_id) continue;
        if (memcmp(local_ip, ip, 16) != 0) continue;
        /* Window-rolled: count is stale, treat as zero. */
        apr_uint32_t window_sec = BS_DEFAULT_SAFEGUARD_WINDOW;
        if (local_window_start == 0 ||
            (apr_uint32_t)now - local_window_start >= window_sec) {
            return 0;
        }
        return local_count;
    }
    return 0;
}

void bs_safeguard_record_presentation(request_rec *r,
                                      const unsigned char ip[16],
                                      int threshold, int window, int ttl,
                                      apr_int64_t now, apr_uint32_t ns_id)
{
    if (!bs_shm.safeguard_table || !bs_shm.mutex) return;

    apr_uint32_t base = bs_safeguard_bucket(ip, ns_id);
    /* Load-shed under heavy contention — same rationale as
     * bs_flagged_ip_add. */
    apr_status_t rv = apr_global_mutex_trylock(bs_shm.mutex);
    if (APR_STATUS_IS_EBUSY(rv)) return;
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: safeguard-table mutex_lock failed; "
            "dropping presentation record");
        return;
    }

    int matched_idx = -1;
    int empty_idx   = -1;
    for (unsigned i = 0; i < BS_SAFEGUARD_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.safeguard_capacity;
        bs_safeguard_slot *slot = &bs_shm.safeguard_table[idx];
        apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
        if (v & 1U) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (!slot->used) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (slot->ns_id != ns_id) continue;
        if (memcmp(slot->ip, ip, 16) == 0) {
            matched_idx = (int)idx;
            break;
        }
    }

    int target_idx;
    if (matched_idx >= 0) {
        target_idx = matched_idx;
    } else if (empty_idx >= 0) {
        target_idx = empty_idx;
    } else {
        apr_time_t now_t = apr_time_now();
        apr_int64_t prev = __atomic_load_n(
            &bs_shm.header->probe_warn_safeguard_us, __ATOMIC_RELAXED);
        if (now_t - (apr_time_t)prev > apr_time_from_sec(60) &&
            __atomic_compare_exchange_n(
                &bs_shm.header->probe_warn_safeguard_us, &prev,
                (apr_int64_t)now_t, 0, __ATOMIC_RELAXED,
                __ATOMIC_RELAXED)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: safeguard-table probe saturated at "
                "bucket %u (capacity %" APR_SIZE_T_FMT "); overwriting "
                "— consider raising BotShieldSafeguardCapacity",
                base, bs_shm.safeguard_capacity);
        }
        target_idx = (int)base;
    }

    bs_safeguard_slot *slot = &bs_shm.safeguard_table[target_idx];
    apr_uint32_t v0 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
    __atomic_store_n(&slot->version, v0 | 1U, __ATOMIC_RELEASE);

    apr_uint32_t now_sec = (apr_uint32_t)now;
    int fresh_slot = (matched_idx < 0);
    if (fresh_slot) {
        memcpy(slot->ip, ip, 16);
        slot->used                 = 1;
        slot->ns_id                = ns_id;
        slot->present_window_start = now_sec;
        slot->present_count        = 1;
        slot->safeguard_until      = 0;
    } else if (slot->present_window_start == 0
               || now_sec - slot->present_window_start
                  >= (apr_uint32_t)window) {
        /* Window rolled — start fresh counting from this presentation. */
        slot->present_window_start = now_sec;
        slot->present_count        = 1;
    } else {
        slot->present_count++;
    }
    if (slot->present_count >= (apr_uint32_t)threshold) {
        slot->safeguard_until = now + ttl;
    }

    __atomic_store_n(&slot->version, (v0 | 1U) + 1U, __ATOMIC_RELEASE);
    apr_global_mutex_unlock(bs_shm.mutex);
}

void bs_safeguard_clear(request_rec *r, const unsigned char ip[16],
                        apr_uint32_t ns_id)
{
    if (!bs_shm.safeguard_table || !bs_shm.mutex) return;
    apr_uint32_t base = bs_safeguard_bucket(ip, ns_id);

    /* Security review HIGH #6 — distinguish EBUSY (expected shedding
     * under load) from other failures (mutex genuinely broken —
     * operator should know). Mirrors the
     * bs_safeguard_record_presentation pattern. */
    apr_status_t rv = apr_global_mutex_trylock(bs_shm.mutex);
    if (APR_STATUS_IS_EBUSY(rv)) return;
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: safeguard-table mutex_lock failed; "
            "dropping clear (entry will expire on its own TTL)");
        return;
    }
    for (unsigned i = 0; i < BS_SAFEGUARD_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.safeguard_capacity;
        bs_safeguard_slot *slot = &bs_shm.safeguard_table[idx];
        apr_uint32_t vc = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
        if (vc & 1U) continue;
        if (!slot->used) continue;
        if (slot->ns_id != ns_id) continue;
        if (memcmp(slot->ip, ip, 16) != 0) continue;
        apr_uint32_t v0 = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
        __atomic_store_n(&slot->version, v0 | 1U, __ATOMIC_RELEASE);
        slot->used                 = 0;
        slot->ns_id                = 0;
        slot->present_window_start = 0;
        slot->present_count        = 0;
        slot->safeguard_until      = 0;
        memset(slot->ip, 0, 16);
        __atomic_store_n(&slot->version, (v0 | 1U) + 1U, __ATOMIC_RELEASE);
        break;
    }
    apr_global_mutex_unlock(bs_shm.mutex);
}

/* ======================================================================
 * Embedded-bootstrap nonce table (MEDIUM #2 phase 2)
 * ====================================================================== */

int bs_embedded_nonce_consume(request_rec *r,
                              const unsigned char *nonce, apr_size_t nonce_len,
                              apr_int64_t expires_at, apr_uint32_t ns_id)
{
    if (!bs_shm.nonce_table || !bs_shm.mutex ||
        bs_shm.nonce_capacity == 0) {
        /* SHM unavailable: fail-closed. The verify endpoint can't
         * mint a cookie if we can't track redemption. */
        return 0;
    }
    if (!nonce || nonce_len == 0 || nonce_len > 32) return 0;

    /* Compose siphash input: nonce bytes + 4-byte ns_id (LE). */
    unsigned char buf[32 + 4];
    memcpy(buf, nonce, nonce_len);
    buf[nonce_len + 0] = (unsigned char)(ns_id & 0xFF);
    buf[nonce_len + 1] = (unsigned char)((ns_id >> 8) & 0xFF);
    buf[nonce_len + 2] = (unsigned char)((ns_id >> 16) & 0xFF);
    buf[nonce_len + 3] = (unsigned char)((ns_id >> 24) & 0xFF);
    apr_uint64_t fp = bs_siphash24(bs_shm.header->siphash_key,
                                   buf, nonce_len + 4);
    apr_uint32_t base = (apr_uint32_t)(fp % bs_shm.nonce_capacity);
    apr_int64_t now_sec = (apr_int64_t)apr_time_sec(apr_time_now());

    apr_status_t rv = apr_global_mutex_trylock(bs_shm.mutex);
    if (APR_STATUS_IS_EBUSY(rv)) return 0;
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
            "mod_botshield: nonce-table mutex_lock failed; "
            "rejecting verify");
        return 0;
    }

    int empty_idx = -1;
    int evict_idx = -1;
    for (unsigned i = 0; i < BS_NONCE_PROBE_LIMIT; i++) {
        apr_uint32_t idx = (base + i) % bs_shm.nonce_capacity;
        bs_nonce_slot *slot = &bs_shm.nonce_table[idx];
        apr_uint32_t vn = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
        if (vn & 1U) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (!slot->used) {
            if (empty_idx < 0) empty_idx = (int)idx;
            continue;
        }
        if (slot->nonce_hash == fp && slot->ns_id == ns_id) {
            if (slot->expires_at > now_sec) {
                /* Fresh duplicate — replay attempt. */
                apr_global_mutex_unlock(bs_shm.mutex);
                return 0;
            }
            /* Expired same-fingerprint slot — fine to reuse. */
            evict_idx = (int)idx;
            break;
        }
        if (slot->expires_at < now_sec && evict_idx < 0) {
            evict_idx = (int)idx;
        }
    }
    int target_idx = empty_idx >= 0 ? empty_idx
                  : evict_idx >= 0 ? evict_idx : -1;
    if (target_idx < 0) {
        /* Probe window fully occupied with fresh entries. Reuse the
         * safeguard probe-warn slot for log throttling rather than
         * burning a fourth header field for one extra warning. */
        apr_time_t now_t = apr_time_now();
        apr_int64_t prev = __atomic_load_n(
            &bs_shm.header->probe_warn_safeguard_us, __ATOMIC_RELAXED);
        if (now_t - (apr_time_t)prev > apr_time_from_sec(60) &&
            __atomic_compare_exchange_n(
                &bs_shm.header->probe_warn_safeguard_us, &prev,
                (apr_int64_t)now_t, 0, __ATOMIC_RELAXED,
                __ATOMIC_RELAXED)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: nonce-table probe saturated at "
                "bucket %u (capacity %" APR_SIZE_T_FMT "); failing "
                "verify closed — consider raising "
                "BotShieldEmbeddedNonceCapacity", base,
                bs_shm.nonce_capacity);
        }
        apr_global_mutex_unlock(bs_shm.mutex);
        return 0;
    }
    bs_nonce_slot *slot = &bs_shm.nonce_table[target_idx];
    apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_ACQUIRE);
    __atomic_store_n(&slot->version, v | 1U, __ATOMIC_RELEASE);
    slot->used       = 1;
    slot->nonce_hash = fp;
    slot->ns_id      = ns_id;
    slot->expires_at = expires_at;
    __atomic_store_n(&slot->version, (v | 1U) + 1U, __ATOMIC_RELEASE);
    apr_global_mutex_unlock(bs_shm.mutex);
    return 1;
}

/* ======================================================================
 * Rotating Bloom filter (M5.2)
 *
 * Two buffers share the same hash geometry. Writes go to whichever
 * buffer bloom_active points at; queries check each independently and
 * OR the results so "seen" means "fully present in A or fully present
 * in B" (not the weaker "each bit present in A or B"). Rotation is
 * driven by inserts (rotate-on-insert) and optionally by mod_watchdog
 * for low-traffic freshness — a CAS on bloom_next_rotate serializes
 * the rotation across processes without a lock.
 * ====================================================================== */

/* Compute K bit indices using SipHash + Kirsch-Mitzenmacher double
 * hashing: hash once for h1, salt and re-hash for h2, generate each
 * of the K indices as (h1 + i*h2) mod m_bits. ns_id is folded into
 * both inputs so different namespaces compute disjoint bit-position
 * sets — same physical Bloom buffer, logically isolated states. */
static void bs_bloom_indices(const unsigned char ip[16],
                             apr_uint32_t *out, apr_size_t m_bits,
                             apr_uint32_t ns_id)
{
    unsigned char buf[16 + 4];
    memcpy(buf, ip, 16);
    buf[16] = (unsigned char)( ns_id        & 0xFF);
    buf[17] = (unsigned char)((ns_id >>  8) & 0xFF);
    buf[18] = (unsigned char)((ns_id >> 16) & 0xFF);
    buf[19] = (unsigned char)((ns_id >> 24) & 0xFF);
    apr_uint64_t h1 = bs_siphash24(bs_shm.header->siphash_key,
                                   buf, sizeof(buf));
    buf[0] ^= 0x9e;   /* domain separator for the second hash */
    apr_uint64_t h2 = bs_siphash24(bs_shm.header->siphash_key,
                                   buf, sizeof(buf));
    for (int i = 0; i < BS_BLOOM_K; i++) {
        out[i] = (apr_uint32_t)((h1 + (apr_uint64_t)i * h2) % m_bits);
    }
}

void bs_bloom_rotate_if_due(apr_int64_t now_sec)
{
    if (!bs_shm.bloom_bufs[0]) return;
    apr_int64_t due =
        (apr_int64_t)apr_atomic_read64(
            (apr_uint64_t *)&bs_shm.header->bloom_next_rotate);
    if (now_sec < due) return;

    apr_int64_t next = now_sec +
        (apr_int64_t)bs_shm.header->bloom_window_secs / 2;
    apr_uint64_t prev = apr_atomic_cas64(
        (apr_uint64_t *)&bs_shm.header->bloom_next_rotate,
        (apr_uint64_t)next, (apr_uint64_t)due);
    if ((apr_int64_t)prev != due) return;   /* another worker rotated */

    apr_uint32_t old_active = apr_atomic_read32(&bs_shm.header->bloom_active);
    apr_uint32_t new_active = old_active ^ 1U;
    /* Clear the buffer that's about to start accepting writes.
     * Atomic relaxed loop instead of plain memset because the insert
     * path writes via byte-level __atomic_or_fetch — a plain memset
     * would race with concurrent writers per the C memory model.
     * Borrow the global mutex opportunistically (trylock) for clean
     * cross-table serialization; the atomic loop is what actually
     * fixes the race. */
    int held_mutex = 0;
    if (bs_shm.mutex &&
        apr_global_mutex_trylock(bs_shm.mutex) == APR_SUCCESS) {
        held_mutex = 1;
    }
    apr_uint64_t *p64 = (apr_uint64_t *)bs_shm.bloom_bufs[new_active];
    apr_size_t n64 = bs_shm.bloom_buf_bytes / 8;
    for (apr_size_t i = 0; i < n64; i++) {
        __atomic_store_n(&p64[i], (apr_uint64_t)0, __ATOMIC_RELAXED);
    }
    unsigned char *tail_start =
        (unsigned char *)bs_shm.bloom_bufs[new_active] + (n64 * 8);
    for (apr_size_t i = 0; i < bs_shm.bloom_buf_bytes - (n64 * 8); i++) {
        __atomic_store_n(&tail_start[i], (unsigned char)0,
                         __ATOMIC_RELAXED);
    }
    apr_atomic_set32(&bs_shm.header->bloom_active, new_active);
    if (held_mutex) apr_global_mutex_unlock(bs_shm.mutex);
}

void bs_bloom_add(const unsigned char ip[16], apr_uint32_t ns_id)
{
    if (!bs_shm.bloom_bufs[0]) return;
    bs_bloom_rotate_if_due((apr_int64_t)apr_time_sec(apr_time_now()));

    apr_size_t m_bits = (apr_size_t)bs_shm.bloom_buf_bytes * 8;
    apr_uint32_t indices[BS_BLOOM_K];
    bs_bloom_indices(ip, indices, m_bits, ns_id);

    apr_uint32_t active = apr_atomic_read32(&bs_shm.header->bloom_active);
    unsigned char *buf = bs_shm.bloom_bufs[active & 1U];
    for (int i = 0; i < BS_BLOOM_K; i++) {
        apr_uint32_t bit_idx  = indices[i];
        apr_size_t   byte_idx = bit_idx / 8;
        unsigned char mask    = (unsigned char)(1U << (bit_idx % 8));
        __atomic_or_fetch(&buf[byte_idx], mask, __ATOMIC_RELAXED);
    }
}

int bs_bloom_seen(const unsigned char ip[16], apr_uint32_t ns_id)
{
    if (!bs_shm.bloom_bufs[0]) return 0;
    apr_size_t m_bits = (apr_size_t)bs_shm.bloom_buf_bytes * 8;
    apr_uint32_t indices[BS_BLOOM_K];
    bs_bloom_indices(ip, indices, m_bits, ns_id);

    int in_a = 1, in_b = 1;
    for (int i = 0; i < BS_BLOOM_K; i++) {
        apr_uint32_t bit_idx  = indices[i];
        apr_size_t   byte_idx = bit_idx / 8;
        unsigned char mask    = (unsigned char)(1U << (bit_idx % 8));
        unsigned char a = __atomic_load_n(&bs_shm.bloom_bufs[0][byte_idx],
                                          __ATOMIC_RELAXED);
        unsigned char b = __atomic_load_n(&bs_shm.bloom_bufs[1][byte_idx],
                                          __ATOMIC_RELAXED);
        if (!(a & mask)) in_a = 0;
        if (!(b & mask)) in_b = 0;
        if (!in_a && !in_b) return 0;
    }
    return in_a || in_b;
}

/* ======================================================================
 * State persistence (M6)
 *
 * Narrow, boring format. Goal: survive graceful restart. Crashes lose
 * state since last save. Dimension mismatches, bad checksums, missing
 * file: all "start fresh," never fatal.
 * ====================================================================== */

static apr_uint64_t bs_fnv64(apr_uint64_t h, const unsigned char *data,
                             apr_size_t len)
{
    for (apr_size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* Slurp a whole file into a freshly-allocated buffer. Returns NULL on
 * any error; *out_len is valid only on success. */
static unsigned char *bs_state_read_all(apr_pool_t *p, const char *path,
                                        apr_size_t *out_len,
                                        const char **err)
{
    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, path,
                                    APR_FOPEN_READ | APR_FOPEN_BINARY,
                                    APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        *err = (APR_STATUS_IS_ENOENT(rv)) ? "no prior state file"
                                          : "cannot open state file";
        return NULL;
    }
    apr_finfo_t info;
    rv = apr_file_info_get(&info, APR_FINFO_SIZE, f);
    if (rv != APR_SUCCESS || info.size <= 0 ||
        info.size > (apr_off_t)(256 * 1024 * 1024)) {
        apr_file_close(f);
        *err = "bad size";
        return NULL;
    }
    unsigned char *buf = apr_palloc(p, (apr_size_t)info.size);
    apr_size_t want = (apr_size_t)info.size;
    rv = apr_file_read(f, buf, &want);
    apr_file_close(f);
    if (rv != APR_SUCCESS || want != (apr_size_t)info.size) {
        *err = "short read";
        return NULL;
    }
    *out_len = want;
    return buf;
}

void bs_state_load(apr_pool_t *p, server_rec *s, const char *path)
{
    const char *err = NULL;
    apr_size_t len = 0;
    unsigned char *buf = bs_state_read_all(p, path, &len, &err);
    if (!buf) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s: %s (starting fresh)",
            path, err ? err : "unavailable");
        return;
    }

    if (len < 60) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s too short (%" APR_SIZE_T_FMT
            " bytes); starting fresh", path, len);
        return;
    }

    apr_uint64_t want_fnv;
    memcpy(&want_fnv, buf + len - 8, 8);
    apr_uint64_t got_fnv = bs_fnv64(BS_FNV64_SEED, buf, len - 8);
    if (want_fnv != got_fnv) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s checksum mismatch; starting fresh",
            path);
        return;
    }

    unsigned char *p_cur = buf;
    unsigned char *p_end = buf + len - 8;

    apr_uint32_t magic, version;
    apr_int64_t  saved_at;
    memcpy(&magic,    p_cur, 4);  p_cur += 4;
    memcpy(&version,  p_cur, 4);  p_cur += 4;
    memcpy(&saved_at, p_cur, 8);  p_cur += 8;
    if (magic != BS_STATE_MAGIC) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s bad magic; starting fresh", path);
        return;
    }
    if (version != BS_STATE_FORMAT_VERSION) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s version %u (expected %u); "
            "starting fresh", path, version, BS_STATE_FORMAT_VERSION);
        return;
    }
    apr_int64_t now = (apr_int64_t)apr_time_sec(apr_time_now());
    apr_int64_t age = now - saved_at;
    if (age < 0 || age > BS_STATE_MAX_AGE_SECS) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s is %" APR_INT64_T_FMT " s old; "
            "starting fresh", path, age);
        return;
    }

    /* SipHash key restore: makes the post_config-randomized key a
     * no-op so flagged-IP entries (bucket-indexed under the saved
     * key) resolve to the right buckets after restart. */
    if (p_end - p_cur < (ptrdiff_t)sizeof(bs_shm.header->siphash_key)) {
        goto corrupt;
    }
    memcpy(bs_shm.header->siphash_key, p_cur,
           sizeof(bs_shm.header->siphash_key));
    p_cur += sizeof(bs_shm.header->siphash_key);

    if (p_end - p_cur < 4) { goto corrupt; }
    apr_uint32_t saved_cap;
    memcpy(&saved_cap, p_cur, 4); p_cur += 4;
    if (saved_cap != (apr_uint32_t)bs_shm.flagged_capacity) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s flagged-IP capacity %u != "
            "current %" APR_SIZE_T_FMT "; starting fresh",
            path, saved_cap, bs_shm.flagged_capacity);
        return;
    }
    apr_size_t flagged_bytes =
        (apr_size_t)saved_cap * sizeof(bs_flagged_ip_slot);
    if ((apr_size_t)(p_end - p_cur) < flagged_bytes) { goto corrupt; }
    memcpy(bs_shm.flagged_table, p_cur, flagged_bytes);
    p_cur += flagged_bytes;
    int kept = 0, dropped = 0;
    for (apr_size_t i = 0; i < bs_shm.flagged_capacity; i++) {
        bs_flagged_ip_slot *slot = &bs_shm.flagged_table[i];
        slot->version = 0;
        if (!slot->used) continue;
        if (slot->expires_at < now) {
            slot->used  = 0;
            slot->flags = 0;
            memset(slot->ip, 0, 16);
            slot->expires_at = 0;
            dropped++;
        } else {
            kept++;
        }
    }

    if (p_end - p_cur < 16) { goto corrupt; }
    apr_uint32_t saved_buf_bytes, saved_active;
    apr_int64_t  saved_next_rotate;
    memcpy(&saved_buf_bytes,  p_cur, 4); p_cur += 4;
    memcpy(&saved_active,     p_cur, 4); p_cur += 4;
    memcpy(&saved_next_rotate, p_cur, 8); p_cur += 8;
    if (saved_buf_bytes != (apr_uint32_t)bs_shm.bloom_buf_bytes) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
            "mod_botshield: state file %s bloom buf_bytes %u != "
            "current %" APR_SIZE_T_FMT "; flagged loaded, bloom fresh",
            path, saved_buf_bytes, bs_shm.bloom_buf_bytes);
        goto done_log;
    }
    if ((apr_size_t)(p_end - p_cur) < 2 * saved_buf_bytes) { goto corrupt; }
    memcpy(bs_shm.bloom_bufs[0], p_cur, saved_buf_bytes);
    p_cur += saved_buf_bytes;
    memcpy(bs_shm.bloom_bufs[1], p_cur, saved_buf_bytes);
    p_cur += saved_buf_bytes;
    apr_atomic_set32(&bs_shm.header->bloom_active, saved_active & 1U);
    bs_shm.header->bloom_next_rotate = saved_next_rotate;

done_log:
    if (bs_shm.metrics) {
        __atomic_fetch_add(&bs_shm.metrics->state_loads_total, 1,
                           __ATOMIC_RELAXED);
        __atomic_store_n(&bs_shm.metrics->state_load_last_kept,
                         (apr_uint64_t)kept, __ATOMIC_RELAXED);
        __atomic_store_n(&bs_shm.metrics->state_load_last_dropped,
                         (apr_uint64_t)dropped, __ATOMIC_RELAXED);
    }
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: state loaded from %s (age %" APR_INT64_T_FMT " s): "
        "flagged kept %d, dropped-stale %d, bloom buffers restored",
        path, age, kept, dropped);
    return;

corrupt:
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: state file %s truncated past header; starting fresh",
        path);
}

/* fsync the directory containing `path` so the post-rename directory
 * entry is durable on crash/power-loss. APR doesn't expose a directory-
 * fsync helper; fall back to plain POSIX open+fsync+close. Errors are
 * logged at INFO and non-fatal. */
static void bs_fsync_parent_dir(apr_pool_t *p, server_rec *s,
                                const char *path)
{
    char *dir = apr_pstrdup(p, path);
    char *slash = strrchr(dir, '/');
    if (!slash) return;
    if (slash == dir) dir[1] = '\0';
    else              *slash = '\0';
    int fd = open(dir, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_FROM_OS_ERROR(errno), s,
            "mod_botshield: state save: cannot open '%s' for fsync", dir);
        return;
    }
    if (fsync(fd) < 0) {
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_FROM_OS_ERROR(errno), s,
            "mod_botshield: state save: fsync('%s') failed", dir);
    }
    close(fd);
}

apr_status_t bs_state_save(apr_pool_t *p, server_rec *s,
                           const char *path, const bs_shm_runtime *rt)
{
    apr_time_t t_start = apr_time_now();
    apr_size_t flagged_bytes = rt->flagged_capacity
                               * sizeof(bs_flagged_ip_slot);
    apr_size_t bloom_bytes   = rt->bloom_buf_bytes;
    apr_size_t key_bytes     = sizeof(rt->header->siphash_key);
    apr_size_t total = 4 + 4 + 8                    /* header */
                     + key_bytes                    /* siphash key */
                     + 4 + flagged_bytes            /* flagged */
                     + 4 + 4 + 8 + 2 * bloom_bytes  /* bloom */
                     + 8;                           /* fnv */

    unsigned char *buf = apr_palloc(p, total);
    unsigned char *pc  = buf;

    apr_uint32_t magic   = BS_STATE_MAGIC;
    apr_uint32_t version = BS_STATE_FORMAT_VERSION;
    apr_int64_t  now     = (apr_int64_t)apr_time_sec(apr_time_now());
    memcpy(pc, &magic,   4); pc += 4;
    memcpy(pc, &version, 4); pc += 4;
    memcpy(pc, &now,     8); pc += 8;
    memcpy(pc, rt->header->siphash_key, key_bytes); pc += key_bytes;

    apr_uint32_t cap = (apr_uint32_t)rt->flagged_capacity;
    memcpy(pc, &cap, 4); pc += 4;

    /* Serialize the flagged-IP copy against bs_flagged_ip_add's
     * writer. Without the lock, a concurrent add's odd-version mid-
     * state can be captured.
     *
     * Security review MEDIUM #7 — was apr_global_mutex_lock
     * (blocking). bs_state_save runs from contexts where blocking on
     * a worker-held mutex stalls the parent or watchdog indefinitely.
     * Use timedlock with a 2-second ceiling: the critical section
     * we'd be waiting on is a bounded probe-loop (~10 slot scans)
     * followed by short stores; 2s is generous and short enough to
     * fail cleanly if something's wedged. */
    if (rt->mutex) {
        apr_status_t lr = apr_global_mutex_timedlock(
            rt->mutex, apr_time_from_sec(2));
        if (lr != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, lr, s,
                "mod_botshield: state save: could not lock mutex "
                "within 2s; skipping save to avoid blocking "
                "the parent or writing an inconsistent snapshot");
            return lr;
        }
    }
    memcpy(pc, rt->flagged_table, flagged_bytes);
    if (rt->mutex) apr_global_mutex_unlock(rt->mutex);
    pc += flagged_bytes;

    apr_uint32_t bb = (apr_uint32_t)rt->bloom_buf_bytes;
    apr_uint32_t act = apr_atomic_read32(&rt->header->bloom_active);
    apr_int64_t  nxt = rt->header->bloom_next_rotate;
    memcpy(pc, &bb,  4); pc += 4;
    memcpy(pc, &act, 4); pc += 4;
    memcpy(pc, &nxt, 8); pc += 8;
    /* Security review MEDIUM #5 — bloom buffers are mutated on the
     * request hot path via byte-level __atomic_or_fetch. Read with
     * matching atomic granularity. */
    for (int j = 0; j < 2; j++) {
        const unsigned char *src = rt->bloom_bufs[j];
        for (apr_size_t i = 0; i < bb; i++) {
            pc[i] = __atomic_load_n(&src[i], __ATOMIC_RELAXED);
        }
        pc += bb;
    }

    apr_uint64_t fnv = bs_fnv64(BS_FNV64_SEED, buf, pc - buf);
    memcpy(pc, &fnv, 8); pc += 8;

    /* Atomic write: .tmp then rename. */
    const char *tmp_path = apr_psprintf(p, "%s.tmp", path);
    apr_file_t *f = NULL;
    apr_status_t rv = apr_file_open(&f, tmp_path,
        APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE
          | APR_FOPEN_BINARY,
        APR_FPROT_UREAD | APR_FPROT_UWRITE, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
            "mod_botshield: state save: cannot open %s for writing",
            tmp_path);
        return rv;
    }
    apr_size_t want = total;
    rv = apr_file_write(f, buf, &want);
    if (rv == APR_SUCCESS && want == total) {
        rv = apr_file_sync(f);
    }
    apr_file_close(f);
    if (rv != APR_SUCCESS || want != total) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
            "mod_botshield: state save: write/fsync failed");
        apr_file_remove(tmp_path, p);
        return rv;
    }
    rv = apr_file_rename(tmp_path, path, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, s,
            "mod_botshield: state save: rename %s -> %s failed",
            tmp_path, path);
        apr_file_remove(tmp_path, p);
        return rv;
    }
    bs_fsync_parent_dir(p, s, path);

    apr_time_t t_end = apr_time_now();
    apr_int64_t duration_us = (apr_int64_t)(t_end - t_start);
    if (duration_us < 0) duration_us = 0;

    if (rt->metrics) {
        __atomic_fetch_add(&rt->metrics->state_saves_total, 1,
                           __ATOMIC_RELAXED);
        __atomic_store_n(&rt->metrics->state_save_last_unix,
                         (apr_uint64_t)apr_time_sec(t_end),
                         __ATOMIC_RELAXED);
        __atomic_store_n(&rt->metrics->state_save_last_bytes,
                         (apr_uint64_t)total, __ATOMIC_RELAXED);
        __atomic_store_n(&rt->metrics->state_save_last_duration_us,
                         (apr_uint64_t)duration_us, __ATOMIC_RELAXED);
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
        "mod_botshield: state saved to %s (%" APR_SIZE_T_FMT " bytes, "
        "%" APR_INT64_T_FMT " us)", path, total, duration_us);
    return APR_SUCCESS;
}

apr_status_t bs_state_cleanup(void *data)
{
    bs_state_cleanup_ctx *ctx = data;
    /* Use the snapshotted SHM rt — on a graceful restart, the global
     * bs_shm has already been overwritten by the new generation.
     * ctx->shm_rt remembers OUR generation's pointers. */
    if (!ctx->shm_rt.shm || !ctx->shm_rt.flagged_table ||
        !ctx->shm_rt.bloom_bufs[0]) {
        return APR_SUCCESS;
    }
    bs_state_save(ctx->pool, ctx->server, ctx->path, &ctx->shm_rt);
    return APR_SUCCESS;
}

/* ======================================================================
 * SHM segment lifecycle
 * ====================================================================== */

apr_status_t bs_shm_cleanup(void *data)
{
    /* Graceful-restart guard. The cleanup callback was registered
     * against the OLD pconf with that generation's apr_shm_t* as
     * data. By the time this fires, a new bs_post_config may have
     * already overwritten the global bs_shm with the new generation's
     * pointers. Unconditionally memset would zero out the new
     * generation's bs_shm — any worker forked from the parent AFTER
     * this point would inherit a NULLed struct and segfault on first
     * request. Only zero if our generation is still the active one. */
    apr_shm_t *old_shm = data;
    if (bs_shm.shm == old_shm) {
        memset(&bs_shm, 0, sizeof(bs_shm));
    }
    return APR_SUCCESS;
}

/* ======================================================================
 * Capacity-headroom watchdog (E13.1)
 *
 * Periodic walk over the four reputation tables + Bloom buffers,
 * NOTICE / WARNING when load factors approach the probe-saturation
 * cliff. The reactive "probe saturated" warnings inside the writer
 * paths fire AT the cliff — by then entries are already being
 * overwritten. The forward-looking warnings here give operators
 * time to bump capacity directives gracefully.
 *
 * Cleanup #1 — unified walker. The four checks share a single
 * rate-limited NOTICE/WARNING state and dispatch through one
 * descriptor table; the per-table differences live in a small
 * "count used slots" callback that knows how to interpret the
 * per-slot empty-marker convention.
 * ====================================================================== */

typedef apr_uint64_t (*bs_headroom_count_fn)(apr_int64_t now_sec);

/* All four slot types now share the same empty-marker convention
 * (apr_uint32_t used == 0). The flagged-IP count additionally
 * filters by TTL so the gauge tracks "active" rather than
 * "physically occupied" entries — that bias toward late warnings
 * is documented and matches the prior behavior. */
static apr_uint64_t bs_headroom_count_flagged(apr_int64_t now_sec)
{
    if (!bs_shm.flagged_table || !bs_shm.flagged_capacity) return 0;
    apr_uint64_t used = 0;
    for (apr_size_t i = 0; i < bs_shm.flagged_capacity; i++) {
        const bs_flagged_ip_slot *slot = &bs_shm.flagged_table[i];
        apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_RELAXED);
        if ((v & 1U) == 0 &&
            slot->used != 0 &&
            slot->expires_at > now_sec) {
            used++;
        }
    }
    return used;
}

static apr_uint64_t bs_headroom_count_strike(apr_int64_t now_sec)
{
    (void)now_sec;
    if (!bs_shm.strike_table || !bs_shm.strike_capacity) return 0;
    apr_uint64_t used = 0;
    for (apr_size_t i = 0; i < bs_shm.strike_capacity; i++) {
        const bs_strike_slot *slot = &bs_shm.strike_table[i];
        apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_RELAXED);
        if ((v & 1U) == 0 && slot->used != 0) {
            used++;
        }
    }
    return used;
}

static apr_uint64_t bs_headroom_count_safeguard(apr_int64_t now_sec)
{
    (void)now_sec;
    if (!bs_shm.safeguard_table || !bs_shm.safeguard_capacity) return 0;
    apr_uint64_t used = 0;
    for (apr_size_t i = 0; i < bs_shm.safeguard_capacity; i++) {
        const bs_safeguard_slot *slot = &bs_shm.safeguard_table[i];
        apr_uint32_t v = __atomic_load_n(&slot->version, __ATOMIC_RELAXED);
        if ((v & 1U) == 0 && slot->used != 0) {
            used++;
        }
    }
    return used;
}

typedef struct {
    const char            *table_name;
    const char            *directive_name;
    bs_headroom_count_fn   count;
    apr_size_t            *capacity;       /* points into bs_shm */
    apr_int64_t            last_warn;      /* per-table cooldown */
} bs_headroom_table;

/* Single-process state — mod_watchdog runs callbacks in the parent
 * only, so static module-scope storage is sufficient. */
static bs_headroom_table bs_headroom_tables[] = {
    { "flagged-IP", "BotShieldFlaggedIPCapacity",
      bs_headroom_count_flagged, &bs_shm.flagged_capacity, 0 },
    { "strike", "BotShieldRateLimitEscalateCapacity",
      bs_headroom_count_strike, &bs_shm.strike_capacity, 0 },
    { "safeguard",
      "BotShieldSafeguardCapacity / BotShieldEmbeddedNonceCapacity",
      bs_headroom_count_safeguard, &bs_shm.safeguard_capacity, 0 },
};
#define BS_HEADROOM_TABLE_COUNT \
    (sizeof(bs_headroom_tables) / sizeof(bs_headroom_tables[0]))

static apr_int64_t bs_headroom_bloom_last_warn = 0;

static void bs_headroom_check(server_rec *sv,
                              const char *table_name,
                              const char *directive_name,
                              apr_uint64_t used, apr_size_t capacity,
                              apr_int64_t *last_warn,
                              apr_int64_t now_sec)
{
    if (capacity == 0) return;
    int pct = (int)((used * 100) / capacity);
    int level;
    if      (pct >= BS_HEADROOM_WARN_PCT)   level = APLOG_WARNING;
    else if (pct >= BS_HEADROOM_NOTICE_PCT) level = APLOG_NOTICE;
    else { *last_warn = 0; return; }   /* below threshold; reset cooldown */

    if (now_sec - *last_warn < BS_HEADROOM_REWARN_SEC) return;
    *last_warn = now_sec;
    ap_log_error(APLOG_MARK, level, 0, sv,
        "mod_botshield: %s table at %d%% (%" APR_UINT64_T_FMT
        "/%" APR_SIZE_T_FMT "); approaching probe-saturation. "
        "Consider raising %s.",
        table_name, pct, used, capacity, directive_name);
}

apr_status_t bs_headroom_watchdog_cb(int state, void *data, apr_pool_t *pool)
{
    (void)pool;
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    server_rec *sv = data;
    if (!sv) return APR_SUCCESS;

    apr_int64_t now_sec = (apr_int64_t)apr_time_sec(apr_time_now());

    /* Walk the open-addressed reputation tables via the unified
     * dispatch table. Each entry's count() does the per-table
     * empty-marker interpretation (flags == 0, rule_slot == EMPTY,
     * used == 0); the rest of the heavy lifting is shared. */
    for (size_t i = 0; i < BS_HEADROOM_TABLE_COUNT; i++) {
        bs_headroom_table *t = &bs_headroom_tables[i];
        apr_uint64_t used = t->count(now_sec);
        bs_headroom_check(sv, t->table_name, t->directive_name,
                          used, *t->capacity, &t->last_warn, now_sec);
    }

    /* Bloom — bit-fill against the ln(2) rated-FP design point.
     * Both buffers OR'd at lookup, so the higher-fill buffer governs
     * the effective FP. Compare the peak fill across the two. */
    if (bs_shm.bloom_bufs[0] && bs_shm.bloom_buf_bytes) {
        apr_uint64_t total_bits = (apr_uint64_t)bs_shm.bloom_buf_bytes * 8;
        if (total_bits > 0) {
            apr_uint64_t bits_a = bs_popcount_buffer(
                bs_shm.bloom_bufs[0], bs_shm.bloom_buf_bytes);
            apr_uint64_t bits_b = bs_popcount_buffer(
                bs_shm.bloom_bufs[1], bs_shm.bloom_buf_bytes);
            apr_uint64_t peak = (bits_a > bits_b) ? bits_a : bits_b;
            int pct = (int)((peak * 100) / total_bits);
            int level;
            if      (pct >= BS_HEADROOM_WARN_PCT)   level = APLOG_WARNING;
            else if (pct >= BS_HEADROOM_NOTICE_PCT) level = APLOG_NOTICE;
            else { bs_headroom_bloom_last_warn = 0; return APR_SUCCESS; }
            if (now_sec - bs_headroom_bloom_last_warn
                >= BS_HEADROOM_REWARN_SEC) {
                bs_headroom_bloom_last_warn = now_sec;
                ap_log_error(APLOG_MARK, level, 0, sv,
                    "mod_botshield: Bloom filter peak buffer at %d%% "
                    "fill (%" APR_UINT64_T_FMT "/%" APR_UINT64_T_FMT
                    " bits); false-positive rate climbing past design "
                    "point. Consider raising BotShieldBloomIPs or "
                    "shortening BotShieldBloomWindow.",
                    pct, peak, total_bits);
            }
        }
    }

    return APR_SUCCESS;
}

/* mod_watchdog periodic-save callback. Runs in the parent/watchdog
 * process context with a short-lived pool. AP_WATCHDOG_STATE_RUNNING
 * fires at the configured interval. STARTING/STOPPING we ignore; the
 * graceful-shutdown save still happens via pool cleanup. */
apr_status_t bs_state_save_watchdog_cb(int state, void *data,
                                 apr_pool_t *pool)
{
    if (state != AP_WATCHDOG_STATE_RUNNING) return APR_SUCCESS;
    bs_state_cleanup_ctx *ctx = data;
    if (!ctx || !ctx->path) return APR_SUCCESS;
    if (!ctx->shm_rt.shm || !ctx->shm_rt.flagged_table ||
        !ctx->shm_rt.bloom_bufs[0]) {
        return APR_SUCCESS;   /* SHM not up yet; nothing to save */
    }
    /* Use the callback's own pool so temporaries die with this tick. */
    bs_state_save(pool, ctx->server, ctx->path, &ctx->shm_rt);
    return APR_SUCCESS;
}
