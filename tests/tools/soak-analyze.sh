#!/bin/bash
# tests/stress/soak-analyze.sh — post-mortem check on a soak report.
#
# Reads a report file produced by soak.sh and asserts:
#   - counters in the sample series are monotonically non-decreasing
#     (any decrease means SHM reset mid-run — crash, graceful, etc.)
#   - worker RSS growth bounded (default: final - initial < 200 MB)
#   - log file growth reasonable (default: < 200 MB over the run)
#   - no 'metrics: unknown' WARNINGs in the apache error log since
#     the soak started
#   - no module crash signatures in journalctl since the soak started
#
# Usage: soak-analyze.sh <report-file>
# Exit code: 0 if clean, 1 if any check failed.

set -u

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <report-file>" >&2
  exit 2
fi
REPORT="$1"
if [[ ! -s "$REPORT" ]]; then
  echo "report file missing or empty: $REPORT" >&2
  exit 2
fi

# Config knobs — tune if real leaks hide below these thresholds.
#   RSS: pool-based growth plateaus; more than 200 MB of sustained
#        growth indicates a real leak, not normal worker ramp-up.
#   Log: scaled to soak wall-clock. At 50 rps with decision+prose
#        lines at ~300-500 B each, 100 MB/hr is well above legitimate
#        logging rate while still catching a runaway log spam bug.
MAX_RSS_GROWTH_KB=$((200 * 1024))
MAX_LOG_GROWTH_PER_HOUR_MB=${MAX_LOG_GROWTH_PER_HOUR_MB:-100}
CRITICAL_COUNTERS="botshield_tier_pass_total \
botshield_tier_form_total \
botshield_tier_captcha_total \
botshield_outcome_declined_total \
botshield_outcome_challenged_total"

fail=0

echo "=== soak report: $REPORT ==="

# Pull the start_unix / start_rss / start_log from the header.
start_unix=$(grep -oE "start_unix=[0-9]+"   "$REPORT" | head -1 | cut -d= -f2)
start_rss=$(grep -oE "start_rss_kb=[0-9]+"  "$REPORT" | head -1 | cut -d= -f2)
start_log=$(grep -oE "start_log_bytes=[0-9]+" "$REPORT" | head -1 | cut -d= -f2)

# Count samples (t= lines). Minimum is 4: even the 60s smoke samples
# every 15s (4 points); an 8h overnight samples every 30min (~18
# points). Fewer than 4 means the sampling loop aborted early
# (broken driver, missing env, etc.) — treat as an unreliable
# report, not a pass. This closes the false-green surfaced when
# M11.5 archived common.sh and the old soak.sh died instantly but
# its analyzer still printed "soak: PASS" on the stub output.
nsamples=$(grep -c '^t=' "$REPORT")
echo "  samples collected: $nsamples"
if [[ "$nsamples" -lt 4 ]]; then
  echo "  FAIL: need at least 4 samples to analyze (got $nsamples)"
  echo "        — this usually means the soak driver died early;"
  echo "          check /tmp/bs_soak_*_load.out for errors"
  exit 1
fi

# RSS growth: last sample's rss_kb vs start_rss_kb
last_rss=$(grep '^t=' "$REPORT" | tail -1 | \
           grep -oE "rss_kb=[0-9]+" | cut -d= -f2)
rss_delta=$(( last_rss - start_rss ))
echo "  RSS: start=${start_rss} kB, final=${last_rss} kB, delta=${rss_delta} kB"
if [[ "$rss_delta" -gt "$MAX_RSS_GROWTH_KB" ]]; then
  echo "  FAIL: RSS grew by ${rss_delta} kB > ${MAX_RSS_GROWTH_KB} kB threshold"
  fail=1
else
  echo "  OK:  RSS growth within bound"
fi

# Log file growth, scaled to wall-clock duration.
last_t=$(grep '^t=' "$REPORT" | tail -1 | \
         grep -oE "^t=[0-9]+" | cut -d= -f2)
duration_sec=$(( last_t - start_unix ))
[[ "$duration_sec" -le 0 ]] && duration_sec=60   # minimum for smoke runs
last_log=$(grep '^t=' "$REPORT" | tail -1 | \
           grep -oE "log_bytes=[0-9]+" | cut -d= -f2)
log_delta=$(( last_log - start_log ))
# Threshold = MB-per-hour * hours; minimum 50 MB floor for short runs.
hours=$(awk "BEGIN {printf \"%.3f\", $duration_sec / 3600}")
threshold_mb=$(awk "BEGIN {printf \"%d\", $MAX_LOG_GROWTH_PER_HOUR_MB * $hours}")
[[ "$threshold_mb" -lt 50 ]] && threshold_mb=50
threshold_bytes=$(( threshold_mb * 1024 * 1024 ))
echo "  log: start=${start_log} B, final=${last_log} B, delta=${log_delta} B"
echo "       duration=${duration_sec}s, threshold=${threshold_mb} MB (${MAX_LOG_GROWTH_PER_HOUR_MB} MB/hour × ${hours}h)"
if [[ "$log_delta" -gt "$threshold_bytes" ]]; then
  echo "  FAIL: log grew by ${log_delta} B > ${threshold_bytes} B threshold"
  fail=1
else
  echo "  OK:  log growth within bound"
fi

# Counter monotonicity: for each critical counter, extract the
# value at each sample and assert it never decreases.
echo "  counter monotonicity:"
for metric in $CRITICAL_COUNTERS; do
  # Extract the sequence of values across all samples.
  # The metrics field is semicolon-joined in the report; pull out
  # this specific metric's value at each sample.
  vals=$(grep '^t=' "$REPORT" | \
         awk -v m="$metric " '
           BEGIN {FS="metrics=\""}
           NF>1 {
             # Split the metrics payload on ; and find the one matching.
             n = split($2, arr, ";")
             for (i=1; i<=n; i++) {
               if (arr[i] ~ ("^" m)) {
                 split(arr[i], kv, " ")
                 print kv[2]
                 break
               }
             }
           }')
  # Walk, detect any decrease. Also guard against two degenerate
  # cases that previously snuck past as "OK":
  #   (a) the series is empty (metric never appeared) — prev would
  #       stay -1 and we'd report "final=-1", which looked fine.
  #   (b) some sample parsed as a negative number (scrape error).
  nvals=0
  prev=-1
  decreases=0
  negatives=0
  for v in $vals; do
    [[ -z "$v" ]] && continue
    nvals=$((nvals + 1))
    if [[ "$v" -lt 0 ]]; then
      negatives=$((negatives + 1))
    fi
    if [[ "$prev" -gt -1 && "$v" -lt "$prev" ]]; then
      decreases=$((decreases + 1))
    fi
    prev=$v
  done
  final=${prev:-0}
  if [[ "$nvals" -eq 0 ]]; then
    echo "    FAIL: $metric — no values in any sample (scrape failed?)"
    fail=1
  elif [[ "$negatives" -gt 0 ]]; then
    echo "    FAIL: $metric — $negatives negative value(s) in series"
    fail=1
  elif [[ "$decreases" -gt 0 ]]; then
    echo "    FAIL: $metric decreased $decreases time(s) (SHM reset? crash?)"
    fail=1
  else
    echo "    OK:   $metric monotonic, final=$final"
  fi
done

# 'metrics: unknown' WARNING check (M9.2 vocabulary-drift guard)
since=$(date -d "@$start_unix" '+%Y-%m-%d %H:%M:%S')
echo "  metrics-drift warnings since soak start ($since):"
drift=$(sudo grep -c "metrics: unknown" /var/log/apache2/error.log || true)
# Crude: count the whole log. Could narrow by date but the log
# likely has far fewer lines than the soak window's sample count.
# If any are present, that's a red flag.
if [[ "$drift" -gt 0 ]]; then
  echo "    FAIL: $drift 'metrics: unknown' line(s) in error log"
  sudo grep "metrics: unknown" /var/log/apache2/error.log | tail -3
  fail=1
else
  echo "    OK:   no metrics-drift warnings"
fi

# Crash signatures in journalctl since the soak started
since_iso=$(date -d "@$start_unix" --iso-8601=seconds)
crashes=$(sudo journalctl -u apache2 --since "$since_iso" --no-pager 2>/dev/null | \
          grep -cE "SIGSEGV|core dumped|segfault|AddressSanitizer" || true)
echo "  crash signatures since soak start:"
if [[ "$crashes" -gt 0 ]]; then
  echo "    FAIL: $crashes crash signature line(s) in journalctl"
  sudo journalctl -u apache2 --since "$since_iso" --no-pager 2>/dev/null | \
    grep -E "SIGSEGV|core dumped|segfault|AddressSanitizer" | head -3
  fail=1
else
  echo "    OK:   no crash signatures"
fi

echo ""
if [[ "$fail" == "0" ]]; then
  echo "soak: PASS"
  exit 0
else
  echo "soak: FAIL"
  exit 1
fi
