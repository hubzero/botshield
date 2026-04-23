#!/bin/bash
# tests/stress/soak.sh — long-duration soak test (M10.4).
#
# Launches a steady rate-limited load against the module for hours,
# periodically samples /metrics + worker RSS + log file size, writes
# each sample to a timestamped report file. Designed to be started
# before going home ("nohup tests/stress/soak.sh --duration 8h &")
# and analyzed in the morning.
#
# Workload is internal-only (pass / form / captcha-render) — does NOT
# hit any third-party provider. Mix is 70/20/10 pass/form/captcha.
#
# Rate limiting is REAL (python-driven, 1/RPS interval between sends)
# so log growth is predictable and bounded across overnight runs.
#
# Usage:
#   tests/stress/soak.sh [--duration DURATION] [--rps N] [--report PATH]
#     --duration  2m | 30m | 8h | 12h etc. Converted to seconds.
#     --rps       exact target rps. Default 50. Load is moderate —
#                 the goal is to exercise all hot paths for hours,
#                 not stress throughput.
#     --report    report file path. Default /tmp/bs_soak_<ts>.report.
#
# Exit code:
#   0 — soak completed, analyzer says pass
#   1 — soak aborted or analyzer found a problem
#
# Monitor while running:
#   tail -f $REPORT
#   sudo tail -f /var/log/apache2/botshield-dev-error.log | grep 'decision'

set -u

DURATION="8h"
RPS=50
REPORT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --rps)      RPS="$2";      shift 2 ;;
    --report)   REPORT="$2";   shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# Convert duration string (2m / 30m / 8h / N) to seconds
case "$DURATION" in
  *s)  duration_sec=${DURATION%s}          ;;
  *m)  duration_sec=$(( ${DURATION%m} * 60 )) ;;
  *h)  duration_sec=$(( ${DURATION%h} * 3600 )) ;;
  *)   duration_sec=$DURATION              ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/../lib/common.sh"

ts=$(date +%Y%m%d_%H%M%S)
[[ -z "$REPORT" ]] && REPORT="/tmp/bs_soak_${ts}.report"
LOAD_OUT="/tmp/bs_soak_${ts}_load.out"

echo "Soak starting:"
echo "  duration : $DURATION ($duration_sec s)"
echo "  target   : ${RPS} rps (rate-limited, python-driven)"
echo "  report   : $REPORT"
echo "  load log : $LOAD_OUT"
echo ""

# -------- Baseline snapshot --------
start_unix=$(date +%s)
start_log_size=$(sudo stat -c %s "$ERROR_LOG" 2>/dev/null || echo 0)
start_rss=$(ps -C apache2 -o rss= | awk '{s+=$1} END {print s+0}')

echo "# soak_run timestamp=$ts duration=$DURATION rps=$RPS" > "$REPORT"
echo "# start_unix=$start_unix start_rss_kb=$start_rss start_log_bytes=$start_log_size" >> "$REPORT"

# -------- Launch the load --------
"$HERE/soak_load.py" "$RPS" "$duration_sec" "$BASE" \
  > "$LOAD_OUT" 2>&1 &
LOAD_PID=$!

# -------- Periodic sampling loop --------
sample() {
  local t_unix rss log_size metrics
  t_unix=$(date +%s)
  rss=$(ps -C apache2 -o rss= | awk '{s+=$1} END {print s+0}')
  log_size=$(sudo stat -c %s "$ERROR_LOG" 2>/dev/null || echo 0)
  metrics=$(bs_curl "$BASE/botshield/metrics" | \
            grep -E "^botshield_(tier|outcome|state_saves|state_loads|captcha_inflight|shm_flagged_used|bloom_bits)" | \
            tr '\n' ';')
  echo "t=$t_unix rss_kb=$rss log_bytes=$log_size metrics=\"$metrics\"" \
    >> "$REPORT"
}

# Sample once at start so first-vs-last comparison is clean.
sample

# Sampling interval: scaled to duration. Short runs sample often for
# smoke testing; overnight runs sample every 30 minutes.
if   [[ "$duration_sec" -le 300 ]];   then interval=15    # <=5m: every 15s
elif [[ "$duration_sec" -le 3600 ]];  then interval=300   # <=1h: every 5m
else interval=1800                                        # >1h: every 30m
fi

while kill -0 "$LOAD_PID" 2>/dev/null; do
  sleep "$interval"
  kill -0 "$LOAD_PID" 2>/dev/null && sample
done

# Wait and record final sample
wait "$LOAD_PID"
load_rc=$?
sample

{
  echo ""
  echo "# --- load summary ---"
  cat "$LOAD_OUT" | sed 's/^/# /'
} >> "$REPORT"

echo ""
echo "Soak complete. Report: $REPORT"
echo "load exit code: $load_rc"

# -------- Analyze --------
echo ""
echo "Running analyzer..."
"$HERE/soak-analyze.sh" "$REPORT"
exit $?
