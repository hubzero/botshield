#!/bin/bash
# tests/bench/run-rate-bench.sh — fixed-rate (non-saturating)
# benchmark sweep, complementary to run-bench.sh.
#
# run-bench.sh saturates Apache at -c 100 and reports throughput
# losses. That answers "what's the capacity ceiling?" but
# produces scary RPS deltas because the static-file workload is
# the cheapest possible per-request denominator.
#
# This script answers "at a realistic production load, how much
# latency does BotShield add?" by issuing a fixed RPS through
# vegeta (which corrects for coordinated omission) for each
# scenario. The scenarios are deliberately run well below the
# saturation point measured by run-bench.sh; if the chosen rate
# is achievable in the baseline, any latency growth in the
# BotShield-on scenarios is real per-request work, not contention
# noise.
#
# Vegeta's coordinated-omission-corrected latency distribution
# (p50 / p95 / p99 / p99.9) is the canonical surface. The script
# also surfaces success rate; below 99.9% means the rate is too
# high for that scenario and the latencies are unreliable.
#
# Usage:
#   tests/bench/run-rate-bench.sh                       # rates 100, 250
#   tests/bench/run-rate-bench.sh --rate 250            # single rate
#   tests/bench/run-rate-bench.sh --rate 100,250,500    # multiple rates
#   tests/bench/run-rate-bench.sh --duration 60         # longer run
#   tests/bench/run-rate-bench.sh --rate 1000 --max-workers 1000
#                                                       # production-class
#                                                       # box: raise both
#
# Output: tests/bench/results/<timestamp>-rate-<r>/<scenario>.json
#         + a stdout summary table per rate.
#
# Dev-box ceiling: a stock Apache event-MPM (150 workers) can't
# sustain target rates above ~400/s in vegeta's open-loop mode.
# The summary flags scenarios where vegeta's achieved rate fell
# below 95% of target, since their reported latencies include
# worker-queue wait. For higher rates, tune mpm_event and bump
# --max-workers in tandem.

set -u

BENCH_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$BENCH_DIR/../.." && pwd)
SCENARIO_DIR=$BENCH_DIR/scenarios
TS=$(date +%Y%m%d-%H%M%S)
RESULTS_ROOT=$BENCH_DIR/results
ACTIVE_CONF=/etc/apache2/sites-available/botshield-bench.conf
DOCROOT=/var/www/botshield-bench
ROBOTS_PATH=/etc/botshield/bench-robots.txt

DURATION=30
# Default rates picked for what a stock Apache event-MPM (150
# workers) on a dev box can sustain in vegeta's open-loop mode
# without TIME_WAIT exhaustion or worker-pool starvation. On a
# WSL2 dev box, target rates above ~400 are throttled by the
# MAX_WORKERS cap below — vegeta reports them as 100% success
# but the achieved-rate field shows the truth. Higher target
# rates (1k+) require tuned MPM (MaxRequestWorkers≥1024) and
# a wider ephemeral-port range; pass --rate explicitly there
# and bump --max-workers in tandem.
RATES_STR="100,250"
URL=http://127.0.0.1:8080/bench.html
# Cap vegeta's worker goroutines so a stalled scenario can't
# spawn enough OS threads to crash the Go runtime (errno=11
# from clone(); seen at unbounded -max-workers when Apache
# falls behind).
MAX_WORKERS=200

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rate)        RATES_STR=$2; shift 2;;
        --duration)    DURATION=$2; shift 2;;
        --url)         URL=$2; shift 2;;
        --max-workers) MAX_WORKERS=$2; shift 2;;
        -h|--help)
            sed -n '/^# Usage/,/^# Output/p' "$0" | sed 's/^# \?//'
            exit 0;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

IFS=',' read -ra RATES <<< "$RATES_STR"

# --- prerequisites ----------------------------------------------------

require() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
require vegeta
require sudo
require apachectl
require jq

# --- one-time setup (mirror run-bench.sh) -----------------------------

echo "[setup] installing docroot at $DOCROOT"
sudo mkdir -p "$DOCROOT"
sudo cp "$BENCH_DIR/bench.html" "$DOCROOT/bench.html"
sudo chmod 644 "$DOCROOT/bench.html"
sudo install -m 644 -D "$BENCH_DIR/bench-robots.txt" "$ROBOTS_PATH"

if [[ ! -f /etc/botshield/secret ]]; then
    sudo install -d -m 755 /etc/botshield
    sudo install -m 600 /dev/null /etc/botshield/secret
    sudo openssl rand -hex 32 | sudo tee /etc/botshield/secret >/dev/null
fi

ENABLED_LINK=/etc/apache2/sites-enabled/botshield-bench.conf
if [[ ! -L "$ENABLED_LINK" ]]; then
    sudo ln -sf "$ACTIVE_CONF" "$ENABLED_LINK"
fi

DEV_VHOST=/etc/apache2/sites-available/botshield-dev.conf
DEV_BACKUP=$RESULTS_ROOT/.dev-vhost-backup-$TS.conf
if [[ -f "$DEV_VHOST" ]]; then
    mkdir -p "$RESULTS_ROOT"
    sudo cp "$DEV_VHOST" "$DEV_BACKUP"
fi

# --- scenarios --------------------------------------------------------

# Pull the scenario list (skip 10 + 11 — those are -t1/-c1 isolation
# scenarios; the singleconn shape is already covered by run-bench.sh
# and doesn't fit the fixed-rate model).
declare -a SCENARIOS
mapfile -t SCENARIOS < <(ls "$SCENARIO_DIR"/*.conf | grep -vE 'singleconn' | sort)

echo
echo "[bench] $TS  fixed-rate mode"
echo "[bench] rates: ${RATES[*]} duration=${DURATION}s target=$URL"
echo

# --- per-rate sweep ---------------------------------------------------

for rate in "${RATES[@]}"; do
    RESULTS=$RESULTS_ROOT/$TS-rate-${rate}
    mkdir -p "$RESULTS"

    echo "==================== rate=${rate}/s ===================="

    for scenario_path in "${SCENARIOS[@]}"; do
        scenario=$(basename "$scenario_path" .conf)
        echo "----- $scenario @ ${rate}/s -----"

        sudo cp "$scenario_path" "$ACTIVE_CONF"
        if ! sudo apachectl configtest 2>&1 | grep -q "Syntax OK"; then
            echo "  configtest failed — skipping" >&2
            continue
        fi
        sudo systemctl reload apache2 || { echo "  reload failed" >&2; continue; }

        # Active readiness — same shape as run-bench.sh.
        ready=0
        for _ in $(seq 1 50); do
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                        --max-time 1 "$URL" 2>/dev/null || echo "000")
            if [[ "$code" == "200" ]]; then ready=1; break; fi
            sleep 0.2
        done
        if [[ "$ready" != "1" ]]; then
            echo "  endpoint never returned 200 after reload — skipping" >&2
            continue
        fi
        sleep 3

        # Per-scenario header overrides — for the cookied scenario,
        # mint a real cookie via the same helper run-bench.sh uses.
        lua_tag=$(grep -m1 -oE '^# *WRK_LUA:.*' "$scenario_path" \
                  | sed -E 's/^# *WRK_LUA:[[:space:]]*//' || true)
        cookie_hdr=()
        if [[ "$lua_tag" == "cookie" ]]; then
            cookie=$(python3 "$BENCH_DIR/scripts/mint_cookie.py")
            if [[ -z "$cookie" ]]; then
                echo "  cookie mint failed — skipping" >&2
                continue
            fi
            cookie_hdr=(-header "Cookie: _bs_verified=${cookie}")
        fi

        # Vegeta: stdin target spec, stdout binary results stream.
        # `attack` writes results to stdout; `report` consumes them.
        echo "GET $URL" | \
            vegeta attack \
                -rate="${rate}/s" \
                -duration="${DURATION}s" \
                -timeout=10s \
                -max-workers="$MAX_WORKERS" \
                -workers=50 \
                -header="User-Agent: Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0" \
                -header="Accept-Language: en-US,en;q=0.9" \
                "${cookie_hdr[@]}" \
            | vegeta report -type=json \
            > "$RESULTS/$scenario.json"

        # Quick visual.
        jq -r '"  hit=" + (.requests|tostring) +
                " ok=" + ((.success * 100) | tostring | .[0:5]) + "%" +
                " p50=" + ((.latencies."50th" / 1000000) | tostring | .[0:6]) + "ms" +
                " p99=" + ((.latencies."99th" / 1000000) | tostring | .[0:6]) + "ms"' \
            "$RESULTS/$scenario.json" 2>/dev/null \
            || echo "  (jq parse failed)"
    done

    # --- per-rate summary -----------------------------------------

    echo
    python3 - "$RESULTS" "$rate" <<'PYEOF'
import json, os, sys

results_dir, rate = sys.argv[1], sys.argv[2]

def fmt_us(ns):
    if ns is None: return "?"
    us = ns / 1000.0
    if us < 1000: return f"{us:.0f}us"
    return f"{us/1000:.2f}ms"

rows = []
for f in sorted(os.listdir(results_dir)):
    if not f.endswith(".json"): continue
    try:
        with open(os.path.join(results_dir, f)) as fh:
            d = json.load(fh)
    except Exception:
        continue
    rows.append({
        "name":  f.replace(".json", ""),
        "ok":    d.get("success", 0) * 100,
        "rps":   d.get("rate", 0),
        "p50":   d.get("latencies", {}).get("50th"),
        "p95":   d.get("latencies", {}).get("95th"),
        "p99":   d.get("latencies", {}).get("99th"),
        "p999":  d.get("latencies", {}).get("99.9th") or d.get("latencies", {}).get("999th"),
    })

target_rate = float(rate)
throttled = [r for r in rows if r["rps"] < target_rate * 0.95]

if not rows:
    sys.exit(0)

# Baseline = the first scenario at this rate (01-baseline if present).
base = next((r for r in rows if "baseline" in r["name"] and "loaded" not in r["name"]), rows[0])
b_p50, b_p99 = base["p50"] or 1, base["p99"] or 1

print(f"Summary @ {rate}/s")
print("=" * (60 + len(rate)))
print()
header = f"{'scenario':<32} {'ok%':>6} {'p50':>10} {'p95':>10} {'p99':>10} {'p99 Δ':>8}"
print(header)
print("-" * len(header))
for r in rows:
    p99d = (((r["p99"] or 0) - b_p99) / b_p99 * 100) if r["p99"] and b_p99 else 0
    print(f"{r['name']:<32} {r['ok']:>5.2f}% "
          f"{fmt_us(r['p50']):>10} {fmt_us(r['p95']):>10} "
          f"{fmt_us(r['p99']):>10} {p99d:>+7.1f}%")
print()
print(f"Δ columns are vs {base['name']}.")
print(f"ok% < 99.9 → rate is too high for this scenario; latencies unreliable.")
if throttled:
    names = ", ".join(t["name"] for t in throttled)
    print(f"WARN: achieved rate < 95% of target ({rate}/s) for: {names}")
    print(f"  vegeta is bound by --max-workers; the latencies above include")
    print(f"  worker-queue wait, not just per-request work. Lower --rate or")
    print(f"  raise --max-workers to recover a clean signal.")
print(f"Raw vegeta JSON: {results_dir}")
print()
PYEOF
done

# --- restore dev vhost ------------------------------------------------

if [[ -f "$DEV_BACKUP" ]]; then
    echo "[teardown] restoring dev vhost"
    sudo cp "$DEV_BACKUP" "$DEV_VHOST"
fi
sudo rm -f "$ENABLED_LINK"
sudo apachectl configtest >/dev/null && sudo systemctl reload apache2

echo "[bench] done."
