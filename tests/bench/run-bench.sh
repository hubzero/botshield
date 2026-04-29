#!/bin/bash
# tests/bench/run-bench.sh — comparative latency / throughput sweep
# across mod_botshield configurations.
#
# For each scenario in tests/bench/scenarios/:
#   1. Install the scenario as the active vhost on port 8080.
#   2. apachectl configtest && systemctl reload apache2.
#   3. 5 s wrk warmup (discarded).
#   4. 30 s wrk measure (-t4 -c100 --latency); raw output saved.
#
# After all scenarios run, prints a comparison table (RPS, p50, p99,
# p99.9, max) with delta % vs the baseline scenario.
#
# All scenarios hit a tiny static file
# (/var/www/botshield-bench/bench.html, ~140 bytes). The static
# handler is the cheapest content path Apache offers — any
# delta between scenarios is per-request mod_botshield cost.
#
# Usage:
#   tests/bench/run-bench.sh [--quick]    # --quick = 5s measure
#
# Output: tests/bench/results/<timestamp>/
#
# Requires: wrk, sudo (for apachectl reload + file install).

set -u

BENCH_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$BENCH_DIR/../.." && pwd)
SCENARIO_DIR=$BENCH_DIR/scenarios
TS=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR=$BENCH_DIR/results/$TS
ACTIVE_CONF=/etc/apache2/sites-available/botshield-bench.conf
DOCROOT=/var/www/botshield-bench
ROBOTS_PATH=/etc/botshield/bench-robots.txt

WARMUP_SEC=5
MEASURE_SEC=30
THREADS=4
CONNECTIONS=100
URL=http://127.0.0.1:8080/bench.html

# Realistic-browser headers attached to every wrk request. wrk's
# default request has neither User-Agent nor Accept-Language, which
# the built-in heuristics score as +40 (missing-UA) +15 (missing-AL)
# = 55, well above the silent threshold of 20. Without these headers
# every BotShield-enabled request gets challenged and the benchmark
# measures interstitial-issue throughput instead of pass-through.
WRK_HEADERS=(
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0"
    -H "Accept-Language: en-US,en;q=0.9"
)

if [[ "${1:-}" == "--quick" ]]; then
    MEASURE_SEC=5
fi

mkdir -p "$RESULTS_DIR"

# --- prerequisites ----------------------------------------------------

require() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 1; }; }
require wrk
require sudo
require apachectl

# --- one-time setup ---------------------------------------------------

echo "[setup] installing docroot at $DOCROOT"
sudo mkdir -p "$DOCROOT"
sudo cp "$BENCH_DIR/bench.html" "$DOCROOT/bench.html"
sudo chmod 644 "$DOCROOT/bench.html"

echo "[setup] installing robots fixture at $ROBOTS_PATH"
sudo install -m 644 -D "$BENCH_DIR/bench-robots.txt" "$ROBOTS_PATH"

# Ensure /etc/botshield/secret exists (some scenarios require it).
if [[ ! -f /etc/botshield/secret ]]; then
    echo "[setup] generating /etc/botshield/secret"
    sudo install -d -m 755 /etc/botshield
    sudo install -m 600 /dev/null /etc/botshield/secret
    sudo openssl rand -hex 32 | sudo tee /etc/botshield/secret >/dev/null
fi

# Enable the bench vhost (a fresh symlink in sites-enabled).
ENABLED_LINK=/etc/apache2/sites-enabled/botshield-bench.conf
if [[ ! -L "$ENABLED_LINK" ]]; then
    sudo ln -sf "$ACTIVE_CONF" "$ENABLED_LINK"
fi

# Save the dev vhost so we can put it back at the end.
DEV_VHOST=/etc/apache2/sites-available/botshield-dev.conf
DEV_BACKUP=$RESULTS_DIR/.dev-vhost-backup.conf
if [[ -f "$DEV_VHOST" ]]; then
    sudo cp "$DEV_VHOST" "$DEV_BACKUP"
fi

# --- run scenarios ----------------------------------------------------

declare -a SCENARIOS
mapfile -t SCENARIOS < <(ls "$SCENARIO_DIR"/*.conf | sort)

echo
echo "[bench] $TS"
echo "[bench] threads=$THREADS connections=$CONNECTIONS warmup=${WARMUP_SEC}s measure=${MEASURE_SEC}s"
echo "[bench] target=$URL"
echo

for scenario_path in "${SCENARIOS[@]}"; do
    scenario=$(basename "$scenario_path" .conf)
    echo "----- $scenario -----"

    sudo cp "$scenario_path" "$ACTIVE_CONF"
    if ! sudo apachectl configtest 2>&1 | grep -q "Syntax OK"; then
        echo "  configtest failed — skipping" >&2
        sudo apachectl configtest 2>&1 | sed 's/^/    /' >&2
        continue
    fi
    sudo systemctl reload apache2 || { echo "  reload failed" >&2; continue; }

    # Active readiness poll. After reload, Apache may take a moment
    # to drain old workers and fully reload the new config. Poll
    # the endpoint up to ~10 s for a clean 200; bail if we never
    # get one (the wrk run would otherwise mix old + new requests
    # or hit socket-reset storms during the transition).
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
    # Settle aggressively so the kernel's accept queue and Apache's
    # worker pool are fully steady-state. Reload-time worker draining
    # can otherwise leak into the wrk run as connection RSTs and
    # corrupt the per-thread elapsed-time accounting (manifests as
    # `Requests/sec: 0.00` with an absurd `requests in <huge>m`
    # number).
    sleep 3

    # Per-scenario overrides. Each scenario .conf may carry header
    # comments like:
    #   # WRK_FLAGS: -t 1 -c 1     (replaces the default -t/-c)
    #   # WRK_LUA: cookie          (use wrk-cookie.lua + mint a cookie first)
    # The default is -t$THREADS -c$CONNECTIONS with no Lua script.
    flags=$(grep -m1 -oE '^# *WRK_FLAGS:.*' "$scenario_path" \
            | sed -E 's/^# *WRK_FLAGS:[[:space:]]*//' || true)
    lua_tag=$(grep -m1 -oE '^# *WRK_LUA:.*' "$scenario_path" \
              | sed -E 's/^# *WRK_LUA:[[:space:]]*//' || true)
    if [[ -z "$flags" ]]; then
        flags="-t$THREADS -c$CONNECTIONS"
    fi
    lua_args=()
    if [[ -n "$lua_tag" ]]; then
        case "$lua_tag" in
            cookie)
                cookie=$(python3 "$BENCH_DIR/scripts/mint_cookie.py")
                if [[ -z "$cookie" ]]; then
                    echo "  cookie mint failed — skipping" >&2
                    continue
                fi
                export BENCH_COOKIE="$cookie"
                lua_args=(-s "$BENCH_DIR/wrk-cookie.lua")
                echo "  minted cookie (${#cookie} chars)"
                ;;
            *)
                echo "  unknown WRK_LUA tag '$lua_tag' — skipping Lua hook" >&2
                ;;
        esac
    fi

    # Warmup (always at low concurrency — we're shaking out connection setup,
    # not stressing the server). Cookie hook applies during warmup too so
    # the SHM cookie-cache state is consistent.
    wrk -t2 -c20 -d${WARMUP_SEC}s --latency \
        "${WRK_HEADERS[@]}" "${lua_args[@]}" "$URL" \
        >/dev/null 2>&1 || true

    # Measure.
    # shellcheck disable=SC2086  # word-split flags intentional
    wrk $flags -d${MEASURE_SEC}s --latency \
        "${WRK_HEADERS[@]}" "${lua_args[@]}" "$URL" \
        > "$RESULTS_DIR/$scenario.txt"

    # Verify the response was the static file, not an interstitial.
    # The "Bytes/req" sanity check catches the case where heuristics
    # or a misconfigured scenario challenged every request — the
    # interstitial HTML is ~10 KB while bench.html is ~140 bytes.
    bytes_per_req=$(awk '
        /requests in/ {
            req=$1
            gsub(/[^0-9.]/, "", $5); bytes_n=$5
            unit=$5; gsub(/[0-9.]/, "", unit)
            if (unit ~ /GB/) bytes_n *= 1024 * 1024 * 1024
            else if (unit ~ /MB/) bytes_n *= 1024 * 1024
            else if (unit ~ /KB/) bytes_n *= 1024
            if (req > 0) printf "%d\n", bytes_n / req
        }
    ' "$RESULTS_DIR/$scenario.txt")
    if [[ -n "$bytes_per_req" ]] && (( bytes_per_req > 1500 )); then
        echo "  ⚠ ${bytes_per_req}B/req — looks like requests were" \
             "challenged (interstitial response). Check headers / config." >&2
    fi

    unset BENCH_COOKIE

    # Quick visual.
    grep -E "Requests/sec|Latency " "$RESULTS_DIR/$scenario.txt" \
        | sed 's/^/  /'
    echo
done

# --- summary table ----------------------------------------------------

python3 - <<PYEOF
import os, re, sys

results_dir = "$RESULTS_DIR"

def parse(path):
    """Pull the headline numbers out of a wrk text report.

    wrk's plain-text format isn't a stable contract; this parser
    looks for the canonical lines and tolerates absent fields by
    leaving them None.

    Flags runs with >1% socket errors as suspect — the run probably
    overlapped a config reload or the kernel hit a per-tcp-conn
    cap, and the latency / RPS numbers should not be trusted."""
    data = {"file": os.path.basename(path), "suspect": False}
    with open(path) as f:
        text = f.read()

    m = re.search(r"Requests/sec:\s+([\d.]+)", text)
    rps = float(m.group(1)) if m else None
    # wrk's `Requests/sec` line is computed as
    # total_requests / elapsed_seconds, but if its monotonic-clock
    # reading wraps (rare; reproducible at -c1 when the connection
    # blocks briefly during Apache's reload), elapsed becomes
    # absurdly large and the headline RPS is 0.00 even though the
    # per-thread Req/Sec line and the latency distribution are
    # fine. Fall back to per-thread Req/Sec * thread count when
    # this happens.
    if rps is not None and rps == 0.0:
        rps = None
        m_per_thread = re.search(
            r"^\s*Req/Sec\s+([\d.]+)([kKmM]?)\b", text, re.MULTILINE)
        m_threads = re.search(r"(\d+)\s+threads?\s+and\s+\d+\s+connections?",
                              text)
        if m_per_thread and m_threads:
            base = float(m_per_thread.group(1))
            unit = m_per_thread.group(2).lower()
            if unit == "k":   base *= 1000
            elif unit == "m": base *= 1_000_000
            rps = base * int(m_threads.group(1))
            data["rps_recovered"] = True
        else:
            data["suspect"] = True
    data["rps"] = rps

    # connect / write / timeout errors above ~1% are real
    # disruption (config reload mid-run, kernel back-pressure).
    # `read` errors on loopback at -c100 are normal — Apache
    # closes keepalive connections after MaxKeepAliveRequests
    # and wrk's read of the closing FIN counts as a "read" error.
    # Don't flag those.
    m = re.search(r"Socket errors:.*?connect (\d+),\s*read (\d+),"
                  r"\s*write (\d+),\s*timeout (\d+)", text)
    if m:
        connect_e = int(m.group(1))
        write_e   = int(m.group(3))
        timeout_e = int(m.group(4))
        non_read_errs = connect_e + write_e + timeout_e
        m2 = re.search(r"(\d+) requests in", text)
        total = int(m2.group(1)) if m2 else 0
        if total and non_read_errs > total * 0.01:
            data["suspect"] = True
            data["err_total"] = non_read_errs
            data["req_total"] = total

    m = re.search(r"Latency\s+([\d.]+)(\w+)\s+([\d.]+)(\w+)\s+([\d.]+)(\w+)", text)
    if m:
        data["lat_avg_us"] = _to_us(m.group(1), m.group(2))
        data["lat_stdev_us"] = _to_us(m.group(3), m.group(4))
        data["lat_max_us"] = _to_us(m.group(5), m.group(6))

    # Latency Distribution block: 50% / 75% / 90% / 99%
    pcts = {}
    in_block = False
    for line in text.splitlines():
        if "Latency Distribution" in line:
            in_block = True
            continue
        if in_block:
            m = re.match(r"\s+(\d+)%\s+([\d.]+)(\w+)", line)
            if m:
                pcts[int(m.group(1))] = _to_us(m.group(2), m.group(3))
            elif line.strip() == "":
                in_block = False
    data["p50_us"] = pcts.get(50)
    data["p99_us"] = pcts.get(99)
    return data

def _to_us(n, unit):
    n = float(n)
    return {
        "us": n,
        "ms": n * 1000,
        "s":  n * 1_000_000,
        "m":  n * 60 * 1_000_000,
    }.get(unit, n)

def fmt_us(v):
    if v is None: return "?"
    if v < 1000: return f"{v:.0f}us"
    if v < 1_000_000: return f"{v/1000:.2f}ms"
    return f"{v/1_000_000:.2f}s"

def fmt_rps(v):
    if v is None: return "?"
    if v >= 1000: return f"{v/1000:.1f}k"
    return f"{v:.0f}"

paths = sorted(p for p in (os.path.join(results_dir, f)
                           for f in os.listdir(results_dir))
               if p.endswith(".txt"))
rows = [parse(p) for p in paths]
if not rows:
    sys.exit(0)

baseline = rows[0]
base_rps = baseline.get("rps") or 0
base_p50 = baseline.get("p50_us") or 0
base_p99 = baseline.get("p99_us") or 0

print()
print("Summary")
print("=======")
print()
header = f"{'scenario':<32} {'RPS':>10} {'rps Δ':>8} {'p50':>10} {'p50 Δ':>8} {'p99':>10} {'p99 Δ':>8}"
print(header)
print("-" * len(header))
for r in rows:
    name = r["file"].replace(".txt", "")
    rps  = r.get("rps")
    p50  = r.get("p50_us")
    p99  = r.get("p99_us")
    rps_d = f"{((rps - base_rps)/base_rps*100):+.1f}%" if rps and base_rps else "—"
    p50_d = f"{((p50 - base_p50)/base_p50*100):+.1f}%" if p50 and base_p50 else "—"
    p99_d = f"{((p99 - base_p99)/base_p99*100):+.1f}%" if p99 and base_p99 else "—"
    flag = ""
    if r.get("suspect"):  flag = " *"
    elif r.get("rps_recovered"): flag = " ~"
    print(f"{name:<32}{flag:<2} {fmt_rps(rps):>10} {rps_d:>8} "
          f"{fmt_us(p50):>10} {p50_d:>8} {fmt_us(p99):>10} {p99_d:>8}")
print()
print(f"Δ columns are vs the first scenario ({rows[0]['file'].replace('.txt','')}).")
if any(r.get("suspect") for r in rows):
    print("(*) suspect run — wrk reported high non-read socket errors "
          "or a broken RPS measurement. Re-run that scenario in isolation.")
if any(r.get("rps_recovered") for r in rows):
    print("(~) wrk's headline Requests/sec was 0.00 (timer wraparound); "
          "RPS recovered from per-thread Req/Sec × thread count. "
          "Latency distribution still authoritative.")
print(f"Raw wrk output: {results_dir}")
PYEOF

# --- restore dev vhost ------------------------------------------------

if [[ -f "$DEV_BACKUP" ]]; then
    echo
    echo "[teardown] restoring dev vhost"
    sudo cp "$DEV_BACKUP" "$DEV_VHOST"
fi
sudo rm -f "$ENABLED_LINK"
sudo apachectl configtest >/dev/null && sudo systemctl reload apache2

echo "[bench] done. results: $RESULTS_DIR"
