#!/bin/bash
# tests/fuzz/run.sh — launcher for the LibFuzzer harness.
#
# Builds the harness if stale, seeds the corpus if empty, then
# fuzzes for the requested duration. Not wired into CI yet;
# coverage-guided fuzzing wants budgets measured in minutes to
# hours, and a per-PR budget buys you very little.
#
# Usage:
#   tests/fuzz/run.sh              # 30-second smoke
#   tests/fuzz/run.sh 300          # 5-minute campaign
#   tests/fuzz/run.sh 3600 -jobs=4 # 1-hour parallel campaign
#
# Extra LibFuzzer args can be passed positionally after the
# duration; see `tests/fuzz/fuzz_cookie -help=1` for the full
# menu. Common ones: -jobs=N, -workers=N, -max_len=N, -dict=<file>.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$HERE/fuzz_cookie"
CORPUS="$HERE/corpus"

DURATION="${1:-30}"
shift || true

if [[ ! -x "$BIN" ]]; then
  echo "fuzz binary missing; building..."
  make -C "$ROOT" fuzz
fi

# Seed the corpus with real cookies the first time. Subsequent runs
# skip the mint — the corpus only grows from there.
if [[ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]]; then
  echo "corpus empty; seeding from real cookies..."
  "$ROOT/tests/.venv/bin/python" "$HERE/seed_corpus.py"
fi

echo "fuzzing for ${DURATION}s (corpus: $(ls -1 "$CORPUS" | wc -l) seeds)..."
"$BIN" -max_total_time="$DURATION" -print_final_stats=1 "$@" "$CORPUS"
