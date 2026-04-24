#!/bin/bash
# tests/fuzz/run.sh — launcher for the LibFuzzer harnesses.
#
# Builds the selected harness if stale, seeds the corpus if empty,
# then fuzzes for the requested duration. Not wired into CI yet;
# coverage-guided fuzzing wants budgets measured in minutes to
# hours, and a per-PR budget buys you very little.
#
# Usage:
#   tests/fuzz/run.sh                     # fuzz_cookie, 30s smoke
#   tests/fuzz/run.sh --target robots 60  # fuzz_robots, 60s
#   tests/fuzz/run.sh 300                 # fuzz_cookie, 5 min
#   tests/fuzz/run.sh 3600 -jobs=4        # fuzz_cookie, 1 hr parallel
#
# Extra LibFuzzer args can be passed positionally after the
# duration; see `tests/fuzz/<bin> -help=1` for the full menu.
# Common ones: -jobs=N, -workers=N, -max_len=N, -dict=<file>.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

TARGET="cookie"
if [[ "${1:-}" == "--target" ]]; then
  TARGET="$2"
  shift 2
fi
case "$TARGET" in
  cookie)
    BIN="$HERE/fuzz_cookie"
    CORPUS="$HERE/corpus"
    SEEDS=""                       # minted by seed_corpus.py
    MAKE_TARGET="fuzz"
    ;;
  robots)
    BIN="$HERE/fuzz_robots"
    CORPUS="$HERE/corpus-robots"
    SEEDS="$HERE/seeds-robots"     # checked-in starter inputs
    MAKE_TARGET="fuzz-robots"
    ;;
  *)
    echo "unknown --target '$TARGET' (expected cookie|robots)" >&2
    exit 2
    ;;
esac

DURATION="${1:-30}"
shift || true

if [[ ! -x "$BIN" ]]; then
  echo "fuzz binary missing; building..."
  make -C "$ROOT" "$MAKE_TARGET"
fi

# Seed the corpus the first time. Subsequent runs skip — the corpus
# only grows from there. fuzz_cookie uses seed_corpus.py (mints
# live HMAC-signed cookies); fuzz_robots copies from the tracked
# seeds-robots/ starter set.
mkdir -p "$CORPUS"
if [[ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]]; then
  if [[ "$TARGET" == "cookie" ]]; then
    echo "corpus empty; seeding from real cookies..."
    "$ROOT/tests/.venv/bin/python" "$HERE/seed_corpus.py"
  elif [[ -n "$SEEDS" && -d "$SEEDS" ]]; then
    echo "corpus empty; copying from $SEEDS..."
    cp "$SEEDS"/* "$CORPUS/"
  fi
fi

echo "fuzzing $TARGET for ${DURATION}s (corpus: $(ls -1 "$CORPUS" | wc -l) seeds)..."
# LibFuzzer writes `crash-<hash>` / `leak-<hash>` / `timeout-<hash>`
# / `slow-unit-<hash>` reproducer files to its current working
# directory, not next to the binary. cd into tests/fuzz/ first so
# the reproducers land alongside the harness + corpus — what the
# README claims and what operators actually want on a finding.
# .gitignore catches these patterns at the repo root AND inside
# tests/fuzz/ (see the `crash-*` etc. entries in .gitignore).
cd "$HERE"
"$BIN" -max_total_time="$DURATION" -print_final_stats=1 "$@" "$CORPUS"
