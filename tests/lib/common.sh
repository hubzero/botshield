# shellcheck shell=bash
# tests/lib/common.sh — shared helpers for the mod_botshield test suite.
#
# Source me from any test script. Provides:
#   - BASE, ERROR_LOG constants scoped to the dev vhost
#   - t_pass / t_fail / t_skip  (one-line PASS/FAIL/SKIP output; FAIL exits)
#   - curl wrappers that take care of -sk + a default timeout
#   - log_mark / log_slice     (capture only lines from this test run)
#   - metrics_snapshot         (curl /botshield/metrics → file)
#   - metrics_counter_delta    (cheap diff between two snapshots)
#   - fetch_pending_cookie     (grabs _bs_captcha_pending for a given demo path)
#   - wait_idle                (sleep long enough that cv_inflight settles + 1)
#   - enum_sets                (exported: TIERS, OUTCOMES, COOKIES, PROVIDERS)
#
# Tests assume the dev vhost at apache/botshield-dev.conf is installed
# and Apache is running. tests/setup/provision.sh gets you there from
# a fresh box.

set -u

BASE="${BS_BASE:-https://localhost}"
ERROR_LOG="${BS_ERROR_LOG:-/var/log/apache2/botshield-dev-error.log}"
APACHE_ERROR_LOG="${BS_APACHE_ERROR_LOG:-/var/log/apache2/error.log}"

# Enum sets, kept 1:1 with the M9.1 log vocabulary + M9.2 counter names.
# If a new value is added to one of these, all consumers should fail
# loud — that's the whole point.
export TIERS="none pass silent form captcha"
export OUTCOMES="declined challenged verified rejected failopen rate_limited inflight_capped pending_missing misconfigured debug"
export COOKIES="ok expired bad_sig bad_format absent"
# Provider names: underscore form matches the counter metric names;
# hyphen form matches the log's provider= value. Callers that need
# the hyphenated form construct it from this list.
export PROVIDERS="turnstile hcaptcha recaptcha_v2 recaptcha_v3 friendly geetest"

t_pass() { printf "  PASS: %s\n" "$*"; }
t_fail() { printf "  FAIL: %s\n" "$*" >&2; exit 1; }
t_skip() { printf "  SKIP: %s\n" "$*"; exit 0; }

# Wrapper around curl with the flags tests almost always want:
#   -s silent, -k insecure (self-signed cert), --max-time bounded.
# Usage identical to curl otherwise.
bs_curl() {
  curl -sk --max-time 10 "$@"
}

# Two-file curl that separates headers and body so downstream scripts
# can grep either cleanly. Writes headers to $1, body to $2, then
# forwards $3... as additional curl args.
#
# Example:
#   bs_curl_split /tmp/h /tmp/b -X POST -d "a=b" "$BASE/foo"
bs_curl_split() {
  local hf="$1" bf="$2"; shift 2
  curl -sk --max-time 10 -D "$hf" -o "$bf" "$@"
}

# Capture the current size of the botshield error log so a later
# log_slice call can extract only lines added during the test.
#
# Usage:
#   local mark; mark=$(log_mark)
#   # ... drive traffic ...
#   local slice; slice=$(log_slice "$mark")
#   grep "decision" "$slice" | ...
log_mark() {
  sudo stat -c %s "$ERROR_LOG"
}

log_slice() {
  local mark="$1"
  local out; out=$(mktemp /tmp/bs_log_slice.XXXXXX)
  sudo tail -c +$((mark + 1)) "$ERROR_LOG" > "$out"
  printf "%s" "$out"
}

# Scrape /botshield/metrics into a temp file whose path is echoed.
# Caller can diff two snapshots to get counter deltas.
metrics_snapshot() {
  local out; out=$(mktemp /tmp/bs_metrics.XXXXXX.prom)
  bs_curl "$BASE/botshield/metrics" > "$out"
  printf "%s" "$out"
}

# Print the integer value of a Prometheus counter/gauge by name.
# Usage: metrics_value /tmp/snapshot.prom botshield_tier_pass_total
metrics_value() {
  local f="$1" metric="$2"
  grep "^$metric " "$f" | awk '{print $2}'
}

# Print delta(after - before) for a named metric. 0 if either side
# is missing (metric wasn't exposed).
metrics_delta() {
  local before="$1" after="$2" metric="$3"
  local b a; b=$(metrics_value "$before" "$metric")
  a=$(metrics_value "$after" "$metric")
  echo $(( ${a:-0} - ${b:-0} ))
}

# Visit a captcha-demo path, extract the _bs_captcha_pending cookie
# from the Set-Cookie header, and echo its raw value (without the
# "_bs_captcha_pending=" prefix).
#
# Usage:
#   local p; p=$(fetch_pending_cookie captcha-demo)
#   bs_curl -b "_bs_captcha_pending=$p" ...
fetch_pending_cookie() {
  local path="${1:-captcha-demo}"
  local jar; jar=$(mktemp /tmp/bs_jar.XXXXXX.txt)
  bs_curl -c "$jar" "$BASE/$path" > /dev/null
  local val
  val=$(awk '$6 == "_bs_captcha_pending" {print $7}' "$jar")
  rm -f "$jar"
  printf "%s" "$val"
}

# Sleep long enough for a small burst of captcha-verify calls to drain
# (in-flight semaphore back to 0, log-throttle decisions emit, etc.).
wait_idle() {
  sleep "${1:-3}"
}

# Assert that a metric's delta equals an expected integer. Fails the
# test loud with a diff message.
#
# Usage:
#   assert_metric_delta $before $after botshield_outcome_verified_total 5
assert_metric_delta() {
  local before="$1" after="$2" metric="$3" want="$4"
  local got; got=$(metrics_delta "$before" "$after" "$metric")
  if [[ "$got" != "$want" ]]; then
    t_fail "$metric delta=$got, wanted $want"
  fi
}

# Assert that a pattern appears N times in the decision-log slice.
# Filters to "mod_botshield: decision " lines only so the pre-M9
# prose log (which also mentions tier=X, provider=X) can't inflate
# the count.
#
# Usage:
#   assert_decision_count "$slice" "outcome=verified " 3
assert_decision_count() {
  local slice="$1" pattern="$2" want="$3"
  local got
  got=$(grep -c "mod_botshield: decision .*${pattern}" "$slice" || true)
  if [[ "$got" != "$want" ]]; then
    t_fail "expected $want decision lines matching '$pattern', got $got"
  fi
}

# Assert a count-greater-than-or-equal, for cases where exact count
# is hard to predict (e.g., some tests drive N requests and expect
# at least N decision lines, with extras from background traffic).
assert_decision_ge() {
  local slice="$1" pattern="$2" want="$3"
  local got
  got=$(grep -c "mod_botshield: decision .*${pattern}" "$slice" || true)
  if [[ "$got" -lt "$want" ]]; then
    t_fail "expected >=$want decision lines matching '$pattern', got $got"
  fi
}

# Assert a response header equals an expected value. Accepts the
# header file produced by bs_curl_split.
#
# Usage:
#   assert_header /tmp/hdr "X-Botshield" "captcha-ok"
assert_header() {
  local hf="$1" name="$2" want="$3"
  local got
  got=$(grep -i "^$name:" "$hf" | head -1 | sed -E "s/^[^:]+: ?//;s/\r$//")
  if [[ "$got" != "$want" ]]; then
    t_fail "$name: expected '$want', got '$got'"
  fi
}

# Assert a response's first status line contains a given HTTP code.
assert_status() {
  local hf="$1" want="$2"
  local got
  got=$(head -1 "$hf" | grep -oE "HTTP/[0-9.]+ [0-9]+" | awk '{print $2}')
  if [[ "$got" != "$want" ]]; then
    t_fail "HTTP status: expected $want, got $got"
  fi
}
