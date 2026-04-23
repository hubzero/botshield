#!/bin/bash
# integration/m8_1_rate_limit — per-IP rate limit on the verify
# endpoint (default 30/min). 40 POSTs from one XFF IP: first ~30
# should succeed, remainder should get 429 Retry-After. Also asserts
# the log-throttle collapses the burst of 429s into a single log
# line (one per 60-second window per IP).
set -u
source "$(dirname "$0")/../lib/common.sh"

pending=$(fetch_pending_cookie captcha-demo)
[[ -z "$pending" ]] && t_fail "couldn't mint a pending cookie"

# Pick an IP that almost certainly hasn't been seen by any prior
# test run: use the current epoch-seconds as the last-two octets so
# the same test re-run five seconds later picks a different IP.
# Rate-limit ring has 4096 slots, so collisions are rare anyway,
# but occasional flakes from a stale slot at the chosen IP have
# been observed — this makes them vanishingly unlikely.
t=$(date +%s)
ip="198.51.100.$((t % 200 + 50))"

before=$(metrics_snapshot)
rl_before=$(metrics_value "$before" botshield_outcome_rate_limited_total)
rm -f "$before"

mark=$(log_mark)
# Fire the 40 POSTs in parallel so they all hit the rate-limit slot
# within ~1 second — serial curl to Cloudflare's siteverify is ~500ms
# per request, so 40 serial hits span ~20s and can cross the 1-minute
# rate-limit window boundary, resetting the count mid-test.
tmpdir=$(mktemp -d)
for i in $(seq 1 40); do
  (bs_curl -o /dev/null -w "%{http_code}\n" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-For: $ip" \
    -b "_bs_captcha_pending=$pending" \
    -d "cf-turnstile-response=x&return_to=/" \
    "$BASE/botshield/captcha-verify/turnstile" > "$tmpdir/$i") &
done
wait

declare -A codes
for i in $(seq 1 40); do
  code=$(cat "$tmpdir/$i")
  codes[$code]=$(( ${codes[$code]:-0} + 1 ))
done
rm -rf "$tmpdir"

after=$(metrics_snapshot)
rl_after=$(metrics_value "$after" botshield_outcome_rate_limited_total)
rm -f "$after"
rl_delta=$(( rl_after - rl_before ))

n429=${codes[429]:-0}
if [[ "$n429" -lt 1 ]]; then
  echo "  IP used: $ip"
  echo "  response distribution:"
  for k in "${!codes[@]}"; do echo "    HTTP $k: ${codes[$k]}"; done
  echo "  rate_limited counter delta: $rl_delta"
  t_fail "expected at least one 429 after 40 parallel POSTs from $ip"
fi
t_pass "rate limit fires: $n429 × 429 among 40 parallel POSTs from $ip (counter delta $rl_delta)"

# Log throttle: even if many 429s fired, the 'captcha-verify rate
# limit' log line must appear at most a small number of times per IP
# per 60-second window (ideally 1). Tolerate up to 2 in case a
# second window rolled over during the burst.
slice=$(log_slice "$mark")
log_lines=$(grep -c "captcha-verify rate limit.*ip=$ip" "$slice")
rm -f "$slice"
if [[ "$log_lines" -gt 2 ]]; then
  t_fail "log throttle broke: $log_lines rate-limit log lines for $ip (expected ≤2)"
fi
t_pass "log throttle collapsed $n429 × 429 into $log_lines log line(s)"
