#!/bin/bash
# integration/m9_2_vocab_sync — assert zero 'metrics: unknown'
# WARNING lines in the apache error log during this run. Any such
# line means a decision-log emission used an enum string the
# counter lookup didn't recognize — vocabulary drift between M9.1
# and M9.2.
set -u
source "$(dirname "$0")/../lib/common.sh"

# We read from the apache-global error.log here (not the vhost's
# log) because these warnings are logged via ap_log_rerror which
# lands in the vhost's log, BUT the vhost log is where we look.
# Either way, same mechanism.
before=$(sudo wc -l < "$ERROR_LOG")

# Drive a mix covering many enum values so any drift gets exposed.
bs_curl -o /dev/null \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -H "X-Forwarded-For: 203.0.113.220" "$BASE/" > /dev/null

bs_curl -o /dev/null -A "python-requests/2.31" \
  -H "X-Forwarded-For: 203.0.113.221" "$BASE/" > /dev/null

bs_curl -o /dev/null "$BASE/captcha-demo" > /dev/null

pending=$(fetch_pending_cookie captcha-demo)
bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "cf-turnstile-response=x" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

after=$(sudo wc -l < "$ERROR_LOG")
new_lines=$(sudo tail -n $(( after - before )) "$ERROR_LOG" || true)

drift_count=$(printf "%s" "$new_lines" | grep -c "metrics: unknown" || true)
if [[ "$drift_count" -gt 0 ]]; then
  echo "  offending lines:"
  printf "%s" "$new_lines" | grep "metrics: unknown" | head -5
  t_fail "M9.2 vocabulary drift: $drift_count 'metrics: unknown' WARNINGs"
fi
t_pass "no vocabulary drift across $(( after - before )) new log lines"
