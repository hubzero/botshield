#!/bin/bash
# unit/decision_format — drive a small, diverse traffic mix and assert
# every `mod_botshield: decision ` line emitted is well-formed: all
# required keys present, enum values from the documented sets. Proves
# the M9.1 log-vocabulary contract holds under a range of outcomes.
set -u
source "$(dirname "$0")/../lib/common.sh"

mark=$(log_mark)

# Cover multiple outcome classes so the validator sees a range
# of enum values rather than just one.
# pass tier
bs_curl -o /dev/null \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -H "X-Forwarded-For: 203.0.113.150" "$BASE/" > /dev/null

# asset pass-through
bs_curl -o /dev/null "$BASE/favicon.ico" > /dev/null

# form tier (scraper UA)
bs_curl -o /dev/null -A "python-requests/2.31" \
  -H "X-Forwarded-For: 203.0.113.151" "$BASE/" > /dev/null

# captcha-challenged (interstitial)
bs_curl -o /dev/null "$BASE/captcha-demo" > /dev/null

# pending_missing (verify POST without pending cookie)
bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "cf-turnstile-response=x" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

# bad content-type (captcha rejected before libcurl)
bs_curl -o /dev/null -X POST -H "Content-Type: application/json" -d '{}' \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

# unknown endpoint (tier=none, outcome=rejected)
bs_curl -o /dev/null "$BASE/botshield/nonexistent-path" > /dev/null

slice=$(log_slice "$mark")
dir="$(cd "$(dirname "$0")/.." && pwd)"
result=$(awk -f "$dir/lib/decision_gate.awk" "$slice" 2>&1)

if [[ "$result" == *"0 failed"* ]]; then
  t_pass "decision-log format validator: $result"
else
  echo "$result"
  t_fail "decision-log format validator found violations"
fi
