#!/bin/bash
# integration/m8_1_content_type — the M8.1 Content-Type prefilter.
# Verify requests with a Content-Type other than application/x-www-
# form-urlencoded must return 415 before libcurl is touched.
set -u
source "$(dirname "$0")/../lib/common.sh"

pending=$(fetch_pending_cookie captcha-demo)
[[ -z "$pending" ]] && t_fail "couldn't mint a pending cookie"

# 1. JSON body → 415
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/json" \
  -b "_bs_captcha_pending=$pending" \
  -d '{"cf-turnstile-response":"x"}' \
  "$BASE/botshield/captcha-verify/turnstile"
assert_status "$hdr" "415"
assert_header "$hdr" "X-Botshield" "captcha-bad-content-type"
rm -f "$hdr" "$body"
t_pass "Content-Type: application/json → 415"

# 2. No Content-Type at all → 415
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type:" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x" \
  "$BASE/botshield/captcha-verify/turnstile"
assert_status "$hdr" "415"
rm -f "$hdr" "$body"
t_pass "missing Content-Type → 415"

# 3. Form-urlencoded gets past the prefilter (we don't care about the
#    final outcome here)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile"
status=$(head -1 "$hdr" | grep -oE "HTTP/[0-9.]+ [0-9]+" | awk '{print $2}')
if [[ "$status" == "415" ]]; then
  cat "$hdr"; rm -f "$hdr" "$body"
  t_fail "form-urlencoded body wrongly rejected as 415"
fi
rm -f "$hdr" "$body"
t_pass "form-urlencoded body gets past the prefilter (HTTP $status)"
