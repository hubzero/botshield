#!/bin/bash
# integration/m8_1_pending_cookie — the M8.1 pending-cookie guardrail.
#
# POSTing to /botshield/captcha-verify/<provider> without a valid
# _bs_captcha_pending cookie must short-circuit to 403 before libcurl
# is constructed. Also asserts a tampered cookie (wrong HMAC) is
# rejected the same way.
set -u
source "$(dirname "$0")/../lib/common.sh"

# 1. No cookie at all
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile"
assert_status "$hdr" "403"
assert_header "$hdr" "X-Botshield" "captcha-pending-missing"
rm -f "$hdr" "$body"
t_pass "missing pending cookie → 403 + captcha-pending-missing"

# 2. Tampered cookie (right shape, wrong HMAC)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|9999999999|$(printf 'de%.0s' {1..32})" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile"
assert_status "$hdr" "403"
assert_header "$hdr" "X-Botshield" "captcha-pending-missing"
rm -f "$hdr" "$body"
t_pass "tampered pending cookie → 403 + captcha-pending-missing"

# 3. Valid cookie → gets past the pending check (we won't assert the
#    final outcome because Turnstile's siteverify response can vary;
#    just confirm it's NOT a captcha-pending-missing reject).
pending=$(fetch_pending_cookie captcha-demo)
[[ -z "$pending" ]] && t_fail "couldn't mint a pending cookie"
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile"
xbs=$(grep -i "^X-Botshield:" "$hdr" | sed -E "s/^[^:]+: ?//;s/\r$//")
if [[ "$xbs" == "captcha-pending-missing" ]]; then
  cat "$hdr"; rm -f "$hdr" "$body"
  t_fail "valid pending cookie still triggered captcha-pending-missing"
fi
rm -f "$hdr" "$body"
t_pass "valid pending cookie gets past the guard (X-Botshield=$xbs)"
