#!/bin/bash
# integration/m8_captcha_hcaptcha — exercise hCaptcha's OK + REJECTED
# paths against the module's verify endpoint.
#
# hCaptcha's always-pass sitekey (10000000-ffff-...) is paired with a
# canonical test *token* (10000000-aaaa-bbbb-cccc-000000000001) —
# unlike Turnstile, the token value matters: any other string yields
# invalid-input-response. The REJECTED branch exploits that by
# posting a deliberately wrong token.
#
# Requires a live network path to hcaptcha.com/siteverify. Skips if
# unreachable.
set -u
source "$(dirname "$0")/../lib/common.sh"

if ! curl -sk --max-time 5 -o /dev/null \
      "https://api.hcaptcha.com/siteverify"; then
  t_skip "api.hcaptcha.com unreachable"
fi

ok_token="10000000-aaaa-bbbb-cccc-000000000001"

# -------- OK path (always-pass sitekey + its canonical test token) --------
pending=$(fetch_pending_cookie hcaptcha-demo)
[[ -z "$pending" ]] && t_fail "could not mint pending cookie from /hcaptcha-demo"

hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "h-captcha-response=$ok_token&return_to=/" \
  "$BASE/botshield/captcha-verify/hcaptcha"

assert_status "$hdr" "303"
assert_header "$hdr" "X-Botshield" "captcha-ok"
if ! grep -qi "^Set-Cookie: _bs_verified=" "$hdr"; then
  cat "$hdr"; rm -f "$hdr" "$body"
  t_fail "no _bs_verified cookie on successful hCaptcha verify"
fi
rm -f "$hdr" "$body"
t_pass "hCaptcha always-pass token → 303 + captcha-ok + cookie set"

# -------- REJECTED path (garbage token) --------
pending=$(fetch_pending_cookie hcaptcha-demo)
mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "h-captcha-response=not-a-real-token&return_to=/" \
  "$BASE/botshield/captcha-verify/hcaptcha"

assert_status "$hdr" "403"
assert_header "$hdr" "X-Botshield" "captcha-rejected"
rm -f "$hdr" "$body"

slice=$(log_slice "$mark")
# Assert on the decision line rather than the "captcha REJECTED"
# prose line: the prose line is log-throttled (1 per IP per 60s),
# so if an earlier rejection happened within the window it won't
# re-emit. The decision line is never throttled — every request
# produces one and only one.
if ! grep -q "decision .*outcome=rejected .*provider=hcaptcha .*reason=\"invalid-input-response\"" "$slice"; then
  cat "$slice"; rm -f "$slice"
  t_fail "no 'outcome=rejected provider=hcaptcha reason=invalid-input-response' decision line"
fi
rm -f "$slice"
t_pass "hCaptcha bogus token → 403 + captcha-rejected + decision log invalid-input-response"
