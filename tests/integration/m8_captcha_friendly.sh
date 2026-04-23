#!/bin/bash
# integration/m8_captcha_friendly — plumbing smoke for Friendly
# Captcha.
#
# Friendly does not publish always-pass test keys; real keys come
# from the free tier at friendlycaptcha.com. This test exercises the
# module's routing to the Friendly code path:
#
#   - body field name is 'frc-captcha-solution' (the odd one out —
#     Turnstile uses cf-turnstile-response, hCaptcha uses h-captcha-
#     response, reCAPTCHA uses g-recaptcha-response, Friendly uses
#     frc-captcha-solution)
#   - siteverify URL is api.friendlycaptcha.com/api/v1/siteverify
#   - response body carries a top-level 'success' bool + 'errors'
#
# With placeholder API keys the request 401s and the module fail-
# opens; with real keys and a bogus solution it REJECTS. Either
# proves the plumbing is intact.
#
# Set BS_FRIENDLY_SOLUTION to exercise the OK branch with a real
# solved token.
set -u
source "$(dirname "$0")/../lib/common.sh"

if ! curl -sk --max-time 5 -o /dev/null \
      "https://api.friendlycaptcha.com/api/v1/siteverify"; then
  t_skip "api.friendlycaptcha.com unreachable"
fi

# -------- Plumbing smoke: garbage solution reaches siteverify --------
pending=$(fetch_pending_cookie friendly-demo)
[[ -z "$pending" ]] && t_fail "could not mint pending cookie from /friendly-demo"

mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "frc-captcha-solution=garbage&return_to=/" \
  "$BASE/botshield/captcha-verify/friendly"
rm -f "$hdr" "$body"

slice=$(log_slice "$mark")
if grep -q "decision .*provider=friendly alg=captcha-friendly" "$slice"; then
  t_pass "Friendly plumbing: siteverify round-trip emits provider=friendly"
else
  cat "$slice"; rm -f "$slice"
  t_fail "no decision line with provider=friendly alg=captcha-friendly"
fi
rm -f "$slice"

# -------- Body-field-name regression: wrong field → 400 no_token --------
# If someone refactors the field name, this catches it: the module
# should log 'missing token field' and return 400, not silently hit
# siteverify with an empty solution.
pending=$(fetch_pending_cookie friendly-demo)
mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "solution=x&return_to=/" \
  "$BASE/botshield/captcha-verify/friendly"

assert_status "$hdr" "400"
rm -f "$hdr" "$body"

slice=$(log_slice "$mark")
if ! grep -q "missing token field 'frc-captcha-solution'" "$slice"; then
  cat "$slice"; rm -f "$slice"
  t_fail "expected 'missing token field frc-captcha-solution' log"
fi
rm -f "$slice"
t_pass "Friendly body field name stable: frc-captcha-solution"

# -------- Optional OK branch (real solution) --------
if [[ -n "${BS_FRIENDLY_SOLUTION:-}" ]]; then
  pending=$(fetch_pending_cookie friendly-demo)
  hdr=$(mktemp); body=$(mktemp)
  bs_curl_split "$hdr" "$body" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b "_bs_captcha_pending=$pending" \
    -d "frc-captcha-solution=$BS_FRIENDLY_SOLUTION&return_to=/" \
    "$BASE/botshield/captcha-verify/friendly"
  assert_status "$hdr" "303"
  assert_header "$hdr" "X-Botshield" "captcha-ok"
  rm -f "$hdr" "$body"
  t_pass "Friendly real solution → 303 + captcha-ok"
else
  t_pass "OK branch skipped — set BS_FRIENDLY_SOLUTION to exercise"
fi
