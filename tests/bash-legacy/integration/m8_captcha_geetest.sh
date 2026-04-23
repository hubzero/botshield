#!/bin/bash
# integration/m8_captcha_geetest — plumbing smoke for GeeTest v4.
#
# GeeTest is the outlier: the module signs lot_number with an HMAC
# of the captcha_key (rather than sending the raw secret over the
# wire), so this test exercises a custom siteverify_fn code path no
# other provider uses. A break in the HMAC signing, URL building, or
# response parsing will only surface here.
#
# GeeTest does not publish test keys; real captcha_id + captcha_key
# come from dashboard.geetest.com. With placeholders the request
# errors and the module fail-opens; the decision line still carries
# provider=geetest alg=captcha-geetest which is the regression
# signal we care about.
#
# The frontend packs four fields (lot_number, captcha_output,
# pass_token, gen_time) into a single JSON body-field named
# 'geetest-token'. That JSON-split is part of the code path this
# test exercises.
#
# Set BS_GEETEST_TOKEN to a solved token JSON to exercise the OK
# branch.
set -u
source "$(dirname "$0")/../lib/common.sh"

if ! curl -sk --max-time 5 -o /dev/null \
      "https://gcaptcha4.geetest.com/validate"; then
  t_skip "gcaptcha4.geetest.com unreachable"
fi

# -------- Plumbing smoke: garbage JSON reaches siteverify --------
pending=$(fetch_pending_cookie geetest-demo)
[[ -z "$pending" ]] && t_fail "could not mint pending cookie from /geetest-demo"

garbage='{"lot_number":"l","captcha_output":"o","pass_token":"p","gen_time":"1"}'

mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  --data-urlencode "geetest-token=$garbage" \
  --data-urlencode "return_to=/" \
  "$BASE/botshield/captcha-verify/geetest"
rm -f "$hdr" "$body"

slice=$(log_slice "$mark")
if grep -q "decision .*provider=geetest alg=captcha-geetest" "$slice"; then
  t_pass "GeeTest plumbing: HMAC-signed round-trip emits provider=geetest"
else
  cat "$slice"; rm -f "$slice"
  t_fail "no decision line with provider=geetest alg=captcha-geetest"
fi
rm -f "$slice"

# -------- Body-field-name regression: wrong field → 400 no_token --------
pending=$(fetch_pending_cookie geetest-demo)
mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "lot_number=l&captcha_output=o&pass_token=p&gen_time=1&return_to=/" \
  "$BASE/botshield/captcha-verify/geetest"

assert_status "$hdr" "400"
rm -f "$hdr" "$body"

slice=$(log_slice "$mark")
if ! grep -q "missing token field 'geetest-token'" "$slice"; then
  cat "$slice"; rm -f "$slice"
  t_fail "expected 'missing token field geetest-token' log"
fi
rm -f "$slice"
t_pass "GeeTest body field name stable: geetest-token (single JSON field)"

# -------- Optional OK branch (real token JSON) --------
if [[ -n "${BS_GEETEST_TOKEN:-}" ]]; then
  pending=$(fetch_pending_cookie geetest-demo)
  hdr=$(mktemp); body=$(mktemp)
  bs_curl_split "$hdr" "$body" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b "_bs_captcha_pending=$pending" \
    --data-urlencode "geetest-token=$BS_GEETEST_TOKEN" \
    --data-urlencode "return_to=/" \
    "$BASE/botshield/captcha-verify/geetest"
  assert_status "$hdr" "303"
  assert_header "$hdr" "X-Botshield" "captcha-ok"
  rm -f "$hdr" "$body"
  t_pass "GeeTest real token → 303 + captcha-ok"
else
  t_pass "OK branch skipped — set BS_GEETEST_TOKEN to exercise"
fi
