#!/bin/bash
# integration/m8_captcha_recaptcha_v3 — plumbing smoke for Google
# reCAPTCHA v3.
#
# v3 has no published always-pass keys (real keys come from the
# admin console). This test proves the module reaches v3's
# siteverify and emits a decision line with the right provider=/alg=
# values — a refactor that breaks v3's URL, body-field name, or
# response parsing will show up here even without real keys.
#
# The operator can provide a real v3 token via BS_RECAPTCHA_V3_TOKEN
# to additionally exercise the OK branch + score threshold.
#
# Skips if www.google.com/recaptcha is unreachable.
set -u
source "$(dirname "$0")/../lib/common.sh"

if ! curl -sk --max-time 5 -o /dev/null \
      "https://www.google.com/recaptcha/api/siteverify"; then
  t_skip "www.google.com/recaptcha unreachable"
fi

# -------- Plumbing smoke: garbage token reaches siteverify --------
pending=$(fetch_pending_cookie recaptcha-v3-demo)
[[ -z "$pending" ]] && t_fail "could not mint pending cookie from /recaptcha-v3-demo"

mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "g-recaptcha-response=garbage-token&return_to=/" \
  "$BASE/botshield/captcha-verify/recaptcha-v3"
rm -f "$hdr" "$body"

# Placeholder secret → v3 responds without a score → module fail-opens
# with a WARNING. Real secret + garbage token → error-codes=
# [invalid-input-response] and REJECTED. Accept either — both prove
# the module correctly routes to v3's code path.
slice=$(log_slice "$mark")
if grep -q "decision .*provider=recaptcha-v3 alg=captcha-recaptcha-v3" "$slice"; then
  t_pass "v3 plumbing: siteverify round-trip emits provider=recaptcha-v3"
else
  cat "$slice"; rm -f "$slice"
  t_fail "no decision line with provider=recaptcha-v3 alg=captcha-recaptcha-v3"
fi
rm -f "$slice"

# -------- Optional OK branch (real token) --------
if [[ -n "${BS_RECAPTCHA_V3_TOKEN:-}" ]]; then
  pending=$(fetch_pending_cookie recaptcha-v3-demo)
  hdr=$(mktemp); body=$(mktemp)
  bs_curl_split "$hdr" "$body" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b "_bs_captcha_pending=$pending" \
    -d "g-recaptcha-response=$BS_RECAPTCHA_V3_TOKEN&return_to=/" \
    "$BASE/botshield/captcha-verify/recaptcha-v3"

  assert_status "$hdr" "303"
  assert_header "$hdr" "X-Botshield" "captcha-ok"
  rm -f "$hdr" "$body"
  t_pass "v3 real token (BS_RECAPTCHA_V3_TOKEN) → 303 + captcha-ok"
else
  t_pass "OK branch skipped — set BS_RECAPTCHA_V3_TOKEN to exercise with a real token"
fi
