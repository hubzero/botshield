#!/bin/bash
# acceptance/captcha_tier — the high-confidence-bot-or-real-user
# journey. /captcha-demo is configured with BotShieldScoreCaptcha 3
# which forces every request into the captcha tier regardless of
# heuristics.
#
# Flow:
#   1. GET /captcha-demo (no cookie) → interstitial HTML with a
#      Turnstile widget + _bs_captcha_pending cookie.
#   2. POST to /botshield/captcha-verify/turnstile with the pending
#      cookie and the always-pass Turnstile token → 303 + Set-Cookie
#      _bs_verified.
#   3. GET /captcha-demo with _bs_verified → real demo page
#      (challenge lifted).
#
# Requires live Turnstile siteverify; skips if unreachable.
set -u
source "$(dirname "$0")/../lib/common.sh"

if ! curl -sk --max-time 5 -o /dev/null \
      "https://challenges.cloudflare.com/turnstile/v0/siteverify"; then
  t_skip "challenges.cloudflare.com unreachable"
fi

# 1. Probe /captcha-demo cookieless. The module should serve the
#    interstitial + mint _bs_captcha_pending. fetch_pending_cookie
#    does both in one hop.
pending=$(fetch_pending_cookie captcha-demo)
if [[ -z "$pending" ]]; then
  t_fail "no _bs_captcha_pending minted — captcha interstitial broken"
fi
t_pass "cookieless /captcha-demo → interstitial + pending cookie"

# The interstitial body should reference the turnstile widget —
# sanity check that we're not accidentally looking at the real page.
body=$(mktemp)
bs_curl -o "$body" "$BASE/captcha-demo"
if ! grep -q "cf-turnstile" "$body"; then
  cat "$body"; rm -f "$body"
  t_fail "interstitial missing cf-turnstile widget"
fi
rm -f "$body"
t_pass "interstitial body carries Turnstile widget"

# 2. POST valid-token to the verify endpoint. Always-pass site+secret
#    pair means Turnstile returns success regardless of token value.
#    return_to=/ because /captcha-demo is permanently at captcha tier
#    (score threshold 3) — the user journey after a solve is to
#    continue browsing the normal site, not to bounce back to the
#    always-challenge demo page.
mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile"

assert_status "$hdr" "303"
assert_header "$hdr" "X-Botshield" "captcha-ok"

# Capture the verified cookie the response set.
verified=$(grep -i "^Set-Cookie: _bs_verified=" "$hdr" | head -1 | \
  sed -E 's/^[Ss]et-[Cc]ookie: _bs_verified=([^;]+).*/\1/;s/\r$//')
rm -f "$hdr" "$body"

if [[ -z "$verified" ]]; then
  t_fail "verify response didn't set _bs_verified"
fi
t_pass "valid captcha solve → 303 + captcha-ok + _bs_verified issued"

# 3. Replay / (normal path) with the verified cookie + browser-like
#    headers. This is the real post-solve journey: user dismisses the
#    interstitial and continues browsing. Challenge should be lifted,
#    tier drops to pass.
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -b "_bs_verified=$verified" "$BASE/"

if grep -qi "^X-Botshield: challenge" "$hdr"; then
  cat "$hdr"; rm -f "$hdr" "$body"
  t_fail "verified cookie didn't lift challenge on normal path"
fi
assert_status "$hdr" "200"
rm -f "$hdr" "$body"
t_pass "verified cookie → 200 on normal path, challenge cleared"

# Confirm the decision log captured the verified outcome during the
# verify POST.
slice=$(log_slice "$mark")
if ! grep -q "mod_botshield: decision .*outcome=verified .*provider=turnstile" "$slice"; then
  echo "--- slice tail ---"; tail -5 "$slice"
  rm -f "$slice"
  t_fail "expected outcome=verified provider=turnstile in decision log"
fi
rm -f "$slice"
t_pass "decision log: outcome=verified provider=turnstile"
