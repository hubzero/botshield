#!/bin/bash
# integration/m8_captcha_turnstile — exercise Cloudflare Turnstile's
# three outcome paths against the module's verify endpoint:
#
#   OK       — always-pass secret → 303 + captcha-turnstile cookie
#   REJECTED — always-fail secret → 403 + error-codes in log
#   TIMEOUT  — 100 ms timeout → fail-open (303 + cookie + WARNING log)
#
# Requires a live network path to challenges.cloudflare.com. If that's
# unreachable, the test SKIPs rather than failing.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Reachability check — bail early if Cloudflare is unreachable.
if ! curl -sk --max-time 5 -o /dev/null \
      "https://challenges.cloudflare.com/turnstile/v0/siteverify"; then
  t_skip "challenges.cloudflare.com unreachable — skipping live-provider test"
fi

# Helper: grab a fresh pending cookie for the captcha-demo scope.
pending=$(fetch_pending_cookie captcha-demo)
if [[ -z "$pending" ]]; then
  t_fail "could not mint pending cookie from /captcha-demo"
fi

# -------- OK path (always-pass) ---------
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/captcha-demo" \
  "$BASE/botshield/captcha-verify/turnstile"

assert_status "$hdr" "303"
assert_header "$hdr" "X-Botshield" "captcha-ok"
if ! grep -qi "^Set-Cookie: _bs_verified=" "$hdr"; then
  cat "$hdr"; rm -f "$hdr" "$body"
  t_fail "no _bs_verified cookie on successful verify"
fi
rm -f "$hdr" "$body"
t_pass "always-pass secret → 303 + captcha-ok + _bs_verified set"

# -------- REJECTED path (always-fail) ---------
# Requires a temporarily-installed always-fail secret. Write it, point
# the verify Location at it, reload, test, revert.
fail_secret="/etc/botshield/turnstile-fail-secret"
if [[ ! -s "$fail_secret" ]]; then
  echo -n "2x0000000000000000000000000000000AA" | \
    sudo tee "$fail_secret" > /dev/null
  sudo chmod 600 "$fail_secret"
fi

# Swap the Location's secret path in the dev config
conf=/etc/apache2/sites-available/botshield-dev.conf
sudo sed -i \
  "s|BotShieldCaptchaSecretFile /etc/botshield/turnstile-secret|BotShieldCaptchaSecretFile /etc/botshield/turnstile-fail-secret|" \
  "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1

mark=$(log_mark)

pending=$(fetch_pending_cookie captcha-demo)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/captcha-demo" \
  "$BASE/botshield/captcha-verify/turnstile"

# Revert secret swap before asserting so the test is safe if it fails
sudo sed -i \
  "s|BotShieldCaptchaSecretFile /etc/botshield/turnstile-fail-secret|BotShieldCaptchaSecretFile /etc/botshield/turnstile-secret|" \
  "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1

assert_status "$hdr" "403"
assert_header "$hdr" "X-Botshield" "captcha-rejected"
rm -f "$hdr" "$body"

# Log should carry error-codes from the parser
slice=$(log_slice "$mark")
if ! grep -q "captcha REJECTED .*error-codes=\[" "$slice"; then
  cat "$slice"; rm -f "$slice"
  t_fail "REJECTED log line missing error-codes"
fi
rm -f "$slice"
t_pass "always-fail secret → 403 + captcha-rejected + error-codes logged"

# -------- TIMEOUT path (aggressive 100ms timeout) ---------
sudo sed -i \
  "s|BotShieldCaptchaTimeout    1500|BotShieldCaptchaTimeout    100|" \
  "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1

mark=$(log_mark)
pending=$(fetch_pending_cookie captcha-demo)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/captcha-demo" \
  "$BASE/botshield/captcha-verify/turnstile"

sudo sed -i \
  "s|BotShieldCaptchaTimeout    100|BotShieldCaptchaTimeout    1500|" \
  "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1

# Fail-open: 303 + _bs_verified + captcha-ok header + WARNING in log
assert_status "$hdr" "303"
assert_header "$hdr" "X-Botshield" "captcha-ok"
rm -f "$hdr" "$body"

slice=$(log_slice "$mark")
if ! grep -q "captcha .* failing open.*provider=turnstile" "$slice"; then
  cat "$slice"; rm -f "$slice"
  t_fail "TIMEOUT log line missing 'failing open'"
fi
rm -f "$slice"
t_pass "100ms timeout → fail-open 303 + cookie + 'failing open' WARNING"
