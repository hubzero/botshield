#!/bin/bash
# integration/m9_1_enum_coverage — drive traffic that hits every
# reachable outcome value, assert each shows up at least once in
# the decision log.
#
# "Reachable" here excludes misconfigured (requires an intentional
# config break) — we just want to prove the decision log is actually
# emitting across the full surface, not one enum value per commit.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Outcomes we'll drive in this test. misconfigured and debug require
# explicit config changes (debug=On, or removing secrets) and aren't
# part of ordinary traffic.
reachable="declined challenged verified rejected failopen rate_limited pending_missing"

mark=$(log_mark)

# declined: clean-browser + browser-looking headers → pass tier
bs_curl -o /dev/null \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -H "X-Forwarded-For: 203.0.113.210" "$BASE/" > /dev/null

# challenged: scraper UA → form tier interstitial
bs_curl -o /dev/null -A "python-requests/2.31" \
  -H "X-Forwarded-For: 203.0.113.211" "$BASE/" > /dev/null

# verified: valid pending cookie + valid-token (always-pass) Turnstile
pending=$(fetch_pending_cookie captcha-demo)
bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

# rejected: POST with missing token field → 400 (outcome=rejected)
pending=$(fetch_pending_cookie captcha-demo)
bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

# failopen: 100 ms timeout forces a fail-open on the next verify.
# Temporarily override the Timeout directive in the dev config.
conf=/etc/apache2/sites-available/botshield-dev.conf
sudo sed -i "s|BotShieldCaptchaTimeout    1500|BotShieldCaptchaTimeout    100|" "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1
pending=$(fetch_pending_cookie captcha-demo)
bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "cf-turnstile-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null
sudo sed -i "s|BotShieldCaptchaTimeout    100|BotShieldCaptchaTimeout    1500|" "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1

# rate_limited: flood one IP past the 30/min budget. Parallel POSTs
# so all 45 hit the rate slot within ~1s — serial calls to live
# Cloudflare span ~20s which can cross the 1-minute rate window
# boundary and reset the count mid-test. Time-salted IP so repeat
# runs don't collide with stale slots from prior test runs.
rl_ip="198.51.100.$(( ($(date +%s) + 37) % 250 + 1 ))"
pending=$(fetch_pending_cookie captcha-demo)
for i in $(seq 1 45); do
  bs_curl -o /dev/null -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-For: $rl_ip" \
    -b "_bs_captcha_pending=$pending" \
    -d "cf-turnstile-response=x&return_to=/" \
    "$BASE/botshield/captcha-verify/turnstile" > /dev/null &
done
wait

# pending_missing: POST with no cookie
bs_curl -o /dev/null -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "cf-turnstile-response=x" \
  "$BASE/botshield/captcha-verify/turnstile" > /dev/null

slice=$(log_slice "$mark")

missing=""
for o in $reachable; do
  count=$(grep -c "mod_botshield: decision .*outcome=$o " "$slice" || true)
  if [[ "$count" -lt 1 ]]; then
    missing="$missing $o"
  fi
done
rm -f "$slice"

if [[ -n "$missing" ]]; then
  t_fail "outcomes never emitted during this run:$missing"
fi
t_pass "every reachable outcome emitted at least once"
