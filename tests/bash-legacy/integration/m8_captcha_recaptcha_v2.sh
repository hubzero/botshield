#!/bin/bash
# integration/m8_captcha_recaptcha_v2 — OK + REJECTED paths for
# Google reCAPTCHA v2.
#
# Google's published test keypair (sitekey 6LeIxAcTAAAAAJcZ…,
# secret 6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe) accepts any token
# value, so OK is just "post anything non-empty to the verify URL."
# REJECTED swaps in an intentionally-wrong secret via the pre-created
# recaptcha-v2-badsecret file.
#
# Skips if www.google.com/recaptcha/api/siteverify is unreachable.
set -u
source "$(dirname "$0")/../lib/common.sh"

if ! curl -sk --max-time 5 -o /dev/null \
      "https://www.google.com/recaptcha/api/siteverify"; then
  t_skip "www.google.com/recaptcha unreachable"
fi

# -------- OK path --------
pending=$(fetch_pending_cookie recaptcha-v2-demo)
[[ -z "$pending" ]] && t_fail "could not mint pending cookie from /recaptcha-v2-demo"

hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "g-recaptcha-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/recaptcha-v2"

assert_status "$hdr" "303"
assert_header "$hdr" "X-Botshield" "captcha-ok"
if ! grep -qi "^Set-Cookie: _bs_verified=" "$hdr"; then
  cat "$hdr"; rm -f "$hdr" "$body"
  t_fail "no _bs_verified cookie on successful reCAPTCHA v2 verify"
fi
rm -f "$hdr" "$body"
t_pass "reCAPTCHA v2 test-keypair → 303 + captcha-ok + cookie set"

# -------- REJECTED path (swap in bad secret) --------
bad_secret="/etc/botshield/recaptcha-v2-badsecret"
if ! sudo test -s "$bad_secret"; then
  # Create it on the fly — any string that isn't the real test secret
  # yields invalid-input-secret from siteverify.
  echo -n "0000000000000000000000000000000000000000" | \
    sudo tee "$bad_secret" > /dev/null
  sudo chmod 600 "$bad_secret"
fi

conf=/etc/apache2/sites-available/botshield-dev.conf
sudo sed -i \
  "s|BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v2-secret|BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v2-badsecret|" \
  "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1

mark=$(log_mark)

pending=$(fetch_pending_cookie recaptcha-v2-demo)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "_bs_captcha_pending=$pending" \
  -d "g-recaptcha-response=x&return_to=/" \
  "$BASE/botshield/captcha-verify/recaptcha-v2"

# Revert before asserting so a test failure doesn't leave the vhost
# broken for the next test.
sudo sed -i \
  "s|BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v2-badsecret|BotShieldCaptchaSecretFile /etc/botshield/recaptcha-v2-secret|" \
  "$conf"
sudo systemctl reload apache2 >/dev/null
sleep 1

assert_status "$hdr" "403"
assert_header "$hdr" "X-Botshield" "captcha-rejected"
rm -f "$hdr" "$body"

# Assert the decision line (not the "captcha REJECTED" prose line,
# which is log-throttled 1/IP/60s — flaky under rapid re-runs).
slice=$(log_slice "$mark")
if ! grep -q "decision .*outcome=rejected .*provider=recaptcha-v2 " "$slice"; then
  cat "$slice"; rm -f "$slice"
  t_fail "no 'outcome=rejected provider=recaptcha-v2' decision line"
fi
rm -f "$slice"
t_pass "reCAPTCHA v2 bad secret → 403 + captcha-rejected + decision outcome=rejected"
