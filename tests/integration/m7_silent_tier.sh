#!/bin/bash
# integration/m7_silent_tier — verify the silent-tier auto-submit
# interstitial end-to-end:
#   1. cookieless silent-band request → challenge page with auto=1
#   2. locally solve the PoW and assemble the 15-field cookie
#   3. replay with the cookie → tier drops to pass (DECLINED)
#
# Catches regressions in the cookie envelope shape, canonical HMAC
# order, silent-tier routing, or the tier-dispatch logic.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Use a fresh IP each run — otherwise Bloom remembers us and
# first-sight-ip doesn't fire, pushing the score below silent.
fresh_ip="203.0.113.$((180 + RANDOM % 40))"

# 1. Cookieless silent-band probe. Mozilla UA + missing Accept-
# Language (15) + first-sight-ip (5) = score 20 → silent tier.
html=$(mktemp)
bs_curl -o "$html" -A "Mozilla/5.0 (X11) Chrome/145" \
  -H "X-Forwarded-For: $fresh_ip" "$BASE/" || t_fail "silent probe failed"

# Extract window.__bsChallenge = {...};
ch=$(grep -oE 'window\.__bsChallenge=\{[^;]+' "$html" | sed 's/^window\.__bsChallenge=//')
if [[ -z "$ch" ]]; then
  rm -f "$html"
  t_fail "no __bsChallenge JSON in response body"
fi
rm -f "$html"

# auto=1 means silent tier. If it's 0 we got form tier instead —
# first-sight-ip may not have fired (IP was already in Bloom).
auto=$(printf "%s" "$ch" | python3 -c 'import json,sys;print(json.load(sys.stdin)["auto"])')
if [[ "$auto" != "1" ]]; then
  t_fail "expected auto=1 (silent tier), got auto=$auto — is the IP already bloomed?"
fi
t_pass "silent-tier challenge served with auto=1"

# 2. Local PoW solve + cookie assembly.
dir="$(cd "$(dirname "$0")/.." && pwd)"
cookie=$(printf "%s" "$ch" | "$dir/tools/solve_pow.py") || \
  t_fail "PoW solver failed"
t_pass "PoW solved, cookie payload assembled"

# 3. Replay with the signed cookie. Browser-like headers so
# heuristics stay quiet; fresh IP so first-sight-ip doesn't penalize.
# Cookied + score 0 → pass tier → DECLINED (no challenge header).
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -H "X-Forwarded-For: $fresh_ip" \
  -b "_bs_verified=$cookie" "$BASE/"

# A challenged response has X-Botshield: challenge. A DECLINED
# (passed through) response doesn't.
if grep -qi "^X-Botshield: challenge" "$hdr"; then
  echo "--- response headers ---"
  cat "$hdr"
  rm -f "$hdr" "$body"
  t_fail "cookied replay still returned a challenge — cookie not accepted"
fi
rm -f "$hdr" "$body"
t_pass "cookied replay declined — 15-field cookie verified end-to-end"
