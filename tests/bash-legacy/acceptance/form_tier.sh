#!/bin/bash
# acceptance/form_tier — the cookieless-but-recoverable journey.
#
# 1. Suspicious-looking request arrives with no _bs_verified cookie.
#    → Module serves the silent or form-tier interstitial.
# 2. We locally solve the PoW + assemble a 15-field signed cookie
#    (the same work the interstitial JS does in a real browser).
# 3. We replay with that cookie.
#    → Module accepts it, tier drops to pass, origin content served.
#
# If this ever breaks, users who trip a heuristic have no recovery
# path short of a captcha — the silent/form tier stops working as a
# graceful step-up and every marginal visitor ends up at a captcha
# or worse.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Time-salted fresh IP → first-sight-ip fires → combined with UA
# penalty lands us in silent/form band.
t=$(date +%s)
ip="203.0.$(( (t / 256) % 250 + 1 )).$(( t % 250 + 1 ))"

# 1. Cookieless probe.
html=$(mktemp)
bs_curl -o "$html" -A "Mozilla/5.0 (X11) Chrome/145" \
  -H "X-Forwarded-For: $ip" "$BASE/" || t_fail "initial probe failed"

ch=$(grep -oE 'window\.__bsChallenge=\{[^;]+' "$html" | sed 's/^window\.__bsChallenge=//')
rm -f "$html"

if [[ -z "$ch" ]]; then
  t_fail "no challenge JSON served — suspicious UA should land at silent/form tier"
fi
t_pass "cookieless suspicious request → interstitial with challenge JSON"

# 2. Solve PoW, build the 15-field cookie.
dir="$(cd "$(dirname "$0")/.." && pwd)"
cookie=$(printf "%s" "$ch" | "$dir/tools/solve_pow.py") || \
  t_fail "PoW solver failed"
t_pass "PoW solved, cookie assembled"

# 3. Replay with the cookie + browser-like headers. Fresh IP means
# no prior Bloom hit to penalize us; cookie supplies verified=1.
mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -H "X-Forwarded-For: $ip" \
  -b "_bs_verified=$cookie" "$BASE/"

if grep -qi "^X-Botshield: challenge" "$hdr"; then
  echo "--- headers ---"; cat "$hdr"
  rm -f "$hdr" "$body"
  t_fail "cookied replay still returned a challenge — cookie not honored"
fi
assert_status "$hdr" "200"
rm -f "$hdr" "$body"
t_pass "cookied replay → 200, no challenge"

# Decision log should now show cookie=ok tier=pass for this IP.
slice=$(log_slice "$mark")
if ! grep -E "mod_botshield: decision " "$slice" | grep "ip=$ip " | \
     grep -q "tier=pass .*cookie=ok"; then
  echo "--- decision lines for this IP ---"
  grep "ip=$ip " "$slice" || echo "(none)"
  rm -f "$slice"
  t_fail "expected tier=pass cookie=ok in decision log for ip=$ip"
fi
rm -f "$slice"
t_pass "decision log: tier=pass cookie=ok after PoW solve"
