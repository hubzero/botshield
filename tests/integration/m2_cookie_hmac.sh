#!/bin/bash
# integration/m2_cookie_hmac — issue a challenge, mint a valid cookie
# via PoW solve, flip one byte in the HMAC signature, replay, assert
# the cookie is rejected with reason="signature mismatch".
set -u
source "$(dirname "$0")/../lib/common.sh"

# Time-salted across two octets so the IP is almost certainly not
# in Bloom from a prior run (otherwise first-sight-ip doesn't fire
# and the score stays in pass tier, so no challenge is served).
t=$(date +%s)
fresh_ip="203.1.$(( (t / 256) % 250 + 1 )).$(( t % 250 + 1 ))"

# 1. Get a silent-tier challenge (Mozilla UA + missing AL +
#    first-sight-ip = score 20).
html=$(mktemp)
bs_curl -o "$html" -A "Mozilla/5.0 (X11) Chrome/145" \
  -H "X-Forwarded-For: $fresh_ip" "$BASE/"

ch=$(grep -oE 'window\.__bsChallenge=\{[^;]+' "$html" | sed 's/^window\.__bsChallenge=//')
rm -f "$html"

if [[ -z "$ch" ]]; then
  t_skip "fresh IP didn't reach silent/form/captcha tier — can't produce a challenge"
fi

# 2. Solve PoW + build cookie
dir="$(cd "$(dirname "$0")/.." && pwd)"
valid=$(printf "%s" "$ch" | "$dir/tools/solve_pow.py") || \
  t_fail "PoW solver failed"

# 3. Confirm the valid cookie round-trips (sanity for the tampered test)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -H "X-Forwarded-For: $fresh_ip" \
  -b "_bs_verified=$valid" "$BASE/"
if grep -qi "^X-Botshield: challenge" "$hdr"; then
  cat "$hdr"; rm -f "$hdr" "$body"
  t_fail "sanity check: valid cookie was rejected, can't test tampered"
fi
rm -f "$hdr" "$body"
t_pass "sanity: valid cookie replays cleanly"

# 4. Tamper with the HMAC signature. The cookie payload is base64
#    of "v|alg|salt|nonce|diff|exp|score|flags|ps|pf|pc|ca|auto|sighex|counter".
#    Decode, flip one hex char in the signature (field 13 after split
#    on '|'), re-encode. The signature is 64 hex chars.
tampered=$(python3 <<PYEOF
import base64, sys
raw = base64.b64decode("$valid").decode()
fields = raw.split("|")
sig = list(fields[13])
# Flip one hex char: 'a' -> 'b', 'b' -> 'a', etc.
sig[0] = 'b' if sig[0] == 'a' else 'a'
fields[13] = "".join(sig)
print(base64.b64encode("|".join(fields).encode()).decode(), end="")
PYEOF
)

mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" \
  -A "Mozilla/5.0 (X11) Chrome/145" -H "Accept-Language: en-US" \
  -H "X-Forwarded-For: $fresh_ip" \
  -b "_bs_verified=$tampered" "$BASE/"
rm -f "$hdr" "$body"

# Assert the log shows the cookie was rejected with "signature mismatch"
slice=$(log_slice "$mark")
if ! grep -q "_bs_verified rejected: signature mismatch" "$slice"; then
  echo "--- slice tail ---"
  tail -5 "$slice"
  rm -f "$slice"
  t_fail "tampered cookie didn't produce 'signature mismatch' log"
fi
rm -f "$slice"
t_pass "tampered cookie rejected with signature mismatch"
