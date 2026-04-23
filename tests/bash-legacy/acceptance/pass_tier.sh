#!/bin/bash
# acceptance/pass_tier — the happy path. A plausible-looking browser
# with a plausible header set arrives at /, gets no interstitial, and
# receives origin content.
#
# If this test fails, every regular user is seeing a challenge — the
# module is no longer usable as a drop-in. This is the single most
# important acceptance signal.
set -u
source "$(dirname "$0")/../lib/common.sh"

# A "normal user" IP: time-salted so it's Bloom-fresh (but we don't
# care — the other heuristics should keep us below the silent
# threshold regardless). Two octets of salt so repeat runs don't
# collide.
t=$(date +%s)
ip="198.18.$(( (t / 256) % 250 + 1 )).$(( t % 250 + 1 ))"

mark=$(log_mark)
hdr=$(mktemp); body=$(mktemp)
bs_curl_split "$hdr" "$body" \
  -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "X-Forwarded-For: $ip" \
  "$BASE/"

# No challenge header = no interstitial served.
if grep -qi "^X-Botshield: challenge" "$hdr"; then
  echo "--- headers ---"; cat "$hdr"
  rm -f "$hdr" "$body"
  t_fail "browser-like request got a challenge — pass tier is broken"
fi

assert_status "$hdr" "200"
rm -f "$hdr" "$body"
t_pass "browser-like request → 200, no challenge"

# Confirm the decision log agrees: tier=pass outcome=declined.
slice=$(log_slice "$mark")
if ! grep -E "mod_botshield: decision " "$slice" | grep "ip=$ip " | grep -q "tier=pass .*outcome=declined"; then
  echo "--- decision lines for this IP ---"
  grep "ip=$ip" "$slice" || echo "(none)"
  rm -f "$slice"
  t_fail "expected tier=pass outcome=declined in decision log for ip=$ip"
fi
rm -f "$slice"
t_pass "decision log: tier=pass outcome=declined"
