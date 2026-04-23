#!/bin/bash
# integration/m5_2_bloom_first_sight — the rotating Bloom filter's
# first-sight penalty. Fresh IP should pick up the first-sight-ip
# reason; a repeat hit from the same IP should NOT.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Time-salted across two octets so the IP is Bloom-fresh every
# run. ($RANDOM is only 0-32767 and reseeds per shell; with
# frequent runs and a Bloom window of days, eventually a re-run
# would pick an already-seen IP and fail the first-sight-ip check.)
t=$(date +%s)
ip="203.2.$(( (t / 256) % 250 + 1 )).$(( t % 250 + 1 ))"

# Use python-requests UA so the heuristic total is high enough to
# challenge (pushing the decision into silent/form, which is where
# first-sight-ip gets evaluated). Without a challenge we don't feed
# Bloom at all; the penalty is only computed on cookieless/sig-
# mismatch paths that reach the scoring block.
ua="python-requests/2.31"

mark=$(log_mark)

# First hit
bs_curl -o /dev/null -A "$ua" -H "X-Forwarded-For: $ip" "$BASE/" > /dev/null

# Second hit from the SAME IP
bs_curl -o /dev/null -A "$ua" -H "X-Forwarded-For: $ip" "$BASE/" > /dev/null

slice=$(log_slice "$mark")
lines=$(grep "mod_botshield: decision " "$slice" | grep "ip=$ip")
first_line=$(echo "$lines" | head -1)
second_line=$(echo "$lines" | tail -1)
rm -f "$slice"

if [[ -z "$first_line" || -z "$second_line" || "$first_line" == "$second_line" ]]; then
  t_fail "expected two decision lines for ip=$ip, got:\n$lines"
fi

if ! echo "$first_line" | grep -q "first-sight-ip"; then
  echo "  first line: $first_line"
  t_fail "first hit should carry first-sight-ip in reasons"
fi
t_pass "first hit from fresh IP → first-sight-ip in reasons"

if echo "$second_line" | grep -q "first-sight-ip"; then
  echo "  second line: $second_line"
  t_fail "second hit should NOT carry first-sight-ip (Bloom already has it)"
fi
t_pass "second hit from same IP → first-sight-ip cleared"
