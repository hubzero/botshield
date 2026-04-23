#!/bin/bash
# integration/m5_1_flagged_ip — hit /admin/.env to land an honeypot
# flag on an XFF IP, then hit / from the same IP, assert the second
# request's decision carries reason="flagged-ip".
#
# Also verifies the rollback-resistance property: the flag lives in
# SHM, not the cookie, so a client without a cookie still gets the
# flag penalty on subsequent requests.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Random IP so test is safe to re-run (each run flags a new slot
# rather than reusing a possibly-stale one from the state file).
ip="198.51.100.$((100 + RANDOM % 150))"

mark=$(log_mark)

# 1. Trip the honeypot scope
bs_curl -o /dev/null -H "X-Forwarded-For: $ip" "$BASE/admin/.env" > /dev/null

# The honeypot write goes through the flagged-IP mutex path. Give it
# a moment so the next request reliably reads the freshly-written
# slot.
sleep 1

# 2. Hit / from the same IP
bs_curl -o /dev/null -H "X-Forwarded-For: $ip" "$BASE/" > /dev/null

slice=$(log_slice "$mark")

# Assert we see a decision line with reason containing flagged-ip,
# from our specific IP, AFTER the honeypot hit.
if ! grep "mod_botshield: decision " "$slice" | \
     grep "ip=$ip" | grep -q "flagged-ip"; then
  echo "--- log slice (tail) ---"
  tail -20 "$slice"
  rm -f "$slice"
  t_fail "no decision line with reason='flagged-ip' for ip=$ip after honeypot"
fi
rm -f "$slice"
t_pass "honeypot write propagates to subsequent request's flagged-ip signal"
