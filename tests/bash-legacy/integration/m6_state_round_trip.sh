#!/bin/bash
# integration/m6_state_round_trip — flag an IP, restart apache, assert
# the flag is still present after the state file is loaded.
#
# Needs root to restart apache. Test is self-cleaning — the flag
# entry carries a 1-hour TTL and will expire naturally; we don't
# need to scrub the state file afterward.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Pick an IP unlikely to already be flagged.
ip="198.51.100.$((200 + RANDOM % 55))"

# 1. Trip the honeypot (writes to SHM + will be saved on pconf cleanup)
bs_curl -o /dev/null -H "X-Forwarded-For: $ip" "$BASE/admin/.env" > /dev/null
sleep 1

# 2. Confirm the flag is live via the decision log (a subsequent
#    request should carry flagged-ip).
bs_curl -o /dev/null -H "X-Forwarded-For: $ip" "$BASE/" > /dev/null
slice1=$(log_slice "$(log_mark)")
# (^ slice1 is meaningless — we're just refreshing shm sync)
rm -f "$slice1"

# 3. Record a baseline: how many flagged entries are kept right now?
before=$(metrics_snapshot)
used_before=$(metrics_value "$before" botshield_shm_flagged_used)
rm -f "$before"

# 4. Restart apache. State file is written on pconf cleanup (old
#    process), read in the new parent's post_config.
sudo systemctl restart apache2
sleep 2

# 5. After restart: same IP should still be flagged.
mark=$(log_mark)
bs_curl -o /dev/null -H "X-Forwarded-For: $ip" "$BASE/" > /dev/null
slice=$(log_slice "$mark")

if ! grep "mod_botshield: decision " "$slice" | \
     grep "ip=$ip" | grep -q "flagged-ip"; then
  tail -5 "$slice"
  rm -f "$slice"
  t_fail "flag for $ip did not survive restart via state file"
fi
rm -f "$slice"
t_pass "flag for $ip round-tripped through state file across restart"

# 6. Verify the state-load log line names a non-zero 'kept' value
kept=$(sudo tail -n 50 "$APACHE_ERROR_LOG" | \
       grep "state loaded" | tail -1 | grep -oE "kept [0-9]+" | awk '{print $2}')
if [[ -z "$kept" || "$kept" -lt 1 ]]; then
  t_fail "state loaded with kept=${kept:-0}, expected >=1"
fi
t_pass "state-load log shows kept=$kept (≥ 1 flagged entry preserved)"

# 7. Gauge reflects it too
after=$(metrics_snapshot)
used_after=$(metrics_value "$after" botshield_shm_flagged_used)
rm -f "$after"
if [[ -z "$used_after" || "$used_after" -lt 1 ]]; then
  t_fail "/metrics botshield_shm_flagged_used=${used_after:-0}, expected >=1"
fi
t_pass "shm_flagged_used gauge reflects the restored flag ($used_after entries)"
