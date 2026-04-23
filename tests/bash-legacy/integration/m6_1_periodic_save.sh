#!/bin/bash
# integration/m6_1_periodic_save — confirm the mod_watchdog periodic
# save fires on the 30s interval configured in the dev vhost.
#
# The dev vhost sets BotShieldStateSaveInterval 30 specifically so
# this test is tractable. If that's been changed, the test skips
# rather than waits forever.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Verify the dev config sets the interval to something reasonably
# short. If it's at the 300s default, the test would take too long.
interval=$(grep -E "^\s*BotShieldStateSaveInterval" \
           /etc/apache2/sites-available/botshield-dev.conf | \
           awk '{print $2}' | head -1)
if [[ -z "$interval" || "$interval" -gt 60 ]]; then
  t_skip "BotShieldStateSaveInterval is ${interval:-unset}; want <=60 for this test"
fi

# Record baseline: current state_saves_total counter.
before=$(metrics_snapshot)
saves_before=$(metrics_value "$before" botshield_state_saves_total)
rm -f "$before"

# Drive a flagged-IP write so there's something worth saving.
bs_curl -o /dev/null -H "X-Forwarded-For: 198.51.100.250" \
  "$BASE/admin/.env" > /dev/null

# Wait for one periodic cycle plus a little slack for the watchdog
# to emit. Slack = 10s.
echo "  waiting $(( interval + 10 ))s for periodic save to fire..."
sleep $(( interval + 10 ))

after=$(metrics_snapshot)
saves_after=$(metrics_value "$after" botshield_state_saves_total)
rm -f "$after"

delta=$(( saves_after - saves_before ))
if [[ "$delta" -lt 1 ]]; then
  t_fail "state_saves_total delta=$delta after waiting $(( interval + 10 ))s (expected ≥1)"
fi
t_pass "periodic save fired $delta time(s) in $(( interval + 10 ))s window"

# Also confirm the most recent save log mentions a non-zero duration
# (catches the regression where apr_time_now rollback produced
# negative durations pre-M10.1).
latest_dur=$(sudo tail -n 20 "$APACHE_ERROR_LOG" | \
             grep -oE "state saved to .* \(.*, [0-9-]+ us\)" | tail -1 | \
             grep -oE "[0-9-]+ us" | awk '{print $1}')
if [[ -z "$latest_dur" ]]; then
  t_fail "no 'state saved' line found with a duration"
fi
if [[ "$latest_dur" -lt 0 ]]; then
  t_fail "state-save duration is negative ($latest_dur us) — clock rollback not clamped"
fi
t_pass "periodic-save duration is non-negative ($latest_dur us)"
