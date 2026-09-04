#!/bin/bash
# tests/setup/reset-state.sh — between-run state reset.
#
# Wipes the state file, restarts Apache. Counters reset because SHM
# is bound to pconf and Apache recreates it on restart; Bloom +
# flagged-IP tables also reset (empty state file → empty tables).
#
# Tests that need a known-clean starting point can `exec` this before
# any other work. Most tests don't need it — they work from a log
# mark + metrics snapshot, asserting deltas rather than absolute
# values.
#
# Usage:  sudo tests/setup/reset-state.sh

set -eu

if [[ $EUID -ne 0 ]]; then
  echo "reset-state.sh must be run as root (use sudo)." >&2
  exit 1
fi

# Both of these were hardcoded, and the state path was the PRODUCTION
# one: /var/lib/botshield/state.bin, not the test instance's. Run as
# root on a host that serves a real site -- which is exactly the host
# this script exists for -- it deleted live state rather than test
# state. Nothing is lost while the server stays up, since the module
# holds its tables in shared memory and rewrites the file on the next
# periodic save, but a restart in that window would have started the
# site with an empty flagged-IP table and Bloom filter.
#
# Now both are parameters, and the defaults follow the platform rather
# than assuming Debian.
if [[ -e /usr/sbin/httpd ]]; then
  DEFAULT_SERVICE=httpd-bstest
  DEFAULT_STATE=/var/lib/botshield-test/state.bin
else
  DEFAULT_SERVICE=apache2
  DEFAULT_STATE=/var/lib/botshield/state.bin
fi
SERVICE="${BS_APACHE_SERVICE:-$DEFAULT_SERVICE}"
STATE="${BS_STATE_FILE:-$DEFAULT_STATE}"

# Refuse to touch a live server's state. This script resets a TEST
# instance; if it is pointed at production, that is a mistake worth
# stopping rather than performing.
case "$SERVICE" in
  httpd|apache2)
    echo "reset-state.sh: refusing to reset '$SERVICE' -- that is the live" >&2
    echo "  server. Set BS_APACHE_SERVICE to the test instance." >&2
    exit 2 ;;
esac

echo "resetting $STATE and restarting $SERVICE"
rm -f "$STATE"
systemctl restart "$SERVICE"
sleep 1
