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

rm -f /var/lib/botshield/state.bin
systemctl restart apache2
sleep 1
