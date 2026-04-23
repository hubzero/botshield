# shellcheck shell=bash
# tests/stress/lib.sh — minimal bash helpers for the soak driver.
#
# The pytest suite has its own framework under tests/botshield_test/,
# but soak.sh is a shell script and only needs three things: the
# dev-vhost base URL, the path to the botshield error log, and a
# curl wrapper with the standard flags (self-signed cert, timeout).
#
# Kept here so the soak runner doesn't depend on the archived
# tests/bash-legacy/lib/common.sh. Everything else soak needs
# (Python load generator, analyzer) is already self-contained.

BASE="${BS_BASE:-https://localhost}"
ERROR_LOG="${BS_ERROR_LOG:-/var/log/apache2/botshield-dev-error.log}"

bs_curl() {
  curl -sk --max-time 10 "$@"
}
