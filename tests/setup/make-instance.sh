#!/bin/bash
# Generate an isolated httpd test instance for one xdist worker.
#
# Per-worker CONFIG files are not enough on their own: every worker
# talks to the same Apache, so one worker's config_override still
# changes what another worker's requests see. Each worker therefore
# needs its own server process, its own ports, its own logs and its own
# BotShield state file. That is what this generates.
#
# Measured before this existed: `--parallel` interleaved two
# config_override edits into one shared dev-vhost.conf, producing
# mode='monitor', httpd refused to start, and 177 tests failed for that
# reason rather than on their own merits.
#
# Usage: make-instance.sh <n>        n = 0..7, worker index
set -euo pipefail
N="${1:?worker index required}"
[ "$N" -ge 0 ] && [ "$N" -le 7 ] || { echo "worker index must be 0..7" >&2; exit 2; }

SRC=/etc/httpd/bstest
DST="$SRC/w$N"
# 8543, not 8443: the original single-instance httpd-bstest owns 8443,
# and w0 would collide with it. Keeping the ranges disjoint means the
# two schemes can run side by side.
HTTPS=$(( 8543 + N ))
HTTP=$(( 8181 + N ))
RUNDIR="/run/httpd-bstest-w$N"
LOGDIR="/var/log/httpd/bstest/w$N"
STATE="/var/lib/botshield-test/state-w$N.bin"
# The external load-state file is read by the request path and written
# by the load-state tests. Shared across instances it makes those tests
# race; per-worker it is just another isolated input.
LOADSTATE="/etc/botshield/load.state.w$N.test"

sudo mkdir -p "$DST" "$LOGDIR" "$RUNDIR"
sudo chown apache:apache "$RUNDIR" "$LOGDIR"
# Explicit mode: root's umask is 077 on this host, so `sudo mkdir` makes
# these 700 and the test user cannot even traverse in to READ the config
# it is about to override. Same umask that broke _atomic_write.
sudo chmod 755 "$DST" "$LOGDIR"
# 0644: apache reads this on every load-refresh tick. Unlike the secret
# files, it is not sensitive and must stay world-readable.
sudo touch "$LOADSTATE" && sudo chmod 644 "$LOADSTATE"
sudo chown "$(id -u):$(id -g)" "$LOADSTATE"

# Rewrite both files together: the vhost's Listen addresses must match
# the ports the main config opened, so they cannot be templated apart.
for f in httpd.conf dev-vhost.conf; do
    sudo sed -e "s#/run/httpd-bstest\b#$RUNDIR#g" \
             -e "s#127\.0\.0\.1:8443#127.0.0.1:$HTTPS#g" \
             -e "s#127\.0\.0\.1:8081#127.0.0.1:$HTTP#g" \
             -e "s#/var/log/httpd/bstest/#$LOGDIR/#g" \
             -e "s#/var/lib/botshield-test/state\.bin#$STATE#g" \
             -e "s#/etc/botshield/load\.state\.test#$LOADSTATE#g" \
             -e "s#$SRC/dev-vhost\.conf#$DST/dev-vhost.conf#g" \
             "$SRC/$f" | sudo tee "$DST/$f" >/dev/null
done

# config_override writes the vhost file directly as the invoking user,
# not through sudo, so the generated copies must match the original's
# ownership. Left root-owned they raise PermissionError on every test
# that overrides config -- which is most of them.
sudo chown "$(id -u):$(id -g)" "$DST/dev-vhost.conf"
sudo chmod 644 "$DST/dev-vhost.conf"

sudo httpd -f "$DST/httpd.conf" -t 2>&1 | tail -1
echo "instance w$N: https=$HTTPS http=$HTTP state=$STATE conf=$DST"
