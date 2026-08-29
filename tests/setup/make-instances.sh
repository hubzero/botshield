#!/bin/bash
# Provision and start N isolated test instances (w0..wN-1).
#
# The count matters: xdist's `-n auto` picks one worker per core, and a
# worker whose instance does not exist just gets connection refused --
# which surfaces as dozens of unrelated test failures rather than as
# "you forgot to provision". tests/run derives its -n from how many of
# these are actually running, so the two cannot drift apart.
set -euo pipefail
N="${1:-4}"
HERE="$(cd "$(dirname "$0")" && pwd)"
for ((i=0; i<N; i++)); do
    "$HERE/make-instance.sh" "$i" >/dev/null
    sudo systemctl restart "httpd-bstest@$i"
done
sleep 3
for ((i=0; i<N; i++)); do
    printf "  w%d %-8s https://localhost:%d -> %s\n" "$i" \
        "$(systemctl is-active httpd-bstest@$i)" $((8543+i)) \
        "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:$((8543+i))/botshield/dashboard || echo ERR)"
done
