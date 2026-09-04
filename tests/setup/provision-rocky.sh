#!/bin/bash
# Provision an isolated httpd test instance on RHEL-family (Rocky).
#
# Replaces the prose in bstest-setup.md, which described this by hand and
# whose steps had to be followed correctly for the suite to work at all.
# It is also what lets CI run on the platform production actually uses:
# a container starts with nothing, so every path this creates had to
# become a script before a Rocky runner had anything to talk to.
#
# Touches nothing belonging to a live server. Separate ports, config,
# logs, state and module binary throughout -- the module installs as
# mod_botshield-test.so precisely so a running production instance keeps
# loading its own.
#
# Usage:
#   sudo tests/setup/provision-rocky.sh [--prefix DIR] [--https N] [--http N]
#
# Defaults to /etc/httpd/bstest on 8443/8081, which is what the test
# harness looks for.
set -euo pipefail

PREFIX=/etc/httpd/bstest
HTTPS_PORT=8443
HTTP_PORT=8081
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --https)  HTTPS_PORT="$2"; shift 2 ;;
    --http)   HTTP_PORT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

NAME="$(basename "$PREFIX")"
LOGDIR="/var/log/httpd/$NAME"
RUNDIR="/run/httpd-$NAME"
STATEDIR="/var/lib/botshield-test"
DOCROOT="/var/www/${NAME}-repo"
LOADSTATE="/etc/botshield/load.state.test"
MODULE_DIR="$(apxs -q LIBEXECDIR)"

say() { printf '  %s\n' "$*"; }

# --- packages -----------------------------------------------------------
# Only when something is missing: in a container this is the slow step,
# and on a developer's box it is usually a no-op.
need=()
command -v httpd  >/dev/null || need+=(httpd)
command -v apxs   >/dev/null || need+=(httpd-devel)
command -v gcc    >/dev/null || need+=(gcc)
command -v make   >/dev/null || need+=(make)
[[ -e /usr/include/openssl/evp.h ]] || need+=(openssl-devel)
[[ -e /usr/include/curl/curl.h ]]   || need+=(libcurl-devel)
[[ -e /usr/include/json-c/json.h ]] || need+=(json-c-devel)
# The suite talks HTTPS throughout, so mod_ssl is not optional. A
# minimal image has httpd without it, and the failure is an "Invalid
# command 'SSLEngine'" that reads like a config typo.
[[ -e /etc/httpd/conf.modules.d/00-ssl.conf ]] || need+=(mod_ssl)
# Not bare python3: RHEL 8 ships 3.6 under that name and the pinned
# test dependencies need 3.9 or newer, so a bare `python3 -m venv` gets
# as far as resolving httpx before failing. Pick the newest interpreter
# present and install one only if there is nothing usable.
PYBIN=""
for candidate in python3.12 python3.11 python3.10 python3.9; do
  command -v "$candidate" >/dev/null && { PYBIN="$candidate"; break; }
done
[[ -n "$PYBIN" ]] || need+=(python3.11)
# apxs compiles with the flags httpd itself was built with, and those
# name /usr/lib/rpm/redhat/redhat-hardened-cc1. A minimal image has gcc
# but not that spec file, and the build fails on a path rather than on
# anything to do with the code.
[[ -e /usr/lib/rpm/redhat/redhat-hardened-cc1 ]] || need+=(redhat-rpm-config)
if [[ ${#need[@]} -gt 0 ]]; then
  say "installing: ${need[*]}"
  dnf install -y "${need[@]}" >/dev/null
fi
[[ -n "$PYBIN" ]] || PYBIN=python3.11
say "python: $($PYBIN --version)"

# The apache account owns the runtime dirs and reads the state files.
id apache >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin apache

# --- build and install the module under a test-only name ----------------
say "building the module"
make -C "$REPO" build >/dev/null
install -m 755 "$REPO/src/.libs/botshield.so" "$MODULE_DIR/mod_botshield-test.so"

# --- directories --------------------------------------------------------
# Explicit modes throughout. Root's umask is 077 on some hosts, which
# makes these 700, and then the unprivileged test user cannot traverse in
# to read the config it is about to rewrite -- config_override replaces
# files, so it needs write on the directory, not just the file.
install -d -m 755 "$PREFIX" "$LOGDIR" "$RUNDIR" "$STATEDIR" /etc/botshield
install -d -m 755 "$DOCROOT"
chown apache:apache "$RUNDIR" "$LOGDIR" "$STATEDIR"

# The docroot is a copy, not a symlink into the checkout: apache cannot
# traverse a developer's 0700 home directory, and the failure that
# produces is a 403 that looks like a module decision.
cp -r "$REPO/tests" "$REPO/docs" "$DOCROOT/" 2>/dev/null || true
chown -R apache:apache "$DOCROOT"

# 0644, and this one matters. The module reads it at RUNTIME as the
# apache user, not at config-parse time as root, so a blanket 0600 across
# /etc/botshield leaves the load tests timing out on a file the server
# cannot open.
touch "$LOADSTATE"; chmod 644 "$LOADSTATE"; echo normal > "$LOADSTATE"

# 0600 root-only, and the module enforces it: these are read as root at
# config-parse time, so the apache user never needs them, and anything
# looser is refused outright rather than warned about.
for secret in secret app-integration-secret; do
  [[ -s "/etc/botshield/$secret" ]] || openssl rand -hex 32 > "/etc/botshield/$secret"
  chmod 600 "/etc/botshield/$secret"; chown root:root "/etc/botshield/$secret"
done

# --- a self-signed certificate -----------------------------------------
# At the path the vhost names. That path is one of the few things in
# apache/botshield-dev.conf that is not a Define, and it does not need to
# be: a throwaway localhost certificate is the same everywhere.
CERTDIR=/etc/ssl/botshield-dev
install -d -m 755 "$CERTDIR"
if [[ ! -s "$CERTDIR/server.crt" ]]; then
  say "generating a self-signed certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
    -subj "/CN=localhost" >/dev/null 2>&1
fi
chmod 644 "$CERTDIR/server.crt"; chmod 640 "$CERTDIR/server.key"
chown root:apache "$CERTDIR/server.key"

# --- the instance config ------------------------------------------------
# Every environment-specific value is a Define, so the vhost below is the
# repository's own apache/botshield-dev.conf included unmodified. There
# is deliberately no adapted copy: the previous one drifted 156 lines
# from the original while claiming to be generated by a script that did
# not exist.
cat > "$PREFIX/httpd.conf" <<EOF
# Generated by tests/setup/provision-rocky.sh -- edit that, not this.
ServerRoot /etc/httpd
ServerName localhost
PidFile $RUNDIR/httpd.pid
DefaultRuntimeDir $RUNDIR

Listen 127.0.0.1:$HTTP_PORT
Listen 127.0.0.1:$HTTPS_PORT https

# The base module set, but NOT conf.modules.d/30-botshield.conf: that
# loads the production build, and a test for a directive the working
# tree just added would assert against the old one.
IncludeOptional conf.modules.d/0*.conf
IncludeOptional conf.modules.d/1*.conf
LoadModule botshield_module modules/mod_botshield-test.so

User apache
Group apache
ErrorLog $LOGDIR/error.log
LogLevel warn
TypesConfig /etc/mime.types

# The suite addresses clients by X-Forwarded-For, which is how one test
# run reaches the module as a thousand different visitors.
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 127.0.0.1

<Directory />
    AllowOverride None
    Require all denied
</Directory>

ExtendedStatus On
<Location "/server-status">
    SetHandler server-status
    Require ip 127.0.0.1
</Location>

# Server scope on purpose. The load watchdog and the state file are read
# once against the main server_rec; inside a vhost the module rejects
# them outright now, but the rule is easier to follow than to debug.
BotShieldDecisionLog $LOGDIR/botshield.log
BotShieldLoadStateFile $LOADSTATE
BotShieldLoadRefreshInterval 1
BotShieldStateFile $STATEDIR/state.bin

Define BS_REPO $DOCROOT
Define APACHE_LOG_DIR $LOGDIR
Define BS_HTTP 127.0.0.1:$HTTP_PORT
Define BS_HTTPS 127.0.0.1:$HTTPS_PORT

IncludeOptional $PREFIX/dev-vhost.conf
EOF

cp "$REPO/apache/botshield-dev.conf" "$PREFIX/dev-vhost.conf"
chmod 644 "$PREFIX/httpd.conf" "$PREFIX/dev-vhost.conf"

# --- the pytest virtualenv ---------------------------------------------
# tests/run treats a missing venv as a hard failure rather than a silent
# skip, on the reasoning that a test run which quietly tests nothing is
# worse than one that stops.
VENV="$REPO/tests/.venv"
if [[ ! -x "$VENV/bin/pytest" ]]; then
  say "creating the pytest venv"
  "$PYBIN" -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip >/dev/null
"$VENV/bin/pip" install --quiet -r "$REPO/tests/requirements-test.txt" >/dev/null
say "pytest venv ready"

say "checking the generated config"
httpd -f "$PREFIX/httpd.conf" -t

say "provisioned $PREFIX on https://127.0.0.1:$HTTPS_PORT"
say "start it with: httpd -f $PREFIX/httpd.conf -k start"
