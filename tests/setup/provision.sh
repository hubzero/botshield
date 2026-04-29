#!/bin/bash
# tests/setup/provision.sh — one-shot idempotent setup.
#
# Brings a freshly-installed Ubuntu/Debian box to a state where
# `tests/run` works:
#   - apt packages for build + runtime + test deps
#   - /etc/botshield/ with the secret files tests need (0600)
#   - /etc/ssl/botshield-dev/ with a self-signed cert
#   - /var/lib/botshield/ for the state file
#   - dev vhost installed + enabled, mod_botshield built + enabled
#   - mod_status + mod_remoteip enabled
#   - mpm_event selected (tests assume threaded MPM by default; the
#     mpm matrix test switches as needed)
#
# Idempotent: safe to re-run. Won't overwrite existing secrets
# (it only creates them if they're missing), so if you've set up
# real provider keys for testing, this won't stomp them.
#
# Usage:  sudo tests/setup/provision.sh
# Idempotent: can be run repeatedly without damage.

set -eu

if [[ $EUID -ne 0 ]]; then
  echo "provision.sh must be run as root (use sudo)." >&2
  exit 1
fi

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

echo "== apt packages =="
apt-get update -qq
apt-get install -y -qq \
  apache2 apache2-dev \
  libssl-dev libcurl4-openssl-dev libjson-c-dev \
  libpcre2-dev \
  python3 python3-venv \
  curl openssl >/dev/null

echo "== module build + install =="
cd "$REPO"

# Security review LOW #17 — between `sudo -u $SUDO_USER make` and the
# subsequent `make install` (as root) there's a window where the
# build outputs (src/.libs/mod_botshield.so, src/mod_botshield.la,
# Makefile, .ltargets) sit in $REPO. If $REPO is group- or
# world-writable, an unrelated user on the box can swap the .so for
# a payload between the build and install steps, and `make install`
# carries that payload to /usr/lib/apache2/modules/ as root.
#
# Refuse to proceed if the source tree or its parent is writable by
# anyone other than $SUDO_USER. Single-tenant dev boxes pass; shared
# boxes have to lock down the repo perms first. This is a tripwire,
# not a complete fix — a fully hardened build/install would copy
# source into a root-only staging dir before building. That's a
# bigger restructure; this check catches the most common footgun.
_chk_path_safe() {
    local p="$1"
    while [[ "$p" != "/" ]]; do
        # Bail if any ancestor is writable by group or others.
        if [[ -d "$p" ]]; then
            local mode
            mode=$(stat -c '%a' "$p")
            local g=$(( (mode / 10) % 10 ))
            local o=$(( mode % 10 ))
            if (( (g & 2) != 0 || (o & 2) != 0 )); then
                echo "provision.sh: refusing to build — '$p' is " \
                     "group- or world-writable (mode $mode). On a " \
                     "shared dev box this lets another user inject " \
                     "binaries into 'make install' as root. " \
                     "chmod o-w,g-w '$p' (and any parents) and re-run." >&2
                exit 1
            fi
        fi
        p=$(dirname "$p")
    done
}
_chk_path_safe "$REPO"

sudo -u "$SUDO_USER" make clean >/dev/null || true
sudo -u "$SUDO_USER" make >/dev/null
make install >/dev/null

printf "LoadModule botshield_module /usr/lib/apache2/modules/mod_botshield.so\n" \
  > /etc/apache2/mods-available/botshield.load
a2enmod botshield status remoteip ssl headers rewrite >/dev/null
# Ensure threaded MPM by default
if [[ ! -e /etc/apache2/mods-enabled/mpm_event.load ]]; then
  a2dismod mpm_prefork mpm_worker 2>/dev/null || true
  a2enmod mpm_event >/dev/null
fi

echo "== /etc/ssl/botshield-dev self-signed cert =="
install -d -m 755 /etc/ssl/botshield-dev
if [[ ! -s /etc/ssl/botshield-dev/server.crt ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=localhost" \
    -keyout /etc/ssl/botshield-dev/server.key \
    -out   /etc/ssl/botshield-dev/server.crt \
    >/dev/null 2>&1
  chmod 600 /etc/ssl/botshield-dev/server.key
  chmod 644 /etc/ssl/botshield-dev/server.crt
fi

echo "== /etc/botshield secrets (0600) =="
install -d -m 755 /etc/botshield
# The HMAC secret for cookie signing — generate once if absent.
if [[ ! -s /etc/botshield/secret ]]; then
  openssl rand -hex 32 > /etc/botshield/secret
  chmod 600 /etc/botshield/secret
fi

# Provider dummy secrets. Each is publicly-documented by the provider
# (Turnstile/hCaptcha/reCAPTCHA v2) or a placeholder string (Friendly,
# GeeTest, reCAPTCHA v3). Tests that need REAL secrets read them from
# env vars rather than these files.
install_secret() {
  local path="$1" content="$2"
  [[ -s "$path" ]] && return 0
  printf "%s" "$content" > "$path"
  chmod 600 "$path"
}
install_secret /etc/botshield/turnstile-secret       "1x0000000000000000000000000000000AA"
install_secret /etc/botshield/hcaptcha-secret        "0x0000000000000000000000000000000000000000"
install_secret /etc/botshield/recaptcha-v2-secret    "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
install_secret /etc/botshield/recaptcha-v3-secret    "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
install_secret /etc/botshield/friendly-secret        "FRIENDLYCAPTCHA_FREE_TIER_SECRET_REPLACE_ME_WITH_REAL"
install_secret /etc/botshield/geetest-secret         "GEETEST_CAPTCHA_KEY_REPLACE_WITH_REAL_FROM_DASHBOARD"
# Always-fail variants for test_captcha_rejected_via_bad_secret. These
# are well-formed values the provider deliberately rejects (Turnstile
# publishes 2x000... as the always-fail pair to 1x000...AA always-pass;
# reCAPTCHA v2 has no published always-fail key, so we use a malformed
# string that fails siteverify cleanly without crashing the validator).
install_secret /etc/botshield/turnstile-fail-secret  "2x0000000000000000000000000000000AA"
install_secret /etc/botshield/recaptcha-v2-badsecret "this-is-not-a-real-recaptcha-secret-aaaaaa"
# Shared HMAC key for both directions of app integration: app→module
# feedback envelopes and module→app X-Botshield-Claims headers. The
# two protocols' canonical forms are structurally distinct (single-
# field vs seven-field) so cross-replay isn't possible, and one key
# fits both directions. Fixed value here so pytest can recompute and
# verify signatures with the same bytes. 64 hex chars = 32 bytes,
# well above BS_MIN_SECRET_BYTES.
install_secret /etc/botshield/app-integration-secret \
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
# Clean up legacy app-feedback/-claims secret files from pre-
# consolidation provisions. The directives that referenced them are
# gone; leftover files are harmless but confusing on inspection.
rm -f /etc/botshield/app-feedback-secret /etc/botshield/app-claims-secret

echo "== /var/lib/botshield (state file dir) =="
install -d -m 750 -o www-data -g www-data /var/lib/botshield

echo "== docroot path traversability for www-data =="
# Apache runs as www-data; the dev vhost serves files out of the
# checkout (${BS_REPO}/tests/site/). For Apache to read those, every
# ancestor directory needs the +x (traversal) bit for OTHERS.
#
# On a developer box this is usually already true — /home/<user>/
# defaults to 0755 or 0750. On GitHub Actions runners /home/runner/
# is 0700 by default, which means www-data gets EACCES on every
# request and Apache 403s before the file handler can serve. Walk
# up from $REPO and add o+x to each ancestor (idempotent).
parent="$REPO"
while [[ "$parent" != "/" ]]; do
    chmod o+x "$parent" 2>/dev/null || true
    parent=$(dirname "$parent")
done

echo "== dev vhost =="
# The vhost references this checkout via ${BS_REPO}; set the variable
# to *this* clone's path before the vhost is included so docroot,
# Alias, and BotShield* file references resolve correctly. Lives in
# conf-available/ as a one-line file Apache loads before sites-*.
cat > /etc/apache2/conf-available/botshield-repo.conf <<EOF
# Auto-generated by tests/setup/provision.sh — points the dev vhost
# at this checkout. Override by editing this file or by setting
# BS_REPO via /etc/apache2/envvars before re-running provision.sh.
Define BS_REPO $REPO
EOF
a2enconf botshield-repo >/dev/null
cp "$REPO/apache/botshield-dev.conf" /etc/apache2/sites-available/
a2dissite 000-default 2>/dev/null || true
a2ensite botshield-dev >/dev/null

echo "== configtest + reload =="
apachectl configtest
systemctl reload apache2 || systemctl start apache2
sleep 1

echo "== tests/.venv (pytest framework, M11.4+) =="
# Create an isolated venv owned by the unprivileged user so the test
# suite can install + import the framework without leaking into
# system site-packages. Idempotent: if the venv already exists, we
# just reinstall requirements (cheap on the pinned versions).
VENV="$REPO/tests/.venv"
if [[ ! -d "$VENV" ]]; then
  sudo -u "$SUDO_USER" python3 -m venv "$VENV"
fi
sudo -u "$SUDO_USER" "$VENV/bin/pip" install --upgrade pip --quiet
sudo -u "$SUDO_USER" "$VENV/bin/pip" install \
  -r "$REPO/tests/requirements-test.txt" --quiet
sudo -u "$SUDO_USER" "$VENV/bin/pip" install -e "$REPO/tests" --quiet

echo "== Chromium for Playwright (M11.6) =="
# Playwright ships chromium binaries into ~/.cache/ms-playwright. The
# browser needs a handful of shared libs that aren't always on a
# minimal Ubuntu (Chromium's install-deps would normally pull them,
# but doing it explicitly via apt keeps the install idempotent and
# diff-able). Minimal set that matches a bare ubuntu-24.04 runner.
apt-get install -y -qq \
  libnss3 libnspr4 \
  libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
  libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64 \
  fonts-liberation \
  >/dev/null 2>&1 \
  || apt-get install -y -qq \
       libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
       libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
       libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
       fonts-liberation >/dev/null
# Install the chromium binary itself into the user's cache. Idempotent:
# already-present versions are skipped.
sudo -u "$SUDO_USER" "$VENV/bin/playwright" install chromium >/dev/null

echo "== /etc/botshield/load.state.test (E11.1 test staging) =="
# Same Apache-PrivateTmp workaround as test-robots: PrivateTmp=true
# isolates /tmp away from the test user, so we stage the file under
# /etc/botshield where the test user can write and Apache can read.
# Initial value `normal` so the watchdog finds the file present and
# valid even when no test is actively manipulating it.
install -m 664 -o "$SUDO_USER" -g www-data /dev/stdin \
    /etc/botshield/load.state.test <<< "normal"

echo "== /etc/botshield/test-robots (E2.2 test staging) =="
# Apache's systemd unit sets PrivateTmp=true, which gives the apache2
# process its own isolated /tmp. Files we'd normally stash under /tmp
# are invisible to Apache. Give the E2.2 test suite a non-sandboxed
# directory where the unprivileged test user can drop robots.txt
# fixtures that www-data can read. Uses /etc/botshield/ (world-
# traversable via /etc) rather than /var/lib/botshield/ (0750, not
# traversable by the test user). 0775 with the test user owning and
# www-data in the group lets both sides work without further sudo.
install -d -m 775 -o "$SUDO_USER" -g www-data /etc/botshield/test-robots

echo "== /var/lib/botshield/bots seed =="
# E1 — Allow family (verified-bot). Seed /var/lib/... from the
# bundled apache/bots/*.txt if nothing's there yet. Never stomps
# existing files: once the operator wires tools/refresh-bot-ranges.sh
# into cron, the refreshed files take over and this step is a no-op.
install -d -m 755 -o www-data -g www-data /var/lib/botshield/bots
for f in "$REPO"/apache/bots/*.txt; do
  [[ -f "$f" ]] || continue
  dest="/var/lib/botshield/bots/$(basename "$f")"
  if [[ ! -s "$dest" ]]; then
    install -m 644 -o www-data -g www-data "$f" "$dest"
  fi
done

echo ""
echo "provision.sh: OK — tests/run is ready."
