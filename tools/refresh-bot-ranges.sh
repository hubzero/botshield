#!/bin/bash
# tools/refresh-bot-ranges.sh — pull the latest verified-bot IP
# ranges from each provider and rewrite the on-disk ranges files
# that mod_botshield's Allow family (E1) reads at startup.
#
# Designed to be run from cron. No Apache involvement — the module
# picks up new ranges at next graceful restart. If your operational
# tempo is "reload daily", just wire this to run a little before the
# reload.
#
# Usage:
#     sudo tools/refresh-bot-ranges.sh              # default dest
#     sudo tools/refresh-bot-ranges.sh /some/path   # override dest
#
# Exit code: 0 if ALL providers refreshed; 1 if any failed (others
# still refreshed). Failure is fine operationally — BotShield keeps
# reading the last good file.
#
# Covers the three providers that publish clean JSON ranges:
# Googlebot, Bingbot, Applebot. Providers that only publish via
# PTR + forward-confirm (Yandex, DuckDuck, Facebook, LinkedIn,
# Twitter) are out of scope by design — see CHANGELOG.md E1 for the
# reasoning.

set -u

DEST="${1:-/var/lib/botshield/bots}"
TMP="$(mktemp -d /tmp/bs_bot_refresh.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

# provider_name url
#
# Providers change these URLs without notice. When a refresh fails, we
# keep serving the last-good cached file — the cost of a URL rotation
# is staleness, not module breakage. Check the provider docs and update
# the URL here when that happens.
#   Google:  https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
#   Bing:    https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26
#   Apple:   https://support.apple.com/en-us/HT204683
declare -a PROVIDERS=(
  "googlebot https://developers.google.com/static/crawling/ipranges/common-crawlers.json"
  "bingbot   https://www.bing.com/toolbox/bingbot.json"
  "applebot  https://search.developer.apple.com/applebot.json"
)

mkdir -p "$DEST"

rc=0
for entry in "${PROVIDERS[@]}"; do
  name="${entry%% *}"
  url="${entry#* }"
  url="${url#"${url%%[! ]*}"}"  # trim leading spaces

  tmpfile="$TMP/$name.json"
  out="$DEST/$name.txt"

  if ! curl -sfL --max-time 10 "$url" -o "$tmpfile"; then
    echo "WARN: fetch failed for $name ($url)" >&2
    rc=1
    continue
  fi

  # Extract ipv4Prefix + ipv6Prefix out of the "prefixes" array. All
  # three providers share this shape. Writes sorted + deduplicated.
  if ! python3 -c "
import json, sys
d = json.load(open('$tmpfile'))
prefixes = sorted({
    p.get('ipv4Prefix') or p.get('ipv6Prefix')
    for p in d.get('prefixes', [])
    if (p.get('ipv4Prefix') or p.get('ipv6Prefix'))
})
if not prefixes:
    sys.exit('no prefixes in payload')
print('# refreshed by tools/refresh-bot-ranges.sh')
print('# source: $url')
print('\n'.join(prefixes))
" > "$out.new"; then
    echo "WARN: parse failed for $name" >&2
    rc=1
    rm -f "$out.new"
    continue
  fi

  # Atomic-ish rename — mv is atomic on the same filesystem.
  mv "$out.new" "$out"
  chown www-data:www-data "$out" 2>/dev/null || true
  chmod 644 "$out"
  printf "OK:   %-12s  %4d CIDRs  →  %s\n" "$name" \
    "$(grep -vc '^#' "$out")" "$out"
done

if [[ $rc -ne 0 ]]; then
  echo "one or more providers failed to refresh; existing files left in place" >&2
fi
exit $rc
