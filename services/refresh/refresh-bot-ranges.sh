#!/bin/bash
# services/bot-refresh/refresh-bot-ranges.sh — pull the latest verified-bot IP
# ranges from each provider and rewrite the on-disk ranges files
# that mod_botshield's Allow family (E1) reads at startup.
#
# Designed to be run from cron. No Apache involvement — the module
# picks up new ranges at next graceful restart. If your operational
# tempo is "reload daily", just wire this to run a little before the
# reload.
#
# Usage:
#     sudo services/bot-refresh/refresh-bot-ranges.sh              # default dest
#     sudo services/bot-refresh/refresh-bot-ranges.sh /some/path   # override dest
#
# Exit code: 0 if ALL providers refreshed; 1 if any failed (others
# still refreshed). Failure is fine operationally — BotShield keeps
# reading the last good file.
#
# Covers the three providers that publish clean JSON ranges:
# Googlebot, Bingbot, Applebot. Plus Siteimprove via HTML scrape
# of their static help-center article (no JSON feed exists; the
# page has stable section headings so structure-aware extraction
# is reasonable, with a sanity threshold to catch silent breakage).
# Providers that only publish via PTR + forward-confirm (Yandex,
# DuckDuck, Facebook, LinkedIn, Twitter) are out of scope by
# design: there is no range list to fetch, and confirming one of
# those requires a reverse lookup per request, which belongs in the
# module rather than in a refresh job. See docs/policy.md on the
# allow list.

set -u

DEST="${1:-/var/lib/botshield/bots}"

# The web server account differs by distribution: apache on RHEL-family,
# www-data on Debian-family. Hand ownership to whichever exists. These
# files only ever need to be readable, so a miss is not fatal -- the
# 0644 below already covers the module, which reads them at startup.
chown_web() {
  for _user in apache www-data; do
    if id -u "$_user" >/dev/null 2>&1; then
      chown "$_user:$_user" "$1" 2>/dev/null || true
      return
    fi
  done
}
TMP="$(mktemp -d /tmp/bs_bot_refresh.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

# provider_name url
#
# Providers change these URLs without notice. When a refresh fails, we
# keep serving the last-good cached file — the cost of a URL rotation
# is staleness, not module breakage. Check the provider docs and update
# the URL here when that happens.
#   Google:           https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
#   GoogleOther/...:  same docs page, "Special-case crawlers" section.
#                     Same JSON pool covers GoogleOther, GoogleProducer,
#                     AdsBot, etc.; the allowlist matches only on the
#                     "GoogleOther" UA token, so our ranges file labels
#                     itself "googleother" even though the underlying
#                     payload covers the broader family.
#   Bing:             https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26
#   Apple:            https://support.apple.com/en-us/HT204683
declare -a PROVIDERS=(
  "googlebot   https://developers.google.com/static/crawling/ipranges/common-crawlers.json"
  "googleother https://developers.google.com/static/crawling/ipranges/special-crawlers.json"
  "bingbot     https://www.bing.com/toolbox/bingbot.json"
  "applebot    https://search.developer.apple.com/applebot.json"
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
print('# refreshed by services/bot-refresh/refresh-bot-ranges.sh')
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
  chown_web "$out"
  chmod 644 "$out"
  printf "OK:   %-12s  %4d CIDRs  →  %s\n" "$name" \
    "$(grep -vc '^#' "$out")" "$out"
done

# --- Siteimprove (HTML scrape, no JSON feed available) -----------------
#
# Siteimprove publishes their crawler IPs on a static help-center
# article. Page structure: multiple <h3> sections, of which only one
# (containing "crawler" in the header) is the site-scanning crawler IPs
# we want — others are analytics, performance monitoring, email
# delivery, etc., which run from different infra and shouldn't share
# a verified-bot IP allowlist with the crawler.
#
# Best-effort: keep the last-good file on any failure (parse,
# fetch, structure-changed). Sanity threshold of 30 IPs catches
# silent breakage if the page is redesigned and our section-
# detection misses the crawler block.
#
#   Source: https://help.siteimprove.com/support/solutions/articles/80000448553

SI_URL="https://help.siteimprove.com/support/solutions/articles/80000448553-what-ip-addresses-and-user-agents-are-used-by-siteimprove-"
SI_HTML="$TMP/siteimprove.html"
SI_OUT="$DEST/siteimprove.txt"

if curl -sfL --max-time 10 -A "mod_botshield/refresh-bot-ranges" \
       "$SI_URL" -o "$SI_HTML"; then
  if python3 - "$SI_HTML" "$SI_URL" > "$SI_OUT.new" <<'PY'
import sys, re, ipaddress
from html.parser import HTMLParser

# Streaming HTML parser. Tracks h2-level section boundaries; collects
# body text only while the most-recent <h2> mentions "crawler". h3+
# subsections are ignored as boundaries (the page nests "Content
# suite IP addresses" / "Content suite user agents" under the
# crawler h2). The "crawler" substring on h2 is the stable identifier
# we anchor on — page has used "Content suite crawler ..." for
# years; "crawler" alone scopes to that h2 unambiguously.
class CrawlerSection(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_h2 = False
        self.h2_buf = []
        self.target = False
        self.body = []
    def handle_starttag(self, tag, attrs):
        if tag == "h2":
            self.in_h2 = True
            self.h2_buf = []
            # entering a new h2 ends the previous section
            self.target = False
    def handle_endtag(self, tag):
        if tag == "h2" and self.in_h2:
            self.in_h2 = False
            self.target = "crawler" in "".join(self.h2_buf).lower()
    def handle_data(self, data):
        if self.in_h2:
            self.h2_buf.append(data)
        elif self.target:
            self.body.append(data)

html = open(sys.argv[1]).read()
url = sys.argv[2]
p = CrawlerSection()
p.feed(html)
text = "".join(p.body)

# Plain IPv4 / CIDR — Siteimprove publishes single hosts, no CIDRs,
# but the regex tolerates either form in case they consolidate.
# Digit-boundary lookarounds (not \b) because the page emits some IPs
# directly adjacent to letters (e.g. "...35.156.240.123Content suite..."
# with no whitespace between the IP and the next h3's first character) —
# \b doesn't fire between a digit and a letter (both are word chars), so
# the trailing IP would be silently skipped.
pattern = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?!\d)")
ips = set()
for m in pattern.finditer(text):
    try:
        net = ipaddress.ip_network(m.group(0), strict=False)
        # Skip RFC1918 / loopback / link-local — never legit crawler.
        if net.is_private or net.is_loopback or net.is_link_local:
            continue
        ips.add(str(net) if "/" in m.group(0) else str(net.network_address))
    except ValueError:
        pass

if len(ips) < 30:
    sys.exit(f"only {len(ips)} crawler IPs parsed (threshold 30); "
             f"page structure likely changed - inspect manually")

print("# refreshed by services/bot-refresh/refresh-bot-ranges.sh")
print(f"# source: {url}")
print(f"# count:  {len(ips)} entries (parsed from 'Crawler' section)")
for ip in sorted(ips, key=lambda s: ipaddress.ip_network(s, strict=False)
                                                 .network_address.packed):
    print(ip)
PY
  then
    mv "$SI_OUT.new" "$SI_OUT"
    chown_web "$SI_OUT"
    chmod 644 "$SI_OUT"
    printf "OK:   %-12s  %4d CIDRs  →  %s\n" "siteimprove" \
      "$(grep -vc '^#' "$SI_OUT")" "$SI_OUT"
  else
    echo "WARN: parse failed for siteimprove (HTML structure change?)" >&2
    rm -f "$SI_OUT.new"
    rc=1
  fi
else
  echo "WARN: fetch failed for siteimprove ($SI_URL)" >&2
  rc=1
fi

if [[ $rc -ne 0 ]]; then
  echo "one or more providers failed to refresh; existing files left in place" >&2
fi
exit $rc
