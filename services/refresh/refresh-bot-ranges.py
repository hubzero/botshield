#!/usr/bin/env python3
"""Refresh the verified-crawler IP range files the allow list reads.

Fetches each provider's published ranges and rewrites one file per
provider under the ranges directory. The module reads these through
`BotShieldAllowBot` and re-checks them on the interval set by
`BotShieldAllowRangesRefreshInterval`, so a refresh takes effect
without an Apache reload.

Every provider is independent. A fetch or parse failure for one leaves
that provider's previous file untouched and does not stop the others:
stale published ranges are far better than none, and an upstream having
a bad day must not cost this host its allow list.

Exit code 0 if every provider refreshed, 1 if any failed. The paired
systemd unit treats 1 as success for that reason -- every provider that
answered has already been written.

Providers that publish only via PTR plus forward-confirm (Yandex,
DuckDuckGo, Facebook, LinkedIn, Twitter) are out of scope by design.
There is no range list to fetch, and confirming one of those takes a
reverse lookup per request, which belongs in the module rather than in
a refresh job. See docs/policy.md on the allow list.

Usage:
    sudo refresh-bot-ranges.py [destination-directory]

Defaults to /var/lib/botshield/bots, or BOTSHIELD_BOT_RANGES_DIR.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

USER_AGENT = "mod_botshield/refresh-bot-ranges"
TIMEOUT = 30

DEFAULT_DEST = Path(
    os.environ.get("BOTSHIELD_BOT_RANGES_DIR", "/var/lib/botshield/bots")
)

# Providers rotate these URLs without notice. A rotation costs staleness,
# not breakage: the previous file keeps being served. When one starts
# failing, check the provider's documentation and update the URL here.
#
#   Google:  https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
#            The special-crawlers pool covers GoogleOther, GoogleProducer,
#            AdsBot and friends. The allow list matches only on the
#            "GoogleOther" token, so the file is named for that even
#            though the payload is broader.
#   Bing:    https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26
#   Apple:   https://support.apple.com/en-us/HT204683
JSON_PROVIDERS = {
    "googlebot":
        "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "googleother":
        "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "bingbot":
        "https://www.bing.com/toolbox/bingbot.json",
    "applebot":
        "https://search.developer.apple.com/applebot.json",
}

SITEIMPROVE_URL = (
    "https://help.siteimprove.com/support/solutions/articles/"
    "80000448553-what-ip-addresses-and-user-agents-are-used-by-siteimprove-"
)
# Siteimprove publishes no feed, so this one is scraped. A structural
# change to their page should fail loudly rather than quietly writing a
# nearly-empty allow list, which is what the floor is for.
SITEIMPROVE_MIN_IPS = 30

BANNER = "# refreshed by services/refresh/refresh-bot-ranges.py"


def fetch(url: str) -> bytes:
    """Fetch one URL. Raises on any transport or HTTP failure."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        body = response.read()
    if not body:
        raise RuntimeError("empty response")
    return body


def parse_json_prefixes(body: bytes) -> list[str]:
    """Pull ipv4Prefix and ipv6Prefix out of a provider's prefixes array.

    All four JSON providers share this shape. Returns them sorted and
    deduplicated, and raises if the payload carries none, which is how a
    provider serving a stub or an error page gets caught.
    """
    payload = json.loads(body)
    prefixes = {
        entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        for entry in payload.get("prefixes", [])
        if entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
    }
    if not prefixes:
        raise ValueError("no prefixes in payload")
    return sorted(prefixes)


class CrawlerSection(HTMLParser):
    """Collect the body text of the Siteimprove section about crawlers.

    The page carries several h2 sections and only one is the
    site-scanning crawler. The others are analytics, performance
    monitoring, and email delivery, which run from different
    infrastructure and have no business in a verified-crawler allow
    list. Only h2 counts as a boundary: the page nests h3 subsections
    under the crawler heading, and treating those as boundaries would
    cut the section short.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_heading = False
        self.heading: list[str] = []
        self.collecting = False
        self.body: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "h2":
            self.in_heading = True
            self.heading = []
            self.collecting = False   # a new h2 ends the previous section

    def handle_endtag(self, tag):
        if tag == "h2" and self.in_heading:
            self.in_heading = False
            self.collecting = "crawler" in "".join(self.heading).lower()

    def handle_data(self, data):
        if self.in_heading:
            self.heading.append(data)
        elif self.collecting:
            self.body.append(data)


# Digit-boundary lookarounds rather than \b: the page emits some
# addresses directly against the next heading's first letter, with no
# whitespace between them, and \b does not fire between a digit and a
# letter because both are word characters. The trailing address on a
# section would be silently dropped.
IP_PATTERN = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?!\d)")


def parse_siteimprove(body: bytes) -> list[str]:
    """Extract crawler addresses from the Siteimprove help article."""
    parser = CrawlerSection()
    parser.feed(body.decode("utf-8", errors="replace"))
    text = "".join(parser.body)

    found = set()
    for match in IP_PATTERN.finditer(text):
        try:
            network = ipaddress.ip_network(match.group(0), strict=False)
        except ValueError:
            continue
        # Private, loopback and link-local are never a real crawler, and
        # their presence means the parse wandered outside the section.
        if network.is_private or network.is_loopback or network.is_link_local:
            continue
        found.add(
            str(network) if "/" in match.group(0) else str(network.network_address)
        )

    if len(found) < SITEIMPROVE_MIN_IPS:
        raise ValueError(
            f"only {len(found)} crawler addresses parsed, below the floor of "
            f"{SITEIMPROVE_MIN_IPS}; the page structure has probably changed "
            f"and needs looking at by hand"
        )
    return sorted(
        found,
        key=lambda item: ipaddress.ip_network(item, strict=False)
        .network_address.packed,
    )


def web_server_account() -> str | None:
    """Return whichever web-server account this distribution uses.

    apache on RHEL-family, www-data on Debian-family. A miss is not
    fatal: the file is mode 0644 and the module only ever reads it.
    """
    import pwd

    for name in ("apache", "www-data"):
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    return None


def write_ranges(path: Path, url: str, entries: list[str], note: str = "") -> None:
    """Write one ranges file atomically.

    Written to a temporary name in the destination directory and
    renamed, which is atomic on one filesystem. A refresh interrupted
    halfway therefore leaves the previous file intact rather than a
    truncated one the module would read as a shrunken allow list.
    """
    lines = [BANNER, f"# source: {url}"]
    if note:
        lines.append(f"# {note}")
    lines.extend(entries)
    body = "\n".join(lines) + "\n"

    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(body, encoding="utf-8")
    os.chmod(temporary, 0o644)

    account = web_server_account()
    if account is not None:
        import grp
        import pwd

        try:
            os.chown(
                temporary,
                pwd.getpwnam(account).pw_uid,
                grp.getgrnam(account).gr_gid,
            )
        except (KeyError, PermissionError, OSError):
            pass   # mode 0644 already covers the module's read

    temporary.replace(path)


def refresh_provider(name: str, url: str, dest: Path) -> bool:
    """Refresh one JSON provider. Returns True if the file was replaced."""
    try:
        entries = parse_json_prefixes(fetch(url))
    except (urllib.error.URLError, OSError) as exc:
        print(f"WARN: fetch failed for {name}: {exc}", file=sys.stderr)
        return False
    except (ValueError, RuntimeError) as exc:
        print(f"WARN: parse failed for {name}: {exc}", file=sys.stderr)
        return False

    write_ranges(dest / f"{name}.txt", url, entries)
    print(f"OK:   {name:<12}  {len(entries):>4} CIDRs  ->  {dest / (name + '.txt')}")
    return True


def refresh_siteimprove(dest: Path) -> bool:
    """Refresh Siteimprove. Returns True if the file was replaced."""
    try:
        entries = parse_siteimprove(fetch(SITEIMPROVE_URL))
    except (urllib.error.URLError, OSError) as exc:
        print(f"WARN: fetch failed for siteimprove: {exc}", file=sys.stderr)
        return False
    except ValueError as exc:
        print(f"WARN: parse failed for siteimprove: {exc}", file=sys.stderr)
        return False

    path = dest / "siteimprove.txt"
    write_ranges(
        path, SITEIMPROVE_URL, entries,
        note=f"count:  {len(entries)} entries (parsed from the crawler section)",
    )
    print(f"OK:   {'siteimprove':<12}  {len(entries):>4} CIDRs  ->  {path}")
    return True


def main(argv: list[str]) -> int:
    dest = Path(argv[1]) if len(argv) > 1 else DEFAULT_DEST
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: cannot create {dest}: {exc}", file=sys.stderr)
        return 2

    results = [
        refresh_provider(name, url, dest)
        for name, url in JSON_PROVIDERS.items()
    ]
    results.append(refresh_siteimprove(dest))

    if not all(results):
        print(
            "one or more providers failed to refresh; "
            "their existing files were left in place",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
