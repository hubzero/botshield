#!/usr/bin/env python3
"""Refresh vendor/bot-directory.json from upstream.

Fetches the current bot directory from the microlinkhq repo and
replaces the active vendor file ONLY if the fetched data passes a
set of sanity checks. If any check fails, the active file is left
untouched and the script exits non-zero with a clear description.

Two-file model:
  vendor/bot-directory.json
      The active version. What the build compiles into the module.
      Replaced (in place) on a successful refresh.

  vendor/bot-directory.default.json
      Permanent committed baseline. NEVER modified by this script.
      If the active file is ever lost or corrupted, the build can
      always fall back to this. Originally a copy of the active
      version at the time the feature shipped; updated only via an
      explicit human commit, not via refresh.

Validation checks (any failure aborts the refresh):
  1. Successful HTTP 200 fetch with non-empty body
  2. Parses as valid JSON
  3. Top-level value is an array
  4. Entry count meets a minimum floor (current upstream is ~587;
     floor is 400, well below current but a meaningful canary
     against truncated/broken upstream pushes)
  5. Every sampled entry has the required fields
     (slug, userAgentPatterns, category)
  6. A small set of sentinel bot slugs is present (Googlebot,
     Bingbot, Applebot, OpenAI, Anthropic) — if any of these
     well-known crawlers disappear from upstream, treat that as a
     red flag and refuse to replace

On successful refresh, the previous active version is saved as
vendor/bot-directory.json.prev so an operator can review
the diff or revert by hand.

Usage:
    python3 tools/refresh-bot-directory.py
        Run from repo root (or anywhere — paths resolve relative
        to the script's location).
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

UPSTREAM_URL = (
    "https://raw.githubusercontent.com/microlinkhq/"
    "cloudflare-bot-directory/master/src/index.json"
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
VENDOR_DIR = REPO_ROOT / "vendor"
ACTIVE  = VENDOR_DIR / "bot-directory.json"
DEFAULT = VENDOR_DIR / "bot-directory.default.json"
# .builtin overlay: project-shipped additions, committed.
BUILTIN = VENDOR_DIR / "bot-directory.builtin.json"
# .local overlay: operator-managed additions, gitignored, optional.
LOCAL   = VENDOR_DIR / "bot-directory.local.json"
PREV    = VENDOR_DIR / "bot-directory.json.prev"

# Runtime TSV emitted alongside the vendor JSON. The TSV is what the
# module reads at request time when BotShieldBotDirectory is set.
# Defaults to /var/lib/botshield/bot-directory.tsv but can be
# redirected via the BOTSHIELD_BOT_DIRECTORY_TSV env var (handy for
# CI / packaging that installs to a non-standard prefix). The script
# only writes this if the parent directory is writable; otherwise it
# logs a hint and skips, leaving the vendor JSON as the source of
# truth for the build-time codegen.
RUNTIME_TSV = Path(
    os.environ.get(
        "BOTSHIELD_BOT_DIRECTORY_TSV",
        "/var/lib/botshield/bot-directory.tsv",
    )
)

# Sanity floor — refuse to replace if upstream returned dramatically
# fewer entries than we'd expect. Today's upstream has ~587. A floor
# of 400 catches "they truncated the file" / "they shipped a stub"
# while leaving room for the inevitable churn (entries get
# deduplicated, restructured, etc.).
MIN_ENTRY_COUNT = 400

REQUIRED_FIELDS = {"slug", "userAgentPatterns", "category"}

# Sentinels: slugs that MUST be present. Disappearance of any of
# these is a strong signal that upstream is broken or compromised
# (or has done a major restructure we want to review by hand
# before adopting). The set is deliberately small and conservative
# — these are canonical, long-established bots no curated directory
# should ever omit.
SENTINEL_SLUGS = {
    "google",       # GoogleBot — search engine
    "bing",         # BingBot — search engine
    "apple",        # Applebot — AI search
    "gptbot",       # GPTBot — OpenAI AI crawler
}


def fetch_upstream():
    """Fetch the upstream JSON. Returns body bytes on success;
    raises on transport failure."""
    print(f"fetching {UPSTREAM_URL}")
    req = urllib.request.Request(
        UPSTREAM_URL,
        headers={"User-Agent": "botshield-refresh-bot-directory/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status != 200:
            raise RuntimeError(f"upstream HTTP {resp.status}")
        body = resp.read()
        if not body:
            raise RuntimeError("upstream returned empty body")
        print(f"  fetched {len(body)} bytes")
        return body


def validate(data):
    """Run sanity checks on parsed JSON data. Returns a list of
    error strings; empty list means all checks passed."""
    errs = []

    # Shape check
    if not isinstance(data, list):
        errs.append("top-level value is not a JSON array")
        return errs   # nothing else makes sense to check

    # Volume floor
    if len(data) < MIN_ENTRY_COUNT:
        errs.append(
            f"entry count {len(data)} is below floor {MIN_ENTRY_COUNT} "
            "(upstream may have been truncated or restructured)"
        )

    # Field presence — sample a few entries to keep error output
    # short. If the directory has missing-field issues, three
    # examples are enough to characterize.
    field_problems = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            field_problems.append(f"entry {i} is not a JSON object")
            continue
        missing = REQUIRED_FIELDS - set(entry.keys())
        if missing:
            field_problems.append(
                f"entry {i} (slug={entry.get('slug', '?')}) "
                f"missing fields: {sorted(missing)}"
            )
    if field_problems:
        # Cap reported errors to first 3 to avoid wall-of-text
        for prob in field_problems[:3]:
            errs.append(prob)
        if len(field_problems) > 3:
            errs.append(
                f"... plus {len(field_problems) - 3} more entries "
                "with field issues"
            )

    # Sentinel-slug presence
    slugs = {
        e.get("slug")
        for e in data
        if isinstance(e, dict) and isinstance(e.get("slug"), str)
    }
    missing_sentinels = SENTINEL_SLUGS - slugs
    if missing_sentinels:
        errs.append(
            "missing well-known bot slugs: "
            f"{sorted(missing_sentinels)} — upstream may be broken"
        )

    return errs


def write_atomic(target, body):
    """Write body to target via a temp file + rename, so a partial
    write can never leave a corrupt active file."""
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(body)
    tmp.replace(target)


def merge_overlay(base, overlay_path):
    """Overlay one bot-directory JSON file on top of `base`. Same
    merge contract as tools/gen-bot-directory.py:merge_overlay —
    entries keyed by slug, overlay entries replace base on
    collision, new slugs append. Missing overlay file = no-op."""
    if not overlay_path.exists():
        return base
    try:
        with overlay_path.open("r", encoding="utf-8") as f:
            overlay = json.load(f)
    except Exception as e:
        print(f"   warn: {overlay_path.name} unreadable: {e} (skipping)")
        return base
    if not isinstance(overlay, list) or not overlay:
        return base

    by_slug = {}
    for e in base:
        if isinstance(e, dict) and isinstance(e.get("slug"), str):
            by_slug[e["slug"]] = e

    overrides = 0
    additions = 0
    for e in overlay:
        if not isinstance(e, dict):
            continue
        slug = e.get("slug")
        if not isinstance(slug, str) or not slug:
            continue
        if slug in by_slug:
            overrides += 1
        else:
            additions += 1
        by_slug[slug] = e

    print(f"   merged {overlay_path.name}: +{additions} added, {overrides} overridden")
    return list(by_slug.values())


def emit_runtime_tsv(data):
    """Convert the validated bot-directory JSON to the pipe-delimited
    TSV format the runtime parser consumes, and write it atomically
    to RUNTIME_TSV. One row per (UA-pattern, slug) — bot entries with
    multiple userAgentPatterns yield multiple TSV rows.

    Both the .builtin (project-shipped) and .local (operator) overlays
    are merged in before emission so the runtime TSV reflects the
    same set the build-time codegen sees.

    Skips silently if the runtime parent directory doesn't exist or
    isn't writable — the runtime override is optional and the vendor
    JSON remains the source of truth for build-time codegen."""
    data = merge_overlay(data, BUILTIN)
    data = merge_overlay(data, LOCAL)
    if not RUNTIME_TSV.parent.exists():
        print(
            f"   skip runtime tsv: parent {RUNTIME_TSV.parent} does not exist"
            f"\n   (create it with `sudo mkdir -p {RUNTIME_TSV.parent}` and"
            f"\n    re-run, or set BOTSHIELD_BOT_DIRECTORY_TSV to a writable"
            f" path)"
        )
        return

    if not os.access(str(RUNTIME_TSV.parent), os.W_OK):
        print(
            f"   skip runtime tsv: parent {RUNTIME_TSV.parent} not writable"
            f"\n   (re-run with sudo, or set BOTSHIELD_BOT_DIRECTORY_TSV)"
        )
        return

    rows = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug") or ""
        category = entry.get("category") or ""
        follows = 1 if entry.get("followsRobotsTxt") else 0
        patterns = entry.get("userAgentPatterns") or []
        if not isinstance(patterns, list):
            continue
        for p in patterns:
            if not isinstance(p, str) or not p:
                continue
            # The runtime parser splits on '|' so any pattern / slug /
            # category containing a literal pipe would break parsing.
            # Skip with a warning rather than emit a corrupt row.
            if "|" in p or "|" in slug or "|" in category:
                print(
                    f"   skip {slug}: pipe character in field "
                    "(would break TSV parser)"
                )
                continue
            # Likewise newlines would split a row across lines.
            if "\n" in p or "\r" in p:
                continue
            rows.append((p, slug, category, follows))

    # Sort longest pattern first so the runtime substring scan
    # encounters more-specific matches before less-specific. Mirrors
    # the build-time codegen order.
    rows.sort(key=lambda r: -len(r[0]))

    header = (
        "# /var/lib/botshield/bot-directory.tsv\n"
        "# Generated by tools/refresh-bot-directory.py.\n"
        "# DO NOT EDIT BY HAND - run the refresh tool to update.\n"
        "# Format: pattern|slug|category|followsRobotsTxt\n"
        "# Comments start with '#'; blank lines ignored.\n"
    )
    body_lines = [
        f"{p}|{s}|{c}|{f}"
        for (p, s, c, f) in rows
    ]
    body = (header + "\n".join(body_lines) + "\n").encode("utf-8")
    write_atomic(RUNTIME_TSV, body)
    # Apache reads as the apache user; default umask might leave the
    # file 0600 root-only. Explicitly chmod 0644 so non-root workers
    # can read it.
    try:
        os.chmod(str(RUNTIME_TSV), 0o644)
    except OSError as e:
        print(f"   warn: chmod 0644 {RUNTIME_TSV} failed: {e}")
    print(f"   wrote {RUNTIME_TSV} ({len(rows)} rows)")


def main():
    if not VENDOR_DIR.exists():
        print(f"ERROR: vendor directory does not exist: {VENDOR_DIR}",
              file=sys.stderr)
        return 2

    try:
        body = fetch_upstream()
    except Exception as e:
        print(f"ERROR: fetch failed: {e}", file=sys.stderr)
        return 3

    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as e:
        print(f"ERROR: JSON parse failed: {e}", file=sys.stderr)
        return 4

    errs = validate(data)
    if errs:
        print("VALIDATION FAILED — active file unchanged:",
              file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 5

    # Diff summary against current active
    new_count = len(data)
    old_count = 0
    if ACTIVE.exists():
        try:
            old_data = json.loads(ACTIVE.read_text())
            old_count = len(old_data) if isinstance(old_data, list) else 0
        except Exception:
            old_count = -1   # unreadable; treat as unknown

    # Backup current active to .prev (overwrites any earlier .prev)
    # so an operator can diff or revert without git.
    if ACTIVE.exists():
        ACTIVE.replace(PREV)

    # Pretty-format the JSON so diffs against committed versions
    # are reviewable without a custom JSON differ.
    pretty = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    write_atomic(ACTIVE, pretty.encode("utf-8"))

    delta = new_count - old_count if old_count > 0 else 0
    sign = "+" if delta > 0 else ("" if delta == 0 else "")
    print(f"OK refreshed {ACTIVE.name}: "
          f"{old_count if old_count > 0 else '?'} -> {new_count} "
          f"({sign}{delta:+d})" if old_count > 0
          else f"OK refreshed {ACTIVE.name}: {new_count} entries")
    print(f"   baseline preserved at {DEFAULT.name}")
    if PREV.exists():
        print(f"   previous version backed up to {PREV.name}")

    # Emit the runtime TSV that BotShield's watchdog re-loads on
    # mtime change. Skipped silently if the runtime path isn't
    # writable — the vendor JSON above is still the source of truth.
    emit_runtime_tsv(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
