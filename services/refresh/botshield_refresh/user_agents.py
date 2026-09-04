#!/usr/bin/env python3
"""Refresh data/top-user-agents.json from upstream.

Fetches the current top-100 browser User-Agents list from the
microlinkhq/top-user-agents repo, attaches a browser-family slug
(chrome, firefox, edge, ...) to each entry via
tools/browser_family.py, and replaces the active vendor file ONLY if
the fetched data passes a set of sanity checks. If any check fails,
the active file is left untouched and the script exits non-zero with
a clear description.

Schema written to disk: list of {"ua": "...", "slug": "..."} objects.
The slug is the source of truth for the per-request decision-log tag
(`browser:<slug>`); slug detection happens here once at fetch time
and is preserved through every consumer (codegen, runtime override).

Two-file model (matches the bot-directory pattern):
  data/top-user-agents.json
      The active version. What the build compiles into the module.
      Replaced (in place) on a successful refresh.

  data/top-user-agents.default.json
      Permanent committed baseline. NEVER modified by this script.
      If the active file is ever lost or corrupted, the build can
      always fall back to this. Updated only via an explicit human
      commit, not via refresh.

Validation checks (any failure aborts the refresh):
  1. Successful HTTP 200 fetch with non-empty body
  2. Parses as valid JSON
  3. Top-level value is an array
  4. Entry count >= MIN_ENTRY_COUNT (current upstream is 100;
     floor is 50, well below current but a meaningful canary
     against truncated/broken upstream pushes)
  5. Every entry is a string (UAs are flat strings)
  6. After version-mask normalization, the set of distinct
     templates contains at least one Chrome-shaped template, one
     Firefox-shaped template, and one Safari-shaped template — if
     any major engine family disappears entirely from upstream,
     treat that as a red flag and refuse to replace

On successful refresh:
  - Active JSON written atomically to data/top-user-agents.json
  - Previous active backed up to .prev (operator-local rollback)
  - Distinct version-masked templates also written to
    /var/lib/botshield/browser-templates.txt (configurable via
    BOTSHIELD_BROWSER_TEMPLATES env var) for the runtime
    classifier to consume. Skipped silently if the parent
    directory isn't writable.

Usage:
    python3 tools/refresh-top-user-agents.py
        Run from anywhere; paths resolve relative to the script.
"""

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

from .common import (
    fetch,
    load_dataset,
    write_atomic,
    write_runtime_file,
)

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from browser_family import family

UPSTREAM_URL = (
    "https://raw.githubusercontent.com/microlinkhq/"
    "top-user-agents/refs/heads/master/src/index.json"
)

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = REPO_ROOT / "data"
ACTIVE  = DATA_DIR / "top-user-agents.json"
DEFAULT = DATA_DIR / "top-user-agents.default.json"
# .builtin overlay: project-shipped additions, committed.
BUILTIN = DATA_DIR / "top-user-agents.builtin.json"
# .local overlay: operator-managed additions, gitignored, optional.
LOCAL   = DATA_DIR / "top-user-agents.local.json"
PREV    = DATA_DIR / "top-user-agents.json.prev"

# Runtime browser-templates file. Different name than the upstream
# JSON because the runtime form is normalized (version-masked) and
# stripped of duplicates — it's emitted by this script, not a copy
# of the upstream data.
RUNTIME_TXT = Path(
    os.environ.get(
        "BOTSHIELD_BROWSER_TEMPLATES",
        "/var/lib/botshield/browser-templates.txt",
    )
)

# Sanity floor — refuse to replace if upstream returned dramatically
# fewer entries than expected. Today's upstream has 100. A floor of
# 50 catches "they truncated the file" without false-positives on
# small natural fluctuations.
MIN_ENTRY_COUNT = 50

# Family-detector regexes operate on the version-masked template
# (digits/dots/underscores collapsed to 'X'). Each major engine
# family must appear in at least one template; absence is a red
# flag (upstream broken or restructured).
FAMILY_PROBES = {
    "chrome":  re.compile(r"Chrome/X.*Safari/X"),
    "firefox": re.compile(r"Gecko/X Firefox/X"),
    "safari":  re.compile(r"AppleWebKit/X.*Version/X.*Safari/X"),
}

VERSION_TOKEN_RE = re.compile(r"[\d._]+")


def normalize(ua):
    """Replace runs of digits/dots/underscores with a single 'X'.
    The runtime classifier applies the same transform to incoming
    UAs and tests for exact match against this normalized set."""
    return VERSION_TOKEN_RE.sub("X", ua)


def fetch_upstream():
    """Fetch and parse the upstream user-agent list."""
    print(f"  fetching {UPSTREAM_URL}")
    body = fetch(UPSTREAM_URL)
    print(f"    {len(body)} bytes")
    return json.loads(body.decode("utf-8"))


def validate(data):
    """Sanity-check a parsed payload. Returns a list of error strings;
    empty means it passed.

    Accepts either shape, because the two sources differ: upstream
    publishes a list of User-Agent strings, and this project's
    committed copy stores the coerced list of {ua, slug} objects. Both
    have to pass the same checks, so entries are coerced first and the
    checks run on what comes out.
    """
    errs = []

    if not isinstance(data, list):
        errs.append("top-level value is not a JSON array")
        return errs

    if len(data) < MIN_ENTRY_COUNT:
        errs.append(
            f"entry count {len(data)} is below floor {MIN_ENTRY_COUNT} "
            "(source may have been truncated or restructured)"
        )

    entries = coerce_entries(data)
    unusable = len(data) - len(entries)
    if unusable:
        errs.append(
            f"{unusable} of {len(data)} entries are neither a non-empty "
            "string nor an object carrying a 'ua' field"
        )

    # Every engine family we expect to see must appear somewhere. A
    # list that has lost one of them is a list worth looking at by hand
    # before it becomes the thing every browser is compared against.
    if entries:
        templates = {normalize(entry["ua"]) for entry in entries}
        missing = [
            family_name
            for family_name, probe in FAMILY_PROBES.items()
            if not any(probe.search(template) for template in templates)
        ]
        if missing:
            errs.append(
                f"missing browser engine families: {sorted(missing)} "
                "- the source may be broken"
            )

    return errs


def coerce_entries(raw):
    """Normalize an overlay/payload entry list to a uniform list of
    {ua, slug} dicts. Object entries pass through; string entries
    (legacy or upstream format) get auto-slugged. Same coercion shape
    as tools/gen-browser-templates.py:coerce_entries."""
    out = []
    for entry in raw:
        if isinstance(entry, str) and entry:
            out.append({"ua": entry, "slug": family(entry)})
        elif isinstance(entry, dict) and entry.get("ua"):
            ua = entry["ua"]
            slug = entry.get("slug") or family(ua)
            out.append({"ua": ua, "slug": slug})
    return out


def merge_overlay(base, overlay_path):
    """Append entries from a top-user-agents JSON overlay onto
    `base`. Object form (with slug) preferred; legacy string entries
    get auto-slugged. Missing overlay file = no-op."""
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
    extras = coerce_entries(overlay)
    print(f"   merged {overlay_path.name}: +{len(extras)} entries")
    return base + extras


def emit_runtime_templates(data):
    """Build the deduped, sorted set of {normalized template, slug}
    pairs and write them to the runtime location for the watchdog to
    load. Both .builtin (project-shipped) and .local (operator)
    overlays are merged in before normalization so the runtime file
    reflects the same set the build-time codegen sees.

    File format: one entry per line, two tab-separated fields —
    `<normalized template>\\t<slug>`. The runtime parser falls back
    to family detection when the slug column is missing (so older
    files or hand-written entries still work).

    Sorting is alphabetical, deterministic — gives operators a stable
    file to diff between refreshes."""
    data = merge_overlay(data, BUILTIN)
    data = merge_overlay(data, LOCAL)
    if not RUNTIME_TXT.parent.exists():
        print(
            f"   skip runtime templates: parent {RUNTIME_TXT.parent} "
            f"does not exist (sudo mkdir -p {RUNTIME_TXT.parent} or "
            f"set BOTSHIELD_BROWSER_TEMPLATES)"
        )
        return
    if not os.access(str(RUNTIME_TXT.parent), os.W_OK):
        print(
            f"   skip runtime templates: parent {RUNTIME_TXT.parent} "
            f"not writable (re-run with sudo)"
        )
        return

    by_norm = {}
    for entry in data:
        n = normalize(entry["ua"])
        if n not in by_norm:
            by_norm[n] = entry["slug"]
    pairs = sorted(by_norm.items())
    header = (
        f"# {RUNTIME_TXT}\n"
        "# Generated by tools/refresh-top-user-agents.py.\n"
        "# DO NOT EDIT BY HAND - run the refresh tool to update.\n"
        "# Each non-comment line is `<normalized template>\\t<slug>`.\n"
        "# The runtime classifier applies the same version-mask\n"
        "# transform to incoming UAs and tests for exact template\n"
        "# match; the slug is the browser-family identifier emitted\n"
        "# in the decision log (browser:<slug>). Comments start with\n"
        "# '#'; blank lines ignored. Lines with no tab are accepted\n"
        "# for backward compatibility — slug is auto-detected at\n"
        "# load time.\n"
    )
    body = (header + "\n".join(f"{t}\t{s}" for t, s in pairs) + "\n"
            ).encode("utf-8")
    write_runtime_file(RUNTIME_TXT, body)
    print(f"   wrote {RUNTIME_TXT} ({len(pairs)} templates)")


def main(prefer_project: bool | None = None) -> int:
    """Refresh the browser templates. Returns 0 on success, non-zero if
    nothing usable was found -- in which case every existing file is
    left exactly as it was.

    Same two orders as the bot directory: a checkout curates from
    upstream, a host prefers this project's curated copy and falls back
    to upstream when that has gone stale.
    """
    runtime_only = not DATA_DIR.exists()
    if prefer_project is None:
        prefer_project = runtime_only
    if runtime_only:
        print(f"browser templates: runtime-only, writing {RUNTIME_TXT}")

    try:
        raw, source = load_dataset(
            "browser templates",
            "data/top-user-agents.json",
            fetch_upstream,
            validate,
            prefer_project,
        )
    except RuntimeError as exc:
        # Nothing usable, so nothing is written. The existing
        # templates already passed these checks once; data that just
        # failed them is not an improvement.
        print(f"ERROR: {exc}", file=sys.stderr)
        print("       existing files left unchanged", file=sys.stderr)
        return 1

    entries = coerce_entries(raw)

    if runtime_only:
        emit_runtime_templates(entries)
        return 0

    new_count = len(entries)
    old_count = 0
    if ACTIVE.exists():
        try:
            old_data = json.loads(ACTIVE.read_text())
            old_count = len(old_data) if isinstance(old_data, list) else 0
        except Exception:
            old_count = -1

    if ACTIVE.exists():
        ACTIVE.replace(PREV)

    pretty = json.dumps(entries, indent=2, ensure_ascii=False) + "\n"
    write_atomic(ACTIVE, pretty.encode("utf-8"))

    if old_count > 0:
        print(f"OK refreshed {ACTIVE.name} from {source}: "
              f"{old_count} -> {new_count} ({new_count - old_count:+d} entries)")
    else:
        print(f"OK refreshed {ACTIVE.name} from {source}: {new_count} entries")
    print(f"   baseline preserved at {DEFAULT.name}")
    if PREV.exists():
        print(f"   previous version backed up to {PREV.name}")

    emit_runtime_templates(entries)
    return 0


if __name__ == "__main__":
    sys.exit(main())
