#!/usr/bin/env python3
"""Refresh vendor/top-user-agents.json from upstream.

Fetches the current top-100 browser User-Agents list from the
microlinkhq/top-user-agents repo and replaces the active vendor
file ONLY if the fetched data passes a set of sanity checks. If
any check fails, the active file is left untouched and the script
exits non-zero with a clear description.

Two-file model (matches the bot-directory pattern):
  vendor/top-user-agents.json
      The active version. What the build compiles into the module.
      Replaced (in place) on a successful refresh.

  vendor/top-user-agents.default.json
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
  - Active JSON written atomically to vendor/top-user-agents.json
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

UPSTREAM_URL = (
    "https://raw.githubusercontent.com/microlinkhq/"
    "top-user-agents/refs/heads/master/src/index.json"
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
VENDOR_DIR = REPO_ROOT / "vendor"
ACTIVE  = VENDOR_DIR / "top-user-agents.json"
DEFAULT = VENDOR_DIR / "top-user-agents.default.json"
# .builtin overlay: project-shipped additions, committed.
BUILTIN = VENDOR_DIR / "top-user-agents.builtin.json"
# .local overlay: operator-managed additions, gitignored, optional.
LOCAL   = VENDOR_DIR / "top-user-agents.local.json"
PREV    = VENDOR_DIR / "top-user-agents.json.prev"

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
    print(f"fetching {UPSTREAM_URL}")
    req = urllib.request.Request(
        UPSTREAM_URL,
        headers={"User-Agent": "botshield-refresh-top-user-agents/1.0"},
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

    if not isinstance(data, list):
        errs.append("top-level value is not a JSON array")
        return errs

    if len(data) < MIN_ENTRY_COUNT:
        errs.append(
            f"entry count {len(data)} is below floor {MIN_ENTRY_COUNT} "
            "(upstream may have been truncated or restructured)"
        )

    # Shape check — every entry must be a non-empty string
    bad_shape = 0
    for i, ua in enumerate(data):
        if not isinstance(ua, str) or not ua:
            bad_shape += 1
            if bad_shape <= 3:
                errs.append(
                    f"entry {i} is not a non-empty string "
                    f"(got {type(ua).__name__})"
                )
    if bad_shape > 3:
        errs.append(
            f"... plus {bad_shape - 3} more entries with shape issues"
        )

    # Family probes on the normalized templates
    if isinstance(data, list) and not bad_shape:
        templates = {normalize(ua) for ua in data}
        missing = []
        for family, probe in FAMILY_PROBES.items():
            if not any(probe.search(t) for t in templates):
                missing.append(family)
        if missing:
            errs.append(
                f"missing browser engine families: {sorted(missing)} "
                "— upstream may be broken"
            )

    return errs


def write_atomic(target, body):
    """Write body to target via a temp file + rename, so a partial
    write can never leave a corrupt active file."""
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(body)
    tmp.replace(target)


def merge_overlay(base, overlay_path):
    """Append entries from a top-user-agents JSON overlay onto
    `base`. Same merge contract as
    tools/gen-browser-templates.py:merge_overlay. Missing overlay
    file = no-op."""
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
    extras = [s for s in overlay if isinstance(s, str) and s]
    print(f"   merged {overlay_path.name}: +{len(extras)} UAs")
    return base + extras


def emit_runtime_templates(data):
    """Build the deduped, sorted set of normalized templates and
    write it to the runtime location for the watchdog to load.
    Both .builtin (project-shipped) and .local (operator) overlays
    are merged in before normalization so the runtime file reflects
    the same set the build-time codegen sees.

    Sorting is alphabetical, deterministic — gives operators a
    stable file to diff between refreshes. The runtime classifier
    can use bsearch over the sorted array."""
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

    templates = sorted({normalize(ua) for ua in data})
    header = (
        f"# {RUNTIME_TXT}\n"
        "# Generated by tools/refresh-top-user-agents.py.\n"
        "# DO NOT EDIT BY HAND - run the refresh tool to update.\n"
        "# Each non-comment line is a UA template with runs of\n"
        "# [0-9._]+ replaced by 'X'. The runtime classifier\n"
        "# applies the same transform to incoming UAs and tests\n"
        "# for exact match. Comments start with '#'; blank lines\n"
        "# ignored.\n"
    )
    body = (header + "\n".join(templates) + "\n").encode("utf-8")
    write_atomic(RUNTIME_TXT, body)
    try:
        os.chmod(str(RUNTIME_TXT), 0o644)
    except OSError as e:
        print(f"   warn: chmod 0644 {RUNTIME_TXT} failed: {e}")
    print(f"   wrote {RUNTIME_TXT} ({len(templates)} templates)")


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

    new_count = len(data)
    old_count = 0
    if ACTIVE.exists():
        try:
            old_data = json.loads(ACTIVE.read_text())
            old_count = len(old_data) if isinstance(old_data, list) else 0
        except Exception:
            old_count = -1

    if ACTIVE.exists():
        ACTIVE.replace(PREV)

    pretty = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    write_atomic(ACTIVE, pretty.encode("utf-8"))

    delta = new_count - old_count if old_count > 0 else 0
    print(f"OK refreshed {ACTIVE.name}: "
          f"{old_count if old_count > 0 else '?'} -> {new_count} "
          f"({delta:+d} UAs)" if old_count > 0
          else f"OK refreshed {ACTIVE.name}: {new_count} UAs")
    print(f"   baseline preserved at {DEFAULT.name}")
    if PREV.exists():
        print(f"   previous version backed up to {PREV.name}")

    emit_runtime_templates(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
