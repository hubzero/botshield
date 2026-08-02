#!/usr/bin/env python3
"""Generate src/generated_browser_templates.c from the vendored
top-user-agents.json.

Reads vendor/top-user-agents.json (or falls back to
top-user-agents.default.json if the active file is missing or
unreadable). Each entry is an object with `ua` and `slug` fields:

    [
      {"ua": "Mozilla/5.0 (...)", "slug": "chrome"},
      {"ua": "Mozilla/5.0 (...)", "slug": "firefox"},
      ...
    ]

The slug is the browser-family identifier (chrome, firefox, edge,
safari, ...) and is the source of truth for the per-request decision-
log tag. Slugs are attached at upstream-fetch time by
tools/refresh-top-user-agents.py and stay with the entry through
every overlay layer.

Codegen output is a struct array {normalized template, slug} sorted
alphabetically by normalized template. Runtime lookup returns the
slug directly from the matched entry — zero per-request token-scanning.

Legacy fallback: if an entry is a bare string (an unconverted file
from before the schema change), the family-detection helper in
tools/browser_family.py auto-attaches a slug at codegen time.

Run from anywhere; paths resolve relative to the script's location.
"""

import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
VENDOR_JSON  = REPO_ROOT / "vendor" / "top-user-agents.json"
DEFAULT_JSON = REPO_ROOT / "vendor" / "top-user-agents.default.json"
# .builtin overlay: project-shipped additions, committed.
BUILTIN_JSON = REPO_ROOT / "vendor" / "top-user-agents.builtin.json"
# .local overlay: operator-managed additions, gitignored, optional.
LOCAL_JSON   = REPO_ROOT / "vendor" / "top-user-agents.local.json"
OUTPUT_C     = REPO_ROOT / "src" / "generated_browser_templates.c"

VERSION_TOKEN_RE = re.compile(r"[\d._]+")


# Must stay byte-identical in behaviour to bs_browser_normalize()
# in src/browser_classifier.c -- if the two disagree, no template
# ever matches at runtime.
ANDROID_DEV_RE = re.compile(r"Android X; [^)]*\)")
IOS_BUILD_RE   = re.compile(r"Mobile/[A-Za-z0-9]+")

def normalize(ua):
    u = VERSION_TOKEN_RE.sub("X", ua)
    u = ANDROID_DEV_RE.sub("Android X; D)", u)
    u = IOS_BUILD_RE.sub("Mobile/B", u)
    return u


# Family detection lives in browser_family.py — used at upstream-fetch
# time only. The vendor JSON files carry the slug per-entry; this
# codegen never re-detects. Imported for the legacy-format fallback
# (string entries from a not-yet-converted file get auto-slugged here).
from browser_family import family


def c_string_literal(s):
    """Encode a Python string as a C string literal."""
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"' or c == '\\':
            out.append("\\")
            out.append(c)
        elif 0x20 <= o < 0x7F:
            out.append(c)
        else:
            out.append("\\x{:02x}".format(o))
    out.append('"')
    return "".join(out)


def coerce_entries(raw, source_name):
    """Normalize a JSON entry list to a uniform list of {ua, slug}
    dicts. Object entries pass through (slug auto-detected if absent).
    Legacy string entries get auto-slugged. Malformed entries are
    skipped with a warning."""
    out = []
    for entry in raw:
        if isinstance(entry, str) and entry:
            out.append({"ua": entry, "slug": family(entry)})
        elif isinstance(entry, dict) and entry.get("ua"):
            ua = entry["ua"]
            slug = entry.get("slug") or family(ua)
            out.append({"ua": ua, "slug": slug})
        else:
            print("# warn: {}: skipped malformed entry: {!r}".format(
                source_name, entry), file=sys.stderr)
    return out


def load_active():
    """Load the active vendor JSON, falling back to the default
    baseline if the active is missing/unreadable. Keeps the build
    alive if something deletes the active between vendor commits."""
    for path in (VENDOR_JSON, DEFAULT_JSON):
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list) and data:
                    entries = coerce_entries(data, path.name)
                    print("# loaded {} ({} entries)".format(
                        path.name, len(entries)), file=sys.stderr)
                    return entries
            except Exception as e:
                print("# warn: {} unreadable: {}".format(path.name, e),
                      file=sys.stderr)
    print("ERROR: no usable top-user-agents JSON found", file=sys.stderr)
    sys.exit(1)


def merge_overlay(base, overlay_path):
    """Append entries from a top-user-agents JSON overlay onto
    `base`. Templates de-dupe after version-normalization, so
    adding redundant entries is harmless. Missing overlay = no-op."""
    if not overlay_path.exists():
        return base
    try:
        with overlay_path.open("r", encoding="utf-8") as f:
            overlay = json.load(f)
    except Exception as e:
        print("# warn: {} unreadable: {} (skipping)".format(
            overlay_path.name, e), file=sys.stderr)
        return base
    if not isinstance(overlay, list) or not overlay:
        return base
    extras = coerce_entries(overlay, overlay_path.name)
    print("# merged {}: +{} entries".format(overlay_path.name, len(extras)),
          file=sys.stderr)
    return base + extras


def main():
    # Load order: upstream → builtin (committed) → local (gitignored).
    data = load_active()
    data = merge_overlay(data, BUILTIN_JSON)
    data = merge_overlay(data, LOCAL_JSON)

    # Normalize each UA, dedupe by normalized form, sort alphabetically.
    # First entry encountered for a normalized template wins — collisions
    # are extremely rare (would require two different browser families
    # with the same normalized template string, which the family-
    # identifying tokens are designed to prevent).
    by_norm = {}
    for entry in data:
        n = normalize(entry["ua"])
        if n not in by_norm:
            by_norm[n] = entry["slug"]
    templates = sorted(by_norm.items())   # [(normalized, slug), ...]

    lines = [
        "/* generated_browser_templates.c — auto-generated; do NOT edit by hand.",
        " *",
        " * Regenerated from vendor/top-user-agents.json by",
        " * tools/gen-browser-templates.py. Edit the JSON or the generator,",
        " * then re-run via the Makefile rule.",
        " *",
        " * Each entry is a {normalized template, family slug} pair. The",
        " * normalized template is the original UA with runs of [0-9._]+",
        " * replaced by 'X'; the runtime classifier applies the same",
        " * transform to incoming UAs and tests for exact match. The",
        " * family slug (chrome, firefox, edge, ...) is precomputed here",
        " * so the runtime lookup returns it directly with zero per-",
        " * request token-scanning. Entries are sorted alphabetically by",
        " * the normalized template. */",
        "",
        "#include <stddef.h>   /* NULL */",
        "",
        '#include "browser_classifier.h"',
        "",
        "const bs_browser_template bs_browser_templates[] = {",
    ]
    for norm, slug in templates:
        lines.append("    {{ {}, {} }},".format(
            c_string_literal(norm), c_string_literal(slug)))
    lines.append("    { NULL, NULL }")
    lines.append("};")
    lines.append("")
    lines.append("const apr_size_t bs_browser_templates_count = {};".format(
        len(templates)))
    lines.append("")

    OUTPUT_C.write_text("\n".join(lines), encoding="utf-8")
    print("# wrote {} ({} templates from {} entries)".format(
        OUTPUT_C.name, len(templates), len(data)), file=sys.stderr)


if __name__ == "__main__":
    main()
