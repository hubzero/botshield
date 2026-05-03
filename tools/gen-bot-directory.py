#!/usr/bin/env python3
"""Generate src/generated_bot_directory.c from the vendored
bot-directory.json.

The active vendor file is parsed at build time and emitted as a
static C array of pattern/slug/category triples. The runtime lookup
in src/bot_directory.c does a sequential strcasestr over the
patterns; for ~600 short patterns that's sub-microsecond.

Output format is deliberately minimal — no metadata not consumed by
runtime, no stable ordering requirements (operators don't read the
generated file). The build rule should regenerate when the JSON
file's mtime changes.

Run from anywhere; paths resolve relative to the script's location.
"""

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
VENDOR_JSON  = REPO_ROOT / "vendor" / "bot-directory.json"
DEFAULT_JSON = REPO_ROOT / "vendor" / "bot-directory.default.json"
# .builtin overlay: project-shipped additions, committed to source
# control. Loaded after upstream so corrections we ship win on slug
# collision.
BUILTIN_JSON = REPO_ROOT / "vendor" / "bot-directory.builtin.json"
# .local overlay: operator-managed additions, NOT committed (see
# vendor/.gitignore). Optional; loaded last so operator entries win
# even over our shipped builtin overrides. The seam for deployment-
# specific bots, monitoring tools, internal scrapers, etc.
LOCAL_JSON   = REPO_ROOT / "vendor" / "bot-directory.local.json"
OUTPUT_C     = REPO_ROOT / "src" / "generated_bot_directory.c"


def c_string_literal(s):
    """Encode a Python string as a C string literal. The vendor data
    contains only printable ASCII for our fields (slug, pattern,
    category), but be paranoid about escaping anyway."""
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


def load_active():
    """Load the active vendor JSON. Falls back to the default
    baseline if the active file is missing or unreadable — this
    keeps the build alive if something deletes the active file
    between vendor commits."""
    for path in (VENDOR_JSON, DEFAULT_JSON):
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list) and data:
                    print("# loaded {} ({} entries)".format(path.name, len(data)),
                          file=sys.stderr)
                    return data
            except Exception as e:
                print("# warn: {} unreadable: {}".format(path.name, e),
                      file=sys.stderr)
    print("ERROR: no usable bot-directory JSON found", file=sys.stderr)
    sys.exit(1)


def merge_overlay(base, overlay_path):
    """Overlay one bot-directory JSON file on top of `base`. Same
    JSON shape; entries are keyed by slug. Overlay slugs that
    collide with base replace the base entry (overlay wins); new
    slugs append.

    Missing overlay file is a silent no-op so callers can chain
    optional layers without conditional logic."""
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

    print("# merged {}: +{} added, {} overridden".format(
        overlay_path.name, additions, overrides), file=sys.stderr)
    return list(by_slug.values())


def main():
    # Load order: upstream → builtin (project additions, committed)
    #           → local (operator additions, gitignored, optional).
    # Each later layer overrides earlier on slug collision; new
    # slugs append.
    data = load_active()
    data = merge_overlay(data, BUILTIN_JSON)
    data = merge_overlay(data, LOCAL_JSON)

    # Flatten: each (pattern, slug, category) is one entry. A bot
    # entry can have multiple userAgentPatterns; we emit one row per
    # pattern. Patterns longer first so substring matching prefers
    # the more specific pattern when two could match (operationally
    # rare; just being defensive).
    rows = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug") or ""
        category = entry.get("category") or ""
        patterns = entry.get("userAgentPatterns") or []
        if not isinstance(patterns, list):
            continue
        for p in patterns:
            if isinstance(p, str) and p:
                rows.append((p, slug, category))
    rows.sort(key=lambda r: -len(r[0]))   # longest pattern first

    # Compose C source
    lines = [
        "/* generated_bot_directory.c — auto-generated; do NOT edit by hand.",
        " *",
        " * Regenerated from vendor/bot-directory.json by",
        " * tools/gen-bot-directory.py. Edit the JSON or the generator,",
        " * then re-run via the Makefile rule. */",
        "",
        "#include <stddef.h>   /* NULL */",
        "",
        '#include "bot_directory.h"',
        "",
        "const bs_known_bot_entry bs_known_bots[] = {",
    ]
    for pattern, slug, category in rows:
        lines.append("    {{ {}, {}, {} }},".format(
            c_string_literal(pattern),
            c_string_literal(slug),
            c_string_literal(category),
        ))
    lines.append("    { NULL, NULL, NULL }")
    lines.append("};")
    lines.append("")
    lines.append("const apr_size_t bs_known_bots_count = {};".format(len(rows)))
    lines.append("")

    OUTPUT_C.write_text("\n".join(lines), encoding="utf-8")
    print("# wrote {} ({} pattern rows from {} bot entries)".format(
        OUTPUT_C.name, len(rows), len(data)), file=sys.stderr)


if __name__ == "__main__":
    main()
