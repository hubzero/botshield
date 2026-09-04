#!/usr/bin/env python3
"""Generate src/generated_verified_bots.c from data/verified-bots.json.

The verified-bot built-ins (the bundled set of well-known crawlers
the module ships with — googlebot, bingbot, applebot, googleother,
siteimprove) used to live as a hardcoded C array in src/allowlist.c.
Moving them into a vendor JSON file gives operators the same
.local-overlay tuning capability that bot-directory and browser-
templates already have, without any new module directive.

Layering:
  data/verified-bots.json          # project-curated set (committed)
  data/verified-bots.default.json  # frozen fallback (committed)
  data/verified-bots.local.json    # operator overrides (gitignored)

There is no .builtin layer here because there's no external
upstream for verified-bots — we maintain the entries ourselves, so
the .json file IS the project's curated set (no separate "ours
overlaid on theirs" needed). See tools/gen-bot-directory.py for
the 4-layer pattern that applies when an external upstream exists.

Output format mirrors the legacy bs_builtin_bots[] static array,
so src/allowlist.c and src/config.c continue to consume the same
symbol with no code changes downstream.

Run from anywhere; paths resolve relative to the script's location.
"""

import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT  = SCRIPT_DIR.parent
VENDOR_JSON  = REPO_ROOT / "data" / "verified-bots.json"
DEFAULT_JSON = REPO_ROOT / "data" / "verified-bots.default.json"
# Operator overlay: gitignored, optional. Loaded after the curated
# set so operator entries win on slug collision and new slugs append.
LOCAL_JSON   = REPO_ROOT / "data" / "verified-bots.local.json"
OUTPUT_C     = REPO_ROOT / "src" / "generated_verified_bots.c"


def c_string_literal(s):
    """Encode a Python string as a C string literal."""
    if s is None:
        return "NULL"
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
    """Load data/verified-bots.json, or fall back to the .default
    baseline if the active file is missing/unreadable."""
    for path in (VENDOR_JSON, DEFAULT_JSON):
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list) and data:
                    print("# loaded {} ({} entries)".format(
                        path.name, len(data)), file=sys.stderr)
                    return data
            except Exception as e:
                print("# warn: {} unreadable: {}".format(path.name, e),
                      file=sys.stderr)
    print("ERROR: no usable verified-bots JSON found", file=sys.stderr)
    sys.exit(1)


def merge_overlay(base, overlay_path):
    """Overlay one verified-bots JSON file on top of `base`.
    Entries are keyed by slug. Overlay slugs that collide replace
    the base entry; new slugs append. Missing overlay = no-op."""
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
    data = merge_overlay(load_active(), LOCAL_JSON)

    # Normalize each entry into the bs_allow_bot_entry struct
    # field order: { name, pattern, path, inline_cidrs, ua_only }.
    rows = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        slug = entry.get("slug")
        pattern = entry.get("uaPattern")
        if not isinstance(slug, str) or not slug:
            continue
        if not isinstance(pattern, str) or not pattern:
            continue
        path = entry.get("rangesPath")
        if not isinstance(path, str) or not path:
            path = None
        inline = entry.get("inlineCidrs")
        if not isinstance(inline, str) or not inline:
            inline = None
        ua_only = 1 if entry.get("uaOnly") else 0
        rows.append((slug, pattern, path, inline, ua_only))

    lines = [
        "/* generated_verified_bots.c — auto-generated; do NOT edit by hand.",
        " *",
        " * Regenerated from data/verified-bots.json by",
        " * tools/gen-verified-bots.py. Edit the JSON or the generator,",
        " * then re-run via the Makefile rule.",
        " *",
        " * Defines bs_builtin_bots[] — the bundled set of verified-bot",
        " * entries (UA pattern + ranges-file metadata) the module ships",
        " * with. Composed with operator-declared BotShieldAllowBot",
        " * entries at post_config to form the active verified-bot",
        " * allowlist. */",
        "",
        "#include <stddef.h>",
        "",
        '#include "allowlist.h"',
        "",
        "const bs_allow_bot_entry bs_builtin_bots[] = {",
    ]
    for slug, pattern, path, inline, ua_only in rows:
        lines.append("    {{ {}, {}, {}, {}, {} }},".format(
            c_string_literal(slug),
            c_string_literal(pattern),
            c_string_literal(path),
            c_string_literal(inline),
            ua_only,
        ))
    lines.append("    { NULL, NULL, NULL, NULL, 0 }")
    lines.append("};")
    lines.append("")

    OUTPUT_C.write_text("\n".join(lines), encoding="utf-8")
    print("# wrote {} ({} verified-bot entries)".format(
        OUTPUT_C.name, len(rows)), file=sys.stderr)


if __name__ == "__main__":
    main()
