#!/usr/bin/env python3
"""Generate src/generated_browser_templates.c from the vendored
top-user-agents.json.

Reads vendor/top-user-agents.json (or falls back to
top-user-agents.default.json if the active file is missing or
unreadable), normalizes each UA by replacing runs of digits/dots/
underscores with 'X', dedupes, sorts alphabetically, and emits a
static C array of normalized templates.

Output format is deliberately minimal — a NULL-terminated array of
const char * — so the runtime classifier can iterate or bsearch
without any auxiliary metadata. The runtime applies the same
normalization to incoming UAs and tests for exact match.

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


def normalize(ua):
    return VERSION_TOKEN_RE.sub("X", ua)


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
                    print("# loaded {} ({} UAs)".format(path.name, len(data)),
                          file=sys.stderr)
                    return data
            except Exception as e:
                print("# warn: {} unreadable: {}".format(path.name, e),
                      file=sys.stderr)
    print("ERROR: no usable top-user-agents JSON found", file=sys.stderr)
    sys.exit(1)


def merge_overlay(base, overlay_path):
    """Append entries from a top-user-agents JSON overlay onto
    `base`. Templates de-dupe after version-normalization, so
    adding redundant strings is harmless. Missing overlay = no-op."""
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
    added = sum(1 for s in overlay if isinstance(s, str) and s)
    print("# merged {}: +{} UAs".format(overlay_path.name, added),
          file=sys.stderr)
    return base + [s for s in overlay if isinstance(s, str) and s]


def main():
    # Load order: upstream → builtin (committed) → local (gitignored).
    data = load_active()
    data = merge_overlay(data, BUILTIN_JSON)
    data = merge_overlay(data, LOCAL_JSON)

    # Normalize, dedupe, sort
    templates = sorted({
        normalize(ua) for ua in data
        if isinstance(ua, str) and ua
    })

    lines = [
        "/* generated_browser_templates.c — auto-generated; do NOT edit by hand.",
        " *",
        " * Regenerated from vendor/top-user-agents.json by",
        " * tools/gen-browser-templates.py. Edit the JSON or the generator,",
        " * then re-run via the Makefile rule.",
        " *",
        " * Each entry is a normalized UA template — the original UA with",
        " * runs of [0-9._]+ replaced by 'X'. The runtime classifier",
        " * applies the same transform to incoming UAs and tests for exact",
        " * match. Templates are deduped and sorted alphabetically; the",
        " * runtime can use bsearch or sequential strcmp at this scale. */",
        "",
        "#include <stddef.h>   /* NULL */",
        "",
        '#include "browser_classifier.h"',
        "",
        "const char *const bs_browser_templates[] = {",
    ]
    for t in templates:
        lines.append("    {},".format(c_string_literal(t)))
    lines.append("    NULL")
    lines.append("};")
    lines.append("")
    lines.append("const apr_size_t bs_browser_templates_count = {};".format(
        len(templates)))
    lines.append("")

    OUTPUT_C.write_text("\n".join(lines), encoding="utf-8")
    print("# wrote {} ({} templates from {} UAs)".format(
        OUTPUT_C.name, len(templates), len(data)), file=sys.stderr)


if __name__ == "__main__":
    main()
