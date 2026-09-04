"""Browser family-slug detection — shared helper for the build-time
codegen and the upstream-refresh tool.

The family-identifying tokens (Edg/, OPR/, Chrome/, Firefox/, etc.)
don't contain digits/dots/underscores, so this works equivalently on
raw UAs and version-normalized templates. Mirrors the priority order
used by the C-side bs_browser_family fallback in
src/browser_classifier.c.

Single source of truth for "raw UA → family slug." After fetch, the
slug is stored alongside its UA in the JSON template files; gen-
browser-templates.py reads slug directly from the JSON and never re-
detects.
"""

# Order matters: Chromium derivatives (Edge, Opera, Brave, Samsung,
# etc.) carry "Chrome/" in their UA, so they must be detected by their
# distinguishing token first. Most-specific tokens win.
FAMILY_TOKENS = [
    ("EdgA/",             "edge-mobile"),
    ("EdgiOS/",           "edge-ios"),
    ("Edg/",              "edge"),
    ("OPiOS/",            "opera-ios"),
    ("OPR/",              "opera"),
    ("SamsungBrowser/",   "samsung"),
    ("Brave",             "brave"),
    ("YaBrowser/",        "yandex"),
    ("Ddg/",              "duckduckgo"),
    ("AVG/",              "avg"),
    ("Avast/",            "avast"),
    ("ADG/",              "adguard"),
    ("median",            "median"),
    ("obsidian",          "obsidian"),
    ("ScalboostBrowser/", "scalboost"),
    ("CriOS/",            "chrome-ios"),
    ("FxiOS/",            "firefox-ios"),
    ("Firefox/",          "firefox"),
]


def family(s):
    """Return a browser-family slug for `s` (raw UA or normalized
    template). Never returns None — falls back to "browser" generic
    when no token matches."""
    for token, slug in FAMILY_TOKENS:
        if token in s:
            return slug
    if "Chrome/" in s:
        return "chrome-mobile" if "Mobile" in s else "chrome"
    if "Safari/" in s:
        return "safari-mobile" if "Mobile/" in s else "safari"
    if "Mobile/" in s:
        return "ios-webview"
    return "browser"
