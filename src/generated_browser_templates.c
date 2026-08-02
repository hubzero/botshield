/* generated_browser_templates.c — auto-generated; do NOT edit by hand.
 *
 * Regenerated from vendor/top-user-agents.json by
 * tools/gen-browser-templates.py. Edit the JSON or the generator,
 * then re-run via the Makefile rule.
 *
 * Each entry is a {normalized template, family slug} pair. The
 * normalized template is the original UA with runs of [0-9._]+
 * replaced by 'X'; the runtime classifier applies the same
 * transform to incoming UAs and tests for exact match. The
 * family slug (chrome, firefox, edge, ...) is precomputed here
 * so the runtime lookup returns it directly with zero per-
 * request token-scanning. Entries are sorted alphabetically by
 * the normalized template. */

#include <stddef.h>   /* NULL */

#include "browser_classifier.h"

const bs_browser_template bs_browser_templates[] = {
    { "Mozilla/X (Android X; D) Gecko/X Firefox/X", "firefox" },
    { "Mozilla/X (Linux; Android X; D) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X", "chrome-mobile" },
    { "Mozilla/X (Linux; Android X; D) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X EdgA/X", "edge-mobile" },
    { "Mozilla/X (Linux; Android X; D) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X OPR/X", "opera" },
    { "Mozilla/X (Linux; Android X; D) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X", "chrome" },
    { "Mozilla/X (Linux; Android X; D) AppleWebKit/X (KHTML, like Gecko) SamsungBrowser/X Chrome/X Mobile Safari/X", "samsung" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko)", "browser" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Brave Chrome/X Safari/X", "brave" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X", "chrome" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Edg/X", "edge" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X OPR/X", "opera" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Version/X Safari/X", "safari" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Version/X Safari/X Ddg/X", "duckduckgo" },
    { "Mozilla/X (Macintosh; Intel Mac OS X X; rv:X) Gecko/X Firefox/X", "firefox" },
    { "Mozilla/X (Windows NT X; WOWX; rv:X) Gecko/X Firefox/X", "firefox" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X", "browser" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X ADG/X Safari/X", "adguard" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X", "chrome" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X AVG/X", "avg" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Avast/X", "avast" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Edg/X", "edge" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Edge/X", "chrome" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X OPR/X", "opera" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X YaBrowser/X Safari/X", "yandex" },
    { "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) ScalboostBrowser/X Chrome/X Electron/X Safari/X", "scalboost" },
    { "Mozilla/X (Windows NT X; WinX; xX; rv:X) Gecko/X Firefox/X", "firefox" },
    { "Mozilla/X (Windows NT X; rv:X) Gecko/X Firefox/X", "firefox" },
    { "Mozilla/X (XX; CrOS xX X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X", "chrome" },
    { "Mozilla/X (XX; Linux xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X", "chrome" },
    { "Mozilla/X (XX; Linux xX) AppleWebKit/X Chrome/X Safari/X", "chrome" },
    { "Mozilla/X (XX; Linux xX; rv:X) Gecko/X Firefox/X", "firefox" },
    { "Mozilla/X (XX; Ubuntu; Linux xX; rv:X) Gecko/X Firefox/X", "firefox" },
    { "Mozilla/X (iPad; CPU OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Version/X Mobile/B Safari/X", "safari-mobile" },
    { "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) CriOS/X Mobile/B Safari/X", "chrome-ios" },
    { "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) GSA/X Mobile/B Safari/X", "safari-mobile" },
    { "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Mobile/B", "ios-webview" },
    { "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Version/X Mobile/B Safari/X", "safari-mobile" },
    { NULL, NULL }
};

const apr_size_t bs_browser_templates_count = 37;
