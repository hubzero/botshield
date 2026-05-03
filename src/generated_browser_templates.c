/* generated_browser_templates.c — auto-generated; do NOT edit by hand.
 *
 * Regenerated from vendor/top-user-agents.json by
 * tools/gen-browser-templates.py. Edit the JSON or the generator,
 * then re-run via the Makefile rule.
 *
 * Each entry is a normalized UA template — the original UA with
 * runs of [0-9._]+ replaced by 'X'. The runtime classifier
 * applies the same transform to incoming UAs and tests for exact
 * match. Templates are deduped and sorted alphabetically; the
 * runtime can use bsearch or sequential strcmp at this scale. */

#include <stddef.h>   /* NULL */

#include "browser_classifier.h"

const char *const bs_browser_templates[] = {
    "Mozilla/X (Android X; Mobile; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (Linux; Android X; K) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X",
    "Mozilla/X (Linux; Android X; K) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X EdgA/X",
    "Mozilla/X (Linux; Android X; K) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (Linux; Android X; K) AppleWebKit/X (KHTML, like Gecko) SamsungBrowser/X Chrome/X Mobile Safari/X",
    "Mozilla/X (Linux; Android X; Pixel X Pro) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X OPR/X",
    "Mozilla/X (Linux; Android X; SM-GXB) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X EdgA/X",
    "Mozilla/X (Linux; Android X; SM-JXG) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X EdgA/X",
    "Mozilla/X (Linux; Android X; SM-SXB) AppleWebKit/X (KHTML, like Gecko) Chrome/X Mobile Safari/X OPR/X",
    "Mozilla/X (Linux; Android X; XRI Build/UKQX; wv) AppleWebKit/X (KHTML, like Gecko) Version/X Chrome/X Mobile Safari/X median",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Brave Chrome/X Safari/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Edg/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X OPR/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Version/X Safari/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X) AppleWebKit/X (KHTML, like Gecko) Version/X Safari/X Ddg/X",
    "Mozilla/X (Macintosh; Intel Mac OS X X; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (Windows NT X; WOWX; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X ADG/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X AVG/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Avast/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X Edg/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X OPR/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X YaBrowser/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) ScalboostBrowser/X Chrome/X Electron/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX) AppleWebKit/X (KHTML, like Gecko) obsidian/X Chrome/X Electron/X Safari/X",
    "Mozilla/X (Windows NT X; WinX; xX; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (Windows NT X; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (XX; CrOS xX X) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (XX; Linux xX) AppleWebKit/X (KHTML, like Gecko) Chrome/X Safari/X",
    "Mozilla/X (XX; Linux xX; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (XX; Ubuntu; Linux xX; rv:X) Gecko/X Firefox/X",
    "Mozilla/X (iPad; CPU OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Version/X Mobile/XEX Safari/X",
    "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) CriOS/X Mobile/XEX Safari/X",
    "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Mobile/XEX",
    "Mozilla/X (iPhone; CPU iPhone OS X like Mac OS X) AppleWebKit/X (KHTML, like Gecko) Version/X Mobile/XEX Safari/X",
    NULL
};

const apr_size_t bs_browser_templates_count = 37;
