/* heuristics.c — cheap built-in score signals. See heuristics.h
 * for the operator-level model. */
#include <string.h>

#include <httpd.h>
#include <http_config.h>

#include <apr_strings.h>
#include <apr_tables.h>

#include "botshield.h"
#include "allowlist.h"   /* bs_check_allow */
#include "heuristics.h"
#include "score.h"       /* bs_score_add */

/* Cheap built-in signals, run on requests we're about to challenge.
 * Called after the cookie check — a verified cookie skips scoring
 * entirely. */
void bs_run_builtin_heuristics(request_rec *r)
{
    /* E1: crawler allow-list runs first. A verified crawler adds a
     * large negative penalty that dominates anything else scoring
     * might pile on (scraper UA tokens in "Googlebot" etc.) and
     * collapses tier dispatch to pass. */
    bs_dir_cfg *dcfg = ap_get_module_config(r->per_dir_config,
                                            &botshield_module);
    bs_check_allow(r, dcfg);

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (!ua || !*ua) {
        bs_score_add(r, BS_PENALTY_MISSING_UA, 3600, "missing-user-agent");
    }
    const char *al = apr_table_get(r->headers_in, "Accept-Language");
    if (!al || !*al) {
        bs_score_add(r, BS_PENALTY_MISSING_AL, 3600, "missing-accept-language");
    }

    /* Obvious scraper / HTTP-library UA fragments. Case-sensitive on
     * purpose — we pick both casings where both actually appear in the
     * wild. Matches are flagged, not blocked, so false positives only
     * cost a tier bump. */
    if (ua && *ua) {
        static const char *const scraper_tokens[] = {
            "curl", "Wget", "wget",
            "python", "Python", "python-requests",
            "urllib", "httpx", "aiohttp",
            "Go-http-client", "okhttp", "axios", "scrapy",
            "java", "Java", "libwww", "lwp-request",
            NULL
        };
        for (int i = 0; scraper_tokens[i]; i++) {
            if (strstr(ua, scraper_tokens[i])) {
                bs_score_add(r, BS_PENALTY_SCRAPER_UA, 3600,
                    apr_psprintf(r->pool, "scraper-ua-%s", scraper_tokens[i]));
                break;
            }
        }
    }
}
