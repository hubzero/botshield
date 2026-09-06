/* heuristics.c — the HTTP-library token list. See heuristics.h for
 * what this file used to be and why it is not that any more. */
#include <string.h>

#include <httpd.h>

#include <apr_tables.h>

#include "heuristics.h"

/* Which HTTP-library token, if any, this User-Agent carries.
 *
 * Read by the ua=@scraper cohort selector. It used to be shared with a
 * scraperua score so that a rule and a score could not disagree about
 * what a scraper is; the score is gone and the rule is the only
 * caller, but one list remains the point -- a second copy of this
 * would drift from the first.
 *
 * Case-sensitive on purpose: both casings appear in the wild and both
 * are listed. This flags rather than blocks, so a false positive costs
 * a client one tier rather than the page.
 */
const char *bs_ua_scraper_token(request_rec *r)
{
    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (!ua || !*ua) return NULL;
    static const char *const scraper_tokens[] = {
        "curl", "Wget", "wget",
        "python", "Python", "python-requests",
        "urllib", "httpx", "aiohttp",
        "Go-http-client", "okhttp", "axios", "scrapy",
        "java", "Java", "libwww", "lwp-request",
        NULL
    };
    for (int i = 0; scraper_tokens[i]; i++) {
        if (strstr(ua, scraper_tokens[i])) return scraper_tokens[i];
    }
    return NULL;
}
