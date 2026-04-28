/* heuristics.h — cheap built-in score signals.
 *
 * Run on requests we're about to challenge — i.e. the cookie was
 * missing or invalid and bs_check_policy didn't short-circuit.
 * Pile up score-add reasons so bs_decide_tier has something to
 * work with:
 *
 *   - E1 verified-crawler allow-list (negative penalty for verified
 *     crawlers — a dominant credit; positive penalty for fakes)
 *   - missing User-Agent  (BS_PENALTY_MISSING_UA)
 *   - missing Accept-Language  (BS_PENALTY_MISSING_AL)
 *   - obvious scraper / HTTP-library UA fragments  (BS_PENALTY_SCRAPER_UA)
 *
 * All checks are cheap (string ops, no DNS/HTTP/SHM), case-sensitive
 * where matching real-world casings matters, and false-positive-
 * tolerant — they're flags, not blocks. */
#ifndef BOTSHIELD_HEURISTICS_H
#define BOTSHIELD_HEURISTICS_H

#include <httpd.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Walk the cheap built-ins. Caller is responsible for not running
 * this when a verified cookie is in play (we'd be charging penalties
 * to a known-good client). */
void bs_run_builtin_heuristics(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_HEURISTICS_H */
