/* heuristics.h — the HTTP-library token list.
 *
 * This was the BotShieldHeuristicTrigger family: five named predicates
 * an operator bound score actions to. The predicates were restatements
 * of conditions a rule already expresses -- ua="", ua=@scraper,
 * firstsight=yes -- and what the family added was scoring, which no
 * longer reaches a tier. It is gone; see the sig-* rules in
 * tests/setup/botshield-dev.conf for what replaced it.
 *
 * What survives is the one piece with no rule equivalent: the list of
 * HTTP-library tokens, which ua=@scraper reads. */
#ifndef BOTSHIELD_HEURISTICS_H
#define BOTSHIELD_HEURISTICS_H

#include <httpd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The HTTP-library token this User-Agent carries, or NULL. Backs the
 * ua=@scraper cohort selector.
 *
 * This declaration used to sit after the #endif, outside the include
 * guard and outside the extern "C" block. */
const char *bs_ua_scraper_token(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_HEURISTICS_H */
