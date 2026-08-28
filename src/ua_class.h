/* ua_class.h — unified User-Agent classifier for mod_botshield.
 *
 * Three signals consolidated into one cached per-request answer:
 *   - browser-templates  (vendor/top-user-agents.json — top-100 real UAs)
 *   - bot directory      (vendor/bot-directory.json — ~600 known crawlers)
 *   - verified-bot       (operator/built-in UA pattern + IP cross-check)
 *
 * Browser-first ordering: real-user traffic is the dominant case, so
 * a positive browser-template match short-circuits before the AC
 * directory walk and the verified-bot IP cross-check. Real users pay
 * one classifier; bots pay all three.
 *
 * The classification is cached on r->pool via apr_pool_userdata so
 * downstream call sites (bs_check_allow, bs_ua_is_crawler_candidate,
 * decision-log slug attachment) all read the same answer instead of
 * re-walking the trie / templates set per consumer.
 *
 * Lifetime of pointer fields: known_slug / known_category point into
 * the bot-directory active state (one-tick destroy-grace, longer
 * than r->pool); verified_name points into pconf-allocated
 * bs_allow_bot_entry (lifetime of the module). Both are safe to
 * read for the request's duration. */
#ifndef BOTSHIELD_UA_CLASS_H
#define BOTSHIELD_UA_CLASS_H

#include <httpd.h>
#include <http_config.h>   /* cmd_parms for the directive setter */

#ifdef __cplusplus
extern "C" {
#endif

/* Single highest-signal label, for decision-log embedding and
 * coarse metrics. The struct fields below are the source of truth
 * for code that needs case analysis (e.g. fake-bot vs verified-bot
 * scoring). */
typedef enum {
    BS_UA_CLASS_UNKNOWN = 0,
    BS_UA_CLASS_BROWSER,
    BS_UA_CLASS_UNKNOWN_BOT,  /* no directory hit, but UA has bot-y tokens (bot/crawl/spider/curl/...) */
    BS_UA_CLASS_KNOWN_BOT,    /* directory hit OR allowlist UA pattern without IP verification */
    BS_UA_CLASS_FAKE_BOT,     /* allowlist UA pattern + IP cross-checked + IP not in ranges */
    BS_UA_CLASS_VERIFIED_BOT, /* allowlist UA pattern + IP cross-checked + IP confirmed */
} bs_ua_class_label;

typedef struct bs_ua_class {
    bs_ua_class_label label;

    int          is_browser;        /* matched a top-100 real-browser template */
    const char  *browser_slug;      /* "chrome", "firefox", "edge", "safari", ... when is_browser=1 */

    int          is_known_bot;      /* matched the Cloudflare bot directory */
    const char  *known_slug;        /* e.g. "google", NULL if not */
    const char  *known_category;    /* e.g. "search engine" */
    /* Botgroup for the matched directory entry — names taken from
     * the IETF aipref content-signal vocabulary plus mod_botshield's
     * "monitor" extension (search/ai-input/ai-train/monitor). NULL
     * if the bot's category doesn't map to a botgroup. Used by
     * @botgroup selectors in BotShieldBotRateLimit /
     * BotShieldRateLimit / BotShieldRequestTrigger / robots.txt. */
    const char  *known_botgroup;

    /* Strict semantics: is_verified_bot means "IP cross-checked AND
     * confirmed." The no-IP-check fall-throughs (verified_ua_only,
     * verified_unranged) leave both is_verified_bot and is_fake_bot
     * zero — those land in the known-bot pool downstream. */
    int          is_verified_bot;   /* allowlist UA pattern + IP confirmed */
    int          is_fake_bot;       /* allowlist UA pattern + IP cross-checked + IP missed */
    const char  *verified_name;     /* operator-declared name on UA pattern match */
    int          verified_ua_only;  /* operator's `*` target — IP check intentionally skipped */
    int          verified_unranged; /* IP check expected but data not available (ranges not loaded, or `-verified-bots`) */

    /* Heuristic last-resort signal. Set when none of the directory
     * / verified-bot / browser-template passes hit AND the UA
     * contains a bot-y substring (bot, crawl, spider, spyder, fetch,
     * slurp, scrap, curl, wget). Distinct from is_known_bot — there
     * is no slug, no operator, no category. The presence of this
     * flag means "we don't know which bot, but it's clearly not a
     * real user." */
    int          is_unknown_bot;
    const char  *unknown_bot_token;  /* the matched substring, for diagnostics */
    /* Request arrived with no User-Agent header at all, or an empty
     * one. Distinct from is_unknown_bot even though it implies it: that
     * flag means "the UA string identified itself as bot-shaped", this
     * one means "there was no UA to judge". Keeping them separate lets
     * the rate limiter meter absent-UA traffic in its own bucket
     * instead of draining the shared unknown-bot aggregate, and keeps
     * the two findings distinguishable in diagnostics. */
    int          is_no_ua;
} bs_ua_class;

/* Idempotent — first call computes + caches on r->pool, subsequent
 * calls return the same pointer. Always non-NULL. UAs that are
 * A missing or empty User-Agent produces label=UNKNOWN_BOT with
 * is_unknown_bot and is_no_ua set. No real browser omits the header, so
 * "unknown" would overstate our uncertainty -- we do know it is not a
 * browser. Measured on this deployment: 47 source IPs, each sending no
 * UA on 100% of its requests, 99.8% of their paths exploit probes
 * hunting known webshell filenames. */
const bs_ua_class *bs_classify_request_ua(request_rec *r);

/* post_read_request hook. Calls bs_classify_request_ua so the cached
 * answer is populated before any consumer (policy.c, allowlist.c,
 * decision-log slug attach) needs it. Always returns DECLINED so
 * other modules' hooks still run. Registered with APR_HOOK_LAST so
 * mod_remoteip's earlier hook has rewritten r->useragent_ip first. */
int bs_classify_request_hook(request_rec *r);

/* bs_classify_flags lives in botshield.h (cross-file types); see
 * the comment above the bs_server_cfg.classify field for the per-
 * pass fail-safe semantics. */

/* BotShieldClassify directive setter — TAKE_ARGV.
 *
 * Grammar:
 *   Standalone form (one token, exclusive):
 *       BotShieldClassify On    # all four enabled
 *       BotShieldClassify Off   # all four disabled
 *   Compositional form (optional starting state + zero or more deltas):
 *       BotShieldClassify [All|None] [+/-flag]...
 *
 * Recognized flag names (each is a "turn off this pass" / "turn on
 * this pass"): browsers, known-bots, verified-bots, unknown-bots.
 * Mixing On/Off with flags is a config-time error; use All/None
 * for the compositional form. */
const char *bs_set_classify(cmd_parms *cmd, void *dconf,
                            int argc, char *const argv[]);

/* Stable string form of the label, e.g. "verified-bot". For decision-
 * log embedding and metrics tags; the returned pointer is into static
 * rodata. */
const char *bs_ua_class_label_str(bs_ua_class_label l);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_UA_CLASS_H */
