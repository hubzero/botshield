/* ua_class.c — unified UA classifier. See ua_class.h for the
 * design; this file owns the implementation and call-site
 * orchestration. Browser-first ordering keeps real-user traffic
 * (the dominant case) on the fastest path: a positive match in
 * the top-100 templates short-circuits before the AC directory
 * walk and the verified-bot IP cross-check. */

#include "ua_class.h"

#include <string.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_hash.h>

#include "allowlist.h"          /* bs_allow_*, bs_bot_ranges_state, bs_ua_classify */
#include "botshield.h"          /* bs_server_cfg, botshield_module */
#include "bot_directory.h"      /* bs_ua_is_known_bot */
#include "browser_classifier.h" /* bs_ua_is_browser */

/* Pool-userdata key for the per-request cache. APR's userdata is
 * keyed by string; using a stable, non-overlapping prefix avoids
 * collisions with other modules' userdata. */
#define BS_UA_CLASS_USERDATA_KEY "mod_botshield_ua_class"

const char *bs_ua_class_label_str(bs_ua_class_label l)
{
    switch (l) {
    case BS_UA_CLASS_BROWSER:      return "browser";
    case BS_UA_CLASS_UNKNOWN_BOT:  return "unknown-bot";
    case BS_UA_CLASS_KNOWN_BOT:    return "known-bot";
    case BS_UA_CLASS_FAKE_BOT:     return "fake-bot";
    case BS_UA_CLASS_VERIFIED_BOT: return "verified-bot";
    case BS_UA_CLASS_UNKNOWN:
    default:                        return "unknown";
    }
}

/* Heuristic last-resort tokens. A UA that didn't match any of the
 * curated classifiers but contains one of these substrings is
 * almost certainly an automated client of some kind. The list is
 * deliberately narrow — no "http" alone (matches httpd/https/etc.),
 * no "agent" (too many false positives in browser UAs). Order
 * doesn't affect correctness; first-match short-circuits. */
static const char *const bs_unknown_bot_tokens[] = {
    "bot",     /* covers any *Bot, robot, etc. */
    "crawl",   /* crawler, crawling */
    "spider",  /* and Spyder via the next entry */
    "spyder",
    "fetch",   /* fetcher */
    "slurp",   /* historical Yahoo Slurp pattern */
    "scrap",   /* scraper, scrapy */
    "curl",    /* PycURL, libcurl */
    "wget",
    /* "http" catches the RFC 9309-style self-ID convention where
     * bots embed +http://example.com/bot or +https://... in their
     * UA. Verified zero false positives against the browser-template
     * set (0 of 115 raw / 37 normalized templates contain 'http'),
     * since real browser UAs report engine/version/OS rather than
     * URLs. Library-default UAs that contain 'http' (Go-http-client,
     * python-httpx, guzzlehttp, okhttp, etc.) already match more-
     * specific directory entries first via longest-match. */
    "http",
    NULL
};

/* Find the verified-bot entry by name. Operator-declared entries
 * (in scfg->allow_bots) win over the built-in table on collision —
 * mirror of bs_check_allow's lookup contract. Returns NULL if no
 * entry exists for `name`. */
static const bs_allow_bot_entry *find_allow_entry(bs_server_cfg *scfg,
                                                  const char *name)
{
    if (!name) return NULL;
    if (scfg->allow_bots) {
        const bs_allow_bot_entry *e =
            apr_hash_get(scfg->allow_bots, name, APR_HASH_KEY_STRING);
        if (e) return e;
    }
    for (const bs_allow_bot_entry *b = bs_builtin_bots; b->name; b++) {
        if (strcmp(b->name, name) == 0) return b;
    }
    return NULL;
}

/* Phase 2: verified-bot UA pattern + IP cross-check. Splits out
 * cleanly from the browser-first short-circuit so the hot path stays
 * readable.
 *
 * is_verified_bot is set ONLY when the IP cross-check ran AND the
 * client IP was confirmed. Without an actual IP check, the UA pattern
 * just contributes the bot's name to the known-bot pool — the
 * verified-bot credit (BS_CREDIT_ALLOW) requires real verification.
 *
 * Three no-IP-check fall-throughs all land in the known-bot pool
 * downstream:
 *   - operator's `*` target           → verified_ua_only=1
 *   - BotShieldClassify -verified-bots → verified_unranged=1
 *   - rangesPath declared, file not loaded → verified_unranged=1 */
static void classify_verified(request_rec *r, const char *ua,
                              bs_ua_class *out)
{
    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    if (!scfg || !scfg->bot_classifier) return;

    const char *name = bs_ua_classify(scfg->bot_classifier, ua);
    if (!name) return;

    out->verified_name = name;

    const bs_allow_bot_entry *entry = find_allow_entry(scfg, name);
    if (entry && entry->ua_only) {
        /* Operator's `*` target — they explicitly opted out of IP
         * verification for this bot. UA match alone doesn't qualify
         * for verified-bot credit; bot lands in known-bot pool. */
        out->verified_ua_only = 1;
        return;
    }

    /* BotShieldClassify -verified-bots: subsystem-wide IP check
     * disabled. Same effect as ranges-not-loaded — bot lands in
     * known-bot pool without credit. */
    if (!scfg->classify.verified_bots) {
        out->verified_unranged = 1;
        return;
    }

    /* Atomic-load the live ranges state — the watchdog can swap
     * this pointer at any moment. */
    apr_array_header_t *ranges = NULL;
    bs_bot_ranges_state *st =
        __atomic_load_n(&scfg->bot_ranges, __ATOMIC_ACQUIRE);
    if (st && st->by_name) {
        ranges = apr_hash_get(st->by_name, name, APR_HASH_KEY_STRING);
    }

    if (!ranges) {
        /* UA matched but no ranges loaded — file missing, malformed,
         * or fetch hasn't completed yet. Bot lands in known-bot pool;
         * bs_check_allow bumps bot_unverified_total so operators can
         * monitor the load-gap rate. */
        out->verified_unranged = 1;
        return;
    }

    if (bs_allow_ip_in_ranges(ranges, r)) {
        out->is_verified_bot = 1;
    } else {
        out->is_fake_bot = 1;
    }
}

const bs_ua_class *bs_classify_request_ua(request_rec *r)
{
    if (!r) return NULL;

    bs_ua_class *cached = NULL;
    apr_pool_userdata_get((void **)&cached,
                          BS_UA_CLASS_USERDATA_KEY, r->pool);
    if (cached) return cached;

    cached = apr_pcalloc(r->pool, sizeof(*cached));
    /* Park the cache slot before doing any work. If a downstream
     * call recurses into bs_classify_request_ua (it shouldn't, but
     * defensively), it'll see the half-built struct and return —
     * the alternative would be a stack overflow. */
    apr_pool_userdata_setn(cached, BS_UA_CLASS_USERDATA_KEY,
                           NULL, r->pool);

    const char *ua = apr_table_get(r->headers_in, "User-Agent");
    if (!ua || !*ua) {
        /* No UA at all. This is not an ambiguous case: every real
         * browser sends the header, so absence is positive evidence
         * that the client is not one. Labelling it "unknown" claimed
         * uncertainty we do not have and buried 84% of the unclassified
         * traffic on the dashboard under a name that invited people to
         * go looking for a classifier gap that was not there.
         *
         * is_no_ua as well as is_unknown_bot so the rate limiter can
         * meter this separately -- see bs_bot_rate_lookup. */
        cached->is_no_ua        = 1;
        cached->is_unknown_bot  = 1;
        cached->unknown_bot_token = "no-ua";
        cached->label           = BS_UA_CLASS_UNKNOWN_BOT;
        return cached;
    }

    bs_server_cfg *scfg =
        ap_get_module_config(r->server->module_config, &botshield_module);
    bs_classify_flags flags = scfg ? scfg->classify : BS_CLASSIFY_FLAGS_ALL;

    /* Browser-first short-circuit. Real-user traffic dominates;
     * matching one of the top-100 curated browser templates means
     * this UA is a real browser (UAs from real users vary only in
     * version digits, which the template-set's normalization
     * absorbs). Such UAs cannot also legitimately be in the bot
     * directory or claim a verified-bot pattern, so we skip both
     * passes. Gated by classify.browsers — when off, the pass is
     * skipped here (is_browser stays 0); the fail-safe for
     * downstream consumers like bs_ua_is_crawler_candidate is
     * handled there, not by faking is_browser=1 here. */
    if (flags.browsers) {
        const char *bslug = bs_ua_browser_slug(ua);
        if (bslug) {
            cached->is_browser   = 1;
            cached->browser_slug = bslug;
            cached->label        = BS_UA_CLASS_BROWSER;
            return cached;
        }
    }

    /* Retired and non-existent agent identities.
     *
     * Checked before the directory walk because these are spoofed by
     * construction: no IP could make them genuine, so unlike the
     * allow-list fake-bot path this needs no ranges file.
     *
     *   Google-Extended  never a crawler at all -- a robots.txt control
     *                    token, introduced 2023-09, governing whether
     *                    content Googlebot ALREADY fetched may train
     *                    Gemini/Vertex. Nothing fetches under this name.
     *   Claude-Web       retired by Anthropic, superseded by ClaudeBot /
     *   anthropic-ai     Claude-User / Claude-SearchBot (documented
     *                    2026-02).
     *
     * Observed on this deployment: one Google Cloud address sent all
     * three, ten requests each, cycling vendor identities -- UA probing
     * to find which names are blocked.
     *
     * Patterns are checked against live agents before being added here:
     * ClaudeBot, Claude-User and Claude-SearchBot contain none of these
     * substrings ("anthropic.com" does not contain "anthropic-ai"), and
     * Googlebot does not contain "Google-Extended". */
    static const struct {
        const char *pattern;
        const char *slug;
    } bs_retired_agents[] = {
        { "Google-Extended", "google-extended" },
        { "Claude-Web",      "claude-web" },
        { "anthropic-ai",    "anthropic-ai" },
        { NULL, NULL }
    };
    for (int i = 0; bs_retired_agents[i].pattern; i++) {
        if (strcasestr(ua, bs_retired_agents[i].pattern)) {
            cached->is_fake_bot   = 1;
            /* verified_name, not just known_slug: the scoring path in
             * allowlist.c gates on verified_name being set, and that is
             * what applies BS_PENALTY_FAKE_BOT and emits the
             * fake-bot:<name> reason. Setting only known_slug
             * classified the request correctly and then scored it as if
             * nothing had happened. */
            cached->verified_name = bs_retired_agents[i].slug;
            cached->known_slug    = bs_retired_agents[i].slug;
            cached->label         = BS_UA_CLASS_FAKE_BOT;
            return cached;
        }
    }

    /* Known-bot directory walk (Aho-Corasick over ~600 patterns).
     * Sets known_slug + known_category + known_botgroup if the UA
     * matches any directory entry. Gated by classify.known_bots. */
    if (flags.known_bots
        && bs_ua_is_known_bot(ua, &cached->known_slug,
                              &cached->known_category,
                              &cached->known_botgroup)) {
        cached->is_known_bot = 1;
    }

    /* Verified-bot UA pattern + IP cross-check. The UA-classifier
     * pass always runs if a classifier exists; the IP cross-check
     * inside classify_verified is gated by classify.verified_bots
     * (when off, matches become UA-only). */
    classify_verified(r, ua, cached);

    /* Heuristic last-resort: if nothing more authoritative matched,
     * scan for bot-y substrings. Catches the long tail of self-
     * identifying tools (PycURL, generic "compatible; crawler" UAs,
     * etc.) that don't appear in the curated directory. Skipped if
     * any other bot signal is already set or if the heuristic is
     * disabled by classify.unknown_bots. */
    if (flags.unknown_bots
        && !cached->is_known_bot
        && !cached->is_verified_bot
        && !cached->is_fake_bot
        && !cached->verified_name) {
        for (const char *const *t = bs_unknown_bot_tokens; *t; t++) {
            if (strcasestr(ua, *t)) {
                cached->is_unknown_bot   = 1;
                cached->unknown_bot_token = *t;
                break;
            }
        }
    }

    /* Final label: highest-signal wins. verified_name without
     * is_verified_bot/is_fake_bot (UA-only target or unranged) lands
     * in KNOWN_BOT — the bot is known to us, just not IP-verified. */
    if (cached->is_verified_bot) {
        cached->label = BS_UA_CLASS_VERIFIED_BOT;
    } else if (cached->is_fake_bot) {
        cached->label = BS_UA_CLASS_FAKE_BOT;
    } else if (cached->is_known_bot || cached->verified_name) {
        cached->label = BS_UA_CLASS_KNOWN_BOT;
    } else if (cached->is_unknown_bot) {
        cached->label = BS_UA_CLASS_UNKNOWN_BOT;
    } else {
        cached->label = BS_UA_CLASS_UNKNOWN;
    }

    return cached;
}

int bs_classify_request_hook(request_rec *r)
{
    /* Populate the per-request cache early so every downstream
     * consumer reads the same answer instead of re-walking the
     * trie / templates set. The function is idempotent so consumers
     * can also call it directly (defense against hook-ordering
     * surprises). */
    bs_classify_request_ua(r);
    return DECLINED;
}


/* --- BotShieldClassify directive ---------------------------------- *
 *
 * Grammar (parsed in main below):
 *   Standalone:    BotShieldClassify On
 *                  BotShieldClassify Off
 *   Compositional: BotShieldClassify [All|None] [+/-flag]...
 * Mixing standalone with deltas is rejected.
 *
 * Recognized flag names (case-insensitive):
 *   browsers, known-bots, verified-bots, unknown-bots
 *
 * The setter mutates scfg->classify in place. Last directive wins
 * if the same vhost has multiple BotShieldClassify lines (Apache's
 * standard merge behavior — we just overwrite). */

static int classify_flag_set(bs_classify_flags *f, const char *name,
                             unsigned char value)
{
    /* Case-insensitive name match. Returns 1 if `name` matched a
     * known flag, 0 otherwise (caller logs the error). */
    if      (strcasecmp(name, "browsers")      == 0) f->browsers      = value;
    else if (strcasecmp(name, "known-bots")    == 0) f->known_bots    = value;
    else if (strcasecmp(name, "verified-bots") == 0) f->verified_bots = value;
    else if (strcasecmp(name, "unknown-bots")  == 0) f->unknown_bots  = value;
    else return 0;
    return 1;
}

const char *bs_set_classify(cmd_parms *cmd, void *dconf,
                            int argc, char *const argv[])
{
    (void)dconf;
    if (argc == 0) {
        return "BotShieldClassify: at least one argument required "
               "(On / Off / [All|None] [+/-flag]...)";
    }

    bs_server_cfg *scfg = ap_get_module_config(
        cmd->server->module_config, &botshield_module);
    if (!scfg) {
        return "BotShieldClassify: server config not initialized";
    }

    /* Standalone form: 'On' or 'Off' as the only argument. */
    if (argc == 1) {
        if (strcasecmp(argv[0], "On") == 0) {
            scfg->classify = BS_CLASSIFY_FLAGS_ALL;
            return NULL;
        }
        if (strcasecmp(argv[0], "Off") == 0) {
            scfg->classify = BS_CLASSIFY_FLAGS_NONE;
            return NULL;
        }
        /* fall through to compositional parsing */
    }

    /* Compositional form: optional [All|None] starting state, then
     * zero or more +flag / -flag deltas applied left-to-right. */

    /* On/Off are exclusive standalone tokens — reject when mixed. */
    for (int i = 0; i < argc; i++) {
        if (strcasecmp(argv[i], "On") == 0
            || strcasecmp(argv[i], "Off") == 0) {
            return apr_psprintf(cmd->pool,
                "BotShieldClassify: '%s' is a standalone token; "
                "cannot mix with other arguments. Use 'All' / 'None' "
                "for the compositional form.", argv[i]);
        }
    }

    /* Determine starting state and the index of the first delta. */
    bs_classify_flags state = BS_CLASSIFY_FLAGS_ALL;
    int first_delta = 0;
    if (strcasecmp(argv[0], "All") == 0) {
        state = BS_CLASSIFY_FLAGS_ALL;
        first_delta = 1;
    } else if (strcasecmp(argv[0], "None") == 0) {
        state = BS_CLASSIFY_FLAGS_NONE;
        first_delta = 1;
    } /* else implicit 'All', argv[0] is a delta — leave first_delta=0 */

    /* Apply deltas. */
    for (int i = first_delta; i < argc; i++) {
        const char *tok = argv[i];
        if (!tok || (tok[0] != '+' && tok[0] != '-')) {
            return apr_psprintf(cmd->pool,
                "BotShieldClassify: '%s' is not a valid delta — "
                "expected +<flag> or -<flag>", tok ? tok : "(null)");
        }
        unsigned char value = (tok[0] == '+') ? 1 : 0;
        if (!classify_flag_set(&state, tok + 1, value)) {
            return apr_psprintf(cmd->pool,
                "BotShieldClassify: unknown flag '%s' — recognized "
                "names are: browsers, known-bots, verified-bots, "
                "unknown-bots", tok + 1);
        }
    }

    scfg->classify = state;
    return NULL;
}

int bs_ua_is_declared_crawler(const bs_ua_class *cls)
{
    if (!cls || !cls->is_known_bot || cls->is_fake_bot) return 0;
    if (cls->known_category
        && strcmp(cls->known_category, "LIBRARY_OR_TOOL") == 0) {
        return 0;
    }
    return 1;
}
