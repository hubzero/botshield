/* generated_verified_bots.c — auto-generated; do NOT edit by hand.
 *
 * Regenerated from vendor/verified-bots.json by
 * tools/gen-verified-bots.py. Edit the JSON or the generator,
 * then re-run via the Makefile rule.
 *
 * Defines bs_builtin_bots[] — the bundled set of verified-bot
 * entries (UA pattern + ranges-file metadata) the module ships
 * with. Composed with operator-declared BotShieldAllowBot
 * entries at post_config to form the active verified-bot
 * allowlist. */

#include <stddef.h>

#include "allowlist.h"

const bs_allow_bot_entry bs_builtin_bots[] = {
    { "googlebot", "Googlebot", NULL, NULL, 0 },
    { "bingbot", "bingbot", NULL, NULL, 0 },
    { "applebot", "Applebot", NULL, NULL, 0 },
    { "googleother", "GoogleOther", NULL, NULL, 0 },
    { "siteimprove", "Siteimprove.com", NULL, NULL, 0 },
    { NULL, NULL, NULL, NULL, 0 }
};
