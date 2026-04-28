/* templates.h — challenge-page rendering.
 *
 * Owns the static HTML/CSS/JS template strings for both the PoW
 * widget (M2/M7) and the captcha-tier widgets (M8: Turnstile,
 * hCaptcha, reCAPTCHA v2/v3, Friendly, GeeTest), plus the page
 * shell that hosts them. Plus the render function that fills in
 * the per-request substitutions and emits the response body.
 *
 * Two-step substitution model:
 *
 *   1. Widget template is filled with the per-request bits (prompt,
 *      logo, label, help, the inline challenge JSON or captcha
 *      site key + verify URL). Result is a self-contained widget
 *      block with scoped CSS.
 *   2. Page shell (built-in BS_DEFAULT_PAGE_TEMPLATE or operator's
 *      BotShieldChallengeFile) gets the widget block spliced in at
 *      its BS_WIDGET_MARKER placeholder.
 *
 * The render function sets r->status, content-type, cache-control,
 * and X-Botshield: challenge headers, then ap_rputs the body.
 * Caller is responsible for the surrounding decision-log entry. */
#ifndef BOTSHIELD_TEMPLATES_H
#define BOTSHIELD_TEMPLATES_H

#include <httpd.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Render the challenge interstitial. Picks PoW or captcha widget
 * based on tier + cfg state, splices into the page shell, writes
 * the response.
 *
 *   r            — request to write to
 *   cfg          — directory cfg with prompt/logo/help/captcha bits
 *   tier         — silent/form/captcha (drives widget choice)
 *   challenge_js — the inline-challenge JSON from bs_challenge_json
 *   issue_auto   — 1 for the auto-submitting silent splash, 0 for
 *                  the visible-checkbox form-PoW
 *
 * Returns 1 if served via a captcha provider widget (caller logs
 * the captcha alg), 0 if served via the PoW widget. */
int bs_render_challenge_page(request_rec *r,
                             const bs_dir_cfg *cfg,
                             bs_tier tier,
                             const char *challenge_js,
                             int issue_auto);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_TEMPLATES_H */
