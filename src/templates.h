/* templates.h — challenge-page rendering.
 *
 * Owns the static HTML/CSS/JS template strings for both the PoW
 * widget (M2/M7) and the captcha-tier widgets (M8: Turnstile,
 * hCaptcha, reCAPTCHA v2/v3, Friendly, GeeTest), plus the page
 * shell that hosts them. Plus the render function that fills in
 * the per-request substitutions and emits the response body.
 *
 * Per-tier interstitial mapping (driven by bs_decide_tier in
 * botshield.c):
 *   silent  → auto-submit splash (no user click)
 *   form    → reCAPTCHA-shaped checkbox the JS solves
 *   captcha → configured third-party provider's widget
 *
 * When captcha tier is selected but no provider is configured on
 * the scope, the render code falls through to form-PoW (documented
 * in the decision log as reason="captcha_fallback").
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

/* Built-in safeguard explainer page handler, served at
 * <BotShieldEndpointPrefix>/safeguard-info. Reads `?return=` for the
 * continue link and renders a static HTML explanation of why the
 * client landed here (auto-check failed N times). The counter reset
 * already happened upstream in bs_apply_safeguard, so this handler
 * is a pure render. GET only. */
int bs_safeguard_info_handler(request_rec *r);

/* <prefix>/preview/{silent,form}. Renders the real interstitial with a
 * deliberately unsolvable payload so the page can be looked at in its
 * working state. Mints nothing and changes no state. */
int bs_preview_handler(request_rec *r, int want_auto);

/* <prefix>/preview -- index of the client-facing pages, so they are
 * discoverable without reading the source. */
int bs_preview_index_handler(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_TEMPLATES_H */
