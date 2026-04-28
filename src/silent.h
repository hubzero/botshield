/* silent.h — E17 silent-tier verification handlers.
 *
 * The silent tier (BS_TIER_SILENT) hands the proof-of-work off to a
 * Web Worker on the page rather than serving an interstitial. Three
 * endpoints make up the round-trip:
 *
 *   GET  <prefix>/embedded.js          static wrapper script
 *   GET  <prefix>/embedded-worker.js   PoW solver Web Worker body
 *   GET  <prefix>/embedded-bootstrap   JSON: per-call PoW challenge,
 *                                      IP-bound via HMAC
 *   POST <prefix>/embedded-verify      JSON: client posts solved
 *                                      counter (PoW-GCM) or captcha
 *                                      provider token, gets
 *                                      _bs_verified back
 *
 * Plus a side endpoint:
 *
 *   GET  <prefix>/widget.html          form-tier interstitial widget
 *                                      iframe content (E18 / form
 *                                      captcha — lives here because
 *                                      it shares the small-static-
 *                                      handler shape).
 *
 * The bootstrap-sig helpers (bs_format_bound_ip_hex,
 * bs_compute_bootstrap_sig) used by both /embedded-bootstrap and
 * /embedded-verify live in challenge.h alongside the rest of the
 * challenge-minting code. */
#ifndef BOTSHIELD_SILENT_H
#define BOTSHIELD_SILENT_H

#include <httpd.h>

#include "botshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- Static handlers (no cfg dependency) ------------------------ */

int bs_embedded_js_handler(request_rec *r);
int bs_embedded_worker_handler(request_rec *r);
int bs_form_widget_handler(request_rec *r);

/* --- Cfg-driven handlers --------------------------------------- */

int bs_embedded_bootstrap_handler(request_rec *r, bs_dir_cfg *cfg);
int bs_embedded_verify_handler(request_rec *r, bs_dir_cfg *cfg);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_SILENT_H */
