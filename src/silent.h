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
 * bs_compute_bootstrap_sig) are exposed because the M7 challenge-
 * issuance JSON path in botshield.c also computes the same bound-IP
 * envelope. They'll move to challenge.h in the eventual challenge.c
 * extraction. */
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

/* --- Bootstrap-sig helpers (also called from M7 issuance) ----- *
 *
 * Format the request's client IP into a 33-byte hex string (16
 * bytes IPv6-mapped + NUL). Returns 1 on success, 0 if the client
 * IP isn't parseable as a numeric address. */
int  bs_format_bound_ip_hex(const char *useragent_ip,
                            char out_hex[33]);

/* HMAC-SHA-256 over (nonce_hex || bound_ip_hex || expires_at) under
 * the bootstrap-purpose derived key. Writes 65 chars (BS_SIG_BYTES*2
 * + NUL) of hex into out_sig_hex. */
void bs_compute_bootstrap_sig(apr_pool_t *p,
                              const unsigned char key[32],
                              const char *nonce_hex,
                              const char *bound_ip_hex,
                              apr_time_t expires_at,
                              char out_sig_hex[BS_SIG_BYTES * 2 + 1]);

#ifdef __cplusplus
}
#endif

#endif /* BOTSHIELD_SILENT_H */
