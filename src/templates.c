/* templates.c — challenge page rendering.
 *
 * All the static HTML/CSS/JS strings used to build challenge
 * interstitials live here, plus bs_render_challenge_page which
 * fills in per-request substitutions (prompt, logo, help, the
 * inline challenge JSON or captcha sitekey/verify URL) and emits
 * the response.
 *
 * Two template tracks:
 *   PoW (M2/M7)     — BS_WIDGET_TEMPLATE: the visible-checkbox or
 *                     auto-submitting splash with embedded PoW
 *                     worker JS.
 *   Captcha (M8)    — BS_CAPTCHA_WIDGET_TEMPLATE plus reCAPTCHA-v3
 *                     and GeeTest variants, each calling out to
 *                     the provider's hosted widget JS.
 *
 * Page shell BS_DEFAULT_PAGE_TEMPLATE is the built-in default;
 * operators override via BotShieldChallengeFile (validated at
 * config time to contain the BS_WIDGET_MARKER placeholder). */
#include <string.h>

#include <httpd.h>
#include <http_log.h>
#include <http_protocol.h>
#include <apr_strings.h>

#include "botshield.h"
#include "captcha.h"     /* bs_mint_pending_cookie */
#include "templates.h"

/* Default help panel content. HTML allowed because the string is emitted
 * directly into the panel; admins override via BotShieldHelpFile. */
static const char BS_DEFAULT_HELP_HTML[] =
"<p>A quick automated check that filters out bots. Your browser solves "
"a small math puzzle in the background \xe2\x80\x94 no pictures to "
"identify, and nothing personal is sent. It usually takes a second "
"or two.</p>";

/* Embedded Guardian shield — used when BotShieldLogoFile isn't set. */
static const char BS_DEFAULT_LOGO_SVG[] =
"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\" "
"focusable=\"false\">"
"<defs><linearGradient id=\"bsg\" x1=\"0\" x2=\"0\" y1=\"0\" y2=\"1\">"
"<stop offset=\"0\" stop-color=\"#3b7a66\"/>"
"<stop offset=\"1\" stop-color=\"#1a3a2e\"/>"
"</linearGradient></defs>"
"<path d=\"M32 4 L56 12 V32 C56 46 44 56 32 60 C20 56 8 46 8 32 V12 Z\" "
"fill=\"url(#bsg)\" stroke=\"#0f2a22\" stroke-width=\"1.5\"/>"
"<path d=\"M19 32 L28 41 L45 22\" fill=\"none\" stroke=\"#fff3b0\" "
"stroke-width=\"5.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
"</svg>";

/* --- Challenge page templates ---
 *
 * Rendering is a two-step substitution:
 *
 *   1. BS_WIDGET_TEMPLATE — the self-contained widget block (scoped CSS,
 *      widget markup, help slot, live-status element, JS). apr_psprintf
 *      fills the content substitutions (prompt/%s, logo/%s, label/%s,
 *      help/%s, difficulty/%d, cookie_ttl/%d). This block carries all
 *      the styles needed to render the widget — no <head> CSS required.
 *
 *   2. BS_DEFAULT_PAGE_TEMPLATE — a page shell (<!DOCTYPE>, <head>, body
 *      layout) with a BS_WIDGET_MARKER placeholder where the widget
 *      block is injected. When the admin sets BotShieldChallengeFile,
 *      their file replaces this shell — but the widget block stays
 *      module-controlled so the JS/DOM contract doesn't drift.
 *
 * Targets WCAG 2.1 AA: body-text contrast >= 4.5:1, UI-component
 * contrast >= 3:1, visible :focus-visible outline, no color-only
 * affordances, aria-live polite status, prefers-reduced-motion aware.
 *
 * Keep literal `%` out of the template — escape as %% for real percent. */

static const char BS_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.75rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:left}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-widget{display:inline-flex;align-items:center;\n"
" background:#fafafa;border:1px solid #d3d9dd;border-radius:4px;\n"
" box-shadow:0 1px 1px rgba(0,0,0,.04);min-width:300px}\n"
".bs-widget.bs-bare{background:transparent;border:0;box-shadow:none;\n"
" min-width:0;padding:0}\n"
".bs-widget.bs-bare .bs-btn{padding:0;border-radius:4px}\n"
".bs-widget.bs-auto{background:transparent;border:0;box-shadow:none;\n"
" min-width:0;padding:0}\n"
".bs-widget.bs-auto .bs-btn{padding:.6rem 0;cursor:default;\n"
" pointer-events:none;justify-content:center}\n"
/* Silent-tier visual cleanup: the brand column is purely decorative
 * so display:none-ing it is fine, but the label carries the button's
 * accessible name — visually hide it via the screen-reader-only
 * technique so the a11y tree still exposes "Verify you are human"
 * to axe/screen readers. An earlier revision display:none'd the
 * label too, which made axe-core's button-name check fail
 * critical (caught by tests/pytests/test_browser_a11y.py). */
".bs-widget.bs-auto .bs-brand{display:none}\n"
".bs-widget.bs-auto .bs-label{position:absolute;width:1px;height:1px;\n"
" padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);\n"
" white-space:nowrap;border:0}\n"
".bs-widget.bs-auto ~ .bs-help-toggle,\n"
".bs-widget.bs-auto ~ .bs-help{display:none}\n"
".bs-btn{display:inline-flex;align-items:center;gap:.85rem;\n"
" flex:1;padding:.9rem 1rem;background:transparent;border:0;\n"
" font:inherit;color:#1f2530;cursor:pointer;text-align:left;\n"
" border-top-left-radius:4px;border-bottom-left-radius:4px}\n"
".bs-btn:focus-visible{outline:3px solid #2f5d50;outline-offset:-3px}\n"
".bs-check{width:28px;height:28px;border:2px solid #7a8487;\n"
" border-radius:3px;background:#fff;flex-shrink:0;position:relative}\n"
".bs-label{font-size:15px;font-weight:500;color:#1f2530}\n"
".bs-brand{display:flex;flex-direction:column;align-items:center;\n"
" gap:.15rem;padding:.65rem 1rem;border-left:1px solid #e4e7ea;\n"
" color:#55605e;line-height:1;user-select:none}\n"
".bs-brand svg{display:block;width:32px;height:32px}\n"
".bs-brand .nm{font-size:11px;font-weight:600;letter-spacing:.03em;\n"
" color:#1f2530;margin-top:.3rem}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-working .bs-check{border:none;background:transparent;\n"
" border:3px solid #e4e7ea;border-top-color:#2f5d50;\n"
" border-radius:50%%;animation:bs-spin .8s linear infinite}\n"
".bs-done .bs-check{background:#2f5d50;border-color:#2f5d50}\n"
".bs-done .bs-check::after{content:\"\";position:absolute;\n"
" left:9px;top:4px;width:6px;height:12px;border:solid #fff;\n"
" border-width:0 2.5px 2.5px 0;transform:rotate(45deg)}\n"
".bs-working .bs-btn,.bs-done .bs-btn{pointer-events:none}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-help-toggle{display:inline-flex;align-items:center;gap:.4rem;\n"
" background:transparent;border:0;padding:.25rem .5rem;font:inherit;\n"
" font-size:12px;color:#55605e;cursor:pointer;border-radius:3px}\n"
".bs-help-toggle:hover{color:#2f5d50}\n"
".bs-help-toggle:hover .bs-help-icon{background:#2f5d50}\n"
".bs-help-toggle:focus-visible{outline:2px solid #2f5d50;outline-offset:2px}\n"
".bs-help-icon{display:inline-flex;align-items:center;\n"
" justify-content:center;width:16px;height:16px;border-radius:50%%;\n"
" background:#55605e;color:#fff;font-size:11px;font-weight:700;line-height:1}\n"
".bs-help{max-width:420px;background:#eef2f0;border-left:3px solid #2f5d50;\n"
" border-radius:4px;padding:.85rem 1rem;font-size:13px;line-height:1.5;\n"
" color:#1f2530;text-align:left}\n"
".bs-help :first-child{margin-top:0}\n"
".bs-help :last-child{margin-bottom:0}\n"
".bs-help a{color:#2f5d50}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
"@keyframes bs-spin{to{transform:rotate(360deg)}}\n"
"@media (prefers-reduced-motion: reduce){\n"
" .bs-working .bs-check{animation:none;border-top-color:#7a8487}\n"
"}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<div class=\"bs-widget%s\" id=\"c\">\n"
" <button type=\"button\" class=\"bs-btn\" id=\"btn\""
" aria-describedby=\"msg\"%s>\n"
"  <span class=\"bs-check\" id=\"cb\" aria-hidden=\"true\"></span>\n"
"  %s"
" </button>\n"
" %s"
"</div>\n"
"%s"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script>window.__bsChallenge=%s;</script>\n"
"<script>\n"
"(function(){\n"
" var CH = window.__bsChallenge;\n"
" if (!CH) return;\n"
" /* The cookie is now server-minted via /botshield/embedded-verify,\n"
"    so the JS never references the name (, #2). */\n"
" var box = document.getElementById('c');\n"
" var msg = document.getElementById('msg');\n"
" var btn = document.getElementById('btn');\n"
" function hexToBytes(h){\n"
"  var b = new Uint8Array(h.length/2);\n"
"  for (var i=0; i<b.length; i++) b[i] = parseInt(h.substr(i*2,2),16);\n"
"  return b;\n"
" }\n"
" function meetsTarget(digest, difficulty){\n"
"  var fb = Math.floor(difficulty/2);\n"
"  for (var i=0; i<fb; i++) if (digest[i] !== 0) return false;\n"
"  if (difficulty & 1) return (digest[fb] >> 4) === 0;\n"
"  return true;\n"
" }\n"
" function begin(){\n"
"  box.classList.add('bs-working');\n"
"  btn.setAttribute('aria-disabled', 'true');\n"
"  startChallenge();\n"
" }\n"
" if (CH.auto){\n"
"  msg.textContent = 'Checking your browser\\u2026';\n"
"  if (document.readyState === 'loading') {\n"
"   document.addEventListener('DOMContentLoaded', begin, {once:true});\n"
"  } else {\n"
"   begin();\n"
"  }\n"
" } else {\n"
"  btn.addEventListener('click', function h(e){\n"
"   if(!e.isTrusted) return;\n"
"   btn.removeEventListener('click', h);\n"
"   begin();\n"
"  });\n"
" }\n"
" function startChallenge(){\n"
"  var saltB  = hexToBytes(CH.salt);\n"
"  var nonceB = hexToBytes(CH.nonce);\n"
"  var counter = 0;\n"
"  var BATCH = 2048;\n"
"  var t0 = Date.now();\n"
"  msg.textContent = 'Verifying\\u2026';\n"
"  function doBatch(){\n"
"   var promises = [];\n"
"   var start = counter;\n"
"   for (var i=0; i<BATCH; i++){\n"
"    var cstr = String(start+i);\n"
"    var buf = new Uint8Array(saltB.length + nonceB.length + cstr.length);\n"
"    buf.set(saltB, 0);\n"
"    buf.set(nonceB, saltB.length);\n"
"    for (var j=0; j<cstr.length; j++) buf[saltB.length+nonceB.length+j] = cstr.charCodeAt(j);\n"
"    promises.push(crypto.subtle.digest('SHA-256', buf));\n"
"   }\n"
"   Promise.all(promises).then(function(results){\n"
"    for (var i=0; i<results.length; i++){\n"
"     if (meetsTarget(new Uint8Array(results[i]), CH.difficulty)){\n"
"      finish(start+i); return;\n"
"     }\n"
"    }\n"
"    counter = start + BATCH;\n"
"    var elapsed = ((Date.now()-t0)/1000).toFixed(1);\n"
"    msg.textContent = 'Verifying\\u2026 (' + counter.toLocaleString() +\n"
"                      ' hashes, ' + elapsed + 's)';\n"
"    setTimeout(doBatch, 0);\n"
"   }).catch(function(err){\n"
"    msg.textContent = 'Verification failed: ' + (err && err.message || err);\n"
"   });\n"
"  }\n"
"  function finish(counterVal){\n"
"   box.classList.remove('bs-working');\n"
"   box.classList.add('bs-done');\n"
"   msg.textContent = 'Verified \\u2014 reloading\\u2026';\n"
"   /*  POST the solution to the server\n"
"      and let it mint the cookie via Set-Cookie + HttpOnly,\n"
"      instead of setting document.cookie locally. JS can't read\n"
"      the cookie back, but it doesn't need to: server validates\n"
"      and the next request's bs_handler accepts the new cookie.\n"
"      round-trip bound_ip + bootstrap_sig for\n"
"      IP-binding. */\n"
"   var body = JSON.stringify({\n"
"    provider: 'pow-gcm',\n"
"    cookie_prefix: CH.cookie_prefix,\n"
"    bound_ip: CH.bound_ip,\n"
"    bootstrap_sig: CH.bootstrap_sig,\n"
"    counter: counterVal\n"
"   });\n"
"   fetch('/botshield/embedded-verify', {\n"
"    method: 'POST',\n"
"    credentials: 'same-origin',\n"
"    headers: {'Content-Type':'application/json'},\n"
"    body: body\n"
"   }).then(function(resp){\n"
"    if (resp.ok || resp.status === 204) {\n"
"     setTimeout(function(){ location.reload(); }, 250);\n"
"    } else {\n"
"     msg.textContent = 'Verification failed (' + resp.status + ')';\n"
"    }\n"
"   }).catch(function(err){\n"
"    msg.textContent = 'Verification failed: ' +\n"
"                       (err && err.message || err);\n"
"   });\n"
"  }\n"
"  doBatch();\n"
" }\n"
" var ht = document.querySelector('.bs-help-toggle');\n"
" if (ht) {\n"
"  ht.addEventListener('click', function(){\n"
"   var expanded = ht.getAttribute('aria-expanded') === 'true';\n"
"   ht.setAttribute('aria-expanded', expanded ? 'false' : 'true');\n"
"   var panel = document.getElementById('bs-help');\n"
"   if (panel) panel.hidden = expanded;\n"
"  });\n"
" }\n"
"})();\n"
"</script>\n";

/* Captcha-tier widget template (M8). Embeds the provider's async script
 * + a container div with the provider's CSS class and our site key, and
 * a form that POSTs back to /<prefix>/captcha-verify when the provider's
 * JS callback fires. Printf substitutions (in order):
 *   %s script_url, %s form_action, %s return_to_esc, %s widget_class,
 *   %s site_key, %s provider_name_esc.
 * The scoped <style> block re-declares a small subset of the PoW widget
 * CSS so we don't depend on BS_WIDGET_TEMPLATE's styles being present. */
static const char BS_CAPTCHA_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.85rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:center}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-prompt{font-size:15px;font-weight:500;color:#1f2530;margin:0}\n"
".bs-sub{font-size:13px;color:#55605e;margin:0}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<p class=\"bs-prompt\">Please complete the check to continue.</p>\n"
"<p class=\"bs-sub\">Provided by %s.</p>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<form id=\"bscf\" method=\"POST\" action=\"%s\">\n"
" <input type=\"hidden\" name=\"return_to\" value=\"%s\">\n"
" <div class=\"%s\" data-sitekey=\"%s\" data-action=\"botshield\""
" data-callback=\"bsOnSolve\"></div>\n"
"</form>\n"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script src=\"%s\" async defer></script>\n"
"<script>\n"
"function bsOnSolve(token){\n"
" var m = document.getElementById('msg');\n"
" if (m) m.textContent = 'Verifying\\u2026';\n"
" document.getElementById('bscf').submit();\n"
"}\n"
"</script>\n";

/* reCAPTCHA v3 widget template (M8). Different from the render-pattern
 * template above — v3 has no visible widget; the script runs
 * grecaptcha.execute() on load and auto-submits the form once the
 * token comes back. Printf substitutions (in order):
 *   %s provider_name_esc, %s form_action, %s return_to_esc,
 *   %s token_field, %s script_url_with_render_param, %s sitekey_js_esc.
 * The CSS reuses the subset that BS_CAPTCHA_WIDGET_TEMPLATE defines so
 * we don't grow a second copy of every style rule. */
static const char BS_RECAPTCHA_V3_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.85rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:center}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-prompt{font-size:15px;font-weight:500;color:#1f2530;margin:0}\n"
".bs-sub{font-size:13px;color:#55605e;margin:0}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
".bs-spin{width:32px;height:32px;border:3px solid #e4e7ea;\n"
" border-top-color:#2f5d50;border-radius:50%%;\n"
" animation:bs-spin .8s linear infinite}\n"
"@keyframes bs-spin{to{transform:rotate(360deg)}}\n"
"@media (prefers-reduced-motion: reduce){\n"
" .bs-spin{animation:none;border-top-color:#7a8487}\n"
"}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<p class=\"bs-prompt\">Checking your browser\\u2026</p>\n"
"<div class=\"bs-spin\" aria-hidden=\"true\"></div>\n"
"<p class=\"bs-sub\">Provided by %s.</p>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<form id=\"bscf\" method=\"POST\" action=\"%s\">\n"
" <input type=\"hidden\" name=\"return_to\" value=\"%s\">\n"
" <input type=\"hidden\" name=\"%s\" id=\"bs-token\" value=\"\">\n"
"</form>\n"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script src=\"%s\" async defer></script>\n"
"<script>\n"
"(function(){\n"
" var sk = '%s';\n"
" function exec(){\n"
"  grecaptcha.ready(function(){\n"
"   grecaptcha.execute(sk, {action: 'botshield'}).then(function(t){\n"
"    document.getElementById('bs-token').value = t;\n"
"    var m = document.getElementById('msg');\n"
"    if (m) m.textContent = 'Verifying\\u2026';\n"
"    document.getElementById('bscf').submit();\n"
"   });\n"
"  });\n"
" }\n"
" function start(){\n"
"  if (typeof grecaptcha !== 'undefined' && grecaptcha.ready) {\n"
"   exec();\n"
"  } else {\n"
"   setTimeout(start, 50);\n"
"  }\n"
" }\n"
" if (document.readyState === 'loading') {\n"
"  document.addEventListener('DOMContentLoaded', start, {once:true});\n"
" } else {\n"
"  start();\n"
" }\n"
"})();\n"
"</script>\n";

/* GeeTest v4 widget template (M8). GeeTest neither renders into a
 * named div (like Turnstile/hCaptcha/v2/Friendly) nor calls execute
 * directly (like reCAPTCHA v3) — instead its gt4.js exposes a global
 * initGeetest4({captchaId, product}, callback) that produces a captcha
 * object the caller drops into a container and wires for onSuccess.
 * Printf substitutions (in order):
 *   %s provider_name_esc, %s form_action, %s return_to_esc,
 *   %s token_field, %s widget_script_url, %s sitekey_js_esc.
 * When the user solves the slider, our onSuccess handler pulls
 * captchaObj.getValidate() (a 4-field object) and stringifies it into
 * the hidden input named `token_field` so the verify handler can parse
 * it apart. */
static const char BS_GEETEST_WIDGET_TEMPLATE[] =
"<style>\n"
".bs-stack{display:flex;flex-direction:column;align-items:center;\n"
" gap:.85rem;width:100%%;max-width:540px;margin:0 auto;\n"
" font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;\n"
" color:#1f2530;text-align:center}\n"
".bs-stack *,.bs-stack *::before,.bs-stack *::after{box-sizing:border-box}\n"
".bs-prompt{font-size:15px;font-weight:500;color:#1f2530;margin:0}\n"
".bs-sub{font-size:13px;color:#55605e;margin:0}\n"
".bs-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;\n"
" overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}\n"
".bs-msg{font-size:12px;color:#55605e;min-height:1.3em;\n"
" text-align:center;word-break:break-word;max-width:320px;margin:0}\n"
".bs-noscript{padding:.9rem 1rem;color:#b02a37;background:#fdf4f4;\n"
" border:1px solid #f3c8c8;border-radius:4px}\n"
"#bs-gt{min-height:60px;display:flex;justify-content:center}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"<h1 class=\"bs-sr\">Verify you are human</h1>\n"
"<p class=\"bs-prompt\">Please complete the check to continue.</p>\n"
"<p class=\"bs-sub\">Provided by %s.</p>\n"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"<form id=\"bscf\" method=\"POST\" action=\"%s\">\n"
" <input type=\"hidden\" name=\"return_to\" value=\"%s\">\n"
" <input type=\"hidden\" name=\"%s\" id=\"bs-token\" value=\"\">\n"
"</form>\n"
"<div id=\"bs-gt\" aria-live=\"polite\"></div>\n"
"<p class=\"bs-msg\" id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n"
"</div>\n"
"<script src=\"%s\" async defer></script>\n"
"<script>\n"
"(function(){\n"
" var captchaId = '%s';\n"
" function boot(){\n"
"  if (typeof initGeetest4 === 'undefined') { setTimeout(boot, 50); return; }\n"
"  initGeetest4({captchaId: captchaId, product: 'bind'}, function(cap){\n"
"   cap.appendTo('#bs-gt');\n"
"   cap.onSuccess(function(){\n"
"    var v = cap.getValidate();\n"
"    document.getElementById('bs-token').value = JSON.stringify(v);\n"
"    var m = document.getElementById('msg');\n"
"    if (m) m.textContent = 'Verifying\\u2026';\n"
"    document.getElementById('bscf').submit();\n"
"   });\n"
"  });\n"
" }\n"
" if (document.readyState === 'loading') {\n"
"  document.addEventListener('DOMContentLoaded', boot, {once:true});\n"
" } else {\n"
"  boot();\n"
" }\n"
"})();\n"
"</script>\n";

/* Built-in page shell used when BotShieldChallengeFile isn't set. The
 * marker position mirrors what we ask admins to use in their templates —
 * one canonical insertion point inside <main>. */
static const char BS_DEFAULT_PAGE_TEMPLATE[] =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<meta name=\"robots\" content=\"noindex,nofollow\">\n"
"<meta name=\"theme-color\" content=\"#2f5d50\">\n"
"<title>Verify you are human</title>\n"
"<style>\n"
" html,body{margin:0;padding:0}\n"
" body{background:#f5f5f2;min-height:100vh;display:flex;\n"
"  flex-direction:column;align-items:center;justify-content:center;\n"
"  padding:1rem;font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<main>\n"
BS_WIDGET_MARKER "\n"
"</main>\n"
"</body>\n"
"</html>\n";

/* Render the challenge interstitial. Picks PoW or captcha widget,
 * splices into the page shell, writes the response. */
int bs_render_challenge_page(request_rec *r,
                             const bs_dir_cfg *cfg,
                             bs_tier tier,
                             const char *challenge_js,
                             int issue_auto)
{
    const char *prompt     = cfg->prompt     ? cfg->prompt     : BS_DEFAULT_PROMPT;
    const char *logo_svg   = cfg->logo_svg   ? cfg->logo_svg   : BS_DEFAULT_LOGO_SVG;
    const char *logo_label = cfg->logo_label ? cfg->logo_label : BS_DEFAULT_LOGO_LABEL;
    int help_mode  = bs_effective_int(cfg->help_mode,  BS_DEFAULT_HELP_MODE);
    int show_logo  = bs_effective_int(cfg->show_logo,  1);
    int show_label = bs_effective_int(cfg->show_label, 1);
    int show_box   = bs_effective_int(cfg->show_box,   1);
    const char *help_content = cfg->help_html ? cfg->help_html : BS_DEFAULT_HELP_HTML;

    const char *help_html = "";
    if (help_mode == BS_HELP_ON) {
        help_html = apr_psprintf(r->pool,
            "<div class=\"bs-help\" id=\"bs-help\">%s</div>\n", help_content);
    } else if (help_mode == BS_HELP_BUTTON) {
        help_html = apr_psprintf(r->pool,
            "<button type=\"button\" class=\"bs-help-toggle\""
            " aria-expanded=\"false\" aria-controls=\"bs-help\">"
            "<span class=\"bs-help-icon\" aria-hidden=\"true\">?</span>"
            "<span>What is this?</span></button>\n"
            "<div class=\"bs-help\" id=\"bs-help\" hidden>%s</div>\n",
            help_content);
    }

    /* Chrome toggles: build conditional widget fragments. When the label is
     * hidden, move the prompt text to an aria-label on the button so the
     * button keeps an accessible name. */
    const char *prompt_esc = ap_escape_html(r->pool, prompt);
    const char *widget_mod = apr_pstrcat(r->pool,
                                         show_box   ? "" : " bs-bare",
                                         issue_auto ? " bs-auto" : "",
                                         NULL);
    const char *aria_attr  = show_label
        ? ""
        : apr_psprintf(r->pool, " aria-label=\"%s\"", prompt_esc);
    const char *prompt_span = show_label
        ? apr_psprintf(r->pool,
              "<span class=\"bs-label\">%s</span>\n", prompt_esc)
        : "";
    const char *brand_div = show_logo
        ? apr_psprintf(r->pool,
              "<div class=\"bs-brand\" aria-hidden=\"true\">%s"
              "<span class=\"nm\">%s</span></div>\n",
              logo_svg, ap_escape_html(r->pool, logo_label))
        : "";

    /* Captcha tier (M8): if we're at captcha tier AND a provider is fully
     * configured, render the provider's widget instead of the PoW checkbox.
     * If captcha tier resolves but no provider/key/secret is configured,
     * the caller already issued a PoW challenge and we stub to form-PoW
     * here — preserves the pre-M8 fall-through behavior and lets operators
     * opt in to captcha only on scopes they've configured. */
    char *widget;
    int use_captcha_widget = (tier == BS_TIER_CAPTCHA)
        && cfg->captcha_provider
        && cfg->captcha_site_key
        && cfg->captcha_secret;
    if (use_captcha_widget) {
        /* M8.1: mint a short-lived HMAC-signed "pending" cookie so the
         * verify endpoint can short-circuit random POST spray before
         * calling libcurl. Set early so it rides out on the challenge
         * response. If mint fails (RAND_bytes) we still render — worst
         * case is the verify endpoint falls back to rate-limit + in-
         * flight cap as the only guardrails. */
        const char *pending = bs_mint_pending_cookie(r, cfg);
        if (pending) {
            apr_table_add(r->err_headers_out, "Set-Cookie", pending);
        }
        const char *prefix = cfg->endpoint_prefix
            ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
        /* Per-provider verify URL: {prefix}/captcha-verify/{provider}.
         * Encoding the provider in the path lets operators run multiple
         * providers on one vhost by giving each its own <Location> block
         * with the matching secret/sitekey. */
        const char *verify_url = apr_pstrcat(r->pool, prefix,
            "/captcha-verify/", cfg->captcha_provider->name, NULL);
        const char *return_esc  = ap_escape_html(r->pool,
            r->unparsed_uri ? r->unparsed_uri : "/");
        const char *provider_esc = ap_escape_html(r->pool,
            cfg->captcha_provider->name);
        const char *pname = cfg->captcha_provider->name;
        if (strcmp(pname, "recaptcha-v3") == 0) {
            /* v3 script URL embeds the sitekey in its query string, so
             * the render-pattern widget_script_url from the registry
             * isn't used directly — build it here instead. */
            const char *v3_script_url = apr_psprintf(r->pool,
                "%s?render=%s",
                cfg->captcha_provider->widget_script_url,
                cfg->captcha_site_key);
            widget = apr_psprintf(r->pool, BS_RECAPTCHA_V3_WIDGET_TEMPLATE,
                provider_esc,
                verify_url,
                return_esc,
                cfg->captcha_provider->token_field,
                v3_script_url,
                cfg->captcha_site_key);
        } else if (strcmp(pname, "geetest") == 0) {
            widget = apr_psprintf(r->pool, BS_GEETEST_WIDGET_TEMPLATE,
                provider_esc,
                verify_url,
                return_esc,
                cfg->captcha_provider->token_field,
                cfg->captcha_provider->widget_script_url,
                cfg->captcha_site_key);
        } else {
            widget = apr_psprintf(r->pool, BS_CAPTCHA_WIDGET_TEMPLATE,
                provider_esc,
                verify_url,
                return_esc,
                cfg->captcha_provider->widget_class,
                cfg->captcha_site_key,
                cfg->captcha_provider->widget_script_url);
        }
    } else {
        widget = apr_psprintf(r->pool, BS_WIDGET_TEMPLATE,
                              widget_mod,
                              aria_attr,
                              prompt_span,
                              brand_div,
                              help_html,
                              challenge_js);
    }

    const char *page = cfg->challenge_html ? cfg->challenge_html
                                           : BS_DEFAULT_PAGE_TEMPLATE;
    const char *marker_pos = strstr(page, BS_WIDGET_MARKER);

    char *body;
    if (marker_pos) {
        apr_size_t prefix_len = (apr_size_t)(marker_pos - page);
        body = apr_pstrcat(r->pool,
                           apr_pstrmemdup(r->pool, page, prefix_len),
                           widget,
                           marker_pos + sizeof(BS_WIDGET_MARKER) - 1,
                           NULL);
    } else {
        /* Shouldn't happen — config-time check rejects files without the
         * marker, and the built-in default has it hard-coded. Fall back to
         * appending so we still serve *something* if someone trips this. */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_botshield: challenge page has no '%s' marker; "
                      "appending widget at end", BS_WIDGET_MARKER);
        body = apr_pstrcat(r->pool, page, widget, NULL);
    }

    r->status = HTTP_OK;
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Botshield",   "challenge");
    ap_rputs(body, r);

    return use_captcha_widget;
}
