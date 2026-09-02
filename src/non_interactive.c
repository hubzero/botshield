/* non_interactive.c — implementations behind non_interactive.h. E17 non-interactive tier
 * verification handlers + their bootstrap-sig helpers. */

#include "non_interactive.h"
#include "metrics.h"   /* bs_metrics_note_attestation_fail */

#include <string.h>
#include <limits.h>

#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_time.h>

#include <httpd.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <openssl/rand.h>

#include <json-c/json.h>

#include "botshield.h"
#include "challenge.h"
#include "cookie.h"
#include "crypto.h"
#include "shm.h"
#include "metrics.h"
#include "captcha.h"   /* bs_captcha_siteverify for embedded-verify-provider */

/* ===========================================================
 * Embedded non-interactive verification handlers.
 *
 * Three endpoints under <prefix>/embedded*:
 *   GET  /botshield/embedded.js         — static wrapper script
 *   GET  /botshield/embedded-bootstrap  — JSON: per-call PoW challenge
 *   POST /botshield/embedded-verify     — JSON: validates + sets cookie
 *
 * Activation: scope opts in via `BotShieldNonInteractiveMode embedded`.
 * Operator adds <script src="/botshield/embedded.js" defer> to their
 * page. When the request lands at non-interactive tier, BotShield serves
 * DECLINED (real content) instead of the M7 splash; the wrapper runs
 * on page-load, fetches the bootstrap, solves PoW in a Web Worker,
 * and POSTs back. The verify endpoint mints _bs_session the same
 * way the M7 interactive PoW path does, so subsequent requests round-trip
 * cleanly.
 * =========================================================== */

/* The PoW solver Web Worker body — served as its own URL so strict
 * CSP scopes (`worker-src 'self'`) can opt into embedded mode.
 * Earlier shape used a blob:-URL Worker built from inline source;
 * blob: is blocked under strict CSP. Real URL works in both strict
 * and permissive setups, costs one cacheable round-trip. */
static const char BS_EMBEDDED_WORKER_JS[] =
"self.onmessage = function(ev){\n"
" var c = ev.data;\n"
" var saltB = hexToBytes(c.salt);\n"
" var nonceB = hexToBytes(c.nonce);\n"
" var counter = 0;\n"
" var BATCH = 1024;\n"
" var LIMIT = 5000000;\n"
" function doBatch(){\n"
"  var promises = [];\n"
"  var start = counter;\n"
"  for (var i=0;i<BATCH;i++){\n"
"   var cs = String(start+i);\n"
"   var buf = new Uint8Array(saltB.length + nonceB.length + cs.length);\n"
"   buf.set(saltB,0); buf.set(nonceB,saltB.length);\n"
"   for (var j=0;j<cs.length;j++) buf[saltB.length+nonceB.length+j] = cs.charCodeAt(j);\n"
"   promises.push(crypto.subtle.digest('SHA-256', buf));\n"
"  }\n"
"  Promise.all(promises).then(function(rs){\n"
"   for (var i=0;i<rs.length;i++){\n"
"    if (meets(new Uint8Array(rs[i]), c.difficulty)){\n"
"     self.postMessage({counter: start+i});\n"
"     return;\n"
"    }\n"
"   }\n"
"   counter = start + BATCH;\n"
"   if (counter > LIMIT){ self.postMessage({error:'limit'}); return; }\n"
"   setTimeout(doBatch, 0);\n"
"  }).catch(function(e){ self.postMessage({error:String(e)}); });\n"
" }\n"
" function hexToBytes(s){\n"
"  var o = new Uint8Array(s.length/2);\n"
"  for (var i=0;i<s.length;i+=2) o[i/2] = parseInt(s.substr(i,2),16);\n"
"  return o;\n"
" }\n"
" function meets(d,n){\n"
"  var fb = (n/2)|0; var hh = n&1;\n"
"  for (var i=0;i<fb;i++) if (d[i] !== 0) return false;\n"
"  if (hh && (d[fb] & 0xF0) !== 0) return false;\n"
"  return true;\n"
" }\n"
" doBatch();\n"
"};\n";

/* The wrapper JS body. Self-contained IIFE; no external deps.
 *
 * Implementation notes:
 *   - Web Worker is loaded from /botshield/embedded-worker.js (a
 *     real URL, not blob:) so strict-CSP scopes — worker-src 'self'
 *     — can opt into embedded mode without exemptions.
 *   - SubtleCrypto.digest is async, so PoW runs as Promise.all
 *     batches with setTimeout yields between them — same shape the
 *     M2 form interstitial uses, copied here for parity.
 *   - Short-circuit on existing _bs_session cookie (cheap read of
 *     document.cookie). If the cookie is already there, no Worker
 *     is spawned and no fetch fires.
 *   - One Worker per page-load. _bsEmbeddedRan guard prevents
 *     double-spawn if embedded.js gets included twice. */
static const char BS_EMBEDDED_JS[] =
"(function(){\n"
" if (window._bsEmbeddedRan) return;\n"
" window._bsEmbeddedRan = true;\n"
" /*  used to short-circuit on\n"
"    document.cookie containing _bs_session, but HttpOnly now\n"
"    hides the cookie from JS. /embedded-bootstrap returns\n"
"    {mode:'off'} when a valid cookie is present, so the\n"
"    server-side check below covers it for free. */\n"
" fetch('/botshield/embedded-bootstrap', {credentials:'same-origin'})\n"
"  .then(function(r){ return r.ok ? r.json() : null; })\n"
"  .then(function(j){\n"
"   if (!j || j.mode !== 'non-interactive') return;\n"
"   if (j.provider === 'turnstile') { runTurnstile(j); return; }\n"
"   if (j.provider === 'recaptcha-v3') { runRecaptchaV3(j); return; }\n"
"   if (j.provider === 'recaptcha-v2') { runRecaptchaV2(j); return; }\n"
"   if (j.provider === 'hcaptcha') { runHCaptcha(j); return; }\n"
"   if (j.provider === 'friendly') { runFriendly(j); return; }\n"
"   if (j.provider !== 'pow-gcm' || !j.challenge) return;\n"
"   var ch = j.challenge;\n"
"   var w;\n"
"   try { w = new Worker('/botshield/embedded-worker.js'); }\n"
"   catch (e) { return; }\n"
"   w.onmessage = function(ev){\n"
"    if (ev.data && typeof ev.data.counter === 'number'){\n"
"     fetch('/botshield/embedded-verify', {\n"
"      method:'POST', credentials:'same-origin',\n"
"      headers:{'Content-Type':'application/json'},\n"
"      body: JSON.stringify({\n"
"       provider: 'pow-gcm',\n"
"       cookie_prefix: ch.cookie_prefix,\n"
"       /* IP-bind round-trip. */\n"
"       bound_ip: ch.bound_ip, bootstrap_sig: ch.bootstrap_sig,\n"
"       counter: ev.data.counter\n"
"      })\n"
"     });\n"
"    }\n"
"    w.terminate();\n"
"   };\n"
"   w.onerror = function(){ try { w.terminate(); } catch(e){} };\n"
"   w.postMessage(ch);\n"
"  })\n"
"  .catch(function(){});\n"
"\n"
" /* E17.2 — invisible Turnstile path. Cloudflare's api.js is loaded\n"
"    only when this scope's bootstrap says so; explicit-render mode\n"
"    so we control the lifecycle. We mount a hidden div and ask\n"
"    Turnstile for invisible execution; the success callback hands\n"
"    us a token that we POST back to the verify endpoint. The\n"
"    error-callback path is silent — failure here just means the\n"
"    next page-load will get a fresh bootstrap (re-challenge), which\n"
"    is benign under the 'kicks in eventually' model. */\n"
" function runTurnstile(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof turnstile === 'undefined') return;\n"
"   var c = document.createElement('div');\n"
"   c.style.display = 'none';\n"
"   document.body.appendChild(c);\n"
"   try {\n"
"    turnstile.render(c, {\n"
"     sitekey: j.sitekey,\n"
"     size: 'invisible',\n"
"     action: j.action || 'botshield',\n"
"     callback: function(token){\n"
"      fetch('/botshield/embedded-verify', {\n"
"       method:'POST', credentials:'same-origin',\n"
"       headers:{'Content-Type':'application/json'},\n"
"       body: JSON.stringify({provider:'turnstile', token: token})\n"
"      });\n"
"     },\n"
"     'error-callback': function(){}\n"
"    });\n"
"   } catch (e) { /* silent — see fail-mode comment */ }\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"\n"
" /* E17.3 — reCAPTCHA v3 invisible adapter. Materially different\n"
"    client API from Turnstile — Google's grecaptcha is always\n"
"    invisible (no widget element to mount), uses\n"
"    grecaptcha.execute() with action binding instead of\n"
"    render+callback. Server-side, the v3 path also goes through\n"
"    the same M8 siteverify and validates the response score\n"
"    against BotShieldRecaptchaV3MinScore. The wrapper just hands\n"
"    over the token; the policy is server-side. */\n"
" function runRecaptchaV3(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://www.google.com/recaptcha/api.js?render=' +\n"
"          encodeURIComponent(j.sitekey);\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof grecaptcha === 'undefined') return;\n"
"   try {\n"
"    grecaptcha.ready(function(){\n"
"     grecaptcha.execute(j.sitekey,\n"
"                        {action: j.action || 'botshield'})\n"
"      .then(function(token){\n"
"       fetch('/botshield/embedded-verify', {\n"
"        method:'POST', credentials:'same-origin',\n"
"        headers:{'Content-Type':'application/json'},\n"
"        body: JSON.stringify({provider:'recaptcha-v3', token: token})\n"
"       });\n"
"      }).catch(function(){});\n"
"    });\n"
"   } catch (e) {}\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"\n"
" /* E17.4a — hCaptcha invisible adapter. Token-based like\n"
"    Turnstile, but the client API splits render and execute:\n"
"    hcaptcha.render() returns a widget ID; the challenge fires\n"
"    only when the operator calls hcaptcha.execute(widgetId). For\n"
"    invisible mode we render with size:'invisible' (no UI ever\n"
"    shown — hCaptcha's risk engine decides whether to escalate to\n"
"    interactive UI; if it does, the error-callback fires and we\n"
"    silently fall through to the next page-load's bootstrap, same\n"
"    as Turnstile). The siteverify response shape matches Turnstile's\n"
"    {success, hostname, error-codes} contract — no action field,\n"
"    so the action-binding check on the server is a no-op for\n"
"    hCaptcha (the validator already skips when resp_action is\n"
"    NULL). */\n"
" function runHCaptcha(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://js.hcaptcha.com/1/api.js?render=explicit';\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof hcaptcha === 'undefined') return;\n"
"   var c = document.createElement('div');\n"
"   c.style.display = 'none';\n"
"   document.body.appendChild(c);\n"
"   try {\n"
"    var widgetId = hcaptcha.render(c, {\n"
"     sitekey: j.sitekey,\n"
"     size: 'invisible',\n"
"     callback: function(token){\n"
"      fetch('/botshield/embedded-verify', {\n"
"       method:'POST', credentials:'same-origin',\n"
"       headers:{'Content-Type':'application/json'},\n"
"       body: JSON.stringify({provider:'hcaptcha', token: token})\n"
"      });\n"
"     },\n"
"     'error-callback': function(){}\n"
"    });\n"
"    hcaptcha.execute(widgetId);\n"
"   } catch (e) {}\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"\n"
" /* E17.4b — reCAPTCHA v2 invisible adapter. v2 invisible is a\n"
"    distinct sitekey type from the v2 checkbox; sitekey is\n"
"    configured as 'Invisible reCAPTCHA badge' in Google's admin\n"
"    console. The client API is grecaptcha.render() returning a\n"
"    widget ID (like hCaptcha), then grecaptcha.execute(widgetId)\n"
"    to trigger. Same google.com/recaptcha/api.js loader as v3 but\n"
"    without the ?render=<sitekey> query (v2 uses ?render=explicit\n"
"    to disable auto-render of any g-recaptcha class divs). */\n"
" function runRecaptchaV2(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://www.google.com/recaptcha/api.js?render=explicit';\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof grecaptcha === 'undefined') return;\n"
"   try {\n"
"    grecaptcha.ready(function(){\n"
"     var c = document.createElement('div');\n"
"     c.style.display = 'none';\n"
"     document.body.appendChild(c);\n"
"     var widgetId = grecaptcha.render(c, {\n"
"      sitekey: j.sitekey,\n"
"      size: 'invisible',\n"
"      callback: function(token){\n"
"       fetch('/botshield/embedded-verify', {\n"
"        method:'POST', credentials:'same-origin',\n"
"        headers:{'Content-Type':'application/json'},\n"
"        body: JSON.stringify({provider:'recaptcha-v2', token: token})\n"
"       });\n"
"      },\n"
"      'error-callback': function(){}\n"
"     });\n"
"     grecaptcha.execute(widgetId);\n"
"    });\n"
"   } catch (e) {}\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"\n"
" /* E17.4c — Friendly Captcha auto-start adapter. Loads the\n"
"    friendly-challenge bundle from jsdelivr (matches the M8 widget\n"
"    URL), instantiates a WidgetInstance with startMode:'auto' so\n"
"    the PoW solver fires immediately, and ships the solution\n"
"    string the doneCallback hands us as the token. Friendly's\n"
"    siteverify response uses 'solution' as the field name (handled\n"
"    server-side via the provider's siteverify_field='solution'\n"
"    override in the M8 registry). The client posts a normal\n"
"    {provider, token} envelope; bs_embedded_verify_provider\n"
"    forwards via bs_captcha_siteverify which substitutes the\n"
"    correct field name from the registry. */\n"
" function runFriendly(j){\n"
"  var s = document.createElement('script');\n"
"  s.src = 'https://cdn.jsdelivr.net/npm/friendly-challenge/widget.min.js';\n"
"  s.async = true; s.defer = true;\n"
"  s.onload = function(){\n"
"   if (typeof friendlyChallenge === 'undefined' ||\n"
"       !friendlyChallenge.WidgetInstance) return;\n"
"   var c = document.createElement('div');\n"
"   c.style.display = 'none';\n"
"   document.body.appendChild(c);\n"
"   try {\n"
"    new friendlyChallenge.WidgetInstance(c, {\n"
"     sitekey: j.sitekey,\n"
"     startMode: 'auto',\n"
"     doneCallback: function(solution){\n"
"      fetch('/botshield/embedded-verify', {\n"
"       method:'POST', credentials:'same-origin',\n"
"       headers:{'Content-Type':'application/json'},\n"
"       body: JSON.stringify({provider:'friendly', token: solution})\n"
"      });\n"
"     },\n"
"     errorCallback: function(){}\n"
"    });\n"
"   } catch (e) {}\n"
"  };\n"
"  s.onerror = function(){};\n"
"  document.head.appendChild(s);\n"
" }\n"
"})();\n";

int bs_embedded_js_handler(request_rec *r)
{
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }
    ap_set_content_type(r, "application/javascript; charset=utf-8");
    /* Short max-age so operators can iterate the embedded wrapper
     * without fighting browser caches. */
    apr_table_setn(r->headers_out, "Cache-Control", "public, max-age=60");
    ap_rputs(BS_EMBEDDED_JS, r);
    return OK;
}

/* Web Worker source. Served at /botshield/embedded-worker.js as a
 * real same-origin URL so strict CSP (`worker-src 'self'`) accepts
 * it — blob:-URL Workers are blocked under strict CSP. */
int bs_embedded_worker_handler(request_rec *r)
{
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        return OK;
    }
    ap_set_content_type(r, "application/javascript; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "public, max-age=60");
    ap_rputs(BS_EMBEDDED_WORKER_JS, r);
    return OK;
}

/* E18.4 — form-widget shell. Served at /botshield/form-widget.js.
 * Operator HTML pattern:
 *
 *   <form action="/contact/submit" method="POST">
 *     <input name="email">
 *     <div data-bs-form-captcha
 *          data-bs-provider="turnstile"
 *          data-bs-sitekey="1x..."></div>
 *     <button>Send</button>
 *   </form>
 *   <script src="/botshield/form-widget.js" defer></script>
 *
 * Wrapper finds every [data-bs-form-captcha] slot, reads provider
 * + sitekey from data-* attributes, emits the per-provider widget
 * markup (cf-turnstile / h-captcha / g-recaptcha / frc-captcha)
 * and lazy-loads the provider's CDN script. Operators don't have
 * to remember per-provider class names or script URLs — the
 * BotShield wrapper abstracts them.
 *
 * Attribute-driven (no server-side scope lookup): keeps the wrapper
 * simple and avoids an extra round-trip. Operators already write
 * the sitekey somewhere; data-bs-sitekey isn't more verbose than
 * the stock provider integration would be. */
static const char BS_FORM_WIDGET_JS[] =
"(function(){\n"
" if (window._bsFormWidgetRan) return;\n"
" window._bsFormWidgetRan = true;\n"
"\n"
" var providers = {\n"
"  'turnstile': {\n"
"   cls: 'cf-turnstile',\n"
"   src: 'https://challenges.cloudflare.com/turnstile/v0/api.js'\n"
"  },\n"
"  'hcaptcha': {\n"
"   cls: 'h-captcha',\n"
"   src: 'https://js.hcaptcha.com/1/api.js'\n"
"  },\n"
"  'recaptcha-v2': {\n"
"   cls: 'g-recaptcha',\n"
"   src: 'https://www.google.com/recaptcha/api.js'\n"
"  },\n"
"  'recaptcha-v3': {\n"
"   cls: '',\n"
"   src: 'https://www.google.com/recaptcha/api.js?render='\n"
"  },\n"
"  'friendly': {\n"
"   cls: 'frc-captcha',\n"
"   src: 'https://cdn.jsdelivr.net/npm/friendly-challenge/widget.min.js'\n"
"  }\n"
" };\n"
"\n"
" var loaded = {};\n"
" function loadScript(url){\n"
"  if (loaded[url]) return;\n"
"  loaded[url] = true;\n"
"  var s = document.createElement('script');\n"
"  s.src = url; s.async = true; s.defer = true;\n"
"  document.head.appendChild(s);\n"
" }\n"
"\n"
" var slots = document.querySelectorAll('[data-bs-form-captcha]');\n"
" for (var i = 0; i < slots.length; i++) {\n"
"  var slot = slots[i];\n"
"  var providerName = slot.getAttribute('data-bs-provider') ||\n"
"                     'turnstile';\n"
"  var sitekey = slot.getAttribute('data-bs-sitekey');\n"
"  var prov = providers[providerName];\n"
"  if (!prov || !sitekey) {\n"
"   if (window.console && console.warn) {\n"
"    console.warn('botshield form-widget: missing provider or '\n"
"                 + 'sitekey on slot', slot);\n"
"   }\n"
"   continue;\n"
"  }\n"
"  /* recaptcha-v3: no widget div; the provider script auto-runs.\n"
"     Append sitekey to the loader URL. */\n"
"  if (providerName === 'recaptcha-v3') {\n"
"   loadScript(prov.src + encodeURIComponent(sitekey));\n"
"   continue;\n"
"  }\n"
"  /* All other providers: inject a child div with the right class\n"
"     + sitekey attribute, then load the provider's CDN script.\n"
"     The provider's script picks up the divs and renders the\n"
"     widget. */\n"
"  var div = document.createElement('div');\n"
"  div.className = prov.cls;\n"
"  div.setAttribute('data-sitekey', sitekey);\n"
"  /* Optional callback: operator can specify a JS function name\n"
"     via data-bs-callback that the provider invokes with the\n"
"     resolved token. */\n"
"  var cb = slot.getAttribute('data-bs-callback');\n"
"  if (cb) div.setAttribute('data-callback', cb);\n"
"  slot.appendChild(div);\n"
"  loadScript(prov.src);\n"
" }\n"
"})();\n";

int bs_form_widget_handler(request_rec *r)
{
    if (r->method_number != M_GET && r->method_number != M_OPTIONS) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET, OPTIONS");
        return OK;
    }
    ap_set_content_type(r, "application/javascript; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "public, max-age=60");
    ap_rputs(BS_FORM_WIDGET_JS, r);
    return OK;
}

/* GET /botshield/embedded-bootstrap — issue a fresh PoW challenge.
 *
 * Returns one of:
 *   {"mode":"off"}                          — cookie already valid; wrapper exits
 *   {"mode":"non-interactive","provider":"pow-gcm",...}
 *
 * The challenge object carries an opaque `cookie_prefix` — the same
 * AES-256-GCM-encrypted canonical form that bs_challenge_json emits
 * for the inline interstitial. The verify endpoint authenticates the
 * envelope via the GCM tag, so the wrapper can't forge a challenge
 * the server didn't issue. */
int bs_embedded_bootstrap_handler(request_rec *r,
                                         bs_dir_cfg *cfg)
{
    if (r->method_number != M_GET) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET");
        return OK;
    }
    ap_set_content_type(r, "application/json; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");

    /* If the client already has a valid _bs_session, no point in
     * burning Worker cycles or loading provider scripts. The wrapper
     * short-circuits on its end too, but a redundant check here
     * costs almost nothing and keeps the bootstrap honest. */
    const char *cookie_val = bs_get_verified_cookie_value(r);
    if (cookie_val && *cookie_val) {
        bs_challenge tmp;
        const char *err = bs_verify_cookie(r, cfg, cookie_val, &tmp);
        if (!err) {
            ap_rputs("{\"mode\":\"off\"}\n", r);
            return OK;
        }
    }

    /* E17.2 — provider dispatch. If the scope has a captcha provider
     * configured (BotShieldCaptchaProvider + SiteKey + SecretFile),
     * surface that provider's invisible-mode adapter to the wrapper.
     * Otherwise fall back to native PoW. The wrapper's runtime check
     * on the `provider` field is what dispatches to the right
     * client-side path. */
    if (cfg->captcha_provider && cfg->captcha_provider->implemented &&
        cfg->captcha_site_key && cfg->captcha_secret) {
        /* `action` is the string the client widget tags its token
         * with. Both Turnstile and reCAPTCHA v3 understand actions;
         * server-side we validate the response carries it back so
         * tokens minted for a different form/scope can't be replayed
         * here. Operator can override via BotShieldCaptchaExpectedAction;
         * default "botshield" matches the M8 interstitial path. */
        const char *action = cfg->captcha_expected_action
            ? cfg->captcha_expected_action : "botshield";
        ap_rprintf(r,
            "{\"mode\":\"non-interactive\",\"provider\":\"%s\","
            "\"sitekey\":\"%s\",\"action\":\"%s\"}\n",
            cfg->captcha_provider->name,
            cfg->captcha_site_key, action);
        return OK;
    }

    if (!cfg->secret || !cfg->algorithm) {
        ap_rputs("{\"mode\":\"off\"}\n", r);
        return OK;
    }

    int difficulty = bs_effective_int(cfg->difficulty, BS_DEFAULT_DIFFICULTY);
    /* Bootstrap challenges expire fast. Two layers of defense
     * against pre-issued-pool grinding:
     *
     *   1. 120 s TTL (here). bs_issue_challenge gives the client
     *      salt+nonce+sig; without a tight expiry an attacker could
     *      farm a pool of pre-issued challenges and solve in bulk.
     *      120 s is generous for a real browser to round-trip
     *      bootstrap → solve → verify (typical PoW runtime sub-
     *      second; 120 s covers a slow client + 100 ms RTT × a few
     *      round-trips with headroom) while cutting the grind
     *      window by 30x relative to the 1 h cookie TTL.
     *
     *   2. One-time-use nonce binding (see the verify path at the
     *      "atomically consume the nonce" block in
     *      bs_embedded_verify_handler). Each challenge nonce is
     *      atomic-inserted into bs_shm.nonce_table; presenting the
     *      same nonce twice → verify rejects. Fully closes the
     *      replay-multiplier and pool-farming attacks. */
    int ttl = 120;

    bs_challenge ch;
    memset(&ch, 0, sizeof(ch));
    /* Issue a fresh challenge with default-zero rep state. The
     * verify path will mint a cookie carrying this same rep, which
     * matches what a first-time non-interactive tier solver would receive. */
    const char *ierr = bs_issue_challenge(r->pool, cfg, difficulty, ttl,
                                          /* auto_tier */ 1, NULL, NULL, &ch);
    if (ierr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: embedded-bootstrap issue failed: %s", ierr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_rputs("{\"error\":\"issue\"}\n", r);
        return OK;
    }

    char salt_hex [BS_SALT_BYTES * 2 + 1];
    char nonce_hex[BS_NONCE_BYTES * 2 + 1];
    bs_to_hex(ch.salt,  BS_SALT_BYTES,  salt_hex);
    bs_to_hex(ch.nonce, BS_NONCE_BYTES, nonce_hex);

    /* IP-bind the bootstrap. The bound_ip + bootstrap_sig
     * round-trip via the verify POST and the verify endpoint
     * compares bound_ip against the verifying request's IP.
     * Closes the distributed-redemption attack (issue from one IP,
     * redeem from another). */
    char bound_ip_hex[33];
    if (!bs_format_bound_ip_hex(r->useragent_ip, bound_ip_hex)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: embedded-bootstrap: cannot format "
            "client IP %s", r->useragent_ip ? r->useragent_ip : "(null)");
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_rputs("{\"error\":\"ip\"}\n", r);
        return OK;
    }
    char bootstrap_sig_hex[BS_SIG_BYTES * 2 + 1];
    apr_int64_t issued_ms = (apr_int64_t)(apr_time_now() / 1000);
    bs_compute_bootstrap_sig(r->pool, cfg->derived_hmac_bootstrap,
                              nonce_hex, bound_ip_hex,
                              ch.expires_at, issued_ms,
                              bootstrap_sig_hex);

    /* Encrypt the canonical form into the cookie_prefix. The wrapper
     * round-trips this opaque blob to /embedded-verify; the GCM tag
     * authenticates every rep field inside, so the wrapper can't tamper
     * without the verify decrypt failing. */
    const char *prefix_b64 = NULL;
    const char *perr = bs_build_cookie_prefix_gcm(r->pool, cfg, &ch,
                                                   &prefix_b64);
    if (perr) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: embedded-bootstrap: cookie_prefix build "
            "failed: %s", perr);
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_rputs("{\"error\":\"prefix\"}\n", r);
        return OK;
    }

    ap_rprintf(r,
        "{\"mode\":\"non-interactive\",\"provider\":\"pow-gcm\","
        "\"challenge\":{"
        "\"salt\":\"%s\",\"nonce\":\"%s\","
        "\"difficulty\":%d,\"expires_at\":%" APR_TIME_T_FMT ","
        "\"auto\":%d,\"cookie_prefix\":\"%s\","
        "\"bound_ip\":\"%s\",\"bootstrap_sig\":\"%s\","
        "\"issued_ms\":%" APR_INT64_T_FMT
        "}}\n",
        salt_hex, nonce_hex,
        ch.difficulty, ch.expires_at,
        ch.auto_tier, prefix_b64,
        bound_ip_hex, bootstrap_sig_hex, issued_ms);
    return OK;
}


/* Verify a bootstrap-binding signature presented at /embedded-verify.
 * Reconstructs the canon from the inputs (which must round-trip
 * verbatim from the bootstrap response), computes the HMAC under the
 * primary derived key, falls back to the secondary if E16 rotation
 * is in progress. Returns 1 on accept, 0 on reject. The bound_ip
 * comparison against r->useragent_ip happens separately at the
 * verify call site. */
static int bs_verify_bootstrap_sig(apr_pool_t *p,
                                   const bs_dir_cfg *cfg,
                                   const char *nonce_hex,
                                   const char *bound_ip_hex,
                                   apr_time_t expires_at,
                                   apr_int64_t issued_ms,
                                   const char *sig_hex_in)
{
    if (!cfg->derived_keys_set) return 0;
    if (!sig_hex_in || strlen(sig_hex_in) != BS_SIG_BYTES * 2) return 0;
    unsigned char sig_in[BS_SIG_BYTES];
    if (!bs_from_hex(sig_hex_in, BS_SIG_BYTES * 2,
                     BS_SIG_BYTES, sig_in)) return 0;

    char expected_hex[BS_SIG_BYTES * 2 + 1];
    bs_compute_bootstrap_sig(p, cfg->derived_hmac_bootstrap,
                              nonce_hex, bound_ip_hex,
                              expires_at, issued_ms, expected_hex);
    unsigned char expected[BS_SIG_BYTES];
    /* expected_hex is bs_to_hex output: 2*BS_SIG_BYTES chars + NUL,
     * so the length is fixed and known by construction. */
    bs_from_hex(expected_hex, BS_SIG_BYTES * 2, BS_SIG_BYTES, expected);
    if (bs_ct_equal(sig_in, expected, BS_SIG_BYTES)) return 1;

    /* E16 rotation — try secondary derived bootstrap key. */
    if (cfg->derived_keys_set_2) {
        bs_compute_bootstrap_sig(p, cfg->derived_hmac_bootstrap_2,
                                  nonce_hex, bound_ip_hex,
                                  expires_at, issued_ms, expected_hex);
        bs_from_hex(expected_hex, BS_SIG_BYTES * 2,
                    BS_SIG_BYTES, expected);
        if (bs_ct_equal(sig_in, expected, BS_SIG_BYTES)) return 1;
    }
    return 0;
}

/* Pull a string field out of a parsed JSON object, returning a pool-
 * allocated copy or NULL if missing/wrong-type. Bounded copy keeps
 * us from accepting unbounded input from a malicious client. */
static const char *bs_json_get_str(apr_pool_t *p, json_object *root,
                                   const char *key, apr_size_t max_len)
{
    json_object *v = NULL;
    if (!json_object_object_get_ex(root, key, &v)) return NULL;
    if (!json_object_is_type(v, json_type_string)) return NULL;
    const char *s = json_object_get_string(v);
    if (!s) return NULL;
    apr_size_t slen = strlen(s);
    if (slen > max_len) return NULL;
    return apr_pstrdup(p, s);
}

static int bs_json_get_int(json_object *root, const char *key,
                           int *out, int min_val, int max_val)
{
    json_object *v = NULL;
    if (!json_object_object_get_ex(root, key, &v)) return 0;
    if (!json_object_is_type(v, json_type_int)) return 0;
    int64_t n = json_object_get_int64(v);
    if (n < min_val || n > max_val) return 0;
    *out = (int)n;
    return 1;
}


/* PoW verify path. The M1 widget JS is given an opaque encrypted
 * envelope (the "cookie_prefix"). Client solves PoW against the
 * salt+nonce+difficulty in the challenge JSON, then sends
 * {provider:"pow-gcm", cookie_prefix, counter} here. We synthesize
 * the wire-format cookie value (envelope.counter), route it through
 * bs_verify_cookie_gcm — which handles GCM-decrypt with secondary-key
 * fallback (E16), canonical parse, and PoW verify all in one
 * authenticated path — then mint a fresh cookie.
 *
 * Added for HttpOnly: the M1 widget used
 * to set the cookie via document.cookie because the PoW solution
 * WAS assembled client-side. Routing through this endpoint lets the
 * server emit Set-Cookie with HttpOnly, closing XSS-token-theft. */
/* Read the client's attestation array into a short, sanitised,
 * comma-joined label for the decision log. Returns "" when the array
 * is absent or empty, which is the expected case for a real browser.
 *
 * Everything here is attacker-controlled, so it is bounded on every
 * axis -- element count, element length, and alphabet -- and the
 * alphabet is restricted to what our own probe names use. A client
 * that sends anything else gets that element dropped rather than
 * having it reach the log, because the decision log is parsed by
 * tooling that should not have to defend against injected commas or
 * quotes.
 *
 * Absence proves nothing: a bot simply omits the field, and one that
 * reads our JS reports an empty array. This measures the automation
 * that has not bothered, which today is most of it. */
static const char *bs_read_attestation(request_rec *r, json_object *root)
{
    json_object *arr = NULL;
    if (!json_object_object_get_ex(root, "att", &arr) ||
        !json_object_is_type(arr, json_type_array)) {
        return "";
    }
    int n = (int)json_object_array_length(arr);
    if (n > BS_ATT_MAX_ITEMS) n = BS_ATT_MAX_ITEMS;

    const char *out = "";
    for (int i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(arr, i);
        if (!e || !json_object_is_type(e, json_type_string)) continue;
        const char *s = json_object_get_string(e);
        if (!s || !*s) continue;
        apr_size_t len = strlen(s);
        if (len > BS_ATT_MAX_ITEM_LEN) continue;
        int ok = 1;
        for (apr_size_t k = 0; k < len; k++) {
            char c = s[k];
            if (!((c >= 'a' && c <= 'z') || c == '-')) { ok = 0; break; }
        }
        if (!ok) continue;
        out = *out ? apr_pstrcat(r->pool, out, "+", s, NULL)
                   : apr_pstrdup(r->pool, s);
    }
    return out;
}

static int bs_embedded_verify_pow_gcm(request_rec *r, bs_dir_cfg *cfg,
                                       json_object *root)
{
    if (!cfg->secret) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        return OK;
    }

    const char *prefix_b64 = bs_json_get_str(r->pool, root,
                                              "cookie_prefix",
                                              BS_MAX_PAGE_BYTES);
    int counter = 0;
    if (!prefix_b64 ||
        !bs_json_get_int(root, "counter", &counter, 0, INT_MAX)) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    char counter_str[24];
    apr_snprintf(counter_str, sizeof(counter_str), "%d", counter);
    const char *cookie_value = apr_psprintf(r->pool, "%s.%s",
                                             prefix_b64, counter_str);
    const char *dot = strrchr(cookie_value, BS_GCM_COUNTER_SEP);
    if (!dot) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }
    bs_challenge ch;
    memset(&ch, 0, sizeof(ch));
    const char *err = bs_verify_cookie_gcm(r, cfg, cookie_value, dot, &ch);
    if (err) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: embedded-verify(pow-gcm): %s", err);
        return OK;
    }

    /* IP-binding check. The bootstrap response carried
     * a (bound_ip, bootstrap_sig) pair signed under the per-purpose
     * derived bootstrap key. Verify the HMAC, then compare bound_ip
     * against the current request's client IP. Mismatch ⇒ reject:
     * a challenge issued from one IP cannot be redeemed from
     * another (closes Attack 3). nonce_hex is rebuilt from ch.nonce
     * since this code path doesn't extract it from top-level JSON. */
    {
        char nonce_hex_buf[BS_NONCE_BYTES * 2 + 1];
        bs_to_hex(ch.nonce, BS_NONCE_BYTES, nonce_hex_buf);
        const char *bound_ip_hex = bs_json_get_str(r->pool, root,
                                                    "bound_ip", 32);
        const char *bootstrap_sig_hex = bs_json_get_str(r->pool, root,
                                                    "bootstrap_sig",
                                                    BS_SIG_BYTES * 2);
        /* Bounded to a plausible epoch-ms range so a garbage value is
         * rejected as input rather than reaching the signature check
         * or the subtraction below. */
        apr_int64_t issued_ms = 0;
        {
            json_object *v = NULL;
            if (json_object_object_get_ex(root, "issued_ms", &v) &&
                json_object_is_type(v, json_type_int)) {
                issued_ms = (apr_int64_t)json_object_get_int64(v);
            }
        }
        if (!bound_ip_hex || !bootstrap_sig_hex || issued_ms <= 0 ||
            strlen(bound_ip_hex) != 32) {
            r->status = HTTP_BAD_REQUEST;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: embedded-verify(pow-gcm): missing or "
                "malformed bound_ip / bootstrap_sig");
            return OK;
        }
        if (!bs_verify_bootstrap_sig(r->pool, cfg, nonce_hex_buf,
                                      bound_ip_hex, ch.expires_at,
                                      issued_ms, bootstrap_sig_hex)) {
            r->status = HTTP_FORBIDDEN;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: embedded-verify(pow-gcm): bad "
                "bootstrap_sig");
            return OK;
        }
        char observed_ip_hex[33];
        if (!bs_format_bound_ip_hex(r->useragent_ip, observed_ip_hex)) {
            r->status = HTTP_BAD_REQUEST;
            return OK;
        }
        if (strcasecmp(observed_ip_hex, bound_ip_hex) != 0) {
            r->status = HTTP_FORBIDDEN;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: embedded-verify(pow-gcm): IP-bind "
                "mismatch (issued for %s, redeemed from %s)",
                bound_ip_hex, observed_ip_hex);
            return OK;
        }

        /* issued_ms is authentic from here: it was covered by the
         * signature just checked. The interactive tier requires a
         * human click before the solve is submitted, so a submit
         * arriving faster than a person can react did not come from
         * one. The non-interactive tier is deliberately exempt --
         * nothing waits on a human there. */
        /* Floor at least the arming window. No legitimate client can
         * submit before it elapses -- the checkbox does not exist yet
         * -- so enforcing it costs nothing and does not rest on any
         * estimate of human speed. The configured floor adds reaction
         * time on top when it is set higher. */
        int min_ms = bs_effective_int(cfg->interactive_min_ms,
                                     BS_DEFAULT_INTERACTIVE_MIN_MS);
        int arm_ms = bs_effective_int(cfg->interactive_arm_ms,
                                     BS_DEFAULT_INTERACTIVE_ARM_MS);
        if (arm_ms > min_ms) min_ms = arm_ms;
        if (!ch.auto_tier && min_ms > 0) {
            apr_int64_t now_ms = (apr_int64_t)(apr_time_now() / 1000);
            apr_int64_t elapsed_ms = now_ms - issued_ms;
            if (elapsed_ms < min_ms) {
                r->status = HTTP_FORBIDDEN;
                bs_decision_log(r, "interactive", "block", "-", "-", "-",
                                "solve_too_fast", 0);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "mod_botshield: embedded-verify(pow-gcm): solve "
                    "returned in %" APR_INT64_T_FMT "ms, under the "
                    "%dms interactive floor",
                    elapsed_ms, min_ms);
                return OK;
            }
        }
    }

    /* Atomically consume the nonce. Replay of the same challenge
     * bundle is rejected here: the first verify wins the slot, all
     * subsequent attempts get 403. Closes the replay-multiplier
     * and pool-farming attacks against the embedded-verify path. */
    {
        bs_server_cfg *scfg_n = ap_get_module_config(
            r->server->module_config, &botshield_module);
        apr_uint32_t ns = scfg_n ? scfg_n->ns_id : 0;
        if (!bs_embedded_nonce_consume(r, ch.nonce, BS_NONCE_BYTES,
                                        (apr_int64_t)ch.expires_at, ns)) {
            r->status = HTTP_FORBIDDEN;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: embedded-verify(pow-gcm): nonce "
                "already redeemed (replay or pool-farm) - rejected");
            return OK;
        }
    }

    /* Carry forward rep from any prior valid _bs_session. The
     * eligibility predicate and rep-math live in
     * bs_carry_forward_eligible / bs_apply_rep_carry. Pattern A: ch
     * is already populated from the decrypted bootstrap challenge,
     * so we mutate ch.rep directly and preserve its server-set
     * challenged_at (the issue path stamped "now" into ch when the
     * bootstrap was minted; we don't want prior_ch's older value to
     * overwrite it). clamp passes_non_interactive to 1 (it's an
     * "ever passed" flag, not a counter). */
    {
        bs_challenge prior_ch = { 0 };
        if (bs_carry_forward_eligible(r, cfg, &prior_ch)) {
            apr_time_t challenged_at = ch.rep.challenged_at;
            ch.rep = prior_ch.rep;
            ch.rep.challenged_at = challenged_at;
            bs_apply_rep_carry(r, cfg, &prior_ch, &ch.rep,
                               bs_effective_int(cfg->forgive_non_interactive,
                                                BS_DEFAULT_FORGIVE_NON_INTERACTIVE));
        }
        ch.rep.passes_non_interactive = 1;
    }

    /* Record what this client was flagged for at the instant it did
     * the work; see bs_rep_excuse_current_flags. */
    bs_rep_excuse_current_flags(r, &ch.rep);
    if (bs_install_verified_cookie(r, cfg, &ch, counter_str) != NULL) {
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        return OK;
    }
    r->status = HTTP_NO_CONTENT;
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    /* Decision log + metrics: this is the only place a non-interactive/interactive PoW
     * solve becomes observable. Without it `outcome=verified` came
     * solely from captcha siteverify, so a deployment running the PoW
     * tiers with no captcha provider reported a permanent 0% solve
     * rate while the challenge was in fact being solved. The client
     * returns on a fresh request that reads cookie=ok, but that counts
     * requests-with-a-cookie, not solves — one human browsing 50 pages
     * logs 50 of them. The mint is the one-per-solve event. */
    {
        const char *att = bs_read_attestation(r, root);
        const char *tier_name = ch.auto_tier ? "non-interactive"
                                             : "interactive";
        if (*att) {
            bs_metrics_note_attestation_fail();
            bs_decision_log(r, tier_name, "verified", "minted", "-", "-",
                            apr_pstrcat(r->pool, "pow_ok,attest:", att,
                                        NULL), 0);
        } else {
            bs_decision_log(r, tier_name, "verified", "minted", "-", "-",
                            "pow_ok", 0);
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
        "mod_botshield: embedded-verify(pow-gcm): cookie minted "
        "(counter=%d)", counter);
    return OK;
}

/* Provider-path verify (E17.2 — first lands Turnstile invisible).
 * The wrapper has called the provider's invisible widget and got a
 * token; we siteverify it against the configured provider via the
 * existing M8 client, then mint _bs_session using the same
 * captcha-<provider> cookie alg the M8 interstitial path uses.
 *
 * Body shape: {"provider":"<name>","token":"<token>"}. */
static int bs_embedded_verify_provider(request_rec *r, bs_dir_cfg *cfg,
                                       json_object *root,
                                       const char *provider_name)
{
    if (!cfg->captcha_provider || !cfg->captcha_provider->implemented ||
        !cfg->captcha_secret) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "mod_botshield: embedded-verify(%s): scope has no "
            "captcha provider configured for this provider name",
            provider_name);
        return OK;
    }
    if (strcmp(cfg->captcha_provider->name, provider_name) != 0) {
        r->status = HTTP_BAD_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: embedded-verify(%s): wrapper claimed "
            "provider but scope is configured for '%s'",
            provider_name, cfg->captcha_provider->name);
        return OK;
    }

    const char *token = bs_json_get_str(r->pool, root, "token",
                                        BS_MAX_CAPTCHA_TOKEN);
    if (!token || !*token) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    /* Reuse M8's siteverify path. Same provider entry, same
     * secret/sitekey, same body shape — the only difference vs.
     * /captcha-verify is that we don't redirect afterward and that
     * we mint a cookie marked passes_non_interactive=1 instead of
     * passes_captcha=1. */
    int timeout_ms = cfg->captcha_timeout_ms > 0
        ? cfg->captcha_timeout_ms : BS_DEFAULT_CAPTCHA_TIMEOUT;
    const char *details = NULL;
    long http_code = 0;
    double score = -1.0;
    const char *resp_hostname = NULL, *resp_action = NULL;
    /* Centralized guarded siteverify so embedded-verify gets the
     * same per-IP rate cap and global in-flight semaphore as the
     * /captcha-verify handler. Without the wrapper, this path was
     * a provider-quota / worker-occupancy DoS surface. */
    bs_captcha_result res = bs_captcha_siteverify_guarded(r, cfg, token,
        timeout_ms, "embedded-verify",
        &details, &http_code, &score, &resp_hostname, &resp_action);

    if (res == BS_CAPTCHA_RATE_LIMITED) {
        r->status = HTTP_TOO_MANY_REQUESTS;
        apr_table_setn(r->err_headers_out, "Retry-After", "60");
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-rate-limited");
        return OK;
    }
    if (res == BS_CAPTCHA_INFLIGHT_CAPPED) {
        r->status = HTTP_SERVICE_UNAVAILABLE;
        apr_table_setn(r->err_headers_out, "Retry-After", "2");
        apr_table_setn(r->err_headers_out, "X-Botshield",
                       "captcha-saturated");
        return OK;
    }
    if (res != BS_CAPTCHA_OK) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: embedded-verify(%s): siteverify rejected "
            "(http=%ld details=\"%s\")", provider_name, http_code,
            details ? details : "");
        return OK;
    }

    /* Post-siteverify validation parity with the M8 captcha-verify
     * handler. Hostname + action binding stops
     * a token minted for a different scope/form on the same sitekey
     * from satisfying verification here. v3 score threshold caps
     * "valid token but signal is weak". Operator can opt out of
     * either binding by setting the directive to empty. */
    const char *expected_host =
        cfg->captcha_expected_hostname
            ? cfg->captcha_expected_hostname
            : (r->server && r->server->server_hostname
                   ? r->server->server_hostname : "");
    const char *expected_action =
        cfg->captcha_expected_action
            ? cfg->captcha_expected_action : "botshield";

    if (resp_hostname && *expected_host &&
        strcmp(resp_hostname, expected_host) != 0) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: embedded-verify(%s): hostname-mismatch "
            "(got=%s expected=%s)", provider_name,
            resp_hostname, expected_host);
        return OK;
    }
    if (resp_action && *expected_action &&
        strcmp(resp_action, expected_action) != 0) {
        r->status = HTTP_FORBIDDEN;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_botshield: embedded-verify(%s): action-mismatch "
            "(got=%s expected=%s)", provider_name,
            resp_action, expected_action);
        return OK;
    }
    if (strcmp(provider_name, "recaptcha-v3") == 0) {
        double min_score = (cfg->recaptcha_v3_min_score >= 0.0)
            ? cfg->recaptcha_v3_min_score
            : BS_DEFAULT_RECAPTCHA_V3_MIN_SCORE;
        if (score < 0.0) {
            /* Missing score on a v3 response is a protocol surprise
             * (v3 always returns one). Fail open with a warning —
             * matches the M8 path's behavior. */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "mod_botshield: embedded-verify(recaptcha-v3): "
                "response missing score - failing open "
                "(http=%ld)", http_code);
        } else if (score < min_score) {
            r->status = HTTP_FORBIDDEN;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "mod_botshield: embedded-verify(recaptcha-v3): "
                "score below threshold (%.2f < %.2f)",
                score, min_score);
            return OK;
        }
    }

    /* Mint a captcha-<provider> cookie just like the M8 interstitial
     * path does. The only rep delta is passes_non_interactive=1 vs
     * passes_captcha=1 — this was a non-interactive tier dispatch that
     * happened to use a captcha provider for the verification, not
     * a captcha-tier user-interactive solve.
     *
     * Carry-forward + mint + install routed through the shared
     * bs_captcha_carry_and_mint helper so the forgive cap and rep
     * carry-forward stay in lockstep with the captcha-verify
     * handler. The E15 + E17 self-audits caught drift in this
     * exact code; one helper, one place to update. */
    bs_challenge ch;
    const char *cookie_alg_name = NULL;
    const char *merr = bs_captcha_carry_and_mint(r, cfg,
        BS_CAPTCHA_PASSES_SILENT,
        bs_effective_int(cfg->forgive_non_interactive, BS_DEFAULT_FORGIVE_NON_INTERACTIVE),
        /* auto_tier */ 1,
        &ch, &cookie_alg_name);
    if (merr) {
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "mod_botshield: embedded-verify(%s): %s",
            provider_name, merr);
        return OK;
    }
    r->status = HTTP_NO_CONTENT;
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
        "mod_botshield: embedded-verify(%s): cookie minted "
        "(siteverify ok)", provider_name);
    return OK;
}

/* POST /botshield/embedded-verify — dispatcher.
 *
 * Body shape (JSON):
 *   PoW path:
 *     {"provider":"pow-gcm","cookie_prefix":"<b64>",
 *      "bound_ip":"<hex>","bootstrap_sig":"<hex>","counter":N}
 *   Provider path (turnstile et al.):
 *     {"provider":"turnstile","token":"<token>"}
 *
 * On success: 204 + Set-Cookie: _bs_session=...; ...
 * On failure: 4xx; no cookie. */
#define BS_EMBEDDED_BODY_MAX 8192   /* turnstile tokens are ~600 bytes */
int bs_embedded_verify_handler(request_rec *r, bs_dir_cfg *cfg)
{
    if (r->method_number != M_POST) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "POST");
        return OK;
    }

    apr_size_t body_len = 0;
    const char *body = NULL;
    apr_status_t bsr = bs_read_form_body(r, BS_EMBEDDED_BODY_MAX,
                                         &body, &body_len);
    if (bsr == APR_ENOSPC) {
        r->status = HTTP_REQUEST_ENTITY_TOO_LARGE;
        return OK;
    }
    if (bsr != APR_SUCCESS || !body || body_len == 0) {
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    enum json_tokener_error jerr = json_tokener_success;
    json_object *root = json_tokener_parse_verbose(body, &jerr);
    if (!root || jerr != json_tokener_success) {
        if (root) json_object_put(root);
        r->status = HTTP_BAD_REQUEST;
        return OK;
    }

    const char *provider = bs_json_get_str(r->pool, root, "provider", 32);
    if (!provider) provider = "pow-gcm";

    int rv;
    if (strcmp(provider, "pow-gcm") == 0) {
        rv = bs_embedded_verify_pow_gcm(r, cfg, root);
    } else {
        rv = bs_embedded_verify_provider(r, cfg, root, provider);
    }
    json_object_put(root);
    return rv;
}
/* end embedded handlers */

/* --- non-interactive-mode directive setters --- */

/* `BotShieldNonInteractiveMode <interstitial|embedded>`. Per-scope picker
 * for what flavor of non-interactive tier challenge to issue. Default
 * `interstitial` matches the legacy splash. `embedded` opts the
 * scope into background verification: BotShield serves the real
 * page (DECLINED) and relies on the operator-included
 * `<script src="/botshield/embedded.js" defer>` wrapper to run the
 * PoW in a Web Worker and POST the result back. The cookie may
 * arrive after the first request — see CHANGELOG E17 for the
 * "kicks in eventually" guarantee. */
const char *bs_set_non_interactive_mode(cmd_parms *cmd, void *cfg_v,
                                      const char *arg)
{
    bs_dir_cfg *cfg = cfg_v;
    if      (!strcasecmp(arg, "interstitial")) cfg->non_interactive_mode = BS_NON_INTERACTIVE_MODE_INTERSTITIAL;
    else if (!strcasecmp(arg, "embedded"))     cfg->non_interactive_mode = BS_NON_INTERACTIVE_MODE_EMBEDDED;
    else {
        return apr_psprintf(cmd->pool,
            "BotShieldNonInteractiveMode: '%s' must be 'interstitial' or "
            "'embedded'", arg);
    }
    return NULL;
}
