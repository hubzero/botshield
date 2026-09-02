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
#include <http_core.h>   /* ap_get_server_name */
#include <apr_strings.h>

#include "botshield.h"
#include "captcha.h"     /* bs_mint_pending_cookie */
#include "metrics.h"    /* bs_bot_share_pct */
#include "templates.h"

/* Default help panel content. HTML allowed because the string is emitted
 * directly into the panel; admins override via BotShieldHelpFile. */
static const char BS_DEFAULT_HELP_HTML[] =
"<p>A quick automated check that filters out bots. Your browser solves "
"a small math puzzle in the background \xe2\x80\x94 no pictures to "
"identify, and nothing personal is sent. It usually takes a second "
"or two.</p>";

/* Shown on the non-interactive tier only, and only once the solve has run
 * longer than a person is willing to watch a spinner. Deliberately
 * short and free of instruction: there is nothing for them to do. */
/* The non-interactive tier's widget label. Cloudflare's page-level line here is
 * "Checking if the site connection is secure", which describes
 * something that is not happening: TLS was negotiated before this
 * response was built and nothing about the connection is being
 * examined. What the page does is hand the client a proof-of-work and
 * see whether a real browser engine solves it. */
static const char BS_SILENT_PROMPT[] = "Verifying you are human\xe2\x80\xa6";

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
/* The non-interactive tier is the same bordered widget as the interactive tier,
 * differing only in that there is nothing to click: same box,
 * same label column, same brand column. Turnstile's widget looks
 * the same whether it is waiting on the user or working by
 * itself, and that is the right call -- a borderless spinner on
 * an empty page reads as a stall, while a widget reads as a
 * widget. */
".bs-widget.bs-auto .bs-btn{cursor:default;pointer-events:none}\n"
/* Arming window on the interactive tier. The checkbox is ABSENT,
 * not present-but-dead: a visible control that swallows clicks is
 * a frustration trap, and the users who click fastest are the
 * confident ones. The widget still occupies its final size, so the
 * checkbox does not shove the layout when it arrives -- a button
 * that appears under an already-moving cursor is its own bug.
 *
 * What shows meanwhile is the spinner the non-interactive tier
 * uses, which is honest: the proof-of-work really is running. */
".bs-widget.bs-arming .bs-btn{cursor:default;pointer-events:none}\n"
".bs-widget.bs-arming .bs-check{border:3px solid #e4e7ea;\n"
" border-top-color:#2f5d50;border-radius:50%%;background:transparent;\n"
" animation:bs-spin .8s linear infinite}\n"
".bs-widget.bs-arming .bs-label{color:#55605e}\n"
"@media (prefers-reduced-motion: reduce){\n"
" .bs-widget.bs-arming .bs-check{animation:none}\n"
"}\n"
/* No help affordance on the non-interactive tier: it is a control the
 * client cannot use on a page they will not be on long enough to
 * read it. The label stays visible here, unlike an earlier
 * revision that hid it -- axe-core's button-name check goes
 * critical when the button has no accessible name (caught by
 * tests/pytests/test_browser_a11y.py, which needs `playwright
 * install` on this host to actually run). */
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
" text-align:center;word-break:break-word;max-width:400px;margin:0}\n"
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
/* Silent-tier context block. A spinner alone on an unbranded grey
 * field is indistinguishable from a site that has hung, and the
 * non-interactive tier is exactly the one the client never asked for and
 * cannot act on. .bs-host names what they are waiting for -- the
 * first thing Cloudflare's interstitial shows, for the same
 * reason: it also says the page belongs to the site and not to an
 * ISP or an extension. .bs-late carries the reassurance, revealed
 * on a timer, because most solves finish well inside 1.5s and
 * paying a paragraph of explanation on a page that flashes past
 * makes the fast case feel heavier than it is. */
".bs-host{font-size:19px;font-weight:600;color:#1f2530;margin:0;\n"
" text-align:center;letter-spacing:-.01em;word-break:break-word}\n"
/* The visible heading on the non-interactive tier. Cloudflare puts
 * "Checking if the site connection is secure" here, which is not
 * what is happening -- TLS was established before this page was
 * built, and nothing about the connection is under examination.
 * What is actually checked is whether the client runs a real
 * browser engine, so that is what it says. */
".bs-late{max-width:400px;margin:0;font-size:12px;color:#7a8487;\n"
" text-align:center;opacity:0;transition:opacity .35s ease}\n"
".bs-late b{font-weight:600;color:#55605e}\n"
".bs-late.on{opacity:1}\n"
/* The footer's two lines belong together and closer than the stack's
 * own .75rem rhythm, which is spacing between unrelated blocks. */
".bs-foot{display:flex;flex-direction:column;align-items:center;\n"
" gap:.2rem;margin:0}\n"
/* The reference id is the only thing on this page an operator can
 * search for. Without it a stranded user reports \"it hung on a
 * grey page\", which is unfindable in a 100M decision log. */
".bs-ref{font-size:11px;color:#7a8487;margin:0;text-align:center;\n"
" font-family:ui-monospace,SFMono-Regular,Menlo,monospace;\n"
" word-break:break-all}\n"
"@keyframes bs-spin{to{transform:rotate(360deg)}}\n"
"@media (prefers-reduced-motion: reduce){\n"
" .bs-working .bs-check{animation:none;border-top-color:#7a8487}\n"
" .bs-late{transition:none}\n"
"}\n"
"</style>\n"
"<div class=\"bs-stack\">\n"
"%s"
"<noscript><div class=\"bs-noscript\">JavaScript is required to continue."
"</div></noscript>\n"
"%s"
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
"%s"
"%s"
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
" /* The non-interactive widget states its progress in its label, the way\n"
"    Turnstile does, so the status line under the box carries only\n"
"    the counter -- printing the phrase in both places is the same\n"
"    sentence twice, two lines apart. */\n"
" var lbl = document.querySelector('.bs-label');\n"
" /* Attestation, not fingerprinting.\n"
"\n"
"    Every probe below asks whether this environment BEHAVES like a\n"
"    browser. None of them derives a stable identifier for the\n"
"    device -- no canvas, no WebGL, no font or audio measurement --\n"
"    because the interactive tier shows a help panel promising that\n"
"    nothing personal is sent, and that promise has to survive\n"
"    contact with this function.\n"
"\n"
"    It runs at load on both tiers, so on the interactive tier it\n"
"    finishes during the time the click was going to cost anyway.\n"
"    Results are reported, not enforced: several probes have real\n"
"    false positives (privacy browsers, extensions that patch\n"
"    natives) and a wrong answer here should cost a log line, not\n"
"    someone\u2019s access. */\n"
" var ATT = (function(){\n"
"  var f = [];\n"
"  function p(name, fn){\n"
"   try { if (fn()) f.push(name); } catch (e) { /* probe threw:\n"
"     inconclusive, not a failure -- a locked-down but real browser\n"
"     throws here too */ }\n"
"  }\n"
"  /* The one unambiguous signal: WebDriver sets this by spec. */\n"
"  p('webdriver', function(){ return navigator.webdriver === true; });\n"
"  /* Known automation harnesses leave globals behind. */\n"
"  p('automation-global', function(){\n"
"   return !!(window._phantom || window.callPhantom ||\n"
"             window.__nightmare || window.domAutomation ||\n"
"             window.__selenium_unwrapped);\n"
"  });\n"
"  /* A UA claiming Chrome with no window.chrome is a mismatch\n"
"     between what it says and what it is. */\n"
"  p('chrome-ua-no-chrome', function(){\n"
"   return / Chrome\\//.test(navigator.userAgent) && !window.chrome;\n"
"  });\n"
"  /* Real browsers always report at least one language. */\n"
"  p('no-languages', function(){\n"
"   return !!navigator.languages && navigator.languages.length === 0;\n"
"  });\n"
"  /* A zero-sized screen means nothing is displaying this. */\n"
"  p('no-screen', function(){\n"
"   return !(window.screen && screen.width > 0 && screen.height > 0);\n"
"  });\n"
"  /* Natives that no longer report as native have been replaced. */\n"
"  p('patched-native', function(){\n"
"   return Function.prototype.toString\n"
"     .call(Function.prototype.bind).indexOf('[native code]') < 0;\n"
"  });\n"
"  return f;\n"
" })();\n"
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
" /* The solve starts at load on both tiers. On the interactive\n"
"    tier the click then releases an answer that is already\n"
"    computed, which does two things: the click feels instant, and\n"
"    the server's issue -> submit delta stops including PoW time.\n"
"    That delta is the interactive floor, and while the solve sat\n"
"    inside it a slow device could clear the floor on compute alone\n"
"    -- measuring the CPU rather than the human it is meant to. */\n"
" var solved = null;      /* counter, once found */\n"
" var pow_ms = -1;        /* client-measured solve duration */\n"
" var react_ms = -1;      /* client-measured armed -> click */\n"
" var released = !!CH.auto;  /* interactive: set by the click */\n"
" if (CH.auto){\n"
"  msg.textContent = '';\n"
"  /* Reveal the explanation only if the solve outlasts it. */\n"
"  var late = document.getElementById('late');\n"
"  if (late) setTimeout(function(){ late.classList.add('on'); },\n"
"                       1500);\n"
"  if (document.readyState === 'loading') {\n"
"   document.addEventListener('DOMContentLoaded', begin, {once:true});\n"
"  } else {\n"
"   begin();\n"
"  }\n"
" } else {\n"
"  begin();\n"
"  /* Arming window. Until it elapses the widget shows a spinner and\n"
"     no checkbox, so there is nothing to click and nothing to be\n"
"     confused by. Two things come out of it:\n"
"\n"
"     - the earliest legitimate submit is now (window + a human's\n"
"       reaction) by construction, which is a fact rather than the\n"
"       guess about people that a bare floor rests on;\n"
"     - a click that lands DURING the window, or within a few ms of\n"
"       the checkbox appearing, did not come from someone who saw it.\n"
"       A person's click scatters across hundreds of ms after the\n"
"       reveal; a poller's lands immediately after it. That gap is\n"
"       the signal, so it survives shrinking the window. */\n"
"  var armed_at = 0;\n"
"  box.classList.add('bs-arming');\n"
"  var label_final = lbl ? lbl.textContent : '';\n"
"  if (lbl) lbl.textContent = 'Starting check\\u2026';\n"
"  setTimeout(function(){\n"
"   box.classList.remove('bs-arming');\n"
"   box.classList.remove('bs-working');\n"
"   if (lbl) lbl.textContent = label_final;\n"
"   armed_at = Date.now();\n"
"  }, CH.arm_ms || 0);\n"
"  btn.addEventListener('click', function h(e){\n"
"   if(!e.isTrusted) return;\n"
"   if (!armed_at) { ATT.push('click-before-armed'); return; }\n"
"   /* Gap between the checkbox appearing and the click. A person\n"
"      who was already looking at the widget still needs ~200ms to\n"
"      react, and longer to move a cursor. A poller clicks at its\n"
"      own polling interval -- measured at ~100ms for a headless\n"
"      browser watching for the class to drop. 150ms sits between\n"
"      the two. Reported, never enforced: it is measured on the\n"
"      client, so it is forgeable by anyone who reads this file. */\n"
"   react_ms = Date.now() - armed_at;\n"
"   if (react_ms < 150) ATT.push('click-on-arm');\n"
"   btn.removeEventListener('click', h);\n"
"   released = true;\n"
"   if (solved !== null) submit(solved);\n"
"   else msg.textContent = 'Verifying you are human\\u2026';\n"
"  });\n"
" }\n"
" /* submit() lives at the outer scope on purpose: the click\n"
"    handler on the interactive tier calls it, and that handler\n"
"    is not inside startChallenge(). It was, briefly, and the\n"
"    button silently did nothing -- caught by driving the page in\n"
"    a real browser, not by the suite, which POSTs to\n"
"    embedded-verify directly and never executes this file. */\n"
" function submit(counterVal){\n"
"  box.classList.remove('bs-working');\n"
"  box.classList.add('bs-done');\n"
"  if (lbl) lbl.textContent = 'Success!';\n"
"  msg.textContent = 'Reloading\\u2026';\n"
"  /*  POST the solution to the server\n"
"     and let it mint the cookie via Set-Cookie + HttpOnly,\n"
"     instead of setting document.cookie locally. JS can't read\n"
"     the cookie back, but it doesn't need to: server validates\n"
"     and the next request's bs_handler accepts the new cookie.\n"
"     round-trip bound_ip + bootstrap_sig for\n"
"     IP-binding. */\n"
"  var body = JSON.stringify({\n"
"   provider: 'pow-gcm',\n"
"   cookie_prefix: CH.cookie_prefix,\n"
"   bound_ip: CH.bound_ip,\n"
"   bootstrap_sig: CH.bootstrap_sig,\n"
"   issued_ms: CH.issued_ms,\n"
"   /* Client timings. Forgeable alone -- this file is readable --\n"
"      but bounded above by the server's own issue->submit\n"
"      measurement, so overstating one costs real wall time and\n"
"      understating it proves nothing. Their value is excluding\n"
"      network: react_ms is a human reaction with no RTT in it,\n"
"      which the server number can never isolate. */\n"
"   pow_ms: pow_ms,\n"
"   react_ms: react_ms,\n"
"   att: ATT,\n"
"   counter: counterVal\n"
"  });\n"
"  fetch('/botshield/embedded-verify', {\n"
"   method: 'POST',\n"
"   credentials: 'same-origin',\n"
"   headers: {'Content-Type':'application/json'},\n"
"   body: body\n"
"  }).then(function(resp){\n"
"   if (resp.ok || resp.status === 204) {\n"
"    setTimeout(function(){ location.reload(); }, 250);\n"
"   } else {\n"
"    msg.textContent = 'Verification failed (' + resp.status + ')';\n"
"   }\n"
"  }).catch(function(err){\n"
"   msg.textContent = 'Verification failed: ' +\n"
"                      (err && err.message || err);\n"
"  });\n"
" }\n"
" function startChallenge(){\n"
"  var saltB  = hexToBytes(CH.salt);\n"
"  var nonceB = hexToBytes(CH.nonce);\n"
"  var counter = 0;\n"
"  var BATCH = 2048;\n"
"  var t0 = Date.now();\n"
"  if (!CH.auto) msg.textContent = 'Verifying you are human\\u2026';\n"
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
"    msg.textContent = CH.auto\n"
"      ? counter.toLocaleString() + ' hashes, ' + elapsed + 's'\n"
"      : 'Verifying you are human\\u2026 (' +\n"
"        counter.toLocaleString() + ' hashes, ' + elapsed + 's)';\n"
"    setTimeout(doBatch, 0);\n"
"   }).catch(function(err){\n"
"    msg.textContent = 'Verification failed: ' + (err && err.message || err);\n"
"   });\n"
"  }\n"
"  /* Solve finished. Submit now if we are allowed to; otherwise\n"
"     hold the answer until the click says so. */\n"
"  function finish(counterVal){\n"
"   solved = counterVal;\n"
"   if (pow_ms < 0) pow_ms = Date.now() - t0;\n"
"   if (!released) {\n"
"    box.classList.remove('bs-working');\n"
"    msg.textContent = '';\n"
"    return;\n"
"   }\n"
"   submit(counterVal);\n"
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
" text-align:center;word-break:break-word;max-width:400px;margin:0}\n"
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
" text-align:center;word-break:break-word;max-width:400px;margin:0}\n"
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
" text-align:center;word-break:break-word;max-width:400px;margin:0}\n"
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
/* ----------------------------------------------------------------------
 * <prefix>/preview/{non-interactive,interactive} -- render the interstitials as a
 * client sees them, for design work.
 *
 * Uses the real bs_render_challenge_page with the real template, CSS
 * and script. A mock would drift from the thing being designed within
 * a release, which is the whole reason this is not a static file.
 *
 * The payload is synthetic and deliberately unsolvable: difficulty 24
 * is ~2^24 hashes, so the widget sits in its working state instead of
 * completing and redirecting away before it can be looked at. That is
 * also exactly the state an operator wants to see -- the page as it
 * appears when the proof-of-work is NOT succeeding.
 *
 * No challenge is minted: no nonce slot consumed, no cookie set, no
 * counter moved. A preview that altered state would be a preview you
 * could not leave open.
 *
 * non-interactive -> auto=1, the self-solving tier (BS_TIER_NONINTERACTIVE).
 * form   -> auto=0, the click-to-verify tier. Internally BS_TIER_INTERACTIVE;
 *           the decision log and metrics call it "interactive" and
 *           BotShieldScoreInteractive sets its threshold. Same page, the
 *           checkbox is live rather than decorative.
 * -------------------------------------------------------------------- */
/* <prefix>/preview -- index of the pages a client can be shown.
 *
 * Exists because the three previews are otherwise only discoverable by
 * reading the source or the commit that added them, which is a poor
 * way to find the thing you want to redesign. Each entry says what
 * state the page is in, since two of them are the same template
 * differing by one flag and the difference is not obvious from a
 * screenshot. */
int bs_preview_index_handler(request_rec *r)
{
    if (r->method_number != M_GET) return HTTP_METHOD_NOT_ALLOWED;
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    const char *px = (cfg && cfg->endpoint_prefix)
                   ? cfg->endpoint_prefix : BS_DEFAULT_ENDPOINT_PREFIX;
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Robots-Tag", "noindex, nofollow");
    ap_rprintf(r,
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      "<title>BotShield page previews</title><style>"
      "html,body{margin:0;padding:0}"
      "body{background:#f5f5f2;color:#222;padding:2rem 1rem;"
      "font:14px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}"
      "main{max-width:640px;margin:0 auto;background:#fff;"
      "border:1px solid #ddd;border-radius:8px;padding:1.5rem 1.75rem;"
      "box-shadow:0 1px 3px rgba(0,0,0,.05)}"
      "h1{margin:0 0 .25rem;font-size:1.25rem;color:#2f5d50}"
      ".sub{color:#666;margin:0 0 1.25rem}"
      "ul{list-style:none;margin:0;padding:0}"
      "li{padding:.85rem 0;border-top:1px solid #eee}"
      "a{color:#2f5d50;font-weight:600;text-decoration:none}"
      "a:hover{text-decoration:underline}"
      "code{background:#f2f2ef;padding:.1rem .3rem;border-radius:3px;"
      "font-size:.9em}"
      ".d{color:#555;margin:.25rem 0 0}"
      ".n{color:#777;font-size:.875rem;margin-top:1.5rem;"
      "border-top:1px solid #eee;padding-top:1rem}"
      "</style></head><body><main>"
      "<h1>Page previews</h1>"
      "<p class=\"sub\">What a client is shown, rendered from the live "
      "templates rather than copies.</p><ul>");
    ap_rprintf(r,
      "<li><a href=\"%s/preview/non-interactive\">%s/preview/non-interactive</a>"
      "<p class=\"d\">Non-interactive tier. The check runs by itself "
      "and the "
      "widget is decorative &mdash; most visitors never see this "
      "resolve. Shown here mid-check, because the proof-of-work is set "
      "unsolvable so it cannot complete and navigate away.</p></li>",
      px, px);
    ap_rprintf(r,
      "<li><a href=\"%s/preview/interactive\">%s/preview/interactive</a>"
      "<p class=\"d\">Interactive tier &mdash; the same template as the "
      "one above, but the checkbox is live and waits for a click. "
      "Threshold set by <code>BotShieldScoreInteractive</code>.</p></li>",
      px, px);
    ap_rprintf(r,
      "<li><a href=\"%s/preview/safeguard\">%s/preview/safeguard</a>"
      "<p class=\"d\">The anti-loop explainer, shown once after five "
      "unsolved challenges in ten minutes. Also served at "
      "<code>%s/safeguard-info</code>, which is the URL clients "
      "actually reach.</p></li>", px, px, px);
    ap_rputs("</ul><p class=\"n\">These render the real templates and "
             "change no state: nothing is minted, no counter moves, no "
             "cookie is set. Safe to leave open.</p>"
             "</main></body></html>", r);
    return OK;
}

int bs_preview_handler(request_rec *r, int want_auto)
{
    if (r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }
    bs_dir_cfg *cfg = ap_get_module_config(r->per_dir_config,
                                           &botshield_module);
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Robots-Tag", "noindex, nofollow");

    const char *js = apr_psprintf(r->pool,
        "{\"salt\":\"%s\",\"nonce\":\"%s\",\"difficulty\":24,"
        "\"expires_at\":%" APR_TIME_T_FMT ",\"cookie_prefix\":\"preview\","
        "\"bound_ip\":\"00000000000000000000ffff7f000001\","
        "\"bootstrap_sig\":\"%s\",\"auto\":%d,\"arm_ms\":%d}",
        "00000000000000000000000000000000",
        "0000000000000000",
        (apr_time_t)(apr_time_sec(apr_time_now()) + 300),
        "0000000000000000000000000000000000000000000000000000000000000000",
        want_auto ? 1 : 0,
        /* The preview has to arm like the real widget or it cannot
         * show the state it exists to show. */
        want_auto ? 0 : bs_effective_int(cfg->interactive_arm_ms,
                                         BS_DEFAULT_INTERACTIVE_ARM_MS));

    (void)bs_render_challenge_page(r, cfg,
                                   want_auto ? BS_TIER_NONINTERACTIVE : BS_TIER_INTERACTIVE,
                                   js, want_auto);
    /* Serves 403, same as a real interstitial. Tried resetting to 200
     * after the render and it does not take -- ap_rputs commits the
     * headers with whatever status is set at the time, so the only way
     * to change it would be threading a status through
     * bs_render_challenge_page, which is not worth altering a shared
     * signature for. It is arguably right anyway: this is a preview OF
     * a refusal page, and it renders identically in a browser. */
    return OK;
}

int bs_render_challenge_page(request_rec *r,
                             const bs_dir_cfg *cfg,
                             bs_tier tier,
                             const char *challenge_js,
                             int issue_auto)
{
    /* The non-interactive tier's label is a status, not an invitation: there is
     * no checkbox to tick. Turnstile makes the same split -- "Verify
     * you are human" when it wants a click, "Verifying..." when it is
     * working on its own. An operator's BotShieldPrompt still wins,
     * since it is the string they chose to put in front of clients. */
    const char *prompt     = cfg->prompt ? cfg->prompt
                           : (issue_auto ? BS_SILENT_PROMPT
                                         : BS_DEFAULT_PROMPT);
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

    /* Silent-tier context. issue_auto is the tier where the client is
     * given nothing to do and no reason for the wait, so it is the one
     * that needs saying what site it is and that the wait ends by
     * itself. The interactive tier already shows a prompt, a logo and a help
     * toggle; repeating the hostname above them is clutter.
     *
     * ap_get_server_name honours UseCanonicalName, so this shows the
     * configured ServerName rather than whatever Host: the client sent
     * when the operator has asked for that. Escaped either way -- with
     * UseCanonicalName Off it is client-supplied text. */
    const char *host_esc = ap_escape_html(r->pool, ap_get_server_name(r));

    /* The document heading. On the non-interactive tier it is visible and
     * descriptive, under the hostname, which is the order Cloudflare
     * uses -- what site, then what is happening. On the interactive tier the
     * widget's own prompt is the visible instruction, so the heading
     * stays screen-reader-only and there is exactly one h1 either
     * way. */
    const char *h1_html = issue_auto
        ? ""   /* the hostname block below is the h1 on this tier */
        : "<h1 class=\"bs-sr\">Verify you are human</h1>\n";

    const char *host_html = "";
    const char *late_html = "";
    if (issue_auto) {
        host_html = apr_psprintf(r->pool,
            "<h1 class=\"bs-host\">%s</h1>\n", host_esc);

        /* One line, revealed late. The earlier version explained the
         * check in a paragraph and then footnoted it with a second --
         * on a page whose entire job is to be over quickly, that is
         * more to read than the wait it was covering for. What a
         * stalled visitor needs is that the wait ends by itself, which
         * the heading now carries, and something to look at that is
         * not a spinner, which this is.
         *
         * Omitted rather than guessed at when the hour has not carried
         * enough requests to have an answer. */
        int share = bs_bot_share_pct();
        if (share >= 0) {
            late_html = apr_psprintf(r->pool,
                "<p class=\"bs-late\" id=\"late\">Bots were <b>%d%%</b> "
                "of traffic here in the last hour.</p>\n",
                share);
        }
    }

    /* Reference id, on both tiers: the interactive tier is if anything more
     * likely to strand someone, since it needs a click that can fail.
     * Sourced from mod_unique_id, which is not a dependency -- when it
     * is not loaded the line is simply absent rather than showing an
     * id the operator cannot look up. */
    const char *ref_html = "";
    { const char *uid = apr_table_get(r->subprocess_env, "UNIQUE_ID");
      if (uid && *uid) {
          ref_html = apr_psprintf(r->pool,
              "<p class=\"bs-ref\">Ref: %s</p>\n",
              ap_escape_html(r->pool, uid));
      } }

    const char *foot_html = *ref_html
        ? apr_pstrcat(r->pool, "<div class=\"bs-foot\">\n", ref_html,
                      "</div>\n", NULL)
        : "";

    /* Captcha tier (M8): if we're at captcha tier AND a provider is fully
     * configured, render the provider's widget instead of the PoW checkbox.
     * If captcha tier resolves but no provider/key/secret is configured,
     * the caller already issued a PoW challenge and we stub to interactive PoW
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
                              h1_html,
                              host_html,
                              widget_mod,
                              aria_attr,
                              prompt_span,
                              brand_div,
                              help_html,
                              late_html,
                              foot_html,
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

    /* 403 Forbidden + X-Robots-Tag so search engines don't index the
     * interstitial as if it were the page being crawled. Browsers
     * still render the body and execute the inline JS / captcha
     * widget on a 4xx response (Cloudflare / DataDome / Akamai all
     * use this same pattern), so legitimate clients still solve the
     * challenge and get redirected back to the original URL.
     * Setting r->status here + returning OK from the caller bypasses
     * Apache's ErrorDocument substitution — our body is what ships. */
    r->status = HTTP_FORBIDDEN;
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Botshield",   "challenge");
    apr_table_setn(r->headers_out, "X-Robots-Tag",  "noindex, nofollow");
    ap_rputs(body, r);

    return use_captcha_widget;
}

/* --- Safeguard explainer page (E10 redirect mode) ------------------
 *
 * Served at <BotShieldEndpointPrefix>/safeguard-info when a client
 * trips the safeguard threshold. The redirect itself happens in
 * bs_apply_safeguard which also clears the per-IP counter, so this
 * handler is a pure render — no SHM mutation, no state.
 *
 * The page explains what happened in plain language and offers a
 * Continue link back to the original URL (passed as ?return=).
 * Continue is a normal anchor link; clicking it re-fetches the
 * original URL, which gets a fresh challenge cycle (because the
 * counter was already cleared at redirect time).
 *
 * The return URL is validated for same-origin shape (must be a path
 * starting with a single '/') to avoid open-redirect risk if a bot
 * crafts a malicious return param. Failed validation falls back to
 * '/'. */

static const char BS_SAFEGUARD_INFO_TEMPLATE[] =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<meta name=\"robots\" content=\"noindex,nofollow\">\n"
"<title>Verification interrupted</title>\n"
"<style>\n"
" html,body{margin:0;padding:0}\n"
" body{background:#f5f5f2;min-height:100vh;display:flex;\n"
"  flex-direction:column;align-items:center;justify-content:center;\n"
"  padding:1rem;font:14px/1.5 system-ui,-apple-system,\"Segoe UI\",sans-serif;color:#222}\n"
" main{max-width:520px;background:#fff;border:1px solid #ddd;\n"
"  border-radius:8px;padding:1.5rem 1.75rem;box-shadow:0 1px 3px rgba(0,0,0,.05)}\n"
" h1{margin:0 0 .75rem;font-size:1.25rem;color:#2f5d50}\n"
" p{margin:.5rem 0}\n"
" ul{margin:.5rem 0 1rem;padding-left:1.25rem}\n"
" li{margin:.25rem 0}\n"
" .continue{display:inline-block;margin-top:.75rem;padding:.5rem 1rem;\n"
"  background:#2f5d50;color:#fff;text-decoration:none;border-radius:4px}\n"
" .continue:hover{background:#264a40}\n"
" .small{color:#666;font-size:.875rem;margin-top:1.25rem}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<main>\n"
"<h1>We could not auto-verify your browser</h1>\n"
"<p>Our automated check did not complete successfully. This usually\n"
"happens because of one of the following:</p>\n"
"<ul>\n"
"<li>JavaScript is disabled in your browser.</li>\n"
"<li>A privacy or security extension is blocking cookies or scripts on this site.</li>\n"
"<li>Your browser version does not support the verification check.</li>\n"
"</ul>\n"
"<p>You can try again by following the link below. If the same thing\n"
"keeps happening, try a different browser or contact the site\n"
"administrator.</p>\n"
"<p><a class=\"continue\" href=\"%s\">Continue to %s</a></p>\n"
/* One line at the 520px container width. The previous wording ran to
 * 93 characters and wrapped, which made a reassurance read like a
 * warning -- two muted lines under a button look like small print
 * about a problem rather than a note that the problem is cleared. */
"<p class=\"small\">Counter reset &mdash; this link starts a fresh check.</p>\n"
"</main>\n"
"</body>\n"
"</html>\n";

/* Pull and validate the `?return=` query parameter. Returns a pool-
 * allocated path that's guaranteed to start with a single '/'. On
 * any validation failure (missing, malformed, scheme-bearing, double-
 * slash open-redirect attempt) returns "/". */
static const char *bs_safeguard_extract_return(request_rec *r)
{
    if (!r->args || !*r->args) return "/";
    const char *q = r->args;
    while (*q) {
        const char *amp = strchr(q, '&');
        apr_size_t pair_len = amp ? (apr_size_t)(amp - q) : strlen(q);
        if (pair_len > 7 && strncmp(q, "return=", 7) == 0) {
            char *enc = apr_pstrmemdup(r->pool, q + 7, pair_len - 7);
            ap_unescape_url(enc);
            /* Same-origin path only: must start with a single '/'.
             * Reject "//", "/\\", or anything that looks like a host
             * specifier — those are open-redirect vectors. Also
             * reject empty after unescape. */
            if (!*enc) return "/";
            if (enc[0] != '/') return "/";
            if (enc[1] == '/' || enc[1] == '\\') return "/";
            return enc;
        }
        if (!amp) break;
        q = amp + 1;
    }
    return "/";
}

int bs_safeguard_info_handler(request_rec *r)
{
    if (r->method_number != M_GET) {
        r->status = HTTP_METHOD_NOT_ALLOWED;
        apr_table_setn(r->headers_out, "Allow", "GET");
        ap_set_content_type(r, "text/plain; charset=utf-8");
        ap_rputs("GET required.\n", r);
        return OK;
    }

    const char *return_url = bs_safeguard_extract_return(r);
    const char *return_url_attr = ap_escape_html(r->pool, return_url);
    /* Display version is the same path; no special truncation needed
     * for typical HUBzero URLs. Operators with very long URIs can
     * customize via a future BotShieldSafeguardPageFile if it ever
     * matters. */
    const char *body = apr_psprintf(r->pool,
        BS_SAFEGUARD_INFO_TEMPLATE, return_url_attr, return_url_attr);

    r->status = HTTP_OK;
    ap_set_content_type(r, "text/html; charset=utf-8");
    apr_table_setn(r->headers_out, "Cache-Control", "no-store");
    apr_table_setn(r->headers_out, "X-Botshield",   "safeguard-info");
    apr_table_setn(r->headers_out, "X-Robots-Tag",  "noindex, nofollow");
    ap_rputs(body, r);
    return OK;
}
