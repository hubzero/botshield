# Captcha and app-bridge

mod_botshield ships two integration surfaces with third parties:

1. **Captcha tier (M8)** — when the score crosses
   `BotShieldScoreCaptcha`, the module renders a third-party
   captcha widget (Turnstile / hCaptcha / reCAPTCHA / Friendly /
   GeeTest) and verifies the token via libcurl on POST.
2. **App bridge (E5 + E8.2)** — a signed two-way protocol between
   mod_botshield and the upstream application: the app emits
   reputation feedback as a response header; the module emits
   verified-claims as a request header.

Both surfaces share one HMAC key
(`BotShieldAppIntegrationSecretFile`) — wire-format separation
keeps the directions distinct without separate keys.

## Captcha tier (M8)

### Provider registry

Six providers ship in the registry:

| Provider | Token field | Notes |
|---|---|---|
| `turnstile` | `cf-turnstile-response` | Cloudflare Turnstile. Always-pass test keys at https://developers.cloudflare.com/turnstile/troubleshooting/testing/ |
| `hcaptcha` | `h-captcha-response` | hCaptcha. Test keys at https://docs.hcaptcha.com/#integration-testing-test-keys |
| `recaptcha-v2` | `g-recaptcha-response` | Google reCAPTCHA v2. Test pair at https://developers.google.com/recaptcha/docs/faq |
| `recaptcha-v3` | `g-recaptcha-response` | Google reCAPTCHA v3. Score-thresholded; configure via `BotShieldRecaptchaV3MinScore` |
| `friendly` | `frc-captcha-solution` | Friendly Captcha. The `solution` form field is mandated by the provider |
| `geetest` | `geetest_payload` | GeeTest v4. HMAC-signed; uses `captcha_id` + `captcha_key` rather than a generic site key + secret |

Cohabitation: a single vhost can register multiple providers and
route requests to different ones via `<LocationMatch>` scopes — the
registry is per-scope, not per-server.

### Configuration

```apache
BotShieldCaptchaProvider        turnstile
BotShieldCaptchaSiteKey         "1x00000000000000000000AA"
BotShieldCaptchaSecretFile      /etc/botshield/captcha-turnstile-secret
BotShieldCaptchaTimeout         1000   # ms; 100..5000
BotShieldCaptchaConnectTimeout  250    # ms
BotShieldRecaptchaV3MinScore    0.5    # only meaningful for recaptcha-v3
BotShieldCaptchaCABundle        /etc/ssl/certs/ca-certificates.crt
```

The secret file holds the provider's verify-side secret (or for
GeeTest, the `captcha_key` used to HMAC the lot_number). Mode 0600,
read once at config-parse time.

`BotShieldCaptchaTimeout` is the total HTTP siteverify budget. On
timeout the verify path **fails open** — the request gets the same
treatment it would on a clean pass. Provider-outage scenarios
shouldn't black-hole legitimate traffic.

`BotShieldCaptchaCABundle` is optional. If unset, libcurl uses its
compiled-in default (usually `/etc/ssl/certs/ca-certificates.crt`
on Debian-family). Operators with custom trust stores or air-gapped
deployments can pin a specific bundle.

### Verify-endpoint hardening (M8.1)

The captcha-verify endpoint
(`<prefix>/captcha-verify/<provider>`) is guarded by six layers of
pre-libcurl checks. Each rejects cheaply before any outbound call,
so the endpoint cannot be trivially weaponized as a siteverify
amplifier or worker-starvation vector.

| Check | Reject reason |
|---|---|
| Content-Type prefilter | Not `application/x-www-form-urlencoded` → 415 |
| 8 KB body cap | Body exceeded → 413 |
| Token-field presence | Missing or empty `<token-field>` → 400 |
| HMAC-signed pending cookie | `_bs_captcha_pending` mismatch / expired → 403 |
| Per-IP rate limit | Over `BotShieldCaptchaRateLimit` per minute → 429 with Retry-After |
| Global in-flight semaphore | Over `BotShieldCaptchaMaxInFlight` → 503 |

The pending cookie is minted at interstitial render time
(HttpOnly, Secure, SameSite=Lax, Max-Age=300) and required at
verify time. It binds the verify call to the same client that
received the challenge, blocking off-host replay.

```apache
BotShieldCaptchaRateLimit    30   # per IP per minute, 0..1000
BotShieldCaptchaMaxInFlight  64   # global, 1..1024
```

### Hostname / action binding

Several providers (hCaptcha, reCAPTCHA, Turnstile) return a
`hostname` and `action` field in the siteverify response. mod_
botshield validates these against operator-configured expectations:

```apache
BotShieldCaptchaExpectedHostname  example.com
BotShieldCaptchaExpectedAction    botshield
```

NULL (unset) uses runtime defaults: server hostname from
`r->server->server_hostname` and the literal action `botshield`.
Empty string disables the check entirely.

GeeTest binds host/action via HMAC at request time — the runtime
defaults don't surface in the response — so these directives are
no-ops for that provider.

### Multi-provider per vhost

```apache
<VirtualHost *:443>
    ServerName example.com
    BotShieldEnabled on

    <LocationMatch "^/login">
        BotShieldCaptchaProvider   turnstile
        BotShieldCaptchaSiteKey    "..."
        BotShieldCaptchaSecretFile /etc/botshield/turnstile-secret
    </LocationMatch>

    <LocationMatch "^/api/v1/auth">
        BotShieldCaptchaProvider   hcaptcha
        BotShieldCaptchaSiteKey    "..."
        BotShieldCaptchaSecretFile /etc/botshield/hcaptcha-secret
    </LocationMatch>
</VirtualHost>
```

The verify endpoint URL is per-provider:
`<prefix>/captcha-verify/<provider>` (e.g.
`/botshield/captcha-verify/turnstile`). The interstitial JS posts to
the matching path. A vhost-wide single-provider deployment can use
the bare `<prefix>/captcha-verify` form.

## E18 — inline form captcha

Some applications already render their own form captcha and want
mod_botshield to validate the token inline rather than hand
visitors a separate interstitial. Enable with:

```apache
BotShieldFormCaptcha on
```

The fixup hook intercepts POSTs to the configured scope, reads the
form body once (capped at 256 KiB), validates the captcha token via
the standard provider siteverify path, and either:

- on success: caches the token validity and lets the original
  handler run with the body replayed via an input filter, or
- on failure: returns 403 with a decision-log line explaining why.

The body-replay filter uses `apr_bucket_immortal_create` so the
upstream handler reads the bytes a second time without a
deferred-pool copy. This lets the application run its existing
form-handler logic unchanged while mod_botshield enforces captcha
upstream of the application's own validation.

`BotShieldFormCaptcha on` requires a captcha provider configured
on the same scope. Without one, the directive logs a misconfig and
no-ops.

## App bridge (E5 + E8.2)

The app bridge gives the upstream application two protocols for
exchanging signed reputation data with the module without ever
appearing on the wire to the client.

### E5 — App-to-module feedback

The app emits a response header on responses where it has classified
the request after-the-fact:

```
X-BotShield-Feedback: event=scanner-hit;sig=<hmac-sha256-hex>
```

mod_botshield strips the header before the response leaves the
server (so it never reaches the client), verifies the HMAC against
the integration secret, looks up `event=scanner-hit` in the
configured `BotShieldFeedbackTrigger` table, and applies the
corresponding action.

```apache
BotShieldAppFeedback              on
BotShieldAppIntegrationSecretFile /etc/botshield/app-integration-secret

BotShieldFeedbackTrigger scanner-hit  flag=honeypot_hit ttl=3600 log=app-trap
BotShieldFeedbackTrigger human-pass   flag=app_verified_human ttl=3600
BotShieldFeedbackTrigger session-ok   flag=app_verified_session ttl=3600
```

Wire format details:

- The HMAC covers everything before `;sig=`.
- `event` must be a single token from the configured table —
  unmapped events log at DEBUG and are ignored.
- Multiple `X-BotShield-Feedback` headers on one response are
  rejected (the strip filter catches all copies; the verify path
  rejects multi-value).
- Header name is configurable via `BotShieldAppFeedbackHeader` if
  the default name conflicts with another module's vocabulary.

The event-name → action indirection is the security property: a
compromised app can emit any event name, but only configured
mappings reach module memory. Renaming, retiring, or muting an
event is a config change with no app-side coordination.

Feedback runs through the same shadow-mode + observe-mode gate as
the other trigger families. Under `BotShieldShadowMode on` the
filter logs `feedback-trigger:<event>:observe` without mutating the
flagged-IP table. Per-trigger `mode=observe` works the same way.

### E8.2 — Module-to-app claims

mod_botshield can emit a signed claims header on the request seen
by the upstream application:

```
X-Botshield-Claims: tier=pass;ip=192.0.2.42;flags=app_verified_human;sig=<hmac>
```

The application reads this to know what mod_botshield decided about
the current request — without re-implementing tier inspection.

```apache
BotShieldAppClaims                on
BotShieldAppIntegrationSecretFile /etc/botshield/app-integration-secret
```

mod_botshield strips any client-supplied `X-Botshield-Claims`
header on the way in, then emits a fresh signed value before
handing the request to the next phase. Any application-side
spoofing attempt is dropped before the app sees it.

Claims fields:

- `tier` — one of `pass`, `silent`, `form`, `captcha` (the
  decision-log `tier` enum minus `none`).
- `ip` — the client IP after `mod_remoteip` rewrite (so apps see
  the real client, not the edge).
- `flags` — comma-joined flag-bit names (`honeypot_hit,
  scanner_probe`, etc.). Empty if no flags set.
- `sig` — HMAC-SHA-256 hex over the canonical form.

The same integration secret file backs both directions; the
canonical forms differ structurally so cross-replay is blocked by
parser shape, not by key separation.

## Where to next

- Real-world deployment topology: [deployment](../deployment/index.html).
- Tier model and scoring: [operator model](../operator-model/index.html).
- Triggers, allow lists, robots: [policy](../policy/index.html).
- Decision log + metrics: [observability](../observability/index.html).
