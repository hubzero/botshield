# mod_botshield

Low-latency bot detection for Apache 2.4. Cookieless requests get a
self-contained proof-of-work interstitial; verified visitors receive a
short-lived cookie and pass through on their next request.

**Status: early alpha.** The baseline PoW tier works end-to-end and passes
WCAG 2.1 AA. Server-side HMAC signing, scoring heuristics, shared-memory
rate tracking, Bloom-filter IP reputation, silent-PoW output filtering, and
captcha providers are all planned but not yet implemented.

## How it works

1. A request without a valid `_bs_verified` cookie is intercepted by the
   module's handler (registered at `APR_HOOK_FIRST`).
2. If the request URI ends in a static-asset extension (`.css`, `.js`,
   `.png`, `.svg`, …) the module declines and Apache serves the file
   normally. This keeps the challenge page's own linked assets working.
3. Otherwise the module renders a self-contained HTML page with inline
   CSS, inline JavaScript, and the widget logo inlined as SVG. No network
   round trips from the challenge page.
4. The client solves a SHA-256 proof-of-work (`N` leading hex zeros on
   `SHA-256(salt:fingerprint:nonce)`), writes
   `_bs_verified=<timestamp>:<hash>`, and reloads.
5. The next request carries the cookie; the module validates format and
   freshness and declines — Apache serves the real content.

## Build

You need Apache 2.4 development headers — `apache2-dev` on Debian/Ubuntu,
`httpd-devel` on RHEL-family.

```
make enable     # build, install, a2enmod, configtest, reload
```

Step-by-step equivalents:

```
make            # compile with apxs -c
make install    # install the .so into Apache's modules dir
sudo a2enmod botshield
sudo apachectl configtest && sudo systemctl reload apache2
```

`make disable` removes the module without deleting the `.so`.

## Minimal configuration

```apache
<VirtualHost *:443>
    ServerName example.test
    DocumentRoot /var/www/example
    # ... SSLEngine, cert files, etc.

    BotShieldEnabled On
</VirtualHost>
```

## Directives

| Directive | Default | Purpose |
|---|---|---|
| `BotShieldEnabled on\|off` | `off` | Master on/off for the enclosing scope |
| `BotShieldDebug on\|off` | `off` | Return `403 "Hello World"` for every request (smoke test) |
| `BotShieldCookieTTL N` | `300` | Seconds a verified cookie is honoured |
| `BotShieldDifficulty N` | `4` | Leading hex zeros the PoW must produce (1..8) |
| `BotShieldPromptText "..."` | `I'm not a robot` | Label next to the checkbox |
| `BotShieldLogoFile /path.svg` | embedded Guardian | SVG served inline as the logo (≤ 64 KB) |
| `BotShieldLogoLabel "..."` | `botshield` | Small caption under the logo |
| `BotShieldHelp off\|on\|button` | `button` | Help visibility: nothing, always-on panel, or a `?` link that expands |
| `BotShieldHelpFile /path.html` | built-in text | HTML fragment used as the help panel (≤ 64 KB) |
| `BotShieldChallengeFile /path.html` | built-in shell | Full HTML page template wrapping the widget; must contain the marker `<!-- BOTSHIELD -->` (≤ 256 KB) |
| `BotShieldShowLogo on\|off` | `on` | Show the brand column |
| `BotShieldShowLabel on\|off` | `on` | Show the prompt text; when off, moves to the button's `aria-label` |
| `BotShieldShowBox on\|off` | `on` | Show the widget's outer box (border/background/shadow) |

All directives are valid in server config, `<VirtualHost>`, `<Directory>`,
`<Location>`, `<Files>`, and their `*Match` variants. **Not `.htaccess`** —
keeping bot-protection config out of writable filesystem locations is a
deliberate choice.

File-backed `*File` directives read their targets **once at config-parse
time** and cache the bytes on the per-directory config — no per-request
file I/O. Missing, unreadable, or oversized files fail `apachectl
configtest`, so a broken template can't be reloaded into a running server.

## Per-URL scoping

`<Location>` is usually what you want for a bot gate — routes don't always
map 1:1 to filesystem paths. Example: gate only login and the JSON API,
leave the rest of the site alone:

```apache
BotShieldEnabled Off

<LocationMatch "^/(login|api)(/|$)">
    BotShieldEnabled On
</LocationMatch>
```

## Customizing the challenge page

Three layers, each independent:

- **Widget content** — prompt, logo, caption, help text are all strings
  or files you provide.
- **Widget chrome** — `BotShieldShow{Logo,Label,Box}` strip the widget
  down to a lone checkbox if you want to style the surroundings yourself.
- **Page shell** — `BotShieldChallengeFile` replaces the full page HTML
  with your own template. The module splices the widget in at
  `<!-- BOTSHIELD -->` so the DOM contract the JavaScript relies on stays
  module-controlled.

See `apache/botshield-dev.conf` for worked examples of each.

## Accessibility

The default interstitial passes axe-core WCAG 2.1 AA with zero
violations — landmarks, focus-visible outlines, `aria-live` status on the
progress message, `prefers-reduced-motion` handling, and sufficient
contrast in both light and dark regions of the widget. Stripping chrome
preserves accessibility: the prompt moves to `aria-label` when visually
hidden, the live-status region is always present, and the screen-reader-
only `<h1>` is emitted regardless of how much chrome you've removed.

## Security note on the baseline tier

The verification cookie is set by client JavaScript and validated on the
server only by format (regex) and timestamp window. A motivated attacker
can forge a cookie that matches the pattern and bypass the challenge. The
baseline is still useful in practice because it filters every bot that
can't execute JavaScript — which is most of them.

Server-side HMAC signing of challenges and cookies is the next planned
milestone and closes this gap.

## Development

`apache/botshield-dev.conf` is a working HTTPS dev vhost that exercises
each directive on its own URL of a fake "Crestline Research Library"
test site:

| Path | What it demonstrates |
|---|---|
| `/` | Default widget |
| `/debug` | `BotShieldDebug` 403 smoke test |
| `/about.html` | Custom prompt, logo file, logo caption, help file, help always-on |
| `/search.html` | All chrome toggles off — just a bare checkbox |
| `/api/users.json` | `BotShieldShowBox off` — widget without outer box |
| `/login.html` | `BotShieldChallengeFile` — widget spliced into a site-themed page |

The test site lives under `testsite/` and is git-ignored. See the header
of `apache/botshield-dev.conf` for how to set up the self-signed cert
and docroot.

## License

MIT. See `LICENSE`.
