# Staging policy changes

mod_botshield supports two complementary dry-run modes so you
can deploy new rules without affecting production traffic until
you're confident the matches are correct.

- **Per-rule observe** — pin a single directive into observe mode.
  Useful for staging individual rules.
- **Scope-level `BotShieldEnabled LogOnly`** — flip every match to
  observe within the enclosing `<VirtualHost>` / `<Location>` /
  `<Directory>` regardless of per-rule setting. Useful for staging
  an entire policy revision, with per-`<Location>` carve-outs for
  paths you want to enforce immediately.

Either signal is sufficient; they compose with OR semantics. A rule
runs in observe mode if EITHER its per-rule mode is `observe` OR
the effective `BotShieldEnabled` for the request's scope is
`LogOnly`. There is no priority order to memorize.

## What "observe" means precisely

When a rule fires in observe mode:

- The rule's predicate evaluates normally (path match, cohort
  match, env present, etc.).
- The decision log records the would-have-done outcome with an
  `:observe` suffix on the reason token.
- The matching observe-mode metric counter increments
  (`trigger_observed_total`, `rate_limit_observed_total`).
- **No** flag bits are set on the IP.
- **No** score is added to the request.
- **No** status code, redirect, or log tag side-effect is emitted.

The audit trail captures everything the rule WOULD have done; the
client response is unaffected. Observe matches never short-circuit
the policy walk — the next rule still gets its chance.

## Per-rule observe mode

Add `mode=observe` to any directive that supports it:

```apache
BotShieldRequestTrigger    admin-trap   path="/admin/.env"  flag=scanner_probe ttl=3600 log=admin-trap mode=observe
BotShieldRequestTrigger    legacy-admin path="/wp-admin/*"  status=403 mode=observe
BotShieldRateLimit      api-burst    60 min "" * mode=observe
BotShieldFlagTrigger    honeypot_hit action=tier_floor min=captcha mode=observe
```

The rule still evaluates against every matching request, but takes
no action. Matches appear in the decision log:

```
mod_botshield: decision tier=nochallenge outcome=allow ip=192.0.2.42
    score=0 cookie=absent provider=- alg=- reason="path-trigger:admin-trap:observe"
    path="/admin/.env"
```

Watch the log for hours or days. When matches look correct, remove
`mode=observe` and reload Apache to flip the rule into enforcement.

## Scope-level `BotShieldEnabled LogOnly`

For staging a whole policy revision at once, set the directive at
vhost scope:

```apache
BotShieldEnabled LogOnly
```

Every rule in scope flips to observe regardless of its per-rule
setting. Useful before a release or when comparing a new ruleset
against production traffic without any enforcement risk. Switch to
`BotShieldEnabled On` when you're ready to enforce.

`BotShieldEnabled` is tri-state: `On` / `Off` / `LogOnly`. It is
valid in `RSRC_CONF | ACCESS_CONF` scope, so per-`<Location>`
overrides give you fine-grained partial rollouts:

```apache
<VirtualHost *:443>
    ServerName example.com
    BotShieldEnabled LogOnly                # most paths: observe
    <Location "/login">
        BotShieldEnabled On                 # /login: enforce now
    </Location>
    <Location "/healthcheck">
        BotShieldEnabled Off                # bare-metal probe: skip
    </Location>
</VirtualHost>
```

The `bs_dir_cfg` merge picks the most-specific scope. An unset
inner scope inherits the outer.

## Coverage

Both observe signals reach every gating surface:

| Family | Honors per-rule | Honors `LogOnly` | Reason format |
|---|---|---|---|
| Path triggers | yes | yes | `path-trigger:<name>:observe` |
| Cookie triggers | yes | yes | `cookietrigger:<name>:observe` |
| Env triggers | yes | yes | `envtrigger:<name>:observe` |
| Load triggers | yes | yes | `loadtrigger:<name>:observe` |
| Feedback triggers | yes | yes | `feedbacktrigger:<event>:observe` |
| Flag triggers | yes | yes | `flagtrigger:<flag>:observe` |
| Rate-limit | yes | yes | `rate-limit:<name>:observe` |
| Robots Disallow | n/a | yes | `robotsblock:<group>:observe` |
| Form-captcha | n/a | yes | `form-captcha:<scope>:observe` |

Transport-level errors (415 / 413 / 400 on form-captcha; 503 on
captcha-verify in-flight cap; 503 misconfigured) intentionally
still fire under log-only mode — those are misconfiguration, not
policy.

## Tuning workflow

The full path from "draft policy" to "live enforcement":

1. **Draft** — write the new rule with `mode=observe` (or set
   `BotShieldEnabled LogOnly` to dry-run a whole revision).
2. **Reload** — `apachectl configtest && systemctl reload apache2`.
3. **Watch** — tail the error log for `:observe` matches, or query
   the matching `*_observed_total` Prometheus counter:

   ```sh
   curl -s http://localhost/botshield/metrics | grep observed
   # botshield_trigger_observed_total{name="admin-trap",family="path"} 38
   # botshield_rate_limit_observed_total{name="api-burst"} 142
   ```
4. **Iterate** — if matches are wrong (false positives, missing
   cohort, broken predicate) edit and reload. The observe gate
   isolates iteration from production traffic.
5. **Promote** — remove `mode=observe` (or change
   `BotShieldEnabled LogOnly` to `On`) and reload. Watch the matching
   non-observe counter (`tier_<t>_total`, `outcome_<o>_total`) to
   confirm enforcement is happening.

## Common pitfalls

**Promoting individual rules from a log-only revision.**
`BotShieldEnabled LogOnly` overrides every rule's per-rule mode. If
you switch the scope to `On` but the rule still has `mode=observe`,
the rule is still in observe — that's the OR semantics. Walk the
new rules and remove `mode=observe` before flipping the scope to
`On`.

**Observe-mode logs not appearing.** mod_botshield's decision log
emits at `info`. Apache's default `LogLevel warn` hides them.
Bump just this module:

```apache
LogLevel botshield_module:info
```

The `*_observed_total` Prometheus counters increment regardless of
log level — useful as a level-independent visibility check.

**Counting observe matches in error log.** The `:observe` suffix is
the canonical filter:

```sh
grep -c ':observe' /var/log/apache2/error.log
```

Counter aggregation across rule names is more efficient at scale —
prefer Prometheus for production dashboards, log grep for
forensics.

## Where to next

- Tier model and scoring: [site model](site-model.md).
- Per-family rule semantics: [policy](policy.md).
- Metrics + decision log surface: [observability](observability.md).
