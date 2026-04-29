# Staging policy changes

mod_botshield supports two complementary dry-run modes so operators
can deploy new rules without affecting production traffic until
they're confident the matches are correct.

- **Per-rule observe** — pin a single directive into observe mode.
  Useful for staging individual rules.
- **Global shadow mode** — flip every match to observe regardless
  of per-rule setting. Useful for staging an entire policy revision.

Either signal is sufficient; they compose with OR semantics. A rule
runs in observe mode if EITHER its per-rule mode is `observe` OR
`BotShieldShadowMode on` is set. There is no priority order to
memorize.

## What "observe" means precisely

When a rule fires in observe mode:

- The rule's predicate evaluates normally (path match, cohort
  match, env present, etc.).
- The decision log records the would-have-done outcome with an
  `:observe` suffix on the reason token.
- The matching observe-mode metric counter increments
  (`block_path_observed_total`, `trigger_observed_total`).
- **No** flag bits are set on the IP.
- **No** score is added to the request.
- **No** status code, redirect, or log tag side-effect is emitted.

The audit trail captures everything the rule WOULD have done; the
client response is unaffected. Observe matches never short-circuit
the policy walk — the next rule still gets its chance.

## Per-rule observe mode

Add `mode=observe` to any directive that supports it:

```apache
BotShieldPathTrigger    /admin/.env  flag=scanner_probe ttl=3600 log=admin-trap mode=observe
BotShieldBlockPath      legacy-admin "/wp-admin/*" "" * mode=observe
BotShieldRateLimit      api-burst    60 min "" * mode=observe
BotShieldFlagTrigger    honeypot_hit action=tier_floor min=captcha mode=observe
```

The rule still evaluates against every matching request, but takes
no action. Matches appear in the decision log:

```
mod_botshield: decision tier=pass outcome=declined ip=192.0.2.42
    score=0 cookie=absent provider=- alg=- reason="path-trigger:admin-trap:observe"
    path="/admin/.env"
```

Watch the log for hours or days. When matches look correct, remove
`mode=observe` and reload Apache to flip the rule into enforcement.

## Global `BotShieldShadowMode`

For staging a whole policy revision at once, set the server-wide
flag:

```apache
BotShieldShadowMode on
```

Every rule in scope flips to observe regardless of its per-rule
setting. Useful before a release or when comparing a new ruleset
against production traffic without any enforcement risk. Flip back
to `off` when you're ready to enforce.

`BotShieldShadowMode` is tri-state: `on` / `off` / unset (inherit).
Operators usually set it at the main server scope and inherit; per-
vhost overrides are valid for partial rollouts.

## Coverage

Both observe signals reach every gating surface:

| Family | Honors per-rule | Honors shadow_mode | Reason format |
|---|---|---|---|
| Path triggers | yes | yes | `path-trigger:<name>:observe` |
| Cookie triggers | yes | yes | `cookie-trigger:<name>:observe` |
| Env triggers | yes | yes | `env-trigger:<name>:observe` |
| Load triggers | yes | yes | `load-trigger:<name>:observe` |
| Feedback triggers | yes | yes | `feedback-trigger:<event>:observe` |
| Flag triggers | yes | yes | `flag-trigger:<flag>:observe` |
| Block-path | yes | yes | `block-path:<name>:observe` |
| Rate-limit | yes | yes | `rate-limit:<name>:observe` |
| Robots Disallow | n/a | yes | `robots-block:<group>:observe` |
| Form-captcha | n/a | yes | `form-captcha:<scope>:observe` |

Transport-level errors (415 / 413 / 400 on form-captcha; 503 on
captcha-verify in-flight cap; 503 misconfigured) intentionally
still fire under shadow mode — those are misconfiguration, not
policy.

## Tuning workflow

The full path from "draft policy" to "live enforcement":

1. **Draft** — write the new rule with `mode=observe` (or set
   `BotShieldShadowMode on` to dry-run a whole revision).
2. **Reload** — `apachectl configtest && systemctl reload apache2`.
3. **Watch** — tail the error log for `:observe` matches, or query
   the matching `*_observed_total` Prometheus counter:

   ```sh
   curl -s http://localhost/botshield/metrics | grep observed
   # botshield_block_path_observed_total{name="legacy-admin"} 142
   # botshield_trigger_observed_total{name="admin-trap",family="path"} 38
   ```
4. **Iterate** — if matches are wrong (false positives, missing
   cohort, broken predicate) edit and reload. The observe gate
   isolates iteration from production traffic.
5. **Promote** — remove `mode=observe` (or flip
   `BotShieldShadowMode off`) and reload. Watch the matching
   non-observe counter (`tier_<t>_total`, `outcome_<o>_total`) to
   confirm enforcement is happening.

## Common pitfalls

**Promoting individual rules from a shadow-mode revision.**
`BotShieldShadowMode on` overrides every rule's per-rule mode. If
you flip the global off but the rule still has `mode=observe`, the
rule is still in observe — that's the OR semantics. Walk the new
rules and remove `mode=observe` before flipping the global off.

**Observe-mode logs not appearing.** mod_botshield's decision log
emits at `info`. Apache's default `LogLevel warn` hides them.
Bump just this module:

```apache
LogLevel mod_botshield:info
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

- Tier model and scoring: [operator model](../operator-model/index.html).
- Per-family rule semantics: [policy](../policy/index.html).
- Metrics + decision log surface: [observability](../observability/index.html).
