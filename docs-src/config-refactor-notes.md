# Notes toward a config refactor

Written 2026-08-28, after the second production lockout in three days.
Both were caused by the same shape of problem, and neither was a coding
error: in both cases every individual directive did exactly what it
documented, and the combination locked a real user out of the site.

These are notes on the *condition*, not a design. The point is to record
what the failures had in common while it is still fresh.

## The two incidents

**#1 — `tier_floor` bypasses the score ceiling.** The operator parked
`BotShieldScoreInteractive` and `BotShieldScoreCaptcha` at 10000 to make a scope
effectively challenge-free. A `scanner_probe` flag carries a compiled-in
`tier_floor` of `form`, which is MAX'd in *after* the score-to-tier
decision and never consults the thresholds. Users hit a form challenge in
a scope configured to have none.

**#2 — a flag score at or above the silent threshold is a permanent
loop.** The documented fix for #1 is to reset the floors and keep
`action=score add=50`. But solving a challenge does not clear a flag, and
flag scores re-apply on every request, so a score of 50 against the
default silent threshold of 20 re-challenges forever. The reporter solved
the challenge roughly once per second for four minutes.

The second incident was caused by following this repository's own
documented remedy for the first.

## What the two have in common

**1. Composition is invisible at the point of configuration.**

Each directive is locally sensible. The hazard only exists in the
interaction between a flag's compiled-in action, a threshold set
somewhere else in the file, and a lifecycle rule (flags outlive solves)
that is not written down near either. Nothing an operator can read in one
place tells them the combination is dangerous.

**2. Compiled-in defaults are invisible state.**

`scanner_probe` had two actions before anyone configured anything. The
config file that "sets" the flag's behaviour was in fact *adding to*
behaviour that already existed, and `reset` — the keyword that makes the
declaration authoritative — is optional and easy to omit. An operator
reading the deployed config cannot see the effective policy. There is no
way to ask the module what it will actually do.

**3. Units are unmarked and thresholds are action-at-a-distance.**

`add=50` is meaningless without knowing `BotShieldScoreNonInteractive` is 20, and
that directive was not present in the deployed file at all — it was the
compiled default. The number that made 50 dangerous was in neither the
config nor the docs page being followed.

**4. The dangerous states are unreachable to testing.**

The loop only appears on the *second* request after a solve. Any test
that solves once and asserts success passes. Both incidents were found by
a user filing a ticket, and neither would have been caught by adding more
of the tests we already write.

**5. Failure is silent and asymmetric.**

Every one of these misconfigurations fails *closed* — toward challenging
more people. There is no warning at startup, nothing in the error log,
and the decision log records each individual challenge as a normal event.
A thousand identical challenges to one IP looks like a thousand rows,
not like one bug.

## A third instance, found while writing this down

Adding `BotShieldDbStatsFile` to `conf/botshield.conf` did nothing. The
directive is `RSRC_CONF`, that file is included at vhost scope, and an
`RSRC_CONF` directive inside a `<VirtualHost>` parses cleanly and is
then ignored. `apachectl configtest` said `Syntax OK`, the reload
succeeded, and the dashboard reported "no monitor configured" — which
reads as *the operator forgot the directive* rather than *the directive
is present and being discarded*.

This is the same five properties again, with a different mechanism.
That file's own header documents the trap for `BotShieldStateFile`,
which is how it was diagnosed in under a minute — but documentation in
one file cannot protect a directive added later, and nothing in the
system said a word. Scope errors are mechanically detectable: the
module knows a directive's required scope and knows where it was found.

It is worth noting that the same class of bug has now produced two user
lockouts and one silently dead feature within one week, which is
evidence about the configuration system rather than about the people
using it.

## What a refactor should probably provide

Roughly in order of how much each would have helped:

- **An effective-policy dump.** `apachectl -M`-style: ask the module to
  print the resolved policy — every flag, every trigger, compiled-in and
  configured, after `reset` processing, with thresholds inlined and the
  source of each value named. Both incidents were diagnosable in seconds
  once the effective values were in front of us, and invisible before.

- **Cross-directive validation at startup.** A flag score at or above
  the silent threshold is almost certainly a mistake; so is a
  `tier_floor` above a parked ceiling. These are checkable at
  post-config, where a warning costs nothing and reaches the operator
  before the users do.

- **Warn on a directive accepted into a scope where it does nothing.**
  Silently discarding an `RSRC_CONF` directive found inside a vhost is
  the single cheapest thing on this list to fix and has already cost
  one debugging session.

- **Make lifecycle explicit in the directive surface.** The real bug in
  #2 is that "score" and "flag" have different lifetimes — one is
  forgiven, one is not — and the syntax makes them look alike. Whatever
  replaces this should say how long an effect lasts and what clears it,
  at the point where the effect is declared.

- **Loop detection as a first-class signal.** The safeguard counter
  already exists and already fired here; it trips per-IP and stays
  invisible. Repeated solve→challenge cycles for one client are a
  distinct, nameable condition and should be surfaced as one, not left
  as a pattern someone has to notice in a log.

- **Defaults that cannot silently compose.** Either compiled-in triggers
  are absent unless declared, or a declaration is always authoritative.
  The current middle ground — defaults exist, declarations append,
  `reset` is opt-in — is the mechanism behind both incidents.

## Caveat

Nothing above argues the current behaviour is wrong on its own terms.
Flags outliving solves is defensible; a tier floor that ignores
thresholds is defensible. The problem is that the system gives an
operator no way to see what those choices add up to, and the failure mode
of guessing wrong is locking real users out of a production site.
