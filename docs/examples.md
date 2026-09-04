# Example configs

The module ships no default rules. An unset score threshold never
fires, so a fresh deployment scores nothing and challenges nothing
until you declare both a trigger and a threshold — see
[Policy](policy.md#no-compiled-in-defaults) for why. The first two
files here are what the module used to seed automatically before that
changed, kept as a documented starting point for anyone who wants that
shape. The third shows how a whole deployment fits together.

None of them is a required include. Copy what you want into your own
config; the module never reads any of these files.

## What's here

- **[`flag-triggers.conf.example`](https://github.com/hubzero/botshield/blob/main/docs/examples/flag-triggers.conf.example)**
  — the `BotShieldFlagTrigger` slate: honeypot and fake-bot detection
  forced to captcha, scanner-probe and repeat-PoW-failure signals
  escalating tier, and the three application-issued trust credits
  (`app_verified_human`, `app_verified_session`, `app_trust_signal`)
  that subtract score without ever raising tier.
- **[`heuristic-triggers.conf.example`](https://github.com/hubzero/botshield/blob/main/docs/examples/heuristic-triggers.conf.example)**
  — the `BotShieldHeuristicTrigger` slate: conservative score adds for
  a missing User-Agent, a missing Accept-Language, a known
  HTTP-library UA token, an IP never seen before, and a cookie held
  without ever passing a challenge.
- **[`full-site.conf.example`](https://github.com/hubzero/botshield/blob/main/docs/examples/full-site.conf.example)**
  — a whole deployment rather than one directive family: where the
  configuration gets included and why that location is a safety
  decision, what order the layers go in, and which scopes to enforce in
  what sequence. It enforces nothing as written, because the rollout
  order is the part worth copying.

All three are annotated in full — syntax, every match key, the
`reset` keyword, `mode=observe` staging — so they double as a reference
you can read next to real values instead of in the abstract.

## Seeing it running rather than reading about it

`apache/botshield-dev.conf` in the repository wires the same slate
into a live vhost, alongside the score thresholds that make it act
(`BotShieldScoreNonInteractive`, `BotShieldScoreInteractive`,
`BotShieldScoreCaptcha` — themselves unset by default, for the same
reason). That is the fastest way to see the starter slate doing
something rather than just reading its comments.

## Adopting it

1. Pick a threshold. Nothing fires without
   `BotShieldScoreNonInteractive`, `BotShieldScoreInteractive`, and
   `BotShieldScoreCaptcha` set — the [Directive reference](directives.md)
   has the syntax, and `httpd -t -D DUMP_BOTSHIELD_POLICY` will tell
   you which of the three you've left unset.
2. Copy the lines you want from either file into your vhost or server
   config.
3. Reload, then read the results back with the same dump flag — it
   prints every effective flag trigger and heuristic with its source,
   so "is this rule actually in effect" never has to be a guess. See
   [Policy](policy.md#reading-the-effective-policy) for what that
   output looks like.

The values in both files match this project's own `src/score.h` at the
time they were written. The module never reads either file, so nothing
keeps them in sync with the header automatically — once you've copied
a line into your own config, it's yours to keep current.
