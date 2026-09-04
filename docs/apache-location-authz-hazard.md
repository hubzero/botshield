# `<Location>` silently voids `<Files>` access control

Written for an Ansible CLAUDE.md. The incident behind it exposed a
production database password to the public internet for five days.

## The rule

**Never write a broad `<Location>` or `<LocationMatch>` containing
`Require` directives into a vhost that protects files with `<Files>` or
`<FilesMatch>`.** The `<Location>` wins, and the file rules stop
applying. Nothing warns you: `apachectl configtest` says `Syntax OK`,
the reload succeeds, and every protected file becomes readable.

## Why it happens

Apache 2.4 merges configuration sections in a fixed order, regardless of
where they appear in the file:

```
<Directory>  →  <Files> / <FilesMatch>  →  <Location> / <LocationMatch>
```

`<Location>` merges **last**. And the authorization block of the
later-merged section **replaces** the earlier one rather than combining
with it — so whatever a `<Location>` says about `Require` is the final
word, and the `<FilesMatch>` deny that came before it is discarded
unevaluated.

Verified on Apache 2.4.37 (Rocky 8) with a four-line config:

```apache
DocumentRoot /srv/htdocs
<Directory /srv/htdocs>
    Require all granted
</Directory>
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
```

`GET /configuration.php` → **403**. Add this and change nothing else:

```apache
<Location "/">
    Require all granted
</Location>
```

`GET /configuration.php` → **200**, serving the file's contents.

It replaces in both directions, which is the proof that this is
replacement and not a permissive merge. With `<FilesMatch>` granting and
`<Location "/">` denying, the result is 403 — the `<Location>` wins
again, this time by being stricter. The direction of the override
follows the merge order, not the strictness.

## Why it is dangerous specifically

Three properties combine badly:

1. **It fails open.** The mistake grants access rather than removing it,
   so no user reports a problem.
2. **It is invisible to every check.** `configtest` passes — the syntax
   is valid and both sections are legal. Nothing is logged. The only way
   to see it is `LogLevel authz_core:trace8`, which shows the
   `<FilesMatch>` rule never being evaluated for the request.
3. **The two directives are usually far apart** — often in different
   files, one hand-written and one generated — so nobody reads them
   together.

## The incident

A hand-maintained `conf.d` drop-in blocked a credential-scanning /24:

```apache
<Location "/">
    <RequireAll>
        Require all granted
        Require not ip 185.177.72.0/24
    </RequireAll>
</Location>
```

Locally correct, and it did block the scanner. But it voided the vhost's
own file rules, including:

```apache
<FilesMatch (.*\.php$)>
    Require all denied
</FilesMatch>
```

That deny is the only thing stopping Apache from serving PHP **source**
for any path that is not one of the handful of proxied entry points.
With it gone, `https://<site>/configuration.php` returned 200 with the
Joomla configuration in plaintext — database host, user, and password —
to anyone who asked. Five IPs fetched it 39 times over five days before
it was noticed. The credential was rotated.

Note what the blast radius was *not* limited to. The `<Location>` was
written to solve a narrow problem (one scanner, one /24) but its match
was `/`, so its effect was every file rule in the vhost.

## The fix

`AuthzMergeRules Off` is the directive that would express "do not let
this section replace what came before". **It does not exist in Apache
2.4.37** — it is absent from `mod_authz_core.so` in that build
(`httpd-2.4.37-65.module+el8.10`), and using it is a hard configtest
failure: `Invalid command 'AuthzMergeRules'`. Do not reach for it on
RHEL 8 / Rocky 8.

So the match itself has to be narrowed to exclude every path the file
rules protect:

```apache
<LocationMatch "^(?!.*\.php$)(?!.*/composer\.json$)(?!.*/installed\.json$).*$">
    <RequireAll>
        Require all granted
        Require not ip 185.177.72.0/24
    </RequireAll>
</LocationMatch>
```

Confirmed: with this form the `<FilesMatch>` deny survives and
`configuration.php` returns 403 again.

**The exclusion list must name every file rule the vhost relies on, not
just the one you remember.** Anything the `<Location>` still matches
gets its `<Files>` deny replaced. Missing one is the same bug again,
narrower.

Better still, when it fits the requirement: put the block somewhere that
does not merge over file rules at all — `<Directory>`, or a
`RewriteRule` / mod_authz at server scope, or the firewall. An IP block
in particular does not belong in `<Location>`; it has nothing to do with
URL space.

## For Ansible specifically

- **Treat `<Location`/`<LocationMatch` with `Require` inside as a
  reviewed construct.** If a template or task emits one, the play should
  state which `<Files>`/`<FilesMatch>` rules exist in that vhost and why
  they are unaffected.
- **Drop-ins are the high-risk shape.** A `conf.d/*.conf` file authored
  independently of the vhost is exactly the case where the author cannot
  see the file rules they are about to void. Ordering by filename does
  not help — section merge order ignores file order.
- **`configtest` is not a sufficient gate for this class of change.**
  Add an assertion to the play instead: after reload, fetch a known
  protected path and assert the status code.

  ```yaml
  - name: Protected files must stay protected after any vhost change
    ansible.builtin.uri:
      url: "https://{{ site_fqdn }}/{{ item }}"
      status_code: [403, 404]
      validate_certs: yes
    loop:
      - configuration.php
      - composer.json
      - installed.json
  ```

  This is worth having regardless of the cause. It is a direct test of
  the property that actually matters, and it would have caught this
  within one play run instead of five days.
- **Prefer generating the whole vhost over layering drop-ins onto a
  vhost you do not own.** The failure mode here is specifically about
  two authors who never read each other's rules.

## The general lesson

The narrow bug is an Apache merge-order rule. The general one is that a
config change scoped to `/` has a blast radius of `/`, whatever it was
written for — and that access-control regressions fail open, so they are
found by whoever is scanning you rather than by your monitoring. Any
change touching authorization deserves a positive test that a protected
thing is still protected, not just a test that the intended block works.
