# Contributing to mod_botshield

Thanks for your interest. The project is small and the workflow is
deliberately low-ceremony.

## Quick start

```sh
git clone https://github.com/hubzero/botshield.git
cd botshield
sudo tests/setup/provision.sh
tests/run --parallel --mark "not browser"
```

`provision.sh` is idempotent; it installs apt packages, builds and
installs the module, sets up a self-signed-cert HTTPS dev vhost on
`localhost`, generates per-provider dummy captcha secrets, and
creates the test venv at `tests/.venv/`. Re-run it any time you
want to reset the environment.

After that, `tests/run` is the dispatcher — flags + markers are
documented in [`tests/README.md`](tests/README.md).

## Reporting bugs and asking questions

- **Bugs**: open a GitHub issue with reproduction steps. A minimal
  Apache config snippet plus a `curl` invocation that triggers the
  problem is the gold standard.
- **Security bugs**: do not open public issues. See
  [SECURITY.md](SECURITY.md).
- **Questions / feature ideas**: GitHub Discussions is fine for
  open-ended things; issues are fine for things you want tracked.

## Submitting a pull request

1. Fork → branch from `main`.
2. Make the change. Keep it focused — one concern per PR is
   easier to review than three concerns bundled.
3. **Run the test suite**:
   ```sh
   tests/run --parallel
   ```
   PRs are gated on CI. Locally-green tests + clean CI is the
   baseline; flake-on-CI-only happens occasionally and is a
   conversation, not an automatic block.
4. **Rebuild the docs** if you touched `docs/*.md` or
   `gh-pages/{site.json,assets,templates}`:
   ```sh
   make docs
   git add gh-pages/public/
   ```
   The `pages.yml` workflow's build job will fail your PR if you forget.
5. **Commit messages**: imperative, focused on the *why* when it
   isn't obvious from the diff. The git log shows the style; copy
   what you see. No "fix typo" PRs are too small to be welcome.
6. **Open the PR**. Describe what changed and what you tested.
   Screenshots / log excerpts when relevant.

## Where things live

- `src/` — the C source. 19 modules, each `.c` paired with `.h`.
  `DESIGN.md` explains the module split.
- `conf/` — the one config artifact an installer places on a host:
  the `LoadModule` line. Its comment names the destination on each
  distribution.
- `data/` — the bot directory, verified-bot ranges and user-agent
  corpora the module loads at startup. Installed to `/etc/botshield`.
- `services/` — systemd units and their scripts, one directory each:
  `dbmon`, `fpmmon`, and `refresh` (which pulls new bot data).
- `docs/` — markdown source for the operator handbook (rendered to
  `gh-pages/public/`). `docs/examples/` holds annotated
  `.conf.example` files to copy from, not to install as-is.
- `gh-pages/` — the site builder: `build_site.py`, `check_links.py`,
  `site.json` (nav + card copy), `templates/`, `assets/`, and
  `public/` (the built site, committed and served by GitHub Pages).
- `tools/` — developer utilities, not shipped: the generators that
  rebuild `data/` from upstream sources, and two C benchmarks.
- `tests/pytests/` — pytest cases against a running Apache. Reusable
  framework helpers in `tests/botshield_test/`.
- `tests/unit/` — in-process C tests that link the sources directly
  and need no server. `make unit`.
- `tests/setup/` — everything that builds a test instance, including
  `provision.sh`, `provision-rocky.sh`, and the dev vhost
  `botshield-dev.conf` those two install.
- `tests/fuzz/` — LibFuzzer harnesses for the cookie + robots parsers.
- `tests/bench/` — wrk + oha benchmark scripts.

`DESIGN.md` is current-state architecture; update it when you change
behavior, not just when you ship a feature. There is no separate
changelog — the git log is the narrative record, and commit messages
are written to be read that way.

## Code style

- C99. Apache style for indentation (4 spaces, no tabs except
  Makefile). `.editorconfig` enforces the basics.
- Function/symbol prefixes: `bs_` / `BS_` for cross-file public
  symbols. File-local helpers use `static` and don't need the
  prefix.
- Comments explain *why* something is the way it is when the
  code itself can't say it. Don't narrate what `if (x > 0)` does;
  do explain why we picked `x > 0` over `x >= 0`.
- No regex on the hot path — hand-rolled byte scanners
  (`memcmp` / `memchr`). Reserve regex for config-time.

## License

By contributing, you agree your contribution is licensed under the
MIT License (see [LICENSE](LICENSE)).
