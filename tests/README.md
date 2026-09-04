# mod_botshield test suite

Pytest-based regression and acceptance tests, plus fuzz and
benchmark suites for the Apache module.

## Layout

```
tests/
├── run                   # dispatcher — runs pytest with sane defaults
├── pyproject.toml        # pytest config + editable-install metadata
├── requirements-test.txt # pinned deps (installed into tests/.venv)
├── conftest.py           # pytest fixtures (apache, fresh_ip, log_slice, …)
├── README.md             # (this file)
│
├── botshield_test/       # framework helpers (importable Python package)
│   ├── apache.py         # reload/restart + transactional config_override
│   ├── client.py         # httpx wrapper with bs-specific defaults
│   ├── config.py         # paths + constants, env-var overrides
│   ├── cookies.py        # pending cookie, PoW solver, tamper helpers
│   ├── enums.py          # TIERS / OUTCOMES / COOKIES / PROVIDERS
│   ├── ips.py            # time-salted fresh_ip() + rate-slot flavor
│   ├── load.py           # rate-limited load generator (soak + fixtures)
│   ├── logs.py           # log_slice + structured decision parser + validator
│   ├── metrics.py        # /metrics snapshot + delta
│   └── providers.py      # per-captcha-provider specs (quirks as data)
│
├── pytests/              # 55 test files (test_*.py); assets/axe.min.js for a11y
│   ├── test_acceptance_*.py     # end-to-end user journeys
│   ├── test_app_*.py            # X-BotShield-Feedback / -Claims (E5/E8.2)
│   ├── test_browser_a11y.py     # Playwright accessibility smoke
│   ├── test_capacity_metrics.py # SHM headroom (E13.1)
│   ├── test_captcha_*.py        # M8 + M8.1 verify endpoint
│   ├── test_cookie_*.py         # cookie format + verify + property tests
│   ├── test_form_captcha.py     # E18 inline form captcha
│   ├── test_load_*.py           # E11 load-aware throttling
│   ├── test_robots.py           # E2.2 RFC 9309 + Crawl-delay
│   ├── test_safeguard.py        # E10 anti-loop
│   ├── test_secret_rotation.py  # E16
│   ├── test_shadow_mode.py      # E12
│   ├── test_soak.py             # @slow + @serial soak runner
│   ├── test_triggers.py         # E3/E4/E6/E7/E14 trigger families
│   ├── test_namespace.py        # E13 multi-vhost isolation
│   └── …                        # plus ~30 more
│
├── site/                 # dev-vhost docroot (committed; 4 minimum fixtures)
│   ├── index.html        # pass-through baseline (no __bsChallenge marker)
│   ├── bs-custom-help.html
│   ├── bs-custom-page.html
│   └── assets/logos/01-guardian.svg
│
├── fuzz/                 # LibFuzzer harnesses (M11.8)
│   ├── _fuzz_stubs.h     # minimal Apache runtime stubs
│   ├── fuzz_cookie.c     # harness for bs_verify_cookie
│   ├── fuzz_robots.c     # harness for the robots.txt parser
│   ├── seed_corpus.py    # populates corpus/ with real cookies
│   ├── seeds-robots/     # checked-in robots.txt seed corpus
│   └── run.sh            # `run.sh --target {cookie|robots} <seconds>`
│
├── bench/                # benchmark suite (out of pytest)
│   ├── run-bench.sh      # wrk saturation sweep across 12 scenarios
│   ├── run-rate-bench.sh # oha fixed-rate sweep at 1k/5k/10k RPS
│   ├── scenarios/        # 12 vhost configs from baseline → kitchen-sink
│   ├── bench.html        # tiny static target served by the bench docroot
│   ├── bench-robots.txt  # robots.txt for the bench scenarios
│   ├── wrk-cookie.lua    # cookie attacher for the cookied scenario
│   └── scripts/          # mint_cookie.py, helpers
│
└── setup/
    ├── provision.sh         # idempotent one-shot box setup (creates .venv)
    ├── reset-state.sh       # between-run state-file wipe
    └── sudoers.d.example    # template for scoped passwordless apachectl
```

## Prerequisites

The target is **Ubuntu 24.04** on a dev box with sudo. Debian 12 and
Ubuntu 22.04 work identically. The setup script installs everything:

- `apache2`, `apache2-dev`
- `libssl-dev`, `libcurl4-openssl-dev`, `libjson-c-dev`, `libpcre2-dev`
- `python3`, `python3-venv` (pytest framework lives in `tests/.venv`)
- `curl`, `openssl`
- Chromium runtime libs (libnss3, libatk, libxkbcommon, …) for
  Playwright

Pinned Python deps (`requirements-test.txt`): `httpx`, `pytest`,
`pytest-xdist`, `pytest-timeout`, `pytest-playwright`, `playwright`,
`pytest-rerunfailures`, `pytest-html`, `hypothesis`,
`prometheus_client`. `provision.sh` creates `tests/.venv`, installs
them, pulls Chromium into `~/.cache/ms-playwright`, and apt-installs
the matching shared-lib dependencies.

RHEL-family isn't scripted but the dependency list maps cleanly:
`httpd-devel`, `openssl-devel`, `libcurl-devel`, `json-c-devel`,
`pcre2-devel`, `python3`.

## One-shot setup

From a fresh box with the repo checked out:

```bash
sudo tests/setup/provision.sh
```

The script is **idempotent** — safe to re-run. On first run it:

- Refuses to proceed if the repo path is group/world-writable
  (preempts a make-install hijack on shared boxes).
- Installs apt packages.
- Builds the module (`make`) and installs it
  (`/usr/lib/apache2/modules/mod_botshield.so`).
- Creates a self-signed cert at `/etc/ssl/botshield-dev/` (for the
  HTTPS dev vhost on localhost).
- Generates `/etc/botshield/secret` (HMAC key, 32 bytes hex) if it
  doesn't exist, `chmod 600`. Same for the per-provider dummy secret
  files (`/etc/botshield/{turnstile,hcaptcha,recaptcha-v2,recaptcha-v3,
  friendly,geetest}-secret`) and the shared
  `app-integration-secret` for E5/E8.2.
- Creates `/var/lib/botshield/` owned by `www-data` for the state
  file, plus seeds `/var/lib/botshield/bots/` from `data/bots/*.txt`
  (Googlebot / Bingbot / Applebot CIDR ranges).
- Stages `/etc/botshield/test-robots/` (writable by the test user,
  readable by Apache — works around `PrivateTmp=true` for E2.2 tests)
  and `/etc/botshield/load.state.test` (initial value `normal`, for
  E11.1 tests).
- Installs `apache/botshield-dev.conf` as the enabled site, enables
  `mod_botshield`, `mod_status`, `mod_remoteip`, `mod_ssl`,
  `mod_headers`. Selects `mpm_event` as the default MPM.
- `apachectl configtest` and reloads.

If you later modify the module source, `make && sudo make install &&
sudo systemctl reload apache2` is enough — you don't need to re-run
`provision.sh`.

`tests/setup/sudoers.d.example` is a template for granting the
test user passwordless `apachectl reload` / `systemctl restart
apache2` so the test runner doesn't prompt mid-run. Operator-
optional; the suite works without it (sudo will prompt once per
boot).

## Running tests

```bash
tests/run                      # pytest suite, default markers (~9 min)
tests/run --parallel           # one httpd per worker; ~3x faster (~3 min)
tests/run --fast               # skip @heavy and @browser; quick edit loop
tests/run --slow               # include @slow tests (soak, periodic_save)
tests/run --match cookie       # substring filter; passed to pytest as -k
tests/run --mark "not browser" # pytest -m marker expression
tests/run --verbose            # pytest -v instead of -q
tests/run --list               # show tests that would run, don't execute

# Soak specifically (60s / 25 rps by default):
tests/run --slow --match soak

# Overnight soak (8h / 50 rps):
BS_SOAK_DURATION_SEC=28800 BS_SOAK_RPS=50 \
  tests/run --slow --match soak
```

Exit code is `0` if every test passed (or was skipped), `1` if any
test failed.

You can also invoke pytest directly — useful for iterating on one
test with pytest's full traceback + `--pdb`:

```bash
tests/.venv/bin/pytest tests/pytests/test_cookie_gcm.py -v
tests/.venv/bin/pytest tests/pytests/ -k "captcha and not rejected"
tests/.venv/bin/pytest tests/pytests/ -m "not serial" -n auto
```

## Markers

Defined in `pyproject.toml`; consumed by `tests/run` and the GitHub
Actions workflow.

- `@pytest.mark.serial` — mutates state that is global to the httpd
  *installation*, not just one instance. Runs outside the xdist pool.
  Now rare: `test_mpm_matrix` is the honest case, because `a2enmod`
  switches the MPM for every server on the box. Most tests carried
  this marker only because they all shared one Apache; per-worker
  instances (below) removed that reason and 27 files were unmarked.
- `@pytest.mark.heavy` — several seconds, usually waiting on the 1s
  watchdog. In the full gate, out of `--fast`. Deliberately *not*
  `@slow`: that marker is opt-in and already filtered from the default
  run, so reusing it would quietly drop load-state, trigger-dispatch
  and namespace isolation from the gate to make one lane quicker.
- `@pytest.mark.slow` — multi-second wait (e.g. the 40-second
  watchdog tick). Excluded by default; opt in with `tests/run --slow`.
- `@pytest.mark.live_network` — requires reachable third-party
  captcha siteverify (Cloudflare, Google, hCaptcha, Friendly,
  GeeTest). Skips if unreachable rather than failing. Auto-retries
  twice via `pytest-rerunfailures` (applied through a collection
  hook in `conftest.py` — new live_network tests inherit the policy
  automatically).
- `@pytest.mark.live_provider` — requires a real provider secret
  via env var. Skips without the env var.
- `@pytest.mark.acceptance` — end-to-end user-journey test.
- `@pytest.mark.browser` — runs in a real headless Chromium via
  pytest-playwright. Catches regressions no request library can see
  (interstitial JS execution, cookie attribute enforcement,
  auto-submit form wiring).

## Parallel testing

`--parallel` gives each xdist worker its own httpd instance rather than
sharing one. That is the whole reason it works: the tests swap vhost
config and reload, so on a shared server concurrent workers interleave
edits into invalid config. Measured before this existed — two overrides
collided into `mode='monitor'`, httpd refused to start, and 177 tests
failed for that reason rather than on their own merits.

Provision the instances once:

```bash
tests/setup/make-instances.sh 6      # w0..w5
```

Each gets its own port (8543+n), runtime dir, logs, SHM state file and
external load-state file. `config.py` resolves all of it from
`PYTEST_XDIST_WORKER`, and those per-worker values deliberately outrank
the `BS_*` environment variables: honouring an env var under xdist would
send every worker back to one server. Outside xdist the `BS_*` variables
win, and below them sit platform defaults.

### Provisioning

    sudo tests/setup/provision-rocky.sh     # RHEL family, and what CI runs
    sudo tests/setup/provision.sh           # Debian family

Both are idempotent and both end with a config check, so a failure
points at the thing that is actually wrong rather than surfacing later
as a test that cannot connect. The Rocky one is also what the CI
container runs, which is deliberate: a provisioning path that only CI
exercises is a path that breaks without anyone noticing.

### Platform

`config.py` detects which Apache is installed and derives every default
from that: the binary to invoke, the service to restart, and where the
config, logs and state live. RHEL-family means `httpd` and the
`/etc/httpd/bstest` instance; Debian-family means `apache2` and
`/etc/apache2`. `BS_PLATFORM=rhel|debian` overrides the detection and
each individual `BS_*` variable still overrides its own default.

Nothing needs sourcing before a run. There used to be a `bstest.env` for
this, and it was a workaround for the harness having no platform notion
at all: it shelled out to `httpd`, the RHEL binary, while defaulting its
paths to `/etc/apache2`, the Debian layout. That is wrong on both
platforms, and it failed differently on each — on RHEL the paths were
wrong unless you remembered the env file, and in CI the binary did not
exist, so every config-parse test failed with `httpd: command not found`
and had done for months without anyone reading the log.

`tests/run --parallel` derives `-n` from how many instances are
actually running, never `auto`. `auto` picks one worker per core, and a
worker whose instance does not exist just gets connection refused —
which surfaces as dozens of unrelated test failures rather than as
"provision more instances".

Worker ports start at 8543 so they never collide with the original
single instance on 8443, which `--parallel`'s second phase still uses
for the serial tests.

### If a run crashes

A crashed run can leave the shared vhost mid-override — e.g. a stray
`BotShieldScoreSilent 500`, which then fails unrelated tests *even
single-process*. If tests start failing inexplicably, diff the vhost
against a known-good copy before suspecting the code.

## Reports

Every pytest invocation writes two reports to `tests/reports/`:

- `pytests-<phase>.xml` — JUnit XML, picked up by GitHub Actions'
  native test-summary view.
- `pytests-<phase>.html` — self-contained HTML, downloadable as a
  CI artifact for triage when a test fails.

`<phase>` is `not_serial` / `serial` under `--parallel`, or `all`
otherwise. The directory is gitignored.

## Provider secrets

Three providers don't publish iconic always-pass keys, so the
matching tests skip unless an operator supplies real credentials:

| Provider | Env vars | Source |
|---|---|---|
| Friendly Captcha | `BS_FRIENDLY_SECRET`, `BS_FRIENDLY_SITEKEY`, `BS_FRIENDLY_SOLUTION` | [friendlycaptcha.com](https://friendlycaptcha.com) free tier |
| GeeTest v4 | `BS_GEETEST_KEY`, `BS_GEETEST_ID`, `BS_GEETEST_TOKEN` | [dashboard.geetest.com](https://dashboard.geetest.com) |
| reCAPTCHA v3 (real score) | `BS_RECAPTCHA_V3_SECRET`, `BS_RECAPTCHA_V3_SITEKEY`, `BS_RECAPTCHA_V3_TOKEN` | [reCAPTCHA admin](https://www.google.com/recaptcha/admin) |

Tests that need these print `SKIP: <reason>` if the env var isn't set,
so the suite passes without them. To run those tests end-to-end:

```bash
export BS_FRIENDLY_SECRET="..."
export BS_FRIENDLY_SITEKEY="..."
export BS_FRIENDLY_SOLUTION="..."
tests/run --match friendly
```

CI passes the `_TOKEN` / `_SOLUTION` flavors as repo secrets to the
test-fast job (see `.github/workflows/ci.yml`).

Published provider dummies (committed in `provision.sh`):

| Provider | Always-pass sitekey | Always-pass secret |
|---|---|---|
| Turnstile | `1x00000000000000000000AA` | `1x0000000000000000000000000000000AA` |
| hCaptcha | `10000000-ffff-ffff-ffff-000000000001` | `0x0000000000000000000000000000000000000000` |
| reCAPTCHA v2 | `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI` | `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe` |

## Fuzzing

Two coverage-guided LibFuzzer harnesses, each ASan + UBSan +
libFuzzer. Not in the default pytest suite — fuzzing wants minutes-
to-hours budgets, not per-PR budgets. Run manually:

```bash
sudo apt install -y clang libclang-rt-dev    # one-time
make fuzz                                     # builds tests/fuzz/fuzz_cookie
make fuzz-robots                              # builds tests/fuzz/fuzz_robots

tests/fuzz/run.sh --target cookie 30          # 30-second smoke
tests/fuzz/run.sh --target cookie 3600        # 1-hour campaign
tests/fuzz/run.sh --target robots 1800        # 30-minute robots-parser campaign
```

A crash, UB report, or leak produces a `crash-<hash>` /
`leak-<hash>` / `timeout-<hash>` / `slow-unit-<hash>` file next to
the binary — those are the minimized reproducer inputs. The
`workflow_dispatch`-only `fuzz-nightly` CI job runs both harnesses
sequentially (30 m each) and uploads artifacts on a finding.

The hypothesis-driven byte-tamper test in
`pytests/test_cookie_property.py` covers the cookie parser at ~50
exec/sec via HTTP; LibFuzzer here covers it at 200k+ exec/sec
in-process with coverage feedback. Complementary, not redundant —
HTTP hypothesis catches end-to-end issues (cookies the module
accepts it shouldn't); LibFuzzer catches memory safety / UB bugs
in the parsing C.

## Benchmarks

Two complementary suites under `tests/bench/`. Out of the pytest
runner — these are operator-driven measurements, not pass/fail
gates.

```bash
tests/bench/run-bench.sh             # wrk saturation: 12 scenarios × 30s
tests/bench/run-rate-bench.sh        # oha fixed-rate: 1k/5k/10k RPS sweep
```

`run-bench.sh` answers "what's the capacity ceiling?" — useful for
sizing but produces deltas amplified by the cheap static-file
denominator. `run-rate-bench.sh` answers "at production-realistic
load, how much latency does BotShield add?" — better proxy for
real-world cost. Both write JSON results under
`tests/bench/results/<timestamp>-…/`. The directory is gitignored
and growing — wipe periodically with `rm -rf tests/bench/results/`
if it gets unwieldy.

See `docs/deployment.md` "Performance characteristics" for the
canonical numbers.

## What tests must not assume

- **Absolute counter values.** Always work in deltas: `metrics.snapshot()`
  before, drive traffic, `metrics.snapshot()` after, then
  `metrics.delta(before, after)`. Counters may be any non-negative
  value at test start.
- **Empty flagged-IP table.** Prior runs may have flagged IPs that
  persist in the state file. Use `rate_slot_ip` (a fresh, un-flagged
  IP per call) or request the `clean_state` fixture to wipe the
  state file + restart.
- **Fresh Bloom filter.** Same reason. Use `fresh_ip` — the
  allocator picks from `100.64.0.0/10` (CGN), which no earlier run
  has touched.
- **Log position.** Use the `log_slice` fixture to extract only this
  test's lines from the botshield error log.

## Between-run state reset

Most tests use deltas and don't need a reset. For tests that DO
need a known-clean SHM + state file, request the `clean_state`
fixture:

```python
def test_fresh_setup(clean_state, fresh_ip):
    # SHM + state file are empty. Apache just finished restarting.
    ...
```

Or from the shell:

```bash
sudo tests/setup/reset-state.sh
```

## Debugging a failing test

When a test fails, pytest prints the traceback with surrounding
source. Additional forensics:

- Module errors: `sudo tail -50 /var/log/apache2/error.log`
- Decision log: `sudo tail -50 /var/log/apache2/botshield-dev-error.log`
- Access log: `sudo tail -50 /var/log/apache2/botshield-dev-access.log`
- Current SHM counters: `curl -sk https://localhost/botshield/metrics`
- Current mod_status: `curl -sk https://localhost/server-status`
- Drop into pdb on failure:
  `tests/.venv/bin/pytest pytests/test_X.py --pdb`

`config_override` guarantees revert on exception, so a test that
blows up mid-swap leaves the vhost in its pre-test state. If the box
is somehow left in an odd state anyway,
`sudo tests/setup/provision.sh` restores the baseline.

## Writing a new test

Put the file under `tests/pytests/`, named `test_<something>.py`.
Request the fixtures you need by parameter name — no imports.

```python
"""One-line description of what this test proves."""

from botshield_test import client, metrics


def test_some_path_emits_challenged(fresh_ip, log_slice):
    before = metrics.snapshot()
    with log_slice as slc:
        client.get("/some-path", xff=fresh_ip, ua="python-requests/2.31")
        lines = slc.decision_lines(ip=fresh_ip, outcome="challenged")
    after = metrics.snapshot()

    assert len(lines) == 1
    deltas = metrics.delta(before, after)
    assert deltas["botshield_outcome_challenged_total"] == 1
```

Markers (declared at module level via `pytestmark =
pytest.mark.serial` or per-test via `@pytest.mark.live_network`)
are documented in the "Markers" section above.
