# mod_botshield test suite

Regression and acceptance tests for the module. Two frameworks live
side-by-side during the M11.4–M11.5 rebuild:

- **Bash suite** (`unit/`, `integration/`, `acceptance/`, `stress/`) —
  the original lightweight shell scripts. One file per test, source
  `lib/common.sh`, emit `PASS:` / `FAIL:` / `SKIP:` lines.
- **Pytest suite** (`pytests/` + `botshield_test/` + `conftest.py`) —
  the pytest rebuild introduced in M11.4. Shared helpers in
  `botshield_test/`, pytest fixtures in `conftest.py`, tests under
  `pytests/`.

Both run under `tests/run` and in CI. The pytest suite is the forward-
looking one; M11.5 archives the bash tests to `bash-legacy/` and
retires them from the default run.

## Layout

```
tests/
├── run              # dispatcher — walks categories, runs tests
├── pyproject.toml        # pytest config + editable-install metadata
├── requirements-test.txt # pinned pytest deps (installed into .venv)
├── conftest.py           # pytest fixtures (apache, fresh_ip, log_slice, …)
├── lib/
│   ├── common.sh          # bash helpers (legacy; retires in M11.5)
│   └── decision_gate.awk  # key=value decision-log validator
├── botshield_test/        # pytest framework helpers (M11.4+)
│   ├── apache.py          # reload/restart + transactional config_override
│   ├── client.py          # httpx wrapper with bs-specific defaults
│   ├── config.py          # paths + constants, env-var overrides
│   ├── cookies.py         # pending cookie, PoW solver, tamper helpers
│   ├── enums.py           # TIERS / OUTCOMES / COOKIES / PROVIDERS
│   ├── ips.py             # time-salted fresh_ip() + rate-slot flavor
│   ├── logs.py            # log_slice + structured decision parser
│   └── metrics.py         # /metrics snapshot + delta
├── setup/
│   ├── provision.sh       # idempotent one-shot box setup
│   └── reset-state.sh     # between-run state-file wipe
├── unit/            # bash: no-Apache-needed checks (format validators)
├── integration/    # bash: tests against a running Apache + module
├── acceptance/     # bash: end-to-end user journeys
├── pytests/        # pytest: migrated tests (M11.4+ growing)
├── stress/         # wrk, MPM matrix, soak (opt-in, slow)
└── tools/          # test utilities (soak analyzer, etc.)
```

## Prerequisites

The target is **Ubuntu 24.04** on a dev box with sudo. Debian 12 and
Ubuntu 22.04 work identically. The setup script installs what's needed:

- `apache2`, `apache2-dev`
- `libssl-dev`, `libcurl4-openssl-dev`, `libjson-c-dev`, `libpcre2-dev`
- `python3`, `python3-venv` (pytest framework lives in `tests/.venv`)
- `curl`, `openssl`, `wrk`

Pinned Python deps: `httpx`, `pytest`, `pytest-xdist`, `pytest-timeout`
(see `requirements-test.txt`). `provision.sh` creates `tests/.venv`
and installs them. Playwright + Chromium arrive in M11.6.

RHEL-family isn't scripted yet but the dependency list maps cleanly:
`httpd-devel`, `openssl-devel`, `libcurl-devel`, `json-c-devel`,
`pcre2-devel`, `python3`, `wrk` (EPEL).

## One-shot setup

From a fresh box with the repo checked out:

```bash
sudo tests/setup/provision.sh
```

This script is **idempotent** — safe to re-run. On first run it:

- Installs apt packages.
- Builds the module (`make`) and installs it
  (`/usr/lib/apache2/modules/mod_botshield.so`).
- Creates a self-signed cert at `/etc/ssl/botshield-dev/` (for the
  HTTPS dev vhost on localhost).
- Generates `/etc/botshield/secret` (HMAC key, 32 bytes hex) if it
  doesn't exist, `chmod 600`.
- Writes provider dummy secrets at `/etc/botshield/*-secret` for each
  supported provider (Turnstile/hCaptcha/reCAPTCHA v2/reCAPTCHA v3/
  Friendly/GeeTest). The published dummies go in verbatim; the ones
  without public dummies get placeholder strings that are later
  overridden by env vars.
- Creates `/var/lib/botshield/` owned by `www-data` for the state file.
- Installs `apache/botshield-dev.conf` as the enabled site, enables
  `mod_botshield`, `mod_status`, `mod_remoteip`, `mod_ssl`.
- Selects `mpm_event` as the default MPM.
- `apachectl configtest` and reloads.

If you later modify the module source, `make && sudo make install &&
sudo systemctl reload apache2` is enough — you don't need to re-run
`provision.sh`.

## Running tests

```bash
tests/run                      # run everything except stress
tests/run --only unit          # just the unit category
tests/run --only integration   # just integration
tests/run --match m7           # any test whose path contains "m7"
tests/run --list               # list tests that would run
tests/run --verbose            # show each test's stdout inline
tests/run --only stress        # opt-in; these are slow
```

Exit code is `0` if every test passed (or was skipped), `1` if any
test failed. The summary at the end names the failing tests so you
can re-run one with `--match`:

```
=====================================================
tests: 12 passed, 1 skipped, 2 failed
failed:
  - integration/m8_captcha_friendly
  - integration/m8_captcha_geetest
```

## Output format

Each test prints a one-line marker per assertion:

```
=== integration/m7_silent_tier ===
  PASS: silent tier challenged cookie-less fresh IP
  PASS: PoW solve round-trip accepted
  PASS: 15-field cookie parses on replay
```

`t_fail` exits the test script immediately — a single failure aborts
that test, but the dispatcher continues to the next. On failure, the
test's stdout is printed in full so you can see what came before.

## Provider secrets

Three providers don't publish iconic always-pass keys:

| Provider | Env var | Site key source |
|---|---|---|
| Friendly Captcha | `BS_FRIENDLY_SECRET`, `BS_FRIENDLY_SITEKEY` | [friendlycaptcha.com](https://friendlycaptcha.com) free tier |
| GeeTest v4 | `BS_GEETEST_KEY`, `BS_GEETEST_ID` | [dashboard.geetest.com](https://dashboard.geetest.com) |
| reCAPTCHA v3 (real score) | `BS_RECAPTCHA_V3_SECRET`, `BS_RECAPTCHA_V3_SITEKEY` | [reCAPTCHA admin](https://www.google.com/recaptcha/admin) |

Tests that need these print `SKIP: <reason>` if the env var isn't set,
so the suite passes without them. To run those tests end-to-end, sign
up for the free tier, then:

```bash
export BS_FRIENDLY_SECRET="..."
export BS_FRIENDLY_SITEKEY="..."
tests/run --match friendly
```

Published provider dummies (committed in `provision.sh`):

| Provider | Always-pass sitekey | Always-pass secret |
|---|---|---|
| Turnstile | `1x00000000000000000000AA` | `1x0000000000000000000000000000000AA` |
| hCaptcha | `10000000-ffff-ffff-ffff-000000000001` | `0x0000000000000000000000000000000000000000` |
| reCAPTCHA v2 | `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI` | `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe` |

## What tests must not assume

- **Absolute counter values.** Always work in deltas: `metrics_snapshot`
  before, drive traffic, `metrics_snapshot` after, diff. Counters may
  be any non-negative value at test start.
- **Empty flagged-IP table.** Prior runs may have flagged IPs that
  persist in the state file. Tests that care should use IPs unlikely
  to have been flagged (e.g. uncommon XFF ranges), or call
  `tests/setup/reset-state.sh` explicitly.
- **Fresh Bloom filter.** Same reason. First-sight penalties might
  not fire if the IP was in Bloom from a prior run.
- **Log position.** Use `log_mark` + `log_slice` to extract only this
  test's lines from the botshield error log.

## Between-run state reset

Most tests use deltas and don't need a reset. For tests that DO need
a known-clean SHM + state file:

```bash
sudo tests/setup/reset-state.sh
```

This deletes `/var/lib/botshield/state.bin` and restarts Apache.
After restart, all SHM counters start at 0, flagged-IP table is empty,
Bloom filters are empty.

## Debugging a failing test

When a test fails, `tests/run` prints its full stdout. Additional
forensics:

- Module errors: `sudo tail -50 /var/log/apache2/error.log`
- Decision log: `sudo tail -50 /var/log/apache2/botshield-dev-error.log`
- Access log: `sudo tail -50 /var/log/apache2/botshield-dev-access.log`
- Current SHM counters: `curl -sk https://localhost/botshield/metrics`
- Current mod_status: `curl -sk https://localhost/server-status`

Tests that manipulate Apache config (MPM matrix, for instance) clean
up after themselves; if a test exits mid-way and leaves the box in an
odd state, `sudo tests/setup/provision.sh` restores the baseline.

## Writing a new test

Start from `integration/m9_3_metrics_parity.sh` as a template — it
exercises the typical pattern: snapshot metrics and log position,
drive traffic, snapshot again, assert deltas.

Convention:

```bash
#!/bin/bash
# Short description of what this test proves.
set -u
source "$(dirname "$0")/../lib/common.sh"

# Optional: early skip if required env isn't present
if [[ -z "${BS_SOMETHING:-}" ]]; then
  t_skip "BS_SOMETHING not set"
fi

# 1. Snapshot
before=$(metrics_snapshot)
mark=$(log_mark)

# 2. Drive traffic
bs_curl -o /dev/null "$BASE/some-path"

# 3. Assert
after=$(metrics_snapshot)
assert_metric_delta "$before" "$after" botshield_outcome_challenged_total 1

slice=$(log_slice "$mark")
assert_decision_count "$slice" "outcome=challenged" 1

t_pass "some-path emits one challenged decision"
```

Make the script executable (`chmod +x`) and put it under the right
category directory. `tests/run` picks it up automatically.
