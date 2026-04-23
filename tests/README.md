# mod_botshield test suite

Pytest-based regression and acceptance tests for the module. As of
M11.5 the bash suite is archived in `bash-legacy/` — pytest is the
canonical framework.

## Layout

```
tests/
├── run                   # dispatcher — runs pytest, + stress/ opt-in
├── pyproject.toml        # pytest config + editable-install metadata
├── requirements-test.txt # pinned deps (installed into tests/.venv)
├── conftest.py           # pytest fixtures (apache, fresh_ip, log_slice, …)
├── botshield_test/       # framework helpers
│   ├── apache.py         # reload/restart + transactional config_override
│   ├── client.py         # httpx wrapper with bs-specific defaults
│   ├── config.py         # paths + constants, env-var overrides
│   ├── cookies.py        # pending cookie, PoW solver, tamper helpers
│   ├── enums.py          # TIERS / OUTCOMES / COOKIES / PROVIDERS
│   ├── ips.py            # time-salted fresh_ip() + rate-slot flavor
│   ├── logs.py           # log_slice + structured decision parser + validator
│   ├── metrics.py        # /metrics snapshot + delta
│   └── providers.py      # per-captcha-provider specs (quirks as data)
├── pytests/              # the test files themselves
├── setup/
│   ├── provision.sh      # idempotent one-shot box setup (creates .venv)
│   └── reset-state.sh    # between-run state-file wipe
├── stress/               # wrk + soak (bash, opt-in, slow)
├── tools/                # soak analyzer
└── bash-legacy/          # M11.1–M11.3 bash tests, kept for reference
```

## Prerequisites

The target is **Ubuntu 24.04** on a dev box with sudo. Debian 12 and
Ubuntu 22.04 work identically. The setup script installs what's needed:

- `apache2`, `apache2-dev`
- `libssl-dev`, `libcurl4-openssl-dev`, `libjson-c-dev`, `libpcre2-dev`
- `python3`, `python3-venv` (pytest framework lives in `tests/.venv`)
- `curl`, `openssl`, `wrk`

Pinned Python deps: `httpx`, `pytest`, `pytest-xdist`,
`pytest-timeout`, `pytest-playwright`, `playwright` (see
`requirements-test.txt`). `provision.sh` creates `tests/.venv`,
installs them, pulls the Chromium binary into `~/.cache/ms-playwright`,
and apt-installs Chromium's shared-lib dependencies (libnss3, libatk,
libxkbcommon, etc.).

## Markers

- `@pytest.mark.serial` — mutates shared Apache state (config swap,
  SHM restart). Runs outside the xdist pool.
- `@pytest.mark.slow` — multi-second wait (e.g. the 40-second
  watchdog tick). Excluded by default; opt in with `tests/run --slow`.
- `@pytest.mark.live_network` — requires reachable third-party
  captcha siteverify (Cloudflare, Google, hCaptcha, Friendly,
  GeeTest). Skips if unreachable rather than failing.
- `@pytest.mark.live_provider` — requires a real provider token
  passed via env var (e.g. `BS_RECAPTCHA_V3_TOKEN`). Skips without.
- `@pytest.mark.acceptance` — end-to-end user-journey test.
- `@pytest.mark.browser` — runs in a real headless Chromium via
  pytest-playwright. Catches regressions no request library can see
  (interstitial JS execution, cookie attribute enforcement,
  auto-submit form wiring).

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
tests/run                      # pytest suite, default markers
tests/run --parallel           # xdist parallel (non-serial tests); ~20% faster
tests/run --slow               # include @slow tests (periodic_save, 40s wait)
tests/run --match cookie       # substring filter; passed to pytest as -k
tests/run --verbose            # pytest -v instead of -q
tests/run --list               # show tests that would run, don't execute
tests/run --only stress        # opt-in; soak + load (long-running)
tests/run --only all           # pytest + stress
```

Exit code is `0` if every test passed (or was skipped), `1` if any
test failed.

You can also invoke pytest directly — useful for iterating on one
test with pytest's full traceback + `--pdb`:

```bash
tests/.venv/bin/pytest tests/pytests/test_cookie_hmac.py -v
tests/.venv/bin/pytest tests/pytests/ -k "captcha and not rejected"
tests/.venv/bin/pytest tests/pytests/ -m "not serial" -n auto
```

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

- **Absolute counter values.** Always work in deltas: `metrics.snapshot()`
  before, drive traffic, `metrics.snapshot()` after, then
  `metrics.delta(before, after)`. Counters may be any non-negative
  value at test start.
- **Empty flagged-IP table.** Prior runs may have flagged IPs that
  persist in the state file. Use `rate_slot_ip` (a fresh, un-flagged
  IP per call) or request the `clean_state` fixture to wipe the
  state file + restart.
- **Fresh Bloom filter.** Same reason. Use `fresh_ip` — the allocator
  picks from `100.64.0.0/10` (CGN), which no earlier run has touched.
- **Log position.** Use the `log_slice` fixture to extract only this
  test's lines from the botshield error log.

## Between-run state reset

Most tests use deltas and don't need a reset. For tests that DO need
a known-clean SHM + state file, request the `clean_state` fixture:

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
pytest.mark.serial` or per-test via `@pytest.mark.live_network`) are
documented in the "Markers" section above.
