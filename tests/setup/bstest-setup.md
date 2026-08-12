# Running the suite on RHEL / Rocky (isolated instance)

`tests/setup/provision.sh` is Debian-only (apt, apache2, a2enmod). On a
RHEL-family host — including one already running a production site —
use a second httpd instance instead. Nothing below touches the live
server's config, logs, state, or module binary.

## Why a second instance and not `BS_APACHE_SERVICE=httpd`

The framework calls `sudo systemctl restart $BS_APACHE_SERVICE` between
tests. Pointed at the live service that is dozens of production
restarts per run. Every path the suite touches is env-overridable, so a
separate systemd unit gives full isolation with no test-code changes.

## What must differ from the live server

| | live | test |
|---|---|---|
| ports | 80 / 443 | 127.0.0.1:8081 / 8443 |
| config | `sites.d/` | `/etc/httpd/bstest/` |
| logs | `/var/log/httpd/` | `/var/log/httpd/bstest/` |
| state file | `/var/lib/botshield/state.bin` | `/var/lib/botshield-test/` |
| decision log | `/var/log/httpd/botshield.log` | `/var/log/httpd/bstest/botshield.log` |
| runtime dir | `/run/httpd` | `/run/httpd-bstest` |
| module .so | `mod_botshield.so` | `mod_botshield-test.so` |

Three of those are easy to get wrong:

**Decision log.** It defaults to `logs/botshield.log`, ServerRoot-relative.
ServerRoot is `/etc/httpd` so the stock `conf.modules.d` can be reused,
and `/etc/httpd/logs` is a symlink to `/var/log/httpd` — so *defaulting*
it writes test decisions into the production decision log. Set it.

**Module binary.** `conf.modules.d/30-botshield.conf` LoadModules the
production `.so`. Include only `0*.conf` / `1*.conf` and add an explicit
`LoadModule ... mod_botshield-test.so`, or an experimental build cannot
be tested without shipping it live.

**State file.** `BotShieldStateFile` is server-scope only. Inside a
`<VirtualHost>` it is ignored, silently falling back to the default —
which is production's.

## Gotchas that cost time

- `Type=notify` needs `-DFOREGROUND`, or httpd daemonizes, the
  readiness notice arrives from a forked PID, and systemd kills it.
- Do **not** use `RuntimeDirectory=`; systemd deletes it on stop and the
  suite's rapid restarts race the recreate.
- Secret files must be mode `0600` — the module refuses group-readable
  ones. They are read as root at config-parse time, so the `apache` user
  never needs them.
- `/etc/httpd/bstest` and `/etc/botshield` must be **writable by the test
  user**: `config_override()` replaces files, which needs directory write.
- DocumentRoot cannot live under a `0700` home directory. Copy
  `tests/site` somewhere apache can traverse.
- Secret files need mode `0600`, but **`/etc/botshield/load.state.test`
  does not** — it is not a secret and the module reads it at RUNTIME as
  the `apache` user, not at config-parse time as root. A blanket
  `chmod 600 /etc/botshield/*` leaves `load_state` pinned at 0 and every
  load test timing out on a file the server cannot open. It needs `0644`.
- `test_app_feedback` and `test_app_claims` hardcode the expected value
  of `/etc/botshield/app-integration-secret`
  (`0123456789abcdef` repeated to 64 chars). A random secret there means
  no HMAC can ever verify and the failures look like the feedback
  feature being broken.
- `BS_ERROR_LOG` must match the vhost's `ErrorLog` exactly. The
  reference vhost writes `botshield-dev-error.log`; pointing the env at
  a different name makes every log assertion fail with `assert []`
  while the decision lines sit in the other file.

## Run

    . tests/bstest.env
    tests/.venv/bin/pytest tests/pytests -q \
        --deselect tests/pytests/test_mpm_matrix.py -k "not browser"

`test_mpm_matrix` and some robots tests shell out to `a2enmod`
(Debian-only). Browser tests need `playwright install`.
