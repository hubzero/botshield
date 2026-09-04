# services/

Units installed onto a production host alongside the module, one
directory each, holding the unit and whatever it launches.

| Directory | Unit | Purpose |
|---|---|---|
| `dbmon/` | `botshield-dbmon.service` | Samples MariaDB saturation |
| `fpmmon/` | `botshield-fpmmon.service` | Samples PHP-FPM saturation |
| `refresh/` | `botshield-refresh.timer` | Refreshes crawler IP ranges, the bot directory, and browser UA templates |

The refresher is one entry point over a small package, `botshield-refresh.py`.
Run it with no arguments for all three datasets, or name one:
`ranges`, `directory`, `user-agents`.

Install with `make install-monitors`, which copies the scripts to
`/usr/local/share/botshield`, installs the units, and enables nothing.
Each one needs a prerequisite first. Setup, verification, and the
reasoning behind the design are in
[`docs/monitoring.md`](../docs/monitoring.md).

**What belongs here.** Anything installed on a host that runs the
module, but that is not the module. Not build tooling: the generators
that produce compiled-in source live in `tools/`, and mixing the two is
what this directory was split out of. The distinction is the audience.
Everything here ships to an operator; everything in `tools/` is used by
someone working on the module.

None of these is a dependency of httpd, and that is deliberate. Each is
built to fail without taking the web server down with it.
