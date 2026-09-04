# Background jobs

Three units ship with the module and none of them is installed by
`make install`. They run outside httpd on purpose, and httpd does not
depend on any of them.

| Unit | What it does |
|---|---|
| `botshield-dbmon.service` | Samples MariaDB saturation |
| `botshield-fpmmon.service` | Samples PHP-FPM saturation |
| `botshield-refresh.timer` | Refreshes three external data sets |

Install all four unit files and their scripts:

```sh
make install-monitors
```

That creates an unprivileged `botshield-mon` account, copies the
scripts to `/usr/local/share/botshield`, installs the units, and
reloads systemd. It deliberately enables nothing: each monitor needs a
prerequisite set up first, described below.

## Why the monitors are separate processes

The module never opens a database or FastCGI connection. Blocking
network calls have no place in the watchdog, and a backend too sick to
answer must not be able to stall the code whose job is to shed load
*because* that backend is sick. So the monitors sample, write files,
and the module reads those files on its next tick. Nothing the monitors
do can block a request.

That separation is also why they are not dependencies of httpd. If a
monitor dies, the module keeps serving on its remaining load signals.
Monitoring must not be able to take the web server down with it.

Each monitor writes two files, because they have different readers:

- **`<name>.state`** holds one word, `normal`, `warm`, or `hot`, for
  `BotShieldLoadStateFile`. Written only when the state changes, since
  the module gates its read on mtime.
- **`<name>.stats`** holds key-value telemetry for the dashboard graph,
  written every pass. A gap in a time series is indistinguishable from
  a gap in the data, so this one is unconditional.

You give the monitor the `.state` path and it derives the other.

### The stop reset matters

Both units carry an `ExecStopPost` that writes `normal` back to the
state file, and it runs on crash as well as on clean stop. The module
caches the last value it read and has no staleness timeout, so without
that reset, a monitor that dies while the backend is hot would leave
`hot` latched. The module would then shed traffic indefinitely against
a backend that had already recovered.

This is also why both units set `RuntimeDirectoryPreserve=yes`. Without
it, systemd removes the runtime directory on stop, deletes the reset
that `ExecStopPost` just wrote, and leaves the module with a missing
file, which it treats as "keep the value I cached". That is exactly the
latched-hot case the reset exists to prevent.

## Database monitor

The account needs `USAGE`, which covers `SHOW GLOBAL STATUS`, plus
`SELECT` on `performance_schema` for the per-table breakdown. It is
refused site data outright:

```sql
CREATE USER 'botshield-mon'@'localhost' IDENTIFIED VIA unix_socket;
GRANT USAGE ON *.* TO 'botshield-mon'@'localhost';
GRANT SELECT ON performance_schema.* TO 'botshield-mon'@'localhost';
```

Authentication is `unix_socket`: the kernel vouches for the process
uid, so there is no password stored anywhere and nothing to rotate or
leak. The system account existing is the credential. On a host without
socket authentication available, the script accepts a
`--defaults-file` instead.

```sh
sudo systemctl enable --now botshield-dbmon.service
```

## PHP-FPM monitor

This one speaks FastCGI directly to the pool socket rather than
fetching a status URL through Apache. A proxied scrape queues behind
the same worker shortage it is trying to measure, so it fails precisely
when the number matters most. Talking to the pool directly also means
the status path never has to be routable from the web.

Enable the status path in the pool config:

```ini
pm.status_path = /status
```

The shipped unit assumes a pool on `127.0.0.1:9000`. For a pool on a
unix socket, change `--address` and narrow
`RestrictAddressFamilies` to `AF_UNIX`.

PHP-FPM is worth its own signal because `pm.max_children` is a real
hard ceiling, unlike `MaxRequestWorkers`, which is routinely set to a
number the machine cannot actually serve. When every child is busy,
requests sit in the pool's listen queue and the site stalls while
Apache still reports idle workers.

```sh
sudo systemctl enable --now botshield-fpmmon.service
```

One caveat worth knowing: the unit sets `IPAddressAllow=localhost` as
defence in depth, and on kernels without BPF cgroup firewalling systemd
logs that it is proceeding without it. The setting degrades to nothing
rather than failing, so treat it as a bonus and not as the reason the
scrape is confined.

## Verifying a monitor

Read the files rather than trusting the unit is green:

```sh
cat /run/botshield/db-load.state          # normal | warm | hot
cat /run/botshield/db-load.stats          # key=value telemetry
```

Then point the module at them and confirm it agrees:

```apache
BotShieldLoadStateFile /run/botshield/db-load.state
BotShieldDbStatsFile   /run/botshield/db-load.stats
BotShieldFpmStatsFile  /run/botshield/fpm-load.stats
```

All three are server scope. Inside a `<VirtualHost>` they are a
config-parse error rather than a silent discard, but the rule is easier
to follow than to debug. The load state drives
`BotShieldLoadTrigger`, covered in [Policy](policy.md#load-triggers).

## Data refresh

One timer refreshes three external data sets, each of which the module
re-reads when the file's mtime changes. That is the point of running
them: a refresh lands without a rebuild and without an Apache reload.
The copies compiled into the module are baselines, not the only source.

| Data | Written to | Read when you set |
|---|---|---|
| Verified-crawler IP ranges | `/var/lib/botshield/bots/*.txt` | `BotShieldAllowBot` |
| Bot directory | `/var/lib/botshield/bot-directory.tsv` | `BotShieldBotDirectory` |
| Browser UA templates | `/var/lib/botshield/browser-templates.txt` | `BotShieldBrowserTemplates` |

The last two are written whether or not their directive is set. Without
the directive the module keeps using its compiled-in baseline and the
file is simply ignored, so setting them is what turns the refresh into
something that has an effect:

```apache
BotShieldBotDirectory     /var/lib/botshield/bot-directory.tsv
BotShieldBrowserTemplates /var/lib/botshield/browser-templates.txt
```

Each has a companion `...RefreshInterval` directive controlling how
often the watchdog re-checks mtime. Both default to 300 seconds.

```sh
sudo systemctl enable --now botshield-refresh.timer
systemctl list-timers botshield-refresh.timer
```

Daily, with an hour of randomised delay so every host running this does
not hit the same upstreams at the same instant, and persistent so a day
is not skipped silently after downtime.

### Failure is designed to be boring

Each of the three scripts validates what it fetched before replacing
anything, and leaves the previous data untouched if the check fails.
The bot directory refuses an upstream that returns implausibly few
entries or has lost one of a small set of sentinel bots, on the theory
that a truncated or restructured feed should be reviewed by a person
rather than adopted silently.

The three steps are independent in the unit, so one upstream being down
does not stop the other two. A partial refresh is a normal outcome
worth seeing in the journal rather than a unit failure: stale published
data beats none, and every source that answered has already been
written.

### The same scripts serve two purposes

`refresh-bot-directory.py` and `refresh-top-user-agents.py` behave
differently depending on whether a repository checkout is beside them.

In a checkout they treat `data/` as the source of truth: the fetched
JSON is validated and written there, to be reviewed, committed, and
compiled into the module at build time. On a host with no checkout they
run in runtime-only mode, skipping the JSON entirely and writing just
the files the module reads. Each says which mode it chose on the first
line of its output, so a surprising result is traceable to the mode
rather than to the fetch.

That is why `make install-monitors` copies them out of `tools/` rather
than `services/`: they are genuinely both, and the mode is decided by
where they find themselves.

## Where to next

- Load shedding and what the tiers do with a hot backend:
  [site model](site-model.md).
- The directives these files feed:
  [directive reference](directives.md).
- Reading the resulting decisions: [observability](observability.md).
