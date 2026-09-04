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

One timer, one entry point, three datasets, each of which the module
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

**Siteimprove is currently failing this check**, as of September 2026.
It is the one source with no published feed, so its addresses are
scraped from a help article, and that article has been restructured:
the section the parser anchors on now yields 13 addresses against a
floor of 30. The floor is doing its job. The last good file, 44
entries, stays in place, and the other sources are unaffected.
Repairing it means working out the new page structure by hand, and
guessing wrong is worse than being stale in either direction: too few
addresses and a legitimate crawler starts getting challenged, too many
and analytics or email infrastructure ends up in a crawler allow list.

### Two sources, in an order that depends on where it runs

Each dataset can come from this project's committed copy or from the
upstream that copy was built from, and which is tried first depends on
whether a repository checkout is present.

**On a host**, the project's copy is preferred. It has already survived
these same checks and a person looked at it before committing it, which
is a stronger claim than whatever an upstream happens to be serving
this minute, and it is one request to one host rather than several to
several. If that copy has gone stale, past 45 days by default, the
refresher falls back to the upstreams directly. A host therefore stays
current even if this project goes quiet, and is never strictly
dependent on anyone continuing to maintain it.

**In a checkout**, the order reverses. Refreshing there means fetching
upstream, validating, and committing the result, which is the act of
curating the data every host then prefers. Pulling this project's own
committed copy back down would be circular. The same run writes the
`data/` JSON for review and the runtime files.

Either order can be forced:

```sh
botshield-refresh.py --prefer-project     # as a host would
botshield-refresh.py --upstream           # as a maintainer would
```

Set `BOTSHIELD_MAX_DATA_AGE_DAYS` to change how long curated data is
trusted, and `BOTSHIELD_PROJECT_REPO` to point at a fork.

Each run says which source it used per dataset, so a surprising result
is traceable to the source rather than guessed at.

### Nothing good is ever replaced by nothing

The rule throughout: **a dataset that cannot be refreshed keeps the file
it already has.** Data is validated before it replaces anything, and
written through a temporary file and a rename, so an interrupted or
rejected refresh cannot leave a truncated file behind.

Stale data that passed these checks once is better than data that just
failed them, and far better than an empty allow list, which would not
fail loudly. It would quietly stop recognising every crawler it used to
allow. So a failed refresh is reported and nothing else happens.

This is verified rather than asserted: with every network path broken,
a full run exits non-zero, names each dataset it could not refresh, and
leaves all six existing files byte-for-byte identical.

## Where to next

- Load shedding and what the tiers do with a hot backend:
  [site model](site-model.md).
- The directives these files feed:
  [directive reference](directives.md).
- Reading the resulting decisions: [observability](observability.md).
