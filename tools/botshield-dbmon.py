#!/usr/bin/python3
"""Sample MariaDB saturation and publish it for mod_botshield.

Runs outside httpd on purpose. mod_botshield never links a DB client:
blocking network I/O has no place in the watchdog, and a database too
sick to answer must not be able to stall the code whose job is to shed
load *because* the database is sick. This writes files; the module
picks them up on its next tick and is never blocked by us.

Two output files, because they have different readers and different
rules:

  <state>        one bare token (normal|warm|hot) for
                 BotShieldLoadStateFile, whose parser rejects anything
                 else. Written only on change -- the module gates its
                 read on mtime.
  <state>.stats  key=value telemetry for the dashboard graph. Written
                 every pass: it is a time series, and a gap in it is
                 indistinguishable from a gap in the data.

Auth is unix_socket: the kernel vouches for the process uid, so there
is no password stored anywhere and nothing to rotate or leak. The DB
user needs only USAGE (which covers SHOW GLOBAL STATUS) plus SELECT on
performance_schema for --report's per-table breakdown; it is refused
site data outright. A --defaults-file path remains for hosts without
unix_socket auth available.
"""

import argparse
import os
import sys
import time
import tempfile

try:
    import MySQLdb
except ImportError:
    sys.stderr.write("python3-mysql (MySQLdb) is required\n")
    sys.exit(2)

# Counters pulled in a single round trip so the deltas share one point
# in time; separate queries would let them drift apart.
COUNTERS = (
    "Queries", "Threads_running", "Threads_connected",
    "Table_locks_waited", "Table_locks_immediate",
    "Innodb_row_lock_waits", "Slow_queries", "Aborted_clients",
)

# Threads_running is the fast signal: it moves on CPU saturation and on
# lock pileups before throughput does, because a stalled query still
# counts as running while contributing no QPS. QPS alone cannot tell a
# busy server from a jammed one -- both can read low.
DEFAULTS = {
    "warm_threads": 12, "hot_threads": 25,
    # Contention as a share of lock acquisitions in the window. Above
    # ~1% is generally treated as noticeable contention.
    "warm_lockpct": 1.0, "hot_lockpct": 5.0,
}


class Sampler(object):
    def __init__(self, defaults_file=None, db_user=None,
                 socket="/var/lib/mysql/mysql.sock"):
        self.defaults_file = defaults_file
        self.db_user = db_user
        self.socket = socket
        self.conn = None
        self.prev = None

    def _connect(self):
        # connect_timeout so a wedged server surfaces as a scrape
        # failure on a bounded schedule instead of parking the loop.
        if self.db_user:
            # unix_socket auth: the kernel vouches for our uid, so there
            # is no password to store, rotate, or leak. Preferred over a
            # defaults file precisely because there is no secret at all.
            self.conn = MySQLdb.connect(user=self.db_user,
                                        unix_socket=self.socket,
                                        connect_timeout=5)
        else:
            self.conn = MySQLdb.connect(read_default_file=self.defaults_file,
                                        connect_timeout=5)

    def raw(self):
        """Current counter values, reconnecting once if the link died."""
        for attempt in (1, 2):
            try:
                if self.conn is None:
                    self._connect()
                cur = self.conn.cursor()
                cur.execute(
                    "SHOW GLOBAL STATUS WHERE Variable_name IN (%s)"
                    % ",".join(["%s"] * len(COUNTERS)), COUNTERS)
                rows = cur.fetchall()
                cur.close()
                out = {}
                for k, v in rows:
                    if isinstance(k, bytes):
                        k = k.decode()
                    if isinstance(v, bytes):
                        v = v.decode()
                    try:
                        out[k] = int(v)
                    except ValueError:
                        out[k] = 0
                return out
            except Exception:
                # A dropped connection is normal across a DB restart;
                # retry once on a fresh link before calling it a
                # failure, so a restart doesn't register as an outage.
                self.conn = None
                if attempt == 2:
                    return None
        return None

    def prime(self):
        """Take the baseline the first delta subtracts from.

        Separate from raw() because raw() is deliberately stateless --
        callers that only want a reading shouldn't disturb the series.
        """
        self.prev = self.raw()
        return self.prev is not None

    def sample(self, elapsed):
        """Deltas against the previous call, or None if unavailable.

        Rates come from deltas, never from since-boot totals: a total is
        an average over the whole uptime and goes numb to a spike
        happening right now. This host reads 0.09% lock contention since
        boot regardless of what the last minute looked like.
        """
        cur = self.raw()
        if cur is None:
            self.prev = None      # don't delta across a gap
            return None
        prev, self.prev = self.prev, cur
        if prev is None or elapsed <= 0:
            return None           # first pass has nothing to subtract

        def d(key):
            return max(0, cur.get(key, 0) - prev.get(key, 0))

        waited, immediate = d("Table_locks_waited"), d("Table_locks_immediate")
        total = waited + immediate
        return {
            "qps": int(d("Queries") / elapsed),
            "threads_run": cur.get("Threads_running", 0),
            "threads_conn": cur.get("Threads_connected", 0),
            "lock_waits": waited,
            "lock_pct": round(100.0 * waited / total, 3) if total else 0.0,
            "slow": d("Slow_queries"),
            "aborted": d("Aborted_clients"),
        }


def classify(s, cfg):
    """Worst-of across dimensions, not an average.

    A lock pileup and a thread pileup are each independently sufficient
    reason to shed; averaging them would let a healthy-looking dimension
    mask a saturated one.
    """
    state = "normal"
    if s["threads_run"] >= cfg["warm_threads"] or s["lock_pct"] >= cfg["warm_lockpct"]:
        state = "warm"
    if s["threads_run"] >= cfg["hot_threads"] or s["lock_pct"] >= cfg["hot_lockpct"]:
        state = "hot"
    return state


def write_atomic(path, text):
    """Rename into place so no reader ever sees a torn file."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".dbmon-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text + "\n")
        os.chmod(tmp, 0o644)      # httpd children read these as apache
        os.rename(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def run_loop(args, cfg):
    sampler = Sampler(args.defaults_file, args.db_user, args.socket)
    stats_path = (args.state_file[:-6] if args.state_file.endswith(".state")
                  else args.state_file) + ".stats"
    last_state = None
    fails = 0
    last_t = time.monotonic()   # monotonic: immune to clock steps
    sampler.prime()             # so the first delta spans a real window

    while True:
        time.sleep(args.interval)
        now = time.monotonic()
        s = sampler.sample(now - last_t)
        last_t = now
        if s is None:
            # A scrape failure is not evidence of load, so we don't
            # invent one. But staying silent forever is its own bug: the
            # module caches the last value it read, so an outage that
            # begins while we are saying "hot" would shed traffic
            # indefinitely against a database nobody can even see.
            #
            # So: ride out short outages (a DB restart is routine and
            # reconnects within a tick or two), then withdraw the claim.
            # We exit rather than write "normal" inline so there is one
            # recovery path instead of two -- systemd restarts us with a
            # clean connection and a fresh baseline, and ExecStopPost
            # performs the reset. Exiting on the *first* failure would
            # be wrong: routine DB restarts would burn through
            # StartLimitBurst and systemd would stop restarting us
            # altogether, which is how a monitor ends up dead.
            fails += 1
            if fails >= args.fail_grace:
                sys.stderr.write(
                    "mariadb unreachable for %d consecutive samples; "
                    "withdrawing load claim and exiting for restart\n"
                    % fails)
                return 0
            continue
        fails = 0

        state = classify(s, cfg)
        # The exists() check covers first pass and someone deleting the
        # file underneath us; without it a steady "normal" would never
        # recreate it and the module would hold its last cached value.
        if state != last_state or not os.path.exists(args.state_file):
            write_atomic(args.state_file, state)
            if state != last_state:
                sys.stdout.write(
                    "load state -> %s (threads=%d lock=%.3f%% qps=%d)\n"
                    % (state, s["threads_run"], s["lock_pct"], s["qps"]))
                sys.stdout.flush()
            last_state = state

        # Thresholds go in the file alongside the readings. The
        # dashboard draws its warm/hot bands from these, so the graph
        # cannot disagree with the state we published; a second copy of
        # the numbers in httpd.conf could drift and nothing would catch
        # it.
        write_atomic(stats_path, "ts=%d %s state=%s warm_threads=%d "
                     "hot_threads=%d" % (
                         time.time(),
                         " ".join("%s=%s" % kv for kv in sorted(s.items())),
                         state, cfg["warm_threads"], cfg["hot_threads"]))


def run_report(args, cfg):
    sampler = Sampler(args.defaults_file, args.db_user, args.socket)
    if not sampler.prime():
        sys.stderr.write("cannot reach mariadb\n")
        return 1
    time.sleep(args.report)
    s = sampler.sample(args.report)
    if s is None:
        # prime() succeeded, so this is the second read failing, not a
        # missing baseline -- the two used to share one message.
        sys.stderr.write("mariadb went away mid-sample\n")
        return 1

    print("window       %ds" % args.report)
    print("qps          %d" % s["qps"])
    print("threads_run  %d   (warm>=%d hot>=%d)"
          % (s["threads_run"], cfg["warm_threads"], cfg["hot_threads"]))
    print("threads_conn %d" % s["threads_conn"])
    print("lock_waits   %d" % s["lock_waits"])
    print("lock_pct     %.3f%%  (warm>=%.1f%% hot>=%.1f%%)"
          % (s["lock_pct"], cfg["warm_lockpct"], cfg["hot_lockpct"]))
    print("slow_queries %d" % s["slow"])
    print("state        %s" % classify(s, cfg))

    # Cumulative since server start, unlike everything above. Kept that
    # way deliberately: it answers "which table is structurally the
    # problem", a question about the whole uptime rather than about this
    # window. Labelled so the two aren't read as one series.
    print("\ntop tables by lock wait (cumulative since server start):")
    try:
        cur = sampler.conn.cursor()
        cur.execute("SELECT OBJECT_SCHEMA, OBJECT_NAME, COUNT_STAR,"
                    " ROUND(SUM_TIMER_WAIT/1e9,1)"
                    " FROM performance_schema.table_lock_waits_summary_by_table"
                    " WHERE COUNT_STAR > 0 ORDER BY SUM_TIMER_WAIT DESC LIMIT 5")
        for db, tbl, ops, ms in cur.fetchall():
            print("  %-10s %-38s %10s ops %9s ms" % (db, tbl, ops, ms))
        cur.close()
    except Exception as e:
        print("  (unavailable: %s)" % e)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-file", help="path to publish load state to")
    p.add_argument("--interval", type=int, default=10, help="seconds between samples")
    p.add_argument("--report", type=int, nargs="?", const=10, metavar="SECS",
                   help="one-shot baseline to stdout instead of the publish loop")
    p.add_argument("--db-user", help="connect as this user over the unix "
                   "socket (no password; requires unix_socket auth)")
    p.add_argument("--socket", default="/var/lib/mysql/mysql.sock")
    p.add_argument("--defaults-file", default="/root/.my.cnf",
                   help="credentials file, used only when --db-user is absent")
    p.add_argument("--fail-grace", type=int, default=6, metavar="N",
                   help="consecutive failed samples tolerated before "
                        "withdrawing the load claim and exiting (default 6)")
    for k, v in sorted(DEFAULTS.items()):
        p.add_argument("--" + k.replace("_", "-"), type=type(v), default=v)
    args = p.parse_args()
    cfg = dict((k, getattr(args, k)) for k in DEFAULTS)

    if args.report:
        return run_report(args, cfg)
    if not args.state_file:
        p.error("--state-file is required unless --report is given")
    try:
        run_loop(args, cfg)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
