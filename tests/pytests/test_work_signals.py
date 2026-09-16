"""Rule conditions on work signals, not on request duration.

busyworkersatleast=, fpmbusyatleast=, fpmqueueatleast= and
dbrunningatleast= exist because latencyatleast= measures the wrong
thing for shedding. Apache request duration includes the time spent
sending the response, so one slow client downloading a large file reads
as a slow server while costing almost nothing. Each signal here counts
something that is occupied only while work is being done: an Apache
worker slot, a PHP-FPM process, a database thread.

The PHP-FPM and database figures come from the external monitors'
stats files. These tests point the instance at a file they write
themselves, which makes the firing path deterministic -- unlike
latency, a test can set these numbers exactly. That also covers the
branch the latency tests cannot: a stale sample must decline, because
a monitor that stopped writing is neither a calm server nor a loaded
one.
"""

from __future__ import annotations

import subprocess
import time

import pytest

from botshield_test import apache, client


PROBE = "/work-signal-probe"
STATEDIR = "/var/lib/botshield-test"

# A fresh file name per write, and the config points at whichever one
# this test wrote.
#
# The reader skips a stats file whose mtime has not changed since the
# last tick, which is right in production and a trap in a test: where
# mtime has one-second granularity -- an overlay filesystem in CI, for
# instance -- two writes in the same second look identical, the second
# one is never read, and the test asserts against the numbers the
# previous test left behind. That is what broke
# test_fpm_busy_declines_below_it in CI while it passed here: 79 of 100
# busy read as the earlier test's 40 of 50, which is 80%.
_files = {"fpm": None, "db": None}
_seq = [0]


def _new_path(kind: str) -> str:
    _seq[0] += 1
    path = f"{STATEDIR}/{kind}-signal-{_seq[0]}.stats"
    _files[kind] = path
    return path


def _write(path: str, body: str) -> None:
    subprocess.run(["sudo", "tee", path], input=body.encode(),
                   stdout=subprocess.DEVNULL, check=True)
    subprocess.run(["sudo", "chmod", "0644", path], check=True)




def _stamp(age: int) -> int:
    """A sample timestamp no earlier test has used, so waiting on it
    proves the watchdog read *this* file."""
    return int(time.time()) - age - _seq[0]


def _fpm(active: int, max_children: int = 100, queue: int = 0,
         age: int = 0) -> list:
    pct = active * 100 // max_children
    path = _new_path("fpm")
    ts = _stamp(age)
    _write(path,
           f"ts={ts} active={active} "
           f"max_children={max_children} listen_queue={queue} pct={pct} "
           f"state=normal warm_pct=50 hot_pct=80\n")
    return [("fpm_sample_unix", ts), ("fpm_active_processes", active),
            ("fpm_max_children", max_children),
            ("fpm_listen_queue", queue)]


def _db(threads: int, age: int = 0) -> list:
    path = _new_path("db")
    ts = _stamp(age)
    _write(path,
           f"ts={ts} threads_run={threads} qps=1 "
           f"lock_pct=0.0 state=normal warm_threads=12 hot_threads=25\n")
    return [("db_sample_unix", ts), ("db_threads_running", threads)]


def _gauge(name: str) -> float | None:
    for line in client.get("/botshield/metrics").text.splitlines():
        if line.startswith(f"botshield_{name} "):
            return float(line.split()[1])
    return None


def _wait_for(*pairs, timeout: float = 20.0) -> None:
    """Wait until every gauge the rule will read holds the value this
    test wrote.

    Waiting on the sample timestamp alone was not enough. It is the
    last field the reader stores, so it proves the file was read -- but
    under load the tick can land between the request and the read, and
    a test that only checked the timestamp went on to assert against
    whatever the previous test had left. Checking each value the rule
    depends on removes the gap."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(_gauge(n) == v for n, v in pairs):
            return
        time.sleep(0.25)
    have = ", ".join(f"{n}={_gauge(n)} want {v}" for n, v in pairs)
    raise AssertionError(f"stats never reached the written sample: {have}")


def _rule(condition: str) -> str:
    return (
        "    <BotShieldRule work-shed>\n"
        f"        BotShieldPath      {PROBE}\n"
        f"        {condition}\n"
        "        BotShieldRespond   451\n"
        "    </BotShieldRule>"
    )


def _main_scope(condition: str) -> str:
    """One override at main scope: the stats files are server-scope
    settings, and a main-scope rule inherits into the vhost. Nesting a
    second override on the same file would put two reverts on one
    pristine copy."""
    fpm = _files["fpm"] or f"{STATEDIR}/fpm-signal-none.stats"
    db = _files["db"] or f"{STATEDIR}/db-signal-none.stats"
    return (f"BotShieldStateSaveInterval 30\n"
            f"BotShieldFpmStatsFile {fpm}\n"
            f"BotShieldDbStatsFile {db}\n" + _rule(condition))


def _fires(config_override, fresh_ip, condition: str, wait=None) -> bool:
    with config_override(r"BotShieldStateSaveInterval\s+\d+",
                         _main_scope(condition), count=1):
        if wait:
            _wait_for(*wait)
        return client.get(PROBE, xff=fresh_ip).status_code == 451


@pytest.fixture(scope="module", autouse=True)
def _tidy_stats_files():
    """One file per write means one file per test; sweep them at the
    end rather than leaving a few dozen in the instance's state
    directory for whoever looks next."""
    yield
    subprocess.run("sudo rm -f " + STATEDIR + "/*-signal-*.stats",
                   shell=True, check=False)


# --- Parsing ---------------------------------------------------------

@pytest.mark.parametrize("directive", [
    "BotShieldBusyWorkersAtLeast", "BotShieldFpmBusyAtLeast",
    "BotShieldFpmQueueAtLeast", "BotShieldDbRunningAtLeast",
])
@pytest.mark.parametrize("value", ["0", "-3", "many", "!5"])
def test_rejects_a_bad_threshold(config_override, directive, value):
    """0 is refused rather than read as "always": a shedding rule with
    a floor of nothing sheds everyone. '!' is refused because there is
    no "below" condition; the quiet case falls through instead."""
    with pytest.raises(subprocess.CalledProcessError):
        with config_override(r"BotShieldStateSaveInterval\s+\d+",
                             _main_scope(f"{directive} {value}"), count=1):
            pass


def test_fpm_busy_is_a_percentage(config_override):
    with pytest.raises(subprocess.CalledProcessError):
        with config_override(r"BotShieldStateSaveInterval\s+\d+",
                             _main_scope("BotShieldFpmBusyAtLeast 101"),
                             count=1):
            pass


def test_the_dump_shows_each_condition(config_override):
    conf = (
        "BotShieldEnabled On\n"
        "    <BotShieldRule work-dump>\n"
        f"        BotShieldPath                 {PROBE}\n"
        "        BotShieldBusyWorkersAtLeast   400\n"
        "        BotShieldFpmBusyAtLeast       80\n"
        "        BotShieldFpmQueueAtLeast      5\n"
        "        BotShieldDbRunningAtLeast     25\n"
        "        BotShieldRespond              503\n"
        "    </BotShieldRule>"
    )
    with config_override(r"BotShieldEnabled\s+On", conf, count=1):
        dump = apache.policy_dump()
    line = next(l for l in dump.splitlines() if l.startswith("work-dump"))
    for want in ("busyworkersatleast=400", "fpmbusyatleast=80%",
                 "fpmqueueatleast=5", "dbrunningatleast=25"):
        assert want in line, f"{want!r} missing from dump line: {line}"


# --- PHP-FPM -----------------------------------------------------------

def test_fpm_busy_fires_at_the_threshold(config_override, fresh_ip):
    sample = _fpm(active=80)
    assert _fires(config_override, fresh_ip, "BotShieldFpmBusyAtLeast 80",
                  wait=sample)


def test_fpm_busy_declines_below_it(config_override, fresh_ip):
    sample = _fpm(active=79)
    assert not _fires(config_override, fresh_ip,
                      "BotShieldFpmBusyAtLeast 80",
                  wait=sample)


def test_fpm_busy_is_relative_to_the_pool(config_override, fresh_ip):
    """The same 40 workers are 80% of a 50-worker pool and 40% of a
    100-worker one. A threshold is about saturation, not a count."""
    sample = _fpm(active=40, max_children=50)
    assert _fires(config_override, fresh_ip, "BotShieldFpmBusyAtLeast 80",
                  wait=sample)


def test_fpm_queue_fires(config_override, fresh_ip):
    sample = _fpm(active=100, queue=7)
    assert _fires(config_override, fresh_ip, "BotShieldFpmQueueAtLeast 5",
                  wait=sample)


def test_a_stale_fpm_sample_declines(config_override, fresh_ip):
    """A monitor that stopped writing ten minutes ago reported a full
    pool. That is not evidence of load now, and shedding on it would
    punish traffic for a broken service."""
    sample = _fpm(active=100, age=600)
    assert not _fires(config_override, fresh_ip,
                      "BotShieldFpmBusyAtLeast 50",
                  wait=sample)


# --- Database ----------------------------------------------------------

def test_db_running_fires(config_override, fresh_ip):
    sample = _db(threads=30)
    assert _fires(config_override, fresh_ip,
                  "BotShieldDbRunningAtLeast 25",
                  wait=sample)


def test_db_running_declines_below_it(config_override, fresh_ip):
    sample = _db(threads=24)
    assert not _fires(config_override, fresh_ip,
                      "BotShieldDbRunningAtLeast 25",
                  wait=sample)


def test_a_stale_db_sample_declines(config_override, fresh_ip):
    sample = _db(threads=90, age=600)
    assert not _fires(config_override, fresh_ip,
                      "BotShieldDbRunningAtLeast 25",
                  wait=sample)


# --- Apache busy workers -----------------------------------------------

def test_busy_workers_gauge_is_published():
    """-1 only before the first watchdog tick; this instance has been
    up for longer than that."""
    busy = _gauge("apache_busy_workers")
    assert busy is not None and busy >= 0, busy


def test_busy_workers_declines_far_above_the_pool(config_override,
                                                  fresh_ip):
    """Bracketed from above only. The count a request sees includes
    whatever else the test host is doing at that tick, so "fires at N"
    for any N a test can arrange would pass or fail on timing."""
    assert not _fires(config_override, fresh_ip,
                      "BotShieldBusyWorkersAtLeast 1000000")


# --- Shed accounting -----------------------------------------------------

def _counter(name: str) -> int:
    v = _gauge(name)
    assert v is not None, f"botshield_{name} absent from metrics"
    return int(v)


def _shed_delta(config_override, fresh_ip, body: str, sample) -> tuple:
    """Run one request against a rule and report how the two shed
    totals moved. Returns (status, shed_delta, observed_delta)."""
    fpm = _files["fpm"] or f"{STATEDIR}/fpm-signal-none.stats"
    db = _files["db"] or f"{STATEDIR}/db-signal-none.stats"
    conf = (f"BotShieldStateSaveInterval 30\n"
            f"BotShieldFpmStatsFile {fpm}\n"
            f"BotShieldDbStatsFile {db}\n" + body)
    with config_override(r"BotShieldStateSaveInterval\s+\d+", conf,
                         count=1):
        _wait_for(*sample)
        shed0 = _counter("shed_total")
        obs0 = _counter("shed_observed_total")
        status = client.get(PROBE, xff=fresh_ip).status_code
        return (status, _counter("shed_total") - shed0,
                _counter("shed_observed_total") - obs0)


def _block(*lines: str) -> str:
    inner = "".join(f"        {l}\n" for l in lines)
    return ("    <BotShieldRule shed-probe>\n"
            f"        BotShieldPath  {PROBE}\n"
            f"{inner}    </BotShieldRule>")


def test_a_load_conditioned_refusal_counts_as_shed(config_override,
                                                   fresh_ip):
    sample = _fpm(active=90)
    status, shed, obs = _shed_delta(config_override, fresh_ip, _block(
        "BotShieldFpmBusyAtLeast 80", "BotShieldRespond 503"), sample)
    assert (status, shed, obs) == (503, 1, 0)


def test_observe_counts_as_would_shed_only(config_override, fresh_ip):
    sample = _fpm(active=90)
    status, shed, obs = _shed_delta(config_override, fresh_ip, _block(
        "BotShieldFpmBusyAtLeast 80", "BotShieldRespond 503",
        "BotShieldMode observe"), sample)
    assert status != 503
    assert (shed, obs) == (0, 1)


def test_a_rule_without_a_load_condition_is_not_shedding(config_override,
                                                         fresh_ip):
    """A facet trap answering 403 is a refusal, not shedding. Counting
    it would make the number say the server was loaded when it was not."""
    sample = _fpm(active=90)
    status, shed, obs = _shed_delta(config_override, fresh_ip, _block(
        "BotShieldRespond 451"), sample)
    assert (status, shed, obs) == (451, 0, 0)


def test_a_load_rule_that_lets_the_request_through_is_not_shedding(
        config_override, fresh_ip):
    """The monitor exemption has this shape: a condition, then
    nochallenge. Nothing was turned away."""
    sample = _fpm(active=90)
    status, shed, obs = _shed_delta(config_override, fresh_ip, _block(
        "BotShieldFpmBusyAtLeast 80", "BotShieldNoChallenge"), sample)
    assert (shed, obs) == (0, 0)


def test_the_dashboard_shows_the_shed_counts():
    page = client.get("/botshield/dashboard").text
    assert "Requests shed" in page and "Would shed" in page
