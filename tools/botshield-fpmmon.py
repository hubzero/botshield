#!/usr/bin/python3
"""Sample PHP-FPM saturation and publish it for mod_botshield.

A sibling of botshield-dbmon.py, same contract and same reasoning: the
module never speaks to PHP-FPM, it reads files. Blocking I/O has no
place in the watchdog, and a pool too saturated to answer must not be
able to stall the code whose job is to shed load because the pool is
saturated.

Scrapes pm.status_path by speaking FastCGI **directly to the pool
socket**, not by fetching a status URL through Apache. An
Apache-proxied scrape queues behind the same worker shortage it is
trying to measure, so it fails precisely when the number matters most.
Talking to the pool directly also means the status path never has to be
routable from the web.

Why PHP-FPM is worth its own signal here: pm.max_children is a genuine
hard ceiling, unlike MaxRequestWorkers which is routinely set to a
number the machine cannot actually serve. When every child is busy,
further requests sit in the pool's listen queue and the site stalls
while Apache still reports idle workers.

Two output files, as with the database monitor:

  <state>        one bare token (normal|warm|hot) for
                 BotShieldLoadStateFile, written only on change.
  <state>.stats  key=value telemetry for the dashboard graph, written
                 every pass because a gap in a time series is
                 indistinguishable from a gap in the data.
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
import tempfile
import time

# Status fields we act on. "listen queue" and "max children reached" are
# the ones a process count cannot give you: they separate a pool that is
# busy from a pool that has run out, which is the distinction that
# decides whether shedding helps.
FCGI_RESPONDER = 1
FCGI_BEGIN, FCGI_END, FCGI_PARAMS, FCGI_STDIN, FCGI_STDOUT = 1, 3, 4, 5, 6

DEFAULTS = {
    # Percent of pm.max_children that counts as warm / hot. Below the
    # ceiling on purpose: once children are exhausted the queue is
    # already forming and shedding is late.
    "warm_pct": 50,
    "hot_pct": 80,
    # Listen-queue depth that on its own means hot. A queue of 1 is
    # scheduling jitter, not backlog: observed on 2026-08-31 declaring
    # hot at active=1/100, i.e. with 99 children idle. That single
    # sample gated the shed ladder's hot rungs, which fired 193 times
    # against a server whose latency never left 26-39ms.
    "hot_queue": 5,
}


def _fcgi_len(n):
    return struct.pack("!I", n | 0x80000000) if n > 127 else bytes([n])


def _fcgi_pair(k, v):
    k, v = k.encode(), v.encode()
    return _fcgi_len(len(k)) + _fcgi_len(len(v)) + k + v


def _fcgi_record(rtype, req_id, data=b""):
    pad = (8 - len(data) % 8) % 8
    return (struct.pack("!BBHHBB", 1, rtype, req_id, len(data), pad, 0)
            + data + b"\0" * pad)


def fcgi_get(addr, status_path, timeout=5):
    """One FastCGI GET of the status path, returning the parsed JSON.

    Raises on any failure; the caller decides what a failure means.
    """
    if addr.startswith("/"):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(addr)
    else:
        host, _, port = addr.rpartition(":")
        s = socket.create_connection((host, int(port)), timeout)
        s.settimeout(timeout)
    try:
        params = {
            "SCRIPT_NAME": status_path,
            "SCRIPT_FILENAME": status_path,
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": "json",
            "REQUEST_URI": status_path + "?json",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "GATEWAY_INTERFACE": "CGI/1.1",
            "SERVER_SOFTWARE": "botshield-fpmmon",
        }
        s.sendall(_fcgi_record(FCGI_BEGIN, 1,
                               struct.pack("!HB5x", FCGI_RESPONDER, 0)))
        s.sendall(_fcgi_record(FCGI_PARAMS, 1,
                               b"".join(_fcgi_pair(k, v)
                                        for k, v in params.items())))
        s.sendall(_fcgi_record(FCGI_PARAMS, 1))
        s.sendall(_fcgi_record(FCGI_STDIN, 1))

        out = b""
        while True:
            head = s.recv(8)
            if len(head) < 8:
                break
            _, rtype, _, clen, plen, _ = struct.unpack("!BBHHBB", head)
            body = b""
            while len(body) < clen + plen:
                chunk = s.recv(clen + plen - len(body))
                if not chunk:
                    break
                body += chunk
            if rtype == FCGI_STDOUT:
                out += body[:clen]
            elif rtype == FCGI_END:
                break
    finally:
        s.close()

    # CGI response: headers, blank line, then the JSON body.
    _, _, payload = out.partition(b"\r\n\r\n")
    if not payload:
        _, _, payload = out.partition(b"\n\n")
    return json.loads(payload.decode("utf8", "replace"))


def read_max_children(pool_conf):
    """pm.max_children out of the pool config.

    Read rather than configured separately so the ceiling the dashboard
    normalises against is always the ceiling PHP-FPM is enforcing. A
    second copy in a systemd unit would drift the first time someone
    retunes the pool, and the graph would quietly misreport.
    """
    with open(pool_conf) as f:
        for line in f:
            line = line.strip()
            if line.startswith(";"):
                continue
            m = re.match(r"pm\.max_children\s*=\s*(\d+)", line)
            if m:
                return int(m.group(1))
    return 0


_RANK = {"normal": 0, "warm": 1, "hot": 2}


def _worst(a, b):
    """Worst-of, so no signal can quietly downgrade another."""
    return a if _RANK[a] >= _RANK[b] else b


def classify(s, cfg):
    """Worst-of across saturation and queueing.

    Percent-of-children is the smooth signal; the queue is the discrete
    one. They are not redundant: a pool can sit at 100% of children with
    an empty queue and be keeping up exactly, and it can show a modest
    active count with a queue if requests are arriving in bursts.

    A queue does mean someone waited, but depth matters. This used to
    call hot on any queue at all, and in production that meant
    `active=1/100 queue=1` -- one busy child, ninety-nine idle --
    publishing the same state as a genuinely exhausted pool. Depth 1 is
    a request that arrived between accepts, not a backlog. So a shallow
    queue is warm, and hot needs either real depth or a queue forming
    while the pool is already near its ceiling.
    """
    state = "normal"
    if s["pct"] >= cfg["warm_pct"]:
        state = _worst(state, "warm")
    if s["pct"] >= cfg["hot_pct"]:
        state = _worst(state, "hot")
    if s["listen_queue"] > 0:
        state = _worst(state, "warm")
    if (s["listen_queue"] >= cfg["hot_queue"]
            or (s["listen_queue"] > 0 and s["pct"] >= cfg["hot_pct"])):
        state = _worst(state, "hot")
    if s["max_children_reached_delta"] > 0:
        # Unchanged: the pool actually ran out of children. That is the
        # one signal here that is never jitter.
        state = _worst(state, "hot")
    return state


def write_atomic(path, text):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".fpmmon-")
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


def sample(args, prev_reached):
    raw = fcgi_get(args.address, args.status_path)
    active = int(raw.get("active processes", 0))
    maxc = args.max_children or 0
    reached = int(raw.get("max children reached", 0))
    return {
        "active": active,
        "idle": int(raw.get("idle processes", 0)),
        "total": int(raw.get("total processes", 0)),
        "max_active": int(raw.get("max active processes", 0)),
        "listen_queue": int(raw.get("listen queue", 0)),
        "max_listen_queue": int(raw.get("max listen queue", 0)),
        "slow_requests": int(raw.get("slow requests", 0)),
        "max_children_reached": reached,
        # Delta, not the total: the cumulative count says the ceiling was
        # hit at some point since start, which is true forever after the
        # first time and therefore useless as a live signal.
        "max_children_reached_delta": (
            max(0, reached - prev_reached) if prev_reached is not None else 0),
        "max_children": maxc,
        "pct": (active * 100 // maxc) if maxc else 0,
    }


def run_report(args, cfg):
    try:
        s = sample(args, None)
    except Exception as e:
        sys.stderr.write("cannot reach php-fpm status: %s\n" % e)
        return 1
    print("pool             %s" % args.address)
    print("active/max       %d/%d  (%d%%)" % (s["active"], s["max_children"],
                                              s["pct"]))
    print("idle / total     %d / %d" % (s["idle"], s["total"]))
    print("max active seen  %d" % s["max_active"])
    print("listen queue     %d  (peak %d)" % (s["listen_queue"],
                                              s["max_listen_queue"]))
    print("children ceiling hit %d times since pool start"
          % s["max_children_reached"])
    print("slow requests    %d" % s["slow_requests"])
    print("state            %s  (warm>=%d%% hot>=%d%%, queue>=%d = hot)"
          % (classify(s, cfg), cfg["warm_pct"], cfg["hot_pct"],
             cfg["hot_queue"]))
    return 0


def run_loop(args, cfg):
    stats_path = (args.state_file[:-6] if args.state_file.endswith(".state")
                  else args.state_file) + ".stats"
    last_state = None
    prev_reached = None
    fails = 0

    while True:
        time.sleep(args.interval)
        try:
            s = sample(args, prev_reached)
            prev_reached = s["max_children_reached"]
            fails = 0
        except Exception as e:
            # Same posture as the database monitor: a scrape failure is
            # not evidence of load, so we assert nothing. Ride out short
            # outages -- an FPM reload drops connections briefly -- then
            # exit and let systemd restart us, which withdraws the claim
            # through ExecStopPost rather than adding a second reset path.
            fails += 1
            if fails >= args.fail_grace:
                sys.stderr.write(
                    "php-fpm status unreachable for %d consecutive samples "
                    "(%s); withdrawing load claim and exiting for restart\n"
                    % (fails, e))
                return 0
            continue

        state = classify(s, cfg)
        if state != last_state or not os.path.exists(args.state_file):
            write_atomic(args.state_file, state)
            if state != last_state:
                sys.stdout.write(
                    "load state -> %s (active=%d/%d queue=%d)\n"
                    % (state, s["active"], s["max_children"],
                       s["listen_queue"]))
                sys.stdout.flush()
            last_state = state

        write_atomic(stats_path,
                     "ts=%d %s state=%s warm_pct=%d hot_pct=%d" % (
                         time.time(),
                         " ".join("%s=%s" % kv for kv in sorted(s.items())),
                         state, cfg["warm_pct"], cfg["hot_pct"]))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-file", help="path to publish load state to")
    p.add_argument("--address", default="127.0.0.1:9000",
                   help="pool listen address: host:port or /path/to.sock")
    p.add_argument("--status-path", default="/status",
                   help="pm.status_path configured on the pool")
    p.add_argument("--pool-config",
                   default="/etc/opt/remi/php82/php-fpm.d/www.conf",
                   help="pool config, read once for pm.max_children")
    p.add_argument("--max-children", type=int, default=0,
                   help="override pm.max_children instead of reading it")
    p.add_argument("--interval", type=int, default=10)
    p.add_argument("--report", action="store_true",
                   help="one-shot to stdout instead of the publish loop")
    p.add_argument("--fail-grace", type=int, default=6, metavar="N")
    for k, v in sorted(DEFAULTS.items()):
        p.add_argument("--" + k.replace("_", "-"), type=int, default=v)
    args = p.parse_args()
    cfg = dict((k, getattr(args, k)) for k in DEFAULTS)

    if not args.max_children:
        try:
            args.max_children = read_max_children(args.pool_config)
        except OSError as e:
            sys.stderr.write("cannot read %s: %s\n" % (args.pool_config, e))
            return 2
    if not args.max_children:
        sys.stderr.write(
            "pm.max_children not found in %s and --max-children not given; "
            "refusing to run, because every percentage this publishes would "
            "be normalised against a ceiling we invented\n" % args.pool_config)
        return 2

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
