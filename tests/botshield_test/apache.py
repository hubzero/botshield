"""Apache control + transactional config mutation.

The `config_override` context manager is the single biggest reason
the Python rebuild happens. The bash suite swaps config with `sed -i`,
reloads, tests, reverts — and leaks broken config on any failure
between swap and revert. A try/finally in Python guarantees the
revert, so a blown test can't cascade.
"""

from __future__ import annotations

import re
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from .config import (APACHE_SERVICE, DEV_VHOST_CONF, HTTPD_BIN, HTTPD_CONF,
                     SERVICE_MODE,
                     STATE_FILE)


def configtest(*directives):
    """Run `httpd -t` against this worker's instance config with each
    of `directives` prepended via -C. Return (returncode, stderr).

    Used for directives whose only correct behaviour is to be
    rejected at config time: a live reload with a broken config would
    take the instance down for the rest of the session, and configtest
    does the same parse pass without swapping anything in."""
    # -c, not -C. Both inject a directive, but -C is processed BEFORE
    # the config files and -c after, which decides whether the module
    # has been loaded by the time the directive is looked up. With -C
    # the answer depends on the server build, and in a Rocky container
    # it came back "Invalid command 'BotShieldCookieTTL', perhaps
    # misspelled or defined by a module not included" -- a test for a
    # valid directive failing because the module was not there yet.
    # After the config files the module is always loaded, and an
    # invalid value is still rejected, which is what these tests check.
    cmd = ["sudo", HTTPD_BIN, "-f", HTTPD_CONF]
    for d in directives:
        cmd += ["-c", d]
    cmd += ["-t"]
    result = subprocess.run(cmd, capture_output=True, text=True,
                            check=False)
    return result.returncode, result.stderr


def policy_dump() -> str:
    """Run `httpd -t -D DUMP_BOTSHIELD_POLICY` against this worker's
    own instance config and return the dump on stdout.

    This is a config-test invocation, so it neither reloads nor
    disturbs the running instance -- it re-parses the config files as
    they are on disk right now. That means a `config_override` block
    takes effect for the dump without a reload, but also that the dump
    must be taken *inside* the block, before the file is reverted."""
    result = subprocess.run(
        ["sudo", HTTPD_BIN, "-f", HTTPD_CONF, "-t",
         "-D", "DUMP_BOTSHIELD_POLICY"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, (
        f"config test failed, so there is no dump to assert on:\n"
        f"{result.stderr[-800:]}"
    )
    return result.stdout


def _service(verb: str) -> None:
    """Ask the instance to reload, restart or start.

    Two ways, because not every environment has an init system. Under
    systemd the unit is addressed by name. Without one -- a container
    job, where systemctl cannot work at all -- httpd signals itself
    through its own config, which is what `-k` is for.
    """
    if SERVICE_MODE == "systemd":
        cmd = ["sudo", "systemctl", verb, APACHE_SERVICE]
    else:
        signal = {"reload": "graceful", "restart": "restart",
                  "start": "start", "stop": "stop"}[verb]
        cmd = ["sudo", HTTPD_BIN, "-f", HTTPD_CONF, "-k", signal]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


def reload() -> None:
    """Graceful reload: config re-read, new workers spun, old workers
    drain. Faster than restart and the right choice for most config
    changes."""
    _service("reload")
    # Brief settle so the new pool is up before the caller issues
    # their first request. Reloads are fast but not instantaneous.
    time.sleep(1)


def restart() -> None:
    """Hard restart. SHM counters reset, workers recreated from scratch."""
    _service("restart")
    time.sleep(2)


_MPMS = ("event", "worker", "prefork")


def current_mpm() -> str | None:
    """Return the currently-enabled MPM's short name, or None if
    none is enabled (which would be unusual)."""
    for mpm in _MPMS:
        if Path(f"/etc/apache2/mods-enabled/mpm_{mpm}.load").exists():
            return mpm
    return None


def switch_mpm(target: str) -> None:
    """Switch Apache to the named MPM (event / worker / prefork).

    Idempotent — switching to the already-active MPM is a no-op.
    Used by the M11.8 MPM-matrix fixture; tests that call this must
    restore the default (event) on teardown.

    Performs a full restart, not a reload, because a reload can't
    swap MPMs — the serving model is baked in at process start.
    """
    if target not in _MPMS:
        raise ValueError(f"unknown MPM {target!r}; want one of {_MPMS}")
    active = current_mpm()
    if active == target:
        return

    # a2dismod is noisy on stderr; discard unless there's a real
    # problem (the restart will complain if MPM config is broken).
    # All current MPMs get disabled — a2enmod prints a warning if
    # the target conflicts otherwise.
    for mpm in _MPMS:
        if mpm != target:
            subprocess.run(
                ["sudo", "a2dismod", f"mpm_{mpm}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
    subprocess.run(
        ["sudo", "a2enmod", f"mpm_{target}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=True,
    )
    restart()


def reset_state() -> None:
    """Wipe the state file + restart so SHM + flagged-IP start empty.

    Used by tests whose setup needs a guaranteed-clean slate (e.g.,
    "first-sight-ip must fire for this IP" when prior runs may have
    seeded Bloom for it). Expensive — prefer a fresh IP when the test
    admits one.
    """
    subprocess.run(
        ["sudo", "rm", "-f", STATE_FILE],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    restart()


def _pristine_paths(conf_path: Path):
    return (Path(str(conf_path) + ".pristine"),
            Path(str(conf_path) + ".dirty"))


def _stash_pristine(conf_path: Path, original: str) -> None:
    """Record the pre-override content and mark the file as mutated."""
    pristine, dirty = _pristine_paths(conf_path)
    _atomic_write(pristine, original)
    _atomic_write(dirty, "")


def _clear_pristine(conf_path: Path) -> None:
    """Drop the marker; the override reverted cleanly."""
    _, dirty = _pristine_paths(conf_path)
    subprocess.run(["sudo", "rm", "-f", str(dirty)],
                   check=False, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def restore_pristine_config(conf: str = DEV_VHOST_CONF) -> str | None:
    """If a previous run died inside config_override, put the vhost back.

    Called at session start. Returns a message if it restored anything,
    None if the config was already clean. Restoring at session START
    rather than end is deliberate: the run that made the mess is by
    definition not around to clean up after itself.
    """
    conf_path = Path(conf)
    pristine, dirty = _pristine_paths(conf_path)
    if not dirty.exists() or not pristine.exists():
        return None
    _atomic_write(conf_path, pristine.read_text())
    _clear_pristine(conf_path)
    reload()
    return f"restored {conf} from a previous run's interrupted override"

@contextmanager
def config_override(
    pattern: str, replacement: str, *,
    conf: str = DEV_VHOST_CONF,
    count: int | None = None,
):
    """Swap one or more lines in the dev vhost, reload, run the block,
    revert.

    `pattern` is a Python regex; `replacement` replaces every match
    (re.sub with default `count=0`). The dev vhost typically has two
    copies of each per-provider directive (one in the verify-endpoint
    Location, one in the demo-path Location); replacing both is what
    tests want in practice, and not replacing both leaves the config
    inconsistent.

    Pass `count=N` to require exactly N matches — useful when a
    test is only expecting one and wants a loud fail if a future
    config change makes the pattern ambiguous.

    Guaranteed cleanup: the revert + reload fires even if the body
    raises. If the revert itself fails, that exception masks the
    original — not ideal, but less dangerous than skipping it.

    Usage:
        with config_override(
            r"BotShieldCaptchaTimeout\\s+\\d+",
            "BotShieldCaptchaTimeout 100",
        ):
            # Apache now has the 100ms timeout.
            ...
        # Original timeout restored; a reload already fired.
    """
    conf_path = Path(conf)
    original = conf_path.read_text()

    found = len(re.findall(pattern, original))
    if found == 0:
        raise ValueError(
            f"config_override: pattern {pattern!r} matched zero lines in {conf}"
        )
    if count is not None and found != count:
        raise ValueError(
            f"config_override: pattern {pattern!r} matched {found} lines "
            f"in {conf}, expected {count}"
        )

    mutated = re.sub(pattern, replacement, original)

    # Stage the mutated file via a root-owned temp path. sudo mv is
    # atomic; a partial write can't leave the vhost in a broken state.
    #
    # The finally below reverts on any exception, but not on the pytest
    # process being killed -- a `timeout`, a Ctrl-C that lands wrong, a
    # CI step cancelled. That leaves this test's injected rules in the
    # shared vhost, where they apply to every later run: a leftover
    # `BotShieldRequestTrigger p-block path="/*" status=451` turned 30
    # unrelated tests red and read as a product bug for two full suite
    # runs. So stash the original and drop a marker first, and let
    # session start put it back.
    _stash_pristine(conf_path, original)
    _atomic_write(conf_path, mutated)
    try:
        reload()
        yield
    finally:
        _atomic_write(conf_path, original)
        _clear_pristine(conf_path)
        reload()


def _atomic_write(path: Path, content: str) -> None:
    """Write `content` to `path` via a sudo'd temp file + rename.

    Apache vhost files are root-owned. A normal open() would fail
    with EACCES; shelling out to tee/sponge is the idiomatic way.
    """
    tmp = path.parent / f".{path.name}.tmp"
    # `sudo tee` writes as root. The body is fed via stdin so quoting
    # isn't an issue. Discard stdout; we only care about exit code.
    subprocess.run(
        ["sudo", "tee", str(tmp)],
        input=content,
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["sudo", "mv", str(tmp), str(path)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    # Restore world-readability explicitly rather than inheriting
    # root's umask. `sudo tee` creates the temp file with whatever
    # umask root has; on Debian that is 022 and the result is 0644, but
    # on a hardened host (RHEL/Rocky with umask 077) it is 0600 -- and
    # config_override reads the file back with a plain
    # Path.read_text() as the unprivileged test user. Without this the
    # first override poisons the file and every later test dies with
    # EACCES, which looks like 150+ module failures rather than one
    # permissions bug.
    subprocess.run(
        ["sudo", "chmod", "644", str(path)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
