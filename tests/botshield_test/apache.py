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

from .config import APACHE_SERVICE, DEV_VHOST_CONF, STATE_FILE


def reload() -> None:
    """Graceful reload: config re-read, new workers spun, old workers
    drain. Faster than restart and the right choice for most config
    changes."""
    subprocess.run(
        ["sudo", "systemctl", "reload", APACHE_SERVICE],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    # Brief settle so the new pool is up before the caller issues
    # their first request. Reloads are fast but not instantaneous.
    time.sleep(1)


def restart() -> None:
    """Hard restart. SHM counters reset, workers recreated from scratch."""
    subprocess.run(
        ["sudo", "systemctl", "restart", APACHE_SERVICE],
        check=True,
        stdout=subprocess.DEVNULL,
    )
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
    _atomic_write(conf_path, mutated)
    try:
        reload()
        yield
    finally:
        _atomic_write(conf_path, original)
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
