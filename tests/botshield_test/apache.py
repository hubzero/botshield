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
def config_override(pattern: str, replacement: str, *, conf: str = DEV_VHOST_CONF):
    """Swap a line in the dev vhost, reload, run the block, revert.

    `pattern` is a Python regex matched line-by-line. `replacement`
    replaces the whole matched region (re.sub semantics). Exactly
    one match is required — ambiguity means the caller's pattern is
    too broad, and silent multi-match substitution is how bash tests
    have quietly corrupted their own config.

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

    matches = re.findall(pattern, original)
    if len(matches) == 0:
        raise ValueError(
            f"config_override: pattern {pattern!r} matched zero lines in {conf}"
        )
    if len(matches) > 1:
        raise ValueError(
            f"config_override: pattern {pattern!r} matched {len(matches)} "
            f"lines in {conf} — tighten it"
        )

    mutated = re.sub(pattern, replacement, original, count=1)

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
