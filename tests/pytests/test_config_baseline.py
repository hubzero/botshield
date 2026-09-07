"""The vhost drift guard, and the snapshot rule that backstops it.

Written after a dev vhost accumulated ~130 lines of leftover rules from
a dozen interrupted overrides and still reported a green lane. Two
separate holes let that happen, and each has a test here:

  - .pristine is written by the same test user that does the
    overriding, so a second concurrent process recorded an already
    mutated file as the clean one.
  - restore_pristine_config is gated on the .dirty marker, so once any
    override exited cleanly the recovery stopped looking and the suite
    ran against whatever was on disk.

The drift that got through included a live
`BotShieldBotRateLimit @ai-train 1 sec scope=group` in the baseline,
which is both wrong config and a flake generator on a per-slot counter.
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest

from botshield_test import apache
from botshield_test.config import DEV_VHOST_CONF


def test_drift_from_the_generated_baseline_is_repaired():
    """The check must actually fire. A guard nobody has seen trip is
    indistinguishable from one that does not work -- which is how the
    .pristine path went bad unnoticed for a full run."""
    conf = Path(DEV_VHOST_CONF)
    baseline = Path(str(conf) + ".baseline")
    if not baseline.exists():
        pytest.skip("instance predates the baseline; re-run make-instances.sh")

    want = baseline.read_text()
    assert conf.read_text() == want, (
        "vhost was already drifted at test start -- session start should "
        "have repaired it"
    )

    # Drift it the way a killed override does: append, don't replace.
    marker = f"# drift-probe {uuid.uuid4().hex}"
    try:
        apache._atomic_write(conf, want + "\n" + marker + "\n")
        assert marker in conf.read_text(), "probe did not land"

        msg = apache.verify_baseline_config()

        assert msg and "drifted" in msg, f"drift went unreported; msg={msg!r}"
        assert conf.read_text() == want, (
            "vhost was not put back to the generated baseline"
        )
    finally:
        # An assertion firing between the drift and the repair
        # would otherwise leave the probe in the vhost for every
        # later test in this worker -- the exact leak under test.
        if conf.read_text() != want:
            apache._atomic_write(conf, want)
            apache.reload()


def test_a_clean_vhost_reports_nothing():
    """Silence when there is nothing to say. A guard that cries every
    session gets ignored, and then it may as well not run."""
    baseline = Path(str(Path(DEV_VHOST_CONF)) + ".baseline")
    if not baseline.exists():
        pytest.skip("instance predates the baseline; re-run make-instances.sh")
    assert apache.verify_baseline_config() is None


def test_a_missing_baseline_is_reported_not_skipped():
    """The absent-guard case says so out loud.

    Returning None here would reproduce the original bug in miniature:
    the check appears to run, finds nothing to complain about because
    it cannot look, and the operator reads that as 'clean'.
    """
    absent = f"/tmp/bs-no-baseline-{uuid.uuid4().hex}.conf"
    Path(absent).write_text("BotShieldEnabled On\n")
    try:
        msg = apache.verify_baseline_config(absent)
        assert msg and "undetected" in msg, (
            f"a missing baseline must be announced; msg={msg!r}"
        )
    finally:
        Path(absent).unlink(missing_ok=True)


def test_second_writer_does_not_record_a_mutated_file_as_pristine():
    """The concurrency hole itself.

    Process A stashes the clean text and starts editing. Process B --
    another ./run against the same instance -- reaches the same code
    with A's edits already on disk. If B is allowed to stash, the
    snapshot now says the mutated file is the clean one, and the next
    session 'restores' the mess permanently. A's snapshot is the only
    one that was ever true, so A keeps it.
    """
    probe = Path(f"/tmp/bs-stash-{uuid.uuid4().hex}.conf")
    pristine, dirty = apache._pristine_paths(probe)
    try:
        assert apache._stash_pristine(probe, "CLEAN\n") is True, (
            "the first writer must take the snapshot"
        )
        assert pristine.read_text() == "CLEAN\n"

        assert apache._stash_pristine(probe, "MUTATED\n") is False, (
            "the second writer must be refused"
        )
        assert pristine.read_text() == "CLEAN\n", (
            "a mutated file was recorded as pristine -- this is the bug "
            "that made ~130 lines of leftover rules permanent"
        )
    finally:
        for p in (pristine, dirty, probe):
            subprocess.run(["sudo", "rm", "-f", str(p)], check=False)
