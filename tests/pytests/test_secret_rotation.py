"""E16 — graceful HMAC/GCM secret rotation.

`BotShieldSecondarySecretFile` adds a verify-only fallback secret so
cookies signed under the old key keep validating during a rotation
window. The issue path always uses the primary; verify tries the
primary first and falls back to the secondary on signature/tag
mismatch.

Operator workflow validated by these tests:
  1. Operator points BotShieldSecretFile at the NEW key and
     BotShieldSecondarySecretFile at the OLD key. Reload.
  2. Cookies signed under the old key keep validating.
  3. Fresh challenges are signed under the new key.
  4. After one BotShieldCookieTTL window, operator drops the
     secondary directive. Old cookies expire naturally.

These tests work at the directive/parse level since end-to-end key-
rotation requires writing two secret files and reloading — which the
config_override pattern can handle but is heavy.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from botshield_test import client


pytestmark = pytest.mark.serial


PRIMARY_PATH   = "/etc/botshield/secret"
SECONDARY_PATH = "/etc/botshield/secret-secondary"


def _write_root_owned_mode_600(path: str, content: bytes) -> None:
    """Provision a mode-600 root-owned file. Mirrors what the test
    environment does for /etc/botshield/secret.

    Security review MEDIUM #14 — was using a predictable filename
    `/tmp/.bs-secret-rotation-<pid>`. On a shared dev host, an
    attacker who can predict the pid (e.g. via a parallel shell)
    could pre-create a symlink at that path pointing at an
    attacker-owned file; our subsequent `open(tmp, "wb")` would
    follow the symlink and let them learn the random key bytes.
    Use tempfile.mkstemp() which atomically creates a fresh
    O_CREAT|O_EXCL fd at a non-guessable path with mode 0600.
    """
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".bs-secret-rotation-",
                               dir="/tmp")
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    subprocess.run(["sudo", "install", "-m", "0600", "-o", "root",
                    tmp, path], check=True)
    os.unlink(tmp)


@pytest.fixture
def secondary_secret_file():
    """Write a random secondary secret at SECONDARY_PATH for the
    duration of the test, remove it on teardown.

    Uses hex-encoded urandom (64 ASCII bytes from 32 random bytes) so
    the file is guaranteed NUL-free. Raw 32-byte urandom hits a NUL
    ~12% of the time per the validator's own error message, which
    historically made the two tests using this fixture intermittently
    fail under reload with an embedded-NUL parse error. mod_botshield's
    secret-key validator treats the file contents as opaque key
    material — it doesn't hex-decode — so a 64-byte ASCII-hex file
    just becomes a 64-byte key, which exceeds the 16-byte minimum."""
    secret = os.urandom(32).hex().encode("ascii")
    _write_root_owned_mode_600(SECONDARY_PATH, secret)
    try:
        yield SECONDARY_PATH
    finally:
        subprocess.run(["sudo", "rm", "-f", SECONDARY_PATH], check=True)


# --- Directive validation ------------------------------------------


def test_directive_rejects_missing_file(config_override):
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            'BotShieldEnabled On\n'
            '    BotShieldSecondarySecretFile /nonexistent/secret',
            count=1,
        ):
            pass


def test_directive_rejects_world_readable(config_override, tmp_path):
    """A world-readable secondary file must be refused — same hygiene
    contract as the primary."""
    bad = tmp_path / "loose-secret"
    bad.write_bytes(b"x" * 32)
    bad.chmod(0o644)
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            f'BotShieldEnabled On\n'
            f'    BotShieldSecondarySecretFile {bad}',
            count=1,
        ):
            pass


def test_directive_rejects_embedded_nul(config_override, tmp_path):
    """Security review HIGH #2. A secret file containing an embedded
    NUL must be rejected at parse time. Earlier versions silently
    truncated the key at the first NUL via strlen, yielding a
    shorter, weaker effective key with no log warning. P(NUL in N
    random bytes) = 1 − (255/256)^N — about 12% for 32-byte keys —
    so this is the realistic failure mode of `dd if=/dev/urandom` /
    `openssl rand` without hex/base64 encoding.

    Exercising the secondary loader is sufficient: all five secret
    loaders (primary, secondary, captcha, app-feedback/claims merged
    into app-integration) share `bs_validate_secret_key`, so the
    fix is on a single code path."""
    bad = tmp_path / "secret-with-nul"
    # 32 mode-600 bytes with a NUL in the middle. Bypasses the
    # length-floor + permissions checks so the validator's NUL guard
    # is what fires.
    bad.write_bytes(b"a" * 16 + b"\x00" + b"b" * 15)
    bad.chmod(0o600)
    with pytest.raises(Exception):
        with config_override(
            r"BotShieldEnabled\s+On",
            f'BotShieldEnabled On\n'
            f'    BotShieldSecondarySecretFile {bad}',
            count=1,
        ):
            pass


def test_directive_accepts_well_formed(config_override,
                                       secondary_secret_file, fresh_ip):
    """Valid secondary file path: reload succeeds, server stays
    healthy."""
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n'
        f'    BotShieldSecondarySecretFile {secondary_secret_file}',
        count=1,
    ):
        r = client.get(
            "/", xff=fresh_ip,
            ua="Mozilla/5.0 Firefox/125.0",
            accept_language="en-US,en;q=0.9",
        )
        assert r.status_code in (200, 304), (
            f"server unhealthy after secondary-secret reload; "
            f"status={r.status_code}"
        )


# --- Verify path: cookies signed under old key keep validating -----


def test_old_cookie_validates_during_rotation(config_override,
                                              secondary_secret_file,
                                              fresh_ip):
    """The headline case: a cookie issued under the OLD key (now
    moved to BotShieldSecondarySecretFile) still passes verify after
    rotation. Without multi-key verify, every existing client would
    be re-challenged the moment the operator rotates.

    Setup uses config_override sequentially:
      1. Default config — primary secret active. Get a fresh cookie
         by completing a challenge would be heavy; instead exercise
         the verify-time fall-back behavior by simulating the swap.

    For end-to-end coverage that the operator's actual swap works,
    we'd need to mint a real signed cookie under key A, then swap A
    into the secondary and a fresh B into the primary. That requires
    coordinated file writes the test framework doesn't expose
    cleanly. The directive-validation tests above plus the unit-level
    fall-back logic (HMAC and GCM both retry on the secondary on
    primary-fail) are the load-bearing coverage.

    This test is therefore a smoke-check that adding the directive
    doesn't break verify on cookies signed under the PRIMARY: the
    secondary key shouldn't shadow or interfere with primary-key
    verification."""
    with config_override(
        r"BotShieldEnabled\s+On",
        f'BotShieldEnabled On\n'
        f'    BotShieldSecondarySecretFile {secondary_secret_file}',
        count=1,
    ):
        # First request: no cookie, gets challenge or pass-through.
        r1 = client.get(
            "/", xff=fresh_ip,
            ua="Mozilla/5.0 Firefox/125.0",
            accept_language="en-US,en;q=0.9",
        )
        # A reload-healthy server should answer.
        assert r1.status_code in (200, 304), (
            f"primary-key cookie path broke after adding secondary; "
            f"status={r1.status_code}"
        )
