"""Security review: numeric directive setters reject malformed values.

atoi() silently accepts "60sec" as 60 and invokes UB on overflow.
The bounded-parse helpers now back every directive setter — check
that malformed values cause Apache to REFUSE to start rather than
starting with silently-truncated config.

We drive this via a temporary single-vhost config file + `apachectl
configtest` instead of a live reload, because a genuinely broken
directive would leave Apache in an unusable state for the rest of
the suite. configtest does the same parse pass without swapping
the running config, so failures here don't poison later tests.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest


pytestmark = pytest.mark.serial


def _configtest(snippet: str) -> tuple[int, str]:
    """Write the given <VirtualHost>-ready snippet under
    conf-available/ and run `apachectl -t`. Return (rc, stderr).
    Cleans up the file no matter what."""
    # Include file approach: Apache has `Include` but we need a
    # whole mini-config. Easier: drop a temp file under
    # /etc/apache2/conf-available and `-C Include` it at configtest
    # time. Even easier: use apachectl's `-D` define + -C directive
    # mechanism... actually simplest of all is to just feed a full
    # config snippet via apachectl's -C option for one-shot dirs.
    #
    # apachectl -C "BotShieldCookieTTL garbage" -t
    cmd = ["sudo", "apachectl", "-C", snippet, "-t"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.returncode, result.stderr


# Each case: (snippet, error_substring_we_expect)
CASES = [
    ("BotShieldCookieTTL 60sec",
     "BotShieldCookieTTL"),
    ("BotShieldCookieTTL 99999999999999999999",
     "BotShieldCookieTTL"),
    ("BotShieldCookieTTL -1",
     "BotShieldCookieTTL"),
    ("BotShieldDifficulty 9x",
     "BotShieldDifficulty"),
    ("BotShieldDifficulty 0",
     "BotShieldDifficulty"),
    ("BotShieldDifficulty 9",
     "BotShieldDifficulty"),
    ("BotShieldFlaggedIPCapacity 10garbage",
     "BotShieldFlaggedIPCapacity"),
    ("BotShieldBloomIPs 99999999999999",
     "BotShieldBloomIPs"),
    ("BotShieldBloomWindow 30d",
     "BotShieldBloomWindow"),
    ("BotShieldStateSaveInterval 20",   # 1..29 is explicitly disallowed
     "BotShieldStateSaveInterval"),
    ("BotShieldShmSize -5M",
     "BotShieldShmSize"),
    ("BotShieldShmSize 9999999999G",     # overflow path in suffix mul
     "BotShieldShmSize"),
]


@pytest.mark.parametrize("snippet,err_substr", CASES,
                         ids=[c[0].replace(" ", "_")[:30] for c in CASES])
def test_malformed_directive_rejected(snippet, err_substr):
    """configtest must fail with a message mentioning the directive
    name. Silent acceptance would let operators deploy nonsense
    config with values like `60sec → 60` or `99e99 → INT_MAX`."""
    rc, err = _configtest(snippet)
    assert rc != 0, (
        f"configtest accepted malformed directive {snippet!r}; "
        f"a regression against the bounded-parse setters"
    )
    assert err_substr in err, (
        f"error for {snippet!r} doesn't mention the directive name — "
        f"operators won't know what to fix. stderr:\n{err[-500:]}"
    )


def test_valid_directive_accepted():
    """Regression guard: bounded parsers must not false-reject a
    well-formed value."""
    rc, err = _configtest("BotShieldCookieTTL 3600")
    assert rc == 0, (
        f"bounded parser false-rejected a valid 'BotShieldCookieTTL 3600'; "
        f"stderr: {err}"
    )
