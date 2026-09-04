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

import tempfile
from pathlib import Path

import pytest

from botshield_test import apache


# No longer serial. The marker meant "mutates Apache config or SHM",
# and both were only a problem because every test shared one server.
# Each xdist worker now drives its own httpd instance with its own
# ports, logs, SHM and state file (tests/setup/make-instance.sh), so
# these are independent. Verified: this file's tests pass under -n 4.


def _configtest(snippet: str) -> tuple[int, str]:
    """Parse `snippet` against THIS instance and return (rc, stderr).

    Delegates to the shared helper. It used to run `apachectl -C ... -t`
    with no -f, which parses the default server config: on a box that
    also serves a live site that is the production config, so these
    tests asserted against the DEPLOYED module rather than the one just
    built -- a check for a directive the working tree had added would
    have failed on the old binary. In a container there is no botshield
    in the default config at all, and every case came back "Invalid
    command", including the one asserting a VALID directive is
    accepted.
    """
    return apache.configtest(snippet)


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

# Directives the module resolves once from the main server: the SHM
# segment is sized and attached before vhosts merge, and the load
# watchdog is registered against the main server_rec. RSRC_CONF lets
# Apache accept them inside <VirtualHost>, where the module then never
# reads them -- so the module has to refuse them itself.
SERVER_ONLY = [
    ("BotShieldShmSize", "8M"),
    ("BotShieldFlaggedIPCapacity", "2048"),
    ("BotShieldBloomIPs", "10000"),
    ("BotShieldBloomWindow", "3600"),
    ("BotShieldStateFile", "/tmp/bs-scope-test.bin"),
    ("BotShieldStateSaveInterval", "60"),
    ("BotShieldRateLimitEscalateCapacity", "2048"),
    ("BotShieldSafeguardCapacity", "2048"),
    ("BotShieldEmbeddedNonceCapacity", "2048"),
    ("BotShieldDbStatsFile", "/tmp/bs-db.stats"),
    ("BotShieldFpmStatsFile", "/tmp/bs-fpm.stats"),
]


@pytest.mark.parametrize("name,value", SERVER_ONLY,
                         ids=[n for n, _ in SERVER_ONLY])
def test_server_only_directive_rejected_in_vhost(name, value):
    """Inside <VirtualHost> these must be a config error naming the
    directive.

    This was a startup NOTICE and that was not enough: the config
    parses, configtest is green, httpd starts, and the directive does
    nothing. BotShieldDbStatsFile in a vhost left the dashboard
    reporting "no monitor" behind a clean configtest, which is the
    worst failure shape available -- it looks like the feature is
    broken rather than like the config is."""
    rc, err = apache.configtest(
        "<VirtualHost 127.0.0.1:19999>", f"{name} {value}", "</VirtualHost>",
    )
    assert rc != 0, (
        f"{name} accepted inside <VirtualHost>; it would be parsed and "
        f"then silently ignored"
    )
    assert name in err, (
        f"rejection does not name {name}, so an operator cannot tell "
        f"which line to move. stderr:\n{err[-400:]}"
    )


@pytest.mark.parametrize("name,value", SERVER_ONLY,
                         ids=[n for n, _ in SERVER_ONLY])
def test_server_only_directive_accepted_at_server_scope(name, value):
    """The other half: they must still work where they belong. A guard
    that rejects everywhere would pass the test above."""
    rc, err = apache.configtest(f"{name} {value}")
    assert rc == 0, (
        f"{name} rejected at server scope, where it is required to "
        f"work. stderr:\n{err[-400:]}"
    )
