"""Apache error-log slicing + structured decision-line parsing.

The big win over `grep -q` in bash: `decision_lines()` returns a
list of dicts. Tests write

    assert any(d["outcome"] == "rejected" for d in lines)

and pytest's tb on failure shows the full list, not `grep: not found`.

Log file is root-readable only; everything that touches it goes
through sudo.
"""

from __future__ import annotations

import re
import subprocess
from contextlib import contextmanager

from .config import ERROR_LOG

# mod_botshield decision-line shape (M9.1):
#   mod_botshield: decision tier=<t> outcome=<o> ip=<ip> score=<n>
#                  cookie=<c> provider=<p> alg=<a> reason="<r>" path="<p>"
#
# Every field is `key=value` with the value unquoted except reason
# and path which are double-quoted (they can contain spaces/commas).
# A regex that captures key/value pairs correctly handles both.
_DECISION_PREFIX = "mod_botshield: decision "
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)')


def _parse_decision(line: str) -> dict | None:
    """Parse one `mod_botshield: decision ...` line to a dict.

    Returns None for any log line that isn't a decision line.
    Unquotes reason="..." and path="..." into plain strings.
    """
    idx = line.find(_DECISION_PREFIX)
    if idx < 0:
        return None
    tail = line[idx + len(_DECISION_PREFIX):]
    out: dict[str, str] = {}
    for key, val in _KV.findall(tail):
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        out[key] = val
    return out


@contextmanager
def log_slice():
    """Capture log lines written during the context block.

    Yields a `LogSlice` bound to the current byte-offset of the
    error log. Inside the block (or after), call `.decision_lines()`
    / `.grep()` / `.text()` to get lines that landed since entry.

    No temp files: each access shells out `sudo tail -c +N` and reads
    stdout. A couple hundred KB per test is a non-issue.

    Usage:
        with log_slice() as slc:
            # ... drive traffic ...
            lines = slc.decision_lines(outcome="rejected")
            assert lines, "expected at least one rejection"
    """
    yield _LogSlice(start=_log_size())


class _LogSlice:
    def __init__(self, start: int):
        self._start = start

    def _materialize(self) -> str:
        """Read `ERROR_LOG[start:]` via `sudo tail -c +N` and return
        it. Cheap to call repeatedly; pytest tests rarely run more
        than a few assertions per slice."""
        result = subprocess.run(
            ["sudo", "tail", "-c", f"+{self._start + 1}", ERROR_LOG],
            check=True, capture_output=True, text=True,
        )
        return result.stdout

    def text(self) -> str:
        """Raw slice content. Useful for assertions that don't parse."""
        return self._materialize()

    def grep(self, pattern: str) -> list[str]:
        """Return slice lines matching `pattern` (regex)."""
        rx = re.compile(pattern)
        return [ln for ln in self._materialize().splitlines() if rx.search(ln)]

    def decision_lines(self, **filters) -> list[dict]:
        """Return parsed decision dicts, optionally filtered.

        `filters` are exact-match key=value pairs. Any decision whose
        parsed field doesn't equal the filter value is dropped.

        Usage:
            slc.decision_lines(outcome="verified", provider="turnstile")
        """
        out: list[dict] = []
        for line in self._materialize().splitlines():
            d = _parse_decision(line)
            if d is None:
                continue
            if all(d.get(k) == v for k, v in filters.items()):
                out.append(d)
        return out


def _log_size() -> int:
    """Current byte-size of the error log. sudo because it's root-only."""
    result = subprocess.run(
        ["sudo", "stat", "-c", "%s", ERROR_LOG],
        check=True, capture_output=True, text=True,
    )
    return int(result.stdout.strip())
