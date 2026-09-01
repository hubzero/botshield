"""Apache error-log slicing + structured decision-line parsing.

The big win over `grep -q` in bash: `decision_lines()` returns a
list of dicts. Tests write

    assert any(d["outcome"] == "block" for d in lines)

and pytest's tb on failure shows the full list, not `grep: not found`.

Log file is root-readable only; everything that touches it goes
through sudo.
"""

from __future__ import annotations

import re
import subprocess
from contextlib import contextmanager

from .config import ERROR_LOG
from .enums import (COOKIES, OUTCOMES, PROVIDERS, TIERS, provider_log,
                    tier_log)

REQUIRED_DECISION_KEYS = (
    "tier", "outcome", "ip", "score",
    "cookie", "provider", "alg", "reason", "path",
)

# Provider enum values as they appear in the decision-log's `provider=`
# field (hyphenated, plus the sentinel "-" for non-captcha tiers).
_PROVIDER_LOG_VALUES = {"-", *(provider_log(p) for p in PROVIDERS)}

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
    # The prefix also matches the startup notice
    #   "mod_botshield: decision log active: <path> (default set: ...)"
    # which parses into a dict of whatever k=v happens to appear in the
    # tail and no `outcome`, so callers doing d["outcome"] hit a
    # KeyError on a line that was never a decision. Every real decision
    # payload begins with tier=.
    if not tail.startswith("tier="):
        return None
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
            lines = slc.decision_lines(outcome="block")
            assert lines, "expected at least one block"
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


def validate_decision(d: dict) -> list[str]:
    """Return a list of validation failures for one parsed decision
    dict. Empty list = clean.

    Replaces `tests/lib/decision_gate.awk`. Same rules:
      - every required key present
      - tier/outcome/cookie values in their enum
      - provider is `-` or a known hyphenated name
      - score is an integer (positive, negative, or zero)
    """
    problems: list[str] = []
    for key in REQUIRED_DECISION_KEYS:
        if key not in d:
            problems.append(f"missing key {key!r}")

    # TIERS holds the metric spelling; the log spells non_interactive
    # with a hyphen (see enums.tier_log).
    if d.get("tier") and d["tier"] not in {tier_log(t) for t in TIERS}:
        problems.append(f"tier={d['tier']!r} not in enum")
    if d.get("outcome") and d["outcome"] not in OUTCOMES:
        problems.append(f"outcome={d['outcome']!r} not in enum")
    if d.get("cookie") and d["cookie"] not in set(COOKIES) | {"-"}:
        problems.append(f"cookie={d['cookie']!r} not in enum")
    if d.get("provider") and d["provider"] not in _PROVIDER_LOG_VALUES:
        problems.append(f"provider={d['provider']!r} not in enum")

    score = d.get("score")
    if score is not None:
        try:
            int(score)
        except (TypeError, ValueError):
            problems.append(f"score={score!r} not an integer")

    return problems
