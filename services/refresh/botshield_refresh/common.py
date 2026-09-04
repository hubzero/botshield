"""Shared plumbing for the three data refreshers.

Fetching, atomic writes, ownership, and the two-source strategy every
dataset follows. Each refresher module supplies only what is specific
to its data: where upstream lives, how to parse it, what makes a
payload implausible, and what the module reads at runtime.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "mod_botshield/refresh"
TIMEOUT = 30

# Where the curated copies live. A host prefers these over upstream:
# they are the data this project fetched, validated, reviewed, and
# committed, which is a stronger claim than whatever upstream is
# serving right now.
PROJECT_REPO = os.environ.get("BOTSHIELD_PROJECT_REPO", "hubzero/botshield")
PROJECT_REF = os.environ.get("BOTSHIELD_PROJECT_REF", "main")
PROJECT_RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
PROJECT_COMMITS_API = (
    "https://api.github.com/repos/{repo}/commits"
    "?path={path}&sha={ref}&per_page=1"
)

# How long curated data may go untouched before a host stops trusting
# it and goes to upstream itself. Long enough that a quiet fortnight in
# the project is not treated as abandonment, short enough that a host
# does not serve months-old ranges because nobody tagged a release.
MAX_PROJECT_DATA_AGE_DAYS = int(
    os.environ.get("BOTSHIELD_MAX_DATA_AGE_DAYS", "45")
)


def fetch(url: str, accept: str | None = None) -> bytes:
    """Fetch one URL. Raises on any transport or HTTP failure."""
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        body = response.read()
    if not body:
        raise RuntimeError("empty response")
    return body


def project_data_age_days(path: str) -> float | None:
    """How long ago the project last committed `path`, in days.

    The raw file endpoint serves no Last-Modified, so the commit date
    comes from the API. Returns None when that cannot be determined --
    rate limit, network, an unexpected shape -- and the caller treats
    unknown age as a reason to go to upstream rather than to trust
    data of unknown vintage.
    """
    url = PROJECT_COMMITS_API.format(repo=PROJECT_REPO, ref=PROJECT_REF, path=path)
    try:
        payload = json.loads(fetch(url, accept="application/vnd.github+json"))
    except (urllib.error.URLError, OSError, ValueError, RuntimeError):
        return None

    try:
        stamp = payload[0]["commit"]["committer"]["date"]
        committed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (IndexError, KeyError, TypeError, ValueError):
        return None

    return (datetime.now(timezone.utc) - committed).total_seconds() / 86400.0


def fetch_project_data(path: str) -> bytes:
    """Fetch one file from the project's data directory on GitHub."""
    return fetch(PROJECT_RAW.format(repo=PROJECT_REPO, ref=PROJECT_REF, path=path))


def load_dataset(
    label: str,
    project_path: str,
    fetch_upstream,
    validate,
    prefer_project: bool,
):
    """Get one dataset, from the project's copy or from upstream.

    Two orders, chosen by `prefer_project`:

    In a checkout, `prefer_project` is false. Refreshing means going to
    upstream, validating, and committing the result -- pulling this
    project's own committed data back down would be circular, and
    curating it is the whole point of running the refresher there.

    On a host, `prefer_project` is true. The curated copy is preferred
    because it has already survived these same checks and a person
    looked at it. Upstream is the fallback for when the project's copy
    has gone stale, which keeps a host current even if this project
    goes quiet, and is the reason a host is never strictly dependent on
    anyone continuing to maintain it.

    Returns (parsed_data, source_description). Raises RuntimeError if
    neither source yields data that passes `validate`.
    """
    attempts = []

    if prefer_project:
        age = project_data_age_days(project_path)
        if age is None:
            print(f"  {label}: project data age unknown, going to upstream")
        elif age > MAX_PROJECT_DATA_AGE_DAYS:
            print(
                f"  {label}: project data is {age:.0f} days old "
                f"(limit {MAX_PROJECT_DATA_AGE_DAYS}), going to upstream"
            )
        else:
            attempts.append(
                (
                    f"project data ({age:.0f} days old)",
                    lambda: json.loads(fetch_project_data(project_path)),
                )
            )

    attempts.append(("upstream", fetch_upstream))

    problems = []
    for description, getter in attempts:
        try:
            data = getter()
        except Exception as exc:
            problems.append(f"{description}: {exc}")
            print(f"  {label}: {description} unavailable: {exc}")
            continue

        errors = validate(data)
        if errors:
            problems.append(f"{description}: " + "; ".join(errors))
            print(f"  {label}: {description} failed validation, not using it")
            for error in errors:
                print(f"      {error}")
            continue

        print(f"  {label}: using {description}")
        return data, description

    raise RuntimeError(f"{label}: no usable source. " + " | ".join(problems))


def write_atomic(target: Path, body: bytes) -> None:
    """Write via a temporary file and a rename.

    The rename is atomic on one filesystem, so an interrupted refresh
    leaves the previous file intact rather than a truncated one. A
    half-written allow list would read as a shrunken allow list.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(body)
    temporary.replace(target)


def web_server_account() -> str | None:
    """Whichever web-server account this distribution uses.

    apache on RHEL-family, www-data on Debian-family. A miss is not
    fatal: these files are mode 0644 and the module only reads them.
    """
    import pwd

    for name in ("apache", "www-data"):
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    return None


def write_runtime_file(target: Path, body: bytes) -> None:
    """Write a file the module reads, owned so the module can read it."""
    write_atomic(target, body)
    try:
        os.chmod(target, 0o644)
    except OSError as exc:
        print(f"   warn: chmod 0644 {target} failed: {exc}", file=sys.stderr)

    account = web_server_account()
    if account is None:
        return
    import grp
    import pwd

    try:
        os.chown(
            target, pwd.getpwnam(account).pw_uid, grp.getgrnam(account).gr_gid
        )
    except (KeyError, PermissionError, OSError):
        pass   # 0644 already covers the module's read
