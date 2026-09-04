#!/usr/bin/env python3
"""Refresh every external dataset mod_botshield reads at runtime.

Three datasets, each hot-reloaded by the module when the file's mtime
changes, so a refresh takes effect without a rebuild and without an
Apache reload:

    crawler IP ranges  -> /var/lib/botshield/bots/*.txt
    bot directory      -> /var/lib/botshield/bot-directory.tsv
    browser templates  -> /var/lib/botshield/browser-templates.txt

Two sources, in an order that depends on where this is running.

On a host, this project's committed data is preferred. It has already
survived the same validation applied here and a person looked at it
before it was committed, which is a stronger claim than whatever an
upstream happens to be serving this minute. It is also one request to
one host rather than several to several. If that copy has gone stale,
past BOTSHIELD_MAX_DATA_AGE_DAYS, this falls back to the upstreams
directly, so a host stays current even if this project goes quiet and
is never strictly dependent on anyone maintaining it.

In a checkout the order reverses: refreshing means fetching upstream,
validating, and committing the result, which is the act of curating
the data everyone else then prefers. Pulling this project's own
committed copy back down would be circular.

Nothing is ever replaced by something that failed validation, and
nothing is replaced by nothing. Every dataset that cannot be refreshed
keeps the file it already has. Stale data that passed these checks
once is better than data that just failed them, and far better than an
empty allow list, which is why a failure here is reported rather than
acted on.

Usage:
    botshield-refresh.py                 # all three
    botshield-refresh.py ranges          # just crawler IP ranges
    botshield-refresh.py directory       # just the bot directory
    botshield-refresh.py user-agents     # just browser templates

Exit code 0 if everything refreshed, 1 if any dataset did not. The
systemd unit treats 1 as success, because a partial refresh has
already written every dataset that did work.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from botshield_refresh import directory, ranges, user_agents  # noqa: E402

DATASETS = {
    "ranges": ("crawler IP ranges", ranges.main),
    "directory": ("bot directory", directory.main),
    "user-agents": ("browser templates", user_agents.main),
}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Refresh the data mod_botshield reads at runtime.",
    )
    parser.add_argument(
        "dataset",
        nargs="?",
        default="all",
        choices=["all", *DATASETS],
        help="which dataset to refresh (default: all)",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--prefer-project",
        dest="prefer_project",
        action="store_true",
        default=None,
        help="prefer this project's committed data over upstream "
             "(the default on a host with no checkout)",
    )
    source.add_argument(
        "--upstream",
        dest="prefer_project",
        action="store_false",
        help="always go straight to upstream (the default in a checkout)",
    )
    args = parser.parse_args(argv[1:])

    selected = DATASETS if args.dataset == "all" else {
        args.dataset: DATASETS[args.dataset]
    }

    failed = []
    for name, (label, refresh) in selected.items():
        print(f"== {label} ==")
        try:
            if refresh(args.prefer_project) != 0:
                failed.append(label)
        except Exception as exc:                      # noqa: BLE001
            # One dataset blowing up must not stop the others, and must
            # not leave its files half-written: every writer here
            # validates first and renames into place.
            print(f"ERROR: {label} failed: {exc}", file=sys.stderr)
            failed.append(label)
        print()

    if failed:
        print(
            "did not refresh: " + ", ".join(failed)
            + " -- existing files for these were left in place",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
