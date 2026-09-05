"""Every apache example in the docs must parse.

The directive pages drifted badly once already: 972a659 retired the
one-line key=value form, and thirty-seven examples across two pages
went on demonstrating it -- including the page the module's own error
message tells you to read. An operator following that error arrived at
a document showing the syntax it had just refused.

Nothing caught it because nothing checked. This does: each ```apache
fence that mentions a trigger directive is written to a file and run
through httpd -t against the live test instance, exactly as an operator
would have it included.

It has already earned its place twice while running as a hand script --
once on BotShieldLogAs used in an example a step before the directive
existed, once on a fence still carrying the old comma path list.

A fence that is *meant* to be rejected -- the "before" half of a
migration example -- carries `# configtest: skip` on its own line.
"""

from __future__ import annotations

import os
import re
import subprocess

import pytest

from botshield_test import config as bs_config


DOCS = ["docs/directives.md", "docs/policy.md"]
FENCE = re.compile(r"```apache\n(.*?)```", re.DOTALL)
TRIGGER = re.compile(
    r"BotShield(Rule|RequestTrigger|CookieTrigger|EnvTrigger|LoadTrigger|"
    r"FlagTrigger|Trigger|HeuristicTrigger|FeedbackTrigger)"
)
SKIP_MARK = "# configtest: skip"


def _repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", ".."))


def _fences():
    root = _repo_root()
    out = []
    for rel in DOCS:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for m in FENCE.finditer(text):
            body = m.group(1)
            if not TRIGGER.search(body):
                continue
            if SKIP_MARK in body:
                continue
            line = text[: m.start()].count("\n") + 1
            out.append(pytest.param(body, id=f"{rel}:{line}"))
    return out


@pytest.mark.parametrize("snippet", _fences())
def test_doc_example_parses(snippet, tmp_path):
    """One fence, one configtest.

    Parametrised rather than looped so a broken example names itself in
    the failure list instead of hiding behind whichever one ran first.
    """
    conf = tmp_path / "doc_snippet.conf"
    conf.write_text(snippet, encoding="utf-8")
    os.chmod(tmp_path, 0o755)
    os.chmod(conf, 0o644)

    result = subprocess.run(
        ["sudo", bs_config.HTTPD_BIN, "-f", bs_config.HTTPD_CONF,
         "-c", f"Include {conf}", "-t"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        detail = "\n".join(
            l for l in result.stderr.splitlines()
            if l.strip() and "Syntax OK" not in l
        )
        pytest.fail(
            "documented example does not parse:\n"
            f"{snippet}\n--- httpd said ---\n{detail}"
        )
