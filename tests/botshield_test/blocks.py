"""Render a flat trigger directive as the container form.

The one-line `key=value` spelling is retired in the module, but it is
still the compact way to *say* a rule in test code: one Python string
instead of eight, and it survives the f-string templating a dozen
tests do to vary one attribute at a time.

So tests keep writing the compact form and `config_override` renders
it through here before the config reaches Apache. What lands on disk,
and therefore what the module parses, is the block form -- these
tests exercise the container path, not a retired one. The flat
spelling's rejection has its own test; it is not covered by silence
here.
"""
from __future__ import annotations

import re

FAMILIES = (
    "BotShieldRequestTrigger", "BotShieldRule", "BotShieldFlagTrigger",
    "BotShieldHeuristicTrigger", "BotShieldCookieTrigger",
    "BotShieldEnvTrigger", "BotShieldFeedbackTrigger",
    "BotShieldLoadTrigger", "BotShieldTrigger",
)

# Families whose rules carry no name.
_NAMELESS = frozenset({"BotShieldTrigger"})

# key -> inner directive. Mirrors bs_section_key() in src/triggers.c;
# only the names that are not just the capitalised key appear here.
_SPELL = {
    "ua": "BotShieldUserAgent", "ipspec": "BotShieldIPSpec",
    "ttl": "BotShieldTTL", "minload": "BotShieldMinLoad",
    "accesslog": "BotShieldAccessLog", "bscookie": "BotShieldBSCookie",
    "bs-cookie": "BotShieldBSCookie",
}

# Apache quotes a whole argument, not just the value, so both
# log="BAN 2h" and "log=BAN 2h" mean the same thing and both have to
# survive being split apart and put back together.
_ARG = re.compile(r'"[^"]*"|\'[^\']*\'|(?:[^\s"\']|"[^"]*"|\'[^\']*\')+')


def _split_args(text):
    """Apache-style argument split: quotes protect spaces."""
    return [m.group(0) for m in _ARG.finditer(text)]


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _spell(key: str) -> str:
    return _SPELL.get(key, "BotShield" + key[:1].upper() + key[1:])


def to_blocks(text: str) -> str:
    """Rewrite every flat trigger line in `text`. Other lines pass
    through untouched, so a caller can hand us a whole config."""
    out: list[str] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        body = line.lstrip()
        fam = next((f for f in FAMILIES
                    if body.startswith(f + " ") or body.startswith(f + "\t")), None)
        if not fam:
            out.append(line)
            i += 1
            continue

        indent = line[: len(line) - len(body)]
        joined, j = body, i
        while joined.rstrip().endswith("\\"):
            joined = joined.rstrip()[:-1].rstrip()
            j += 1
            if j >= len(lines):
                break
            joined += " " + lines[j].strip()

        rest = joined[len(fam):].strip()
        parts = rest.split(None, 1)
        if not parts:
            out.append(line)
            i += 1
            continue
        # BotShieldTrigger takes no name: it is identified by the
        # <Location> it sits in, not by a word. Everything after the
        # directive is a setting.
        if fam in _NAMELESS:
            name, attrs = "", rest
        else:
            name, attrs = parts[0], (parts[1] if len(parts) > 1 else "")

        # `reset` is a bare positional on the flag/heuristic families.
        bare = []
        while True:
            head = attrs.split(None, 1)
            if head and head[0].lower() == "reset":
                bare.append("BotShieldReset")
                attrs = head[1] if len(head) > 1 else ""
            else:
                break

        pairs = []
        malformed = False
        for arg in _split_args(attrs):
            arg = _unquote(arg)
            # Load triggers compare rather than assign: state>=warm.
            # Split on the first operator so the operator can travel
            # with the value, where a directive name can hold it.
            m = re.match(r"(!?)([A-Za-z][A-Za-z0-9_-]*)(>=|<=|>|<|=)(.*)$", arg)
            if not m:
                malformed = True
                break
            neg, key, op, value = m.groups()
            sep = True
            if op != "=":
                value = op + value
            # The flat form negates by prefixing the key. A directive
            # name cannot start with '!', so it moves to the value.
            if neg:
                value = "!" + value
            # Refuse to guess: anything that is not key=value means the
            # line is not what we think it is, so leave it alone and let
            # Apache complain rather than invent a rule.
            pairs.append((key.lower(), value))
        # `reset` alone is a whole rule: it clears what came before
        # and declares nothing. Requiring a key=value pair here left
        # those lines flat, which the module no longer accepts.
        if malformed or (not pairs and not bare):
            out.append(line)
            i = j + 1
            continue

        out.append(f"{indent}<{fam} {name}>" if name else f"{indent}<{fam}>")
        for b in bare:
            out.append(f"{indent}    {b}")
        for key, value in pairs:
            value = _unquote(value)
            if value == "":
                # ua="" is a match on an absent User-Agent. Without the
                # quotes the block form would read as a valueless line.
                out.append(f'{indent}    {_spell(key):<22}""')
                continue
            if key == "path" and "," in value:
                for entry in (e.strip() for e in value.split(",")):
                    if entry:
                        out.append(f"{indent}    {_spell(key):<22}{entry}")
            else:
                out.append(f"{indent}    {_spell(key):<22}{value}")
        out.append(f"{indent}</{fam}>")
        i = j + 1
    return "\n".join(out)


def block_pattern(family: str, name: str) -> str:
    """Regex matching an entire `<family name> ... </family>` block.

    Tests used to anchor on the one-line spelling of a rule they wanted
    to replace. That text no longer exists in a config, and a pattern
    that matches nothing fails loudly but unhelpfully, so this builds
    the anchor instead of every caller hand-writing a multi-line one.
    """
    return (r"<" + re.escape(family) + r"\s+" + re.escape(name) + r">"
            r"(?:.|\n)*?</" + re.escape(family) + r">")
