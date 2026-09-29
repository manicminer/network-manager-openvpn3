# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal inspection of OpenVPN profile text.

The profile stored in the NetworkManager connection is already normalized by
the import code: every file reference is inlined and inline credentials are
moved into the connection's username/password.
"""

import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class StaticChallenge:
    text: str
    echo: bool


def _directives(text):
    """Yield (name, args) for every directive outside inline <tag> blocks."""
    inline_tag = None
    for raw in text.splitlines():
        line = raw.strip()
        if inline_tag is not None:
            if line == f"</{inline_tag}>":
                inline_tag = None
            continue
        if not line or line[0] in "#;":
            continue
        if line.startswith("<") and line.endswith(">") and not line.startswith("</"):
            inline_tag = line[1:-1]
            yield inline_tag, []
            continue
        try:
            parts = shlex.split(line, comments=False)
        except ValueError:
            parts = line.split()
        yield parts[0], parts[1:]


def needs_user_pass(text):
    return any(name == "auth-user-pass" for name, _ in _directives(text))


def static_challenge(text):
    for name, args in _directives(text):
        if name == "static-challenge" and args:
            echo = len(args) > 1 and args[1] == "1"
            return StaticChallenge(args[0], echo)
    return None


def first_remote(text):
    """Return (host, port) of the first remote, port may be None."""
    for name, args in _directives(text):
        if name == "remote" and args:
            return args[0], (args[1] if len(args) > 1 else None)
    return None
