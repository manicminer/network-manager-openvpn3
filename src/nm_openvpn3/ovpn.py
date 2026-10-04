# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal inspection of OpenVPN profile text.

The profile stored in the NetworkManager connection is already normalized by
the import code: every file reference is inlined, inline credentials are
moved into the connection's username/password, and comments are gone.

Comment lines are still skipped below.  A connection written by an older
build of this plugin still has them, and this only reads profiles -- being
able to read one is not a reason to rewrite it.
"""

import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class StaticChallenge:
    text: str
    echo: bool

# <connection> holds options, not a payload: a client profile may well keep
# its only remote (and its credentials) in there.  Everything else between
# angle brackets -- <ca>, <key>, <pkcs12> ... -- is opaque content whose lines
# are not directives.  Keep this in step with option_scopes[] in
# properties/ovpn-import.c.
OPTION_SCOPES = ("connection",)


def _directives(text):
    """Yield (name, args) for every directive, inline <tag> payloads excluded.

    An option scope such as <connection> is reported as a block of its own and
    its contents are then yielded as the directives they are.
    """
    inline_tag = None
    scope = None
    for raw in text.splitlines():
        line = raw.strip()
        if inline_tag is not None:
            if line == f"</{inline_tag}>":
                inline_tag = None
            continue
        if not line or line[0] in "#;":
            continue
        if line.startswith("</") and line.endswith(">") and line[2:-1] == scope:
            scope = None
            continue
        if line.startswith("<") and line.endswith(">") and not line.startswith("</"):
            tag = line[1:-1]
            if tag in OPTION_SCOPES:
                scope = tag
            else:
                inline_tag = tag
            yield tag, []
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
