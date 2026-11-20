# <legal>
# LASAA tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
# TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
# OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see License.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM26-0426
# </legal>
"""The multi-turn query format that ask_gpt.py and ask_claude_aws.py read
with --multi-turn.

A query is a list of turns.  Each turn is a "# ROLE" line (System, User, or
Assistant), a blank line, and the content with every line indented by two
spaces.  Turns are separated by a blank line:

    # User

      What does this function do?

    # Assistant

      It frees the list.

    # User

      Twice?

A blank line inside content may be written empty or as two spaces.  A blank
line followed by an indented line continues the turn; one followed by a
"# ROLE" line ends it.  Blank lines at the start and end of each turn's
content are dropped, as is trailing whitespace on blank lines.

An optional System turn comes first; the others alternate between User and
Assistant, starting and ending with User.

The web UI writes this format itself (lasaa_webui/chat.py), since the UI
doesn't import the pipeline; test_lasaa_webui.py checks the two agree.
"""

import re

ROLES = ("System", "User", "Assistant")
_HEADER_RE = re.compile(r"^# (System|User|Assistant)[ \t]*$")
INDENT = "  "


class FormatError(ValueError):
    pass


def parse(text):
    """Turns of a multi-turn query: a list of {"role", "content"} with roles
    in lowercase ("system", "user", "assistant").  Raises FormatError."""
    turns = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _HEADER_RE.match(line)
        if m:
            turns.append((m.group(1), []))
        elif not line.strip():
            if turns:
                turns[-1][1].append("")
        elif line.startswith(INDENT):
            if not turns:
                raise FormatError(f"line {n}: content before the first '# ROLE' line")
            turns[-1][1].append(line[len(INDENT):])
        else:
            raise FormatError(f"line {n}: not a '# System', '# User', or '# Assistant' "
                              f"line, and not content indented by two spaces: {line[:60]!r}")
    if not turns:
        raise FormatError("no turns (expected a '# User' line)")
    result = []
    for i, (role, lines) in enumerate(turns):
        while lines and not lines[0]:
            lines.pop(0)
        while lines and not lines[-1]:
            lines.pop()
        if not lines:
            raise FormatError(f"turn {i + 1} ({role}) is empty")
        result.append({"role": role.lower(), "content": "\n".join(lines)})
    roles = [t["role"] for t in result]
    body = roles[1:] if roles[0] == "system" else roles
    expected = ["user" if i % 2 == 0 else "assistant" for i in range(len(body))]
    if not body or body != expected or body[-1] != "user":
        raise FormatError("turns must be an optional System turn, then User and Assistant "
                          "turns in alternation, starting and ending with User "
                          f"(got: {', '.join(r.capitalize() for r in roles)})")
    return result


def system_and_messages(turns):
    """(the System turn's content or None, the other turns)."""
    if turns and turns[0]["role"] == "system":
        return turns[0]["content"], turns[1:]
    return None, turns


def format_turns(turns):
    """The text of a multi-turn query for *turns* (the inverse of parse())."""
    parts = []
    for t in turns:
        body = "\n".join(INDENT + line if line.strip() else ""
                         for line in t["content"].strip("\n").split("\n"))
        parts.append(f"# {t['role'].capitalize()}\n\n{body}\n")
    return "\n".join(parts)
