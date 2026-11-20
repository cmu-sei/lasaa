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
"""Rendering untrusted text (LLM output, alert messages) as HTML."""

import json
import re

from markdown_it import MarkdownIt
from markupsafe import Markup, escape

from .outdir import split_reasoning

ALLOWED_SCHEMES = ("http:", "https:", "vscode:")

_md = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False})
_md.enable(["table", "strikethrough"])


def _validate_link(url):
    u = re.sub(r"[\x00-\x20]", "", url).lower()
    return u.startswith(ALLOWED_SCHEMES) or u.startswith("#")


_md.validateLink = _validate_link


def markdown(text):
    """Render markdown with raw HTML disabled and only http/https/vscode links."""
    return Markup(_md.render(text or ""))


def _is_json_tail(line):
    s = line.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return False
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return False
    return isinstance(obj, dict) and bool({"verdict", "need_defs"} & obj.keys())


def answer_parts(body):
    """Split a header-less reply into (reasoning, answer without its JSON tail).

    The tail is the {"verdict": ...} and {"need_defs": [...]} objects at the
    end, on lines of their own or at the end of the last sentence (sometimes
    in bold).
    """
    reasoning, answer = split_reasoning(body or "")
    lines = answer.rstrip("\n").split("\n")
    while lines:
        if _is_json_tail(lines[-1]) or not lines[-1].strip():
            lines.pop()
            continue
        last = lines[-1]
        start = max(last.rfind('{"verdict"'), last.rfind('{"need_defs"'))
        if start > 0 and _is_json_tail(last[start:].rstrip().rstrip("*_`")):
            lines[-1] = last[:start].rstrip().rstrip("*_`").rstrip()
            continue
        break
    return reasoning, "\n".join(lines)


_WBR_AT = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[_./:-])(?=.)")


def wbr(text):
    """Escape *text* and allow line breaks in long identifiers (such as rule
    names) between CamelCase words and after _ . / : -.  <wbr> marks a break
    opportunity without adding a character, so copying and searching the
    text still work."""
    return Markup("<wbr>").join(escape(part) for part in _WBR_AT.split(text or ""))


def wbr_path(text):
    """Like wbr(), but for a file path: line breaks only after each /."""
    return Markup("/<wbr>").join(escape(part) for part in (text or "").split("/"))
