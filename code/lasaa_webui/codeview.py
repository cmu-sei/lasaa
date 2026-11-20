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
"""Source code for display: safe path lookup, highlighting, function ranges.

Lines are split on "\\n" only, as add_line_nums.split_lines() does, so line
numbers match the alerts, ctags, and git even when the code contains form
feeds or other characters that str.splitlines() treats as line breaks.
"""

import bisect
import html
import json
import os

from pygments import lex
from pygments.formatters import HtmlFormatter
from pygments.lexers import TextLexer, get_lexer_for_filename
from pygments.token import STANDARD_TYPES
from pygments.util import ClassNotFound

FUNC_KINDS = ("function", "method")
DECL_KINDS = ("struct", "union", "enum", "class", "macro", "typedef", "variable",
              "externvar", "prototype")
CONTEXT_LINES = 2
LONG_RANGE = 400      # longer ranges are shown as a window around the lines of interest
WINDOW = 40


def safe_path(src, rel):
    """Return the real path of *rel* inside *src*, or None if it's outside or not a file."""
    if not rel or "\0" in rel:
        return None
    root = os.path.realpath(src)
    full = os.path.realpath(os.path.join(root, rel))
    if not full.startswith(root + os.sep) or not os.path.isfile(full):
        return None
    return full


def split_lines(text):
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _css_class(ttype):
    while ttype not in STANDARD_TYPES:
        ttype = ttype.parent
    return STANDARD_TYPES[ttype]


def highlight(path, text):
    """Return one HTML string per line of *text*."""
    lines = split_lines(text)
    try:
        lexer = get_lexer_for_filename(path, stripnl=False, stripall=False, ensurenl=True)
    except ClassNotFound:
        lexer = TextLexer(stripnl=False, ensurenl=True)
    # Pygments turns "\r" into "\n"; drop it so the line count is unchanged.
    joined = "\n".join(line.replace("\r", "") for line in lines) + "\n"
    out, cur = [], []
    for ttype, value in lex(joined, lexer):
        parts = value.split("\n")
        cls = _css_class(ttype)
        for i, part in enumerate(parts):
            if i > 0:
                out.append("".join(cur))
                cur = []
            if part:
                esc = html.escape(part, quote=False)
                cur.append(f'<span class="{cls}">{esc}</span>' if cls else esc)
    if cur:
        out.append("".join(cur))
    if len(out) != len(lines):
        # Shouldn't happen, but never show shifted line numbers.
        return [html.escape(line, quote=False) for line in lines]
    return out


def pygments_css():
    light = HtmlFormatter(style="default").get_style_defs(".code")
    dark = HtmlFormatter(style="monokai").get_style_defs(".code")
    return (light + "\n@media (prefers-color-scheme: dark) {\n" + dark + "\n}\n"
            ".code { background: transparent !important; }\n")


class FuncBounds:
    """func_bounds.json: [[file, start, end, name, kind], ...]."""

    def __init__(self, path):
        self.funcs, self.decls = {}, {}
        try:
            with open(path, encoding="utf-8") as f:
                rows = json.load(f)
        except (OSError, json.JSONDecodeError):
            rows = []
        for row in rows:
            file, start, end, name, kind = row[:5]
            target = self.funcs if kind in FUNC_KINDS else self.decls if kind in DECL_KINDS else None
            if target is not None:
                target.setdefault(os.path.normpath(file), []).append((start, end, name, kind))
        for d in (self.funcs, self.decls):
            for v in d.values():
                v.sort()

    def enclosing(self, file, line):
        """Return (start, end, name, kind) of what contains *line*, or None."""
        file = os.path.normpath(file)
        ranges = self.funcs.get(file, [])
        idx = bisect.bisect_right(ranges, (line, float("inf"))) - 1
        while idx >= 0:
            if ranges[idx][1] >= line:
                return ranges[idx]
            idx -= 1
        best = None
        for r in self.decls.get(file, []):
            if r[0] > line:
                break
            if r[1] >= line and (best is None or r[1] - r[0] < best[1] - best[0]):
                best = r
        return best


def pane(src, file, lines_of_interest, fb, full=False):
    """Build one code pane: a file region around *lines_of_interest*.

    Returns None if the file isn't in the snapshot, else a dict with file,
    title, rows [(line number or None for a gap, html)], and truncated.
    """
    path = safe_path(src, file)
    if path is None:
        return None
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        text = f.read()
    hl = highlight(path, text)
    n = len(hl)
    focus = sorted({ln for ln in lines_of_interest if 1 <= ln <= n}) or [1]
    title = file
    if full:
        spans = [(1, n)]
    else:
        enc = fb.enclosing(file, focus[0])
        if enc:
            start, end = enc[0], enc[1]
            title = f"{file} — {enc[2]} ({enc[3]})"
        else:
            start, end = focus[0] - 10, focus[0] + 10
        start = min([start] + focus) - CONTEXT_LINES
        end = max([end] + focus) + CONTEXT_LINES
        start, end = max(1, start), min(n, end)
        if end - start > LONG_RANGE:
            spans = []
            for ln in focus:
                lo, hi = max(start, ln - WINDOW), min(end, ln + WINDOW)
                if spans and lo <= spans[-1][1] + 1:
                    spans[-1] = (spans[-1][0], max(spans[-1][1], hi))
                else:
                    spans.append((lo, hi))
        else:
            spans = [(start, end)]
    rows = []
    shown_to = 0
    for lo, hi in spans:
        if lo > shown_to + 1:
            rows.append((None, f"lines {shown_to + 1}–{lo - 1} not shown"))
        rows.extend((ln, hl[ln - 1]) for ln in range(lo, hi + 1))
        shown_to = hi
    if shown_to < n:
        rows.append((None, f"lines {shown_to + 1}–{n} not shown"))
    return {"file": file, "title": title, "rows": rows, "nlines": n,
            "range": (spans[0][0], spans[-1][1])}
