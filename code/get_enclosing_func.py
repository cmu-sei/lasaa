#!/usr/bin/env python3
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

import argparse
import functools
import sys
import os
import json
import pdb
import pprint
from bisect import bisect_right
from add_line_nums import add_line_nums
stop = pdb.set_trace


def find_preceding_comment_start(lines, start_line):
    """Return the 1-based start line of a short comment before start_line."""
    max_comment_lines = 100
    start_line_idx = start_line - 1 # Change from 1-based numbering to 0-based numbering.
    comment_end_idx = start_line_idx - 1
    if comment_end_idx < 0:
        return start_line

    if lines[comment_end_idx].strip() == "":
        comment_end_idx -= 1
        if comment_end_idx < 0 or lines[comment_end_idx].strip() == "":
            return start_line

    stripped = lines[comment_end_idx].lstrip()
    if stripped.startswith("//"):
        comment_start_idx = comment_end_idx
        while (
            comment_start_idx > 0 and
            comment_end_idx - comment_start_idx + 1 < max_comment_lines and
            lines[comment_start_idx - 1].lstrip().startswith("//")
        ):
            comment_start_idx -= 1
        if comment_end_idx - comment_start_idx + 1 < max_comment_lines:
            return comment_start_idx + 1
        return start_line

    if "*/" not in lines[comment_end_idx]:
        return start_line

    comment_start_idx = comment_end_idx
    while (
        comment_start_idx >= 0 and
        comment_end_idx - comment_start_idx + 1 < max_comment_lines and
        "/*" not in lines[comment_start_idx]
    ):
        comment_start_idx -= 1

    if comment_start_idx < 0:
        return start_line
    if comment_end_idx - comment_start_idx + 1 >= max_comment_lines:
        return start_line
    before_open_comment = lines[comment_start_idx].split("/*", 1)[0]
    if before_open_comment.strip() != "":
        return start_line
    return comment_start_idx + 1


def get_enclosing_func_range(filename, alert_line_num, fb_info):
    """Return (start_line, end_line) of the function containing *alert_line_num*.

    Returns (None, None) if no function in *fb_info* contains that line.  Two
    locations that yield the same range are inside the same function, even
    though get_enclosing_func() may render them as differently elided
    snippets for a long function.
    """
    ranges = fb_info["func_bounds"].get(cached_realpath(filename))
    if not ranges:
        return (None, None)
    # Largest index whose start_line <= alert_line_num.
    idx = bisect_right(ranges, (alert_line_num, float('inf'))) - 1
    # Walk back in case of overlapping/nested ranges; for disjoint ranges
    # (typical C code) this terminates on the first iteration.
    while idx >= 0:
        start_line, end_line = ranges[idx]
        if end_line >= alert_line_num:
            return (start_line, end_line)
        idx -= 1
    return (None, None)


def get_enclosing_func(filename, alert_line_num, fb_info):
    filename = cached_realpath(filename)
    (start_line, end_line) = get_enclosing_func_range(
        filename, alert_line_num, fb_info)
    if start_line is None:
        return ""
    return render_range(filename, start_line, end_line, alert_line_num, "Function")


# Source files don't move during a run, and resolving a path takes a system
# call per component, so each file's realpath is looked up once.
cached_realpath = functools.lru_cache(maxsize=65536)(os.path.realpath)


def numbered_lines(filename):
    """The lines of *filename* with line-number annotations (add_line_nums()),
    cached while the file is unchanged, since many alerts share a file."""
    st = os.stat(filename)
    return _numbered_lines(filename, st.st_mtime_ns, st.st_size)


@functools.lru_cache(maxsize=64)
def _numbered_lines(filename, mtime_ns, size):
    with open(filename, 'r', encoding="utf-8", errors="replace") as file:
        contents = file.read()
    return tuple(add_line_nums(contents, ret_as_line_list=True))


def render_range(filename, start_line, end_line, alert_line_num, what):
    """Return lines start_line..end_line of filename (with line-number
    annotations and any preceding comment), eliding the middle of a range over
    2000 lines while keeping the part around alert_line_num.
    """
    lines = numbered_lines(filename)

    if end_line - start_line <= 2000:
        snippet_start_line = find_preceding_comment_start(lines, start_line)
        func_text = ''.join(lines[snippet_start_line - 1:end_line])
    else:
        print(f"Warning: {what} on lines {start_line}--{end_line} of {filename} exceeds max line count.")
        chosen_lines = []
        last_chosen = start_line - 1
        for i in range(start_line, end_line + 1):
            is_chosen = (
                (i - start_line <= 200) or
                (abs(i - alert_line_num) <= 1000) or
                (end_line - i <= 50)
            )
            if is_chosen:
                if last_chosen != i - 1:
                    chosen_lines.append("...\n")
                chosen_lines.append(lines[i - 1])  # 1-based indexing for line nums
                last_chosen = i
        func_text = ''.join(chosen_lines)

    return func_text


def get_enclosing_decl_range(filename, line_num, fb_info):
    """Return (start_line, end_line) of the innermost non-function
    declaration (macro, type, or global/prototype declaration; see
    DECL_KINDS) containing line_num, or (None, None) if there is none.

    This is a fallback for lines outside any function.
    """
    best = (None, None)
    for (start_line, end_line) in fb_info.get("decl_bounds", {}).get(
            cached_realpath(filename), ()):
        if start_line > line_num:
            break
        if end_line >= line_num and (
                best[0] is None or end_line - start_line < best[1] - best[0]):
            best = (start_line, end_line)
    return best


def get_enclosing_decl(filename, line_num, fb_info):
    """Like get_enclosing_func(), but for get_enclosing_decl_range()."""
    filename = cached_realpath(filename)
    (start_line, end_line) = get_enclosing_decl_range(filename, line_num, fb_info)
    if start_line is None:
        return ""
    return render_range(filename, start_line, end_line, line_num, "Declaration")


AGGREGATE_KINDS = ("struct", "union", "enum", "class")
# Kinds that get_enclosing_decl_range() considers.  Members and enumerators are
# left out (their aggregate covers them), as is "namespace" (it would cover
# everything in it).
DECL_KINDS = AGGREGATE_KINDS + ("macro", "typedef", "variable", "externvar", "prototype")


def extend_typedefs_to_aggregates(raw):
    """Return raw with each typedef's range widened to include the aggregate
    declared along with it.

    For "typedef struct _foo { ... } foo_t;", ctags puts the typedef tag
    (foo_t) only on the closing line, so showing its range alone would show
    just "} foo_t;".  The struct tag (_foo, or "__anon..." if unnamed) covers
    the whole declaration and ends on that same line; if several aggregates
    end there (e.g., nested ones), the outermost one is used.
    """
    agg_start = {}
    for (filename, line_start, line_end, _, kind) in raw:
        if kind in AGGREGATE_KINDS and line_start < line_end:
            key = (filename, line_end)
            agg_start[key] = min(line_start, agg_start.get(key, line_start))
    result = []
    for row in raw:
        (filename, line_start, line_end, func_name, kind) = row
        if kind == "typedef" and line_start == line_end:
            line_start = agg_start.get((filename, line_end), line_start)
            row = (filename, line_start, line_end, func_name, kind)
        result.append(row)
    return result


def load_func_bounds_etc(filename, base_dir):
    """Return a dict with keys:
      "func_bounds": realpath(filename) -> sorted list of function (start_line, end_line)
      "decl_bounds": same, for the declaration kinds in DECL_KINDS
      "by_name": name -> list of (filename, line_start, line_end, name, kind)
    """
    with open(filename, 'r') as f:
        raw = json.load(f)

    grouped = {}
    decl_grouped = {}
    by_name = {}
    real = {}    # realpath() of each file once, not once per entry
    for (filename, line_start, line_end, func_name, kind) in extend_typedefs_to_aggregates(raw):
        if base_dir:
            if filename not in real:
                real[filename] = os.path.realpath(os.path.join(base_dir, filename))
            filename = real[filename]
        by_name.setdefault(func_name, [])
        by_name[func_name].append((filename, line_start, line_end, func_name, kind))
        if kind in ["function", "method"]:
            grouped.setdefault(filename, []).append((line_start, line_end))
        elif kind in DECL_KINDS:
            decl_grouped.setdefault(filename, []).append((line_start, line_end))

    for ranges in list(grouped.values()) + list(decl_grouped.values()):
        ranges.sort()
    return {"func_bounds":grouped, "decl_bounds":decl_grouped, "by_name":by_name}


def main():
    parser = argparse.ArgumentParser(description="Find and return the function enclosing a specified line in a C file.")
    parser.add_argument("filename", type=str, help="C source code file.")
    parser.add_argument("line_num", type=int, help="The line number to examine (1-indexed).")
    parser.add_argument("func_boundaries", type=str, help="Function-boundary JSON file.")
    parser.add_argument("-b", "--base_dir", type=str, required=True, help="Project base directory")
    args = parser.parse_args()

    func_bounds_db = load_func_bounds_etc(args.func_boundaries, args.base_dir)
    all_files = set(func_bounds_db["func_bounds"].keys())

    c_file = args.filename
    if args.base_dir:
        c_file = os.path.realpath(c_file)
    if c_file not in all_files:
        sys.stderr.write("Unrecognized filename: " + repr(c_file) + "\n")
        sys.stderr.write("Known filenames:\n")
        pprint.pprint(list(sorted(all_files)), stream=sys.stderr)
        sys.exit(1)

    func_text = get_enclosing_func(args.filename, args.line_num, func_bounds_db)
    if not func_text:
        sys.stderr.write("Error: unable to locate function enclosing specified line!\n")
    sys.stdout.write(func_text)


if __name__ == "__main__":
    main()
