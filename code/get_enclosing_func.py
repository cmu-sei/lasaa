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
import sys
import os
import json
import pdb
import pprint
from bisect import bisect_right
from add_line_nums import add_line_nums
stop = pdb.set_trace


def get_enclosing_func(filename, alert_line_num, fb_info):
    filename = os.path.realpath(filename)
    func_boundaries = fb_info["func_bounds"]

    def find_start_and_end():
        ranges = func_boundaries.get(filename)
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

    (start_line, end_line) = find_start_and_end()
    if start_line is None:
        return ""

    with open(filename, 'r') as file:
        contents = file.read()
    lines = add_line_nums(contents, ret_as_line_list=True)

    if end_line - start_line <= 300:
        func_text = ''.join(lines[start_line - 1:end_line])
    else:
        chosen_lines = []
        last_chosen = start_line - 1
        for i in range(start_line, end_line + 1):
            is_chosen = (
                (i - start_line <= 10) or
                (abs(i - alert_line_num) <= 100) or
                (end_line - i <= 3)
            )
            if is_chosen:
                if last_chosen != i - 1:
                    chosen_lines.append("...\n")
                chosen_lines.append(lines[i - 1])  # 1-based indexing for line nums
                last_chosen = i
        func_text = ''.join(chosen_lines)

    return func_text


def load_func_bounds_etc(filename, base_dir):
    """Return dict: realpath(filename) -> sorted list of (start_line, end_line)."""
    with open(filename, 'r') as f:
        raw = json.load(f)

    grouped = {}
    by_name = {}
    for (filename, line_start, line_end, func_name, kind) in raw:
        if base_dir:
            filename = os.path.realpath(os.path.join(base_dir, filename))
        by_name.setdefault(func_name, [])
        by_name[func_name].append((filename, line_start, line_end, func_name, kind))
        if kind in ["function", "method"]:
            grouped.setdefault(filename, []).append((line_start, line_end))

    for ranges in grouped.values():
        ranges.sort()
    return {"func_bounds":grouped, "by_name":by_name}


def main():
    parser = argparse.ArgumentParser(description="Find and return the function enclosing a specified line in a C file.")
    parser.add_argument("filename", type=str, help="C source code file.")
    parser.add_argument("line_num", type=int, help="The line number to examine (1-indexed).")
    parser.add_argument("func_boundaries", type=str, help="Function-boundary JSON file.")
    parser.add_argument("-b", "--base_dir", type=str, help="Project base directory")
    args = parser.parse_args()

    func_boundaries = load_func_bounds(args.func_boundaries, args.base_dir)
    all_files = set(func_boundaries.keys())

    c_file = args.filename
    if args.base_dir:
        c_file = os.path.realpath(c_file)
    if c_file not in all_files:
        sys.stderr.write("Unrecognized filename: " + repr(c_file) + "\n")
        sys.stderr.write("Known filenames:\n")
        pprint.pprint(list(sorted(all_files)), stream=sys.stderr)
        sys.exit(1)

    func_text = get_enclosing_func(args.filename, args.line_num, func_boundaries)
    if not func_text:
        sys.stderr.write("Error: unable to locate function enclosing specified line!\n")
    sys.stdout.write(func_text)


if __name__ == "__main__":
    main()
