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
"""
Add line numbers to a file.

Usage:
    add_line_numbers.py [input_file] [-o output_file]

If input_file is omitted, reads from stdin.
If -o is omitted, writes to stdout.
"""

import argparse
import sys


def add_line_nums(file_contents, ret_as_line_list=False):
    """
    Takes the full text of a file as a single string, and returns a new string
    where each line (unless it ends with a backslash) has " // Line N" appended,
    with N being the 1-based line number.
    """
    out_lines = []
    # splitlines(True) preserves the line-ending characters
    lines = file_contents.splitlines(keepends=True)
    for idx, line in enumerate(lines, start=1):
        # Separate the line content from its newline(s)
        # so we can re-attach them after appending our marker.
        if line.endswith("\r\n"):
            content, newline = line[:-2], "\r\n"
        elif line.endswith("\n") or line.endswith("\r"):
            content, newline = line[:-1], line[-1]
        else:
            content, newline = line, ""

        # If the content ends with a backslash, do not append the marker
        if content.endswith("\\") or len(content.strip()) == 0 or content.strip().startswith('#'):
            out_lines.append(content + newline)
        else:
            out_lines.append(f"{content} // Line {idx}\n")

    if ret_as_line_list:
        return out_lines
    else:
        return "".join(out_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Add line numbers to a file.",
        epilog="Lines ending with backslash, empty lines, and comment lines are not numbered."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        help="Input file (reads from stdin if omitted)"
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file (writes to stdout if omitted)"
    )

    args = parser.parse_args()

    # Read input
    if args.input_file:
        try:
            with open(args.input_file, "r") as f:
                contents = f.read()
        except FileNotFoundError:
            sys.exit(f"Error: Input file '{args.input_file}' not found.")
        except IOError as e:
            sys.exit(f"Error reading '{args.input_file}': {e}")
    else:
        contents = sys.stdin.read()

    # Process
    result = add_line_nums(contents)

    # Write output
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(result)
        except IOError as e:
            sys.exit(f"Error writing to '{args.output}': {e}")
    else:
        sys.stdout.write(result)


if __name__ == "__main__":
    main()
