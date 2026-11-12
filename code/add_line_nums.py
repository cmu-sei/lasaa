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


def split_lines(file_contents):
    """Split *file_contents* into lines at "\n" only, keeping line endings.

    We deliberately avoid str.splitlines(), which also breaks on form feed
    (\x0c), vertical tab (\x0b), \x1c-\x1e, NEL (\x85), and U+2028/U+2029.
    Real source files contain some of those: ImageMagick, for instance, uses
    ASCII form feeds as section separators.  Counting them as line breaks makes
    our line numbers disagree with ctags, git, sed, wc, and the numbers the
    annotator recorded, which silently shifts both the flagged line reported to
    the LLM and the extracted enclosing-function body.
    """
    parts = file_contents.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1] != "":
        lines.append(parts[-1])
    return lines


def add_line_nums(file_contents, ret_as_line_list=False):
    """
    Takes the full text of a file as a single string, and returns a new string
    where each line (unless it ends with a backslash) has " // Line N" appended,
    with N being the 1-based line number.

    Lines are delimited by "\n" only; see split_lines().
    """
    out_lines = []
    lines = split_lines(file_contents)
    for idx, line in enumerate(lines, start=1):
        # Separate the line content from its newline(s)
        # so we can re-attach them after appending our marker.
        if line.endswith("\r\n"):
            content, newline = line[:-2], "\r\n"
        elif line.endswith("\n"):
            content, newline = line[:-1], "\n"
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
