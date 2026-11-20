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
"""Import alerts into the LASAA web UI (see web-ui-design.md).

  ./lasaa_webui_import.py --workspace DIR --alerts ALERTS.json --src SRC_DIR [--out OUT_DIR]

Import an existing alerts file and the source tree its paths are relative
to (the -b of adjudicate_alerts.py), and optionally an
adjudicate_alerts.py output directory.  The source tree is frozen into a
snapshot; the output directory is copied and indexed as a run.

The snapshot keeps the C, C++, and Java files (the extensions that the
pipeline's ctags run reads), common build files (Makefile,
CMakeLists.txt, ...), and every file that an alert or trace step names.
--include GLOB adds files; --only GLOB replaces the extension list (the
files the alerts name are still kept).  --fields-for-llm F1,F2,... sets
the alert fields that LASAA runs on this analysis show the LLM (default:
every field but the ID).

--workspace DIR is required: the directory that holds the UI's database,
snapshots, and LASAA output (for example ~/.lasaa-ui).  It is created if
it doesn't exist.

Example (tinykv demo):
  ./lasaa_webui_import.py --workspace ~/.lasaa-ui --alerts ../examples/tinykv/lasaa_demo/out/alerts.json \\
      --src ../examples/tinykv --out ../examples/tinykv/lasaa_demo/lasaa_out

Example (the demo_def_lookup.c dry run, written to /tmp/o):
  ./lasaa_webui_import.py --workspace ~/.lasaa-ui --project demo_def_lookup --alerts demo_def_lookup.alerts.json \\
      --src . --only demo_def_lookup.c --out /tmp/o
"""

import argparse
import sys

from lasaa_webui.importer import run_import
from lasaa_webui.workspace import Workspace


def parse_args(argv):
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--workspace", required=True,
                   help="workspace directory (e.g. ~/.lasaa-ui)")
    p.add_argument("--alerts", required=True, help="LASAA-format alerts file")
    p.add_argument("--src", required=True,
                   help="source tree the alert paths are relative to")
    p.add_argument("--out", help="adjudicate_alerts.py output directory")
    p.add_argument("--project", help="project name (default: basename of --src)")
    p.add_argument("--label", help="label for the snapshot")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="leave paths matching GLOB (relative to --src) out of the snapshot")
    p.add_argument("--include", action="append", default=[], metavar="GLOB",
                   help="also keep paths matching GLOB (relative to --src) in the snapshot")
    p.add_argument("--only", action="append", default=[], metavar="GLOB",
                   help="keep only paths matching GLOB (plus the files the alerts name), "
                        "instead of the source files")
    p.add_argument("--id-field", help="name of the alert ID field (default: guessed)")
    p.add_argument("--fields-for-llm", metavar="F1,F2,...",
                   help="the alert fields that LASAA runs on this analysis show the LLM, "
                        "in order (default: every field but the ID).  Use it to keep "
                        "labels or other fields the LLM shouldn't see out of the prompts")
    p.add_argument("--client", help="LLM client that made the replies "
                                    "(default: guessed from the model name)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        run_import(Workspace(args.workspace), args)
    except ValueError as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
