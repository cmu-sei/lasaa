#!/usr/bin/env python3
"""Compare LASAA's verdicts with the ground truth for the tinykv demo.

Usage:
    score.py OUT_DIR/adjudications.json [lasaa_demo/ground_truth.json]

Prints a confusion table and the two numbers that matter for triage (LASAA
discards only the alerts it adjudicates `false`):
  - false positives filtered: ground-truth-false alerts adjudicated `false`
  - flaws lost: ground-truth true/dependent alerts adjudicated `false`
"""

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

import json
import os
import sys

VERDICTS = ["true", "dependent", "false", "uncertain"]


def main(argv):
    if len(argv) not in (2, 3):
        sys.exit(__doc__)
    gt_path = argv[2] if len(argv) == 3 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ground_truth.json")
    with open(argv[1]) as f:
        adj = {a["Alert_ID"]: a["verdict"] for a in json.load(f)}
    with open(gt_path) as f:
        gt = json.load(f)

    table = {(g, v): 0 for g in VERDICTS[:3] for v in VERDICTS + ["missing"]}
    wrong = []
    for g in gt:
        v = adj.get(g["Alert_ID"], "missing")
        table[(g["Verdict"], v)] += 1
        lost = g["Verdict"] != "false" and v == "false"
        kept_fp = g["Verdict"] == "false" and v not in ("false", "missing")
        if lost or kept_fp:
            wrong.append((g, v))

    cols = VERDICTS + ["missing"]
    label = "truth \\ LASAA"
    print(f"{label:<14}" + "".join(f"{c:>11}" for c in cols))
    for g in VERDICTS[:3]:
        print(f"{g:<14}" + "".join(f"{table[(g, c)]:>11}" for c in cols))

    n_fp = sum(1 for g in gt if g["Verdict"] == "false")
    n_real = len(gt) - n_fp
    filtered = table[("false", "false")]
    lost = table[("true", "false")] + table[("dependent", "false")]
    print(f"\nFalse positives filtered: {filtered} of {n_fp}")
    print(f"Flaws lost (real alerts adjudicated false): {lost} of {n_real}")
    if wrong:
        print("\nAlerts to look at:")
        for g, v in wrong:
            short_id = g['Alert_ID'][0:6] + "..." + g['Alert_ID'][-3:-1]
            print(f"  [Alert {short_id}] "
                  f"{g['File']}:{g['Line']} {g['Tool']} {g['RuleID']}: "
                  f"truth={g['Verdict']}, LASAA={v}")


if __name__ == "__main__":
    main(sys.argv)
