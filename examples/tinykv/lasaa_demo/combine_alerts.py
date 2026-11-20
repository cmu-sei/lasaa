#!/usr/bin/env python3
"""Combine the LASAA alert files converted from Clang (SARIF) and Cppcheck
(XML) into one alert file whose alerts all have the same fields.

Usage:
    combine_alerts.py OUT.json CLANG.json CPPCHECK.json

Each output alert has: Alert_ID, File, Line, Column, Tool, RuleID, Message,
CWEs (a list), and CodeFlow (a list of {File, Line, Msg}; possibly empty).
Alert_IDs are kept from the converters, so `sarif_to_lasaa.py -u` still
matches the Clang alerts.

Clang's SARIF has no CWE IDs, so CWEs for Clang alerts are filled in from
the checker name (and, for unix.Malloc, the message).
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
import sys

FIELDS = ["Alert_ID", "File", "Line", "Column", "Tool", "RuleID", "Message",
          "CWEs", "CodeFlow"]

CLANG_CWES = {
    "core.NullDereference": ["CWE-476"],
    "core.NonNullParamChecker": ["CWE-476"],
    "core.DivideZero": ["CWE-369"],
    "core.StackAddressEscape": ["CWE-562"],
    "core.UndefinedBinaryOperatorResult": ["CWE-457"],
    "core.uninitialized.Assign": ["CWE-457"],
    "core.uninitialized.Branch": ["CWE-457"],
    "core.uninitialized.UndefReturn": ["CWE-457"],
    "core.CallAndMessage": ["CWE-457"],
    "unix.cstring.NullArg": ["CWE-476"],
    "alpha.unix.Stream": ["CWE-775"],
}

# unix.Malloc covers several kinds of defect; pick by message.
MALLOC_CWES = [
    ("Use of memory after it is freed", ["CWE-416"]),
    ("Attempt to free released memory", ["CWE-415"]),
    ("Potential leak", ["CWE-401"]),
    ("Potential memory leak", ["CWE-401"]),
    ("Argument to free()", ["CWE-590"]),
]


def clang_cwes(rule_id, message):
    if rule_id == "unix.Malloc":
        for prefix, cwes in MALLOC_CWES:
            if message.startswith(prefix):
                return cwes
        return []
    if rule_id == "alpha.unix.Stream" and "never closed" not in message:
        return []
    return CLANG_CWES.get(rule_id, [])


def from_clang(a):
    return {
        "Alert_ID": a["Alert_ID"],
        "File": a["File"],
        "Line": a["Line"],
        "Column": a.get("Column"),
        "Tool": "clang-analyzer",
        "RuleID": a.get("RuleID"),
        "Message": a.get("Message"),
        "CWEs": clang_cwes(a.get("RuleID"), a.get("Message", "")),
        "CodeFlow": a.get("CodeFlow") or [],
    }


def from_cppcheck(a):
    flow = [{"File": loc.get("file"), "Line": loc.get("line"),
             "Msg": loc.get("info", "")}
            for loc in a.get("AdditionalLocations", [])]
    return {
        "Alert_ID": a["Alert_ID"],
        "File": a["File"],
        "Line": a["Line"],
        "Column": a.get("Column"),
        "Tool": "cppcheck",
        "RuleID": a.get("CppcheckID"),
        "Message": a.get("VerboseMessage") or a.get("Message"),
        "CWEs": a.get("CWEs") or [],
        "CodeFlow": flow,
    }


def main(argv):
    if len(argv) != 4:
        sys.exit(__doc__)
    out_path, clang_path, cppcheck_path = argv[1:]
    with open(clang_path) as f:
        alerts = [from_clang(a) for a in json.load(f)]
    with open(cppcheck_path) as f:
        alerts += [from_cppcheck(a) for a in json.load(f)]
    alerts.sort(key=lambda a: (a["File"], a["Line"], a["Tool"]))
    with open(out_path, "w") as f:
        json.dump(alerts, f, indent=2)
        f.write("\n")
    print(f"{out_path}: {len(alerts)} alerts")


if __name__ == "__main__":
    main(sys.argv)
