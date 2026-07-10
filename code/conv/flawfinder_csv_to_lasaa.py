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

import csv
import json
import sys
import hashlib

def main():
    if len(sys.argv) != 4 or sys.argv[2] != "-o":
        print("Usage: ./flawfinder_csv_to_lasaa.py <input.csv> -o <output.json>", file=sys.stderr)
        sys.exit(1)

    input_filename = sys.argv[1]
    output_filename = sys.argv[3]

    with open(input_filename, "r", newline="", encoding="utf-8-sig") as alert_file:
        input_alert_list = list(csv.DictReader(alert_file))

    output_alert_list = []
    for input_alert in input_alert_list:
        for fld in ["ToolVersion", "RuleId", "HelpUri"]:
            if fld in input_alert:
                del input_alert[fld]
        alert_id = hashlib.sha256(repr(input_alert).encode('utf-8')).hexdigest()[:24]
        output_alert = {"Alert_ID": alert_id}
        output_alert.update(input_alert)
        output_alert_list.append(output_alert)

    with open(output_filename, "w") as outf:
        json.dump(output_alert_list, outf, indent=2)
        outf.write("\n")

if __name__ == "__main__":
    main()
