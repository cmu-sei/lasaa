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
import os
import json

def parse_verdict_line(line):
    """Parse a verdict line and return the verdict value."""
    try:
        data = json.loads(line)
        return data.get("verdict")
    except (json.JSONDecodeError, KeyError):
        pass
    return None

def get_verdict_of_reply_file(filepath, kill_if_missing=False, valid_verdicts=None, ptr_model_name=None):
    if valid_verdicts is None:
        valid_verdicts = ("true", "false", "dependent", "uncertain")
    # Read the file and find the last verdict line
    verdict = None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if ptr_model_name and lines:
            if lines[0].startswith("# Model: "):
                line0 = lines[0][len("# Model: "):]
                model_name_end = (line0.replace("#",",") + ",").index(",")
                ptr_model_name[0] = line0[:model_name_end].strip()
            
        # Find the last line that contains '{"verdict":'
        for line in reversed(lines):
            if line.__contains__('{"verdict":'):
                if "}" not in line:
                    break
                line = line[line.index('{"verdict":'):] # Delete text before '{"verdict":'
                line = line[:line.rindex('}')+1] # Delete text after '}'
                line = line.strip()#.replace(" ", "")
                verdict = parse_verdict_line(line)
                break
        has_bad_verdict = verdict==None or (valid_verdicts != '*' and verdict not in valid_verdicts)
        if kill_if_missing and has_bad_verdict:
            os.remove(filepath)
    except (IOError, UnicodeDecodeError):
        pass
    if valid_verdicts != '*' and verdict not in valid_verdicts:
        verdict = "missing"
    return verdict
