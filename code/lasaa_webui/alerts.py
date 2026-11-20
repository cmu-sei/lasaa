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
"""Reading LASAA-format alert files and pulling out the fields the UI shows."""

import gzip
import json
import os
import re

from .outdir import sanitize_alert_id

ID_FIELDS = ("Alert_ID", "Fused_Alert_ID", "Issue ID", "ID", "id")
RULE_FIELDS = ("RuleID", "Rule", "RuleName", "Checker", "Rule ID", "CppcheckID")
MESSAGE_FIELDS = ("Message", "Issue Text", "Msg", "message")
SEVERITY_FIELDS = ("Severity", "Issue Priority", "Level", "severity")
CWE_FIELDS = ("CWEs", "CWE(s)", "CWE")
# The pipeline's default --more-ctx-fields, plus Trace.
CTX_FIELDS = ("Traces", "CodeFlow", "MoreContext", "AdditionalLocations", "Trace")


def load_alert_file(path):
    """Return the list of alerts in a LASAA JSON (or .json.gz) file."""
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("alerts")
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of alerts")
    for a in data:
        if not isinstance(a, dict):
            raise ValueError(f"{path}: fused alerts ([ID, [subalerts]]) aren't supported yet")
    return data


def guess_id_field(alerts, explicit=None):
    if explicit:
        return explicit
    env = os.environ.get("LASAA_ALERT_ID_FIELD")
    if env:
        return env
    keys = alerts[0].keys() if alerts else ()
    for f in ID_FIELDS:
        if f in keys:
            return f
    for k in keys:
        if re.search(r'(?<![a-z0-9])id(?![a-z0-9])', k.lower()):
            return k
    raise ValueError("can't tell which field is the alert ID; use --id-field")


def first(alert, fields):
    for f in fields:
        v = alert.get(f)
        if v not in (None, ""):
            return v
    return None


def cwes_of(alert):
    v = first(alert, CWE_FIELDS)
    if v is None:
        return []
    items = v if isinstance(v, list) else re.split(r'[,;\s]+', str(v))
    out = []
    for item in items:
        item = str(item).strip()
        if not item:
            continue
        if re.fullmatch(r'[0-9]+', item):
            item = "CWE-" + item
        out.append(item)
    return out


def trace_steps(alert):
    """Return [(field, step number, {File, Line, Msg})] for the context fields.
    A step may also use lowercase keys, and "info" for the message, as in
    cppcheck's AdditionalLocations."""
    steps = []
    for field in CTX_FIELDS:
        val = alert.get(field)
        if not isinstance(val, list):
            continue
        items = []
        for elem in val:
            items.extend(elem if isinstance(elem, list) else [elem])
        n = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            file = item.get("File") or item.get("file")
            line = item.get("Line") if item.get("Line") is not None else item.get("line")
            if file and line is not None:
                n += 1
                msg = item.get("Msg") or item.get("msg") or item.get("info")
                steps.append((field, n, {"File": file, "Line": line, "Msg": msg}))
    return steps


def summarize(alert, id_field):
    """Return the alert-table columns for one alert."""
    alert_id = str(alert[id_field])
    line = alert.get("Line")
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = None
    return {
        "alert_id": alert_id,
        "basename": sanitize_alert_id(alert_id),
        "tool": alert.get("Tool"),
        "file": first(alert, ("File", "Path")),
        "line": line,
        "cwes": cwes_of(alert),
        "rule": first(alert, RULE_FIELDS),
        "message": first(alert, MESSAGE_FIELDS),
        "severity": first(alert, SEVERITY_FIELDS),
    }
