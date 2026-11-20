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
"""Exports of an analysis's alerts with their LLM and manual verdicts.

adjudications_json() writes the adjudicate_alerts.py adjudications.json
format, so conv/sarif_to_lasaa.py -u can read it, plus "adjudicator_type".
For a manual verdict, "explanation" is the reviewer's note (or, for a
confirm without a note, the LLM's explanation), and the LLM's verdict and
explanation move to "llm_verdict" and "llm_explanation".
"""

import csv
import io
import json

CSV_COLUMNS = ["Alert_ID", "Tool", "File", "Line", "Rule", "CWEs", "Severity", "Message",
               "verdict", "adjudicator_type", "llm_verdict", "trial_split", "review_action",
               "blind_review", "note", "dep_on_line", "reviewed_at", "llm_explanation"]


def entry(d, review):
    """The exported facts about one alert row *d* (from the alert list)."""
    llm_expl = (d.get("explanation") or "").strip()
    out = {"llm_verdict": d["verdict"], "llm_explanation": llm_expl,
           "note": review["note"] if review else None}
    if review is not None:
        out.update(verdict=review["verdict"], adjudicator_type="manual",
                   explanation=(review["note"] or
                                (llm_expl if review["verdict"] == d["verdict"] else "")))
    elif d["verdict"]:
        out.update(verdict=d["verdict"], adjudicator_type="LLM", explanation=llm_expl)
    else:
        out.update(verdict=None, adjudicator_type=None, explanation="")
    return out


def adjudications_json(rows, reviews, id_field):
    """JSON text: one entry per alert with an LLM or manual verdict."""
    out = []
    for d in rows:
        review = reviews.get(d["alert_id"])
        e = entry(d, review)
        if e["verdict"] is None:
            continue
        item = {id_field: d["basename"], "verdict": e["verdict"],
                "adjudicator_type": e["adjudicator_type"], "CWEs": ", ".join(d["cwes"]),
                "explanation": e["explanation"]}
        if review is not None:
            item.update(llm_verdict=e["llm_verdict"], llm_explanation=e["llm_explanation"])
            if review["dep_on_line"]:
                item["dep_on_line"] = review["dep_on_line"]
        out.append(item)
    return json.dumps(out, indent=2) + "\n"


def _cell(v):
    """Keep spreadsheets from running LLM or alert text as a formula."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return "" if v is None else v


def adjudications_csv(rows, reviews):
    """CSV text: one row per alert, with full explanations."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for d in rows:
        review = reviews.get(d["alert_id"])
        e = entry(d, review)
        w.writerow([_cell(v) for v in (
            d["alert_id"], d["tool"], d["file"], d["line"], d["rule"], ", ".join(d["cwes"]),
            d["severity"], d["message"], e["verdict"], e["adjudicator_type"],
            e["llm_verdict"], d["split_text"], review["action"] if review else None,
            (1 if review["blind"] else 0) if review else None, e["note"],
            review["dep_on_line"] if review else None,
            review["created_at"] if review else None, e["llm_explanation"])])
    return buf.getvalue()
