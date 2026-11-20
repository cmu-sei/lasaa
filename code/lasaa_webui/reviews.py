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
"""Manual reviews: append-only rows in the review table.

The current review of an alert is its latest row, unless that row is a
"clear".  Changing a review adds a row, so the history keeps every earlier
verdict and note:

- A new verdict is a "confirm" if it equals the LLM verdict on screen, else
  an "override".  It is blind if blind mode was on and the alert had never
  been reviewed (so the reviewer hadn't seen the LLM's answer).
- Changing only the note or the dependency line is a "note-only" row that
  keeps the verdict, its blind flag, and the run it was compared with.
"""

from . import db

VERDICTS = ("true", "false", "dependent", "uncertain")
MAX_NOTE = 20000
MAX_DEP = 300


def _norm(text, limit):
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    return text[:limit] or None


def current_all(conn, analysis_id):
    """{alert_id: row} of the current reviews in an analysis."""
    rows = conn.execute(
        "SELECT r.* FROM review r JOIN (SELECT alert_id, max(review_id) AS m FROM review "
        "WHERE analysis_id=? GROUP BY alert_id) x ON r.review_id = x.m",
        (str(analysis_id),)).fetchall()
    return {r["alert_id"]: r for r in rows if r["action"] != "clear"}


def current(conn, analysis_id, alert_id):
    row = conn.execute("SELECT * FROM review WHERE analysis_id=? AND alert_id=? "
                       "ORDER BY review_id DESC LIMIT 1",
                       (str(analysis_id), alert_id)).fetchone()
    return row if row is not None and row["action"] != "clear" else None


def history(conn, analysis_id, alert_id):
    """All of an alert's review rows, newest first."""
    return conn.execute("SELECT * FROM review WHERE analysis_id=? AND alert_id=? "
                        "ORDER BY review_id DESC", (str(analysis_id), alert_id)).fetchall()


def _insert(conn, analysis_id, alert_id, verdict, action, note, dep, run_id, blind):
    conn.execute(
        "INSERT INTO review(analysis_id, alert_id, verdict, action, note, dep_on_line, "
        "shown_run_id, blind, reviewer, created_at) VALUES (?,?,?,?,?,?,?,?,'',?)",
        (str(analysis_id), alert_id, verdict, action, note, dep,
         None if run_id is None else str(run_id), int(bool(blind)), db.now()))
    conn.commit()


def save(conn, analysis_id, alert_id, verdict, llm_verdict, run_id, blind_mode,
         note=None, dep_on_line=None):
    """Record a review and return its action, or None if nothing changed.

    *note* and *dep_on_line* of None keep the current ones.  *llm_verdict* is
    the verdict of run *run_id*, the one on screen (None if there is none).
    """
    if verdict not in VERDICTS:
        raise ValueError(f"bad verdict {verdict!r}")
    cur = current(conn, analysis_id, alert_id)
    note = _norm(note, MAX_NOTE) if note is not None else (cur["note"] if cur else None)
    dep = (_norm(dep_on_line, MAX_DEP) if dep_on_line is not None
           else (cur["dep_on_line"] if cur else None))
    if cur is not None and cur["verdict"] == verdict:
        if (cur["note"], cur["dep_on_line"]) == (note, dep):
            return None
        _insert(conn, analysis_id, alert_id, verdict, "note-only", note, dep,
                cur["shown_run_id"], cur["blind"])
        return "note-only"
    action = "confirm" if verdict == llm_verdict else "override"
    blind = blind_mode and not history(conn, analysis_id, alert_id)
    _insert(conn, analysis_id, alert_id, verdict, action, note, dep, run_id, blind)
    return action


def clear(conn, analysis_id, alert_id):
    """Make the alert unreviewed again.  Returns False if it already was."""
    if current(conn, analysis_id, alert_id) is None:
        return False
    _insert(conn, analysis_id, alert_id, "", "clear", None, None, None, False)
    return True
