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
"""Turning pipeline output files into database rows.

Pages read only the database.  The indexer reads a run's output directory,
stores every query and reply file in llm_file (once per output directory,
since they're shared by every run over it), and writes one run_result per
alert.  run_result.phases is a JSON list of:

  {"kind": "orig" | "augdef.R" | "lre" | "uncert", "hash": H, "query": NAME,
   "trials": [{"trial": K, "file": NAME, "verdict": V}, ...]}

listing only the trials the final answer used.
"""

import collections
import json
import os

from . import db, outdir

# What a missing key in a # opts= line means: the pipeline records LookupMax
# always, but TellUnfound and simp_maj only when they are on.
# explain_uncertain is recorded only for uncertain alerts, so it isn't
# compared.
OPTS_ABSENT = {"TellUnfound": False, "simp_maj": False}
OPTS_IGNORED = ("explain_uncertain",)


def opts_diff(alert_opts, run_opts):
    """How *alert_opts* (an alert's # opts=) differ from the run's, as
    "N = 5 (run: 10)" strings; [] if they agree.

    An imported run's opts are a whole # opts= dict (they have LookupMax).
    A UI run records only N, t, CC, and LRE, and leaves the rest at the
    pipeline's defaults, so only those keys are compared."""
    whole = "LookupMax" in run_opts
    out = []
    for k in dict.fromkeys(list(run_opts) + list(alert_opts)):
        if k in OPTS_IGNORED or (k not in run_opts and not whole):
            continue
        mine = alert_opts.get(k, OPTS_ABSENT.get(k))
        theirs = run_opts.get(k, OPTS_ABSENT.get(k))
        if mine != theirs:
            out.append(f"{k} = {json.dumps(mine)} (run: {json.dumps(theirs)})")
    return out


def index_files(conn, ws, out_dir_rel):
    """Store new or changed query/reply files of an output directory."""
    out_dir = ws.path(out_dir_rel)
    known = {r["name"]: (r["size"], r["mtime"]) for r in conn.execute(
        "SELECT name, size, mtime FROM llm_file WHERE out_dir=?", (out_dir_rel,))}
    on_disk = set()
    for name in os.listdir(out_dir):
        m = outdir.PHASE_FILE_RE.match(name)
        if not m:
            continue
        on_disk.add(name)
        st = os.stat(out_dir / name)
        if known.get(name) == (st.st_size, st.st_mtime):
            continue
        text = outdir.read_text(out_dir / name)
        row = {"verdict": None, "need_defs": None, "model": None, "effort": None,
               "input_tokens": None, "cached_input_tokens": None,
               "output_tokens": None, "reasoning_tokens": None}
        if m["ext"] == "reply":
            info = outdir.parse_reply(text)
            row.update({k: info[k] for k in row if k != "need_defs"})
            row["need_defs"] = json.dumps(info["need_defs"]) if info["need_defs"] else None
        conn.execute(
            "INSERT OR REPLACE INTO llm_file(out_dir, name, size, mtime, content, verdict, "
            "need_defs, model, effort, input_tokens, cached_input_tokens, output_tokens, "
            "reasoning_tokens) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (out_dir_rel, name, st.st_size, st.st_mtime, text, row["verdict"],
             row["need_defs"], row["model"], row["effort"], row["input_tokens"],
             row["cached_input_tokens"], row["output_tokens"], row["reasoning_tokens"]))
    for name in set(known) - on_disk:
        # Deleted by the pipeline (e.g. a malformed reply, to be asked again).
        conn.execute("DELETE FROM llm_file WHERE out_dir=? AND name=?", (out_dir_rel, name))
    conn.commit()


def models_in(conn, out_dir_rel):
    """Return Counter{(model, effort): number of replies} for an output directory."""
    return collections.Counter(
        (r["model"], r["effort"] or "") for r in conn.execute(
            "SELECT model, effort FROM llm_file WHERE out_dir=? AND name LIKE '%.reply' "
            "AND model IS NOT NULL", (out_dir_rel,)))


def index_run(conn, ws, run_id):
    """(Re)compute the run_result rows of one run from its output directory."""
    run = conn.execute("SELECT * FROM run WHERE run_id=?", (run_id,)).fetchone()
    out_dir_rel = run["out_dir"]
    out_dir = ws.path(out_dir_rel)
    index_files(conn, ws, out_dir_rel)
    selection = db.loads(run["selection"], {})
    wanted = set(selection.get("alert_ids") or [])

    by_basename = {r["basename"]: r["alert_id"] for r in conn.execute(
        "SELECT basename, alert_id FROM alert WHERE analysis_id=?", (run["analysis_id"],))}
    groups = outdir.scan_dir(out_dir)

    def read(name):
        return outdir.read_text(out_dir / name)

    verdicts = {}

    def verdict_of(name):
        if name not in verdicts:
            row = conn.execute("SELECT verdict FROM llm_file WHERE out_dir=? AND name=?",
                               (out_dir_rel, name)).fetchone()
            verdicts[name] = row["verdict"] if row else None
        return verdicts[name]

    def phase_json(ps, n):
        trials = [{"trial": i, "file": ps.replies[i], "verdict": verdict_of(ps.replies[i])}
                  for i in range(n) if i in ps.replies]
        return {"kind": ps.kind, "hash": ps.hash, "query": ps.query, "trials": trials}

    run_opts = db.loads(run["opts"])
    totals = collections.Counter()
    for basename, group in groups.items():
        alert_id = outdir.basename_to_alert_id(basename, by_basename)
        if alert_id is None or (wanted and alert_id not in wanted):
            continue
        chain = outdir.reconstruct_chain(group, read)
        phases = [phase_json(ps, chain["n1"]) for ps in chain["phase1"]]
        if chain["lre"] is not None:
            phases.append(phase_json(chain["lre"], chain["n2"]))
        if chain["uncert"] is not None:
            u = chain["uncert"]
            phases.append({"kind": "uncert", "hash": u.hash, "query": u.query,
                           "trials": [{"trial": 0, "file": u.replies[0], "verdict": None}]})
        deciding = [p for p in phases if p["kind"] != "uncert"]
        split = collections.Counter(t["verdict"] or "missing"
                                    for t in (deciding[-1]["trials"] if deciding else []))
        warnings = list(chain["warnings"])
        diff = opts_diff(chain["opts"], run_opts) if run_opts and chain["opts"] else []
        if diff:
            warnings.append("options differ from the run's: " + ", ".join(diff))

        verdict = final_text = explanation = None
        tok = {"input_tokens": None, "cached_input_tokens": None, "output_tokens": None}
        if group["final_answer"]:
            final_text = read(group["final_answer"])
            info = outdir.parse_reply(final_text)
            verdict = info["verdict"]
            explanation = info["body"]
            tok = {k: info[k] for k in tok}
            for k, v in tok.items():
                totals[k] += v or 0
        conn.execute(
            "INSERT OR REPLACE INTO run_result(run_id, analysis_id, alert_id, verdict, "
            "final_answer, explanation, split, phases, definitions, warnings, input_tokens, "
            "cached_input_tokens, output_tokens) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, run["analysis_id"], alert_id, verdict, final_text, explanation,
             json.dumps(dict(split)), json.dumps(phases),
             json.dumps(outdir.added_definitions(chain["phase1"], read)),
             json.dumps(warnings), tok["input_tokens"], tok["cached_input_tokens"],
             tok["output_tokens"]))
    conn.execute("UPDATE run SET input_tokens=?, cached_input_tokens=?, output_tokens=? "
                 "WHERE run_id=?", (totals["input_tokens"], totals["cached_input_tokens"],
                                     totals["output_tokens"], run_id))
    conn.commit()
