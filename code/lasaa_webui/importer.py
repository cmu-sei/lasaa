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
"""`lasaa_webui_import.py`: bring an existing alerts file, source tree, and
(optionally) adjudicate_alerts.py output directory into the workspace.

The source tree becomes a frozen snapshot, the alerts file an analysis, and
the output directory is copied to lasaa/<analysis>/<config>/ and indexed as
one run with status "imported".
"""

import collections
import json
import os
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

from . import alerts as alerts_mod
from . import db, indexer, outdir, runs, snapshot
from .workspace import slugify


def guess_client(model):
    m = model.lower()
    if m.startswith(("claude", "us.anthropic.", "anthropic.", "us-gov.anthropic.")):
        return "ask_claude_aws.py"
    return "ask_gpt.py"


def read_out_dir_models(out_dir):
    """Return Counter{(model, effort)} over the reply headers in *out_dir*."""
    counts = collections.Counter()
    for name in os.listdir(out_dir):
        if name.endswith(".reply") and outdir.PHASE_FILE_RE.match(name):
            with open(os.path.join(out_dir, name), encoding="utf-8", errors="replace") as f:
                info = outdir.parse_header(f.readline())
            if info["model"]:
                counts[(info["model"], info["effort"] or "")] += 1
    return counts


def read_out_dir_opts(out_dir):
    counts = collections.Counter()
    for name in os.listdir(out_dir):
        if name.endswith(".final_answer"):
            with open(os.path.join(out_dir, name), encoding="utf-8", errors="replace") as f:
                opts = outdir.parse_header(f.readline())["opts"]
            if opts is not None:
                counts[json.dumps(opts, sort_keys=True)] += 1
    return counts


def is_external(src, file):
    if not file:
        return True
    full = os.path.realpath(os.path.join(src, file))
    return not (full.startswith(os.path.realpath(src) + os.sep) and os.path.isfile(full))


def alert_paths(alert_list, origin):
    """Paths (relative to *origin*) of the files that the alerts and their
    trace steps name.  The snapshot keeps them whatever their extension."""
    origin = os.path.realpath(origin)
    paths = set()
    for a in alert_list:
        files = [alerts_mod.first(a, ("File", "Path"))]
        files += [step["File"] for _, _, step in alerts_mod.trace_steps(a)]
        for f in files:
            if not isinstance(f, str) or not f:
                continue
            full = os.path.normpath(os.path.join(origin, f))   # as freeze() names it
            if full.startswith(origin + os.sep):
                paths.add(os.path.relpath(full, origin))
    return paths


def get_or_create_project(conn, name, origin):
    proj = conn.execute("SELECT * FROM project WHERE name=?", (name,)).fetchone()
    if proj is None:
        slug = slugify(name)
        n = 1
        while conn.execute("SELECT 1 FROM project WHERE slug=?", (slug,)).fetchone():
            n += 1
            slug = f"{slugify(name)}-{n}"
        conn.execute("INSERT INTO project(name, slug, origin, created_at) VALUES (?,?,?,?)",
                     (name, slug, origin, db.now()))
        conn.commit()
        proj = conn.execute("SELECT * FROM project WHERE name=?", (name,)).fetchone()
    return proj


def create_snapshot(ws, conn, proj, origin, label=None, excludes=(), includes=(), only=(),
                    keep=(), commit=None, log=print, fallback_func_bounds=None,
                    build_command=None, build=None):
    """Freeze *origin* (a directory) into a new snapshot of *proj*; return its row.

    With *commit*, *origin* must be a git checkout, and the snapshot is of that
    commit (via git archive) rather than of the working tree.

    With *build_command*, the tree is first copied to a work/ directory in a
    fresh temporary directory, outside the workspace (so that a build run as
    another user can reach it), and built there: *build*(work_dir,
    compdb_path) runs the command under bear and returns its exit status.
    Both paths are in work_dir's parent, which *build* may hand to the build
    user; bear's output is then read as untrusted.  The snapshot then also keeps every
    file the compile commands read, and gets a compile_commands.json that
    points into src/.  A failed build is recorded (build_status 'failed')
    and the snapshot is made from what it compiled.  If anything raises,
    the snapshot is deleted.
    """
    if commit:
        gi = snapshot.git_info(origin)
        head = snapshot.resolve_commit(origin, commit)
        gi = {"head": head, "dirty": False, "repo_url": gi.get("repo_url")}
    else:
        gi = snapshot.git_info(origin)
        if gi.get("dirty"):
            log("Warning: the git checkout has uncommitted changes; the snapshot is marked dirty.")
    cur = conn.execute(
        "INSERT INTO snapshot(project_id, label, origin, build_command, git_head, git_dirty, "
        "repo_url, dir, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (proj["project_id"], label, origin, build_command or None, gi.get("head"),
         int(gi["dirty"]) if gi else None, gi.get("repo_url"), "", db.now()))
    snap_id = cur.lastrowid
    conn.commit()
    snap_rel = f"projects/{proj['slug']}/snapshots/{snap_id}"
    snap_dir = ws.path(snap_rel)
    try:
        return _fill_snapshot(ws, conn, proj, snap_id, snap_rel, origin, gi, label, excludes,
                              includes, only, keep, commit, log, fallback_func_bounds,
                              build_command, build)
    except BaseException:
        conn.rollback()
        conn.execute("DELETE FROM snapshot WHERE snap_id=?", (snap_id,))
        conn.commit()
        snapshot.remove_tree(snap_dir)
        raise


def _fill_snapshot(ws, conn, proj, snap_id, snap_rel, origin, gi, label, excludes, includes,
                   only, keep, commit, log, fallback_func_bounds, build_command, build):
    snap_dir = ws.path(snap_rel)
    snap_dir.mkdir(parents=True)
    prev = conn.execute("SELECT dir FROM snapshot WHERE project_id=? AND snap_id<? AND dir!='' "
                        "ORDER BY snap_id DESC LIMIT 1",
                        (proj["project_id"], snap_id)).fetchone()
    prev_pair = None
    if prev:
        try:
            with open(ws.path(prev["dir"]) / "manifest.json") as f:
                prev_pair = (str(ws.path(prev["dir"]) / "src"), json.load(f)["files"])
        except (OSError, KeyError, json.JSONDecodeError):
            pass
    tree = origin
    tmp = build_tmp = work = None
    keep, dirs = set(keep), set()
    compdb = build_status = None
    try:
        if build_command:
            build_tmp = tempfile.mkdtemp(prefix="lasaa-build-")
            work = Path(build_tmp) / "work"
            if commit:
                work.mkdir()
                log(f"Exporting commit {gi['head'][:12]} of {origin} to {work} ...")
                snapshot.git_export(origin, gi["head"], work)
            else:
                log(f"Copying {origin} to {work} for the build ...")
                snapshot.copy_tree(origin, work)
            tree = str(work)
            rc = build(work, Path(build_tmp) / "compile_commands.json")
            # Written by the build's user: no symlinks, and only a list counts.
            data = snapshot.read_untrusted_file(Path(build_tmp) / "compile_commands.json")
            (snap_dir / "compile_commands.build.json").write_bytes(data)
            try:
                compdb = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError):
                compdb = []
            if not isinstance(compdb, list):
                compdb = []
            compdb = [e for e in compdb if isinstance(e, dict)]
            build_status = "ok" if rc == 0 else "failed"
            if rc != 0:
                log(f"Warning: the build failed (exit status {rc}); the snapshot keeps the "
                    f"{len(compdb)} compile command(s) it recorded.")
            if not compdb:
                log("Warning: the build compiled nothing, so Clang Static Analyzer can't run on "
                    "this snapshot.  If the directory was already built, make the build redo "
                    "everything (for example, make -B).")
            log(f"Listing the files that {len(compdb)} compile command(s) read ...")
            inputs, dirs = snapshot.build_inputs(compdb, work, env=snapshot_env(), log=log)
            keep |= inputs
        elif commit:
            tmp = tempfile.TemporaryDirectory(dir=snap_dir)
            tree = tmp.name
            log(f"Exporting commit {gi['head'][:12]} of {origin} ...")
            snapshot.git_export(origin, gi["head"], tree)
        log(f"Freezing {origin} ...")
        files, skipped, n_other = snapshot.freeze(
            tree, snap_dir / "src", excludes, prev_pair, includes=includes, only=only,
            keep=keep, dirs=dirs)
        if compdb is not None:
            with open(snap_dir / "compile_commands.json", "w", encoding="utf-8") as f:
                json.dump(snapshot.rewrite_compdb(compdb, work, snap_dir / "src"), f, indent=1)
                f.write("\n")
    finally:
        if tmp is not None:
            tmp.cleanup()
        if build_tmp is not None:
            snapshot.remove_tree(build_tmp)
    log(f"  Kept {len(files)} source file(s); left out {n_other} other file(s).")
    for sk in skipped:
        log(f"  Skipped {sk['path']}: {sk['reason']}.")
    err = snapshot.compute_func_bounds(snap_dir / "src", snap_dir / "func_bounds.json")
    if err:
        log(f"Warning: ctags failed ({err}).")
        if fallback_func_bounds and os.path.isfile(fallback_func_bounds):
            shutil.copyfile(fallback_func_bounds, snap_dir / "func_bounds.json")
            log("  Using the output directory's func_bounds.json instead.")
    snapshot.write_manifest(snap_dir / "manifest.json", {
        "origin": origin, "commit": commit, "git_head": gi.get("head"),
        "git_dirty": gi.get("dirty"), "repo_url": gi.get("repo_url"),
        "build_command": build_command or None, "build_status": build_status,
        "build_units": len(compdb) if compdb is not None else None,
        "excludes": list(excludes), "includes": list(includes), "only": list(only),
        "source_extensions": sorted(snapshot.SOURCE_EXTENSIONS),
        "build_files": list(snapshot.BUILD_FILE_GLOBS), "non_source_left_out": n_other,
        "created_at": db.now(),
        "files": files, "skipped": skipped})
    conn.execute("UPDATE snapshot SET dir=?, build_status=?, build_units=? WHERE snap_id=?",
                 (snap_rel, build_status, len(compdb) if compdb is not None else None, snap_id))
    conn.commit()
    return conn.execute("SELECT * FROM snapshot WHERE snap_id=?", (snap_id,)).fetchone()


def snapshot_env():
    """The environment for subprocesses that run on the code: no API keys."""
    return runs.env("Alert_ID", secrets=False)


def insert_alerts(conn, analysis_id, alert_list, id_field, src, log=print, tool=None):
    """Add *alert_list* to the alert table; return how many were added.

    *tool* fills in the Tool column for alerts without a Tool field: one
    name for all of them, or a list with one name per alert.
    """
    seen = set()
    for ord_, a in enumerate(alert_list):
        fallback = tool[ord_] if isinstance(tool, list) else tool
        s = alerts_mod.summarize(a, id_field)
        if s["basename"] in seen:
            log(f"Warning: duplicate alert ID {s['alert_id']!r}; keeping the first.")
            continue
        seen.add(s["basename"])
        conn.execute(
            "INSERT INTO alert(analysis_id, alert_id, basename, ord, tool, file, line, cwes, "
            "rule, message, severity, external, record) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (analysis_id, s["alert_id"], s["basename"], ord_, s["tool"] or fallback, s["file"],
             s["line"], json.dumps(s["cwes"]), s["rule"], s["message"], s["severity"],
             int(is_external(src, s["file"])), json.dumps(a)))
    conn.commit()
    return len(seen)


def check_fields_for_llm(fields, alert_list, log):
    """The --fields-for-llm list, normalized ("" for none: every field but
    the ID).  Warns about names that no alert has."""
    if not (fields or "").strip():
        return ""
    names = [f.strip() for f in fields.split(",")]
    if not all(names):
        raise ValueError("--fields-for-llm: separate the field names with single commas.")
    known = set().union(*(a.keys() for a in alert_list))
    missing = [n for n in names if n not in known]
    if missing:
        log(f"Warning: no alert has these --fields-for-llm fields: {', '.join(missing)}")
    return ",".join(names)


def run_import(ws, args, log=print):
    alerts_path = os.path.abspath(args.alerts)
    origin = os.path.abspath(args.src)
    out_src = os.path.abspath(args.out) if args.out else None
    if not os.path.isdir(origin):
        raise SystemExit(f"Error: {origin} is not a directory.")
    if out_src and not os.path.isdir(out_src):
        raise SystemExit(f"Error: {out_src} is not a directory.")
    alert_list = alerts_mod.load_alert_file(alerts_path)
    id_field = alerts_mod.guess_id_field(alert_list, args.id_field)
    fields = check_fields_for_llm(args.fields_for_llm, alert_list, log)
    if any("Base_Dir" in a for a in alert_list):
        raise SystemExit("Error: alerts with a Base_Dir field aren't supported yet.")
    if any(("Verdict" in a or "verdict" in a) for a in alert_list):
        log("Note: the alerts have a ground-truth Verdict field; the UI doesn't show it.")

    excludes = list(args.exclude or [])
    if out_src and os.path.realpath(out_src).startswith(os.path.realpath(origin) + os.sep):
        rel = os.path.relpath(os.path.realpath(out_src), os.path.realpath(origin))
        excludes.append(rel)
        log(f"Leaving {rel}/ out of the snapshot (it's the output directory).")

    conn = ws.connect()
    proj = get_or_create_project(conn, args.project or os.path.basename(origin.rstrip("/")),
                                 origin)
    snap = create_snapshot(ws, conn, proj, origin, label=args.label, excludes=excludes,
                           includes=args.include or (), only=args.only or (),
                           keep=alert_paths(alert_list, origin), log=log,
                           fallback_func_bounds=os.path.join(out_src, "func_bounds.json")
                           if out_src else None)
    snap_id = snap["snap_id"]
    snap_dir = ws.path(snap["dir"])

    # --- Analysis and alerts ---------------------------------------------
    tools = sorted({str(a.get("Tool")) for a in alert_list if a.get("Tool")})
    cur = conn.execute(
        "INSERT INTO analysis(snap_id, tool, options, status, source, dir, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (snap_id, "imported", json.dumps({"tools": tools, "id_field": id_field,
                                          **({"fields_for_llm": fields} if fields else {})}),
         "done", alerts_path, "", db.now()))
    analysis_id = cur.lastrowid
    an_rel = f"projects/{proj['slug']}/analyses/{analysis_id}"
    ws.path(an_rel).mkdir(parents=True)
    shutil.copyfile(alerts_path, ws.path(an_rel) / ("alerts.json.gz" if alerts_path.endswith(".gz")
                                                     else "alerts.json"))
    conn.execute("UPDATE analysis SET dir=? WHERE analysis_id=?", (an_rel, analysis_id))
    n = insert_alerts(conn, analysis_id, alert_list, id_field, snap_dir / "src", log)
    log(f"Imported {n} alerts (analysis {analysis_id}).")

    # --- LASAA output ----------------------------------------------------
    if out_src:
        models = read_out_dir_models(out_src)
        (model, effort), _ = models.most_common(1)[0] if models else (("unknown", ""), 0)
        if len(models) > 1:
            log(f"Warning: replies come from several models: {dict(models)}; "
                f"recording {model} {effort}.")
        client = args.client or guess_client(model)
        conn.execute("INSERT OR IGNORE INTO config(client, model, effort, created_at) "
                     "VALUES (?,?,?,?)", (client, model, effort, db.now()))
        config_id = conn.execute(
            "SELECT config_id FROM config WHERE client=? AND model=? AND effort=? AND endpoint=''",
            (client, model, effort)).fetchone()[0]
        out_rel = f"projects/{proj['slug']}/lasaa/{analysis_id}/{config_id}"
        log(f"Copying {out_src} ...")
        shutil.copytree(out_src, ws.path(out_rel))
        opts = read_out_dir_opts(out_src)
        run_opts = json.loads(opts.most_common(1)[0][0]) if opts else None
        if len(opts) > 1:
            log(f"Warning: final answers were made with different options: {dict(opts)}")
        basenames = {b for b in outdir.scan_dir(ws.path(out_rel))}
        by_basename = {r["basename"]: r["alert_id"] for r in conn.execute(
            "SELECT basename, alert_id FROM alert WHERE analysis_id=?", (analysis_id,))}
        ids = sorted({outdir.basename_to_alert_id(b, by_basename) for b in basenames} - {None})
        unknown = [b for b in basenames if outdir.basename_to_alert_id(b, by_basename) is None]
        if unknown:
            log(f"Warning: {len(unknown)} alerts in the output directory aren't in the "
                f"alerts file (e.g. {unknown[0]}).")
        cur = conn.execute(
            "INSERT INTO run(analysis_id, config_id, out_dir, opts, selection, command, status, "
            "created_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (analysis_id, config_id, out_rel, json.dumps(run_opts) if run_opts else None,
             json.dumps({"alert_ids": ids, "imported_from": out_src}),
             shlex.join([os.path.basename(sys.argv[0])] + sys.argv[1:]),
             "imported", db.now(), db.now()))
        run_id = cur.lastrowid
        conn.commit()
        log(f"Indexing run {run_id} ({model}, effort {effort or 'default'}) ...")
        indexer.index_run(conn, ws, run_id)
        n = conn.execute("SELECT count(*), count(verdict) FROM run_result WHERE run_id=?",
                         (run_id,)).fetchone()
        log(f"  {n[0]} alerts, {n[1]} with a final answer.")
    conn.commit()
    conn.close()
    return analysis_id
