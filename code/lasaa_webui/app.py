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
"""The web server: pages over the workspace database, and manual reviews."""

import asyncio
import collections
import contextlib
import datetime
import fnmatch
import hashlib
import html
import json
import math
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import alerts as alerts_mod
from . import chat as chat_mod
from . import codeview, csa, db, export, importer, jobs, models, prompt_sizes, render, reviews, runs
from . import snapshot as snapshot_mod
from . import outdir
from .outdir import strip_reply_header
from .security import SecurityMiddleware

HERE = Path(__file__).resolve().parent
LICENSE_FILE = HERE.parent.parent / "License.txt"    # at the top of the repository
VERDICT_ORDER = {"uncertain": 0, "true": 1, "dependent": 2, None: 3, "false": 4}
LLM_TEST_PROMPT = "What is the capital of France?"
LLM_TEST_MAX_OUTPUT = 1000    # output-token cap for the run form's connectivity test
LLM_TEST_SECONDS = 120
LONG_POLL_SECONDS = 25        # how long the run form's estimate waits for new prompt sizes
DELETED_NAME_MAX = 40        # longest old name kept in a deleted project's name
SHOW_EDITOR_LINKS = False     # show the "Open in editor" links (and the "e" shortcut)
# The examples that the home page's new-snapshot form can fill in with one
# click (if the directory exists): the tinykv demo of the README.
EXAMPLES = [{"label": "tinykv", "project": "tinykv",
             "origin": runs.CODE_DIR.parent / "examples" / "tinykv",
             "build_command": "make -B -j$(nproc)"}]
FILTER_KEYS = ("verdict", "review", "tool", "rule", "cwe", "severity", "file", "q", "hide_false")
REVIEW_FILTERS = [("unreviewed", "unreviewed"), ("reviewed", "reviewed"),
                  ("agrees", "reviewed, agrees with LLM"),
                  ("disagrees", "reviewed, disagrees with LLM")]
PHASE_TITLES = {"orig": "Original prompt and responses",
                "lre": "LLM reasoning evaluation (LRE)",
                "uncert": "Explanation of the disagreement"}


class Settings:
    def __init__(self, editor_url="vscode://file/{path}:{line}", path_map=(), allowed_hosts=(),
                 blind_mode=False, allow_builds_as_server_user=False):
        self.editor_url = editor_url
        self.path_map = list(path_map)       # [(from prefix, to prefix)]
        self.allowed_hosts = list(allowed_hosts)
        self.blind_mode = blind_mode         # offer the blind-mode toggle (--blind-mode)
        # Builds run as the build user only when the server is root; otherwise
        # they're refused unless this is set (--allow-builds-as-server-user).
        self.allow_builds_as_server_user = allow_builds_as_server_user


def phase_title(kind):
    if kind.startswith("augdef."):
        return f"Prompt with definitions (round {int(kind.split('.')[1]) + 1}) and responses"
    return PHASE_TITLES.get(kind, kind)


def split_text(split, verdict, short=False):
    """"7/10 true" (or "7/10" if *short*), or the counts of each verdict if
    none of the trials gave the final one ("2 uncertain, 1 false"; with
    *short*, "dep" for "dependent")."""
    if not split:
        return ""
    total = sum(split.values())
    if verdict in split:
        return f"{split[verdict]}/{total}" + ("" if short else f" {verdict}")
    return ", ".join(f"{n} {'dep' if short and v == 'dependent' else v}"
                     for v, n in sorted(split.items(), key=lambda kv: -kv[1]))


def create_app(ws, token, settings=None):
    settings = settings or Settings()
    runner = jobs.JobRunner(ws, settings.allow_builds_as_server_user)
    asker = chat_mod.Asker(ws)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        runner.recover()
        asker.recover()
        yield
        await asker.shutdown()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.runner = runner

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        # A plain page, since these come back from form submissions.
        return HTMLResponse(
            "<!doctype html><title>Error</title><link rel=stylesheet href=/static/ui.css>"
            f"<main><h1>{exc.status_code}</h1><p>{html.escape(str(exc.detail))}</p>"
            "<p>Use the browser's Back button to return to the form.</p></main>",
            status_code=exc.status_code)
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters["markdown"] = render.markdown
    templates.env.globals["phase_title"] = phase_title
    templates.env.globals["blind_toggle"] = settings.blind_mode
    templates.env.globals["show_editor_links"] = SHOW_EDITOR_LINKS
    templates.env.globals["can_build"] = runner.can_build
    templates.env.filters["wbr"] = render.wbr
    templates.env.filters["wbr_path"] = render.wbr_path
    css = codeview.pygments_css()
    # Static URLs carry a hash of the files (?v=...), so that a browser
    # fetches them again after a change instead of using a cached copy.
    h = hashlib.sha256(css.encode())
    for f in sorted((HERE / "static").iterdir()):
        h.update(f.name.encode() + b"\0" + f.read_bytes())
    templates.env.globals["asset_v"] = h.hexdigest()[:12]
    fb_cache = {}

    def conn():
        c = ws.connect()
        return c

    def blind_mode(c):
        return settings.blind_mode and db.get_setting(c, "blind") == "1"

    def page(request, name, **ctx):
        ctx["csrf"] = request.state.csrf_token
        if "blind" not in ctx:
            c = conn()
            ctx["blind"] = blind_mode(c)
            c.close()
        ctx["here"] = request.url.path + (("?" + request.url.query) if request.url.query else "")
        return templates.TemplateResponse(request, name, ctx)

    def local_url(url, prefix="/"):
        """*url* if it is a path on this server under *prefix*, else None."""
        if not isinstance(url, str) or not url.startswith(prefix) or url.startswith("//") \
                or "\\" in url or any(ord(ch) < 32 for ch in url):
            return None
        rest = url[len(prefix):]
        if prefix != "/" and rest and rest[0] not in "/?#":
            return None
        return url

    def with_param(url, key, value):
        base, _, frag = url.partition("#")
        base += ("&" if "?" in base else "?") + urlencode({key: value})
        return base + ("#" + frag if frag else "")

    def func_bounds(snap):
        if snap["snap_id"] not in fb_cache:
            fb_cache[snap["snap_id"]] = codeview.FuncBounds(ws.path(snap["dir"]) / "func_bounds.json")
        return fb_cache[snap["snap_id"]]

    def editor_link(snap, file, line):
        path = os.path.join(snap["origin"], file)
        for src, dst in settings.path_map:
            if path == src or path.startswith(src.rstrip("/") + "/"):
                path = dst.rstrip("/") + path[len(src.rstrip("/")):]
                break
        return (settings.editor_url.replace("{path}", quote(path, safe="/:"))
                .replace("{line}", str(line or 1)))

    def load_analysis(c, analysis_id):
        an = c.execute("SELECT * FROM analysis WHERE analysis_id=?", (analysis_id,)).fetchone()
        if an is None:
            raise HTTPException(404, "No such analysis")
        snap = c.execute("SELECT * FROM snapshot WHERE snap_id=?", (an["snap_id"],)).fetchone()
        proj = c.execute("SELECT * FROM project WHERE project_id=?",
                         (snap["project_id"],)).fetchone()
        runs = c.execute(
            "SELECT run.*, config.client, config.model, config.effort FROM run "
            "JOIN config USING (config_id) WHERE analysis_id=? AND status!='draft' "
            "ORDER BY run_id DESC", (analysis_id,)).fetchall()
        return an, snap, proj, runs

    def pick_run(runs, run_id):
        if run_id is not None:
            for r in runs:
                if r["run_id"] == run_id:
                    return r
            raise HTTPException(404, "No such run")
        return runs[0] if runs else None

    def alert_rows(c, analysis_id, run, blind=False):
        """The alerts with *run*'s results and their current reviews, in list
        order: by LLM verdict (by location if *blind*).  Reviewing an alert
        doesn't move it, so k after a save goes back to it."""
        rows = c.execute(
            "SELECT alert.*, rr.verdict, rr.split, rr.input_tokens, rr.output_tokens, "
            "rr.cached_input_tokens, rr.warnings, rr.explanation FROM alert "
            "LEFT JOIN run_result rr ON rr.alert_id=alert.alert_id AND rr.run_id=? "
            "WHERE alert.analysis_id=?", (run["run_id"] if run else -1, analysis_id)).fetchall()
        revs = reviews.current_all(c, analysis_id)
        out = []
        for r in rows:
            d = dict(r)
            d["cwes"] = json.loads(d["cwes"])
            d["split"] = db.loads(d["split"], {})
            d["split_text"] = split_text(d["split"], d["verdict"])
            d["split_short"] = split_text(d["split"], d["verdict"], short=True)
            d["review"] = revs.get(d["alert_id"])
            out.append(d)
        out.sort(key=lambda d: (0 if blind else VERDICT_ORDER.get(d["verdict"], 3),
                                d["file"] or "", d["line"] or 0, d["ord"]))
        return out

    def list_view(rows, f, blind):
        """(filtered rows, rows to show, number of unreviewed false rows collapsed).
        False alerts are shown unless hide_false is set (the UI is mainly
        for demos, which should show both kinds)."""
        shown = apply_filters(rows, f)
        hide_false = not blind and bool(f.get("hide_false")) and f.get("verdict") != "false"
        visible = [d for d in shown
                   if not (hide_false and d["verdict"] == "false" and d["review"] is None)]
        return shown, visible, len(shown) - len(visible)

    def apply_filters(rows, f):
        def keep(d):
            if f.get("verdict"):
                if (d["verdict"] or "none") != f["verdict"]:
                    return False
            rv = f.get("review")
            if rv and not {"unreviewed": d["review"] is None,
                           "reviewed": d["review"] is not None,
                           "agrees": d["review"] is not None
                           and d["review"]["verdict"] == d["verdict"],
                           "disagrees": d["review"] is not None
                           and d["review"]["verdict"] != d["verdict"]}.get(rv, True):
                return False
            for key in ("tool", "rule", "severity"):
                if f.get(key) and (d[key] or "") != f[key]:
                    return False
            if f.get("cwe") and f["cwe"].upper() not in [c.upper() for c in d["cwes"]]:
                return False
            if f.get("file") and not fnmatch.fnmatch(d["file"] or "", f["file"]) \
                    and not fnmatch.fnmatch(d["file"] or "", f["file"].rstrip("/") + "/*"):
                return False
            if f.get("q"):
                hay = " ".join(str(d[k] or "") for k in ("message", "rule", "file", "alert_id"))
                if f["q"].lower() not in hay.lower():
                    return False
            return True
        return [d for d in rows if keep(d)]

    def filters_of(request, blind=False):
        """The list filters in the query string.  Blind mode drops the verdict filter."""
        return {k: request.query_params.get(k, "").strip() for k in FILTER_KEYS
                if request.query_params.get(k, "").strip()
                and not (blind and k in ("verdict", "hide_false"))}

    def qs(**params):
        params = {k: v for k, v in params.items() if v not in (None, "")}
        return ("?" + urlencode(params)) if params else ""

    # ------------------------------------------------------------------

    @app.get("/static/pygments.css")
    def pygments_css():
        return Response(css, media_type="text/css")

    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    def project_view(c, p):
        """*p* with its snapshots, their analyses, and the analyses' runs."""
        snaps = []
        for s in c.execute("SELECT * FROM snapshot WHERE project_id=? ORDER BY snap_id DESC",
                           (p["project_id"],)):
            analyses = []
            for a in c.execute("SELECT analysis.*, (SELECT count(*) FROM alert WHERE "
                               "alert.analysis_id=analysis.analysis_id) AS n_alerts "
                               "FROM analysis WHERE snap_id=? ORDER BY analysis_id DESC",
                               (s["snap_id"],)):
                runs = c.execute(
                    "SELECT run.*, config.model, config.effort, "
                    "(SELECT count(verdict) FROM run_result rr WHERE rr.run_id=run.run_id) "
                    "AS n_done FROM run JOIN config USING (config_id) "
                    "WHERE analysis_id=? AND status!='draft' ORDER BY run_id DESC",
                    (a["analysis_id"],)).fetchall()
                analyses.append({"a": a, "tools": db.loads(a["options"], {}).get("tools", []),
                                 "runs": runs})
            snaps.append({"s": s, "analyses": analyses})
        return {"p": p, "snaps": snaps}

    def deleted_name(p, max_len=DELETED_NAME_MAX):
        """The name a deleted project takes: "deleted ID NAME yyyy-mm-dd hh-mm",
        with NAME shortened if it is long.  The ID keeps it unique."""
        name = p["name"]
        if len(name) > max_len:
            name = name[:max_len - 1].rstrip() + "…"
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H-%M")
        return f"deleted {p['project_id']} {name} {stamp}"

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        c = conn()
        projects = project_rows(c, hidden=False)
        n_deleted = c.execute("SELECT count(*) FROM project WHERE hidden").fetchone()[0]
        recent = c.execute("SELECT * FROM job WHERE project_id IS NULL OR project_id NOT IN "
                           "(SELECT project_id FROM project WHERE hidden) "
                           "ORDER BY job_id DESC LIMIT 8").fetchall()
        c.close()
        return page(request, "home.html", projects=projects, jobs=recent, n_deleted=n_deleted,
                    examples=example_presets())

    def example_presets():
        """The EXAMPLES that exist here, as {label, fill: {form field: value}}."""
        out = []
        for ex in EXAMPLES:
            if not os.path.isdir(ex["origin"]):
                continue
            fill = {"project": ex["project"], "origin": str(ex["origin"])}
            if runner.can_build():
                fill.update(build="yes", build_command=ex["build_command"])
            else:
                fill.update(build="no", build_command="")
            out.append({"label": ex["label"], "fill": fill})
        return out

    def project_rows(c, hidden):
        """The projects for a list (the deleted ones if *hidden*), with counts."""
        return c.execute(
            "SELECT project.*, (SELECT count(*) FROM snapshot s WHERE s.project_id="
            "project.project_id) AS n_snaps, (SELECT count(*) FROM analysis a JOIN snapshot s "
            "USING (snap_id) WHERE s.project_id=project.project_id) AS n_analyses, "
            "(SELECT max(created_at) FROM snapshot s WHERE s.project_id=project.project_id) "
            "AS last_snap FROM project WHERE hidden=? ORDER BY "
            + ("project_id DESC" if hidden else "name"), (int(hidden),)).fetchall()

    @app.get("/legal", response_class=HTMLResponse)
    def legal(request: Request):
        return page(request, "legal.html")

    @app.get("/legal/license", response_class=HTMLResponse)
    def legal_license(request: Request):
        try:
            text = LICENSE_FILE.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raise HTTPException(404, f"License.txt was not found (expected at {LICENSE_FILE})")
        return page(request, "license.html", text=text)

    @app.get("/projects/deleted", response_class=HTMLResponse)
    def deleted_projects(request: Request):
        c = conn()
        projects = project_rows(c, hidden=True)
        c.close()
        return page(request, "deleted_projects.html", projects=projects)

    def restored_name(c, p):
        """The name a restored project takes back: its old one, or, if a new
        project has that name now, the old one with "(restored)" after it."""
        base = p["old_name"]
        if not base:                       # deleted before old_name was kept
            m = re.fullmatch(r"deleted \d+ (.*) \d{4}-\d\d-\d\d \d\d-\d\d", p["name"])
            base = m[1] if m else p["name"]
        name, n = base, 1
        while c.execute("SELECT 1 FROM project WHERE name=? AND project_id!=?",
                        (name, p["project_id"])).fetchone():
            n += 1
            name = f"{base} (restored)" if n == 2 else f"{base} (restored {n - 1})"
        return name

    @app.post("/project/{project_id}/restore")
    def project_restore(request: Request, project_id: int):
        c = conn()
        try:
            p = c.execute("SELECT * FROM project WHERE project_id=?", (project_id,)).fetchone()
            if p is None:
                raise HTTPException(404, "No such project")
            if p["hidden"]:
                c.execute("UPDATE project SET name=?, hidden=0, old_name=NULL "
                          "WHERE project_id=?", (restored_name(c, p), project_id))
                c.commit()
        finally:
            c.close()
        return RedirectResponse(f"/project/{project_id}", 303)

    @app.get("/project/{project_id}", response_class=HTMLResponse)
    def project_page(request: Request, project_id: int):
        c = conn()
        p = c.execute("SELECT * FROM project WHERE project_id=?", (project_id,)).fetchone()
        if p is None:
            c.close()
            raise HTTPException(404, "No such project")
        view = project_view(c, p)
        recent = c.execute("SELECT * FROM job WHERE project_id=? ORDER BY job_id DESC LIMIT 8",
                           (project_id,)).fetchall()
        c.close()
        return page(request, "project.html", proj=p, pv=view, jobs=recent)

    @app.post("/project/{project_id}/delete")
    def project_delete(request: Request, project_id: int):
        """"Delete" a project: hide it from the lists and rename it, so that
        its name can start a new project.  Its files and rows stay, and
        links to it still work."""
        c = conn()
        try:
            p = c.execute("SELECT * FROM project WHERE project_id=?", (project_id,)).fetchone()
            if p is None:
                raise HTTPException(404, "No such project")
            if not p["hidden"]:
                if c.execute("SELECT 1 FROM job WHERE project_id=? AND status IN "
                             "('queued', 'running')", (project_id,)).fetchone():
                    bad_request("This project has a job that is queued or running; "
                                "cancel it or wait for it to finish first.")
                c.execute("UPDATE project SET name=?, hidden=1, old_name=? WHERE project_id=?",
                          (deleted_name(p), p["name"], project_id))
                c.commit()
        finally:
            c.close()
        return RedirectResponse("/", 303)

    @app.get("/analysis/{analysis_id}", response_class=HTMLResponse)
    def alert_list(request: Request, analysis_id: int, run: int | None = None):
        c = conn()
        an, snap, proj, runs = load_analysis(c, analysis_id)
        cur_run = pick_run(runs, run)
        blind = blind_mode(c)
        rows = alert_rows(c, analysis_id, cur_run, blind)
        c.close()
        f = filters_of(request, blind)
        shown, visible, n_false = list_view(rows, f, blind)
        counts = collections.Counter(d["verdict"] or "none" for d in shown)
        n_reviewed = sum(d["review"] is not None for d in shown)
        options = {k: sorted({d[k] for d in rows if d[k]}) for k in ("tool", "rule", "severity")}
        options["verdict"] = [v for v in ("uncertain", "true", "dependent", "false", "none")
                              if any((d["verdict"] or "none") == v for d in rows)]
        options["review"] = REVIEW_FILTERS
        link_qs = qs(run=run, **f)
        export_qs = qs(run=cur_run["run_id"] if cur_run else None,
                       **{k: v for k, v in f.items() if k != "hide_false"})
        return page(request, "alerts.html", an=an, snap=snap, proj=proj, runs=runs,
                    run=cur_run, run_opts=db.loads(cur_run["opts"]) if cur_run else None,
                    rows=visible, total=len(rows), n_shown=len(shown), counts=counts,
                    n_reviewed=n_reviewed, blind=blind, export_qs=export_qs,
                    n_false=n_false, filters=f, options=options, link_qs=link_qs,
                    filtered=any(k != "hide_false" for k in f),
                    n_false_shown=0 if blind else sum(
                        d["verdict"] == "false" and d["review"] is None for d in visible),
                    show_false_url=f"/analysis/{analysis_id}" + qs(
                        run=run, **{k: v for k, v in f.items() if k != "hide_false"}),
                    hide_false_url=f"/analysis/{analysis_id}" + qs(run=run, **{**f, "hide_false": "1"}),
                    multi_tool=len(options["tool"]) > 1,
                    has_sarif=bool(db.loads(an["options"], {}).get("sarif")))

    @app.get("/analysis/{analysis_id}/alert/{basename}", response_class=HTMLResponse)
    def alert_detail(request: Request, analysis_id: int, basename: str,
                     run: int | None = None, full: int = 0,
                     open_chat: int | None = Query(None, alias="chat")):
        c = conn()
        an, snap, proj, runs = load_analysis(c, analysis_id)
        alert = c.execute("SELECT * FROM alert WHERE analysis_id=? AND basename=?",
                          (analysis_id, basename)).fetchone()
        if alert is None:
            c.close()
            raise HTTPException(404, "No such alert")
        record = json.loads(alert["record"])
        results = c.execute(
            "SELECT rr.*, run.created_at AS run_created, run.status AS run_status, run.opts, "
            "run.out_dir, config.model, config.effort, config.client FROM run_result rr "
            "JOIN run USING (run_id) JOIN config USING (config_id) "
            "WHERE rr.analysis_id=? AND rr.alert_id=? ORDER BY rr.run_id DESC",
            (analysis_id, alert["alert_id"])).fetchall()
        result = None
        if results:
            result = next((r for r in results if r["run_id"] == run), None) if run else results[0]
            if result is None:
                c.close()
                raise HTTPException(404, "No result for this alert in that run")
        list_run = pick_run(runs, run) if runs else None

        lasaa = None
        if result is not None:
            def file_row(name):
                row = c.execute("SELECT * FROM llm_file WHERE out_dir=? AND name=?",
                                (result["out_dir"], name)).fetchone()
                return dict(row) if row else None
            phases = []
            for ph in json.loads(result["phases"]):
                q = file_row(ph["query"]) if ph["query"] else None
                trials = []
                for t in ph["trials"]:
                    fr = file_row(t["file"])
                    if fr is None:
                        continue
                    reasoning, answer = render.answer_parts(strip_reply_header(fr["content"]))
                    trials.append({**t, "row": fr, "reasoning": reasoning, "answer": answer,
                                   "need_defs": db.loads(fr["need_defs"])})
                phases.append({**ph, "prompt": q["content"] if q else None, "trials": trials,
                               "split": collections.Counter(t["verdict"] or "missing"
                                                            for t in trials)})
            reasoning, answer = render.answer_parts(result["explanation"])
            split = db.loads(result["split"], {})
            lasaa = {"r": result, "phases": phases, "reasoning": reasoning, "answer": answer,
                     "split": split, "split_text": split_text(split, result["verdict"]),
                     "definitions": db.loads(result["definitions"], []),
                     "warnings": db.loads(result["warnings"], []),
                     "opts": db.loads(result["opts"])}

        # Neighbors in the alert list, with the list's filters.
        blind = blind_mode(c)
        f = filters_of(request, blind)
        all_rows = alert_rows(c, analysis_id, list_run, blind)
        _, visible, _ = list_view(all_rows, f, blind)
        visible_ids = {d["alert_id"] for d in visible}
        order = [d for d in all_rows if d["alert_id"] in visible_ids
                 or d["alert_id"] == alert["alert_id"]]
        ids = [d["basename"] for d in order]
        pos = ids.index(basename) if basename in ids else None
        nav_qs = qs(run=run, **f)
        prev_b = ids[pos - 1] if pos else None
        next_b = ids[pos + 1] if pos is not None and pos + 1 < len(ids) else None

        # Review: the current one, its history, and whether the LLM's answer
        # is hidden (blind mode, until the alert is reviewed).
        review = reviews.current(c, analysis_id, alert["alert_id"])
        hist = [dict(h) for h in reviews.history(c, analysis_id, alert["alert_id"])]
        hidden = blind and review is None
        saved = None
        saved_b = request.query_params.get("saved")
        if saved_b:
            sa = c.execute("SELECT * FROM alert WHERE analysis_id=? AND basename=?",
                           (analysis_id, saved_b)).fetchone()
            if sa is not None:
                saved = {"alert": sa, "review": reviews.current(c, analysis_id, sa["alert_id"]),
                         "here": saved_b == basename}
        chat = chat_ctx(c, analysis_id, alert, lasaa["r"]["run_id"] if lasaa else None,
                        open_chat)
        c.close()
        self_url = f"/analysis/{analysis_id}/alert/{basename}"
        list_url = f"/analysis/{analysis_id}" + nav_qs

        # Code panes: the flagged location first, then trace steps in other
        # functions or files, in trace order.
        src = ws.path(snap["dir"]) / "src"
        fb = func_bounds(snap)
        steps = alerts_mod.trace_steps(record)
        multi_field = len({s[0] for s in steps}) > 1

        def key_for(file, line):
            if full:
                return (file, None)
            enc = fb.enclosing(file, line)
            return (file, (enc[0], enc[1]) if enc else line)
        groups = collections.OrderedDict()
        if alert["file"] and alert["line"]:
            groups[key_for(alert["file"], alert["line"])] = {"file": alert["file"],
                                                              "lines": {alert["line"]},
                                                              "steps": {}}
        for field, n, step in steps:
            try:
                line = int(step["Line"])
            except (TypeError, ValueError):
                continue
            k = key_for(step["File"], line)
            g = groups.setdefault(k, {"file": step["File"], "lines": set(), "steps": {}})
            g["lines"].add(line)
            label = f"{field} {n}" if multi_field else str(n)
            g["steps"].setdefault(line, []).append({"n": label, "msg": step.get("Msg") or ""})
        panes = []
        for g in groups.values():
            p = codeview.pane(src, g["file"], g["lines"], fb, full=bool(full))
            if p is None:
                panes.append({"file": g["file"], "missing": True})
                continue
            p["steps"] = g["steps"]
            p["flag"] = alert["line"] if g["file"] == alert["file"] else None
            p["editor"] = editor_link(snap, g["file"], min(g["lines"]))
            panes.append(p)

        fields = [(k, v if isinstance(v, str) else json.dumps(v, indent=1))
                  for k, v in record.items()]
        next_url = (f"/analysis/{analysis_id}/alert/{next_b}" + nav_qs) if next_b else list_url
        return page(request, "alert.html", an=an, snap=snap, proj=proj, alert=alert,
                    cwes=json.loads(alert["cwes"]), fields=fields, lasaa=lasaa,
                    results=results, panes=panes, full=full, nav_qs=nav_qs,
                    prev_b=prev_b, next_b=next_b, pos=pos, n_list=len(ids),
                    list_url=list_url, self_url=self_url, next_url=next_url,
                    back_url=self_url + nav_qs + ("&" if nav_qs else "?") + f"full={full}"
                    if full else self_url + nav_qs,
                    blind=blind, hidden=hidden, review=review, history=hist, saved=saved,
                    verdicts=reviews.VERDICTS, chat=chat,
                    editor=editor_link(snap, alert["file"], alert["line"]))

    @app.post("/analysis/{analysis_id}/alert/{basename}/review")
    async def post_review(request: Request, analysis_id: int, basename: str):
        form = await request.form()
        c = conn()
        try:
            an, snap, proj, runs = load_analysis(c, analysis_id)
            alert = c.execute("SELECT * FROM alert WHERE analysis_id=? AND basename=?",
                              (analysis_id, basename)).fetchone()
            if alert is None:
                raise HTTPException(404, "No such alert")
            prefix = f"/analysis/{analysis_id}"
            back = local_url(form.get("back"), prefix) or f"{prefix}/alert/{basename}"
            nxt = local_url(form.get("next"), prefix) or back
            run_id = form.get("run", "")
            run_id = int(run_id) if run_id.isdigit() else None
            if run_id is not None and run_id not in [r["run_id"] for r in runs]:
                raise HTTPException(400, "No such run")
            rr = c.execute("SELECT verdict FROM run_result WHERE run_id=? AND alert_id=?",
                           (run_id, alert["alert_id"])).fetchone() if run_id else None
            llm_verdict = rr["verdict"] if rr else None
            blind = blind_mode(c)
            op = form.get("op")
            if op == "clear":
                reviews.clear(c, analysis_id, alert["alert_id"])
            elif op in ("save", "confirm"):
                if op == "confirm":
                    if llm_verdict is None or (blind and reviews.current(
                            c, analysis_id, alert["alert_id"]) is None):
                        raise HTTPException(400, "There is no LLM verdict to confirm")
                    verdict = llm_verdict
                else:
                    verdict = form.get("verdict")
                    if verdict not in reviews.VERDICTS:
                        raise HTTPException(400, "Choose a verdict")
                reviews.save(c, analysis_id, alert["alert_id"], verdict, llm_verdict, run_id,
                             blind, note=form.get("note"), dep_on_line=form.get("dep_on_line"))
            else:
                raise HTTPException(400, "Unknown action")
            db.backup_daily(c, ws.db_path)
        finally:
            c.close()
        if form.get("go") == "next" and op != "clear":
            return RedirectResponse(with_param(nxt, "saved", basename), 303)
        return RedirectResponse(with_param(back, "saved", basename) + "#review", 303)

    # ---------------------------------------------------------------
    # "Ask an LLM" (chat.py)
    # ---------------------------------------------------------------

    def chat_ctx(c, analysis_id, alert, run_id, open_id=None, msg=None, question=""):
        """The template variables for _chat.html, or None when the section
        isn't shown: blind mode hides LASAA's answer, or there is neither a
        final answer in run *run_id* to ask about nor an earlier conversation."""
        if blind_mode(c) and reviews.current(c, analysis_id, alert["alert_id"]) is None:
            return None
        rr = c.execute("SELECT verdict FROM run_result WHERE run_id=? AND alert_id=?",
                       (run_id, alert["alert_id"])).fetchone() if run_id else None
        can_start = rr is not None and rr["verdict"] is not None
        chats = chat_mod.chats_of(c, analysis_id, alert["alert_id"])
        if not chats and not can_start:
            return None
        open_chat = next((x for x in chats if x["chat_id"] == open_id), None)
        turns = chat_mod.turns_of(c, open_id) if open_chat else []
        now = datetime.datetime.now(datetime.timezone.utc)
        for t in turns:
            if t["status"] == "pending":
                t["elapsed"] = max(0, int((now - datetime.datetime.fromisoformat(
                    t["created_at"])).total_seconds()))
        choice = model_choice_ctx(c)
        keys = [m["key"] for m in choice["ready_models"] + choice["saved_models"]]
        model_key = db.get_setting(c, "chat_model")
        return {"url": f"/analysis/{analysis_id}/alert/{alert['basename']}/chat",
                "run_id": run_id, "can_start": can_start, "chats": chats, "open": open_chat,
                "turns": turns, "pending": any(t["status"] == "pending" for t in turns),
                "ready_models": choice["ready_models"], "saved_models": choice["saved_models"],
                "model_key": model_key if model_key in keys else "ready:0",
                "msg": msg, "question": question}

    def chat_context(c, alert, run_id):
        """chat.context_text() for the alert's result in run *run_id*."""
        rr = c.execute("SELECT rr.*, run.out_dir FROM run_result rr JOIN run USING (run_id) "
                       "WHERE rr.run_id=? AND rr.alert_id=?",
                       (run_id, alert["alert_id"])).fetchone() if run_id else None
        if rr is None or rr["verdict"] is None:
            raise ValueError("LASAA has no final answer for this alert in that run.")
        phases = json.loads(rr["phases"])
        ph = chat_mod.final_prompt_phase(phases)
        q = c.execute("SELECT content FROM llm_file WHERE out_dir=? AND name=?",
                      (rr["out_dir"], ph["query"])).fetchone() if ph and ph["query"] else None
        if q is None:
            raise ValueError("The prompt that LASAA's answer came from isn't available.")
        explanation = rr["explanation"] or ""
        answer = outdir.split_reasoning(explanation)[1]
        return chat_mod.context_text(q["content"], answer,
                                     chat_mod.answer_kind(phases, explanation))

    def chat_alert(c, analysis_id, basename):
        load_analysis(c, analysis_id)
        alert = c.execute("SELECT * FROM alert WHERE analysis_id=? AND basename=?",
                          (analysis_id, basename)).fetchone()
        if alert is None:
            raise HTTPException(404, "No such alert")
        return alert

    def int_or_none(s):
        return int(s) if isinstance(s, str) and s.isdigit() else None

    @app.get("/analysis/{analysis_id}/alert/{basename}/chat", response_class=HTMLResponse)
    def chat_fragment(request: Request, analysis_id: int, basename: str,
                      run: int | None = None, open: int | None = None):
        """The "Ask an LLM" section (htmx: opening a conversation, polling)."""
        c = conn()
        try:
            alert = chat_alert(c, analysis_id, basename)
            ctx = chat_ctx(c, analysis_id, alert, run, open)
        finally:
            c.close()
        return fragment(request, "_chat.html", chat=ctx)

    @app.post("/analysis/{analysis_id}/alert/{basename}/chat", response_class=HTMLResponse)
    async def chat_post(request: Request, analysis_id: int, basename: str):
        """Start a conversation, ask a follow-up, try again, cancel, or delete
        (htmx; returns the section)."""
        form = await request.form()
        op = form.get("op")
        run_id = int_or_none(form.get("run"))
        chat_id = int_or_none(form.get("chat"))
        question = (form.get("question") or "").strip()
        c = conn()
        msg, start, open_id = None, None, chat_id
        try:
            alert = chat_alert(c, analysis_id, basename)
            if blind_mode(c) and reviews.current(c, analysis_id, alert["alert_id"]) is None:
                raise HTTPException(400, "Blind mode hides LASAA's answer until you review "
                                         "the alert.")
            ch = None
            if op != "new":
                ch = c.execute("SELECT * FROM chat WHERE chat_id=? AND analysis_id=? "
                               "AND alert_id=?", (chat_id, analysis_id,
                                                  alert["alert_id"])).fetchone()
                if ch is None:
                    raise HTTPException(404, "No such conversation")
            turns = chat_mod.turns_of(c, ch["chat_id"]) if ch else []
            pending = [t for t in turns if t["status"] == "pending"]
            try:
                if op in ("new", "ask") and not question:
                    raise ValueError("Type a question first.")
                if len(question) > chat_mod.MAX_QUESTION:
                    raise ValueError(f"A question can be at most {chat_mod.MAX_QUESTION:,} "
                                     "characters.")
                if op == "new":
                    key = form.get("model_key") or ""
                    spec = spec_of_key(c, key)
                    spec = models.validate(dict(spec, flex=False,
                                                concurrency=models.DEFAULT_CONCURRENCY))
                    var = models.key_var(spec)
                    if var and not os.environ.get(var):
                        raise ValueError(f"{var} isn't set in the server's environment.")
                    context = chat_context(c, alert, run_id)
                    label = models.label(spec) + (f", {spec['effort']} effort"
                                                  if spec["effort"] else "")
                    open_id = chat_mod.create(c, analysis_id, alert["alert_id"], run_id, spec,
                                              label, context)
                    start = chat_mod.add_turn(c, open_id, question)
                    db.set_setting(c, "chat_model", key)
                elif op in ("ask", "retry"):
                    if pending:
                        raise ValueError("Wait for the answer (or cancel it) first.")
                    if op == "retry":
                        if not turns or turns[-1]["status"] == "done":
                            raise ValueError("There is no question to try again.")
                        question = turns[-1]["question"]
                    start = chat_mod.add_turn(c, ch["chat_id"], question)
                elif op == "cancel":
                    for t in pending:
                        asker.cancel(t["turn_id"])
                    c.execute("UPDATE chat_turn SET status='cancelled', finished_at=? "
                              "WHERE chat_id=? AND status='pending'", (db.now(), ch["chat_id"]))
                elif op == "delete":
                    for t in pending:
                        asker.cancel(t["turn_id"])
                    c.execute("DELETE FROM chat WHERE chat_id=?", (ch["chat_id"],))
                    open_id = None
                else:
                    raise HTTPException(400, "Unknown action")
                c.commit()
                question = ""
            except ValueError as e:
                c.rollback()
                msg = str(e)
            if start is not None:
                asker.start(start)
            ctx = chat_ctx(c, analysis_id, alert, run_id, open_id, msg=msg, question=question)
            if ctx is None and msg:              # a section that isn't shown otherwise
                ctx = {"msg": msg, "url": f"/analysis/{analysis_id}/alert/{basename}/chat"}
        finally:
            c.close()
        return fragment(request, "_chat.html", chat=ctx)

    @app.post("/settings/blind")
    async def toggle_blind(request: Request):
        if not settings.blind_mode:
            raise HTTPException(404, "Blind mode is off; start the server with --blind-mode")
        form = await request.form()
        c = conn()
        db.set_setting(c, "blind", "0" if blind_mode(c) else "1")
        c.close()
        return RedirectResponse(local_url(form.get("back")) or "/", 303)

    def export_rows(request, analysis_id, run):
        c = conn()
        an, snap, proj, runs = load_analysis(c, analysis_id)
        cur_run = pick_run(runs, run)
        rows = alert_rows(c, analysis_id, cur_run)
        revs = reviews.current_all(c, analysis_id)
        c.close()
        f = {k: v for k, v in filters_of(request).items() if k != "hide_false"}
        name = f"{proj['slug']}-analysis{analysis_id}" + (f"-run{cur_run['run_id']}"
                                                          if cur_run else "")
        return an, apply_filters(rows, f), revs, name

    @app.get("/analysis/{analysis_id}/export.json")
    def export_json(request: Request, analysis_id: int, run: int | None = None):
        an, rows, revs, name = export_rows(request, analysis_id, run)
        id_field = db.loads(an["options"], {}).get("id_field") or "Alert_ID"
        return Response(export.adjudications_json(rows, revs, id_field),
                        media_type="application/json", headers={
                            "Content-Disposition": f'attachment; filename="{name}.json"'})

    @app.get("/analysis/{analysis_id}/export.csv")
    def export_csv(request: Request, analysis_id: int, run: int | None = None):
        an, rows, revs, name = export_rows(request, analysis_id, run)
        return Response(export.adjudications_csv(rows, revs), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})

    @app.get("/analysis/{analysis_id}/export.sarif")
    async def export_sarif(request: Request, analysis_id: int, run: int | None = None,
                           sup: str = ""):
        """The analysis's SARIF file with each result's verdict in
        properties.lasaa (sarif_to_lasaa.py -u).  *sup* "manual" adds SARIF
        suppressions for manual false verdicts, "all" for LLM ones too."""
        if sup not in ("", "manual", "all"):
            bad_request("Unknown suppression choice.")
        an, rows, revs, name = export_rows(request, analysis_id, run)
        an_opts = db.loads(an["options"], {})
        sarif_rel = an_opts.get("sarif")
        if not sarif_rel:
            raise HTTPException(404, "This analysis has no SARIF file (Clang analyses do).")
        c = conn()
        snap = c.execute("SELECT * FROM snapshot WHERE snap_id=?", (an["snap_id"],)).fetchone()
        c.close()
        src = ws.path(snap["dir"]) / "src"
        id_field = an_opts.get("id_field") or "Alert_ID"

        def make():
            with tempfile.TemporaryDirectory() as tmp:
                adj = Path(tmp) / "adjudications.json"
                out = Path(tmp) / "updated.sarif"
                adj.write_text(export.adjudications_json(rows, revs, id_field), encoding="utf-8")
                cmd = [sys.executable, str(jobs.CODE_DIR / "conv" / "sarif_to_lasaa.py"),
                       str(ws.path(an["dir"]) / sarif_rel), "-b", str(src), "-u", str(adj),
                       "-o", str(out)] + an_opts.get("sarif_args", [])
                cmd += {"": [], "manual": ["--sup-fp", "--sup-fp-manual"],
                        "all": ["--sup-fp"]}[sup]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   env=runs.env(id_field, secrets=False))
                if r.returncode != 0:
                    raise HTTPException(500, "sarif_to_lasaa.py failed: " + r.stderr[-500:])
                sarif = json.loads(out.read_text(encoding="utf-8"))
            # Point the relative URIs at the tree the snapshot was made from.
            for sr in sarif.get("runs", []):
                base = sr.get("originalUriBaseIds", {}).get("SRCROOT")
                if base is not None:
                    base["uri"] = "file://" + quote(snap["origin"].rstrip("/")) + "/"
            return json.dumps(sarif, indent=1, ensure_ascii=False) + "\n"
        text = await asyncio.to_thread(make)
        return Response(text, media_type="application/sarif+json", headers={
            "Content-Disposition": f'attachment; filename="{name}.sarif"'})

    @app.get("/snapshot/{snap_id}/file/{rel:path}", response_class=HTMLResponse)
    def file_view(request: Request, snap_id: int, rel: str, line: int = 0):
        c = conn()
        snap = c.execute("SELECT * FROM snapshot WHERE snap_id=?", (snap_id,)).fetchone()
        proj = snap and c.execute("SELECT * FROM project WHERE project_id=?",
                                  (snap["project_id"],)).fetchone()
        c.close()
        if snap is None:
            raise HTTPException(404, "No such snapshot")
        src = ws.path(snap["dir"]) / "src"
        p = codeview.pane(src, rel, [line] if line else [], func_bounds(snap), full=True)
        if p is None:
            raise HTTPException(404, "No such file in this snapshot")
        p["steps"], p["flag"] = {}, line or None
        p["editor"] = editor_link(snap, rel, line)
        return page(request, "file.html", snap=snap, proj=proj, pane=p)

    # ------------------------------------------------------------------
    # Snapshots, cppcheck, and jobs
    # ------------------------------------------------------------------

    def tail(path, n=200):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return "".join(collections.deque(f, n))
        except OSError:
            return ""

    def bad_request(msg):
        raise HTTPException(400, msg)

    @app.post("/snapshots")
    async def new_snapshot(request: Request):
        form = await request.form()
        name = (form.get("project") or "").strip()
        origin = os.path.abspath(os.path.expanduser((form.get("origin") or "").strip()))
        commit = (form.get("commit") or "").strip()
        if not name:
            bad_request("Give the project a name.")
        if not os.path.isdir(origin):
            bad_request(f"{origin} is not a directory on this machine.")
        if commit:
            try:
                commit = await asyncio.to_thread(snapshot_mod.resolve_commit, origin, commit)
            except ValueError as e:
                bad_request(str(e))
        # The form's required radios make the user choose; the command
        # counts only with "Build with command".
        build_command = ((form.get("build_command") or "").strip()
                         if form.get("build") == "yes" else "")
        if build_command and not runner.can_build():
            bad_request(jobs.NO_BUILD_MESSAGE)
        if build_command and not shutil.which("bear"):
            bad_request("bear isn't installed, so the build can't be recorded; use the "
                        "lasaa-web-ui Docker image (see lasaa_webui/README.md).")
        c = conn()
        proj = importer.get_or_create_project(c, name, origin)
        if build_command:
            c.execute("UPDATE project SET build_command=? WHERE project_id=?",
                      (build_command, proj["project_id"]))
            c.commit()
        params = {"origin": origin, "commit": commit, "label": (form.get("label") or "").strip(),
                  "exclude": shlex.split(form.get("exclude") or ""),
                  "build_command": build_command}
        job_id = runner.submit(c, proj["project_id"], "snapshot",
                               f"Snapshot of {origin}" + (f" at {commit[:10]}" if commit else "")
                               + (", built" if build_command else ""), params)
        c.close()
        return RedirectResponse(f"/job/{job_id}", 303)

    @app.get("/suggest-build", response_class=HTMLResponse)
    def suggest_build(request: Request, origin: str = ""):
        """A hint under the build-command field: a command for the build
        files at the top of *origin*, which the user can take or not."""
        origin = os.path.abspath(os.path.expanduser(origin.strip())) if origin.strip() else ""
        cmd = snapshot_mod.suggest_build_command(origin) if os.path.isdir(origin) else None
        c = conn()
        proj = c.execute("SELECT build_command FROM project WHERE origin=? AND build_command "
                         "IS NOT NULL AND NOT hidden ORDER BY project_id DESC LIMIT 1", (origin,)).fetchone()
        c.close()
        return templates.TemplateResponse(request, "_build_hint.html", {
            "suggested": cmd, "last": proj["build_command"] if proj else None})

    def create_analysis(c, snap, tool, opts):
        cur = c.execute("INSERT INTO analysis(snap_id, tool, options, status, dir, created_at) "
                        "VALUES (?, ?, ?, 'queued', '', ?)",
                        (snap["snap_id"], tool, json.dumps(opts), db.now()))
        an_id = cur.lastrowid
        c.execute("UPDATE analysis SET dir=? WHERE analysis_id=?",
                  (f"projects/{snap['slug']}/analyses/{an_id}", an_id))
        c.commit()
        return an_id

    def load_snapshot(c, snap_id):
        snap = c.execute("SELECT snapshot.*, project.slug FROM snapshot JOIN project "
                         "USING (project_id) WHERE snap_id=?", (snap_id,)).fetchone()
        if snap is None:
            c.close()
            raise HTTPException(404, "No such snapshot")
        return snap

    @app.post("/snapshot/{snap_id}/analyze")
    async def run_analyzers(request: Request, snap_id: int):
        """Run the checked analyzers into one new analysis."""
        form = await request.form()
        c = conn()
        snap = load_snapshot(c, snap_id)
        c.close()
        params, labels = {}, []
        if form.get("clang") == "1":
            if form.get("clang_preset") not in csa.PRESETS:
                bad_request("Unknown Clang preset.")
            if not snap["build_units"]:
                bad_request("Clang Static Analyzer needs a snapshot made with a build command "
                            "that compiled something.")
            params["clang"] = {"preset": form.get("clang_preset")}
            labels.append(("clang-analyzer", "clang"))
        if form.get("cppcheck") == "1":
            if form.get("cppcheck_preset") not in jobs.CPPCHECK_PRESETS:
                bad_request("Unknown cppcheck preset.")
            try:
                extra = jobs.check_cppcheck_args(shlex.split(form.get("extra_args") or ""))
            except (ValueError, jobs.JobError) as e:
                bad_request(str(e))
            params["cppcheck"] = {"preset": form.get("cppcheck_preset"), "extra_args": extra,
                                  "use_compdb": form.get("use_compdb") == "1"
                                  and bool(snap["build_units"])}
            labels.append(("cppcheck", "cppcheck"))
        if not params:
            bad_request("Choose at least one analyzer.")
        c = conn()
        an_id = create_analysis(c, snap, ", ".join(n for n, _ in labels), params)
        title = " and ".join(f"{n} ({params[k]['preset']})" for n, k in labels)
        job_id = runner.submit(c, snap["project_id"], "analyze",
                               f"{title} on snapshot {snap_id}", params,
                               snap_id=snap_id, analysis_id=an_id)
        c.close()
        return RedirectResponse(f"/job/{job_id}", 303)

    @app.get("/job/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: int):
        c = conn()
        job = c.execute("SELECT * FROM job WHERE job_id=?", (job_id,)).fetchone()
        proj = job and c.execute("SELECT * FROM project WHERE project_id=?",
                                 (job["project_id"],)).fetchone()
        c.close()
        if job is None:
            raise HTTPException(404, "No such job")
        return page(request, "job.html", job=job, proj=proj,
                    log_tail=tail(ws.path(job["log"])))

    @app.post("/job/{job_id}/cancel")
    async def job_cancel(request: Request, job_id: int):
        runner.cancel(job_id)
        return RedirectResponse(f"/job/{job_id}", 303)

    # ------------------------------------------------------------------
    # LASAA runs
    # ------------------------------------------------------------------

    RUN_FORM_DEFAULTS = {"scope": "all", "sample_n": "20", "seed": "", "skip_reviewed": "1",
                         "skip_external": "1", "skip_done": "", "model_key": "ready:0",
                         "provider": "OpenAI", "custom_model": "", "region": "us-east-1",
                         "region_custom": "", "prefix": "auto", "prefix_custom": "",
                         "base_url": "", "api_type": "", "api_key_name": "", "or_endpoint": "",
                         "max_output_tokens": "", "flex": "", "concurrency": "200",
                         "effort": "", "n": "5", "cc": "1", "threshold": "80%", "lre": "1"}

    def fields_for_llm(an):
        """The --fields-for-llm of runs on *an*: "" (every field but the ID)
        unless it was imported with lasaa_webui_import.py --fields-for-llm.
        (Older cppcheck analyses stored a list; it is ignored.)"""
        if an["tool"] != "imported":
            return ""
        return db.loads(an["options"], {}).get("fields_for_llm") or ""

    def matching_rows(c, analysis_id, filters):
        runs_ = load_analysis(c, analysis_id)[3]
        list_run = None
        if filters.get("run", "").isdigit():
            list_run = pick_run(runs_, int(filters["run"]))
        elif runs_:
            list_run = runs_[0]
        rows = alert_rows(c, analysis_id, list_run)
        return apply_filters(rows, {k: v for k, v in filters.items() if k in FILTER_KEYS})

    def snap_repo(snap):
        """(Repo_URL, Repo_Rev) for need_defs lookups, if the snapshot is a clean checkout."""
        return ((snap["repo_url"], snap["git_head"])
                if snap["repo_url"] and snap["git_head"] and not snap["git_dirty"] else None)

    def id_field_of(an):
        return db.loads(an["options"], {}).get("id_field") or "Alert_ID"

    def alert_records(c, an, alert_ids=None, internal=False):
        """The alerts of *an* (those in *alert_ids*; only those whose file is
        in the snapshot if *internal*), as in its alerts file."""
        id_field = id_field_of(an)
        records = [json.loads(r["record"]) for r in c.execute(
            "SELECT record FROM alert WHERE analysis_id=? AND (external=0 OR ?) ORDER BY ord",
            (an["analysis_id"], not internal))]
        if alert_ids is not None:
            wanted = set(alert_ids)
            records = [r for r in records if str(r.get(id_field)) in wanted]
        return records

    sizes_registry = prompt_sizes.Registry()

    def sizes_of(c, an, snap):
        """The prompt sizes of *an*'s alerts (prompt_sizes.py), and the
        arguments for their PromptSizes.ensure()."""
        repo = snap_repo(snap)
        fields = fields_for_llm(an)
        key = {"fields": fields, "repo": bool(repo), "code": runs.pipeline_stamp()}
        ps = sizes_registry.get(an["analysis_id"], ws.path(f"{an['dir']}/prompt_sizes.json"), key)
        id_field = id_field_of(an)
        records, inside = {}, []
        for r in c.execute("SELECT basename, external, record FROM alert WHERE analysis_id=?",
                           (an["analysis_id"],)):
            if r["external"]:        # the pipeline stops at an alert whose file is missing
                ps.sizes.setdefault(r["basename"], [])
            else:
                records[r["basename"]] = json.loads(r["record"])
                inside.append(r["basename"])
        src = ws.path(snap["dir"]) / "src"
        repos_dir = ws.path("repos") if repo else None

        def launch(order, scratch):
            subset = Path(scratch) / "subset.json"
            out = Path(scratch) / "out"
            out.mkdir()
            runs.write_subset(subset, [records[b] for b in order], src, repo)
            return (runs.dry_run_command(subset, src, out, fields, repos_dir),
                    runs.env(id_field, secrets=False), runs.CODE_DIR, out)
        return ps, inside, launch

    def read_run_form(fd):
        form = {k: fd.get(k, "") for k in RUN_FORM_DEFAULTS}
        filters = {k[2:]: v for k, v in fd.multi_items() if k.startswith("f_") and v}
        return form, filters, fd.getlist("pick")

    def saved_models(c):
        return [{"id": r["saved_id"], "name": r["name"], "spec": json.loads(r["spec"])}
                for r in c.execute("SELECT * FROM saved_model ORDER BY name")]

    def spec_of_key(c, key):
        """The spec of a ready-made ("ready:N") or saved ("saved:ID") model.
        Raises ValueError."""
        if key.startswith("ready:") and key[6:].isdigit() and int(key[6:]) < len(models.MODELS):
            return models.new_spec(**models.MODELS[int(key[6:])])
        if key.startswith("saved:") and key[6:].isdigit():
            row = c.execute("SELECT spec FROM saved_model WHERE saved_id=?",
                            (int(key[6:]),)).fetchone()
            if row is None:
                raise runs.RunError("That saved config was deleted; choose another model.")
            return models.new_spec(**{k: v for k, v in json.loads(row[0]).items()
                                      if k in models.SPEC_FIELDS})
        raise runs.RunError("Choose a model.")

    def spec_from_form(c, form):
        """The model spec (models.py) that the run form's Model panel
        describes.  A ready-made or saved model's provider, name, and
        endpoint come from it; the effort, region and prefix, flex tier, and
        concurrency always come from the form.  Raises ValueError."""
        key = form["model_key"]
        if key != "custom":
            spec = spec_of_key(c, key)
        else:
            try:
                cap = int(form["max_output_tokens"]) if form["max_output_tokens"].strip() else None
            except ValueError:
                raise runs.RunError("Max output tokens must be a whole number.")
            spec = models.new_spec(
                provider=form["provider"], model=form["custom_model"].strip(),
                base_url=form["base_url"].strip(), api_type=form["api_type"],
                api_key_name=form["api_key_name"].strip(),
                or_endpoint=form["or_endpoint"].strip(),
                max_output_tokens=cap if form["provider"] in ("Fireworks", "OpenRouter") else None)
        region = form["region_custom"].strip() if form["region"] == "custom" else form["region"]
        prefix = {"auto": "", "custom": form["prefix_custom"].strip()}.get(form["prefix"],
                                                                          form["prefix"])
        try:
            concurrency = int(form["concurrency"] or models.DEFAULT_CONCURRENCY)
        except ValueError:
            raise runs.RunError("Concurrency must be a whole number.")
        spec.update(effort=form["effort"], region=region, prefix=prefix,
                    flex=form["flex"] == "1", concurrency=concurrency)
        return models.validate(spec)

    def run_choice(c, an, form, filters, picks):
        """What the run form chooses: {spec, config (its cache identity),
        config_id (None if the config is new), opts, sel, out_rel}.  Raises
        ValueError for a form it can't use."""
        analysis_id = an["analysis_id"]
        if form["scope"] == "picked":
            rows = [d for d in alert_rows(c, analysis_id, None) if d["alert_id"] in set(picks)]
        else:
            rows = matching_rows(c, analysis_id, filters)
        spec = spec_from_form(c, form)
        config = models.config_of(spec)
        try:
            n = int(form["n"])
            sample_n = int(form["sample_n"] or 0)
            seed = int(form["seed"] or 0)
        except ValueError:
            raise runs.RunError("The trial count, sample size, and seed must be whole numbers.")
        opts = runs.run_opts(n, form["threshold"], form["cc"] == "1", form["lre"] == "1")
        row = c.execute("SELECT config_id FROM config WHERE client=? AND model=? AND effort=? "
                        "AND endpoint=?", (config["client"], config["model"], config["effort"],
                                           config["endpoint"])).fetchone()
        config_id = row[0] if row else None
        done = set()
        if form["skip_done"] == "1" and config_id is not None:
            done = {r[0] for r in c.execute(
                "SELECT rr.alert_id FROM run_result rr JOIN run USING (run_id) WHERE "
                "run.analysis_id=? AND run.config_id=? AND rr.verdict IS NOT NULL",
                (analysis_id, config_id))}
        sel = runs.choose(rows, scope=form["scope"], n=sample_n, seed=seed, picked=picks,
                          skip_reviewed=form["skip_reviewed"] == "1",
                          skip_external=form["skip_external"] == "1", skip_done=done)
        sel["filters"] = filters
        sel["form"] = form
        proj_slug = ws_slug(c, an)
        out_rel = (f"projects/{proj_slug}/lasaa/{analysis_id}/{config_id}"
                   if config_id is not None else None)
        sel["model"] = spec
        return {"spec": spec, "config": config, "config_id": config_id, "opts": opts,
                "sel": sel, "out_rel": out_rel}

    def ws_slug(c, an):
        return c.execute("SELECT project.slug FROM project JOIN snapshot USING (project_id) "
                         "WHERE snap_id=?", (an["snap_id"],)).fetchone()[0]

    def run_estimate(c, an, snap, ch):
        """(The estimate for run_choice() *ch*, or None if no prompt sizes
        are known yet; its PromptSizes).  Starts measuring any sizes not
        known yet, the chosen alerts first."""
        ps, inside, launch = sizes_of(c, an, snap)
        ps.ensure(inside, ch["sel"]["basenames"], launch)
        hist = runs.history(c, ch["config"]["model"], ch["config"]["effort"])
        price = models.price_for(ch["config"]["model"], models.load_prices(),
                                 ch["spec"]["provider"])
        out_dir = ws.path(ch["out_rel"]) if ch["out_rel"] else None
        est = runs.estimate(ps.sizes, ch["sel"]["basenames"], out_dir, ch["opts"], hist, price)
        return est, ps

    async def estimate_ctx(c, an, snap, form, filters, picks, wait=None):
        """The template variables for _estimate.html.  With *wait* (the
        version the page shows), first wait for newer sizes (a long poll)."""
        try:
            ch = run_choice(c, an, form, filters, picks)
            est, ps = run_estimate(c, an, snap, ch)
            if wait is not None and ps.version == wait and ps.running():
                await ps.wait(wait, LONG_POLL_SECONDS)
                est, ps = run_estimate(c, an, snap, ch)
        except (ValueError, OSError) as e:
            return {"est_error": str(e)}
        return {"e": est, "sel": ch["sel"], "opts": ch["opts"], "effort": ch["config"]["effort"],
                "measuring": ps.running(), "sizes_version": ps.version,
                "est_error": ps.error, "n_measured": len(ps.sizes)}

    def fragment(request, name, **ctx):
        ctx.setdefault("csrf", request.state.csrf_token)
        return templates.TemplateResponse(request, name, ctx)

    @app.get("/analysis/{analysis_id}/run/new", response_class=HTMLResponse)
    async def run_new(request: Request, analysis_id: int):
        c = conn()
        an, snap, proj, _ = load_analysis(c, analysis_id)
        filters = {k: v for k, v in filters_of(request).items() if k != "hide_false"}
        if request.query_params.get("run"):
            filters["run"] = request.query_params["run"]
        picks = request.query_params.getlist("pick")
        n_matching = len(matching_rows(c, analysis_id, filters))
        form = dict(RUN_FORM_DEFAULTS, scope="picked" if picks else "all",
                    seed=str(random.randrange(1, 10**6)))
        est = await estimate_ctx(c, an, snap, form, filters, picks)
        choice = model_choice_ctx(c)
        c.close()
        return page(request, "run_new.html", an=an, snap=snap, proj=proj, form=form,
                    fields_for_llm=fields_for_llm(an),
                    filters=filters, picks=picks, n_matching=n_matching,
                    list_qs=qs(**filters), providers=models.PROVIDERS, efforts=models.EFFORTS,
                    regions=models.BEDROCK_REGIONS, prefixes=models.BEDROCK_PREFIXES,
                    api_types=models.API_TYPES, key_suffix=models.KEY_SUFFIX,
                    default_cap=models.DEFAULT_OUTPUT_CAPS["Fireworks"],
                    key_status=key_status(), test_prompt=LLM_TEST_PROMPT, **choice, **est)

    def model_choice_ctx(c, msg=None):
        """The template variables for _model_choice.html (the model list)."""
        prices = models.load_prices()

        def priced(spec):
            spec = models.validate(dict(spec))
            return models.price_for(spec["model"], prices, spec["provider"])
        ready = [{"key": f"ready:{i}", "provider": m["provider"],
                  "label": models.label(models.validate(models.new_spec(**m))),
                  "price": priced(models.new_spec(**m))} for i, m in enumerate(models.MODELS)]
        saved = []
        for sv in saved_models(c):
            spec = models.new_spec(**{k: v for k, v in sv["spec"].items() if k in models.SPEC_FIELDS})
            try:
                price = priced(spec)
            except ValueError:
                price = None
            saved.append({"key": f"saved:{sv['id']}", "provider": spec["provider"],
                          "label": sv["name"], "price": price, "spec": spec})
        return {"ready_models": ready, "saved_models": saved, "model_msg": msg}

    def key_status():
        """{provider: whether its API key (or AWS credentials) can be found}."""
        status = {p: bool(os.environ.get(v)) for p, v in models.PROVIDER_KEYS.items()}
        status["AWS Bedrock"] = bool(
            os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE")
            or os.path.exists(os.path.expanduser("~/.aws/credentials")))
        return status

    def model_choice_fragment(request, c, fd, model_key, msg=None):
        form = {k: fd.get(k, "") for k in RUN_FORM_DEFAULTS}
        form["model_key"] = model_key
        return fragment(request, "_model_choice.html", form=form, **model_choice_ctx(c, msg))

    @app.post("/models/save", response_class=HTMLResponse)
    async def model_save(request: Request):
        """Save the Model panel's model as a named config (htmx), and select it."""
        fd = await request.form()
        form = {k: fd.get(k, "") for k in RUN_FORM_DEFAULTS}
        c = conn()
        try:
            spec = spec_from_form(c, form)
        except ValueError as e:
            r = model_choice_fragment(request, c, fd, form["model_key"], f"Not saved: {e}")
            c.close()
            return r
        name = (fd.get("save_name") or "").strip()[:100] or models.label(spec)
        c.execute("INSERT INTO saved_model(name, spec, created_at) VALUES (?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET spec=excluded.spec",
                  (name, json.dumps(spec), db.now()))
        c.commit()
        saved_id = c.execute("SELECT saved_id FROM saved_model WHERE name=?", (name,)).fetchone()[0]
        r = model_choice_fragment(request, c, fd, f"saved:{saved_id}", f"Saved as \u201c{name}\u201d.")
        c.close()
        return r

    @app.post("/models/delete", response_class=HTMLResponse)
    async def model_delete(request: Request):
        """Delete the selected saved config (htmx).  Its cached replies and
        runs stay; they belong to the model, not to the saved name."""
        fd = await request.form()
        key = fd.get("model_key", "")
        c = conn()
        msg = None
        if key.startswith("saved:") and key[6:].isdigit():
            row = c.execute("SELECT name FROM saved_model WHERE saved_id=?", (int(key[6:]),)).fetchone()
            if row:
                c.execute("DELETE FROM saved_model WHERE saved_id=?", (int(key[6:]),))
                c.commit()
                msg = f"Deleted \u201c{row[0]}\u201d."
        r = model_choice_fragment(request, c, fd, "ready:0", msg)
        c.close()
        return r

    @app.post("/llm-test", response_class=HTMLResponse)
    async def llm_test(request: Request):
        """Send a short prompt to the Model panel's model, as a run would (htmx)."""
        fd = await request.form()
        form = {k: fd.get(k, "") for k in RUN_FORM_DEFAULTS}
        prompt = (fd.get("test_prompt") or "").strip()[:2000] or LLM_TEST_PROMPT
        c = conn()
        try:
            spec = spec_from_form(c, form)
        except ValueError as e:
            return fragment(request, "_llm_test.html", error=str(e))
        finally:
            c.close()
        var = models.key_var(spec)
        if var and not os.environ.get(var):
            return fragment(request, "_llm_test.html",
                            error=f"{var} isn't set in the server's environment.")
        spec = dict(spec, max_output_tokens=LLM_TEST_MAX_OUTPUT)
        result = await runs.test_llm(spec, prompt, LLM_TEST_SECONDS)
        return fragment(request, "_llm_test.html", **result)

    @app.post("/analysis/{analysis_id}/estimate", response_class=HTMLResponse)
    async def run_estimate_fragment(request: Request, analysis_id: int, wait: int | None = None):
        """The estimate for the run form as it now stands (htmx).  After a
        change to the form, it also takes back a prepared run's Start
        button, which no longer matches.  With *wait*, it is the estimate's
        long poll for prompt sizes still being measured, and leaves the
        buttons alone."""
        fd = await request.form()
        form, filters, picks = read_run_form(fd)
        c = conn()
        an, snap, _, _ = load_analysis(c, analysis_id)
        est = await estimate_ctx(c, an, snap, form, filters, picks, wait=wait)
        c.close()
        return fragment(request, "_estimate.html", an=an, draft_id=fd.get("draft", ""),
                        oob=wait is None, **est)

    @app.post("/analysis/{analysis_id}/runs", response_class=HTMLResponse)
    async def run_create(request: Request, analysis_id: int):
        """Prepare a run (htmx): save it as a draft, with its subset file and
        command, and offer its Start button and budget."""
        fd = await request.form()
        form, filters, picks = read_run_form(fd)
        c = conn()
        an, snap, proj, _ = load_analysis(c, analysis_id)
        old = fd.get("draft", "")
        if old.isdigit():           # the draft this page prepared before
            row = c.execute("SELECT run_id FROM run WHERE run_id=? AND analysis_id=? AND "
                            "status='draft'", (int(old), analysis_id)).fetchone()
            if row:
                c.execute("DELETE FROM run WHERE run_id=?", (row[0],))
                c.commit()
                shutil.rmtree(ws.path(f"projects/{proj['slug']}/runs/{row[0]}"),
                              ignore_errors=True)
        try:
            ch = run_choice(c, an, form, filters, picks)
            config = ch["config"]
            if ch["config_id"] is None:
                c.execute("INSERT OR IGNORE INTO config(client, model, effort, endpoint, "
                          "created_at) VALUES (?,?,?,?,?)",
                          (config["client"], config["model"], config["effort"],
                           config["endpoint"], db.now()))
                c.commit()
                ch = run_choice(c, an, form, filters, picks)
            est, ps = run_estimate(c, an, snap, ch)
            while est is None and ps.running():      # wait for the first sizes
                await ps.wait(ps.version, LONG_POLL_SECONDS)
                est, ps = run_estimate(c, an, snap, ch)
            if est is None:
                raise runs.RunError(ps.error or "The prompt sizes couldn't be measured.")
        except (ValueError, OSError) as e:
            c.close()
            return fragment(request, "_run_actions.html", an=an, prep_error=str(e))
        sel, opts, out_rel = ch["sel"], ch["opts"], ch["out_rel"]
        sel["estimate"] = est
        # The alerts the dry run found get no prompt, so that the progress bar
        # can leave them out (the job confirms the list when it ends).
        sel["no_prompt"] = [b for b in sel["basenames"] if ps.sizes.get(b) == []]
        cur = c.execute("INSERT INTO run(analysis_id, config_id, out_dir, opts, selection, status, "
                        "created_at) VALUES (?,?,?,?,?, 'draft', ?)",
                        (analysis_id, ch["config_id"], out_rel, json.dumps(opts),
                         json.dumps(sel), db.now()))
        run_id = cur.lastrowid
        c.commit()
        run_dir = ws.path(f"projects/{proj['slug']}/runs/{run_id}")
        run_dir.mkdir(parents=True, exist_ok=True)
        src = ws.path(snap["dir"]) / "src"
        repo = snap_repo(snap)
        runs.write_subset(run_dir / "subset.json", alert_records(c, an, sel["alert_ids"]), src, repo)
        cmd = runs.command(run_dir / "subset.json", src, ws.path(out_rel), opts,
                           fields_for_llm(an), ch["spec"],
                           repos_dir=ws.path("repos") if repo else None)
        c.execute("UPDATE run SET command=? WHERE run_id=?", (json.dumps(cmd), run_id))
        c.commit()
        c.close()
        return fragment(request, "_run_actions.html", an=an, draft_id=run_id, sel=sel, e=est,
                        budget_default=runs.budget_default(est),
                        command=shlex.join(str(a) for a in cmd))

    def load_run(c, run_id):
        run = c.execute("SELECT run.*, config.client, config.model, config.effort, "
                        "config.endpoint FROM run JOIN config USING (config_id) WHERE run_id=?",
                        (run_id,)).fetchone()
        if run is None:
            raise HTTPException(404, "No such run")
        return run

    @app.get("/run/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, run_id: int):
        c = conn()
        run = load_run(c, run_id)
        an, snap, proj, _ = load_analysis(c, run["analysis_id"])
        job = c.execute("SELECT * FROM job WHERE run_id=? ORDER BY job_id DESC LIMIT 1",
                        (run_id,)).fetchone()
        c.close()
        sel = db.loads(run["selection"], {})
        if run["status"] == "draft":     # prepared but not started
            return RedirectResponse(f"/analysis/{an['analysis_id']}/run/new", 303)
        prog = runs.progress(ws.path(run["out_dir"]), sel.get("basenames") or [],
                             lre=bool(db.loads(run["opts"], {}).get("LRE", True)),
                             no_prompt=sel.get("no_prompt") or ())
        cmd = json.loads(run["command"]) if run["command"] and run["command"].startswith("[") \
            else run["command"]
        spec = sel.get("model")
        # A local LLM server (the mock, for demos) answers in seconds, so
        # show its progress more often.
        poll_seconds = 1 if models.is_local_url(run["endpoint"] or "") else 2
        return page(request, "run.html", run=run, an=an, snap=snap, proj=proj, sel=sel,
                    poll_seconds=poll_seconds,
                    model_label=models.label(spec) if spec else run["model"],
                    opts=db.loads(run["opts"]), job=job, prog=prog,
                    log_tail=tail(ws.path(job["log"]), 60) if job else "",
                    command=shlex.join(str(a) for a in cmd) if isinstance(cmd, list) else (cmd or ""))

    def parse_budget(form, run):
        try:
            b = form.get("budget")
            bt = form.get("budget_tokens")
            budget = float(b) if b not in (None, "") else None
            budget_tokens = int(float(bt)) if bt not in (None, "") else None
        except ValueError:
            bad_request("The budget must be a number.")
        if (budget is not None and budget <= 0) or (budget_tokens is not None and budget_tokens <= 0):
            bad_request("The budget must be more than zero.")
        return budget, budget_tokens

    def start_run(c, run):
        an, snap, proj, _ = load_analysis(c, run["analysis_id"])
        c.execute("UPDATE run SET status='queued' WHERE run_id=?", (run["run_id"],))
        c.commit()
        return runner.submit(c, proj["project_id"], "lasaa",
                             f"LASAA run {run['run_id']} ({run['model']}) on analysis "
                             f"{run['analysis_id']}", {}, analysis_id=None, run_id=run["run_id"])

    @app.post("/run/{run_id}/start")
    async def run_start(request: Request, run_id: int):
        form = await request.form()
        c = conn()
        run = load_run(c, run_id)
        if run["status"] != "draft":
            c.close()
            bad_request("This run has already been started.")
        budget, budget_tokens = parse_budget(form, run)
        c.execute("UPDATE run SET budget=?, budget_tokens=? WHERE run_id=?",
                  (budget, budget_tokens, run_id))
        c.commit()
        start_run(c, load_run(c, run_id))
        c.close()
        return RedirectResponse(f"/run/{run_id}", 303)

    @app.post("/run/{run_id}/resume")
    async def run_resume(request: Request, run_id: int):
        form = await request.form()
        c = conn()
        run = load_run(c, run_id)
        if run["status"] not in ("failed", "cancelled", "over-budget", "interrupted"):
            c.close()
            bad_request("Only a stopped run can be resumed.")
        budget, budget_tokens = parse_budget(form, run)
        c.execute("UPDATE run SET budget=?, budget_tokens=? WHERE run_id=?",
                  (budget if budget is not None else run["budget"],
                   budget_tokens if budget_tokens is not None else run["budget_tokens"], run_id))
        c.commit()
        start_run(c, load_run(c, run_id))
        c.close()
        return RedirectResponse(f"/run/{run_id}", 303)

    @app.post("/run/{run_id}/cancel")
    async def run_cancel(request: Request, run_id: int):
        c = conn()
        job = c.execute("SELECT job_id FROM job WHERE run_id=? ORDER BY job_id DESC LIMIT 1",
                        (run_id,)).fetchone()
        c.close()
        if job:
            runner.cancel(job["job_id"])
        return RedirectResponse(f"/run/{run_id}", 303)

    return SecurityMiddleware(app, token, settings.allowed_hosts)
