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
"""Long-running jobs: making a snapshot (and building it), running cppcheck
and Clang Static Analyzer into one analysis, and running LASAA.

Jobs run in the server's event loop, one at a time per project.  Each
subprocess gets its own process group, so cancelling a LASAA run also stops
its LLM client.  Output goes to jobs/<job_id>.log in the workspace.  When the
server starts, jobs left running or queued are marked "interrupted"; a LASAA
run is resumed by running the same command again, since the pipeline's cache
skips work already done.
"""

import asyncio
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from . import alerts as alerts_mod
from . import db, importer, indexer, models, runs, snapshot

CODE_DIR = Path(__file__).resolve().parent.parent
MONITOR_SECONDS = 5
# Builds share one uid (snapshot.BUILD_UID), and cleaning up after one kills
# every process of that uid, so only one build runs at a time, across projects.
BUILD_LOCK = threading.Lock()
NO_BUILD_MESSAGE = (
    "Builds are turned off: the server isn't running as root, so a build would run as "
    "the server's own user, with all of its access (see lasaa_webui/README.md).  Run the "
    "server in the Docker container, or, only for code whose build you trust, start it "
    "with --allow-builds-as-server-user.")
CPPCHECK_PRESETS = {"warnings": "warning,portability",
                    "default": "warning,portability,performance",
                    "everything": "warning,portability,performance,style"}
# Extra cppcheck arguments allowed from the form (no --addon, --output-file, ...).
CPPCHECK_ARG_PREFIXES = ("-I", "-D", "-U", "--std=", "--library=", "--platform=",
                         "--suppress=", "--max-configs=", "--force", "--inconclusive")


class JobError(Exception):
    pass


def check_cppcheck_args(args):
    """*args* if every one is an allowed cppcheck option ("-I DIR" may be two words)."""
    expect_value = False
    for a in args:
        if expect_value:
            if a.startswith("-"):
                raise JobError(f"cppcheck option {prev!r} needs a value.")
            expect_value = False
        elif a in ("-I", "-D", "-U"):
            expect_value, prev = True, a
        elif not a.startswith(CPPCHECK_ARG_PREFIXES):
            raise JobError(f"cppcheck argument {a!r} isn't allowed here.")
    if expect_value:
        raise JobError(f"cppcheck option {args[-1]!r} needs a value.")
    return args


class JobRunner:
    def __init__(self, ws, allow_builds_as_server_user=False):
        self.ws = ws
        self.allow_builds_as_server_user = allow_builds_as_server_user
        self.procs = {}          # job_id -> asyncio subprocess
        self.stopping = {}       # job_id -> status to end with (cancelled, over-budget)
        self.tasks = {}

    def can_build(self):
        """Whether snapshots may run build commands (see NO_BUILD_MESSAGE)."""
        return snapshot.builds_as_build_user() or self.allow_builds_as_server_user

    # -- bookkeeping -----------------------------------------------------

    def recover(self):
        """Mark jobs that a previous server left running or queued, and stop
        any build processes it left behind."""
        if snapshot.builds_as_build_user():
            snapshot.kill_build_processes()
        c = self.ws.connect()
        for j in c.execute("SELECT * FROM job WHERE status IN ('running', 'queued')").fetchall():
            c.execute("UPDATE job SET status='interrupted', finished_at=? WHERE job_id=?",
                      (db.now(), j["job_id"]))
            if j["run_id"]:
                c.execute("UPDATE run SET status='interrupted' WHERE run_id=?", (j["run_id"],))
            if j["analysis_id"]:
                c.execute("UPDATE analysis SET status='interrupted' WHERE analysis_id=? "
                          "AND status!='done'", (j["analysis_id"],))
        c.commit()
        c.close()

    def submit(self, conn, project_id, kind, title, params, **refs):
        cur = conn.execute(
            "INSERT INTO job(project_id, kind, title, params, status, snap_id, analysis_id, "
            "run_id, log, created_at) VALUES (?,?,?,?,'queued',?,?,?,'',?)",
            (project_id, kind, title, json.dumps(params), refs.get("snap_id"),
             refs.get("analysis_id"), refs.get("run_id"), db.now()))
        job_id = cur.lastrowid
        conn.execute("UPDATE job SET log=? WHERE job_id=?", (f"jobs/{job_id}.log", job_id))
        conn.commit()
        self.ws.path("jobs").mkdir(exist_ok=True)
        self._kick(project_id)
        return job_id

    def _kick(self, project_id):
        c = self.ws.connect()
        busy = c.execute("SELECT 1 FROM job WHERE project_id=? AND status='running'",
                         (project_id,)).fetchone()
        nxt = None if busy else c.execute(
            "SELECT job_id FROM job WHERE project_id=? AND status='queued' ORDER BY job_id "
            "LIMIT 1", (project_id,)).fetchone()
        if nxt:
            c.execute("UPDATE job SET status='running', started_at=? WHERE job_id=?",
                      (db.now(), nxt["job_id"]))
            c.commit()
            job_id = nxt["job_id"]
            self.tasks[job_id] = asyncio.get_running_loop().create_task(self._run(job_id))
        c.close()

    def cancel(self, job_id):
        c = self.ws.connect()
        j = c.execute("SELECT * FROM job WHERE job_id=?", (job_id,)).fetchone()
        if j and j["status"] == "queued":
            c.execute("UPDATE job SET status='cancelled', finished_at=? WHERE job_id=?",
                      (db.now(), job_id))
            if j["run_id"]:
                c.execute("UPDATE run SET status='cancelled' WHERE run_id=?", (j["run_id"],))
            c.commit()
        elif j and j["status"] == "running":
            self._stop(job_id, "cancelled")
        c.close()

    def _stop(self, job_id, status):
        self.stopping[job_id] = status
        proc = self.procs.get(job_id)
        if proc is not None and proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def _run(self, job_id):
        c = self.ws.connect()
        job = c.execute("SELECT * FROM job WHERE job_id=?", (job_id,)).fetchone()
        c.close()
        log_path = self.ws.path(job["log"])
        status, error = "done", None
        with open(log_path, "a", encoding="utf-8") as log:
            def say(msg):
                log.write(msg.rstrip("\n") + "\n")
                log.flush()
            say(f"=== {job['title']} ({db.now()})")
            try:
                status = await KINDS[job["kind"]](self, job, say, log) or "done"
            except JobError as e:
                status, error = "failed", str(e)
                say(f"Error: {e}")
            except Exception as e:      # keep the server up; record what happened
                status, error = "failed", f"{type(e).__name__}: {e}"
                say(traceback.format_exc())
            status = self.stopping.pop(job_id, None) or status
            say(f"=== {status} ({db.now()})")
        self.procs.pop(job_id, None)
        c = self.ws.connect()
        c.execute("UPDATE job SET status=?, error=?, finished_at=? WHERE job_id=?",
                  (status, error, db.now(), job_id))
        if job["run_id"]:
            c.execute("UPDATE run SET status=?, finished_at=? WHERE run_id=?",
                      (status, db.now(), job["run_id"]))
        if job["analysis_id"] and status != "done":
            c.execute("UPDATE analysis SET status=? WHERE analysis_id=?",
                      (status, job["analysis_id"]))
        c.commit()
        c.close()
        self.tasks.pop(job_id, None)
        self._kick(job["project_id"])

    async def run_process(self, job_id, cmd, log, cwd, env, monitor=None):
        """Run *cmd* in its own process group with output to *log*; return its
        exit code.  *monitor*, if given, is called every few seconds."""
        log.write("$ " + shlex.join(str(a) for a in cmd) + "\n")
        log.flush()
        proc = await asyncio.create_subprocess_exec(
            *[str(a) for a in cmd], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.procs[job_id] = proc
        if job_id in self.stopping:          # cancelled while starting
            self._stop(job_id, self.stopping[job_id])
        while True:
            try:
                await asyncio.wait_for(asyncio.shield(proc.wait()), MONITOR_SECONDS)
                break
            except asyncio.TimeoutError:
                if monitor is not None:
                    await monitor()
        return proc.returncode


# -------------------------------------------------------------------
# Job kinds.  Each returns the final status (or None for "done").
# -------------------------------------------------------------------

async def job_snapshot(runner, job, say, log):
    p = json.loads(job["params"])
    ws = runner.ws
    loop = asyncio.get_running_loop()

    def build(work_dir, compdb_path):
        # Called from the worker thread; the build runs in the event loop, as
        # its own process group, so that cancel stops it.
        say(f"Building in {work_dir}: {p['build_command']}")
        cmd = ["bear", "--output", compdb_path, "--", "sh", "-c", p["build_command"]]
        env = importer.snapshot_env()
        as_user = snapshot.builds_as_build_user()
        if as_user:
            # Not a sandbox (see snapshot.BUILD_UID), but the build can't read
            # the server's environment or the workspace, or write root's files.
            snapshot.chown_tree(work_dir.parent, snapshot.BUILD_UID, snapshot.BUILD_GID)
            cmd = snapshot.as_build_user(cmd)
            env.update(HOME=str(work_dir), USER=snapshot.BUILD_USER,
                       LOGNAME=snapshot.BUILD_USER)
            say(f"(as user {snapshot.BUILD_USER}, uid {snapshot.BUILD_UID})")
        elif runner.allow_builds_as_server_user:
            say("(as the server's own user, since the server isn't running as root and was "
                "started with --allow-builds-as-server-user)")
        else:                   # a job queued before a restart without the option
            raise JobError(NO_BUILD_MESSAGE)
        if not BUILD_LOCK.acquire(blocking=False):
            say("Waiting for another project's build to finish ...")
            BUILD_LOCK.acquire()
        try:
            rc = asyncio.run_coroutine_threadsafe(
                runner.run_process(job["job_id"], cmd, log, work_dir, env), loop).result()
        finally:
            try:
                if as_user:
                    left = snapshot.kill_build_processes()
                    if left:
                        raise JobError(f"{left} process(es) of the build couldn't be stopped.")
            finally:
                BUILD_LOCK.release()
        if job["job_id"] in runner.stopping:
            raise JobError("The build was stopped.")
        return rc

    def work():
        c = ws.connect()
        proj = c.execute("SELECT * FROM project WHERE project_id=?",
                         (job["project_id"],)).fetchone()
        snap = importer.create_snapshot(
            ws, c, proj, p["origin"], label=p.get("label"), excludes=p.get("exclude", []),
            includes=p.get("include", []), commit=p.get("commit") or None, log=say,
            build_command=p.get("build_command") or None, build=build)
        c.execute("UPDATE job SET snap_id=? WHERE job_id=?", (snap["snap_id"], job["job_id"]))
        c.commit()
        c.close()
    await asyncio.to_thread(work)


async def run_cppcheck(runner, job, p, an_dir, snap_dir, say, log):
    """Run cppcheck (options *p*) on the snapshot and convert its output;
    return (alerts file, version, options to record)."""
    src = snap_dir / "src"
    version = subprocess.run(["cppcheck", "--version"], capture_output=True,
                             text=True).stdout.strip()
    say(version)
    xml = an_dir / "cppcheck.xml"
    compdb = snap_dir / "compile_commands.json"
    use_compdb = bool(p.get("use_compdb")) and compdb.exists()
    if p.get("use_compdb") and not use_compdb:
        raise JobError("This snapshot has no compile_commands.json.")
    # With the compilation database, the defines and include paths come
    # from the build; --relative-paths keeps the reported paths relative.
    inputs = ([f"--project={compdb}", f"--relative-paths={src}"] if use_compdb
              else ["-D_GNU_SOURCE", "."])
    cmd = (["cppcheck", "-q", "--xml", f"--output-file={xml}",
            f"--enable={CPPCHECK_PRESETS[p['preset']]}", "--inconclusive", "--library=posix",
            f"-j{p.get('jobs') or os.cpu_count() or 1}"]
           + check_cppcheck_args(p.get("extra_args", [])) + inputs)
    clean_env = runs.env("Alert_ID", secrets=False)
    rc = await runner.run_process(job["job_id"], cmd, log, src, clean_env)
    if job["job_id"] in runner.stopping:
        return None
    if rc != 0 or not xml.exists():
        raise JobError(f"cppcheck exited with status {rc}.")
    alerts_json = an_dir / "cppcheck.alerts.json"
    rc = await runner.run_process(
        job["job_id"], [sys.executable, CODE_DIR / "conv" / "cppcheck_to_lasaa.py", xml,
                        "-o", alerts_json], log, CODE_DIR, clean_env)
    if rc != 0:
        raise JobError(f"cppcheck_to_lasaa.py exited with status {rc}.")
    return alerts_json, version, {"preset": p["preset"],
                                  "extra_args": p.get("extra_args", []),
                                  "use_compdb": use_compdb,
                                  "command": shlex.join(str(a) for a in cmd)}


# sarif_to_lasaa.py options for CSA's SARIF, recorded with the analysis so
# that the SARIF export (-u) computes the same Alert_IDs.  CSA gives no
# severity, so Level would always be SARIF's default "warning".
CSA_SARIF_ARGS = ["--no-default-level"]


async def run_csa(runner, job, p, an_dir, snap_dir, say, log):
    """Run Clang Static Analyzer (options *p*) over the snapshot's
    compilation database and convert the merged SARIF; return (alerts
    file, version, options to record)."""
    src = snap_dir / "src"
    compdb = snap_dir / "compile_commands.json"
    if not compdb.exists():
        raise JobError("This snapshot has no compile_commands.json; make a snapshot with a "
                       "build command first.")
    r = subprocess.run(["clang", "--version"], capture_output=True, text=True)
    version = r.stdout.splitlines()[0] if r.returncode == 0 and r.stdout else "clang (unknown)"
    say(version)
    out = an_dir / "csa"
    clean_env = runs.env("Alert_ID", secrets=False)
    cmd = [sys.executable, "-m", "lasaa_webui.csa", compdb, out, "--root", src,
           "--preset", p["preset"], "-j", str(p.get("jobs") or os.cpu_count() or 1)]
    rc = await runner.run_process(job["job_id"], cmd, log, CODE_DIR, clean_env)
    if job["job_id"] in runner.stopping:
        return None
    sarif = out / "merged.sarif"
    if rc != 0 or not sarif.exists():
        raise JobError(f"Clang Static Analyzer exited with status {rc}.")
    with open(out / "summary.json", encoding="utf-8") as f:
        summary = json.load(f)
    alerts_json = an_dir / "clang.alerts.json"
    rc = await runner.run_process(
        job["job_id"], [sys.executable, CODE_DIR / "conv" / "sarif_to_lasaa.py", sarif,
                        "-b", src, *CSA_SARIF_ARGS, "-o", alerts_json], log, CODE_DIR,
        clean_env)
    if rc != 0:
        raise JobError(f"sarif_to_lasaa.py exited with status {rc}.")
    return alerts_json, version, {"preset": p["preset"], "units": summary["units"],
                                  "failed_units": [f["file"] for f in summary["failed"]],
                                  "duplicates_dropped": summary["duplicates_dropped"],
                                  "command": shlex.join(str(a) for a in cmd)}


# The analyzers an analysis can run, in the order they run: the params
# key, the Tool for alerts without one, and the runner.
ANALYZERS = (("clang", "clang", run_csa), ("cppcheck", "cppcheck", run_cppcheck))


async def job_analyze(runner, job, say, log):
    """Run the analyzers in the job's params ({"clang": {...}, "cppcheck":
    {...}}, either optional) and put all their alerts into one analysis.
    If any of them fails, so does the analysis."""
    p = json.loads(job["params"])
    ws = runner.ws
    c = ws.connect()
    an = c.execute("SELECT * FROM analysis WHERE analysis_id=?", (job["analysis_id"],)).fetchone()
    snap = c.execute("SELECT * FROM snapshot WHERE snap_id=?", (an["snap_id"],)).fetchone()
    c.execute("UPDATE analysis SET status='running' WHERE analysis_id=?", (an["analysis_id"],))
    c.commit()
    c.close()
    an_dir = ws.path(an["dir"])
    an_dir.mkdir(parents=True, exist_ok=True)
    snap_dir = ws.path(snap["dir"])
    done = []                 # (key, fallback tool, alerts file, version, options)
    for key, tool, run in ANALYZERS:
        if not p.get(key):
            continue
        say(f"--- {tool}")
        res = await run(runner, job, p[key], an_dir, snap_dir, say, log)
        if res is None:       # stopped
            return None
        done.append((key, tool) + res)
    if not done:
        raise JobError("No analyzer was chosen.")

    def load():
        alert_list, tools = [], []
        for key, tool, path, _, _ in done:
            part = alerts_mod.load_alert_file(str(path))
            say(f"{tool}: {len(part)} alerts.")
            alert_list += part
            tools += [tool] * len(part)
        with open(an_dir / "alerts.json", "w", encoding="utf-8") as f:
            json.dump(alert_list, f, indent=2)
            f.write("\n")
        c = ws.connect()
        n = importer.insert_alerts(c, an["analysis_id"], alert_list, "Alert_ID",
                                   snap_dir / "src", say, tool=tools)
        opts = {"id_field": "Alert_ID", "tools": [t for _, t, *_ in done],
                **{key: o for key, _, _, _, o in done}}
        if p.get("clang"):
            opts["sarif"] = "csa/merged.sarif"
            opts["sarif_args"] = CSA_SARIF_ARGS
        c.execute("UPDATE analysis SET status='done', tool_version=?, options=? "
                  "WHERE analysis_id=?", ("; ".join(v for _, _, _, v, _ in done),
                                          json.dumps(opts), an["analysis_id"]))
        c.commit()
        c.close()
        say(f"{n} alerts in all.")
    await asyncio.to_thread(load)


async def job_lasaa(runner, job, say, log):
    ws = runner.ws
    c = ws.connect()
    run = c.execute("SELECT run.*, config.model FROM run JOIN config USING (config_id) "
                    "WHERE run_id=?", (job["run_id"],)).fetchone()
    an = c.execute("SELECT * FROM analysis WHERE analysis_id=?", (run["analysis_id"],)).fetchone()
    c.execute("UPDATE run SET status='running' WHERE run_id=?", (run["run_id"],))
    c.commit()
    c.close()
    sel = json.loads(run["selection"])
    out_dir = ws.path(run["out_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    spec = sel.get("model") or {}
    if spec:
        n = runs.prune_truncated_replies(out_dir, sel["basenames"], models.output_cap(spec))
        if n:
            say(f"Removed {n} replies cut short by a lower output-token cap, to ask again.")
    n = runs.prune_pending_queries(out_dir)
    if n:
        say(f"Removed {n} unanswered query file(s) left from earlier runs.")
    price = models.price_for(run["model"], models.load_prices(), spec.get("provider"))
    since = time.time() - 1
    id_field = db.loads(an["options"], {}).get("id_field") or "Alert_ID"

    def index():
        c = ws.connect()
        indexer.index_run(c, ws, run["run_id"])
        s = runs.spend(c, run["out_dir"], since, sel["basenames"], price)
        prev = db.loads(c.execute("SELECT selection FROM run WHERE run_id=?",
                                  (run["run_id"],)).fetchone()[0], {})
        spent = prev.get("spent_before", {"input_tokens": 0, "output_tokens": 0})
        tin = spent["input_tokens"] + s["input_tokens"]
        tout = spent["output_tokens"] + s["output_tokens"]
        cost = models.cost(price, tin, tout)
        c.execute("UPDATE run SET input_tokens=?, output_tokens=?, cost=? WHERE run_id=?",
                  (tin, tout, cost, run["run_id"]))
        c.commit()
        c.close()
        return tin, tout, cost

    async def monitor():
        tin, tout, cost = await asyncio.to_thread(index)
        if run["budget"] is not None and cost is not None and cost > run["budget"]:
            say(f"Budget of ${run['budget']:.2f} reached (${cost:.2f} spent); stopping.")
            runner._stop(job["job_id"], "over-budget")
        elif run["budget_tokens"] is not None and tin + tout > run["budget_tokens"]:
            say(f"Budget of {run['budget_tokens']:,} tokens reached; stopping.")
            runner._stop(job["job_id"], "over-budget")

    cmd = json.loads(run["command"])
    rc = await runner.run_process(job["job_id"], cmd, log, CODE_DIR, runs.env(id_field),
                                  monitor=monitor)
    tin, tout, cost = await asyncio.to_thread(index)
    # Remember what this attempt spent, so a resumed run adds to it.
    c = ws.connect()
    sel["spent_before"] = {"input_tokens": tin, "output_tokens": tout}
    c.execute("UPDATE run SET selection=? WHERE run_id=?", (json.dumps(sel), run["run_id"]))
    c.commit()
    c.close()
    if job["job_id"] in runner.stopping:
        return None
    if rc != 0:
        p = runs.progress(out_dir, sel["basenames"])
        say(f"{p['finished']} of {p['alerts']} alerts have a final answer.")
        raise JobError(f"adjudicate_alerts.py exited with status {rc}.")
    # Alerts the pipeline gave no prompt aren't a failure: say which they are.
    no_prompt = runs.no_prompt_alerts(out_dir, sel["basenames"])
    c = ws.connect()
    sel["no_prompt"] = no_prompt
    c.execute("UPDATE run SET selection=? WHERE run_id=?", (json.dumps(sel), run["run_id"]))
    c.commit()
    c.close()
    p = runs.progress(out_dir, sel["basenames"], no_prompt=no_prompt)
    say(f"{p['finished']} of {p['alerts']} alerts have a final answer.")
    if no_prompt:
        say(f"{len(no_prompt)} alert{'s' if len(no_prompt) != 1 else ''} got no prompt (the "
            "file is outside the snapshot, or LASAA couldn't find the enclosing function), "
            "so they have no verdict: " + ", ".join(no_prompt[:20])
            + (" …" if len(no_prompt) > 20 else ""))
    if p["finished"] < p["alerts"]:
        raise JobError(f"Only {p['finished']} of {p['alerts']} alerts have a final answer; "
                       "see the log (the LLM client may have failed).")


KINDS = {"snapshot": job_snapshot, "analyze": job_analyze, "lasaa": job_lasaa}
