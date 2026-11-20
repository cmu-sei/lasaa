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
"""LASAA runs started from the UI: choosing alerts, building the
adjudicate_alerts.py command, estimating cost, and tracking progress.

Each (analysis, config) has one output directory, shared by its runs as a
cache.  A run writes its alerts to a subset file with Base_Dir set to the
snapshot's src/, so the pipeline shows the LLM paths relative to it: prompts
don't depend on where the workspace is.
"""

import asyncio
import collections
import hashlib
import json
import math
import os
import random
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import models, outdir

CODE_DIR = Path(__file__).resolve().parent.parent
# The LLM client scripts (tests replace these with a fake client).
CLIENT_SCRIPTS = {c: CODE_DIR / c for c in models.CLIENTS}
CHARS_PER_TOKEN = 4.0
DEFAULT_OUTPUT_TOKENS = 2000      # per reply, when there are no earlier replies to go by
API_KEY_ENV = ("OPENAI_API_KEY", "FIREWORKS_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY",
               "AWS_ACCESS_KEY_ID")
SECRET_ENV = API_KEY_ENV + ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


class RunError(ValueError):
    pass


# -------------------------------------------------------------------
# Options
# -------------------------------------------------------------------

def threshold_count(threshold, n):
    """The trial count for a threshold written as 80%, 0.8, K/n, or K/N (as
    adjudicate_alerts.parse_threshold_count computes it)."""
    s = str(threshold).strip()
    m = re.fullmatch(r'([0-9]+)/([0-9]+|[Nn])', s)
    if m:
        if m[2] not in "nN" and int(m[2]) != n:
            raise RunError(f"Threshold {s} doesn't match {n} trials.")
        count = int(m[1])
    elif re.fullmatch(r'[0-9]+(?:\.[0-9]+)?%', s):
        count = math.ceil(n * float(s[:-1]) / 100 - 1e-6)
    elif re.fullmatch(r'0\.[0-9]+', s):
        count = math.ceil(n * float(s) - 1e-6)
    else:
        raise RunError("Write the threshold as 80%, 0.8, or a count like 2/3.")
    if count <= n / 2 or count > n:
        raise RunError("The threshold must be more than half of the trials, and at most all.")
    return count


def run_opts(n, threshold, cc, lre):
    """The options as the pipeline records them in # opts= (N, t, CC, LRE)."""
    if n < 1 or n > 99:
        raise RunError("The number of trials must be from 1 to 99.")
    if not cc and not lre:
        return {"N": 1, "t": None, "CC": False, "LRE": False}
    return {"N": n, "t": threshold_count(threshold, n) if cc else None, "CC": bool(cc),
            "LRE": bool(lre)}


# -------------------------------------------------------------------
# Selection
# -------------------------------------------------------------------

def choose(rows, scope="all", n=None, seed=None, picked=(), skip_reviewed=True,
           skip_external=True, skip_done=()):
    """Choose alerts from *rows* (the alert list's dicts, already filtered).

    *scope* is "all", "sample" (a simple random sample of *n*, by *seed*),
    or "picked" (the IDs in *picked*; the skip options don't apply to alerts
    picked by hand).
    """
    skipped = collections.Counter()
    pop = []
    picked = set(picked)
    for d in sorted(rows, key=lambda d: d["ord"]):
        if scope == "picked":
            if d["alert_id"] in picked:
                pop.append(d)
            continue
        if skip_reviewed and d.get("review"):
            skipped["reviewed"] += 1
        elif skip_external and d["external"]:
            skipped["outside the snapshot"] += 1
        elif d["alert_id"] in skip_done:
            skipped["already adjudicated by this model"] += 1
        else:
            pop.append(d)
    chosen = pop
    if scope == "sample":
        if not n or n < 1:
            raise RunError("Give a sample size of at least 1.")
        chosen = random.Random(seed).sample(pop, min(n, len(pop)))
        chosen.sort(key=lambda d: d["ord"])
    elif scope not in ("all", "picked"):
        raise RunError(f"Unknown scope {scope!r}.")
    if not chosen:
        raise RunError("No alerts match.")
    return {"scope": scope, "n": n, "seed": seed,
            "population": len(pop), "skipped": dict(skipped),
            "alert_ids": [d["alert_id"] for d in chosen],
            "basenames": [d["basename"] for d in chosen]}


def write_subset(path, records, base_dir, repo=None):
    """Write the alerts file for a run.  Ground-truth Verdict fields are dropped
    (the pipeline would treat them as benchmark labels)."""
    out = []
    for r in records:
        r = {k: v for k, v in r.items() if k not in ("Verdict", "verdict", "Base_Dir")}
        r["Base_Dir"] = str(base_dir)
        if repo:
            r["Repo_URL"], r["Repo_Rev"] = repo
        out.append(r)
    Path(path).write_text(json.dumps(out, indent=1) + "\n")


def command(subset, base_dir, out_dir, opts, fields, spec, repos_dir=None,
            dont_run_llm=False):
    """The adjudicate_alerts.py command line for a run of model *spec*
    (models.py)."""
    cmd = [sys.executable, str(CODE_DIR / "adjudicate_alerts.py"), "-a", str(subset),
           "-b", str(base_dir), "-o", str(out_dir), "-n", str(opts["N"]),
           "--cc", "1" if opts["CC"] else "0", "--lre", "1" if opts["LRE"] else "0",
           "--need-defs-style", "standalone"]
    if opts["CC"]:
        cmd += ["-t", f"{opts['t']}/n"]
    if fields:
        cmd += ["--fields-for-llm", fields]
    cmd += ["--llm-script", str(CLIENT_SCRIPTS[models.client_of(spec)])]
    if repos_dir:
        cmd += ["--repos-dir", str(repos_dir)]
    if dont_run_llm:
        cmd.append("--dont-run-llm")
    return cmd + ["--"] + models.client_args(spec)


async def ask_once(spec, query, timeout, extra_args=()):
    """Send the query file text *query* to model *spec* with its LLM client
    (in a scratch directory, so nothing reaches a run's cache), with
    *extra_args* for the client.  Returns (the reply file's text, or None if
    there's none; the end of the client's output).  Cancelling the task
    kills the client."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "q.query"), "w", encoding="utf-8") as f:
            f.write(query)
        cmd = ([sys.executable, str(CLIENT_SCRIPTS[models.client_of(spec)]), tmp,
                "--print-skipped", "0"] + models.client_args(spec) + list(extra_args))
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=CODE_DIR, env=env("Alert_ID"), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            timed_out = True
            out = b""
        finally:
            if proc.returncode is None:        # timed out, or the request was cancelled
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await proc.wait()
        output = "\n".join(out.decode("utf-8", "replace").splitlines()[-40:])
        if timed_out:
            output = (output + "\n" if output else "") + f"(No reply within {timeout} s.)"
        try:
            with open(os.path.join(tmp, "q.reply"), encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            text = None
    return text, output


async def test_llm(spec, prompt, timeout):
    """Send *prompt* to model *spec* with its LLM client, as a run would.
    Returns {ok, seconds, reply, header, output}: the reply without its
    header lines or reasoning, what its "# Model:" header says, and the end
    of the client's output (shown when something went wrong)."""
    started = time.monotonic()
    text, output = await ask_once(spec, prompt + "\n", timeout)
    seconds = round(time.monotonic() - started, 1)
    if text is None:
        return {"ok": False, "seconds": seconds, "reply": "", "header": {}, "output": output}
    reply = outdir.REASONING_RE.sub("", outdir.strip_reply_header(text)).strip()
    return {"ok": True, "seconds": seconds, "reply": reply[:4000],
            "header": outdir.parse_header(text), "output": output}


def env(id_field, secrets=True):
    e = dict(os.environ)
    e["LASAA_ALERT_ID_FIELD"] = id_field
    e.pop("LASAA_FIELDS_FOR_LLM", None)
    if not secrets:
        for k in SECRET_ENV:
            e.pop(k, None)
    return e


def prune_truncated_replies(out_dir, basenames, cap):
    """Delete the replies of *basenames* that the output-token cap cut short
    (their verdict is "uncertain" for "token limit reached") at fewer than
    *cap* tokens, with their alert's .final_answer, so that a run with a
    higher cap asks them again.  A cut-short reply's output_tokens is the
    cap it had.  Returns how many replies."""
    if not cap or not os.path.isdir(out_dir):
        return 0
    wanted = set(basenames)
    n = 0
    for name in os.listdir(out_dir):
        m = outdir.PHASE_FILE_RE.match(name)
        if not (m and m["ext"] == "reply" and m["base"] in wanted):
            continue
        path = os.path.join(out_dir, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if '"reason": "token limit reached"' not in text:
            continue
        used = outdir.parse_header(text)["output_tokens"]
        if used is not None and used < cap:
            os.remove(path)
            n += 1
            try:
                os.remove(os.path.join(out_dir, f"{m['base']}.final_answer"))
            except FileNotFoundError:
                pass
    return n


def prune_pending_queries(out_dir):
    """Delete query files whose replies aren't all there.  The LLM client sends
    every such query in the directory, but a run's pipeline rewrites the ones
    it needs each round; this keeps it from paying for leftovers (from a
    cancelled run with other alerts, or a dry run).  Returns how many."""
    n = 0
    for g in outdir.scan_dir(out_dir).values():
        for ps in g["sets"].values():
            if ps.query is None:
                continue
            need = ps.run_n if ps.run_n else 1
            if any(i not in ps.replies for i in range(need)):
                os.remove(os.path.join(out_dir, ps.query))
                n += 1
    return n


# -------------------------------------------------------------------
# Cost estimate
# -------------------------------------------------------------------

def history(conn, model, effort=""):
    """What earlier replies and results from *model* at *effort* say about a
    run's cost.  Efforts can differ a lot in reasoning tokens, so other
    efforts are used only when this one has no history (efforts_matched)."""
    # Replies are matched through their runs' configs (a reply's header may
    # name the effort "default", or the model by a dated name).
    replies_sql = ("SELECT avg(output_tokens), "
                   "avg(max(output_tokens - coalesce(reasoning_tokens, 0), 0)), count(*) "
                   "FROM llm_file WHERE name LIKE '%.reply' AND output_tokens IS NOT NULL "
                   "AND out_dir IN (SELECT run.out_dir FROM run JOIN config USING (config_id) "
                   "WHERE config.model=?{})")
    results_sql = ("SELECT rr.phases, run.opts FROM run_result rr JOIN run USING (run_id) "
                   "JOIN config USING (config_id) WHERE config.model=? "
                   "AND rr.verdict IS NOT NULL{}")
    by_effort = " AND config.effort=?"
    out = conn.execute(replies_sql.format(by_effort), (model, effort)).fetchone()
    results = conn.execute(results_sql.format(by_effort), (model, effort)).fetchall()
    matched = bool(out[2] or results)
    if not matched:
        out = conn.execute(replies_sql.format(""), (model,)).fetchone()
        results = conn.execute(results_sql.format(""), (model,)).fetchall()
    n = n_lre_on = lre = defs = 0
    for phases, opts in results:
        kinds = [p["kind"] for p in json.loads(phases)]
        n += 1
        defs += sum(k.startswith("augdef.") for k in kinds)
        # Only runs with LRE on say how often it is needed.
        if (json.loads(opts) if opts else {}).get("LRE", True):
            n_lre_on += 1
            lre += "lre" in kinds
    return {"output_per_reply": out[0] or DEFAULT_OUTPUT_TOKENS,
            # The reply text, without the reasoning, which the LRE prompt leaves out.
            "answer_per_reply": out[1] or DEFAULT_OUTPUT_TOKENS,
            "replies": out[2], "results": n, "effort_matched": matched,
            "lre_rate": lre / n_lre_on if n_lre_on else 1.0,
            "defs_rounds": defs / n if n else 1.0}


def pipeline_stamp():
    """Changes when the pipeline's code does (which can change its prompts)."""
    files = sorted(CODE_DIR.glob("*.py")) + sorted(CODE_DIR.glob("*.txt"))
    return hashlib.sha256(repr([(f.name, f.stat().st_mtime_ns, f.stat().st_size)
                                for f in files]).encode()).hexdigest()[:16]


def dry_run_command(subset, base_dir, out_dir, fields, repos_dir=None):
    """The command for a dry run (--dont-run-llm) of the alerts in *subset*,
    which writes their first-round queries into *out_dir*.  The prompts
    don't depend on the model or the options, so one dry run serves every
    estimate on the same alerts.  The pipeline handles the alerts in the
    file's order, and prints "BASENAME: waiting: ..." after writing each
    one's query (see prompt_sizes.py)."""
    spec = models.validate(models.new_spec(**models.MODELS[0]))     # never run
    return command(subset, base_dir, out_dir, run_opts(1, "", False, False), fields, spec,
                   repos_dir=repos_dir, dont_run_llm=True)


def query_sizes(out_dir):
    """{basename: [[stem, chars]]} for the query files in *out_dir*, where a
    stem such as "A.1a2b3c4d.orig" names the prompt in every output
    directory."""
    out = {}
    with os.scandir(out_dir) as it:
        for e in it:
            m = outdir.PHASE_FILE_RE.match(e.name)
            if m and m["ext"] == "query":
                out.setdefault(m["base"], []).append(
                    [f"{m['base']}.{m['hash']}.{m['kind']}", e.stat().st_size])
    return out


def estimate(sizes, basenames, out_dir, opts, hist, price):
    """Estimate a run's tokens and cost from the prompt *sizes* of its alerts
    (*basenames*; see query_sizes(), where [] means no prompt).  Returns
    None if no sizes are known yet.

    While some sizes are still unknown, the alerts with known sizes stand
    for the rest (exact is false): those in *basenames*, or if there are
    none yet, every alert in *sizes*.  Trials whose replies are already in
    *out_dir* cost nothing.  The low end is the first round only; the high
    end adds LRE (if on) and need_defs rounds at the rates in *hist*
    (every alert, with no history)."""
    sample = [b for b in basenames if b in sizes] or list(sizes)
    if not sample:
        return None
    exact = len(sample) == len(basenames) and all(b in sizes for b in basenames)
    scale = 1 if exact else len(basenames) / len(sample)
    existing = set(os.listdir(out_dir)) if out_dir and os.path.isdir(out_dir) else set()
    out_tok = hist["output_per_reply"]
    n1 = opts["N"]
    n2 = opts["N"] if opts["CC"] else 1
    t = {"trials": 0, "cached": 0, "alerts": 0, "no_prompt": 0,
         "low_in": 0.0, "low_out": 0.0, "extra_in": 0.0, "extra_out": 0.0}
    for b in sample:
        if not sizes[b]:
            t["no_prompt"] += 1
            continue
        t["alerts"] += 1
        for stem, chars in sizes[b]:
            in_tok = chars / CHARS_PER_TOKEN
            missing = [i for i in range(n1) if f"{stem}.try{i:02d}.reply" not in existing]
            t["trials"] += n1
            t["cached"] += n1 - len(missing)
            t["low_in"] += len(missing) * in_tok
            t["low_out"] += len(missing) * out_tok
            if missing and opts["LRE"]:
                lre_in = in_tok + n1 * hist["answer_per_reply"]
                t["extra_in"] += hist["lre_rate"] * n2 * lre_in
                t["extra_out"] += hist["lre_rate"] * n2 * out_tok
            if missing:
                t["extra_in"] += hist["defs_rounds"] * n1 * in_tok * 1.2
                t["extra_out"] += hist["defs_rounds"] * n1 * out_tok
    t = {k: v * scale for k, v in t.items()}
    low = (round(t["low_in"]), round(t["low_out"]))
    high = (round(t["low_in"] + t["extra_in"]), round(t["low_out"] + t["extra_out"]))
    return {"alerts": round(t["alerts"]), "no_prompt": round(t["no_prompt"]),
            "trials": round(t["trials"]), "cached": round(t["cached"]),
            "exact": exact, "measured": len(sample), "selected": len(basenames),
            "low": low, "high": high,
            "low_cost": models.cost(price, *low), "high_cost": models.cost(price, *high),
            "price": price, "history": hist}


def budget_default(est):
    """1.5 times the high estimate, in dollars (if priced) or tokens."""
    if est.get("price"):
        return f"{max(1, math.ceil((est['high_cost'] or 0) * 150) / 100):.2f}"
    return str(int(math.ceil(sum(est["high"]) * 1.5 / 1000) * 1000))


# -------------------------------------------------------------------
# Progress and spend
# -------------------------------------------------------------------

# The progress bar's weights for an alert's phases (see alert_progress()):
# the original trials, definition-lookup round i (front-loaded, since most
# alerts need few rounds; the 10 rounds of the pipeline's default
# --max-need-defs-rounds add up to 2), LRE, and the final answer.
WEIGHT_ORIG = 3
WEIGHT_AUGDEF = [2 * ((11 - i) ** 2 - 0.5) / 500 for i in range(10)]
WEIGHT_LRE = 1
WEIGHT_FINAL = 4


def _answered_fraction(ps):
    n = ps.run_n or 1
    return sum(1 for i in range(n) if i in ps.replies) / n


def alert_progress(group, lre=True):
    """(score, max) of one alert's output files, *group* from outdir.scan_dir()
    (None if it has none): each phase's weight times the fraction of its
    trials answered.  A phase that is known to be skipped counts as done:
    the definition rounds not asked once there is an LRE or "explain
    uncertain" query, and LRE once there is an "explain uncertain" query.
    That query counts as half the final answer; a final answer, as all of it.
    Only the newest prompt of each phase counts (an older one may be left
    from a run before the prompts changed)."""
    top = WEIGHT_ORIG + sum(WEIGHT_AUGDEF) + (WEIGHT_LRE if lre else 0) + WEIGHT_FINAL
    if group is None:
        return 0.0, top
    if group["final_answer"] is not None:
        return top, top
    newest = {}
    for ps in group["sets"].values():
        if ps.query is not None and (ps.kind not in newest
                                     or ps.query_mtime > newest[ps.kind].query_mtime):
            newest[ps.kind] = ps
    score = WEIGHT_ORIG * _answered_fraction(newest["orig"]) if "orig" in newest else 0.0
    uncert = "uncert" in newest
    defs_over = "lre" in newest or uncert
    for i, w in enumerate(WEIGHT_AUGDEF):
        ps = newest.get(f"augdef.{i}")
        score += w * _answered_fraction(ps) if ps else (w if defs_over else 0)
    if lre:
        score += (WEIGHT_LRE * _answered_fraction(newest["lre"]) if "lre" in newest
                  else WEIGHT_LRE if uncert else 0)
    if uncert:
        score += WEIGHT_FINAL / 2
    return score, top


def progress(out_dir, basenames, lre=True, no_prompt=()):
    """Trials answered and queued, and alerts finished, for a run's alerts,
    and "fraction", the progress bar's estimate of how much of the run is
    done (alert_progress(), averaged over the alerts).  *lre*: whether the
    run uses LRE.  The alerts in *no_prompt* (known to get no prompt; see
    no_prompt_alerts()) are left out, and counted in "no_prompt", while
    they have no output files."""
    groups = outdir.scan_dir(out_dir) if os.path.isdir(out_dir) else {}
    skip = {b for b in no_prompt if b not in groups}
    p = {"queued": 0, "answered": 0, "finished": 0,
         "alerts": len([b for b in basenames if b not in skip]),
         "no_prompt": len([b for b in basenames if b in skip])}
    done = total = 0.0
    for b in basenames:
        if b in skip:
            continue
        g = groups.get(b)
        score, top = alert_progress(g, lre)
        done += score
        total += top
        if g is None:
            continue
        p["finished"] += g["final_answer"] is not None
        for ps in g["sets"].values():
            if ps.query is None:
                continue
            n = ps.run_n or 1
            p["queued"] += n
            p["answered"] += sum(1 for i in range(n) if i in ps.replies)
    p["fraction"] = done / total if total else (1.0 if p["no_prompt"] else 0.0)
    return p


def no_prompt_alerts(out_dir, basenames):
    """The alerts of *basenames* with no output files at all, after the
    pipeline has finished normally: the ones it gave no prompt (the file is
    outside the snapshot, or it couldn't find the enclosing function), since
    it writes every first-round query before it calls the LLM."""
    groups = outdir.scan_dir(out_dir) if os.path.isdir(out_dir) else {}
    return [b for b in basenames if b not in groups]


def spend(conn, out_dir_rel, since, basenames, price):
    """Tokens and cost of the replies written since *since* (epoch seconds) for
    *basenames*: what a run has spent so far.  Needs the files indexed."""
    want = set(basenames)
    tin = tout = 0
    for name, i, o in conn.execute(
            "SELECT name, input_tokens, output_tokens FROM llm_file WHERE out_dir=? AND "
            "mtime>=? AND name LIKE '%.reply'", (out_dir_rel, since)):
        m = outdir.PHASE_FILE_RE.match(name)
        if m and m["base"] in want:
            tin += i or 0
            tout += o or 0
    return {"input_tokens": tin, "output_tokens": tout, "cost": models.cost(price, tin, tout)}
