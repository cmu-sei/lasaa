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
"""Asking an LLM about an alert ("Ask an LLM" on the alert page).

A conversation is about one run result: its first question goes to the LLM
with the final non-LRE prompt of the alert (the original prompt, plus any
definitions that need_defs rounds added) and LASAA's final answer, in
blocks like the pipeline's LRE prompt.  Follow-up questions resend the
whole conversation, as the clients' multi-turn query format (the clients'
--multi-turn, multi_turn.py): no reasoning state is carried between turns.

These prompts are the one kind the UI builds itself (AGENTS.prod.md,
invariant 1).  They go to the client in a scratch directory, never to a
run's output directory, so they can't reach the pipeline's cache, and the
conversation is kept only in ui.sqlite.

Each question runs as an asyncio task in the server (not a job, so it
needn't wait for a LASAA run).  A turn is "pending" until its reply comes
back, then "done", or "failed", "cancelled", or (when the server restarted
while it was pending) "interrupted".
"""

import asyncio
import hashlib
import json

from . import db, models, outdir, render, runs

ASK_SECONDS = 15 * 60          # how long one question may take
MAX_QUESTION = 20000           # characters
TRUNCATED_MARK = "<!-- REACHED MAX TOKEN LIMIT -->"

INTRO = ("Below is a question posed to an LLM and the LLM's answer.  "
         "Following those is a question for you.\n\n")
NOTES = {
    "lre": ("(Note: This adjudication response was written after seeing earlier responses "
            "to the same question, which are not shown here, and may refer to them.)"),
    "uncert": ("(Note: Several responses to this question disagreed.  The adjudication "
               "response is an explanation of their disagreement, written after seeing them; "
               "they are not shown here.)"),
    "bare": ("(Note: Several responses to this question disagreed, and no explanation of the "
             "disagreement was produced, so the adjudication response is only the verdict.)"),
}
DEFS_NOTE = ("(Note: Definitions cannot be requested at this stage using the mechanism "
             "described above.)")
ANSWER_NOTE = "Answer the question below directly; you don't need to end with a JSON verdict line."
QUESTION_HEAD = "QUESTION FOR YOU:\n\n"


# -------------------------------------------------------------------
# The prompt
# -------------------------------------------------------------------

def final_prompt_phase(phases):
    """The last orig or augdef.R phase of a run result's phases (indexer.py):
    the prompt whose trials decided the verdict, or that LRE resolved."""
    first = [p for p in phases if p["kind"] == "orig" or p["kind"].startswith("augdef.")]
    return first[-1] if first else None


def answer_kind(phases, answer):
    """Which note the final answer needs: "uncert" (an explanation of a
    disagreement), "bare" (a verdict line only), "lre" (an LRE reply), or
    None (a reply to the prompt itself)."""
    if phases and phases[-1]["kind"] == "uncert":
        return "uncert"
    if not render.answer_parts(answer)[1].strip():
        return "bare"
    if any(p["kind"] == "lre" for p in phases):
        return "lre"
    return None


def _block(name, content):
    if not content.endswith("\n"):
        content += "\n"
    h = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
    return f"### BEGIN {name} (hash={h})\n\n{content}### END {name} (hash={h})\n\n"


def context_text(prompt, answer, kind):
    """The first question's text before the question: the adjudication
    prompt and answer (without its reasoning), and the notes."""
    notes = ([NOTES[kind]] if kind else []) + [DEFS_NOTE]
    return (INTRO + _block("Adjudication question", prompt)
            + _block("Adjudication response", answer)
            + "\n\n".join(notes) + "\n\n" + ANSWER_NOTE + "\n\n")


def format_turns(turns):
    """*turns* ({role, content}) in the clients' multi-turn query format.
    The same as multi_turn.format_turns(), which the UI doesn't import."""
    parts = []
    for t in turns:
        body = "\n".join("  " + line if line.strip() else ""
                         for line in t["content"].strip("\n").split("\n"))
        parts.append(f"# {t['role'].capitalize()}\n\n{body}\n")
    return "\n".join(parts)


def conversation(context, turns):
    """The turns to send for *turns* (the done ones, then the new one): the
    first question goes after *context*; answers are sent without reasoning."""
    out = []
    for i, t in enumerate(turns):
        q = t["question"]
        out.append({"role": "user", "content": (context + QUESTION_HEAD + q) if i == 0 else q})
        if t.get("answer") is not None:
            out.append({"role": "assistant", "content": t["answer"] or "(no answer)"})
    return out


def parse_answer(text):
    """The parts of a reply file the page shows: answer and reasoning, the
    header's facts, and whether the output-token cap cut it short (then
    the clients' made-up "uncertain" verdict line is dropped)."""
    info = outdir.parse_reply(text)
    answer = info["answer"] or ""
    truncated = TRUNCATED_MARK in answer
    if truncated:
        answer = answer[:answer.index(TRUNCATED_MARK)]
    return {"answer": answer.strip(), "reasoning": info["reasoning"], "model": info["model"],
            "input_tokens": info["input_tokens"],
            "cached_input_tokens": info["cached_input_tokens"],
            "output_tokens": info["output_tokens"],
            "reasoning_tokens": info["reasoning_tokens"], "truncated": truncated}


# -------------------------------------------------------------------
# Storage
# -------------------------------------------------------------------

def chats_of(c, analysis_id, alert_id):
    """The alert's conversations, newest first, each with its first question."""
    return [dict(r) for r in c.execute(
        "SELECT chat.*, (SELECT question FROM chat_turn t WHERE t.chat_id=chat.chat_id "
        "ORDER BY turn_id LIMIT 1) AS first_question, "
        "(SELECT COUNT(*) FROM chat_turn t WHERE t.chat_id=chat.chat_id) AS n_turns "
        "FROM chat WHERE analysis_id=? AND alert_id=? ORDER BY chat_id DESC",
        (analysis_id, alert_id))]


def turns_of(c, chat_id):
    return [dict(r) for r in c.execute(
        "SELECT * FROM chat_turn WHERE chat_id=? ORDER BY turn_id", (chat_id,))]


def create(c, analysis_id, alert_id, run_id, spec, label, context):
    cur = c.execute(
        "INSERT INTO chat(analysis_id, alert_id, run_id, spec, model_label, context, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (analysis_id, alert_id, run_id, json.dumps(spec), label, context, db.now()))
    return cur.lastrowid


def add_turn(c, chat_id, question):
    """A new pending turn.  Turns that didn't get an answer are dropped
    first, so the conversation sent stays question, answer, question..."""
    c.execute("DELETE FROM chat_turn WHERE chat_id=? AND status NOT IN ('done', 'pending')",
              (chat_id,))
    cur = c.execute("INSERT INTO chat_turn(chat_id, question, status, created_at) "
                    "VALUES (?,?,'pending',?)", (chat_id, question, db.now()))
    return cur.lastrowid


def query_for(c, turn_id):
    """(the model spec, the query file text) for pending turn *turn_id*."""
    turn = c.execute("SELECT * FROM chat_turn WHERE turn_id=?", (turn_id,)).fetchone()
    ch = c.execute("SELECT * FROM chat WHERE chat_id=?", (turn["chat_id"],)).fetchone()
    done = [t for t in turns_of(c, ch["chat_id"])
            if t["status"] == "done" and t["turn_id"] < turn_id]
    turns = [{"question": t["question"], "answer": t["answer"]} for t in done]
    turns.append({"question": turn["question"]})
    return json.loads(ch["spec"]), format_turns(conversation(ch["context"], turns))


# -------------------------------------------------------------------
# Running questions
# -------------------------------------------------------------------

class Asker:
    """The questions being asked, as asyncio tasks of the server's loop."""

    def __init__(self, ws):
        self.ws = ws
        self.tasks = {}            # turn_id -> task
        self.stopping = False

    def recover(self):
        """At startup: turns left pending by an earlier server."""
        c = self.ws.connect()
        c.execute("UPDATE chat_turn SET status='interrupted', finished_at=? "
                  "WHERE status='pending'", (db.now(),))
        c.commit()
        c.close()

    async def shutdown(self):
        """At server shutdown: stop the clients (they run in sessions of
        their own, so Ctrl-C doesn't reach them); their turns are
        "interrupted"."""
        self.stopping = True
        tasks = list(self.tasks.values())
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def start(self, turn_id):
        task = asyncio.get_running_loop().create_task(self._ask(turn_id))
        self.tasks[turn_id] = task
        task.add_done_callback(lambda _t: self.tasks.pop(turn_id, None))

    def cancel(self, turn_id):
        task = self.tasks.get(turn_id)
        if task is not None:
            task.cancel()

    def _finish(self, turn_id, **fields):
        c = self.ws.connect()
        fields["finished_at"] = db.now()
        c.execute(f"UPDATE chat_turn SET {', '.join(k + '=?' for k in fields)} "
                  "WHERE turn_id=? AND status='pending'", (*fields.values(), turn_id))
        c.commit()
        c.close()

    async def _ask(self, turn_id):
        c = self.ws.connect()
        try:
            spec, query = query_for(c, turn_id)
        finally:
            c.close()
        try:
            text, output = await runs.ask_once(spec, query, ASK_SECONDS, ["--multi-turn"])
        except asyncio.CancelledError:
            self._finish(turn_id, status="interrupted" if self.stopping else "cancelled")
            raise
        except Exception as e:                      # e.g., the client couldn't start
            self._finish(turn_id, status="failed", error=str(e))
            return
        if text is None:
            self._finish(turn_id, status="failed", error=output or "No reply.")
            return
        a = parse_answer(text)
        price = models.price_for(spec["model"], models.load_prices(), spec["provider"])
        cost = models.cost(price, a["input_tokens"] or 0, a["output_tokens"] or 0) \
            if a["input_tokens"] is not None else None
        self._finish(turn_id, status="done", reply=text, answer=a["answer"],
                     reasoning=a["reasoning"], model=a["model"],
                     input_tokens=a["input_tokens"],
                     cached_input_tokens=a["cached_input_tokens"],
                     output_tokens=a["output_tokens"], reasoning_tokens=a["reasoning_tokens"],
                     truncated=int(a["truncated"]), cost=cost)
