#!/usr/bin/env python3
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
"""Build the reply cache that mock_llm_server.py serves, from the .query and
.reply files already in a web UI workspace (default ~/.lasaa-ui).

Each .query file is paired with its replies the way ask_gpt.py pairs them:
X.runNN.query with X.tryKK.reply (trial KK), and X.query with X.reply
(trial 0).  Every reply becomes one line of the output JSONL file:

  {"prompt_sha256", "model", "reasoning_effort", "trial", "text", "usage", "source"}

"model" and "reasoning_effort" come from the reply's "# Model: …" header
("default" when the run gave no --reasoning-effort), "text" is the reply
after the header, and "usage" holds the header's token counts.

The server serves the reply for the (model, effort, prompt, trial) of each
request, so each one must have only one.  Identical reply files (a copy of a
project, say) are stored once; two different replies for the same trial (from
two runs of the same prompt) are an error, and nothing is written.

Usage:
  ./mock_llm_build_cache.py [--workspace ~/.lasaa-ui] [-o CACHE.jsonl]

The cache is kept outside the workspace (default ~/.lasaa-mock/), so that
clearing the workspace doesn't remove it.  In the web UI's Docker container,
mount that directory from the host so that it outlives the container.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

DEFAULT_WORKSPACE = "~/.lasaa-ui"
DEFAULT_CACHE = "~/.lasaa-mock/mock_llm_cache.jsonl"

_RUN_RE = re.compile(r"^(?P<base>.+)\.run[0-9]+\.query$")
_TRY_RE = re.compile(r"\.try(?P<k>[0-9]+)\.reply$")
_MODEL_RE = re.compile(r"^# Model: (?P<model>[^,]+), reasoning_effort='(?P<effort>[^']*)'")
# "name: N" (Responses API header) or "name=N" (chat-completion usage line)
_COUNT_RE = re.compile(r"\b(?P<name>[a-z_]+)(?::\s*|=)(?P<n>[0-9]+)\b")
# Chat-completion names for the Responses API's counts
_COUNT_ALIASES = {"prompt_tokens": "input_tokens", "completion_tokens": "output_tokens"}


def prompt_sha256(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def replies_of(query_path: Path) -> list[Path]:
    """The reply files that answer *query_path*, sorted by name."""
    m = _RUN_RE.match(query_path.name)
    if m:
        prefix = m.group("base") + "."
        return sorted(p for p in query_path.parent.glob(glob_escape(prefix) + "try*.reply")
                      if _TRY_RE.search(p.name) and p.name[len(prefix):].count(".") == 1)
    reply = query_path.with_suffix(".reply")
    return [reply] if reply.exists() else []


def glob_escape(s: str) -> str:
    return re.sub(r"([*?\[])", r"[\1]", s)


def parse_reply(text: str):
    """(model, effort, usage, body) of a reply file, or None if it has no
    "# Model: …" header."""
    lines = text.split("\n")
    m = _MODEL_RE.match(lines[0])
    if not m:
        return None
    i = 0
    while i < len(lines) and lines[i].startswith("# "):
        i += 1
    header = lines[:i]
    if i < len(lines) and lines[i] == "":
        i += 1      # ask_gpt.py puts one blank line after the header
    body = "\n".join(lines[i:])
    usage = {}
    for line in header:
        for c in _COUNT_RE.finditer(line):
            name = _COUNT_ALIASES.get(c.group("name"), c.group("name"))
            if name in ("input_tokens", "output_tokens", "cached_input_tokens",
                        "reasoning_tokens"):
                usage[name] = int(c.group("n"))
    return m.group("model").strip(), m.group("effort"), usage, body


def trial_of(reply_path: Path) -> int:
    m = _TRY_RE.search(reply_path.name)
    return int(m.group("k")) if m else 0


def build(workspace: Path) -> tuple[list[dict], dict, list[str]]:
    """(entries, stats, conflicts)."""
    entries, by_key, conflicts = [], {}, []
    stats = {"queries": 0, "replies": 0, "duplicates": 0, "no_header": 0}
    for dirpath, dirnames, filenames in os.walk(workspace):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".query"):
                continue
            qpath = Path(dirpath, name)
            prompt = qpath.read_text(encoding="utf-8")
            sha = prompt_sha256(prompt)
            stats["queries"] += 1
            for rpath in replies_of(qpath):
                raw = rpath.read_text(encoding="utf-8")
                parsed = parse_reply(raw)
                if parsed is None:
                    stats["no_header"] += 1
                    continue
                model, effort, usage, body = parsed
                trial = trial_of(rpath)
                source = str(rpath.relative_to(workspace))
                key = (model, effort, sha, trial)
                if key in by_key:
                    earlier_raw, earlier_source = by_key[key]
                    if raw == earlier_raw:
                        stats["duplicates"] += 1
                    else:
                        conflicts.append(f"{earlier_source}\n    {source}")
                    continue
                by_key[key] = (raw, source)
                entries.append({"prompt_sha256": sha, "model": model,
                                "reasoning_effort": effort, "trial": trial,
                                "text": body, "usage": usage, "source": source})
                stats["replies"] += 1
    return entries, stats, conflicts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--workspace", default=DEFAULT_WORKSPACE,
                    help=f"Web UI workspace to scan (default {DEFAULT_WORKSPACE})")
    ap.add_argument("-o", "--output", default=DEFAULT_CACHE,
                    help=f"Cache file to write (default {DEFAULT_CACHE})")
    args = ap.parse_args()

    workspace = Path(args.workspace).expanduser()
    if not workspace.is_dir():
        sys.exit(f"Error: workspace '{workspace}' is not a directory.")
    entries, stats, conflicts = build(workspace)
    if conflicts:
        print(f"Error: {len(conflicts)} trial(s) have two different replies (the same prompt, "
              f"model, effort, and trial number, from two runs), so the mock couldn't tell "
              f"which to serve.  Remove one run of each, or build from a directory that has "
              f"just one (--workspace).  Nothing was written.", file=sys.stderr)
        for c in conflicts[:20]:
            print(f"  {c}", file=sys.stderr)
        if len(conflicts) > 20:
            print(f"  … and {len(conflicts) - 20} more", file=sys.stderr)
        sys.exit(1)

    out = Path(args.output).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    os.replace(tmp, out)

    keys = {}
    for e in entries:
        k = (e["model"], e["reasoning_effort"])
        keys.setdefault(k, set()).add(e["prompt_sha256"])
    print(f"Scanned {stats['queries']} query files; wrote {stats['replies']} replies to '{out}'"
          f" ({stats['duplicates']} identical copies skipped, {stats['no_header']} without a "
          f"header).")
    for (model, effort), prompts in sorted(keys.items()):
        n = sum(1 for e in entries if (e["model"], e["reasoning_effort"]) == (model, effort))
        print(f"  {model}, reasoning_effort='{effort}': {len(prompts)} prompts, {n} replies")


if __name__ == "__main__":
    main()
