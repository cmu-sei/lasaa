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
"""A mock OpenAI Responses API endpoint that answers from cached replies, for
fast offline demos.  Build the cache first with mock_llm_build_cache.py.

  POST /v1/responses   single-turn requests only ("input" is a string)
  GET  /v1/models      the models in the cache

Every request must carry an "X-LASAA-Trial: K" header, which ask_gpt.py
sends with --mock-llm-server: K is the trial number of the reply file it will
write (X.tryKK.reply; 0 for X.reply).  The request is matched on (model,
reasoning effort, SHA-256 of the prompt, K), and gets the reply that the
original run wrote for that trial, so replaying a run gives the same replies
whatever the order of the requests, and so the same later prompts (augdef,
LRE) that are built from them.  The effort is "default" when the request has
no "reasoning.effort".  Each answer is sent whole after a random delay (2-4 s
by default).  A request without the header gets an immediate 400 error, and
one with no cached reply an immediate 404.

For the web UI, start lasaa_webui_serve.py with --mock-llm, which saves a
model config ("Mock: MODEL (EFFORT)") for each model and effort in the cache.
(By hand: provider "Other" with base URL http://127.0.0.1:8100/v1, API type
"response", and an API key variable (…_LASAA_KEY) that is set to anything.)
The UI passes --mock-llm-server for a base URL whose host is a numeric IP
address or localhost.

Usage:
  ./mock_llm_server.py [--cache FILE] [--host 127.0.0.1] [--port 8100]
                       [--min-delay 2] [--max-delay 4]
"""

import argparse
import hashlib
import json
import re
import random
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_CACHE = "~/.lasaa-mock/mock_llm_cache.jsonl"
TRIAL_HEADER = "X-LASAA-Trial"          # as in ask_gpt.py


class ReplyCache:
    """The replies by (model, effort, prompt SHA-256, trial)."""

    def __init__(self, path: Path):
        self.replies: dict[tuple, dict] = {}
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                e = json.loads(line)
                if "trial" not in e:
                    sys.exit(f"Error: '{path}' line {n} has no trial number; "
                             "rebuild it with mock_llm_build_cache.py.")
                key = (e["model"], e["reasoning_effort"], e["prompt_sha256"], e["trial"])
                if key in self.replies:
                    sys.exit(f"Error: '{path}' line {n} repeats a (model, effort, prompt, "
                             "trial); rebuild it with mock_llm_build_cache.py.")
                self.replies[key] = e
        # How many trials each (model, effort, prompt) has, for error messages
        self.trials: dict[tuple, int] = {}
        for k in self.replies:
            self.trials[k[:3]] = self.trials.get(k[:3], 0) + 1

    def models(self) -> list[str]:
        return sorted({k[0] for k in self.replies})


def response_object(model: str, entry: dict) -> dict:
    """A completed Responses API object carrying *entry*'s text and usage."""
    u = entry.get("usage", {})
    usage = {"input_tokens": u.get("input_tokens", 0),
             "input_tokens_details": {"cached_tokens": u.get("cached_input_tokens", 0)},
             "output_tokens": u.get("output_tokens", 0),
             "output_tokens_details": {"reasoning_tokens": u.get("reasoning_tokens", 0)}}
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    return {
        "id": "resp_mock_" + uuid.uuid4().hex,
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": [{
            "type": "message",
            "id": "msg_mock_" + uuid.uuid4().hex,
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": entry["text"], "annotations": []}],
        }],
        "usage": usage,
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "metadata": {},
        "parallel_tool_calls": False,
        "tool_choice": "auto",
        "tools": [],
    }


def make_handler(cache: ReplyCache, min_delay: float, max_delay: float):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass    # replaced by the one-line log in do_POST

        def send_json(self, status: int, obj: dict) -> None:
            data = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def send_error_json(self, status: int, message: str, code: str) -> None:
            log(f"{status} {self.path}: {message}")
            self.send_json(status, {"error": {"message": message, "type": "invalid_request_error",
                                              "param": None, "code": code}})

        def do_GET(self):
            if self.path.rstrip("/") == "/v1/models":
                self.send_json(200, {"object": "list", "data": [
                    {"id": m, "object": "model", "created": 0, "owned_by": "mock"}
                    for m in cache.models()]})
            else:
                self.send_error_json(404, f"Unknown path {self.path}", "not_found")

        def do_POST(self):
            start = time.monotonic()
            try:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError) as e:
                return self.send_error_json(400, f"Bad JSON body: {e}", "bad_request")
            if self.path.rstrip("/") != "/v1/responses":
                return self.send_error_json(
                    404, f"The mock serves only POST /v1/responses, not {self.path}", "not_found")

            prompt = req.get("input")
            if not isinstance(prompt, str):
                return self.send_error_json(
                    400, "The mock handles only single-turn requests ('input' must be a string)",
                    "unsupported")
            trial_text = (self.headers.get(TRIAL_HEADER) or "").strip()
            if not re.fullmatch(r"[0-9]+", trial_text):
                return self.send_error_json(
                    400, f"The mock needs an '{TRIAL_HEADER}: K' header with the trial "
                         f"number (got {trial_text!r}); run ask_gpt.py with "
                         "--mock-llm-server", "missing_trial")
            trial = int(trial_text)
            model = req.get("model", "")
            effort = (req.get("reasoning") or {}).get("effort") or "default"
            sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            what = (f"model={model!r}, reasoning_effort={effort!r}, prompt sha256={sha[:16]}… "
                    f"({len(prompt)} chars, starts {prompt[:60]!r})")

            entry = cache.replies.get((model, effort, sha, trial))
            if entry is None:
                n = cache.trials.get((model, effort, sha))
                if n:
                    return self.send_error_json(
                        404, f"No cached reply for trial {trial} (only {n} trials cached) "
                             f"for {what}", "cache_miss")
                return self.send_error_json(404, f"No cached reply for {what}", "cache_miss")

            delay = random.uniform(min_delay, max_delay)
            time.sleep(max(0.0, delay - (time.monotonic() - start)))
            self.send_json(200, response_object(model, entry))
            log(f"200 {model} effort={effort} sha={sha[:12]} trial {trial} "
                f"after {time.monotonic() - start:.1f}s ({entry['source']})")

    return Handler


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cache", default=DEFAULT_CACHE,
                    help=f"Cache from mock_llm_build_cache.py (default {DEFAULT_CACHE})")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--min-delay", type=float, default=0.4, help="Seconds")
    ap.add_argument("--max-delay", type=float, default=0.8, help="Seconds")
    args = ap.parse_args()
    if not 0 <= args.min_delay <= args.max_delay:
        sys.exit("Error: need 0 <= --min-delay <= --max-delay.")

    cache_path = Path(args.cache).expanduser()
    if not cache_path.exists():
        sys.exit(f"Error: cache '{cache_path}' not found; run mock_llm_build_cache.py first.")
    cache = ReplyCache(cache_path)
    log(f"Loaded {len(cache.replies)} replies for {len(cache.trials)} (model, effort, prompt) "
        f"keys from '{cache_path}'; models: {', '.join(cache.models())}")

    server = ThreadingHTTPServer((args.host, args.port),
                                 make_handler(cache, args.min_delay, args.max_delay))
    server.daemon_threads = True
    log(f"Serving on http://{args.host}:{args.port}/v1 "
        f"(delay {args.min_delay:g}-{args.max_delay:g} s); Ctrl+C stops.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
