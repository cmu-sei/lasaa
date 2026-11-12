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
"""
Send queries to Claude on AWS Bedrock and record its replies.

Each `<name>.query` file is sent to the model and the answer is written to
`<name>.reply` (or `<name>.tryNN.reply` for `<name>.runN.query` files).
Queries whose reply file already exists are skipped.

USAGE
-----
    ask_claude_aws.py [options] PATH...

Queries are sent immediately via InvokeModel, up to --concurrency at a time,
and each .reply file is written as soon as its answer arrives.

PROMPT CACHING
--------------
Claude caches a prompt only when the request asks for it, and the cache pays
off only when the same prompt is sent again: writing an entry costs 1.25x the
normal input price (2x for the 1-hour TTL), and each later read costs 0.1x.
The shared instructions at the start of different queries are too short to
cache (the minimum is 1024-4096 tokens, depending on the model), so the only
repeated prompts are the tries of a `<name>.runN.query` file with N > 1.
Accordingly, with --prompt-cache 5m (the default) or 1h, those prompts are
marked for caching; single-try queries are not, since they would pay the
write premium for nothing.  The first try of each such query is sent alone,
and the remaining tries are sent as soon as it finishes (ahead of queries not
yet started), because a cache entry cannot be read until the request that
writes it has begun responding.

Reply headers report `input_tokens` (all prompt tokens, including cached
ones), `cached_input_tokens` (tokens read from the cache), and, when nonzero,
`cache_write_input_tokens` (tokens written to the cache).
"""
import sys, re
import asyncio
import contextlib
import heapq
import itertools
from pathlib import Path
import argparse
import hashlib
import json
import traceback

import aiofiles                # pip install aiofiles

def parse_args():
    # --help shows only the overview and the options, to fit on one screen;
    # --help-details also shows the rest of the docstring.
    details = "--help-details" in sys.argv
    overview, sep, rest = __doc__.partition("\nUSAGE")
    parser = argparse.ArgumentParser(
        description=overview.strip(),
        epilog=((sep + rest).strip() if details else
                "Run with --help-details for how queries are sent and how prompt caching works."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    need_files = not ({"--list-models", "--help-details"} & set(sys.argv))
    parser.add_argument("paths", nargs=("+" if need_files else "*"),
                        help="Path(s) to query file(s) or directory(ies) of query files")
    parser.add_argument("--help-details", action="store_true",
                        help="Explain how queries are sent and how prompt caching works")
    parser.add_argument("--list-models", action="store_true", help="List available models")
    parser.add_argument("--model", type=str, help="Model to use")
    parser.add_argument("--reasoning-effort", help="One of {low, medium, high}")
    parser.add_argument("--region-name", type=str, default="us-east-1",
                        help="AWS region (e.g., us-east-1, us-gov-east-1)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of parallel queries")
    parser.add_argument("--timeout", type=int, default=1200, help="Timeout in seconds")
    parser.add_argument("--max-output-tokens", type=int)
    parser.add_argument("--prompt-cache", choices=["5m", "1h", "off"], default="5m",
                        help="Cache lifetime for prompts sent more than once (the tries of a "
                             ".runN.query file), or 'off' (default: %(default)s)")
    parser.add_argument("--print-skipped", type=int,
                        choices=[0, 1], help="Print which queries already have answers")
    global cmdline_args
    cmdline_args = parser.parse_args()
    if cmdline_args.help_details:
        parser.print_help()
        sys.exit(0)

if __name__ == "__main__":
    parse_args()

sys.stderr.write("Importing boto3... ");
sys.stderr.flush()
import boto3 # pip install boto3
from botocore.config import Config
sys.stderr.write("Done.\n");

DEFAULT_MODEL = "us.anthropic.claude-sonnet-4-6"

# ----------------------------------------------------------------- #

def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

# -------------------- runN expansion helper ---------------------- #
_RUN_RE = re.compile(r'^(?P<base>.+)\.run(?P<n>[0-9]+)\.query$')

def expand_query_file(query_path: Path) -> list[tuple[Path, Path]]:
    """
    Given a query file, return a list of (query_path, reply_path) pairs.

    If the filename matches `basename.runN.query`, return N pairs with
    reply paths `basename.try00.reply`, `basename.try01.reply`, …
    Otherwise return a single pair with the standard `.reply` suffix.
    """
    m = _RUN_RE.match(query_path.name)
    if m:
        base = m.group("base")
        n = int(m.group("n"))
        # Determine zero-padding width: at least 2 digits
        width = max(2, len(str(n - 1)))
        pairs = []
        for i in range(n):
            reply_name = f"{base}.try{str(i).zfill(width)}.reply"
            pairs.append((query_path, query_path.parent / reply_name))
        return pairs
    else:
        return [(query_path, query_path.with_suffix(".reply"))]

# -------------------- skip-check helper -------------------------- #
def should_skip(reply_path: Path) -> bool:
    """
    Return True if this (query, reply) pair should be skipped.
    """
    if not reply_path.exists():
        return False
    return True

# -------------------------- core worker -------------------------- #
# Models that reject `thinking: {type: "adaptive"}` and `output_config.effort`.
NO_ADAPTIVE_THINKING_MODELS = ("haiku-4-5","sonnet-4-5")

def model_supports_adaptive_thinking(model: str) -> bool:
    return not any(name in model for name in NO_ADAPTIVE_THINKING_MODELS)


def build_request_body(prompt: str, opts) -> dict:
    """Anthropic Messages request body for InvokeModel."""
    content = {"type": "text", "text": prompt}
    if opts.get("cache_ttl"):
        # An explicit breakpoint (rather than top-level automatic caching, which
        # older Bedrock deployments reject) caches the whole prompt.
        content["cache_control"] = {"type": "ephemeral"}
        if opts["cache_ttl"] != "5m":
            content["cache_control"]["ttl"] = opts["cache_ttl"]
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": opts["max_tokens"],
        "messages": [
            {"role": "user", "content": [content]}
        ],
    }
    if opts.get("thinking", True):
        body["thinking"] = {"type": "adaptive"}
        body["output_config"] = {"effort": opts["effort"]}  # This is the reasoning effort.
    return body


# Messages API usage fields and the Bedrock response headers that carry the same counts.
USAGE_HEADERS = {
    "input_tokens": "x-amzn-bedrock-input-token-count",
    "output_tokens": "x-amzn-bedrock-output-token-count",
    "cache_read_input_tokens": "x-amzn-bedrock-cache-read-input-token-count",
    "cache_creation_input_tokens": "x-amzn-bedrock-cache-write-input-token-count",
}


def get_usage(result: dict, headers: dict) -> dict:
    """Token counts from a Messages API result, filling gaps from Bedrock's response headers."""
    usage = dict(result.get("usage") or {})
    for key, header in USAGE_HEADERS.items():
        if usage.get(key) is None and headers.get(header) is not None:
            usage[key] = int(headers[header])
    return usage


def format_usage(usage: dict) -> str:
    """Token counts for the reply header.

    As in ask_gpt.py, input_tokens counts every prompt token and
    cached_input_tokens is the subset read from the cache.  (The Messages API's
    own input_tokens excludes the tokens read from or written to the cache.)
    """
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    cache_read = usage.get("cache_read_input_tokens")
    cache_write = usage.get("cache_creation_input_tokens")
    if input_tokens is None and output_tokens is None:
        return ""
    if input_tokens is not None:
        input_tokens += (cache_read or 0) + (cache_write or 0)
    fields = f", input_tokens={input_tokens}"
    if cache_read is not None:
        fields += f", cached_input_tokens={cache_read}"
    if cache_write:
        fields += f", cache_write_input_tokens={cache_write}"
    return fields + f", output_tokens={output_tokens}"


def format_reply(result: dict, model: str, opts, query_path,
                 usage: dict) -> str:
    """Turn a Messages API result into the text of a .reply file."""
    response_text = ""
    reasoning = ""
    for content_part in result.get("content", []):
        part_type = content_part.get("type")
        if part_type == "thinking":
            reasoning += content_part.get("thinking", "")
        elif part_type == "text":
            response_text += content_part.get("text", "")

    actual_model = result.get("model", model)
    stop_reason = result.get("stop_reason")

    extra_header = ""
    if stop_reason and stop_reason not in ("end_turn", "stop"):
        extra_header += f", stop_reason='{stop_reason}'"

    if not response_text:
        print(f"No response for '{query_path}', stop_reason={stop_reason}.")

    if stop_reason == "max_tokens":
        response_text = (response_text + "<!-- REACHED MAX TOKEN LIMIT -->\n" +
            '{"verdict": "uncertain", "reason": "token limit reached"}\n')

    if reasoning:
        if not reasoning.endswith("\n"):
            reasoning += "\n"
        reasoning_hash = hashlib.sha256(reasoning.encode("utf-8")).hexdigest()[:12]
        response_text = (
            f"<reasoning_{reasoning_hash}>\n" +
            reasoning +
            f"</reasoning_{reasoning_hash}>\n\n" +
            response_text)

    extra_header += format_usage(usage)

    response = (f"# Model: {actual_model}, reasoning_effort='{opts['effort']}'"
                + extra_header + "\n\n" + response_text)
    if not response.endswith("\n"):
        response += "\n"
    return response


def query_claude(prompt: str, client, model: str, opts) -> tuple[dict, dict]:
    """Blocking Bedrock call. Safe to run inside a worker thread.

    Returns (result_dict, usage_dict).
    """
    resp = client.invoke_model(
        modelId=model,
        body=json.dumps(build_request_body(prompt, opts)),
    )

    # resp["body"] is a one-shot stream; read it here, inside the thread.
    result = json.loads(resp["body"].read())
    return (result, get_usage(result, resp["ResponseMetadata"]["HTTPHeaders"]))


async def process_query_file(
    query_path: Path,
    reply_path: Path,
    client,
    model: str,
    opts,
) -> None:
    """Read <file>.query → call Claude on Bedrock → write reply (async)."""
    # --- read prompt ------------------------------------------------
    try:
        async with aiofiles.open(query_path, "r", encoding="utf-8") as f:
            prompt = await f.read()
    except Exception as e:
        die(f"Error reading '{query_path}': {e}")

    # --- call Claude on Bedrock (blocking call in a worker thread) --
    try:
        result, usage = await asyncio.to_thread(query_claude, prompt, client, model, opts)
    except Exception as e:
        sys.stderr.write(f"Error generating completion for '{query_path}': {e}\n")
        sys.stderr.write(traceback.format_exc())
        die("Exiting due to error.")

    # --- assemble reply --------------------------------------------
    response = format_reply(result, model, opts, query_path, usage)

    # --- write reply -----------------------------------------------
    try:
        async with aiofiles.open(reply_path, "w", encoding="utf-8") as f:
            await f.write(response)
        print(f"Wrote reply to '{reply_path}'.")
    except Exception as e:
        die(f"Error writing '{reply_path}': {e}")

# --------------------- orchestration helpers --------------------- #
class PrioritySemaphore:
    """Semaphore that wakes waiters in order of priority (lowest first), FIFO within a priority."""

    def __init__(self, value: int):
        self._value = value
        self._waiters = []  # heap of (priority, seq, future)
        self._seq = itertools.count()

    async def acquire(self, priority: int) -> None:
        if self._value > 0 and not self._waiters:
            self._value -= 1
            return
        fut = asyncio.get_running_loop().create_future()
        heapq.heappush(self._waiters, (priority, next(self._seq), fut))
        try:
            await fut
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self.release()  # granted just before cancellation; pass it on
            raise

    def release(self) -> None:
        while self._waiters:
            _, _, fut = heapq.heappop(self._waiters)
            if not fut.done():
                fut.set_result(None)
                return
        self._value += 1

    @contextlib.asynccontextmanager
    async def slot(self, priority: int):
        await self.acquire(priority)
        try:
            yield
        finally:
            self.release()


async def run_tasks(task_pairs: list[tuple[Path, Path]], client, model, opts, concurrency: int) -> None:
    """
    Launch a task for each (query_path, reply_path) pair but bound
    outstanding API calls with a semaphore.

    With prompt caching, the tries of one query are grouped: the first try
    writes the cache entry, and the others are sent after it finishes so that
    they read the entry.  They take priority over queries not yet started, so
    that they start before the entry expires.
    """
    sem = PrioritySemaphore(concurrency)

    min_est_time_per_query = 5.0
    delay = min_est_time_per_query / max(concurrency, 10)

    groups = []  # (query_path, [reply_path, ...])
    for qp, rp in task_pairs:
        if opts.get("cache_ttl") and groups and groups[-1][0] == qp:
            groups[-1][1].append(rp)
        else:
            groups.append((qp, [rp]))

    async def _query(query_path: Path, reply_path: Path, priority: int, query_opts):
        async with sem.slot(priority):
            await process_query_file(query_path, reply_path, client, model, query_opts)

    async def _bounded_group(idx, query_path: Path, reply_paths: list[Path]):
        init_delay = (0 if idx == 0 else 0.100)
        tot_delay = init_delay + idx * delay
        await asyncio.sleep(tot_delay)  # stagger launches
        if len(reply_paths) == 1:
            # Nothing would read a cache entry, so don't pay to write one.
            await _query(query_path, reply_paths[0], 1, dict(opts, cache_ttl=None))
            return
        await _query(query_path, reply_paths[0], 1, opts)
        await asyncio.gather(*(_query(query_path, rp, 0, opts) for rp in reply_paths[1:]))

    await asyncio.gather(*(
        _bounded_group(i, qp, rps) for i, (qp, rps) in enumerate(groups)
    ))

# --------------------------- list models ------------------------- #
def list_models(region_name: str) -> None:
    # change "us-east-1" to "us-gov-east-1" for GovCloud
    bedrock = boto3.client("bedrock", region_name=region_name)  # control plane, not bedrock-runtime

    # List foundation models
    print("Anthropic models:")
    for m in bedrock.list_foundation_models(byProvider="anthropic")["modelSummaries"]:
        print(m["modelId"])

    print("\nModel IDs:")
    # List inference profiles (these are what you'll usually pass to invoke_model)
    for p in bedrock.list_inference_profiles()["inferenceProfileSummaries"]:
        print(p["inferenceProfileId"], "->", p["inferenceProfileName"])

# ------------------------------ CLI ------------------------------ #
async def main() -> None:
    args = cmdline_args

    if args.list_models:
        list_models(args.region_name)
        return

    model = args.model or DEFAULT_MODEL

    opts = {
        "effort": args.reasoning_effort or "high",
        "max_tokens": args.max_output_tokens or 60000,
        "cache_ttl": None if args.prompt_cache == "off" else args.prompt_cache,
    }
    if not model_supports_adaptive_thinking(model):
        # Such models reject adaptive thinking and the effort setting, so run without thinking.
        if args.reasoning_effort:
            print(f"Warning: --reasoning-effort is ignored for '{model}' (thinking is disabled).")
        opts["thinking"] = False
        opts["effort"] = "none"

    task_pairs = gather_task_pairs(args.paths)

    print(f"Number of queries to send to the LLM: {len(task_pairs)}")

    # A single low-level boto3 client is thread-safe and can be shared across
    # the worker threads that asyncio.to_thread spins up.
    #
    # credentials from env vars (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) or
    # ~/.aws/credentials
    boto_config = Config(
        read_timeout=args.timeout,
        connect_timeout=args.timeout,
        max_pool_connections=max(args.concurrency, 10),
        retries={"max_attempts": 10, "mode": "adaptive"},  # back off when throttled
    )
    client = boto3.client(
        "bedrock-runtime",
        region_name=args.region_name,
        config=boto_config,
    )

    await run_tasks(task_pairs, client, model, opts, args.concurrency)


def gather_task_pairs(paths: list[str]) -> list[tuple[Path, Path]]:
    """Find the .query files under `paths` and return the (query, reply) pairs still to do."""
    query_files = []

    for path_str in paths:
        target = Path(path_str)

        if target.is_file():
            if target.suffix != ".query":
                die(f"Error: File '{target}' does not end with '.query'.")
            query_files.append(target)

        elif target.is_dir():
            dir_query_files = [p for p in target.iterdir() if p.suffix == ".query"]
            if not dir_query_files:
                print(f"Warning: No .query files found in directory '{target}'.")
            else:
                query_files.extend(dir_query_files)

        else:
            die(f"Error: '{target}' is neither a file nor a directory.")

    if not query_files:
        die("Error: No .query files found in any of the provided paths.")

    # Expand .runN.query files into multiple (query_path, reply_path) pairs,
    # then filter out any pairs whose reply already exists and should be skipped.
    task_pairs = []
    reply_set = set()
    skipped = []
    for qf in query_files:
        for qp, rp in expand_query_file(qf):
            if should_skip(rp):
                skipped.append(rp)
                continue
            if rp not in reply_set:
                reply_set.add(rp)
                task_pairs.append((qp, rp))

    if cmdline_args.print_skipped is None:
        cmdline_args.print_skipped = (len(skipped) <= 10)
    if cmdline_args.print_skipped:
        for reply_path in skipped:
            print(f"Skipping '{reply_path}': reply already exists.")
    else:
        if len(skipped) > 0:
            print(f"Skipping {len(skipped)} files because reply already exists.")
    return task_pairs

if __name__ == "__main__":
    asyncio.run(main())
