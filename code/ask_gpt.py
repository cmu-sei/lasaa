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
import os, sys, re
import asyncio
from pathlib import Path
import argparse
import hashlib
import httpx
import traceback
import random
import time
from datetime import datetime, timezone

import aiofiles                # pip install aiofiles

def parse_args():
    parser = argparse.ArgumentParser(
        description="Send a query to an LLM and record its reply."
    )
    need_files = "--list-models" not in sys.argv
    parser.add_argument("paths", nargs=("+" if need_files else "*"), help="Path(s) to query file(s) or directory(ies) of query files")
    parser.add_argument("--list-models", action="store_true", help="List available models")
    parser.add_argument("--model", type=str, help="Model to use")
    parser.add_argument("--reasoning-effort", help="One of {low, medium, high}")
    parser.add_argument("--temperature", type=float, help="Sampling temperature")
    parser.add_argument("--provider", choices=["OpenAI", "Fireworks", "Gemini"], default="OpenAI")
    parser.add_argument("--base-url", help="Endpoint for OpenAI-style API")
    parser.add_argument("--api-key-name", help="The *name* of the env var with the API key (no '$')")
    parser.add_argument("--api-type", choices=["chat_completion", "response"])
    parser.add_argument("--concurrency", type=int, default=100, help="Number of parallel queries")
    parser.add_argument("--timeout", type=int, default=1200, help="Timeout in seconds")
    parser.add_argument("--max-output-tokens", type=int)
    parser.add_argument("--check-verdict", type=int, default=0,
                        choices=[0, 1], help="Redo queries that lack a verdict line")
    parser.add_argument("--print-skipped", type=int,
                        choices=[0, 1], help="Print which queries already have answers")
    global cmdline_args
    cmdline_args = parser.parse_args()
    
if __name__ == "__main__":
    parse_args()

sys.stderr.write("Importing openai... ");
sys.stderr.flush()
import openai # pip install --upgrade openai
AsyncOpenAI = openai.AsyncOpenAI
sys.stderr.write("Done.\n");

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
    if cmdline_args.check_verdict and '{"verdict":' not in reply_path.read_text(encoding='utf-8'):
        print(f"Redoing '{reply_path}' because it lacks a JSON verdict line.")
        return False
    return True

# ------------------------------------------------------------
class CircuitBreaker:
    """Tracks consecutive fails; trips when threshold is reached."""
    def __init__(self, threshold: int = 7):
        self.threshold = threshold
        self.consecutive_fails = 0
        self._tripped = False

    def record_fail(self) -> None:
        self.consecutive_fails += 1
        if self.consecutive_fails >= self.threshold:
            self._tripped = True

    def record_success(self) -> None:
        self.consecutive_fails = 0

    @property
    def is_tripped(self) -> bool:
        return self._tripped

# -------------------------- core worker -------------------------- #
async def process_query_file_via_response_api(
    query_path: Path,
    reply_path: Path,
    client: AsyncOpenAI,
    model: str,
    opts
) -> None:
    """Read <file>.query → call OpenAI (Responses API) → write reply (async)."""
    # --- read prompt ------------------------------------------------
    try:
        async with aiofiles.open(query_path, "r", encoding="utf-8") as f:
            prompt = await f.read()
    except Exception as e:
        print(f"Error reading '{query_path}': {e}")
        raise

    # --- call OpenAI (Responses) -----------------------------------
    try:
        extra_kwargs = {}
        if opts.get("reasoning_effort"):
            # Supported by reasoning models via the Responses API
            extra_kwargs["reasoning"] = {"effort": opts["reasoning_effort"]}
        if opts.get("temperature") is not None:
            extra_kwargs["temperature"] = opts["temperature"]

        resp = await client.responses.create(
            model=model,
            input=prompt,          # you can also pass [{"role":"user","content": prompt}]
            **extra_kwargs
        )

        # Convenient aggregate of all text outputs (provided by Responses SDK)
        response_text = getattr(resp, "output_text", None)
        if response_text is None:
            # Fallback: join any text outputs from the output array
            chunks = []
            for item in getattr(resp, "output", []) or []:
                if getattr(item, "type", None) == "message":
                    for c in getattr(item, "content", []) or []:
                        if c.get("type") == "output_text":
                            chunks.append(c.get("text", ""))
            response_text = "".join(chunks) if chunks else ""

        actual_model = getattr(resp, "model", model)
    except Exception as e:
        print(f"Error generating completion for '{query_path}': {e}")
        print(traceback.format_exc())
        raise

    # --- write reply -----------------------------------------------
    try:
        usage = getattr(resp, "usage", None)

        # Common fields
        output_tokens = getattr(usage, "output_tokens", None) if usage else None
        input_tokens = getattr(usage, "input_tokens", None) if usage else None

        # Reasoning token counts can live in a details object for some models
        reasoning_tokens = None
        if usage:
            # e.g., usage.output_tokens_details.reasoning_tokens
            details = getattr(usage, "output_tokens_details", None)
            if details is not None:
                reasoning_tokens = getattr(details, "reasoning_tokens", None)
            # fallback in case the SDK surfaces it directly
            if reasoning_tokens is None:
                reasoning_tokens = getattr(usage, "reasoning_tokens", None)

        header_bits = [f"Model: {actual_model}"]
        if input_tokens is not None:
            header_bits.append(f"input_tokens: {input_tokens}")
        if reasoning_tokens is not None:
            header_bits.append(f"reasoning_tokens: {reasoning_tokens}")
        if output_tokens is not None:
            header_bits.append(f"output_tokens: {output_tokens}")

        response = "# " + ", ".join(header_bits) + "\n\n" + (response_text or "")
        if not response.endswith("\n"):
            response += "\n"

        async with aiofiles.open(reply_path, "w", encoding="utf-8") as f:
            await f.write(response)
        print(f"Wrote reply to '{reply_path}'.")
    except Exception as e:
        print(f"Error writing '{reply_path}': {e}")
        raise


# -------------------------- core worker -------------------------- #
async def process_query_file_via_chat_completion(
    query_path: Path,
    reply_path: Path,
    client: AsyncOpenAI,
    model: str = "o4-mini-2025-04-16",
    opts = None,
    breaker = None
) -> None:
    """Read <file>.query → call OpenAI → write reply (async)."""
    # --- read prompt ------------------------------------------------
    try:
        async with aiofiles.open(query_path, "r", encoding="utf-8") as f:
            prompt = await f.read()
    except Exception as e:
        print(f"Error reading '{query_path}': {e}")
        raise

    # --- call OpenAI with streaming --------------------------------

    response = ""
    reasoning = ""
    finish_reason = None
    actual_model = model
    usage = None

    extra_kwargs = {}
    if cmdline_args.max_output_tokens:
        extra_kwargs["max_tokens"] = cmdline_args.max_output_tokens
    if opts and opts.get("temperature") is not None:
        extra_kwargs["temperature"] = opts["temperature"]
    if opts and opts.get("reasoning_effort"):
        extra_kwargs["reasoning_effort"] = opts["reasoning_effort"]
    try:
        if os.getenv("SIMULATE_503") == "1":
            req = httpx.Request("POST", "https://example.test/v1/chat/completions")
            resp = httpx.Response(
                503,
                request=req,
                json={"error": {"message": "The engine is currently overloaded, please try again later"}}
            )
            raise openai.APIStatusError("simulated 503", response=resp, body=resp.json())
        stream = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            stream=True,  # Enable streaming
            **extra_kwargs
        )

        
        async for chunk in stream:
            if chunk.choices:
                choice = chunk.choices[0]
                
                # Accumulate content from delta
                if choice.delta.content:
                    response += choice.delta.content
                
                # Accumulate reasoning if present (for reasoning models)
                if hasattr(choice.delta, 'reasoning_content') and choice.delta.reasoning_content:
                    reasoning += choice.delta.reasoning_content
                
                # Capture finish_reason from final chunk
                if choice.finish_reason:
                    finish_reason = choice.finish_reason
            
            # Capture model name if present
            if hasattr(chunk, 'model'):
                actual_model = chunk.model

            usage = getattr(chunk, "usage", None)

    except Exception as e:
        print(f"Error generating completion for '{query_path}': {e}")
        if isinstance(e, openai.APIStatusError):
            # Gracefully handle occasional 503s from due to high demand,
            # rather than instantly crashing.
            # Note: the particular query is left unanswered, but this script
            # (ask_gpt.py) is run iteratively until all queries have valid
            # answers or the max number of attempts is made.
            if e.status_code == 503:
                if breaker:
                    breaker.record_fail()
                await asyncio.sleep(1.0 + random.uniform(0, 3))
                return
        raise

    if breaker:
        breaker.record_success()
    
    extra_header = ""
    if finish_reason and finish_reason != "stop":
        extra_header += f", finish_reason='{finish_reason}'"
    
    if not response:
        print(f"No response for '{query_path}', finish_reason={finish_reason}.")
        response = ""
    
    if finish_reason == "length":
        response = (response + "<!-- REACHED MAX TOKEN LIMIT -->\n" + 
            '{"verdict": "uncertain", "reason": "token limit reached"}\n')
    
    if reasoning:
        if not reasoning.endswith("\n"):
            reasoning += "\n"
        reasoning_hash = hashlib.sha256(reasoning.encode("utf-8")).hexdigest()[:12]
        response = (
            f"<reasoning_{reasoning_hash}>\n" +
            reasoning +
            f"</reasoning_{reasoning_hash}>\n\n" +
            response)
    
    if usage:
        extra_header += f"\n# prompt_tokens={usage.prompt_tokens}, completion_tokens={usage.completion_tokens}"
    response = f"# Model: {actual_model}" + extra_header + "\n\n" + response
    
    # --- write reply -----------------------------------------------
    try:
        if not response.endswith("\n"):
            response += "\n"
        async with aiofiles.open(reply_path, "w", encoding="utf-8") as f:
            await f.write(response)
        print(f"Wrote reply to '{reply_path}'.")
    except Exception as e:
        print(f"Error writing '{reply_path}': {e}")
        raise

# --------------------- orchestration helpers --------------------- #
async def run_tasks(task_pairs: list[tuple[Path, Path]], client: AsyncOpenAI, api_type, model, opts, concurrency: int) -> None:
    """
    Launch a task for each (query_path, reply_path) pair but bound
    outstanding API calls with a semaphore.
    """
    sem = asyncio.Semaphore(concurrency)
    breaker = CircuitBreaker(threshold=7)
    min_est_time_per_query = 5.0
    delay = min_est_time_per_query / max(concurrency, 10)

    async def _bounded_task(idx, query_path: Path, reply_path: Path):
        start_time = time.time()
        init_delay = (0 if idx == 0 else 0.100)
        tot_delay = init_delay + idx * delay
        await asyncio.sleep(tot_delay)  # stagger launches
        async with sem:
            if breaker.is_tripped:
                return  # skip remaining work once we've given up
            elapsed = (time.time() - start_time)
            #print(f"Query {idx+1} starting at time t = {elapsed:0.2f} seconds.")
            if api_type == "chat_completion" or model in ["o1-mini"]:
                await process_query_file_via_chat_completion(query_path, reply_path, client, model, opts, breaker)
            else:
                await process_query_file_via_response_api(query_path, reply_path, client, model, opts)

    await asyncio.gather(*(
        _bounded_task(i, qp, rp) for i, (qp, rp) in enumerate(task_pairs)
    ))

    if breaker.is_tripped:
        die(f"Exiting due to {breaker.threshold} consecutive 503s.")


# ------------------------------ CLI ------------------------------ #
async def main() -> None:
    args = cmdline_args

    opts = {}
    if args.reasoning_effort:
        opts["reasoning_effort"] = args.reasoning_effort
    if args.temperature is not None:
        opts["temperature"] = args.temperature
    model = args.model

    openai_kwargs = {"timeout": args.timeout, "max_retries": 5}
    cafile = os.getenv("SSL_CERT_FILE")
    if cafile:
        http_client = httpx.AsyncClient(verify=cafile)
        openai_kwargs["http_client"] = http_client

    client = None
    if args.provider == "Fireworks":
        if not model:
            die("Must specify '--model' parameter, e.g., '--model gpt-oss-120b'.")
        if (cmdline_args.max_output_tokens is None):
            cmdline_args.max_output_tokens = 16000
        if ("/" not in model) and not model.startswith("accounts/fireworks/models/"):
            model = "accounts/fireworks/models/" + model
        args.api_type = "chat_completion"
        client = AsyncOpenAI(
            base_url = "https://api.fireworks.ai/inference/v1",
            api_key=os.environ["FIREWORKS_API_KEY"],
            **openai_kwargs
        )
    elif args.provider == "Gemini":
        default_model = "gemini-2.5-flash"
        args.api_type = "chat_completion"
        api_key_name = args.api_key_name or "GEMINI_API_KEY"
        api_key = os.getenv(api_key_name)
        if not api_key:
            die(f"Error: environment variable {api_key_name!r} is not set.")
        client = AsyncOpenAI(
            base_url = args.base_url or "https://generativelanguage.googleapis.com/v1beta/openai/",
            api_key=api_key,
            **openai_kwargs
        )
    else:
        default_model = "o4-mini-2025-04-16"
        if args.base_url:
            openai_kwargs["base_url"] = args.base_url
            if (args.api_type == None):
                args.api_type = "chat_completion"
        if args.api_key_name:
            api_key = os.getenv(args.api_key_name)
            if not api_key:
                die(f"Error: environment variable {args.api_key_name!r} is not set.")
            openai_kwargs["api_key"] = api_key
        client = AsyncOpenAI(**openai_kwargs)  # respects OPENAI_API_KEY env var

    if args.list_models:
        models = await client.models.list()
        print(f"Date       | Model ID")
        print(f"-----------+------------------------------------")
        for model in models.data:
            try:
                datestamp = datetime.fromtimestamp(model.created, tz=timezone.utc).strftime("%Y-%m-%d")
            except:
                datestamp = "????-??-??"
            print(f"{datestamp} | {model.id}")
        return

    if not model:
        model = default_model

    query_files = []
    
    for path_str in args.paths:
        target = Path(path_str)
        
        if target.is_file():
            if target.suffix != ".query":
                print(f"Error: File '{target}' does not end with '.query'.")
                sys.exit(1)
            query_files.append(target)
            
        elif target.is_dir():
            dir_query_files = [p for p in target.iterdir() if p.suffix == ".query"]
            if not dir_query_files:
                print(f"Warning: No .query files found in directory '{target}'.")
            else:
                query_files.extend(dir_query_files)
                
        else:
            print(f"Error: '{target}' is neither a file nor a directory.")
            sys.exit(1)
    
    if not query_files:
        print("Error: No .query files found in any of the provided paths.")
        sys.exit(1)

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
    print(f"Number of queries to send to the LLM: {len(task_pairs)}")

    await run_tasks(task_pairs, client, args.api_type, model, opts, args.concurrency)

if __name__ == "__main__":
    asyncio.run(main())
