# LASAA web UI

<legal>
LASAA tool

Copyright 2026 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Licensed under a MIT (SEI)-style license, please see License.txt or contact
permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

This Software includes and/or makes use of Third-Party Software each subject
to its own license.

DM26-0426
</legal>

A local, single-user web app for taking a codebase from source tree to
reviewed alerts: snapshot (and build) the code, run cppcheck and Clang
Static Analyzer, run LASAA on some or all of the alerts, and confirm or
override each verdict.  The design is in `../web-ui-design.md`.

**Warning: building is not sandboxed.**  When you make a snapshot with
"Build with command", the project's build scripts run in the same
container as the server.  In the container set up below, they run as an
unprivileged user (`lasaa-build`), so they can't read your API keys,
your AWS credentials, or the UI's workspace, can't modify the read-only
mounts, and are stopped when the build ends.  But they can still use the
network and read every file in the container that any user may read.
Choose "Build with command" only for code whose build you trust.
"Don't build" is safe for untrusted code: snapshots and analyses without
a build only read and parse the code.

## Starting the Docker container

The UI's image builds on the demo image (which has cppcheck and Clang),
which builds on the base `lasaa` image (which has `bear`).
From the parent of `code/` (where the Dockerfiles are):

    docker build -f Dockerfile -t lasaa .
    docker build -f Dockerfile.demo -t lasaa-demo .
    docker build -f Dockerfile.web-ui -t lasaa-web-ui .

Then start a container.  Publish the port on the host's loopback address
only, mount the code you want to analyze, and keep the workspace (the
UI's database, snapshots, and LASAA output) on the host so that it
outlives the container:

    docker run -it --rm -p 127.0.0.1:8000:8000 \
        --security-opt no-new-privileges \
        -v ${PWD}:/host:ro -w /host \
        -v /path/to/your/project:/src/project:ro \
        -v $HOME/.lasaa-ui:/root/.lasaa-ui \
        -v $HOME/.lasaa-mock:/root/.lasaa-mock \
        -e OPENAI_API_KEY -e FIREWORKS_API_KEY -v $HOME/.aws:/root/.aws:ro \
        lasaa-web-ui bash

The `-e` options pass API keys through from the host's environment
(OpenAI for the GPT models, Fireworks for gpt-oss-120b), and the `.aws`
mount provides the credentials for Claude on AWS Bedrock.  Leave out the
ones you don't use.  The `:ro` mounts keep LASAA and your project
read-only in the container (the UI writes only to its workspace); drop
`:ro` from `/host` in a container where you also edit LASAA or run the
command-line demos.  `no-new-privileges` keeps a build from getting
root back through a setuid program.  The `.lasaa-mock` mount keeps the
mock LLM's reply cache (see "Offline demos with a mock LLM" below); leave
it out if you don't use the mock.

## Launching the server

Inside the container:

    cd /host/code
    ./lasaa_webui_serve.py --workspace ~/.lasaa-ui --host 0.0.0.0

`--workspace` is required; it is the directory mounted above.
(`--host 0.0.0.0` lets Docker's port mapping reach the server; the
`-p 127.0.0.1:…` above still publishes it only to your machine.)
The server warns at startup if no API key is set (and there is no
`~/.aws/credentials` or `~/.aws/config`), since LASAA runs would fail.

The server prints a URL with a one-time token, like
`http://localhost:8000/?token=...`.  Open it in a browser on the host.
Requiring the token is a security defense-in-depth measure.
(The token is also written to `token` in the workspace.  Each start
makes a new one.)
Stop the server with Ctrl-C; unfinished jobs are marked
"interrupted" and can be resumed after a restart.

Run `./lasaa_webui_serve.py --help` for the other options, such as `--port`
and `--blind-mode`.

**Predefined model configs.**  To have model configs ready in the run
form without making them by hand (for example, a local Ollama server or
a company LLM proxy), list them in a JSON file and pass
`--model-configs FILE` (more than once for several files):

    ./lasaa_webui_serve.py --workspace ~/.lasaa-ui --host 0.0.0.0 \
        --model-configs ../model_configs.example.json

Each config has a `name` (shown under "Saved" in the model list) and the
fields of the run form's Model panel: `provider` ("Other" if not given,
or any other provider), `model`, `effort`, `base_url`, `api_type`, and
`api_key_name` (for "Other"), `region` and `prefix` (AWS Bedrock),
`or_endpoint` (OpenRouter), `max_output_tokens`, `flex`, and
`concurrency`; see `../model_configs.example.json`.  They are checked as
the form checks them (an "Other" config's API key must come from a
variable named `…_LASAA_KEY`), and a bad one stops the server.  Each
start saves them, replacing saved configs with the same names; others
are left alone.  Keep the file outside the workspace, so that clearing
the workspace doesn't remove it.  The server notes any config whose API
key variable isn't set.  Choosing a config fills in its effort and other
run settings, which stay editable.

## Workflow

1. **Snapshot.**  On the home page, under "New snapshot", give a project
   name, a directory as the container sees it (e.g. `/src/project`),
   optionally a git commit, and either "Don't build" or "Build with
   command" and the command.  The UI freezes a copy of the source files,
   so later views and prompts refer to exactly that code.  Clang Static
   Analyzer needs a build command; the form suggests one (`make -B`).
   The build runs the project's own scripts without a sandbox (see the
   warning above), so for untrusted code, choose "Don't build".
   If it fails part-way, the snapshot keeps what compiled.
2. **Analyze.**  On the snapshot, check the analyzers (Clang, cppcheck),
   choose their presets, and click "Run the selected analyzers".  Their
   alerts go into one analysis.  (To bring in alerts and LASAA output
   made on the command line instead, use `./lasaa_webui_import.py`; see
   `--help`.)
3. **Run LASAA.**  In the alert list, click "Run LASAA on all N alerts…",
   or filter or check (`x`) alerts first.  Choose the model, effort, and
   other settings; the cost estimate follows your choices.  Click
   "Prepare the run" and set a budget, then "Start the run".  The run
   page shows progress and spend, with Cancel and Resume.
4. **Review.**  Open an alert to see the code, the trace, and the LLM's
   explanation.  Press `c` to confirm the verdict.  If focus is in
   a text box, press Esc to enable the keyboard shortcuts.  To ask an
   LLM about the alert, the code, or LASAA's answer (and follow-up
   questions), use "Ask an LLM" (`a`); the LLM is sent the prompt LASAA's
   verdict came from and its final answer.  Conversations are kept with
   the alert, and can be deleted.
5. **Export.**  The alert list links to CSV and adjudications JSON
   exports with the manual verdicts and notes.

## Example: tinykv

`../../examples/tinykv` is a small C key-value server with a mix of real
defects and code that analyzers misjudge (see its `lasaa_demo/README.md`).
With the `docker run` command above, started from `fr/`, it is at
`/host/examples/tinykv` in the container, so no extra `-v` is needed.

**From scratch, in the browser.**

1. Under "New snapshot", enter the project name `tinykv`, the directory
   `/host/examples/tinykv`, choose "Build with command", enter
   `make -B -j$(nproc) all tests/test_main`, and click "Make snapshot".
   (Or click "Fill in the tinykv example" at the top of the form, which
   fills in the project, the directory, and "Build with command" with
   `make -B -j$(nproc)`, then click "Make snapshot".)
   The ground-truth file in `lasaa_demo/` isn't a source file, so it is
   left out of the snapshot.
2. On the new snapshot, leave both analyzers checked, with their default
   presets, and click "Run the selected analyzers".  Clang finds 23
   alerts and cppcheck 10: the 33 alerts of the command-line demo, in
   one analysis.
3. Open the analysis, click "Run LASAA on all N alerts…", and choose a
   small, cheap run: a random sample of 5 alerts, `gpt-6-luna` with medium
   effort, 3 trials per phase, threshold `2/3`.  Check the estimate (a few
   cents at most), click "Prepare the run", then "Start the run".  It
   takes about a minute.
4. Review the alerts.  See also `lasaa_demo/ground_truth.json`.

**Importing the command-line demo.**  `lasaa_demo/README.md` runs both
Clang and Cppcheck (33 alerts) and adjudicates them on the command line.
After its steps 1 and 2 (`lasaa_demo/out/` and `lasaa_demo/lasaa_out/`),
import the results and start the server:

    cd /host/code
    ./lasaa_webui_import.py --workspace ~/.lasaa-ui \
        --alerts ../examples/tinykv/lasaa_demo/out/alerts.json \
        --src ../examples/tinykv --out ../examples/tinykv/lasaa_demo/lasaa_out
    ./lasaa_webui_serve.py --workspace ~/.lasaa-ui --host 0.0.0.0

The imported run shows up as the project's first analysis, with its
verdicts and explanations.  LASAA runs from the UI show the LLM every
alert field except the ID; the demo's alerts have just the fields its
command-line run used.  For an alerts file with fields the LLM shouldn't
see (a label, say), give the list to show at import:
`./lasaa_webui_import.py --fields-for-llm File,Line,Message,... ...`.


## Offline demos with a mock LLM

For a demo that runs offline or shouldn't wait on a real model,
`../mock_llm_server.py` is a stand-in for the OpenAI Responses API that
answers from replies already in a workspace.  It matches each request
on the exact prompt text (by SHA-256), the model, the reasoning effort
("default" when none is given), and the trial number, and answers with
the reply that the original run got for that trial.  So it never shows
one model's answer as another's, and a replayed run gets the same
replies whatever order its requests come in, and so the same later
prompts (definition lookups and LRE, which are built from earlier
replies).  Each answer is sent whole after a random delay of 2 to 4
seconds, so the run page still shows progress.  A request with no
cached reply gets an immediate error (HTTP 404), and the server logs it.

The trial number comes in an `X-LASAA-Trial` HTTP header, which
`ask_gpt.py` sends with `--mock-llm-server` (the trial `KK` of the
reply file `X.tryKK.reply` it will write; 0 for `X.reply`).  The UI
passes that option for any "Other" model whose base URL's host is a
numeric IP address or `localhost`; other servers (Ollama, LiteLLM, and
so on) ignore the header.  The mock refuses requests without it
(HTTP 400).

First build the cache from the workspace's `.query` and `.reply` files:

    cd /host/code
    ./mock_llm_build_cache.py        # writes ~/.lasaa-mock/mock_llm_cache.jsonl

The cache is kept outside the workspace, so `rm -rf ~/.lasaa-ui/*`
leaves it alone, and the `.lasaa-mock` mount in the `docker run` command
above keeps it on the host across containers (without the mount, it is
lost with the container).

The builder prints how many prompts and replies it found for each model
and effort.  Rerun it after real runs add replies.  Byte-identical
copies of a reply (a copied project, or an earlier mock run) are stored
once, but if two runs have different replies for the same prompt,
model, effort, and trial, it names both files and stops without writing
the cache; remove one of the runs, or point `--workspace` at a
directory that has just one.

Then, in the same container as the UI, start the mock (in another
shell, or in the background):

    ./mock_llm_server.py &           # http://127.0.0.1:8100/v1
    ./lasaa_webui_serve.py --workspace ~/.lasaa-ui-demo --host 0.0.0.0 --mock-llm

With `--mock-llm`, the UI reads the cache at startup and saves a model
config for each model and effort in it, named like "Mock: gpt-6-luna
(medium)": provider "Other", base URL `http://127.0.0.1:8100/v1`, API
type `response`, and the API key variable `MOCK_LLM_LASAA_KEY`, which the
server sets to a dummy value if it isn't set (the mock doesn't check
it).  Each start replaces configs with those names, so they come back
after the workspace is cleared; configs for a model or effort no longer
in the cache are left alone (delete them in the run form).  The mock
needn't be running yet.  `--mock-llm-url` and `--mock-llm-cache` give a
different URL (its host must be a numeric IP address or `localhost`) or
cache.

In the run form, choose a "Mock: …" config under "Saved".  Choosing it
sets the reasoning effort to the config's; leave it, since another
effort isn't in the cache.  To switch to the live OpenAI endpoint,
choose a ready-made OpenAI model instead; the server doesn't need
restarting.  While a run on a local base URL like the mock's is going,
its run page refreshes every second instead of every 2 seconds.

The mock's options: `--cache`, `--host`, `--port` (default 8100), and
`--min-delay` and `--max-delay` in seconds; see `--help`.

Things to know:

- **Use a fresh workspace for each demo.**  A run's replies are kept
  per analysis and model config, and the mock's config (an "Other"
  model with its own base URL) is separate from the original run's, so
  the first mock run asks the mock for everything, even in the
  workspace the cache came from.  But LASAA skips every query that
  already has its replies, so a second mock run on the same analysis
  reuses the first one's and asks nothing.  For each demo, use a fresh
  workspace (`~/.lasaa-ui-demo` above, which the `docker run` command
  needs to mount) or a new analysis.
- **Use the original run's settings.**  The settings that shape the
  prompts (the alerts, fields shown, number of trials, LRE, and so on)
  must match the run that made the replies.  An LRE prompt includes
  every phase-1 reply, for example, so fewer trials give LRE prompts
  that aren't cached, and more trials ask for trials that aren't.
  Rehearse the demo once and look for `400` and `404` lines in the
  mock's log.  A miss makes `ask_gpt.py` exit with an error, which ends
  the LASAA run early with the remaining alerts unanswered.
- **Single-turn only.**  "Ask an LLM" sends conversations, which the mock
  refuses (HTTP 400), and "Test the connection" sends a prompt that isn't
  in the cache.  Only LASAA runs work against the mock.
- The mock serves only `POST /v1/responses` and `GET /v1/models`, not
  chat completions.
