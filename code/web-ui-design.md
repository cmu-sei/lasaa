# LASAA Web UI — Design

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


## Goals and non-goals

The web UI takes a codebase from source tree to reviewed alerts in one place: snapshot the code, run cppcheck and Clang Static Analyzer, run LASAA on all alerts or a chosen subset, and let a person confirm or override each verdict with a note.

**Goals**

- Run locally as a single-user server. No accounts, but real web security (see Security).
- Keep a frozen copy of every codebase version that was analyzed, so code views, LASAA prompts, and reviews always refer to the exact code the alerts came from.
- Drive the existing pipeline (`adjudicate_alerts.py`, the clients, `conv/`) without changing its prompts or cache behavior.
- Make triage fast: verdict-first ordering, keyboard review, and the LLM's reasoning next to the code.
- Collect manual verdicts in a form that can be exported (SARIF, adjudications JSON, CSV) and compared with LLM verdicts.

**Non-goals for now**

- Cascading (matching alerts and reviews from an older snapshot to a newer one). The data model leaves room for it; see Data model.
- Multi-user collaboration, accounts, or deployment on a shared server.
- Analyzers other than cppcheck and Clang Static Analyzer.
- Editing source code in the UI.

**Constraints from the pipeline**

- Prompt text is a cache key. The UI must not change how prompts are built; it only chooses inputs and options.
- Only `false` alerts may be hidden, and never silently. (The list shows them by default, since the UI is mainly for demos.) `true`, `dependent`, and `uncertain` always reach the reviewer.

## Architecture

The UI is a thin local web app over the existing command-line pipeline: it owns a workspace directory and a SQLite database, starts the analyzers and `adjudicate_alerts.py` as subprocesses, and indexes the files they write.

```text
+---------+       +--------------------------+        +------------------------+
| Browser |------>| Web server               |        | ui.sqlite              |
+---------+ HTTP  | pages, JSON API,         |------->| alerts, run results,   |
                  | live progress; token,    |        | jobs; reviews live     |
                  | Host check, CSRF, CSP    |        | only here              |
                  +--------------------------+        +------------------------+
                               |                                  ^
                               | start, cancel                    | writes
                               |                                  |
                               v                                  |
                  +--------------------------+        +------------------------+
                  | Job runner               | round  | Indexer                |
                  | one process group per    |------->| parses .reply and      |
                  | job, logged              |        | .final_answer files    |
                  +--------------------------+        +------------------------+
                               |                                  ^
                               |                                  | reads
                               v                                  |
+--------------------------------------------+        +------------------------+
| Subprocesses (existing tools, unchanged)   | write  | Workspace files        |
|                                            |------->| snapshots (read-only   |
| snapshot copy + ctags                      |        | src), analysis output, |
| bear + build command                       |        | LASAA output dirs      |
| cppcheck, clang analyzer                   |        +------------------------+
| conv/ converters                           |
| adjudicate_alerts.py + LLM client ------------+
+--------------------------------------------+  |
                                                |
                                                |     +------------------------+
                                                +---->| LLM provider API       |
                                                      +------------------------+
```

The job runner starts the existing tools and wakes the indexer after each pipeline round; the indexer turns what they write into database rows, and pages read only the database.

- **Web server** (`lasaa_webui/`, Python). Serves pages and a small JSON API, bound to 127.0.0.1.
- **Job runner**, in the server process. Runs one long job at a time per project (snapshot, build, analyze, adjudicate), each in its own process group, with stdout and stderr captured to a log. Job state is persisted, so a restarted server shows interrupted jobs and can resume them. Resuming is just rerunning the same command, since the pipeline's on-disk cache skips work already done.
- **Indexer.** After each pipeline round, and on demand, it reads `.final_answer` and `.reply` files into the database (verdict, explanation, per-trial verdicts, token counts). Pages read only the database; they never parse pipeline files on request.
- **Review store.** Manual verdicts and notes live only in the database, never in pipeline files (see Review store).

The pipeline itself is not imported. That keeps the UI from depending on internal functions, and anything the UI does can be reproduced from a shell with the command it logged.

**Workspace layout** (the required `--workspace DIR`, for example `~/.lasaa-ui/`):

```
ui.sqlite                          projects, snapshots, analyses, runs, alerts, reviews, jobs
jobs/<job>.log                     output of each job (snapshot, cppcheck, LASAA run)
projects/<proj>/
  snapshots/<snap>/
    src/                           frozen copy: source files only, after the build (read-only)
    manifest.json                  origin, HEAD commit, dirty flag, build command and status,
                                   file hashes, skipped files, time
    compile_commands.build.json    bear's output, with paths into the build's work/
    compile_commands.json          rewritten to point into src/
    func_bounds.json
  analyses/<analysis>/
    cppcheck.xml | csa/units/*.sarif, csa/merged.sarif, csa/summary.json
    alerts.json                    LASAA-format alerts
  lasaa/<analysis>/<config>/       adjudicate_alerts.py output dir (shared cache)
  runs/<run>/
    subset.json                    the run's alerts, with Base_Dir set to the snapshot's src/
```

The model list is `lasaa_webui/models.py` (Python 3.10 has no TOML reader), and prices come from `code/model_prices.csv` (by model and provider, else by model). A run's selection (alert IDs, filters, sample size, seed, model spec, estimate) and command are stored in its database row.

**Models.** The run form's Model panel offers ready-made models (shown with their provider and price), the user's saved configs ("Save config" and "Delete"; table `saved_model`), and "Another model…": a provider (OpenAI, AWS Bedrock, Fireworks, Gemini, OpenRouter, or Other), the model's name, and what that provider needs (Other: base URL, API type, and an API key variable, which must be named `…_LASAA_KEY` so that no other secret can be sent to a typed-in URL; OpenRouter: the endpoint tag, required; Fireworks and OpenRouter: max output tokens). The client follows from the provider (`ask_claude_aws.py` for AWS Bedrock, else `ask_gpt.py`). Every model also has the effort, the region and model prefix (AWS Bedrock; the prefix follows the region by default), flex tier (OpenAI), and concurrency. A "config" (one output directory, so one cache) is the client, the model, the effort, and the endpoint: "" for OpenAI and AWS Bedrock, the provider for Fireworks and Gemini, `OpenRouter:` plus the endpoint tag (a quantization), or the base URL. The Bedrock model is kept without its region prefix (`us.` and `global.` share a cache); the API type, flex tier, region, key variable, concurrency, and output cap don't split the cache. Before a run, replies that a lower output cap cut short (verdict "uncertain", "token limit reached") are deleted, with their `.final_answer`, so a higher cap asks them again. At the bottom of the panel, "Test the connection" sends a short prompt to the model with its client, as a run would (into a scratch directory, with a 1000-token cap), and shows the reply or the client's error. (Future work: listing a provider's models through its API.)

One output directory per (analysis, LASAA config) means that every run with the same model and prompt variant shares one cache. A config is the client, model, and reasoning effort. The prompt variant is fixed, since the UI is mainly for demos: `--dep-as-tp` off, `--need-defs-style standalone`, and no `--fields-for-llm` (the LLM sees every alert field except the ID) unless an imported analysis was given one with `lasaa_webui_import.py --fields-for-llm`. Options that only change how existing replies are combined (`-n`, `-t`, `--cc`, `--lre`) are per run, not per config, because the pipeline recomputes `.final_answer` cheaply when they change. Each run therefore copies its alerts' `.final_answer` text into the database, so a later run with different options doesn't overwrite an earlier run's results.

## Data model

Everything hangs off a frozen snapshot: an analysis belongs to one snapshot, an alert to one analysis, and a review to one alert, so every code view and every verdict refers to exactly the code that was analyzed.

| Entity       | Key               | Holds |
| ---          | ---               | --- |
| Project      | `project_id`      | Name, origin (local path or git URL), default build command, notes, hidden flag ("Delete project" hides it from the lists and renames it to `deleted ID NAME yyyy-mm-dd hh-mm`, freeing the name; nothing is removed from disk), and the name it had before (for "Restore") |
| Snapshot     | `snap_id`         | Frozen source files, build command, compilation database, HEAD commit (if git), dirty flag, file-hash manifest, creation time |
| Analysis     | `analysis_id`     | Snapshot, tool (cppcheck or CSA), tool version, options, status, `alerts.json` |
| Alert        | (`analysis_id`, `Alert_ID`) | File, line, CWEs, rule, message, severity, trace, and the full LASAA-format record; `fingerprint` column reserved for cascading |
| LASAA config | `config_id`       | Client, model, reasoning effort (prompt variant fixed); one output dir per (analysis, config) |
| Run          | `run_id`          | Analysis, config, `-n`/`-t`/`--cc`/`--lre`, selection, budget, command line, status, cost |
| Run result   | (`run_id`, alert) | Verdict, explanation, per-trial verdicts, uncertain explanation, definitions supplied, tokens, cost |
| Review       | (alert, revision) | Manual verdict, confirmation flag, note, reviewer, time; append-only history |
| Chat         | `chat_id`         | "Ask an LLM": alert, run result, model spec, the context sent with the first question; its turns (question, answer, reasoning, tokens, cost, status) are in `chat_turn`. Deleting a chat deletes its turns |

**Creating a snapshot.** The user gives a local directory, optionally a commit of the git checkout it is in (exported with `git archive`, so the working tree's state doesn't matter), and optionally a build command (required for CSA; milestone 4). Cloning from a URL isn't supported. The frozen copy is taken after the build, so generated sources are in it, but it keeps only source files.

1. Copy the whole origin tree to `work/`, a disposable directory in a fresh temporary directory outside the workspace (so that the build user can reach it; see Security), skipping `.git`. Binary files are copied too, since the build may need them. From a git checkout this is the working tree. If it has uncommitted changes, the UI warns, and the snapshot is recorded as dirty along with its `HEAD` commit.
2. If there is a build command, run `bear -- <build command>` in `work/` (see Running analyzers). Without one, there is no `work/`: the files are frozen straight from the origin (or from the exported commit).
3. Freeze: copy the source files of `work/` into `src/`. A file is kept if it has one of the extensions that the pipeline's ctags run maps to C, C++, or Java (`.c`, `.h`, `.cc`, `.cpp`, `.hpp`, `.inl`, `.java`, and so on; `ctags --list-maps=C++`), is a common build file (`Makefile`, `*.mk`, `CMakeLists.txt`, `*.cmake`, `configure.ac`, `meson.build`), matches an `--include` glob, or is named by an alert or trace step. `--only GLOB` replaces the extension list. Since the pipeline takes functions and `need_defs` definitions only from files ctags reads, a re-run on the snapshot sees the same context as one on the origin. This keeps generated sources (a generated `config.h` or parser) and leaves out objects, libraries, data files, and LLM output directories. Kept files whose first 8 KB contain a NUL byte, or that are over a size limit (default 10 MB), are skipped. The manifest lists the skipped files and the whitelist, and counts the files left out. After a build, every file under `work/` that a compile command reads is kept too (from `clang -M` with that entry's flags), since CSA compiles from `src/` and needs headers with other extensions, such as `.inc`, `.def`, or `.tcc`. The directories the compile commands run in are kept even if empty.
4. Rewrite `compile_commands.json` to point into `src/`, make `src/` read-only, compute `func_bounds.json` with ctags, and delete `work/`.

Files identical to the previous snapshot of the same project are hard-linked, so repeated snapshots of a large repository cost little disk. When the origin is a github.com repository, alerts get `Repo_URL` and `Repo_Rev` (the `HEAD` commit) so that `need_defs` can look outside the snapshot through `repo_cache.py`. For a dirty snapshot, definitions fetched that way may not match local edits, and the warning says so.

**Alert identity.** Within an analysis, an alert is identified by the converter's deterministic `Alert_ID`. That ID includes the line number, so it is not stable across snapshots. Cascading will add a separate `fingerprint` and a mapping table between snapshots; nothing else in this design depends on IDs being stable across snapshots.

## Running analyzers

Both analyzers run against the frozen `src/` and write only into the analysis directory. The snapshot's "Analyze" form has a checkbox for each analyzer, with its options, and one button: the checked analyzers run in one job (CSA first) and their alerts go into one analysis, so all of a snapshot's alerts can be triaged in one list. If one analyzer fails, the analysis fails. The build happens once, when the snapshot is made, and its `compile_commands.json` drives Clang Static Analyzer (CSA) and gives cppcheck accurate include paths and defines.

**Build step** (at snapshot time; needed for CSA, optional for cppcheck)

1. Run `bear --output compile_commands.build.json -- sh -c '<build command>'` in `work/`, as the unprivileged build user when the server runs as root, and without API keys or AWS credentials in its environment (see Security). The build is a process group of its own, so Cancel stops it (and deletes the half-made snapshot); afterwards, and on Cancel, every process of the build user is killed, including any the build left running in the background. The form suggests a command from the build files at the top of the directory (`CMakeLists.txt`, `meson.build`, `configure`, or a Makefile), and the command used last time for the same directory, but the user must type or accept it. The form has two radio buttons, "Don't build" and "Build with command", with neither selected at first; the browser won't submit the form until one is chosen, so a snapshot is never left unbuilt (or built) by accident. Typing a command, or taking a suggestion, selects "Build with command". For make, the suggestion is `make -B`, because a tree that was already built would otherwise compile nothing and record no commands.
2. Rewrite the paths in `compile_commands.json` from `work/` to `src/`, and drop precompiled-header flags (`-include-pch`), since `.pch` files aren't frozen.
3. Freeze `src/` as described under Data model. Analyses never see `work/`.

If the build fails part-way, the snapshot is made anyway from the commands that bear recorded, and the project page says "the build failed" next to it; the log is on the job page. A build that records no compile commands is flagged too, and CSA isn't offered for it.

**cppcheck**

- With a compilation database (a checkbox, on by default when the snapshot has one): `cppcheck --project=compile_commands.json --relative-paths=src/ --xml --enable=<preset> --inconclusive --library=posix -j N`.
- Without one: run in `src/` on `.`, so reported paths are relative, with `--inconclusive --library=posix -D_GNU_SOURCE`. The form takes extra arguments, limited to `-I`, `-D`, `-U`, `--std=`, `--library=`, `--platform=`, `--suppress=`, `--max-configs=`, `--force`, and `--inconclusive` (no `--addon`, which runs scripts, or `--output-file`).
- Alerts get the Tool `cppcheck`. Runs show the LLM every field the converter writes except the ID; `LocationInfo` and `AdditionalLocations` carry cppcheck's secondary locations (for example, the condition that a `nullPointerRedundantCheck` is about), and the pipeline adds the functions containing `AdditionalLocations` to the prompt.
- Convert with `conv/cppcheck_to_lasaa.py`.
- Presets: "warnings" (`warning,portability`), "default" (adds `performance`), and "everything" (adds `style`, which is noisy).

**Clang Static Analyzer**

- For each entry in `compile_commands.json`, run `clang --analyze --analyzer-output sarif` with that entry's flags, in parallel (`lasaa_webui/csa.py`). Running it per entry, instead of through `scan-build`, gives one SARIF file per translation unit and doesn't depend on `scan-build` intercepting the compiler. Since the build compiler may be GCC, only the flags that change what is parsed are passed on (`-I`, `-D`, `-U`, `-include`, `-isystem`, `-std=`, `-m32`, and the like); `clang++` is used for C++ entries. A unit that fails is listed in the log, and the rest go on.
- Checker presets: "default" (clang's default checkers, which include core, unix, cplusplus, nullability, and some `security.insecureAPI` checkers, without `deadcode.DeadStores`, which is style noise, and with `alpha.unix.Stream`, which finds `FILE*` leaks; these are the tinykv demo's settings) and "security" (adds `security.FloatLoopCounter` and a curated set of `alpha.security.*` and `alpha.unix.cstring.*` checkers). Checkers that the installed clang lacks are left out, with a note in the log.
- Merge the per-unit SARIF files into one SARIF run (`csa/merged.sarif`), then convert it once with `conv/sarif_to_lasaa.py -b src/ --no-default-level` (CSA gives no levels, so `Level` would always be SARIF's default `warning`). One merged file keeps `sarif_to_lasaa.py -u` working for export; the analysis records the converter options (`sarif_args`) so that the export passes them too and gets the same `Alert_ID`s. URIs under `src/` become relative, with `uriBaseId` `SRCROOT` (left undefined in the file), so the paths and `Alert_ID`s don't depend on where the workspace is. An alert in a header shows up once per translation unit that includes it; results with the same rule, location, and message are kept once (the first unit's trace), and the log says how many were dropped.

**After either tool**

- Alerts whose primary location is outside the project (system headers) are kept, marked "external", and left out of the default LASAA selection, with their count shown.
- Tool versions, options, and the exact commands are stored with the analysis.
- Importing an existing SARIF file (any tool) is a small addition: skip the build and use `sarif_to_lasaa.py`.

## Running LASAA

A run is: pick alerts and options while the estimated cost follows them, prepare the run (which shows its command and a budget), start it, then watch progress. All but the last happen on one page; changing an option after preparing takes the Start button back, so what starts is what was shown. The UI writes the selected alerts to a subset file and runs `adjudicate_alerts.py -a subset.json -b snapshot/src -o <config dir> --llm-script <client> -- <client args>`. The prompt depends only on the alert's fields, not on which file it came from, so subsets share the config's cache.

- **Paths in prompts.** Each alert in the subset file gets `Base_Dir` set to the snapshot's `src/`. The pipeline then shows paths relative to it, so prompts don't contain the workspace's location and don't change if the workspace moves. Alerts without `Base_Dir` show absolute paths, so a UI run can't reuse the replies of a command-line run made with `-b`; imported runs stay browsable and reviewable.
- **Ground-truth labels** (`Verdict` fields) are dropped from the subset file.
- **Leftover queries.** The LLM client sends every unanswered query in the output directory, not just this run's. Before each run (and resume), the UI deletes query files whose replies aren't all there; the pipeline rewrites the ones it needs.

**Selection**

- Filters: tool, rule, CWE, severity, file or directory glob, current LLM verdict, review status, and free text over the message. Manually reviewed alerts are left out unless the user includes them.
- Scope: all matching alerts, alerts checked in the list (`x`), or a **random sample of N** of the matching alerts.
- A sample is a simple random sample. (Stratified samples, N per rule or severity, were dropped.)
- The seed, the filter, and the size of the population sampled from are stored with the run. With that, the stats page can extrapolate from a reviewed sample to the whole population, with a confidence interval. Sampling without replacement across runs ("another 20 not yet adjudicated") is an option.

**Cost estimate and budget**

1. Run the pipeline with `--dont-run-llm` into a scratch directory (so the shared output directory isn't touched) to write the first round of queries, for the analysis's alerts in the snapshot (the pipeline stops at an alert whose file is missing). The prompts don't depend on the model or the options, so their sizes are kept per alert in the analysis's `prompt_sizes.json` until the pipeline's code changes, and the form recomputes the estimate from them as the options change. One dry run goes in the background (`prompt_sizes.py`), over the alerts not measured yet: the form's selection first, then the rest ordered by the SHA-256 of their IDs (random-looking whatever the IDs are). The pipeline handles alerts in the file's order and prints a status line after writing each query, so the UI reads the sizes of the queries written so far: after the first 100 alerts, then every 0.5 s. (An earlier version ran separate dry runs in growing chunks; one run is simpler and faster.) The page shows at once; the estimate follows by long poll, extrapolated from the alerts measured so far (and marked so) until every alert is measured. "Prepare the run" waits only for the first 100. On 3,000 synthetic alerts (350k lines; `perf/make_synthetic_project.py`), the first estimate came 1.4 s after the page, within 1% of the exact one at 6.2 s.
2. Count input tokens in those `.query` files (characters divided by 4) and multiply by the number of trials. Trials whose replies are already in the config's output directory are free.
3. Estimate output tokens from earlier replies by the same model and effort, read from `# Model:` headers (the model's other efforts only if there are none at this effort; a default if there are none at all).  Efforts can differ a lot in reasoning tokens.
4. Show the result as a range. The low end is phase 1 only. The high end adds `need_defs` rounds and (if LRE is on) LRE rounds, scaled by how often they occurred in past results with the same model and effort (for LRE, only results of runs with LRE on), or assumed for every alert when there's no history. An LRE prompt holds the phase-1 replies without their reasoning (`strip_hdr_and_reasoning`), so its input counts each reply as `output_tokens` minus `reasoning_tokens`.

Prices come from `code/model_prices.csv` (model, provider, input and output $ per million tokens, source URL, access date), reread whenever they are needed. A model name matches a row after dropping a provider prefix (`us.anthropic.`, `accounts/fireworks/models/`) or by a dated name (`o4-mini` matches `o4-mini-2025-04-16`). Cached input is charged at the full price, so costs err high. Costs are shown with the as-of date of the prices used; without a price, estimates show tokens only and the budget is in tokens. (Deferred: a "paste this prompt into a chatbot, paste back its JSON" workflow for updating prices.)

Before starting, the user sets a budget (default: 1.5 times the high estimate). While the run goes, the indexer adds up the token counts in reply headers written since the run started; when the total passes the budget, the UI stops the job with status `over-budget`. The cache keeps what's done, so raising the budget and resuming loses nothing; spend is added up across attempts.

**Progress, cancel, resume**

- Progress shows trials answered out of trials queued, alerts finished out of alerts selected, and the money spent. It's computed by counting `.tryKK.reply` files against the `.runNN.query` files. The progress bar is an estimate of the work done (`runs.alert_progress()`, averaged over the alerts): each phase's weight times the fraction of its trials answered, with weights (`runs.WEIGHT_*`) 3 for the original trials, 2 in all for the definition rounds (front-loaded, since most alerts need few), 1 for LRE (when on), and 4 for the final answer. Phases known to be skipped count as done: the remaining definition rounds once an LRE or "explain uncertain" query exists, and LRE once an "explain uncertain" query exists, which counts as half the final answer. Alerts finished alone made the bar sit near zero for most of a run and then jump. Alerts that get no prompt (LASAA can't find the enclosing function; the pipeline skips them) are left out of the bar and the counts, and named on the page: "Prepare the run" records the ones the estimate's dry run found (`selection.no_prompt`), and when the job ends, the alerts with no output files at all (the pipeline writes every first-round query before it calls the LLM) replace that list. They don't fail the run; any other alert without a final answer does. The page polls for it every 2 seconds (htmx), rather than using server-sent events; every second when the model's base URL is local (`models.is_local_url()`), as for the mock LLM, which answers in a few seconds.
- Cancel sends SIGTERM to the job's process group, which includes the LLM client.
- Resume reruns the same command. A server restart marks running jobs as interrupted and offers resume.

**Per-alert reruns** (rerunning one alert from its page with more trials or another model) are no longer planned. To rerun an alert, check it in the list and use "Run LASAA on the checked alerts…".

**Provider settings.** The client (`ask_gpt.py` or `ask_claude_aws.py`), model, effort, and endpoint are chosen per config, in the run form's Model panel (see **Models** under Architecture). The ready-made models are gpt-6-luna and gpt-6-sol (OpenAI), Claude Haiku 5.5, Sonnet 5.5, and Opus 5.5 (AWS Bedrock), and gpt-oss-120b (Fireworks); any other model can be named, including one at an endpoint URL. Keys come from the server's environment (a key file is deferred; see Security).

## Review store

Reviews are append-only rows in SQLite: the current review of an alert is its latest row (unless that row is a `clear`), and every earlier verdict and note stays in the history. There is no undo and no editing in place: a change is a new row, so nothing a reviewer typed is ever lost.

```sql
CREATE TABLE review (
  review_id     INTEGER PRIMARY KEY,
  analysis_id   TEXT NOT NULL,
  alert_id      TEXT NOT NULL,
  verdict       TEXT NOT NULL,   -- true | false | dependent | uncertain ('' for clear)
  action        TEXT NOT NULL,   -- confirm | override | note-only | clear
  note          TEXT,            -- markdown
  dep_on_line   TEXT,            -- for dependent: file:line it depends on
  shown_run_id  TEXT,            -- run result on screen when the review was made
  blind         INTEGER NOT NULL DEFAULT 0,  -- LLM verdict hidden at review time
  reviewer      TEXT NOT NULL,   -- unused for now (single user): ''
  created_at    TEXT NOT NULL
);
CREATE INDEX review_alert ON review(analysis_id, alert_id, review_id);
```

- **Confirm** records the LLM's verdict as the manual one in a single keystroke. **Override** records a different verdict, with an optional note. The action is worked out by comparing the chosen verdict with the LLM's.
- **Changing a review.** A different verdict adds a `confirm` or `override` row; the note field starts with the current note, so it carries over. Changing only the note or the dependency line adds a `note-only` row that keeps the verdict, its `blind` flag, and its `shown_run_id`, so a blind review stays blind. **Clear** adds a `clear` row and makes the alert unreviewed again. To fix a mistaken keystroke, go back with `k` and pick the right verdict or clear it.
- `shown_run_id` records which LLM answer the reviewer was looking at, so agreement statistics can account for it.
- **Blind mode** hides the LLM verdict and explanation until the reviewer commits a verdict, then reveals them. It is off and hidden by default, since it confuses a demo; `--blind-mode` adds its toggle to the page header. It also blinds the alert list: no verdict, trial, or token columns, no verdict filter or counts, no collapsed `false` row, and file-and-line order. A review is blind if blind mode was on and the alert had never been reviewed. Blind reviews give unbiased agreement data (useful for evaluating models); normal reviews are faster for triage.
- There are no reviewer names: the UI is single-user. The `reviewer` column is kept, empty, in case that changes.
- Reviews are never written into `.final_answer`, `adjudications.json`, or `alerts.json`. They leave the database only through export.
- The database is backed up to `ui.sqlite.bak` (SQLite online backup) once a day and before any schema migration.

## Screens and interaction

Most time is spent on two screens: the alert list and the alert detail. Both are built for keyboard triage of hundreds of alerts.

**Alert list**

- Columns: alert ID (its first 8 characters, linked to the alert), verdict (`dep` for `dependent`, to save width), trial split ("7/10", or the count of each verdict when no trial gave the final one), review status, rule (with line-break opportunities between CamelCase words and after `_ . / : -`, so a long rule name wraps in a narrow window), CWE, severity, file:line (which wraps after each `/`), message, and cost.
- Above the table: "Run LASAA on all N alerts…" (or "on the N matching alerts…" when filtered) and "Run LASAA on the N checked alerts…" buttons, and the export links.
- Default order: `uncertain`, `true`, `dependent`, not adjudicated, and `false` last. Reviewing an alert doesn't move it, so `k` after a save goes back to it; the "Review: unreviewed" filter shows what is left. `false` alerts are shown by default, since the UI is mainly for demos and a demo should show both kinds. A "Hide the N unreviewed alerts adjudicated false" link collapses them into one row with their count ("412 unreviewed alerts adjudicated false are hidden. Show them"); they are never filtered out without notice.
- Filters are the same as for run selection, and a filter can be turned into a run selection or a sample with one click.
- Grouping by rule, CWE, file, or verdict, with counts per group (not built yet). An analysis that ran both cppcheck and CSA lists their alerts together, with a Tool column and filter, but the UI doesn't try to match alerts across tools (CSA reports no CWEs).
- Bulk actions: run LASAA on the checked alerts (`x`); the exports follow the filter. (Adding the same note to many alerts isn't built.)

**Alert detail**

- **Code pane.** The enclosing function (from `func_bounds.json`) with syntax highlighting and the flagged line marked. "Expand" shows the whole file. Each trace or `CodeFlow` step is a numbered marker in the gutter; steps in other files open as stacked panes in trace order.
- **LASAA pane.** The verdict, then the trial breakdown, then the winning explanation rendered as markdown. Below that, collapsed sections: the uncertain explanation, the LRE reply, each trial's reply, the definitions supplied by `need_defs`, and the exact prompt. Each run result for the alert has a tab, newest first.
- **Review pane.** Confirm, override (with verdict choice), a note, clear, and the review history. (A "depends on" field for `dependent` was dropped from the form; the `dep_on_line` column stays for old reviews and the export.) After a save, the next page says which alert was saved, with a link back to it.
- **Ask an LLM.** A question about the alert, the code, or LASAA's answer, for a ready-made model or a saved config (never the flex tier), with follow-up questions. The first question is sent with the final non-LRE prompt of the run result on screen (the original prompt plus any `need_defs` definitions) and LASAA's final answer, in `### BEGIN`/`### END` blocks like the LRE prompt's, with a note when the answer is an LRE reply (it may refer to responses not shown) or an explanation of a disagreement, and a note that definitions can't be requested. Follow-ups resend the conversation in the clients' `--multi-turn` format (`multi_turn.py`); no reasoning state is carried over. Conversations are kept per alert, listed with their model and run, and can be deleted. Hidden while blind mode hides LASAA's answer, and for an alert with no final answer and no conversation.
- **Open in editor.** Hidden for now (`SHOW_EDITOR_LINKS = False` in `app.py`; the code is kept). A `vscode://file/...` link (`--editor-url` sets another URL template) to the same file and line. `--editor-path-map FROM=TO` covers the server running in Docker while the editor runs on the host.

**Keyboard**

| Key | Action |
| --- | --- |
| `j` / `k` | Next / previous alert |
| `c` | Confirm the LLM verdict and go to the next alert |
| `t`, `f`, `d`, `u` | Choose true, false, dependent, or uncertain, and go to the note |
| `Ctrl+Enter` | Save the review and go to the next alert |
| `n` | Focus the note |
| `a` | Focus the "Ask an LLM" question (`Ctrl+Enter` sends it) |
| `[` / `]` | Previous / next trace step |
| `e` | Open in editor (only while the links are shown) |
| `b` | Toggle blind mode (only with `--blind-mode`) |
| `/` | Focus the filter |
| `Esc` | Leave a text field; close the key help |
| `?` | Show all keys |

**Other screens**

- **Home:** a list of projects (each links to its project page), recent jobs, and the new-snapshot form.
- **Snapshot:** analyses, runs, and their costs, with buttons to analyze and to start a run.
- **Jobs:** live logs, cancel, resume.
- **Legal:** the copyright and license notice (`/legal`, linked from every page's header). Its "License.txt" link shows the repository's `License.txt` (`/legal/license`), read when the page is asked for.
- **Settings:** not built as a screen. The editor link and path mapping are server options (`--editor-url`, `--editor-path-map`), the ready-made models and prices are `models.py` and `model_prices.csv`, and the run form shows whether each provider's API key is set. Blind mode, when `--blind-mode` is given, is a toggle in the page header (`b`).
- Dropped: a **Compare runs** screen (two runs as a verdict-by-verdict matrix) and a **Stats** screen (manual against LLM verdicts, with sample extrapolation). The exports cover these for now.

## Security

There are no accounts. The server is meant for a single-user workstation, but it can run builds (arbitrary code) and spend API money, so it must stay safe if its port is exposed by mistake, and against web pages open in the same browser. The threats are: accidental network exposure (for example, `docker run -p 8000:8000` without `127.0.0.1:` publishes the port on every interface), CSRF and DNS rebinding from a malicious site, XSS through analyzed code or LLM output, and the analyzed codebase itself. Of these, a malicious build is not defended against yet (see **Running things**).

**Access**

- Bind to 127.0.0.1 by default. Inside Docker the server must listen on 0.0.0.0, so the documented command publishes only to the host's loopback: `docker run -p 127.0.0.1:8000:8000 ...`. Binding elsewhere needs `--allow-remote` and prints a warning.
- At startup, generate a 256-bit random token and print a URL that contains it, as Jupyter does. The first request exchanges the token for a session cookie (`HttpOnly`, `SameSite=Strict`) and redirects to a URL without the token. The token is also written to a mode-0600 file in the workspace, which is itself mode 0700. The token is the only defense if the port is exposed by mistake: the `Host` check doesn't stop a client on the network, which can send `Host: localhost` itself.
- Reject any request whose `Host` header's hostname isn't `localhost`, `127.0.0.1`, or `[::1]` (`--allowed-host` adds more). This defeats DNS rebinding. The port isn't checked, since a Docker port mapping or an SSH tunnel changes the port the browser sees.

**Requests**

- Every state-changing action is a POST, never a GET.
- Every POST carries a per-session anti-CSRF token (a hidden form field, or a header for API calls), checked server-side, and its `Origin` header must match the request's `Host` header.
- No CORS headers. `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, no inline scripts, and all static assets served locally.
- `Referrer-Policy: same-origin`, not `no-referrer`: under `no-referrer`, browsers send `Origin: null` on form POSTs, which the `Origin` check would reject. Other sites still get no referrer.

**Untrusted content**

- Source code, alert messages, and LLM output are untrusted. LLM output can repeat text planted in code comments. Everything is HTML-escaped; markdown is rendered with raw HTML disabled, and only `http`, `https`, and `vscode` links are allowed.
- The file viewer resolves paths only inside the snapshot's `src/` (checked after `realpath`), and doesn't follow symlinks that point outside.

**Running things**

- Subprocesses get argument lists, never `shell=True`. The one exception is the build command, which the user typed; it runs through `sh -c` and is shown in the log.
- Building a codebase runs its build scripts, which is arbitrary code, and **builds are not sandboxed**. When the server runs as root (as in the Docker image), the build runs as a dedicated unprivileged user (`lasaa-build`, uid 65532; `setpriv --no-new-privs`) in a temporary `work/` it owns, outside the workspace. So it can't read the server's environment (`/proc/<pid>/environ`), the workspace (mode 0700: the token, `ui.sqlite`, other snapshots), or anything under `/root` (such as a mounted `~/.aws`), and can't write root's files or the read-only mounts (the README's `docker run` mounts `/host` and the project `:ro` and sets `--security-opt no-new-privileges`). When the build ends or is cancelled, `kill -KILL -1` run as that uid stops everything it started; since that would stop another build too, builds run one at a time, across projects. bear's output is read without following symlinks, and the freeze keeps only files whose real path is inside `work/`. The build still has the network, and can read every file in the container that any user may read, which includes the project and the LASAA directory, and a kernel bug could let it out. When the server doesn't run as root, a build would run as the server's user, with all of its access, so builds are refused (the form disables "Build with command", and the server and the job check again) unless the server was started with `--allow-builds-as-server-user`. So the README and the snapshot form warn to build only code whose build is trusted. Snapshots and analyses without a build only copy, read, and parse the code, so "Don't build" is the choice for untrusted code. Clang (`clang -M`, CSA) and cppcheck still run as the server's user on the build's compile commands; their flags are filtered, but an allowed flag such as `-include FILE` can make them read a file the build user couldn't.
- Future work: run `clang -M`, CSA, and cppcheck on built snapshots as the build user too; and run each build in a real sandbox (its own throwaway container, or `bwrap` once the container allows user namespaces) with only a copy of the tree, no network, and no keys, workspace, or `/host`.

**API keys**

- Read from the server's environment or a mode-0600 `secrets.toml` in the workspace. (So far only the environment; the key file is deferred.)
- Never sent to the browser. The run form shows only whether each provider's key is set.
- Redacted from logged commands and job logs.

## Export and interop

Every export works on the current filter or selection and the run on screen. (Recording which reviews and run results each export included is deferred.)

| Export | Contents | How |
| --- | --- | --- |
| Adjudications JSON | One entry per alert with a verdict: `{Alert_ID, verdict, adjudicator_type, CWEs, explanation}`. `adjudicator_type` is `"manual"` when a reviewer set the verdict, otherwise `"LLM"`. For a manual verdict, `explanation` is the reviewer's note (for a confirm without a note, the LLM's explanation), and the entry adds `llm_verdict`, `llm_explanation`, and `dep_on_line` if set | The `adjudications.json` format plus those fields, so `sarif_to_lasaa.py -u` can read it and SARIF consumers that read only `explanation` see the reviewer's reasoning |
| Updated SARIF | The merged Clang SARIF with `verdict`, `adjudicator_type`, and `explanation` (the note, for a manual verdict), plus `llm_verdict`, `llm_explanation`, and `dep_on_line` for reviewed alerts, in `result.properties.lasaa`. `SRCROOT` is set to the directory the snapshot was made from | `conv/sarif_to_lasaa.py -u` with the file above, extended to copy the new fields; suppressions only where the user chooses: none, manual `false` (`--sup-fp --sup-fp-manual`), or LLM `false` too (`--sup-fp`) |
| CSV | One row per alert: location, rule, verdict, `adjudicator_type`, LLM verdict, trial split, review action, blind flag, note, full LLM explanation. Cells that start with `=`, `+`, `-`, or `@` get a leading `'`, so a spreadsheet doesn't run alert or LLM text as a formula | New; unlike `conv_adjud_json_to_csv.py`, it doesn't truncate explanations |
| HTML report | One self-contained file: summary counts, then each alert with code, verdicts, explanation, and note | Same templates as the UI, assets inlined, no scripts needed |

Verdicts are never written into an alerts file. `adjudicate_alerts.py` reads a `verdict` or `Verdict` field in an alerts file as a ground-truth label, which would turn on benchmark behavior. Reviewed alerts are kept out of new LASAA runs by the UI's selection instead.

The SARIF export applies to analyses that ran CSA, and has only the CSA alerts (cppcheck 2.7 doesn't write SARIF); cppcheck-only and imported analyses get the others. The changes to `sarif_to_lasaa.py` (the `-u` extension, `--sup-fp-manual`, `--no-default-level`, and percent-decoding URIs, so that `a%20b.c` is the file `a b.c`) are the only changes this design makes to existing production code. Without `--no-default-level`, only the decoding can change a prompt, and only for a path with a `%` escape, which didn't name a real file before.

## Technology choices

Python with server-rendered pages and no JavaScript build step: it matches the rest of LASAA, runs in the existing Docker image, and works with no internet access apart from the LLM endpoint.

| Part | Choice | Why |
| --- | --- | --- |
| Server | FastAPI on uvicorn | Async subprocesses for jobs; small. Live progress is polled with htmx |
| Pages | Jinja2 templates + htmx (vendored file) | Partial page updates without a single-page app or Node toolchain |
| Keyboard, panes | About 300 lines of plain JavaScript | Shortcuts and trace navigation only |
| Highlighting | Pygments, server-side | No client library; same output in the HTML report |
| Markdown | markdown-it-py with HTML disabled | Safe rendering of LLM explanations |
| Storage | SQLite (standard library), WAL mode | One file, no server, easy backup |
| Tests | `unittest`, plus a fixture output directory | Matches the existing tests; covers indexer, host check, CSRF, path checks |

The code goes in `code/lasaa_webui/`, started with `./lasaa_webui_serve.py --workspace DIR [--port N]`. The new Python packages go into `Dockerfile.web-ui`, which builds on the demo image (with cppcheck and Clang), so the main `Dockerfile` stays minimal. A single-page app (React or similar) was considered and rejected: it adds a build toolchain and more code, and the screens here are mostly documents with a few controls.
