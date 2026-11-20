# LASAA demo on tinykv

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

## Alerts for tinykv

tinykv (about 10k lines of C) has a mix of deliberate defects and code that
static analyzers misjudge. Running Clang Static Analyzer and Cppcheck on it
gives 33 alerts:

| Ground truth | Count |
| ---          | ---   |
| `true`       | 20    |
| `dependent`  | 1     |
| `false`      | 12    |

`ground_truth.json` has the verdict and a one-line justification for each alert.

## Steps

Use the `lasaa-demo` Docker image, which adds Clang (with `scan-build`) and
Cppcheck to the base LASAA image. Build it after building the base image:

```bash
docker build -f Dockerfile.demo -t lasaa-demo .
docker run -it --rm -v ${PWD}:/host -w /host lasaa-demo bash
```

Then, from inside the Docker container:

```bash
# 1. Run the analyzers and convert their output (writes lasaa_demo/out/).
cd /host/examples/tinykv
lasaa_demo/run_analyzers.sh

# 2. Adjudicate.
export LASAA_FIELDS_FOR_LLM="File,Line,Column,Tool,RuleID,Message,CWEs,CodeFlow"
 export OPENAI_API_KEY=...
../../code/adjudicate_alerts.py -a lasaa_demo/out/alerts.json \
    -o lasaa_demo/lasaa_out -b "$PWD"

# 3. Score against the ground truth.
lasaa_demo/score.py lasaa_demo/lasaa_out/adjudications.json

# 4. Optional: write the verdicts back into the Clang SARIF file.
../../code/conv/sarif_to_lasaa.py lasaa_demo/out/clang.sarif -b "$PWD" \
    -u lasaa_demo/lasaa_out/adjudications.json -o lasaa_demo/out/clang.updated.sarif
```

To see the prompts without calling an LLM, add `--dont-run-llm` in step 2.

## What the pipeline does

- **`run_analyzers.sh`** runs both analyzers and builds the combined alert
  file:
  - Clang runs through `scan-build -sarif`, with the `alpha.unix.Stream`
    checker on and dead-store checks off.
  - Cppcheck runs with `--enable=warning,portability --inconclusive`.
  - Both outputs go through the LASAA converters in `../../code/conv/`.
- **`merge_sarif.py`** joins scan-build's per-file SARIF output into one run.
- **`combine_alerts.py`** gives every alert the same fields. It also fills in
  CWE IDs for Clang alerts, which Clang's SARIF lacks.

## Alerts worth showing

- **A real flaw:**
  - **Use after free**, `store.c:286`. The eviction callback uses `victim`
    after it has been freed.
  - **NULL to `strcasecmp`**, `commands.c:281`. A bare `INFO` command crashes
    the server.
- **A plain false positive:** `net.c:208`. Clang doesn't model `accept()`
  writing to the address buffer.
- **False positives that need a definition looked up (`need_defs`):**
  - `store.c:280` needs `ht_random_entry`.
  - `commands.c:567` needs `set_opts_has_expiry`.

  Each of these is false only because of a function defined in another file.
- **Dependent:** `commands.c:866` goes away once `commands.c:865` is fixed.
- **False positives on infeasible paths:**
  - `server.c:127` and `server.c:673` depend on an invariant about the
    client array.
  - `persist.c:646` depends on `validate_list()` having already checked the
    data.
- **Same flaw, two tools:** `hashtable.c:109` and `server.c:285` are each
  reported by both Clang and Cppcheck.

## Notes

- **Line numbers and Alert_IDs** in `ground_truth.json` match clang 14 and
  Cppcheck 2.7 (Ubuntu 22.04) on the code as committed. Other versions, or
  edits to the code, will change them.
- **The deliberate defects are not marked in the sources.** Their comments
  read like ordinary code, so the LLM isn't given hints.
