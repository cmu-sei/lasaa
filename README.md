# LASAA (LLMs for Adjudication of Static Analysis Alerts)

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

## Description of LASAA

LASAA uses a large language model (LLM) to *adjudicate* static-analysis alerts
(i.e., to decide whether an alert indicates a real flaw).  It also reports a
justification along with every verdict.

LASAA is analyzer-agnostic: it ingests alerts in a small common format, and the
`code/conv` directory provides converters from SARIF and a few other formats to
the LASAA input format, as well as a template for prompting a frontier LLM to
create a converter for other formats.

For each alert, LASAA builds a query containing the alert's fields
(file, line, CWE, message), the source code of the function that contains the
flagged line (located by running `ctags` over the project), and instructions
telling the LLM to classify the alert as `true`, `false`, `dependent`, or
`uncertain`.  A verdict of `dependent` means that the alert would be fixed as a
side effect of fixing an earlier line with the same flaw type; pointing a
developer at the line that actually needs repair is generally more useful than
flagging every downstream symptom.  If the LLM needs the definition of a struct
or macro that isn't in the supplied function, it can ask for it, and LASAA
looks the symbol up (again via `ctags`), appends the definition to the prompt,
and re-issues the query.

LASAA implements two independently selectable mechanisms for mitigating LLM
mistakes (both enabled by default):

* **Consistency check (CC):** run the query N times (default 10) and return the
  verdict only if it was reached on at least a threshold percentage of the
  trials (default 80%); otherwise return `uncertain`.  Raising the threshold
  generally reduces the number of wrong verdicts at the expense of more
  `uncertain` verdicts.  A plain majority-vote baseline is also available as an
  alternative to CC.
* **LLM reasoning evaluation (LRE):** when the trials disagree, present the
  original query and the discordant responses back to the LLM and ask it to
  weigh the competing reasoning and then write its own answer.  Unlike a
  majority vote, this lets a well-reasoned minority position win.  LRE and CC
  can be combined: the LRE prompt itself is run N times and a consistency check
  is applied to its verdicts.

Queries and replies are stored on disk (in the specified output directory), so
re-running with different options reuses the earlier LLM calls when possible.
This also enables a run of LASAA to be stopped and later resumed by simply
rerunning the original command.

We evaluated LASAA on three benchmark test suites (Juliet, FormAI, and SV-COMP)
with several LLMs.  With mistake mitigation enabled, the mid-tier reasoning
models we tested (o4-mini, gpt-oss-120b, gpt-oss-20b) reached at least 98%
recall (the percentage of real bugs correctly flagged as needing attention) and
at least 94.8% specificity (the percentage of false alerts correctly dismissed)
on every suite.
The `code/eval_bench` directory contains the prompts that we used for
the three benchmark suites.

For more information, see our paper: <https://arxiv.org/pdf/2607.09979>.


## Building and running the Docker container

See the comments in `Dockerfile` for information on how to build and run the
LASAA Docker container.
If a proxy sits between your machine and the LLM provider, you may need to add
the proxy's TLS certificate to the `proxy_cert` directory before building the
Docker container; otherwise the proxy might be recognized as a MITM attack.

Briefly, to build and run:

    docker build -f Dockerfile -t lasaa . # Don't forget the period.
    docker run -it --rm -v ${PWD}:/host -w /host lasaa bash

## Testing the connection to the LLM endpoint

The `ask_gpt.py` script makes a query to an LLM and records the answer.
Before running LASAA, we suggest running a simple example with this script, to
test connectivity to the LLM.

Example (from inside the Docker container built and started as described
above), using the commercial OpenAI endpoint (see the next section for using a
different endpoint):

    root@9c7f3fbed57d:/host# cd /host/code

    root@9c7f3fbed57d:/host/code#  export OPENAI_API_KEY=... # your OpenAI key
    
    root@9c7f3fbed57d:/host/code# cat example.query
    What is the capital of France?

    root@9c7f3fbed57d:/host/code# ./ask_gpt.py example.query
    Importing openai... Done.
    Wrote reply to 'example.reply'.

    root@9c7f3fbed57d:/host/code# cat example.reply
    # Model: o4-mini-2025-04-16, reasoning_tokens: 64, output tokens: 129

    The capital of France is Paris.

## Choosing an LLM endpoint

By default, `ask_gpt.py` uses the commercial OpenAI API endpoint, and it
expects your OpenAI API key to be stored in the environment variable
`OPENAI_API_KEY`.  You can specify a different provider (and a different
environment variable for the API key) with the following command-line
arguments:

    --base-url
    --api-key-name
    --api-type {chat_completion,response}

The following command-line arguments might also be useful:

    --help / -h
    --list-models
    --model
    --reasoning-effort
    --concurrency

## Adjudicating alerts

The core functionality of the `adjudicate_alerts.py` script is to create
`.query` files.  After producing a batch of `.query` files,
`adjudicate_alerts.py` calls `ask_gpt.py`, which reads these `.query` files,
sends the queries to the LLM, and records the LLM's responses in corresponding
`.reply` files.  This process iterates until a final answer is reached or the
maximum number of attempts is reached.  (To just produce `.query` files without
running the LLM, use the command-line option `--dont-run-llm`.)

The final adjudications are recorded in a file named "adjudications.json" in
the output directory (specified by the "-o" option).
There is also a `.final_answer` file for each alert.

When running `adjudicate_alerts.py`, any options that appear after ` -- ` are
passed to `ask_gpt.py`.  For example:

`./adjudicate_alerts.py ... -- --base-url https://... --api-key-name FOO_API_KEY --api-type chat_completion --model gpt-oss-120b`

## Demo

From inside the LASAA Docker container:

    cd /host/code
    flawfinder --csv demo.c > demo_ff.csv
    ./conv/flawfinder_csv_to_lasaa.py demo_ff.csv -o demo_alerts.json
     export OPENAI_API_KEY=... # your OpenAI key
    rm -f out_demo/*
    ./adjudicate_alerts.py --alerts demo_alerts.json -o out_demo -b . -s demo.c --cc 0 --lre 0
    less out_demo/adjudications.json

(The leading space in front of `export OPENAI_API_KEY=...` prevents it from being stored in the Bash history.)

## Mistake-mitigation options

For the consistency check (CC) step and the LLM reasoning evaluation (LRE)
step, the number of trials (i.e., the number of times to send the query to the
LLM) is specified by the `-n` option.
For CC, the threshold is specified by `-t`.  It can be specified either as a
percentage (like `-t 80%` or `-t 0.80`) or as a count (like `-t 8/n`).
For example, `-t 3/n -n 4` indicates that 4 trials are to be performed, and at
least 3 of the 4 trials must agree on a verdict to pass the consistency check.

CC can be turned off by `--cc 0`, and LRE can be turned off by `--lre 0`.

## Additional demos

Multiple rounds of macro/struct lookup:

`./adjudicate_alerts.py -a demo_def_lookup.alerts.json -o out_demo_defs -b . -s demo_def_lookup.c -t 2/n -n 3 --lre 0`

Alert with data flow that spans multiple files:

`./adjudicate_alerts.py -a flow_example/flow_example.alerts.json -o out_flow_example -b flow_example/ -t 3/n -n 4 --lre 0`

## Rerunning with different options

Suppose you just ran the following:

    ./adjudicate_alerts.py --alerts alerts.json -o out -b example_src --cc 1 --lre 0 -n 5

Now suppose you want to try it again with different options, e.g., `--lre 1 -n 10`.
You can re-use the intermediate results by re-using the output directory:

    ./adjudicate_alerts.py --alerts alerts.json -o out -b example_src --cc 1 --lre 1 -n 10

In the header line of each `.final_answer` file, LASAA records the options used.
LASAA automatically deletes the `.final_answer` files when running with
different options.  The `.final_answer` files are cheap to regenerate if all
the `.reply` files already exist.

## Updating SARIF files

To convert from SARIF to LASAA's input format:

    /host/code/conv/sarif_to_lasaa.py orig.sarif [-b BASE_DIR] -o alerts_for_lasaa.json

After running LASAA, you can produce an updated SARIF file with LASAA's
verdicts and explanations as follows:

    /host/code/conv/sarif_to_lasaa.py orig.sarif [-b BASE_DIR] -u adjudications.json -o updated.sarif

The LASAA distribution includes a pair of files to demonstrate this capability:

    cd /host/code/conv
    ./sarif_to_lasaa.py example_alerts.sarif -u example_adjudications.json -o updated_alerts.sarif

Note that the LASAA `Alert_ID` for SARIF files is a truncated SHA-256 hash of a
representation of the alert; adjudications are matched to alerts in the SARIF
file by recomputing the hash and finding a matching `Alert_ID` in the
adjudications file.  As a consequence of this, if a base directory is specified
with `-b` when converting from SARIF to LASAA's input format, the same base
directory must be specified when updating the SARIF file.
