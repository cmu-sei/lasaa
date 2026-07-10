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

## Building and running the Docker container

See the comments in `Dockerfile` for information on how to build and run the
LASAA Docker container.
If a proxy sits between your machine and the LLM provider, you may need to add
the proxy's TLS certificate to the `proxy_cert` directory before building the
Docker container; otherwise the proxy might be recognized as a MITM attack.

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
".query" files.  After producing a batch of ".query" files,
`adjudicate_alerts.py` calls `ask_gpt.py`, which reads these ".query" files,
sends the queries to the LLM, and records the LLM's responses in corresponding
".reply" files.  This process iterates until a final answer is reached or the
maximum number of attempts is reached.

The final adjudications are recorded in a file named "adjudications.json" in
the output directory (specified by the "-o" option).

When running `adjudicate_alerts.py`, any options that appear after ` -- ` are
passed to `ask_gpt.py`.  For example:

`./adjudicate_alerts.py ... -- --base-url https://... --api-key-name FOO_API_KEY --api-type chat_completion --model gpt-oss-120b`

## Demo

From inside the LASAA Docker container:

    cd /host/code
    flawfinder --csv demo.c > demo_ff.csv
    ./conv/flawfinder_csv_to_lasaa.py demo_ff.csv -o demo_alerts.json
     export OPENAI_API_KEY=... # your OpenAI key
    rm -f demo_out/*   
    ./adjudicate_alerts.py --alerts demo_alerts.json -o demo_out -b . -s demo.c --consistency-check 0 --lre 0 --run-llm
    less demo_out/adjudications.json

## Rerunning with different options

Suppose you just ran the following:

    ./adjudicate_alerts.py --alerts alerts.json -o out -b example_src --consistency-check 1 --lre 0 --num-trials 5 --run-llm

Now suppose you want to try it again with different options, e.g., `--lre 1 --num-trials 10`.  You can re-use the intermediate results by re-using the output directory:

    ./adjudicate_alerts.py --alerts alerts.json -o out -b example_src --consistency-check 1 --lre 1 --num-trials 10 --run-llm

In the header line of each `.final_answer` file, LASAA records the options used.  LASAA automatically deletes the `.final_answer` files when running with different options.  The `.final_answer` files are cheap to regenerate if all the `.reply` files already exist.

## Updating SARIF files

To convert from SARIF to LASAA's input format:

    /host/code/conv/sarif_to_lasaa.py orig.sarif [-b BASE_DIR] -o alerts_for_lasaa.json

After running LASAA, you can produce an updated SARIF file with LASAA's verdicts and explanations as follows:

    /host/code/conv/sarif_to_lasaa.py orig.sarif [-b BASE_DIR] -u adjudications.json -o updated.sarif

The LASAA distribution includes a pair of files to demonstrate this capability:

    cd /host/code/conv
    ./sarif_to_lasaa.py example_alerts.sarif -u example_adjudications.json -o updated_alerts.sarif

Note that the LASAA `Alert_ID` for SARIF files is a truncated SHA-256 hash of a representation of the alert; adjudications are matched to alerts in the SARIF file by recomputing the hash and finding a matching `Alert_ID` in the adjudications file.  As a consequence of this, if a base directory is specified with `-b` when converting from SARIF to LASAA's input format, the same base directory must be specified when updating the SARIF file.
