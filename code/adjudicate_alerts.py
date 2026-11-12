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
adjudicate_alerts.py - Adjudicate static-analysis alerts via an LLM pipeline.

This builds the original LLM prompt for each alert, and then drives the
pipeline (controlled by --consistency-check and --llm-resolve) to produce a
final answer.

LASAA has two mistake-mitigation methods:
(1) Consistency Check (CC): run the query multiple times and return "uncertain"
unless a consistency threshold is met.
(2) LLM Reasoning Evaluation (LRE): ask the LLM to resolve discordant runs by
evaluating the reasoning provided in the runs.  A consistency check can be
applied to the LRE prompt: LASAA runs the LRE prompt $N$ times and returns
"uncertain" unless the results are consistent on a given percentage of runs.

Turning off the consistency check is equivalent to running a single trial, so
it is handled by setting the relevant trial count to 1 rather than by a
separate code path.  The pipeline therefore has just two shapes:
  - LRE off: run the original prompt over phase 1 and take the (possibly
    single-trial) consistency-check majority.
  - LRE on: run the original prompt over phase 1, and if the runs are not
    unanimous, run the LRE resolve prompt over phase 2 and take the (possibly
    single-trial) consistency-check majority.

The core functionality of this script is to create ".query" files.  It calls
a separate script (ask_gpt.py) that sends the contents of ".query" files to
an LLM and records the LLM's response in corresponding ".reply" files.
To avoid actually running the LLM, use the "--dont-run-llm" option.

A query file with a name ending like ".run{N}.query" will be run N times by
ask_gpt.py.

Query / reply file naming:
  basename.HASH.query       -- ask_gpt runs once
                               reply:  basename.HASH.reply
  basename.HASH.runNN.query -- ask_gpt runs NN times
                               replies: basename.HASH.try00.reply
                                        ...
                                        basename.HASH.try{NN-1}.reply
"""

import sys
import os
import argparse
import glob
import hashlib
import math
import shutil
import re
import time
import pdb
import json
import gzip
import shlex
import subprocess
import textwrap
import csv
import importlib.util
from pathlib import Path
from collections import Counter

from get_enclosing_func import (get_enclosing_func,
                                get_enclosing_func_range,
                                get_enclosing_decl,
                                get_enclosing_decl_range,
                                load_func_bounds_etc,
                                cached_realpath)
from add_line_nums import add_line_nums, split_lines
from parse_verdict import get_verdict_of_reply_file
import repo_cache

stop = pdb.set_trace
stderr = sys.stderr
stdout = sys.stdout


class Glo():
    cert_rule_id_to_title = None
    pass
glo = Glo()
glo.files_used = set()
glo.run_query_index = {}      # see run_queries_in()
glo.tokenize_warned = False
glo.already_warned = set()


if os.getenv("LASAA_USE_REPR", "0") == "1":
    glo.to_str = repr
else:
    glo.to_str = lambda x: json.dumps(x, separators=(', ', ': '))


# ===================================================================
# Prompt template
# ===================================================================

prompt_intro_with_dep = (
"""
I want you to adjudicate whether the following static-analysis alert is a true positive, a false positive, or dependent.  If the indicated flaw (as indicated by, e.g., the CWE number) isn't present in the code, mark the alert as a false positive even if some other flaw is present.  Do not make assumptions about what situations (involving the environment external to the program) are plausible or not, and particularly do not make any assumptions about input to the program.  However, you may assume that system/library functions behave in accordance with their documentation, you may make reasonable assumptions about function arguments (e.g., if a function takes arguments `buf` and `buflen`, it may be reasonable to assume that `buf` points to a buffer of size `buflen`), etc.  For library functions that try to allocate memory, don't forget that allocation might fail due to lack of memory.

The term "dependent alert" refers to an alert that would be eliminated by fixing an earlier line of code that itself has a flaw that a static-analysis tool should flag.  More specifically:

1. If an alert flags a code flaw, but the flagged misbehavior can occur only if there is an earlier-executed line with the same type of code flaw (on the same data), and fixing the earlier bug would eliminate the flagged alert, then the alert should be marked as dependent, not a true positive or false positive.  For example, in `struct Foo *x = malloc(sizeof(struct Foo)); x->field1 = 1; x->field2 = 2;`, the assignment to `x->field2` has a flaw (because `x` isn't checked for being NULL), but this null-pointer dereference would have already been tripped in the assignment to `x->field1`, so the assignment to `x->field2` should be marked as dependent, and the assignment to `x->field1` should be marked as a true positive.  For dependent alerts, cite the line with the earlier code flaw, briefly indicate how it should be fixed, and argue that the alert becomes a false positive in the fixed code.  Do not mark an alert as dependent simply because of missing error-checking; an alert should be marked dependent only if there is an earlier line that triggers the same kind of error as the current flagged line triggers.

2. When an alert flags a line that, in isolation, is perfectly correct and only misbehaves because of earlier undefined behavior (UB) elsewhere, treat that alert as a false positive, not as dependent or as a true positive.  For example, if the program corrupts the heap and then calls `malloc`, the call to `malloc` shouldn't be flagged, since it can cause a vulnerability only because of the earlier UB.  The earlier heap corruption should be flagged, not the subsequent call to `malloc`.  Likewise, if `p = library_call(q)` might cause UB because `q` might be invalid, don't mark a line that uses `p` as a true positive merely because the definition of `p` (i.e., `p = library_call(q)`) possibly involves UB; the definition of `p` should be flagged, not the use of `p`.

When adjudicating an alert, ignore unrelated or tenuously related UB when deciding whether the flagged alert is true, false, or dependent.  Incidental UB that merely occurs on the way to setting up the flagged condition should not affect your verdict.

If the alert is a true positive, give a trace demonstrating the vulnerability and say {"verdict": "true"} at the end of your response.
If the alert is a false positive, give a proof sketch arguing why it is a false positive and say {"verdict": "false"} at the end of your response.
If the alert is a dependent alert, give the line number on which it depends and say {"verdict": "dependent"} at the end of your response.
If you are uncertain, explain and say {"verdict": "uncertain"} at the end of your response.
If you need the definitions of structs, macros, or other entities, then say {"need_defs": [...]} on the line before you say {"verdict": "uncertain"}.  Each item in the `need_defs` list should be an identifier (and therefore should not contain any spaces; e.g., do not use "struct foo" but instead just "foo"); we will look it up using `ctags`.  If there are multiple definitions of a given symbol, we will provide all definitions.
""").lstrip()

#=====================================================================
prompt_intro_without_dep = (
"""
I want you to adjudicate whether the following static-analysis alert is a true positive or a false positive.  If the indicated flaw (as indicated by, e.g., the CWE number) isn't present in the code, mark the alert as a false positive even if some other flaw is present.  Do not make assumptions about what situations (involving the environment external to the program) are plausible or not, and particularly do not make any assumptions about input to the program.  However, you may assume that system/library functions behave in accordance with their documentation, you may make reasonable assumptions about function arguments (e.g., if a function takes arguments `buf` and `buflen`, it may be reasonable to assume that `buf` points to a buffer of size `buflen`), etc.  For library functions that try to allocate memory, don't forget that allocation might fail due to lack of memory.

The term "dependent alert" refers to an alert that would be eliminated by fixing an earlier line of code that itself has a flaw that a static-analysis tool should flag.  More specifically:

1. If an alert flags a code flaw, but the flagged misbehavior can occur only if there is an earlier-executed line with the same type of code flaw (on the same data), and fixing the earlier bug would eliminate the flagged alert, then the alert is considered to be dependent.  For example, in `struct Foo *x = malloc(sizeof(struct Foo)); x->field1 = 1; x->field2 = 2;`, the assignment to `x->field2` has a flaw (because `x` isn't checked for being NULL), but this null-pointer dereference would have already been tripped in the assignment to `x->field1`, so the assignment to `x->field2` is dependent, but the assignment to `x->field1` is not dependent.  An alert is dependent only if there is an earlier line that triggers the same kind of error as the current flagged line triggers.

2. When an alert flags a line that, in isolation, is perfectly correct and only misbehaves because of earlier undefined behavior (UB) elsewhere, treat that alert as a false positive, not dependent.  For example, if the program corrupts the heap and then calls `malloc`, the call to `malloc` shouldn't be flagged, since it can cause a vulnerability only because of the earlier UB.  The earlier heap corruption should be flagged, not the subsequent call to `malloc`.  Likewise, if `p = library_call(q)` might cause UB because `q` might be invalid, don't mark a line that uses `p` as a true positive merely because the definition of `p` (i.e., `p = library_call(q)`) possibly involves UB; the definition of `p` should be flagged, not the use of `p`.

When adjudicating an alert, disregard unrelated or tenuously related UB.  Incidental UB that merely occurs on the way to setting up the flagged condition should not affect your verdict.

For this task, treat dependent alerts as true positives.

If the alert is a true positive, give a trace demonstrating the vulnerability and say {"verdict": "true"} at the end of your response.
If the alert is a false positive, give a proof sketch arguing why it is a false positive and say {"verdict": "false"} at the end of your response.
If you are uncertain, explain and say {"verdict": "uncertain"} at the end of your response.
If you need the definitions of structs, macros, or other entities, then say {"need_defs": [...]} on the line before you say {"verdict": "uncertain"}.  Each item in the `need_defs` list should be an identifier (and therefore should not contain any spaces; e.g., do not use "struct foo" but instead just "foo"); we will look it up using `ctags`.  If there are multiple definitions of a given symbol, we will provide all definitions.
""").lstrip()

#=====================================================================
prompt_intro = (prompt_intro_without_dep if ("--dep-as-tp" in sys.argv) else prompt_intro_with_dep)

# Alternative wording of the need_defs paragraph (--need-defs-style standalone).
# Some models (e.g., Claude Opus 5.5) rarely request definitions under the
# default wording, which ties the request to a verdict of "uncertain", and
# instead rely on their recollection of the project's source code.
need_defs_para_verdict = (
"""If you need the definitions of structs, macros, or other entities, then say {"need_defs": [...]} on the line before you say {"verdict": "uncertain"}.  Each item in the `need_defs` list should be an identifier (and therefore should not contain any spaces; e.g., do not use "struct foo" but instead just "foo"); we will look it up using `ctags`.  If there are multiple definitions of a given symbol, we will provide all definitions.
""")
need_defs_para_standalone = (
"""The code below is only part of a larger program.  If your verdict depends on the definition or behavior of a function, macro, struct, type, global variable, or constant that is not shown, do not rely on your memory of the project's source code (the version here may differ from the one you remember); instead, request the definitions.  To request definitions, end your response with a line of the form {"need_defs": ["name1", "name2"]} and do not give a verdict; we will then ask you again with the requested definitions appended.  Each item in the `need_defs` list should be an identifier (and therefore should not contain any spaces; e.g., do not use "struct foo" but instead just "foo"); we will look it up using `ctags`.  If there are multiple definitions of a given symbol, we will provide all definitions.
""")


# ===================================================================
# Utility helpers
# ===================================================================

def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)

def warn_once(msg):
    if msg in glo.already_warned:
        return
    glo.already_warned.add(msg)
    sys.stderr.write(msg + "\n")

def read_whole_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()

def load_json(filename):
    if filename.endswith(".json.gz"):
        with gzip.open(filename, "rt", encoding="utf-8") as f:
            return json.load(f)
    elif filename.endswith(".json"):
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        raise ValueError(f"Unsupported file extension: '{filename}'. Expected '.json' or '.json.gz'.")

def compute_prompt_hash(prompt, p_type):
    """First 8 hex digits of the SHA-256 hash of *prompt*."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:8] + "." + p_type


def write_file_if_needed(filepath, content):
    """Write *content* to *filepath* unless it already has that content. Also some side effects."""
    orig_filepath = filepath
    # os.path.realpath(filepath), resolving the directory only once.
    (dirname, basename) = os.path.split(filepath)
    filepath = os.path.join(cached_realpath(dirname or "."), basename)
    if os.path.islink(filepath):
        filepath = os.path.realpath(filepath)
    # Remove any ".query" files that specify a different number of runs.
    m = RUN_QUERY_RE.match(filepath)
    if m:
        (dirname, basename) = os.path.split(filepath)
        siblings = run_queries_in(dirname).setdefault(os.path.basename(m.group(1)), set())
        for sibling in list(siblings):
            if sibling != basename:
                try:
                    os.remove(os.path.join(dirname, sibling))
                except OSError:
                    pass
                siblings.discard(sibling)
    #
    glo.files_used.add(orig_filepath)
    written = True
    if os.path.isfile(filepath):
        try:
            if read_whole_file(filepath) == content:
                written = False
        except Exception:
            pass
    if written:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    if m:
        siblings.add(basename)
        run_queries_seen(dirname)
    return written


RUN_QUERY_RE = re.compile(r"^(.*)[.]run[0-9][0-9][.]query$")


def run_queries_in(dirname):
    """{prefix: set of the "<prefix>.runNN.query" file names} in *dirname*.

    Listing a large output directory for every query written made writing
    the queries quadratic, so the listing is kept, and updated by
    write_file_if_needed().  It is redone if the directory has changed
    since (its mtime), e.g. by the LLM client between rounds."""
    mtime = os.stat(dirname).st_mtime_ns
    entry = glo.run_query_index.get(dirname)
    if entry is None or entry[0] != mtime:
        index = {}
        for e in os.scandir(dirname):
            m = RUN_QUERY_RE.match(e.name)
            if m:
                index.setdefault(m.group(1), set()).add(e.name)
        entry = glo.run_query_index[dirname] = [mtime, index]
    return entry[1]


def run_queries_seen(dirname):
    """Note that run_queries_in(dirname) is up to date with our own changes."""
    entry = glo.run_query_index.get(dirname)
    if entry is not None:
        entry[0] = os.stat(dirname).st_mtime_ns


def strip_hdr_and_reasoning(s):
    """Remove <reasoning_HEX>...</reasoning_HEX> wrapper if present."""
    pattern = r"<reasoning_([0-9a-fA-F]+)>"
    match = re.search(pattern, s)
    if not match:
        # Remove header line
        if s.startswith("# Model:") and "\n" in s:
            s = s.split("\n", 1)[1].lstrip()
        return s
    hex_code = match.group(1)
    closing_tag = f"</reasoning_{hex_code}>"
    closing_pos = s.find(closing_tag)
    if closing_pos == -1:
        return s
    return s[closing_pos + len(closing_tag):].lstrip()

def get_cwes_in_alert(alert):
    for field_name in ["CWEs", "CWE(s)", "CWE"]:
        val = alert.get(field_name)
        if val is not None:
            if type(val) is str:
                return val.split(",")
            elif type(val) is list:
                return val
            else:
                return []
    return ""

def get_alert_file(alert):
    for field_name in ["File", "file"]:
        val = alert.get(field_name)
        if val is not None:
            return val
    return ""

# ===================================================================
# need_defs helpers
# ===================================================================

# Unbraced form that some LLMs (e.g., Claude Sonnet 5) write instead, possibly
# with markdown emphasis: need_defs: ["a", "b"] or **need_defs:** ["a"].
NEED_DEFS_UNBRACED_RE = re.compile(r'^[\s*`"\']*need_defs[*`"\']*\s*:[\s*]*(?=\[)')


def extract_need_defs(text):
    """Return the list from the last need_defs request line in text, or None.

    A request line contains {"need_defs": [...]} (possibly followed by more
    JSON on the same line, e.g., the verdict) or starts with need_defs: [...].
    """
    decoder = json.JSONDecoder()
    for line in reversed(text.splitlines()):
        names = None
        try:
            if '{"need_defs":' in line:
                obj = decoder.raw_decode(line, line.index('{"need_defs":'))[0]
                names = obj.get("need_defs")
            else:
                m = NEED_DEFS_UNBRACED_RE.match(line)
                if m:
                    names = decoder.raw_decode(line, m.end())[0]
        except (json.JSONDecodeError, ValueError):
            pass
        if isinstance(names, list) and names:
            return names
    return None


def collect_need_defs(reply_contents):
    """Return the union of all need_defs names across reply_contents, or None."""
    seen = set()
    all_names = []
    for content in reply_contents:
        names = extract_need_defs(content)
        if names:
            for name in names:
                if name not in seen:
                    seen.add(name)
                    all_names.append(name)
    return all_names or None


MAX_DEFS_PER_NAME = 20
_LOW_PRIORITY_KINDS = ("member", "field")
# A line holding only the head of an aggregate declaration whose "{" is on the
# next line, e.g., "typedef enum" or "typedef struct foo".  ctags starts an
# anonymous aggregate's range at the "{" line, so we back up over such a line.
_DECL_HEAD_RE = re.compile(r'^\s*(typedef|(typedef\s+)?(struct|union|enum|class)(\s+\w+)?)'
                           r'\s*(/[/*].*)?$')


def choose_def_entries(entries, base_dir, hint_file):
    """Return (entries_to_show, num_omitted) for one symbol.

    At most MAX_DEFS_PER_NAME definitions are shown.  When there are more (as
    can happen when the whole repo is searched), prefer definitions in the
    flagged file, then in nearby directories, and struct members last.  The
    chosen ones keep their original (sorted) order.  With no more than
    MAX_DEFS_PER_NAME entries this is the identity, so prompts (and their
    cached replies) are unaffected.
    """
    if len(entries) <= MAX_DEFS_PER_NAME:
        return entries, 0
    hint_parts = tuple(Path(hint_file).parent.parts) if hint_file else ()

    def rank(i):
        (filename, line_start, _, _, kind) = entries[i]
        rel = Path(os.path.relpath(filename, start=base_dir))
        common = 0
        for a, b in zip(rel.parent.parts, hint_parts):
            if a != b:
                break
            common += 1
        return (kind in _LOW_PRIORITY_KINDS, rel.as_posix() != Path(hint_file or "").as_posix(),
                -common, rel.as_posix(), line_start)

    chosen = sorted(sorted(range(len(entries)), key=rank)[:MAX_DEFS_PER_NAME])
    return [entries[i] for i in chosen], len(entries) - MAX_DEFS_PER_NAME


def read_text_file_or_none(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except (IOError, UnicodeDecodeError):
        return None


def get_defs_snippets(names, func_bounds_db, base_dir, hint_file=None,
                      read_file=read_text_file_or_none):
    """Return (snippets, unfound): annotated definition snippets for the
    requested names, and the names for which no definition could be shown.

    File paths are shown relative to *base_dir*.  *hint_file* (the flagged
    file, relative to the same root) is used only to choose among more than
    MAX_DEFS_PER_NAME definitions of one symbol.  File contents are obtained
    with read_file(filename), which returns None if the file can't be read.
    """
    by_name = func_bounds_db.get("by_name", {})
    snippets = []
    unfound = []
    seen = set()
    for name in names:
        entries = by_name.get(name, [])
        if not entries:
            warn_once(f"Warning: definition of '{name}' not found in func_bounds.")
            unfound.append(name)
            continue
        (entries, num_omitted) = choose_def_entries(entries, base_dir, hint_file)
        if num_omitted:
            warn_once(f"Warning: '{name}' has {len(entries) + num_omitted} definitions; "
                      f"showing {len(entries)}.")
        first_snippet_of_name = len(snippets)
        # Already shown under another name (e.g., "typedef struct foo {...} foo_t;").
        shown_elsewhere = False
        for (filename, line_start, line_end, _, kind) in entries:
            key = (filename, line_start)
            if key in seen:
                shown_elsewhere = True
                continue
            seen.add(key)
            contents = read_file(filename)
            if contents is None:
                continue
            raw_lines = split_lines(contents)
            end = max(line_end, line_start)
            if kind in ("typedef", "struct", "union", "enum", "class"):
                while line_start > 1 and _DECL_HEAD_RE.match(raw_lines[line_start - 2]):
                    line_start -= 1
            # Extend single-line entries to capture multi-line macro continuations
            if end == line_start:
                while end < len(raw_lines) and raw_lines[end - 1].rstrip().endswith('\\'):
                    end += 1
            annotated = add_line_nums(contents, ret_as_line_list=True)
            text = ''.join(annotated[line_start - 1:end])
            rel_filename = os.path.relpath(filename, start=base_dir)
            snippets.append(
                f"\nDefinition of `{name}` ({kind}) in {rel_filename}, "
                f"lines {line_start}-{end}:\n"
                f"```\n{text}```\n"
            )
        if len(snippets) == first_snippet_of_name and not shown_elsewhere:
            unfound.append(name)
        if num_omitted and len(snippets) > first_snippet_of_name:
            snippets.append(f"\n({num_omitted} more definitions of `{name}` omitted.)\n")
    return (snippets, unfound)


def get_repo_cache(args):
    """Return the shared RepoCache, creating it on first use."""
    if glo.repo_cache is None:
        repos_dir = args.repos_dir or os.path.join(args.base_dir, "repos")
        status_file = args.repo_status_file or os.getenv("LASAA_REPO_STATUS_FILE")
        try:
            limit = repo_cache.parse_size(args.repo_size_limit)
        except ValueError as e:
            die(f"Error: --repo-size-limit: {e}")
        glo.repo_cache = repo_cache.RepoCache(repos_dir, limit, status_file)
    return glo.repo_cache


def lookup_def_snippets(names, func_bounds_db, base_dir, repo_ref, hint_file, args):
    """Like get_defs_snippets, but falls back to the full repo for missing symbols.

    If every requested name is defined in the files we already have, they are
    looked up there, as before.  Otherwise, if the alert says which repo and
    commit it is about (*repo_ref* = (url, rev)), the commit is downloaded (once;
    it persists) and *all* the names are looked up in ctags data for the full
    repo at that commit, whose files are shown relative to the repo root.  The
    files are read from git's objects for that commit, not from a working tree
    (which another process could be changing).  If the repo can't be provided,
    we quietly fall back to the files we already have.
    """
    by_name = func_bounds_db.get("by_name", {})
    if repo_ref is None or all(name in by_name for name in names):
        return get_defs_snippets(names, func_bounds_db, base_dir, hint_file)
    (repo_url, rev) = repo_ref
    try:
        (repo_db, snapshot) = get_repo_cache(args).get_func_bounds_db(repo_url, rev)
    except repo_cache.RepoUnavailable as e:
        warn_once(f"Warning: full repo unavailable ({e}); "
                  f"looking up definitions in the downloaded files only.")
        return get_defs_snippets(names, func_bounds_db, base_dir, hint_file)
    warn_if_repo_differs(snapshot, base_dir, hint_file)
    # The repo db's file names are relative to the repo root.
    return get_defs_snippets(names, repo_db, ".", hint_file, read_file=snapshot.read_text)


def warn_if_repo_differs(snapshot, base_dir, hint_file):
    """Warn if the flagged file differs between the repo commit and base_dir.

    They should be byte-identical; if not (say, because of .gitattributes
    conversions in base_dir), line numbers from the alert may not match the
    repo's ctags data.
    """
    if not hint_file:
        return
    try:
        with open(os.path.join(base_dir, hint_file), "rb") as f:
            local = f.read()
    except OSError:
        return
    in_repo = snapshot.read_bytes(hint_file)
    if in_repo is not None and in_repo != local:
        warn_once(f"Warning: {hint_file!r} in {snapshot} differs from the copy in {base_dir}.")


def build_augmented_prompt(original_prompt, def_snippets, unfound_names=()):
    """Return original_prompt with the definition snippets appended, followed
    by a note naming the requested symbols whose definitions weren't found."""
    prompt = original_prompt
    if def_snippets:
        prompt += "\nHere are definitions of potentially relevant symbols:" + "".join(def_snippets)
    if unfound_names:
        prompt += ("\nWe could not find definitions of the following symbols, so please "
                   "don't request them again: "
                   + ", ".join(f"`{name}`" for name in unfound_names) + "\n")
    return prompt


# ===================================================================
# Trial-reply helpers
# ===================================================================

def get_trial_replies(out_dir, basename, prompt_hash, num_trials, valid_verdicts):
    """Read tryXX.reply files.

    Returns (verdicts, contents, filepaths) or None if any reply is missing.
    """
    verdicts = []
    contents = []
    filepaths = []
    has_missing_verdicts = False
    for i in range(num_trials):
        path = os.path.join(out_dir, f"{basename}.{prompt_hash}.try{i:02d}.reply")
        if not os.path.isfile(path):
            has_missing_verdicts = True
            continue
        glo.files_used.add(path)
        content = read_whole_file(path)
        # A reply that requests need_defs but omits the verdict line is
        # treated as "uncertain" rather than deleted as malformed.
        need_defs_only_ok = (extract_need_defs(content) is not None
                             and "uncertain" in valid_verdicts)
        verdict = get_verdict_of_reply_file(path, kill_if_missing=not need_defs_only_ok, valid_verdicts=valid_verdicts)
        if verdict == "missing" and need_defs_only_ok:
            verdict = "uncertain"
        if verdict == "missing":
            has_missing_verdicts = True
            continue
        verdicts.append(verdict)
        contents.append(content)
        filepaths.append(path)
    if has_missing_verdicts:
        return None
    return (verdicts, contents, filepaths)


def winning_reply_content(files, verdicts, winner, valid_verdicts):
    """Return the content of the first reply (in trial order) whose verdict is *winner*.

    A need_defs-only reply counts as "uncertain" (see get_trial_replies) but
    has no verdict line, so replies that state the verdict are preferred.  If
    none does, the verdict line is appended, so that the ".final_answer" made
    from the content always states its verdict.
    """
    winners = [f for f, v in zip(files, verdicts) if v == winner]
    stated = [f for f in winners
              if get_verdict_of_reply_file(f, valid_verdicts=valid_verdicts) == winner]
    content = read_whole_file((stated or winners)[0])
    if not stated:
        if not content.endswith("\n"):
            content += "\n"
        content += json.dumps({"verdict": winner}) + "\n"
    return content


def is_unanimous(verdicts, valid_verdicts):
    """True when every verdict is the same."""
    rv = [v for v in verdicts if v in valid_verdicts]
    return len(rv) > 0 and len(set(verdicts)) == 1


def consistency_check(verdicts, threshold, valid_verdicts):
    """Return the verdict meeting *threshold* (trial count), or None.

    Denominator is the total number of replies (including uncertain / missing).
    """
    total = len(verdicts)
    if total == 0:
        return None
    counts = Counter(verdicts)
    for v in valid_verdicts:
        if v in ["missing"]:
            continue
        if counts.get(v, 0) >= threshold:
            return v
    return None


def parse_threshold_count(threshold_arg, num_trials):
    """Parse a threshold argument and return a trial count.

    Accepted forms:
      - "80%" for a percentage
      - "0.8" for a fraction of num_trials
      - "8/n" for an explicit trial count

    For backward compatibility, a bare number greater than 50 is treated as a
    percentage when num_trials is at most 50.
    """
    s = str(threshold_arg).strip()
    threshold_fraction = None
    threshold_count = None

    if re.fullmatch(r'[0-9]+(?:[.][0-9]+)?%', s):
        threshold_fraction = float(s[:-1]) / 100.0
    elif re.fullmatch(r'0[.][0-9]+', s):
        threshold_fraction = float(s)
    elif re.fullmatch(r'[0-9]+/[Nn]', s):
        threshold_count = int(s.split("/", 1)[0])
    elif re.fullmatch(r'[0-9]+(?:[.][0-9]+)?', s):
        value = float(s)
        if value > 50 and num_trials <= 50:
            threshold_fraction = value / 100.0
        else:
            die("Error: --threshold must be written as a percentage like "
                "'80%', a fraction like '0.80', or a count like '8/n'.")
    else:
        die("Error: --threshold must be written as a percentage like "
            "'80%', a fraction like '0.80', or a count like '8/n'.")

    if threshold_fraction is not None:
        if threshold_fraction <= 0.5:
            die("Error: --threshold must be greater than 50%.")
        threshold_count = math.ceil(num_trials * threshold_fraction - 1e-6)

    if threshold_count <= num_trials / 2:
        die("Error: --threshold must be greater than 50%.")
    if threshold_count > num_trials:
        die("Error: --threshold cannot require more trials than --num-trials.")
    return threshold_count


def simp_maj_verdict(verdicts, valid_verdicts):
    """Uses two-stage simple majority voting.
    First stage: positive (true/dep/uncertain) vs negative (false).
    Second stage (if positive): true vs dependent vs uncertain.
    The second stage can actually be won by a mere plurality rather a majority
    if uncertain is present, but the LLMs never seem to return "uncertain".
    """
    assert(valid_verdicts == ("true", "dependent", "false", "uncertain"))
    counts = Counter(verdicts)
    pos_count = counts.get("true",0) + counts.get("dependent",0) + counts.get("uncertain",0)
    neg_count = counts.get("false",0)

    # Stage 1: positive vs negative
    if neg_count > pos_count:
        return "false"

    # Stage 2: subclasses of positive (true, dep, uncertain)
    best = None
    best_count = 0
    for v in valid_verdicts:
        if v in ["missing", "false"]:
            continue
        c = counts.get(v, 0)
        if c > best_count:
            best_count = c
            best = v
    return best


# ===================================================================
# Prompt builders
# ===================================================================

def format_prompt_blocks(intro, original_prompt, reply_contents, verdicts):
    """Format intro + original question + numbered reply blocks."""
    items = [("Original question", original_prompt, {})]
    for i, (content, verdict) in enumerate(zip(reply_contents, verdicts)):
        if verdict == "missing":
            continue
        stripped = strip_hdr_and_reasoning(content)
        items.append((f"Response {i}", stripped, {"verdict": verdict}))

    parts = [intro]
    for block_name, block_content, opts in items:
        if not block_content.endswith("\n"):
            block_content += "\n"
        h = hashlib.sha256(block_content.encode("utf-8")).hexdigest()[:12]
        extra = ""
        if "verdict" in opts:
            extra = f" (verdict='{opts['verdict']}')"
        parts.append(f"### BEGIN {block_name} (hash={h}){extra}\n\n")
        parts.append(block_content)
        parts.append(f"### END {block_name} (hash={h})\n\n")
    return "".join(parts)

resolve_prompt_intro = (
"""
Below is a question and discordant responses to it.  Carefully evaluate these responses.  Then, write your own response to the original question.  Your response should also briefly indicate what you find wrong/unconvincing about responses that reached a different final answer.  (You don't need to address each input response individually; just briefly point out what the flaws are.)  If the different responses seem to be interpreting the original question differently, briefly discuss this and pick what you consider to be the best interpretation.
"""
).strip()

def build_resolve_prompt(original_prompt, reply_contents, verdicts):
    intro = resolve_prompt_intro + "\n\n"
    return format_prompt_blocks(intro, original_prompt,
                                 reply_contents, verdicts)


def build_explain_prompt(original_prompt, reply_contents, verdicts):
    intro = (
        "Below is a question and discordant responses to it.  "
        "Please explain the source of the disagreement among these responses.  "
        "What aspects of the question or code are ambiguous or difficult to "
        "analyze?  What are the key points of contention?\n\n"
    )
    return format_prompt_blocks(intro, original_prompt,
                                 reply_contents, verdicts)


# ===================================================================
# Build the original prompt for one alert
# ===================================================================

# The default --more-ctx-fields.  AdditionalLocations comes from
# conv/cppcheck_to_lasaa.py (with lowercase "file" and "line" keys).
DEFAULT_MORE_CTX_FIELDS = "Traces,CodeFlow,MoreContext,AdditionalLocations"


def collect_more_ctx_locations(row, more_ctx_fields):
    """Return a list of (file, line) pairs from the alert's extra-context fields.

    Each field named in *more_ctx_fields* should hold either a list of dicts or
    a list of lists of dicts; each dict with both a "File" and a "Line" field
    (or "file" and "line", as in cppcheck's AdditionalLocations) contributes
    one location.
    """
    locations = []
    for field in more_ctx_fields:
        val = row.get(field)
        if not isinstance(val, list):
            continue
        items = []
        for elem in val:
            if isinstance(elem, list):
                items.extend(elem)
            else:
                items.append(elem)
        for item in items:
            if not isinstance(item, dict):
                continue
            ctx_file = item.get("File") or item.get("file")
            ctx_line = item.get("Line") if item.get("Line") is not None else item.get("line")
            if not ctx_file or ctx_line is None:
                continue
            try:
                ctx_line = int(ctx_line)
            except (TypeError, ValueError):
                continue
            locations.append((ctx_file, ctx_line))
    return locations


def build_original_prompt(subalerts, func_bounds_db, base_dir, args):
    """Build the adjudication prompt for a single alert.

    *base_dir* is the directory that the alert's file paths are relative to
    (see get_alert_base_dir).  Returns the prompt string, or None if the
    enclosing function can't be found.
    """
    # Alerts with their own base dir are shown to the LLM with paths relative
    # to it, so that the location of the base dir (which might reveal, e.g.,
    # whether the code is before or after a fix) isn't leaked to the LLM.
    # Other alerts keep the old display format, so existing prompt hashes
    # (and thus cached replies) stay valid.
    has_own_base_dir = (subalerts[0].get("Base_Dir") is not None)

    if len(subalerts)==1 and ("Orig_LLM_Query" in subalerts[0]):
        return subalerts[0]["Orig_LLM_Query"]
    CWE_list = []
    CWE_set = set()
    for row in subalerts:
        for cwe in get_cwes_in_alert(row):
            if type(cwe) != str:
                continue
            cwe = cwe.strip()
            if cwe == "":
                continue
            if cwe not in CWE_set:
                CWE_set.add(cwe)
                CWE_list.append(cwe)
    
    hints = []
    if "CWE-457" in CWE_set:
        hints.append(
            "Remember that when passing the address of a variable to a "
            "function, the callee might initialize the variable before "
            "using it.\n"
        )


    prompt = prompt_intro
    prompt += "".join(hints)

    for row in subalerts:
        alert_info_lines = ["<alert_info>"]
        for field in glo.fields_for_llm or row.keys():
            if field == glo.alert_id_field:
                continue
            if field in ("Base_Dir", "Repo_URL", "Repo_Rev") and not glo.fields_for_llm:
                continue
            alert_info_lines.append(field + ": " + glo.to_str(row.get(field)))
        alert_info_lines.append("</alert_info>")
        prompt += "\n" + "\n".join(alert_info_lines) + "\n"

    snippet_list = []
    # Function identities (realpath, start_line) already covered by a
    # flagged-line snippet.  A MoreContext location inside one of those adds
    # nothing, and for a function over 300 lines the elided rendering differs
    # per location, so plain text dedup would not catch it.
    shown_funcs = set()
    for row in subalerts:
        filepath_in_alert = os.path.join(row.get("Path", ""), row["File"])
        filepath_with_base = os.path.join(base_dir, filepath_in_alert)
        if not os.path.exists(filepath_with_base):
            stderr.write("Error: file not found: " + repr(filepath_with_base) + "\n")
            stderr.write(" - Info: current dir: " + repr(os.path.realpath(".")) + "\n")
            stderr.write(" - Info: base_dir: " + repr(base_dir) + "\n")
            stderr.write(" - Info: path from alert: " + repr(filepath_in_alert) + "\n")
            if os.path.split(os.path.realpath(base_dir))[1] == filepath_in_alert.split("/")[0] and os.path.exists(os.path.join(base_dir, "..", filepath_in_alert)):
                stderr.write(" - Hint: Try base_dir = " + repr(os.path.realpath(os.path.join(base_dir, ".."))) + "\n")
            stderr.write("Stopping due to above error.\n")
            sys.exit(1)
        filepath = filepath_with_base
        snippet = get_enclosing_func(
            filepath, int(row["Line"]), func_bounds_db)
        if not snippet:
            alert_id = row.get(glo.alert_id_field)
            sys.stderr.write(
                f"Error: unable to locate function for Alert {alert_id!r} "
                f"(file {filepath_in_alert}, line {row['Line']}).\n")
            return None
        snippet_list.append(
            f"\nFile {filepath_in_alert if has_own_base_dir else filepath}:\n"
            + "```\n"
            + snippet
            + "```\n"
        )
        (func_start, _) = get_enclosing_func_range(
            filepath, int(row["Line"]), func_bounds_db)
        if func_start is not None:
            shown_funcs.add((cached_realpath(filepath), func_start))

    extra_snippet_list = []
    has_extra_decl = False
    for row in subalerts:
        for (ctx_file, ctx_line) in collect_more_ctx_locations(row, args.more_ctx_fields):
            ctx_filepath_in_alert = os.path.join(row.get("Path", ""), ctx_file)
            filepath = os.path.join(base_dir, ctx_filepath_in_alert)
            if not os.path.exists(filepath):
                warn_once(f"Warning: extra-context file not found: {filepath!r}")
                continue
            (func_start, _) = get_enclosing_func_range(
                filepath, ctx_line, func_bounds_db)
            is_decl = False
            if func_start is None:
                # Outside any function: fall back to the enclosing macro, type,
                # or global declaration (e.g., a macro that a callback runs in).
                (func_start, decl_end) = get_enclosing_decl_range(
                    filepath, ctx_line, func_bounds_db)
                is_decl = func_start is not None
            func_id = (cached_realpath(filepath), func_start)
            if func_start is not None and func_id in shown_funcs:
                continue  # already shown; see shown_funcs above
            if is_decl:
                snippet = get_enclosing_decl(filepath, ctx_line, func_bounds_db)
            else:
                snippet = get_enclosing_func(filepath, ctx_line, func_bounds_db)
            if not snippet:
                warn_once(
                    f"Warning: unable to locate function or declaration for extra context "
                    f"(file {ctx_file!r}, line {ctx_line}).\n")
                continue
            has_extra_decl = has_extra_decl or is_decl
            if func_start is not None:
                shown_funcs.add(func_id)
            # Lines of a multi-line macro end in "\", so they get no "// Line N"
            # annotation; give the range so the context line can be located.
            line_range = f", lines {func_start}-{decl_end}" if is_decl else ""
            extra_snippet_list.append(
                f"\nFile {ctx_filepath_in_alert if has_own_base_dir else filepath}{line_range}:\n"
                + "```\n"
                + snippet
                + "```\n"
            )

    prompt += '\nBelow is the source code of the function containing the flagged line.  I have appended "// Line N" to lines to indicate line numbers.'
    seen_snippets = set()
    for snippet in snippet_list:
        if snippet in seen_snippets:
            continue
        seen_snippets.add(snippet)
        prompt += snippet

    extra_parts = []
    for snippet in extra_snippet_list:
        if snippet in seen_snippets:
            continue
        seen_snippets.add(snippet)
        extra_parts.append(snippet)
    if extra_parts:
        # The wording without declarations is unchanged, to keep existing prompt hashes.
        what = "functions and declarations" if has_extra_decl else "functions"
        prompt += f'\nBelow is the source code of additional {what} referenced in the alert.'
        prompt += "".join(extra_parts)
    return prompt


# ===================================================================
# final_answer opts helpers
# ===================================================================

def compute_opts_dict(args, include_explain_uncertain):
    """Build the opts dict recorded as a comment in ".final_answer" files.

    "t" is the threshold expressed as a count of trials (not a percentage):
    the minimum number of the N trials required for consistency.
    """
    use_simp_maj = bool(getattr(args, "simp_maj", False))
    if use_simp_maj:
        threshold_count = None
        N = args.num_trials
    else:
        if args.consistency_check:
            threshold_count = args.threshold
        else:
            threshold_count = None
        N = args.num_trials
        if (not args.consistency_check) and (not args.llm_resolve):
            N = 1
    opts_dict = {
        "N": N,
        "t": threshold_count,
        "CC": bool(args.consistency_check) and not use_simp_maj,
        "LRE": bool(args.llm_resolve),
        "LookupMax": args.max_need_defs_rounds,
    }
    if use_simp_maj:
        opts_dict["simp_maj"] = True
    # Recorded only when on, so existing final answers (made without it) match --tell-unfound 0.
    if args.tell_unfound:
        opts_dict["TellUnfound"] = True
    if include_explain_uncertain:
        opts_dict["explain_uncertain"] = bool(args.explain_uncertain)
    return opts_dict


def parse_final_answer_opts(final_answer_file):
    """Return the opts dict recorded in *final_answer_file*, or None if absent."""
    try:
        with open(final_answer_file, "r", encoding="utf-8") as f:
            first_line = f.readline()
    except OSError:
        return None
    idx = first_line.find("# opts=")
    if idx == -1:
        return None
    json_str = first_line[idx + len("# opts="):].strip()
    closing_curly_idx = json_str.find("}")
    if closing_curly_idx == -1:
        return None
    json_str = json_str[:closing_curly_idx+1]
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None


def parse_reply_header_tokens(filepath):
    """Return token counts parsed from a reply file's header.

    The result is ``(input_tokens, cached_input_tokens, output_tokens)``.

    Handles both the one-line header, e.g.
        # Model: NAME, input_tokens=I, cached_input_tokens=C, output_tokens=O
        # Model: NAME, input_tokens: I, reasoning_tokens: R, output tokens: O
    and the two-line header
        # Model: NAME
        # prompt_tokens=I, completion_tokens=O
    The reasoning-token count, when present, is ignored.  Any count is
    returned as float("nan") when it can't be read.
    """
    header = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("#"):
                    break
                header.append(line)
    except OSError:
        return (float("nan"), float("nan"), float("nan"))
    text = "".join(header)
    input_tok = float("nan")
    cached_input_tok = float("nan")
    output_tok = float("nan")
    m = re.search(r'(?<![A-Za-z0-9_])(?:input_tokens|prompt_tokens)\s*[=:]\s*([0-9]+)', text)
    if m:
        input_tok = int(m.group(1))
    m = re.search(r'(?<![A-Za-z0-9_])(?:cached_input_tokens|cached_tokens)\s*[=:]\s*([0-9]+)', text)
    if m:
        cached_input_tok = int(m.group(1))
    m = re.search(r'(?:output[_ ]tokens|completion_tokens)\s*[=:]\s*([0-9]+)', text)
    if m:
        output_tok = int(m.group(1))
    return (input_tok, cached_input_tok, output_tok)


def parse_reply_header_reasoning_tokens(filepath):
    """Return the reasoning-token count from a reply file's header, or NaN."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("#"):
                    break
                m = re.search(r'(?<![A-Za-z0-9_])reasoning_tokens\s*[=:]\s*([0-9]+)', line)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return float("nan")


def parse_reply_header_model(filepath):
    """Return the model name from a reply file's "# Model:" header, or None."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("#"):
                    break
                m = re.match(r'#\s*Model:\s*([^,\n]+)', line)
                if m:
                    return m.group(1).strip()
    except OSError:
        pass
    return None


def parse_reply_header_effort(filepath):
    """Return the reasoning effort from a reply file's "# Model:" header, or None."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("#"):
                    break
                m = re.match(r'#\s*Model:.*\breasoning_effort=\'([^\']*)\'', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def describe_file_groups(groups):
    """Format {value: [files]} as one line per value with a count and an example file."""
    return "\n".join(f"  {value!r}: {len(files)} file(s), e.g. {files[0]!r}"
                     for value, files in sorted(groups.items(), key=lambda kv: str(kv[0])))


def get_child_arg(child_args, flag):
    """Return the value given for *flag* ("--flag V" or "--flag=V") in *child_args*, or None."""
    for i, tok in enumerate(child_args):
        if tok == flag:
            if i + 1 >= len(child_args):
                die(f"Error: {flag} (after '--') requires a value.")
            return child_args[i + 1]
        if tok.startswith(flag + "="):
            return tok[len(flag) + 1:]
    return None


def infer_llm_settings(out_dir, explicit_effort):
    """Infer (model, effort) from the ".reply" files in *out_dir*, for --auto-model.

    *explicit_effort* is the --reasoning-effort given after '--', or None.  It
    stands in for replies whose header doesn't record an effort, and must
    match the effort of those that do.  The returned effort is None when the
    LLM script should get no --reasoning-effort of its own.  Dies unless all
    the replies agree.
    """
    reply_files = sorted(glob.glob(os.path.join(glob.escape(out_dir), "*.reply")))
    if not reply_files:
        die(f"Error: --auto-model: no \".reply\" files in {out_dir!r}.")
    models = {}
    efforts = {}
    for path in reply_files:
        models.setdefault(parse_reply_header_model(path), []).append(path)
        efforts.setdefault(parse_reply_header_effort(path), []).append(path)

    if None in models:
        die(f"Error: --auto-model: some \".reply\" files in {out_dir!r} have no "
            "\"# Model:\" header:\n" + describe_file_groups(models))
    if len(models) != 1:
        die(f"Error: --auto-model: \".reply\" files in {out_dir!r} name "
            "different models:\n" + describe_file_groups(models))
    (model,) = models.keys()

    recorded = [e for e in efforts if e is not None]
    if len(recorded) > 1:
        die(f"Error: --auto-model: \".reply\" files in {out_dir!r} record "
            "different reasoning efforts:\n" + describe_file_groups(efforts))
    if explicit_effort is not None:
        if recorded and recorded[0] != explicit_effort:
            die(f"Error: --reasoning-effort {explicit_effort!r} doesn't match the "
                f"reasoning effort recorded in \".reply\" files in {out_dir!r}:\n"
                + describe_file_groups(efforts))
        # Already among the child args.
        return (model, None)
    if None in efforts:
        die(f"Error: --auto-model: some \".reply\" files in {out_dir!r} don't "
            "record a reasoning effort; pass --reasoning-effort after '--':\n"
            + describe_file_groups(efforts))
    effort = recorded[0]
    # ask_gpt.py records "default" when run without --reasoning-effort, and
    # ask_claude_aws.py records "none" for models without adaptive thinking.
    if effort in ("default", "none"):
        effort = None
    return (model, effort)


def read_lre_prompt_file(filename):
    """Return the stripped contents of an LRE prompt file; die if unreadable or empty."""
    try:
        intro = read_whole_file(filename).strip()
    except OSError as e:
        die(f"Error: can't read --lre-prompt-file: {e}")
    if not intro:
        die(f"Error: --lre-prompt-file {filename!r} is empty.")
    return intro


def infer_lre_prompt_intro(out_dir, candidates_spec):
    """Pick the LRE prompt intro used by the existing ".lre." query files in *out_dir*.

    *candidates_spec* is the comma-separated list after "auto:" in
    --lre-prompt-file; each item is "default" (the built-in intro) or a file
    name.  Returns (item, intro).  Dies unless every ".lre." query file uses
    the same candidate.
    """
    candidates = []
    for item in candidates_spec.split(","):
        item = item.strip()
        if not item:
            die(f"Error: empty item in --lre-prompt-file auto:{candidates_spec}")
        if item == "default":
            candidates.append((item, resolve_prompt_intro))
        else:
            candidates.append((item, read_lre_prompt_file(item)))

    query_files = sorted(glob.glob(os.path.join(glob.escape(out_dir), "*.lre.run[0-9][0-9].query")))
    if not query_files:
        die(f"Error: --lre-prompt-file auto: no \".lre.\" query files in {out_dir!r}.")
    # The resolve prompt is the intro, a blank line, then the question blocks
    # (see build_resolve_prompt and format_prompt_blocks).
    matches = {}
    for qf in query_files:
        content = read_whole_file(qf)
        names = tuple(name for (name, intro) in candidates
                      if content.startswith(intro + "\n\n### BEGIN Original question "))
        matches.setdefault(names, []).append(qf)
    if () in matches:
        die(f"Error: --lre-prompt-file auto: some \".lre.\" query files in {out_dir!r} "
            "match none of the candidate prompts:\n" + describe_file_groups(matches))
    if len(matches) != 1:
        die(f"Error: --lre-prompt-file auto: \".lre.\" query files in {out_dir!r} "
            "use different prompts:\n" + describe_file_groups(matches))
    (names,) = matches.keys()
    # Several names match only if their files have the same text.
    return next((name, intro) for (name, intro) in candidates if name == names[0])


def strip_final_answer_header(content):
    """Remove the "# Model:" and "# used=" header lines of a ".final_answer"."""
    lines = content.split("\n")
    if lines and lines[0].startswith("# Model:"):
        lines = lines[1:]
        if lines and lines[0].startswith("# used="):
            lines = lines[1:]
    return "\n".join(lines)


def strip_reply_header(content):
    """Remove the leading "# Model:" / token-count header lines from *content*."""
    lines = content.split("\n")
    i = 0
    while i < len(lines) and re.match(
            r'#\s*(Model:|prompt_tokens|completion_tokens|input_tokens|cached_input_tokens)',
            lines[i]):
        i += 1
    return "\n".join(lines[i:]).lstrip("\n")


def query_file_for_reply(reply_path, num_trials):
    """Return the ".query" file corresponding to a ".reply" file, or None.

    Trial replies "X.tryNN.reply" all come from the shared query file
    "X.runMM.query"; a plain "X.reply" (e.g. explain-uncertain) comes from
    "X.query".
    """
    m = re.match(r'^(.*)\.try[0-9][0-9]\.reply$', reply_path)
    if m:
        prefix = m.group(1)
        return f"{prefix}.run{num_trials:02d}.query"
    if reply_path.endswith(".reply"):
        return reply_path[:-len(".reply")] + ".query"
    return None


def gpt_oss_short_name(model):
    """Return "gpt-oss-120b"/"gpt-oss-20b" if *model* names one, else None."""
    if not model:
        return None
    for short in ("gpt-oss-120b", "gpt-oss-20b"):
        if model.endswith(short):
            return short
    return None


def count_gpt_oss_tokens_in_file(path, short_model, tokenizers_dir):
    """Count tokens of *path* via count_gpt_oss_tokens; NaN (with a warning) on failure."""
    try:
        from count_gpt_oss_tokens import count_tokens_in_file
        return count_tokens_in_file(path, short_model, tokenizers_dir)
    except Exception as e:
        if not glo.tokenize_warned:
            stderr.write(f"Warning: --tokenize failed ({e}); "
                         f"affected token counts left as NaN.\n")
            glo.tokenize_warned = True
        return float("nan")


def reply_token_counts(reply_path, args):
    """Return token counts for one reply, applying fallbacks.

    The result is ``(input_tokens, cached_input_tokens, output_tokens)``.

    Counts come from the reply header when present.  For any count still
    missing, --tokenize (gpt-oss models only) and then --guess-token-count are
    applied in that order; anything still unknown stays NaN.
    """
    in_tok, cached_in_tok, out_tok = parse_reply_header_tokens(reply_path)
    in_missing = in_tok != in_tok      # NaN != NaN
    out_missing = out_tok != out_tok
    if not (in_missing or out_missing):
        return (in_tok, cached_in_tok, out_tok)

    query_path = query_file_for_reply(reply_path, args.num_trials)

    if getattr(args, "tokenize", False):
        short = gpt_oss_short_name(parse_reply_header_model(reply_path))
        if short:
            if in_missing and query_path and os.path.isfile(query_path):
                in_tok = count_gpt_oss_tokens_in_file(query_path, short, args.tokenizers_dir)
                in_missing = in_tok != in_tok
            if out_missing and os.path.isfile(reply_path):
                out_tok = count_gpt_oss_tokens_in_file(reply_path, short, args.tokenizers_dir)
                out_missing = out_tok != out_tok

    if getattr(args, "guess_token_count", False):
        short = gpt_oss_short_name(parse_reply_header_model(reply_path))
        if short:
            if in_missing and query_path and os.path.isfile(query_path):
                in_tok = os.path.getsize(query_path) // 4
                in_missing = False
            if out_missing and os.path.isfile(reply_path):
                out_tok = os.path.getsize(reply_path) // 4
                out_missing = False

    return (in_tok, cached_in_tok, out_tok)


def sum_reply_tokens(token_files, args):
    """Tally tokens over *token_files* (the replies used for a final answer).

    Returns ``(model_name, effort, total_input_tokens, total_cached_input_tokens,
    total_reasoning_tokens, total_output_tokens)``.  The model and effort are
    those of the first reply that records one (effort is None if none does).
    A total is NaN if any contributing reply's count couldn't be read (or
    estimated).
    """
    total_input = 0
    total_cached_input = 0
    total_reasoning = 0
    total_output = 0
    model_name = None
    effort = None
    for fp in token_files:
        in_tok, cached_in_tok, out_tok = reply_token_counts(fp, args)
        total_input += in_tok
        total_cached_input += cached_in_tok
        total_reasoning += parse_reply_header_reasoning_tokens(fp)
        total_output += out_tok
        if model_name is None:
            model_name = parse_reply_header_model(fp)
        if effort is None:
            effort = parse_reply_header_effort(fp)
    if model_name is None:
        model_name = "unknown"
    return (model_name, effort, total_input, total_cached_input, total_reasoning, total_output)


def write_final_answer(final_answer_file, content, args, verdict, token_files, used):
    """Write *content* to *final_answer_file*, recording opts and token totals.

    The reply header (if any) at the top of *content* is replaced with two
    header lines.  The first names the model and reasoning effort and tallies
    the input/output tokens summed over *token_files* -- including cached
    input and reasoning tokens when every reply reports them -- across all the
    replies used to produce this final answer, then gives the opts.  The
    second, "# used=", records *used*: which query/reply sets those replies
    came from (see process_alert).
    """
    is_uncertain = (verdict == "uncertain")
    opts_dict = compute_opts_dict(args, include_explain_uncertain=is_uncertain)
    opts_str = f'# opts={json.dumps(opts_dict)}'
    (model_name, effort, total_input, total_cached_input, total_reasoning,
     total_output) = sum_reply_tokens(token_files, args)
    token_bits = [f"input_tokens: {total_input}"]
    if not math.isnan(total_cached_input):
        token_bits.append(f"cached_input_tokens: {total_cached_input}")
    if not math.isnan(total_reasoning):
        token_bits.append(f"reasoning_tokens: {total_reasoning}")
    token_bits.append(f"output_tokens: {total_output}")
    if effort is not None:
        token_bits.insert(0, f"reasoning_effort='{effort}'")
    header = f"# Model: {model_name}, {', '.join(token_bits)} {opts_str}"
    header += f"\n# used={json.dumps(used)}"
    body = strip_reply_header(content)
    new_content = header + "\n" + body
    if not new_content.endswith("\n"):
        new_content += "\n"
    with open(final_answer_file, "w", encoding="utf-8") as f:
        f.write(new_content)


# ===================================================================
# Per-alert pipeline
# ===================================================================

def process_alert(basename, original_prompt, valid_verdicts, out_dir, args, func_bounds_db, base_dir,
                  repo_ref=None, hint_file=None):
    """Drive the pipeline for one alert.  Returns a human-readable status.

    *repo_ref* is (repo_url, commit_sha) or None (see get_alert_repo_ref);
    *hint_file* is the flagged file, relative to the repo root.
    """

    prompt_hash = compute_prompt_hash(original_prompt, "orig")

    final_answer_file = os.path.join(out_dir, f"{basename}.final_answer")
    if os.path.isfile(final_answer_file):
        existing_opts = parse_final_answer_opts(final_answer_file)
        current_opts = compute_opts_dict(args, include_explain_uncertain=False)
        # Mirror the existing file's key set: only compare "explain_uncertain"
        # if it was recorded in the existing ".final_answer".
        if existing_opts is not None and "explain_uncertain" in existing_opts:
            current_opts["explain_uncertain"] = bool(args.explain_uncertain)
        has_verdict = (get_verdict_of_reply_file(final_answer_file,
                                                 valid_verdicts=valid_verdicts) != "missing")
        if existing_opts == current_opts and has_verdict:
            return "already done"
        # Opts differ (or are absent/unreadable), or the answer lacks a verdict
        # line (made by an older version from a need_defs-only reply): discard
        # the stale answer.
        os.remove(final_answer_file)

    use_resolve     = bool(args.llm_resolve)
    use_simp_maj    = bool(args.simp_maj)
    use_consistency = bool(args.consistency_check) and not use_simp_maj
    threshold       = args.threshold

    # We run trials in two phases, as follows.  Disabling the consistency check
    # is equivalent to running a single trial in the CC phase.
    #   Phase 1: Run the original prompt num_trials_phase1 times.  When LRE is
    #            on, these runs are the discordant responses the resolve step
    #            evaluates; when LRE is off, they are the consistency-check
    #            sample.  Either way, this is a single trial only when both
    #            techniques are off.
    #   Phase 2: Run the LRE resolve prompt num_trials_phase2 times (LRE only).
    #            This is the consistency check applied to the resolve step.
    if use_resolve:
        num_trials_phase1 = args.num_trials
        num_trials_phase2 = args.num_trials if (use_consistency or use_simp_maj) else 1
    else:
        num_trials_phase1 = args.num_trials if (use_consistency or use_simp_maj) else 1

    # ------------------------------------------------------------------
    # Phase 1: run the original prompt num_trials_phase1 times.
    # ------------------------------------------------------------------
    orig_run_qf = os.path.join(
        out_dir, f"{basename}.{prompt_hash}.run{num_trials_phase1:02d}.query")
    write_file_if_needed(orig_run_qf, original_prompt)

    orig = get_trial_replies(out_dir, basename, prompt_hash, num_trials_phase1, valid_verdicts=valid_verdicts)
    if orig is None:
        return "waiting: original trial replies"
    orig_verdicts, orig_contents, orig_files = orig

    # Reply files whose tokens count toward the final-answer total.  We keep the
    # original-query replies even when augdef re-runs replace orig_files, since
    # those trials were still spent producing the final answer.
    token_files = list(orig_files)
    # The query/reply sets used, recorded in the ".final_answer" as "# used=".
    # Each is a file-name stem "H.KIND" ("<basename>.H.KIND.runNN.query" and
    # "<basename>.H.KIND.tryKK.reply" with KK < NN, or "<basename>.H.KIND.query"
    # and ".reply" for "uncert").  "phase1" lists the original prompt and then
    # each need_defs round's; the last is the one whose verdicts count.
    used = {"phase1": [prompt_hash], "n1": num_trials_phase1,
            "lre": None, "n2": None, "uncert": None}

    # Handle need_defs: if any trial requested definitions, augment the prompt
    # and re-run the trials with the enriched context.  Repeat so definitions
    # that refer to other symbols can trigger follow-up definition requests.
    attempted_need_defs = set()
    for augdef_round in range(args.max_need_defs_rounds):
        need_defs_names = collect_need_defs(orig_contents)
        if not need_defs_names:
            break
        need_defs_names = [
            name for name in need_defs_names
            if name not in attempted_need_defs
        ]
        if not need_defs_names:
            break
        attempted_need_defs.update(need_defs_names)
        (def_snippets, unfound_names) = lookup_def_snippets(
            need_defs_names, func_bounds_db, base_dir, repo_ref, hint_file, args)
        if not args.tell_unfound:
            unfound_names = []
        if not def_snippets and not unfound_names:
            break
        original_prompt = build_augmented_prompt(original_prompt, def_snippets, unfound_names)
        prompt_hash = compute_prompt_hash(original_prompt, f"augdef.{augdef_round}")
        orig_run_qf = os.path.join(
            out_dir, f"{basename}.{prompt_hash}.run{num_trials_phase1:02d}.query")
        write_file_if_needed(orig_run_qf, original_prompt)
        orig = get_trial_replies(out_dir, basename, prompt_hash, num_trials_phase1, valid_verdicts=valid_verdicts)
        if orig is None:
            return f"waiting: need_defs round {augdef_round} trial replies"
        orig_verdicts, orig_contents, orig_files = orig
        token_files.extend(orig_files)
        used["phase1"].append(prompt_hash)

    # ------------------------------------------------------------------
    # LRE off: consistency check on the original prompt.
    # ------------------------------------------------------------------
    if not use_resolve:
        if use_simp_maj:
            maj = simp_maj_verdict(orig_verdicts, valid_verdicts)
        elif not use_consistency:
            maj = orig_verdicts[0]
        else:
            maj = consistency_check(orig_verdicts, threshold, valid_verdicts)
        if maj is not None:
            content = winning_reply_content(orig_files, orig_verdicts, maj, valid_verdicts)
            write_final_answer(final_answer_file, content, args, maj, token_files, used)
            return f"done ({maj})"
        return handle_uncertain(basename, out_dir, args, original_prompt,
                                 orig_contents, orig_verdicts,
                                 final_answer_file, token_files, used)

    # ------------------------------------------------------------------
    # LRE on: resolve discordant runs, then consistency-check the result.
    # ------------------------------------------------------------------
    if is_unanimous(orig_verdicts, valid_verdicts):
        content = winning_reply_content(orig_files, orig_verdicts, orig_verdicts[0], valid_verdicts)
        write_final_answer(final_answer_file, content, args, orig_verdicts[0], token_files,
                           used)
        return "done (unanimous original)"

    resolve_prompt = build_resolve_prompt(original_prompt,
                                          orig_contents, orig_verdicts)
    rh = compute_prompt_hash(resolve_prompt, "lre")
    resolve_run_qf = os.path.join(
        out_dir, f"{basename}.{rh}.run{num_trials_phase2:02d}.query")
    write_file_if_needed(resolve_run_qf, resolve_prompt)

    res = get_trial_replies(out_dir, basename, rh, num_trials_phase2, valid_verdicts=valid_verdicts)
    if res is None:
        return "waiting: resolve trial replies"
    res_verdicts, res_contents, res_files = res
    token_files.extend(res_files)
    used["lre"], used["n2"] = rh, num_trials_phase2

    if use_simp_maj:
        maj = simp_maj_verdict(res_verdicts, valid_verdicts)
    elif not use_consistency:
        maj = res_verdicts[0]
    else:
        maj = consistency_check(res_verdicts, threshold, valid_verdicts)
    if maj is not None:
        content = winning_reply_content(res_files, res_verdicts, maj, valid_verdicts)
        write_final_answer(final_answer_file, content, args, maj, token_files, used)
        return f"done ({maj})"

    return handle_uncertain(basename, out_dir, args, original_prompt,
                             res_contents, res_verdicts,
                             final_answer_file, token_files, used)


def handle_uncertain(basename, out_dir, args, original_prompt,
                      reply_contents, verdicts, final_answer_file, token_files, used):
    """Write the final_answer file for the uncertain / below-threshold case."""
    if args.explain_uncertain:
        explain_prompt = build_explain_prompt(original_prompt,
                                             reply_contents, verdicts)
        eh = compute_prompt_hash(explain_prompt, "uncert")
        eqf = os.path.join(out_dir, f"{basename}.{eh}.query")
        write_file_if_needed(eqf, explain_prompt)
        erf = os.path.join(out_dir, f"{basename}.{eh}.reply")
        if not os.path.isfile(erf):
            return "waiting: explain-uncertain reply"
        explanation = read_whole_file(erf)
        content = explanation
        if not content.endswith("\n"):
            content += "\n"
        content += '{"verdict": "uncertain"}\n'
        used = dict(used, uncert=eh)
        write_final_answer(final_answer_file, content, args, "uncertain",
                           token_files + [erf], used)
        return "done (uncertain, explained)"
    else:
        content = '{"verdict": "uncertain"}\n'
        write_final_answer(final_answer_file, content, args, "uncertain",
                           token_files, used)
        return "done (uncertain)"


def guess_field_info_if_absent(first_alert):
    is_fused = False
    if isinstance(first_alert, list) and len(first_alert) == 2 and isinstance(first_alert[1], list):
        first_alert = first_alert[1][0]
        is_fused = True
    if not isinstance(first_alert, dict):
        warn_once(f"Warning: malformed first alert: {first_alert!r}")
        return
    if not glo.alert_id_field:
        for try_field in first_alert.keys():
            lower_try_field = try_field.lower()
            id_pat_1 = r'(?<![a-zA-Z0-9])id(?![a-zA-Z0-9])'
            id_pat_2 = r'(?<![A-Z0-9])ID(?![a-zA-Z0-9])'
            if not re.search(id_pat_1, lower_try_field) and not re.search(id_pat_2, try_field):
                continue
            if ("fused" in lower_try_field) and ((not glo.alert_id_field) or ("alert" in lower_try_field) or ("issue" in lower_try_field)):
                glo.alert_id_field = try_field
                break
            if not glo.alert_id_field:
                glo.alert_id_field = try_field
        if glo.alert_id_field:
            normalized = glo.alert_id_field.lower().replace("fused","").replace(" ","").replace("-","").replace("_","")
            if normalized not in ["id","alertid","issueid"]:
                stderr.write(f"Info: using {glo.alert_id_field} as the Alert_ID field.\n")
        else:
            if is_fused:
                glo.alert_id_field = "Fused_Alert_ID"
    if not glo.fields_for_llm:
        try_fields = "Tool,Path,File,Line,CWE(s),Issue Text,Issue Abstract,Code Snippet".split(",")
        if set(try_fields) <= set(first_alert.keys()):
            glo.fields_for_llm = try_fields


def load_function_from_file(file_path, function_name):
    file_path = Path(file_path).resolve()

    # Create a module spec
    spec = importlib.util.spec_from_file_location("user_module", file_path)
    module = importlib.util.module_from_spec(spec)

    # Load the module
    sys.modules["user_module"] = module
    spec.loader.exec_module(module)

    # Get the function
    func = getattr(module, function_name)
    return func


def load_alerts(args):
    filename_list = args.alerts.split()
    alert_list = []
    for filename in filename_list:
        name = filename.lower()
        is_csv = name.endswith(".csv")
        is_tsv = name.endswith(".tsv")
        cur_alert_list = None
        try:
            if filename.endswith(".json.gz"):
                cur_alert_list = load_json(filename)
            else:
                with open(filename, "r", newline="", encoding="utf-8-sig") as alert_file:
                    if is_csv:
                        cur_alert_list = list(csv.DictReader(alert_file))
                    elif is_tsv:
                        cur_alert_list = list(csv.DictReader(alert_file, delimiter="\t"))
                    else:
                        cur_alert_list = json.load(alert_file)
        except Exception as e:
            stderr.write(str(e) + "\n")
            if is_csv:
                fmt = "CSV"
            elif is_tsv:
                fmt = "TSV"
            else:
                fmt = "JSON"
            die(f"Error: file {filename!r} could not be parsed as {fmt}.")
        if type(cur_alert_list) == dict:
            file_info = cur_alert_list
            cur_alert_list = cur_alert_list.get("alerts")
            if cur_alert_list is None:
                die(f"Error: File {filename!r} is a JSON dict but lacks an \"alerts\" field.")
        if not isinstance(cur_alert_list, list):
            die(f"Error: file {filename!r} is not a list.")
        alert_list.extend(cur_alert_list)

    if args.filter:
        fn_keep_alert = load_function_from_file(args.filter, "keep_alert")
    else:
        fn_keep_alert = None

    has_verdicts = False
    new_alert_list = []
    for alert in alert_list:
        if type(alert) != dict:
            if type(alert) == list and len(alert) == 2:
                subalerts = alert[1]
                is_keeper = False
                for subalert in subalerts:
                    if (not fn_keep_alert) or fn_keep_alert(subalert):
                        is_keeper = True
                if not is_keeper:
                    continue
            new_alert_list.append(alert)
            continue
        else:
            rename_map = {"path":"Path", "file":"File", "line":"Line", "rule":"Rule", "verdict":"Verdict",
                          "base_dir":"Base_Dir"}
            new_alert = {rename_map.get(k,k):v for k,v in alert.items()}
            if len(new_alert) != len(alert):
                warn_once(f"Warning: Fields in alert {alert!r} differ only by case (uppercase vs lowercase)")
            alert = new_alert
            if "Rule" in alert and re.match("[A-Za-z]{3}[0-9]{2}-[A-Z]+", alert["Rule"]):
                alert["Rule"] = glo.cert_rule_id_to_title.get(alert["Rule"], alert["Rule"])
            if "Verdict" in alert:
                has_verdicts = True
            if "Orig_LLM_Query" not in alert:
                if not alert.get("File"):
                    stderr.write(f"Error: Field 'File' is missing in alert {alert!r}\n")
                    continue
                if not alert.get("Line"):
                    stderr.write(f"Error: Field 'Line' is missing in alert {alert!r}\n")
                    continue
                try:
                    alert["Line"] = int(alert["Line"])
                except (TypeError, ValueError):
                    stderr.write(f"Error: Invalid value for 'Line' in alert {alert!r}\n")
                    continue
            if fn_keep_alert:
                if not fn_keep_alert(alert):
                    continue
            new_alert_list.append(alert)
    if has_verdicts:
        if not glo.fields_for_llm and not args.just_add_ids:
            stderr.write("Error: --fields-for-llm (or the LASAA_FIELDS_FOR_LLM env var) must be set if a Verdict field is present in an alert.\n")
            all_keys = {}
            for alert in new_alert_list:
                for key in alert.keys():
                    if key not in all_keys:
                        all_keys[key] = True
            fieldnames = list(all_keys.keys())
            glo.fields_for_llm = [fld for fld in fieldnames if fld not in [glo.alert_id_field, "Verdict"]]
            stderr.write("Suggestion (remove unsuitable fields):\nexport LASAA_FIELDS_FOR_LLM=\"" + ",".join(glo.fields_for_llm) + "\"\n")
            sys.exit(1)
    alert_list = new_alert_list
    return alert_list

def load_cert_rule_titles():
    rule_map = {}
    glo.cert_rule_id_to_title = rule_map
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filename = f"{script_dir}/cert_rule_titles.txt"
    if not os.path.exists(filename):
        return
    try:
        with open(filename, "r") as infile:
            for line in infile:
                line = line.strip()
                if not line:
                    continue
                rule_id = line[:line.index(".")]
                rule_map[rule_id] = line
    except Exception as e:
        stderr.write(str(e) + "\n")

# ===================================================================
# Per-alert base directories and ctags databases
# ===================================================================

def get_alert_base_dir(subalerts, args):
    """Return the base directory for an alert, or None (after printing an error).

    An alert may have a "Base_Dir" field, which overrides --base-dir for that
    alert; a relative Base_Dir is relative to --base-dir.  All subalerts of a
    fused alert must agree on Base_Dir.
    """
    base_dirs = set(subalert.get("Base_Dir") for subalert in subalerts)
    if len(base_dirs) > 1:
        stderr.write(f"Error: subalerts have differing Base_Dir values {sorted(map(str, base_dirs))!r}; "
                     f"skipping alert {subalerts[0].get(glo.alert_id_field)!r}.\n")
        return None
    alert_base_dir = base_dirs.pop()
    if alert_base_dir is None:
        return args.base_dir
    if not isinstance(alert_base_dir, str) or alert_base_dir == "":
        stderr.write(f"Error: invalid Base_Dir {alert_base_dir!r}; "
                     f"skipping alert {subalerts[0].get(glo.alert_id_field)!r}.\n")
        return None
    base_dir = os.path.join(args.base_dir, alert_base_dir)
    if not os.path.isdir(base_dir):
        stderr.write(f"Error: Base_Dir {base_dir!r} is not a directory; "
                     f"skipping alert {subalerts[0].get(glo.alert_id_field)!r}.\n")
        return None
    return base_dir


def get_alert_repo_ref(subalerts):
    """Return (Repo_URL, Repo_Rev) for an alert, or None if it doesn't specify a repo.

    These fields say which repository commit the alert's code is at, so that
    definitions missing from the alert's Base_Dir can be looked up in the full
    repo (see lookup_def_snippets).  Both must be present, and all subalerts of
    a fused alert must agree.
    """
    refs = set((sa.get("Repo_URL"), sa.get("Repo_Rev")) for sa in subalerts)
    if refs == {(None, None)}:
        return None
    if len(refs) > 1 or None in list(refs)[0]:
        warn_once(f"Warning: alert {subalerts[0].get(glo.alert_id_field)!r} has missing or "
                  f"inconsistent Repo_URL/Repo_Rev; ignoring them.")
        return None
    (url, rev) = list(refs)[0]
    return (url, rev)


def run_ctags(src_dir, base_dir, func_bounds_file):
    stdout.write(f"Running ctags on {src_dir!r} and recording function begin/end line numbers...\n")
    import find_func_bounds_with_ctags
    fb_args = [src_dir, "-b", base_dir, "-o", func_bounds_file]
    try:
        find_func_bounds_with_ctags.main(fb_args)
    except Exception as e:
        cmd_line = "./find_func_bounds_with_ctags " + shlex.join(fb_args)
        stderr.write("Command line: " + cmd_line + "\n")
        stderr.write("Error: " + str(e) + "\n")
        sys.exit(1)


def get_func_bounds_db(base_dir, subalerts, args):
    """Return the function-bounds database for alerts relative to *base_dir*.

    Databases are built lazily (running ctags if needed) and cached, so ctags
    runs at most once per distinct base directory.  Alerts without a Base_Dir
    field use --func-bounds (if given) or run ctags on --src-dir.  Alerts with
    a Base_Dir field run ctags on that directory; the result is saved in the
    "func_bounds" subdirectory of the output directory.

    If the func-bounds file already exists and is valid JSON (e.g., from a
    previous run using the same output directory), it is reused and ctags is
    not run.  A partially written file is not valid JSON, so it is regenerated.
    """
    if subalerts[0].get("Base_Dir") is None:
        key = None
    else:
        key = os.path.realpath(base_dir)
    if key in glo.func_bounds_dbs:
        return glo.func_bounds_dbs[key]

    ctags_dir = None
    if key is None:
        func_bounds_file = args.func_bounds
        if not func_bounds_file:
            func_bounds_file = os.path.join(args.output, "func_bounds.json")
            ctags_dir = (args.src_dir, args.base_dir)
    else:
        fb_dir = os.path.join(args.output, "func_bounds")
        os.makedirs(fb_dir, exist_ok=True)
        rel = os.path.relpath(key, os.path.realpath(args.base_dir))
        tag = re.sub(r'[^A-Za-z0-9_.-]+', '_', rel).strip("._")[-80:]
        tag += "-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
        func_bounds_file = os.path.join(fb_dir, f"{tag}.json")
        ctags_dir = (base_dir, base_dir)

    if func_bounds_file == "{}":
        func_bounds_db = {}
    else:
        func_bounds_db = None
        if ctags_dir is not None:
            try:
                func_bounds_db = load_func_bounds_etc(func_bounds_file, base_dir)
                stdout.write(f"Reusing function bounds from {func_bounds_file!r}\n")
            except (FileNotFoundError, json.JSONDecodeError):
                pass   # missing or partially written; (re)compute it below
        if func_bounds_db is None:
            if ctags_dir is not None:
                run_ctags(*ctags_dir, func_bounds_file)
            func_bounds_db = load_func_bounds_etc(func_bounds_file, base_dir)
    glo.func_bounds_dbs[key] = func_bounds_db
    return func_bounds_db


# ===================================================================
# Main
# ===================================================================

def main():
    program_start_time = time.time()

    parser = argparse.ArgumentParser(
        description="Adjudicate static-analysis alerts via an LLM pipeline.  "
                    "Creates .query files; use ask_gpt.py to produce .reply "
                    "files.  Run the two scripts alternately until every alert "
                    "has a .final_answer file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
        """
        Environment variables:
          - LASAA_FIELDS_FOR_LLM="fieldname_1,fieldname_2,...,fieldname_n"
            # which fields in the alert are given to the LLM, and in what order
            # (overridden by --fields-for-llm).
          - LASAA_ALERT_ID_FIELD=fieldname # which field is the unique Alert ID.
        """
        ).strip()
    )

    req_args = True
    if "--just-add-ids" in sys.argv:
        req_args = False

    # --- Locations of files and directories ---
    parser.add_argument("-a", "--alerts", type=str, required=True,
                        help="Alerts JSON file")
    parser.add_argument("--func-bounds",
                        help="File with function start/end line information (not used for alerts that have a \"Base_Dir\" field)")
    parser.add_argument("-o", "--output", required=req_args,
                        help="Output directory")
    parser.add_argument("-b", "--base-dir", required=req_args,
                        help="Project base directory (filepaths in the alerts are relative to this).  "
                             "An alert's \"Base_Dir\" field (if present) overrides this for that alert; "
                             "a relative Base_Dir is relative to this directory.")
    parser.add_argument("-s", "--src-dir",
                        help="Project source-code directory (or a single \".c\" file); ctags is run for files in this directory (and its descendents); defaults to base_dir.  Not used for alerts that have a \"Base_Dir\" field (ctags is run on the Base_Dir instead).")
    parser.add_argument("--copy-used-to", help="Copy used files to this directory")

    # --- full-repo lookup of definitions ---
    parser.add_argument("--repos-dir",
                        help="Directory holding the shared per-project git repos that are downloaded "
                             "on demand when the LLM asks for a definition that isn't in the alert's "
                             "files.  Used only for alerts with \"Repo_URL\" and \"Repo_Rev\" fields.  "
                             "(default: BASE_DIR/repos)")
    parser.add_argument("--repo-size-limit", default="750MB",
                        help="Give up on (and delete) a repo that grows beyond this size while being "
                             "downloaded, e.g. 500MB or 2GB (default: 750MB).  torvalds/linux is "
                             "assumed to exceed any limit of 1GB or less.")
    parser.add_argument("--repo-status-file",
                        help="JSON file recording which commits were downloaded, which failed "
                             "permanently, and which repos exceeded the size limit "
                             "(default: $LASAA_REPO_STATUS_FILE, else REPOS_DIR/download_status.json)")

    # --- pipeline options ---
    parser.add_argument("--dep-as-tp", action="store_true",
                        help="Tell LLM to treat dependent alerts as true positives")
    parser.add_argument("--just-add-ids", type=str, metavar="OUTPUT_FILE",
                        help="Add an Alert_ID column to alert table, write to the given file, and exit")
    parser.add_argument("--hash-for-id", action="store_true",
                        help="Use a hash when adding the Alert ID")
    parser.add_argument("--filter",
                        help="Uses function 'keep_alert' defined in specified Python file to filter alerts")
    parser.add_argument("--issue-id", default=None,
                        help="Process only this alert.  Can specify multiple separated by commas.")
    parser.add_argument("--llm-script",
                        help="Use the specified script instead of ask_gpt.py")
    parser.add_argument("--run-llm", action="store_true",
                        help="Run ask_gpt.py; pass args after '--'.")
    parser.add_argument("--dont-run-llm", action="store_true",
                        help="Only generate \".query\" files; don't send them to the LLM.")
    parser.add_argument("--only-high", type=int, default=0,
                        choices=[0, 1],
                        help="Only process high-priority alerts (default: 0)")
    parser.add_argument("--consistency-check", "--cc", type=int, default=1,
                        help="Enable consistency check (default: 1)")
    parser.add_argument("--simp-maj", action="store_true",
                        help="Use simple majority voting instead of the consistency check; "
                             "ties between pos (true/dep) and neg (false) are broken in favor of pos;"
                             "ties between true and dep are broken in favor of true.")
    parser.add_argument("--llm-resolve", "--lre", type=int, default=1,
                        choices=[0, 1],
                        help="Ask LLM to resolve discordant answers by evaluating their reasoning (default: 1)")
    parser.add_argument("-n", "--num-trials", type=int, default=10,
                        help="Number of trials per stage (default: 10)")
    parser.add_argument("-t", "--threshold",
                        help="Consistency-check threshold.  Forms: 80%%, 0.80, "
                             "or 8/n (default: 80%%).")
    parser.add_argument("--max-need-defs-rounds", type=int, default=10,
                        help="Maximum number of need_defs augmentation rounds")
    parser.add_argument("--need-defs-style", default="verdict", choices=["verdict", "standalone"],
                        help="Wording of the need_defs instructions: 'verdict' (default) asks for "
                        "need_defs alongside a verdict of uncertain; 'standalone' asks the LLM to "
                        "request unseen definitions instead of recalling them, with no verdict")
    parser.add_argument("--lre-prompt-file", metavar="FILE",
                        help="Read the intro of the LRE prompt from FILE instead of "
                        "using the built-in one (leading/trailing whitespace is stripped).  "
                        "The form 'auto:default,FILE_1,...,FILE_n' picks whichever of the "
                        "built-in intro ('default') and the given files was used by the "
                        "existing \".lre.\" query files in the output directory, and fails "
                        "if there are none or they disagree.")
    parser.add_argument("--auto-model", action="store_true",
                        help="Infer the model and reasoning effort from the existing "
                        "\".reply\" files in the output directory, and fail if there are "
                        "none or they disagree.  Models named 'claude-*' are run with "
                        "ask_claude_aws.py (as 'us.anthropic.claude-*'); others with "
                        "ask_gpt.py.  Can't be combined with --llm-script or with --model "
                        "after '--'.  A --reasoning-effort after '--' is used for replies "
                        "that don't record one and must match those that do.")
    parser.add_argument("--tell-unfound", type=int, default=1, choices=[0, 1],
                        help="Tell the LLM which need_defs symbols couldn't be found (default: 1)")
    parser.add_argument("--fields-for-llm", metavar="FIELDS",
                        help="Comma-separated list of the alert fields given to the LLM, "
                             "in order (overrides $LASAA_FIELDS_FOR_LLM).  If neither is "
                             "set, all fields except the Alert ID are given to the LLM.")
    parser.add_argument("--more-ctx-fields", default=DEFAULT_MORE_CTX_FIELDS,
                        help="Comma-separated list of alert top-level fields to "
                             "search for additional functions whose source code "
                             f"is included in the query (default: \"{DEFAULT_MORE_CTX_FIELDS}\")")
    parser.add_argument("--explain-uncertain", action="store_true",
                        help="When uncertain, ask the LLM to explain the "
                             "source of disagreement")
    parser.add_argument("--no-explain-uncertain", action="store_true",
                        help="Do not ask the LLM to explain the source of disagreement for 'uncertain' verdicts")
    parser.add_argument("--tokenize", action="store_true",
                        default=(os.getenv("LASAA_TOKENIZE", "0").lower()
                                 in ["1", "true", "yes"]),
                        help="When a reply lacks token counts and its model is "
                             "gpt-oss-20b/gpt-oss-120b, count the query and reply "
                             "tokens with count_gpt_oss_tokens.py. Can also be "
                             "enabled with LASAA_TOKENIZE=1.")
    parser.add_argument("--guess-token-count", action="store_true",
                        help="When a reply lacks token counts, estimate them as "
                             "file size / 4 (query -> input, reply -> output). "
                             "(Not applicable to closed models that hide reasoning tokens.)")
    parser.add_argument("--tokenizers-dir", default="tokenizers",
                        help="Root directory of GPT-OSS tokenizers, used by "
                             "--tokenize (default: tokenizers).")
    parser.add_argument("--overwrite-manual-adj", action="store_true",
                        help="Process even alerts that already have a manual Fused Adjudication")

    glo.alert_id_field = os.getenv("LASAA_ALERT_ID_FIELD")

    try:
        sep = sys.argv.index("--")
        my_args = sys.argv[1:sep]
        child_args = sys.argv[sep + 1:]
    except ValueError:
        my_args = sys.argv[1:]
        child_args = []

    for i in range(0, len(my_args)-1):
        if my_args[i] == "--cc" and my_args[i+1] == "maj":
            my_args[i] = "--simp-maj"
            my_args[i+1] = "--simp-maj"

    args = parser.parse_args(my_args)

    if args.fields_for_llm is not None:
        glo.fields_for_llm = args.fields_for_llm
        if glo.fields_for_llm:
            print(f"--fields-for-llm={glo.fields_for_llm!r}")
    else:
        glo.fields_for_llm = os.getenv("LASAA_FIELDS_FOR_LLM")
        if glo.fields_for_llm:
            print(f"LASAA_FIELDS_FOR_LLM={glo.fields_for_llm!r}")
    if glo.fields_for_llm:
        glo.fields_for_llm = [x.strip() for x in glo.fields_for_llm.split(",")]

    if args.need_defs_style == "standalone":
        global prompt_intro
        assert prompt_intro.count(need_defs_para_verdict) == 1
        prompt_intro = prompt_intro.replace(need_defs_para_verdict, need_defs_para_standalone)

    if args.lre_prompt_file or args.auto_model:
        if not args.output:
            die("Error: --auto-model and --lre-prompt-file auto:... require -o/--output.")
        if not os.path.isdir(args.output):
            die(f"Error: output directory {args.output!r} doesn't exist; it's needed "
                "by --auto-model and --lre-prompt-file auto:....")

    if args.lre_prompt_file:
        global resolve_prompt_intro
        if args.lre_prompt_file.startswith("auto:"):
            (lre_choice, resolve_prompt_intro) = infer_lre_prompt_intro(
                args.output, args.lre_prompt_file[len("auto:"):])
            print(f"--lre-prompt-file auto: using {lre_choice!r}")
        else:
            resolve_prompt_intro = read_lre_prompt_file(args.lre_prompt_file)

    if args.auto_model:
        if args.llm_script:
            die("Error: --auto-model can't be combined with --llm-script.")
        if get_child_arg(child_args, "--model") is not None:
            die("Error: --auto-model can't be combined with --model (after '--').")
        (model, effort) = infer_llm_settings(
            args.output, get_child_arg(child_args, "--reasoning-effort"))
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if model.startswith("claude-"):
            args.llm_script = os.path.join(script_dir, "ask_claude_aws.py")
            model = "us.anthropic." + model
        else:
            args.llm_script = os.path.join(script_dir, "ask_gpt.py")
        child_args += ["--model", model]
        if effort is not None:
            child_args += ["--reasoning-effort", effort]
        print(f"--auto-model: using {os.path.basename(args.llm_script)} "
              + " ".join(shlex.quote(a) for a in child_args))

    if args.simp_maj:
        conflicting = []
        for tok in my_args:
            flag = tok.split("=", 1)[0]
            if flag in ("--cc", "--consistency-check") and "--cc" not in conflicting:
                conflicting.append("--cc")
            elif flag == "--threshold" and "--threshold" not in conflicting:
                conflicting.append("--threshold")
        if conflicting:
            die("Error: --simp-maj cannot be combined with "
                + " or ".join(conflicting) + ".")

    if not args.src_dir:
        args.src_dir = args.base_dir

    #if not args.num_trials and args.consistency_check > 1:
    #    args.num_trials = args.consistency_check
    if not args.threshold:
        if args.consistency_check > 1:
            args.threshold = str(args.consistency_check)
        else:
            args.threshold = "80%"

    args.threshold = parse_threshold_count(args.threshold, args.num_trials)
    if args.max_need_defs_rounds < 0:
        die("Error: --max-need-defs-rounds must be nonnegative.")

    args.more_ctx_fields = [x.strip() for x in args.more_ctx_fields.split(",") if x.strip()]
    
    if args.run_llm and args.dont_run_llm:
        die("Error: both '--run-llm' and '--dont-run-llm' were specified!")

    if not args.dont_run_llm:
        args.run_llm = True

    if args.llm_script:
        llm_script = os.path.realpath(args.llm_script)
        if not os.path.exists(llm_script):
            die(f"Error: File not found: {llm_script!r}")
        if not os.access(llm_script, os.X_OK):
            die(f"Error: File is not marked as executable: {llm_script!r}")
    
    if (not args.no_explain_uncertain) and (not args.explain_uncertain):
        args.explain_uncertain = (os.getenv("LASAA_EXPLAIN_UNCERT", "1").lower() not in ["0", "false", "no"])
    if args.no_explain_uncertain:
        args.explain_uncertain = False
    
    load_cert_rule_titles()
    alert_list = load_alerts(args)

    if args.just_add_ids:
        new_alert_list = []
        alert_id = 1
        width = len(str(len(alert_list)))
        for old_alert in alert_list:
            if args.hash_for_id:
                alert_id = hashlib.sha256(json.dumps(old_alert).encode("utf-8")).hexdigest()[:24]
                new_alert = {"Alert_ID": alert_id}
            else:
                new_alert = {"Alert_ID": f"{alert_id:0{width}d}"}
                alert_id += 1
            new_alert.update(old_alert)
            new_alert_list.append(new_alert)
        all_keys = {}
        for alert in new_alert_list:
            for key in alert.keys():
                if key not in all_keys:
                    all_keys[key] = True
        fieldnames = list(all_keys.keys())
        filename = args.just_add_ids
        if filename.endswith(".csv"):
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for record in new_alert_list:
                    row = dict(record)
                    writer.writerow(row)
        elif filename.endswith(".json"):
            with open(filename, "w") as outf:
                json.dump(new_alert_list, outf, indent=2)
                outf.write("\n")
        else:
            die(f"Unknown filename extension for filename {filename!r}.")
        sys.exit(0)

    if len(alert_list) == 0:
        print("Alert list is empty!")
        return
    guess_field_info_if_absent(alert_list[0])
    if not glo.alert_id_field:
        die("Error: Missing environment variable LASAA_ALERT_ID_FIELD.")

    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)

    glo.func_bounds_dbs = {}
    glo.repo_cache = None

    unrecognized_verdicts = set()

    if args.run_llm:
        max_rounds = 20
    else:
        max_rounds = 1

    if args.issue_id:
        chosen_issue_ids = args.issue_id.split(",")
    else:
        chosen_issue_ids = []

    # Alerts whose LLM verdict disagrees with the ground-truth Verdict field,
    # plus the ones the LLM declined to decide.  Reset at the start of each
    # round; the lists printed at the end are thus those of the final round.
    any_ground_truth = False
    false_negatives = []   # ground truth "true",  adjudicated "false"
    false_positives = []   # ground truth "false", adjudicated "true" or "dep"
    uncertain_alerts = []  # adjudicated "uncertain"

    for ix_round in range(0, max_rounds):
    
        status_counts = Counter()
        num_alerts = 0
        num_manual_adj = 0

        adjudications = []
        false_negatives = []
        false_positives = []
        uncertain_alerts = []

        seen_alert_ids = set()
        for row in alert_list:
            if isinstance(row, list):
                if len(row) != 2:
                    die(f"Invalid alert: expecting a dict or [AlertID, [subalert_1, .., subalert_N]].\nAlert:{row!r}")
                (fused_id, subalerts) = row
                if not isinstance(subalerts, list):
                    stderr.write(f"Error parsing sub-alert list for alert {fused_id!r}\n")
                    continue
            else:
                fused_id = row[glo.alert_id_field]
                subalerts = [row]
            if type(fused_id) == int:
                fused_id = str(fused_id)
            if type(fused_id) != str or str == "":
                die(f"Bad alert ID {fused_id!r} for alert {row!r}")
            def sanitize_alert_id(s):
                ret = re.sub(r'[^A-Za-z0-9_.-]+', '_', s)
                if ret[0] == "-":
                    ret[0] = "_"
                return ret
            sanitized = sanitize_alert_id(fused_id)
            if fused_id != sanitized:
                stderr.write(f"Bad alert ID {fused_id!r}; sanitized to {sanitized!r}.\n")
                fused_id = sanitized
            fused_id = sanitize_alert_id(fused_id)
            if fused_id in seen_alert_ids:
                stderr.write(f"Error: duplicate Alert_ID {fused_id!r}\n")
                continue
            seen_alert_ids.add(fused_id)
            if args.issue_id and (fused_id not in chosen_issue_ids):
                continue
            if args.only_high:
                is_high_priority = False
                for subalert in subalerts:
                    if subalert["Issue Priority"] in ("High", "Critical"):
                        is_high_priority = True
                if not is_high_priority:
                    continue

            cwes = []
            verdict = None
            valid_verdicts = None
            has_overwritable_adjudication = True
            for subalert in subalerts:
                overwritable_adjs = [None, "", "Unknown", "Confirmed - Assisted", "False Positive - Assisted"]
                if subalert.get("Fused Adjudication") not in overwritable_adjs and not args.overwrite_manual_adj:
                    has_overwritable_adjudication = False
                for cwe in get_cwes_in_alert(subalert):
                    if type(cwe) != str:
                        continue
                    cwe = cwe.strip()
                    if cwe:
                        cwes.append(cwe)
                verdict = verdict or str(subalert.get("Verdict", "")).lower()
                valid_verdicts = valid_verdicts or subalert.get("Valid_Verdicts")
                if type(valid_verdicts) not in [list, tuple]:
                    valid_verdicts = None
                else:
                    valid_verdicts = tuple(valid_verdicts)
            if not has_overwritable_adjudication:
                num_manual_adj += 1
                continue
            if valid_verdicts is None:
                valid_verdicts = ("true", "dependent", "false", "uncertain")
            else:
                if "uncertain" not in valid_verdicts:
                    valid_verdicts += ("uncertain",)

            basename = str(fused_id)
            if verdict:
                any_ground_truth = True
                if verdict == "false":
                    basename += ".good"
                elif verdict == "true":
                    basename += ".bad"
                elif verdict == "dependent":
                    basename += ".dep"
                elif verdict == "complex":
                    pass
                else:
                    unrecognized_verdicts.add(verdict)

            base_dir = get_alert_base_dir(subalerts, args)
            if base_dir is None:
                # get_alert_base_dir already printed an error
                continue
            func_bounds_db = get_func_bounds_db(base_dir, subalerts, args)
            original_prompt = build_original_prompt(subalerts, func_bounds_db, base_dir, args)
            if original_prompt is None:
                # build_original_prompt already printed an error
                continue

            num_alerts += 1
            hint_file = os.path.join(subalerts[0].get("Path", ""), subalerts[0]["File"]) if subalerts[0].get("File") else None
            status = process_alert(basename, original_prompt, valid_verdicts, out_dir, args, func_bounds_db, base_dir,
                                   repo_ref=get_alert_repo_ref(subalerts), hint_file=hint_file)
            final_answer_file = os.path.join(out_dir, f"{basename}.final_answer")
            if os.path.isfile(final_answer_file):
                explanation = read_whole_file(final_answer_file)
                if explanation.startswith("# Model:") and "\n" in explanation:
                    explanation = strip_final_answer_header(explanation).strip()

                llm_verdict = get_verdict_of_reply_file(final_answer_file,
                                                       valid_verdicts=valid_verdicts)
                adjudications.append({
                    glo.alert_id_field: basename,
                    "verdict": llm_verdict,
                    "CWEs": ", ".join(cwes),
                    "explanation": explanation,
                })
                if llm_verdict == "uncertain":
                    uncertain_alerts.append(fused_id)
                elif verdict == "true" and llm_verdict == "false":
                    false_negatives.append(fused_id)
                elif verdict == "false" and llm_verdict in ["true", "dependent"]:
                    false_positives.append(fused_id)
            print(f"{basename}: {status}")
            status_counts[status.split(":")[0].split("(")[0].strip()] += 1

        with open(f"{out_dir}/adjudications.json", "w") as outf:
            json.dump(adjudications, outf, indent=2)
            outf.write("\n")

        # --- summary ---
        if unrecognized_verdicts:
            print("\nUnrecognized verdicts: ", list(sorted(unrecognized_verdicts)))
        print()
        if num_manual_adj > 0:
            print(f"Skipped {num_manual_adj} alerts that have a manual adjudication.")
        print(f"Processed {num_alerts} alerts.")
        print("Summary:")
        for s in sorted(status_counts):
            print(f"  {s}: {status_counts[s]}")
        print("Total time: %5.3f sec" % (time.time() - program_start_time))
        
        # We are done once all alerts have been adjudicated.
        if len(adjudications) == num_alerts:
            break

        if args.run_llm:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            llm_script = script_dir + "/ask_gpt.py"
            if args.llm_script:
                llm_script = os.path.realpath(args.llm_script)
            result = subprocess.run([llm_script, out_dir, "--print-skipped", "0"] + child_args)
            if result.returncode != 0:
                break

    if args.copy_used_to:
        os.makedirs(args.copy_used_to, exist_ok=True)
        for used_file in list(glo.files_used):
            if used_file.endswith(".query"):
                reply_file = used_file[0:len(used_file)-len(".query")] + ".reply"
                if os.path.exists(reply_file):
                    glo.files_used.add(reply_file)
        for used_file in sorted(glo.files_used):
            shutil.copy(used_file, args.copy_used_to)
            
    def print_alert_id_list(label, alert_ids):
        print(f"{label}: [" + ", ".join(alert_ids) + "]")

    print()
    if len(adjudications) != num_alerts:
        print(f"Warning: only {len(adjudications)} of {num_alerts} alerts were "
              "adjudicated; the lists below are incomplete.")
    if any_ground_truth:
        print_alert_id_list("Actually-true alerts incorrectly adjudicated as false",
                            false_negatives)
        print_alert_id_list("Actually-false alerts incorrectly adjudicated as true",
                            false_positives)
        print_alert_id_list("Alerts adjudicated as uncertain", uncertain_alerts)

    if len(glo.already_warned) > 0:
        print(f"Encountered {len(glo.already_warned)} warnings.")
        

if __name__ == "__main__":
    main()
