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
"""Read an adjudicate_alerts.py output directory.

The pipeline isn't imported (see web-ui-design.md, "Architecture"), so this
module re-implements the few file-format rules the UI needs:

- file names:  A.H.orig.runNN.query, A.H.orig.tryKK.reply,
               A.H.augdef.R.runNN.query, A.H.lre.runNN.query,
               A.H.uncert.{query,reply}, A.final_answer
- verdicts:    the last line containing {"verdict": ...} wins
               (parse_verdict.get_verdict_of_reply_file)
- need_defs:   the last {"need_defs": [...]} line (extract_need_defs)
- headers:     "# Model: NAME, reasoning_effort='E', input_tokens: N, ..."
- used sets:   a .final_answer's second line, "# used={...}" (process_alert)

reconstruct_chain() works out which query/reply sets produced a
.final_answer.  It reads them from "# used=" when present; for output written
before that line existed, it uses only file contents: H is the first 8 hex digits of the
SHA-256 of the query text, an augdef prompt extends the prompt before it, and
an LRE or explain-uncertain prompt embeds its phase-1 prompt in a block
headed "### BEGIN Original question (hash=<sha256[:12]>)".
"""

import hashlib
import json
import os
import re

VERDICTS = ("true", "false", "dependent", "uncertain")
GROUND_TRUTH_SUFFIXES = (".good", ".bad", ".dep")

PHASE_FILE_RE = re.compile(
    r'^(?P<base>.+?)\.(?P<hash>[0-9a-f]{8})\.(?P<kind>orig|augdef\.[0-9]+|lre|uncert)\.'
    r'(?:(?P<rt>run|try)(?P<n>[0-9][0-9])\.)?(?P<ext>query|reply)$')
FINAL_ANSWER_RE = re.compile(r'^(?P<base>.+)\.final_answer$')
NEED_DEFS_UNBRACED_RE = re.compile(r'^[\s*`"\']*need_defs[*`"\']*\s*:[\s*]*(?=\[)')
REASONING_RE = re.compile(r'<reasoning_([0-9a-fA-F]+)>\n?(.*?)</reasoning_\1>\n*', re.S)
HEADER_LINE_RE = re.compile(
    r'#\s*(Model:|prompt_tokens|completion_tokens|input_tokens|cached_input_tokens|used=)')


def sanitize_alert_id(s):
    """Map an alert ID to the basename the pipeline uses for its files."""
    ret = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(s))
    if ret.startswith("-"):
        ret = "_" + ret[1:]
    return ret


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        return f.read()


def prompt_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


# -------------------------------------------------------------------
# Reply contents
# -------------------------------------------------------------------

def parse_verdict(text):
    """Return the verdict of a reply, or None (same rule as parse_verdict.py)."""
    for line in reversed(text.split("\n")):
        if '{"verdict":' in line:
            if "}" not in line:
                return None
            line = line[line.index('{"verdict":'):]
            line = line[:line.rindex("}") + 1].strip()
            try:
                v = json.loads(line).get("verdict")
            except (json.JSONDecodeError, AttributeError):
                return None
            return v if v in VERDICTS else None
    return None


def parse_need_defs(text):
    """Return the names in the last need_defs request in *text*, or None."""
    decoder = json.JSONDecoder()
    for line in reversed(text.split("\n")):
        names = None
        try:
            if '{"need_defs":' in line:
                obj = decoder.raw_decode(line, line.index('{"need_defs":'))[0]
                names = obj.get("need_defs")
            else:
                m = NEED_DEFS_UNBRACED_RE.match(line)
                if m:
                    names = decoder.raw_decode(line, m.end())[0]
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass
        if isinstance(names, list) and names:
            return [str(n) for n in names]
    return None


def strip_reply_header(text):
    """Remove the leading "# Model:" / token-count header lines."""
    lines = text.split("\n")
    i = 0
    while i < len(lines) and HEADER_LINE_RE.match(lines[i]):
        i += 1
    return "\n".join(lines[i:]).lstrip("\n")


def split_reasoning(body):
    """Split a header-less reply into (reasoning or None, answer text)."""
    m = REASONING_RE.match(body)
    if not m:
        return None, body
    return m.group(2), body[m.end():]


def parse_header(text):
    """Return a dict of what the "# Model:" header lines say."""
    header = []
    for line in text.split("\n"):
        if not line.startswith("#"):
            break
        header.append(line)
    h = "\n".join(header)
    info = {"model": None, "effort": None, "input_tokens": None,
            "cached_input_tokens": None, "output_tokens": None,
            "reasoning_tokens": None, "opts": None, "used": None}
    m = re.search(r'#\s*Model:\s*([^,#\n]+)', h)
    if m:
        info["model"] = m.group(1).strip()
    m = re.search(r"reasoning_effort\s*=\s*'([^']*)'", h)
    if m:
        info["effort"] = m.group(1)
    for key, pat in (
            ("input_tokens", r'(?<![A-Za-z0-9_])(?:input_tokens|prompt_tokens)\s*[=:]\s*([0-9]+)'),
            ("cached_input_tokens", r'(?<![A-Za-z0-9_])(?:cached_input_tokens|cached_tokens)\s*[=:]\s*([0-9]+)'),
            ("output_tokens", r'(?:output[_ ]tokens|completion_tokens)\s*[=:]\s*([0-9]+)'),
            ("reasoning_tokens", r'reasoning_tokens\s*[=:]\s*([0-9]+)')):
        m = re.search(pat, h)
        if m:
            info[key] = int(m.group(1))
    for key, pat in (("opts", r'# opts=(\{.*\})\s*$'), ("used", r'^# used=(\{.*\})\s*$')):
        m = re.search(pat, h, re.M)
        if m:
            try:
                info[key] = json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
    return info


def parse_reply(text):
    """Return the facts the UI shows about one reply file."""
    info = parse_header(text)
    body = strip_reply_header(text)
    reasoning, answer = split_reasoning(body)
    verdict = parse_verdict(text)
    need_defs = parse_need_defs(text)
    if verdict is None and need_defs:
        verdict = "uncertain"   # a need_defs-only reply counts as uncertain
    info.update(verdict=verdict, need_defs=need_defs, body=body,
                reasoning=reasoning, answer=answer)
    return info


# -------------------------------------------------------------------
# Scanning a directory
# -------------------------------------------------------------------

class PhaseSet:
    """One prompt (query file) and its replies."""

    def __init__(self, kind, hash_):
        self.kind = kind        # orig | augdef.R | lre | uncert
        self.hash = hash_
        self.query = None       # file name
        self.run_n = None       # NN of .runNN.query
        self.query_mtime = 0.0
        self.replies = {}       # trial number -> file name ("uncert": trial 0)

    @property
    def key(self):
        return f"{self.hash}.{self.kind}"

    @property
    def is_phase1(self):
        return self.kind == "orig" or self.kind.startswith("augdef.")

    @property
    def augdef_round(self):
        return int(self.kind.split(".")[1]) if self.kind.startswith("augdef.") else -1

    def __repr__(self):
        return f"PhaseSet({self.key}, query={self.query}, replies={sorted(self.replies)})"


def scan_dir(out_dir):
    """Group the files of *out_dir* by basename.

    Returns {basename: {"sets": {key: PhaseSet}, "final_answer": name or None}}.
    """
    groups = {}
    for name in sorted(os.listdir(out_dir)):
        m = PHASE_FILE_RE.match(name)
        if m:
            g = groups.setdefault(m["base"], {"sets": {}, "final_answer": None})
            key = f"{m['hash']}.{m['kind']}"
            ps = g["sets"].get(key)
            if ps is None:
                ps = g["sets"][key] = PhaseSet(m["kind"], m["hash"])
            if m["ext"] == "query":
                ps.query = name
                ps.run_n = int(m["n"]) if m["n"] else None
                ps.query_mtime = os.stat(os.path.join(out_dir, name)).st_mtime
            elif m["rt"] == "try":
                ps.replies[int(m["n"])] = name
            else:
                ps.replies[0] = name
            continue
        m = FINAL_ANSWER_RE.match(name)
        if m:
            g = groups.setdefault(m["base"], {"sets": {}, "final_answer": None})
            g["final_answer"] = name
    return groups


def basename_to_alert_id(basename, sanitized_ids):
    """Map an output basename back to an alert ID (see the .good/.bad/.dep suffixes)."""
    if basename in sanitized_ids:
        return sanitized_ids[basename]
    for suffix in GROUND_TRUTH_SUFFIXES:
        if basename.endswith(suffix) and basename[:-len(suffix)] in sanitized_ids:
            return sanitized_ids[basename[:-len(suffix)]]
    return None


# -------------------------------------------------------------------
# Reconstructing the chain behind a .final_answer
# -------------------------------------------------------------------

def _orig_question_marker(phase1_text):
    block = phase1_text if phase1_text.endswith("\n") else phase1_text + "\n"
    h = hashlib.sha256(block.encode("utf-8")).hexdigest()[:12]
    return f"### BEGIN Original question (hash={h})"


def _same_answer(final_body, reply_text):
    """True if *final_body* is the body of *reply_text* (possibly plus a verdict line)."""
    body = strip_reply_header(reply_text).rstrip("\n")
    fb = final_body.rstrip("\n")
    return fb == body or (fb.startswith(body) and fb[len(body):].strip().startswith('{"verdict":'))


def reconstruct_chain(group, read):
    """Work out the query/reply sets behind one alert's .final_answer.

    *group* is one value of scan_dir(); *read(name)* returns a file's text.
    Returns a dict with:
      opts        the final answer's # opts= (or None)
      phase1      [PhaseSet, ...], from orig through the last augdef round
      lre         PhaseSet or None
      uncert      PhaseSet or None
      n1, n2      trials used from the last phase-1 set and from the LRE set
      warnings    [str]: anything the reconstruction had to guess
    Works without a .final_answer too (a dry run, or a run in progress), using
    the newest sets on disk.
    """
    if group["final_answer"]:
        info = parse_header(read(group["final_answer"]))
        if isinstance(info["used"], dict):
            return _chain_from_used(group, info["opts"], info["used"])
    sets = list(group["sets"].values())
    warnings = []
    texts = {}

    def qtext(ps):
        if ps.query is None:
            return None
        if ps.query not in texts:
            texts[ps.query] = read(ps.query)
        return texts[ps.query]

    final_body = None
    opts = None
    if group["final_answer"]:
        fa_text = read(group["final_answer"])
        opts = parse_header(fa_text)["opts"]
        final_body = strip_reply_header(fa_text)
    n1 = (opts or {}).get("N") or 0
    use_cc = bool((opts or {}).get("CC")) or bool((opts or {}).get("simp_maj"))
    n2 = (n1 if use_cc else 1) if opts else 0

    phase1_sets = [ps for ps in sets if ps.is_phase1 and ps.query]
    lre_sets = [ps for ps in sets if ps.kind == "lre" and ps.query]
    uncert_sets = [ps for ps in sets if ps.kind == "uncert"]

    def lre_for(p1):
        if p1 is None or qtext(p1) is None:
            return None
        marker = _orig_question_marker(qtext(p1))
        found = [ps for ps in lre_sets if marker in qtext(ps)]
        return found[-1] if found else None

    def phase1_for_embedding(ps):
        """The phase-1 set whose prompt is embedded in LRE/uncert set *ps*."""
        text = qtext(ps) or ""
        for p1 in phase1_sets:
            if _orig_question_marker(qtext(p1)) in text:
                return p1
        return None

    last_p1 = lre = uncert = None
    if final_body is not None:
        # The reply the final answer was copied from identifies the deciding set.
        for ps in uncert_sets:
            if 0 in ps.replies and _same_answer(final_body, read(ps.replies[0])):
                uncert = ps
                break
        if uncert is not None:
            last_p1 = phase1_for_embedding(uncert)
            if last_p1 is None:
                warnings.append("explain-uncertain query names no phase-1 prompt on disk")
        else:
            for ps in lre_sets + phase1_sets:
                limit = n2 if ps.kind == "lre" else n1
                if any(_same_answer(final_body, read(ps.replies[i]))
                       for i in range(limit) if i in ps.replies):
                    if ps.kind == "lre":
                        lre = ps
                        last_p1 = phase1_for_embedding(ps)
                    else:
                        last_p1 = ps
                    break
    if last_p1 is None:
        # No final answer, or none of the replies matches it (e.g. "uncertain"
        # without an explanation): take the newest phase-1 prompt that no
        # other phase-1 prompt extends.
        leaves = [ps for ps in phase1_sets
                  if not any(o is not ps and qtext(o).startswith(qtext(ps)) for o in phase1_sets)]
        leaves.sort(key=lambda ps: (ps.query_mtime, ps.augdef_round))
        if leaves:
            last_p1 = leaves[-1]
            if final_body is not None:
                warnings.append("final answer matches no reply; chose the newest prompt")
            if len(leaves) > 1:
                warnings.append(f"{len(leaves)} unrelated prompts on disk; chose the newest")
    if last_p1 is not None and lre is None and (opts or {}).get("LRE", True):
        lre = lre_for(last_p1)

    # Walk back from the last phase-1 set through the augdef rounds to orig.
    chain = []
    cur = last_p1
    while cur is not None:
        chain.append(cur)
        if cur.kind == "orig":
            break
        prev_kind = "orig" if cur.augdef_round == 0 else f"augdef.{cur.augdef_round - 1}"
        cur_text = qtext(cur)
        cands = [ps for ps in phase1_sets if ps.kind == prev_kind
                 and len(qtext(ps)) < len(cur_text) and cur_text.startswith(qtext(ps))]
        if not cands:
            warnings.append(f"no {prev_kind} prompt on disk that {cur.kind} extends")
            break
        cur = max(cands, key=lambda ps: len(qtext(ps)))
    chain.reverse()

    if not n1 and chain:
        n1 = chain[-1].run_n or 0
    if not n2 and lre is not None:
        n2 = lre.run_n or 0
    return {"opts": opts, "phase1": chain, "lre": lre, "uncert": uncert,
            "n1": n1, "n2": n2, "warnings": warnings}


def _chain_from_used(group, opts, used):
    """reconstruct_chain() for a .final_answer that has a "# used=" line."""
    warnings = []

    def get(stem):
        if not stem:
            return None
        ps = group["sets"].get(stem)
        if ps is None:
            warnings.append(f"{stem}, named in the final answer, is not on disk")
        return ps

    phase1 = [ps for ps in map(get, used.get("phase1") or []) if ps is not None]
    return {"opts": opts, "phase1": phase1, "lre": get(used.get("lre")),
            "uncert": get(used.get("uncert")), "n1": used.get("n1") or 0,
            "n2": used.get("n2") or 0, "warnings": warnings}


def added_definitions(chain, read):
    """Return [(round, text)]: what each augdef round appended to the prompt."""
    out = []
    for prev, cur in zip(chain, chain[1:]):
        out.append((cur.augdef_round, read(cur.query)[len(read(prev.query)):].lstrip("\n")))
    return out
