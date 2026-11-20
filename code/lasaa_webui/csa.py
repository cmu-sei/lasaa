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
"""Clang Static Analyzer over a compilation database.

  python3 -m lasaa_webui.csa COMPILE_COMMANDS.json OUT_DIR --root SRC [--preset P] [-j N]

Runs `clang --analyze --analyzer-output sarif` once per entry, in parallel,
writing OUT_DIR/units/NNNN.sarif, and merges them into OUT_DIR/merged.sarif:
one run, rules and artifacts merged, duplicate results (an alert in a header
that several translation units include) dropped, and the URIs of files under
SRC made relative to it (uriBaseId SRCROOT), so conv/sarif_to_lasaa.py gives
the same paths, and so the same Alert_IDs, wherever the workspace is.
OUT_DIR/summary.json lists the units and the ones that failed.  The exit
status is 0 if at least one unit was analyzed.

The compile flags are filtered to the ones that change what the
preprocessor and parser see (include paths, macros, language standard,
target), since the build compiler may be GCC and use flags clang lacks.
"""

import argparse
import concurrent.futures
import json
import os
import shlex
import subprocess
import sys
from urllib.parse import quote, unquote

# Checker presets.  "default" is clang's default set (core, unix, cplusplus,
# deadcode, nullability, and some security.insecureAPI checkers) without
# dead stores, which are style noise, and with alpha.unix.Stream (FILE*
# leaks and misuse).  "security" adds alpha security and buffer checkers.
# Checkers this clang doesn't have are left out, with a note.
PRESETS = {
    "default": {"enable": ["alpha.unix.Stream"], "disable": ["deadcode.DeadStores"]},
    "security": {"enable": ["alpha.unix.Stream", "alpha.security.ArrayBoundV2",
                            "alpha.security.MallocOverflow", "alpha.security.ReturnPtrRange",
                            "alpha.security.cert.env.InvalidPtr",
                            "alpha.security.taint.TaintPropagation",
                            "alpha.unix.cstring.BufferOverlap",
                            "alpha.unix.cstring.NotNullTerminated",
                            "alpha.unix.cstring.OutOfBounds", "security.FloatLoopCounter"],
                 "disable": ["deadcode.DeadStores"]},
}
CXX_EXTENSIONS = frozenset(".cc .cp .cpp .cxx .c++ .C .CPP .CXX .ii".split())
SOURCE_EXTENSIONS = CXX_EXTENSIONS | {".c", ".i"}
# Flags kept from the build's command line: with a separate value, or with
# the value joined on.
VALUE_FLAGS = ("-I", "-D", "-U", "-include", "-imacros", "-isystem", "-iquote", "-idirafter",
               "-isysroot", "--sysroot", "-x", "-target", "--target")
JOINED_PREFIXES = ("-I", "-D", "-U", "-std=", "--std=", "-isystem", "-iquote", "-idirafter",
                   "--sysroot=", "--target=", "-include")
EXACT_FLAGS = frozenset(("-m32", "-m64", "-ansi", "-nostdinc", "-nostdinc++", "-pthread",
                         "-funsigned-char", "-fsigned-char", "-fno-signed-char",
                         "-fno-unsigned-char", "-fms-extensions", "-fno-exceptions",
                         "-fexceptions", "-fno-rtti", "-fgnu89-inline", "-fno-builtin",
                         "-ffreestanding", "-fshort-wchar", "-fopenmp"))
# Flags whose separate value is dropped along with them.
DROP_VALUE_FLAGS = frozenset(("-o", "-MF", "-MT", "-MQ", "-include-pch", "-Xclang", "-Xlinker",
                              "-L", "-l", "-arch"))


def entry_args(entry):
    args = entry.get("arguments")
    if args is None:
        args = shlex.split(entry.get("command", ""))
    return list(args)


def is_cxx(entry):
    args = entry_args(entry)
    compiler = os.path.basename(args[0]) if args else ""
    return "++" in compiler or os.path.splitext(entry["file"])[1] in CXX_EXTENSIONS


def compile_flags(entry):
    """The flags of *entry* that clang should see, without the compiler,
    the input files, -c, -o, dependency outputs, warnings, and code
    generation options."""
    args = entry_args(entry)[1:]
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a in VALUE_FLAGS and i + 1 < len(args):
            out += [a, args[i + 1]]
            i += 2
            continue
        if a in DROP_VALUE_FLAGS:
            i += 2
            continue
        if a in EXACT_FLAGS or (a.startswith(JOINED_PREFIXES) and a not in VALUE_FLAGS
                                and not a.startswith("-include-pch")):
            out.append(a)
        i += 1
    return out


def units(compdb):
    """The entries of *compdb* that clang can analyze, without exact
    duplicates (a file compiled twice with the same flags)."""
    seen, out = set(), []
    for e in compdb:
        if os.path.splitext(e.get("file", ""))[1] not in SOURCE_EXTENSIONS:
            continue
        file = os.path.normpath(os.path.join(e["directory"], e["file"]))
        key = (e["directory"], file, tuple(compile_flags(e)))
        if key not in seen:
            seen.add(key)
            out.append(dict(e, file=file))
    return out


def clang_for(entry, clang="clang"):
    return clang + "++" if is_cxx(entry) and not clang.endswith("++") else clang


def deps_command(entry, clang="clang"):
    """A command that prints the make rule of every file *entry* reads."""
    return [clang_for(entry, clang), "-M", "-MT", "x"] + compile_flags(entry) + [entry["file"]]


def parse_deps(text):
    """The file names in `clang -M` output ("x: a.c b.h \\\\\\n c.h")."""
    body = text.replace("\\\n", " ")
    body = body.split(":", 1)[1] if ":" in body else ""
    names, cur, i = [], "", 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] in " #":
            cur += body[i + 1]
            i += 2
            continue
        if ch.isspace():
            if cur:
                names.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    if cur:
        names.append(cur)
    return names


def available_checkers(clang="clang"):
    out = set()
    for flag in ("-analyzer-checker-help", "-analyzer-checker-help-alpha"):
        r = subprocess.run([clang, "-cc1", flag], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.split()
            # "  core.DivideZero   Description"; continuation lines are indented more.
            if parts and line.startswith("  ") and not line.startswith("   ") and "." in parts[0]:
                out.add(parts[0])
    return out


def checker_flags(preset, available, log=print):
    p = PRESETS[preset]
    flags = []
    for kind, names in (("checker", p["enable"]), ("disable-checker", p["disable"])):
        for name in names:
            if available and name not in available:
                log(f"Note: this clang has no checker {name}; leaving it out.")
                continue
            flags += ["-Xanalyzer", f"-analyzer-{kind}={name}"]
    return flags


def analyze_unit(entry, out_path, checkers, clang="clang"):
    cmd = ([clang_for(entry, clang), "--analyze", "--analyzer-output", "sarif", "-o", out_path]
           + checkers + compile_flags(entry) + [entry["file"]])
    r = subprocess.run(cmd, cwd=entry["directory"], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    return cmd, r


# -------------------------------------------------------------------
# Merging
# -------------------------------------------------------------------

def walk_artifact_locations(obj, fn):
    """Call fn on every dict that has an 'artifactLocation' key."""
    if isinstance(obj, dict):
        if "artifactLocation" in obj:
            fn(obj["artifactLocation"])
        for v in obj.values():
            walk_artifact_locations(v, fn)
    elif isinstance(obj, list):
        for v in obj:
            walk_artifact_locations(v, fn)


def relative_uri(uri, root):
    """(uri, uriBaseId): *uri* relative to *root* if it names a file under it."""
    if not uri.startswith("file://"):
        return uri, None
    path = os.path.normpath(unquote(uri[len("file://"):]))
    root = os.path.normpath(root)
    if path.startswith(root + os.sep):
        return quote(os.path.relpath(path, root)), "SRCROOT"
    return uri, None


def merge(paths, root):
    """Merge the SARIF files *paths* into one run; return (sarif, n duplicates)."""
    merged = base_run = None
    rules, rule_idx = [], {}
    artifacts, art_idx = [], {}
    results, seen, n_dup = [], set(), 0
    for path in paths:
        with open(path, encoding="utf-8") as f:
            sarif = json.load(f)
        for run in sarif.get("runs", []):
            if merged is None:
                merged = {k: v for k, v in sarif.items() if k != "runs"}
                base_run = {k: v for k, v in run.items()
                            if k not in ("results", "artifacts", "invocations")}
            run_rules = run.get("tool", {}).get("driver", {}).get("rules", [])
            run_arts = run.get("artifacts", [])

            def fix_art(loc, run_arts=run_arts):
                uri = loc.get("uri")
                if uri is None and "index" in loc and loc["index"] < len(run_arts):
                    uri = run_arts[loc["index"]]["location"]["uri"]
                if uri is None:
                    return
                uri, base = relative_uri(uri, root)
                loc["uri"] = uri
                if base:
                    loc["uriBaseId"] = base
                if (uri, base) not in art_idx:
                    art_idx[(uri, base)] = len(artifacts)
                    artifacts.append({"location": dict(uri=uri, **({"uriBaseId": base}
                                                                   if base else {}))})
                loc["index"] = art_idx[(uri, base)]

            for res in run.get("results", []):
                walk_artifact_locations(res, fix_art)
                rid = res.get("ruleId")
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                region = loc.get("region", {})
                key = (rid, loc.get("artifactLocation", {}).get("uri"),
                       region.get("startLine"), region.get("startColumn"),
                       res.get("message", {}).get("text"))
                if key in seen:
                    n_dup += 1
                    continue
                seen.add(key)
                if rid is not None:
                    if rid not in rule_idx:
                        rule_idx[rid] = len(rules)
                        rules.append(next((r for r in run_rules if r.get("id") == rid),
                                          {"id": rid}))
                    res["ruleIndex"] = rule_idx[rid]
                results.append(res)
    if merged is None:
        merged = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0"}
        base_run = {"tool": {"driver": {"name": "clang"}}}
    base_run.setdefault("tool", {}).setdefault("driver", {})["rules"] = rules
    base_run["originalUriBaseIds"] = {
        "SRCROOT": {"description": {"text": "The root of the analyzed source tree"}}}
    base_run["artifacts"] = artifacts
    base_run["results"] = results
    merged["runs"] = [base_run]
    return merged, n_dup


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("compdb", help="compile_commands.json")
    ap.add_argument("out_dir")
    ap.add_argument("--root", required=True,
                    help="source tree root; SARIF URIs under it are made relative")
    ap.add_argument("--preset", choices=sorted(PRESETS), default="default")
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--clang", default="clang")
    args = ap.parse_args(argv)

    with open(args.compdb, encoding="utf-8") as f:
        todo = units(json.load(f))
    if not todo:
        sys.exit("The compilation database has no C or C++ files to analyze.")
    unit_dir = os.path.join(args.out_dir, "units")
    os.makedirs(unit_dir, exist_ok=True)
    checkers = checker_flags(args.preset, available_checkers(args.clang))
    print(f"Analyzing {len(todo)} translation unit(s) with {args.jobs} job(s); "
          f"checkers: {' '.join(c for c in checkers if c != '-Xanalyzer') or 'default'}",
          flush=True)
    root = os.path.realpath(args.root)

    def one(i):
        out = os.path.join(unit_dir, f"{i:04d}.sarif")
        if os.path.exists(out):
            os.remove(out)
        return analyze_unit(todo[i], out, checkers, args.clang) + (out,)

    failed, done = [], []
    with concurrent.futures.ThreadPoolExecutor(max(1, args.jobs)) as pool:
        futs = {pool.submit(one, i): i for i in range(len(todo))}
        for n, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            i = futs[fut]
            cmd, r, out = fut.result()
            rel = os.path.relpath(todo[i]["file"], root)
            if r.returncode != 0 or not os.path.exists(out):
                failed.append({"file": rel, "status": r.returncode,
                               "command": shlex.join(cmd), "stderr": r.stderr[-4000:]})
                tail = "\n    ".join(r.stderr.strip().splitlines()[-6:])
                print(f"[{n}/{len(todo)}] {rel}: failed (exit status {r.returncode})\n"
                      f"    $ {shlex.join(cmd)}\n    {tail}", flush=True)
            else:
                done.append((i, out))
                with open(out, encoding="utf-8") as f:
                    k = sum(len(run.get("results", [])) for run in json.load(f).get("runs", []))
                print(f"[{n}/{len(todo)}] {rel}: {k} result(s)", flush=True)

    sarif, n_dup = merge([out for _, out in sorted(done)], root)
    with open(os.path.join(args.out_dir, "merged.sarif"), "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=1)
        f.write("\n")
    n = len(sarif["runs"][0]["results"])
    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump({"units": len(todo), "analyzed": len(done), "failed": failed,
                   "results": n, "duplicates_dropped": n_dup}, f, indent=1)
    print(f"{n} result(s) from {len(done)} of {len(todo)} unit(s)"
          + (f"; dropped {n_dup} duplicate(s) from headers" if n_dup else "")
          + (f"; {len(failed)} unit(s) failed" if failed else "") + ".")
    if not done:
        sys.exit("Every translation unit failed.")


if __name__ == "__main__":
    main()
