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
"""Freezing a source tree into a snapshot's read-only src/ directory."""

import concurrent.futures
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import csa

# The extensions that find_func_bounds_with_ctags.py's ctags run maps to C,
# C++, and Java (`ctags --list-maps=C`, and so on).  The pipeline gets functions
# and need_defs definitions only from these files, so freezing them gives a
# re-run on the snapshot the same context (and so the same prompt hashes).
# Case-sensitive, as in ctags: ".C" and ".H" are C++.
SOURCE_EXTENSIONS = frozenset(
    ".c .c++ .cc .cp .cpp .cxx .h .h++ .hh .hp .hpp .hxx .inl .C .H .CPP .CXX .java".split())
# Build files, kept so that a reviewer can open them.
BUILD_FILE_GLOBS = ("Makefile", "makefile", "GNUmakefile", "*.mk", "CMakeLists.txt",
                    "*.cmake", "configure.ac", "meson.build")
DEFAULT_MAX_TEXT_BYTES = 10 * 1024 * 1024
CODE_DIR = Path(__file__).resolve().parent.parent


def is_source(rel):
    """True if the file *rel* would be kept by the default whitelist."""
    name = os.path.basename(rel)
    return (os.path.splitext(name)[1] in SOURCE_EXTENSIONS
            or any(fnmatch.fnmatchcase(name, g) for g in BUILD_FILE_GLOBS))


def is_binary(path):
    with open(path, "rb") as f:
        return b"\0" in f.read(8192)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _excluded(rel, patterns):
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.rstrip("/") + "/*")
               for p in patterns)


def freeze(origin, dest, excludes=(), prev=None, max_bytes=DEFAULT_MAX_TEXT_BYTES,
           includes=(), only=(), keep=(), dirs=()):
    """Copy the source files of *origin* into *dest* and make it read-only.

    A file is kept if it passes the whitelist (is_source(), plus the globs in
    *includes*; if *only* is nonempty, its globs replace the whitelist) or
    its path is in *keep* (the files that the alerts name), and it doesn't
    match *excludes*.  Globs are relative to *origin*.  Skips .git, binary
    files (a NUL in the first 8 KB), files over *max_bytes*, and symlinks
    that point outside *origin* (symlinks inside it are copied as the files
    they point to).  Files with the same hash as in *prev* (a (src dir,
    manifest files dict) pair for the previous snapshot) are hard-linked to
    it.  The directories in *dirs* (relative to *origin*) are made even if
    they hold no kept files, since a compile command may run in one.

    Returns (files, skipped, n_other): {relpath: sha256}, [{path, reason}],
    and the number of files left out because they aren't on the whitelist.
    """
    origin = os.path.realpath(origin)
    files, skipped, n_other = {}, [], 0
    keep = {os.path.normpath(k) for k in keep}
    prev_src, prev_files = prev if prev else (None, {})
    for dirpath, dirnames, filenames in os.walk(origin):
        rel_dir = os.path.relpath(dirpath, origin)
        rel_dir = "" if rel_dir == "." else rel_dir
        subdirs = []
        for d in sorted(dirnames):
            rel = os.path.join(rel_dir, d)
            full = os.path.join(dirpath, d)
            if d == ".git" or _excluded(rel, excludes):
                continue
            if os.path.islink(full):
                skipped.append({"path": rel, "reason": "symlinked directory"})
                continue
            subdirs.append(d)
        dirnames[:] = subdirs
        for name in sorted(filenames):
            rel = os.path.join(rel_dir, name)
            full = os.path.join(dirpath, name)
            if _excluded(rel, excludes):
                continue
            wanted = _excluded(rel, only) if only else (is_source(rel) or _excluded(rel, includes))
            if not (wanted or rel in keep):
                n_other += 1
                continue
            if os.path.islink(full):
                target = os.path.realpath(full)
                if not (target.startswith(origin + os.sep) and os.path.isfile(target)):
                    skipped.append({"path": rel, "reason": "symlink outside the tree"})
                    continue
                full = target
            if not os.path.isfile(full):
                continue
            if is_binary(full):
                skipped.append({"path": rel, "reason": "binary"})
                continue
            if os.path.getsize(full) > max_bytes:
                skipped.append({"path": rel, "reason": f"over {max_bytes} bytes"})
                continue
            digest = sha256_file(full)
            out = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            linked = False
            if prev_src and prev_files.get(rel) == digest:
                try:
                    os.link(os.path.join(prev_src, rel), out)
                    linked = True
                except OSError:
                    pass
            if not linked:
                shutil.copyfile(full, out)
            files[rel] = digest
    os.makedirs(dest, exist_ok=True)
    for d in dirs:
        full = os.path.normpath(os.path.join(dest, d))
        if full.startswith(os.path.normpath(dest) + os.sep):
            os.makedirs(full, exist_ok=True)
    make_read_only(dest)
    return files, skipped, n_other


def make_read_only(top):
    for dirpath, dirnames, filenames in os.walk(top, topdown=False):
        for name in filenames:
            p = os.path.join(dirpath, name)
            os.chmod(p, stat.S_IMODE(os.lstat(p).st_mode) & ~0o222)
        os.chmod(dirpath, stat.S_IMODE(os.lstat(dirpath).st_mode) & ~0o222)


def remove_tree(top):
    """Delete *top*, including read-only files and directories."""
    def onerror(func, path, _exc):
        os.chmod(os.path.dirname(path), 0o700)
        if os.path.isdir(path) and not os.path.islink(path):
            os.chmod(path, 0o700)
        func(path)
    if os.path.lexists(top):
        os.chmod(top, 0o700)
        shutil.rmtree(top, onerror=onerror)


def copy_tree(origin, dest):
    """Copy all of *origin* except .git to *dest*, for the build (which may
    need any file).  Symlinks stay symlinks."""
    shutil.copytree(origin, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))


# Builds run as this uid and gid when the server runs as root (as in the
# Docker image), so that a build can't read the server's environment, the
# workspace, or root's files, or write files owned by root.  It isn't a
# sandbox: the build still has the network and whatever this uid may read
# or write.  Dockerfile.web-ui names it lasaa-build; no account is needed.
BUILD_UID = BUILD_GID = 65532
BUILD_USER = "lasaa-build"


def builds_as_build_user():
    return os.geteuid() == 0


def chown_tree(top, uid, gid):
    """Give *top* and everything under it to *uid*:*gid*, without
    following symlinks."""
    os.lchown(top, uid, gid)
    for dirpath, dirnames, filenames in os.walk(top):
        for name in dirnames + filenames:
            os.lchown(os.path.join(dirpath, name), uid, gid)


def as_build_user(cmd):
    """*cmd* run as BUILD_UID, with no supplementary groups and no way to
    gain privileges again (setuid programs don't elevate)."""
    return ["setpriv", f"--reuid={BUILD_UID}", f"--regid={BUILD_GID}", "--clear-groups",
            "--no-new-privs", "--", *cmd]


def kill_build_processes():
    """Kill every process running as BUILD_UID, including any that a build
    left running in the background (outside its process group).  kill(-1)
    from that uid reaches all of them (but itself) in one call, so a process
    that keeps forking can't outrun it.  Returns how many were left (0)."""
    left = build_pids()
    for _ in range(10):
        if not left:
            break
        subprocess.run(as_build_user(["kill", "-KILL", "-1"]),
                       capture_output=True, stdin=subprocess.DEVNULL)
        time.sleep(0.05)
        left = build_pids()
    return len(left)


def build_pids():
    """The processes whose real or effective uid is BUILD_UID (from /proc)."""
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/status") as f:
                uids = next(line for line in f if line.startswith("Uid:")).split()[1:3]
        except (OSError, StopIteration):
            continue        # gone already
        if str(BUILD_UID) in uids:
            pids.append(int(name))
    return pids


def read_untrusted_file(path, limit=200 * 1024 * 1024):
    """The bytes of the regular file *path*, which a build may control: a
    symlink or anything but a regular file reads as b""."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return b""
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return b""
        return f.read(limit)


def build_inputs(compdb, work, env=None, log=print):
    """({files}, {directories}) under *work*, relative to it, that the
    compile commands in *compdb* read (from `clang -M`) and run in.  The
    snapshot keeps them, so that Clang Static Analyzer can compile from
    src/ (headers with other extensions, such as .inc or .def, and
    generated files included).  A unit whose dependencies can't be listed
    keeps only its own file."""
    work = os.path.realpath(work)
    files, dirs, failed = set(), set(), 0

    def rel(path, cwd):
        full = os.path.realpath(os.path.join(cwd, path))
        if full.startswith(work + os.sep):
            return os.path.relpath(full, work)
        return None

    def deps(e):
        r = subprocess.run(csa.deps_command(e), cwd=e["directory"], capture_output=True,
                           text=True, env=env, stdin=subprocess.DEVNULL)
        return e, (csa.parse_deps(r.stdout) if r.returncode == 0 else None)

    entries = [e for e in csa.units(compdb) if os.path.isdir(e["directory"])]
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 1) as pool:
        for e, names in pool.map(deps, entries):
            d = rel(".", e["directory"])      # None for work itself
            if d is not None:
                dirs.add(d)
            if names is None:
                failed += 1
                names = [e["file"]]
            files.update(r for r in (rel(n, e["directory"]) for n in names) if r)
    if failed:
        log(f"  Note: couldn't list the headers of {failed} unit(s); kept only their source files.")
    return files, dirs


def rewrite_compdb(compdb, work, src):
    """*compdb* with paths into *work* pointing into *src* instead, and
    precompiled-header flags (-include-pch FILE) dropped, since .pch files
    aren't frozen."""
    prefixes = sorted({str(work), os.path.realpath(work)}, key=len, reverse=True)

    def fix(s):
        for p in prefixes:
            if s == p:
                return str(src)
            s = s.replace(p + os.sep, str(src) + os.sep)
        return s
    out = []
    for e in compdb:
        args, kept, skip = csa.entry_args(e), [], False
        for a in args:
            if skip:
                skip = False
            elif a == "-include-pch":
                skip = True
            elif not a.startswith("-include-pch"):
                kept.append(fix(a))
        e = {k: fix(v) if isinstance(v, str) else v for k, v in e.items() if k != "command"}
        e["arguments"] = kept
        out.append(e)
    return out


def suggest_build_command(origin):
    """A build command for the tree at *origin*, from the build files at its
    top, or None.  The user must still confirm it."""
    def has(name):
        return os.path.isfile(os.path.join(origin, name))
    if has("CMakeLists.txt"):
        return "cmake -S . -B build && cmake --build build -j$(nproc)"
    if has("meson.build"):
        return "meson setup build && ninja -C build"
    if has("configure"):
        return "./configure && make -B -j$(nproc)"
    if any(has(n) for n in ("Makefile", "makefile", "GNUmakefile")):
        return "make -B -j$(nproc)"
    return None


def git_info(origin):
    """Return {head, dirty, repo_url} for a git checkout, or {} if it isn't one."""
    def git(*args):
        r = subprocess.run(["git", "-C", origin, *args], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    head = git("rev-parse", "HEAD")
    if not head:
        return {}
    status = git("status", "--porcelain", "--", ".")
    url = git("config", "--get", "remote.origin.url") or ""
    return {"head": head, "dirty": bool(status), "repo_url": url if "github.com" in url else None}


COMMIT_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/@{}^~-]*$')


def resolve_commit(origin, commit):
    """The full hash of *commit* in the git checkout *origin*; ValueError if none."""
    if not COMMIT_RE.match(commit or ""):
        raise ValueError(f"{commit!r} doesn't look like a commit")
    r = subprocess.run(["git", "-C", origin, "rev-parse", "--verify", "--quiet",
                        commit + "^{commit}"], capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(f"{commit!r} isn't a commit in {origin}")
    return r.stdout.strip()


def git_export(origin, commit, dest):
    """Write the files of *commit* under *origin* (which may be a subdirectory
    of the checkout) into the directory *dest*."""
    r = subprocess.run(["git", "-C", origin, "rev-parse", "--show-prefix"],
                       capture_output=True, text=True, check=True)
    prefix = r.stdout.strip()
    tree = f"{commit}:{prefix}" if prefix else commit
    archive = subprocess.Popen(["git", "-C", origin, "archive", "--format=tar", tree],
                               stdout=subprocess.PIPE)
    tar = subprocess.run(["tar", "-x", "--no-same-owner", "-C", str(dest)], stdin=archive.stdout)
    archive.stdout.close()
    if archive.wait() != 0 or tar.returncode != 0:
        raise RuntimeError(f"git archive of {tree} in {origin} failed")


def compute_func_bounds(src, out_path):
    """Run find_func_bounds_with_ctags.py on *src*; return an error message or None."""
    cmd = [sys.executable, str(CODE_DIR / "find_func_bounds_with_ctags.py"),
           "-b", str(src), "-o", str(out_path), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.isfile(out_path):
        return (r.stderr or r.stdout or "ctags failed").strip()[-2000:]
    return None


def write_manifest(path, manifest):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")
