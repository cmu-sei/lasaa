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
On-demand shallow downloads of specific commits, one shared repo per project.

This is primarily to support the PrimeVul experiment.
If an alert has `Repo_URL` and `Repo_Rev` fields (the repository and the commit
that the alert's code is at), and the LLM asks for a definition that is not in
the files LASAA already has, LASAA downloads just that commit (`git fetch
--depth 1`) into a shared per-project repository, runs `ctags` on the full
checkout, and looks the definition up there.  Options:

    --repos-dir DIR          where repositories live (default: BASE_DIR/repos)
    --repo-size-limit SIZE   give up on a repository larger than this
    --repo-status-file FILE  record of downloaded / failed / too-big repositories
                             (or set LASAA_REPO_STATUS_FILE)

Only github.com repositories are supported.  If a repository can't be
provided, LASAA falls back to the files it already has.

adjudicate_alerts.py uses this when an LLM asks for the definition of a symbol
that isn't in the files it already has (e.g., the files changed by a PrimeVul
commit).  All commits of a project share one git repository under

    ${repos_dir}/${owner}_${repo}/

into which we `git fetch --depth 1` just the commits that are needed (for
PrimeVul: a fix commit and its parent).  Because the commits share one object
store, the before/after versions of a record cost little more than one copy.

Several processes may use the same repos_dir at once, so nothing depends on a
mutable working tree: file contents are read from git's immutable objects by
(repo, rev, path) (see RepoSnapshot), and ctags runs on a private, temporary
copy of the commit's source files.  Its output is cached in

    ${repos_dir}/${owner}_${repo}.func_bounds/${rev}.json

Changes to a repo (init, fetch, deletion) are serialized by an flock on
${repos_dir}/${owner}_${repo}.lock, and read/modify/write of the status file by
an flock on ${status_file}.lock.  The kernel releases an flock when its holder
exits, however abnormally; what such a holder leaves half-done (git's own
*.lock files, incomplete packs) is cleaned up by the next holder of the lock.

Bookkeeping lives in a JSON "status file" (default ${repos_dir}/download_status.json):

    {"owner/repo": {
        "commits": {"<sha>": {"status": "ok"}                        # downloaded
                    {"status": "failed", "reason": "..."}},          # permanent failure
        "too_big": {"limit_bytes": N, "size_bytes": M, "rev": "<sha>"}}}   # size guard hit

A commit recorded as failed is never retried, and a repo recorded as too_big is
retried only if the size limit has since been raised above the recorded one.
Transient failures (network trouble) are not recorded, but they are remembered
for the rest of the run so that we don't retry them every round.

Every failure surfaces as RepoUnavailable; callers are expected to fall back to
whatever they did before the repo existed.
"""

import fcntl
import fnmatch
import io
import json
import os
import re
import socket
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_SIZE_LIMIT = 500 * 1024 * 1024
GB = 1024 ** 3

# Repos that are too big whenever the size limit is at most the given number of
# bytes.  We don't bother trying: the failure would come only after minutes of
# downloading.
HARDCODED_TOO_BIG = {"torvalds/linux": GB}

POLL_SECONDS = 2

# Log a message if a lock can't be had for this long.
LOCK_WAIT_LOG_SECONDS = 60

# The languages that find_func_bounds_with_ctags.py asks ctags to parse, and the
# file-name patterns ctags uses for them if `ctags --list-maps` can't tell us.
CTAGS_LANGUAGES = ("C", "C++", "Java")
FALLBACK_CTAGS_PATTERNS = (
    "*.c", "*.c++", "*.cc", "*.cp", "*.cpp", "*.cxx", "*.h", "*.h++", "*.hh", "*.hp",
    "*.hpp", "*.hxx", "*.inl", "*.C", "*.H", "*.CPP", "*.CXX", "*.java")

# git's messages when the repo or commit will never be retrievable.
_PERMANENT_ERRORS = (
    "repository not found",
    "not found",
    "couldn't find remote ref",
    "not our ref",
    "no such remote ref",
    "terminal prompts disabled",     # GitHub asks for a login for missing repos
    "does not appear to be a git repository",
)


class RepoUnavailable(Exception):
    """The requested repo/commit could not be provided (see the message)."""


class _SizeExceeded(Exception):
    def __init__(self, size):
        super().__init__(size)
        self.size = size


def parse_size(text):
    """Parse '500MB', '1.5GB', '2048K', or a plain byte count into bytes."""
    m = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)I?B?\s*", str(text), re.I)
    if not m:
        raise ValueError(f"invalid size {text!r}; expected e.g. 500MB, 1GB, or a byte count")
    scale = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
    return int(float(m.group(1)) * scale[m.group(2).upper()])


def format_size(nbytes):
    return f"{nbytes / (1024 ** 2):.0f} MB"


def repo_key_from_github_url(url):
    """Return 'owner/repo' (lowercased) for a github.com URL, else None."""
    m = re.fullmatch(r"https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?/?",
                     str(url).strip())
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}".lower()


def github_clone_url(key):
    return f"https://github.com/{key}.git"


def dir_size(path):
    """Disk usage in bytes of everything below *path* (without following symlinks)."""
    total = 0
    stack = [str(path)]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for entry in it:
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    total += getattr(st, "st_blocks", 0) * 512 or st.st_size
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
        except OSError:
            continue
    return total


@contextmanager
def file_lock(path, log, wait_log_seconds=LOCK_WAIT_LOG_SECONDS):
    """Hold an exclusive flock on *path* (created if need be) for the with-block.

    The holder's pid, host, and start time are written into the file, so that a
    process waiting a long time can say whom it is waiting for.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as f:
        start = time.monotonic()
        logged = False
        while True:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not logged and time.monotonic() - start >= wait_log_seconds:
                    f.seek(0)
                    holder = f.read().strip() or "unknown process"
                    log(f"Still waiting for lock {path} (held by {holder})...")
                    logged = True
                time.sleep(0.1)
        try:
            f.seek(0)
            f.truncate()
            f.write(f"pid {os.getpid()} on {socket.gethostname()} "
                    f"since {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.flush()
            yield
        finally:
            f.seek(0)
            f.truncate()
            f.flush()
            fcntl.flock(f, fcntl.LOCK_UN)


class RepoSnapshot:
    """Read-only access to the files of one commit, straight from git's objects.

    Objects never change, so reads need no lock and are unaffected by whatever
    other processes do to the repo (short of deleting it).
    """

    def __init__(self, cache, key, rev):
        self.cache = cache
        self.key = key
        self.rev = rev
        self._blobs = {}

    def __repr__(self):
        return f"{self.key}@{self.rev[:12]}"

    def read_bytes(self, relpath):
        """Return the contents of *relpath* at this commit, or None if there is no
        such file.  Symlinks within the repo are followed."""
        relpath = os.path.normpath(relpath).replace(os.sep, "/")
        if relpath not in self._blobs:
            self._blobs[relpath] = self.cache._read_blob(self.key, self.rev, relpath)
        return self._blobs[relpath]

    def read_text(self, relpath):
        """Like read_bytes, but decoded as open(relpath, 'r').read() would: in the
        locale's encoding, with universal newlines.  None if it can't be decoded."""
        data = self.read_bytes(relpath)
        if data is None:
            return None
        try:
            return io.TextIOWrapper(io.BytesIO(data)).read()
        except UnicodeDecodeError:
            return None


class RepoCache:
    def __init__(self, repos_dir, size_limit=DEFAULT_SIZE_LIMIT, status_file=None,
                 clone_url_fn=github_clone_url, key_fn=repo_key_from_github_url,
                 poll_seconds=POLL_SECONDS, log=None):
        self.repos_dir = Path(repos_dir).resolve()
        self.size_limit = size_limit
        self.status_file = Path(status_file) if status_file else self.repos_dir / "download_status.json"
        self.clone_url_fn = clone_url_fn
        self.key_fn = key_fn
        self.poll_seconds = poll_seconds
        self.log = log or (lambda msg: print(msg, flush=True))
        self._unavailable = {}  # (key, rev) -> message; failures not to retry this run
        self._dbs = {}          # (key, rev) -> func-bounds db

    # ---- status file ----------------------------------------------------

    def _load_status(self):
        """Return the status file's current contents (re-read on every call, since
        other processes may have changed it)."""
        try:
            return json.loads(self.status_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as e:
            raise RepoUnavailable(f"cannot read status file {self.status_file}: {e}")

    def _save_status(self, status):
        self.status_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=self.status_file.name + ".tmp.", dir=self.status_file.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(status, f, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp, self.status_file)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _update_status(self, key, update):
        """Apply *update* to the status of repo *key*, atomically with respect to
        other processes: reload the file, call update(repo_status), save."""
        with file_lock(str(self.status_file) + ".lock", self.log):
            self._remove_stale_status_temps()
            status = self._load_status()
            update(status.setdefault(key, {}))
            self._save_status(status)

    def _remove_stale_status_temps(self):
        """Delete temporary files left by _save_status calls that died before
        renaming them.  Call only while holding the status lock."""
        for p in self.status_file.parent.glob(glob_escape(self.status_file.name) + ".tmp.*"):
            p.unlink(missing_ok=True)

    def _repo_status(self, key):
        return self._load_status().get(key, {})

    def _record_commit(self, key, rev, **info):
        def update(repo_status):
            repo_status.setdefault("commits", {})[rev] = info
        self._update_status(key, update)

    # ---- paths ----------------------------------------------------------

    def repo_dir(self, key):
        return self.repos_dir / re.sub(r"[^A-Za-z0-9_.-]+", "_", key.replace("/", "_"))

    def _func_bounds_path(self, key, rev):
        d = self.repo_dir(key)
        return d.parent / (d.name + ".func_bounds") / f"{rev}.json"

    def _lock_path(self, key):
        d = self.repo_dir(key)
        return d.parent / (d.name + ".lock")

    def _project_lock(self, key):
        """Serialize changes to repo *key* (init, fetch, delete) across processes."""
        return file_lock(self._lock_path(key), self.log)

    # ---- git ------------------------------------------------------------

    def _git(self, key, args, size_guard=False, extra_env=None):
        """Run git in the repo; return (returncode, output).  Raises _SizeExceeded."""
        repo = self.repo_dir(key)
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0",
                   GIT_HTTP_LOW_SPEED_LIMIT="1000", GIT_HTTP_LOW_SPEED_TIME="60",
                   **(extra_env or {}))
        # Never run LFS filters: they would download large files.
        # safe.directory: the cache may be owned by another uid (e.g., a host mount
        # seen from a container); without this, git refuses with "dubious ownership".
        cmd = ["git", "-C", str(repo), "-c", f"safe.directory={repo.resolve()}",
               "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=",
               "-c", "filter.lfs.required=false", "-c", "core.autocrlf=false",
               "-c", "advice.detachedHead=false"] + args
        with tempfile.TemporaryFile() as out:
            proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, env=env,
                                    start_new_session=True)
            while True:
                try:
                    proc.wait(timeout=self.poll_seconds)
                    break
                except subprocess.TimeoutExpired:
                    if size_guard:
                        size = dir_size(repo)
                        if size > self.size_limit:
                            os.killpg(proc.pid, signal.SIGKILL)
                            proc.wait()
                            raise _SizeExceeded(size)
            if size_guard:
                size = dir_size(repo)
                if size > self.size_limit:
                    raise _SizeExceeded(size)
            out.seek(0)
            return proc.returncode, out.read().decode("utf-8", "replace").strip()

    def _git_base_cmd(self, key):
        repo = self.repo_dir(key)
        return ["git", "-C", str(repo), "-c", f"safe.directory={repo.resolve()}"]

    def _has_commit(self, key, rev):
        if not (self.repo_dir(key) / ".git").is_dir():
            return False
        rc, _ = self._git(key, ["cat-file", "-e", rev + "^{commit}"])
        return rc == 0

    def _read_blob(self, key, rev, relpath):
        """Return the bytes of *relpath* at commit *rev*, or None if it isn't a
        file there (symlinks within the repo are followed)."""
        proc = subprocess.run(self._git_base_cmd(key) + ["cat-file", "--batch", "--follow-symlinks"],
                              input=f"{rev}:{relpath}\n".encode("utf-8"),
                              capture_output=True, env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
        (header, _, rest) = proc.stdout.partition(b"\n")
        fields = header.split()
        if proc.returncode != 0 or len(fields) != 3 or fields[1] != b"blob":
            return None
        size = int(fields[2])
        return rest[:size] if len(rest) >= size else None

    # ---- public API -----------------------------------------------------

    def snapshot(self, repo_url, rev):
        """Return a RepoSnapshot of commit *rev*, downloading the commit if necessary.

        Raises RepoUnavailable.
        """
        key = self.key_fn(repo_url)
        if key is None:
            raise RepoUnavailable(f"unsupported repository URL {repo_url!r} (only github.com is supported)")
        if not re.fullmatch(r"[0-9a-f]{40}", rev):
            raise RepoUnavailable(f"revision must be a full 40-digit hex SHA: {rev!r}")
        if (key, rev) in self._unavailable:
            raise RepoUnavailable(self._unavailable[(key, rev)])
        try:
            self._ensure_commit(key, rev)
        except RepoUnavailable as e:
            self._unavailable[(key, rev)] = str(e)
            raise
        return RepoSnapshot(self, key, rev)

    def _check_not_given_up(self, key, rev):
        """Raise RepoUnavailable if *key*@*rev* is known to be unobtainable."""
        if key in HARDCODED_TOO_BIG and self.size_limit <= HARDCODED_TOO_BIG[key]:
            raise RepoUnavailable(
                f"{key} is assumed to exceed the size limit ({format_size(self.size_limit)}); "
                f"raise the limit above {format_size(HARDCODED_TOO_BIG[key])} to try it")
        status = self._repo_status(key)
        too_big = status.get("too_big")
        if too_big and too_big["limit_bytes"] >= self.size_limit:
            raise RepoUnavailable(
                f"{key} previously exceeded the size limit "
                f"({format_size(too_big['limit_bytes'])}; see {self.status_file})")
        rec = status.get("commits", {}).get(rev)
        if rec and rec.get("status") == "failed":
            raise RepoUnavailable(f"download of {key}@{rev[:12]} failed permanently: "
                                  f"{rec.get('reason')} (see {self.status_file})")
        return rec

    def _ensure_commit(self, key, rev):
        rec = self._check_not_given_up(key, rev)
        if rec and rec.get("status") == "ok" and self._has_commit(key, rev):
            return
        with self._project_lock(key):
            # Another process may have fetched it, or given up, while we waited.
            rec = self._check_not_given_up(key, rev)
            if self._has_commit(key, rev):
                if not (rec and rec.get("status") == "ok"):
                    self._record_commit(key, rev, status="ok")
                return
            try:
                self._fetch(key, rev)
            except _SizeExceeded as e:
                self._give_up_on_size(key, rev, e.size)

    def _fetch(self, key, rev):
        """Download commit *rev*.  Call only while holding the project lock."""
        repo = self.repo_dir(key)
        self.log(f"Downloading {key} commit {rev[:12]} into {repo} "
                 f"(size limit {format_size(self.size_limit)})...")
        repo.mkdir(parents=True, exist_ok=True)
        if not (repo / ".git").is_dir():
            rc, out = self._git(key, ["init", "-q"])
            if rc == 0:
                rc, out = self._git(key, ["remote", "add", "origin", self.clone_url_fn(key)])
            if rc != 0:
                raise RepoUnavailable(f"git init failed in {repo}: {out}")
        self._remove_stale_git_state(repo)
        rc, out = self._git(key, ["fetch", "--depth", "1", "--no-tags", "--no-recurse-submodules",
                                  "origin", rev], size_guard=True)
        if rc != 0:
            self._remove_incomplete_packs(repo)
            if any(pat in out.lower() for pat in _PERMANENT_ERRORS):
                reason = out.splitlines()[-1] if out else "fetch failed"
                self._record_commit(key, rev, status="failed", reason=reason)
                raise RepoUnavailable(f"cannot download {key}@{rev[:12]}: {reason}")
            raise RepoUnavailable(f"cannot download {key}@{rev[:12]} (will retry next run): {out}")
        if not self._has_commit(key, rev):
            raise RepoUnavailable(f"fetch of {key}@{rev[:12]} succeeded but the commit is missing")
        self._record_commit(key, rev, status="ok")

    @staticmethod
    def _remove_incomplete_packs(repo):
        for p in (repo / ".git" / "objects" / "pack").glob("tmp_pack_*"):
            p.unlink(missing_ok=True)

    @classmethod
    def _remove_stale_git_state(cls, repo):
        """Delete what a git process killed in mid-fetch leaves behind: its *.lock
        files (e.g., shallow.lock), which would make every later fetch fail, and
        incomplete packs.  Call only while holding the project lock: then no other
        git process of ours can be changing the repo."""
        git_dir = repo / ".git"
        for p in list(git_dir.glob("*.lock")) + list((git_dir / "refs").rglob("*.lock")):
            p.unlink(missing_ok=True)
        cls._remove_incomplete_packs(repo)

    def _give_up_on_size(self, key, rev, size):
        """The repo outgrew the limit: record it, and delete the repo entirely.

        Deleting keeps the disk usage bounded; every commit of the repo is
        unavailable until the limit is raised.  Call only while holding the
        project lock.
        """
        repo = self.repo_dir(key)
        self.log(f"{key} exceeded the size limit ({format_size(size)} > "
                 f"{format_size(self.size_limit)}); deleting {repo}.")
        shutil.rmtree(repo, ignore_errors=True)
        shutil.rmtree(self._func_bounds_path(key, rev).parent, ignore_errors=True)

        def update(status):
            status["too_big"] = {"limit_bytes": self.size_limit, "size_bytes": size, "rev": rev}
            for r in [r for r, rec in status.get("commits", {}).items() if rec.get("status") == "ok"]:
                del status["commits"][r]
        self._update_status(key, update)
        for k in [k for k in self._dbs if k[0] == key]:
            del self._dbs[k]
        raise RepoUnavailable(f"{key} exceeded the size limit ({format_size(size)} > "
                              f"{format_size(self.size_limit)})")

    def get_func_bounds_db(self, repo_url, rev):
        """Return (func_bounds_db, snapshot) for the full repo at *rev*.

        ctags runs once per (repo, rev); the result is cached on disk next to the
        repo.  File names in the db are relative to the repo root; read the files
        with snapshot.read_text().  Raises RepoUnavailable (including if ctags fails).
        """
        from get_enclosing_func import load_func_bounds_etc
        snap = self.snapshot(repo_url, rev)
        key = snap.key
        if (key, rev) not in self._dbs:
            path = self._func_bounds_path(key, rev)
            if not path.is_file():
                rec = self._repo_status(key).get("commits", {}).get(rev, {})
                if rec.get("ctags_failed"):
                    raise RepoUnavailable(f"ctags previously failed on {key}@{rev[:12]}: "
                                          f"{rec['ctags_failed']} (see {self.status_file})")
                self._run_ctags(key, rev, path)
            try:
                self._dbs[(key, rev)] = load_func_bounds_etc(str(path), None)
            except (OSError, ValueError) as e:
                raise RepoUnavailable(f"cannot read ctags data {path}: {e}")
        return self._dbs[(key, rev)], snap

    def _run_ctags(self, key, rev, path):
        """Run ctags on a private copy of *rev*'s source files; write *path*."""
        import contextlib
        import find_func_bounds_with_ctags
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + f".tmp{os.getpid()}")
        with tempfile.TemporaryDirectory(prefix=f"repo_cache.{self.repo_dir(key).name}.{rev[:12]}.") as tmpdir:
            src = Path(tmpdir) / "src"
            nfiles = self._export_source_files(key, rev, src, Path(tmpdir) / "index")
            self.log(f"Running ctags on {nfiles} source files of {key}@{rev[:12]}...")
            try:
                if nfiles == 0:
                    tmp.write_text("[\n]\n", encoding="utf-8")
                else:
                    with contextlib.redirect_stdout(io.StringIO()):
                        find_func_bounds_with_ctags.main([str(src), "-b", str(src), "-o", str(tmp)])
                os.replace(tmp, path)
            except (Exception, SystemExit) as e:
                reason = str(e) or type(e).__name__
                self._record_commit(key, rev, status="ok", ctags_failed=reason)
                raise RepoUnavailable(f"ctags failed on {key}@{rev[:12]}: {reason}")
            finally:
                if tmp.exists():
                    tmp.unlink()

    def _export_source_files(self, key, rev, dest, index_file):
        """Write the files of *rev* that ctags would parse into *dest*, using a
        private index file (the shared repo's index and working tree are not
        touched).  Return the number of files written."""
        patterns = ctags_file_patterns()
        # Held so that the repo isn't deleted (see _give_up_on_size) mid-export.
        with self._project_lock(key):
            rc, out = self._git(key, ["ls-tree", "-r", "-z", "--full-tree", rev])
            if rc != 0:
                raise RepoUnavailable(f"git ls-tree of {key}@{rev[:12]} failed: {out}")
            paths = []
            for entry in out.split("\0"):
                (meta, _, name) = entry.partition("\t")
                # Regular files only: a symlink could point outside the copy.  (Names
                # that aren't valid UTF-8 are skipped; git wouldn't recognize them.)
                if meta.split()[:1] in (["100644"], ["100755"]) and "\ufffd" not in name and \
                        ctags_would_parse(name.rsplit("/", 1)[-1], patterns):
                    paths.append(name)
            if not paths:
                return 0
            env = {"GIT_INDEX_FILE": str(index_file)}
            rc, out = self._git(key, ["read-tree", rev], extra_env=env)
            if rc == 0:
                dest.mkdir(parents=True)
                proc = subprocess.run(
                    self._git_base_cmd(key) + ["-c", "core.autocrlf=false",
                                               "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=",
                                               "-c", "filter.lfs.required=false",
                                               f"--work-tree={dest}", "checkout-index", "-z", "--stdin"],
                    input="".join(p + "\0" for p in paths).encode("utf-8"), capture_output=True,
                    env=dict(os.environ, GIT_TERMINAL_PROMPT="0", **env))
                (rc, out) = (proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace").strip())
            if rc != 0:
                raise RepoUnavailable(f"cannot write the source files of {key}@{rev[:12]}: {out}")
            return len(paths)


def glob_escape(name):
    return re.sub(r"([*?\[])", r"[\1]", name)


def ctags_would_parse(basename, patterns):
    """Does *basename* match one of *patterns*?  Like ctags, ignore a trailing
    ".in" (as in config.h.in), unless the name matches as is."""
    names = [basename]
    if basename.endswith(".in"):
        names.append(basename[:-len(".in")])
    return any(fnmatch.fnmatchcase(n, pat) for n in names for pat in patterns)


_ctags_patterns = None


def ctags_file_patterns():
    """Return the file-name patterns ctags maps to CTAGS_LANGUAGES."""
    global _ctags_patterns
    if _ctags_patterns is None:
        patterns = []
        try:
            for lang in CTAGS_LANGUAGES:
                out = subprocess.run(["ctags", f"--list-maps={lang}"], capture_output=True,
                                     text=True, timeout=15, check=True).stdout
                for line in out.splitlines():
                    fields = line.split()
                    if fields and fields[0] == lang:
                        patterns += fields[1:]
        except (OSError, subprocess.SubprocessError):
            patterns = []
        _ctags_patterns = tuple(patterns) or FALLBACK_CTAGS_PATTERNS
    return _ctags_patterns
