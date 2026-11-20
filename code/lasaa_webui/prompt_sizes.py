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
"""Prompt sizes for the run form's cost estimate, measured in the background.

The estimate needs each alert's first-round prompt, which only a dry run of
the pipeline gives.  A dry run costs about 1.2 s (startup and ctags) plus
about 2 ms per alert (3,000 synthetic alerts over 350k lines: 6 s), so for
a large analysis the form shouldn't wait for all of them.

One dry run measures every alert not measured yet, in an order chosen here:
the form's selection when it starts first, then the rest by the SHA-256 of
their basenames (random-looking whatever the IDs are, and the same every
time).  The pipeline handles the alerts in that order, and prints
"BASENAME: waiting: original trial replies" after writing each one's query.
So once an alert's line is out, its query file and those of every alert
before it are complete, and an alert passed over without a line has no
prompt.  The sizes are taken from the files after the first FIRST_UPDATE
alerts (a quick, sampled estimate), and then at most every UPDATE_SECONDS.
They are kept per alert in the analysis's prompt_sizes.json until the
pipeline's code changes.
"""

import asyncio
import collections
import hashlib
import json
import os
import re
import signal
import tempfile
import time

from . import runs

FIRST_UPDATE = 100
UPDATE_SECONDS = 0.5
STATUS_RE = re.compile(r"^([A-Za-z0-9_.-]+): waiting: original trial replies$")


def dry_run_order(basenames, wanted):
    """The order to measure *basenames* in: those in *wanted* first."""
    return sorted(basenames, key=lambda b: (b not in wanted,
                                            hashlib.sha256(b.encode()).hexdigest()))


class PromptSizes:
    """The prompt sizes of one analysis's alerts: {basename: [[stem, chars]]},
    [] for an alert with no prompt; a missing basename isn't measured yet."""

    def __init__(self, path, key):
        self.path, self.key = path, key
        self.sizes = {}
        self.version = 0            # bumped whenever sizes or error change
        self.error = None
        self.task = None
        self._changed = asyncio.Event()
        try:
            saved = json.loads(path.read_text())
            if saved["key"] == key:
                self.sizes = saved["sizes"]
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def running(self):
        return self.task is not None and not self.task.done()

    def ensure(self, basenames, wanted, launch):
        """Start measuring the alerts in *basenames* not measured yet, those
        in *wanted* first, unless a dry run is already going (its order
        stays).  *launch(order, scratch_dir)* writes the alerts' subset file
        in that order and returns (command, env, cwd, out_dir) for their dry
        run."""
        todo = [b for b in basenames if b not in self.sizes]
        if todo and not self.running():
            self.error = None
            order = dry_run_order(todo, set(wanted))
            self.task = asyncio.get_running_loop().create_task(self._work(order, launch))

    async def _work(self, order, launch):
        pos = {b: i for i, b in enumerate(order)}
        tail = collections.deque(maxlen=40)        # for the error message
        with tempfile.TemporaryDirectory() as scratch:
            (cmd, env, cwd, out_dir) = launch(order, scratch)
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=cwd, env={**env, "PYTHONUNBUFFERED": "1"},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                start_new_session=True, limit=1 << 22)       # long error lines
            done = taken = 0        # alerts order[:done] are written; [:taken] are in sizes
            last = time.monotonic()
            try:
                while (line := await proc.stdout.readline()):
                    line = line.decode("utf-8", "replace").rstrip("\n")
                    tail.append(line)
                    m = STATUS_RE.match(line)
                    if m and m[1] in pos:
                        done = max(done, pos[m[1]] + 1)
                    if (done >= min(FIRST_UPDATE, len(order)) and done > taken
                            and (taken == 0 or time.monotonic() - last >= UPDATE_SECONDS)):
                        taken = self._take(order, taken, done, out_dir)
                        last = time.monotonic()
                rc = await proc.wait()
            finally:
                if proc.returncode is None:            # cancelled
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await proc.wait()
            if rc == 0:
                done = len(order)
            else:
                self.error = ("The dry run for the estimate failed:\n" + "\n".join(tail))[-3000:]
            if done > taken:
                self._take(order, taken, done, out_dir)
        self._bump()        # finished: long polls waiting for more can return

    def _take(self, order, taken, done, out_dir):
        """Record the sizes of the alerts order[taken:done]; returns done."""
        found = runs.query_sizes(out_dir)
        for b in order[taken:done]:
            self.sizes[b] = found.get(b, [])
        self._save()
        self._bump()
        return done

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"key": self.key, "sizes": self.sizes}))
        os.replace(tmp, self.path)

    def _bump(self):
        self.version += 1
        self._changed.set()
        self._changed = asyncio.Event()

    async def wait(self, version, timeout):
        """Return when the sizes have changed since *version*, or after
        *timeout* seconds, or at once if nothing is being measured."""
        if self.version != version or not self.running():
            return
        try:
            await asyncio.wait_for(self._changed.wait(), timeout)
        except asyncio.TimeoutError:
            pass


class Registry:
    """The PromptSizes of each analysis, for as long as the server runs."""

    def __init__(self):
        self.by_analysis = {}

    def get(self, analysis_id, path, key):
        s = self.by_analysis.get(analysis_id)
        if s is None or s.key != key:
            if s is not None and s.running():
                s.task.cancel()
            s = self.by_analysis[analysis_id] = PromptSizes(path, key)
        return s
