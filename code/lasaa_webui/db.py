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
"""The UI's SQLite database (ui.sqlite in the workspace)."""

import datetime
import json
import os
import shutil
import sqlite3
import time

SCHEMA_VERSION = 7

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS project (
  project_id    INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  slug          TEXT NOT NULL UNIQUE,
  origin        TEXT,
  build_command TEXT,
  notes         TEXT,
  hidden        INTEGER NOT NULL DEFAULT 0,  -- "deleted": left out of the UI's lists
  old_name      TEXT,            -- a deleted project's name before it was renamed
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshot (
  snap_id       INTEGER PRIMARY KEY,
  project_id    INTEGER NOT NULL REFERENCES project,
  label         TEXT,
  origin        TEXT NOT NULL,
  build_command TEXT,
  build_status  TEXT,            -- NULL (no build) | ok | failed
  build_units   INTEGER,         -- entries in compile_commands.json
  git_head      TEXT,
  git_dirty     INTEGER,
  repo_url      TEXT,
  dir           TEXT NOT NULL,   -- relative to the workspace
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analysis (
  analysis_id   INTEGER PRIMARY KEY,
  snap_id       INTEGER NOT NULL REFERENCES snapshot,
  tool          TEXT NOT NULL,   -- the analyzers, e.g. 'clang-analyzer, cppcheck' | imported
  tool_version  TEXT,
  options       TEXT,
  status        TEXT NOT NULL,
  source        TEXT,            -- for imports: the alerts file imported
  dir           TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert (
  analysis_id   INTEGER NOT NULL REFERENCES analysis,
  alert_id      TEXT NOT NULL,
  basename      TEXT NOT NULL,   -- sanitized ID, as in pipeline file names
  ord           INTEGER NOT NULL,
  tool          TEXT,
  file          TEXT,
  line          INTEGER,
  cwes          TEXT NOT NULL,   -- JSON list
  rule          TEXT,
  message       TEXT,
  severity      TEXT,
  external      INTEGER NOT NULL DEFAULT 0,
  fingerprint   TEXT,            -- reserved for cascading
  record        TEXT NOT NULL,   -- the full LASAA-format alert, JSON
  PRIMARY KEY (analysis_id, alert_id)
);
CREATE TABLE IF NOT EXISTS config (
  config_id     INTEGER PRIMARY KEY,
  client        TEXT NOT NULL,
  model         TEXT NOT NULL,
  effort        TEXT NOT NULL DEFAULT '',
  endpoint      TEXT NOT NULL DEFAULT '',   -- see models.config_of()
  created_at    TEXT NOT NULL,
  UNIQUE (client, model, effort, endpoint)
);
CREATE TABLE IF NOT EXISTS run (
  run_id        INTEGER PRIMARY KEY,
  analysis_id   INTEGER NOT NULL REFERENCES analysis,
  config_id     INTEGER NOT NULL REFERENCES config,
  out_dir       TEXT NOT NULL,   -- relative to the workspace
  opts          TEXT,            -- JSON: N, t, CC, LRE, ... (as in # opts=)
  selection     TEXT,            -- JSON
  budget        REAL,            -- dollars
  budget_tokens INTEGER,         -- input + output tokens, for models without a price
  command       TEXT,
  status        TEXT NOT NULL,   -- imported | queued | running | done | ...
  created_at    TEXT NOT NULL,
  finished_at   TEXT,
  input_tokens  INTEGER,
  cached_input_tokens INTEGER,
  output_tokens INTEGER,
  cost          REAL
);
CREATE TABLE IF NOT EXISTS run_result (
  run_id        INTEGER NOT NULL REFERENCES run,
  analysis_id   INTEGER NOT NULL,
  alert_id      TEXT NOT NULL,
  verdict       TEXT,            -- NULL: not adjudicated yet
  final_answer  TEXT,            -- copy of the .final_answer text
  explanation   TEXT,            -- final answer body without its header
  split         TEXT,            -- JSON {"verdict": count} of the deciding trials
  phases        TEXT NOT NULL,   -- JSON list, see indexer.py
  definitions   TEXT,            -- JSON [[round, text]]
  warnings      TEXT,            -- JSON list
  input_tokens  INTEGER,
  cached_input_tokens INTEGER,
  output_tokens INTEGER,
  cost          REAL,
  PRIMARY KEY (run_id, alert_id)
);
-- Query and reply files, shared by every run over the same output directory.
CREATE TABLE IF NOT EXISTS llm_file (
  out_dir       TEXT NOT NULL,
  name          TEXT NOT NULL,
  size          INTEGER NOT NULL,
  mtime         REAL NOT NULL,
  content       TEXT NOT NULL,
  verdict       TEXT,
  need_defs     TEXT,            -- JSON list
  model         TEXT,
  effort        TEXT,
  input_tokens  INTEGER,
  cached_input_tokens INTEGER,
  output_tokens INTEGER,
  reasoning_tokens INTEGER,
  PRIMARY KEY (out_dir, name)
);
CREATE TABLE IF NOT EXISTS saved_model (   -- the run form's "Save config"
  saved_id      INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  spec          TEXT NOT NULL,   -- JSON: a model spec (models.py)
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS review (
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
CREATE INDEX IF NOT EXISTS review_alert ON review(analysis_id, alert_id, review_id);
-- Long-running work: making a snapshot, running the analyzers, running LASAA.
CREATE TABLE IF NOT EXISTS job (
  job_id        INTEGER PRIMARY KEY,
  project_id    INTEGER REFERENCES project,
  kind          TEXT NOT NULL,   -- snapshot | analyze | lasaa
  title         TEXT NOT NULL,
  params        TEXT NOT NULL,   -- JSON: what the job needs to run (or rerun)
  status        TEXT NOT NULL,   -- queued | running | done | failed | cancelled |
                                 -- over-budget | interrupted
  snap_id       INTEGER,         -- what the job made or worked on
  analysis_id   INTEGER,
  run_id        INTEGER,
  log           TEXT NOT NULL,   -- log file, relative to the workspace
  error         TEXT,
  created_at    TEXT NOT NULL,
  started_at    TEXT,
  finished_at   TEXT
);
-- "Ask an LLM" on the alert page (chat.py): conversations about one run
-- result, and their questions and answers.  Deleting a chat deletes them.
CREATE TABLE IF NOT EXISTS chat (
  chat_id       INTEGER PRIMARY KEY,
  analysis_id   INTEGER NOT NULL,
  alert_id      TEXT NOT NULL,
  run_id        INTEGER NOT NULL,  -- the run result whose prompt and answer it is about
  spec          TEXT NOT NULL,   -- JSON: the model spec (models.py), without the flex tier
  model_label   TEXT NOT NULL,
  context       TEXT NOT NULL,   -- what goes before the first question (chat.context_text)
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chat_alert ON chat(analysis_id, alert_id, chat_id);
CREATE TABLE IF NOT EXISTS chat_turn (
  turn_id       INTEGER PRIMARY KEY,
  chat_id       INTEGER NOT NULL REFERENCES chat ON DELETE CASCADE,
  question      TEXT NOT NULL,   -- markdown
  status        TEXT NOT NULL,   -- pending | done | failed | cancelled | interrupted
  reply         TEXT,            -- the reply file as the client wrote it
  answer        TEXT,            -- without the header, reasoning, or a cut-off mark
  reasoning     TEXT,
  model         TEXT,            -- what the reply's header says
  input_tokens  INTEGER,
  cached_input_tokens INTEGER,
  output_tokens INTEGER,
  reasoning_tokens INTEGER,
  truncated     INTEGER NOT NULL DEFAULT 0,  -- cut off by the output-token cap
  cost          REAL,
  error         TEXT,
  created_at    TEXT NOT NULL,
  finished_at   TEXT
);
CREATE INDEX IF NOT EXISTS chat_turn_chat ON chat_turn(chat_id, turn_id);
"""

# Statements that upgrade a database from version N-1 to N (before SCHEMA,
# which creates any missing tables, runs).
MIGRATIONS = {
    2: ["ALTER TABLE run ADD COLUMN budget_tokens INTEGER"],
    3: ["ALTER TABLE snapshot ADD COLUMN build_status TEXT",
        "ALTER TABLE snapshot ADD COLUMN build_units INTEGER"],
    4: [],          # saved_model, which SCHEMA creates
    5: [],          # chat and chat_turn, which SCHEMA creates
    6: ["ALTER TABLE project ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0"],
    7: ["ALTER TABLE project ADD COLUMN old_name TEXT"],
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def connect(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init(path):
    """Open the database at *path*, creating or upgrading its schema."""
    conn = connect(path)
    row = None
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError:
        pass
    version = int(row["value"]) if row else 0
    if version > SCHEMA_VERSION:
        raise SystemExit(f"Error: {path} has schema version {version}; "
                         f"this code knows only up to {SCHEMA_VERSION}.")
    if 0 < version < SCHEMA_VERSION:
        backup(conn, str(path) + ".bak")
        for v in range(version + 1, SCHEMA_VERSION + 1):
            for stmt in MIGRATIONS.get(v, []):
                conn.execute(stmt)
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                 (str(SCHEMA_VERSION),))
    conn.commit()
    return conn


def backup(conn, dest):
    """Copy the database to *dest* with SQLite's online backup."""
    tmp = dest + ".tmp"
    out = sqlite3.connect(tmp)
    with out:
        conn.backup(out)
    out.close()
    shutil.move(tmp, dest)


def backup_daily(conn, path, max_age=24 * 3600):
    """Back up the database to *path*.bak unless that is less than a day old."""
    dest = str(path) + ".bak"
    try:
        if time.time() - os.path.getmtime(dest) < max_age:
            return False
    except OSError:
        pass
    backup(conn, dest)
    return True


def get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", ("setting." + key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                 ("setting." + key, value))
    conn.commit()


def loads(s, default=None):
    return json.loads(s) if s else default
