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
"""Saved model configs from files (lasaa_webui_serve.py --model-configs).

A file is a JSON list of configs, each an object with a "name" (as shown
under "Saved" in the run form's model list) and the fields of a model spec
(models.SPEC_FIELDS; "provider" defaults to "Other"), for example

  [{"name": "Llama 70B (local Ollama)", "model": "llama3.1:70b",
    "base_url": "http://127.0.0.1:11434/v1", "api_type": "chat_completion",
    "api_key_name": "OLLAMA_LASAA_KEY"}]

Each config is checked as the run form checks one (models.validate()), so an
"Other" config's API key must come from a variable named …_LASAA_KEY.  At
startup the server saves them all, replacing saved configs with the same
names (install()); saved configs not in the files are left alone.  A bad
file or entry stops the server, rather than starting with some configs.
"""

import json
from pathlib import Path

from . import db, models

NAME_MAX = 100                  # as the run form's "Save config" keeps
_STR_FIELDS = ("provider", "model", "effort", "region", "prefix", "base_url", "api_type",
               "api_key_name", "or_endpoint")


def check_entry(entry):
    """(name, spec) for one config object.  Raises ValueError."""
    if not isinstance(entry, dict):
        raise ValueError("isn't a JSON object")
    unknown = sorted(set(entry) - {"name"} - set(models.SPEC_FIELDS))
    if unknown:
        raise ValueError(f"unknown field{'s' if len(unknown) > 1 else ''} "
                         f"{', '.join(unknown)} (known: name, {', '.join(models.SPEC_FIELDS)})")
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > NAME_MAX:
        raise ValueError(f'needs a "name" of 1 to {NAME_MAX} characters')
    fields = {k: v for k, v in entry.items() if k != "name"}
    fields.setdefault("provider", "Other")
    for k in _STR_FIELDS:
        if k in fields and not isinstance(fields[k], str):
            raise ValueError(f'"{k}" must be a string')
    if "concurrency" in fields and (isinstance(fields["concurrency"], bool)
                                    or not isinstance(fields["concurrency"], int)):
        raise ValueError('"concurrency" must be a whole number')
    cap = fields.get("max_output_tokens")
    if cap is not None and (isinstance(cap, bool) or not isinstance(cap, int)):
        raise ValueError('"max_output_tokens" must be a whole number or null')
    if "flex" in fields and not isinstance(fields["flex"], bool):
        raise ValueError('"flex" must be true or false')
    return name.strip(), models.validate(models.new_spec(**fields))


def load(path):
    """[(name, spec)] from the config file *path*.  Raises OSError, or
    ValueError naming the file and the entry."""
    path = Path(path).expanduser()
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except ValueError as e:
            raise ValueError(f"{path} isn't valid JSON: {e}") from None
    if not isinstance(data, list):
        raise ValueError(f"{path} must hold a JSON list of configs")
    out = []
    for i, entry in enumerate(data, 1):
        label = f"{path}, config {i}"
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            label += f" ({entry['name'].strip()!r})"
        try:
            out.append(check_entry(entry))
        except ValueError as e:
            raise ValueError(f"{label}: {e}") from None
    return out


def check_unique(named_specs):
    """Raises ValueError if two configs have the same name."""
    seen = set()
    for name, _ in named_specs:
        if name in seen:
            raise ValueError(f"two configs are named {name!r}")
        seen.add(name)


def install(conn, named_specs):
    """Save *named_specs* as configs, replacing any with the same names."""
    for name, spec in named_specs:
        conn.execute("INSERT INTO saved_model(name, spec, created_at) VALUES (?,?,?) "
                     "ON CONFLICT(name) DO UPDATE SET spec=excluded.spec",
                     (name, json.dumps(spec), db.now()))
    conn.commit()
