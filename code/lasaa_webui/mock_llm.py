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
"""Saved configs for ../mock_llm_server.py (lasaa_webui_serve.py --mock-llm).

At startup, the server reads the mock's reply cache and saves one "Other"
model config for each (model, effort) in it, named "Mock: MODEL (EFFORT)",
so that a demo needn't make them by hand (saved configs are kept in the
workspace's database, so clearing the workspace removes them).  A config
with the same name is replaced; configs for pairs no longer in the cache
are left alone.  The configs' API key variable, KEY_VAR, is set to a dummy
value in the server's environment if it isn't set; the mock doesn't check it.

The cache is read directly (one JSON object per line, with "model" and
"reasoning_effort"; see ../mock_llm_build_cache.py), so the mock needn't be
running yet.  The base URL's host must be local (models.is_local_url()), so
that runs pass --mock-llm-server, which the mock needs.  The configs are
saved with model_configs.install(), as --model-configs saves its own.
"""

import json
from pathlib import Path

from . import models

DEFAULT_URL = "http://127.0.0.1:8100/v1"
DEFAULT_CACHE = "~/.lasaa-mock/mock_llm_cache.jsonl"     # as in mock_llm_build_cache.py
KEY_VAR = "MOCK_LLM" + models.KEY_SUFFIX
NAME_PREFIX = "Mock: "


def cached_pairs(cache_path):
    """The sorted (model, effort) pairs in the cache, with the effort as in a
    spec ("" for the client's default, which the cache calls "default").
    Raises OSError or ValueError."""
    pairs = set()
    with open(Path(cache_path).expanduser(), encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
                model, effort = e["model"], e["reasoning_effort"]
            except (ValueError, KeyError, TypeError):
                raise ValueError(f"{cache_path} line {n} isn't a cache entry; "
                                 "rebuild it with mock_llm_build_cache.py.") from None
            pairs.add((model, "" if effort == "default" else effort))
    return sorted(pairs)


def config_name(model, effort):
    return f"{NAME_PREFIX}{model} ({effort or 'default'})"


def specs(pairs, url=DEFAULT_URL):
    """([(name, spec)], [skipped (model, effort, reason)]) for *pairs*."""
    if not models.is_local_url(url):
        raise ValueError(f"The mock's URL {url!r} must have a numeric IP address or "
                         "localhost as its host, so that runs send the trial number.")
    out, skipped = [], []
    for model, effort in pairs:
        spec = models.new_spec(provider="Other", model=model, effort=effort, base_url=url,
                               api_type="response", api_key_name=KEY_VAR)
        try:
            out.append((config_name(model, effort), models.validate(spec)))
        except ValueError as e:
            skipped.append((model, effort, str(e)))
    return out, skipped
