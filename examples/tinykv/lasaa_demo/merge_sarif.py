#!/usr/bin/env python3
"""Merge the per-translation-unit SARIF files from `scan-build -sarif` into
one SARIF file with a single run (which is what conv/sarif_to_lasaa.py
expects).

Usage:
    merge_sarif.py OUT.sarif IN1.sarif [IN2.sarif ...]

Rules and artifacts are merged by id/URI, their indexes are renumbered, and
duplicate results (same rule, file, line, and message, e.g., from a header
that several translation units include) are dropped.
"""

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

import json
import sys


def walk_artifact_locations(obj, fn):
    """Call fn on every dict that has an 'artifactLocation' key."""
    if isinstance(obj, dict):
        if 'artifactLocation' in obj:
            fn(obj['artifactLocation'])
        for v in obj.values():
            walk_artifact_locations(v, fn)
    elif isinstance(obj, list):
        for v in obj:
            walk_artifact_locations(v, fn)


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    out_path, in_paths = argv[1], argv[2:]

    merged = None
    rules, rule_idx = [], {}
    artifacts, art_idx = [], {}
    results, seen = [], set()

    for path in sorted(in_paths):
        with open(path) as f:
            sarif = json.load(f)
        for run in sarif.get('runs', []):
            if merged is None:
                merged = {k: v for k, v in sarif.items() if k != 'runs'}
                base_run = {k: v for k, v in run.items()
                            if k not in ('results', 'artifacts')}
            run_rules = run.get('tool', {}).get('driver', {}).get('rules', [])
            run_arts = run.get('artifacts', [])

            def fix_art(loc, run_arts=run_arts):
                uri = loc.get('uri')
                if uri is None and 'index' in loc:
                    uri = run_arts[loc['index']]['location']['uri']
                    loc['uri'] = uri
                if uri is None:
                    return
                if uri not in art_idx:
                    art_idx[uri] = len(artifacts)
                    artifacts.append({'location': {'uri': uri}})
                loc['index'] = art_idx[uri]

            for res in run.get('results', []):
                rid = res.get('ruleId')
                loc = res['locations'][0]['physicalLocation']
                key = (rid, loc['artifactLocation'].get('uri'),
                       loc['region'].get('startLine'),
                       res.get('message', {}).get('text'))
                if key in seen:
                    continue
                seen.add(key)
                if rid is not None and rid not in rule_idx:
                    rule = next((r for r in run_rules if r.get('id') == rid),
                                {'id': rid})
                    rule_idx[rid] = len(rules)
                    rules.append(rule)
                if rid is not None:
                    res['ruleIndex'] = rule_idx[rid]
                walk_artifact_locations(res, fix_art)
                results.append(res)

    if merged is None:
        sys.exit('No SARIF runs found in the input files.')
    base_run.setdefault('tool', {}).setdefault('driver', {})['rules'] = rules
    base_run['artifacts'] = artifacts
    base_run['results'] = results
    merged['runs'] = [base_run]
    with open(out_path, 'w') as f:
        json.dump(merged, f, indent=2)
    print(f'{out_path}: {len(results)} results from {len(in_paths)} files')


if __name__ == '__main__':
    main(sys.argv)
