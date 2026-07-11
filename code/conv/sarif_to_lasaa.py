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
sarif_to_lasaa.py - Convert SARIF static-analysis output to LASAA JSON format.

Reads a SARIF file (assumed to contain a single run; multiple runs trigger a
warning and only the first is used) and writes a JSON list of alert dicts.

Two modes:

  Default                : write LASAA input JSON (the alert dicts below).
      ./sarif_to_lasaa.py orig.sarif [-b BASE] -o alerts_for_lasaa.json

  Update (-u ADJUDICATIONS): write an *updated SARIF* file in which each
      result is annotated with the LASAA verdict and explanation from the
      adjudications JSON (a list of {Alert_ID, verdict, explanation} dicts).
      Adjudications are matched to results by Alert_ID, so pass the same
      SARIF file and --base-dir used for the original conversion.
      The verdict + explanation are stored in each result's
      `properties.lasaa`; results whose verdict is a "false positive" also
      optionally get a standard SARIF `suppressions` entry.
      ./sarif_to_lasaa.py orig.sarif -u adjudications.json [-b BASE] -o updated.sarif

Each alert dict contains three categories of fields:

(A) LASAA-special fields - LASAA itself uses these:
      File   : str  - file path (resolved relative to LASAA's --base-dir)
      Line   : int  - line number of the flagged code
      CWEs   : list - list of CWE IDs (e.g., ["CWE-89"])

(B) LLM-facing fields - shown to the LLM along with the source code:
      Tool             : tool that produced the alert
      Message          : alert message text
      RuleID           : the rule ID in the SARIF file
      RuleName         : human-readable rule name
      RuleDescription  : short description of the rule
      RuleHelp         : longer help/explanation (when distinct)
      Function         : enclosing function name (when reported)
      Column           : column number (when reported)
      CodeFlow         : compact summary of data-flow / taint-path steps

(C) Filter-only fields: useful for selecting which alerts to feed to the LLM
    (e.g., "only error-level" or "security-severity >= 7"):
      Level             : "error" | "warning" | "note" | "none"
      SecuritySeverity  : float 0-10  (CodeQL/GitHub style, when present)
      Rank              : float 0-100 (SARIF rank, when present)
      BaselineState     : "new" | "unchanged" | "updated" | "absent"
      Suppressed        : True iff the result has an accepted suppression
      Tags              : merged list of rule + result tags
      Properties        : tool-specific property bag (minus tags / sev)
      Fingerprints      : fingerprints / partialFingerprints for de-dup

LASAA_FIELDS_FOR_LLM="File,Line,CWEs,Tool,Message,RuleID,RuleName,RuleDescription,RuleHelp,Function,Column,CodeFlow"
"""

import argparse
import json
import re
import sys
import hashlib
from typing import Any, Optional


# -------------------------- CWE extraction helpers --------------------------

# Matches a CWE-ish suffix in tags / ids: "cwe-079", "CWE_89", "external/cwe/cwe-89"
_CWE_TAG_RE = re.compile(r'(?:^|[/_\-])cwe[-_]?(\d+)\b', re.IGNORECASE)
# Matches a bare or prefixed CWE id: "89", "CWE-89", "CWE_089"
_CWE_ID_RE  = re.compile(r'^\s*(?:CWE[-_]?)?(\d+)\s*$', re.IGNORECASE)


def _normalize_cwe(value: Any) -> Optional[str]:
    """Normalize a single CWE-like value to "CWE-N", or return None."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    m = _CWE_ID_RE.match(s)
    if m:
        return f"CWE-{int(m.group(1))}"
    m = _CWE_TAG_RE.search(s)
    if m:
        return f"CWE-{int(m.group(1))}"
    return None


def _cwes_from_tags(tags) -> list:
    out = []
    for tag in (tags or []):
        if not isinstance(tag, str):
            continue
        m = _CWE_TAG_RE.search(tag)
        if m:
            out.append(f"CWE-{int(m.group(1))}")
    return out


def _cwes_from_relationships(rule) -> list:
    """Pull CWEs from a rule's `relationships` referencing the CWE taxonomy."""
    out = []
    for rel in (rule.get('relationships') or []):
        target = rel.get('target') or {}
        comp = target.get('toolComponent') or {}
        if 'CWE' in (comp.get('name') or '').upper():
            c = _normalize_cwe(target.get('id'))
            if c:
                out.append(c)
    return out


def _cwes_from_taxa(result) -> list:
    """Pull CWEs from a result's `taxa` field referencing the CWE taxonomy."""
    out = []
    for tx in (result.get('taxa') or []):
        comp = tx.get('toolComponent') or {}
        if 'CWE' in (comp.get('name') or '').upper():
            c = _normalize_cwe(tx.get('id'))
            if c:
                out.append(c)
    return out


def _cwes_from_properties_cwe(props) -> list:
    """Pull CWEs from a `properties.cwe` field (string or list)."""
    out = []
    if not props:
        return out
    val = props.get('cwe')
    if val is None:
        return out
    if isinstance(val, list):
        for v in val:
            c = _normalize_cwe(v)
            if c:
                out.append(c)
    else:
        # Could be "CWE-89" or "CWE-89, CWE-90" or just "89"
        for piece in str(val).split(','):
            c = _normalize_cwe(piece)
            if c:
                out.append(c)
    return out


def extract_cwes(result, rule) -> list:
    """Combine all CWE-extraction strategies and dedupe (preserving order)."""
    cwes = []
    if rule:
        rprops = rule.get('properties') or {}
        cwes.extend(_cwes_from_tags(rprops.get('tags')))
        cwes.extend(_cwes_from_properties_cwe(rprops))
        cwes.extend(_cwes_from_relationships(rule))
    rprops = result.get('properties') or {}
    cwes.extend(_cwes_from_tags(rprops.get('tags')))
    cwes.extend(_cwes_from_properties_cwe(rprops))
    cwes.extend(_cwes_from_taxa(result))

    seen, uniq = set(), []
    for c in cwes:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


# --------------------------- Rule lookup --------------------------------

def find_rule(run, result):
    """Find the rule object referenced by a result. Returns dict or None."""
    rule_id   = result.get('ruleId')
    rule_idx  = result.get('ruleIndex')
    rule_ref  = result.get('rule') or {}

    tool      = run.get('tool') or {}
    driver    = tool.get('driver') or {}
    drv_rules = driver.get('rules') or []
    exts      = tool.get('extensions') or []

    # 1. result.rule.toolComponent.index + result.rule.index
    if isinstance(rule_ref, dict):
        idx = rule_ref.get('index')
        tc  = rule_ref.get('toolComponent') or {}
        tc_idx = tc.get('index')
        if tc_idx is not None and 0 <= tc_idx < len(exts):
            ext_rules = exts[tc_idx].get('rules') or []
            if idx is not None and 0 <= idx < len(ext_rules):
                return ext_rules[idx]
        if idx is not None and 0 <= idx < len(drv_rules):
            return drv_rules[idx]

    # 2. result.ruleIndex (driver-only)
    if rule_idx is not None and 0 <= rule_idx < len(drv_rules):
        return drv_rules[rule_idx]

    # 3. Search by id, in driver then extensions
    if rule_id:
        for r in drv_rules:
            if r.get('id') == rule_id:
                return r
        for ext in exts:
            for r in (ext.get('rules') or []):
                if r.get('id') == rule_id:
                    return r
    return None


# ---------------------- Message / location resolution -------------------

def resolve_message(result, rule) -> str:
    """Resolve the result message, expanding messageStrings templates if needed."""
    msg = result.get('message') or {}
    if isinstance(msg, str):
        return msg
    text = msg.get('text')
    if text:
        return text
    msg_id = msg.get('id')
    args = msg.get('arguments') or []
    if msg_id and rule:
        tmpl = ((rule.get('messageStrings') or {}).get(msg_id) or {}).get('text')
        if tmpl:
            try:
                return tmpl.format(*args)
            except Exception:
                return tmpl
    return msg.get('markdown') or ''


def primary_location(result):
    """Return (uri, uri_base_id, line, column, function_name)."""
    locs = result.get('locations') or []
    if not locs:
        return None, None, None, None, None
    loc = locs[0]
    phys = loc.get('physicalLocation') or {}
    art = phys.get('artifactLocation') or {}
    region = phys.get('region') or {}
    function = None
    for ll in (loc.get('logicalLocations') or []):
        function = ll.get('fullyQualifiedName') or ll.get('name')
        if function:
            break
    return (art.get('uri'), art.get('uriBaseId'),
            region.get('startLine'), region.get('startColumn'),
            function)


def resolve_path(uri: Optional[str], uri_base_id: Optional[str],
                 base_uris: dict, base_dir) -> str:
    """Resolve a SARIF artifact URI into a usable path string.

    If the SARIF declares a uriBaseId pointing to an absolute file:// URI,
    we deliberately keep the *relative* portion only - the user supplies
    an absolute root via LASAA's '--base-dir'.
    """
    if not uri:
        return None
    if uri_base_id and uri_base_id in base_uris:
        base_uri = (base_uris[uri_base_id] or {}).get('uri') or ''
        if base_uri:
            sep = '' if base_uri.endswith('/') or not base_uri else '/'
            uri = base_uri + sep + uri
    if uri.startswith('file://'):
        uri = uri[len('file://'):]
    if base_dir and uri.startswith(base_dir):
        uri = uri[len(base_dir):]
    return uri


# ---------------------- Severity, flows, tags ---------------------------

def severity_info(result, rule) -> tuple:
    level = result.get('level')
    if not level and rule:
        level = (rule.get('defaultConfiguration') or {}).get('level')
    if not level:
        level = 'warning'              # SARIF default

    sec_sev = None
    rprops = result.get('properties') or {}
    if 'security-severity' in rprops:
        try:
            sec_sev = float(rprops['security-severity'])
        except (TypeError, ValueError):
            pass
    if sec_sev is None and rule:
        rprops2 = rule.get('properties') or {}
        if 'security-severity' in rprops2:
            try:
                sec_sev = float(rprops2['security-severity'])
            except (TypeError, ValueError):
                pass
    rank = result.get('rank')
    return level, sec_sev, rank


def code_flow_summary(result):
    """Compact summary of the first thread of the first code flow."""
    flows = result.get('codeFlows') or []
    if not flows:
        return None
    threads = (flows[0].get('threadFlows') or [])
    if not threads:
        return None
    steps = []
    for step_loc in (threads[0].get('locations') or []):
        location = step_loc.get('location') or {}
        phys = location.get('physicalLocation') or {}
        art = phys.get('artifactLocation') or {}
        region = phys.get('region') or {}
        msg = ((location.get('message') or {}).get('text') or '').strip()
        uri = art.get('uri') or '?'
        line = region.get('startLine')
        loc_str = f"{uri}:{line}" if line is not None else uri
        step_summary = {
            "File": uri,
            "Line": line,
            "Msg": msg
        }
        steps.append(step_summary)
    return steps


def collect_tags(result, rule) -> list:
    tags = []
    if rule:
        for t in ((rule.get('properties') or {}).get('tags') or []):
            if isinstance(t, str):
                tags.append(t)
    for t in ((result.get('properties') or {}).get('tags') or []):
        if isinstance(t, str) and t not in tags:
            tags.append(t)
    return tags


# ---------------------- Per-result conversion ---------------------------

def convert_result(result, run, base_uris, tool_name, args) -> dict:
    rule = find_rule(run, result)

    raw_rule_id = result.get('ruleId') or (rule.get('id') if rule else None)

    uri, uri_base_id, line, column, function = primary_location(result)
    file_path = resolve_path(uri, uri_base_id, base_uris, args.base_dir)

    message = resolve_message(result, rule)
    cwes    = extract_cwes(result, rule)
    level, sec_sev, rank = severity_info(result, rule)

    rule_name = (rule or {}).get('name')
    rule_desc = ((rule or {}).get('shortDescription') or {}).get('text')
    rule_full = ((rule or {}).get('fullDescription') or {}).get('text')
    rule_help = ((rule or {}).get('help') or {}).get('text')

    longer_help = None
    short = (rule_desc or '').strip()
    if rule_full and rule_full.strip() != short:
        longer_help = rule_full
    elif rule_help and rule_help.strip() != short:
        longer_help = rule_help

    cflow = code_flow_summary(result)
    tags  = collect_tags(result, rule)

    suppressions = result.get('suppressions') or []
    is_suppressed = any(
        (s or {}).get('status', 'accepted') == 'accepted' for s in suppressions
    )

    alert = {}

    # ---- (A) LASAA-special fields (used by LASAA's own logic) ----
    alert["File"] = file_path
    alert["Line"] = line
    if cwes:
        alert["CWEs"] = ", ".join(cwes)

    # ---- (B) LLM-facing fields (shown to the LLM as alert context) ----
    if tool_name:
        alert["Tool"] = tool_name
    if message:
        alert["Message"] = message
    if raw_rule_id:
        alert["RuleID"] = raw_rule_id
    if rule_name and rule_name != raw_rule_id:
        alert["RuleName"] = rule_name
    if rule_desc:
        alert["RuleDescription"] = rule_desc
    if longer_help:
        alert["RuleHelp"] = longer_help
    if function:
        alert["Function"] = function
    if column is not None:
        alert["Column"] = column
    if cflow:
        alert["CodeFlow"] = cflow

    # ---- (C) Filter-only fields ----
    alert["Level"] = level
    if sec_sev is not None:
        alert["SecuritySeverity"] = sec_sev
    if rank is not None:
        alert["Rank"] = rank
    bs = result.get('baselineState')
    if bs:
        alert["BaselineState"] = bs
    if is_suppressed:
        alert["Suppressed"] = True
    if tags:
        alert["Tags"] = tags
    rprops = result.get('properties') or {}
    extra_props = {k: v for k, v in rprops.items()
                   if k not in ('tags', 'security-severity', 'cwe')}
    if extra_props:
        alert["Properties"] = extra_props
    fps = result.get('fingerprints') or result.get('partialFingerprints')
    if fps:
        alert["Fingerprints"] = fps

    return alert


# ---------------------- Top-level ---------------------------------------

def iter_results(sarif: dict, args):
    """Yield ``(alert_id, alert_without_id, result)`` for each convertible
    result in the SARIF file's (first) run.

    The ``alert_id`` is computed exactly as in :func:`convert_sarif`, so the
    same SARIF file (with the same ``--base-dir``) always yields the same IDs.
    This lets us map LASAA adjudications - keyed by ``Alert_ID`` - back onto the
    original SARIF result objects (the third tuple element, yielded so callers
    can annotate it in place).
    """
    runs = sarif.get('runs') or []
    if not runs:
        print("Warning: SARIF file contains no runs.", file=sys.stderr)
        return
    if len(runs) > 1:
        print(f"Warning: SARIF file contains {len(runs)} runs; "
              f"only the first will be processed.", file=sys.stderr)

    run = runs[0]
    base_uris = run.get('originalUriBaseIds') or {}
    results   = run.get('results') or []
    tool_name = ((run.get('tool') or {}).get('driver') or {}).get('name')

    for i, r in enumerate(results):
        try:
            alert_without_id = convert_result(r, run, base_uris, tool_name, args)
            if alert_without_id is None:
                continue
            alert_id = hashlib.sha256(
                json.dumps(alert_without_id).encode('utf-8')).hexdigest()[:32]
            yield alert_id, alert_without_id, r
        except Exception as e:
            print(f"Warning: failed to convert result #{i}: {e}",
                  file=sys.stderr)


def convert_sarif(sarif: dict, args) -> list:
    alerts = []
    for alert_id, alert_without_id, _result in iter_results(sarif, args):
        alert = {"Alert_ID": alert_id}
        alert.update(alert_without_id)
        alerts.append(alert)
    return alerts


# ---------------------- SARIF annotation (update mode) ------------------

def annotate_result(result: dict, adjudication: dict) -> None:
    """Annotate a single SARIF result with a LASAA verdict + explanation.

    The full adjudication is always stored in the result's `properties` bag
    (under a `lasaa` key) - SARIF has no standard field for an arbitrary
    triage verdict + rationale, so a property bag is the spec-sanctioned place
    for custom data.  When the verdict marks the alert as a false positive we
    additionally add a standard SARIF `suppressions` entry, which is the
    spec's mechanism for "reviewed and determined not to be a real problem".
    """
    verdict = adjudication.get("verdict")
    explanation = adjudication.get("explanation")

    # (1) Record the structured adjudication in the property bag.
    props = result.get("properties")
    if not isinstance(props, dict):
        props = {}
        result["properties"] = props
    lasaa = {}
    if verdict is not None:
        lasaa["verdict"] = verdict
    if explanation is not None:
        lasaa["explanation"] = explanation
    props["lasaa"] = lasaa

    # (2) Optionally emit a standard suppression for false positives.
    global cmdline_args
    if cmdline_args.sup_fp and isinstance(verdict, str) and \
            verdict.strip().lower() == "false":
        suppression = {
            "kind": "external",        # the verdict comes from outside the source
            "status": "accepted",
            "properties": {"source": "LASAA"},
        }
        if explanation:
            suppression["justification"] = explanation
        result.setdefault("suppressions", []).append(suppression)


def update_sarif(sarif: dict, adjudications: list, args) -> dict:
    """Return `sarif` with each result annotated by its LASAA adjudication.

    Adjudications are matched to results by `Alert_ID`.  The input SARIF dict
    is modified in place (and also returned for convenience).
    """
    adj_by_id = {}
    for adj in adjudications:
        if not isinstance(adj, dict):
            print("Warning: adjudication entry is not an object; skipping.",
                  file=sys.stderr)
            continue
        aid = adj.get("Alert_ID")
        if aid is None:
            print("Warning: adjudication missing 'Alert_ID'; skipping.",
                  file=sys.stderr)
            continue
        if aid in adj_by_id:
            print(f"Warning: duplicate Alert_ID {aid} in adjudications; "
                  f"using the last one.", file=sys.stderr)
        adj_by_id[aid] = adj

    matched_ids = set()
    for alert_id, _alert, result in iter_results(sarif, args):
        adj = adj_by_id.get(alert_id)
        if adj is None:
            continue
        annotate_result(result, adj)
        matched_ids.add(alert_id)

    unmatched = [aid for aid in adj_by_id if aid not in matched_ids]
    if unmatched:
        print(f"Warning: {len(unmatched)} adjudication(s) did not match any "
              f"result in the SARIF file (Alert_IDs: "
              f"{', '.join(unmatched)}).", file=sys.stderr)
    print(f"Annotated {len(matched_ids)} of {len(adj_by_id)} adjudicated "
          f"alert(s) into the SARIF file.", file=sys.stderr)
    return sarif


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Convert SARIF static-analysis output to LASAA JSON.")
    ap.add_argument("sarif_file",
                    help="Input SARIF file (.sarif / .json).")
    ap.add_argument("-o", "--output",
                    help="Output file (default: stdout). In default mode this "
                         "is LASAA input JSON; with -u it is updated SARIF.")
    ap.add_argument("-b", "--base-dir",
                    help="Relativize file names to this directory")
    ap.add_argument("-u", "--update", metavar="ADJUDICATIONS",
                    help="Path to a LASAA adjudications JSON file. When given, "
                         "produce an updated SARIF file (annotated with each "
                         "alert's verdict and explanation) instead of LASAA "
                         "input JSON. Use the same SARIF file and --base-dir "
                         "as the original conversion so the Alert_IDs match.")
    ap.add_argument("--sup-fp", action="store_true",
                    help="When updating the SARIF file, add a 'suppressions' entry for false positives")
    args = ap.parse_args(argv)

    global cmdline_args
    cmdline_args = args

    if args.base_dir and not args.base_dir.endswith("/"):
        args.base_dir += "/"

    with open(args.sarif_file, 'r', encoding='utf-8') as f:
        sarif = json.load(f)

    if args.update:
        with open(args.update, 'r', encoding='utf-8') as f:
            adjudications = json.load(f)
        result_obj = update_sarif(sarif, adjudications, args)
    else:
        result_obj = convert_sarif(sarif, args)

    text = json.dumps(result_obj, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(text)
            f.write('\n')
    else:
        sys.stdout.write(text)
        sys.stdout.write('\n')


if __name__ == "__main__":
    main()
