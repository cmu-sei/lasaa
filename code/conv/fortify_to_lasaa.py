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
Convert a Fortify SCA FVDL file to the LASAA JSON input format.

Usage:
    fortify_to_lasaa.py [options] <input.fvdl> -o <output.json>

The input may also be an .fpr file (a zip archive), in which case the
embedded audit.fvdl is extracted and converted.

Output fields useful to provide to the LLM (via --fields-for-llm):
    File, Line     -- sink location (LASAA special fields)
    Function       -- name of the enclosing function
    Kingdom, Type, Subtype, AnalyzerName
    CWEs           -- from the rule metadata (LASAA special field)
    Abstract       -- Fortify's one-paragraph description of the finding,
                      with <Replace .../> placeholders substituted
    Trace          -- the (primary) analysis trace: list of
                      {File, Line, ActionType, Action, ...} dicts

Output fields useful mainly for filtering:
    InstanceID, ClassID
    InstanceSeverity, Confidence, DefaultSeverity
    Impact, Probability, Accuracy  -- from the rule metadata

FVDL versions differ in (a) the XML namespace URI and (b) whether trace
entries contain inline <Node> elements or <NodeRef> references into a
<UnifiedNodePool>; both forms are handled.
"""

import argparse
import hashlib
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile


def strip_namespaces(root):
    """Rewrite all tags (and attribute names) to their local names.

    FVDL files use different namespace URIs depending on the SCA version
    (e.g. "xmlns://www.fortifysoftware.com/schema/fvdl"); some exports have
    no namespace at all.  Stripping namespaces lets the rest of the code
    match on local names only.
    """
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith('{'):
            el.tag = el.tag.split('}', 1)[1]
        for k in list(el.attrib):
            if k.startswith('{'):
                el.attrib[k.split('}', 1)[1]] = el.attrib.pop(k)


def _maybe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


_REPLACE_RE = re.compile(r'<Replace\s+key="([^"]*)"[^>]*>(?:\s*</Replace>)?')
_TAG_RE = re.compile(r'</?[A-Za-z][^>]*>')


def render_description(elem, defs):
    """Render a Description child (e.g. <Abstract>) to plain text.

    Depending on the FVDL version, the markup (Paragraph, Replace, code, ...)
    appears either as XML-escaped text or as real child elements; both forms
    are reduced to one string of markup, then <Replace key="..."/> is
    substituted from the vulnerability's ReplacementDefinitions and the
    remaining tags are stripped.
    """
    if elem is None:
        return None
    parts = [elem.text or '']
    for child in elem:
        parts.append(ET.tostring(child, encoding='unicode'))
    raw = ''.join(parts)
    raw = _REPLACE_RE.sub(lambda m: defs.get(m.group(1), m.group(1)), raw)
    raw = _TAG_RE.sub('', raw)
    raw = html.unescape(raw)
    return re.sub(r'\s+', ' ', raw).strip()


def parse_cwes(group_text):
    """Parse an altcategoryCWE group like "CWE ID 134, CWE ID 787"."""
    if not group_text:
        return []
    return [f'CWE-{n}' for n in re.findall(r'\d+', group_text)]


def node_to_dict(node):
    """Convert a trace <Node> element to a dict for the Trace field."""
    d = {}
    loc = node.find('SourceLocation')
    if loc is not None:
        if loc.get('path'):
            d['File'] = loc.get('path')
        if loc.get('line'):
            d['Line'] = _maybe_int(loc.get('line'))
    action = node.find('Action')
    if action is not None:
        if action.get('type'):
            d['ActionType'] = action.get('type')
        if action.text and action.text.strip():
            d['Action'] = action.text.strip()
    if (node.get('isDefault') or '').lower() == 'true':
        d['IsDefault'] = True
    if node.get('label'):
        d['Label'] = node.get('label')
    return d


def collect_traces(unified, node_pool):
    """Return a list of traces; each trace is a list of node dicts.

    Each <Entry> holds either an inline <Node> or a <NodeRef id="..."/>
    referencing the document-level <UnifiedNodePool>.
    """
    traces = []
    for trace in unified.findall('Trace'):
        for primary in trace.findall('Primary'):
            entries = []
            for entry in primary.findall('Entry'):
                node = entry.find('Node')
                if node is None:
                    ref = entry.find('NodeRef')
                    if ref is not None:
                        node = node_pool.get(ref.get('id'))
                        if node is None:
                            print(f'Warning: NodeRef id={ref.get("id")!r} '
                                  'not found in UnifiedNodePool',
                                  file=sys.stderr)
                if node is None:
                    continue
                d = node_to_dict(node)
                if d:
                    entries.append(d)
            if entries:
                traces.append(entries)
    return traces


def pick_sink(traces):
    """Pick the reported (sink) location: the last isDefault node, else the
    last node that has a source location."""
    flat = [n for t in traces for n in t]
    for n in reversed(flat):
        if n.get('IsDefault') and 'File' in n:
            return n
    for n in reversed(flat):
        if 'File' in n:
            return n
    return None


def resolve_context(unified, context_pool):
    """Return the <Context> element, resolving ContextPool references.

    Older FVDL inlines <Context> under <Unified>; newer versions reference a
    document-level <ContextPool> via <ContextId> or an empty <Context id=..>.
    """
    ctx = unified.find('Context')
    if ctx is not None:
        if len(ctx) == 0 and ctx.get('id') is not None:
            return context_pool.get(ctx.get('id'))
        return ctx
    ctx_id = unified.findtext('ContextId')
    if ctx_id is not None:
        return context_pool.get(ctx_id.strip())
    return None


def vuln_to_alert(vuln, pools):
    """Convert one <Vulnerability> element into a LASAA alert dict
    (without the Alert_ID field)."""
    alert = {}

    class_info = vuln.find('ClassInfo')
    instance_info = vuln.find('InstanceInfo')
    class_id = class_info.findtext('ClassID') if class_info is not None else None

    unified = vuln.find('AnalysisInfo/Unified')
    defs = {}
    traces = []
    context = None
    if unified is not None:
        defs = {d.get('key'): d.get('value', '')
                for d in unified.findall('ReplacementDefinitions/Def')}
        traces = collect_traces(unified, pools['nodes'])
        context = resolve_context(unified, pools['contexts'])

    # --- sink location (LASAA special fields File and Line) ----------------
    sink = pick_sink(traces)
    if sink is None and context is not None:
        decl = context.find('FunctionDeclarationSourceLocation')
        if decl is not None:
            sink = {'File': decl.get('path'), 'Line': _maybe_int(decl.get('line'))}
    if sink is not None:
        if sink.get('File'):
            alert['File'] = sink['File']
        if sink.get('Line') is not None:
            alert['Line'] = sink['Line']

    if context is not None:
        func = context.find('Function')
        if func is not None and func.get('name'):
            name = func.get('name')
            if func.get('enclosingClass'):
                name = f"{func.get('enclosingClass')}.{name}"
            alert['Function'] = name

    # --- classification -----------------------------------------------------
    if class_info is not None:
        for tag in ('Kingdom', 'Type', 'Subtype', 'AnalyzerName'):
            text = class_info.findtext(tag)
            if text:
                alert[tag] = text

    meta = pools['rule_meta'].get(class_id, {})
    alert['CWEs'] = parse_cwes(meta.get('altcategoryCWE', ''))

    desc = pools['descriptions'].get(class_id)
    if desc is not None:
        abstract = render_description(desc.find('Abstract'), defs)
        if abstract:
            alert['Abstract'] = abstract

    if traces:
        alert['Traces'] = traces

    # --- fields for filtering ------------------------------------------------
    if instance_info is not None:
        for fld in ['InstanceID' 'InstanceSeverity', 'Confidence']:
            text = instance_info.findtext(fld)
            if text:
                alert[fld] = text
    if class_info is not None:
        default_severity = class_info.findtext('DefaultSeverity')
        if default_severity:
            alert['DefaultSeverity'] = default_severity
    for name in ('Impact', 'Probability', 'Accuracy'):
        if name in meta:
            alert[name] = meta[name]

    if class_id:
        alert['ClassID'] = class_id

    return alert


def build_pools(root):
    """Index the document-level pools that vulnerabilities reference."""
    rule_meta = {}
    for rule in root.findall('./EngineData/RuleInfo/Rule'):
        groups = {g.get('name'): (g.text or '').strip()
                  for g in rule.findall('MetaInfo/Group')}
        rule_meta[rule.get('id')] = groups
    return {
        'nodes': {n.get('id'): n for n in root.findall('./UnifiedNodePool/Node')},
        'contexts': {c.get('id'): c for c in root.findall('./ContextPool/Context')},
        'descriptions': {d.get('classID'): d for d in root.findall('./Description')},
        'rule_meta': rule_meta,
    }


def parse_fvdl(source):
    """Parse an .fvdl file (or .fpr archive, or file-like object)."""
    if isinstance(source, str) and source.lower().endswith('.fpr'):
        with zipfile.ZipFile(source) as zf:
            with zf.open('audit.fvdl') as f:
                tree = ET.parse(f)
    else:
        tree = ET.parse(source)
    root = tree.getroot()
    strip_namespaces(root)
    return root


def convert(source, id_field='Alert_ID'):
    root = parse_fvdl(source)
    pools = build_pools(root)

    base_path = root.findtext('./Build/SourceBasePath')
    if base_path:
        print(f'Note: SourceBasePath is {base_path!r} '
              '(candidate for the LASAA --base-dir option)', file=sys.stderr)

    alerts = []
    for vuln in root.findall('./Vulnerabilities/Vulnerability'):
        alert = vuln_to_alert(vuln, pools)
        alert_id = hashlib.sha256(
            json.dumps(alert).encode('utf-8')).hexdigest()[:24]
        out = {id_field: alert_id}
        out.update(alert)
        alerts.append(out)
    return alerts


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Convert a Fortify FVDL (or FPR) file to LASAA JSON input.',
    )
    parser.add_argument('fvdl_input',
        help='Fortify .fvdl file, .fpr archive, or "-" for stdin (FVDL XML).',
    )
    parser.add_argument('-o', '--output',
        help='LASAA JSON file (omit or use "-" for stdout).',
    )
    parser.add_argument('--id-field', default='Alert_ID',
        help='Field name to use for the Alert ID (default: "Alert_ID").',
    )
    args = parser.parse_args(argv)

    src = sys.stdin if args.fvdl_input == '-' else args.fvdl_input
    alerts = convert(src, id_field=args.id_field)
    text = json.dumps(alerts, indent=2)

    if args.output in [None, '-']:
        sys.stdout.write(text + '\n')
    else:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(text + '\n')
        print(
            f'Wrote {len(alerts)} alert(s) to {args.output}',
            file=sys.stderr,
        )


if __name__ == '__main__':
    main()
