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
Convert Cppcheck XML output to LASAA JSON input format.

Usage:
    cppcheck_to_lasaa.py [options] <input.xml> -o <output.json>
"""

import argparse
import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET


# <error> attributes we map to dedicated, friendly field names. Anything else
# encountered on an <error> element is preserved under "Cppcheck_<name>".
_KNOWN_ERROR_ATTRS = frozenset({
    'id', 'severity', 'msg', 'verbose', 'inconclusive', 'cwe', 'remark', 'file0',
})


def parse_cwes(cwe_attr):
    """Parse a Cppcheck ``cwe`` attribute into a list of ``CWE-<n>`` strings.

    Cppcheck normally emits a single bare integer (e.g. ``cwe="312"``) but we
    accept comma-separated lists for robustness. Returns ``[]`` for empty
    input, which keeps the LASAA ``CWEs`` field present-but-empty.
    """
    if not cwe_attr:
        return []
    cwes = []
    for token in cwe_attr.split(','):
        token = token.strip()
        if not token:
            continue
        if not token.upper().startswith('CWE-'):
            token = f'CWE-{token}'
        cwes.append(token)
    return cwes


def _maybe_int(value):
    """Convert to int when possible; otherwise return the original value."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def location_to_dict(loc):
    """Convert a ``<location>`` element to a dict, preserving every attribute."""
    d = dict(loc.attrib)
    if 'line' in d:
        d['line'] = _maybe_int(d['line'])
    if 'column' in d:
        d['column'] = _maybe_int(d['column'])
    return d


def error_to_alert(error):
    """Convert one ``<error>`` XML element into a LASAA alert dict.

    The returned dict does *not* include the Alert_ID field; the caller is
    expected to compute that from the dict's ``repr`` and prepend it.
    """
    alert = {}
    attrs = error.attrib
    file0 = None

    # --- well-known <error> attributes -------------------------------------
    checker_id = attrs.get('id')
    if checker_id:
        if checker_id == "ConfigurationNotChecked":
            return None
        alert['CppcheckID'] = checker_id
    if 'severity' in attrs:
        alert['Severity'] = attrs['severity']
    if 'msg' in attrs:
        alert['Message'] = attrs['msg']
    if 'verbose' in attrs and attrs.get('verbose') != attrs.get('msg'):
        alert['VerboseMessage'] = attrs['verbose']
    if 'inconclusive' in attrs:
        alert['Inconclusive'] = attrs['inconclusive'].strip().lower() == 'true'
    if 'remark' in attrs:
        alert['Remark'] = attrs['remark']
    if 'file0' in attrs:
        file0 = attrs['file0']

    # CWEs is always emitted (possibly empty) so downstream consumers can
    # rely on the field's presence.
    alert['CWEs'] = parse_cwes(attrs.get('cwe', ''))

    # Preserve any unrecognized <error> attributes verbatim.
    for k, v in attrs.items():
        if k not in _KNOWN_ERROR_ATTRS:
            alert[f'Cppcheck_{k}'] = v

    # --- <location> children -----------------------------------------------
    locations = error.findall('location')
    if locations:
        primary = locations[0].attrib
        if 'file' in primary:
            alert['File'] = primary['file']
        if 'line' in primary:
            alert['Line'] = _maybe_int(primary['line'])
        if 'column' in primary:
            alert['Column'] = _maybe_int(primary['column'])
        file0 = primary.get('file0') or file0
        if file0 and file0 != primary.get('file'):
            alert['SourceFile'] = file0
        if 'info' in primary:
            alert['LocationInfo'] = primary['info']
        # Preserve any other primary-location attributes Cppcheck may emit.
        for k, v in primary.items():
            if k not in {'file', 'line', 'column', 'file0', 'info'}:
                alert[f'PrimaryLocation_{k}'] = v
        if len(locations) > 1:
            alert['AdditionalLocations'] = [
                location_to_dict(loc) for loc in locations[1:]
            ]

    # --- <symbol> children (emitted by some Cppcheck versions) -------------
    symbols = [s.text for s in error.findall('symbol') if s.text is not None]
    if symbols:
        alert['Symbols'] = symbols

    # --- any other unrecognized child elements -----------------------------
    extras = []
    for child in error:
        if child.tag in ('location', 'symbol'):
            continue
        extras.append({
            'tag': child.tag,
            'attrib': dict(child.attrib),
            'text': child.text,
        })
    if extras:
        alert['CppcheckExtraElements'] = extras

    return alert


def compute_alert_id(alert):
    """Return the first 24 hex digits of SHA-256(repr(alert))."""
    return hashlib.sha256(repr(alert).encode('utf-8')).hexdigest()[:24]


def convert(xml_source, id_field='Alert_ID'):
    """Parse Cppcheck XML and return a list of LASAA alert dicts.

    ``xml_source`` may be a path or a file-like object.
    """
    tree = ET.parse(xml_source)
    root = tree.getroot()

    cppcheck_elem = root.find('cppcheck')

    alerts = []
    for error in root.iter('error'):
        alert = error_to_alert(error)
        if alert is None:
            continue
        alert_id = compute_alert_id(alert)
        # Build a new dict so Alert_ID appears first in the JSON output.
        out = {id_field: alert_id}
        out.update(alert)
        alerts.append(out)
    return alerts


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Convert Cppcheck XML output to LASAA JSON input.',
    )
    parser.add_argument(
        'xml_input',
        help='Cppcheck XML file (use "-" for stdin).',
    )
    parser.add_argument(
        '-o', '--output',
        help='LASAA JSON file (omit or use "-" for stdout).',
    )
    parser.add_argument(
        '--id-field',
        default='Alert_ID',
        help='Field name to use for the Alert ID (default: "Alert_ID").',
    )
    args = parser.parse_args(argv)

    src = sys.stdin if args.xml_input == '-' else args.xml_input
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
