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
Function Location Finder

This script identifies the location of functions defined in a codebase
using ctags and outputs them as tuples of [filename, begin_line, end_line, func_name].
"""

import argparse
import subprocess
import sys
import os
import re
import json
import pdb
import traceback
from pathlib import Path
from typing import List, Tuple, Optional, Dict

stop = pdb.set_trace


class FunctionLocator:
    def __init__(self, use_universal_ctags=True):
        self.use_universal_ctags = use_universal_ctags
        self.ctags_cmd = self._find_ctags_command()
    
    def _find_ctags_command(self) -> str:
        """Find the appropriate ctags command."""
        # Try to find Universal Ctags first (better features)
        for cmd in ['ctags-universal', 'uctags', 'ctags']:
            if self._command_exists(cmd):
                # Check if it's Universal Ctags
                try:
                    result = subprocess.run([cmd, '--version'], 
                                          capture_output=True, text=True, timeout=15)
                    if 'Universal Ctags' in result.stdout:
                        return cmd
                except (subprocess.SubprocessError, FileNotFoundError):
                    continue
        
        # Fallback to any ctags
        for cmd in ['ctags', 'exuberant-ctags']:
            if self._command_exists(cmd):
                return cmd
        
        raise RuntimeError("ctags not found. Please install Universal Ctags.")
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH."""
        try:
            subprocess.run([command, '--version'], 
                          capture_output=True, timeout=15)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _run_ctags(self, paths: List[str]) -> str:
        """Run ctags on the given paths and return the output."""
        cmd = [
            self.ctags_cmd,
            '--output-format=json',  # Use JSON output if available
            '--fields=+nezS',        # Include line numbers, end lines, signatures
            '--kinds-c=+f',          # Include functions for C
            '--kinds-c++=+f',        # Include functions for C++
            '--kinds-java=+m',       # Include methods for Java
            '--languages=C,C++,Java',# Only process C/C++/Java files
            '--recurse',             # Recurse into directories
            '-f', '-',               # Output to stdout
        ] + paths
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            raise RuntimeError(
                f"ctags failed (JSON output format may not be supported by your ctags version; "
                f"please install Universal Ctags): {result.stderr}"
            )
        if not result.stdout.strip().startswith('{'):
            raise RuntimeError(
                "ctags did not produce JSON output. Please install Universal Ctags."
            )
        return result.stdout
    
    def _parse_json_output(self, output: str) -> List[Tuple[str, int, int, str]]:
        """Parse JSON format ctags output."""
        functions = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                tag = json.loads(line)
                kind = tag.get('kind')
                if True: # if kind in ['function', 'method']:
                    filename = tag.get('path', '')
                    func_name = tag.get('name', '')
                    begin_line = int(tag.get('line', 0))
                    end_line = tag.get('end')
                    
                    if end_line == None:
                        if kind in ["function", "method"]:
                            sys.stderr.write(f"Warning: Missing end line for {tag.get('kind')} {func_name!r}; skipping it.\n")
                            continue
                        else:
                            end_line = begin_line
                    end_line = int(end_line)
                    functions.append((filename, begin_line, end_line, func_name, tag.get('kind')))
            
            except (json.JSONDecodeError, ValueError, KeyError):
                continue
        
        return functions
    
    def find_functions(self, paths: List[str]) -> List[Tuple[str, int, int, str]]:
        """Find all functions in the given paths."""
        # Validate paths
        valid_paths = []
        for path in paths:
            if os.path.exists(path):
                valid_paths.append(path)
            else:
                print(f"Warning: Path '{path}' does not exist", file=sys.stderr)
        
        if not valid_paths:
            raise ValueError("No valid paths provided")
        
        # Run ctags and parse JSON output
        output = self._run_ctags(valid_paths)
        functions = self._parse_json_output(output)
        
        # Sort by filename, then by line number
        functions.sort(key=lambda x: (x[0], x[1]))
        
        return functions


def main(alt_args=None):
    parser = argparse.ArgumentParser(
        description='Find function/method locations in codebases',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s src/                     # Analyze all source files in src/
  %(prog)s file1.c file2.cpp        # Analyze specific files
  %(prog)s -o functions.txt src/    # Output to file
        """
    )
    
    parser.add_argument('paths', nargs='+',
                       help='Files or directories to analyze')
    parser.add_argument('-o', '--output', 
                       help='Output file (default: stdout)')
    parser.add_argument("-b", "--base-dir", required=True,
                        help="Project base directory (filepaths will be written relative to this)")
    
    args = parser.parse_args(alt_args)
    base_dir = args.base_dir
    
    class DummyException(Exception):
        pass
    ExceptionToCatch = (Exception if alt_args==None else DummyException)

    try:
        locator = FunctionLocator()
        functions = locator.find_functions(args.paths)
        functions = [list(x) for x in functions]
        for row in functions:
            row[0] = os.path.relpath(row[0], base_dir)
        
        output_data = ("[\n" + ",\n".join(
            json.dumps(list(item), separators=(", ", ": "), indent=None) for item in functions) +
            "\n]\n")
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_data)
            print(f"Found {len(functions)} functions, written to {args.output}")
        else:
            sys.stdout.write(output_data)
    
    except ExceptionToCatch as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
