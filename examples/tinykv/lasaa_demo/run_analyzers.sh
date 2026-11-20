#!/bin/bash
# Run Clang Static Analyzer and Cppcheck on tinykv and convert their output
# into one LASAA alert file.
#
# Usage: lasaa_demo/run_analyzers.sh [OUT_DIR]     (default: lasaa_demo/out)
#
# Needs: scan-build (clang-tools), cppcheck, make, python3.
# Set LASAA_DIR to the LASAA `code` directory if it isn't ../../code
# relative to the tinykv directory.
#
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

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(dirname "$HERE")
LASAA_DIR=${LASAA_DIR:-$(cd "$PROJ/../../code" && pwd)}
OUT=$(mkdir -p "${1:-$HERE/out}" && cd "${1:-$HERE/out}" && pwd)

cd "$PROJ"

# 1. Clang Static Analyzer, via scan-build, one SARIF file per source file.
#    alpha.unix.Stream adds FILE* leak checks; dead stores are style noise.
rm -rf "$OUT/scan-build"
echo "Running Clang Static Analyzer..."
make clean >/dev/null
scan-build -sarif -o "$OUT/scan-build" \
    -enable-checker alpha.unix.Stream \
    -disable-checker deadcode.DeadStores \
    make all tests/test_main >"$OUT/scan-build.log" 2>&1
make clean >/dev/null
echo "Running merge_sarif.py..."
python3 "$HERE/merge_sarif.py" "$OUT/clang.sarif" \
    $(find "$OUT/scan-build" -name '*.sarif')

# 2. Cppcheck (warnings and portability; style checks are mostly noise here).
echo "Running Cppcheck..."
cppcheck -q --library=posix --enable=warning,portability --inconclusive \
    --std=c11 -D_GNU_SOURCE -I src --xml --output-file="$OUT/cppcheck.xml" \
    src cli tests

# 3. Convert to LASAA format and combine.
echo "Creating alerts.json..."
python3 "$LASAA_DIR/conv/sarif_to_lasaa.py" "$OUT/clang.sarif" -b "$PROJ" \
    -o "$OUT/clang.alerts.json"
python3 "$LASAA_DIR/conv/cppcheck_to_lasaa.py" "$OUT/cppcheck.xml" \
    -o "$OUT/cppcheck.alerts.json"
python3 "$HERE/combine_alerts.py" "$OUT/alerts.json" \
    "$OUT/clang.alerts.json" "$OUT/cppcheck.alerts.json"

echo "Finished."
