#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="$REPO_ROOT/images/audit-buildenv-common/run.sh"
SCRATCH="$REPO_ROOT/scratch/buildenv-smoke/binary"

"$RUNNER" audit-binary-analysis:local "$REPO_ROOT/images/test/binary" "$SCRATCH" -- bash -lc '
  set -euo pipefail
  gcc -g -O0 /workspace/hello.c -o /scratch/hello
  /scratch/hello | tee /scratch/hello.out
  analyze-binary /scratch/hello /scratch/analysis
  test -s /scratch/analysis/summary.json
  test -s /scratch/analysis/readelf-all.txt
  test -s /scratch/analysis/nm-symbols.txt
  test -s /scratch/analysis/checksec.txt
  test -s /scratch/analysis/binwalk.txt
  test -s /scratch/analysis/retdec-fileinfo.txt
  test -s /scratch/analysis/ssdeep.txt
  test -s /scratch/analysis/tlsh.txt
  test -s /scratch/analysis/die.json -o -s /scratch/analysis/die.txt
  grep -q "helper" /scratch/analysis/nm-symbols.txt
  (ghidra-analyzeHeadless 2>&1 || true) | grep -q "Headless Analyzer"
  java -version >/scratch/java-version.txt 2>&1
  retdec-fileinfo --help >/scratch/retdec-fileinfo-help.txt 2>&1
  retdec-decompiler --help >/scratch/retdec-decompiler-help.txt 2>&1
  cwe_checker --help >/scratch/cwe-checker-help.txt 2>&1
  check_cwe --help >/scratch/check-cwe-help.txt 2>&1
  floss --help >/scratch/floss-help.txt 2>&1
  diec --help >/scratch/diec-help.txt 2>&1 || diec -h >/scratch/diec-help.txt 2>&1
  syft version >/scratch/syft-version.txt 2>&1
  grype version >/scratch/grype-version.txt 2>&1
  trivy --version >/scratch/trivy-version.txt 2>&1
  ssdeep -h >/scratch/ssdeep-help.txt 2>&1 || true
  tlsh -version >/scratch/tlsh-version.txt 2>&1
  qemu-x86_64-static --version >/scratch/qemu-version.txt 2>&1
  apktool --version >/scratch/apktool-version.txt 2>&1
  jadx --version >/scratch/jadx-version.txt 2>&1
  ilspycmd --version >/scratch/ilspycmd-version.txt 2>&1
  frida --version >/scratch/frida-version.txt 2>&1
  /opt/binary-analysis-venv/bin/python3 - <<PY
import angr
import capstone
import lief
import pefile
from elftools.elf.elffile import ELFFile
print("binary parser imports ok")
PY
'
