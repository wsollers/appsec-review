[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).ProviderPath
)
$ErrorActionPreference = "Stop"
$runner = Join-Path $RepoRoot "images/audit-buildenv-common/run.ps1"
$scratch = Join-Path $RepoRoot "scratch/buildenv-smoke/binary"
& $runner audit-binary-analysis:local (Join-Path $RepoRoot "images/test/binary") $scratch -- bash -lc @'
set -euo pipefail
gcc -g -O0 /workspace/hello.c -o /scratch/hello
/scratch/hello | tee /scratch/hello.out
analyze-binary /scratch/hello /scratch/analysis
test -s /scratch/analysis/summary.json
test -s /scratch/analysis/readelf-all.txt
test -s /scratch/analysis/nm-symbols.txt
grep -q "helper" /scratch/analysis/nm-symbols.txt
/opt/binary-analysis-venv/bin/python3 - <<PY
import capstone
import lief
import pefile
from elftools.elf.elffile import ELFFile
print("binary parser imports ok")
PY
'@
exit $LASTEXITCODE
