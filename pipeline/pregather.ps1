# pregather.ps1 — PowerShell twin of pregather.sh (same flags, same outputs). Keep in sync.
#   .\pipeline\pregather.ps1 -Target <src> -Scratch <dir> -Project <name> [-Msvc <dir>] [-CompileDb <path>] [-CodeQL] [-Csa]
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][string]$Scratch, [Parameter(Mandatory)][string]$Project,
      [string]$Msvc = "-", [string]$CompileDb = "", [switch]$CodeQL, [switch]$Csa)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent (Split-Path -Parent $PSCommandPath); $Run = Join-Path $Here "images/audit-native/run.ps1"
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
function Get-HostPython {
  foreach ($candidate in @("python3", "python")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    if ($cmd.Source -like "*\WindowsApps\python3.exe") { continue }
    & $candidate --version *> $null
    if ($LASTEXITCODE -eq 0) { return $candidate }
  }
  throw "No usable host Python found. Install Python or disable the broken python3 App Execution Alias."
}
$Python = Get-HostPython
function Step($n) { Write-Host "`n#### [$n] $(Get-Date -Format T)" -ForegroundColor Cyan }
function Invoke-AuditNative { param([Parameter(Mandatory)][string[]]$Command) & $Run -Workspace $Target -Msvc $Msvc -Scratch $Scratch -Command $Command; if ($LASTEXITCODE) { throw "step failed ($LASTEXITCODE)" } }
Step "compile database"
if ($CompileDb) {
  & $Python (Join-Path $Here "pipeline/normalize_compile_db.py") $CompileDb (Resolve-Path $Target).ProviderPath (Join-Path $Scratch "compile_commands.json") $Project
  if ($LASTEXITCODE) { throw "compile database normalization failed ($LASTEXITCODE)" }
} else {
  Invoke-AuditNative -Command @("/opt/scripts/vcxproj_to_compile_commands.py", "--root", "/workspace", "--config", "Release", "--platform", "x64", "--msvc-root", "/msvc", "--out", "/scratch/compile_commands.json", "--audit", "/scratch/compile-command-audit.seed.json")
}
Step "native SAST (clang-tidy + cppcheck)"
Invoke-AuditNative -Command @("/opt/scripts/run_native_sast.py", "--compile-commands", "/scratch/compile_commands.json", "--out", "/scratch/native-sast")
Step "feasibility gate"; Invoke-AuditNative -Command @("/opt/scripts/compile_feasibility_gate.py", "--compile-commands", "/scratch/compile_commands.json", "--out", "/scratch/feasibility.json")
Step "emit IR"; Remove-Item -Recurse -Force (Join-Path $Scratch ir),(Join-Path $Scratch linked) -ErrorAction SilentlyContinue
Invoke-AuditNative -Command @("/opt/scripts/compile_feasibility_gate.py", "--compile-commands", "/scratch/compile_commands.json", "--out", "/scratch/feasibility-ir.json", "--emit-ir", "--ir-dir", "/scratch/ir")
Step "link per project"; Invoke-AuditNative -Command @("/opt/scripts/link_ir.py", "--feasibility", "/scratch/feasibility-ir.json", "--out", "/scratch/linked")
Step "ir-facts"; foreach ($m in Get-ChildItem (Join-Path $Scratch linked) -Filter *.bc) { $n = $m.BaseName; Invoke-AuditNative -Command @("/opt/ir-facts/ir-facts", "/scratch/linked/$n.bc", "-o", "/scratch/ir-facts-$n.json") }
if ($Csa) { Step "CSA"; Invoke-AuditNative -Command @("/opt/scripts/run_csa.py", "--compile-commands", "/scratch/compile_commands.json", "--out", "/scratch/csa", "--ctu", "--alpha") }
if ($CodeQL) { Step "CodeQL traced DB + mythos pack"
  $oldAuditNativeImage = $env:AUDIT_NATIVE_IMAGE
  try {
    $env:AUDIT_NATIVE_IMAGE = if ($env:AUDIT_CODEQL_IMAGE) { $env:AUDIT_CODEQL_IMAGE } else { "audit-codeql-native:local" }
    $ram = if ($env:CODEQL_RAM) { $env:CODEQL_RAM } else { "12000" }
    & $Run -Workspace $Target -Msvc $Msvc -Scratch $Scratch -Command @("/opt/scripts/run-codeql.sh", "--langs", "cpp", "--traced-cpp", "/scratch/compile_commands.json", "--ram", $ram)
    if ($LASTEXITCODE) { throw "CodeQL regular suite failed ($LASTEXITCODE)" }
    & $Run -Workspace $Here -Msvc "-" -Scratch $Scratch -Command @("bash", "-c", "set -euo pipefail; cd /scratch/codeql; rm -f db-cpp/db-cpp/default/cache/.lock; codeql database analyze db-cpp /workspace/queries/mythos-cpp --additional-packs=/opt/codeql/qlpacks --format=sarif-latest --output=mythos.sarif --threads=4 --ram=$ram --rerun > mythos-analyze.log 2>&1; python3 -c 'import json; print(""mythos findings:"", sum(len(r.get(""results"", [])) for r in json.load(open(""mythos.sarif"")).get(""runs"", [])))'")
    if ($LASTEXITCODE) { throw "CodeQL mythos query pack failed ($LASTEXITCODE)" }
  } finally {
    if ($oldAuditNativeImage) { $env:AUDIT_NATIVE_IMAGE = $oldAuditNativeImage } else { Remove-Item Env:AUDIT_NATIVE_IMAGE -ErrorAction SilentlyContinue }
  }
}
Step "manifest"; & $Python (Join-Path $Here "pipeline/manifest.py") $Scratch $Project $Target
if ($LASTEXITCODE) { throw "manifest generation failed ($LASTEXITCODE)" }
Write-Host "pregather complete -> $Scratch" -ForegroundColor Green
