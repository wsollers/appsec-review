# pregather.ps1 — PowerShell twin of pregather.sh (same flags, same outputs). Keep in sync.
#   .\pipeline\pregather.ps1 -Target <src> -Scratch <dir> -Project <name> [-Msvc <dir>] [-CompileDb <path>] [-CodeQL] [-Csa]
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][string]$Scratch, [Parameter(Mandatory)][string]$Project,
      [string]$Msvc = "-", [string]$CompileDb = "", [switch]$CodeQL, [switch]$Csa)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent (Split-Path -Parent $PSCommandPath); $Run = Join-Path $Here "images/audit-native/run.ps1"
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
function Step($n) { Write-Host "`n#### [$n] $(Get-Date -Format T)" -ForegroundColor Cyan }
function R { param([Parameter(ValueFromRemainingArguments)][string[]]$c) & $Run $Target $Msvc $Scratch -- @c; if ($LASTEXITCODE) { throw "step failed ($LASTEXITCODE)" } }
Step "compile database"
if ($CompileDb) {
  $root = (Resolve-Path $Target).Path -replace '\\','/'
  $db = Get-Content $CompileDb -Raw | ConvertFrom-Json
  foreach ($e in $db) { if (-not $e.project) { $e | Add-Member project $Project }
    foreach ($k in 'directory','file','output') { if ($e.$k -and $e.$k.StartsWith($root)) { $e.$k = '/workspace' + $e.$k.Substring($root.Length) } }
    if ($e.arguments) { $e.arguments = @($e.arguments | ForEach-Object { if ($_.StartsWith($root)) { '/workspace' + $_.Substring($root.Length) } else { $_ } }) } }
  $db | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $Scratch 'compile_commands.json')
} else {
  R /opt/scripts/vcxproj_to_compile_commands.py --root /workspace --config Release --platform x64 --msvc-root /msvc --out /scratch/compile_commands.json --audit /scratch/compile-command-audit.seed.json
}
Step "feasibility gate"; R /opt/scripts/compile_feasibility_gate.py --compile-commands /scratch/compile_commands.json --out /scratch/feasibility.json
Step "emit IR"; Remove-Item -Recurse -Force (Join-Path $Scratch ir),(Join-Path $Scratch linked) -ErrorAction SilentlyContinue
R /opt/scripts/compile_feasibility_gate.py --compile-commands /scratch/compile_commands.json --out /scratch/feasibility-ir.json --emit-ir --ir-dir /scratch/ir
Step "link per project"; R /opt/scripts/link_ir.py --feasibility /scratch/feasibility-ir.json --out /scratch/linked
Step "ir-facts"; foreach ($m in Get-ChildItem (Join-Path $Scratch linked) -Filter *.bc) { $n = $m.BaseName; R /opt/ir-facts/ir-facts "/scratch/linked/$n.bc" -o "/scratch/ir-facts-$n.json" }
if ($Csa) { Step "CSA"; R /opt/scripts/run_csa.py --compile-commands /scratch/compile_commands.json --out /scratch/csa --ctu --alpha }
if ($CodeQL) { Step "CodeQL traced DB + mythos pack"
  $env:AUDIT_NATIVE_IMAGE = if ($env:AUDIT_CODEQL_IMAGE) { $env:AUDIT_CODEQL_IMAGE } else { "audit-codeql-native:local" }
  & $Run $Target $Msvc $Scratch -- /opt/scripts/run-codeql.sh --langs cpp --traced-cpp /scratch/compile_commands.json --ram $(if ($env:CODEQL_RAM) { $env:CODEQL_RAM } else { "12000" })
  & $Run $Here - $Scratch -- bash -c "cd /scratch/codeql && rm -f db-cpp/db-cpp/default/cache/.lock && codeql database analyze db-cpp /workspace/queries/mythos-cpp --additional-packs=/opt/codeql/qlpacks --format=sarif-latest --output=mythos.sarif --threads=4 --ram=12000 --rerun 2>&1 | grep -iE error || true"
  Remove-Item Env:AUDIT_NATIVE_IMAGE }
Step "manifest"; python3 (Join-Path $Here "pipeline/manifest.py") $Scratch $Project $Target
Write-Host "pregather complete -> $Scratch" -ForegroundColor Green
