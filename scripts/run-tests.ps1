<#
.SYNOPSIS
Run a named pytest suite with a unique base temp and a log file.
.DESCRIPTION
PowerShell twin of scripts/run-tests.sh with the same options (-PascalCase). -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Suite,
    [switch]$Background,
    [switch]$Parallel,
    [switch]$Strict,
    [string]$Acceptance,
    [ValidateRange(1, 2)][int]$Workers,
    [int]$Deadline,
    [int]$CaseDeadline,
    [switch]$DryRun,
    [string[]]$Extra,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')
if ($Acceptance) {
    Get-ChildItem Env: | Where-Object { $_.Name -like 'APPSEC_NATIVE_*' } |
        ForEach-Object { Remove-Item -LiteralPath ("Env:" + $_.Name) }
}
Invoke-Ops -Name 'run-tests' -Bound $PSBoundParameters -Positional @('Suite')
