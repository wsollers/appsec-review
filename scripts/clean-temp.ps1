<#
.SYNOPSIS
Remove disposable state under test/tmp (dry run unless -Yes).
.DESCRIPTION
PowerShell twin of scripts/clean-temp.sh with the same options (-PascalCase). -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [switch]$Yes,
    [string]$OlderThan,
    [switch]$Docker,
    [switch]$DryRun,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')
Invoke-Ops -Name 'clean-temp' -Bound $PSBoundParameters -Positional @()
