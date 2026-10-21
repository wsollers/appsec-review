<#
.SYNOPSIS
End the current review (every non-terminal run) with SAFE_TERMINATE; -Now cancels at once.
.DESCRIPTION
PowerShell twin of scripts/review-stop.sh with the same options (-PascalCase). -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [switch]$Now,
    [switch]$Yes,
    [string]$Reason,
    [switch]$DryRun,
    [string]$Url,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')
Invoke-Ops -Name 'review-stop' -Bound $PSBoundParameters -Positional @()
