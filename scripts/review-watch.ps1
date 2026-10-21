<#
.SYNOPSIS
Print one line per newly started job and the final status; exit 0/1 by status.
.DESCRIPTION
PowerShell twin of scripts/review-watch.sh with the same options (-PascalCase). -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [string]$Run,
    [switch]$Once,
    [double]$Interval,
    [string]$Url,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')
Invoke-Ops -Name 'review-watch' -Bound $PSBoundParameters -Positional @()
