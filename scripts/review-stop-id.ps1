<#
.SYNOPSIS
End one review by Dagster run id or application run id.
.DESCRIPTION
PowerShell twin of scripts/review-stop-id.sh with the same options (-PascalCase). -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Id,
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
Invoke-Ops -Name 'review-stop-id' -Bound $PSBoundParameters -Positional @('Id')
