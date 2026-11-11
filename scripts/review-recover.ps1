<#
.SYNOPSIS
Recover one failed application run through the existing guarded steps, in order.
.DESCRIPTION
PowerShell twin of scripts/review-recover.sh with the same options (-PascalCase). For one application
run id it checks that every recorded Dagster dispatch is terminal, reconciles the run's SUBMITTED
submission intent, verifies worker stop for every dispatch, prints the repair plan, asks for one
confirmation (-Yes pre-confirms; -Force never does), admits exactly that plan and resumes the run.
It stops at the first refusal and overrides no check. -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$RunId,
    [switch]$Yes,
    [switch]$NoProbe,
    [double]$IdWait,
    [switch]$DryRun,
    [switch]$Force,
    [string]$Url,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')
Invoke-Ops -Name 'review-recover' -Bound $PSBoundParameters -Positional @('RunId')
