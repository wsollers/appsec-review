<#
.SYNOPSIS
Launch wave1_review on the target the stack is built for; returns at once.
.DESCRIPTION
PowerShell twin of scripts/review-start.sh with the same options (-PascalCase). -Profile and -Overlay
select the runtime profile (same provider family) and capacity overlay for this run only; -Target and
-Recording must match the container. -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [string]$Target,
    [string]$Overlay,
    [ValidateSet('record', 'replay', 'off')][string]$Recording,
    [ValidateSet('dev', 'prod', 'copilot-dev', 'copilot-prod')][string]$Profile,
    [string]$RunId,
    [double]$IdWait,
    [switch]$StopOnFirstError,
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
Invoke-Ops -Name 'review-start' -Bound $PSBoundParameters -Positional @()
