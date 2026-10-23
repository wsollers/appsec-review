<#
.SYNOPSIS
Start (and if needed build) the Dagster stack, then check health, the Claude overlay and model connectivity.
.DESCRIPTION
PowerShell twin of scripts/stack-start.sh with the same options (-PascalCase). -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$NoProbe,
    [switch]$DryRun,
    [switch]$Force,
    [string]$Target,
    [string]$Overlay,
    [ValidateSet('record', 'replay', 'off')][string]$Recording,
    [ValidateSet('dev', 'prod', 'copilot-dev', 'copilot-prod')][string]$Profile,
    [string]$Url,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')
Invoke-Ops -Name 'stack-start' -Bound $PSBoundParameters -Positional @()
