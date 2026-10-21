<#
.SYNOPSIS
Show container logs.
.DESCRIPTION
PowerShell twin of scripts/stack-logs.sh with the same options (-PascalCase). -Wsl re-runs the bash
twin inside the WSL distribution named by -Distro (default Ubuntu-24.04) with translated paths; use it
when the Dagster stack runs in WSL. -Help prints the option list. Details: docs/operations/operator-scripts.md.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('postgres', 'code-location', 'daemon', 'webserver')][string]$Service,
    [int]$Tail,
    [switch]$Follow,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')
Invoke-Ops -Name 'stack-logs' -Bound $PSBoundParameters -Positional @('Service')
