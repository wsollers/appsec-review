# ADR-0011: Windows twin of code-location.sh. Runs the host-owned Dagster code location under WSL,
# where the process tree's POSIX-only modules (fcntl, pwd, resource) import cleanly and host Docker
# is Docker Desktop's WSL integration. Foreground: keep this window open while the stack runs.
#
#   .\orchestrator\dagster\code-location.ps1 [-Command start|prepare|check] [-Distro <name>]
param(
    [ValidateSet('start', 'prepare', 'check')][string]$Command = 'start',
    [string]$Distro = ''
)
$ErrorActionPreference = 'Stop'
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$script = (Join-Path $PSScriptRoot 'code-location.sh') -replace '\\', '/'
$linuxScript = (& wsl.exe @wslArgs -- wslpath -a -u $script).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxScript) { throw "wslpath could not translate $script" }
& wsl.exe @wslArgs -- bash $linuxScript $Command
exit $LASTEXITCODE
