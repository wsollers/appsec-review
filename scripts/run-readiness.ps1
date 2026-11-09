<#
.SYNOPSIS
Prepare the review host: preconditions, signing key and anchor, build/smoke/report every image, re-pin, sign, CodeQL packs.
.DESCRIPTION
PowerShell twin of scripts/run-readiness.sh with the same options (-PascalCase). The review host is WSL
(docs/operations/run-readiness.md), so on Windows this always runs the bash twin inside WSL (-Wsl is
implied; the distribution comes from -Distro, default Ubuntu-24.04); under pwsh on Linux it runs the
bash twin directly. -Help prints the option list.
.EXAMPLE
.\scripts\run-readiness.ps1 -DryRun
.EXAMPLE
.\scripts\run-readiness.ps1 -From images -Jobs 4
#>
[CmdletBinding()]
param(
    [ValidateSet('host', 'key', 'images', 'pin', 'sign', 'codeql')][string]$From,
    [ValidateSet('host', 'key', 'images', 'pin', 'sign', 'codeql')][string]$Only,
    [ValidateRange(1, 64)][int]$Jobs,
    [string]$DockerContext,
    [string]$PrivateKey,
    [string]$HostLabel,
    [switch]$DryRun,
    [switch]$Wsl,
    [string]$Distro = 'Ubuntu-24.04',
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')

$arguments = New-Object System.Collections.Generic.List[string]
if ($Help) {
    $arguments.Add('--help')
} else {
    if ($From) { $arguments.Add('--from'); $arguments.Add($From) }
    if ($Only) { $arguments.Add('--only'); $arguments.Add($Only) }
    if ($Jobs) { $arguments.Add('--jobs'); $arguments.Add([string]$Jobs) }
    if ($DockerContext) { $arguments.Add('--docker-context'); $arguments.Add($DockerContext) }
    if ($PrivateKey) { $arguments.Add('--private-key'); $arguments.Add($PrivateKey) }
    if ($HostLabel) { $arguments.Add('--host-label'); $arguments.Add($HostLabel) }
    if ($DryRun) { $arguments.Add('--dry-run') }
}

Write-Host "[run-readiness] repository: $($script:OpsRoot) (from $($script:OpsRootSource))"
$onLinux = (Test-Path variable:IsLinux) -and $IsLinux
$bashTwin = Join-Path (Join-Path $script:OpsRoot 'scripts') 'run-readiness.sh'
if ($onLinux) {
    & bash $bashTwin @arguments
    exit $LASTEXITCODE
}
# Windows: the host is WSL, always.
$bashScript = ConvertTo-WslPath -Distro $Distro -Path $bashTwin
& wsl.exe -d $Distro -- bash $bashScript @arguments
exit $LASTEXITCODE
