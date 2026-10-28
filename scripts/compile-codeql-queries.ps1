<#
.SYNOPSIS
Compile the CodeQL queries that need compiling into the shared compile cache review runs mount.
.DESCRIPTION
PowerShell twin of scripts/compile-codeql-queries.sh with the same options (-PascalCase). CodeQL
compiles run only under Linux Docker, so on Windows this always runs the bash twin inside WSL (the
distribution comes from -Distro, else from a \\wsl.localhost\<distro>\ checkout path, else the WSL
default distribution); under pwsh on Linux it runs the bash twin directly. -Wsl is accepted for
consistency with the other twins and is implied on Windows.
Details: docs/operations/codeql-analysis.md (Compiling CodeQL queries) and scripts/README.md.
.EXAMPLE
.\scripts\compile-codeql-queries.ps1 -DryRun
.EXAMPLE
.\scripts\compile-codeql-queries.ps1 -Language go,java -Ram 7000 -Threads 8
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)][string[]]$Pack,
    [string[]]$Language,
    [int]$Ram,
    [int]$Threads,
    [switch]$DryRun,
    [switch]$AllowConcurrent,
    [switch]$Wsl,
    [string]$Distro,
    [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot 'lib') 'common.ps1')

$arguments = New-Object System.Collections.Generic.List[string]
if ($Help) {
    $arguments.Add('--help')
} else {
    foreach ($item in @($Language)) { if ($item) { $arguments.Add('--language'); $arguments.Add($item) } }
    if ($Ram) { $arguments.Add('--ram'); $arguments.Add([string]$Ram) }
    if ($Threads) { $arguments.Add('--threads'); $arguments.Add([string]$Threads) }
    if ($DryRun) { $arguments.Add('--dry-run') }
    if ($AllowConcurrent) { $arguments.Add('--allow-concurrent') }
    foreach ($item in @($Pack)) { if ($item) { $arguments.Add($item) } }
}

Write-Host "[compile-codeql-queries] repository: $($script:OpsRoot) (from $($script:OpsRootSource))"
$onLinux = (Test-Path variable:IsLinux) -and $IsLinux
if ($onLinux) {
    & bash (Join-Path (Join-Path $script:OpsRoot 'scripts') 'compile-codeql-queries.sh') @arguments
    exit $LASTEXITCODE
}

if (-not $Distro -and $script:OpsRoot -match '^\\\\wsl(\.localhost|\$)\\(?<distro>[^\\]+)\\') {
    $Distro = $Matches['distro']
}
$windowsScript = Join-Path (Join-Path $script:OpsRoot 'scripts') 'compile-codeql-queries.sh'
if ($Distro) {
    $bashScript = ConvertTo-WslPath -Distro $Distro -Path $windowsScript
    $selector = @('-d', $Distro)
} else {
    $translated = & wsl.exe -e wslpath -a ($windowsScript -replace '\\', '/')
    if ($LASTEXITCODE -ne 0 -or -not $translated) { throw "wslpath could not translate '$windowsScript'" }
    $bashScript = ([string]($translated | Select-Object -First 1)).Trim()
    $selector = @()
}
Write-Host "[compile-codeql-queries] running in WSL ($(if ($Distro) { $Distro } else { 'default distribution' })): $bashScript"
& wsl.exe @selector -e bash $bashScript @arguments
exit $LASTEXITCODE
