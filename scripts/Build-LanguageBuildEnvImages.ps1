<#
.SYNOPSIS
    Builds language build/LSP/MCP worker images and binary-analysis workers.
#>
[CmdletBinding()]
param(
    [string]$Only = "cpp,java,go,typescript,php,dotnet,python,rust,binary",
    [switch]$NoCache,
    [string]$DockerContext = "",
    [string]$ContextDir = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$selected = $Only -split "," | ForEach-Object { $_.Trim() }
function Want([string]$name) { return $selected -contains $name }

$dockerCtxArgs = @()
if ($DockerContext) { $dockerCtxArgs = @("--context", $DockerContext) }
& docker @dockerCtxArgs info | Out-Null

$noCacheArgs = @()
if ($NoCache) { $noCacheArgs = @("--no-cache") }

$results = New-Object System.Collections.Generic.List[string]
$failed = $false

function Build-One([string]$Name, [string]$Tag, [string]$Dir) {
    Write-Host ""
    Write-Host "=== Building $Name -> $Tag ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $buildArgs = $script:dockerCtxArgs + @("build", "--progress=plain") + $script:noCacheArgs + @("-t", $Tag, (Join-Path $script:ContextDir "images/$Dir"))
    & docker @buildArgs
    $sw.Stop()
    if ($LASTEXITCODE -ne 0) {
        $script:results.Add("FAIL $Name -> $Tag ($([int]$sw.Elapsed.TotalSeconds)s)")
        $script:failed = $true
    } else {
        $script:results.Add("OK   $Name -> $Tag ($([int]$sw.Elapsed.TotalSeconds)s)")
    }
}

if (Want "cpp") { Build-One "cpp" "audit-buildenv-cpp:local" "audit-buildenv-cpp" }
if (Want "java") { Build-One "java" "audit-buildenv-java:local" "audit-buildenv-java" }
if (Want "go") { Build-One "go" "audit-buildenv-go:local" "audit-buildenv-go" }
if (Want "typescript") { Build-One "typescript" "audit-buildenv-typescript:local" "audit-buildenv-typescript" }
if (Want "php") { Build-One "php" "audit-buildenv-php:local" "audit-buildenv-php" }
if (Want "dotnet") { Build-One "dotnet" "audit-buildenv-dotnet:local" "audit-buildenv-dotnet" }
if (Want "python") { Build-One "python" "audit-buildenv-python:local" "audit-buildenv-python" }
if (Want "rust") { Build-One "rust" "audit-buildenv-rust:local" "audit-buildenv-rust" }
if (Want "binary") { Build-One "binary" "audit-binary-analysis:local" "audit-binary-analysis" }

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
foreach ($r in $results) { Write-Host $r }
if ($failed) { exit 1 }
