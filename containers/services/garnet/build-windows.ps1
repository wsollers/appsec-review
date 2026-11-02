<#
.SYNOPSIS
Builds the Windows Nano Server Garnet image for the inference result cache.

.DESCRIPTION
Fetches Microsoft Garnet at the exact v2.2.5 commit, verifies the checkout, and builds
Dockerfile.nanoserver with that checkout as the build context on a Docker host in Windows-containers
mode. Prints the resulting local image ID. Nothing is pushed.
#>
[CmdletBinding()]
param(
    [string]$Tag = "appsec-review/garnet:2.2.5-nanoserver-ltsc2022",
    [string]$SourceDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repository = "https://github.com/microsoft/garnet.git"
$ReleaseTag = "v2.2.5"
$Commit = "8d007138208ce030eb10a50c80e636b1678b83e4"
$Dockerfile = Join-Path $PSScriptRoot "Dockerfile.nanoserver"

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

foreach ($tool in @("git", "docker")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is required on PATH"
    }
}

$osType = (& docker info --format "{{.OSType}}").Trim()
if ($LASTEXITCODE -ne 0) {
    throw "docker info failed; is the Docker engine running?"
}
if ($osType -ne "windows") {
    throw "Docker is in '$osType' containers mode; switch Docker Desktop to Windows containers first"
}

$remote = (& git ls-remote $Repository "refs/tags/$ReleaseTag")
if ($LASTEXITCODE -ne 0 -or -not $remote) {
    throw "cannot resolve $ReleaseTag at $Repository"
}
$remoteCommit = ($remote -split "\s+")[0]
if ($remoteCommit -ne $Commit) {
    throw "$ReleaseTag now points to $remoteCommit, not the pinned $Commit; refusing to build"
}

if (-not $SourceDirectory) {
    $SourceDirectory = Join-Path $env:LOCALAPPDATA "appsec-review\garnet-src\$Commit"
}
if (-not (Test-Path (Join-Path $SourceDirectory ".git"))) {
    New-Item -ItemType Directory -Force -Path $SourceDirectory | Out-Null
    Invoke-Checked git @("-C", $SourceDirectory, "init", "--quiet")
}
Invoke-Checked git @("-C", $SourceDirectory, "-c", "core.autocrlf=false", "fetch", "--quiet", "--depth", "1",
                     $Repository, $Commit)
Invoke-Checked git @("-C", $SourceDirectory, "-c", "core.autocrlf=false", "checkout", "--quiet", "--force",
                     "--detach", "FETCH_HEAD")
Invoke-Checked git @("-C", $SourceDirectory, "clean", "-ffdx", "--quiet")
$head = (& git -C $SourceDirectory rev-parse HEAD).Trim()
if ($head -ne $Commit) {
    throw "checkout is at $head, expected $Commit"
}

Write-Host "Building $Tag from Garnet $ReleaseTag ($Commit) in $SourceDirectory"
Invoke-Checked docker @("build", "--platform", "windows/amd64", "-f", $Dockerfile, "-t", $Tag,
                        $SourceDirectory)

$imageId = (& docker image inspect --format "{{.Id}}" $Tag).Trim()
if ($LASTEXITCODE -ne 0 -or -not $imageId) {
    throw "cannot inspect the built image $Tag"
}
Write-Output $imageId
