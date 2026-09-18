<#
.SYNOPSIS
    One-time build of a local scancode-toolkit:local Docker image, used by the
    "scancode" step in Invoke-VendorAuditPrePass.ps1.

.DESCRIPTION
    Build-AuditImages.ps1 now builds this automatically as part of its normal
    "scancode" step (added 2026-09-18) -- use this script instead only if you want
    to (re)build just this one image without running the full image-build pass.

    There is no published ghcr.io/aboutcode-org/scancode-toolkit image to pull
    (confirmed directly: an anonymous `docker manifest inspect` against that
    path returns "denied", and ScanCode Toolkit's own docs - Install ScanCode
    using docker - say explicitly to clone the repo and `docker build` it
    yourself). This script does exactly that, once, so the orchestrator's
    scancode step has a local image to reference by name.

    Kept as its own script rather than folded into Build-AuditToolbox.ps1
    because it builds a completely separate image (ScanCode's own multi-stage
    Dockerfile, not ours) - same reasoning as why ScanCode isn't baked into
    vendor-audit-toolbox itself (heavy dependency footprint, per that
    Dockerfile's own "NOT included" note).

.PARAMETER Tag
    Local image tag to build. Must match the Image value the "scancode" step
    in Invoke-VendorAuditPrePass.ps1 references. Defaults to scancode-toolkit:local.

.PARAMETER CloneDir
    Where to clone the scancode-toolkit source. Defaults to a scancode-toolkit-src
    subfolder next to this script. Safe to delete after the image is built -
    only the resulting Docker image is needed at scan time.

.EXAMPLE
    ./Build-ScanCodeImage.ps1
#>
[CmdletBinding()]
param(
    [string]$Tag = "scancode-toolkit:local",
    [string]$CloneDir = (Join-Path $PSScriptRoot "scancode-toolkit-src")
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required to clone the ScanCode Toolkit source - install Git for Windows and retry."
}

if (-not (Test-Path $CloneDir)) {
    Write-Host "Cloning aboutcode-org/scancode-toolkit into $CloneDir ..." -ForegroundColor Cyan
    & git clone --depth 1 "https://github.com/aboutcode-org/scancode-toolkit.git" $CloneDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed with exit code $LASTEXITCODE" }
} else {
    Write-Host "$CloneDir already exists - using it as-is (delete it first to re-clone fresh)." -ForegroundColor DarkGray
}

Write-Host "Building $Tag from ScanCode Toolkit's own Dockerfile ..." -ForegroundColor Cyan
Write-Host "This is a separate, fairly heavy multi-stage build (its own Python env, native deps) - expect several minutes." -ForegroundColor DarkGray

& docker build --progress=plain --tag $Tag $CloneDir
if ($LASTEXITCODE -ne 0) {
    throw "docker build failed with exit code $LASTEXITCODE - see output above."
}

Write-Host "Built $Tag" -ForegroundColor Green
Write-Host "Sanity check:" -ForegroundColor Cyan
& docker run --rm $Tag --help | Select-Object -First 5
Write-Host ""
Write-Host "The scancode step in Invoke-VendorAuditPrePass.ps1 will now find this image by name." -ForegroundColor Green
