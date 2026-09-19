<#
.SYNOPSIS
    Builds every pinned appsec-review Docker image from one entrypoint.

.DESCRIPTION
    PowerShell twin of build-audit-images.sh. Prefer the bash version from WSL for the
    performance reasons documented in the repo README (WSL ext4 filesystem, not
    /mnt/c or /mnt/f) — typical WSL checkout: ~/projects/appsec-review. This script is
    for building from native Windows PowerShell + Docker Desktop instead.

    Builds, in order:
      audit-static     vendor-audit-toolbox:latest   (repo-root context; COPYs scripts/)
      audit-native     audit-native:local             (self-contained; slow - SVF build)
      audit-codeql     audit-codeql:local             (needs a pre-downloaded CodeQL bundle;
                                                        auto-downloaded unless -SkipCodeQL)
      audit-iac        audit-iac:local                (self-contained)
      audit-container  audit-container:local          (repo-root context; COPYs scripts/run-dockerfile-lint.sh)
      audit-report     audit-report:local             (self-contained)
      scancode         scancode-toolkit:local          (clones aboutcode-org/scancode-toolkit and
                                                         builds ITS OWN Dockerfile -- there is no
                                                         publishable ghcr.io/aboutcode-org/scancode-toolkit
                                                         image to pull; confirmed directly, anonymous
                                                         manifest pull returns "denied", and ScanCode's
                                                         own install docs say to build it yourself. Kept
                                                         as its own build step -- not baked into
                                                         audit-static -- per that Dockerfile's own "NOT
                                                         included" note (heavy dependency footprint).)

.PARAMETER Only
    Comma-separated subset of: static,native,codeql,iac,container,report,scancode. Default: all.

.PARAMETER ScanCodeCloneDir
    Where to clone aboutcode-org/scancode-toolkit source for the scancode build step. Reused
    as-is on later runs (delete it to re-clone fresh). Default: scripts/scancode-toolkit-src.

.PARAMETER NoCache
    Pass --no-cache to every docker build.

.PARAMETER SkipCodeQL
    Skip audit-codeql entirely (no bundle download, no build).

.PARAMETER CodeqlBundleVersion
    CodeQL bundle release tag to download if missing. Default: codeql-bundle-v2.27.0
    (matches images/audit-codeql/README.md).

.PARAMETER StaticTag
    Tag for audit-static. Default: vendor-audit-toolbox:latest (the default $ImageTag
    every orchestrator script expects).

.PARAMETER ContextDir
    Repo root. Defaults to the parent of this script's directory.

.PARAMETER DockerContext
    `docker --context NAME` for every build (e.g. `desktop-linux` to land images in Docker
    Desktop's engine instead of WSL's own native dockerd when the two are separate contexts -
    check with `docker context ls` / `docker context show`). Default: whatever the current
    default context already resolves to; this overrides it for this invocation only, it does
    not change your default context or touch images already built under a different one.

.EXAMPLE
    ./Build-AuditImages.ps1
    ./Build-AuditImages.ps1 -Only iac,container -NoCache
    ./Build-AuditImages.ps1 -SkipCodeQL
    ./Build-AuditImages.ps1 -DockerContext desktop-linux
#>
[CmdletBinding()]
param(
    [string]$Only = "static,native,codeql,iac,container,report,scancode",
    [switch]$NoCache,
    [switch]$SkipCodeQL,
    [string]$CodeqlBundleVersion = "codeql-bundle-v2.27.0",
    [string]$StaticTag = "vendor-audit-toolbox:latest",
    [string]$ContextDir = (Split-Path -Parent $PSScriptRoot),
    [string]$DockerContext = "",
    [string]$ScanCodeCloneDir = (Join-Path $PSScriptRoot "scancode-toolkit-src")
)

$ErrorActionPreference = "Stop"

$selected = $Only -split "," | ForEach-Object { $_.Trim() }
function Want([string]$name) { return $selected -contains $name }

Write-Host "Repo root: $ContextDir" -ForegroundColor Cyan
$dockerCtxArgs = @()
if ($DockerContext) {
    $dockerCtxArgs = @("--context", $DockerContext)
    Write-Host "Docker context: $DockerContext (override, this invocation only)" -ForegroundColor Cyan
} else {
    $currentCtx = (docker context show) 2>$null
    Write-Host "Docker context: $currentCtx (default, not overridden)" -ForegroundColor DarkGray
}
& docker @dockerCtxArgs info | Out-Null

# Preflight: audit-static and audit-container both COPY from repo-root scripts/;
# fail loudly here rather than letting docker build fail with an opaque
# "file not found" partway through a long build.
$requiredScripts = @(
    "scripts/build_symbol_index.py", "scripts/build_semantic_index.py",
    "scripts/query_semantic_index.py", "scripts/scrub_evidence.py", "scripts/php_parse_coverage.py",
    "scripts/run-sast-php.sh", "scripts/run-semantic-index-batched.sh", "scripts/run-dockerfile-lint.sh"
)
$missing = @()
foreach ($rel in $requiredScripts) {
    if (-not (Test-Path (Join-Path $ContextDir $rel))) { $missing += $rel }
}
if ($missing.Count -gt 0) {
    throw "Missing required file(s) expected by images/audit-static or images/audit-container COPY: $($missing -join ', ')"
}

$noCacheArgs = @()
if ($NoCache) { $noCacheArgs = @("--no-cache") }

$results = New-Object System.Collections.Generic.List[string]
$anyFailed = $false

function Build-One([string]$Name, [string]$Tag, [string]$Dockerfile, [string]$Context) {
    Write-Host ""
    Write-Host "=== Building $Name -> $Tag ===" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $buildArgs = $script:dockerCtxArgs + @("build", "--progress=plain") + $script:noCacheArgs + @("-t", $Tag, "-f", $Dockerfile, $Context)
    & docker @buildArgs
    $sw.Stop()
    if ($LASTEXITCODE -ne 0) {
        $script:results.Add("FAIL $Name -> $Tag ($([int]$sw.Elapsed.TotalSeconds)s)")
        Write-Host "Build failed: $Name. If a tool install step failed, that tool's version pin most" -ForegroundColor Red
        Write-Host "likely drifted (an unpinned go/pip/curl install pulling something new) - see the" -ForegroundColor Red
        Write-Host "Dockerfile's own version-pinning header." -ForegroundColor Red
        $script:anyFailed = $true
        return
    }
    $script:results.Add("OK   $Name -> $Tag ($([int]$sw.Elapsed.TotalSeconds)s)")
}

if (Want "static") {
    Build-One "audit-static" $StaticTag (Join-Path $ContextDir "images/audit-static/Dockerfile") $ContextDir
}

if (Want "native") {
    Write-Host ""
    Write-Host "audit-native build includes an SVF build from source - expect several minutes." -ForegroundColor DarkGray
    Build-One "audit-native" "audit-native:local" (Join-Path $ContextDir "images/audit-native/Dockerfile") (Join-Path $ContextDir "images/audit-native")
}

if (Want "codeql") {
    if ($SkipCodeQL) {
        Write-Host ""
        Write-Host "=== Skipping audit-codeql (-SkipCodeQL) ===" -ForegroundColor Yellow
        $results.Add("SKIP audit-codeql (-SkipCodeQL)")
    } else {
        $bundle = Join-Path $ContextDir "images/audit-codeql/codeql-bundle-linux64.tar.zst"
        if (-not (Test-Path $bundle)) {
            Write-Host ""
            Write-Host "=== Downloading CodeQL bundle ($CodeqlBundleVersion) - audit-codeql needs this before build ===" -ForegroundColor Cyan
            $url = "https://github.com/github/codeql-action/releases/download/$CodeqlBundleVersion/codeql-bundle-linux64.tar.zst"
            Invoke-WebRequest -Uri $url -OutFile $bundle
        }
        Build-One "audit-codeql" "audit-codeql:local" (Join-Path $ContextDir "images/audit-codeql/Dockerfile") (Join-Path $ContextDir "images/audit-codeql")
    }
}

if (Want "iac") {
    Build-One "audit-iac" "audit-iac:local" (Join-Path $ContextDir "images/audit-iac/Dockerfile") (Join-Path $ContextDir "images/audit-iac")
}

if (Want "container") {
    Build-One "audit-container" "audit-container:local" (Join-Path $ContextDir "images/audit-container/Dockerfile") $ContextDir
}

if (Want "report") {
    Build-One "audit-report" "audit-report:local" (Join-Path $ContextDir "images/audit-report/Dockerfile") (Join-Path $ContextDir "images/audit-report")
}

if (Want "scancode") {
    Write-Host ""
    Write-Host "=== Building scancode-toolkit:local ===" -ForegroundColor Cyan
    $scancodeCloneOk = $true
    if (-not (Test-Path $ScanCodeCloneDir)) {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            Write-Host "git is required to clone the ScanCode Toolkit source - install Git for Windows and retry, or build scancode manually with Build-ScanCodeImage.ps1." -ForegroundColor Red
            $results.Add("FAIL scancode -> scancode-toolkit:local (git not found)")
            $anyFailed = $true
            $scancodeCloneOk = $false
        } else {
            Write-Host "Cloning aboutcode-org/scancode-toolkit into $ScanCodeCloneDir ..." -ForegroundColor Cyan
            & git clone --depth 1 "https://github.com/aboutcode-org/scancode-toolkit.git" $ScanCodeCloneDir
            if ($LASTEXITCODE -ne 0) {
                Write-Host "git clone failed with exit code $LASTEXITCODE" -ForegroundColor Red
                $results.Add("FAIL scancode -> scancode-toolkit:local (git clone failed)")
                $anyFailed = $true
                $scancodeCloneOk = $false
            }
        }
    } else {
        Write-Host "$ScanCodeCloneDir already exists - using it as-is (delete it first to re-clone fresh)." -ForegroundColor DarkGray
    }
    if ($scancodeCloneOk) {
        Write-Host "Building scancode-toolkit:local from ScanCode Toolkit's own Dockerfile (separate, fairly heavy multi-stage build - its own Python env, native deps; expect several minutes) ..." -ForegroundColor DarkGray
        Build-One "scancode" "scancode-toolkit:local" (Join-Path $ScanCodeCloneDir "Dockerfile") $ScanCodeCloneDir
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
foreach ($r in $results) { Write-Host $r }

if ($anyFailed) { exit 1 }
