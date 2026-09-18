<#
.SYNOPSIS
    Builds the vendor-audit-toolbox Docker image used by
    Invoke-VendorAuditPrePass.ps1 (Phase 0A of the Vendor Code Audit Playbook).

.DESCRIPTION
    Thin wrapper around `docker build`. Split out from the orchestrator script
    so you can rebuild the toolbox on its own (after editing the Dockerfile,
    bumping a tool version, etc.) without re-running a scan.

.PARAMETER ContextDir
    Docker build context. Defaults to the repository root. The Dockerfile lives
    under images/audit-static and COPYs scripts from the repo's scripts/
    directory.

.PARAMETER Tag
    Image tag to build. Defaults to vendor-audit-toolbox:latest.

.PARAMETER NoCache
    Pass --no-cache to force a full rebuild (useful after bumping @latest
    Go-tool versions baked into earlier layers).

.EXAMPLE
    ./Build-AuditToolbox.ps1
    ./Build-AuditToolbox.ps1 -Tag vendor-audit-toolbox:2026-08-31 -NoCache
#>
[CmdletBinding()]
param(
    [string]$ContextDir = (Split-Path -Parent $PSScriptRoot),
    [string]$Tag = "vendor-audit-toolbox:latest",
    [switch]$NoCache
)

$ErrorActionPreference = "Stop"

$dockerfile = Join-Path $ContextDir "images/audit-static/Dockerfile"
if (-not (Test-Path $dockerfile)) {
    throw "No Dockerfile found at $dockerfile - pass -ContextDir pointing at the repository root."
}
# scrub_evidence.py (E4-1 fix - evidence-tree secret scrubbing) and
# php_parse_coverage.py (S6-1 fix - PHP parse-coverage ledger) added to this
# preflight list on 2026-09-01, alongside the Dockerfile COPY line that now
# pulls them in - without both changes together, this check would pass but
# `docker build` would fail later with a much less clear "file not found"
# from COPY itself.
# run-sast-php.sh, analyze_dependency_lifecycle.py, and eol-reference.json were
# added to the Dockerfile's COPY line on 2026-09-17 (dependency-lifecycle step,
# design-v3.md L1 broadening) but NOT added here at the same time - confirmed
# 2026-09-18 as the root cause of a real failure: vendor-audit-toolbox:latest
# was built before that Dockerfile change, so /opt/scripts/analyze_dependency_
# lifecycle.py did not exist in the running container and the dependency-
# lifecycle step failed with "python3: can't open file ... No such file or
# directory" (exit 2) until the image was rebuilt. Added retroactively here so
# this preflight check actually catches the next drift of this kind before a
# docker build, instead of after a step silently fails inside a stale image.
foreach ($required in @("build_symbol_index.py", "md_to_sarif.py", "build_semantic_index.py", "query_semantic_index.py", "scrub_evidence.py", "php_parse_coverage.py", "run-semantic-index-batched.sh", "run-sast-php.sh", "analyze_dependency_lifecycle.py", "eol-reference.json")) {
    if (-not (Test-Path (Join-Path $ContextDir "scripts/$required"))) {
        throw "Missing scripts/$required - the image COPYs this in at build time."
    }
}

Write-Host "Building $Tag from $ContextDir using $dockerfile ..." -ForegroundColor Cyan
Write-Host "This installs a Go toolchain, a Rust toolchain (for weggli), Composer packages, and" -ForegroundColor DarkGray
Write-Host "several pip/go-installed scanners from their upstream sources - expect this to take" -ForegroundColor DarkGray
Write-Host "several minutes on first build and to need outbound network access." -ForegroundColor DarkGray

# --progress=plain forces Docker to stream each RUN step's real stdout/stderr
# instead of collapsing it behind the interactive BuildKit UI - without this,
# a failure deep inside a chained RUN (e.g. one `go install` in a list of
# eight) shows only the step boundary, not the actual compiler/tool error
# that caused it. Worth the noisier output for that reason alone.
$buildArgs = @("build", "--progress=plain", "-t", $Tag, "-f", $dockerfile)
if ($NoCache) { $buildArgs += "--no-cache" }
$buildArgs += $ContextDir

& docker @buildArgs
if ($LASTEXITCODE -ne 0) {
    throw "docker build failed with exit code $LASTEXITCODE - see output above. If a specific tool's install step failed, that's the most likely thing to have drifted (an @latest Go/cargo install pulling a version that changed its build requirements); pin that tool's version in the Dockerfile and retry."
}

Write-Host "Built $Tag" -ForegroundColor Green
