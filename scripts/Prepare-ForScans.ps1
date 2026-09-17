<#
.SYNOPSIS
    Step-0 host bootstrap for the appsec-review harness: checks and, with per-item
    confirmation, installs the command-line prerequisites via winget, verifies Docker
    is actually usable (not just installed), and optionally hands off to the existing
    scripts/Build-AuditImages.ps1 to build the pinned Docker images.

.DESCRIPTION
    This script only provisions the host. It does not build images itself (that is
    scripts/Build-AuditImages.ps1's job, invoked here as an optional last step) and it
    is not the fast pre-run readiness check (that is appsec-review-process/review_cli.py
    check, which is non-mutating and safe to run before every driver invocation -- this
    script is the one-time/occasional step that actually changes the machine).

    Tools checked: git, ripgrep, 7-Zip, GitHub CLI (gh), Docker Desktop.
    The Claude Code / model CLI is detected only, never auto-installed -- there is no
    winget package for it and the real install method (npm global install, an official
    installer, or something private for a future model endpoint) is not yet confirmed.
    See appsec-review-process/model-config.json's invocation section for the current
    state of that decision.

.PARAMETER Yes
    Skip the per-tool confirmation prompt and install everything that's missing.
    Without this switch, every missing tool is confirmed individually before installing.

.PARAMETER CheckOnly
    Detect and report only. Never calls winget, never prompts to install anything.
    Safe to run any time, including unattended.

.PARAMETER Only
    Comma-separated subset of: git,ripgrep,7zip,gh,docker,claude-cli. Default: all.

.PARAMETER BuildImages
    After host tools are confirmed and Docker is confirmed usable, invoke
    scripts/Build-AuditImages.ps1 (itself asked for confirmation unless -Yes is also
    passed, since a full image build is long-running).

.PARAMETER DockerContext
    Passed through to Build-AuditImages.ps1 -DockerContext when -BuildImages is used.

.EXAMPLE
    ./Prepare-ForScans.ps1 -CheckOnly
    ./Prepare-ForScans.ps1
    ./Prepare-ForScans.ps1 -Only docker,gh
    ./Prepare-ForScans.ps1 -BuildImages -DockerContext desktop-linux
#>
[CmdletBinding()]
param(
    [switch]$Yes,
    [switch]$CheckOnly,
    [string]$Only = "git,ripgrep,7zip,gh,docker,claude-cli",
    [switch]$BuildImages,
    [string]$DockerContext = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Selected = $Only.Split(",") | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ }

function Write-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $mark = if ($Ok) { "[OK]  " } else { "[MISS]" }
    Write-Host "$mark $Name -- $Detail"
}

function Test-WingetAvailable {
    return [bool](Get-Command winget -ErrorAction SilentlyContinue)
}

function Confirm-Install {
    param([string]$Name)
    if ($script:Yes) { return $true }
    $answer = Read-Host "Install $Name now via winget? [y/N]"
    return $answer -match '^[Yy]'
}

function Install-WingetPackage {
    param([string]$Id, [string]$Name)
    Write-Host "Installing $Name ($Id) via winget..."
    winget install --id $Id -e --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$Name install via winget exited $LASTEXITCODE -- check output above."
        return $false
    }
    return $true
}

# Each entry: key, human name, detection scriptblock (returns bool), winget package id
$Tools = @(
    @{ Key = "git";        Name = "git";                  Check = { [bool](Get-Command git -ErrorAction SilentlyContinue) };  WingetId = "Git.Git" }
    @{ Key = "ripgrep";    Name = "ripgrep (rg)";          Check = { [bool](Get-Command rg -ErrorAction SilentlyContinue) };   WingetId = "BurntSushi.ripgrep.MSVC" }
    @{ Key = "7zip";       Name = "7-Zip (7z)";            Check = { [bool](Get-Command 7z -ErrorAction SilentlyContinue) };   WingetId = "7zip.7zip" }
    @{ Key = "gh";         Name = "GitHub CLI (gh)";       Check = { [bool](Get-Command gh -ErrorAction SilentlyContinue) };   WingetId = "GitHub.cli" }
)

Write-Host "=== appsec-review host bootstrap ==="
Write-Host "Repo root: $RepoRoot"
Write-Host ""

if (-not (Test-WingetAvailable) -and ($Selected | Where-Object { $_ -in @("git","ripgrep","7zip","gh","docker") })) {
    Write-Warning "winget not found on PATH. Install 'App Installer' from the Microsoft Store, then re-run this script. Falling back to detect-only for winget-installed tools."
}

$results = @()

foreach ($tool in $Tools) {
    if ($tool.Key -notin $Selected) { continue }
    $ok = & $tool.Check
    if ($ok) {
        Write-Result -Name $tool.Name -Ok $true -Detail "found"
        $results += @{ tool = $tool.Key; ok = $true; action = "none" }
        continue
    }
    if ($CheckOnly -or -not (Test-WingetAvailable)) {
        Write-Result -Name $tool.Name -Ok $false -Detail "not found (winget install: $($tool.WingetId))"
        $results += @{ tool = $tool.Key; ok = $false; action = "not-installed" }
        continue
    }
    if (Confirm-Install -Name $tool.Name) {
        $installed = Install-WingetPackage -Id $tool.WingetId -Name $tool.Name
        $ok2 = & $tool.Check
        Write-Result -Name $tool.Name -Ok $ok2 -Detail $(if ($ok2) { "installed" } else { "install ran but tool still not detected on PATH -- a new shell may be needed" })
        $results += @{ tool = $tool.Key; ok = $ok2; action = "installed" }
    } else {
        Write-Result -Name $tool.Name -Ok $false -Detail "skipped (declined)"
        $results += @{ tool = $tool.Key; ok = $false; action = "declined" }
    }
}

# --- Docker: installed-ness and actually-usable-ness are two different questions ---
if ("docker" -in $Selected) {
    $dockerCli = [bool](Get-Command docker -ErrorAction SilentlyContinue)
    $dockerUsable = $false
    if ($dockerCli) {
        docker info *> $null
        $dockerUsable = ($LASTEXITCODE -eq 0)
    }

    if ($dockerUsable) {
        Write-Result -Name "Docker" -Ok $true -Detail "docker info responded -- engine is usable"
        $results += @{ tool = "docker"; ok = $true; action = "none" }
    } elseif ($dockerCli) {
        Write-Result -Name "Docker" -Ok $false -Detail "docker CLI present but 'docker info' failed -- Docker Desktop is likely not running. Launch it, complete first-run setup (EULA, WSL2 backend), then re-run this script."
        $results += @{ tool = "docker"; ok = $false; action = "needs-manual-start" }
    } elseif ($CheckOnly -or -not (Test-WingetAvailable)) {
        Write-Result -Name "Docker" -Ok $false -Detail "not found (winget install: Docker.DockerDesktop)"
        $results += @{ tool = "docker"; ok = $false; action = "not-installed" }
    } elseif (Confirm-Install -Name "Docker Desktop") {
        Install-WingetPackage -Id "Docker.DockerDesktop" -Name "Docker Desktop" | Out-Null
        Write-Result -Name "Docker" -Ok $false -Detail "winget install ran -- Docker Desktop still needs a manual first launch (EULA, WSL2 backend setup) before it's usable. Re-run this script after that to confirm."
        $results += @{ tool = "docker"; ok = $false; action = "installed-needs-manual-first-run" }
    } else {
        Write-Result -Name "Docker" -Ok $false -Detail "skipped (declined)"
        $results += @{ tool = "docker"; ok = $false; action = "declined" }
    }
}

# --- Claude / model CLI: detect only, never auto-install ---
if ("claude-cli" -in $Selected) {
    $claudePath = (Get-Command claude -ErrorAction SilentlyContinue).Source
    if ($claudePath) {
        Write-Result -Name "claude (model CLI)" -Ok $true -Detail "found at $claudePath -- confirm separately whether this is the full-featured CLI or a restricted build (see model-config.json invocation.status)"
        $results += @{ tool = "claude-cli"; ok = $true; action = "none" }
    } else {
        Write-Result -Name "claude (model CLI)" -Ok $false -Detail "not found on PATH. No winget package exists for this -- install per Anthropic's current instructions (commonly 'npm install -g @anthropic-ai/claude-code', requires Node.js/npm) or point model-config.json's invocation.command_template at whatever CLI you actually intend to use (e.g. a private fable endpoint's client)."
        $results += @{ tool = "claude-cli"; ok = $false; action = "manual-install-required" }
    }
}

Write-Host ""
$allOk = -not ($results | Where-Object { -not $_.ok })
if ($allOk) {
    Write-Host "All selected tools are present and usable."
} else {
    $missing = ($results | Where-Object { -not $_.ok } | ForEach-Object { $_.tool }) -join ", "
    Write-Host "Still missing/unusable: $missing"
}

if ($BuildImages) {
    if (-not $allOk -and ("docker" -in $Selected)) {
        $dockerResult = $results | Where-Object { $_.tool -eq "docker" } | Select-Object -First 1
        if (-not $dockerResult.ok) {
            Write-Warning "Skipping image build -- Docker is not confirmed usable yet."
            return
        }
    }
    $go = $Yes -or (Read-Host "Run scripts/Build-AuditImages.ps1 now? This is long-running. [y/N]") -match '^[Yy]'
    if ($go) {
        $buildArgs = @()
        if ($DockerContext) { $buildArgs += @("-DockerContext", $DockerContext) }
        & (Join-Path $RepoRoot "scripts\Build-AuditImages.ps1") @buildArgs
    } else {
        Write-Host "Skipped image build. Run scripts\Build-AuditImages.ps1 yourself when ready."
    }
}
