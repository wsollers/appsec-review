# PowerShell twin of engagement_job.sh.
# Runs broad static evidence, native pregather, correlation, deep confirmation,
# retrieval planning, LLM input assembly, and final job-status gating.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Project,

    [Parameter(Mandatory = $true)]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [string]$Out,

    [string]$CompileDb = "",
    [string]$RunId = "",
    [string]$AttemptId = "",
    [string]$Msvc = "-",
    [string]$StaticImage = $(if ($env:STATIC_IMAGE) { $env:STATIC_IMAGE } else { "vendor-audit-toolbox:latest" }),
    [ValidateSet("auto", "bash", "powershell")]
    [string]$StaticRunner = $(if ($env:STATIC_RUNNER) { $env:STATIC_RUNNER } else { "auto" }),
    [string]$StaticSteps = "",
    [switch]$SkipStatic,
    [switch]$SkipNative,
    [switch]$NoCodeQL,
    [switch]$NoCsa
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if ($RunId) {
    & python -B (Join-Path $Root 'appsec-review-process/phase1.py') pipeline-out --reserve --run-id $RunId --attempt-id $AttemptId --out ([IO.Path]::GetFullPath($Out))
    if ($LASTEXITCODE -ne 0) { throw 'Run-owned pipeline output validation failed' }
}
$Target = (Resolve-Path $Target).ProviderPath
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).ProviderPath

$StaticEvidence = Join-Path $Out "static-evidence"
$NativeScratch = Join-Path $Out "native-scratch"
$LlmDir = Join-Path $Out "llm"
$LogDir = Join-Path $Out "logs"
$Manifest = Join-Path $Out "job-manifest.jsonl"
New-Item -ItemType Directory -Force -Path $StaticEvidence, $NativeScratch, $LlmDir, $LogDir | Out-Null
Set-Content -Path $Manifest -Value "" -NoNewline -Encoding UTF8

function Add-ManifestRow {
    param(
        [string]$Step,
        [int]$ExitCode,
        [int]$Seconds,
        [string]$Log,
        [string]$Note = ""
    )
    $row = [ordered]@{
        step = $Step
        exit_code = $ExitCode
        seconds = $Seconds
        log = $Log
        stderr_log = Join-Path (Split-Path -Parent $Log) 'stderr.log'
    }
    if ($Note) { $row.note = $Note }
    ($row | ConvertTo-Json -Compress) | Add-Content -Path $Manifest -Encoding UTF8
}

function Invoke-LoggedStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @()
    )
    $log = Join-Path (Join-Path $LogDir $Name) 'stdout.log'
    Write-Host ""
    Write-Host "#### [$Name] $(Get-Date -Format o)"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $exitCode = 0
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & python -B (Join-Path $Root 'appsec-review-process/pipeline_step.py') --logs (Join-Path $LogDir $Name) --cwd $Root -- $FilePath @Arguments
            $exitCode = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
        } finally {
            $ErrorActionPreference = $prevEap
        }
    } catch {
        $exitCode = 1
        $_ | Out-String | Tee-Object -FilePath $log -Append | Out-Null
        Write-Warning "$Name threw: $($_.Exception.Message)"
    }
    $sw.Stop()
    Add-ManifestRow -Step $Name -ExitCode $exitCode -Seconds ([int]$sw.Elapsed.TotalSeconds) -Log $log
    return $exitCode
}

function Get-BashPath {
    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if ($bash) { return $bash.Source }
    return ""
}

$runStatic = -not $SkipStatic
$runNative = -not $SkipNative
$runCodeql = -not $NoCodeQL
$runCsa = -not $NoCsa

if ($runStatic) {
    $psStatic = Join-Path $Root "scripts/Invoke-VendorAuditPrePass.ps1"
    $bashStatic = Join-Path $Root "scripts/Invoke-VendorAuditPrePass.sh"
    $bashPath = Get-BashPath

    if (($StaticRunner -eq "powershell") -or (($StaticRunner -eq "auto") -and (Test-Path $psStatic))) {
        $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $psStatic, "-RepoPath", $Target, "-EvidencePath", $StaticEvidence, "-ImageTag", $StaticImage, "-CleanEvidence")
        if ($StaticSteps) { $args += @("-Steps", $StaticSteps) }
        [void](Invoke-LoggedStep -Name "static-prepass" -FilePath (Get-Process -Id $PID).Path -Arguments $args)
    } elseif (($StaticRunner -eq "bash") -or (($StaticRunner -eq "auto") -and $bashPath -and (Test-Path $bashStatic))) {
        $args = @($bashStatic, $Target, $StaticEvidence, "--image-tag", $StaticImage, "--clean-evidence")
        if ($StaticSteps) { $args += @("--steps", $StaticSteps) }
        [void](Invoke-LoggedStep -Name "static-prepass" -FilePath $bashPath -Arguments $args)
    } else {
        $log = Join-Path $LogDir "static-prepass.log"
        "WARNING: no usable static prepass runner found; skipping static pre-pass" | Tee-Object -FilePath $log
        Add-ManifestRow -Step "static-prepass" -ExitCode 127 -Seconds 0 -Log $log -Note "no usable static prepass runner found"
    }

    [void](Invoke-LoggedStep -Name "static-summary" -FilePath "python" -Arguments @(
        (Join-Path $Root "scripts/summarize_evidence.py"),
        $StaticEvidence,
        "-o",
        (Join-Path $StaticEvidence "SUMMARY.md")
    ))
}

if ($runNative) {
    $pregatherArgs = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $Root "pipeline/pregather.ps1"),
        "-Target", $Target,
        "-Scratch", $NativeScratch,
        "-Project", $Project,
        "-Msvc", $Msvc
    )
    if ($CompileDb) {
        $pregatherArgs += @("-CompileDb", (Resolve-Path $CompileDb).ProviderPath)
    }
    if ($runCodeql) { $pregatherArgs += "-CodeQL" }
    if ($runCsa) { $pregatherArgs += "-Csa" }
    [void](Invoke-LoggedStep -Name "native-pregather" -FilePath (Get-Process -Id $PID).Path -Arguments $pregatherArgs)

    [void](Invoke-LoggedStep -Name "native-assemble" -FilePath "python" -Arguments @(
        (Join-Path $Root "pipeline/assemble.py"),
        "--scratch", $NativeScratch,
        "--out", (Join-Path $LlmDir "native-bundle.json"),
        "--repo", $Root
    ))
}

[void](Invoke-LoggedStep -Name "correlate-findings" -FilePath "python" -Arguments @(
    (Join-Path $Root "pipeline/correlate_findings.py"),
    "--static-evidence", $StaticEvidence,
    "--native-scratch", $NativeScratch,
    "--bundle", (Join-Path $LlmDir "native-bundle.json"),
    "--out", (Join-Path $LlmDir "correlated-findings.json")
))

[void](Invoke-LoggedStep -Name "deep-confirmation" -FilePath "python" -Arguments @(
    (Join-Path $Root "pipeline/deep_confirm.py"),
    "--static-evidence", $StaticEvidence,
    "--native-scratch", $NativeScratch,
    "--correlated-findings", (Join-Path $LlmDir "correlated-findings.json"),
    "--out", (Join-Path $LlmDir "deep-confirmation.json")
))

[void](Invoke-LoggedStep -Name "retrieval-plan" -FilePath "python" -Arguments @(
    (Join-Path $Root "pipeline/generate_retrieval_plan.py"),
    "--static-evidence", $StaticEvidence,
    "--native-scratch", $NativeScratch,
    "--correlated-findings", (Join-Path $LlmDir "correlated-findings.json"),
    "--out", (Join-Path $LlmDir "retrieval-plan.json")
))

[void](Invoke-LoggedStep -Name "llm-input" -FilePath "python" -Arguments @(
    (Join-Path $Root "pipeline/build_llm_input.py"),
    "--project", $Project,
    "--target", $Target,
    "--static-evidence", $StaticEvidence,
    "--native-scratch", $NativeScratch,
    "--bundle", (Join-Path $LlmDir "native-bundle.json"),
    "--correlated-findings", (Join-Path $LlmDir "correlated-findings.json"),
    "--deep-confirmation", (Join-Path $LlmDir "deep-confirmation.json"),
    "--retrieval-plan", (Join-Path $LlmDir "retrieval-plan.json"),
    "--out-dir", $LlmDir
))

$statusArgs = @(
    (Join-Path $Root "pipeline/job_status.py"),
    "--manifest", $Manifest,
    "--out", $Out,
    "--static-evidence", $StaticEvidence,
    "--native-scratch", $NativeScratch,
    "--llm-dir", $LlmDir
)
if ($runStatic) { $statusArgs += "--static-enabled" }
if ($runNative) { $statusArgs += "--native-enabled" }
if ($runNative -and $runCodeql) { $statusArgs += "--codeql-enabled" }

Write-Host ""
Write-Host "#### [job-status] $(Get-Date -Format o)"
$statusLog = Join-Path $LogDir "job-status.log"
& python @statusArgs *>&1 | Tee-Object -FilePath $statusLog
$statusRc = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }

Write-Host ""
if ($statusRc -eq 0) {
    Write-Host "Engagement job complete: OK."
} else {
    Write-Host "Engagement job complete: DEGRADED. See $(Join-Path $Out 'job-status.md')"
}
Write-Host "Manifest: $Manifest"
Write-Host "LLM input: $(Join-Path $LlmDir 'ENGAGEMENT_LLM_INPUT.md')"
exit $statusRc
