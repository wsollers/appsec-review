<#
.SYNOPSIS
    Tests whether `claude -p` dispatch works under Claude Max subscription auth (as
    opposed to being hard-restricted to ANTHROPIC_API_KEY pay-as-you-go billing), and
    compares reported cost against an API-key-billed baseline for the same lane.

.DESCRIPTION
    This is the test flagged as an open TODO in claude/review-cli-harness-2026-09-17.md
    / claude/TODO.md: an ANTHROPIC_API_KEY env var forces API/Console pay-as-you-go
    billing and overrides a Claude Max subscription login even when logged into Max
    elsewhere. This script saves the current ANTHROPIC_API_KEY (if any) to a local
    variable, removes it from THIS PROCESS's environment only (your persisted user/
    system env var is never touched), runs a cheap bare `claude -p` sanity check first,
    then -- unless -QuickCheckOnly is passed -- dispatches the requested review_cli.py
    lane with the key still unset, and finally restores the key (even if the dispatch
    throws or fails). It prints a before/after `review_cli.py cost` diff so you can see
    exactly what this one no-key attempt added.

    The API key is restored in a `finally` block so it comes back even on error --
    but if this script is killed hard (Ctrl+C twice, terminal closed, machine sleeps
    mid-run) the restore may not run. If ANTHROPIC_API_KEY looks unset in a later
    shell and you didn't mean to unset it permanently, re-set it from your normal
    secrets source; this script's copy only lives in that one process's memory and is
    never written to disk.

.PARAMETER RunId
    The run ID to test against, e.g. 20260917T193147Z-2319a6.

.PARAMETER Lane
    The lane to (re)dispatch for the comparison. Defaults to 02-evidence-pregather,
    which is already known-OK and verification-only for this run, so re-running it is
    cheap regardless of which billing mode ends up engaged -- a low-risk way to test
    auth without burning real budget on a lane that hasn't run yet.

.PARAMETER Budget
    Budget tier for the lane dispatch. Defaults to probe (the cheapest tier) since
    this is an auth test, not a real evidence-gathering pass.

.PARAMETER QuickCheckOnly
    Only run the bare `claude -p "reply with OK"` sanity check with no API key set,
    then restore the key and stop -- skips the full review_cli.py lane dispatch.
    Use this first if you just want a fast, minimal-cost read on whether auth works
    at all before spending anything on a real lane.

.EXAMPLE
    powershell -File scripts\Test-SubscriptionAuth.ps1 -RunId 20260917T193147Z-2319a6 -QuickCheckOnly

    Fastest possible check: one bare claude -p call with no key, restore key, report.

.EXAMPLE
    powershell -File scripts\Test-SubscriptionAuth.ps1 -RunId 20260917T193147Z-2319a6

    Full test: bare sanity check, then re-dispatch 02-evidence-pregather (probe budget)
    with no key, then a before/after cost diff for that lane.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RunId,

    [string]$Lane = "02-evidence-pregather",

    [string]$Budget = "probe",

    [switch]$QuickCheckOnly
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$cliPath  = Join-Path $repoRoot "appsec-review-process\review_cli.py"
if (-not (Test-Path $cliPath)) {
    throw "Could not find review_cli.py at '$cliPath'. Run this script from its normal location under scripts\, in a checkout where appsec-review-process\ is a sibling directory."
}

function Get-NumOrZero {
    param($Value)
    if ($null -eq $Value) { return 0 }
    return [double]$Value
}

function Get-Cost {
    param([string]$RunId)
    $raw = python $cliPath cost --run-id $RunId 2>&1
    try {
        return ($raw | Out-String) | ConvertFrom-Json
    } catch {
        Write-Host "Could not parse 'cost' output as JSON -- raw output was:" -ForegroundColor Red
        Write-Host $raw
        throw
    }
}

# --- Save + remove the API key ----------------------------------------------
$savedApiKey = $env:ANTHROPIC_API_KEY
$hadKey = -not [string]::IsNullOrEmpty($savedApiKey)

if ($hadKey) {
    Write-Host "Saving ANTHROPIC_API_KEY (length $($savedApiKey.Length) chars) to a local variable and removing it from THIS PROCESS's environment. This does not touch your persisted user/system environment variable -- a new shell will still have it." -ForegroundColor Yellow
    Remove-Item Env:ANTHROPIC_API_KEY
} else {
    Write-Host "ANTHROPIC_API_KEY was already unset in this process -- nothing to save." -ForegroundColor Yellow
}

if ($env:ANTHROPIC_API_KEY) {
    throw "ANTHROPIC_API_KEY is still set after the removal attempt -- aborting before dispatching anything billed. (Is it being re-set by a profile script on every prompt?)"
}

$quickCheckOk = $false
try {
    # --- Cheapest possible signal first: a bare claude -p call with no key ---
    Write-Host "`n=== Bare 'claude -p' sanity check with NO ANTHROPIC_API_KEY set ===" -ForegroundColor Cyan
    $quickRaw = claude -p "Reply with exactly the single word: OK" --output-format json 2>&1
    $quickExit = $LASTEXITCODE
    Write-Host $quickRaw

    if ($quickExit -eq 0) {
        try {
            $quickParsed = ($quickRaw | Out-String) | ConvertFrom-Json
            if ($quickParsed.is_error -eq $false) {
                $quickCheckOk = $true
            }
        } catch {
            Write-Host "Bare check exited 0 but did not produce parseable JSON -- treat as inconclusive, inspect the raw output above." -ForegroundColor Yellow
        }
    }

    if ($quickCheckOk) {
        Write-Host "Bare check succeeded with no API key set. subtype=$($quickParsed.subtype) total_cost_usd=$($quickParsed.total_cost_usd)" -ForegroundColor Green
    } else {
        Write-Host "Bare check did NOT cleanly succeed with no API key set (exit=$quickExit) -- this itself is the answer: claude -p dispatch appears to require ANTHROPIC_API_KEY / does not fall back to Max subscription auth for -p. See the raw output above for the actual error (e.g. an auth/login prompt or error)." -ForegroundColor Red
    }

    if ($QuickCheckOnly -or -not $quickCheckOk) {
        if ($QuickCheckOnly) {
            Write-Host "`n-QuickCheckOnly was passed -- stopping here without touching '$Lane'." -ForegroundColor Cyan
        } else {
            Write-Host "`nSkipping the full lane dispatch since the bare check already failed -- no point spending a real lane's budget on a dispatch we expect to fail the same way. Re-run with -QuickCheckOnly to iterate faster once you've addressed the auth issue." -ForegroundColor Yellow
        }
    } else {
        # --- Full comparison: before/after cost for the real lane dispatch ---
        Write-Host "`n=== Cost before no-key lane dispatch ===" -ForegroundColor Cyan
        $before = Get-Cost -RunId $RunId
        $before | ConvertTo-Json -Depth 6 | Write-Host

        Write-Host "`n=== Dispatching '$Lane' (budget=$Budget) with NO ANTHROPIC_API_KEY set ===" -ForegroundColor Cyan
        python $cliPath run --run-id $RunId --lane $Lane --budget $Budget
        $dispatchExit = $LASTEXITCODE

        Write-Host "`n=== Cost after no-key lane dispatch ===" -ForegroundColor Cyan
        $after = Get-Cost -RunId $RunId
        $after | ConvertTo-Json -Depth 6 | Write-Host

        $beforeLane = $before.by_lane.$Lane
        $afterLane  = $after.by_lane.$Lane
        $callsDelta = (Get-NumOrZero $afterLane.calls)          - (Get-NumOrZero $beforeLane.calls)
        $costDelta  = (Get-NumOrZero $afterLane.total_cost_usd) - (Get-NumOrZero $beforeLane.total_cost_usd)

        Write-Host "`n=== This attempt's delta for lane '$Lane' ===" -ForegroundColor Green
        Write-Host "  calls added:          $callsDelta"
        Write-Host "  total_cost_usd added: $costDelta"

        if ($dispatchExit -ne 0) {
            Write-Host "`nreview_cli.py run exited non-zero ($dispatchExit) with no API key set. Check outputs\$Lane\raw-response.json and status.json for this attempt (it will be the newest one, since prior outputs get auto-archived to outputs\$Lane\attempts\ before every dispatch) for the actual error." -ForegroundColor Red
        } elseif ($costDelta -eq 0) {
            Write-Host "`nDispatch succeeded and added `$0 to total_cost_usd for this attempt -- consistent with Max subscription auth covering the call instead of pay-as-you-go API billing. Still worth eyeballing outputs\$Lane\raw-response.json directly to confirm nothing silently short-circuited (e.g. it recognizing the evidence was already present and doing near-zero real work, independent of billing mode)." -ForegroundColor Green
        } else {
            Write-Host "`nDispatch succeeded but still added `$$costDelta to total_cost_usd for this attempt -- claude -p appears to still be metering a cost even without ANTHROPIC_API_KEY set. This could mean it silently fell back to a different still-billed auth path, or that total_cost_usd is a notional/list-price estimate the CLI always computes regardless of how the call is actually billed. Worth checking whatever your Max plan's own usage dashboard shows for this timeframe as a cross-check, since this script can only see what the CLI's own JSON reports." -ForegroundColor Yellow
        }
    }
}
finally {
    # --- Always restore, even if something above threw ----------------------
    if ($hadKey) {
        $env:ANTHROPIC_API_KEY = $savedApiKey
        Write-Host "`nRestored ANTHROPIC_API_KEY to this process's environment." -ForegroundColor Yellow
    } else {
        Write-Host "`nNothing to restore (ANTHROPIC_API_KEY was unset before this script ran)." -ForegroundColor Yellow
    }
}
