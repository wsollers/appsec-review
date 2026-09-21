<#
.SYNOPSIS
    Locally surfaces a sample of gitleaks findings for visual inspection,
    with heuristics for whether a value looks like plaintext vs. something
    encrypted/encoded. Runs entirely on this machine - nothing here is sent
    anywhere; it just prints to your own terminal.

.DESCRIPTION
    gitleaks was run with --redact, so the evidence JSON itself does NOT
    contain the actual secret values (Secret/Match are already masked) - by
    design, so the evidence directory itself isn't a second copy of live
    credentials. To actually look at a value, this script goes back to the
    real source file on disk (using File/StartLine/StartColumn/EndColumn
    from the gitleaks report to locate it precisely) rather than re-running
    gitleaks without --redact, which would leave plaintext secrets sitting
    in an evidence file that might later get zipped up, shared, or attached
    somewhere.

    By default this shows structure only (which JSON key the secret belongs
    to, length, Shannon entropy, format fingerprint - base64/hex/GUID/JWT-
    shaped) and NOT the raw value. Pass -ShowValue to also print the raw
    string, once you've decided you actually want to see it here.

    2026-09-01 remediation note (finding E4-2, adversarial process review):
    -ShowValue used to be a plain, unguarded switch - a wrapper script, a
    scheduled/automated re-run, or a copy-pasted command line saved
    somewhere could set it once and silently start writing raw secret
    values into whatever is capturing stdout (a transcript, a CI log, a
    redirected file). This script now refuses to run with -ShowValue unless
    it's being run interactively with its output going to your own console
    - see the guard immediately after param() below.

.PARAMETER GitleaksJson
    Path to the gitleaks evidence JSON. Default: .\evidence-infra\secrets\gitleaks.json

.PARAMETER RepoPath
    Path to the actual repo checkout the report's File paths are relative
    to (i.e. what you passed as -RepoPath to Invoke-VendorAuditPrePass.ps1).
    Default: .\fsh-infra

.PARAMETER Count
    How many unique findings (by Fingerprint) to show. Default: 5.

.PARAMETER ShowValue
    Also print the raw extracted value. Off by default. Refused outright
    when this session isn't interactive or stdout appears redirected - see
    the remediation note above.

.PARAMETER Summary
    Instead of the detailed per-finding view, print one compact table row
    per ALL findings (not just -Count of them) - JSON key, format
    fingerprint (including path/resource-ID detection), length, entropy.
    Still no raw values. Use this first to see the overall shape of all 40
    before deciding which ones need a closer -ShowValue look.

.EXAMPLE
    ./inspect-secrets.ps1 -Summary
.EXAMPLE
    ./inspect-secrets.ps1
.EXAMPLE
    ./inspect-secrets.ps1 -Count 10 -ShowValue
#>
[CmdletBinding()]
param(
    [string]$GitleaksJson = ".\evidence-infra\secrets\gitleaks.json",
    [string]$RepoPath = ".\fsh-infra",
    [int]$Count = 5,
    [switch]$ShowValue,
    [switch]$Summary
)

$ErrorActionPreference = "Stop"

# E4-2 guard: refuse -ShowValue in any context where the raw secret value
# could end up somewhere other than your own screen - a non-interactive
# host (a scheduled task, a CI runner, another script invoking this one) or
# stdout that's been redirected to a file/pipe. [Console]::IsOutputRedirected
# throws in some hosts (notably the ISE) that don't expose a real console -
# treat that as "can't confirm it's safe" and refuse too, rather than assume
# the best case.
if ($ShowValue) {
    $redirected = $true
    try { $redirected = [Console]::IsOutputRedirected } catch { $redirected = $true }
    if (-not [Environment]::UserInteractive -or $redirected) {
        throw ("-ShowValue refused: this session is non-interactive or stdout is redirected " +
               "(Environment.UserInteractive=$([Environment]::UserInteractive)). This guard exists " +
               "so a scripted/automated re-run - or a copy-pasted command line saved in a wrapper " +
               "script - can't silently start writing raw secret values into a transcript, CI log, " +
               "or redirected file. Run this directly in an interactive terminal, with output going " +
               "to your own screen, if you really want -ShowValue.")
    }
}

if (-not (Test-Path $GitleaksJson)) {
    throw "Can't find $GitleaksJson - pass -GitleaksJson, or run this from F:\Barracuda after the secrets step."
}
if (-not (Test-Path $RepoPath)) {
    throw "Can't find $RepoPath - pass -RepoPath pointing at the same folder you scanned."
}
$RepoPath = (Resolve-Path $RepoPath).Path

function Get-ShannonEntropy([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return 0 }
    $len = $s.Length
    $counts = @{}
    foreach ($ch in $s.ToCharArray()) {
        if ($counts.ContainsKey($ch)) { $counts[$ch]++ } else { $counts[$ch] = 1 }
    }
    $entropy = 0.0
    foreach ($c in $counts.Values) {
        $p = $c / $len
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 2)
}

function Get-FormatFingerprint([string]$s) {
    $tags = @()
    # Path/resource-ID shaped: 2+ slash-delimited segments, each segment
    # looking like a name/GUID/id rather than one uniform blob. This is the
    # shape of an Azure resource ID (/subscriptions/<guid>/resourceGroups/...)
    # or any hierarchical path/reference - NOT a random secret. Checked
    # before the base64 check below, since '/' is technically a valid
    # base64 character and would otherwise get misclassified.
    if ($s -match '^/?[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){2,}/?$') {
        $segments = $s.Trim('/') -split '/'
        $tags += "path/resource-ID-shaped ($($segments.Count) segments)"
        if ($s -match '(?i)subscriptions|resourceGroups|providers/Microsoft\.') {
            $tags += "Azure-resource-ID-shaped"
        }
    }
    if ($tags.Count -eq 0) {
        if ($s -match '^[A-Za-z0-9+/]+={0,2}$' -and $s.Length -ge 16) { $tags += "base64-like" }
        if ($s -match '^[0-9a-fA-F]+$' -and $s.Length -ge 16) { $tags += "hex-like" }
        if ($s -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { $tags += "GUID" }
        if ($s -match '^eyJ') { $tags += "JWT-shaped" }
        if ($s.Length -eq 88 -and $s -match '==$') { $tags += "Azure-storage-key-shaped(88ch,base64,==)" }
    }
    if ($tags.Count -eq 0) { $tags += "no-recognized-format" }
    return ($tags -join ", ")
}

function Get-Value([PSCustomObject]$finding, [string]$RepoPath) {
    $filePath = Join-Path $RepoPath $finding.File
    if (-not (Test-Path $filePath)) { return $null }
    $lines = Get-Content $filePath -TotalCount $finding.EndLine
    if ($lines.Count -lt $finding.StartLine) { return $null }
    $lineText = $lines[$finding.StartLine - 1]
    $value = $null
    if ($finding.StartColumn -and $finding.EndColumn -and $finding.StartColumn -le $lineText.Length) {
        $endCol = [Math]::Min($finding.EndColumn, $lineText.Length)
        $len = $endCol - $finding.StartColumn + 1
        if ($len -gt 0) { $value = $lineText.Substring($finding.StartColumn - 1, $len) }
    }
    if (-not $value) { $value = $lineText.Trim() }
    return [PSCustomObject]@{ LineText = $lineText; Value = $value }
}

function Get-JsonKeyContext([string]$line) {
    # Terraform's JSON state is normally one "key": value per line when
    # written by `terraform apply` - try to pull the attribute name the
    # value on this line belongs to, purely for triage context.
    if ($line -match '"([^"]+)"\s*:') { return $matches[1] }
    return "(could not determine key from this line)"
}

$content = Get-Content $GitleaksJson -Raw | ConvertFrom-Json
$allUnique = $content | Sort-Object Fingerprint -Unique
$filePath = $null

if ($Summary) {
    Write-Host "Summary of all $($allUnique.Count) unique findings (no raw values):" -ForegroundColor Cyan
    Write-Host ""
    $rows = foreach ($finding in $allUnique) {
        $extracted = Get-Value $finding $RepoPath
        $filePath = Join-Path $RepoPath $finding.File
        if (-not $extracted) {
            [PSCustomObject]@{ Line = $finding.StartLine; JsonKey = "(unreadable)"; Length = 0; Entropy = 0; Format = "(could not read file/line)" }
        } else {
            [PSCustomObject]@{
                Line    = $finding.StartLine
                JsonKey = Get-JsonKeyContext $extracted.LineText
                Length  = $extracted.Value.Length
                Entropy = Get-ShannonEntropy $extracted.Value
                Format  = Get-FormatFingerprint $extracted.Value
            }
        }
    }
    $rows | Sort-Object Line | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    $pathLike = ($rows | Where-Object { $_.Format -like "path/resource-ID-shaped*" }).Count
    $noFormat = ($rows | Where-Object { $_.Format -eq "no-recognized-format" }).Count
    $recognized = $rows.Count - $pathLike - $noFormat
    Write-Host ""
    Write-Host "$pathLike of $($rows.Count) look path/resource-ID-shaped (likely NOT real secrets - probably gitleaks matching on a sensitive-sounding key name near an Azure resource reference)." -ForegroundColor $(if ($pathLike -gt 0) { "Green" } else { "Gray" })
    Write-Host "$recognized of $($rows.Count) match a real-secret-shaped format (base64/hex/GUID/JWT/storage-key)." -ForegroundColor $(if ($recognized -gt 0) { "Yellow" } else { "Gray" })
    Write-Host "$noFormat of $($rows.Count) matched no recognized format - worth a manual look with -ShowValue." -ForegroundColor Gray
} else {
    $unique = $allUnique | Select-Object -First $Count
    Write-Host "Showing $($unique.Count) of $($content.Count) total findings ($($allUnique.Count) unique fingerprints). Use -Summary to see the shape of all of them at once." -ForegroundColor Cyan
    Write-Host ""

    $i = 0
    foreach ($finding in $unique) {
        $i++
        $filePath = Join-Path $RepoPath $finding.File
        $extracted = Get-Value $finding $RepoPath
        if (-not $extracted) {
            Write-Host "[$i] $($finding.File):$($finding.StartLine) - file/line not readable, skipping" -ForegroundColor Red
            continue
        }
        $keyName = Get-JsonKeyContext $extracted.LineText

        Write-Host "[$i] $($finding.File):$($finding.StartLine)" -ForegroundColor Yellow
        Write-Host "    RuleID:       $($finding.RuleID)"
        Write-Host "    JSON key:     $keyName"
        Write-Host "    Length:       $($extracted.Value.Length) chars"
        Write-Host "    Entropy:      $(Get-ShannonEntropy $extracted.Value) bits/char  (plain English ~4, random base64/hex ~5.5-6, near-uniform ciphertext usually 7-8)"
        Write-Host "    Format:       $(Get-FormatFingerprint $extracted.Value)"
        if ($ShowValue) {
            Write-Host "    Value:        $($extracted.Value)" -ForegroundColor Magenta
        }
        Write-Host ""
    }
}

Write-Host "Reminder: entropy/format here are heuristics for triage, not proof either way - a real Azure client secret" -ForegroundColor DarkGray
Write-Host "and a chunk of ciphertext can both look like high-entropy base64. The strongest actual signal that this" -ForegroundColor DarkGray
Write-Host "file is plaintext (not Terraform's native state encryption) is structural: run the check below." -ForegroundColor DarkGray
Write-Host ""

# Quick structural check: Terraform's native state-encryption feature wraps
# the ENTIRE file in an envelope and the normal "resources" array won't be
# present in cleartext at the top level if it's active.
$sample = Get-Content $filePath -TotalCount 50 -ErrorAction SilentlyContinue
$sampleText = $sample -join "`n"
if ($sampleText -match '"resources"\s*:') {
    Write-Host "Top-level 'resources' key found in plaintext in the first 50 lines - this state file is NOT using Terraform's native state encryption. It's a normal, fully plaintext local state file." -ForegroundColor Green
} elseif ($sampleText -match '"encryption"\s*:' -or $sampleText -match '"encrypted_data"\s*:') {
    Write-Host "Found 'encryption'/'encrypted_data' keys - this state file MAY be using Terraform's native state encryption. Worth re-checking whether gitleaks' matches are actually inside an encrypted envelope (less likely given discrete generic-api-key hits, but confirm)." -ForegroundColor Yellow
} else {
    Write-Host "Could not confirm from the first 50 lines alone - check further into the file by hand." -ForegroundColor Yellow
}
