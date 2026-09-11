# Get-RepoComposition.ps1
# Walks a repo tree (no Docker needed - runs directly against the Windows
# filesystem, so it's fast even though the container's own walk of the same
# tree over the bind mount is slow) and reports:
#   - "Code" files (recognized source-code extensions) - count + total bytes
#   - "Other" files (everything else: binaries, data, docs, configs, media,
#     build output, etc.) - count + total bytes
#   - A per-extension breakdown (count + bytes) written to a CSV, sorted
#     largest-first, so you can see exactly what's eating space/file-count
#   - Directories skipped entirely (via -ExcludeDir, same names as the
#     toolbox's own --exclude/--exclude-dir lists) reported separately, so
#     you can see how much of the tree Docker still mounts and semgrep still
#     walks past even though it never analyzes anything inside them.
#
# Usage:
#   .\Get-RepoComposition.ps1 -Path .\fsh-server -OutDir .\evidence-server\_local
#   .\Get-RepoComposition.ps1 -Path .\fsh-server -ExcludeDir .git,node_modules,vendor,bin,obj,.terraform,Library,Temp

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$OutDir = ".",

    # Same default exclude list as cloc's --exclude-dir and the semgrep
    # steps' --exclude flags in Invoke-VendorAuditPrePass.ps1, so the
    # "excluded" bucket below tells you what those tools are already
    # skipping, not an arbitrary different list.
    [string[]]$ExcludeDir = @(".git", "node_modules", "vendor", "bin", "obj", ".terraform", "Library", "Temp")
)

$Path = (Resolve-Path $Path).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

# Recognized source-code extensions across the languages this toolbox's
# semgrep/SAST steps actually target (owasp-top-ten, csharp, golang, python,
# php, java, security-audit, plus cppcheck's C/C++ and a few common
# scripting/markup/IaC extensions that show up in most repos). Anything not
# in this set is bucketed as "Other" - that's the honest answer to "is it
# just code": everything NOT in this list is what "Other" is measuring.
$codeExtensions = @(
    # C / C++
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
    # C#
    ".cs", ".csx",
    # Go
    ".go",
    # Python
    ".py", ".pyi", ".pyw",
    # PHP
    ".php", ".phtml", ".php3", ".php4", ".php5", ".inc",
    # Java / JVM
    ".java", ".kt", ".kts", ".scala",
    # JS/TS (owasp-top-ten and security-audit cover these too)
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    # Mobile (Android/iOS source - matches sast-mobile-android/-ios)
    ".swift", ".m", ".mm",
    # Ruby, Rust, misc languages semgrep's registry also covers
    ".rb", ".rs",
    # Scripting
    ".sh", ".bash", ".ps1", ".psm1",
    # SQL
    ".sql",
    # IaC / config-as-code (checkov/tfsec/trivy/kube-linter territory -
    # arguably "code" in the sense that it's audited source, not data)
    ".tf", ".tfvars", ".yaml", ".yml", ".json"
)
$codeExtSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$codeExtensions, [System.StringComparer]::OrdinalIgnoreCase)
$excludeSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$ExcludeDir, [System.StringComparer]::OrdinalIgnoreCase)

# Manual stack-based walk (not Get-ChildItem -Recurse) so excluded
# directories are pruned BEFORE descending into them - same principle as the
# --exclude flags on cloc/semgrep, and much faster than walking everything
# and filtering afterward on a tree with a large vendor/node_modules/.git.
$codeCount = 0L; $codeBytes = 0L
$otherCount = 0L; $otherBytes = 0L
$excludedCount = 0L; $excludedBytes = 0L
$byExt = @{}   # ext -> [count, bytes]

function Add-ExtStat([string]$ext, [long]$size) {
    if (-not $byExt.ContainsKey($ext)) { $byExt[$ext] = @{ Count = 0L; Bytes = 0L } }
    $byExt[$ext].Count += 1
    $byExt[$ext].Bytes += $size
}

$stack = [System.Collections.Generic.Stack[string]]::new()
$stack.Push($Path)
$dirCount = 0

while ($stack.Count -gt 0) {
    $dir = $stack.Pop()
    $dirCount++
    if ($dirCount % 500 -eq 0) { Write-Host "  ...scanned $dirCount directories so far" -ForegroundColor DarkGray }

    try {
        $entries = [System.IO.Directory]::EnumerateFileSystemEntries($dir)
    } catch {
        Write-Warning "Could not read '$dir': $($_.Exception.Message)"
        continue
    }

    foreach ($entry in $entries) {
        try {
            $attr = [System.IO.File]::GetAttributes($entry)
        } catch {
            continue  # broken symlink / permission issue - skip rather than abort the whole walk
        }

        if ($attr.HasFlag([System.IO.FileAttributes]::Directory)) {
            $name = Split-Path $entry -Leaf
            if ($excludeSet.Contains($name)) {
                # Count what's INSIDE the excluded dir too, so you know how
                # much is actually being skipped, not just that it exists.
                try {
                    $sub = Get-ChildItem -LiteralPath $entry -Recurse -File -Force -ErrorAction SilentlyContinue
                    foreach ($f in $sub) {
                        $excludedCount++
                        $excludedBytes += $f.Length
                    }
                } catch { }
                continue  # pruned - never descended into
            }
            $stack.Push($entry)
        } else {
            $fi = [System.IO.FileInfo]::new($entry)
            $ext = $fi.Extension
            if ($codeExtSet.Contains($ext)) {
                $codeCount++
                $codeBytes += $fi.Length
            } else {
                $otherCount++
                $otherBytes += $fi.Length
            }
            Add-ExtStat -ext $(if ($ext) { $ext.ToLowerInvariant() } else { "(no extension)" }) -size $fi.Length
        }
    }
}

function Format-Bytes([long]$bytes) {
    if ($bytes -ge 1GB) { return "{0:N2} GB" -f ($bytes / 1GB) }
    if ($bytes -ge 1MB) { return "{0:N2} MB" -f ($bytes / 1MB) }
    if ($bytes -ge 1KB) { return "{0:N2} KB" -f ($bytes / 1KB) }
    return "$bytes B"
}

# --- Console summary ---
Write-Host ""
Write-Host "===== Repo composition: $Path =====" -ForegroundColor Cyan
Write-Host ("Code files:     {0,8:N0}   {1,12}" -f $codeCount, (Format-Bytes $codeBytes)) -ForegroundColor Green
Write-Host ("Other files:    {0,8:N0}   {1,12}" -f $otherCount, (Format-Bytes $otherBytes)) -ForegroundColor Yellow
Write-Host ("Excluded (skipped entirely - {0}):" -f ($ExcludeDir -join ", ")) -ForegroundColor DarkGray
Write-Host ("                {0,8:N0}   {1,12}" -f $excludedCount, (Format-Bytes $excludedBytes)) -ForegroundColor DarkGray
Write-Host ("TOTAL scanned+other (excludes not counted above): {0,8:N0}   {1,12}" -f ($codeCount + $otherCount), (Format-Bytes ($codeBytes + $otherBytes)))

# --- Per-extension CSV, largest byte total first ---
$extRows = $byExt.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
        Extension  = $_.Key
        Category   = if ($codeExtSet.Contains($_.Key)) { "Code" } else { "Other" }
        FileCount  = $_.Value.Count
        Bytes      = $_.Value.Bytes
        Size       = Format-Bytes $_.Value.Bytes
    }
} | Sort-Object -Property Bytes -Descending

$csvPath = Join-Path $OutDir "repo-composition-by-extension.csv"
$extRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`nPer-extension breakdown written to: $csvPath" -ForegroundColor Cyan

# --- Summary text file ---
$summaryPath = Join-Path $OutDir "repo-composition-summary.txt"
$summaryLines = @(
    "Repo composition: $Path"
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Excluded directories (skipped entirely, matches toolbox --exclude lists): $($ExcludeDir -join ', ')"
    ""
    ("Code files:   {0,8:N0}   {1,12}" -f $codeCount, (Format-Bytes $codeBytes))
    ("Other files:  {0,8:N0}   {1,12}" -f $otherCount, (Format-Bytes $otherBytes))
    ("Excluded:     {0,8:N0}   {1,12}" -f $excludedCount, (Format-Bytes $excludedBytes))
    ""
    "See repo-composition-by-extension.csv for the full per-extension breakdown."
)
$summaryLines | Set-Content -Path $summaryPath -Encoding UTF8
Write-Host "Summary written to: $summaryPath" -ForegroundColor Cyan
