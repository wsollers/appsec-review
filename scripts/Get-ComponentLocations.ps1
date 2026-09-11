<#
.SYNOPSIS
    Extracts per-component source-file locations from a CycloneDX SBOM produced by syft,
    to support classifying SCA/CVE findings by where in the repo each package actually
    lives (real server module vs. sample/demo module vs. vendored third-party source
    tree vs. an unrelated subsystem that happens to share the git repo).

.DESCRIPTION
    Context (2026-09-08, fsh-server "Barracuda" vendor audit): the sbom step in
    Invoke-VendorAuditPrePass.ps1 runs `syft dir:/workspace`, which is a whole-directory
    scan. It catalogs every pom.xml (and package.json, go.mod, etc.) anywhere under the
    repo root, with no concept of what actually gets compiled and packaged into the
    artifact that ships as the running server. A spot-check on 2026-09-08 showed a single
    package name (junit) resolving to five different pom.xml files across the repo,
    including what look like a sample/demo module, two vendored copies of protobuf's own
    source tree, and an apparently unrelated monitoring dashboard subproject -- alongside
    what may be the real server module. Ranking CVE findings by "is this in the server
    stack" requires knowing which of those source locations is real.

    syft's java-pom-cataloger does not capture Maven <scope> (test/provided/compile/
    runtime) as CycloneDX `scope` or as a property -- confirmed empirically against this
    SBOM before writing this script, so this script does not attempt to filter by scope.
    It surfaces the `syft:location:N:path` propert(ies) per component instead, which is
    the only positional signal syft's CycloneDX output actually carries.

    v2 (2026-09-08, same day): a full run against the real 3,311-component SBOM showed
    1,531 components (46%) with NO location property at all. That's too large a chunk to
    leave unclassified, so this version also captures each component's
    `syft:package:foundBy` / `syft:package:type` / `syft:package:language` properties and
    adds a second console summary that breaks the no-location bucket down by those
    instead -- the goal is to see what KIND of thing syft found without a path (a
    different cataloger entirely, e.g. binary/DLL version-resource detection, vs.
    something that should have had a path and didn't) before deciding how/whether it can
    be classified as "server" or not. The full CSV now also carries these columns so a
    later join against cve-list.csv keeps this context.

    Classifying by path (or by foundBy/type for the no-location bucket) against the real
    repo layout is a separate, subsequent step -- this script only extracts the raw data
    so that classification can happen with real facts in hand instead of guesses.

.PARAMETER SbomPath
    Path to the CycloneDX SBOM JSON file (sbom.cdx.json from the sbom evidence step).

.PARAMETER OutputCsv
    Where to write the full package -> location(s) CSV. One row per (package, version,
    location path) combination, so a package found via multiple pom.xml files produces
    multiple rows -- this is deliberate, so a later join against cve-list.csv can match
    on Package+Version and pull back every source location that contributed to that
    finding. Components with no location produce one row with an empty Location.

.PARAMETER SummaryTopLevels
    Number of leading path segments to group by for the console path-prefix summary
    (default 3). A smaller number gives a coarser, faster-to-read census of where
    components live; increase it if the top-level directories are too broad to be
    useful (e.g. everything lands under one "/GM/" segment).

.EXAMPLE
    .\Get-ComponentLocations.ps1 -SbomPath F:\Barracuda\evidence-server\sbom\sbom.cdx.json -OutputCsv F:\Barracuda\evidence-server\sbom\component-locations.csv

    Writes the full per-location CSV, prints a console summary of unique path prefixes
    with component counts, and prints a second summary breaking down components that
    have NO location data by their foundBy/type/language instead. Paste both summary
    blocks back so the real vs. sample/vendored/unrelated/no-path classification can be
    built from actual repo structure and cataloger behavior.

.EXAMPLE
    .\Get-ComponentLocations.ps1 -SbomPath F:\Barracuda\evidence-server\sbom\sbom.cdx.json -OutputCsv F:\Barracuda\evidence-server\sbom\component-locations.csv -SummaryTopLevels 5

    Same, but groups the path-prefix summary five segments deep instead of three -- use
    this once the 3-segment summary shows a few buckets that are too large/broad to be
    useful on their own (e.g. hundreds of components under one "/GM/gaiya/WOD" prefix).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SbomPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputCsv,

    [int]$SummaryTopLevels = 3
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SbomPath)) {
    throw "SBOM file not found: $SbomPath"
}

Write-Host "Loading SBOM: $SbomPath" -ForegroundColor DarkCyan
$sbom = Get-Content -LiteralPath $SbomPath -Raw | ConvertFrom-Json

if (-not $sbom.components) {
    throw "No .components array found in SBOM -- is this a valid CycloneDX file?"
}

Write-Host "Total components in SBOM: $($sbom.components.Count)" -ForegroundColor DarkCyan

function Get-PropValue {
    param($Properties, [string]$PropName)
    $match = @($Properties | Where-Object { $_.name -eq $PropName })
    if ($match.Count -gt 0) { return $match[0].value }
    return ""
}

$rows = New-Object System.Collections.Generic.List[object]

foreach ($component in $sbom.components) {
    $name    = $component.name
    $version = if ($component.version) { $component.version } else { "" }
    $group   = if ($component.group) { $component.group } else { "" }
    $purl    = $component.purl

    $foundBy  = Get-PropValue -Properties $component.properties -PropName "syft:package:foundBy"
    $pkgType  = Get-PropValue -Properties $component.properties -PropName "syft:package:type"
    $language = Get-PropValue -Properties $component.properties -PropName "syft:package:language"

    # Pull every syft:location:N:path property. There can be more than one when the
    # same resolved package is referenced from multiple places for a single component
    # entry (rarer than multiple *separate* component entries for the same name+version,
    # which is the pattern the junit spot-check showed -- but handle both shapes).
    $locationProps = @($component.properties | Where-Object {
        $_.name -match '^syft:location:\d+:path$'
    })

    if ($locationProps.Count -eq 0) {
        # No location metadata at all for this component -- still emit one row so it's
        # visible in the output rather than silently dropped.
        $rows.Add([PSCustomObject]@{
            Package  = $name
            Group    = $group
            Version  = $version
            Purl     = $purl
            FoundBy  = $foundBy
            PkgType  = $pkgType
            Language = $language
            Location = ""
        })
        continue
    }

    foreach ($locProp in $locationProps) {
        $rows.Add([PSCustomObject]@{
            Package  = $name
            Group    = $group
            Version  = $version
            Purl     = $purl
            FoundBy  = $foundBy
            PkgType  = $pkgType
            Language = $language
            Location = $locProp.value
        })
    }
}

Write-Host "Total (package, version, location) rows: $($rows.Count)" -ForegroundColor DarkCyan

$rows | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "Wrote full location data to: $OutputCsv" -ForegroundColor Green

# --- Console summary 1: unique path prefixes with counts, so it's short enough to paste back ---
Write-Host ""
Write-Host "=== Path-prefix summary (top $SummaryTopLevels segments), component-instance counts ===" -ForegroundColor DarkCyan

$prefixCounts = @{}

foreach ($row in $rows) {
    if ([string]::IsNullOrWhiteSpace($row.Location)) {
        $prefix = "(no location data)"
    }
    else {
        # Normalize to forward slashes, split, take the leading N segments.
        $normalized = $row.Location -replace '\\', '/'
        $segments = $normalized.Split('/') | Where-Object { $_ -ne "" }
        $take = [Math]::Min($SummaryTopLevels, $segments.Count)
        $prefix = "/" + ($segments[0..($take - 1)] -join "/")
    }

    if ($prefixCounts.ContainsKey($prefix)) {
        $prefixCounts[$prefix]++
    }
    else {
        $prefixCounts[$prefix] = 1
    }
}

$prefixCounts.GetEnumerator() |
    Sort-Object -Property Value -Descending |
    ForEach-Object {
        "{0,6}  {1}" -f $_.Value, $_.Key
    } | Write-Host

# --- Console summary 2: for rows with NO location, break down by foundBy/type/language ---
Write-Host ""
Write-Host "=== No-location breakdown by (FoundBy | PkgType | Language), row counts ===" -ForegroundColor DarkCyan

$noLocationRows = @($rows | Where-Object { [string]::IsNullOrWhiteSpace($_.Location) })
Write-Host "Total rows with no location data: $($noLocationRows.Count)" -ForegroundColor DarkCyan

$noLocationCounts = @{}

foreach ($row in $noLocationRows) {
    $fb = if ($row.FoundBy) { $row.FoundBy } else { "(none)" }
    $pt = if ($row.PkgType) { $row.PkgType } else { "(none)" }
    $lg = if ($row.Language) { $row.Language } else { "(none)" }
    $key = "$fb | $pt | $lg"

    if ($noLocationCounts.ContainsKey($key)) {
        $noLocationCounts[$key]++
    }
    else {
        $noLocationCounts[$key] = 1
    }
}

$noLocationCounts.GetEnumerator() |
    Sort-Object -Property Value -Descending |
    ForEach-Object {
        "{0,6}  {1}" -f $_.Value, $_.Key
    } | Write-Host

# --- Sample no-location package names per bucket, so the breakdown above isn't just numbers ---
Write-Host ""
Write-Host "=== Sample package names per no-location (FoundBy | PkgType | Language) bucket (up to 5 each) ===" -ForegroundColor DarkCyan

$noLocationGroups = $noLocationRows | Group-Object -Property {
    $fb = if ($_.FoundBy) { $_.FoundBy } else { "(none)" }
    $pt = if ($_.PkgType) { $_.PkgType } else { "(none)" }
    $lg = if ($_.Language) { $_.Language } else { "(none)" }
    "$fb | $pt | $lg"
}

foreach ($grp in ($noLocationGroups | Sort-Object -Property Count -Descending)) {
    $samples = ($grp.Group | Select-Object -First 5 | ForEach-Object { "$($_.Package)@$($_.Version)" }) -join ", "
    Write-Host "  [$($grp.Count)] $($grp.Name)"
    Write-Host "      e.g. $samples"
}

Write-Host ""
Write-Host "Paste both summary blocks (path-prefix and no-location breakdown) back into the chat --" -ForegroundColor Yellow
Write-Host "that's what's needed to classify real-server vs. sample/vendored/unrelated/no-path components." -ForegroundColor Yellow
