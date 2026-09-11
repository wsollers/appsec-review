# One-time patch: replaces the broken "dotnet tool install" BinSkim block in
# Dockerfile with the working self-contained-binary install.
#
# Uses .NET's File::ReadAllLines/WriteAllText with an explicit UTF-8 encoding
# and line-anchor matching (not a big literal block match) so this is immune
# to both the codepage/em-dash display issue seen earlier AND to CRLF-vs-LF
# line-ending differences, either of which broke the previous version of
# this script silently.
#
# Run once from F:\Barracuda (an absolute path is resolved internally, so it
# doesn't matter whether your PowerShell prompt and .NET's own working
# directory agree - they don't have to for this script to work), then
# delete this file - it's not part of the toolbox image itself.

$path = Join-Path (Get-Location) "Dockerfile"
if (-not (Test-Path $path)) {
    Write-Host "No Dockerfile found in $(Get-Location) - run this from F:\Barracuda." -ForegroundColor Red
    exit 1
}
$path = (Resolve-Path $path).Path

$lines = [System.IO.File]::ReadAllLines($path, [System.Text.Encoding]::UTF8)

# Locate the block by content anchors instead of matching an exact multi-line
# string, so differing line endings or a stray whitespace change can't break
# the match the way exact block matching did last time.
$startIdx = -1
$endIdx = -1
for ($i = 0; $i -lt $lines.Length; $i++) {
    if ($startIdx -lt 0 -and $lines[$i] -like "*BinSkim (binary hardening checker*") {
        $startIdx = $i
    }
    if ($lines[$i] -like "*dotnet tool install*Microsoft.CodeAnalysis.BinSkim*") {
        $endIdx = $i + 1   # the ENV PATH line immediately following it
        break
    }
}

if ($startIdx -lt 0 -or $endIdx -lt 0 -or $endIdx -lt $startIdx) {
    Write-Host "Could not find the expected old BinSkim block by anchor search either." -ForegroundColor Red
    Write-Host "Don't guess further - paste back the output of this command:" -ForegroundColor Red
    Write-Host '  Get-Content .\Dockerfile | Select-String -Context 3,3 BinSkim' -ForegroundColor Red
    exit 1
}

if (($lines[$startIdx..$endIdx] -join "`n") -notmatch "dotnet tool install") {
    Write-Host "Dockerfile already looks patched (no 'dotnet tool install' in the matched block) - nothing to do." -ForegroundColor Yellow
    exit 0
}

$newBlock = @(
    "# --- BinSkim (binary hardening checker - ASLR/DEP/stack canaries/",
    "#     strong-naming; NOT a dependency/CVE scanner, complements the SBOM work",
    "#     below, doesn't replace it) ----------------------------------------------",
    "# Strongest on PE/COFF (Windows) binaries - a good match if the game server's",
    "# Packer-built images are Windows (windows-game-server / windows-build-server",
    "# in fsh-infra suggest they are). For Linux ELF binaries (Android .so, any",
    "# Linux-built native libs), pair with ``checksec`` instead - add",
    "# ``apt-get install -y checksec`` above if you need it; omitted here to keep",
    "# this block focused.",
    "#",
    "# ``dotnet tool install --global Microsoft.CodeAnalysis.BinSkim`` (the",
    "# officially-documented-sounding install path) does NOT actually work: the",
    "# published NuGet package was never packaged as a proper dotnet global tool",
    "# (no DotnetToolSettings.xml) - a PR to add that packaging",
    "# (microsoft/binskim#790) was closed unmerged. Confirmed directly against the",
    "# package for this build: it's a plain NuGet .nupkg (a zip) containing",
    "# self-contained, per-RID published binaries under tools/net9.0/<rid>/ (e.g.",
    "# linux-x64, win-x64, osx-x64, linux-arm64) - each bundles its own .NET",
    "# runtime, so no .NET SDK install is needed at all (the SDK install this",
    "# block used to carry existed only for this failed dotnet-tool step and has",
    "# been dropped). Pull the linux-x64 build directly instead:",
    "ARG BINSKIM_VERSION=4.4.9.11",
    "RUN mkdir -p /opt/binskim && cd /opt/binskim \",
    "    && curl -fsSL `"https://www.nuget.org/api/v2/package/Microsoft.CodeAnalysis.BinSkim/`${BINSKIM_VERSION}`" -o binskim.zip \",
    "    && unzip -q binskim.zip `"tools/net9.0/linux-x64/*`" -d extracted \",
    "    && mv extracted/tools/net9.0/linux-x64/* . \",
    "    && rm -rf extracted binskim.zip \",
    "    && chmod +x BinSkim \",
    "    && ln -s /opt/binskim/BinSkim /opt/binskim/binskim",
    "ENV PATH=`"/opt/binskim:`${PATH}`""
)

$before = if ($startIdx -gt 0) { $lines[0..($startIdx - 1)] } else { @() }
$after  = if ($endIdx -lt ($lines.Length - 1)) { $lines[($endIdx + 1)..($lines.Length - 1)] } else { @() }

$updatedLines = $before + $newBlock + $after
$updatedText = ($updatedLines -join "`n") + "`n"

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($path, $updatedText, $utf8NoBom)

Write-Host "Patched: Dockerfile now uses the self-contained BinSkim binary install." -ForegroundColor Green
Write-Host "Replaced lines $($startIdx + 1) to $($endIdx + 1) (1-based, original file)." -ForegroundColor DarkGray
