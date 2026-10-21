# Readiness check for the Windows host build toolchain. PowerShell 7+.
#
# Inventories the installed Visual Studio toolchain (versions and SHA-256 of the executables actually
# resolved) and builds the repository-owned canary with MSVC, clang-cl and MSVC AddressSanitizer. The
# canaries are built, never run. Exits non-zero when any step fails; writes a JSON report.
#requires -Version 7.0
param(
    [string] $OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) 'appsec-windows-readiness')
)
. (Join-Path $PSScriptRoot 'Common.ps1')

$canary = Join-Path $PSScriptRoot 'canary'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
$scratch = Join-Path $OutputDirectory 'scratch'
if (Test-Path $scratch) { Remove-Item -Recurse -Force $scratch }
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

$vs = Find-VisualStudio
$environment = Get-BuildEnvironment -VisualStudio $vs -Scratch $scratch

function Invoke-Tool([string] $Name, [string[]] $Arguments, [string] $Label) {
    $file = Resolve-Tool -Environment $environment -Name $Name
    if (-not $file) { return [pscustomobject]@{ Label = $Label; ExitCode = $null; Missing = $Name } }
    $result = Invoke-Bounded -File $file -Arguments $Arguments -Environment $environment -WorkingDirectory $scratch `
        -TimeoutSeconds 600 -StdoutPath (Join-Path $scratch "$Label.out") -StderrPath (Join-Path $scratch "$Label.err")
    $result | Add-Member -NotePropertyName Label -NotePropertyValue $Label -PassThru
}

function First-Line([string] $Path) {
    $line = (Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction SilentlyContinue)
    return $(if ($line) { $line.Trim() } else { $null })
}

$tools = [ordered]@{}
foreach ($entry in @(
        @{ Name = 'cl'; Arguments = @(); Stream = 'Stderr' }, @{ Name = 'clang-cl'; Arguments = @('--version'); Stream = 'Stdout' },
        @{ Name = 'clang-tidy'; Arguments = @('--version'); Stream = 'Stdout' }, @{ Name = 'cmake'; Arguments = @('--version'); Stream = 'Stdout' },
        @{ Name = 'ninja'; Arguments = @('--version'); Stream = 'Stdout' }, @{ Name = 'msbuild'; Arguments = @('-version', '-nologo'); Stream = 'Stdout' },
        @{ Name = 'link'; Arguments = @(); Stream = 'Stdout' }, @{ Name = 'dumpbin'; Arguments = @('/nologo'); Stream = 'Stdout' })) {
    $result = Invoke-Tool $entry.Name $entry.Arguments "version-$($entry.Name)"
    $path = Resolve-Tool -Environment $environment -Name $entry.Name
    $tools[$entry.Name] = [ordered]@{
        path = $path; sha256 = $(if ($path) { Get-Sha256 $path } else { $null })
        version = $(if ($result.PSObject.Properties['Missing']) { $null } else { First-Line $result.($entry.Stream) })
    }
}

function Build-Canary([string] $Label, [string[]] $ConfigureFlags) {
    $build = Join-Path $scratch "build-$Label"
    $configure = Invoke-Tool 'cmake' (@('-S', $canary, '-B', $build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release') + $ConfigureFlags) "$Label-configure"
    if ($configure.ExitCode -ne 0) { return [ordered]@{ label = $Label; ok = $false; stage = 'configure'; exit_code = $configure.ExitCode } }
    $compile = Invoke-Tool 'cmake' @('--build', $build) "$Label-build"
    $exe = Join-Path $build 'canary.exe'
    $built = ($compile.ExitCode -eq 0) -and (Test-Path $exe)
    return [ordered]@{
        label = $Label; ok = $built; stage = $(if ($built) { 'built' } else { 'build' }); exit_code = $compile.ExitCode
        output = $(if ($built) { 'canary.exe' } else { $null }); output_sha256 = $(if ($built) { Get-Sha256 $exe } else { $null })
        build_dir = $build
    }
}

$canaries = @(
    (Build-Canary 'msvc' @('-DCMAKE_CXX_COMPILER=cl')),
    (Build-Canary 'clang-cl' @('-DCMAKE_CXX_COMPILER=clang-cl')),
    (Build-Canary 'msvc-asan' @('-DCMAKE_CXX_COMPILER=cl', '-DCMAKE_CXX_FLAGS=/fsanitize=address /Zi')))

# ASan evidence is read from the binary's imports; nothing is executed.
$asan = $canaries | Where-Object { $_.label -eq 'msvc-asan' }
if ($asan.ok) {
    $imports = Invoke-Tool 'dumpbin' @('/nologo', '/dependents', (Join-Path $asan.build_dir 'canary.exe')) 'asan-imports'
    $asan['sanitizer_runtime_referenced'] = [bool](Select-String -Path $imports.Stdout -Pattern 'clang_rt\.asan|asan' -Quiet)
    if (-not $asan['sanitizer_runtime_referenced']) { $asan.ok = $false; $asan.stage = 'no-asan-runtime' }
}

$report = [ordered]@{
    schema = 'appsec-review/windows-readiness/1'
    visual_studio = [ordered]@{
        display_name = $vs.displayName; version = $vs.installationVersion; path = $vs.installationPath
        channel = $vs.channelId; instance_id = $vs.instanceId
    }
    tools = $tools
    canaries = $canaries | ForEach-Object { $_.Remove('build_dir'); $_ }
    ok = -not ($canaries | Where-Object { -not $_.ok })
}
$reportPath = Join-Path $OutputDirectory 'readiness.json'
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
Write-Host ("readiness {0}: {1}" -f $(if ($report.ok) { 'OK' } else { 'FAILED' }), $reportPath)
foreach ($item in $report.canaries) { Write-Host ("  {0,-10} {1}" -f $item.label, $(if ($item.ok) { 'built' } else { "failed at $($item.stage)" })) }
exit $(if ($report.ok) { 0 } else { 1 })
