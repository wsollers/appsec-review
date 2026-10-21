# Build a C/C++ source tree natively on the Windows host. PowerShell 7+.
#
# The source is copied into a fresh per-run directory and built there with a clean environment, a wall-clock
# limit and the process tree killed on timeout. Nothing the build produces is run. The result is a JSON
# document with the toolchain identity, the exact commands the build ran, and a SHA-256 inventory of what it
# produced. This is NOT a sandbox: the build runs as the invoking user (see docs/architecture/windows-host-runner.md),
# so any source other than the repository's own canary needs -AcceptHostRisk.
#requires -Version 7.0
param(
    [Parameter(Mandatory)] [string] $Source,
    [Parameter(Mandatory)] [string] $RunDirectory,
    [ValidateSet('cmake', 'msbuild')] [string] $BuildSystem = 'cmake',
    [string] $Project,                                   # msbuild: .sln or .vcxproj relative to Source
    [ValidateSet('cl', 'clang-cl')] [string] $Compiler = 'clang-cl',
    [ValidateSet('none', 'address')] [string] $Sanitize = 'none',
    [string] $Configuration = 'Release',
    [int] $TimeoutSeconds = 1800,
    [int] $MaxInventoryFiles = 5000,
    [switch] $AcceptHostRisk
)
. (Join-Path $PSScriptRoot 'Common.ps1')

$canaryRoot = (Resolve-Path (Join-Path $PSScriptRoot 'canary')).Path
$Source = (Resolve-Path $Source).Path
if (-not $Source.StartsWith($canaryRoot, [StringComparison]::OrdinalIgnoreCase) -and -not $AcceptHostRisk) {
    throw 'Refusing to build target source on the host without -AcceptHostRisk: the build runs as your user, unsandboxed.'
}
New-Item -ItemType Directory -Force -Path $RunDirectory | Out-Null
$RunDirectory = (Resolve-Path $RunDirectory).Path
if (Get-ChildItem -LiteralPath $RunDirectory -Force | Select-Object -First 1) { throw "RunDirectory must be empty: $RunDirectory" }

$workspace = Join-Path $RunDirectory 'workspace'
$logs = Join-Path $RunDirectory 'logs'
$scratch = Join-Path $RunDirectory 'scratch'
$build = Join-Path $RunDirectory 'build'
foreach ($directory in $workspace, $logs, $scratch, $build) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
& "$env:SystemRoot\System32\robocopy.exe" $Source $workspace /E /NFL /NDL /NJH /NJS /NP /XD .git | Out-Null
if ($LASTEXITCODE -ge 8) { throw "copying the source failed (robocopy exit $LASTEXITCODE)" }

$vs = Find-VisualStudio
$environment = Get-BuildEnvironment -VisualStudio $vs -Scratch $scratch
$steps = [System.Collections.Generic.List[object]]::new()
$gaps = [System.Collections.Generic.List[string]]::new()

function Step([string] $Label, [string] $Tool, [string[]] $Arguments, [string] $WorkingDirectory = $workspace) {
    $file = Resolve-Tool -Environment $environment -Name $Tool
    if (-not $file) { throw "$Tool is not available in the build environment" }
    $result = Invoke-Bounded -File $file -Arguments $Arguments -Environment $environment -WorkingDirectory $WorkingDirectory `
        -TimeoutSeconds $TimeoutSeconds -StdoutPath (Join-Path $logs "$Label.stdout.txt") -StderrPath (Join-Path $logs "$Label.stderr.txt")
    $steps.Add([ordered]@{
        label = $Label; tool = $Tool; tool_sha256 = Get-Sha256 $file; argv = $Arguments; exit_code = $result.ExitCode
        timed_out = $result.TimedOut; seconds = $result.Seconds
        stdout_sha256 = Get-Sha256 $result.Stdout; stderr_sha256 = Get-Sha256 $result.Stderr })
    return $result
}

$sanitizeFlag = switch ($Compiler) { 'cl' { '/fsanitize=address /Zi' } default { '-fsanitize=address' } }
$status = 'SUCCEEDED'
$commandsPath = $null
if ($BuildSystem -eq 'cmake') {
    $flags = @("-DCMAKE_BUILD_TYPE=$Configuration", "-DCMAKE_CXX_COMPILER=$Compiler", "-DCMAKE_C_COMPILER=$Compiler", '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    if ($Sanitize -eq 'address') { $flags += @("-DCMAKE_CXX_FLAGS=$sanitizeFlag", "-DCMAKE_C_FLAGS=$sanitizeFlag") }
    $configure = Step 'configure' 'cmake' (@('-S', $workspace, '-B', $build, '-G', 'Ninja') + $flags)
    if ($configure.ExitCode -ne 0) { $status = 'FAILED' } else {
        $compile = Step 'build' 'cmake' @('--build', $build)
        if ($compile.ExitCode -ne 0) { $status = 'FAILED' }
        # The exact command lines Ninja ran or would run, in order: compile and link, from the build graph itself.
        $commands = Step 'commands' 'ninja' @('-C', $build, '-t', 'commands')
        $commandsPath = $commands.Stdout
    }
} else {
    if (-not $Project) { throw '-Project is required for -BuildSystem msbuild' }
    $binlog = Join-Path $logs 'msbuild.binlog'
    $flags = @((Join-Path $workspace $Project), "/p:Configuration=$Configuration", '/p:Platform=x64', '/m', '/nr:false', '/nologo', "/bl:$binlog")
    if ($Compiler -eq 'clang-cl') { $flags += '/p:PlatformToolset=ClangCL' }
    if ($Sanitize -eq 'address') { $flags += '/p:EnableASAN=true' }
    $compile = Step 'build' 'msbuild' $flags
    if ($compile.ExitCode -ne 0) { $status = 'FAILED' }
    $commandsPath = $binlog
}
if ($steps | Where-Object { $_.timed_out }) { $status = 'TIMED_OUT' }

$extensions = '.exe', '.dll', '.lib', '.obj', '.pdb', '.json'
$inventory = @()
$seen = 0
foreach ($file in Get-ChildItem -LiteralPath $build, $workspace -Recurse -File -ErrorAction SilentlyContinue) {
    if ($extensions -notcontains $file.Extension.ToLowerInvariant()) { continue }
    if ($file.FullName.StartsWith($canaryRoot) -or $file.FullName -like '*\CMakeFiles\*') { continue }
    $seen++
    if ($seen -gt $MaxInventoryFiles) { $gaps.Add("inventory truncated at $MaxInventoryFiles files"); break }
    $inventory += [ordered]@{ path = $file.FullName.Substring($RunDirectory.Length + 1).Replace('\', '/'); bytes = $file.Length; sha256 = Get-Sha256 $file.FullName }
}

# AddressSanitizer evidence is read from imports; the produced binaries are never run.
$sanitizerEvidence = @()
if ($Sanitize -eq 'address') {
    $dumpbin = Resolve-Tool -Environment $environment -Name 'dumpbin'
    foreach ($item in $inventory | Where-Object { $_.path -match '\.(exe|dll)$' }) {
        $output = & $dumpbin /nologo /dependents (Join-Path $RunDirectory $item.path) 2>&1 | Out-String
        $sanitizerEvidence += [ordered]@{ path = $item.path; asan_runtime_referenced = [bool]($output -match 'asan') }
    }
    if (-not $sanitizerEvidence) { $gaps.Add('no executable or DLL was produced to carry sanitizer evidence') }
    elseif ($sanitizerEvidence | Where-Object { -not $_.asan_runtime_referenced }) { $gaps.Add('a produced binary does not reference the AddressSanitizer runtime') }
}

$result = [ordered]@{
    schema = 'appsec-review/windows-host-build/1'
    status = $status
    host_risk = if ($AcceptHostRisk) { 'accepted: target source was built unsandboxed as the invoking user' } else { 'repository canary' }
    request = [ordered]@{ build_system = $BuildSystem; compiler = $Compiler; sanitize = $Sanitize; configuration = $Configuration; project = $Project; timeout_seconds = $TimeoutSeconds }
    toolchain = [ordered]@{ visual_studio = $vs.displayName; version = $vs.installationVersion; instance_id = $vs.instanceId }
    steps = $steps
    commands_artifact = if ($commandsPath) { [ordered]@{ path = $commandsPath.Substring($RunDirectory.Length + 1).Replace('\', '/'); sha256 = Get-Sha256 $commandsPath } } else { $null }
    outputs = $inventory
    sanitizer_evidence = $sanitizerEvidence
    gaps = $gaps
}
$resultPath = Join-Path $RunDirectory 'result.json'
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resultPath -Encoding utf8
Write-Host ("{0}: {1} ({2} output file(s), {3} step(s))" -f $status, $resultPath, $inventory.Count, $steps.Count)
exit $(if ($status -eq 'SUCCEEDED' -and -not $gaps.Count) { 0 } elseif ($status -eq 'SUCCEEDED') { 2 } else { 1 })
