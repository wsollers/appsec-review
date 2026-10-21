# Shared helpers for the operator scripts in scripts/ (PowerShell twins of the bash scripts).
# Dot-source this file; do not execute it. The real logic is deploy/dagster/bin/ops.py: the twins
# translate their -PascalCase parameters to ops.py's --kebab-case options and run it either with a
# local Python (native Windows stack) or, with -Wsl, through the bash twin inside WSL (WSL stack).
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A checkout is a directory holding appsec-review.toml and deploy/dagster/bin/ops.py.
function Test-RepoRoot {
    param([string]$Path)
    if (-not $Path) { return $false }
    return ((Test-Path -LiteralPath (Join-Path $Path 'appsec-review.toml')) -and
            (Test-Path -LiteralPath (Join-Path (Join-Path (Join-Path (Join-Path $Path 'deploy') 'dagster') 'bin') 'ops.py')))
}

# Walk up from $Start (like git does) to the nearest checkout; $null when there is none.
function Find-RepoRoot {
    param([string]$Start)
    $directory = $Start
    while ($directory) {
        if (Test-RepoRoot $directory) { return $directory }
        $parent = Split-Path -Parent $directory
        if (-not $parent -or $parent -eq $directory) { break }
        $directory = $parent
    }
    return $null
}

# The checkout the scripts act on, in this order: $env:APPSEC_REPO_ROOT; the checkout that contains the
# directory the script was started in (so starting in a checkout, including one on a WSL path such as
# \\wsl.localhost\Ubuntu-24.04\home\you\appsec-review, acts on that checkout wherever it lives); then the
# checkout this script file belongs to.
function Resolve-OpsRoot {
    if ($env:APPSEC_REPO_ROOT) {
        $configured = [System.IO.Path]::GetFullPath($env:APPSEC_REPO_ROOT)
        if (-not (Test-RepoRoot $configured)) {
            throw "APPSEC_REPO_ROOT is not an appsec-review checkout (no appsec-review.toml and deploy/dagster/bin/ops.py): $configured"
        }
        return @($configured, 'APPSEC_REPO_ROOT')
    }
    $here = $null
    try { $here = (Get-Location -PSProvider FileSystem -ErrorAction Stop).ProviderPath } catch { $here = $null }
    $found = Find-RepoRoot $here
    if ($found) { return @($found, 'current directory') }
    return @([System.IO.Path]::GetFullPath((Join-Path (Join-Path $PSScriptRoot '..') '..')), 'script location')
}

$script:OpsRootChoice = Resolve-OpsRoot
$script:OpsRoot = $script:OpsRootChoice[0]
$script:OpsRootSource = $script:OpsRootChoice[1]

function ConvertTo-OpsFlag {
    param([Parameter(Mandatory)][string]$Name)
    '--' + (($Name -creplace '([a-z0-9])([A-Z])', '$1-$2').ToLowerInvariant())
}

function Test-OpsPython {
    param([Parameter(Mandatory)][string]$Path)
    try {
        & $Path -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

# The interpreter to use: $env:APPSEC_PYTHON, this checkout's .venv, the main checkout's .venv
# (git worktrees), then python / python3 from PATH.
function Get-OpsPython {
    if ($env:APPSEC_PYTHON) { return $env:APPSEC_PYTHON }
    $candidates = @((Join-Path (Join-Path (Join-Path $script:OpsRoot '.venv') 'Scripts') 'python.exe'),
                    (Join-Path (Join-Path (Join-Path $script:OpsRoot '.venv') 'bin') 'python'))
    $common = & git -C $script:OpsRoot rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -eq 0 -and $common) {
        $main = Split-Path -Parent ($common | Select-Object -First 1)
        $candidates += @((Join-Path (Join-Path (Join-Path $main '.venv') 'Scripts') 'python.exe'),
                         (Join-Path (Join-Path (Join-Path $main '.venv') 'bin') 'python'))
    }
    foreach ($candidate in $candidates) {
        if ((Test-Path -LiteralPath $candidate) -and (Test-OpsPython $candidate)) { return $candidate }
    }
    foreach ($name in 'python', 'python3') {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($found -and (Test-OpsPython $found.Source)) { return $found.Source }
    }
    throw 'No Python 3.11+ found; create .venv or set $env:APPSEC_PYTHON.'
}

# Windows path -> WSL path. UNC paths into the distribution are mapped directly; others use wslpath.
function ConvertTo-WslPath {
    param([Parameter(Mandatory)][string]$Distro, [Parameter(Mandatory)][string]$Path)
    if ($Path -match '^\\\\wsl(\.localhost|\$)\\[^\\]+\\(?<rest>.*)$') {
        return '/' + ($Matches['rest'] -replace '\\', '/')
    }
    $translated = & wsl.exe -d $Distro -e wslpath -a ($Path -replace '\\', '/')
    if ($LASTEXITCODE -ne 0 -or -not $translated) { throw "wslpath could not translate '$Path' in $Distro" }
    return ([string]($translated | Select-Object -First 1)).Trim()
}

# Build the ops.py argument list from a script's bound parameters. Parameters named in
# $Positional are passed as plain arguments after the options; -Extra goes after "--".
function ConvertTo-OpsArguments {
    param(
        [Parameter(Mandatory)][hashtable]$Bound,
        [string[]]$Positional = @(),
        [string]$Distro = ''
    )
    $skip = @('Wsl', 'Distro', 'Help', 'Extra')
    $flags = New-Object System.Collections.Generic.List[string]
    $tail = New-Object System.Collections.Generic.List[string]
    foreach ($key in $Bound.Keys) {
        if ($skip -contains $key) { continue }
        $value = $Bound[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $flags.Add((ConvertTo-OpsFlag $key)) }
            continue
        }
        $text = [string]$value
        if ($Distro -and $text -match '^([A-Za-z]:[\\/]|\\\\)') { $text = ConvertTo-WslPath -Distro $Distro -Path $text }
        if ($Positional -contains $key) { $tail.Add($text) } else { $flags.Add((ConvertTo-OpsFlag $key)); $flags.Add($text) }
    }
    $result = @($flags) + @($tail)
    if ($Bound.ContainsKey('Extra') -and $Bound['Extra']) { $result += @('--') + @($Bound['Extra']) }
    return $result
}

# Run one operator command and exit with its status.
function Invoke-Ops {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Bound,
        [string[]]$Positional = @()
    )
    $useWsl = $Bound.ContainsKey('Wsl') -and $Bound['Wsl']
    $distro = if ($Bound.ContainsKey('Distro') -and $Bound['Distro']) { [string]$Bound['Distro'] } else { 'Ubuntu-24.04' }
    # A checkout on a WSL path names its own distribution; use it unless -Distro was given.
    if (-not ($Bound.ContainsKey('Distro') -and $Bound['Distro']) -and $script:OpsRoot -match '^\\\\wsl(\.localhost|\$)\\(?<distro>[^\\]+)\\') {
        $distro = $Matches['distro']
    }
    $helpRequested = $Bound.ContainsKey('Help') -and $Bound['Help']
    Write-Host "[$Name] repository: $($script:OpsRoot) (from $($script:OpsRootSource))"
    if ($useWsl) {
        $script = ConvertTo-WslPath -Distro $distro -Path (Join-Path (Join-Path $script:OpsRoot 'scripts') "$Name.sh")
        $arguments = if ($helpRequested) { @('--help') } else { ConvertTo-OpsArguments -Bound $Bound -Positional $Positional -Distro $distro }
        Write-Host "[$Name] running in WSL ($distro): $script"
        & wsl.exe -d $distro -e bash $script @arguments
    } else {
        $python = Get-OpsPython
        $arguments = if ($helpRequested) { @('--help') } else { ConvertTo-OpsArguments -Bound $Bound -Positional $Positional }
        $ops = Join-Path (Join-Path (Join-Path (Join-Path $script:OpsRoot 'deploy') 'dagster') 'bin') 'ops.py'
        & $python $ops $Name @arguments
    }
    exit $LASTEXITCODE
}
