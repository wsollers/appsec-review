<#
.SYNOPSIS
Render the report of a finished review run to PDF or to a single-page HTML file.

.DESCRIPTION
html  runs only the Python renderer (stdlib, no Docker).
pdf   renders report.tex with the Python renderer, then compiles it in the tool-report-latex image
      under the standard runtime boundary (no network, read-only root, all capabilities dropped,
      non-root, template and input mounted read-only, one writable scratch directory).

Works from any current directory, in PowerShell 7 and Windows PowerShell 5.1. The run directory is
only read. Exit status: 0 success, 1 render failure, 2 usage error or a missing prerequisite.

.PARAMETER Run
Run id (looked up in -RunsDir) or a run directory.
.PARAMETER Format
pdf (default) or html.
.PARAMETER RunsDir
Directory holding run directories (default: <repo>\runs).
.PARAMETER OutputDir
Where <run-id>.pdf / <run-id>.html is written (default: <repo>\runs\reports, which git ignores).
.PARAMETER Limit
Render only the first N packages (a bounded sample).
.PARAMETER Package
Render only packages whose id starts with or contains this value (repeatable).
.PARAMETER MaxCells
Interchanges drawn per package (default 6).
.PARAMETER Image
Report image for pdf (default appsec-review/tool-report-latex:1.0.0).
.PARAMETER KeepWork
Keep the staging directory (report.tex, build log) next to the output.
.PARAMETER Help
Show this help.

.EXAMPLE
scripts\render-report.ps1 -Run 2026-10-21-0007 -Format html
.EXAMPLE
scripts\render-report.ps1 -Run 2026-10-21-0007 -Format pdf -Limit 3 -OutputDir C:\Temp\reports

The pdf format needs the image: containers\build-all.ps1 build tool-report-latex
#>
[CmdletBinding()]
param(
    [string]$Run,
    [ValidateSet('pdf', 'html')]
    [string]$Format = 'pdf',
    [string]$RunsDir,
    [string]$OutputDir,
    [int]$Limit = 0,
    [string[]]$Package = @(),
    [int]$MaxCells = 0,
    [string]$Image = 'appsec-review/tool-report-latex:1.0.0',
    [switch]$KeepWork,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Show-Usage {
    @"
Usage: scripts\render-report.ps1 -Run <run-id|run-dir> [-Format pdf|html] [options]

Render the report of a review run to PDF or single-page HTML.

  -Run <id|dir>        run id (looked up in -RunsDir) or a run directory   (required)
  -Format pdf|html     output format (default: pdf)
  -RunsDir <dir>       directory holding run directories (default: <repo>\runs)
  -OutputDir <dir>     where <run-id>.pdf / <run-id>.html is written
                       (default: <repo>\runs\reports, which git ignores)
  -Limit <n>           render only the first n packages (a bounded sample)
  -Package <id>[,..]   render only packages whose id starts with or contains the value
  -MaxCells <n>        interchanges drawn per package (default: 6)
  -Image <tag>         report image for pdf (default: appsec-review/tool-report-latex:1.0.0)
  -KeepWork            keep the staging directory (report.tex, build log) next to the output
  -Help                show this help

Environment: APPSEC_PYTHON selects the Python 3.11+ interpreter; APPSEC_DOCKER_BIN a Docker client.
The pdf format needs the image: containers\build-all.ps1 build tool-report-latex
"@
}

function Stop-Render([string]$Message, [int]$Code = 2) {
    [Console]::Error.WriteLine("render-report: $Message")
    exit $Code
}

if ($Help) { Show-Usage; exit 0 }
if (-not $Run) { Show-Usage | ForEach-Object { [Console]::Error.WriteLine($_) }; Stop-Render '-Run is required' }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = (Resolve-Path -LiteralPath (Join-Path $ScriptDir '..')).ProviderPath
if (-not $RunsDir) { $RunsDir = Join-Path $Repo 'runs' }
if (-not $OutputDir) { $OutputDir = Join-Path (Join-Path $Repo 'runs') 'reports' }

# -- Python -----------------------------------------------------------------------------------------
$PythonExe = $env:APPSEC_PYTHON
$PythonPrefix = @()
if (-not $PythonExe) {
    $venvPython = if ([IO.Path]::DirectorySeparatorChar -eq '\') { Join-Path $Repo '.venv\Scripts\python.exe' } else { Join-Path $Repo '.venv/bin/python' }
    foreach ($candidate in @($venvPython)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $PythonExe = $candidate; break }
    }
}
if (-not $PythonExe) {
    foreach ($name in @('python', 'python3')) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($found -and $found.CommandType -eq 'Application') { $PythonExe = $found.Source; break }
    }
}
if (-not $PythonExe) {
    $launcher = Get-Command 'py' -ErrorAction SilentlyContinue
    if ($launcher) { $PythonExe = $launcher.Source; $PythonPrefix = @('-3') }
}
if (-not $PythonExe) { Stop-Render 'no Python interpreter found; set APPSEC_PYTHON' }
$env:PYTHONPATH = if ($env:PYTHONPATH) { (Join-Path $Repo 'src') + [IO.Path]::PathSeparator + $env:PYTHONPATH } else { Join-Path $Repo 'src' }
$env:PYTHONDONTWRITEBYTECODE = '1'

# -- Run directory ----------------------------------------------------------------------------------
if (Test-Path -LiteralPath (Join-Path $Run 'data') -PathType Container) {
    $RunDir = (Resolve-Path -LiteralPath $Run).ProviderPath
} elseif (Test-Path -LiteralPath (Join-Path (Join-Path $RunsDir $Run) 'data') -PathType Container) {
    $RunDir = (Resolve-Path -LiteralPath (Join-Path $RunsDir $Run)).ProviderPath
} else {
    Stop-Render "run '$Run' not found: neither '$Run\data' nor '$RunsDir\$Run\data' is a directory"
}
$RunId = Split-Path -Leaf $RunDir.TrimEnd('\', '/')
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).ProviderPath

$RenderArgs = @('--run', $RunDir)
if ($Limit -gt 0) { $RenderArgs += @('--limit', "$Limit") }
elseif ($PSBoundParameters.ContainsKey('Limit')) { Stop-Render '-Limit must be a positive integer' }
if ($MaxCells -gt 0) { $RenderArgs += @('--max-cells', "$MaxCells") }
elseif ($PSBoundParameters.ContainsKey('MaxCells')) { Stop-Render '-MaxCells must be a positive integer' }
foreach ($item in $Package) { foreach ($id in ($item -split ',')) { if ($id) { $RenderArgs += @('--package', $id) } } }

# Native commands write progress to stderr; in Windows PowerShell 5.1 that is a terminating error under
# $ErrorActionPreference = 'Stop', so every native call goes through this helper.
function Invoke-Native([string]$Exe, [string[]]$Arguments, [string]$StdOut = $null, [string]$StdErr = $null) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($StdOut) { & $Exe @Arguments 1> $StdOut 2> $StdErr }
        else { & $Exe @Arguments 2>&1 | Out-Null }
        return $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
}

function Invoke-Renderer([string]$Kind, [string]$Out) {
    $allArgs = @($PythonPrefix) + @('-m', 'appsec_review.reporting', 'render') + $RenderArgs + @('--format', $Kind, '--out', $Out)
    return (Invoke-Native $PythonExe $allArgs)
}

$Stage = Join-Path $OutputDir (".render-$RunId-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
$Failed = $false
try {
    # -- HTML -----------------------------------------------------------------------------------
    if ($Format -eq 'html') {
        if ((Invoke-Renderer 'html' $Stage) -ne 0) { Stop-Render 'the HTML renderer failed' 1 }
        $Target = Join-Path $OutputDir "$RunId.html"
        Move-Item -LiteralPath (Join-Path $Stage 'report.html') -Destination $Target -Force
        Write-Output $Target
        exit 0
    }

    # -- PDF ------------------------------------------------------------------------------------
    $Docker = if ($env:APPSEC_DOCKER_BIN) { $env:APPSEC_DOCKER_BIN } else { 'docker' }
    if (-not (Get-Command $Docker -ErrorAction SilentlyContinue)) {
        Stop-Render "Docker is required for -Format pdf but '$Docker' was not found. Install Docker, or use -Format html"
    }
    if ((Invoke-Native $Docker @('image', 'inspect', $Image)) -ne 0) {
        Stop-Render "the report image '$Image' is not available locally (or the Docker daemon is not running). Build it with: containers\build-all.ps1 build tool-report-latex"
    }
    $TemplateDir = Join-Path $Repo 'containers\report\latex\template'
    if (-not (Test-Path -LiteralPath (Join-Path $TemplateDir 'appsec-report.cls'))) { Stop-Render "template not found at $TemplateDir" }
    foreach ($path in @($TemplateDir, $Stage)) { if ($path.Contains(',')) { Stop-Render "a path containing a comma cannot be bind-mounted: $path" } }

    $InputDir = Join-Path $Stage 'input'
    $ScratchDir = Join-Path $Stage 'scratch'
    New-Item -ItemType Directory -Force -Path $InputDir, $ScratchDir | Out-Null
    if ((Invoke-Renderer 'tex' $InputDir) -ne 0) { Stop-Render 'the LaTeX renderer failed' 1 }
    if ($PSVersionTable.PSEdition -eq 'Core' -and ($IsLinux -or $IsMacOS)) { & chmod 0777 $ScratchDir }

    $Container = "appsec-report-$PID"
    $dockerArgs = @('run', '--rm', '--name', $Container,
        '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--user', '10001:10001', '--pids-limit', '256', '--memory', '1g', '--cpus', '2',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=128m',
        '--mount', "type=bind,src=$TemplateDir,dst=/template,readonly",
        '--mount', "type=bind,src=$InputDir,dst=/input,readonly",
        '--mount', "type=bind,src=$ScratchDir,dst=/scratch",
        $Image, '/opt/tool/bin/render-pdf')
    $RenderOut = Join-Path $Stage 'render.out'
    $RenderErr = Join-Path $Stage 'render.err'
    $Status = Invoke-Native $Docker $dockerArgs $RenderOut $RenderErr
    Invoke-Native $Docker @('rm', '-f', $Container) | Out-Null
    $Pdf = Join-Path $ScratchDir 'report.pdf'
    if ($Status -ne 0 -or -not (Test-Path -LiteralPath $Pdf)) {
        $Failed = $true
        [Console]::Error.WriteLine("render-report: PDF rendering failed (exit $Status)")
        if (Test-Path -LiteralPath $RenderErr) { Get-Content -LiteralPath $RenderErr -Tail 40 | ForEach-Object { [Console]::Error.WriteLine($_) } }
        $Log = Join-Path $ScratchDir 'report.log'
        if (Test-Path -LiteralPath $Log) {
            [Console]::Error.WriteLine('--- last lines of the TeX log ---')
            Get-Content -LiteralPath $Log -Tail 40 | ForEach-Object { [Console]::Error.WriteLine($_) }
        }
        exit 1
    }
    $Target = Join-Path $OutputDir "$RunId.pdf"
    Copy-Item -LiteralPath $Pdf -Destination $Target -Force
    Write-Output $Target
    exit 0
} finally {
    if ($KeepWork -or $Failed) {
        [Console]::Error.WriteLine("render-report: kept $Stage")
    } elseif (Test-Path -LiteralPath $Stage) {
        Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
