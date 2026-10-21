# Shared helpers for the Windows host build runner (dot-source this file). PowerShell 7+.
#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-VisualStudio {
    <# The newest Visual Studio with the MSVC x64 toolset, from Microsoft's own inventory tool. #>
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found: Visual Studio is not installed.' }
    $json = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json
    $instance = ($json | ConvertFrom-Json) | Select-Object -First 1
    if (-not $instance) { throw 'No Visual Studio instance with the MSVC x64 toolset was found.' }
    return $instance
}

function Get-BuildEnvironment {
    <# The x64 developer environment, derived from a minimal base so nothing from the user's session leaks in. #>
    param([Parameter(Mandatory)] $VisualStudio, [Parameter(Mandatory)] [string] $Scratch, [string] $Arch = 'x64')
    $vcvars = Join-Path $VisualStudio.installationPath 'VC\Auxiliary\Build\vcvarsall.bat'
    if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found under $($VisualStudio.installationPath)" }
    $system = $env:SystemRoot
    $base = [ordered]@{
        SystemRoot = $system; windir = $system; ComSpec = "$system\System32\cmd.exe"
        PATH = "$system\System32;$system"; PATHEXT = '.COM;.EXE;.BAT;.CMD'
        TEMP = $Scratch; TMP = $Scratch
        ProgramFiles = $env:ProgramFiles; 'ProgramFiles(x86)' = ${env:ProgramFiles(x86)}
        ProgramData = $env:ProgramData; NUMBER_OF_PROCESSORS = $env:NUMBER_OF_PROCESSORS
        PROCESSOR_ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE
        SystemDrive = $env:SystemDrive; ProgramW6432 = $env:ProgramW6432; CommonProgramFiles = $env:CommonProgramFiles
        ALLUSERSPROFILE = $env:ALLUSERSPROFILE; COMPUTERNAME = $env:COMPUTERNAME; USERNAME = 'appsec-build'
        # MSBuild's file tracker and the toolchain expect a per-user profile; give them an empty one inside the run.
        USERPROFILE = $Scratch; APPDATA = "$Scratch\AppData\Roaming"; LOCALAPPDATA = "$Scratch\AppData\Local"
        DOTNET_CLI_TELEMETRY_OPTOUT = '1'; DOTNET_NOLOGO = '1'; MSBUILDDISABLENODEREUSE = '1'
    }
    foreach ($directory in $base['APPDATA'], $base['LOCALAPPDATA']) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
    $start = [System.Diagnostics.ProcessStartInfo]::new("$system\System32\cmd.exe")
    # cmd.exe does not understand the backslash-escaped quotes ArgumentList produces, so this one line is raw.
    $start.Arguments = "/d /s /c `"`"$vcvars`" $Arch >nul && set`""
    $start.WorkingDirectory = $Scratch
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.Environment.Clear()
    foreach ($key in $base.Keys) { $start.Environment[$key] = [string]$base[$key] }
    $process = [System.Diagnostics.Process]::Start($start)
    $text = $process.StandardOutput.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "vcvarsall.bat failed with exit code $($process.ExitCode)" }
    $result = [ordered]@{}
    foreach ($line in $text -split "`r?`n") {
        $split = $line.IndexOf('=')
        if ($split -gt 0) { $result[$line.Substring(0, $split)] = $line.Substring($split + 1) }
    }
    return $result
}

function Resolve-Tool {
    <# Resolve a tool name to a file using the PATH of the given environment, never the caller's. #>
    param([Parameter(Mandatory)] $Environment, [Parameter(Mandatory)] [string] $Name)
    foreach ($directory in ($Environment['Path'] ?? $Environment['PATH']) -split ';') {
        if (-not $directory) { continue }
        foreach ($extension in '.exe', '.cmd', '.bat') {
            $candidate = Join-Path $directory ($Name + $extension)
            if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
        }
    }
    return $null
}

function Invoke-Bounded {
    <# Run one program with a clean environment, a wall-clock limit and its process tree killed on timeout. #>
    param(
        [Parameter(Mandatory)] [string] $File, [string[]] $Arguments = @(), [Parameter(Mandatory)] $Environment,
        [Parameter(Mandatory)] [string] $WorkingDirectory, [int] $TimeoutSeconds = 600,
        [Parameter(Mandatory)] [string] $StdoutPath, [Parameter(Mandatory)] [string] $StderrPath
    )
    $start = [System.Diagnostics.ProcessStartInfo]::new($File)
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    $start.Environment.Clear()
    foreach ($key in $Environment.Keys) { $start.Environment[$key] = [string]$Environment[$key] }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($start)
    $out = $process.StandardOutput.ReadToEndAsync()
    $err = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F *> $null
        $process.WaitForExit()
    }
    $out.Wait(); $err.Wait()
    [System.IO.File]::WriteAllText($StdoutPath, $out.Result)
    [System.IO.File]::WriteAllText($StderrPath, $err.Result)
    return [pscustomobject]@{
        File = $File; Arguments = $Arguments; ExitCode = $(if ($timedOut) { $null } else { $process.ExitCode })
        TimedOut = $timedOut; Seconds = [math]::Round($clock.Elapsed.TotalSeconds, 2)
        Stdout = $StdoutPath; Stderr = $StderrPath
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
