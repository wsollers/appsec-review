param([string]$Common, [string]$Output)
$ErrorActionPreference = 'Stop'
$ownedBin = Split-Path -Parent $Output
Add-Type -Path (Join-Path $PSScriptRoot 'wsl_standin.cs') -OutputAssembly (Join-Path $ownedBin 'wsl.exe') -OutputType ConsoleApplication
$env:PATH = "$ownedBin;$env:PATH"
$env:APPSEC_ACCEPTANCE_WSL_ARGS = $Output
. $Common

$unc = ConvertTo-WslPath -Distro 'Fixture Distro' -Path '\\wsl.localhost\Fixture Distro\home\user\repo with spaces'
if ($unc -ne '/home/user/repo with spaces') { throw "bad UNC conversion: $unc" }
$script:OpsRoot = 'C:\fixture with spaces\repository'
$script:OpsRootSource = 'acceptance stand-in'
$bound = @{
    Wsl = $true
    Distro = 'Fixture Distro'
    Target = 'C:\target with spaces\source'
    RunId = '2026-10-28-0001'
    DryRun = [System.Management.Automation.SwitchParameter]$true
    Extra = @('literal $HOME', 'semi;colon', "c'd")
}
Invoke-Ops -Name 'review-start' -Bound $bound
