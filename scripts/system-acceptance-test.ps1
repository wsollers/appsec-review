# Windows entry point for the system acceptance test. Runs scripts/system-acceptance-test.sh inside
# WSL, in the WSL clone (the POSIX host where the code location and jobs run), passing every other
# argument through.
#
#   .\scripts\system-acceptance-test.ps1 -Distro Ubuntu-24.04 --list
#   .\scripts\system-acceptance-test.ps1 -Distro Ubuntu-24.04 --through sut-checkout
#   .\scripts\system-acceptance-test.ps1 -Distro Ubuntu-24.04 --resume <sat_id> --through <stage>
#
# -Repo is the clone's path relative to the WSL home directory (default projects/appsec-review).
param(
    [string]$Distro = '',
    [string]$Repo = 'projects/appsec-review',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$SatArgs
)
$ErrorActionPreference = 'Stop'
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
# cd ~ first so a relative -Repo resolves against the WSL home; "$@" keeps each argument intact.
& wsl.exe @wslArgs -- bash -c 'cd ~ && cd "$1" && shift && exec bash scripts/system-acceptance-test.sh "$@"' sat $Repo @SatArgs
exit $LASTEXITCODE
