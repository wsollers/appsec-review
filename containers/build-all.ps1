[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'build.py'
& python $scriptPath @Arguments
exit $LASTEXITCODE
