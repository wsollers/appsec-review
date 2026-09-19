# run.ps1 - PowerShell twin of run.sh for language build/LSP/MCP containers.
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)] [string]$Image,
    [Parameter(Mandatory, Position = 1)] [string]$Workspace,
    [Parameter(Mandatory, Position = 2)] [string]$Scratch,
    [Parameter(ValueFromRemainingArguments = $true)] [string[]]$Command
)
$ErrorActionPreference = "Stop"
if ($Command.Count -gt 0 -and $Command[0] -eq "--") { $Command = $Command[1..($Command.Count - 1)] }
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$ws = (Resolve-Path $Workspace).ProviderPath
$scr = (Resolve-Path $Scratch).ProviderPath
$uid = if ($IsLinux) { "$(id -u):$(id -g)" } else { "10001:10001" }
$networkArgs = if ($env:ALLOW_NETWORK -eq "1") { @("--network", "bridge") } else { @("--network", "none") }
$debugArgs = if ($env:DEBUG_CAPS -eq "1") { @("--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined") } else { @() }
$mem = if ($env:MEM_LIMIT) { $env:MEM_LIMIT } else { "12g" }
$args = @(
    "run", "--rm",
    "--user", $uid
) + $networkArgs + @(
    "--hostname", "audit-buildenv", "--add-host", "audit-buildenv:127.0.0.1",
    "--read-only",
    "--cap-drop", "ALL"
) + $debugArgs + @(
    "--security-opt", "no-new-privileges",
    "--pids-limit", $(if ($env:PIDS_LIMIT) { $env:PIDS_LIMIT } else { "2048" }),
    "--memory", $mem, "--memory-swap", $mem,
    "--cpus", $(if ($env:CPU_LIMIT) { $env:CPU_LIMIT } else { "8" }),
    "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=4g",
    "--tmpfs", "/tmp/home:rw,exec,nosuid,nodev,size=1g",
    "-v", "${ws}:/workspace:ro",
    "-v", "${scr}:/scratch:rw",
    "-e", "HOME=/tmp/home",
    "-e", "XDG_CACHE_HOME=/scratch/.cache",
    "-e", "npm_config_cache=/scratch/.npm",
    "-e", "PIP_CACHE_DIR=/scratch/.pip-cache",
    $Image
) + $Command
& docker @args
exit $LASTEXITCODE
