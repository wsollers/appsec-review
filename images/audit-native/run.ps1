# run.ps1 — PowerShell twin of run.sh: the hostile-build boundary for one container step.
#   .\images\audit-native\run.ps1 -Workspace <dir> -Msvc <dir|-> -Scratch <dir> -- <command...>
# Same flags as run.sh, in the same order; keep the two files in sync (diff them in review).
# Windows note: run this from WSL2 pwsh with WSL-filesystem paths for speed; from Windows
# pwsh it works but bind mounts of C:\/F:\ paths cross the slow VM bridge.
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)] [string]$Workspace,
    [Parameter(Mandatory, Position = 1)] [string]$Msvc,
    [Parameter(Mandatory, Position = 2)] [string]$Scratch,
    [Parameter(ValueFromRemainingArguments = $true)] [string[]]$Command
)
$ErrorActionPreference = "Stop"
if ($Command.Count -gt 0 -and $Command[0] -eq "--") { $Command = $Command[1..($Command.Count - 1)] }
$image = if ($env:AUDIT_NATIVE_IMAGE) { $env:AUDIT_NATIVE_IMAGE } else { "audit-native:local" }
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null
$ws  = (Resolve-Path $Workspace).ProviderPath; $scr = (Resolve-Path $Scratch).ProviderPath
$uid = if ($IsLinux) { "$(id -u):$(id -g)" } else { "10001:10001" }
$mem = if ($env:MEM_LIMIT) { $env:MEM_LIMIT } else { "16g" }
$args = @("run", "--rm", "--user", $uid, "--network", "none", "--hostname", "audit-native", "--add-host", "audit-native:127.0.0.1",
          "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
          "--pids-limit", $(if ($env:PIDS_LIMIT) { $env:PIDS_LIMIT } else { "2048" }),
          "--memory", $mem, "--memory-swap", $mem, "--cpus", $(if ($env:CPU_LIMIT) { $env:CPU_LIMIT } else { "8" }),
          "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=4g", "--tmpfs", "/tmp/home:rw,noexec,nosuid,nodev,size=1g",
          "--tmpfs", "/tmp/jvm:rw,exec,nosuid,nodev,size=512m",
          "-v", "${ws}:/workspace:ro")
if ($Msvc -ne "-") { $args += @("-v", "$((Resolve-Path $Msvc).ProviderPath):/msvc:ro") }
$args += @("-v", "${scr}:/scratch:rw", "-e", "HOME=/tmp/home", "-e", "JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/tmp/jvm", $image) + $Command
& docker @args
exit $LASTEXITCODE
