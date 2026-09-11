# Watch-SemgrepProgress.ps1
# Polls `docker exec <container> ps aux` once a minute so you can watch
# pysemgrep/semgrep-core's TIME column move (or not) without babysitting it
# by hand. Ctrl+C to stop - it doesn't touch the container, purely read-only.
#
# Usage:
#   .\Watch-SemgrepProgress.ps1 -ContainerId 475c51f1b01f
#   .\Watch-SemgrepProgress.ps1 -ContainerId 475c51f1b01f -IntervalSeconds 60 -MaxChecks 20

param(
    [Parameter(Mandatory = $true)]
    [string]$ContainerId,

    [int]$IntervalSeconds = 60,

    # 0 = run forever (until Ctrl+C or the container stops)
    [int]$MaxChecks = 0
)

$check = 0
while ($true) {
    $check++
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Bail out cleanly if the container has already stopped/exited, rather
    # than spamming "No such container" errors every minute.
    $stillRunning = docker ps -q -f "id=$ContainerId"
    if (-not $stillRunning) {
        Write-Host "[$timestamp] Container $ContainerId is no longer running - stopping watch. Check 'docker ps -a' and MANIFEST.json for the final result." -ForegroundColor Yellow
        break
    }

    Write-Host ""
    Write-Host "===== $timestamp (check #$check) =====" -ForegroundColor Cyan
    docker exec $ContainerId ps aux

    if ($MaxChecks -gt 0 -and $check -ge $MaxChecks) {
        Write-Host "`nReached -MaxChecks $MaxChecks - stopping. Re-run to keep watching." -ForegroundColor Yellow
        break
    }

    Start-Sleep -Seconds $IntervalSeconds
}
