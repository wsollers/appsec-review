<#
.SYNOPSIS
    Pull and push the appsec-review repo in both the Windows checkout and the WSL clone.

.DESCRIPTION
    For each side, in order Windows -> WSL -> Windows:
      fetch --prune; fast-forward pull when behind; push when ahead.
    The second Windows pass picks up whatever the WSL push published, so both end level with
    origin. Fails closed: a detached HEAD, a missing upstream or a diverged branch (ahead AND behind)
    stops the script without merging or rebasing -- resolve it by hand, or pass -Rebase to allow
    `pull --rebase` for that case. Uncommitted changes are reported, never stashed or discarded;
    git itself refuses a pull that would overwrite them.

.EXAMPLE
    .\scripts\Sync-AppsecReview.ps1
.EXAMPLE
    .\scripts\Sync-AppsecReview.ps1 -NoPush -Distro Ubuntu-24.04
#>
[CmdletBinding()]
param(
    [string]$WindowsPath = 'F:\repos\appsec-review',
    [string]$WslPath = '~/projects/appsec-review',
    [string]$Distro = '',
    [switch]$NoPush,
    [switch]$Rebase
)
$ErrorActionPreference = 'Stop'

function Invoke-SideGit {
    param([Parameter(Mandatory)][ValidateSet('Windows', 'WSL')][string]$Side, [Parameter(Mandatory)][string[]]$GitArgs)
    # Windows PowerShell 5.1 turns native stderr (git's normal progress output) into errors under
    # 'Stop'; exit codes are checked explicitly instead.
    $ErrorActionPreference = 'Continue'
    if ($Side -eq 'Windows') {
        $output = & git -C $WindowsPath @GitArgs 2>&1
    } else {
        # Run through bash so ~ / $HOME expand; every git argument is single-quoted.
        $dir = $WslPath -replace '^~', '$HOME'
        $quoted = ($GitArgs | ForEach-Object { "'" + ($_ -replace "'", "'\''") + "'" }) -join ' '
        $distroArgs = @(); if ($Distro) { $distroArgs = @('-d', $Distro) }
        $output = & wsl.exe @distroArgs -- bash -lc "cd `"$dir`" && git $quoted" 2>&1
    }
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = (($output | ForEach-Object { "$_" }) -join "`n").Trim() }
}

function Assert-Git {
    param([string]$Side, [string[]]$GitArgs, [string]$What)
    $r = Invoke-SideGit -Side $Side -GitArgs $GitArgs
    if ($r.ExitCode -ne 0) { throw "[$Side] $What failed (exit $($r.ExitCode)):`n$($r.Text)" }
    $r.Text
}

function Sync-Side {
    param([string]$Side, [switch]$PullOnly)
    $branch = Assert-Git $Side @('rev-parse', '--abbrev-ref', 'HEAD') 'reading the branch'
    if ($branch -eq 'HEAD') { throw "[$Side] detached HEAD; check out a branch first" }
    $upstream = Invoke-SideGit $Side @('rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}')
    if ($upstream.ExitCode -ne 0) { throw "[$Side] branch '$branch' has no upstream; set one with git push -u origin $branch" }

    $dirty = Assert-Git $Side @('status', '--porcelain') 'reading status'
    if ($dirty -and -not $PullOnly) { Write-Warning "[$Side] uncommitted changes present (left untouched):`n$dirty" }

    Assert-Git $Side @('fetch', '--prune', '--quiet') 'fetch' | Out-Null
    $counts = (Assert-Git $Side @('rev-list', '--left-right', '--count', 'HEAD...@{u}') 'comparing with upstream') -split '\s+'
    $ahead = [int]$counts[0]; $behind = [int]$counts[1]
    Write-Host "[$Side] $branch -> $($upstream.Text): ahead $ahead, behind $behind"

    if ($ahead -gt 0 -and $behind -gt 0) {
        if (-not $Rebase) { throw "[$Side] $branch has diverged from $($upstream.Text); resolve by hand or re-run with -Rebase" }
        Assert-Git $Side @('pull', '--rebase', '--quiet') 'pull --rebase' | Out-Null
        Write-Host "[$Side] rebased onto $($upstream.Text)"
    } elseif ($behind -gt 0) {
        Assert-Git $Side @('pull', '--ff-only', '--quiet') 'pull --ff-only' | Out-Null
        Write-Host "[$Side] fast-forwarded $behind commit(s)"
    }

    if (-not $PullOnly -and -not $NoPush -and $ahead -gt 0) {
        Assert-Git $Side @('push', '--quiet') 'push' | Out-Null
        Write-Host "[$Side] pushed $ahead commit(s)"
    }
    Assert-Git $Side @('rev-parse', '--short', 'HEAD') 'reading HEAD'
}

try {
    $null = Sync-Side 'Windows'
    $wsl = Sync-Side 'WSL'
    $win = Sync-Side 'Windows' -PullOnly
    if ($win -eq $wsl) { Write-Host "In sync: Windows and WSL both at $win" -ForegroundColor Green }
    else { Write-Warning "Windows at $win, WSL at $wsl -- different branches or a push was skipped (-NoPush)" }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
