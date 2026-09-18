<#
.SYNOPSIS
    Runs the Phase 0A tooling pre-pass from the Vendor Code Audit Playbook
    against a local checkout of the vendor repo, writing structured evidence
    for the Phase 1+ LLM prompts.

.DESCRIPTION
    Orchestrates the vendor-audit-toolbox container (see Dockerfile /
    Build-AuditToolbox.ps1) one tool at a time, mounting the target repo
    read-only and an evidence directory read-write, and lays results out as

        <EvidencePath>/
          cloc/            cloc.json, scc.json
          secrets/         gitleaks.json, binary-cert-inventory.txt (S7-1)
          sbom/            sbom.cdx.json, dependency-lifecycle.json (2026-09-17 - L1 broadening:
                            license inventory re-surfaced from the SBOM + best-effort EOL/
                            abandonware signals from eol-reference.json; see that step's Note)
          sca/             osv-scanner.json
          sast-python/     bandit.json
          sast-go/         gosec.json, govulncheck.txt
          sast-cpp/        cppcheck.xml
          sast-multi/      semgrep-owasp.json, semgrep-csharp.json, semgrep-golang.json,
                            semgrep-python.json, semgrep-php.json, semgrep-java.json,
                            semgrep-security-audit.json (2026-09-02 - one file per
                            ruleset, was a single combined semgrep.json; see the
                            comment block above the sast-multi-semgrep-* steps)
          sast-php/        psalm.json, phpstan.json, phpcs.json,
                            parse-coverage.json (S6-1 - independent php -l ledger)
          sast-mobile/     mobsfscan-android.sarif, mobsfscan-ios.sarif,
                            android-coverage.txt, ios-coverage.txt (S1-1/S1-2 -
                            run per-platform explicitly, never --type auto)
          sast-java/       spotbugs-usage.txt (build-dependent - see Note)
          binskim/         binskim.sarif (binary hardening - PE/Windows strongest)
          iac/             checkov.json, tfsec.json, trivy-config.json
          iac-k8s/         kube-linter.json (Kubernetes manifests/Helm/Kustomize)
          iac-docker/      hadolint.txt (Dockerfile lint), base-images.txt (FROM-line inventory)
          license/         scancode.json (license/copyright/package-origin, separate image)
          symbol-index/    (build_symbol_index.py output - one JSON per file
                             + index.json + summary.json)
          _shareable/      (E4-1 - scrubbed copy of the above, produced LAST by
                             the evidence-scrub step; this is the only
                             subdirectory that should ever be zipped and
                             handed off outside this machine)
          MANIFEST.json    what ran, when, exit code, wall-clock duration,
                            and (2026-09-02) whether its expected output file
                            actually landed
          <subdir>/<step>.stderr.log   per-step stderr (see Note below)

    Each step runs independently and a failure in one does not stop the
    others - this mirrors "one bad file shouldn't kill the run" from
    build_symbol_index.py itself. Check MANIFEST.json afterward for anything
    that exited non-zero OR has outputOk=false.

    2026-09-01 remediation note (adversarial process review): "exited
    non-zero" and "treatedOk" are NOT the same thing as "this step
    meaningfully analyzed the target". AllowNonZeroExit is a per-step
    blanket flag, not a per-failure-mode one - it can't distinguish "gitleaks
    exited 2 because it found real secrets" from "binskim/kube-linter/
    joern-parse crashed outright". Steps whose Cmd ends in `|| true`
    (sast-php, iac, binskim, iac-k8s, dockerfile-lint, docker-base-images)
    have the same property at the shell level: a genuine tool crash and "ran
    clean, found nothing" both land as an empty/near-empty evidence file with
    treatedOk=true in MANIFEST.json. The exit code alone still can't tell
    those apart - but as of the 2026-09-01 verification follow-up EVERY step
    now persists its stderr to <EvidenceSubdir>/<Name>.stderr.log (previously
    only the stdout-capturing steps and the ones that redirected internally
    did, so the advice below was unfollowable for binskim/secrets/sast-python/
    etc. - that gap is now closed). So: before trusting a near-empty evidence
    file, open the matching <Name>.stderr.log and confirm the tool actually
    ran to completion rather than crashing early.

    2026-09-02 remediation note (real run against fsh-server surfaced three
    live bugs this pass fixes):

      1. Quote-escaping bugs in weggli-note, ast-grep-scan, and joern-parse's
         Cmd strings caused bash "syntax error: unexpected end of file"
         (exit 2) on every real run - confirmed against real .stderr.log
         output. Two different root causes stacked: (a) an apostrophe
         embedded inside a single-quoted bash string (joern-parse's
         "handle_packet's buffer") has no valid escape in bash single-quotes
         at all; (b) weggli-note/ast-grep-scan tried `\'...\'` to nest a
         literal quote inside a single-quoted string, which doesn't work in
         bash either, AND (worse) those Cmd strings are themselves
         PowerShell DOUBLE-quoted strings, so `\$buf` inside them was never
         protected from PowerShell's own interpolation (backtick, not
         backslash, is PowerShell's escape char) - `$buf` was undefined and
         silently vanished before bash ever ran. Fixed here by rewording all
         three usage-note strings to avoid embedded quote/dollar characters
         entirely, rather than fighting the escaping rules.

      2. treatedOk's formula treated ANY non-zero exit code as fine whenever
         AllowNonZeroExit was set - including bash's own fatal shell exit
         codes (2 = syntax error, 126 = not executable, 127 = command not
         found), which no real tool in this pipeline legitimately uses as a
         "ran fine, found something" signal. Confirmed live: ast-grep-scan
         and joern-parse both hit the bug above (exit 2, a hard crash) and
         BOTH still reported treatedOk=true - only weggli-note's Cmd
         happened to not carry AllowNonZeroExit and so was (accidentally)
         reported correctly. Fixed: exit codes 2/126/127 are now never
         treated as ok regardless of AllowNonZeroExit, unless a step
         explicitly opts in via AllowShellFatalExit (none currently do).

      3. Exit code and evidence-file existence were never cross-checked, so
         a step whose `&&`/`;`-chain broke partway through (joern-parse is
         the worst case: a broken chain silently means "no CPG" for the rest
         of the C++ semantic-search phase) or whose tool failed fast before
         writing anything (confirmed live: sast-multi-semgrep exited 7 in
         ~10s against a multi-hundred-thousand-line repo - far too fast to
         have actually scanned anything, semgrep's own fatal-error exit code)
         could still report treatedOk=true as long as the exit code alone
         looked tolerable. Fixed: steps now declare ExpectedOutput (or
         ExpectedOutputAny for multi-output steps) - a path, relative to
         EvidencePath, that must exist AND be non-empty after the step runs.
         treatedOk is now (exit-code-ok) AND (output-sanity-ok). This is the
         "structural fix" that was tracked as an open item in the
         2026-09-01 remediation doc - it's a lightweight version (existence +
         non-empty, not full schema validation) but it directly catches
         every failure mode observed in the real fsh-server run.

    2026-09-03 remediation note (joern-parse root-caused live against
    fsh-server, see that step's own Note below for full detail): the
    2026-09-02 apostrophe fix above was necessary but not sufficient. Even
    after removing the apostrophe, joern-parse's compound
    `joern-parse ... && echo '...' > README.txt` Cmd string produced
    INCONSISTENT failures depending on invocation context (a bash syntax
    error via `-File` orchestration vs. "command not found" when the exact
    same string was reconstructed and run interactively) despite the string
    itself being confirmed byte-clean three independent ways. This was a
    PowerShell native-argv marshalling problem, not a bash-wording problem -
    no further rewording was ever going to fix it. Separately and more
    concretely, joern-parse was also confirmed NOT on PATH in the toolbox
    image at all (the real binary lives at /opt/joern/joern-cli/joern-parse).
    Fixed by dropping the compound echo entirely (the usage-note text is now
    written directly by PowerShell after success, via new PostSuccessFile/
    PostSuccessText step properties - see the main step-execution loop below)
    and by invoking joern-parse via its full absolute path instead of relying
    on PATH. structural-search (ast-grep-scan) was reported elsewhere as
    sharing this same root cause but has NOT been independently re-tested
    with this same rigor yet - treat it as still open.

    A near-miss worth knowing about even though it needed no code change:
    Windows PowerShell (not PowerShell 7+) can turn a native command's
    stderr output into a terminating NativeCommandError when
    $ErrorActionPreference is "Stop" and stderr is redirected - which every
    step here does. If you're on Windows PowerShell 5.1 and see a step
    "throw" with exitCode=-1 despite the underlying tool actually working
    (confirmed live with cloc: it wrote real output and was still reported
    as having thrown, purely from incidental non-fatal stderr chatter), the
    docker invocation below is deliberately wrapped in a local
    $ErrorActionPreference = "Continue" scope for exactly this reason - keep
    that wrapper if you edit this script on Windows PowerShell, it's a no-op
    under PowerShell 7+ but load-bearing under 5.1. Note this same mechanism
    is also why a redirected stderr FILE can contain PowerShell's formatted
    "At <script>:<line> char:<col> / + CategoryInfo / + FullyQualifiedErrorId"
    framing around a real error line rather than the tool's raw bytes -
    confirmed live via joern-parse's own .stderr.log during the 2026-09-03
    investigation above; that framing describes where in THIS script the
    error surfaced, not anything from inside the container.

    A structural fix for full per-tool output SHAPE validation (e.g. "does
    binskim.sarif contain a runs[] array with the expected tool name", not
    just "does the file exist and have bytes in it") is still stronger than
    what's here and remains a tracked open item; the existence/non-empty
    check below is the interim, always-available signal - a real
    improvement over exit-code-only, but not a substitute for opening the
    evidence file yourself before trusting a "clean" result.

    IMPORTANT: the exact CLI flags below reflect each tool's interface at the
    time this script was written. These tools update their CLIs across
    releases more often than you'd like - before trusting an unattended run,
    do one `docker run --rm <image> <tool> --help` per tool you care about
    and confirm the flags below still match the version Build-AuditToolbox.ps1
    actually built.

    2026-09-04 remediation note (real run against fsh-server surfaced a
    fourth live bug, this time in argument PARSING rather than in a step's
    own Cmd string): invoking this script as
    `powershell -NoProfile -File .\Invoke-VendorAuditPrePass.ps1 ... -Steps sbom sca`
    (space-separated, via a nested nested `powershell.exe -File` child
    process rather than calling the script directly) silently bound ONLY
    "sbom" into $Steps and dropped "sca" - no error, no warning. Confirmed
    live three independent ways: (1) the real run only ever printed
    "==> sbom", never "==> sca", and sca/osv-scanner.json's timestamp never
    moved; (2) a trivial throwaway probe script with the same
    `param([string[]]$Steps)` shape, invoked the same way, reported
    ArgCount=1 / Args=sbom; (3) most damningly, the leftover "sca" token
    didn't just vanish - it landed POSITIONALLY on the next unbound
    parameter in declaration order, $ImageTag (since -ImageTag was never
    given a value on the command line), silently overriding the real
    "vendor-audit-toolbox:latest" default with "sca" - which is exactly why
    the SAME run's sbom step failed with "Unable to find image 'sca:latest'
    locally" / "pull access denied for sca, repository does not exist".
    A comma-separated -Steps sbom,sca invoked the SAME way (via -File) fails
    differently but just as silently-wrong: PowerShell's own comma-as-array-
    literal parsing only applies when the PowerShell language parser itself
    sees the call site (an interactive prompt, or a script calling another
    script directly) - a -File invocation hands the child process's argument
    list to it as literal OS strings, so "sbom,sca" arrives as one single
    string that matches no step name and throws "No matching steps".
    FIXED here three ways, each independently confirmed against a real
    PowerShell parser/binder in a local sandbox before being shipped (NOT
    guesswork - a naive first attempt at fix (2) below, using ONLY
    ValueFromRemainingArguments with no other change, was tried and
    empirically DISPROVEN: PowerShell's parameter binder never revisits a
    parameter once it has been bound by name - `-Steps sbom` claims $Steps
    the moment "sbom" binds to it, so a later loose "sca" token is never
    reconsidered for $Steps regardless of ValueFromRemainingArguments; this
    is a hard PowerShell binder limitation, not something fixable by
    attribute alone):
      (1) $Steps now splits any element that itself contains a comma
          (`$Steps = @($Steps | ForEach-Object { $_ -split "," } | ...)`,
          right after parameter resolution). This is what actually fixes
          the -File-plus-comma case: "sbom,sca" arrives as a single
          one-element array under -File, and this line splits it into
          ["sbom", "sca"] regardless of which invocation style produced it -
          confirmed live in a local sandbox both via `-File` and via direct/
          `-Command` invocation, both now correctly select and attempt both
          steps.
      (2) $ImageTag, $Steps' own declaration order relative to $ImageTag,
          and the script's [CmdletBinding()] no longer matter for safety
          the way they used to: [CmdletBinding(PositionalBinding = $false)]
          is now set, with RepoPath/EvidencePath given explicit
          [Parameter(Position=0)]/[Parameter(Position=1)] (so those two
          still work unnamed if ever called that way) and $Steps given
          [Parameter(Position=2, ValueFromRemainingArguments=$true)].
          $ImageTag deliberately keeps NO position at all now, so it can
          NEVER again be positionally auto-assigned from a stray unnamed
          token - confirmed live: a space-separated `-Steps sbom sca` (which
          still can't produce a 2-element array, per the hard binder
          limitation in the note above) now fails LOUDLY with PowerShell's
          own "A positional parameter cannot be found that accepts argument
          'sca'" error, instead of silently overwriting $ImageTag with
          "sca" and only surfacing as a confusing docker-pull failure
          several steps later. This is a safety net, not a way to make
          space-separated -Steps work - it can't be made to work from
          inside the script; always use a comma, never a space, for more
          than one -Steps value (fix (1) above then makes the comma work
          reliably under EITHER invocation style).
      (3) A diagnostic line is printed immediately after parameter/-Steps
          resolution, stating exactly what RepoPath/EvidencePath/ImageTag/
          Steps this run actually resolved to - so a future mis-binding (of
          any kind, in any invocation style) is visible in the first few
          lines of output instead of surfacing many minutes later as a
          cryptic docker-level error far from its real cause.
    Bottom-line guidance: always separate multiple -Steps values with a
    comma (`-Steps sbom,sca`), never a space - this now works correctly
    whether you call the script directly or wrap it in
    `powershell -NoProfile -File ...`.

    2026-09-10 remediation note (dockerfile-lint root-caused live against
    fsh-server): a fifth confirmed instance of the same PowerShell-to-
    docker.exe argv-marshalling bug class that already hit joern-parse,
    ast-grep-scan, and sast-php (see those steps' own Notes). dockerfile-lint's
    old inline `bash -lc "<compound string>"` Cmd - a
    `while IFS= read -r -d "" f; do ... done < <(find ... -print0)` pipeline
    with an embedded empty-string delimiter (`-d ""`) - produced a truncated/
    corrupted fragment in bash (observed: "unexpected EOF while looking for
    matching `"'" / "syntax error: unexpected end of file"), not any error
    the script's own logic would produce. Fixed the same way as every prior
    instance: moved into a static script baked into the image
    (run-dockerfile-lint.sh) and invoked via a two-literal-element Cmd array
    (no string concatenation, no shell re-parsing in the PowerShell-to-
    docker.exe path). See the dockerfile-lint step's own Note below.

.PARAMETER RepoPath
    Path to the vendor repository checkout to scan (a full git clone, not a
    zip export, if you want gitleaks to see history).

.PARAMETER EvidencePath
    Output directory for all tool evidence. Created if it doesn't exist.

.PARAMETER ImageTag
    Toolbox image tag to run. Defaults to vendor-audit-toolbox:latest - build
    it first with Build-AuditToolbox.ps1.

.PARAMETER Steps
    Optional list of step names to run instead of everything (see the $steps
    table in this script for names). Useful for re-running one tool after
    fixing a flag. If you use -Steps and want a shareable evidence copy,
    include 'evidence-scrub' explicitly - it does not run implicitly when
    -Steps is set to anything else.

    ALWAYS separate multiple step names with a comma (-Steps sbom,sca),
    NEVER a space (-Steps sbom sca does not work and, as of 2026-09-04, now
    fails loudly instead of silently corrupting -ImageTag - see the
    top-level 2026-09-04 remediation note for the real incident that
    surfaced this and why it can't be fixed to accept spaces). The
    comma-separated form now works correctly whether you call this script
    directly or wrap it in `powershell -NoProfile -File ...` - previously
    the -File wrapper broke comma-separated -Steps too (see the same note).

.PARAMETER SkipDockerCheck
    Skip the up-front `docker info` reachability check.

.PARAMETER CleanEvidence
    2026-09-02: wipe EvidencePath's entire contents before running (a real
    "start completely clean" reset), rather than the default behavior below
    of only clearing each selected step's own output file right before that
    step runs. Use this when you want a genuinely fresh full run and don't
    care about anything currently in EvidencePath - it deletes MANIFEST.json
    and every step's evidence, not just the ones you're about to re-run.
    Combining -CleanEvidence with a narrow -Steps list that has a DependsOn
    on a step NOT in that list (e.g. -Steps semantic-index alone) will wipe
    that dependency's evidence too and cause the step to be skipped - if you
    want a clean run of just part of the pipeline, either don't use
    -CleanEvidence, or include the full dependency chain in -Steps.

.EXAMPLE
    ./Invoke-VendorAuditPrePass.ps1 -RepoPath C:\vendor\game-client -EvidencePath C:\audit\evidence

.EXAMPLE
    ./Invoke-VendorAuditPrePass.ps1 -RepoPath ./repo -EvidencePath ./evidence -Steps cloc,secrets,symbol-index

.EXAMPLE
    ./Invoke-VendorAuditPrePass.ps1 -RepoPath ./repo -EvidencePath ./evidence -CleanEvidence
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$RepoPath,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$EvidencePath,

    [string]$ImageTag = "vendor-audit-toolbox:latest",

    # 2026-09-04 fix: ValueFromRemainingArguments means any leftover/
    # unbound command-line token (e.g. a space-separated -Steps value that
    # -File orchestration would otherwise misbind positionally onto the
    # NEXT declared parameter - confirmed live to silently land on
    # $ImageTag and poison it to "sca", causing an unrelated step's docker
    # pull to fail) is appended to $Steps instead. See the top-level
    # .DESCRIPTION's 2026-09-04 remediation note for the full incident this
    # closes.
    [Parameter(Position = 2, ValueFromRemainingArguments = $true)]
    [string[]]$Steps,

    [switch]$SkipDockerCheck,

    [switch]$CleanEvidence
)

$ErrorActionPreference = "Stop"

$RepoPath = (Resolve-Path $RepoPath).ProviderPath
New-Item -ItemType Directory -Force -Path $EvidencePath | Out-Null
$EvidencePath = (Resolve-Path $EvidencePath).ProviderPath

# 2026-09-04 fix: split any -Steps element that itself contains a comma.
# Confirmed live and then independently confirmed in a local sandbox with a
# real PowerShell 7 parser/binder (not guesswork): `-Steps sbom,sca` invoked
# via `powershell -File <script> ...` arrives here as a ONE-element array
# containing the single literal string "sbom,sca" - the comma is never
# treated as the array-literal operator the way it would be for a DIRECT
# script invocation (`.\script.ps1 -Steps sbom,sca` typed at a prompt, or
# one script calling another), because -File hands the child process its
# arguments as literal OS strings, not as PowerShell source to be parsed.
# Rather than tell every caller to remember never to use -File (easy to
# forget, and not always avoidable - e.g. from a scheduled task), split any
# comma-containing element here so both invocation styles land on the same
# correctly-split array. This does NOT help space-separated multiple values
# (`-Steps sbom sca` with no comma) - that failure mode is a genuinely
# different, deeper PowerShell parameter-binding limitation (see the
# ValueFromRemainingArguments/Position comments on the $Steps parameter
# declaration above) that cannot be worked around from inside the script;
# always use a comma, never a space, to pass more than one -Steps value.
if ($Steps) {
    $Steps = @(
        $Steps |
            ForEach-Object { $_ -split "," } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ }
    )
}

# 2026-09-04 fix: print exactly what this run resolved RepoPath/EvidencePath/
# ImageTag/Steps to, immediately after parameter binding, before anything
# else happens. This is deliberately cheap and boring - its entire purpose
# is to make any FUTURE parameter mis-binding (of any kind, from any
# invocation style) visible in the first few lines of console output,
# instead of surfacing many minutes later as a confusing docker-level error
# far from its real cause (confirmed live: a silently-poisoned $ImageTag of
# "sca" only became visible via a "pull access denied for sca, repository
# does not exist" error during the sbom step, several steps and several
# minutes away from where the actual mis-binding happened).
Write-Host "Resolved parameters for this run:" -ForegroundColor DarkCyan
Write-Host "    RepoPath      = $RepoPath" -ForegroundColor DarkCyan
Write-Host "    EvidencePath  = $EvidencePath" -ForegroundColor DarkCyan
Write-Host "    ImageTag      = $ImageTag" -ForegroundColor DarkCyan
Write-Host "    Steps         = $(if ($Steps) { $Steps -join ', ' } else { '(all)' })" -ForegroundColor DarkCyan

if ($CleanEvidence) {
    $existing = Get-ChildItem -Path $EvidencePath -Force -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warning "-CleanEvidence: deleting everything currently under $EvidencePath before this run (MANIFEST.json and all prior step evidence)."
        $existing | Remove-Item -Recurse -Force
    }
}

if (-not $SkipDockerCheck) {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon not reachable. Start Docker Desktop (or your Docker host) and retry, or pass -SkipDockerCheck if you know what you're doing."
    }
}

function New-EvidenceDir([string]$Sub) {
    $p = Join-Path $EvidencePath $Sub
    New-Item -ItemType Directory -Force -Path $p | Out-Null
    return $p
}

# Common mount args: repo read-only at /workspace, evidence read-write at /evidence.
# Steps normally run against our own toolbox image ($ImageTag), but a step can
# set its own Image property (e.g. ScanCode's official image, pulled fresh
# from its own registry rather than baked into the toolbox - see the
# Dockerfile's "NOT included" note for why) to run against a different image
# instead.
function Get-BaseDockerArgs([string]$Image = $ImageTag) {
    $envArgs = @("-e", "HOME=/tmp")
    foreach ($name in @("SEMANTIC_INDEX_BATCH_SIZE", "SEMANTIC_INDEX_SLICE_LIMIT", "SEMANTIC_INDEX_START", "SEMANTIC_INDEX_MODEL", "SEMANTIC_INDEX_TABLE")) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $envArgs += @("-e", "$name=$value")
        }
    }
    return @("run", "--rm") + $envArgs + @(
        "-v", "${RepoPath}:/workspace:ro",
        "-v", "${EvidencePath}:/evidence",
        $Image
    )
}

# Exit codes that mean "the shell itself never got the tool to run" (bash
# syntax error, exec permission denied, command not found). No tool in this
# pipeline legitimately uses these to mean "ran fine, found something" - so
# unlike other non-zero exits, these are NEVER forgiven by AllowNonZeroExit.
# A step can opt out via AllowShellFatalExit if it ever has a real reason to
# (none currently do).
$script:ShellFatalExitCodes = @(2, 126, 127)

# 2026-09-02 fix: an exit code above 128 means the process was terminated by
# a signal (128 + signal number - 137 = SIGKILL, 139 = SIGSEGV, 143 =
# SIGTERM, etc.), never a tool's own "ran fine, found something" exit code.
# Confirmed live: sast-multi-semgrep exited 137 (almost certainly OOM-killed
# partway through a real scan) and, under the old formula, AllowNonZeroExit
# forgave it exactly like it forgave 2/126/127 before that fix - so a run
# that got killed mid-scan still reported treatedOk=true. Same
# AllowShellFatalExit opt-out applies (none currently use it).
function Test-IsSignalKillExitCode([int]$ExitCode) {
    return ($ExitCode -gt 128) -and ($ExitCode -le 192)
}

# One step = one tool invocation. `Cmd` is the argv passed to the container
# (after `docker run --rm -v ... image`); tools that write their own output
# file are told to write directly under /evidence/<...> (preferred - avoids
# PowerShell stdout redirection/encoding pitfalls). Tools that only support
# stdout use `CaptureStdout` and get redirected to `OutFile` by this script.
#
# ExpectedOutput / ExpectedOutputAny (2026-09-02): path(s), relative to
# EvidencePath, that must exist and be non-empty (>0 bytes) for the step to
# be treatedOk. ExpectedOutput is a single required path; ExpectedOutputAny
# is a list where any ONE existing+non-empty path satisfies the check (for
# steps with multiple legitimate output shapes, e.g. ast-grep-scan writes
# either ast-grep.json or ast-grep-usage.txt depending on whether the repo
# has ast-grep rules). Omit both to skip the output-sanity check entirely
# (used only for steps with no single reliable output artifact to point at).
#
# PostSuccessFile / PostSuccessText (2026-09-03): for steps that used to
# echo a static usage-note string from inside their bash -c command (fragile
# - see joern-parse's Note below for why), declare these two instead and the
# main step-execution loop will write PostSuccessText directly to
# PostSuccessFile (relative to EvidencePath, LF-only) via .NET file I/O,
# but only after the step's own success (treatedOk) is confirmed. This never
# touches a shell's argv, so it sidesteps bash-quoting AND PowerShell
# native-argv marshalling entirely for text that never needed to go through
# either.
$allSteps = @(
    [PSCustomObject]@{
        Name = "cloc"
        EvidenceSubdir = "cloc"
        Cmd = @("cloc", "/workspace", "--json", "--out=/evidence/cloc/cloc.json",
                "--exclude-dir=.git,node_modules,vendor,bin,obj,.terraform,Library,Temp")
        CaptureStdout = $false
        ExpectedOutput = "cloc/cloc.json"
    },
    [PSCustomObject]@{
        Name = "scc"
        EvidenceSubdir = "cloc"
        Cmd = @("scc", "/workspace", "--format", "json", "--output", "/evidence/cloc/scc.json")
        CaptureStdout = $false
        ExpectedOutput = "cloc/scc.json"
    },
    [PSCustomObject]@{
        Name = "secrets"
        EvidenceSubdir = "secrets"
        Cmd = @("gitleaks", "detect", "--source=/workspace", "--report-format=json",
                "--report-path=/evidence/secrets/gitleaks.json", "--redact")
        CaptureStdout = $false
        # gitleaks exits non-zero when it finds leaks - that is success for us,
        # not a failure. Handled below via AllowNonZeroExit.
        AllowNonZeroExit = $true
        ExpectedOutput = "secrets/gitleaks.json"
    },
    [PSCustomObject]@{
        Name = "secrets-binary"
        EvidenceSubdir = "secrets"
        Cmd = @("bash", "-lc",
                'out=/evidence/secrets/binary-cert-inventory.txt; : > "$out"; ' +
                'echo "=== .p12 / .pfx / .jks / .keystore files ===" >> "$out"; ' +
                'find /workspace -type f \( -iname "*.p12" -o -iname "*.pfx" -o -iname "*.jks" -o -iname "*.keystore" \) >> "$out" 2>/dev/null; ' +
                'echo "" >> "$out"; ' +
                'echo "=== text/PEM files containing a private-key header ===" >> "$out"; ' +
                'grep -rl -I -E "BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY" /workspace >> "$out" 2>/dev/null; ' +
                'true')
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "secrets/binary-cert-inventory.txt"
        Note = "S7-1 fix (2026-09-01 adversarial process review): gitleaks is text/regex-only and cannot inspect binary credential stores - the real iOS signing certs in fsh-client were found by hand, not by any scanner, before this step existed. This is an inventory pass (find-by-extension + PEM-header grep), not a decrypt/crack attempt - anything it lists still needs the same manual validity/rotation review the original .p12 finding got. A file it doesn't list because it's encoded/obfuscated in some other way is still possible; this closes the known blind spot, not every conceivable one."
    },
    [PSCustomObject]@{
        Name = "sbom"
        EvidenceSubdir = "sbom"
        # 2026-09-08 fix (confirmed live against fsh-server, real 531-package
        # scan): this step's bare `cyclonedx-json=...` output defaults to
        # syft's newest supported CycloneDX spec version - confirmed live
        # that syft 1.51.1 in this image defaults to specVersion 1.7. The
        # sca step's osv-scanner (v1.9.2 in this image) rejects that outright
        # with "invalid specification version" (see sca's own long Note
        # below for the full root-cause chain) - v1.9.2 predates CycloneDX
        # 1.7 and only understands older spec versions (its own --format
        # list for OUTPUT only goes up to cyclonedx-1-5, a strong hint about
        # what its INPUT parser accepts too). Confirmed live, with a real
        # throwaway test file and a real osv-scanner run against it, that
        # pinning to `cyclonedx-json@1.5` produces a file osv-scanner parses
        # successfully (531 packages scanned, no errors). Syft's own --help
        # documents this `@<version>` suffix for SPDX formats explicitly
        # (`spdx-json@2.2`) and it was confirmed live to work identically
        # for cyclonedx-json even though the --help text doesn't spell out
        # an example for it. If a future osv-scanner upgrade supports newer
        # CycloneDX versions, this pin can be loosened - don't remove it
        # without re-confirming osv-scanner's real --help output first, the
        # same way this fix was derived.
        Cmd = @("syft", "dir:/workspace", "-o", "cyclonedx-json@1.5=/evidence/sbom/sbom.cdx.json")
        CaptureStdout = $false
        ExpectedOutput = "sbom/sbom.cdx.json"
        Note = "2026-09-08: pinned to CycloneDX spec version 1.5 (via syft's @<version> output-format suffix) because this image's osv-scanner (v1.9.2) cannot parse the newer CycloneDX 1.7 that syft would otherwise default to - confirmed live via a real, successful 531-package osv-scanner run against a 1.5-pinned SBOM. See sca's Note for the full root-cause chain that led here."
    },
    [PSCustomObject]@{
        Name = "sca"
        EvidenceSubdir = "sca"
        # 2026-09-04 fix (confirmed live against fsh-server): the 2026-09-02
        # Note below correctly predicted "an osv-scanner CLI flag change" as
        # one of the two likely causes of the instant exit-128 failure - and
        # that's exactly what this was, confirmed by getting a real,
        # non-corrupted run (after the separate -Steps/$ImageTag bug above
        # was fixed) and reading its real sca.stderr.log for the first time:
        #   "Failed to parse SBOM using all supported formats: ... No
        #   package sources found, --help for usage information."
        # The SBOM file itself was fine (a real, valid, syft 1.51.1
        # CycloneDX 1.7 document - confirmed by reading its actual header).
        # The real problem: `docker run ... osv-scanner --help` shows this
        # image's osv-scanner (v1.9.2) only exposes `scan`, `fix`, and
        # `help` as top-level COMMANDS - `--sbom` and `--format` are not
        # valid bare global flags anymore (confirmed live: v1.9.2's global
        # options are only --help/--version). The old Cmd called
        # `osv-scanner --sbom=... --format=json` with no `scan` subcommand
        # at all, so osv-scanner never actually read --sbom as an SBOM path
        # - it fell through to a default "no source given" scan attempt,
        # tried to auto-detect a target, and failed to parse anything as
        # any supported format, hence "No package sources found". This is
        # CLI version drift in the underlying tool, not anything wrong with
        # the SBOM or with this script's evidence pipeline. Confirmed the
        # real fix by reading `osv-scanner scan --help` directly (not
        # guessed): scan's options are `--sbom value`, `--format value`
        # (accepts "json" among others), and `--output value` (writes
        # results straight to a file - the same "let the tool write its own
        # output file" pattern already preferred throughout this script,
        # see the top-level comment above $allSteps - so CaptureStdout/
        # OutFile are dropped here in favor of --output, matching how sbom/
        # cloc/etc. already work). Not yet independently re-confirmed with
        # a real run against fsh-server as of this fix - watch
        # sca/sca.stderr.log and sca/osv-scanner.json on the next run.
        Cmd = @("osv-scanner", "scan",
                "--sbom", "/evidence/sbom/sbom.cdx.json",
                "--format", "json",
                "--output", "/evidence/sca/osv-scanner.json")
        CaptureStdout = $false
        AllowNonZeroExit = $true  # osv-scanner exits non-zero when it finds vulnerabilities
        DependsOn = "sbom"
        ExpectedOutput = "sca/osv-scanner.json"
        Note = "2026-09-04: fixed to use osv-scanner's real v1.9.2 CLI shape (`scan --sbom ... --format json --output ...`) after confirming live that the old bare `--sbom=`/`--format=` flags (no `scan` subcommand) are no longer valid - see the long comment above this Note for that part of the root cause. SECOND bug found and fixed 2026-09-08, after the CLI-shape fix above still failed live with 'Failed to parse SBOM using all supported formats ... failed trying json: invalid specification version': osv-scanner v1.9.2 cannot parse the CycloneDX 1.7 that syft defaults to - it only understands older CycloneDX spec versions. Fixed at the SOURCE - see the sbom step's own Note/comment above, which now pins syft's output to CycloneDX 1.5 via the `cyclonedx-json@1.5` output-format suffix. Confirmed live, end to end: a real 1.5-pinned SBOM fed to this exact `osv-scanner scan --sbom ... --format json --output ...` invocation successfully scanned 531 packages with no errors. AllowNonZeroExit stays set since osv-scanner's documented behavior is a non-zero exit when it finds real vulnerabilities - that is success for us, not a failure."
    },
    [PSCustomObject]@{
        Name = "sast-python"
        EvidenceSubdir = "sast-python"
        Cmd = @("bandit", "-r", "/workspace", "-f", "json", "-o", "/evidence/sast-python/bandit.json")
        CaptureStdout = $false
        AllowNonZeroExit = $true  # bandit exits non-zero when findings exist
        ExpectedOutput = "sast-python/bandit.json"
    },
    [PSCustomObject]@{
        Name = "sast-go"
        EvidenceSubdir = "sast-go"
        Cmd = @("gosec", "-fmt=json", "-out=/evidence/sast-go/gosec.json", "/workspace/...")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-go/gosec.json"
    },
    [PSCustomObject]@{
        Name = "sast-cpp"
        EvidenceSubdir = "sast-cpp"
        Cmd = @("cppcheck", "--enable=all", "--inconclusive", "--xml", "--xml-version=2",
                "/workspace")
        CaptureStdout = $true   # cppcheck writes its XML report to stderr, not stdout
        CaptureStderr = $true
        OutFile = "sast-cpp/cppcheck.xml"
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-cpp/cppcheck.xml"
    },
    # 2026-09-02: sast-multi-semgrep SPLIT into one step per ruleset
    # (previously one "semgrep scan" with all 7 --config values at once).
    # History, confirmed live against a real fsh-server run:
    #   1. p/spring (previously in this list) 404s on the registry now and
    #      semgrep treats ANY invalid --config as fatal for the WHOLE
    #      invocation - exit 7 in ~10s, paths.scanned=[]. Fixed by dropping
    #      p/spring (p/java already carries its java.spring.security.* rules,
    #      confirmed by fetching p/java directly - no coverage lost).
    #   2. The combined step had no --exclude list (every other step in this
    #      script has one, e.g. cloc's --exclude-dir=...). Without it,
    #      pysemgrep sat in D (uninterruptible) state for 60+ minutes with
    #      semgrep-core (the real matching engine) at 0:00 CPU time - stuck
    #      walking a huge vendor/node_modules tree over a slow
    #      Docker-Desktop-on-Windows bind mount, never reaching real scanning.
    #   3. Even after adding --exclude and confirming real matching work
    #      started (a semgrep-core worker briefly showed real CPU time),
    #      watching it with Watch-SemgrepProgress.ps1 showed that worker
    #      vanish and never return for 40+ minutes, with only a small,
    #      ambiguous CPU trickle in the parent process and semgrep-core back
    #      at 0:00 - the same stall signature as (2), just triggered later
    #      (most likely re-walking the tree when moving to the next
    #      --config internally). Memory stayed low the whole time
    #      (docker stats), so this isn't simply OOM.
    # Splitting into 7 independent steps - one --config per docker
    # invocation, each writing its own JSON - fixes the diagnosability
    # problem directly: if one specific ruleset is what stalls, you now see
    # exactly which (the others still run/complete via the normal "one step
    # failing doesn't stop the others" behavior), each container's process
    # tree is small enough that `docker exec <id> ps aux` is easy to read,
    # and a stall or crash on one ruleset no longer costs you the other six
    # rulesets' results (the old combined step made the whole thing
    # all-or-nothing). --verbose is also added to every one of these so
    # semgrep actually emits per-file progress to its stderr log instead of
    # going completely silent in non-interactive mode (confirmed live:
    # docker logs on the combined step returned nothing for 59+ minutes
    # despite real activity) - tail <ruleset>.stderr.log with -Wait to watch
    # it live instead of relying on ps aux forensics.
    [PSCustomObject]@{
        Name = "sast-multi-semgrep-owasp"
        EvidenceSubdir = "sast-multi"
        Cmd = @("semgrep", "scan", "--config=p/owasp-top-ten", "--verbose",
                "--exclude=.git", "--exclude=node_modules", "--exclude=vendor",
                "--exclude=bin", "--exclude=obj", "--exclude=.terraform",
                "--exclude=Library", "--exclude=Temp",
                "--json", "--output=/evidence/sast-multi/semgrep-owasp.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-multi/semgrep-owasp.json"
        Note = "Part of the 7-way semgrep split (see the comment block above this step) - broad OWASP Top Ten coverage, language-agnostic. CAUTION: ExpectedOutput only checks the file exists and is non-empty - semgrep writes a small valid JSON file even on a config-resolution failure, complete with an errors[] array and paths.scanned=[]. Always glance at semgrep-owasp.json's own errors[]/paths.scanned before trusting a clean result."
    },
    [PSCustomObject]@{
        Name = "sast-multi-semgrep-csharp"
        EvidenceSubdir = "sast-multi"
        Cmd = @("semgrep", "scan", "--config=p/csharp", "--verbose",
                "--exclude=.git", "--exclude=node_modules", "--exclude=vendor",
                "--exclude=bin", "--exclude=obj", "--exclude=.terraform",
                "--exclude=Library", "--exclude=Temp",
                "--json", "--output=/evidence/sast-multi/semgrep-csharp.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-multi/semgrep-csharp.json"
        Note = "Part of the 7-way semgrep split (see the comment block above sast-multi-semgrep-owasp)."
    },
    [PSCustomObject]@{
        Name = "sast-multi-semgrep-golang"
        EvidenceSubdir = "sast-multi"
        Cmd = @("semgrep", "scan", "--config=p/golang", "--verbose",
                "--exclude=.git", "--exclude=node_modules", "--exclude=vendor",
                "--exclude=bin", "--exclude=obj", "--exclude=.terraform",
                "--exclude=Library", "--exclude=Temp",
                "--json", "--output=/evidence/sast-multi/semgrep-golang.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-multi/semgrep-golang.json"
        Note = "Part of the 7-way semgrep split (see the comment block above sast-multi-semgrep-owasp)."
    },
    [PSCustomObject]@{
        Name = "sast-multi-semgrep-python"
        EvidenceSubdir = "sast-multi"
        Cmd = @("semgrep", "scan", "--config=p/python", "--verbose",
                "--exclude=.git", "--exclude=node_modules", "--exclude=vendor",
                "--exclude=bin", "--exclude=obj", "--exclude=.terraform",
                "--exclude=Library", "--exclude=Temp",
                "--json", "--output=/evidence/sast-multi/semgrep-python.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-multi/semgrep-python.json"
        Note = "Part of the 7-way semgrep split (see the comment block above sast-multi-semgrep-owasp)."
    },
    [PSCustomObject]@{
        Name = "sast-multi-semgrep-php"
        EvidenceSubdir = "sast-multi"
        Cmd = @("semgrep", "scan", "--config=p/php", "--verbose",
                "--exclude=.git", "--exclude=node_modules", "--exclude=vendor",
                "--exclude=bin", "--exclude=obj", "--exclude=.terraform",
                "--exclude=Library", "--exclude=Temp",
                "--json", "--output=/evidence/sast-multi/semgrep-php.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-multi/semgrep-php.json"
        Note = "Part of the 7-way semgrep split (see the comment block above sast-multi-semgrep-owasp). This one specifically is the PRIMARY PHP SAST pass - see sast-php's Note. Semgrep's tree-sitter parser recovers from syntax errors and keeps matching sinks in files that don't fully parse (verified: it still matched a mysql_query() sink in a PHP file with a PHP8-illegal curly-brace offset, where PHPStan hard-errored and skipped the file entirely) - treat this ruleset's findings as authoritative and psalm/phpstan/phpcs as supplementary."
    },
    [PSCustomObject]@{
        Name = "sast-multi-semgrep-java"
        EvidenceSubdir = "sast-multi"
        Cmd = @("semgrep", "scan", "--config=p/java", "--verbose",
                "--exclude=.git", "--exclude=node_modules", "--exclude=vendor",
                "--exclude=bin", "--exclude=obj", "--exclude=.terraform",
                "--exclude=Library", "--exclude=Temp",
                "--json", "--output=/evidence/sast-multi/semgrep-java.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-multi/semgrep-java.json"
        Note = "Part of the 7-way semgrep split (see the comment block above sast-multi-semgrep-owasp). Also carries the Spring-specific rules (java.spring.security.* - injection/tainted-URL/SQLi) that used to live in the now-404ing p/spring config - confirmed by fetching p/java directly."
    },
    [PSCustomObject]@{
        Name = "sast-multi-semgrep-security-audit"
        EvidenceSubdir = "sast-multi"
        Cmd = @("semgrep", "scan", "--config=p/security-audit", "--verbose",
                "--exclude=.git", "--exclude=node_modules", "--exclude=vendor",
                "--exclude=bin", "--exclude=obj", "--exclude=.terraform",
                "--exclude=Library", "--exclude=Temp",
                "--json", "--output=/evidence/sast-multi/semgrep-security-audit.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-multi/semgrep-security-audit.json"
        Note = "Part of the 7-way semgrep split (see the comment block above sast-multi-semgrep-owasp). Added 2026-09-01 (finding S1-3) - the playbook's PHP-security-coverage reasoning already assumed this ruleset was running; it wasn't, until this was added."
    },
    [PSCustomObject]@{
        Name = "sast-php"
        EvidenceSubdir = "sast-php"
        # 2026-09-08 fix (confirmed live against a real container's own
        # sast-php.stderr.log, not guessed): this step's Cmd used to be
        # @("bash", "-lc", "<compound string built via PowerShell '+'
        # concatenation>") - the EXACT same shape that already caused two
        # separate, hard-to-reproduce failures elsewhere in this toolbox
        # (joern-parse and ast-grep-scan - see those steps' own long
        # 2026-09-03/04 comments, and process-review-2026-09-03-semgrep-
        # manual-run-lessons.md Addendum 4's "generalizable lesson"). This
        # step was never revisited with that same architectural fix until
        # now. Separately and more concretely, the real, confirmed bug
        # breaking this step was psalm itself: it hard-requires a config
        # file in the analyzed project and refuses to run at all without one
        # ("Could not locate a config XML file in path /workspace. Have you
        # run 'psalm init' ?") - and /workspace is bind-mounted read-only
        # (see Get-BaseDockerArgs above), so psalm's own init step could
        # never write one there even as a first pass. Both are fixed
        # together: the three-tool logic now lives in a static script baked
        # into the image (run-sast-php.sh, see the Dockerfile) instead of a
        # runtime PowerShell-concatenated string, and that script points
        # psalm at a minimal static psalm.xml also baked into the image
        # (/opt/config/psalm.xml). Cmd is now just two literal array
        # elements - no string concatenation, no shell re-parsing anywhere
        # in the PowerShell-to-docker.exe path.
        Cmd = @("bash", "/opt/scripts/run-sast-php.sh")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutputAny = @("sast-php/psalm.json", "sast-php/phpstan.json", "sast-php/phpcs.json")
        Note = "SECONDARY PHP pass only (finding S6-1, 2026-09-01 adversarial process review) - do not treat a clean/empty result from this step alone as 'PHP is clean'. Verified live: PHPStan hard-errors on PHP 5-era syntax removed by PHP 8 (e.g. a curly-brace string offset) with 'Result is incomplete because of severe errors' and never analyzes that file's real content - a count-only read of phpstan.json sees '1 error', not 'this file was never analyzed'. Psalm keeps going on other files but drops the broken file's own findings. Cross-check every file here against sast-php-parse-coverage's parse-coverage.json (independent php -l check) before trusting a 0-finding file as analyzed, and treat sast-multi-semgrep's p/php + p/security-audit findings as the primary PHP signal, not this step. ExpectedOutputAny only confirms at least one of the three sub-tools produced something - a single sub-tool crashing silently is still possible without this step reporting a problem; check all three files' sizes by hand periodically, not just after a failure. 2026-09-08: psalm's config-file requirement (see the fix comment above this Note) is exactly the kind of silent-per-sub-tool failure this caution already warned about - it was invisible from the exit code/ExpectedOutputAny check alone and only surfaced by reading the real stderr log."
    },
    [PSCustomObject]@{
        Name = "sast-php-parse-coverage"
        EvidenceSubdir = "sast-php"
        Cmd = @("python3", "/opt/scripts/php_parse_coverage.py", "/workspace", "-o", "/evidence/sast-php/parse-coverage.json")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-php/parse-coverage.json"
        Note = "S6-1 fix: independent of Psalm/PHPStan/PHPCS entirely - runs php -l (the interpreter's own syntax check) against every .php file and records NOT_ANALYZED for anything that fails to parse under this container's PHP version. This is the ledger sast-php's Note tells you to cross-check against."
    },
    [PSCustomObject]@{
        Name = "iac"
        EvidenceSubdir = "iac"
        # 2026-09-17: split out of the vendor-audit-toolbox omnibus image into
        # its own audit-iac image (MIGRATION.md item 7) — checkov/tfsec/trivy
        # config now live there, not in $ImageTag.
        Image = "audit-iac:local"
        Cmd = @("bash", "-lc",
                "checkov -d /workspace -o json --output-file-path /evidence/iac/ 2>/evidence/iac/checkov.stderr.log || true; " +
                "tfsec /workspace --format json --out /evidence/iac/tfsec.json || true; " +
                "trivy config --format json --output /evidence/iac/trivy-config.json /workspace || true")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutputAny = @("iac/trivy-config.json", "iac/tfsec.json", "iac/results_json.json")
        Note = "tfsec is upstream-deprecated in favor of Trivy (confirmed during the 2026-09-01 review) - it's left running here for now since it's already wired up and free to keep, but trivy config is the actively-maintained tool this step should be considered to depend on going forward; don't add new IaC coverage to tfsec specifically."
    },
    [PSCustomObject]@{
        Name = "weggli-note"
        EvidenceSubdir = "sast-cpp"
        # 2026-09-02 fix: the previous version of this string tried to nest
        # \'...\' inside a PowerShell double-quoted string to get a literal
        # single-quote into bash - that fails twice over (bash single-quotes
        # can't be escaped with backslash at all, and PowerShell interpolates
        # \$buf before bash ever sees it, since \ is not PowerShell's escape
        # char). Reworded to avoid embedded quotes/dollars entirely instead
        # of fighting the escaping rules - same fix already verified in
        # fix-quote-escaping-v2.ps1. NOTE (2026-09-03): joern-parse's Cmd used
        # this same "compound bash -c string" shape and turned out to have a
        # second, deeper problem beyond quoting (see joern-parse's own Note) -
        # this step has not been independently re-tested with that same
        # rigor; it's short and quote-free so lower-risk, but still unverified.
        Cmd = @("bash", "-lc",
                "echo 'weggli is installed for interactive semantic C/C++ pattern search - example: weggli PATTERN /workspace, where PATTERN is a weggli query such as a memcpy-into-undersized-buffer match. Run it manually per Phase 4B hypothesis, it is not a one-shot batch scanner like the others in this pass.' > /evidence/sast-cpp/weggli-usage.txt")
        CaptureStdout = $false
        ExpectedOutput = "sast-cpp/weggli-usage.txt"
    },
    $(if ((Test-Path (Join-Path $RepoPath "sgconfig.yml") -PathType Leaf) -or (Test-Path (Join-Path $RepoPath ".ast-grep") -PathType Container)) {
        # 2026-09-04 refactor: this step used to be a single "bash", "-lc",
        # "<if/else string built via PowerShell '+' concatenation>" Cmd - the
        # EXACT same shape that turned out to be the real bug behind
        # joern-parse's vendor-exclusion failure (see that step's own long
        # 2026-09-04 comment): a compound string assembled by PowerShell-side
        # "+" concatenation does not reliably survive `& docker @dockerArgs`
        # array-splatting from -File orchestration, even when byte-identical
        # to a string that works fine typed interactively. Rather than wait
        # for this step to fail the same way and re-litigate it, the branch
        # is moved out of bash and into PowerShell entirely: since /workspace
        # is just the bind-mounted $RepoPath, PowerShell can check for
        # sgconfig.yml / .ast-grep directly on the host, before docker is
        # ever invoked, and pick one of two fully shell-free Cmd arrays. No
        # bash, no -lc, no string concatenation, no quoting to get wrong.
        [PSCustomObject]@{
            Name = "ast-grep-scan"
            EvidenceSubdir = "structural-search"
            Cmd = @("ast-grep", "scan", "--json")
            CaptureStdout = $true
            OutFile = "structural-search/ast-grep.json"
            AllowNonZeroExit = $true
            ExpectedOutput = "structural-search/ast-grep.json"
            Note = "sgconfig.yml or .ast-grep/ found in the repo checkout - running ast-grep in batch (rule-driven) mode. Independently confirmed live 2026-09-04 that the no-op branch (below) and its ExpectedOutputAny/PostSuccessFile ordering fix both work correctly end-to-end; this rule-driven branch itself has not yet had its own live confirmation run against a repo that actually has sgconfig.yml/.ast-grep present - watch ast-grep-scan.stderr.log on first run."
        }
    } else {
        [PSCustomObject]@{
            Name = "ast-grep-scan"
            EvidenceSubdir = "structural-search"
            # 2026-09-04 fix (confirmed live): ExpectedOutputAny here originally
            # included "structural-search/ast-grep-usage.txt" - but that's the
            # exact file PostSuccessFile writes AFTER $ok is computed. $ok =
            # $exitOk -and $outputOk, and $outputOk is evaluated from
            # ExpectedOutputAny BEFORE PostSuccessFile ever runs - so the check
            # saw the file didn't exist yet, set outputOk=$false, $ok=$false,
            # and the PostSuccessFile write (gated on $ok) never fired. A real
            # chicken-and-egg deadlock, caught live: exit 0, but the usage note
            # was never written and the step got flagged as needing a look.
            # Fix: no ExpectedOutput/ExpectedOutputAny at all for this branch -
            # exit code from `true` is the only meaningful success signal for
            # an intentional no-op, exactly how joern-parse's PostSuccessFile
            # (a different file than its own ExpectedOutput) already worked
            # correctly without this trap.
            Cmd = @("true")
            AllowNonZeroExit = $true
            PostSuccessFile = "structural-search/ast-grep-usage.txt"
            PostSuccessText = "No ast-grep rule config found at $RepoPath\sgconfig.yml (or a .ast-grep\ directory) - ast-grep scan needs rules to run in batch mode. Use ast-grep run -p PATTERN -l LANG interactively per Phase 4B/1B hypothesis instead - example: docker run --rm -v REPO:/workspace:ro IMAGE ast-grep run -p OBJ.METHOD(ARG) -l php /workspace. See the playbook Phase 0A notes."
            Note = "No sgconfig.yml/.ast-grep found in the repo checkout as of this run - batch mode has nothing to run, so this step just runs a no-op ('true') inside the container (to prove the image/mount are reachable) and writes the usage note directly via PowerShell, never through bash string concatenation. ast-grep's real value here is interactive, hypothesis-driven queries, same as weggli. Independently confirmed live 2026-09-04 against the real fsh-server repo: exit 0, done in 1.2s, ast-grep-usage.txt written cleanly (372 bytes), ast-grep-scan.stderr.log at 0 bytes as expected - the ExpectedOutputAny/PostSuccessFile ordering deadlock described above is confirmed genuinely fixed, not just in local sandbox testing."
        }
    })
    [PSCustomObject]@{
        Name = "joern-parse"
        EvidenceSubdir = "joern"
        # 2026-09-03 fix (confirmed live against fsh-server): two stacked bugs here.
        # (1) 2026-09-02's apostrophe fix ("handle_packet's buffer" -> "the handle_packet
        #     buffer") was necessary but not sufficient. Even after that fix, this step's
        #     compound `joern-parse ... && echo '...' > README.txt` string, run through
        #     PowerShell's native-argv marshalling to docker.exe, produced INCONSISTENT
        #     failures depending on invocation context: "syntax error: unexpected end of
        #     file" (exit 2) when run via `-File` orchestration, vs. "joern-parse: command
        #     not found" (exit 127) when the exact same string was reconstructed and run
        #     interactively with the same volume mounts. The string itself was confirmed
        #     byte-clean three independent ways (a hex dump of the actual file on disk, an
        #     interactive reconstruction with a length/non-ASCII character check, and a
        #     direct diff against the live file's raw bytes) - this was a PowerShell/
        #     native-argv marshalling problem, not a bash-quoting wording problem, and the
        #     exact mechanism was not fully root-caused (chasing it further had
        #     diminishing returns once the fix below made it moot).
        # (2) Separately and more concretely: joern-parse is NOT on PATH in this image at
        #     all - confirmed live via `command -v joern-parse` (finds nothing) and a
        #     filesystem search (`find / -iname 'joern*'`), which located the real binary
        #     at /opt/joern/joern-cli/joern-parse (also present under
        #     /opt/joern/joern-cli/bin/joern-parse). Every run above would have hit this
        #     next regardless of (1) once the marshalling problem was worked around.
        # (3) A third bug, only visible once (1) and (2) were fixed (a syntax error is
        #     caught at bash's PARSE stage, before any redirect is ever opened, so this
        #     was invisible until the command actually got that far): pointing the
        #     tool's own inner stderr redirect at a DIFFERENT bind-mounted file
        #     (joern-parse-tool.stderr.log) than the orchestrator's own per-step capture
        #     (joern-parse.stderr.log) avoided the earlier Permission-denied collision,
        #     but surfaced (4) below.
        # (4) A fourth bug, confirmed live and conclusively: reading
        #     /evidence/joern/joern-parse-tool.stderr.log (a file WRITTEN FROM INSIDE
        #     THE CONTAINER, across the Docker Desktop bind mount between its Linux VM
        #     and the Windows host filesystem) immediately after the step completed
        #     returned STALE content - proven by bracketing a real run with `Get-Date`
        #     (18 real minutes elapsed) while the "fresh" log still showed a timestamp
        #     over 13 hours old, down to the millisecond, which is not possible for two
        #     independent JVM runs by chance. The orchestrator's OWN outer capture
        #     (docker.exe's real stdout/stderr, piped live to PowerShell and written
        #     directly to NTFS - no bind-mount write-back involved) never showed this
        #     problem. Root cause: Windows Docker Desktop's container-to-host bind-mount
        #     write-back path (gRPC-FUSE/VirtioFS) is a known trouble spot for read-after-
        #     write staleness; the outer docker-stream capture path doesn't go through it
        #     at all. Fixed by dropping the inner stderr redirect entirely - joern-parse's
        #     real stderr (including the Java stack trace on failure) now flows through
        #     the container's actual stderr stream and lands in the orchestrator's own
        #     joern-parse.stderr.log, the same reliable path already used for every other
        #     step in this script. One cosmetic side effect: because PowerShell wraps a
        #     redirected native command's stderr lines into NativeCommandError-formatted
        #     text (the same mechanism documented in this script's own top-level
        #     .DESCRIPTION for the cloc/"At line:X char:Y" case), a long multi-line Java
        #     stack trace read through this path will look more verbose/framed than a
        #     raw file dump would - still fully readable, just noisier. Worth it to get
        #     real, fresh data instead of silently-stale bind-mount content.
        # Fixed by addressing all four at once: dropped the compound `&&`/echo string
        # entirely (joern-parse now runs ALONE, invoked by its full absolute path rather
        # than relying on PATH - no `&&`, no embedded quotes, no long message text
        # anywhere near a shell's argv), it no longer writes its own stderr to a
        # bind-mounted file at all (avoids both the collision in (3) and the staleness in
        # (4) at once), ExpectedOutput now checks for the real cpg.bin artifact instead of
        # the old usage-note file (more meaningful anyway - it's the actual output the
        # rest of the pipeline needs), and the static usage-note text is written directly
        # by PowerShell (PostSuccessFile/PostSuccessText, LF-only, see the main
        # step-execution loop below) only after joern-parse's own success is confirmed -
        # never touches a shell's argv or a bind-mounted file again.
        # 2026-09-03/04 addendum: c2cpg.sh (the C/C++ frontend joern-parse invokes) ran
        # for real (~14 real minutes) and then failed with a genuine
        # java.lang.OutOfMemoryError: Java heap space while parsing this repo's bundled
        # third-party C/C++ trees - confirmed live via a clean, well-formed JVM stack
        # trace (not an infra/quoting bug - c2cpg.sh auto-sized itself -J-Xmx7984m and it
        # still wasn't enough). A real directory listing (find /workspace -maxdepth 4
        # -iregex '.*/(protobuf.*|lua.*|libcurl.*)' -type d) confirmed THREE separate
        # protobuf trees (not just the one visible in the partial OOM log excerpt) plus
        # two lua and two libcurl trees.
        # FIRST ATTEMPT (failed, confirmed live): passed --exclude flags to joern-parse
        # after a literal "--frontend-args" separator, per joern-parse's own --help text
        # ("Args specified after the --frontend-args separator will be passed to the
        # front-end verbatim"). A fresh, verified-non-stale run (bracketed with Get-Date,
        # confirmed by a UTC-matching timestamp in the resulting log) showed the exact
        # invoked c2cpg.sh command line was STILL "List(/opt/joern/joern-cli/c2cpg.sh,
        # -J-Xmx7984m, /workspace, --output, /evidence/joern/cpg.bin)" - no --exclude
        # values present at all. joern-parse silently swallowed them rather than
        # forwarding them; the --frontend-args separator did not work as its --help text
        # implied (or needs different syntax than tested).
        # FIX: skip joern-parse's wrapper entirely and invoke c2cpg.sh directly, using
        # the exact real invocation shape captured from its own printed log line above
        # (same -J-Xmx7984m heap, same /workspace input, same --output path) plus
        # --exclude flags per c2cpg.sh's OWN --help output (confirmed live: "--exclude
        # <file1> files or folders to exclude during CPG generation, paths relative to
        # <input-dir> or absolute paths" - a real, verified top-level flag, not routed
        # through any wrapper-specific pass-through mechanism). VERIFY after running:
        # calling c2cpg.sh directly means the "List(...)" wrapper line (which came from
        # joern-parse's own ExternalCommand logging, not c2cpg.sh itself) will NOT
        # appear this time - that specific verification method no longer applies.
        # Instead confirm by checking whether any "Failed to process" / OutOfMemoryError
        # line in joern-parse.stderr.log still references a path under
        # Server/config/robot/protobuf, Server/lib/libcurl, Server/lib/libs/libcurl,
        # Server/lib/libs/lua, Server/lib/libs/protobuf, Server/lib/lua++, or
        # Server/lib/protobuf - if one of those seven still shows up, the exclusion did
        # NOT take effect; if it fails on a different, non-excluded file (or succeeds),
        # the exclusion worked. Read from joern-parse.stderr.log (the outer,
        # non-bind-mounted capture) per the (4) fix above, NOT joern-parse-tool.stderr.log
        # (removed, proved unreliable).
        # 2026-09-04 SECOND ATTEMPT (also failed, confirmed live): the bash -lc
        # one-string form above (built via PowerShell "+"-concatenation across
        # several lines) ran for real (~9-14 real minutes, fresh Get-Date-bracketed,
        # non-stale) and still hit java.lang.OutOfMemoryError while parsing
        # Server/lib/protobuf/build/*.pb.cc - one of the seven excluded paths.
        # Root-caused by direct empirical isolation, not guesswork: the exact same
        # arguments (same 7 --exclude values, same -J-Xmx7984m heap, same /workspace
        # input-dir, same repo mounted :ro) were run a second time completely
        # bypassing this orchestrator - typed directly as `docker run --rm -v
        # <repo>:/workspace:ro -v <evidence>:/evidence <image> bash -lc "c2cpg.sh
        # ..."` at the PowerShell prompt - and that manual run SUCCEEDED, producing
        # a real 29,376,161-byte cpg.bin with zero "Failed to process" lines for any
        # of the seven excluded paths. Since the arguments were byte-identical, this
        # is the SAME class of bug as the original apostrophe/452-char-string
        # PowerShell native-argv-marshalling inconsistency documented above (search
        # this file for "produced INCONSISTENT") - a long string built by
        # PowerShell-side "+" concatenation, then passed through `& docker
        # @dockerArgs` array splatting, does not reliably reach bash -lc intact from
        # -File orchestration, even though it is provably byte-identical to a string
        # that works fine when typed interactively.
        # FIX (architectural, not another string-quoting patch): this step never
        # actually needed a shell at all - no &&, no redirects, no pipes - so the
        # whole "bash", "-lc", "<one big string>" wrapper is removed. Each token
        # (including each --exclude value) is now its own literal PowerShell array
        # element, passed straight through to `docker run ... c2cpg.sh <args>` with
        # no intermediate string concatenation or shell re-parsing anywhere. This
        # closes off the entire class of bug that has now hit this one step twice
        # (the original apostrophe issue was the same root cause: a
        # hand-assembled compound string crossing the -File/array-splat boundary).
        Cmd = @(
                "/opt/joern/joern-cli/c2cpg.sh",
                "-J-Xmx7984m",
                "/workspace",
                "--output", "/evidence/joern/cpg.bin",
                "--exclude", "Server/config/robot/protobuf",
                "--exclude", "Server/lib/libcurl",
                "--exclude", "Server/lib/libs/libcurl",
                "--exclude", "Server/lib/libs/lua",
                "--exclude", "Server/lib/libs/protobuf",
                "--exclude", "Server/lib/lua++",
                "--exclude", "Server/lib/protobuf"
        )
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "joern/cpg.bin"
        PostSuccessFile = "joern/README.txt"
        PostSuccessText = "CPG built at /evidence/joern/cpg.bin. Open it interactively: joern --script <your.sc> /evidence/joern/cpg.bin, or joern-parse + joern-export for a queryable graph. Not scripted further here - Joern queries are written per hypothesis (e.g. taint from the handle_packet buffer to memcpy), same discipline as Phase 4B."
        Note = "Builds a Code Property Graph for the whole mounted tree (all languages Joern's fuzzy C/C++ frontend and its Python/Go/PHP frontends can parse - quality varies most for PHP 5). This step can be slow on a large codebase; budget real wall-clock time for it, unlike the rest of this pass. If this step fails, check joern/joern-parse.stderr.log (the orchestrator's own docker-level capture - this now ALSO carries the tool's real stderr, see the 2026-09-03 fix comment above; joern-parse-tool.stderr.log no longer exists, its bind-mount write-back proved unreliable). Independently confirmed live 2026-09-04: exit 0, ~29 real minutes, zero OOM/'Failed to process' lines, a real 29,376,153-byte cpg.bin - the architectural fix (no shell wrapper at all) resolved both the marshalling inconsistency and the exclusion-not-taking-effect OOM."
    },
    [PSCustomObject]@{
        Name = "symbol-index"
        EvidenceSubdir = "symbol-index"
        Cmd = @("python3", "/opt/scripts/build_symbol_index.py", "/workspace", "-o", "/evidence/symbol-index")
        CaptureStdout = $false
        ExpectedOutput = "symbol-index/index.json"
    },
    [PSCustomObject]@{
        Name = "semantic-index"
        EvidenceSubdir = "semantic-index"
        Cmd = @("bash", "/opt/scripts/run-semantic-index-batched.sh", "/workspace", "/evidence/symbol-index", "/evidence/semantic-index")
        CaptureStdout = $false
        DependsOn = "symbol-index"
        ExpectedOutput = "semantic-index/index.json"
        Note = "Needs symbol-index to have run first (reuses its definition boundaries as chunks). Runs build_semantic_index.py through /opt/scripts/run-semantic-index-batched.sh, which defaults to SEMANTIC_INDEX_BATCH_SIZE=1 and SEMANTIC_INDEX_SLICE_LIMIT=0. That means one embedding at a time, written to LanceDB batch-by-batch in one normal process; set SEMANTIC_INDEX_SLICE_LIMIT to a positive integer only if you need fresh process boundaries. Downloads the embedding model on first run - needs the container to have outbound network access; if your build environment is air-gapped, pre-bake the model into the image instead (see the Dockerfile's Python tools comment). This step deliberately does NOT set AllowNonZeroExit - a signal kill such as 137 is treated as a real degraded run."
    },
    [PSCustomObject]@{
        Name = "binskim"
        EvidenceSubdir = "binskim"
        Cmd = @("bash", "-lc",
                "binskim analyze '/workspace/**' --recurse --output /evidence/binskim/binskim.sarif || true")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "binskim/binskim.sarif"
        Note = "Binary hardening checks (ASLR/DEP/stack canaries/strong-naming) - NOT a CVE scanner, complements the SBOM/osv-scanner pass, doesn't replace it. Strongest on PE/Windows binaries; expect it to skip or weakly-analyze ELF/Mach-O. Can be slow across hundreds of native binaries - consider pointing --recurse at a narrower path if this times out. Silent-failure caution: this step ends in `|| true`, so a real crash and 'ran, found nothing' both read as treatedOk from the exit code alone - the ExpectedOutput check confirms binskim.sarif at least exists and has bytes, but still confirm it actually contains a runs[] array, and check binskim.stderr.log, before trusting an empty-looking result."
    },
    [PSCustomObject]@{
        Name = "sast-mobile-android"
        EvidenceSubdir = "sast-mobile"
        Cmd = @("bash", "-lc",
                'files=$(find /workspace \( -iname "*.java" -o -iname "*.kt" \) -type f | wc -l); ' +
                'echo "Android (.java/.kt) source files found under /workspace: $files" > /evidence/sast-mobile/android-coverage.txt; ' +
                'mobsfscan /workspace --type android --sarif -o /evidence/sast-mobile/mobsfscan-android.sarif || true; ' +
                'if [ "$files" -eq 0 ]; then echo "WARNING: zero matching source files - treat mobsfscan-android.sarif as NOT-SCANNED, not clean." >> /evidence/sast-mobile/android-coverage.txt; fi')
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-mobile/android-coverage.txt"
        Note = "S1-1/S1-2 fix (2026-09-01 adversarial process review): the old single sast-mobile step ran mobsfscan --type auto against the whole tree. Verified against mobsfscan v1.0.0 source: --type auto configures Android rules ONLY whenever any Android source exists anywhere in the mounted tree, and never reaches its iOS branch - so on a client that ships to both platforms (fsh-client does), auto silently drops all iOS coverage while the SARIF still looks populated with Android hits. Never use --type auto here again; this step and sast-mobile-ios run each platform explicitly instead. The android-coverage.txt/ios-coverage.txt guard files exist because mobsfscan also exits 0 with 0 findings on a tree with NO matching source at all (S1-2) - indistinguishable from a real clean scan without this check. ExpectedOutput points at the coverage.txt (always written first) rather than the SARIF (guarded by || true) so this step still reports a real failure if the coverage check itself never ran. OPEN ITEM (2026-09-03, unverified): reported that this step's logs came back 0 bytes on stdout and stderr on a real run - ambiguous between a legitimate no-op (no mobile source in this repo) and the step never actually launching. Check this step's own gating/invocation and the real android-coverage.txt content before assuming either."
    },
    [PSCustomObject]@{
        Name = "sast-mobile-ios"
        EvidenceSubdir = "sast-mobile"
        Cmd = @("bash", "-lc",
                'files=$(find /workspace \( -iname "*.swift" -o -iname "*.m" -o -iname "*.mm" \) -type f | wc -l); ' +
                'echo "iOS (.swift/.m/.mm) source files found under /workspace: $files" > /evidence/sast-mobile/ios-coverage.txt; ' +
                'mobsfscan /workspace --type ios --sarif -o /evidence/sast-mobile/mobsfscan-ios.sarif || true; ' +
                'if [ "$files" -eq 0 ]; then echo "WARNING: zero matching source files - treat mobsfscan-ios.sarif as NOT-SCANNED, not clean." >> /evidence/sast-mobile/ios-coverage.txt; fi')
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sast-mobile/ios-coverage.txt"
        Note = "Companion to sast-mobile-android - see that step's Note for why --type auto is unsafe on this target, and for the open 0-byte-logs item that applies here too. Once the real Android/iOS export project paths are confirmed (still an open follow-up per the playbook), narrow -RepoPath to just those paths for a faster, less noisy run of both steps."
    },
    [PSCustomObject]@{
        Name = "spotbugs-note"
        EvidenceSubdir = "sast-java"
        Cmd = @("bash", "-lc",
                "echo 'SpotBugs+FindSecBugs analyze compiled bytecode, not source - they need each Java service to actually mvn/gradle build first (same build-availability risk as CodeQL/C++). Not run automatically here. Where a service builds cleanly: spotbugs -textui -pluginList /opt/spotbugs/plugin/findsecbugs-plugin.jar -output /evidence/sast-java/<service>.spotbugs.txt <path-to-classes-or-jar>. The reliable batch pass for Java in this tool set is the sast-multi-semgrep step (p/java + p/spring), which runs on source directly.' > /evidence/sast-java/spotbugs-usage.txt")
        CaptureStdout = $false
        ExpectedOutput = "sast-java/spotbugs-usage.txt"
    },
    [PSCustomObject]@{
        Name = "iac-k8s"
        EvidenceSubdir = "iac-k8s"
        # 2026-09-17: split out of the vendor-audit-toolbox omnibus image into
        # its own audit-iac image (MIGRATION.md item 7) — kube-linter now
        # lives there, not in $ImageTag.
        Image = "audit-iac:local"
        Cmd = @("bash", "-lc",
                "kube-linter lint /workspace --format json > /evidence/iac-k8s/kube-linter.json 2>/evidence/iac-k8s/kube-linter.stderr.log || true")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "iac-k8s/kube-linter.json"
        Note = "kube-linter - Kubernetes manifests, Helm charts, and Kustomize, actively maintained (stackrox/kube-linter). If the mounted tree has no K8s/Helm content this just produces an (expected) empty/near-empty result - check kube-linter.stderr.log if you're unsure whether it actually found anything to scan. Note the ExpectedOutput check only requires the file to be non-empty; kube-linter can legitimately write a small-but-valid empty-results JSON object, which passes - it's still worth a manual look on a genuinely K8s-heavy repo that comes back with a tiny file. Confirmed live against fsh-server 2026-09-09/10: real run took 467.9s (not a hang - CPU/PIDs stayed non-zero throughout, consistent with kube-linter walking a 19,384-file tree over a Windows-Docker-Desktop bind mount, not a crash) and completed exit 0."
    },
    [PSCustomObject]@{
        Name = "dockerfile-lint"
        EvidenceSubdir = "iac-docker"
        # 2026-09-17: split out of the vendor-audit-toolbox omnibus image into
        # its own audit-container image (MIGRATION.md item 7) — hadolint and
        # run-dockerfile-lint.sh now live there, not in $ImageTag.
        Image = "audit-container:local"
        # 2026-09-10 fix (confirmed live against a real fsh-server run's
        # dockerfile-lint.stderr.log, not guessed): this step's Cmd used to
        # be @("bash", "-lc", "<compound string built via PowerShell '+'
        # concatenation, containing a `while IFS= read -r -d "" f; do ...
        # done < <(find ... -print0)` process-substitution pipeline with an
        # embedded empty-string delimiter>") - the EXACT same shape that
        # already caused failures in joern-parse, ast-grep-scan, and
        # sast-php (see those steps' own Notes). The real, observed failure
        # here was bash receiving a truncated/corrupted fragment of the
        # intended command ("f;: -c: line 1: unexpected EOF while looking
        # for matching `"'" / "line 2: syntax error: unexpected end of
        # file"), not any error the script's own logic would produce -
        # confirmed by reading the real dockerfile-lint.stderr.log from a
        # live run against fsh-server. Fixed the same way as every prior
        # instance of this bug: the whole thing now lives in a static
        # script baked into the image (run-dockerfile-lint.sh, see the
        # Dockerfile) instead of a runtime PowerShell-concatenated string;
        # Cmd is now just two literal array elements - no string
        # concatenation, no shell re-parsing anywhere in the
        # PowerShell-to-docker.exe path. Behavior (walk /workspace for every
        # Dockerfile*, run `hadolint --no-fail` against each, write
        # hadolint.txt) is unchanged from the original inline command;
        # tested against synthetic fixtures (including a path with spaces
        # and the zero-Dockerfile case) before shipping.
        Cmd = @("bash", "/opt/scripts/run-dockerfile-lint.sh")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        Note = "Hadolint - lints every Dockerfile in the tree directly from source (unpinned/floating base tags, ADD vs COPY, running as root, etc.) - no docker build needed. This is the source-only half of 'what's in these Dockerfiles'; see docker-base-images below for the zero-cost structural half, and the Dockerfile's own comments for the build-dependent deep pass (syft/dive against an actually-built image) that's opportunistic, not automated here. No ExpectedOutput here deliberately: hadolint.txt is created empty (via run-dockerfile-lint.sh's own colon-redirect) even on a repo with zero Dockerfiles, which is a legitimate outcome, not a failure - an emptiness check would false-positive on every Dockerfile-free repo. 2026-09-10: moved to a static baked-in script (run-dockerfile-lint.sh) after a real PowerShell-to-docker.exe argv-marshalling failure - see the fix comment above this Note."
    },
    [PSCustomObject]@{
        Name = "docker-base-images"
        EvidenceSubdir = "iac-docker"
        # 2026-09-17: routed to audit-container for consistency with
        # dockerfile-lint (same EvidenceSubdir, same "container" evidence
        # group) even though this step only needs find/grep/awk, both present
        # in audit-container's minimal base image (MIGRATION.md item 7).
        Image = "audit-container:local"
        Cmd = @("bash", "-lc",
                'find /workspace -iname "Dockerfile*" -type f -print0 | xargs -0 grep -H -i -E "^FROM[[:space:]]" | sort -u > /evidence/iac-docker/base-images.txt || true')
        CaptureStdout = $false
        AllowNonZeroExit = $true
        Note = "Zero-cost base-image inventory: every FROM line across every Dockerfile in the tree, deduped, no build required. Skim this for floating tags (':latest', no tag at all) and EOL/unsupported base OSes - this is exactly how the centos:6.6 and debian:latest Dockerfiles from the earlier profile_repo.py pass were originally found by hand; this step just makes that check repeatable and complete instead of relying on spotting it manually again. No ExpectedOutput here for the same reason as dockerfile-lint: a Dockerfile-free repo legitimately produces an empty base-images.txt. Confirmed live against fsh-server 2026-09-09/10: exit 0, 21.7s."
    },
    [PSCustomObject]@{
        Name = "scancode"
        EvidenceSubdir = "license"
        Image = "scancode-toolkit:local"
        Cmd = @("-clip", "--json-pp", "/evidence/license/scancode.json", "/workspace")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "license/scancode.json"
        Note = "ScanCode Toolkit - license/copyright/package-origin detection, run from its own separately-built image rather than baked into the main toolbox - deliberately kept out of that image per the Dockerfile's own note (heavy dependency footprint). IMPORTANT: there is no publishable ghcr.io/aboutcode-org/scancode-toolkit image to pull (verified directly - anonymous manifest pull returns 'denied', and ScanCode's own docs confirm you must build it yourself); Build-AuditImages.ps1 / build-audit-images.sh now build the local scancode-toolkit:local tag this step references as part of their normal 'scancode' step (added 2026-09-18, run once, reused on later builds), or run Build-ScanCodeImage.ps1 / Build-ScanCodeImage.sh standalone if you only want this one image. Either way, if scancode-toolkit:local doesn't exist yet this step will fail with 'Unable to find image'. Note the image's own ENTRYPOINT already runs scancode, so Cmd here is scancode's arguments only, not the word 'scancode' itself. Can be slow on a large tree (-clip = copyright+license+info+package); consider a narrower -RepoPath for fsh-client given its size before running this against the whole thing."
    },
    [PSCustomObject]@{
        Name = "dependency-lifecycle"
        EvidenceSubdir = "sbom"
        Cmd = @("python3", "/opt/scripts/analyze_dependency_lifecycle.py",
                "--sbom", "/evidence/sbom/sbom.cdx.json",
                "--eol-reference", "/opt/scripts/eol-reference.json",
                "--scancode", "/evidence/license/scancode.json",
                "-o", "/evidence/sbom/dependency-lifecycle.json")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        ExpectedOutput = "sbom/dependency-lifecycle.json"
        DependsOn = "sbom"
        Note = "2026-09-17, added for design-v3.md L1 broadening (full SBOM/dependency/EOL/license scope, not just CVE reachability): cross-references the sbom step's CycloneDX component list against a small hand-curated, offline EOL/abandonware reference table (scripts/eol-reference.json) and re-surfaces the SBOM's own per-component license data, which syft already produces for free but no lane previously consumed. Does NOT call any live EOL-tracking API by design -- see eol-reference.json's own header for why a live lookup here would break the pipeline's run-to-run determinism. --scancode points at the scancode step's deeper license/copyright scan for cross-reference if that step has also run; this step degrades gracefully (a note in the output, not a failure) if scancode.json is absent. Anything not covered by the reference table is reported as 'unknown', never inferred as current -- same discipline the rest of the pipeline applies to code coverage."
    },
    [PSCustomObject]@{
        Name = "evidence-scrub"
        EvidenceSubdir = "_shareable"
        Cmd = @("python3", "/opt/scripts/scrub_evidence.py", "/evidence", "-o", "/evidence/_shareable")
        CaptureStdout = $false
        AllowNonZeroExit = $true
        Note = "E4-1 fix (2026-09-01 adversarial process review + verification follow-up): gitleaks' --redact protects gitleaks' OWN output only. Verified live: semgrep and mobsfscan SARIF both embed the raw matched source line - including, when that line is a hardcoded-secret finding, the literal secret value - by default. This step (deliberately run LAST, after every other step has written its evidence) produces a redacted copy of the whole tree under /evidence/_shareable, using TWO passes: a high-entropy substring filter (catches machine keys/tokens) AND a secret-name-aware value redactor (catches human passwords like a hardcoded db_password that the entropy filter alone missed - that gap was found and fixed during verification). ONLY /evidence/_shareable is safe to zip and hand off; the rest of /evidence, including this step's own input, is internal-only and may contain plaintext secret values. If you use -Steps to run a subset, this step does not run implicitly - add it explicitly, last, whenever you intend to hand evidence off. No ExpectedOutput enforced here since its own input is every other step's evidence - an unusually clean run legitimately has little to scrub; check /evidence/_shareable by hand before a real handoff regardless."
    }
)

$selectedSteps = $allSteps
if ($Steps) {
    $selectedSteps = $allSteps | Where-Object { $_.Name -in $Steps }
    if (-not $selectedSteps) {
        throw "No matching steps for -Steps $($Steps -join ','). Valid names: $(($allSteps | ForEach-Object Name) -join ', ')"
    }
}

$manifestPath = Join-Path $EvidencePath "MANIFEST.json"

# 2026-09-02 fix: MANIFEST.json is now read-merge-written, keyed by step
# name, instead of being rebuilt from scratch and overwritten wholesale.
# Confirmed live this was a real problem twice over: (1) the manifest was
# only ever written ONCE, after the entire -Steps list finished - so
# checking it mid-run (e.g. while sast-multi-semgrep-owasp alone was still
# running for 2+ hours) showed stale content from a PREVIOUS invocation with
# no indication anything from the current run had happened yet; (2) because
# each invocation's final write replaced the whole file with ONLY that
# invocation's own $selectedSteps entries, running -Steps against a subset
# silently discarded every other step's recorded history from earlier runs
# (this is why the original 26-step full-run manifest no longer exists - a
# later single-step -Steps rerun overwrote it down to one entry). Now: any
# existing MANIFEST.json is loaded first, each step's result is merged in
# (added or replacing that step's own prior entry, everything else left
# alone) and the file is rewritten after EVERY step completes, not just at
# the end - so the manifest is always current, and -CleanEvidence (which
# deletes MANIFEST.json before this point) is the only way to actually lose
# history, deliberately.
function Read-ExistingManifest([string]$Path) {
    $result = [ordered]@{}
    if (Test-Path $Path) {
        try {
            $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
            if ($raw.Trim()) {
                $existing = $raw | ConvertFrom-Json
                if ($existing -isnot [System.Array]) { $existing = @($existing) }
                foreach ($item in $existing) {
                    if ($item.step) { $result[[string]$item.step] = $item }
                }
            }
        } catch {
            Write-Warning "Could not parse existing MANIFEST.json at '$Path' - starting fresh instead of merging (it will be overwritten as steps complete). Parse error: $($_.Exception.Message)"
        }
    }
    return $result
}

function Save-Manifest($ManifestByStep, [string]$Path) {
    # ConvertTo-Json collapses a single-item collection to a bare object
    # instead of a 1-element array unless -AsArray is available (PS 7+) -
    # wrap defensively so a one-step run still produces valid manifest JSON
    # (an array) rather than surprising downstream readers like
    # summarize_evidence.py.
    $values = @($ManifestByStep.Values)
    $json = if ($values.Count -eq 1) {
        "[`n" + ($values[0] | ConvertTo-Json -Depth 5) + "`n]"
    } else {
        $values | ConvertTo-Json -Depth 5
    }
    $json | Set-Content -Path $Path -Encoding UTF8
}

$manifestByStep = Read-ExistingManifest -Path $manifestPath

foreach ($step in $selectedSteps) {
    New-EvidenceDir $step.EvidenceSubdir | Out-Null

    if ($step.DependsOn) {
        $depDir = Join-Path $EvidencePath $step.DependsOn
        $depHasOutput = (Test-Path $depDir) -and ((Get-ChildItem -Path $depDir -File -Recurse -ErrorAction SilentlyContinue).Count -gt 0)
        if (-not $depHasOutput) {
            Write-Warning "Skipping $($step.Name) - depends on '$($step.DependsOn)' evidence, which doesn't exist yet. Run that step first (either don't use -Steps to filter, or include '$($step.DependsOn)' in your -Steps list)."
            $manifestByStep[$step.Name] = [PSCustomObject]@{
                step = $step.Name; startedUtc = (Get-Date).ToUniversalTime().ToString("o")
                durationSec = 0; exitCode = -2; outputOk = $false; treatedOk = $false
            }
            Save-Manifest -ManifestByStep $manifestByStep -Path $manifestPath
            continue
        }
    }

    # 2026-09-02 fix: delete this step's own known output file(s) before it
    # runs, every time (not opt-in) - confirmed live this was a real gap,
    # not just a theoretical one. A run of sast-multi-semgrep that got
    # SIGKILLed (exit 137, likely OOM) never got far enough to open/write
    # semgrep.json - but the ExpectedOutput check ("exists and non-empty")
    # was satisfied anyway by a *stale* semgrep.json left over from an
    # earlier, unrelated failed run (still showing that run's own old
    # error), so outputOk/treatedOk both reported true for a step that had
    # produced nothing this run. Clearing the target(s) first means a stale
    # leftover can never again be mistaken for this run's result - if the
    # file exists after the step runs, this run actually wrote it. Only
    # touches the specific file(s) this step declares (ExpectedOutput /
    # ExpectedOutputAny / OutFile), not sibling steps' evidence - safe to
    # use with a narrow -Steps list. For a full clean-slate reset instead,
    # use -CleanEvidence.
    $ownOutputs = [System.Collections.Generic.List[string]]::new()
    if ($step.ExpectedOutput) { $ownOutputs.Add($step.ExpectedOutput) }
    if ($step.ExpectedOutputAny) { foreach ($rel in $step.ExpectedOutputAny) { $ownOutputs.Add($rel) } }
    if ($step.OutFile -and -not $ownOutputs.Contains($step.OutFile)) { $ownOutputs.Add($step.OutFile) }
    foreach ($rel in $ownOutputs) {
        $p = Join-Path $EvidencePath $rel
        if (Test-Path $p -PathType Leaf) {
            Remove-Item -Path $p -Force
            Write-Host "    cleared stale output: $rel" -ForegroundColor DarkGray
        }
    }

    Write-Host "==> $($step.Name)" -ForegroundColor Cyan
    if ($step.Note) { Write-Host "    $($step.Note)" -ForegroundColor DarkYellow }

    $stepImage = if ($step.Image) { $step.Image } else { $ImageTag }
    $dockerArgs = (Get-BaseDockerArgs $stepImage) + $step.Cmd
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $stdoutFile = if ($step.CaptureStdout -and $step.OutFile) { Join-Path $EvidencePath $step.OutFile } else { $null }
    # Every step gets a persisted stderr log (2026-09-01 verification fix): the
    # silent-failure guidance in .DESCRIPTION told readers to check a
    # <step>.stderr.log that previously only existed for the stdout-capturing
    # steps and the ones that redirect internally - so for binskim/secrets/
    # sast-python/etc. there was nothing to check. Now the orchestrator always
    # writes one, whichever execution branch a step takes.
    $stderrFile = Join-Path $EvidencePath "$($step.EvidenceSubdir)/$($step.Name).stderr.log"

    try {
        # 2026-09-02 fix: on Windows PowerShell (not PowerShell 7+), a native
        # command's stderr output gets wrapped as a NativeCommandError record
        # when stderr is redirected - and with the script-wide
        # $ErrorActionPreference = "Stop" above, the FIRST such line becomes
        # a terminating exception here, caught by the catch block below as
        # exitCode=-1 "threw", regardless of whether the tool actually
        # succeeded. Confirmed live: cloc wrote its real output (17507 files
        # scanned, cloc.json written) and was still reported as having
        # thrown, purely because it also wrote something non-fatal to
        # stderr. Scoping ErrorActionPreference down to "Continue" for just
        # this native invocation - restored via finally - fixes that without
        # weakening the rest of the script's own error handling; a real
        # invocation failure (docker.exe missing, etc.) still throws and is
        # still caught below exactly as before.
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            if ($stdoutFile) {
                if ($step.CaptureStderr) {
                    # cppcheck-style: the "report" IS on stderr, so it goes to the
                    # OutFile; nothing left to tee to a separate stderr log.
                    & docker @dockerArgs 2> $stdoutFile 1> $null
                } else {
                    & docker @dockerArgs 1> $stdoutFile 2> $stderrFile
                }
            } else {
                & docker @dockerArgs 2> $stderrFile
            }
        } finally {
            $ErrorActionPreference = $prevEAP
        }
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = -1
        Write-Warning "$($step.Name) threw: $($_.Exception.Message)"
    }
    $sw.Stop()

    # 2026-09-02 fix: shell-fatal exit codes (bash syntax error, exec not
    # found/not executable) are never forgiven by AllowNonZeroExit - no real
    # tool here legitimately uses 2/126/127 to mean "ran fine, found
    # something". Confirmed live: ast-grep-scan and joern-parse both hit a
    # bash syntax error (exit 2) and BOTH still reported treatedOk=true under
    # the old formula, because AllowNonZeroExit forgave any non-(-1) exit
    # code unconditionally.
    $isShellFatal = (-not $step.AllowShellFatalExit) -and (($exitCode -in $script:ShellFatalExitCodes) -or (Test-IsSignalKillExitCode $exitCode))
    $exitOk = (-not $isShellFatal) -and (($exitCode -eq 0) -or ($step.AllowNonZeroExit -and $exitCode -ne -1))

    # 2026-09-02 fix: cross-check the exit code against whether the step's
    # actual output landed. Catches both a broken &&/;-chain that stopped
    # partway through (joern-parse) and a tool that failed fast before
    # writing anything despite an exit code the AllowNonZeroExit allowlist
    # would otherwise have tolerated (sast-multi-semgrep exiting 7 in ~10s).
    $outputOk = $true
    if ($step.ExpectedOutput) {
        $p = Join-Path $EvidencePath $step.ExpectedOutput
        $outputOk = (Test-Path $p -PathType Leaf) -and ((Get-Item $p).Length -gt 0)
    } elseif ($step.ExpectedOutputAny) {
        $outputOk = $false
        foreach ($rel in $step.ExpectedOutputAny) {
            $p = Join-Path $EvidencePath $rel
            if ((Test-Path $p -PathType Leaf) -and ((Get-Item $p).Length -gt 0)) {
                $outputOk = $true
                break
            }
        }
    }

    $ok = $exitOk -and $outputOk
    $manifestByStep[$step.Name] = [PSCustomObject]@{
        step        = $step.Name
        startedUtc  = (Get-Date).ToUniversalTime().AddSeconds(-$sw.Elapsed.TotalSeconds).ToString("o")
        durationSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        exitCode    = $exitCode
        outputOk    = $outputOk
        treatedOk   = $ok
    }
    # Written after EVERY step, not just at the end - so MANIFEST.json is
    # never more than one step behind reality, even mid-run on a long step.
    Save-Manifest -ManifestByStep $manifestByStep -Path $manifestPath

    # 2026-09-03 fix: static usage-note text used to be echoed from inside a
    # step's own bash -c string alongside the tool's real invocation - that
    # compound-string approach turned out to be unreliable (root-caused live
    # against joern-parse; see that step's Note above for the full writeup).
    # Steps that declare PostSuccessFile/PostSuccessText get that text
    # written directly by PowerShell, LF-only via .NET file I/O, and only
    # after the step's own success (treatedOk) is confirmed - this never
    # touches a shell's argv, so it can't be affected by bash-quoting or
    # PowerShell native-argv marshalling ever again.
    if ($ok -and $step.PostSuccessFile -and $step.PostSuccessText) {
        $postPath = Join-Path $EvidencePath $step.PostSuccessFile
        [System.IO.File]::WriteAllText($postPath, $step.PostSuccessText + "`n")
        Write-Host "    wrote $($step.PostSuccessFile)" -ForegroundColor DarkGray
    }

    if ($ok) {
        Write-Host "    done in $([math]::Round($sw.Elapsed.TotalSeconds,1))s (exit $exitCode)" -ForegroundColor Green
    } elseif ($exitOk -and -not $outputOk) {
        Write-Warning "    $($step.Name) exited $exitCode (tolerated) but its expected output file is missing or empty - check its evidence subfolder / stderr log, this step likely didn't actually run to completion."
    } else {
        Write-Warning "    $($step.Name) exited $exitCode - check its evidence subfolder / stderr log before trusting this step's output."
    }
}

Write-Host ""
Write-Host "Pre-pass complete. Evidence written to $EvidencePath" -ForegroundColor Cyan
Write-Host "Manifest: $manifestPath" -ForegroundColor Cyan
$failed = $manifestByStep.Values | Where-Object { -not $_.treatedOk }
if ($failed) {
    Write-Warning "$($failed.Count) step(s) across the FULL manifest (not just this run) need a look before you feed their evidence to Phase 1 prompts: $(($failed | ForEach-Object step) -join ', ')"
}
