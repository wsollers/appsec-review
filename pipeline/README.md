# pipeline — engagement job → pregather → assemble → LLM input

| Phase | Script | LLM? | Output |
|---|---|---|---|
| engagement job | `engagement_job.sh` / `engagement_job.ps1` | no | broad static evidence, native scratch, LLM input index, coverage ledger |
| static prepass | `scripts/Invoke-VendorAuditPrePass.sh` / `.ps1` | no | Semgrep, gitleaks, Trivy/config, SBOM/SCA, BinSkim, Joern, symbol/semantic indexes, `MANIFEST.json` |
| pregather | `pregather.sh` / `pregather.ps1` (twins; logic in container scripts) | no | compile DB, feasibility, IR, linked modules, ir-facts, CSA, CodeQL traced DB + regular C/C++ SARIF + mythos custom-memory SARIF, `pregather-manifest.json` |
| assemble | `assemble.py` (Python, one impl) | no | `bundle.json` + `bundle.md`: verified / unresolved / refuted with IR evidence and `needs` |
| correlate | `correlate_findings.py` | no | cross-tool clusters by nearby file/line across Semgrep, native SAST, CSA/native bundle, CodeQL, and SARIF tools |
| deep confirmation | `deep_confirm.py` | no | per-cluster source/native/CodeQL/IR support plus candidate callers/callees from the symbol index |
| retrieval plan | `generate_retrieval_plan.py` | no | risky files, semantic queries, CodeQL follow-up commands, and source searches |
| handoff | `appsec-review-process/create_handoff.py` | yes | lane-specific task prompt over staged evidence |
| report | `appsec-review-process/10-synthesis-report/` | yes | executive + technical report inputs |

`engagement_job.sh` and `engagement_job.ps1` are the high-level runners for real engagements. They run the existing broad
static pre-pass (Semgrep, gitleaks, Trivy/config, BinSkim, SBOM/SCA, search/indexing, etc.),
then the native `pregather` lane, then `assemble.py`, then writes `llm/ENGAGEMENT_LLM_INPUT.md`
and `llm/coverage-ledger.json`. It also writes `llm/correlated-findings.json/.md`, a deterministic
cross-tool grouping of Semgrep, clang-tidy, cppcheck, SARIF tools, regular CodeQL,
custom mythos CodeQL memory queries, and CSA/native bundle results by nearby file/line.

`llm/deep-confirmation.json/.md` is the deeper confirmation layer. For every correlated cluster it
records the evidence substrates that saw the issue (source SAST, native/CSA bundle, CodeQL), whether
IR facts exist near the source location, the likely enclosing symbol, nearby callees, and candidate
callers from the tree-sitter symbol index. Candidate callers/callees are navigation hints, not
semantic reachability proof; use CodeQL, Joern, source review, or reviewer analysis before making a
final reachability claim.

`llm/retrieval-plan.json/.md` then points the LLM at risky files, symbol-index candidate callers,
semantic-index queries, CodeQL follow-up commands, and source-search patterns. The LLM should start
from those files, not from raw source.

Every top-level step records an exit code, duration, and log path in `job-manifest.jsonl`.
The final `job_status.py` pass writes `job-status.json/.md` and exits non-zero when an
enabled phase failed or a required artifact is missing. That means the job can keep gathering
partial evidence after CodeQL/Semgrep/etc. failures, while still ending with an explicit
degraded status instead of a quiet success.

The static prepass has two host runners over the same Docker toolbox image:
`scripts/Invoke-VendorAuditPrePass.sh` for bash/Linux/WSL and
`scripts/Invoke-VendorAuditPrePass.ps1` for PowerShell/Windows. `engagement_job.sh`
defaults to `--static-runner auto`, which prefers the bash runner. `engagement_job.ps1`
also supports `-StaticRunner auto|bash|powershell` and prefers the PowerShell runner in
`auto`, with bash available as an explicit or fallback path.

Tools live in the images (`images/*/Dockerfile`) — that is the catalog; digests are recorded in
every manifest. Run from WSL2 on Windows with sources on the WSL filesystem (fast); from a
Linux host identically. Host scripts have bash/PowerShell twins; anything with logic is Python.

Native Linux targets (EASTL, yquake2, Unreal): `--compile-db` with the cmake/bear/UBT
compile_commands.json, no `--msvc`; the gate and CodeQL replay detect the GNU driver.
Windows targets: converter + `--msvc`.

## Windows PowerShell Validation

The PowerShell path is validated against EASTL using a WSL UNC target path:

```powershell
.\pipeline\engagement_job.ps1 `
  -Project eastl `
  -Target '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl' `
  -CompileDb '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl\build\compile_commands.json' `
  -Out scratch\eastl-windows-codeql `
  -StaticRunner powershell `
  -StaticSteps cloc
```

That validation completed `Status: OK` with native Tier A feasibility, IR Tier A feasibility,
linked bitcode, `ir-facts`, regular CodeQL, custom Mythos CodeQL, and refreshed LLM artifacts.
CSA/CTU was also tested through `images/audit-native/run.ps1` against the same normalized scratch
and then folded into the regenerated LLM package.

The Windows path now handles:

- WSL UNC paths without PowerShell provider prefixes in Docker mounts
- WSL UNC roots mapped to `/workspace` when normalizing compile databases
- include arguments such as `-I/home/...` mapped to `-I/workspace/...`
- Windows hosts where `python3.exe` is only the Microsoft Store app-execution alias
- PowerShell-safe command arrays for container arguments beginning with `--`

For very large targets, WSL/Linux remains preferred because the Windows/UNC path is materially
slower, especially for `ir-facts` and CodeQL.
