# pipeline — engagement job → pregather → assemble → LLM input

| Phase | Script | LLM? | Output |
|---|---|---|---|
| engagement job | `engagement_job.sh` / `engagement_job.ps1` | no | broad static evidence, native scratch, LLM input index, coverage ledger |
| static prepass | `scripts/Invoke-VendorAuditPrePass.sh` / `.ps1` | no | Semgrep, gitleaks, Trivy/config, SBOM/SCA, BinSkim, Joern, symbol/semantic indexes, `MANIFEST.json` |
| pregather | `pregather.sh` / `pregather.ps1` (twins; logic in container scripts) | no | compile DB, feasibility, IR, linked modules, ir-facts, CSA, CodeQL traced DB + regular C/C++ SARIF + mythos custom-memory SARIF, `pregather-manifest.json` |
| assemble | `assemble.py` (Python, one impl) | no | `bundle.json` + `bundle.md`: verified / unresolved / refuted with IR evidence and `needs` |
| correlate | `correlate_findings.py` | no | cross-tool clusters by nearby file/line across Semgrep, native SAST, CSA/native bundle, CodeQL, and SARIF tools |
| deep confirmation | `deep_confirm.py` | no | per-cluster source/native/CodeQL/IR support plus candidate callers/callees from the symbol index |
| component IR slice | `component_ir_slice.py` | no | optional post-characterization compiled-evidence slices by functional component |
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

After `01-component-characterization` produces a `component-purpose-map.json`, use
`component_ir_slice.py` to turn the linked LLVM IR into component-scoped compiled evidence. This is
not part of the initial engagement job because component ids do not exist until the LLM
characterization lane runs. The output belongs under `llm/component-ir/` and gives downstream
red-team, blue-team, native-memory, and verifier lanes a compact view of compiled functions, direct
call edges, GEP/pointer-arithmetic sites, and memory intrinsics for each functional component.

Example:

```powershell
python pipeline\component_ir_slice.py `
  --ir scratch\eastl-engagement\native-scratch\component-ir\eastl.ll `
  --component-map appsec-review-process\runs\<run_id>\outputs\01-component-characterization\component-purpose-map.json `
  --all-components `
  --out scratch\eastl-engagement\llm\component-ir
```

If only linked bitcode exists, first disassemble it in the native image:

```powershell
.\images\audit-native\run.ps1 F:\repos\appsec-review - F:\repos\appsec-review\scratch\eastl-engagement\native-scratch -- bash -lc "mkdir -p /scratch/component-ir && llvm-dis /scratch/linked/eastl.bc -o /scratch/component-ir/eastl.ll"
```

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

The `semantic-index` step is intentionally low-memory by default. Both host runners invoke
`/opt/scripts/run-semantic-index-batched.sh`, which runs `build_semantic_index.py` in fresh
embedding batches with `SEMANTIC_INDEX_BATCH_SIZE=1` and `SEMANTIC_INDEX_SLICE_LIMIT=0` unless
overridden in the host environment. `SLICE_LIMIT=0` means one normal process; the builder writes
each embedded batch to LanceDB immediately instead of accumulating all vectors in memory. The
runners pass through `SEMANTIC_INDEX_BATCH_SIZE`,
`SEMANTIC_INDEX_SLICE_LIMIT`, `SEMANTIC_INDEX_START`, `SEMANTIC_INDEX_MODEL`, and
`SEMANTIC_INDEX_TABLE` when set. Set `SEMANTIC_INDEX_SLICE_LIMIT` to a positive value only if
the target still needs fresh process boundaries. The final `semantic-index/index.json` is only
complete after the wrapper has processed every selected slice.

Tools live in the images (`images/*/Dockerfile`) — that is the catalog; digests are recorded in
every manifest. Run from WSL2 on Windows with sources on the WSL filesystem (fast); from a
Linux host identically. Host scripts have bash/PowerShell twins; anything with logic is Python.

When a heavy run is performed in WSL, copy the target source and generated engagement artifacts
back into this repo's ignored layout before starting LLM prompt lanes:

```bash
scripts/sync-wsl-engagement-to-repo.sh \
  --project <project> \
  --source-url <git-url> \
  --source-ref <branch-or-commit> \
  --engagement-dir <wsl-scratch/project-engagement> \
  --run-id <run_id>
```

This produces repo-local `targets/<project>` and `scratch/<project>-engagement` paths and, when a
run id is supplied, rewrites the process artifact manifest to those locations. If the source is
already present in WSL, use `--source-dir <wsl-target>` instead of `--source-url`.

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
directory. The full broad static prepass was also run from PowerShell against EASTL; that run
validated the broader static tool stack and found the original monolithic `semantic-index` OOM.

After replacing the monolithic semantic index invocation with
`run-semantic-index-batched.sh`, the Windows path was smoke-tested with:

```powershell
.\scripts\Invoke-VendorAuditPrePass.ps1 `
  -RepoPath scratch\semantic-index-smoke\repo `
  -EvidencePath scratch\semantic-index-smoke\evidence `
  -ImageTag vendor-audit-toolbox:latest `
  -Steps symbol-index,semantic-index
```

The first smoke produced two `semantic-index slice start=... limit=1 batch-size=1` log lines,
`semantic-index/index.json` with `"complete": true`, and a successful semantic query against the
tiny LanceDB index. The implementation was then tightened further so the default full run uses
`batch-size=1`, streams each batch directly into LanceDB, and only uses process slicing when
`SEMANTIC_INDEX_SLICE_LIMIT` is explicitly set.

The focused EASTL rerun of `symbol-index,semantic-index` completed through the PowerShell runner in
875 seconds. Final `semantic-index/index.json` reported 5,086 chunks and 5,086 rows with
`"complete": true`, and `query_semantic_index.py` returned plausible EASTL UTF conversion chunks
from the generated LanceDB table.
and then folded into the regenerated LLM package.

The Windows path now handles:

- WSL UNC paths without PowerShell provider prefixes in Docker mounts
- WSL UNC roots mapped to `/workspace` when normalizing compile databases
- include arguments such as `-I/home/...` mapped to `-I/workspace/...`
- Windows hosts where `python3.exe` is only the Microsoft Store app-execution alias
- PowerShell-safe command arrays for container arguments beginning with `--`

For very large targets, WSL/Linux remains preferred because the Windows/UNC path is materially
slower, especially for `ir-facts` and CodeQL.
