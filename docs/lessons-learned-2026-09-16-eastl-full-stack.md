# Lessons Learned — EASTL Full-Stack Dry Run, 2026-09-16

## Result

The EASTL dry run reached `Status: OK` after the full evidence pipeline completed:

- static pre-pass
- static summary
- native pregather
- native SAST (`clang-tidy` + `cppcheck`)
- compile feasibility
- IR emission
- IR linking
- `ir-facts`
- CSA/CTU
- regular CodeQL C/C++ security-extended
- custom Mythos CodeQL memory query pack
- native bundle assembly
- cross-tool correlation
- deep confirmation
- retrieval plan
- LLM input package
- status gating

Primary successful-run artifacts:

- `scratch/eastl-engagement/job-status.md`
- `scratch/eastl-engagement/job-manifest.jsonl`
- `scratch/eastl-engagement/llm/ENGAGEMENT_LLM_INPUT.md`
- `scratch/eastl-engagement/llm/coverage-ledger.json`
- `scratch/eastl-engagement/llm/correlated-findings.json`
- `scratch/eastl-engagement/llm/deep-confirmation.json`
- `scratch/eastl-engagement/llm/retrieval-plan.json`

The run is a process validation, not a claim that EASTL has exploitable vulnerabilities.
EASTL is a small target here, but it is now a good rehearsal corpus for the LLM lanes.

## Windows PowerShell Validation Addendum

After the WSL/Bash run, the Windows PowerShell + Docker path was validated against the same EASTL
checkout through a WSL UNC path.

Validated Windows job:

```powershell
.\pipeline\engagement_job.ps1 `
  -Project eastl `
  -Target '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl' `
  -CompileDb '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl\build\compile_commands.json' `
  -Out scratch\eastl-windows-codeql `
  -StaticRunner powershell `
  -StaticSteps cloc
```

Result:

- `scratch/eastl-windows-codeql/job-status.md`: `Status: OK`
- static `cloc` through Docker: OK
- native SAST over 126 TUs: OK
- compile feasibility: Tier A, 126/126
- IR feasibility: Tier A, 126/126
- link: `eastl.bc`, about 84 MB
- `ir-facts`: one fact file
- regular CodeQL security-extended: 41 findings
- custom Mythos CodeQL: 8 findings

CSA/CTU was then run through the Windows native Docker wrapper against the same normalized scratch:

```powershell
.\images\audit-native\run.ps1 `
  '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl' `
  - `
  scratch\eastl-windows-codeql\native-scratch `
  -- /opt/scripts/run_csa.py --compile-commands /scratch/compile_commands.json --out /scratch/csa --ctu --alpha
```

CSA result:

- 126/126 TUs analyzed
- CTU map built
- JSON and HTML outputs written
- LLM package regenerated with CSA included

Windows-specific fixes from this validation:

- use PowerShell `.ProviderPath` instead of `.Path` for Docker bind mounts
- map WSL UNC roots to `/workspace` in `normalize_compile_db.py`
- rewrite include arguments such as `-I/home/...` to `-I/workspace/...`
- avoid the Microsoft Store `python3.exe` app-execution alias when selecting host Python
- pass container command arguments as explicit PowerShell arrays so `--compile-commands` is not parsed as a PowerShell parameter

The full broad static toolbox was not run in the Windows validation; `-StaticSteps cloc` was used
to bound cost while validating Docker, native, IR, CodeQL, CSA, and LLM packaging.

## What Changed

### WSL/Bash execution path

Added `scripts/Invoke-VendorAuditPrePass.sh`, a bash runner for the static toolbox so WSL runs
do not need PowerShell. `pipeline/engagement_job.sh` now prefers the bash runner by default
with `--static-runner auto`, while preserving the PowerShell path for Windows Docker runs.

### Repo-local targets and scratch

The intended WSL workflow is:

- clone targets into ignored `targets/`
- write run outputs into ignored `scratch/`
- run from a WSL ext4 checkout such as `~/projects/appsec-review`, not from `/mnt/c` or `/mnt/f`

This keeps Docker bind mounts on fast WSL storage and avoids Windows filesystem IO drag.

If a heavy run already happened elsewhere in WSL, normalize it back into this repo before prompt
lanes:

```bash
scripts/sync-wsl-engagement-to-repo.sh \
  --project eastl \
  --source-url https://github.com/electronicarts/EASTL.git \
  --source-ref master \
  --engagement-dir ~/scratch/eastl-engagement \
  --run-id <run_id>
```

The script clones or mirrors source into ignored `targets/eastl`, copies artifacts into ignored
`scratch/eastl-engagement`, and can restage the run manifest so agents review exact source through
repo-local paths.

### CRLF hardening

The first native run failed at `link per project` with:

```text
/usr/bin/env: 'python3\r': No such file or directory
```

Root cause: Linux/container scripts had CRLF endings. Fixes:

- added `.gitattributes` for LF `.py`/`.sh` and Dockerfiles
- normalized script files
- hardened `images/audit-native/Dockerfile` to strip CRLF from copied `.py`/`.sh` scripts

### Static evidence ownership

Static evidence cleanup failed once because Docker-created files were root-owned:

```text
rm: cannot remove ... Permission denied
```

Fixes in `scripts/Invoke-VendorAuditPrePass.sh`:

- run tool containers as the caller's WSL UID/GID
- fall back to a root Docker cleanup only when stale root-owned evidence already exists

### Native pregather now includes broader pre-IR checks

`pipeline/pregather.sh` / `.ps1` now run native SAST before IR:

- `clang-tidy`
- `cppcheck`

Then they run:

- compile feasibility
- IR emission/linking
- `ir-facts`
- optional CSA
- optional CodeQL regular C/C++ security-extended
- optional custom Mythos CodeQL memory queries

### CodeQL is explicit in artifacts

CodeQL ran successfully on EASTL:

- regular C/C++ security-extended: `0` findings
- custom Mythos memory pack: `0` findings

The LLM package now lists zero-result tools explicitly so “0 findings” is not confused with
“not run.”

### LLM package raw-count table

`pipeline/build_llm_input.py` now writes a full “Findings by tool (raw counts)” table into
`ENGAGEMENT_LLM_INPUT.md` and `coverage-ledger.json`.

Important nuance:

- `static-evidence/SUMMARY.md` is static-only and is generated before native/CodeQL.
- `llm/ENGAGEMENT_LLM_INPUT.md` is the cross-pipeline LLM entrypoint.

### Deep confirmation layer

Added `pipeline/deep_confirm.py` and wired it into `pipeline/engagement_job.sh`.

For each correlated cluster it records:

- source/native/CodeQL evidence substrates
- nearby IR facts
- likely enclosing symbol
- nearby callees
- candidate callers from the symbol index
- a conservative confirmation level

Confirmation levels are routing hints, not vulnerability verdicts:

- `mechanism-confirmed`
- `codeql-ir-corroborated`
- `cross-tool-corroborated`
- `codeql-only`
- `source-only`
- `unclassified`

The artifact is intentionally conservative: tree-sitter caller/callee data is a navigation aid,
not semantic reachability proof.

The deep confirmation markdown is sorted so the LLM sees stronger evidence first. On EASTL after
sorting, the first clusters are the `DecodePart` C++ clusters with source SAST plus nearby IR facts,
not low-value workflow YAML Semgrep hits.

### Semantic index memory behavior

A full static EASTL PowerShell run showed `semantic-index` running for about 39 minutes before
Docker killed it with exit 137 after climbing to roughly 29 GB resident memory. The underlying
`build_semantic_index.py` already supported `--start`, `--limit`, and `--batch-size`, but the
static runners called it once without those slice controls.

Fix:

- added `scripts/run-semantic-index-batched.sh`
- wired both `scripts/Invoke-VendorAuditPrePass.ps1` and `.sh` to use it
- changed `scripts/build_semantic_index.py` to write each embedded batch directly to LanceDB
  instead of accumulating all vectors in memory
- defaulted the semantic step to `SEMANTIC_INDEX_BATCH_SIZE=1`

That means chunks are embedded one at a time and persisted incrementally. The wrapper still supports
process slicing with `SEMANTIC_INDEX_SLICE_LIMIT=<n>` if a future target needs fresh process
boundaries, but the default now keeps the normal full-run shape and avoids the 5,086-process EASTL
case.

Validation:

- rebuilt `vendor-audit-toolbox:latest`
- reran `symbol-index,semantic-index` from PowerShell against EASTL over a WSL UNC path
- `semantic-index` completed in 875 seconds with exit 0
- final `semantic-index/index.json` reported 5,086 available chunks, 5,086 rows written, 5,086
  table rows, and `"complete": true`
- `query_semantic_index.py` successfully retrieved EASTL UTF conversion chunks from the generated
  LanceDB table

Operational note: after interrupting the first strict-slice experiment, a stale Docker container
continued writing the old `semantic-index/index.json`. Check `docker ps` and stop stale scanner
containers before rerunning a step into the same evidence directory after an interrupt.

## EASTL Signal Snapshot

The final EASTL deep confirmation summary showed:

```text
clusters analyzed: 318
symbol index available: True
IR fact files: 1
confirmation levels: {'source-only': 303, 'cross-tool-corroborated': 9, 'unclassified': 6}
```

Interpretation:

- The stack is mechanically healthy.
- Most broad pre-pass results are source-only static-tool noise, which is expected.
- The 9 cross-tool-corroborated clusters are the right LLM rehearsal targets.
- EASTL is useful for pipeline rehearsal, not for measuring real-world game-server recall.

## LLM Prompt Harness Updates After EASTL

The first component-characterization probe was too physical: it identified directory buckets such as
core library, tests/benchmarks, and fetched dependencies. That was useful for exclusions but not
enough to drive ASVS/MASVS, native-memory, red-team, or blue-team work on a large game codebase.

The component lane now requires:

- code-scope classification and explicit exclusions
- a functional component cloud with coarse groups, aliases, search terms, representative locations,
  data classes, trust-boundary relevance, and `parallel_review_group`
- negative evidence for major expected categories that were searched or considered but not found

The component taxonomy now includes multiplayer/game-service categories such as identity/accounts,
REST/microservices, RPC/gRPC/protobuf, TLS/crypto/secrets, player/social/game services,
data/storage/records, admin/live-ops, mobile/console/PC UI and platform glue, content/update/assets,
native runtime/memory, and build/deployment infrastructure.

### Component IR compiled-evidence layer

After component characterization, `pipeline/component_ir_slice.py` now consumes linked LLVM textual
IR plus the component-purpose map and writes per-component compiled-evidence slices under
`llm/component-ir/`.

This closes an important gap between "component map plus source call graph" and "component map plus
compiled evidence." Each slice records:

- functions whose debug source locations match the component's representative locations
- direct call edges observed in the linked IR
- GEP/pointer-arithmetic instructions with source and IR line references
- LLVM memory intrinsics
- allocation-related calls when visible in the IR

Validated on EASTL after disassembling `scratch/eastl-engagement/native-scratch/linked/eastl.bc`:

```text
scratch/eastl-engagement/llm/component-ir/summary.json
```

Summary from the EASTL component map:

```text
FC01 Memory Allocators And Fixed Pools: 6 functions, 2 call edges, 6 GEPs
FC02 Containers, Capacity, And Iterator Arithmetic: 4 functions, 2 call edges, 1 GEP
FC03 Hash Tables And Tree Containers: 12 functions, 27 call edges, 221 GEPs
FC04 String, Encoding, And Text Conversion: 16 functions, 10 call edges, 61 GEPs, 3 memory intrinsics
FC05 Algorithms And Generic Utilities: 8 functions, 11 call edges, 5 GEPs
FC06 Atomic And Concurrency Primitives: 6 functions, 8 call edges, 9 GEPs
FC07 Smart Pointers And Object Lifetime Helpers: 0 functions in linked EASTL IR
```

The FC01 slice now includes `eastl::fixed_pool_base::init(...)` at `source/fixed_pool.cpp:15` with
six compiled GEP instructions. Empty component slices should be treated as coverage/build signals,
not as proof that the component is safe.

The red/blue process is also split:

- general red team: open-ended adversarial inference
- known-list red team: systematic review against the known issue catalog
- general blue team: refutation plus defense/mitigation for open-ended scenarios
- known-list blue team: evidence/control response for catalog-driven hypotheses

This split should be preserved for the large repo so checklist coverage does not crowd out
open-ended inference, and defensive control analysis does not get confused with false-positive
refutation.

### Independent verification and remediation proposal

The first focused independent verification target was `RT-FC04-002` in `FC04 String, Encoding, And
Text Conversion`. A small testcase under
`scratch/eastl-engagement/verification/rt-fc04-002/utf8_extended_probe.cpp` verified that enough-length
unsupported UTF-8 extended lead-byte forms return success, advance source/destination pointers, and
produce `0x0000ffff`.

The authoritative verification environment is the native audit Docker image. Native-image Clang
21.1.0 reproduced the behavior; the earlier MinGW host run is useful only as non-authoritative smoke
evidence. Plain linked LLVM IR and ASan/UBSan-instrumented linked LLVM IR were generated for the
focused probe plus `targets/eastl/source/string.cpp`:

```text
scratch/eastl-engagement/verification/rt-fc04-002/rt-fc04-002-linked.ll
scratch/eastl-engagement/verification/rt-fc04-002/rt-fc04-002-linked.asan-ubsan.ll
```

Executable sanitizer runs are blocked in the current native image because compiler-rt sanitizer
runtime archives are missing. Treat that as an environment limitation, not as a finding refutation.
If sanitizer runtime execution matters for the large repo, add the matching ASan/UBSan compiler-rt
archives to the native image before relying on sanitizer run status.

Added `appsec-review-process/11-remediation-proposal/` as the optional post-verification fix lane.
It consumes a verified finding and testcase, proposes a minimal source/test patch, retests in the
same Docker/native-image environment, and writes `proposed-fix.patch` or `proposed-fix.diff`. Host
compiler results must be labeled non-authoritative and cannot alone justify `verified-locally`. The
fresh-task continuation prompt for the current EASTL remediation rehearsal is:

```text
appsec-review-process/continuation-remediation-rt-fc04-002.md
```

## Commands Worth Keeping

Full EASTL validation:

```bash
cd ~/projects/appsec-review
export CODEQL_LICENSE_BASIS=oss

bash pipeline/engagement_job.sh \
  --project eastl \
  --target "$PWD/targets/eastl" \
  --compile-db "$PWD/targets/eastl/build/compile_commands.json" \
  --out "$PWD/scratch/eastl-engagement" \
  --msvc -
```

Regenerate only deep confirmation and the LLM package:

```bash
python3 pipeline/deep_confirm.py \
  --static-evidence "$PWD/scratch/eastl-engagement/static-evidence" \
  --native-scratch "$PWD/scratch/eastl-engagement/native-scratch" \
  --correlated-findings "$PWD/scratch/eastl-engagement/llm/correlated-findings.json" \
  --out "$PWD/scratch/eastl-engagement/llm/deep-confirmation.json"

python3 pipeline/build_llm_input.py \
  --project eastl \
  --target "$PWD/targets/eastl" \
  --static-evidence "$PWD/scratch/eastl-engagement/static-evidence" \
  --native-scratch "$PWD/scratch/eastl-engagement/native-scratch" \
  --bundle "$PWD/scratch/eastl-engagement/llm/native-bundle.json" \
  --correlated-findings "$PWD/scratch/eastl-engagement/llm/correlated-findings.json" \
  --deep-confirmation "$PWD/scratch/eastl-engagement/llm/deep-confirmation.json" \
  --retrieval-plan "$PWD/scratch/eastl-engagement/llm/retrieval-plan.json" \
  --out-dir "$PWD/scratch/eastl-engagement/llm"
```

Quick checks:

```bash
cat scratch/eastl-engagement/job-status.md
grep -n "deep-confirmation" scratch/eastl-engagement/job-manifest.jsonl
head -80 scratch/eastl-engagement/llm/deep-confirmation.md
grep -n "Findings by tool" scratch/eastl-engagement/llm/ENGAGEMENT_LLM_INPUT.md
```

## What Is Still Only Design

The multi-agent LLM choreography is now partially tracked under `appsec-review-process/`, with lane
prompts, run ids, handoffs, failure propagation, budgets, component taxonomy, and red/blue support
files. It is not yet a fully automated orchestrator.

Tracked prompt/process support now exists for:

- L0A component and purpose identification
- L2 ASVS/MASVS control assessment
- red-team hypothesis
- blue-team refutation
- independent verification
- remediation proposal with Docker/native-image retest
- id Software starter prompt that forces clone isolation, build discovery, and compile database
  generation before evidence collection
- cross-lane synthesis
- lane contracts
- component classification invalidation and rescoping

Missing implementation:

- no fully automated subtask scheduler for launching all red/blue/verification lanes
- no automatic component-cloud batching into parallel subtasks yet
- no final report automation beyond the current synthesis lane prompt
- no component-purpose-map generator
- no ASVS/MASVS applicability runner
- no subtask-spawning orchestrator
- no restart/coordination loop for agent tasks
- no canonical ledger writer beyond design placeholders
- no accepted-fix application workflow beyond proposed patch/diff generation

## Recommended Next Build Step Before the Huge Repo

Create a lightweight manual LLM rehearsal harness before implementing a full orchestrator:

1. `L0A` component characterizer prompt/template and artifact:
   - input: `ENGAGEMENT_LLM_INPUT.md`, symbol index, semantic index, repo profile, static summary
   - output: `component-purpose-map.json/.md`
2. `L2` ASVS/MASVS applicability prompt/template:
   - input: component-purpose map + coverage ledger + evidence package
   - output: control applicability plan with `APPLICABLE`, `LIKELY_NOT_APPLICABLE`, `UNKNOWN`
3. red-team hypothesis prompt:
   - input: top deep-confirmed clusters and component map
   - output: strongest plausible exploitability argument plus missing evidence
4. blue-team refutation prompt:
   - input: red-team claim plus source/evidence references
   - output: refutation or remaining dependency list
5. independent verification prompt:
   - input: only cited evidence/source spans, not discoverer prose
   - output: confirmed/refuted/unresolved disposition
6. remediation proposal prompt:
   - input: verified finding, focused testcase, Docker/native-image commands, IR/sanitizer status
   - output: proposed patch/diff and Docker/native-image retest status
7. synthesis prompt:
   - input: verified facts only
   - output: prioritized findings, limitations, and follow-up work

For the first id Software follow-on, use:

```text
appsec-review-process/initial-idsoftware-game-repo-compile-and-review.md
```

Current seed clone:

```text
project slug: idsoftware-doom3-bfg
repo: https://github.com/id-Software/DOOM-3-BFG.git
commit: 1caba1979589971b5ed44e315d9ead30b278d8b4
Windows target: targets/idsoftware-doom3-bfg
Windows output: scratch/idsoftware-doom3-bfg-engagement
WSL target: ~/targets/idsoftware-doom3-bfg
WSL output: ~/scratch/idsoftware-doom3-bfg-engagement
```

The first output should be a build-discovery note, not findings. The prompt should identify the
buildable projects under the clone, choose a representative native target, and produce or recover a
compile database before the engagement pipeline runs.

This can be driven manually in Codex subtasks first; automation can follow once the prompt shapes
are stable.

## Risks Before the Game-Server Run

- The real repo will be much larger; static evidence may dominate context unless component routing
  happens first.
- Source-only static noise can drown good signals if deep confirmation is not sorted/filtered.
- The symbol index is not a semantic call graph; treat it as retrieval guidance.
- CodeQL and IR coverage are only as good as the compile database.
- Component classification is not implemented, so ASVS/MASVS scoping will be manual unless L0A is
  added first.
- The LLM prompt suite and orchestration loop remain the largest missing piece.

## Suggested Go / No-Go

Go for a game-code dry run only if the purpose is evidence gathering and process shakeout.

Before expecting high-quality final findings, add at least:

- L0A component characterization
- ASVS/MASVS applicability planning
- manual red-team / blue-team / verifier prompt templates
- remediation proposal rehearsal on `RT-FC04-002`
- a small EASTL rehearsal using those prompts
- Doom 3 BFG build-discovery and compile database bootstrap using the id Software starter prompt
