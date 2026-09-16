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

The multi-agent LLM choreography survived mainly as architecture in `docs/design-v3.md`, not as
runnable prompts or orchestration code.

Documented intent exists for:

- L0A component and purpose identification
- L2 ASVS/MASVS control assessment
- red-team hypothesis
- blue-team refutation
- independent verification
- cross-lane synthesis
- lane contracts
- append-only ledger
- component classification invalidation and rescoping

Missing implementation:

- no filled `prompts/lanes/*.md`
- no filled `prompts/skills/*.md`
- no lane contract YAML files
- no component-purpose-map generator
- no ASVS/MASVS applicability runner
- no subtask-spawning orchestrator
- no restart/coordination loop for agent tasks
- no canonical ledger writer beyond design placeholders

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
6. synthesis prompt:
   - input: verified facts only
   - output: prioritized findings, limitations, and follow-up work

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
- a small EASTL rehearsal using those prompts

