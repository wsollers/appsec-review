# Job 27/47 audit: `job_cpg_analysis`

## Scope, identity and verdict

- Audited **only** `/home/wsollers/projects/appsec-review` through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the authorized Ubuntu-22.04 UNC view.
- Branch **main**, exact HEAD **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, clean before and after validation. The required ancestor check succeeded. `.venv/bin/python` imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read the full updated audit brief, authorized `AGENTS.md`, and coordination skill. The assigned ownership is this job/report only. No source, configuration, shared environment, dependencies, services, images, targets, commits or branches were changed. No nested agents, real Joern/compiler/tool/provider executions, integration, acceptance, live or Dagster runs.
- **Result: seven medium and three low functional findings**, reproduced with actual Python functions and synthetic inputs/inspected fake execution boundaries. Shared inherited defects and documentation discrepancies are listed separately. Default-disabled status does not make the opt-in implementation correct.
- **37 tests passed**: all 36 mapped job unit cases plus the environment guard, two workers, shuffled. JUnit execution time **6.713 s**; wrapper total **16.144 s**. Zero failures, errors, skips or tests over ten seconds.

## Registration, activation and intended contract

`runtime/registry.py:95,165` still registers the factory. `appsec-review.toml:2337-2365` declares three steps, one task each, one worker at job/step level, `settings.workers=1`, `max_cpg_bytes=2147483648`, and **`enabled=false`**. The tool remains catalog-enabled but **manual**, version **4.0.630** (`containers/catalog.toml:866-884`).

`runtime/selection.py:11-30` and `orchestration/topology.py:180-211` exclude this job from the default execution graph. The real contract test verified both its absence by default and its hypothetical included topology: predecessor `job_cpp_compiled_analysis`, supplied producer candidates compiled analysis, evidence collection and target catalog, before review-data indexing. The latter is topology description, not permission to execute a disabled job. Retirement metadata is added only when the acceptance handler actually runs (`job.py:64-72,379-384`); a normally omitted job produces no skip summary.

The tool policy is 1 GiB memory, two CPUs, 256 PIDs, 600-second timeout, 16 MiB streams, read-only target and writable scratch (`containers/tools/joern/tool.toml`). No current image execution or resource behavior was measured.

### Accepted inputs and actual reads

The complete `datasets.CONTRACT` contains **21 input requirements**:

| Producer | Requirements | Actual use in this job |
|---|---|---|
| `job_cpp_compiled_analysis` | Required/reject `handoff`; optional/gap `cpp_build_graph`, `clang_ast`, `llvm_ir`, `infer_observations`, `binary_symbols`, `cpp_blocked_branches`, `cpp_plan_and_summary`, `cpp_case_material` | Accepted envelope, bound result, manifest, successful project catalogs, normalized commands and hash-verified run-owned source mappings feed `accepted_cpp_scopes`. Other compiled shards can be inherited in the manifest; declaration/inheritance is not proof of semantic consumption. |
| `job_evidence_collection` | Optional/gap `handoff`, `static_tool_observations`, `static_tool_evidence`, `static_tool_io` | Seed extraction actually reads eligible observation shards from the attempt-pinned manifest. This job does not directly parse the raw static-tool evidence/I/O outputs. |
| `job_target_catalog` | Optional/gap `handoff`, `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents` | Availability and inherited manifest context; the CPG seed call does **not** enable the shared structural-seed fallback. No separate target-catalog payload-reading handler exists here. |

Shared loader `jobs/cpp_index_scopes.py:54-205` uses `accepted_upstream`, verifies the result/manifest binding, accepts only `catalog.projects` entries with `terminal_status=SUCCEEDED` and nonempty commands, verifies the compile-database hash and every mapped source hash, and derives the scope ID from case ID, case snapshot and database hash. Unavailable cases retain the first upstream gap or a fallback reason. The current target fingerprint is checked at load. Generate re-reads and compares scope-ID sets.

Commands are rebased from `/scratch/source` and `/scratch/build` to the read-only accepted case mount; driver selection is normalized to clang/clang++. The mount is the accepted case root, not the original target. Existing upstream command/directory/source-materialization defects therefore remain consequential here; see inherited issues below.

Seed extraction (`seeding/plan.py:22-29`, `ledger.py:147-177,294-371`) verifies the pinned manifest and observation shard hashes, excludes seeded producers' own observations, maps locations to accepted project files, ranks/deduplicates locations, bounds the selected set, and retains omission counters. `ShardSet.open_shard` calls `observe_shard` (`indexing/store.py:85-96`), so the old blanket allegation of “unrecorded seed shard reads” is not valid for this code. Compiled result/source JSON reads still use the shared direct readers rather than job-specific `observe_output` calls; exact payload-read attribution is a shared-boundary limitation, not proof of no consumption.

Mode, depth and seed limit derive from CodeQL export configuration; this job supplies unit/include-scan bounds (`config/seeding.py`, `config/loader.py:1525-1536`). CPG selection is **translation-unit granular**, not a call-depth graph expansion. Changing depth changes its identity/ledger, but does not change its selected TU set. This is the implemented CPG boundary, unlike the richer IR neighborhood.

## Every declared step and task

| Step/task | Real implementation and output | Observed limit or defect |
|---|---|---|
| `load.accepted_cpp` | `job.py:330-337`; `accepted_cpp_scopes`; verify current target fingerprint; emit accepted upstream identities, serialized scopes and unavailable cases. | No tool/model launch. Source/database integrity checks are real; complete runtime admission was not executed. Inherited normalization defects remain. |
| `generate.scopes` | `job.py:339-365`; re-read scopes, compare plan IDs; disabled branch emits unavailable reasons without launching; enabled branch derives seeds and executes scopes with `settings.workers`. | F01, F07, F09. Empty scopes/cases are `NOT_APPLICABLE`; otherwise gap-bearing completion. Disabled default does not run the handler in normal scheduling. |
| Internal generation work of that task | `_generate:107-206`; checkpoint; selected compile DB and exclude regex; `execute_scope_tool` stages fresh scratch and passes fixed c2cpg argv; enforce CPG limit + 1; record timeout/OOM/exit/empty/oversize; retain CPG and manifest; always `JOERN_GAP`. | F01, F06–F09. No-seed/no-supported-selection paths launch nothing. Unseeded failures can be cached by explicit existing design; seeded failed builds are not cached. |
| Internal export work of that task | `_export:209-245`, `export.py`; separate scratch, copied CPG, `joern-export --repr all --format neo4jcsv`, 64 MiB per-file request, parse bounded function record, discard successful raw export. | F02–F06, F10. Tool failure is normally a named gap, but malformed CSV can throw and fail the task. |
| Internal ledger/shard work of that task | `_seeded_record:248-262`, `_publish_shard:265-301`, `_skipped:304-318`; full ledger and compact metadata, blocked evidence entity, optional `ast_node` function facts, partial/unavailable coverage, zero security observations. | F02–F04, F07. No graph relations are generated by this producer. |
| `acceptance.publish_handoff` | `job.py:367-393`, `cpp_index_scopes.publish_scope_indexes:352-391`; compose own shards and unavailable coverage with accepted manifest, replace earlier own shards, verify manifest; write summary, retirement metadata, counts, status. | Final observation/item count intentionally zero. F02–F07 affect summarized/indexed results. Generic unit failure blocks this dependent task (`runtime/units.py:96-120,160-171`). |

There are no additional declared tasks, model workers, prompts, roles, personas or runtime skills launched here. Missing generated task/tool binding declarations are existing **T-147**, not evidence that the two tool commands are absent.

## Parser, identity, publication and downstream expectations

### Parser and bounds

The parser reads METHOD, CALL, IDENTIFIER, LITERAL and CONTROL_STRUCTURE node tables; AST, CONDITION and REACHING_DEF edge tables. It filters pseudo/external methods, attaches calls/branches using AST parents, counts operator calls, obtains branch conditions from node code, and counts reaching definitions by their source node's owner. It does **not** publish call-graph, CFG or PDG edge identities. Calls retain names and a `callee_resolved` flag, not an exact resolved callee identity. General graph/source mapping remains an explicit gap.

Constants: 64 MiB per data CSV, 400,000 rows per table, AST depth 96, 200 calls/function, 100 branches/function, and mostly 200-character display text. Row/call/branch cuts have gap records. AST-depth accounting is defective (F02). CSV header/row shape validation and malformed-input handling are defective (F03). Full-name truncation affects identity, not just display (F04). Header text is read whole; the CSV field-size limit is changed process-wide and not restored. No large-memory stress test was performed.

### Outputs

| Dataset | Actual bytes/ownership | Assessment |
|---|---|---|
| `cpg_graph_coverage` | `observations`, `joern-<scope>`, retrieval-index/2 | One blocked evidence artifact plus optional function AST nodes; source locations and relations absent by design. Shard fingerprint binds inputs/tool/parser identities. |
| `cpg_scope_coverage` | `observations`, `joern-coverage-<attempt>` | Logical declaration cpp-index-coverage/1; physical SQLite schema retrieval-index/2. More-specific prefix wins over `joern-`. |
| `cpg_summary` | Acceptance-task `cpg-analysis-summary.json`, cpg-analysis/1, artifact-only | Declared glob matches summary; broad `*.json` also claims other task JSON. Counts include generated/disabled scopes and retained CPGs, but zero observations/items is deliberate. |
| `cpg_binary` | `data/code-index/joern/**`, protected octet-stream | Owns CPG, DBs, receipts, checkpoint, ledger, parsed export and any leftover export files; metadata-only routes do not validate payload meaning. |

The configured validator checks task topology only. Generic interchange validation checks closed control status/gap fields, **not domain payload keys** (`interchange.py:521-571`). No dedicated cpg-analysis/cpg-export/cpg-manifest JSON Schema file was found under `docs/schemas`; the job does not attach a domain output validator. This is a named validation gap, not a claim that every malformed payload reaches final publication.

Function logical IDs derive from case snapshot, project, truncated full name, path and line (`job.py:286-292`). No stable original Joern node ID survives in exported function records. The parser sorts functions/calls/branches, but F02 makes content order-dependent before sorting.

`job_code_graph_index/scopes.py:47-49,303-309,374-391` treats CPG shards as analyzer neighborhoods, assigned to native CodeQL scopes sharing project root, not primary graph/cross-check evidence. `producers.py:160-190` reads AST-node `fact=cpg`, copies calls/branches/counts into bounded `tool_observation` neighborhood rows, and emits named missing-output gaps. It is therefore a real downstream consumer of faulty counts/identities, despite Joern being default-disabled. Graph and review-data indexing contracts explicitly accept all four CPG datasets. Other downstream consumers were searched, not fully audited.

Legacy string gaps remain tolerated (`Job.strict_gaps` defaults false), and become canonical `producer_reported_gap` with default non-retryable metadata. This is existing architecture/debt, not a new invented terminal status. `JOERN_GAP` is retained even when no CPG was generated; its wording is not reliable execution evidence.

## Functional findings

### CPG-F01 — Medium — The seeded allowlist accepts unselected suffix-matching paths

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/seeded.py:55-66`; `src/appsec_review/jobs/job_cpg_analysis/job.py:129-136`.
- **Trigger:** select `src/a.cpp`, while the accepted project also contains `vendor/src/a.cpp` or `not-src/a.cpp`.
- **Expected:** the regex admits exactly the selected normalized source paths.
- **Actual/repro R1:** all three `/target/source/...` paths are admitted. The negative lookahead uses `.*(?:allowed)$`, so an allowed name is merely a suffix, not an exact relative-path identity.
- **Impact:** the explicit c2cpg exclusion boundary is wider than the selected DB/ledger claims; wrong files can enter the opt-in CPG depending on frontend enumeration. The regex failure is reproduced; actual Joern enumeration was not executed.
- **Confidence:** high for incorrect predicate; live parser extent remains unverified.
- **Smallest correction:** match the full normalized relative path or precisely anchored known source root; test nested/suffix collisions.
- **Overlap:** **T-016** explicitly records live exclude-regex verification at scale as incomplete. This is a concrete deterministic defect, not merely the existing missing live check.

### CPG-F02 — Medium — AST depth caching silently drops valid facts and makes output row-order dependent

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/export.py:150-168`; consumers of owner results in the remaining CALL/branch/reaching-def loops.
- **Trigger:** a valid AST chain exceeds 96 hops; a deep call is read before a shallower call on that chain.
- **Expected:** deterministic ownership; a depth cut must be named and must not poison shallower nodes.
- **Actual/repro R2:** using the real default depth, CSV order `(deep, shallow)` produces **zero calls**; reversing only those rows produces **two calls**. Both outputs have only the two standing no-call/no-CFG-edge gaps, no depth-cut gap.
- **Cause:** depth exhaustion caches `None` for every visited ancestor; the reverse order's cached owner also allows a later deep node to bypass a root-relative depth limit.
- **Impact:** silently incorrect call, branch and dependence counts enter partial CPG neighborhood facts.
- **Confidence:** high, real parser; no configured bound was enlarged.
- **Smallest correction:** distinguish “unknown due to bounded search” from “no owner”; preserve owner distance or compute ownership deterministically, and emit explicit depth/cycle/orphan coverage reasons.
- **Overlap:** broad bounded-export work **T-021**; no exact prior defect found.

### CPG-F03 — Medium — CSV incompleteness can become zero facts, while malformed bounded CSV aborts the task

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/export.py:108-124,130-146`; `src/appsec_review/jobs/job_cpg_analysis/job.py:233-245`; `src/appsec_review/runtime/units.py:96-120,160-171`.
- **Triggers:** METHOD and CALL tables exist but AST is missing; METHOD header lacks `:ID`; or a legitimate quoted CODE field exceeds 1 MiB while its CSV is far below the 64 MiB file cap.
- **Expected:** distinguish missing required structure from true empty facts; represent unsupported/malformed/bounded parser output as a named export gap without losing unrelated scope results.
- **Actual/repro R3:** missing AST yields one function with zero calls and only standing edge-limit gaps; missing ID raises `KeyError('id')`; the bounded large field raises `csv.Error('field larger than field limit (1048576)')`. `_export` catches neither, so the unit fails and dependent acceptance is skipped.
- **Impact:** incomplete export can misstate function counts as empty, or one malformed scope prevents the job's planned summary/publication.
- **Confidence:** high, real CSV reader and traced exception handling.
- **Smallest correction:** validate required table/header relationships and row widths; keep optional absent labels distinct from broken pairs; catch parser failures/field caps into explicit scoped gaps and perform cleanup.
- **Overlap:** **T-021** bounded-export/fixtures is broad; no exact existing TODO found.

### CPG-F04 — Medium — Truncated function names are used as logical identities

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/export.py:137-140`; `src/appsec_review/jobs/job_cpg_analysis/job.py:286-293`; `src/appsec_review/retrieval/index.py:112-123`; downstream `src/appsec_review/jobs/job_code_graph_index/producers.py:175-186`.
- **Trigger:** distinct C++ qualified/template overload identities share their first 200 characters and occur on the same source line/path.
- **Expected:** retain full identity, even if displayed names/signatures are bounded.
- **Actual/repro R4:** two METHOD rows differing after character 200 get the same logical AST-node ID; different signatures/payloads make real `IndexBuilder` raise “conflicting entities”. Neither original method ID is available to disambiguate.
- **Impact:** valid export can prevent shard publication; identical truncated payloads can instead collapse distinct methods and inflate raw function count relative to indexed entities.
- **Confidence:** high for reproduced publication collision; real long-template corpus not run.
- **Smallest correction:** hash the complete original function identity (and necessary source/TU discriminator) before truncating display fields; carry stable identity through the downstream transform.
- **Overlap:** no exact prior TODO/report found; **T-021** covers broader index/source mapping work.

### CPG-F05 — Medium — A failed seeded export is checkpointed and never retried

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/job.py:125-128,162-172,194-205`; `docs/architecture/seeded-neighborhoods.md:101-107`.
- **Trigger:** c2cpg succeeds, but the subsequent export exits nonzero.
- **Expected:** a later retry can recover the missing export without necessarily rebuilding the valid CPG. The shared seeded failure contract says failed work is not checkpointed.
- **Actual/repro R5:** export exits 4, then the same fake executor is made healthy. Retry returns `checkpoint_reused=True`, `cpg_export=None`, with **one build and one export total**. Checkpoint eligibility tests only whether a CPG exists, not export success.
- **Impact:** transient export failure becomes persistent unavailable CPG facts under the same scope identity.
- **Confidence:** high at the actual per-scope checkpoint boundary. The CPG-specific operations page narrows its promise to failed *builds*; this conflicts with the broader retry contract rather than proving the failure harmless.
- **Smallest correction:** independently checkpoint valid CPG generation and successful bounded export, or refuse seeded scope reuse when export failed.
- **Overlap:** analogous to **CPP-F03** but a separate CPG checkpoint condition; **T-016/T-021** broadly relevant.

### CPG-F06 — Medium — Scope reuse does not verify its export execution evidence

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/job.py:87-104,219-220,240-242,187-205`; `src/appsec_review/jobs/cpp_index_scopes.py:278-292,302-343`.
- **Trigger:** after successful seeded generation, the separate export receipt or export compile DB is missing/changed.
- **Expected:** reuse verifies the retained invocation evidence that supports the export.
- **Actual/repro R6:** deleted `export-run/execution.json` and `export-run/compile_commands.json`; `_generate` still returns a reused checkpoint with **six exported functions**, without another export.
- **Cause:** export artifacts affect the initial fingerprint but their references are not stored in the checkpoint result/CPG manifest. Recursive checkpoint validation can see the main execution, parsed export and shard, not the export invocation closure.
- **Impact:** reuse can advance parsed facts whose export execution evidence is no longer resolvable. The parsed JSON itself remains hash-verified; this is **not** a claim that full framework publication accepted corrupt native provenance.
- **Confidence:** high.
- **Smallest correction:** retain a separate export execution/artifact block in the result and validate it during reuse.
- **Overlap:** shared checkpoint pattern already reported as **CSA-F04** for Clang native evidence; this reproduces the CPG-specific missing closure. No exact CPG TODO found.

### CPG-F07 — Medium — Same selected seed keys reuse stale omission/provenance metadata

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/seeded.py:44-46`; `src/appsec_review/jobs/job_cpg_analysis/job.py:107-128,248-262`; `src/appsec_review/seeding/ledger.py:433-451`.
- **Trigger:** a newly admitted upstream plan retains the same selected location keys/settings but changes omitted, outside-database or unlocated counts, or selected seeds' sources.
- **Expected:** refreshed ledger/coverage accounting, even if tool work can be reused.
- **Actual/repro R7:** with seed limit two and the same two selected locations, change total to 12/dropped to 10, outside-database to three, unlocated to two. Reuse returns only `status_counts={"resolved":2}` and the old gaps.
- **Cause:** identity includes selected location rows, not full ledger-affecting seed/plan metadata.
- **Impact:** coverage omissions and seed provenance can remain stale after upstream re-acceptance; no production configuration was edited in this repro.
- **Confidence:** high for the scope cache.
- **Smallest correction:** rebuild the ledger from the current accepted plan around reusable tool results, or bind all output-affecting plan/source fields.
- **Overlap:** exact conceptual overlap with **CSA-F05**, separate CPG identity implementation; **T-016** broadly relevant.

### CPG-F08 — Low — Directory-shaped `cpg.bin` crashes instead of becoming the documented no-CPG gap

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/job.py:136-160`.
- **Trigger:** the tool leaves a directory at `cpg.bin`.
- **Expected:** reject nonregular output and finish with named unavailable coverage.
- **Actual/repro R8:** the regular-file check rejects it, then unconditional `unlink()` raises `IsADirectoryError` before publication.
- **Impact:** an invalid tool output defeats the intended failure-to-gap path for the whole generate task.
- **Confidence:** high, fake external boundary.
- **Smallest correction:** handle nonregular cleanup by type, without following symlinks, and preserve the original producer gap.
- **Overlap:** no exact TODO found.

### CPG-F09 — Low — Whole-program mode runs Joern for an unsupported-only scope

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/job.py:129-136`; `src/appsec_review/jobs/cpp_index_scopes.py:31-37,142-146,187-205`.
- **Trigger:** accepted nonempty command list contains only assembly/another unsupported compile-unit type, and mode is whole-program.
- **Expected:** preserve explicit not-applicable scope/input disposition and launch no frontend.
- **Actual/repro R9:** an actual verified `.S` scope has `supported_compile_unit_count=0`; `_generate` still invokes the fake tool once with an empty database and returns `COMPLETED_WITH_GAPS`.
- **Impact:** unnecessary expensive opt-in execution, and unsupported input is reported as missing CPG tooling coverage rather than not applicable. Seeded empty selections correctly skip, so this is specifically the whole-program path.
- **Confidence:** high at launch dispatch, no real frontend run.
- **Smallest correction:** preflight supported units and carry their not-applicable metadata into publication.
- **Overlap:** applicability debt **T-157**, related but different from **CSA-F07**'s loss of already-skipped scopes.

### CPG-F10 — Low — Failed/limited exports retain raw intermediates that the job says it discards

- **Evidence:** `src/appsec_review/jobs/job_cpg_analysis/job.py:222-245`.
- **Trigger:** export creates partial CSV output then exits nonzero, times out, is OOM-killed or hits the size ceiling.
- **Expected:** discard the failed raw export tree while retaining bounded diagnostic receipts.
- **Actual/repro R10:** exit 9 with `export/partial.csv` returns no record but leaves that file. Only the successful-parse branch and empty-parsed branch remove the tree; the input CPG copy alone is removed on earlier failure branches.
- **Impact:** failed, potentially large intermediate trees persist under protected run data, despite the discard assertion. Their bytes are not published as function facts.
- **Confidence:** high for the reproduced nonzero branch and statically identical early-failure cleanup.
- **Smallest correction:** perform owned scratch/export cleanup in a common `finally` or explicit failure cleanup branch.
- **Overlap:** no exact TODO found.

## Existing overlap and documentation discrepancies

- **CPP-F04** remains inherited: `seeding/units.py:44-58` exits flag dispatch after trying `-I`, so `-isystem`, `-iquote`, and `-idirafter` header seeds select no TU. Supplement K1 reconfirmed all four forms: only `-I` selected unit zero.
- **CPP K06 / historical C11-F08** remains inherited: include-scan budget excludes candidate probes; K2 reconfirmed **six reads for budget one** (`seeding/units.py:72-88`). `source_reader` reads whole bytes before slicing (`seeding/plan.py:40-45`). Not counted again as new CPG findings.
- **CPP K01–K03 / C08** source-materialization/accepted-command normalization defects continue into `cpp_index_scopes`; their parent report was reviewed, not all repros rerun here.
- **T-016** explicitly defers large-project measurements, live exclusion verification, CPG call-site cross-check wiring and several consumers. Those missing features are not newly invented requirements.
- **T-021/T-022** retain general exporter/source-mapping/front-end limitations; **T-168** is marked done, retaining registered historical jobs but retiring them from defaults; **T-147** covers missing authoritative task bindings; **T-157** covers applicability declarations.
- Historical **C07-F13** says disabled CPG executes every run. That is **not true at this revision**: the actual default topology test excludes it. Historical **C07-F18**'s blanket unrecorded-shard claim is also outdated because `open_shard` invokes `observe_shard`. Legacy free-text gaps remain.
- `job.py` module prose and `containers/tools/joern/README.md:18-20` say cut exports stay unavailable, but `_export` accepts nonempty bounded functions with parser gaps and `_publish_shard` marks them partial. The dedicated operations process is closer to this implementation. The generic `JOERN_GAP` still claims a CPG was generated on no-seed/tool-failure paths (existing T-016 wording debt).
- `docs/architecture/code-graph-precomputation.md:54,164-181` retains “nothing retrievable/no exporter” prose contradicted by the seeded export and real graph neighborhood consumer; later sections acknowledge seeded CPG. Do not erase the general source-mapping/acceptance limitation when correcting this.
- T-168's task plan promises a disabled structured skip summary; normal scheduling omits the job and produces no artifact. `retirement_metadata` is instead unconditional metadata on manually reached acceptance. This is a documented-plan/implementation discrepancy, not evidence that disabled tools ran.
- Summary-domain schema/validator absence and broad summary glob are named publication-validation gaps. No replacement schema or policy was invented during this read-only audit.

## Focused validation and exact reproduction commands

All Linux blocks below were passed through this transport, preserving quoting:

```powershell
$script = @'
# One Linux block below
'@
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
  "printf %s $encoded | base64 -d | bash"
```

### Unit suite

Inspected all five mapped test files, shared fixtures and conftest before running. The fake CPG executor only writes recorded/synthetic outputs, and the handler tests replace `execute_scope_tool`. No genuine CPG, compiler, build, provider or subprocess-writing test helper was selected.

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python - <<'PY'
import os
from tests.test_000_unit_environment_guard import offending_environment
bad=offending_environment(os.environ)
assert not bad, bad
import appsec_review
print(appsec_review.__file__)
PY
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 271118 \
  --strict --max-tests 37 --expect-tests 37 --timeout-seconds 180 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_cpg_analysis/test_contract.py \
  tests/unit/job_cpg_analysis/test_export_and_seeded.py \
  tests/unit/job_cpg_analysis/test_handlers.py \
  tests/test_cpg_export.py tests/test_seeded_cpg.py -q
```

**Exit 0.** Exact collection **37**, all passed. Collection **4.706 s**; supervised execution stage **11.094 s**; JUnit **6.713 s**; total wrapper **16.144 s**. No slow cases. The submitted `-q` duplicates the wrapper's `-q`, so its text-summary parser printed “no summary line found” and empty counts; actual JUnit independently reports `tests=37 failures=0 errors=0 skipped=0`. No rerun or invented textual count was used.

Private wrapper identifier: `tests-custom-20261118-125118-891937-3085746`. Under `test/tmp/`:

- Base temp: `tests-custom-20261118-125118-891937-3085746`
- Report: `reports/tests-custom-20261118-125118-891937-3085746.json`
- Log/collection log: `logs/tests-custom-20261118-125118-891937-3085746{,.collection}.log`
- JUnit: `tests-custom-20261118-125118-891937-3085746.junit.xml`
- Timings: `tests-custom-20261118-125118-891937-3085746.timings.sqlite`
- Exact collection: `tests-custom-20261118-125118-891937-3085746.collection.json`

The wrapper's own sequential collection/execution use the same fresh private directory, as authorized. No other pytest invocation/collection was made.

### R1–R8: actual functions, fake external execution

**Exit 0; 1.2476 s measured probe body.** Expected exceptions were caught/asserted as reproduced defects, not pytest failures. All temporary synthetic files were created below a fresh UUID directory in `test/tmp/` and removed in `finally`.

```bash
set -eu
cd /home/wsollers/projects/appsec-review
.venv/bin/python - <<'PY'
import csv, json, os, re, shutil, sqlite3, time, uuid
from pathlib import Path
from unittest.mock import patch
from appsec_review import seeding
from appsec_review.jobs import cpp_seeded
from appsec_review.jobs.job_cpg_analysis import export, seeded, job as j
from tests import seeded_clang_support as sc
from tests.unit.job_cpg_analysis.test_handlers import _make_scope_and_unit, _fake_execution
os.umask(0o022)
base=Path('test/tmp')/('job-audit-cpg-27-repro-'+uuid.uuid4().hex)
base.mkdir(parents=True)
start=time.perf_counter()

def table(p,kind,label,columns,rows):
 p.mkdir(parents=True,exist_ok=True)
 for suffix,data in [('header',[columns]),('data',rows)]:
  with (p/f'{kind}_{label}_{suffix}.csv').open('w',newline='') as f:
   csv.writer(f).writerows(data)
def methods(p,rows=None):
 table(p,'nodes','METHOD',[':ID','NAME:string','FULL_NAME:string','SIGNATURE:string',
       'FILENAME:string','LINE_NUMBER:int','IS_EXTERNAL:boolean','CODE:string'],
       rows or [['m','f','f:int()','int()','a.cpp',1,'false','int f() {}']])
def generate(st,ex,settings=None,plan=None):
 unit=st.unit('generate.scopes',{},seeded=settings or sc.SEEDED,job_id=j.JOB_ID)
 unit.job.config.settings.update(sc.CPG_SETTINGS)
 scope=sc.index_scope(st); s=cpp_seeded.settings_of(unit)
 p=plan or cpp_seeded.plan_for(unit,[scope],s)
 return j._generate(unit,scope,lambda _u:ex,seeded.Run(s,p,p.for_scope(sc.CASE)))
try:
 regex=seeded.exclude_regex(['src/a.cpp'])
 allowed=[p for p in ['/target/source/src/a.cpp','/target/source/vendor/src/a.cpp',
                      '/target/source/not-src/a.cpp'] if not re.match(regex,p)]
 assert len(allowed)==3
 print('R1 suffix-selection:',json.dumps(allowed))

 p=base/'depth';methods(p)
 table(p,'edges','AST',[':START_ID',':END_ID',':TYPE'],
       [['m' if i==0 else f'n{i-1}',f'n{i}','AST'] for i in range(100)])
 counts=[]
 for order in [(99,50),(50,99)]:
  table(p,'nodes','CALL',[':ID','NAME:string','CODE:string'],
        [[f'n{i}',f'call{i}','f()'] for i in order])
  out=export.read_export(p);counts.append(len(out.functions[0].calls))
  print('R2 depth order',order,'calls',[c.name for c in out.functions[0].calls],
        'gaps',out.gaps)
 assert counts==[0,2]

 p=base/'missing_ast';methods(p)
 table(p,'nodes','CALL',[':ID','NAME:string','CODE:string'],[['c','callee','callee()']])
 out=export.read_export(p)
 assert len(out.functions)==1 and out.functions[0].calls==[]
 assert out.gaps==[export.NO_CALL_EDGES_GAP,export.NO_CFG_GAP]
 print('R3 missing AST: functions=1 calls=0, only standing gaps')
 p=base/'bad_header'
 table(p,'nodes','METHOD',['NAME:string','FILENAME:string'],[['f','a.cpp']])
 try: export.read_export(p)
 except KeyError as e: print('R3 malformed header:',repr(e))
 else: raise AssertionError('expected KeyError')
 p=base/'big_field'
 methods(p,[['m','f','f:int()','int()','a.cpp',1,'false','x'*(1048576+1)]])
 try: export.read_export(p)
 except csv.Error as e: print('R3 bounded file with >1MiB field:',repr(e))
 else: raise AssertionError('expected csv.Error')

 p=base/'collision'; prefix='ns::f<'+('T'*200)
 methods(p,[['m1','f',prefix+'A>','int()','a.cpp',1,'false','int f() {}'],
            ['m2','f',prefix+'B>','void()','a.cpp',1,'false','void f() {}']])
 out=export.read_export(p)
 assert out.functions[0].full_name==out.functions[1].full_name
 root,scope,unit=_make_scope_and_unit((base/'collision_shard').resolve())
 try:
  j._publish_shard(unit,scope,artifacts=[dict(scope.compile_database)],tool={'tool':'fake'},
    gaps=out.gaps,cpg=None,cpg_manifest=None,resource_limit=None,compact=None,
    seeded_identity=None,exported=out.as_dict())
 except ValueError as e:
  assert 'conflicting entities' in str(e); print('R4 truncated full-name identity:',str(e))
 else: raise AssertionError('expected identity conflict')

 st=sc.stage((base/'export_retry').resolve())
 ex=sc.CpgExecutor(st.run_root,export_exit_code=4)
 first=generate(st,ex);ex.export_exit_code=0;second=generate(st,ex)
 assert second['checkpoint_reused'] and second['cpg_export'] is None
 assert len(ex.calls)==1 and len(ex.exports)==1
 print('R5 export retry:',json.dumps({'checkpoint_reused':second['checkpoint_reused'],
   'exports_called':len(ex.exports),'cpg_export':second['cpg_export'],
   'resolved':second['seeded']['resolved_seed_count']}))

 st=sc.stage((base/'receipt').resolve());ex=sc.CpgExecutor(st.run_root)
 first=generate(st,ex)
 r=st.run_root/'data/code-index/joern'/sc.index_scope(st).scope_id/'export-run'
 (r/'execution.json').unlink();(r/'compile_commands.json').unlink()
 second=generate(st,ex)
 assert second['checkpoint_reused'] and second['cpg_export'] and len(ex.exports)==1
 print('R6 removed export receipt+DB: checkpoint_reused=True functions=',
       second['cpg_export_function_count'])

 st=sc.stage((base/'seed_identity').resolve());ex=sc.CpgExecutor(st.run_root)
 settings={**sc.SEEDED,'seed_limit':2}
 first=generate(st,ex,settings)
 u=st.unit('generate.scopes',{},seeded=settings,job_id=j.JOB_ID)
 s=cpp_seeded.settings_of(u);scope=sc.index_scope(st)
 p=cpp_seeded.plan_for(u,[scope],s);original=p.for_scope(sc.CASE)
 changed=seeding.SeedPlan({sc.CASE:seeding.ScopeSeeds(sc.CASE,original.seeds,12,10)},
                         not_in_database=3,unlocated=2)
 second=generate(st,ex,settings,changed)
 assert second['checkpoint_reused'] and second['seeded']['status_counts']=={'resolved':2}
 print('R7 changed omissions: expected over_limit=10,file_not_in_database=3,unlocated=2; got',
       second['seeded']['status_counts'])

 root,scope,unit=_make_scope_and_unit((base/'directory').resolve())
 def directory_exec(_u,_s,_t,_argv,scratch,_ef,**kw):
  result=_fake_execution(root,scratch,cpg_bytes=None)
  (scratch/'cpg.bin').mkdir();return result
 with patch.object(j,'execute_scope_tool',directory_exec):
  try: j._generate(unit,scope,lambda _u:object())
  except IsADirectoryError as e: print('R8 invalid nonregular CPG:',type(e).__name__)
  else: raise AssertionError('expected directory failure')
 print('PROBES_SECONDS',round(time.perf_counter()-start,4))
finally:
 shutil.rmtree(base)
 print('scratch_removed',not base.exists())
PY
```

### R9–R10 and inherited K1–K2

**Exit 0; 1.0190 s measured probe body.** Fake scope/tool execution only; scratch removed.

```bash
set -eu
cd /home/wsollers/projects/appsec-review
.venv/bin/python - <<'PY'
import json,os,shutil,time,uuid
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
from appsec_review import seeding
from appsec_review.jobs.cpp_index_scopes import _scope
from appsec_review.jobs.job_cpg_analysis import job as j
from appsec_review.seeding.units import select_units
from appsec_review.storage import run_artifact
from tests.unit.job_cpg_analysis.test_handlers import _make_scope_and_unit,_fake_execution
os.umask(0o022)
base=Path('test/tmp')/('job-audit-cpg-27-supplement-'+uuid.uuid4().hex)
base.mkdir(parents=True);start=time.perf_counter()
try:
 root,scope,unit=_make_scope_and_unit((base/'unsupported').resolve())
 source=scope.case_root/'source'/'a.cpp';source.rename(source.with_suffix('.S'))
 rows=[{'target_path':'native/a.S','arguments':['clang','-c','/scratch/source/a.S']}]
 db=root/scope.compile_database['path'];db.write_text(json.dumps(rows))
 mapping={'project_id':scope.project_id,'root':scope.root,'case_snapshot':scope.case_snapshot,
          'files':[{'target_path':'native/a.S','scratch_path':'source/a.S',
                    'sha256':scope.files[0]['sha256']}]}
 asm=_scope(root,scope.case_id,{'mapping':mapping,
             'compile_database':run_artifact(root,db),'compile_commands':rows})
 calls=[]
 def fake(_u,s,_t,argv,scratch,_ef,**kw):
  calls.append(s.container_compile_database())
  return _fake_execution(root,scratch,cpg_bytes=None)
 with patch.object(j,'execute_scope_tool',fake):
  out=j._generate(unit,asm,lambda _u:object())
 assert calls==[[]] and out['terminal_status']=='COMPLETED_WITH_GAPS'
 print('R9 supported_unit_count=0; tool_calls=1; database=[]; status=',out['terminal_status'])

 root,scope,unit=_make_scope_and_unit((base/'failed_export').resolve())
 def failed_export(_u,_s,_t,argv,scratch,_ef,**kw):
  result=_fake_execution(root,scratch,cpg_bytes=b'staged',exit_code=9)
  (scratch/'export').mkdir()
  (scratch/'export'/'partial.csv').write_text('partial');return result
 with patch.object(j,'execute_scope_tool',failed_export):
  out=j._export(unit,scope,root/'data/code-index/joern'/scope.scope_id,
                scope.case_root/'source/a.cpp',lambda _u:object())
 assert out[0] is None
 remained=root/'data/code-index/joern'/scope.scope_id/'export-run/export/partial.csv'
 print('R10 failed export raw remains=',remained.exists());assert remained.exists()

 reader={'a.cpp':'#include <h.h>','inc/h.h':'int h;'}
 for flag in ['-I','-isystem','-iquote','-idirafter']:
  out=select_units([{'file':'/scratch/source/a.cpp',
                    'arguments':['cc',flag,'/scratch/source/inc']}],
     [seeding.Seed('inc/h.h',1,1)],unit_limit=1,include_scan_files=10,read_text=reader.get)
  print('K1 inherited include flag',flag,'selected',out.selected)
 def select_count():
  reads=[]
  content={'a.cpp':''.join(f'#include "h{i}.h"\n' for i in range(5)),
           **{f'h{i}.h':'int h;' for i in range(5)}}
  def reader(p):reads.append(p);return content.get(p)
  select_units([{'file':'/scratch/source/a.cpp','arguments':['cc']}],
    [seeding.Seed('h0.h',1,1)],unit_limit=1,include_scan_files=1,read_text=reader)
  return reads
 print('K2 inherited include_scan_files=1 actual reads=',select_count())
 print('SUPPLEMENT_SECONDS',round(time.perf_counter()-start,4))
finally:
 shutil.rmtree(base);print('scratch_removed',not base.exists())
PY
git rev-parse HEAD
git --no-pager status --short
```

The final HEAD was unchanged and status output empty. Searches noted the WSL host lacks `rg`; authorized UNC ripgrep was used instead. This was not a missing test dependency and nothing was installed.

## Read inventory and named gaps

**Read fully**

- Updated session brief; authorized `AGENTS.md`; `.claude/skills/multi-session-coordination/SKILL.md`.
- `docs/operations/job_cpg_analysis.md`; T-168 task document; `containers/tools/joern/README.md` and `tool.toml`.
- All five job Python files: `__init__.py`, `job.py`, `datasets.py`, `seeded.py`, `export.py`.
- `jobs/cpp_index_scopes.py`, `jobs/cpp_seeded.py`; `config/seeding.py`; `seeding/plan.py`, `units.py`, `record.py`; `runtime/selection.py`.
- All five mapped unit test files; `tests/seeded_clang_support.py`, `tests/conftest.py`, `tests/test_000_unit_environment_guard.py`, and `tests/test_cpp_index_jobs.py` (not run).
- `scripts/run-tests.sh`, `scripts/lib/common.sh`; exact mapped job-test entry.
- `jobs/job_code_graph_index/scopes.py` (read as a complete directly relevant consumer module, without executing that job).
- Exact TODO sections T-016, T-021, T-022, T-147, T-157, T-159, T-168.

**Sampled/searched**

- `appsec-review.toml` job/settings; registry registration; catalog Joern entry; `config/loader.py:1375-1437,1500-1539`.
- `seeding/ledger.py:1-270,295-460`; structural fallback is not enabled by this producer.
- `runtime/consume.py:145-248`; `inputs.py:450-569`; `handoff.py:180-267`; `units.py:80-239`; `datasets.py:1-205`; `interchange.py:521-606`.
- `orchestration/topology.py:1-220`; `retrieval/core.py:112-125`; `retrieval/index.py` entity de-duplication; `indexing/store.py:40-128`; container executor file-size/request/launch/result portions.
- `job_code_graph_index/producers.py:130-220`, and graph/review-data-indexing CPG input declarations. Repository-wide CPG consumer/schema references.
- `docs/architecture/seeded-neighborhoods.md:1-220`; CPG-related code-graph-precomputation sections; `job-interchange.md:89-143,185-270`.
- Test wrapper `ops_tests.py:320-456,517-565` and `ops_test_guard.py:1-109`.
- Prior per-job compiled-analysis and Clang-static reports by relevant findings; cumulative report and historical C07/CPG references. Historical statements were checked against current source, not adopted as proof.
- Recorded CSV corpus was parsed by the real reader/tests; every raw CSV was not manually read line-by-line.

**Material unread/unexecuted scope**

- Full Joern/JVM frontend/exporter internals, downloaded archive/JAR contents, Docker build/signing closure, actual image identity/resource limits, real `--exclude-regex` behavior, actual compiler/build output and large-target behavior.
- Integration/acceptance/live test files and execution; whole-job runtime admission/final publication; actual disabled/reenabled deployment; actual restart under fresh accepted upstream envelopes; shared-artifact/native evidence closure beyond the sampled/reproduced boundary.
- Complete downstream graph/retrieval/MCP/inference/package jobs and their location-matching behavior; CPG was not promoted to findings or independently compared with real target source.
- Shared modules beyond the listed samples, full domain-schema publication coverage, full TODO/prior-report corpus, and test orderings other than the specified two-worker shuffle.

Passing this focused suite is evidence about these offline cases, **not certification of exact correctness, live output quality, general CPG/PDG coverage, or useful security findings**. No further job was started.
