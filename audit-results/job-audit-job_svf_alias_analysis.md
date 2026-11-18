# Job 23/47 audit — `job_svf_alias_analysis`

## Scope and result

- Audited **only this job**, its tool adapter/driver and directly necessary input, publication and consumer helpers.
- Source: `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`; branch `main`, exact **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**. HEAD and clean tracked state verified before tests and after reproductions. The editable package resolved inside this checkout.
- Read the complete updated shared brief, authorized checkout `AGENTS.md`, and coordination skill. The Windows working checkout was not audited or tested.
- **51 focused tests passed**, no failures/skips/over-10-second cases. Eight additional offline reproduction cases demonstrate five new defects and the known T-159 accounting defect.
- No source/configuration/environment installation edits, real analyzers, LLVM/SVF binaries, target execution, Docker, providers, services, integration/live/Dagster execution or subagents.
- Severity below describes the **retained manually enabled/replay path**, not an assertion that default review runs execute SVF.

## Activation, retirement and authority

The job remains registered (`runtime/registry.py:91,161`) and its contract dispatches through the review graph after compiled analysis (`jobs/job_svf_alias_analysis/datasets.py:99-106`). Central `settings.enabled=false` (`appsec-review.toml:1799-1800`) excludes it through `runtime/selection.py:11-30` and Dagster filtering (`orchestration/dagster/adapter.py:409-411`). The verification probe returned `default_enabled False`.

`tool-svf` is catalog-enabled but **manual** (`containers/catalog.toml:847-852`), retired from default active-image selection under T-168/T-169. The handler remains functional and has no internal disabled branch: a manually admitted execution still runs its units. `retirement_metadata()` is unconditional and is added only to a successfully reached summary (`job.py:69-77,530-533`), not a disabled-job skip publication. This distinction matters for D01 below.

This is a deterministic native analysis producer, **not** a model worker or a vulnerability-finding producer. No prompt, persona or runtime-skill binding exists for it in the guidance registry; all three declared units call Python handlers. Missing declarative task/tool bindings are the already-open T-147, not evidence that `analyze.scopes` never launches a tool.

## Complete task and implementation trace

All paths in tables below are repository-relative; `job.py` and `planning.py` abbreviate `src/appsec_review/jobs/job_svf_alias_analysis/`.

| Declared step/task | Actual implementation and boundaries | Audit result / limit |
|---|---|---|
| `load.accepted_cpp` | `job.py:492-497`; `cpp_index_scopes.py:54-80,164-205`. Reads the admitted compiled-analysis handoff, verifies its bound unit-execution result and index manifest, enumerates successful catalogs, verifies compile-database hash and each materialized source, freezes scope records; compares accepted handoff source fingerprint to current job. | No compiler/tool call. Missing/failed catalogs retained separately; no-command catalog is unavailable. Accepted-upstream/runtime read accounting was inspected, not exercised through a real JobRunner admission. |
| `analyze.scopes` | `job.py:499-516`. Reloads accepted scopes, checks scope-ID set unchanged, separates unsupported/commandless scopes as `SKIPPED_NA`, uses settings-level bounded thread pool; each runnable scope calls `_analyze_scope`. | Actual three-handler reproduction exercised this task with one worker and fake external boundaries. **K01:** ignores nested scope terminal status and trusts only aggregate string gaps. |
| ↳ scope plan/checkpoint | `job.py:334-350`; `planning.py:55-137`. Partitions supported compile commands in the same order used by the container database; expands archive members recursively; plans linked modules sorted by output and unlinked TUs in compile order; records unresolved/archive/open-world causes and trailing module omissions. Scope checkpoint hashes accepted scope, links, settings, tool identity and adapter. | Planner tests pass. **F03:** raw parser-input identities are omitted from checkpoint result. Historical link-loss upstream defect remains relevant, not a new SVF finding. |
| ↳ scope tool execution | `job.py:352-390`; `cpp_index_scopes.py:223-269`; `containers/tools/svf/svf.py:44-165`. Writes plan plus rebased compile database into fresh scratch, mounts accepted case read-only, invokes one tool per scope. Wrapper compiles needed TUs with clang-18/clang++-18 at `-O0 -g`, links with LLVM 21, invokes repository driver per module. Per-compile and per-module failures are returned, siblings ordinarily continue. | Fake executor and fake process runner only. **F01:** execution-wide output-sized file limit also limits bitcode. |
| ↳ native points-to export | Entire `containers/tools/svf/driver/svf-alias-export.cpp`. Configures field-sensitive AndersenWaveDiff and ExtAPI. Walks non-ExtAPI defined functions/instructions; exports nontrivial loads/stores, pointer arguments of direct calls, pointer ICmp operands and indirect targets. Builds module object keys; records dynamic loaders, pointer inline asm and unmodeled direct externals. | Fully read, not compiled/executed. Native analysis correctness, ExtAPI adequacy, actual field collapsing and LLVM 18→21 debug retention are unverified. |
| ↳ parse, normalize, shard | `job.py:98-244,256-326,391-473`. Bounds result/document bytes; checks envelope/list structure; matches planned module IDs; rejects non-analyzed outcomes and escaping/missing/invalid module output; maps accepted source points; emits points-to, indirect-call, memory-object entities and `REFERENCES`; writes module coverage and SQLite index. | **F02/F04:** set-level incompleteness does not correctly govern all coverage/inverted completeness; malformed nested objects/targets escape validation. **K01:** coverage-only reasons and missing-module cases can disappear from root accounting. |
| `acceptance.publish_handoff` | `job.py:518-536`; `cpp_index_scopes.py:351-397`. Publishes scope and unavailable-scope coverage shards, composes accepted input manifest while replacing only this job's older shards, re-verifies manifest, writes summary with counts/upstream/scopes/gaps/retirement. Runtime subsequently owns common handoff/outcome publication. | Real manifest composition and summary handler exercised in R1/R2; no full runtime admission/finalization. **K01:** copies misleading aggregate status/gap count unchanged. |

The three `Unit` declarations and dependencies exactly match the central topology (`job.py:538-547`); `_validate` checks step ordering, task names and positive settings (`job.py:481-489`). No other task/step was found.

## Accepted inputs and LLVM/build semantics

The typed contract has **21 requirements**, all handoff-channel producer evidence:

| Producer | Declared outputs | Actual job use |
|---|---|---|
| `job_cpp_compiled_analysis` | Required `handoff` (`job-handoff/2`, missing→reject); optional `cpp_build_graph`, `clang_ast`, `llvm_ir`, `infer_observations`, `binary_symbols`, `cpp_blocked_branches` (`retrieval-index/2`); `cpp_plan_and_summary` (`cpp-compiled-analysis/2`); `cpp_case_material` (octet-stream). | Uses handoff-bound result `outputs["catalog.projects"]["projects"]`, accepted source mapping/files, normalized compile commands/database and captured normalized links. It **does not parse accepted `llvm_ir` shards or reuse accepted `.bc`**; it recompiles accepted source/commands into analysis bitcode. Manifest verification is not equivalent to semantic reading of every optional dataset. |
| `job_evidence_collection` | Optional `handoff`, `static_tool_observations`, `static_tool_evidence`, `static_tool_io`. | No direct semantic consumption in these handlers. They may be available through manifest composition; declarations do not establish reads. |
| `job_target_catalog` | Optional `handoff`, `target_artifact_inputs`, `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`, `catalog_documents`. | No direct catalog read by this producer; source admission comes from compiled-analysis case material. |

`accepted_upstream` verifies admitted handoff digest/typed permission and observes the envelope (`runtime/consume.py:162-197`). The C++ loader then directly reads its bound result/database/source files; it has no explicit `observe_output` calls for case material. This is a read-accounting limitation, not a claim of missing byte checks or of unauthorized source acquisition. Full runtime receipt projection was not reproduced here.

`IndexScope.container_compile_database` keeps only `clang:compile-unit` supported paths, normalizes compiler by source suffix and rebases `/scratch/source` and `/scratch/build` to read-only `/target` paths (`cpp_index_scopes.py:36-42,97-142`). Link grouping uses `output_path` / `input_paths`; static archives expand through their captured producer; shared libraries stay external with notes; unmatched units become open-world translation-unit modules. Shared-library external effects are left to driver modeling.

Prior audit overlap: `job-audit-job_cpp_compiled_analysis.md` K01 / historical C08-F01 already establishes that accepted language-build link receipts can be lost in the C++ catalog. SVF consequently receives `link_commands=[]` and treats units as standalone; do **not** count this upstream defect as new here.

## Bounds, identities and output contract

Central settings are explicitly validated; no missing-setting fallback is supplied by the job. Shipped values:

| Group | Settings |
|---|---|
| Scope/parallelism | `workers=2`, `max_modules_per_scope=32` |
| Bytes | bitcode `268435456`, per-module output `8388608`, run-result output `1048576` |
| Export | `field_limit=64`, `max_sites=20000`, `max_pts_size=256`, `max_indirect_calls=20000`, `max_targets_per_call=64`, `max_unmodeled_names=64` |
| Times | compile 120s, link 120s, module 300s, Andersen 240s; Andersen must be less than module limit |
| Object fan-in | `max_objects_per_module=5000`, `max_accessors_per_object=64` |

The tool policy independently fixes 1 GiB, 2 CPUs, 256 PIDs, 600s per scope and bounded stdout/stderr (`containers/tools/svf/tool.toml`). Positive values have no aggregate compile-count/time feasibility check, but whole-scope timeout remains a named failure.

- Plan/run/driver schemas are `svf-plan/1`, `svf-run/1`, `svf-alias-output/1`; domain records are `svf-alias-record/1` and `svf-memory-object/1`; summary is `svf-alias-analysis-handoff/1`.
- Module IDs hash kind, output label and compile indexes; entity IDs additionally include accepted case snapshot, scope ID, module ID, target path, source point/role/operand and same-site ordinal. Object entity IDs include scope/module/object key.
- Driver keys include allocation location/name/field and native base-object node. Shared constant data is explicitly `obj:constant:shared`; unknown/black-hole objects contribute incomplete reasons instead of concrete keys.
- DILocation inlined-at chains resolve to the outermost location. `_Sources.point` computes offsets from verified accepted bytes, gives column zero an ambiguous whole-line location, and counts unmapped sites rather than publishing false target locations. Positive out-of-range columns are clamped in bytes but retained numerically; that edge is not validated by the focused suite.
- `complete` on points-to sites depends on their truncation/incomplete-reasons; indirect calls use only their truncation flag. Module closed-world combines planner, driver and missing-bitcode causes.
- Object inversion keeps heap/stack/global objects only, orders accessors free/write/read/compare/pass then location, bounds retained accessor lists, preserves totals, and emits relations for all located accessors, including those outside the retained list.
- Index fingerprint hashes producer artifact identities, tool/parser/normalizer/mapping identities; deterministic `analysis` shard name includes scope and fingerprint. Module coverage is separate from record payload completeness.
- `Job.strict_gaps` remains false; this job is an explicit legacy free-text-gap entry in `tests/test_gap_contract.py:24`. All emitted terminal strings are in the common vocabulary. The runtime wraps actual strings as producer gaps; it does not inspect arbitrary nested scope objects/SQLite coverage to reconstruct omitted reasons (`runtime/handoff.py:196-264`, `interchange.py:521-568`).

| Dataset | Actual surface and owning declaration |
|---|---|
| `svf_alias_sets` | `analysis` shards `svf-cpp-scope-*`, retrieval-index/2; points-to, indirect-call and memory-object records. |
| `svf_alias_scope_coverage` | `analysis` shards `svf-coverage-*`; semantic cpp-index-coverage/1 declaration for unavailable scope coverage. |
| `svf_alias_summary` | `data/jobs/job_svf_alias_analysis/attempts/*/steps/acceptance/tasks/publish_handoff/*.json`, artifact-only; actual summary filename matches. Glob also captures generic task JSON; exact task/document binding is T-147. |
| `svf_alias_raw` | Protected `data/svf/**`: plan, compile DB, receipts, run-result, module outputs, request/checkpoint files and retained TU bitcode. |

R1's real composed manifest was reloaded and actual scope/coverage shards resolved to their unique intended `DatasetDeclaration` owners. No publication glob/shard-prefix mismatch was found for these two normal outputs. This is not full JobRunner artifact-closure acceptance.

## Direct consumers

- `job_code_graph_index/scopes.py:279-366` selects this job's analysis scope shards (not coverage), restores from accepted producer manifests, and assigns a secondary shard to one native CodeQL scope using located-path overlap.
- `job_code_graph_index/job.py:241,264-280` reads SVF entities and applies `graph/svf_crosscheck.py` after other cross-checks. Source-span-matched indirect targets are unioned; qualified function names are intentionally reduced to tails. Membership may agree; absence only contradicts complete closed-world records. Unresolved CodeQL calls gain ineligible secondary-only facts/relations.
- Guard/sink cross-check joins compare and sink-operand sites within modules; any intersection yields may-alias, and complete disjointness can contradict. **F05** breaks the required incomplete-evidence qualification.
- `review/memory_context.py` reads sites by accepted path/line and object relations, emits lead context with object-first bounded balancing and open-world/incomplete gaps. **F02** can make a genuinely incomplete object appear complete when a lead is at a different, otherwise complete accessor.
- `review/slicing/sources.py:123-166` retrieves accepted sites/objects; `review/slicing/strategies/svf.py` follows object allocation/accessor locations and reports missing/incomplete/bounded context. It relies on the producer's completeness flags.
- Additional typed downstream declarations were found in CodeQL, document issue analysis, review-data indexing, security tagging, OWASP control assessment, review-package assembly and inference review. Their individual business logic was not re-audited; declarations alone do not establish use/citation.

## Findings

### SVF-F01 — Medium — Output-sized process file limit prevents permitted bitcode sizes

**Evidence:** `src/appsec_review/jobs/job_svf_alias_analysis/job.py:360-362` passes `max_module_output_bytes + 1` as the execution-wide file limit. `src/appsec_review/jobs/cpp_index_scopes.py:223-235,256-258` documents/passes that limit for every file; `src/appsec_review/container_runtime/executor.py:48-51,276-277` emits Docker `fsize` ulimit. The wrapper writes TU and linked bitcode in `containers/tools/svf/svf.py:76-85,105-114` before checking the separately larger bitcode bound.

**Trigger / expected / actual:** An otherwise permitted linked/TU bitcode file between approximately 8 MiB and the configured 256 MiB cannot be written under shipped policy. The configured bitcode ceiling is misleading; the output ceiling is imposed on compiler/linker files too. R3 captures the actual request with fixture settings: all-file limit **8,388,609**, allowed bitcode **67,108,864**.

**Impact:** Native scopes fail compile/link or lose units well below the declared module byte budget. This may look like a compiler/linker failure rather than the intended bitcode-size outcome.

**Confidence:** High static/request-level; no kernel-limit/native compiler experiment was run.

**Smallest correction:** Separate output-document limits from compiler/linker artifact limits, or make the process limit cover all authorized artifact maxima and retain explicit bounded output checks. Add a fake-executor regression checking the request's limits.

**TODO overlap:** T-168 retirement reduces default exposure but does not fix this retained path. No exact existing TODO/prior report match found.

### SVF-F02 — High — Truncated points-to sets can publish a complete object with a missing free

**Evidence:** Native set truncation is independent of the global site-count bound (`containers/tools/svf/driver/svf-alias-export.cpp:347-367,374-379`). `job.py:232-241` only adds global site/indirect-call truncation reasons; `_memory_objects` inverts retained sets (`job.py:263-280`) and decides object completeness without any per-site truncation check (`job.py:313-315`). Module status uses these incomplete reasons (`job.py:435-437`). `review/memory_context.py:126-132` trusts record `complete`.

**Trigger / expected / actual:** A free site's bounded points-to set drops an object still referenced by another site. The object's published inverse must be incomplete because a relevant accessor was omitted. R4 uses a valid bounded native-shaped set (`max_pts_size=1`, per-site `truncated=true`, global `sites_truncated=false`). The object remains at its compare site with **`complete=true`, `free_count=0`, `accessor_total=1`**, and its module coverage is **`complete`**.

**Impact:** Downstream memory context can falsely describe a full accessor list without the free, even though raw output correctly says the free's set was truncated. This is distinct from K01: the detailed object/module surfaces are already incorrect before aggregation.

**Confidence:** High; reproduced with actual normalization, inversion and SQLite publication.

**Smallest correction:** Carry per-points-to and per-target truncation into module coverage; conservatively mark inverse objects incomplete when set truncation/unmodeled pointer sites can omit incoming accessors. Preserve the exact reason so consumers do not infer an exhaustive list.

**TODO overlap:** Related to T-159's bounds/accounting topic, but its recorded scope concerns reasons already present in module coverage. This defect removes detailed completeness information itself. T-159 was superseded, not repaired.

### SVF-F03 — Medium — Scope checkpoints do not bind raw result/driver bytes they claim to verify

**Evidence:** `job.py:353,377,420,440-444` collects/hashes raw parser-input artifacts, but `job.py:467-472` omits those identities from the saved result. `cpp_index_scopes.py:283-291,323-339` can verify only references actually present in that result. Reuse returns immediately at `job.py:348-350`.

**Trigger / expected / actual:** After a scope checkpoint, a module document or run result is missing/altered before scope reuse. Documentation promises rejection for damaged matching evidence. R5 deletes its **own fixture** `run/result.json` and one `modules/*/alias.json`; the next analysis reports **`checkpoint_reused=true`**, makes no additional tool request and retains the old shard.

**Impact:** Retained shard provenance can no longer resolve to the parser-input document, or can coexist with changed raw evidence. The raw hash's contribution to an opaque fingerprint is not a retained verifiable reference.

**Confidence:** High; reproduced at the actual scope checkpoint boundary. Full already-accepted-handoff verification could independently catch earlier accepted artifact damage; this case also applies before first aggregate acceptance.

**Smallest correction:** Persist exact raw plan/run/module identities in the checkpoint result (or a bound manifest of them) and require them on reuse. Do not weaken the shared integrity checker.

**TODO overlap:** No exact TODO found. T-159 explicitly excludes a different changed-bounds/frozen-config cache concern; this reproduction keeps settings and accepted scope unchanged.

### SVF-F04 — Medium — Nested driver validation admits malformed success or crashes the entire analysis task

**Evidence:** `job.py:147-168` validates section containers and list lengths, not target elements/object values or target counts. `job.py:224-228` silently discards non-object targets and still marks the row complete; `job.py:270` assumes referenced object values have `.get`. `_module_records`/`_memory_objects` calls are not isolated by a per-module normalization error boundary (`job.py:420-425`). `graph/svf_crosscheck.py:181-188` can contradict from the resulting closed-world empty set.

**Trigger / expected / actual:**

- R6 replaces one native target array with `["copy_handler"]`, `target_count=1`. `_valid_driver_document` accepts it; normalization drops the entry and emits a complete empty set; actual graph cross-check says **`disagree`**, “closed-world SVF target set (empty) excludes copy_handler.”
- R7 uses a string instead of a referenced object document. Validation accepts it, then analysis raises **`AttributeError: 'str' object has no attribute 'get'`** rather than marking only that module unavailable.

**Impact:** Malformed/version-drifted tool output becomes false negative evidence, or one malformed module aborts sibling publication. No claim is made that the current native driver normally emits these malformed shapes.

**Confidence:** High parser-contract reproduction.

**Smallest correction:** Validate required nested primitive types, object values/references, completion flags and counts before normalization; reject inconsistent documents as a named module gap. Do not silently filter malformed members into complete empty sets.

**TODO overlap:** No exact TODO found; T-147 is publication/task binding, not this parser.

### SVF-F05 — High — Alias cross-check drops unmodeled empty operands before its completeness test

**Evidence:** `graph/svf_crosscheck.py:193-203` drops **all** empty `points_to` rows, then tests completeness only on survivors. The native driver explicitly emits empty sets with `pointer_not_modeled` or `unknown_object` (`svf-alias-export.cpp:347-348,352-367,392-409`); these are not proven NULL constants. `graph/svf_crosscheck.py:231-238` can convert `no_alias` into a contradiction against a guard.

**Trigger / expected / actual:** A condition contains one known pointer and another unmodeled pointer; the known set is disjoint from the sink. Missing modeling of the second pointer must prevent a negative answer. R8 calls the actual `_alias` with one complete compare, one empty incomplete `pointer_not_modeled` compare, and a complete disjoint sink: result **`no_alias`**, not `unknown`.

**Impact:** The downstream consumer can disqualify a CodeQL guard as contradicted even though SVF lacks enough information for the negative claim.

**Confidence:** High; direct function reproduction plus inspected caller propagation.

**Smallest correction:** Distinguish proven empty constants from unknown/unmodeled/truncated sets; positive intersections can remain may-alias, but a negative answer must account for every relevant incomplete operand.

**TODO overlap:** Historical design intentionally drops empty constants such as NULL, not unknown modeling failures. No exact existing TODO/prior report match found.

### SVF-K01 — High, known T-159 — Nested partial/failed scopes publish aggregate success

**Evidence:** Missing-module coverage branch `job.py:400-403` adds no gap; normalization reasons remain only in `module_rows` (`job.py:435-438`); scope status accounts for those rows (`job.py:464-466`) but aggregate `analyze` does not (`job.py:511-516`). Acceptance copies the aggregate (`job.py:528-536`). Runtime outcomes do not recurse into scope payloads (`runtime/handoff.py:207-232`).

- **R1, unmodified recorded tool output:** plugin module partial/open-world, scope `COMPLETED_WITH_GAPS`, but analyze/publish **`SUCCEEDED`**, **gap count 0**.
- **R2, otherwise valid run envelope with no module outcomes:** both modules unavailable, scope **`FAILED`**, **0 records**, but publish **`SUCCEEDED`**, **gap count 0**.

**Expected:** Aggregate declared control fields preserve every scope/module's incomplete/unavailable state and cause.

**Smallest correction:** Include missing-module/normalization reasons in canonical aggregate gaps and derive aggregate status from declared scope outcomes, not only nonempty string lists.

**Tracking:** **T-159 (`docs/TODO.md:2671-2693`) explicitly describes the root/module disagreement and is marked done only by supersession through T-168/T-169**. Report this as confirmed residual known behavior, not a new independently discovered issue. R2 strengthens the demonstrated impact from partial coverage to zero-record failed coverage.

### SVF-D01 — Low documentation/retirement drift

- T-168 promises a disabled-job `retired_by_policy_oom` skip notice (`docs/TODO.md:2784`, task plan design item 1). Actual disabled selection omits the job; the only SVF retirement metadata call is in enabled/manual publication (`job.py:531`). No disabled skip summary is implemented in inspected dispatch paths.
- Canonical operations page and standalone SVF operations page still primarily describe ordinary opt-in behavior, not retirement. `docs/operations/svf-alias-analysis.md`'s offline example names old `tests/test_svf_*.py` paths; current map names the relocated `tests/unit/job_svf_alias_analysis/` files.
- T-113 historical walkthrough text (`docs/TODO.md:3781-3787`) says 33 cases and “1-input / 3-dataset”; current job has **34** mapped unit cases, **21 requirements / 4 datasets**. This is historical text, not this audit's test evidence.
- `field_limit_collapsed` is advertised by the standalone operations settings table, but the fully read repository driver has no emitted reason with that name. Actual SVF field-collapse behavior was not run or certified.

T-168/T-147/T-113 overlap; do not infer permission to re-enable or repair retired tooling from these observations.

## Focused validation — exact commands and results

All Linux blocks below were sent through this transport, not executed in the Windows checkout:

```powershell
$script = @'
# the Linux block
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

### Checkout/environment preflight

```bash
cd /home/wsollers/projects/appsec-review
git rev-parse HEAD
git branch --show-current
git status --porcelain
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
.venv/bin/python -c 'from tests.test_000_unit_environment_guard import offending_environment; import os; problems=offending_environment(os.environ); print("unit environment:", problems); assert not problems'
```

Exit 0, exact requested SHA / `main`, empty porcelain, package `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`, `unit environment: []`. No environment repair/installation was needed. The wrapper also ran its normal xdist environment preflight.

### Private collection

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
/usr/bin/time -f 'COLLECTION elapsed=%e exit=%x' .venv/bin/python -m pytest \
  --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-svf-90ff79de-collect1 \
  tests/unit/job_svf_alias_analysis/test_contract.py \
  tests/unit/job_svf_alias_analysis/test_svf_alias_analysis.py \
  tests/unit/job_svf_alias_analysis/test_svf_tool.py \
  tests/graph/test_svf_crosscheck.py
```

**51 collected in 0.38s; wall 1.37s; exit 0.** One collection-only `PytestConfigWarning: Unknown config option: cache_dir` because cacheprovider was explicitly disabled. No tests executed during collection.

### Shuffled parallel execution

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
/usr/bin/time -f 'WRAPPER elapsed=%e exit=%x' scripts/run-tests.sh \
  --parallel --test-workers 2 --shuffle-seed 23047 --strict \
  --max-tests 51 --expect-tests 51 --collection-seconds 30 --timeout-seconds 120 -- \
  tests/unit/job_svf_alias_analysis/test_contract.py \
  tests/unit/job_svf_alias_analysis/test_svf_alias_analysis.py \
  tests/unit/job_svf_alias_analysis/test_svf_tool.py \
  tests/graph/test_svf_crosscheck.py
```

**51 passed in 3.58s; 0 failed, 0 errors, 0 skipped, 0 over 10s; exit 0.**

- Split: contract 5, producer 23, wrapper 6, consumer cross-check 17.
- Wrapper total 9.488755s; shell wall 9.73s. Supervised collection 1.479800s; supervised execution/cleanup 7.646847s.
- Both supervisor phases confirmed cleanup, 0 remaining processes; exact 51-node worker collection proofs.
- Slowest case: `tests/unit/job_svf_alias_analysis/test_contract.py::test_registry_and_central_config_parity`, **1.122438s**, passed.
- Wrapper-private session/base: `test/tmp/tests-custom-20261118-123919-247890-2954148`.
- Log: `test/tmp/logs/tests-custom-20261118-123919-247890-2954148.log`.
- JUnit: `test/tmp/tests-custom-20261118-123919-247890-2954148.junit.xml`.
- Timings: `test/tmp/tests-custom-20261118-123919-247890-2954148.timings.sqlite`.
- Report: `test/tmp/reports/tests-custom-20261118-123919-247890-2954148.json`.
- Collection manifest: `test/tmp/tests-custom-20261118-123919-247890-2954148.collection.json`.

Existing tests assert individual scope/record properties but do not catch root-status disagreement, raw-checkpoint omission, global-vs-per-set inverse completeness, malformed target filtering or empty-unmodeled operand loss. Passing tests do not certify native correctness.

### Offline reproductions R1–R8

Command: after the same `set -eu`, `cd`, exact-HEAD check, ran
`/usr/bin/time -f 'REPRO elapsed=%e exit=%x' .venv/bin/python - <<'PY'`
with the following complete Python body. All tool/process work is replaced at external boundaries; actual parsing, normalization, indexing, manifest composition and cross-check functions run.

```python
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch
import json, os, sqlite3, time
from tests.fixtures.svf.builder import SETTINGS, LINK_COMMANDS, ReplayExecutor, scope, unit
from appsec_review.jobs.job_svf_alias_analysis import build_job
from appsec_review.jobs.job_svf_alias_analysis import job as j
from appsec_review.jobs.job_svf_alias_analysis.planning import plan_modules
from appsec_review.indexing.store import ShardSet
from appsec_review.graph.svf_crosscheck import read_svf, SvfShard, _Row, _alias
from tests.graph.test_svf_crosscheck import _call, _run as crosscheck, _svf_entry, CALL
from appsec_review.runtime import UnitContext
from appsec_review.retrieval import write_manifest
os.umask(0o022)
base=Path('test/tmp/job-audit-svf-90ff79de-repro1').resolve()
base.mkdir(parents=True, exist_ok=False)
start=time.monotonic()

def run(name, mutate=None, settings=None):
    root=base/name
    s=scope(root); u=unit(root, settings); ex=ReplayExecutor(root, mutate=mutate)
    result=j._analyze_scope(u,s,LINK_COMMANDS,lambda _:ex)
    return root,s,u,ex,result

def coverage(root, result):
    with sqlite3.connect(root/result['index_identity']['relative_path']) as db:
        return list(db.execute('SELECT area,status,gap FROM coverage ORDER BY area'))

def entities(root, result):
    return list(ShardSet(root,[result['index_identity']]).entities([result['index_identity']]))

def pipeline(name, mutate=None):
    root=base/name; s=scope(root); u=unit(root); u.job.run_id=root.name
    ex=ReplayExecutor(root, mutate=mutate)
    accepted={'handoff':{'source_fingerprint':u.job.source_fingerprint},'handoff_sha256':'e'*64,
              'manifest':{'path':'upstream.json'},'result':{'outputs':{'catalog.projects':{
                  'projects':{s.case_id:{'link_commands':LINK_COMMANDS}}}}}}
    job=build_job(executor_factory=lambda _:ex)
    handlers={x.unit_id:x.handler for x in job.units}
    upstream=root/'upstream.json'
    from appsec_review.storage import file_sha256
    write_manifest(upstream,run_id=root.name,target_snapshot=u.job.source_fingerprint,
                   target_root=u.job.target_root,indexes=[])
    def context(id,outputs):
        step,task=id.split('.')
        location=root/'data'/'jobs'/j.JOB_ID/'attempts'/'attempt_0001'/'steps'/step/'tasks'/task
        location.mkdir(parents=True,exist_ok=True)
        return UnitContext(u.job,id,step,task,location,MappingProxyType(outputs))
    with patch.object(j,'accepted_cpp_scopes',return_value=(accepted,[s],{})):
        loaded=handlers['load.accepted_cpp'](context('load.accepted_cpp',{}))
        analyzed=handlers['analyze.scopes'](context('analyze.scopes',{'load.accepted_cpp':loaded}))
    with patch('appsec_review.retrieval.core.resolve_context_manifest',return_value=(upstream,file_sha256(upstream))):
        published=handlers['acceptance.publish_handoff'](context('acceptance.publish_handoff',{
            'load.accepted_cpp':loaded,'analyze.scopes':analyzed}))
    return root, analyzed, published

root,analyzed,published=pipeline('root-accounting')
assert analyzed['scopes'][0]['terminal_status']=='COMPLETED_WITH_GAPS'
assert analyzed['terminal_status']==published['terminal_status']=='SUCCEEDED'
assert published['counts']['gap_count']==0
print('R1 root-accounting',json.dumps({'scope':analyzed['scopes'][0]['terminal_status'],
     'analyze':analyzed['terminal_status'],'publish':published['terminal_status'],
     'gap_count':published['counts']['gap_count'],'coverage':coverage(root,analyzed['scopes'][0])}))
root,analyzed,published=pipeline('missing-modules',lambda d,o:d.update(modules=[]))
assert analyzed['scopes'][0]['terminal_status']=='FAILED' and published['terminal_status']=='SUCCEEDED'
print('R2 missing-modules',json.dumps({'scope':analyzed['scopes'][0]['terminal_status'],
     'publish':published['terminal_status'],'records':published['item_count'],
     'gap_count':published['counts']['gap_count']}))

root,s,u,ex,result=run('fsize')
request=ex.requests[0]
assert request.file_size_limit_bytes==SETTINGS['max_module_output_bytes']+1
assert request.file_size_limit_bytes<SETTINGS['max_module_bitcode_bytes']
print('R3 fsize',json.dumps({'all_files_limit':request.file_size_limit_bytes,
     'module_bitcode_limit':SETTINGS['max_module_bitcode_bytes']}))

lost={}
def truncate(d,outputs):
    app=next(outputs[m['module_id']] for m in d['modules'] if m['kind']=='link')
    free=next(x for x in app['sites'] if x['file'].endswith('/guard.c') and x['line']==19 and x['role']=='call_arg')
    lost['key']=free['points_to'][0]
    app['objects']['obj:constant:shared']={'kind':'constant','name':'constant data','field':0}
    free['points_to']=['obj:constant:shared']; free['truncated']=True
    assert not app['sites_truncated']
root,s,u,ex,result=run('per-site-truncation',truncate,{**SETTINGS,'max_pts_size':1})
obj=next(x for x in entities(root,result) if x['kind']=='memory_object' and x['payload']['object_key']==lost['key'])
assert obj['payload']['complete'] is True and obj['payload']['accessor_counts']['free']==0
assert next(row[1] for row in coverage(root,result) if row[0].endswith('build/app'))=='complete'
print('R4 truncated-inverse',json.dumps({'object_complete':obj['payload']['complete'],
     'free_count':obj['payload']['accessor_counts']['free'],'accessor_total':obj['payload']['accessor_total'],
     'module_coverage':next(row for row in coverage(root,result) if row[0].endswith('build/app'))}))

root,s,u,ex,result=run('checkpoint')
scratch=root/'data'/'svf'/s.scope_id/'run'
raw=scratch/'result.json'
output=next((scratch/'modules').glob('*/alias.json'))
raw.unlink(); output.unlink()
second=j._analyze_scope(u,s,LINK_COMMANDS,lambda _:ex)
assert second['checkpoint_reused'] is True and len(ex.requests)==1
print('R5 checkpoint',json.dumps({'raw_result_exists':raw.exists(),'driver_output_exists':output.exists(),
      'checkpoint_reused':second['checkpoint_reused'],'tool_requests':len(ex.requests)}))

def bad_targets(d,outputs):
    app=next(outputs[m['module_id']] for m in d['modules'] if m['kind']=='link')
    call=app['indirect_calls'][0]; call['targets']=['copy_handler']; call['target_count']=1
    assert j._valid_driver_document(app,SETTINGS) is None
root,s,u,ex,result=run('malformed-target',bad_targets)
svf=read_svf(ShardSet(root,[result['index_identity']]),result['index_identity'])
fact=_call(CALL,'native/callbacks.c','copy_handler','function_pointer_resolved')
_,by_id=crosscheck([fact],[svf]); entry=_svf_entry(by_id[fact.identity.value])
assert entry['state']=='disagree'
print('R6 malformed-target',json.dumps(entry))

def bad_object(d,outputs):
    app=next(outputs[m['module_id']] for m in d['modules'] if m['kind']=='link')
    key=next(x['points_to'][0] for x in app['sites'] if x['points_to'])
    app['objects'][key]='not-an-object'
    assert j._valid_driver_document(app,SETTINGS) is None
try:
    run('malformed-object',bad_object)
except AttributeError as e:
    print('R7 malformed-object',type(e).__name__,str(e))
else:
    raise AssertionError('malformed object unexpectedly accepted without failure')

shard=SvfShard('analysis','svf-cpp-scope-test','d'*64)
def row(identity,points,complete,why=()):
    return _Row(identity,'points_to_set',{'module_id':'m-one','points_to':points,'complete':complete,
       'module_closed_world':True,'incomplete_reasons':list(why)},'source.c',1,1,shard)
answer=_alias([row('known',['obj:a'],True),row('unknown',[],False,('pointer_not_modeled',))],
              [row('sink',['obj:b'],True)])
assert answer=='no_alias'
print('R8 unknown-empty-operand',answer)
print('CORE_SECONDS',round(time.monotonic()-start,4))
```

**Exit 0; core 0.3353s; shell 0.97s.** The expected incorrect behaviors were asserted; these are defect demonstrations, not eight passing correctness regressions. R7's caught exception is explicitly reported, not concealed as an analyzer success. R1/R2 mock upstream acquisition and resolve an independently written empty upstream manifest; they do not claim to exercise typed upstream admission.

Post-run verification loaded R1's manifest with `load_verified_manifest`, resolved both actual shards using `shard_owner(DATASETS, ...)`, read wrapper JSON/timings, and rechecked HEAD/status. **0.902s core**, exit 0; dataset owners and exact revision matched. No native/live output was inspected.

## Evidence read and remaining coverage

**Read fully**

- Shared brief; authorized `AGENTS.md` and coordination skill.
- `jobs/job_svf_alias_analysis/{__init__,job,planning,datasets}.py`.
- `jobs/cpp_index_scopes.py`; `graph/svf_crosscheck.py`.
- `containers/tools/svf/{svf.py,Dockerfile,tool.toml,README.md}` and all of repository-owned `driver/svf-alias-export.cpp`.
- Canonical and standalone SVF operations pages; historical `docs/architecture/svf-alias-producer.md`; T-168 task plan.
- All three mapped SVF unit files and `tests/graph/test_svf_crosscheck.py`; `tests/fixtures/svf/builder.py` and recorded `result.json`.
- `review/memory_context.py`, `review/slicing/strategies/svf.py`.
- `runtime/selection.py`, `runtime/consume.py`, `runtime/units.py`; unit test guard and environment guard.
- `scripts/run-tests.sh`, `scripts/lib/common.sh`, `deploy/dagster/bin/ops_test_guard.py`.

**Read relevant ranges / searched**

- Central TOML and catalog SVF entries; guidance registry; registry/topology/Dagster selection and direct graph job consumption.
- `runtime/{handoff,runner,inputs,datasets}.py`, `interchange.py`, executor file-size request/Docker argv; `jobs/bound_artifacts.py`; source-slicing accepted SVF joins.
- `docs/architecture/job-interchange.md` through native-reference sections; testing architecture/safety/selector passages; TODO T-147/T-159/T-168/T-169 and SVF/T-113 references; prior cumulative, compiled-analysis and image-pin audit matches.
- Test root conftest safety/collection/timing sections; wrapper argument/build/run/report/supervision code; job-test-map exact selection; graph secondary fixture constants/fact/location builders.
- Recorded module documents were programmatically read in full by replay/reproductions, but manually inspected only for module metadata, bounds and relevant site/object/target records. This is not an independent manual audit of every recorded native row.

**Material unread / unverified**

- SVF upstream source/binaries, ExtAPI implementations, LLVM compiler/linker libraries, asset archives/license payloads, actual image contents and any real target/run-owned evidence.
- No integration/acceptance/live suite, runtime JobRunner claim/final-handoff execution, real container file-size enforcement, native driver compilation or analysis. The kernel consequence in F01 is static/request evidence, not an executed LLVM experiment.
- Other jobs' implementations beyond direct input/output contract and consumer passages; complete retrieval/storage/publication assurance stack; other memory/slicing package suites; every profile and deployment variation.
- Missing-debug-location loss before driver export, indirect-external modeling, field-collapse soundness, object/module identity behavior across multiple accepted build configurations and malformed positive columns remain unverified edge coverage, not additional confirmed findings.
- Retirement does not repair the retained manual/historical path; no recommendation here authorizes enabling it or changing its policy.

Validation logs, JUnit, collection proofs and timing report are retained under the private wrapper prefix. After verification, removed only this audit's `test/tmp/job-audit-svf-90ff79de-repro1`, collection-only `.host-pins.toml`, and wrapper base-temp test-case directory. Cleanup took **0.0693s**; final HEAD remained the exact requested commit and `git status --porcelain` was empty. Repository-root files were inspected; unrelated existing material was left untouched. No other auditor's scratch was removed.
