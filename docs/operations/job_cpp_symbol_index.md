---
title: "cpp_symbol_index"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_cpp_symbol_index"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---

# cpp_symbol_index

## Purpose

Recover compiler-aware symbol definitions, declarations and reference/call neighborhoods from
accepted C/C++ compile scopes using clangd. These are navigation and cross-check facts, not
vulnerabilities or proof that every dynamic call is known. Symbols outside accepted sources are
counted but not indexed as source evidence.

<!-- generated:begin job=job_cpp_symbol_index -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

cpp_symbol_index

Job: `job_cpp_symbol_index`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cpp_symbol_index/job.py#L300) |
| `index` | `index.scopes` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cpp_symbol_index/job.py#L284) |
| `load` | `load.accepted_cpp` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cpp_symbol_index/job.py#L275) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_cpp_compiled_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | required | reject |
| `job_cpp_compiled_analysis` | `cpp_build_graph` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `clang_ast` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `llvm_ir` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `infer_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `binary_symbols` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_blocked_branches` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_plan_and_summary` | `appsec-review/cpp-compiled-analysis/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_case_material` | `application/octet-stream` | handoff | optional | gap |
| `job_evidence_collection` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_evidence` | `appsec-review/static-tool-evidence/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_io` | `appsec-review/container-execution/1` | handoff | optional | gap |
| `job_target_catalog` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_target_catalog` | `target_artifact_inputs` | `appsec-review/target-artifact-intake/1` | handoff | optional | gap |
| `job_target_catalog` | `source_files` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `declaration_symbols` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `components` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `target_documents` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `build_units` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_target_catalog` | `catalog_documents` | `appsec-review/target-catalog/1` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `clangd_coverage` | `acceptance` | `appsec-review/cpp-index-coverage/1` | indexed | `analysis` | `coverage` |
| `clangd_summary` | `acceptance` | `appsec-review/cpp-symbol-index/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `clangd_symbols` | `index` | `appsec-review/retrieval-index/2` | indexed | `analysis` | `find`, `query_precomputed`, `trace` |
| `clangd_tool_io` | `index` | `appsec-review/container-execution/1` | protected | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/test_cpp_index_jobs.py::test_symbol_index_publishes_accepted_symbols_with_complete_coverage` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_cpp_compiled_analysis`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_cpp_symbol_index"]
  producer0["job_cpp_compiled_analysis"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_cpp_compiled_analysis"]
  input1["cpp_build_graph"]
  input_schema1["appsec-review/retrieval-index/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_cpp_compiled_analysis"]
  input2["clang_ast"]
  input_schema2["appsec-review/retrieval-index/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_cpp_compiled_analysis"]
  input3["llvm_ir"]
  input_schema3["appsec-review/retrieval-index/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_cpp_compiled_analysis"]
  input4["infer_observations"]
  input_schema4["appsec-review/retrieval-index/2"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_cpp_compiled_analysis"]
  input5["binary_symbols"]
  input_schema5["appsec-review/retrieval-index/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_cpp_compiled_analysis"]
  input6["cpp_blocked_branches"]
  input_schema6["appsec-review/retrieval-index/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_cpp_compiled_analysis"]
  input7["cpp_plan_and_summary"]
  input_schema7["appsec-review/cpp-compiled-analysis/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_cpp_compiled_analysis"]
  input8["cpp_case_material"]
  input_schema8["application/octet-stream"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_evidence_collection"]
  input9["handoff"]
  input_schema9["appsec-review/job-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_evidence_collection"]
  input10["static_tool_observations"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_evidence_collection"]
  input11["static_tool_evidence"]
  input_schema11["appsec-review/static-tool-evidence/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_evidence_collection"]
  input12["static_tool_io"]
  input_schema12["appsec-review/container-execution/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["handoff"]
  input_schema13["appsec-review/job-handoff/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_catalog"]
  input14["target_artifact_inputs"]
  input_schema14["appsec-review/target-artifact-intake/1"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["source_files"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["declaration_symbols"]
  input_schema16["appsec-review/retrieval-index/2"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["components"]
  input_schema17["appsec-review/retrieval-index/2"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_target_catalog"]
  input18["target_documents"]
  input_schema18["appsec-review/retrieval-index/2"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  producer19["job_target_catalog"]
  input19["build_units"]
  input_schema19["appsec-review/retrieval-index/2"]
  producer19 --> input19 --> job
  input19 -. schema .-> input_schema19
  producer20["job_target_catalog"]
  input20["catalog_documents"]
  input_schema20["appsec-review/target-catalog/1"]
  producer20 --> input20 --> job
  input20 -. schema .-> input_schema20
  output0["clangd_coverage"]
  output_schema0["appsec-review/cpp-index-coverage/1"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["clangd_summary"]
  output_schema1["appsec-review/cpp-symbol-index/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["clangd_symbols"]
  output_schema2["appsec-review/retrieval-index/2"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["clangd_tool_io"]
  output_schema3["appsec-review/container-execution/1"]
  job --> output3
  output3 -. schema .-> output_schema3
```

<!-- generated:end -->

## Process

Source: [job and normalizer](../../src/appsec_review/jobs/job_cpp_symbol_index/job.py),
[strict YAML parser](../../src/appsec_review/jobs/job_cpp_symbol_index/clangd_yaml.py), and
[accepted scope helpers](../../src/appsec_review/jobs/cpp_index_scopes.py).
Tool binding omissions in the generated metadata remain
[T-147](../TODO.md);
the executed tool is resolved in the handler, not inferred from that table.

### `load`

1. Read the accepted compiled-analysis result and manifest through the
   [input contract](../architecture/job-input-contracts.md). Require this snapshot.
2. Verify each successful catalog's compile database and materialized source mapping. Retain
   unsuccessful catalogs or catalogs without commands as unavailable cases, not empty scopes.

### `index`

1. Re-load scopes and reject changes to the planned scope-ID set. Partition compile commands by
   declared Clang support; scopes with no supported commands become `SKIPPED_NA` without launch.
2. In bounded parallel scope workers, check the per-scope checkpoint. Otherwise invoke
   `tool-clangd-indexer` over rewritten accepted compile commands using `--executor=all-TUs`
   and YAML output. [Image pinning](image-pin-verification.md) and
   [signing](signing.md) remain shared launch gates.
3. Compare stderr's processed translation units with the supported database, then parse only the
   supported YAML document subset. Preserve timeout, OOM, exit, output truncation, missing units,
   malformed document and document-cap reasons.
4. Accept unique clangd IDs with an accepted definition or canonical declaration, preferring the
   definition. Convert zero-based positions to accepted source locations. Count external-only
   symbols separately; enforce symbol bounds.
5. Link retained reference containers and targets: call-bit references become `CALLS`, others
   `REFERENCES`. Aggregate repeated edges with occurrence counts and bounded locations; count
   unresolved references without inventing edges. Enforce relation bounds.
6. Publish one analysis shard per scope and save its checkpoint. Coverage is unavailable for a
   failed exit with no symbols, partial with reasons, complete otherwise.

### `acceptance`

1. Compose scope shards plus unavailable-scope coverage with the upstream manifest.
2. Write `cpp-symbol-index-summary.json`, retaining upstream identity, per-scope results, counts
   and reasons. Item count is accepted symbols; external symbols are not included.

## Dataflow

```mermaid
flowchart LR
  cpp["accepted compiled catalogs + source maps"] --> job["job_cpp_symbol_index"]
  job --> scopes["load.accepted_cpp"]
  scopes --> run["index.scopes: clangd-indexer"]
  run --> yaml["strict YAML normalization"]
  yaml --> facts["analysis: symbols + CALLS / REFERENCES"]
  facts --> publish["acceptance.publish_handoff"]
  run -. "failed / truncated / missing translation units" .-> gaps["scope coverage reasons"]
  yaml -. "malformed / capped" .-> gaps
  gaps --> publish
  scopes -. "changed accepted bytes" .-> stop["integrity exception"]
```

## Gaps

The source emits text reasons. [Interchange](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope)
wraps them as `producer_reported_gap`, normally non-retryable; this does not make them advisory.

- Input absent or upstream failed: unavailable accepted catalog and no compile commands. Unsupported
  compile units are explicit `SKIPPED_NA` decisions, not missing supported-unit failures.
- Tooling failure: clangd timeout, OOM or nonzero exit; malformed YAML and an incomplete final
  document also prevent trustworthy full coverage.
- Coverage missing: processed/expected translation-unit mismatch, truncated stdout, document,
  symbol and relation limits. External symbols and unresolved references are separate counters,
  not automatically gap records or evidence of complete resolution.
- Changed source/database/manifest or a matching checkpoint with missing/changed evidence is an
  integrity exception, not a successfully published gap.

Check each cause and its affected scope against the walk's user-approved expected list.

## Acceptance

1. **A. Inputs:** Match compiled handoff/result/manifest identities, source-map hashes and normalized
   compile database to admitted inputs; account for supported versus skipped commands.
2. **B. Independent comparison:** Compare clangd stderr's processed-file set with supported command
   files. Count accepted versus external YAML symbols independently; resolve sampled declaration
   spans against source bytes and compare call-bit references to stored edges and occurrence counts.
3. **C. Gaps:** Group verified outcome records and compare each missing unit, parse failure or
   truncation to raw stdout/stderr and configured bounds; record unsupported inputs separately and
   stop for any unapproved cause.
4. **D. Baseline:** On authorized acceptance, save the corpus namespace and `stepwise.py accept`
   baseline with symbol/edge counts and translation-unit sets. This documentation is not live
   clangd acceptance.

## Resume and invalidation

The scope checkpoint binds schema, scope/source/compile identities, normalizer, tool pin and all
index limits except worker count. Reuse verifies its shard, execution receipt and rewritten
database as well as accepted inputs; a matching but damaged checkpoint fails closed.
Partial outputs can be checkpointed by this producer: unchanged inputs do not promise a retry.
A tool/source/compile/normalizer/limit change invalidates that scope, while other scopes remain
independent. Composition follows [accepted index sets](../architecture/python-and-retrieval.md#accepted-index-sets).
