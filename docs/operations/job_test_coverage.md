---
title: "test_coverage"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_test_coverage"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---

# test_coverage

## Purpose

Normalize coverage reports enumerated by accepted builds and ask how much reported line, branch
and function coverage can be bound to the accepted source inventory. The job never executes tests,
searches for undeclared reports, or infers test quality or security from a percentage. Unresolved
paths remain visible but do not enter bound-source totals.

<!-- generated:begin job=job_test_coverage -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

test_coverage

Job: `job_test_coverage`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_test_coverage/job.py#L390) |
| `index` | `index.coverage` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_test_coverage/job.py#L333) |
| `load` | `load.accepted_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_test_coverage/job.py#L313) |
| `normalize` | `normalize.coverage` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_test_coverage/job.py#L327) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_artifact_indexing` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_catalog` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `archive_members` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_relationships` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_artifact_indexing` | `artifact_index_summary` | `appsec-review/artifact-indexing/1` | handoff | optional | gap |
| `job_language_build` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_language_build` | `topology_refinement_inputs` | `appsec-review/build-topology-refinement/1` | handoff | optional | gap |
| `job_language_build` | `build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `jvm_build_actions` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_language_build` | `language_build_receipts` | `appsec-review/language-build-handoff/2` | handoff | optional | gap |
| `job_language_build` | `build_workspaces` | `application/octet-stream` | handoff | optional | gap |
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
| `test_coverage` | `index` | `appsec-review/retrieval-index/2` | indexed | `analysis` | `query_precomputed` |
| `test_coverage_handoff` | `acceptance` | `appsec-review/test-coverage-handoff/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/test_test_coverage.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_artifact_indexing`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_test_coverage"]
  producer0["job_artifact_indexing"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_artifact_indexing"]
  input1["artifact_catalog"]
  input_schema1["appsec-review/retrieval-index/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_artifact_indexing"]
  input2["archive_members"]
  input_schema2["appsec-review/retrieval-index/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_artifact_indexing"]
  input3["artifact_relationships"]
  input_schema3["appsec-review/retrieval-index/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_artifact_indexing"]
  input4["artifact_index_summary"]
  input_schema4["appsec-review/artifact-indexing/1"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_language_build"]
  input5["handoff"]
  input_schema5["appsec-review/job-handoff/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_language_build"]
  input6["topology_refinement_inputs"]
  input_schema6["appsec-review/build-topology-refinement/1"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_language_build"]
  input7["build_actions"]
  input_schema7["appsec-review/retrieval-index/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_language_build"]
  input8["jvm_build_actions"]
  input_schema8["appsec-review/retrieval-index/2"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_language_build"]
  input9["language_build_receipts"]
  input_schema9["appsec-review/language-build-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_language_build"]
  input10["build_workspaces"]
  input_schema10["application/octet-stream"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  producer11["job_target_catalog"]
  input11["handoff"]
  input_schema11["appsec-review/job-handoff/2"]
  producer11 --> input11 --> job
  input11 -. schema .-> input_schema11
  producer12["job_target_catalog"]
  input12["target_artifact_inputs"]
  input_schema12["appsec-review/target-artifact-intake/1"]
  producer12 --> input12 --> job
  input12 -. schema .-> input_schema12
  producer13["job_target_catalog"]
  input13["source_files"]
  input_schema13["appsec-review/retrieval-index/2"]
  producer13 --> input13 --> job
  input13 -. schema .-> input_schema13
  producer14["job_target_catalog"]
  input14["declaration_symbols"]
  input_schema14["appsec-review/retrieval-index/2"]
  producer14 --> input14 --> job
  input14 -. schema .-> input_schema14
  producer15["job_target_catalog"]
  input15["components"]
  input_schema15["appsec-review/retrieval-index/2"]
  producer15 --> input15 --> job
  input15 -. schema .-> input_schema15
  producer16["job_target_catalog"]
  input16["target_documents"]
  input_schema16["appsec-review/retrieval-index/2"]
  producer16 --> input16 --> job
  input16 -. schema .-> input_schema16
  producer17["job_target_catalog"]
  input17["build_units"]
  input_schema17["appsec-review/retrieval-index/2"]
  producer17 --> input17 --> job
  input17 -. schema .-> input_schema17
  producer18["job_target_catalog"]
  input18["catalog_documents"]
  input_schema18["appsec-review/target-catalog/1"]
  producer18 --> input18 --> job
  input18 -. schema .-> input_schema18
  output0["test_coverage"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["test_coverage_handoff"]
  output_schema1["appsec-review/test-coverage-handoff/1"]
  job --> output1
  output1 -. schema .-> output_schema1
```

<!-- generated:end -->

## Process

Source: [handler and path binding](../../src/appsec_review/jobs/job_test_coverage/job.py),
[format parsers](../../src/appsec_review/jobs/job_test_coverage/parsers.py).

### `load`

1. Read the accepted catalog's repository partition; verify artifact binding, schema, unique paths
   and SHA-256 values. Load accepted language-build and artifact-index publications and require
   their snapshots to match this job.
2. Retain catalog path/hash map, build receipts, three upstream handoff hashes and the artifact
   manifest. Admission is governed by [job input contracts](../architecture/job-input-contracts.md).

### `normalize`

1. Sort build receipts, filter configured applicable families, and select enumerated coverage
   exchange paths or coverage kinds. Cap candidate count; verify each report's origin and bytes.
   An integrity failure stops rather than publishing an unsupported-report gap.
2. Skip oversized artifacts; detect LCOV, Cobertura, JaCoCo or LLVM coverage JSON. Parse within
   format row/node bounds and cap source-file rows. Unsupported or malformed reports contribute
   reasons, never invented zero counters.
3. Normalize separators, file URI and drive prefixes. Try exact catalog paths and build-root
   variants first, then unique suffixes. Bind only one match; preserve unresolved/ambiguous rows
   with null path/hash and bounded candidate lists.
4. Record overlapping bound paths across reports, but retain and sum their rows rather than
   deduplicating coverage. Sum only bound rows into build-unit totals. Successful or partially
   successful receipts without candidates emit `missing_applicable_coverage`. No bound rows is
   unavailable; any gaps with bound rows is partial.

### `index`

1. Verify the inherited manifest and replace only `test-coverage-` analysis shards.
2. Fingerprint each build unit with accepted report identities, snapshot, parser/normalizer/mapping
   and upstream manifest. Write file coverage-cell entities, one aggregate cell and a coverage row,
   or reuse the fingerprint-addressed file.
3. Compose and verify `test-coverage-<attempt>.json`; do not turn unbound cells into source locations.

### `acceptance`

1. Write `accepted-test-coverage.json` with all units, summed totals, upstream hashes and manifest.
2. Publish unit count, not file count, as the item count; use completed-with-gaps when reasons exist,
   success when units exist without gaps, otherwise not-applicable.

## Dataflow

```mermaid
flowchart LR
  receipts["accepted build coverage artifacts"] --> job["job_test_coverage"]
  catalog["accepted catalog path/hash map"] --> job
  job --> parse["normalize.coverage: LCOV / XML / LLVM"]
  parse --> bind["exact or unique-suffix binding"]
  bind --> index["index.coverage: file + aggregate coverage cells"]
  index --> publish["acceptance.publish_handoff: test_coverage_handoff"]
  parse -. "malformed / unsupported / bounds" .-> gaps["legacy reasons"]
  bind -. "unresolved / ambiguous / overlap" .-> gaps
  gaps --> publish
  job -. "changed accepted identity" .-> stop["integrity exception"]
```

## Gaps

The handler emits legacy reasons; [interchange](../architecture/job-interchange.md#the-control-layer-beneath-the-envelope)
converts them to `producer_reported_gap` with non-retryable metadata. Non-retryable is not advisory.

- Input absent: `missing_applicable_coverage` for an applicable successful build without candidates.
- Present but unsupported: `unsupported_coverage_format`.
- Coverage missing or failed: `malformed_coverage`, `artifact_count_truncation`,
  `artifact_byte_bound`, `coverage_file_truncation`, `unresolved_source_path`,
  `ambiguous_source_path`, `path_candidate_truncation`, `overlapping_coverage_reports`.
  Parser failures include negative/inconsistent counts, invalid LCOV ordering, invalid JSON/XML,
  forbidden XML declarations and exceeded parser bounds. Overlap can inflate totals: it is not a
  successful report merge.
- `CoverageIntegrityError` covers missing/bad accepted publication, duplicate catalog paths,
  changed report hashes, invalid origin and snapshot mismatch. These failures are not normal gap
  publications.

No listed cause is automatically approved for a walk; missing applicable coverage has a stated cost.

## Acceptance

1. **A. Inputs:** Compare admitted catalog, language-build and artifact-index handoff hashes;
   reconcile report paths/hashes/origins and family selection against receipts.
2. **B. Independent comparison:** Independently count covered/total lines, branches and functions in
   retained tool-native reports; compare exact and suffix-bound file identities against the catalog.
   Recalculate totals excluding unresolved rows and explicitly account for overlapping reports.
3. **C. Gaps:** Read verified outcomes, group canonical records with their retained reasons, and
   compare skipped reports, ambiguous candidates and omitted rows with the input inventory and
   walk's approved expected causes.
4. **D. Baseline:** At authorized acceptance, use `stepwise.py accept` and record corpus namespace,
   saved baseline, report identities, bound/unbound counts and totals for a future diff. This page
   is not evidence that tests or live acceptance ran.

## Resume and invalidation

Per-unit shards bind report identities, source snapshot, parser/normalizer/mapping versions and
upstream artifact manifest; changed reports rebuild that unit without replacing unrelated indices.
The handler's local fingerprint does not explicitly bind bounds or family settings, so a settings
change alone is not a documented guarantee of shard invalidation. Runtime receipt reuse has the
separate [configuration boundary](../architecture/jobs-and-runtime.md#wave-1-resumability).
The accepted reader verifies both document and full manifest. Generated task binding omissions
remain [T-147](../TODO.md);
they do not authorize interpreting this producer as a test runner.
