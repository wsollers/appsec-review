---
title: "CBMC bounded analysis"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_cbmc_analysis"]
last reconciled: "b9aad27b40ea7e3cb52080254c1f7e60f1fa0556"
---
# CBMC bounded analysis

`job_cbmc_analysis` adds bounded function-entry analysis to eligible, accepted C/C++ scanner
leads before review indexing. It is enabled by default, uses no model, and never executes a
target binary. See the [design and artifact contract](../architecture/cbmc-bounded-analysis.md).

## Provisioning and configuration

Provision [`tool-cbmc`](../../containers/tools/cbmc/README.md) on the review host, update its
host-local image binding and sign/verify it with the existing operator policy. The job
requires the catalog tag and immutable configured image ID to agree. Do not copy another
host's image ID, provision new keys implicitly, or rebuild the image for application-code edits.

The central `[jobs.job_cbmc_analysis.settings]` table selects:

| Bound | Default |
| --- | --- |
| Native scopes / seeds per scope | 8 / 32 |
| Total translation units / function entries | 8 / 16 |
| Command timeout / analysis launch deadline | 45 s / 300 s |
| Increasing unwind limits | 8, 32 |
| Native stdout/stderr / GOTO file | 4 MiB / 64 MiB |
| Source staging | 10,000 files / 128 MiB per scope |
| GOTO instructions / properties | 100,000 / 2,000 |
| Indexed property summaries / trace steps / value characters | 16 / 24 / 200 |

The existing executor retains its no-network, read-only, non-root, 1 GiB memory, two-CPU,
256-PID boundary. Each tool command is wrapped with the image's `timeout`, reserving three
seconds within its outer deadline for termination/cleanup. Its expected deadline exit is
an inconclusive tool result, not a verification pass. Resource admission remains governed by
the central queue; the analysis launch deadline does not bound earlier input verification
or later index publication. Guardian cancellation, OOM/fatal execution policy stops and input
integrity failures propagate; the job does not catch or bypass `ReviewStopped`.

Set `settings.enabled = false` to omit the job from a newly resolved graph. Frozen runs
retain their original configuration and must not be edited to follow this setting.
Disabling a producer or selecting no eligible seeds never establishes safety.

## Read the result

The load step retains `plan.json`, including exact selected source/compile identities and
selection omissions. The analysis step retains its source-only input copies, GOTO binaries,
function tables, native solver JSON and container receipts under the attempt's
`artifacts/cbmc/` tree. Only files bound by the accepted source mapping reach the container:
unlisted workspace files and symlink ancestors cannot supply headers.

The acceptance step publishes result and coverage shards plus `summary.json`. Results use
the existing **`review_signal`** entity kind, which is indirect for every security predicate.
They do not become duplicate scanner leads. Source-mapped property and trace previews remain
bounded; omitted preview data is counted and the complete bounded native artifact is retained.

Inspect the judgment, function-entry assumptions, source hashes, unwind limits, property
statuses, model warnings and coverage together:

- `counterexample_candidate`: a source-mapped safety-property failure with a retained trace,
  conditional on this entry model; not exploitability or caller-reachability proof.
- `bounded_pass`: nonempty consistent successful properties, with unwinding assertions and no
  model warning; not an automatic false-positive dismissal.
- `inconclusive`: no accepted positive/negative conclusion; examine the named gap and receipt.
- `not_attempted`: a selection, staging, function or time budget prevented analysis.

No eligible native work produces `NOT_APPLICABLE`; missing applicable build/scanner evidence
or omitted supported work produces canonical producer gaps. Review packages join results by
the originating observation IDs **and exact source hash/line range**, include their bounded
previews and preserve missing/partial coverage. Existing review adjudication, dossiers and
publication gates remain authoritative.

## Manual validation boundary

Focused units fake only external container/upstream service boundaries and exercise parsing,
selection, source custody, publication, consumer joins, budgets and evidence classification.
They are not a real-engine or Dagster acceptance claim. A separately authorized trial should
cover a real accepted safe/failing native pair, sufficient/insufficient unwinding, an external
body gap, unsupported C++, deadline exhaustion and end-to-end finding-package visibility.
Do not run a target merely because this job or image is now registered.

<!-- generated:begin job=job_cbmc_analysis -->
<!-- generated from: appsec-review.toml, containers/catalog.toml, pipeline/guidance/registry.json, tests/job-test-map.json, src/appsec_review/runtime/registry.py, src/appsec_review/runtime/contracts.py, src/appsec_review/runtime/datasets.py, src/appsec_review/guidance/workers.py, src/appsec_review/mcp/schema.py, src/appsec_review/orchestration/topology.py, src/appsec_review/orchestration/dagster/adapter.py by scripts/generate-docs.py; do not edit -->
## Declared job contract

cbmc_analysis

Job: `job_cbmc_analysis`. Enabled in the dev recipe: **true**.
Declarations describe possible work, not successful execution or consumed evidence.

### Steps and tasks

| Step | Task | Workers | Pool | Bound tool or gap | Handler |
| --- | --- | --- | --- | --- | --- |
| `acceptance` | `acceptance.publish_handoff` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cbmc_analysis/job.py#L338) |
| `analyze` | `analyze.bounded_checks` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cbmc_analysis/job.py#L328) |
| `load` | `load.accepted_inputs` | 1 | `application` | Undeclared ([T-147](../TODO.md)) | [source](../../src/appsec_review/jobs/job_cbmc_analysis/job.py#L322) |

### Accepted input declarations

| Producer | Dataset | Schema | Channel | Availability | Missing policy |
| --- | --- | --- | --- | --- | --- |
| `job_target_catalog` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_target_catalog` | `source_files` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | when_producer_enabled | reject |
| `job_cpp_compiled_analysis` | `cpp_plan_and_summary` | `appsec-review/cpp-compiled-analysis/2` | handoff | optional | gap |
| `job_cpp_compiled_analysis` | `cpp_case_material` | `application/octet-stream` | handoff | optional | gap |
| `job_evidence_collection` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_evidence_collection` | `static_tool_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |
| `job_codeql_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_codeql_analysis` | `codeql_observations` | `appsec-review/codeql-sarif-normalizer/3` | handoff | optional | gap |
| `job_clang_static_analysis` | `handoff` | `appsec-review/job-handoff/2` | handoff | optional | gap |
| `job_clang_static_analysis` | `clang_static_observations` | `appsec-review/retrieval-index/2` | handoff | optional | gap |

### Published dataset declarations

| Dataset | Step | Schema | Stage | Indexes | MCP route |
| --- | --- | --- | --- | --- | --- |
| `cbmc_coverage` | `acceptance` | `appsec-review/retrieval-index/2` | indexed | `observations` | `coverage` |
| `cbmc_plan` | `load` | `appsec-review/cbmc-plan/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |
| `cbmc_raw` | `analyze` | `application/octet-stream` | protected | Not indexed | `coverage`, `query_dataset_inventory` |
| `cbmc_results` | `acceptance` | `appsec-review/retrieval-index/2` | indexed | `observations` | `find`, `search` |
| `cbmc_summary` | `acceptance` | `appsec-review/cbmc-summary/1` | artifact_only | Not indexed | `coverage`, `query_dataset_inventory` |

Protected and artifact-only routes expose sanitized metadata, not payload access.

### Model and guidance declarations

No job-level model declaration; absence of a task binding remains [T-147](../TODO.md), not a nonexecution claim.

### Test selection

| Tier | Files or selectors |
| --- | --- |
| acceptance | None declared |
| integration | None declared |
| live | None declared |
| unit | `tests/unit/job_cbmc_analysis/test_cbmc_analysis.py` |

### Dagster placement

Dispatch: `review_graph`. Review graph member: **true**. Enabled graph member: **true**.

Declared predecessors: `job_codeql_analysis`.

### Declared dataflow

```mermaid
flowchart LR
  job["job_cbmc_analysis"]
  producer0["job_target_catalog"]
  input0["handoff"]
  input_schema0["appsec-review/job-handoff/2"]
  producer0 --> input0 --> job
  input0 -. schema .-> input_schema0
  producer1["job_target_catalog"]
  input1["source_files"]
  input_schema1["appsec-review/retrieval-index/2"]
  producer1 --> input1 --> job
  input1 -. schema .-> input_schema1
  producer2["job_cpp_compiled_analysis"]
  input2["handoff"]
  input_schema2["appsec-review/job-handoff/2"]
  producer2 --> input2 --> job
  input2 -. schema .-> input_schema2
  producer3["job_cpp_compiled_analysis"]
  input3["cpp_plan_and_summary"]
  input_schema3["appsec-review/cpp-compiled-analysis/2"]
  producer3 --> input3 --> job
  input3 -. schema .-> input_schema3
  producer4["job_cpp_compiled_analysis"]
  input4["cpp_case_material"]
  input_schema4["application/octet-stream"]
  producer4 --> input4 --> job
  input4 -. schema .-> input_schema4
  producer5["job_evidence_collection"]
  input5["handoff"]
  input_schema5["appsec-review/job-handoff/2"]
  producer5 --> input5 --> job
  input5 -. schema .-> input_schema5
  producer6["job_evidence_collection"]
  input6["static_tool_observations"]
  input_schema6["appsec-review/retrieval-index/2"]
  producer6 --> input6 --> job
  input6 -. schema .-> input_schema6
  producer7["job_codeql_analysis"]
  input7["handoff"]
  input_schema7["appsec-review/job-handoff/2"]
  producer7 --> input7 --> job
  input7 -. schema .-> input_schema7
  producer8["job_codeql_analysis"]
  input8["codeql_observations"]
  input_schema8["appsec-review/codeql-sarif-normalizer/3"]
  producer8 --> input8 --> job
  input8 -. schema .-> input_schema8
  producer9["job_clang_static_analysis"]
  input9["handoff"]
  input_schema9["appsec-review/job-handoff/2"]
  producer9 --> input9 --> job
  input9 -. schema .-> input_schema9
  producer10["job_clang_static_analysis"]
  input10["clang_static_observations"]
  input_schema10["appsec-review/retrieval-index/2"]
  producer10 --> input10 --> job
  input10 -. schema .-> input_schema10
  output0["cbmc_coverage"]
  output_schema0["appsec-review/retrieval-index/2"]
  job --> output0
  output0 -. schema .-> output_schema0
  output1["cbmc_plan"]
  output_schema1["appsec-review/cbmc-plan/1"]
  job --> output1
  output1 -. schema .-> output_schema1
  output2["cbmc_raw"]
  output_schema2["application/octet-stream"]
  job --> output2
  output2 -. schema .-> output_schema2
  output3["cbmc_results"]
  output_schema3["appsec-review/retrieval-index/2"]
  job --> output3
  output3 -. schema .-> output_schema3
  output4["cbmc_summary"]
  output_schema4["appsec-review/cbmc-summary/1"]
  job --> output4
  output4 -. schema .-> output_schema4
```

<!-- generated:end -->
