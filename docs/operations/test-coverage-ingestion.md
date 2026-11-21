---
title: "Operating test-coverage ingestion"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_language_build", "job_test_coverage"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Operating test-coverage ingestion

`job_test_coverage` runs after target cataloging, language builds, and artifact indexing. It imports
coverage that target build workflows already produced. It must never be used to invoke a target
test runner.

## Configuration

The central job configuration supplies these version identities:

```toml
parser_identity = "appsec-review/test-coverage-parsers/1"
normalizer_identity = "appsec-review/test-coverage-normalizer/1"
mapping_identity = "appsec-review/test-coverage-source-binding/1"
applicable_families = ["native", "go", "dotnet", "node", "python", "rust", "php", "java", "wasm"]

[jobs.job_test_coverage.settings.bounds]
max_artifacts = 10000
max_artifact_bytes = 268435456
max_rows_per_artifact = 1000000
max_files_per_artifact = 100000
max_path_candidates = 32
```

The configured topology is `load.accepted_inputs`, `normalize.coverage`, `index.coverage`, then
`acceptance.publish_handoff`. Parser and mapping identity changes invalidate shards.

## Expected artifacts

Build producers must place coverage files in their run-owned workspace and enumerate them in the
accepted language-build receipt with path, workspace path, size, kind, and SHA-256. Recognized
names (`job_language_build/node.py`) are `lcov`, `lcov.info`, `coverage.lcov`, `cobertura.xml`,
`cobertura-coverage.xml`, `coverage.xml`, `jacoco.xml`, `jacocoreport.xml`,
`jacocotestreport.xml`, `coverage.json`, `coverage-final.json` and `*.coverage.json`; any other
file is picked up only when its artifact kind contains `coverage`. If the bytes do not identify a
supported format, the job records `unsupported_coverage_format`. Receipts whose family is not in
`applicable_families` are skipped and get no shard. The parser, normalizer and mapping identities
in the settings must equal the code constants; any other value fails configuration loading.

JaCoCo's standard `report` PUBLIC declaration with public identifier
`-//JACOCO//DTD Report 1.1//EN` and system identifier `report.dtd` is accepted without loading the
DTD. Internal subsets, user-defined entity declarations/expansion, unknown identifiers and
malformed declarations
remain refused. This exception does not apply to Cobertura. Detection and declaration preflight
use original bytes under the existing artifact/node bounds. The validated header is removed only
from the in-memory tree input, preventing silently omitted unresolved attribute entities; neither
report bytes nor their hashes are rewritten.
Oversized JSON integer tokens and excessive JSON nesting produce artifact-scoped
`malformed_coverage` gaps without aborting valid siblings.

The accepted output is under the job attempt's `artifacts/test-coverage/` directory. Retrieval
shards use the `analysis` index and `test-coverage-` prefix, exposed through
`query_engineering_signals signal_family=test_coverage` with optional exact source-path filtering.
File cells retain `producer_path`, accepted artifact path/hash, and catalog file identity; only the
separate build aggregate is build-wide review context. Identical report bytes at distinct accepted
paths retain distinct provenance and the overlap gap. Downstream code should call
`load_accepted_test_coverage(run_root)` rather than selecting a latest file directly.

The checked-in `appsec-multi-vuln` reports are deterministic parser/source-binding fixtures marked
`provenance: "fixture"` and retained as `artifact_origin: "accepted-input"`. They are not live test
measurements. Reports emitted by an accepted build/test workflow use
`artifact_origin: "build-output"`; only those can describe that execution.

## Gap triage

Common gap prefixes have stable operational meaning:

| Gap | Operator action |
| --- | --- |
| `missing_applicable_coverage` | Configure the existing build/test workflow to emit a supported report and catalog it in the build receipt. |
| `unsupported_coverage_format` | Export LCOV, Cobertura, JaCoCo, or LLVM JSON, or add a bounded parser in a schema revision. |
| `malformed_coverage` | Inspect the hash-identified run artifact; do not infer zero coverage. |
| `artifact_byte_bound`, `artifact_count_truncation`, `coverage_file_truncation` | Decide whether central limits should increase or reports should be partitioned. |
| `unresolved_source_path` | Configure the producer to emit target-relative source paths. |
| `ambiguous_source_path`, `path_candidate_truncation` | Remove basename/path ambiguity or preserve a more specific producer path. |
| `overlapping_coverage_reports` | Prefer one merged report with line-level union semantics. |

Integrity errors are different from coverage gaps. A changed hash, escaped path, unaccepted
handoff, or invalid manifest stops publication and leaves the previous accepted pointer unchanged.

## Verification

Use the owning Linux checkout and editable environment. Collect the four focused unit files first:

```sh
.venv/bin/python -m pytest --collect-only -q --basetemp=test/tmp/test-coverage-collect \
  tests/unit/job_test_coverage/test_parsers.py tests/unit/job_test_coverage/test_ingestion.py \
  tests/unit/job_test_coverage/test_job_graph.py tests/unit/job_test_coverage/test_contract.py
```

Then substitute the inspected count for `N` in this guarded command:

```sh
scripts/run-tests.sh --expect-tests N --max-tests 200 --parallel --test-workers 2 \
  --shuffle-seed 20261120 --strict -- \
  tests/unit/job_test_coverage/test_parsers.py tests/unit/job_test_coverage/test_ingestion.py \
  tests/unit/job_test_coverage/test_job_graph.py tests/unit/job_test_coverage/test_contract.py
```

These units exercise synthetic standard-format report bytes, all four parsers, duplicate source
accounting, artifact/path/hash binding, malformed and bounded inputs, real index/retrieval/context
delivery, and a real runtime coverage publication consumed by prioritization with pinned read
receipts. They do not generate measurements by executing target tests.

`tests/live/test_multivuln_coverage_fixtures.py` is a **manual, explicitly authorized live-tier
check**, not an automatic gate when a target checkout happens to exist. It verifies the target's
19 project records and four fixture reports against the parser and source binder; this proves
fixture ingestion, not live test measurements or security coverage. Follow the
[testing workflow](../architecture/testing.md#working-loop) before selecting it.
