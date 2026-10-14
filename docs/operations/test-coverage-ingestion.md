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
max_artifacts = 256
max_artifact_bytes = 33554432
max_rows_per_artifact = 250000
max_files_per_artifact = 50000
max_path_candidates = 20
```

The configured topology is `load.accepted_inputs`, `normalize.coverage`, `index.coverage`, then
`acceptance.publish_handoff`. Parser and mapping identity changes invalidate shards.

## Expected artifacts

Build producers must place coverage files in their run-owned workspace and enumerate them in the
accepted language-build receipt with path, workspace path, size, kind, and SHA-256. Recognized
names include LCOV `.info`/`.lcov`, Cobertura or generic `coverage.xml`, `jacoco.xml`, and LLVM
coverage JSON names. A producer may also use an artifact kind containing `coverage`; if the bytes
do not identify a supported format, the job records `unsupported_coverage_format`.

The accepted output is under the job attempt's `artifacts/test-coverage/` directory. Retrieval
shards use the `analysis` index and `test-coverage-` prefix. Downstream code should call
`load_accepted_test_coverage(run_root)` rather than selecting a latest file directly.

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

Run the focused suite with:

```text
pytest -q tests/test_test_coverage.py --basetemp=test/tmp/test-coverage
```

The suite covers all four formats, catalog SHA binding, aggregate metrics, malformed and bounded
inputs, absent applicable coverage, and accepted handoff/manifest verification.
