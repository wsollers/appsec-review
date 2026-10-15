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

The accepted output is under the job attempt's `artifacts/test-coverage/` directory. Retrieval
shards use the `analysis` index and `test-coverage-` prefix. Downstream code should call
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

Run the focused suite with:

```text
pytest -q tests/test_test_coverage.py --basetemp=test/tmp/test-coverage
```

The suite covers all four formats, catalog SHA binding, aggregate metrics, malformed and bounded
inputs, absent applicable coverage, and accepted handoff/manifest verification.

When the ignored `targets/appsec-multi-vuln` checkout is available, also run:

```text
pytest -q tests/test_multivuln_coverage_fixtures.py --basetemp=test/tmp/multivuln-coverage
```

That suite verifies the target's 19 project records and four fixture reports against the production
parser and source binder. It proves fixture ingestion, not live test execution or security coverage.
