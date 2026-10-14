# Test-coverage ingestion

See [`engineering-security-signals.md`](engineering-security-signals.md) for this producer's place
in the combined engineering-signal data flow and downstream review boundary.

`job_test_coverage` turns test coverage already emitted by accepted builds into bounded review
signals. It does not run tests, discover commands, or scan the target or build trees. Coverage is a
prioritization and review-completeness signal; it is not evidence that covered code is secure or
that uncovered code is vulnerable.

## Accepted inputs and trust boundary

The job verifies the accepted handoffs for `job_target_catalog`, `job_language_build`, and
`job_artifact_indexing`. Candidate coverage files come only from artifact identities enumerated in
accepted language-build receipts. Before parsing, each candidate must remain a regular,
non-symlink, run-owned file with the accepted SHA-256. The accepted artifact-index manifest is
verified in full and becomes the upstream manifest of the coverage shards.

Coverage data, producer paths, XML, JSON, and build metadata are untrusted data. The parsers do
not resolve external entities and reject DTD/entity declarations. Artifact bytes, parser rows,
source rows, candidate files, and retained path candidates all have central bounds. A bound hit is
a named gap rather than a silent subset.

## Formats and normalization

The generic parser API accepts:

- LCOV records (`SF`, `DA`, `BRDA`, `FN`, and `FNDA`);
- Cobertura XML class, line, branch, and method records;
- JaCoCo XML source-file counters plus class method counters; and
- LLVM `llvm-cov export` JSON file summaries.

Every source record normalizes to line, branch, and function totals and covered counts. Rates are
derived from those integers and are `null` when the corresponding denominator is zero. Counts are
published for each report source row and as build-unit aggregates. If multiple accepted reports
cover the same source path, their additive aggregate is retained with an
`overlapping_coverage_reports` gap because a lossless union is impossible without common
line-level observations.

## Source identity binding

Producer paths never become source identities by themselves. Binding is against the accepted
target-catalog inventory:

1. use an exact target-relative path when available;
2. otherwise accept only one suffix match; and
3. retain zero or multiple candidates as unresolved or ambiguous rows.

A bound row includes the exact accepted catalog path and its catalog SHA-256. Unknown paths,
ambiguous paths, and candidate-list truncation are named gaps. They remain in the handoff and
retrieval shard so consumers can distinguish missing mapping from zero coverage.

## Publication contract

One immutable `analysis` shard named `test-coverage-<build-unit-id>` is produced for each
applicable accepted build receipt. It contains `coverage_cell` entities for source rows and the
build-unit aggregate, plus a scoped `complete`, `partial`, or `unavailable` coverage row. A
successful applicable receipt with no coverage artifact publishes
`missing_applicable_coverage`.

The immutable handoff uses `appsec-review/test-coverage-handoff/1` and records exact upstream
handoff hashes, parser/normalizer/mapping identities, per-unit rows and totals, aggregate totals,
all gaps, and the verified composed retrieval manifest. Accepted loading rechecks handoff binding,
artifact hashes, manifest identity, every manifest shard, and recursive upstream manifests.

The reusable implementation is independent of Dagster:

- `parse_coverage` parses one bounded byte string;
- `bind_coverage_paths` binds normalized rows to accepted catalog identities;
- `ingest_coverage_artifacts` processes accepted receipts without executing anything; and
- `load_accepted_test_coverage` verifies accepted publication for downstream workflows.
