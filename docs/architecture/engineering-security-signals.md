# Engineering security signals

This page is the canonical cross-workflow design for the engineering-signal producers added
to the review graph. The component contracts remain in
[`clang-static-analysis.md`](clang-static-analysis.md),
[`test-coverage-ingestion.md`](test-coverage-ingestion.md),
[`profile-data.md`](profile-data.md), and
[`dependency-intelligence.md`](dependency-intelligence.md); operator procedures are linked below.

The workflows turn already accepted build and evidence material into bounded, immutable review
signals. They do not scan a live target tree during inference, run target tests, execute produced
binaries, or treat missing data as a clean result.

## End-to-end placement

```text
accepted target catalog
        |
        +--> accepted language builds --> artifact index --> test coverage --+
        |          |                           |              profile data --+|
        |          |                           +-----------------------------+|
        |          +--> C/C++ compiled scopes --> Clang static --+--> accepted index set
        |          |                                             |    and review-data audit
        |          +--> native receipts/artifacts ---------------+             |
        |                                                                        v
        +--> evidence collection/Syft --> dependency intelligence ------> review packages
                                               |
                                               +--> bounded model resolution
                                               +--> OpenSSF Scorecard
```

The direct graph in `appsec_review.cli.GRAPH_JOB_IDS` and the Dagster wave encode the same ordering:

- `job_test_coverage` follows `job_artifact_indexing`;
- `job_profile_data` follows `job_artifact_indexing`;
- `job_clang_static_analysis` follows `job_cpp_compiled_analysis`;
- `job_dependency_intelligence` follows the accepted catalog, language-build, artifact-index, and
  evidence-collection producers (Dagster also waits for C/C++ compiled analysis when present); and
- all four precede `job_review_data_indexing`, which audits their declared datasets and composes
  the accepted run view.

Their job handlers, parsers, resolver, clients, and index builders have no Dagster dependency.
Dagster schedules units; the application runtime remains authoritative for configuration hashes,
attempts, checkpoints, receipts, validation, immutable handoffs, manifests, and accepted pointers.

## Contracts at a glance

| Producer | Accepted inputs | Accepted output | Queryable representation |
| --- | --- | --- | --- |
| `job_clang_static_analysis` | `job_cpp_compiled_analysis` handoff; accepted source map and normalized `compile_commands.json` per C/C++ scope | `appsec-review/clang-static-analysis-handoff/1` | `observations` shards `clang-static-<scope-id>` plus unavailable-scope coverage shards |
| `job_test_coverage` | `job_target_catalog`, `job_language_build`, and `job_artifact_indexing` handoffs; hash-listed coverage artifacts | `appsec-review/test-coverage-handoff/1` | `analysis` shard `test-coverage-<build-unit-id>` for every applicable receipt |
| `job_profile_data` | `job_target_catalog`, `job_language_build`, and `job_artifact_indexing` handoffs; hash-listed execution-profile artifacts | `appsec-review/profile-data-handoff/1` | `analysis` shard `profile-data-<build-unit-id>` for every accepted receipt |
| `job_dependency_intelligence` | `job_target_catalog`, `job_language_build`, `job_artifact_indexing`, and `job_evidence_collection` handoffs | `appsec-review/dependency-intelligence-handoff/1` | one `inventory` shard `dependency-intelligence` |

Every input is resolved through `data/jobs/<job-id>/latest.json` to an accepted
`appsec-review/job-handoff/1` and then rechecked by path, hash, schema, and source snapshot where
applicable. A latest pointer is not evidence by itself.

The principal payload schemas and locations are:

| Payload | Schema | Run-owned source |
| --- | --- | --- |
| Target inventory and declarations | `appsec-review/target-catalog/1`; dependency subcatalog `appsec-review/dependency-catalog/1` | accepted `job_target_catalog` publication |
| Build receipts and coverage identities | `appsec-review/language-build-handoff/1` | accepted `job_language_build` publication and its receipt-referenced workspace artifacts |
| Indexed produced artifacts | `appsec-review/artifact-indexing/1` | accepted `job_artifact_indexing` summary and verified `artifacts` manifest shard |
| C/C++ analysis scopes | `appsec-review/cpp-compiled-analysis/2`; protected commands `appsec-review/protected-compile-commands/1` | accepted `job_cpp_compiled_analysis` publication and receipt-referenced protected files |
| SBOM/package observations | `appsec-review/retrieval-index/2` entities from producer `tool-syft` | accepted `job_evidence_collection` observations shards |

Consumers use the producer-specific accepted loaders where one exists, rather than opening an
attempt or SQLite file by guessed path.

Interpretation is deliberately narrower than successful ingestion:

| Signal | May support | Never establishes by itself |
| --- | --- | --- |
| Clang diagnostic | a source-resolved analyzer lead and bounded trace to review | a confirmed vulnerability, exploitability, or clean coverage when no diagnostic appears |
| Coverage cell | counts from one hash-bound report and review-completeness context | that tests ran for the current checkout when the origin is `accepted-input`, that covered code is safe, or that uncovered code is vulnerable |
| Dependency record | a normalized identity candidate, evidence-backed or conservative exposure priority, and bounded advisory nomination | production deployment, affected-version applicability, repository/artifact equivalence, or a vulnerability finding |
| Scorecard record | practices reported for one resolved public source repository | a vulnerability finding, package applicability, or provenance of the accepted artifact bytes |
| Profile hotspot | relative event/sample hotness within one accepted build unit | defect probability, attacker-controlled reachability, severity, or safety of cold code |

## C/C++ Clang analysis

Each accepted compiled scope runs two independent actions from the pinned
`tool-clang-static-analysis` image:

- Clang-Tidy with the configured check globs; and
- Clang Static Analyzer through `clang --analyze` with the configured checker families.

The accepted source snapshot is mounted read-only, runtime networking is disabled, and only
run-owned scratch is writable. The job replays compilation context for analysis but does not build
the project or execute target-produced code. The strict adapter output schema is
`appsec-review/clang-static-output/1`. Each accepted diagnostic becomes a `tool_observation` with
category `source_sast`, rule and message data, bounded analyzer trace, and an exact location mapped
back to the accepted target-relative path and file SHA-256.

Raw compile databases, rewritten commands, analyzer documents, streams, and execution receipts
remain protected under `data/clang-static/<scope-id>/`. Retrieval-visible records contain bounded
facts and resolving hashes, not raw protected commands. One engine may complete while the other
records a gap; valid observations are not discarded.

The job is applicable only to accepted C/C++ scopes. A scope with no compile commands remains
`unavailable`; a scope whose compile units are all outside Clang support (assembly, CUDA) is
`SKIPPED_NA` in `not_applicable_scopes` and never launched (`job_clang_static_analysis/job.py`).
Missing
image/tooling, timeout, OOM, nonzero exit, output truncation, malformed or over-limit results, and a
diagnostic that cannot resolve through the accepted source map are per-scope gaps.

## Test-coverage ingestion

Coverage ingestion imports reports that accepted builds already retained. It never invokes a test
runner. Candidate files must be regular, non-symlink run artifacts enumerated by an accepted
language-build receipt and must still match their accepted SHA-256. The parser accepts:

| Format | Accepted structure |
| --- | --- |
| LCOV | `SF`, `DA`, `BRDA`, `FN`, and `FNDA` records |
| Cobertura | XML class, line, branch, and method records |
| JaCoCo | XML source-file counters and class method counters |
| LLVM | `llvm-cov export` JSON file summaries |

XML external entities and DTD/entity declarations are rejected. Each source row normalizes line,
branch, and function covered/total counts; rates are derived and remain `null` for a zero
denominator. Producer paths are data, not source identities: the binder accepts an exact
target-relative catalog path, otherwise one unique suffix match, and retains unresolved or
ambiguous candidates as gaps. A bound row includes the catalog path and catalog file SHA-256.

Each applicable build unit publishes source `coverage_cell` entities, a build-unit aggregate, and
`complete`, `partial`, or `unavailable` coverage. Multiple reports for one source are added but
also produce `overlapping_coverage_reports`, because the available summaries cannot express a
lossless line-level union. A successful applicable receipt without a report produces
`missing_applicable_coverage`, not zero coverage.

### Deterministic multivuln fixtures

`targets/appsec-multi-vuln` contains four small reports—one for each accepted format—declared in
`support/project-matrix.json` with `provenance: "fixture"`. They name real files and are used to
prove parser and source-binding behavior deterministically without installing every target
toolchain. Language-build retains them as `artifact_origin: "accepted-input"`, and coverage rows
preserve that origin.

Those fixtures are corpus inputs, not measurements of tests run against the current checkout.
Live coverage must be emitted by an actual accepted build/test workflow, cataloged in its receipt,
and appears as `artifact_origin: "build-output"`. A fixture can validate ingestion mechanics; it
cannot support a claim about current test execution, reachability, or security.

## Dependency identity and Scorecard context

Dependency intelligence merges three classes of accepted observation:

1. declared dependencies from the target catalog's `appsec-review/dependency-catalog/1`;
2. package/SBOM observations from accepted Syft `tool_observation` entities; and
3. native evidence from protected compiler/linker rows, accepted artifact loader metadata, and
   hash-bound `.pc`, `*Config.cmake`, or `*-config.cmake` files in accepted workspaces.

Native parsing recognizes `-lfoo`, `-l:libfoo.so`, forwarded `-Wl` arguments, archive/shared
library paths, Windows import names, frameworks, ELF loader dependencies and SONAMEs. Every native
candidate retains the supporting command id/hash, artifact hash, or metadata path/hash. Metadata
fields are bounded and interpreted only as identity hints; they never authorize execution.

Records deduplicate by purl when available, otherwise normalized name plus version/constraint.
Every normalized record also carries a bounded, evidence-backed `maximal_exposure` from the ordered
vocabulary `DEV < DEBUG < QA < PREPROD < PROD`. Development, debug, test/QA, staging/preproduction,
and runtime/production observations are retained even when they conflict, and the maximum wins.
When no accepted observation establishes scope, the job conservatively emits `PROD` with basis
`conservative-default`; this prioritizes investigation and is not proof of production deployment.
Canonical HTTPS repository metadata on the configured public-forge allowlist wins. Only unresolved
native candidates may use model inference. The model receives one bounded candidate and an
evidence-reference allowlist plus the registered runtime skill, persona, role, and task. Its
`appsec-review/native-dependency-resolution-proposal/1` response is schema-validated, restricted to
configured hosts, limited to confidence `0.95`, and remains
`exact_repository_identity: false` until corroborated by accepted metadata.

After dependency resolution, `repositories.deduplicate` groups dependencies by canonical public
forge identity. Scorecard retrieval consumes that repository inventory, so dependencies that map
to the same repository share one cache lookup and at most one bounded HTTP retrieval per run. The
result is associated back to every referring dependency without collapsing package, version,
provenance, exposure, SBOM, or advisory identities.

The client first checks the content-addressed cache rooted at the centrally configured
repository-relative path. A fresh entry must be within `cache_max_age_seconds` and pass pointer,
path, size, and SHA-256 verification. Fresh hits avoid HTTP; stale and missing entries are refreshed.
Corrupt entries and failed cache writes become dependency-scoped gaps while a bounded remote
attempt may still proceed. Cache blobs use exact successful response bytes, atomic pointers, and a
bounded per-repository writer lock.

Remote retrieval uses only the configured HTTPS API and host allowlist, follows no redirects or
repository-provided endpoint, and enforces request-count, response-byte, timeout, and retry limits.
Successful normalized records use `appsec-review/openssf-scorecard-record/1`. Whether cached or
fetched, exact successful response bytes are copied into the run-owned Scorecard task directory and
referenced by SHA-256. Bounded HTTP error or malformed response bytes are also retained when
available.

Every dependency remains in the output even when repository identity or Scorecard context is
missing. The dependency-scoped gap kinds are `unresolved_repository`, `unsupported_host`,
`scorecard_not_found`, `scorecard_rate_limit`, `scorecard_request_failure`,
`scorecard_malformed_response`, `scorecard_cache_invalid`, `scorecard_cache_write_failure`,
`repository_bound`, `model_unavailable`, `model_failure`, and `bounds`. The accepted handoff also
records unique-repository, cache-hit, and HTTP-request counts. Scorecard context describes the
resolved source repository's practices; it does not prove that accepted artifact bytes came from
that repository and is not a vulnerability finding.

The inventory therefore enriches the review's SBOM/package context without rewriting the original
SBOM or changing its evidence identity. Every normalized dependency, including linker/loader and
model-assisted identities, is offered to the bounded `dependency_advisories` OSV/CVE lookup and to
Scorecard retrieval when it has a supported repository identity. Inventory-to-OSV package matches
remain applicability-unverified until a scanner or version-range evaluator corroborates the
observed version. Direct package evidence remains the accepted SBOM, lockfile, manifest, or artifact
observation; inferred repositories, advisory candidates, and Scorecards remain bounded reference
context.

## Execution-profile ingestion

`job_profile_data` imports profile reports already retained by accepted language-build receipts. It
never launches a profiler, runs a target binary, or deserializes executable/pickle data. Textual
folded stacks, perf-script output, Callgrind, and LLVM sample profiles are normalized into bounded
function or symbol event counts. Recognized opaque gmon, pprof protobuf, LLVM raw, and LLVM indexed
profiles remain explicit unsupported-format gaps until a pinned converter is introduced.

Each row retains its report hash, format, artifact origin, build unit, symbol, event, count, and any
available module/source/line. Deterministic ranks describe relative hotness only within a build
unit. They are `context_only`, are not findings, and do not estimate defect probability. Review
packages may use them to direct attention to highly exercised or operationally important code, but
must combine them with reachability, unsafe behavior, complexity, change history, coverage, static
analysis, and deployment exposure before making a security claim.

## Trust, provenance, and integrity

The trust boundary is crossed only through accepted handoffs and hash-bound run artifacts. Target
files and guidance, build output, compiler arguments, coverage reports, SBOM fields, package
metadata, model output, remote responses, and logs are untrusted data. In particular:

- paths must stay inside the run or accepted workspace and symlinks are rejected where inputs are
  expected to be regular files;
- source and artifact identities are SHA-256 bound before parsing;
- parser, normalizer, mapping, adapter, tool, checker, configuration, guidance, upstream handoff,
  and target-snapshot identities participate in checkpoint or shard fingerprints;
- immutable SQLite shard metadata and row counts are verified before accepted loading; and
- changed hashes, escaped paths, wrong schemas, contradictory manifests, or unbound artifacts are
  framework-integrity failures that stop publication and do not advance the accepted pointer.

Producer limitations have different semantics. Unsupported, absent, failed, truncated, timed-out,
or ambiguous analysis may complete with explicit gaps and `COMPLETED_WITH_GAPS`. Such a gap is
unknown coverage, never affirmative evidence that the target, dependency, or source file is clean.

## Outputs, handoffs, and consumers

Run-owned outputs are retained beneath `runs/<run-id>/data/`:

- immutable attempts and accepted pointers under `jobs/<job-id>/`;
- protected Clang material under `clang-static/`;
- raw Scorecard responses under the dependency job attempt's
  `steps/scorecards/tasks/fetch/artifacts/scorecards/`;
- normalized immutable SQLite shards under `indices/observations/`, `indices/analysis/`, and
  `indices/inventory/`; and
- composed, hash-verified index manifests under `indices/manifests/`.

Downstream behavior is deliberately narrower than the available context:

- Clang observations join the `source_sast` scanner-correlation and finding-lead path. They are
  security leads requiring review, not confirmed findings.
- Coverage cells attach by exact source path and build unit to lane-B review packages. Coverage is
  review-completeness and hunt context; it does not currently change the numeric LPS and neither
  covered nor uncovered status is a security conclusion.
- Profile hotspots attach by source path when available and by build unit otherwise. They seed
  hotspot context but do not change numeric prioritization, finding severity, or verification rules.
- Dependency and Scorecard entities are balanced under the normal context cap so a large package
  inventory cannot evict all Scorecard seeds. They seed supply-chain/security-review and red-team
  hunting context; truncation is an explicit package gap.
- The `dependency_advisories` precomputed route combines accepted scanner matches and normalized
  dependency identities with pinned OSV, NVD, KEV, and EPSS reference intelligence. A heuristic
  package-name or purl lookup is an applicability-unverified lead. Repository inference and
  Scorecard data do not establish product
  applicability, change finding severity, or bypass the normal evidence and verification gates.
- `job_review_data_indexing` inventories all engineering-signal producers, exposes their coverage, and retains
  their declared retrieval routes for later prioritization and review. The current numeric review
  prioritization job consumes its own syntax, dependency-graph, Semgrep, CodeQL, and history
  features; these engineering signals complement that ranking rather than silently modifying it.

## Configuration, operation, and development

All model, network, worker, parser identity, checker, and bound settings live in
[`../../appsec-review.toml`](../../appsec-review.toml) under the producer job tables. Changing an
identity-bearing setting invalidates reuse through the resolved configuration and producer
fingerprints. Do not move operational values into prompts.

Operator pages:

- [`../operations/clang-static-analysis.md`](../operations/clang-static-analysis.md)
- [`../operations/test-coverage-ingestion.md`](../operations/test-coverage-ingestion.md)
- [`../operations/profile-data.md`](../operations/profile-data.md)
- [`../operations/dependency-intelligence.md`](../operations/dependency-intelligence.md)
- [`../operations/review-data-indexing.md`](../operations/review-data-indexing.md)
- [`../../deploy/dagster/README.md`](../../deploy/dagster/README.md)

Implementation entry points are under `src/appsec_review/jobs/job_clang_static_analysis/`,
`job_test_coverage/`, `job_profile_data/`, and `job_dependency_intelligence/`; the shared schema vocabulary is in
`jobs/engineering_contracts.py`. Cross-workflow wiring is covered by
`tests/test_engineering_signal_integration.py`; focused behavior lives in
`tests/test_clang_static_analysis.py`, `tests/test_test_coverage.py`, `tests/test_profile_data.py`,
`tests/test_dependency_intelligence.py`, and `tests/test_multivuln_coverage_fixtures.py`.

