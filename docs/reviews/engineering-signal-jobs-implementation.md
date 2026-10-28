# Engineering-signal jobs implementation

Status: implemented and locally verified. Root `AGENTS.md` governs.

## Decisions

1. The original slice added `job_clang_static_analysis`, `job_test_coverage`, and
   `job_dependency_intelligence`; the follow-on slice added `job_profile_data`. All four publish
   immutable handoffs and retrieval shards, and downstream review consumes only accepted outputs.
2. Clang-Tidy and Clang Static Analyzer share one C/C++ job and one hash-pinned tool image. Each
   accepted native compile scope is analyzed from its run-owned compilation database. Missing
   compile context, unsupported commands, tool failure, timeout, and truncation are named gaps.
3. Test-coverage ingestion never runs target tests. It discovers only accepted build artifacts,
   normalizes LCOV, Cobertura XML, JaCoCo XML, and LLVM coverage JSON, binds each source row to the
   target catalog hash, and publishes line/branch/function totals. Unknown formats, ambiguous paths,
   malformed inputs, bounds, and absent coverage for an applicable build unit are gaps.
4. Dependency intelligence consumes declared dependencies, SBOM/package observations, accepted
   artifacts, and native compiler/linker provenance. Deterministic native heuristics retain library
   names, paths, hashes, command identities, and candidate package/repository identities.
5. Model inference is allowed only for unresolved native candidates. It receives a bounded data
   record, a registered runtime skill, one supply-chain investigator persona, and one dependency
   resolver role. Its result is validated, records confidence and evidence references, and is never
   promoted to an exact identity without corroborating metadata.
6. A deterministic repository stage groups all dependencies by canonical public forge identity
   before OpenSSF Scorecard retrieval. Each unique repository receives one cache lookup and at most
   one HTTP request per run; the result fans back out to every referring dependency. HTTPS hosts,
   request count, response bytes, timeout, retries, cache root, cache age, and lock timeout are
   centrally configured. Fresh verified cache entries avoid HTTP. Exact response bytes are stored
   run-owned and hash referenced. Missing or unsupported identities, repository bounds, 404/no
   Scorecard, rate limits, request failures, malformed responses, invalid cache entries, cache-write
   failures, and bound exhaustion are dependency-scoped coverage gaps.
7. Scorecard records and gaps are indexed as dependency context. They seed lane-B ranking/context
   and red-team packages but are not vulnerability findings and cannot raise finding severity.
8. The four jobs are generic producers: their parsers, resolver, client, and index builders have no
   Dagster dependency and are independently testable. Dagster and the direct graph only order them.
9. Central configuration owns versions, limits, model choice, role/persona selection, networking,
   and worker counts. Target files, tool output, model output, and Scorecard responses are data.
10. Verification uses focused unit and orchestration tests, then the broader suite. Live network and
    container checks remain explicit acceptance work and are never inferred from mocked tests.

## Parallel ownership

- Clang producer: `job_clang_static_analysis`, its tool image/rules, focused tests and docs.
- Coverage producer: `job_test_coverage`, format parsers, focused tests and docs.
- Dependency producer: `job_dependency_intelligence`, native inference, Scorecard client/index,
  repository deduplication/cache, registered runtime guidance, focused tests and docs.
- Integration owner: central TOML, registries, graphs, cross-domain indexing, inference review
  consumption, combined tests, and reconciliation.

## Implemented integration

- The direct graph and Dagster wave register and order all four jobs before review-data indexing.
- Language-build preserves well-known coverage exchange files for every supported build family.
- Clang observations are classified as source-SAST and enter scanner correlation and review lanes.
- Coverage cells are attached to the exact source/build unit in lane-B review packages.
- Dependency and Scorecard entities seed lane-B red-team context. Package context bounds still apply;
  truncation is a named gap, and Scorecards remain context rather than vulnerability findings.
- Every normalized dependency, including a native identity completed by bounded model inference,
  enters `dependency_advisories`. Inventory-only OSV package matches are explicitly
  applicability-unverified until corroborated by accepted version-aware evidence.
- Review scope accounts for missing, partial, and failed coverage from each new producer.

## Original verification record

- Focused producer/orchestration integration: 70 passed, 1 skipped; review package/cap tests:
  40 passed; guidance/persona/dependency tests: 165 passed.
- A later combined run reached 241 passed and 1 skipped; two unrelated feed-publication fixtures
  failed with Windows `os.replace` access-denied errors. The full suite cannot collect on this host
  because `hypothesis` and the Unix-only `resource` module are unavailable. Separate broad runs also
  reproduced existing Windows path/permission failures in project probes, SQLite shard creation,
  and CodeQL fixture export.
- Clang tool acceptance built its offline image and exercised both analyzers against a native null
  dereference fixture. No live model-provider or OpenSSF network acceptance was performed.

## 2026-10-14 documentation reconciliation

- Re-audited the current central TOML, producer dataset declarations, direct CLI order, generated
  Dagster dependencies, review-data product rules, schemas, focused tests, and the accepted
  multivuln fixture contract rather than carrying forward the original implementation summary.
- The current registry and configuration each contain 38 jobs; the input-source matrix contains 57
  rows; review-data indexing publishes ten precomputed products. These counts are descriptive and
  are guarded by executable consistency tests rather than treated as runtime authority.
- Operator topology, data-flow tables, navigation, graph implementation status, profile context,
  maximal-exposure semantics, Scorecard gaps, and advisory applicability language were reconciled
  with the current implementation. Live provider, Scorecard, and container availability remain
  environment acceptance gaps unless separately exercised.
- Focused producer verification passed 58 tests across Clang, coverage, the multivuln fixtures,
  profile ingestion, dependency intelligence, and advisory indexing inputs. Documentation and
  configuration consistency passed 58 tests with the Dagster-dependent test skipped and the
  Windows symlink-privilege test deliberately deselected after reproducing `WinError 1314`.
  Review-data indexing passed its other 24 tests; its image-validation acceptance test reproduced
  the host gap `fts_validation.status = unavailable` where that fixture expects the pinned SQLite
  FTS image to verify. No live model-provider, Scorecard-network, or tool-container acceptance was
  inferred from these local results.

## 2026-10-14 Scorecard cache follow-up

- Added `repositories.deduplicate` between repository inference and Scorecard retrieval.
- Added a content-addressed cache with atomic per-repository pointers, exact response hashes,
  bounded locks, and a centrally tunable maximum age (seven days by default).
- Accepted handoffs now expose unique-repository, cache-hit, and HTTP-request counts. Tests cover
  repository fan-out, repository bounds, fresh hits with zero HTTP, expiry, and tamper rejection.

