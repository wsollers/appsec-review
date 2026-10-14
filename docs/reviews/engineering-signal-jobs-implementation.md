# Engineering-signal jobs implementation

Status: implementation in progress. Root `AGENTS.md` governs.

## Decisions

1. The change adds three explicit jobs: `job_clang_static_analysis`, `job_test_coverage`, and
   `job_dependency_intelligence`. They publish immutable handoffs and retrieval shards; downstream
   review consumes only accepted outputs.
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
6. OpenSSF Scorecard is requested for every unique dependency whose source repository resolves to
   a supported public repository identity. HTTPS hosts, request count, response bytes, timeout, and
   retries are centrally configured. Exact response bytes are stored run-owned and hash referenced.
   A missing repository identity, unsupported host, 404/no Scorecard, rate limit, request failure,
   malformed response, or bound exhaustion is a dependency-scoped coverage gap.
7. Scorecard records and gaps are indexed as dependency context. They seed lane-B ranking/context
   and red-team packages but are not vulnerability findings and cannot raise finding severity.
8. The new jobs are generic producers: their parsers, resolver, client, and index builders have no
   Dagster dependency and are independently testable. Dagster and the direct graph only order them.
9. Central configuration owns versions, limits, model choice, role/persona selection, networking,
   and worker counts. Target files, tool output, model output, and Scorecard responses are data.
10. Verification uses focused unit and orchestration tests, then the broader suite. Live network and
    container checks remain explicit acceptance work and are never inferred from mocked tests.

## Parallel ownership

- Clang producer: `job_clang_static_analysis`, its tool image/rules, focused tests and docs.
- Coverage producer: `job_test_coverage`, format parsers, focused tests and docs.
- Dependency producer: `job_dependency_intelligence`, native inference, Scorecard client/index,
  registered runtime guidance, focused tests and docs.
- Integration owner: central TOML, registries, graphs, cross-domain indexing, inference review
  consumption, combined tests, and reconciliation.

