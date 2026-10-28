# Code-graph precomputation: implementation record

Record of the 2026-10-12 work on branch `ccr-67a0aeda-uyt6x6` that took
[code-graph precomputation](../architecture/code-graph-precomputation.md) from an approved plan to
an integrated, offline-verified C/C++ implementation (chunks C0 to C9). This is a historical and
decision record. The design, [`code-graph-index.md`](../operations/code-graph-index.md),
[`codeql-analysis.md`](../operations/codeql-analysis.md),
[`review-data-indexing.md`](../operations/review-data-indexing.md),
[`retrieval-mcp.md`](../operations/retrieval-mcp.md) and
[`inference-security-review.md`](../operations/inference-security-review.md) remain the current
authority. The procedure is the development skill
[`.claude/skills/parallel-implementation`](../../.claude/skills/parallel-implementation/SKILL.md).

## 1. What the work had to fix

Before this work the inference review had no direct evidence for `source_to_sink_reachability`,
`attacker_input_control` or `missing_or_ineffective_guard` beyond CodeQL path observations and
model-cited constructs. There was no call graph, sink or entry-point catalog, guard or range fact;
`entry_down` never launched and `sink_up` ran on `symbol_links`, which hold no source or sink. Two
earlier plans disagreed: a Joern/LLVM `query_precomputed` plan and a CodeQL-first `query_dataflow`
plan. The strategy (merge `ef6e1db`) settled on CodeQL as the primary producer of every fact
family, one typed tool (`query_code_graph`) over a new `graph` index, and graph-fact admissibility
in the review validator.

## 2. Decisions

**User decisions on the plan (A1 to A6, design section 11, recorded with C0 in `664bfa7`):**

| # | Decision |
|---|---|
| A1 | Export through `bqrs decode --format=json` per query in a new runner `export` action; SARIF is untouched. |
| A2 | Attacker-reachable source classes are `remote`, `local_user`, `argv`, `environment`, `file`, `ipc` (`contract.ATTACKER_REACHABLE_SOURCES`); `internal` and `database` are not. |
| A3 | `symbol_links` no longer unlocks `sink_up`; only accepted sink facts do. |
| A4 | `independent_verifier` is granted `query_code_graph`. |
| A5 | The seven graph query sets are retired from `QUERY_SETS` and `query_precomputed`, not deprecated. |
| A6 | C/C++ ships first; other languages follow in separate changes, each with recorded fixtures. |

**Scoring decisions relevant to graph evidence (design "Independent pluggable scoring"):**

- **B1** (merge `1a5673b`, wired in `d412838`). A score reflects adjudicated evidence. The
  `score-factors/1` extractors read graph kinds: `taint_path` reaches `graph_dataflow_path` from a
  counted `dataflow_path` relation, `attacker_control` takes the re-resolved `source_class` of a
  cited `entry_point` or `dataflow_path`, and `guard_absent` reaches `graph_fact` from a cited
  `guard_fact` or `range_fact`. `score_claims` re-resolves cited entities through the pinned
  retrieval core (`AcceptedEvidenceSource`).
- **B2.** Lane B rank weights are configurable; graph facts do not rank units.
- **B3, B4** (stale KEV still admits with a gap; EPSS only ranks and informs) have no graph
  dependency.

**Joern deprecation (`140256c`).** Joern produces nothing retrievable: no exporter, source mapping
or fixtures, and every scope published a `BLOCKED` shard with zero observations. CodeQL already
holds the AST, CFG, SSA and data dependence with maintained models, and the compiler of record
(Clang/LLVM, section 12) is the better second opinion for C/C++. `jobs.job_cpg_analysis.settings.enabled`
now defaults to `false`: no container runs and every accepted C/C++ scope publishes an
`unavailable` row naming the setting. The job and image stay registered until no run depends on a
retained CPG.

**Settled while integrating** (design section 10, "Deviations" and "Integration notes"): the
`none`-guard identity uses the sink's own span (`eb6042f`); a flow's final step matches a sink on
its own span or its exact operand span, and inapplicable ranges carry `range_not_applicable`
(`1fa580e`); the correlation format is one `DERIVED_FROM` per `(path, observation)` with ordered
`code_flows` (C4), and C6's `sarif_path` reader was aligned in the C5 merge (`e7d561d`).

## 3. Work partition and merges

The shared contract `graph/contract.py` (families, modes, closed vocabularies, native identities,
`graph-fact/1` payload and admissibility, `graph-fact-predicates/1`, the raw export contract and
`GraphSettings`) was committed first. Chunks then worked in isolated worktrees with exclusive file
ownership. Merge commits from `git log --first-parent`:

| Chunk | Delivered | Commit |
|---|---|---|
| Strategy | Code-graph precomputation strategy and reconciled graph plans | `ef6e1db` |
| C0 | Shared contract; seven `EntityKind`s, `GUARDS`, the `graph` index | `664bfa7` |
| C8 | `code_graph` matrix lane, retired graph query sets, follow-up accounting | `532da61` |
| C4 | Cross-check (clangd, LLVM IR, Clang AST) and SARIF correlation | `0107f8c` |
| C6 | `query_code_graph` retrieval tool and role capabilities | `32c535e` |
| C7 | Graph facts in review admissibility (`evidence-admissibility/2`), packages v4, routing | `0d36f98` |
| C1 | CodeQL export pack, catalog, columns contract, runner `export` action | `2476869` (lock pin and none-guard identity `eb6042f`) |
| B1 | Evidence-driven scoring (`application_risk_matrix/2`) and rank weights | `1a5673b` (wiring `d412838`) |
| C3 | Graph normalizer and catalog classifier | `68c37d5` (correlation and range fix `1fa580e`) |
| C2 | `job_codeql_analysis` export step | `52dd701` |
| Plan | Clang second producer phase (section 12); Joern deprecation | `6110534`, `140256c` |
| C5 | `job_code_graph_index`; `sarif_path` reader alignment | `e7d561d` |
| C9 | Integration fixes; offline end-to-end and live tier; documentation truth-up | this change (three commits after `e7d561d`) |

## 4. Reconciliations at merge time (C1 to C8)

- **Asset lock.** C1 changed `containers/tools/codeql/assets.lock.json`; the TOML `asset_lock_sha256`
  pin was updated with it (`eb6042f`).
- **None-guard identity.** C1 raised that a `guard_state = none` fact has no condition; the
  contract now defines its condition fields as the sink's span (`contract.none_guard_native`).
- **Correlation at the operand.** Real path-problem flows end at the sink's argument; C4 matches
  the operand span as well, without changing sink identities (`1fa580e`).
- **Range eligibility.** A `range_fact` without an applicable interval became ineligible; the C3
  golden output was regenerated (three range facts changed eligibility, nothing else).
- **Correlation format.** C4's one-relation-per-observation `code_flows` payload replaced the
  per-flow relations C6 had assumed; the C5 merge aligned the reader.
- **Scoring wiring.** `score_claims` was given the configured scoring model and an
  `AcceptedEvidenceSource`, so graph factors are derived in real runs, not only in unit tests.

## 5. C9 integration fixes

Each fix has a focused test in `tests/integration/test_code_graph_integration.py` (or the named
test) and is exercised again by the end-to-end test.

| Seam | Problem found | Fix | Test |
|---|---|---|---|
| Cell and MCP graph grants | Capabilities granted exact package entities only, so every `query_code_graph` row outside the package context was withheld, and a cell could never ask for the callers of a sink's function | Packages publish `retrieval.graph_scopes` (schema v4, not bumped: unreleased). `CellCapability.graph_scopes` and `ScopedRetrievalMcpAdapter` accept a `graph` row of a graph kind or CodeQL-export `symbol` only when its accepted `payload.scope.scope_id` is listed; it and the graph identities it references become addressable and citable. No kind-wide or cross-scope grant | `test_a_review_cell_receives_and_cites_graph_facts_of_its_granted_scope_only`, `test_graph_scope_grants_are_bound_into_the_capability_hash`, `test_the_scoped_mcp_adapter_applies_the_same_scope_bound_graph_grant` |
| Configured caps | `RetrievalCore` used `GraphSettings()` defaults, so `max_call_depth` in TOML had no effect on cells, scoring or MCP | `graph/settings.py::run_graph_settings` reads `jobs.job_code_graph_index.settings.graph` from the run-bound resolved configuration; a hash mismatch is a `RetrievalIntegrityError` | `test_retrieval_core_reads_graph_caps_from_the_run_bound_configuration` |
| CLI | `start`/`resume` omitted the graph job and `--force-from` rejected it | `cli.GRAPH_JOB_IDS` places it between prioritization and indexing | `test_cli_resume_and_force_from_cover_the_code_graph_job` |
| Build units | Unverified that package `build_unit_id` equals the graph shards' `build_unit_id` | Verified: both are build discovery's `build-unit-<20 hex>`; no change | end-to-end `test_codeql_publishes_what_the_graph_job_reads_and_build_units_match` |
| Catalog pin | The graph job normalized with whatever catalog the checkout held | Load fails with `IntegrityError` unless the catalog equals the run-bound `export_queries.catalog_sha256` of every exported language | `tests/test_code_graph_index_job.py::test_a_catalog_other_than_the_configured_codeql_pin_fails_the_load_unit` (the catalog-rebuild test now pins the revised catalog) |
| Evidence map | `review/scope.py` had no `code_graph` producer | Added; the package-level duplicate missing gap was removed | `test_the_review_evidence_map_lists_code_graph_coverage_and_gaps`, `test_a_run_without_graph_shards_names_code_graph_as_missing` |
| Fixture package | `tests/fixtures/graph/job/` had no `__init__.py` | Added | collection |
| CodeQL handoff | Unverified that the real handoff exposes `plan.inventory.plan` and `export.scopes` | Verified: both are handoff-bound; no change | end-to-end |
| Dropped secondary shards (found by the end-to-end test) | `job_codeql_analysis` publishes a manifest of its own shards only, so in a real run the graph job never saw clangd/IR/AST shards and every cross-check was `not_covered` | The graph job restores them from the accepted `job_cpp_symbol_index` and `job_cpp_compiled_analysis` handoffs (re-verified manifests, producer job checked) and composes them into its manifest | end-to-end (`restored_secondary`, `agree` state) |

## 6. Verification

**Offline end to end** (`tests/integration/test_code_graph_end_to_end.py`, no container). One run
goes through the real `job_codeql_analysis` (all six units; injected executor and image resolver;
injected target-catalog, language-build and replay loaders; the real `build_codeql_plan`), the real
`job_code_graph_index`, the real `job_review_data_indexing` (FTS image unavailable) and the real
`job_inference_security_review` with an injected worker that cites only graph identities it was
given or retrieved. It asserts:

- the CodeQL result and handoff bind `plan.inventory.plan` and `export.scopes`; C/C++ scopes export
  `SUCCEEDED` and Python reports `NOT_APPLICABLE`; the clangd shard dropped by the CodeQL manifest
  is restored and a call site cross-checks `agree`;
- package build-unit ids equal the graph shards' `build_unit_id`, and the lead package lists the
  synthetic scope in `graph_scopes` with `path`, `sink`, `entry_point`, `guard` and `range` context;
- the lead whose CodeQL observation correlates `bridged` reaches `supported` (row
  `r6_supported`) with direct-for-mapped-predicate relations: `sink_site` on `affected_construct`,
  `dataflow_path` on `source_to_sink_reachability` and `attacker_input_control`, `guard_fact` on
  `missing_or_ineffective_guard`; the cited path is the `bridged` one and its source class is
  `environment`. It is not `confirmed` because every role uses one model profile (the verifier is
  not provider-independent) and no graph family satisfies `security_impact`;
- the score package carries `taint_path = graph_dataflow_path`, `attacker_control = local`
  (`source_class` `environment`) and `guard_absent = graph_fact`, citing the graph facts;
- the synthetic hunt unit (sink and entry-point families) launches `sink_up` and `entry_down`; units
  without graph facts record `required_source_unavailable`; the `sink_up` hunter's graph queries,
  including `callers` on a symbol it received only through the scope grant, execute with nothing
  withheld;
- the indexing language matrix has `code_graph = unavailable` for Python, and the review
  completeness ledger records `producer:code_graph:` gaps naming the Python scope's missing export
  pack;
- flipping one byte in any of the 21 `graph` shards makes `scope.accept_manifest` raise
  `IntegrityError`;
- `job_cpg_analysis` with the default configuration is absent from execution plans and publishes
  no run artifacts.

**Focused tests** for every C9 fix (section 5) and the chunk suites (`tests/graph`,
`tests/test_code_graph_index_job.py`, `tests/test_retrieval_code_graph.py`,
`tests/review/test_graph_admissibility.py`, `tests/review/test_packages_graph_context.py`,
`tests/test_codeql_export_step.py`, `tests/test_codeql_export_runner.py`) pass.

**Full suite** (`python3 -m pytest -q tests`): see section 6.1.

### 6.1 Full-suite result

`python3 -m pytest -q tests` after C9: 1939 passed, 166 skipped, 4 failed. All four fail
identically on the base commit `e7d561d` and are unrelated to this work:

- `tests/review/test_inference_review_schemas.py::test_schema_set_is_exactly_the_contract_set`;
- three tests in `tests/test_change_context_analysis.py` (a fixture GitHub API route is missing and
  the `attribute.*` units fail).

Skips are environment-dependent tiers (live CodeQL, container images, live models), unchanged by
this work.

## 7. Live-unverified

- Status at the time of this review: the export pack had never run in the pinned CodeQL image and
  the recordings were hand-authored. Since then the image builds from this repository on any Linux
  Docker host, every pack except Swift has compiled and run in it, and the C/C++ native recording
  is copied from a live export (per-language results:
  `rules/codeql-graph-export/README.md#live-verification`). The synthetic recordings remain
  hand-authored and are checked by the per-language live tests.
- `deploy/dagster/verification/code-graph-acceptance.json` does not exist.
- The `appsec-multi-vuln` C/C++ scope has not produced a `dataflow_path` or `guard_fact`; the live
  tier's multi-vuln build commands (CMake) are an assumption until an operator runs it.
- No live model has cited a graph fact; the review path is proven with an injected worker only.
- Dagster `wave1_review` placement of `job_code_graph_index` is covered by the C5 adapter test, not
  by a Dagster run.

## 8. Open concerns

- Real CodeQL payloads keep `security-severity` inside `rule.properties`, which
  `normalize_reported_severity` does not read; a CodeQL lead's reported severity comes from the
  SARIF `level` (`error` maps to `high`). Pre-existing; unrelated to graph facts.
- `job_codeql_analysis` still rewrites the accepted manifest to its own shards. The graph job and
  the indexing job restore what they need, but other consumers that run between them see the
  narrowed manifest. Composing sibling shards in the CodeQL publication would remove the need.
- A scope-granted cell may address every fact of its CodeQL scope (bounded by the scope, not the
  package's paths). For a large build unit this is wider than the package's file range; it is
  never wider than one build unit.
- `retrieval.graph_scopes` was added to schema v4 without a version bump because v4 had not been
  released.

## 9. Next work

- **Live acceptance.** Done for the export packs (native recording refreshed from the live
  export); still to do: write `deploy/dagster/verification/code-graph-acceptance.json`.
- **More languages** (A6): done for C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby and
  Rust; Swift waits for a macOS executor.
- **Clang second producer** (design section 12, partially implemented): K4 is complete as the
  standalone `job_clang_static_analysis`/`tool-clang-static-analysis` producer with bounded
  source-mapped observations and gaps. K1 IR debug locations, K2 macro-precise locations, K3 LLVM
  dominator cross-checking, and optional K5 bounded CFG export remain planned. K6 still requires
  integration of those graph-producing chunks and their live acceptance; K4 itself is already wired
  into source-SAST review and documented under `docs/architecture/clang-static-analysis.md`.
