# ADR-0023: Per-language CodeQL nodes, reachability engines and the 06 correlator

Status: **Proposed** (brief G, 2026-09-29). The node set, the build gating, "never a failure", the
engine jobs, the correlator rules and "language-server and tree-sitter results are hints only" are
William's (brief G design, agreed 2026-09-29); names, schemas, the database store and the tier rule
are the implementer's and need review.

Implementation (2026-09-29): merged to `main` from `codeql-reach` (`1248b43`; follow-up `d3ef6b7` keeps
the CodeQL nodes off `02-evidence-assembly`). 81 lifecycle jobs. Unit tests with fake runners only:
the `audit-codeql` images need a rebuild and B16 records, the QL packs have not been compiled, and
nothing has run live. Decision 9 was aligned to the code on 2026-09-29 (brief M4): the claim ledger
records an engine `conflict` as a proof obligation on the candidate claim, not as a `review_flags`
entry (the ledger has no such field; `tests/test_claim_ledger.py`
`test_dependency_leads_carry_the_correlated_reachability_verdict`). Open items:
`appsec-review-process/TODO.md` section G.

Supersedes: ADR-0017 decision 3 (one `02-codeql-sast` job) and decision 5 (one container per
language inside that job); ADR-0022 decision 3's `lsp` strength (was "may prove `reachable`") and
decision 4's join (a proof now needs a proof-capable engine, disagreement is `conflict`); ADR-0022
decision 9's wiring (06 no longer reads the CPG or CodeQL receipts itself). ADR-0017 decisions 1,
2, 4 and 6 and ADR-0022 decisions 2 and 5 to 8 stand.

## Context

`02-codeql-sast` ran every detected language serially inside one job, dropped every database, and
could not be gated on a build. ADR-0022's CodeQL reachability packs existed but no job ran them, so
`06-cve-reachability` only had the traced C/C++ tables and run-supplied files. The mapping from an
advisory ("package X, function Y") to the names a language uses was a single name comparison.

## Decision

1. **One node per CodeQL language**: `02-codeql-cpp`, `02-codeql-csharp`, `02-codeql-go`,
   `02-codeql-java`, `02-codeql-javascript` (JavaScript and TypeScript; CodeQL's `javascript`
   extractor), `02-codeql-python`, `02-codeql-ruby`, `02-codeql-rust`. PHP has no CodeQL
   extractor and gets no node. The graph is static: every node exists in every run, and a node
   whose language is absent from the checkout publishes `SKIPPED` with skip reason
   `not-applicable-language-absent`. The nodes run in parallel in the Docker resource pool (the
   pool bounds concurrency, as for every B13 job). All share code (`codeql_sast.py`, one
   `run(run_id, dagster_id, language)`), the output contract `codeql-language` and the schema
   `codeql-language.schema.json`; each has its own template, namespace and fingerprint.
   The nodes are not edges of `02-evidence-assembly`: its persona pool makes one check per producer
   and eight more would exceed the shared `pool_groups_max` (32); the claim ledger still runs after
   them through `06-reachability-codeql` -> `06-cve-reachability` -> `claim-ledger-routing`.

2. **Gating.**
   * Interpreted languages (`javascript`, `python`, `ruby`) need only the accepted intake.
   * `java` and `csharp` run `--build-mode none` (supported offline by CodeQL 2.27): they need no
     build and record `build_mode: none` and the fidelity gap of ADR-0017.
   * `cpp` waits for `02-native-build` (edge allowed to be `SKIPPED` non-native / no binaries).
     With an accepted native build that has replayable C/C++ units, one `codeql-cpp-traced` row
     runs per unit (ADR-0017 decision 4's second tool id); `--build-mode none` always runs as well
     (ADR-0017 decision 1: CodeQL always runs). Without units the node records the gap
     `language not built: <cause>; ran --build-mode none only`.
   * `go` has no build-mode none and the pipeline has no Go build step; a checkout with Go
     publishes `OK_WITH_GAPS` with `language not built: ...` and no database. `rust` has no
     suite pinned in `images/audit-codeql/tool.json`; a checkout with Rust publishes
     `OK_WITH_GAPS` with `language not supported by the pinned CodeQL metadata`. Both are image
     requests (TODO section G), never failures.
   * A container that times out, is OOM-killed or exits non-zero is a gap (ADR-0017 decision 5);
     canceled or gate-refused containers and integrity failures block.

3. **Database pointer.** A lane that completes keeps its finalized database (lane argument
   `keep-db`). The worker moves it from the tool scratch into the run's database store
   `data/runs/<run>/codeql-databases/<job>/<attempt>/<plan-key>/` (outside the attempt, so the
   attempt tree hash stays small) and publishes, per database, a pointer:
   `{database_id, job_id, attempt_id, plan_key, language, build_mode, unit_id, bundle_version,
   tool_metadata_sha256, image_digest, source_snapshot_sha256, store_path, tree_sha256, files,
   bytes}`. `tree_sha256` is sha256 over the sorted `(relative path, file sha256)` list. A consumer
   re-hashes the store before use; a mismatch is a gap (`codeql-db-changed`), never a rebuild.

4. **Leads and the ledger.** Each node publishes leads in the ADR-0017 lead shape. The claim
   ledger has one producer row per node (`LEAD_PRODUCERS`); readers that looked for
   `02-codeql-sast` read the eight rows instead (compatibility note in `docs/dependency-reachability.md`
   and `docs/processes/job-catalog.md`). Leads stay P1 (`codeql-security-query`).

5. **Engine jobs, one shared table.** `06-reachability-codeql` (fan-in over every
   `02-codeql-<lang>` node, `02-sca-vulnerability-match` and `02-sbom-inventory`) and
   `06-reachability-ir` (fan-in over `02-code-property-graph`, `02-ir-facts`, SCA and SBOM) both
   publish `engine-reachability.json` (contract `engine-reachability`,
   `engine-reachability.schema.json`):
   `{engine, languages[], rows[{match_id, component_ref, advisory_id, language, verdict, tier,
   symbols[], resolution[], witness[], gaps[], reason}], coverage_gaps[]}` with
   `verdict ∈ {reachable, unreachable, unknown}` and `tier ∈ {direct, through-dependency, null}`.
   * `06-reachability-codeql` runs the pinned pack `data/codeql-reachability/<lang>/` (call-graph
     `edge*` from `EntryPoint` to a `VulnerableCall`, and `TaintTracking::Global` from
     `RemoteFlowSource` to its arguments) against the existing databases, one B13 container per
     language (parallel in the Docker pool, sequential inside the job); symbols reach QL only as
     data-extension rows (ADR-0022 decision 6). C/C++ has no pack: its rows come from the traced
     graph tables the `02-codeql-cpp` receipts hash. The engine never reports `unreachable`.
   * `06-reachability-ir` runs the CPG arbiter (`reachability.py` via `dep_reachability_engines.CpgEngine`,
     with IR facts when present) for native ecosystems; it is the only engine that may report
     `unreachable`. Rust joins when an LLVM-IR/CPG path exists for it. The engine interface
     (`dep_reachability_engines.Engine`) is the extension point for Java bytecode and .NET IL
     (TODO section G).

6. **Symbol resolution through the language.** `dep_symbol_resolver.py` turns
   `(ecosystem, package, version, advisory symbols)` into the names the language uses, reading the
   vendored dependency's own manifest in the checkout: PyPI `top_level.txt`/`RECORD`/package dirs;
   npm `package.json` `exports`/`main`/`module`; Maven jar or source packages (shading relocations
   recorded when a `META-INF/maven` pom declares them); Go module path vs package import path,
   `replace` directives, `vendor/modules.txt`; NuGet `.nuspec` id → assemblies → namespaces;
   Cargo `[lib] name` vs crate name; Packagist PSR-4 autoload namespaces (hints only). Every step
   is recorded in the row's `resolution`. No symbol → `unknown` with reason `no-advisory-symbols`.
   A dependency whose source is not vendored yields `dependency-source-absent` and the tier falls to
   `direct` only.

7. **Tiers.** `direct`: the call of the vulnerable symbol is in application code.
   `through-dependency`: the call is inside the vendored dependency source (application →
   dependency API → vulnerable symbol); only possible when the resolver found the vendored root.

8. **Correlator.** `06-cve-reachability` depends on both engine jobs and the SCA job. It ingests
   every engine table plus the run-supplied language-server and tree-sitter documents (hints) and
   decides per SCA match:
   * `reachable` needs at least one hash-bound witness (every hop's file sha256 in the source
     projection) from a proof-capable engine (`codeql`, `ir`);
   * `unreachable` only from the `ir` engine (complete call graph), with the vulnerable function's
     definition present (dependency source analysed), no dynamic-dispatch/reflection/serialisation
     escape on the path, no weaker engine's name-matched call site, and no other engine saying
     `reachable`;
   * engines disagreeing (`reachable` vs `unreachable`) is `conflict`: listed with both engines'
     reasons, never silently resolved;
   * everything else is `unknown` with every engine's reason and gaps.
   Language-server call hierarchy and tree-sitter results are hints and can never make a verdict
   `reachable`. No model output decides reachability. Outputs: `outputs/cve-reachability.json`
   in its existing contract (`conflict` is written as `unknown`, so Critical stays capped, plus a
   `REACHABILITY_CONFLICT:<match>` gap), `outputs/dependency-reachability.json` (per-match evidence
   from every engine) and `outputs/dependency-reachability-summary.json|md` for the report and
   lanes 07 to 12.

9. **Consumers.** `10-synthesis-report` renders the summary (`conflict` and `unknown` shown as
   such). `07`, `08`, `09` and `12` receive it through the supporting-evidence menu next to
   `cve-reachability.json`. The claim ledger (`claim_ledger._reachability_note`, fed from
   `dependency-reachability-summary.json`) leaves the dependency lead's P1 route and ids unchanged
   and records the verdict on the candidate claim: for a `reachable` match it appends
   "Dependency reachability (06-cve-reachability): reachable for <match> [<tier>]; a P1 review
   claim." to the hypothesis and raises confidence to `medium`; for a `conflict` it appends
   "Reachability CONFLICT for <match>: the engines disagree; flagged for review (never resolved
   silently)." and adds the review obligation "Resolve the conflicting reachability engine verdicts
   for <match> (dependency-reachability-summary.json) before scoring." The ledger has no
   `review_flags` field; the proof obligation is the review flag, so 07/08/09 must discharge it.

## Consequences

* A full run executes up to eight CodeQL containers in parallel instead of serially, bounded by
  the Docker pool; each can be re-run alone.
* Databases are retained for the run (disk: one database per language and traced unit). The store
  is run data, deleted with the run.
* The lane script gains `keep-db` and a reachability script; both are COPYed into `audit-codeql`
  and need an image rebuild and B16 record (TODO section G, WSL commands in
  `docs/dependency-reachability.md`). Until then every CodeQL node is `UNAVAILABLE` (a gap) and
  every CodeQL reachability row is `unknown`.
* Run-supplied CodeQL tables under `inputs/dependency-reachability/codeql/` are no longer read;
  CodeQL evidence comes only from the engine job.
