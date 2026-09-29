# Brief G: per-language CodeQL nodes, reachability engines and correlator (branch `codeql-reach`)

Goal: run CodeQL for every language found, in parallel, as separate graph nodes; then decide reachability of vulnerable dependencies with independent engines that write the same table; then correlate in Python and feed the report and the red/blue lanes. This REPLACES the open E decision ("reachability mode in the audit-codeql lane script or a container step for 06"): the CodeQL packs run in the nodes and engine job below.

## Design (William, agreed 2026-09-29)
1. **`02-codeql-<lang>` nodes, one per CodeQL language** (cpp, java, csharp, go, javascript-typescript, python, ruby, rust where CodeQL supports it; PHP has no CodeQL support: it gets no node, only language-server/tree-sitter hints). The job graph is static, so each node is fixed and publishes `SKIPPED` (`language not present`) when its language is absent from the target. They run in PARALLEL (resource pool bounded like the other docker jobs).
   - Interpreted languages start after intake/partition discovery (no build needed).
   - Compiled languages (cpp, java, csharp, go, rust) start only after a SUCCESSFUL build of that language (`02-native-build` unit results, per language). If the language is compiled and cannot be built, the node publishes `OK_WITH_GAPS` (or `SKIPPED` with reason `language not built: <cause>`) and a gap. NEVER a failure. Java/C# may use build-mode none where CodeQL supports it; record which mode was used.
   - Each node publishes its SAST leads (same lead shape as today; `claim_ledger` must read every `02-codeql-*` producer) AND a hash-bound pointer to its CodeQL database (database directory identity, CodeQL bundle version, language, build mode, source snapshot hash) so the reachability engines reuse it and never rebuild.
   - Existing `02-codeql-sast` is replaced by these nodes (keep its ADR-0017 behaviour: no license gate, timeouts/OOM become per-language gaps). Keep a compatibility note for ledger/report readers.
2. **`06-reachability-codeql`** (fan-in): needs the `02-codeql-<lang>` pointers (whichever succeeded) and `02-sca-vulnerability-match` (vulnerable deps). Runs the reachability queries from `data/codeql-reachability/<lang>/` (call-graph reachability `calls*` from entry points to the advisory symbol; taint tracking `TaintTracking::Global` source-to-sink when the advisory names a sink) per language, in parallel inside the job, against the existing databases. Output: table of `{match, language, verdict: reachable|unreachable|unknown, tier, witness[], gaps}`.
3. **`06-reachability-ir`** (fan-in): for languages with an IR-like form. C/C++ (and Rust when available): LLVM IR facts (`02-ir-facts`) + Joern CPG (`02-code-property-graph`) via the existing `reachability.py` arbiter. Same table shape as (2). Java bytecode and .NET IL are deferred (TODO section G) but the engine interface must allow adding them.
4. **`06-cve-reachability` becomes the Python correlator** (depends on 2 and 3, plus the SCA job): ingests all engine tables, correlates per vulnerable match, and writes (a) the existing `cve-reachability.json` in its current format (so 07, 12 and the report's "Critical requires REACHABLE" rule work unchanged), (b) `dependency-reachability.json` (per-match evidence from every engine), (c) a summary artifact `dependency-reachability-summary.md/json` for the report and the red/blue lanes. Rules: `reachable` needs at least one hash-bound witness from an engine allowed to prove it; `unreachable` only from an engine with a complete call graph AND dependency source present AND no reflection/dynamic-dispatch/serialisation gap on the path; conflicting engine verdicts produce `conflict` (listed, never silently resolved); language-server call hierarchy and tree-sitter results are HINTS only and can never make a verdict `reachable`; no model output decides reachability.
5. **Consumers:** `10-synthesis-report` renders the correlated summary; `07-red-team-adversarial` (via claim-ledger routing), `08`, `09` and `12` receive it as evidence input (as they do the existing reachability table). Update the ledger/routing so a `reachable` dependency match becomes a P1 review claim and `conflict` is flagged for review.

## THE KEY: proper lookup through the proper language
Reachability is only as good as the mapping from an advisory ("package X, function/symbol Y") to the names the language actually uses when a dependency is brought in. Build a per-ecosystem resolver (module `dep_symbol_resolver.py`, one adapter per ecosystem) turning (ecosystem, package, version, advisory symbols) into language-level names, reading the VENDORED dependency's own manifest:
- Python: package name -> import module names (`top_level.txt`, `RECORD`, `__init__` re-exports), submodule paths, `from x import y` aliases.
- npm: `package.json` `exports`/`main`/`module`, re-exports, deep imports, ESM vs CJS.
- Java/Maven: coordinates -> jar classes (fully qualified names), shaded/relocated packages, multi-release jars.
- Go: module path vs package import path, `replace` directives, vendor dir.
- C#/NuGet: package id -> assemblies -> namespaces/types, target framework.
- Rust: crate name vs lib name, features, re-exports.
- Packagist: package -> namespaces (PSR-4 autoload map), for hints only.
Advisory symbols come from the OSV index (`osv_lookup.py`; Go has function-level symbols, other ecosystems mostly do not) or a reviewed map `inputs/cve-reachability-functions.json`. No symbols => `unknown` (package-level presence only) with a clear reason. Record the resolution steps in the witness.
Two tiers in every witness: `direct` (application code calls the vulnerable symbol) and `through-dependency` (application calls a dependency API that reaches the vulnerable symbol; requires the dependency source in the analysed database). Dependencies are VENDORED per version (artifact repository later); a missing dependency source degrades to `direct`-tier-only plus a gap, never a crash.

## Read first
`docs/decisions/ADR-0022*` and `docs/dependency-reachability.md` (E's design and code), `dep_reachability*.py`, `reachability.py`, `data/codeql-reachability/**`, `codeql_sast.py` and `scripts/codeql-sast-lane.sh` (ADR-0017), `native_build.py`/build-plan unit results (how to know per language whether a build succeeded), `claim_ledger.py`, `docs/language-servers.md`, `docs/osv-feed.md`, job wiring of a recent lane for the pattern (job-graph.json, registry templates/contracts, `design-parity-manifest.json`, `dagster_workflow.py`, `docs/processes/catalog/steps.json`). Also 00-common.md.

## Steps (commit per step; tests per step with fakes; no Docker available to you)
1. ADR-0023 (next free number): node set, gating rules, gap semantics, table schema, verdict lattice with `conflict`, tiers, correlator rules.
2. Schemas: codeql-language result + database pointer; engine reachability table (shared by codeql and ir engines); correlated summary.
3. `02-codeql-<lang>` nodes: refactor `codeql_sast.py` so ONE language runs per node (share code), build gating, gap semantics, DB pointer, ledger producers, Dagster ops, job graph/registry/contracts/parity, catalogs regenerated. Retire `02-codeql-sast` from the graph carefully (edges into 02-evidence-assembly, 06 and the ledger move to the per-language nodes).
4. `dep_symbol_resolver.py` + per-ecosystem adapters + fixtures.
5. `06-reachability-codeql`: run packs per language against pointers (fake runner in tests), table output. `06-reachability-ir`: wrap the CPG/LLVM-IR path (extract from E's `cpg` adapter, do not duplicate).
6. Correlator: turn `06-cve-reachability` into the Python correlator, keep its existing output contract, add the summary; edges for 07/08/09/10/12 and ledger routing.
7. Report: render the correlated summary; `conflict` and `unknown` shown honestly.
8. Docs (`docs/dependency-reachability.md` update), WSL smoke script (`scripts/smoke_codeql_per_language.sh`), TODO section G with the OPEN items already listed there (do not delete them).

## Rules
- Work on branch `codeql-reach`; PUSH `origin codeql-reach` (never `main`, not the session default branch).
- Follow docs/agent-briefs/00-common.md. You own: `codeql_sast.py` and its lane script, `02-codeql-*` and `06-reachability-*` wiring, `dep_symbol_resolver*.py`, `dep_reachability*.py`, `data/codeql-reachability/**`, correlator, ledger producer rows for CodeQL, related schemas/tests. Do not touch `poc_fix_*`, `attack_chain_*`, `osv_*`, `owasp_*`, `review_cli.py`, `pipeline_log*.py`.
- Image changes (Go toolchain in `audit-codeql`, .NET SDK) are requests: make the minimal Dockerfile/registry edit if it is needed for a node to work and list it under OPEN with the WSL build command; otherwise only report.
- Merge `origin/main` into your branch before pushing anything that touches generated files, to avoid catalog/parity conflicts. Regenerate generated files with the scripts.
- Expect job-count expectations in tests (`test_design_parity`, `test_vendor_prepass_graph`, `test_dagster` pinned dependency lists, build-discovery doc table, parity manifest full_review list) to need updating when jobs are added: update them.
- Safety: queries and databases run only in the sandboxed containers; nothing executes target code outside them; no output contains hostile payloads.
- Print one status line every 10-15 minutes: `[G] <step> <what you are doing>`. Finish with the report from item 12 of the common rules.
