# ADR-0022: Language-aware dependency reachability for `06-cve-reachability`

Status: **Proposed** (brief E, 2026-09-29). Superseded in part by
[ADR-0023](ADR-0023-per-language-codeql-reachability.md) (brief G): the language server is a hint (decision 3),
the join adds `conflict` and is done by the 06 correlator over engine tables (decision 4), and 06's wiring
changes (decision 9). The engine order per language, "model text never
decides reachability" and "tree-sitter alone is never `reachable`" were decided by William in the
brief; the rest awaits review.

Implementation (2026-09-29): merged to `main` (`f5ca4d3`); 06 derives its evidence in `full_review`
from new edges on `02-code-property-graph` and `02-codeql-sast`. The CodeQL reachability packs in
`data/codeql-reachability/` are written but not compiled, and no job yet runs them, the LSP
incomingCalls walk or `treesitter_ast.py` in a run (those inputs come from `<run>/inputs/`). Unit
tests only; no live run. Details: [`docs/dependency-reachability.md`](../dependency-reachability.md).

## Context

`06-cve-reachability` ran in `full_review` but joined an evidence file that the lifecycle always
wrote as `{"assessments": []}`, so every SCA match ended `unknown` (`REACHABILITY_UNKNOWN:VM-…`).
`reachability.py cve-evidence` could do better for C/C++ but needed a reviewer-written
advisory→function map and ran offline only. After `osv-feed` the OSV index holds affected symbols
(Go today, RustSec and a few others where the source provides them); after `lang-servers` the
compiler images carry language servers, tree-sitter, and CodeQL graph tables for traced C/C++.
ADR-0020 made reachability the final severity arbiter: **Critical requires REACHABLE**.

## Decision

1. **One deterministic analyser.** `dep_reachability.py` computes, per SCA match, a verdict and a
   witness from accepted, hash-bound evidence only. It resolves advisory symbols, picks engines by
   ecosystem, runs them, joins the results through a fixed lattice and emits (a) the evidence rows
   `dependency_workers.build_reachability` already validates (`assessments`) and (b) the full
   per-match record `outputs/dependency-reachability.json`
   (`schemas/dependency-reachability.schema.json` + `dependency-reachability-match.schema.json`).
   No model call; no network. Details and the entry-point table: `docs/dependency-reachability.md`.

2. **Advisory symbols.** Sources, in order, all recorded per symbol (`source`):
   a reviewed advisory→function map (`inputs/cve-reachability-functions.json`, optional, hash-bound);
   the OSV index (`affected[].symbols`, looked up by advisory id and every alias, filtered to the
   affected entry whose ecosystem and package name match the SBOM component). An advisory with no
   symbol is `unknown` with reason `no-advisory-symbols` (package presence only). Symbol text is
   advisory data: it is validated against `^[A-Za-z_$][A-Za-z0-9_$.:<>~-]{0,199}$`, never
   interpreted, and passed to CodeQL only as rows of a generated data extension (decision 6).

3. **Engines per ecosystem** (the dependency's ecosystem decides; the application language is the
   same ecosystem for SCA matches, and C/C++ vendored code is analysed as application code):

   | SBOM ecosystem | Language | Engines, strongest first |
   |---|---|---|
   | `conan`, `generic` with a C/C++ vendored path, `deb`/`rpm`/`apk` linked libraries | C/C++ | `cpg` (Joern CPG + IR facts), `codeql` (traced `CallEdges`/`EntryPoints` tables) |
   | `golang` | Go | `codeql`, `lsp` (gopls), `treesitter` |
   | `maven` | Java | `codeql`, `lsp` (jdtls), `treesitter` |
   | `nuget` | C# | `codeql`, `lsp` (csharp-ls), `treesitter` |
   | `npm` | JavaScript/TypeScript | `codeql`, `lsp` (typescript-language-server), `treesitter` |
   | `pypi` | Python | `codeql`, `lsp` (basedpyright), `treesitter` |
   | `cargo` | Rust | `lsp` (rust-analyzer), `treesitter` (no CodeQL pack yet) |
   | `composer` | PHP | `lsp` (phpactor), `treesitter` (CodeQL has no PHP extractor) |
   | `gem` | Ruby | `codeql` (no pack yet: always a gap), `treesitter` |

   Every engine is an adapter behind one interface (`dep_reachability_engines.Engine.assess`) over
   a language-neutral graph: functions with `file:line` and file sha256, resolved call edges,
   escapes (indirect / ambiguous / dynamic calls) and entry points. Adapter strengths:
   * `cpg`: may return all three states (it is `reachability.py`, unchanged semantics).
   * `codeql`: `reachable` from a resolved `CallEdges` path or a `Reachability.ql` row (decision
     6); never `unreachable` (static edges miss virtual/dynamic dispatch and the tables carry no
     escape rows). `TaintReach.ql` rows are recorded as `taint_paths`, they do not change the state.
   * `lsp`: `reachable` from an `incomingCalls` chain that ends at an entry point; never
     `unreachable` (call hierarchy is best-effort and silent on dynamic dispatch).
   * `treesitter`: never `reachable` or `unreachable`; a name-matched call site is `unknown` with
     a `witness_hint`.

4. **Verdict lattice.** Per engine: `reachable | unreachable | unknown`. Joined per match:
   `reachable` if any engine at `cpg`/`codeql`/`lsp` strength proves a path (the shortest witness
   of the strongest engine wins); else `unreachable` only if the strongest engine that ran is the
   CPG (the one "complete" engine), it returned `unreachable`, and every other engine that ran
   returned `unreachable` or `unknown`-without-hint; else `unknown` with every engine's reason and gap. A match whose
   component is out of scope (dev-only, generated) is not decided here; 02 already records it.
   The 06 `classification` is the joined verdict; `reachable` needs `call` evidence and
   `unreachable` needs `call`/`scope` evidence (existing `REQUIRED_EVIDENCE`).

5. **Witness format.** Ordered hops from an entry point to the call into the vulnerable symbol:
   `{function, file, line, sha256, calls_next_at, resolution}`; the last hop is the application
   call site of the dependency symbol (`note: call into the vulnerable dependency function`), or the
   vulnerable function itself when the dependency is vendored and analysed. Every hop's `sha256` is
   the sha256 of the file bytes in the run's source projection; a hop whose file is not in the
   projection is dropped from `evidence` and the match falls to `unknown`
   (`witness-not-hash-bound`). The witness list is capped at 32 hops.

6. **CodeQL query templates.** `data/codeql-reachability/<lang>/` holds a pinned pack per
   language (`qlpack.yml` with an exact `codeql/<lang>-all` version and a lock file): `CallEdges.ql`,
   `EntryPoints.ql`, `Reachability.ql` (`calls*` from `EntryPoint` to a `VulnerableSymbol`) and
   `TaintReach.ql` (`TaintTracking::Global` from `RemoteFlowSource` to an argument of a
   `VulnerableSymbol` call). The symbols reach the query only as rows of the extensible predicate
   `vulnerableSymbol(package, symbol)` in a data-extension YAML that Python generates
   (`dep_reachability_codeql.data_extension`); no model or advisory text is ever spliced into QL.
   Queries run only inside the pinned `audit-codeql` image, offline.

7. **Entry points.** Per language, a closed source list (`dep_reachability_engines.ENTRY_POINTS`,
   documented in `docs/dependency-reachability.md`): `main`; exported/public symbols of a library
   target; framework handlers and routes recognised by name/annotation (Go `http.HandleFunc`
   handlers, Java `@*Mapping`/servlet `do*`, C# controller actions, Express/Koa route callbacks,
   Flask/FastAPI/Django views, Rust `#[tokio::main]`/actix handlers, PHP route closures); CodeQL
   `EntryPoints.ql` rows; plus a run-supplied hash-bound `inputs/reachability-entry-points.json`
   (same file ADR-0020 reads). No entry point → `unknown` (`no-entry-point`), never `unreachable`.

8. **Failure modes are gaps.** Missing engine input (no accepted CPG, no CodeQL tables for the
   language, no LSP/tree-sitter document), OSV snapshot unusable/over-age, advisory without symbols,
   dependency source not vendored, bound hit, dynamic-dispatch escape, witness not hash-bound: each
   yields `unknown` for that match and a `coverage_gaps` string `REACHABILITY_UNKNOWN:<match>:<reason>`.
   A gap is never "not vulnerable".

9. **Wiring.** `06-cve-reachability` keeps its contract (`cve-reachability`) and gains optional
   upstream edges on `02-code-property-graph` and `02-codeql-sast` (plus the existing `02-ir-facts`).
   Its lifecycle derives the evidence file instead of writing an empty one, binds every input by
   hash (SCA, SBOM, CPG, CodeQL receipts, OSV snapshot identity, reviewed map, entry-point file,
   engine documents) so any change invalidates the attempt, and re-derives byte-for-byte on
   validate. Consumers are unchanged: `07`, `12` via the claim ledger, and the report arbiter
   (`finding_enrichment.py`) reading `outputs/cve-reachability.json`.

## Consequences

* A Go advisory with OSV symbols and a traced/CodeQL call graph can now be `reachable` with a
  witness; everything else is an honest `unknown` with its reason, which caps Critical at High.
* CodeQL for non-C languages and LSP call hierarchy need a container step in the run. Until the
  `audit-codeql` lane script gains a reachability mode (image owner, brief C), those engines read
  documents supplied under `inputs/dependency-reachability/` or produced by the smoke script, and a
  run without them records `engine-input-absent:<engine>:<lang>`.
* `reachability.py` is extended (a CallGraph can be built from generic edge tables), not changed.
