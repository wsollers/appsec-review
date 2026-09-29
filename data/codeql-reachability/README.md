# CodeQL reachability packs (brief E, ADR-0022)

One pack per language, `appsec/<lang>-reachability`, each pinned to the library version shipped
in `codeql-bundle-v2.27.0` (the `audit-codeql` image). `dep_reachability_codeql.py check` verifies
the pins; `tests.test_dep_reachability_engines` runs it.

| Pack | Library pin | Database (offline) |
|---|---|---|
| `go/` | `codeql/go-all 7.3.1` | autobuild; works offline only with a vendored `vendor/` tree |
| `java/` | `codeql/java-all 9.3.0` | build-mode none |
| `csharp/` | `codeql/csharp-all 7.3.0` | build-mode none |
| `javascript/` | `codeql/javascript-all 2.10.1` | build-mode none (JS and TS) |
| `python/` | `codeql/python-all 7.2.5` | build-mode none |

No pack: C/C++ (the traced lane's `queries/appsec-graph-cpp` tables feed the same engine, and the
CPG is the stronger engine), Ruby, Rust (young library; not yet written), PHP (no CodeQL
extractor). Those languages fall back to the language server and tree-sitter.

Every pack has `qlpack.yml` and the same six files:

| File | What it is |
|---|---|
| `Symbols.qll` | `extensible predicate vulnerableSymbol(string package, string symbol)` |
| `Common.qll` | `relPath`, call `edge`, `VulnerableCall`, `EntryPoint` (with `getReason()`) |
| `CallEdges.ql` | caller_name, caller_file, caller_line, call_file, call_line, callee_name, callee_file, callee_line, callee_defined |
| `EntryPoints.ql` | name, file, line, reason |
| `Reachability.ql` | entry_name, entry_file, entry_line, caller_name, call_file, call_line, package, symbol |
| `TaintReach.ql` | source_file, source_line, sink_file, sink_line, package, symbol |

Column names are the contract with `dep_reachability_engines.TABLES`; a CSV whose header differs
is a gap (`codeql-table-invalid`), never partially read.

**Symbols are data.** `vulnerableSymbol` rows come only from the generated model pack
`appsec/<lang>-reachability-symbols` (`dep_reachability_codeql.py symbols`), built from
pattern-validated `{package, symbol}` pairs. Nothing from an advisory or a model is ever written
into a `.ql` file.

**Entry points** per language (`EntryPoint` in each `Common.qll`): Go `main`/`init` and functions
containing a `RemoteFlowSource`; Java `main`, servlet `do*`, `@*Mapping` methods and remote-input
readers; C# static `Main`, public `*Controller` actions and remote-input readers; JavaScript every
module top level, `Http::RouteHandler` functions and remote-input readers; Python every module
body, `main` and remote-input readers.

In a run (ADR-0023) `06-reachability-codeql` runs each pack against the database the
`02-codeql-<lang>` node retained, through `images/audit-codeql/scripts/codeql-reachability-lane.sh`;
`scripts/smoke_codeql_per_language.sh` exercises that path end to end.

Status: **written, not compiled here** (no CodeQL in the authoring container). Run
`scripts/smoke_codeql_reachability.sh` in WSL: it compiles each pack against the bundle and runs
it on `fixtures/dep-reachability/<lang>`. Expect a round of QL compile fixes, as with
`queries/mythos-cpp` and `queries/appsec-graph-cpp`.

Run plan (no shell; `dep_reachability_codeql.py plan --language go` prints it):
`codeql database create /scratch/db --language=<lang> --source-root=/workspace --build-mode=none|autobuild`,
then per query `codeql query run --additional-packs=/inputs/pack:/inputs/symbols:/opt/codeql/qlpacks
--model-packs=appsec/<lang>-reachability-symbols ...` and `codeql bqrs decode --format=csv`.
