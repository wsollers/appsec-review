# Dependency reachability (`06-cve-reachability`, brief E)

Decision record: [ADR-0022](decisions/ADR-0022-dependency-reachability.md). Code:
`appsec-review-process/dep_reachability.py` (core), `dep_reachability_engines.py` (adapters),
`dep_reachability_codeql.py` (CodeQL packs), `dep_reachability_lifecycle.py` (06 bindings),
`reachability.py` (CPG arbiter, extended). Query packs: `data/codeql-reachability/`.

## 1. What 06 answers

For every accepted SCA match (`02-sca-vulnerability-match`): can an entry point of the
application reach a call of the advisory's vulnerable symbol? The answer is `reachable` (with a
witness path), `unreachable` (CPG only, with the target it proved unreachable) or `unknown` (with
the reason and a gap). It feeds the ADR-0020 rule **Critical requires REACHABLE**: the report
arbiter (`finding_enrichment.py`) reads `outputs/cve-reachability.json`, so a dependency finding is
capped at High unless 06 says `reachable`.

Model text never decides reachability. No persona runs in 06.

## 2. Pipeline per match

1. **Component and language.** The SBOM component's ecosystem picks the analysis language
   (`dep_reachability.ECOSYSTEMS`): golang→Go, maven→Java, nuget→C#, npm→JS/TS, pypi→Python,
   cargo→Rust, composer→PHP, gem→Ruby, conan/generic/deb/rpm/apk→C/C++.
2. **Advisory symbols.** A reviewed map `inputs/cve-reachability-functions.json`
   (`{"<advisory id or alias>": ["name" | {"package": .., "symbol": ..}]}`) wins; otherwise the OSV
   index (`affected[].symbols` of the entry whose ecosystem and normalised package name match the
   component). Symbols must match `^[A-Za-z_$][A-Za-z0-9_$.:<>~-]{0,199}$`; rejected rows are
   counted, never echoed. No symbol → `unknown`, gap `no-advisory-symbols` (package presence only).
3. **Engines**, strongest first (`dep_reachability.ENGINES_BY_LANGUAGE`):

   | Language | Engines | Notes |
   |---|---|---|
   | C/C++ | `cpg`, `codeql` | CPG = Joern records of the accepted `02-code-property-graph` (vendored dependency sources are part of it when built with the target); CodeQL = traced `CallEdges`/`EntryPoints` tables from `02-codeql-sast` |
   | Go, Java, C#, JS/TS, Python | `codeql`, `lsp`, `treesitter` | CodeQL packs in `data/codeql-reachability/<lang>` |
   | Ruby | `codeql`, `treesitter` | no pack yet (gap) |
   | Rust, PHP | `lsp`, `treesitter` | no CodeQL pack (Rust library young; PHP has no extractor) |

4. **Lattice** (`dep_reachability.join`): `reachable` if `cpg`, `codeql` or `lsp` proves a path
   (strongest engine, shortest witness); `unreachable` only if the CPG ran, proved no path
   (complete search, no dynamic-dispatch escape, no coverage gap) and no other engine found even a
   name-matched call site; otherwise `unknown`. Tree-sitter never proves anything.
5. **Witness binding.** Each hop is `{function, file, line, sha256, calls_next_at?, resolution?, note?}`;
   `sha256` is the file's hash in the run's source projection. A hop outside the projection makes
   the match `unknown` (`witness-not-hash-bound`). The last hop is the application call site of the
   dependency symbol, or the vulnerable function itself when the dependency is vendored.

## 3. Entry points

Roots per language (step 5; `dep_reachability_engines.ENTRY_POINT_SOURCES`):

| Language | Name-based (CPG, CodeQL tables, LSP) | CodeQL `EntryPoint` class adds | Not covered |
|---|---|---|---|
| C/C++ | `main`, `wmain`, `WinMain`, `wWinMain`, `DllMain`, `LLVMFuzzerTestOneInput` | traced tables: `main`, no-internal-caller, address-taken | exported library API unless listed in the run file; callbacks registered at run time |
| Go | `main`, `init`, `ServeHTTP` | functions reading a `RemoteFlowSource` | goroutines started from reflection; plugin symbols |
| Java | `main`, `doGet`, `doPost`, `doPut`, `doDelete`, `service` | servlet `do*`, `@*Mapping` methods, remote-input readers | DI-wired beans without annotations, reflection, JNI |
| C# | `Main` | public `*Controller` actions, remote-input readers | minimal-API lambdas not reading request data |
| JS/TS | `main` | every module top level, `Http::RouteHandler` functions, remote-input readers | dynamic `require`, event emitters wired by string |
| Python | `main`, `__main__` | every module body, remote-input readers (views/handlers) | `getattr` dispatch, entry points declared only in packaging metadata |
| Rust | `main` | — | async runtimes' generated mains, proc-macro handlers |
| PHP, Ruby | — | — | everything: only run-supplied entry points and tree-sitter hints |

A run adds roots in `inputs/reachability-entry-points.json` (`{"entry_points": ["name", ...]}`,
the same file ADR-0020's code-finding arbiter reads). No root → `unknown`, never `unreachable`.

## 4. Inputs and hash binding in a run

`dep_reachability_lifecycle.bindings` puts every input into the 06 attempt's `inputs.json`, so any
change re-runs 06 and a tampered file is refused on validate:

| Input | Where | Binding |
|---|---|---|
| SCA matches, SBOM | accepted `02-sca-vulnerability-match`, `02-sbom-inventory` | accepted pointer + artifact sha256 |
| CPG | accepted `02-code-property-graph` | pointer, attempt tree hashes, envelope, result sha256, same source generation |
| CodeQL traced tables | accepted `02-codeql-sast` `b13-receipts.json` `graph_outputs` | as CPG, plus each CSV sha256 from the receipt |
| OSV | `data/feeds/osv` (or `APPSEC_OSV_ROOT`), judged at the SCA completion time | snapshot id + data timestamp |
| Reviewed map, entry points | `<run>/inputs/cve-reachability-functions.json`, `reachability-entry-points.json` | sha256 |
| CodeQL tables (other languages) | `<run>/inputs/dependency-reachability/codeql/<lang>/<Table>.csv` | sha256 per table |
| LSP call hierarchy | `<run>/inputs/dependency-reachability/lsp/<lang>.json` (`lsp_driver.py` output; sink queries carry `"sink_symbol": {"package", "symbol"}`) | sha256 |
| Tree-sitter | `<run>/inputs/dependency-reachability/treesitter-ast.json` (`treesitter_ast.py` output) | sha256 |

A missing or unverifiable source is a gap (`ENGINE_INPUT:engine-input-absent:*`,
`engine-input-not-current:*`, `engine-input-mixed-lineage:*`), never a block. Outputs:
`automatic-reachability-evidence.json` (rows `dependency_workers.build_reachability` validates),
`outputs/cve-reachability.json` (unchanged contract) and `outputs/dependency-reachability.json`
(`schemas/dependency-reachability.schema.json`: symbols, per-engine states, verdict, witness,
hints, gaps, counts).

## 5. Offline use

```
python3 appsec-review-process/dep_reachability.py --sca sca.json --sbom sbom.json --source-root <checkout> \
  [--cpg-attempt <02-code-property-graph attempt>] [--codeql-tables go=<dir>] [--lsp go=<lsp.json>] \
  [--treesitter <ast.json>] [--osv-root data/feeds/osv] [--reviewed-map map.json] --output out.json
python3 appsec-review-process/dep_reachability_codeql.py symbols --language go --symbols symbols.json --out <dir>
python3 appsec-review-process/dep_reachability_codeql.py plan --language go
```

## 6. WSL smoke (the user runs this)

```
scripts/smoke_codeql_reachability.sh                 # all five packs, needs audit-codeql:local
scripts/smoke_codeql_reachability.sh go java         # a subset
```

It checks the pack pins, generates the symbols model pack per fixture, runs each planned argv in
`audit-codeql:local` (network none, fixture/pack/symbols read-only, only scratch writable), then
decodes the CSVs and expects the fixture's vulnerable call to be `reachable`. The packs are
**written but not compiled here**; expect a round of QL compile fixes. Go needs the Go toolchain in
the image for `--build-mode=autobuild` (with a vendored `vendor/` tree it works offline); if the
image has none, the Go line FAILs at step 1 and that is an image request for brief C's owner.

## 7. OPEN

- The in-run CodeQL step for Go/Java/C#/JS/Python: packs and plan exist, but no job runs them in
  the container yet (needs a reachability mode in the `audit-codeql` lane script or a 06 container
  step; image files belong to brief C). Until then those tables come from `<run>/inputs/…`.
- LSP call hierarchy in a run: `lsp_driver.py` answers one round of queries; the iterative
  incomingCalls walk (sink → callers → … → entry) is not driven by any job yet.
- Tree-sitter AST in a run: no job publishes `treesitter-ast.json` yet.
- Advisory symbols: OSV has them mostly for Go; other ecosystems need the reviewed map.
- Vendored dependency sources per version (artifact repository) do not exist yet; a dependency
  without source is analysed only at its call sites.
