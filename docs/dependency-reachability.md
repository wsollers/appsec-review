# Dependency reachability (`02-codeql-<lang>`, `06-reachability-*`, `06-cve-reachability`)

Decision records: [ADR-0022](decisions/ADR-0022-dependency-reachability.md) (brief E: symbols,
witness, entry points, failure modes) and [ADR-0023](decisions/ADR-0023-per-language-codeql-reachability.md)
(brief G: per-language CodeQL nodes, engine jobs, correlator; supersedes parts of ADR-0017 and
ADR-0022). Code: `appsec-review-process/codeql_sast.py` (per-language nodes),
`dep_symbol_resolver.py` (symbols through the language), `reachability_engine_jobs.py` (the two
engine jobs), `dep_reachability_correlator.py` + `dep_reachability_lifecycle.py` (06),
`dep_reachability_engines.py` (adapters), `dep_reachability_codeql.py` (packs),
`reachability.py` (CPG arbiter), `dependency_reachability_report.py` (report section 3B). Query
packs: `data/codeql-reachability/`.

## 1. What is answered

For every accepted SCA match (`02-sca-vulnerability-match`): can an entry point of the
application reach a call of the advisory's vulnerable symbol? The answer is one of

| Verdict | Meaning |
|---|---|
| `reachable` | a proof-capable engine (`codeql`, `ir`) has a witness from an entry point to the call, every hop bound to the sha256 of its file in the run's source projection |
| `unreachable` | only the `ir` engine (complete CPG search), with the vulnerable function's source in the graph, a hash-bound target, no other engine `reachable` and no hint of a call site |
| `conflict` | engines disagree (`reachable` vs `unreachable`); both are listed and left for review, never resolved |
| `unknown` | everything else, with every engine's reason and gaps; never "not vulnerable" |

It feeds the ADR-0020 rule **Critical requires REACHABLE**: the report arbiter
(`finding_enrichment.py`) reads `outputs/cve-reachability.json`, where `conflict` and `unknown` are
both `unknown`, so a dependency finding is capped at High unless 06 says `reachable`.

Model text never decides reachability. Language-server call hierarchy and tree-sitter results are
**hints only** and can never make a verdict `reachable` (ADR-0023; in ADR-0022 the language server
could prove a path).

## 2. Graph

```
00-intake ─┬─ 02-codeql-{csharp,go,java,javascript,python,ruby,rust} ─┐
02-native-build ── 02-codeql-cpp ─────────────────────────────────────┤
02-sbom-inventory ── 02-sca-vulnerability-match ──┬───────────────────┴─ 06-reachability-codeql ─┐
02-code-property-graph, 02-ir-facts ──────────────┴───────────────────── 06-reachability-ir ─────┤
                                                                          06-cve-reachability ───┴─ claim-ledger-routing, 07, 13, 10
```

### 2.1 `02-codeql-<lang>` (one node per CodeQL language)

The graph is static: all eight nodes exist in every run and run in parallel in the Docker pool
(`full_review`; the standalone Dagster job `codeql_sast` runs all eight).

| Node | Gating | Build mode | No language in the checkout | Language present but not analysable |
|---|---|---|---|---|
| `02-codeql-cpp` | waits for `02-native-build` | `none` always, plus one `traced` replay per native unit (`audit-codeql-native`) | SKIPPED `not-applicable-language-absent` | no native unit: gap `language not built: <cause>; ran --build-mode none only` |
| `02-codeql-csharp`, `02-codeql-java` | intake | `none` (no build needed; fidelity gap recorded) | SKIPPED | — |
| `02-codeql-javascript` (JS + TS), `02-codeql-python`, `02-codeql-ruby` | intake | `none` | SKIPPED | — |
| `02-codeql-go` | intake | — | SKIPPED | OK_WITH_GAPS `language not built` (no build-mode none, no Go build step) |
| `02-codeql-rust` | intake | — | SKIPPED | OK_WITH_GAPS (no rust suite pinned in `tool.json`) |

PHP has no CodeQL extractor and gets no node (language-server / tree-sitter hints only).

Each node publishes `codeql-language.json` (`schemas/codeql-language.schema.json`): the ADR-0017
leads (claim-ledger producer row per node, P1 `codeql-security-query`) and one **database
pointer** per completed lane. The lane (`codeql-sast-lane.sh ... keep-db`) leaves the finalized
database in its scratch; the worker moves it to `<run>/data/codeql-databases/<job>/<attempt>/<key>/`
(outside the attempt, so the attempt tree hash stays small) and records
`{database_id, build_mode, unit_id, bundle_version, tool_metadata_sha256, image_digest,
source_snapshot_sha256, store_path, tree_sha256, files, bytes}`. Consumers re-hash the store
(`codeql_sast.verify_database`) and treat a mismatch as a gap (`codeql-db-changed`), never a rebuild.

**Compatibility note for readers of `02-codeql-sast`:** the job, its contract `codeql-sast` and
`codeql-sast.json` are gone. Leads are in `jobs/02-codeql-<lang>/attempts/<id>/codeql-language.json`
(same lead shape plus `language`), the traced C/C++ receipts (`graph_outputs`) in
`jobs/02-codeql-cpp/attempts/<id>/b13-receipts.json`. The claim ledger reads all eight producers.

### 2.2 Advisory symbols through the language (`dep_symbol_resolver.py`)

Symbols come from the reviewed map `inputs/cve-reachability-functions.json` (wins) or the OSV index
judged at the SCA completion time (ADR-0022 decision 2). The resolver maps them to the names the
language uses, reading the vendored dependency's own manifest in the source projection (bounded,
link-free, bytes only):

| Ecosystem | Manifest read | Name produced (`vulnerableSymbol(package, symbol)`) |
|---|---|---|
| PyPI | `*.dist-info/top_level.txt`, `RECORD`; `__init__` re-exports | import module + member / `Type.member`, submodule members |
| npm | `node_modules/<name>/package.json` `exports`/`main`/`module` (ESM vs CJS) | bare specifier + export; deep import `pkg/sub` as `default` |
| Maven | jar listing (`zipfile`), `pom.properties`, shade relocations, `META-INF/versions/<n>` | Java package + `Type.method` (and the relocated package) |
| Go | `go.mod` `replace`, `vendor/modules.txt` | import path + function / `Type.Method` (imports keep the original path) |
| NuGet | `packages/<id>.<version>/lib/<tfm>/*.dll` names, `.nuspec` | namespace (assembly name, a recorded heuristic) + `Type.Method` |
| Cargo | `vendor/<crate>/Cargo.toml` `[lib] name` | `lib_name::path` |
| Packagist | `vendor/<v>/<p>/composer.json` PSR-4 | namespace (hints only) |

Every step is recorded in the engine row's `resolution`. Without a vendored manifest the name is
derived by convention, the step says so, and the gap `dependency-source-absent:<eco>:<pkg>` limits
the tier to `direct`. **Tiers**: `direct` (the vulnerable call is in application code) and
`through-dependency` (the call is inside the vendored dependency source, i.e. application →
dependency API → vulnerable symbol).

### 2.3 Engine jobs (one table shape)

Both publish `engine-reachability.json` (`schemas/engine-reachability.schema.json`): one row per SCA
match with `verdict`, `tier`, `symbols`, `resolved`, `resolution`, `witness`, `taint_paths`,
`target`, `database_ids`, `reason`, `gaps`, plus a per-language state (`ran`, `no-matches`,
`no-database`, `no-pack`, `no-engine`, `gap`).

* **`06-reachability-codeql`**: per language with matches and a retained database, the pinned pack
  (`CallEdges`, `EntryPoints`, `Reachability` = `edge*` from `EntryPoint` to a `VulnerableCall`,
  `TaintReach` = `TaintTracking::Global` from `RemoteFlowSource`) runs in one `audit-codeql`
  container (`codeql-reachability-lane.sh LANG THREADS RAM_MB`; network none; database, pack and
  the generated symbols pack mounted read-only; the lane copies the database into its scratch).
  Languages run in parallel inside the job (`reachability_parallel_languages`, default 2). C/C++
  reads the traced `CallEdges`/`EntryPoints` tables the `02-codeql-cpp` receipts hash (no
  container). Ruby, Rust: `no-pack`. Never `unreachable`.
* **`06-reachability-ir`**: `reachability.py` over the accepted CPG plus IR facts
  (`CpgEngine`) for native ecosystems (`conan`, `generic`, `deb`, `rpm`, `apk`). The only engine
  that may say `unreachable`, and only with the vulnerable function defined in the graph.
  Java bytecode, .NET IL, Rust MIR and Go SSA engines plug in behind the same interface (TODO G).

### 2.4 Correlator (`06-cve-reachability`)

`dep_reachability_lifecycle.bindings` binds both engine tables (accepted pointer, attempt tree
hashes, same source generation and the same SCA attempt as the match set; a stale or mixed table is
a gap, `engine-input-stale:*` / `engine-input-mixed-lineage:*`), the OSV snapshot identity, the
entry points and the hint documents; `dep_reachability_correlator.correlate` applies §1. Outputs,
all re-derived byte-for-byte on validate:

| File | Reader |
|---|---|
| `outputs/cve-reachability.json` (unchanged contract) | report arbiter, 07, 12 |
| `outputs/dependency-reachability.json` (per-match evidence from every engine; `verdict` may be `conflict`) | reviewers |
| `outputs/dependency-reachability-summary.json` / `.md` | 10 (section 3B), claim ledger, 07/08/09/12 via the supporting-evidence menu |

The claim ledger (`claim-ledger-routing`, new edge from 06) annotates dependency lead claims: a
`reachable` match is a P1 review claim; a `conflict` gets a review obligation ("resolve the
conflicting reachability engine verdicts before scoring").

## 3. Entry points

Unchanged from ADR-0022 decision 7 (`dep_reachability_engines.ENTRY_POINT_SOURCES`):

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

A run adds roots in `inputs/reachability-entry-points.json` (`{"entry_points": ["name", ...]}`).
No root → `unknown`, never `unreachable`.

## 4. Inputs and hash binding in a run

| Input | Read by | Binding |
|---|---|---|
| SCA matches, SBOM | both engines, 06 | accepted pointer + artifact sha256; 06 checks the engines used the same SCA attempt |
| CodeQL databases | `06-reachability-codeql` | pointer in the accepted `02-codeql-<lang>` result, store tree sha256 re-hashed before use |
| CodeQL traced tables (C/C++) | `06-reachability-codeql` | CSV sha256 from the accepted `02-codeql-cpp` receipts |
| CPG, IR facts | `06-reachability-ir` | pointer, attempt tree hashes, envelope, result sha256, same source generation |
| OSV | engines (symbols), 06 (identity) | snapshot id + data timestamp, judged at the SCA completion time |
| Reviewed map, entry points | engines, 06 | sha256 (`<run>/inputs/...`) |
| LSP call hierarchy, tree-sitter AST (hints) | 06 | sha256 (`<run>/inputs/dependency-reachability/lsp/<lang>.json`, `treesitter-ast.json`) |

Run-supplied CodeQL tables under `inputs/dependency-reachability/codeql/` are no longer read.
A missing or unverifiable source is a gap, never a block.

## 5. Offline use

```
python3 appsec-review-process/dep_symbol_resolver.py --ecosystem pypi --package PyYAML --version 5.3.1 \
  --symbols symbols.json --checkout <checkout>
python3 appsec-review-process/dep_reachability_codeql.py symbols --language go --symbols symbols.json --out <dir>
python3 appsec-review-process/dep_reachability_codeql.py plan --language go
python3 appsec-review-process/dep_reachability.py ...        # brief E's single-process analyser (hints never prove)
```

## 6. WSL (the user runs these)

```
# rebuild both CodeQL images (they COPY scripts/: keep-db and codeql-reachability-lane.sh are new)
python3 -B images/image_build.py build audit-codeql audit-codeql-native
# new B16 records (the image ids change)
python3 -B images/registry_records.py generate && python3 -B images/registry_records.py check
# per language: keep-db lane, retained-database hash, reachability lane, fixture call REACHABLE
CODEQL_IMAGE=audit-codeql:local scripts/smoke_codeql_per_language.sh
# brief E's pack-only smoke (plan argv), still valid
scripts/smoke_codeql_reachability.sh
```

The packs are **written but not compiled in the authoring container**; expect a round of QL
compile fixes (as with `queries/appsec-graph-cpp`). Until the image is rebuilt and registered,
every `02-codeql-<lang>` node is `UNAVAILABLE` (a gap) and every CodeQL reachability row is
`unknown`.

## 7. OPEN

See `appsec-review-process/TODO.md` section G. In short: image rebuild + B16 records; QL compile
round; Go toolchain/build for `02-codeql-go`; a Rust suite for `02-codeql-rust`; Ruby/Rust packs;
Java bytecode, .NET IL, Rust MIR, Go SSA engines; the LSP incomingCalls walk and tree-sitter AST
in a run (hints are still run-supplied); per-language "incomplete call graph" reasons for
reflection/DI/serialisation; OSV symbols outside Go; vendored dependency sources per version.
