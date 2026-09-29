# appsec/cpp-graph-queries

Table queries run by `02-codeql-sast`'s traced C/C++ lane (`codeql-cpp-traced`) on the traced
database, for brief E's reachability and taint work. Output is locator tables, never findings:
`/scratch/graph/<Query>.csv` in each `tools/codeql-cpp-traced-<unit>/` trial. Names and columns
are the contract with brief E (`docs/language-servers.md` §6):

| Query | Columns |
|---|---|
| `CallEdges.ql` | caller_name, caller_file, caller_line, call_file, call_line, callee_name, callee_file, callee_line, callee_defined |
| `EntryPoints.ql` | name, file, line, reason (`main`, `no-internal-caller`, `address-taken`) |
| `FlowSources.ql` | source_type, file, line, function |

Paths are checkout-relative; "" means outside the source root (system headers). Edges are static
(`Call.getTarget()`): virtual dispatch and calls through function pointers resolve to the
declared target only, so a missing edge is not proof of unreachability.

Status: **written, not yet compiled here** (no CodeQL in the authoring container). The smoke script
compiles them: `scripts/smoke_lang_servers.sh audit-codeql-native`. Expect a round of QL compile
fixes, as with `queries/mythos-cpp`.

Manual run on a traced database (repo mounted at /workspace):

```
codeql query run --database=/scratch/db --additional-packs=/opt/codeql/qlpacks \
  --output=/scratch/graph/CallEdges.bqrs /workspace/queries/appsec-graph-cpp/CallEdges.ql
codeql bqrs decode --format=csv --output=/scratch/graph/CallEdges.csv /scratch/graph/CallEdges.bqrs
```
