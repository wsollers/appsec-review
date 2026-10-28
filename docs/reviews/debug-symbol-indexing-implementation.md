# Debug-symbol indexing implementation

## Result and boundaries

The [design](../architecture/debug-symbol-indexing.md) is implemented as a
default-enabled accepted-artifact producer, a dedicated `debug_symbols` index,
and bounded `query_debug_symbols` retrieval shared by review cells and MCP.
The immutable run-start selection is `--compiler-target clang|msvc`, separate
from the target checkout path. The default is `clang`. Both extraction branches
are visible in the DAG; the persisted decision invokes exactly one reader, the
other records a semantic skip, and publication joins both.

The normal CLI, Dagster wave and project-build graph include the job without a
separate opt-in. The selector chooses the reader lane, not a build-host OS or an
MSVC installation. Existing Windows build-execution approval gates are unchanged.
Operators must configure approved host-local LLVM executable paths and SHA-256
pins as described in [operations](../operations/debug-symbol-indexing.md).
The central configuration intentionally does not invent machine-specific pins.
Missing tools and unsupported formats produce named unavailable coverage.

No target program is executed, debugger expression evaluated, source-server
instruction followed, symbol downloaded or evidence uploaded. The feature does
not provision an isolated parser host. Raw private records stay protected;
public records use accepted artifact identities and separately verified source
bindings. Symbols do not establish complete call graphs, runtime values, taint,
exploitability or clean coverage.

## Partition and integration

The manager settled the shared enums, records, identities and acceptance matrix
before assigning three isolated implementation worktrees. Each owner supplied
its own unit tests and committed without pushing.

| Ownership | Implementation commits |
| --- | --- |
| Manager: contracts, launch/configuration, frozen identity, orchestration, metrics aggregation and documentation | `e904db96`, `a8ca5c9d`, `7479e038`, `677f0293` |
| Reader agent: bounded offline DWARF/native-PDB readers, pairing, native inline annotations and genuine compiler fixtures | `e49b85cb`, `066a12ee`, `1e9d52f8` |
| Producer agent: accepted-input decision/extraction/publication job, normalized shard, source authority, coverage and datasets | `0f7aeb17` |
| Retrieval agent: indexed queries, unsigned address lookup, MCP/review capabilities, schemas, roles and query telemetry | `49503f58` |
| Manager: composite graph join, bounded source lookup/cache, real-format end-to-end acceptance and integrity reconciliation | `b8dbf9f7`, `9e47a80f` |

Chunks were merged one at a time with merge commits. No branch was pushed and
no pull request was opened. No shared review-host image pin was changed.

Integration resolved these cross-boundary issues:

- The compiler selection is compared in the first-error safety envelope and
  compiler-only tags cannot bypass native configuration restrictions.
- Telemetry imports the symbol contract without eagerly entering configuration,
  avoiding a fresh-process retrieval/configuration import cycle.
- Default enablement is asserted for both compiler targets. The project-build
  graph explicitly joins the symbol producer before artifact-security
  finalization, retaining the graph's single-terminal invariant. Disabled
  symbol jobs remain transparent.
- Source resolution uses accepted path/checksum lookup maps instead of a
  per-record source-inventory scan. Cached byte-line offsets have explicit
  memory bounds and preserve CR, LF and CRLF boundaries.
- Accepted binary/debug hash changes and escaped references are framework
  integrity failures that block publication. Ordinary exporter failures remain
  observable, named coverage gaps; exception diagnostics are not exposed as
  private symbol metadata.
- End-to-end tests exercise all eight query modes, MCP parity, exact source
  bindings, artifact hashes, privacy and metrics. Positive inline tests check
  the first/last included address and the excluded half-open endpoint for
  Clang/DWARF, Clang/LLD native PDB and genuine MSVC native PDB.

## Observability

Structured decision, artifact outcome, index-completion and query-completion
events are unconditional in the default path, alongside standard unit/job/tool
events. Run metrics expose the selected target, distinct attempts and failures,
latest index counts/duration, query work, truncation and gaps. Repeated attempts
do not double-count the latest accepted record snapshot. Missing measurements
remain null with metric gaps. Names and private paths are not metric labels.

## Verification

The pre-merge feature acceptance revision is
`9e47a80f4f312a19fa23af5e6f95a27eabfa4ea3`, tested on Windows with a
checkout-local Python 3.14 environment. **245 feature tests passed**:

```powershell
.venv\Scripts\python.exe -m pytest `
  tests\test_compiler_target_selection.py `
  tests\test_debug_symbol_end_to_end.py `
  tests\test_debug_symbol_indexing.py `
  tests\test_debug_symbol_metrics.py `
  tests\test_debug_symbol_readers.py `
  tests\test_debug_symbol_retrieval.py `
  tests\test_debug_symbol_source_bounds.py `
  tests\test_debug_symbol_workflow.py `
  --basetemp=test\tmp\debug-symbol-final-acceptance -q
```

Fixtures are self-generated from owned C sources, never executed, and include
LLVM 18.1.3 and genuine MSVC 19.51.36260.0/linker 14.51.36260.0 artifacts.
The reader owner additionally validated real hash-pinned LLVM exporters offline,
with networking disabled. Portable unit tests parse those genuine captured
exports and exercise the bounded subprocess boundary separately.
[Fixture provenance](../../tests/fixtures/debug_symbols/README.md) records
commands, private-path audits and exact format limitations.

Neighboring regression results at `b8dbf9f7` are recorded separately rather than
added to overlapping feature-test totals:

| Regression set | Result |
| --- | --- |
| Topology, Dagster definitions, job selection, inventory/resume, guidance composition | 91 passed; 5 failed |
| Run selection, artifact indexing, retrieval interfaces/core/artifacts/graph, MCP/review capabilities, cells, review metrics, guidance routing and skill separation | 210 passed; 2 failed; 2 skipped |
| Operator scripts | 17 passed; 126 failed; 17 skipped |

The complete operator suite produced the identical pass/fail/skip counts on the
original base `fcac43068d17f139a9d94393b03fe128c6127f12`; its Bash/Unix process,
path, symlink and timestamp assumptions are not available on this Windows host.
The modified PowerShell start wrapper also passed the host's PowerShell parser.

Every failing test in the other two regression sets was checked in a separate
baseline worktree with its own environment:

| Existing failure or host gap | Evidence |
| --- | --- |
| Managed evidence admission in Dagster/retrieval | Baseline also requires verified POSIX custody unavailable on Windows. |
| Multiprocess branch completion deadline | Baseline reproduces the same live-thread deadline assertion. |
| Inventory accepted-attempt reuse | Baseline reproduces `KeyError: 'reused'`. |
| C++ producer topology assertion | Baseline also has the additional IR dependency in the AST producer. |
| Full live wave | Feature run timed out inspecting a Docker tool image; baseline also could not complete, reaching an unavailable configured Claude CLI. No full deployed review is claimed. |
| Runtime-skill symlink rejection | Baseline reproduces Windows privilege error 1314 when creating the fixture symlink. |

Additional baseline probes reproduced the preinstalled CodeQL build-image-pin
expectation mismatch and Linux peer-authenticated Unix-socket requirement in the
legacy stop-policy test. Host-owned pins and security safeguards were not
modified to force these tests green.

The final integrity reconciliation then passed 51 producer/source/end-to-end
tests and the complete 245-test feature set on its committed revision. Broader
host-level execution remains a named validation gap, not evidence that a
deployed target or all repository tests are clean.

## Remaining operational and format limits

Approved executable identities must be configured on the execution host before
real extraction. No tools, images, compiler host or production deployment were
provisioned by this change. A full live review still needs its normal approved
tool/model environment.

LLVM 18.1.3 `pdb2yaml --all` crashes on retained MSVC `S_REGREL32` variable
records. The genuine optimized MSVC fixtures retain layouts and real inline
annotations without that exporter-triggering unused function copy; affected
PDBs outside this tested scope remain explicit tool failures. Mach-O/dSYM,
portable .NET PDB, split/supplementary DWARF, unsupported location expressions,
separated inline-code chunks and unavailable source checksums remain named
coverage gaps. Native PDB inline ranges come from bounded native binary
annotations, not invented procedure-wide fallback intervals.

## Main reconciliation and execution follow-up

Main `093f26d5846d61465dc2b5228fba33ca60605643` was merged without rebasing in
`409fab6ad3cb2b0420cf5ef96a9ab12e92401040`. Fourteen conflicting files were
reconciled, retaining main's topology-derived CLI `_graph_order()`, both target
acquisition modes, binary evidence, syntax retrieval, CodeQL neighborhood
capabilities and role permissions alongside debug-symbol retrieval. The CLI
resume unit fixture now uses the real registry validation, and new parser cases
cover compiler selection with both `--target` and `--system`.

The user explicitly permitted this session to finish the merge and focused
unit checks on its existing Windows worktree after main introduced the
Linux/WSL-only development rule. **342 focused unit tests passed** on the
committed merge:

```powershell
.venv\Scripts\python.exe -m pytest `
  tests\test_compiler_target_selection.py `
  tests\test_debug_symbol_workflow.py `
  tests\test_debug_symbol_retrieval.py `
  tests\test_debug_symbol_metrics.py `
  tests\test_debug_symbol_indexing.py `
  tests\test_debug_symbol_source_bounds.py `
  tests\test_retrieval_interfaces.py `
  tests\test_syntax_retrieval.py `
  tests\test_guidance_compose.py `
  tests\test_guidance_routing.py `
  tests\review\test_capability.py `
  tests\review\test_cell_retrieval.py `
  tests\test_job_selection.py `
  tests\orchestration\test_topology.py `
  --basetemp=test\tmp\debug-symbol-main-merge-final -q
```

No live review, integration or acceptance run was performed for this merge.
The published tool-catalog parity and the additive capability/scoping behavior
passed their unit checks.

The user subsequently questioned the host-local executable prerequisite.
Reusing the exact approved compiler image recorded in each accepted build
receipt, through fresh restricted execution with read-only accepted artifacts,
is the proposed correction; it is **not implemented in this revision**.
Reader availability and an approved fallback for prebuilt artifacts still need
an explicit execution contract. The merge monitor was asked to hold landing
rather than treat conflict resolution as completion of that operational work.
