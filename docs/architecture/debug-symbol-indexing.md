# Build-bound debug-symbol indexing

## Decisions and scope

1. A run selects `compiler_target=clang|msvc`. The CLI spelling is
   `--compiler-target`; the Dagster launch tag is `appsec/compiler_target`.
   This is distinct from the existing target checkout path. The default is
   `clang`, preserving the existing native analysis lane. The resolved selection
   is immutable, hash-bound to the configuration, and part of submission and
   resume identity. Capacity overlays cannot change it.
2. The selector chooses the debug-symbol interpretation lane, not the machine's
   operating system. Clang-produced DWARF and MSVC-produced native PDB are the
   initial formats. Building arbitrary Visual Studio projects is not introduced
   by this feature; existing Windows build execution approval gates still apply.
3. `job_debug_symbol_indexing` consumes accepted, content-verified artifact
   evidence. It never searches a mutable target checkout for symbols. Its
   persisted `decide.target` unit selects `clang_dwarf` or `msvc_pdb`; the
   unselected extraction unit records an explicit skip without invoking its
   reader. Publication joins the selected lane and preserves upstream shards.
4. Binary/debug pairing must precede symbol publication. Use embedded DWARF,
   verified ELF build-ID/debug-link association, or PE CodeView/PDB GUID and age.
   Matching basenames, paths, or symbol names are not identity evidence.
   Unsupported pairing formats are named gaps rather than guessed matches.
5. Normalize compilation units, functions/signatures, address ranges, inline
   frames, source locations, and type layouts into a dedicated `debug_symbols`
   shard. The shared vocabulary is in `appsec_review.debug_symbols.contract`.
   Intervals are unsigned 64-bit half-open ranges; addresses are build-relative,
   not unqualified ASLR-dependent runtime addresses.
6. Source names from debug data are untrusted metadata. Source excerpts require
   a separately verified accepted source identity and checksum relationship.
   Unverified names never create an exact source binding. Public/partial symbols,
   optimization, unsupported location expressions, split debug data, and parser
   limits remain explicit per-family coverage gaps.
7. One typed tool, `query_debug_symbols`, serves symbol, address, source-range,
   type-layout, inline-frame, compilation-unit, coverage, and graph-link modes.
   It takes accepted identities, closed facets, bounded addresses and pagination,
   never SQL, shell, regular expressions, filesystem paths, or download URLs.
   Existing retrieval integrity, capability, response-byte and scope checks apply
   equally to MCP and in-process review cells.
8. Graph links are evidence-backed joins, not inferred call edges. Debug symbols
   do not establish taint flow, complete call graphs, runtime values, vulnerable
   dependency versions, exploitability, or absence of executable code.
9. Extraction is offline and resource-bounded. No target execution, debugger
   expression evaluation, embedded source-server execution, automatic symbol
   download, or external upload is permitted. Raw private symbols/tool output
   remain protected evidence; only normalized approved fields enter retrieval.
10. Producer and query telemetry uses existing structured events and operational
    metric aggregation. Events carry target, lane, counts, duration, coverage,
    gaps, limits, and tool identity; never raw source, symbol names, or private
    paths as metric labels. Failure and unavailable coverage are not zero-result
    success.

## Test-first acceptance matrix

Both compiler targets must exercise the same normalized contract. Tests precede
implementation within each chunk and use injected bounded readers, plus genuine
tool-produced fixtures where the required tools are available.

| Boundary | Required assertions |
| --- | --- |
| Run admission | Closed enum; CLI and launch tags; default; profile/overlay composition; immutable selection; changed-target resume refusal; submission identity separation. |
| Decision node | Persisted route; exactly one reader invoked; unselected lane skipped; both lanes rejoin publication. |
| Pairing | Correct embedded/separate match; binary and symbol hash drift; wrong PDB GUID/age; wrong build ID; ambiguous companion; unsupported input; no name-only trust. |
| Normalization | Functions/signatures, layouts/member offsets, ranges, inline ancestry and compilation units from DWARF and PDB; deterministic identities; unsupported records named. |
| Source authority | Path-only mapping stays non-exact; checksums verified against accepted bytes; external paths never opened; missing source remains binary-resolving evidence. |
| Index publication | Shard integrity, deterministic fingerprint, preserved upstream shards, declared datasets, protected raw artifacts, coverage inventory, resume invalidation. |
| Retrieval | Every mode; exact subjects; half-open range boundaries; 64-bit addresses; stable pages; cursor query binding; cross-artifact/package denial; byte/time/row bounds; unavailable versus empty. |
| Safety | No network/execution; malformed/truncated reader output; tool exit/timeout; oversized files/records; dangerous source-server metadata retained only as data. |
| Observability | Decision/scope/query events, numeric counts and durations, gap and truncation counts, metric aggregation, no private text labels. |
| Regression | Existing run-selection, graph topology, artifact indexes, MCP, review capabilities, dataset inventory and skill-separation suites. |

## Implementation ownership

The manager owns launch/configuration/orchestration integration and this design.
Independent chunks own symbol readers, the indexing job, and retrieval/capability
integration, each with its own focused tests. Shared contract changes are
reconciled by the manager. No image pin is changed without a live build on its
owning host, and no feature branch is pushed without user authorization.

Implementation status and host-dependent validation limitations are recorded in
the accompanying implementation report when integration is complete.
