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

## Workflow and failure semantics

```text
start / review-start
    compiler_target + profile + overlay
                 |
    frozen resolved configuration
                 |
accepted artifact catalog + accepted source identities
                 |
          decide.target
           /          \
 extract.clang_dwarf   extract.msvc_pdb
       selected          skipped          (or the reverse)
           \          /
       acceptance.publish_handoff
                 |
   immutable debug_symbols SQLite shard
                 |
   accepted composite manifest + dataset inventory
                 |
      shared retrieval core
         /              \
 review-cell loop     read-only MCP
```

Both extraction units are visible in the orchestration graph. A nonselected
unit does no artifact parsing and invokes no tool. Its explicit skip is not
an unavailable-coverage gap for the selected target. A selected lane with no
usable debug information publishes unavailable or partial coverage, including
the reason; it never substitutes the other compiler lane.

Malformed input, missing tools, unsupported debug variants, and exhausted parser
bounds are coverage failures. Hash substitution, an escaped run-owned reference,
or a conflicting frozen selection is an integrity failure and prevents
publication. The target program is never launched to recover missing facts.

Resume reuses accepted work only when configuration, accepted upstream handoffs,
artifact hashes, parser/tool identity and parser bounds still match. A changed
compiler target needs a new application run. Rebuilding with debug flags creates
a different artifact and is not a substitute for matching the reviewed artifact.

## Normalized records and indexes

The shared contract defines `SymbolRecord`, `SourceSpan`, `AddressRange`,
`Extraction`, and the closed record/query enums. Each indexed record additionally
retains the accepted artifact identity and SHA-256, debug-artifact SHA-256,
selected lane, producer identity, native record key, and resolving evidence.
Parent keys preserve lexical/inline ownership; they are not call edges.

| Record family | Required meaning | Missing information |
| --- | --- | --- |
| Symbol | Function/data/type identity and recorded name; recorded signature when available. | A missing signature or parameter type is unknown, not an inferred prototype. |
| Source range | Half-open binary range and recorded line/column; exact source identity only after checksum binding. | Path-only source names cannot authorize excerpts or establish a source revision. |
| Type layout | Recorded byte size, member offsets, array bounds and referenced types where emitted. | Dynamic layout expressions, opaque types and absent private type streams are explicit gaps. |
| Inline frame | Recorded inline origin and parent/address relationship. | Optimization may omit or merge information; do not manufacture a unique frame. |
| Compilation unit | Recorded compiler/unit metadata associated with this artifact. | Metadata is not complete build provenance; accepted build receipts remain authoritative. |
| Graph link | An independently supported link to an existing accepted entity. | Names alone nominate a match; they do not establish an exact cross-build graph link. |

Use the common entity/location/relation and coverage tables, plus indexed
artifact/family/subject facets and address intervals. Unsigned address ordering
must preserve the full range including the exclusive `2**64` endpoint; fixed-width
hex storage is suitable where SQLite signed integers are insufficient.
Index construction, not a model turn, does parsing and expensive normalization.

Matching source records requires a checksum algorithm actually supplied by the
debug format and verification against accepted source bytes. An absolute debug
path is never opened. Unbound private source names are omitted or hash-labelled
in public index payloads; raw names remain in protected evidence.

## Query and authority contract

`query_debug_symbols` uses the common retrieval response envelope, deterministic
pagination, accepted-shard verification, coverage rows and resolving identities.
The eight modes are `symbol`, `address`, `source_ranges`, `type_layout`,
`inline_frames`, `compilation_units`, `coverage`, and `graph_links`.
An address is meaningful only with an exact artifact identity. Source-range
lookups use accepted source identities, not arbitrary source path arguments.
Row limits are at most 100; common byte, page, depth and timeout policies still
apply. A cursor is bound to the query and accepted manifest.

Review-cell and MCP capability checks must constrain the requested and returned
subjects. Adding a tool name to an allowlist is insufficient without query and
response scope enforcement. An unsupported mode/input combination is rejected,
not interpreted as an unconstrained enumeration.

Facts read from debug bytes are observed metadata. Their source/graph
associations are computed mappings whose exactness must be recorded separately.
Names and signatures never by themselves establish a security property.

No new runtime skill is needed merely to describe this retrieval tool:
review cells receive the capability-filtered tool schema in their turn catalog.
Runtime skills are for separately configured model jobs, not symbol parsers or
review-cell tools. Existing role permissions and the shared catalog must be
updated rather than copying repository-agent guidance into worker prompts.

## Telemetry contract

Use `DEBUG_SYMBOL_TARGET_SELECTED`, per-artifact completion/failure events,
`DEBUG_SYMBOL_INDEX_COMPLETED`, and `DEBUG_SYMBOL_QUERY_COMPLETED`, alongside
existing job/unit/tool lifecycle events. Index completion reports
`compiler_target`, `artifact_count`, `record_count`, `gap_count`, and
`duration_ms`. Query completion reports its closed `mode`, `returned_count`,
`gap_count`, `truncated_count`, and `duration_ms`.

The run-metric `debug_symbols` section exposes the latest index snapshot rather
than double-counting records across attempts. It counts attempts, failures, and
observed query work separately. Unknown/missing numeric measurements stay null
with metric gaps. These are operational quality/coverage metrics, not counts of
confirmed vulnerabilities.

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
