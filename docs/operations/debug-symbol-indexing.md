---
title: "Debug-symbol indexing"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_debug_symbol_indexing"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Debug-symbol indexing

`job_debug_symbol_indexing` is enabled by default in the normal review graph.
It consumes accepted native binary/debug artifacts after artifact indexing;
no separate enable flag or manual job launch is needed. It does not rebuild a
target to invent debug information.

Select the compiler/debug lane at run start:

```powershell
appsec-review start --target targets\customer --compiler-target clang
.\scripts\review-start.ps1 -CompilerTarget msvc
```

`--target` remains the checkout path. The equivalent Dagster tag is
`appsec/compiler_target=clang|msvc`. The default is `clang`; resume restores the
frozen choice. The selector chooses the symbol reader, not the build-host OS or
an MSVC installation.

## Managed reader environments

No host-local LLVM installation or executable-path configuration is required.
For build-produced artifacts, extraction starts a fresh instance of the exact
immutable image recorded in that artifact's accepted language-build receipt.
An accepted receipt with `build_outcome="built"` remains eligible when its
`terminal_status` is `COMPLETED_WITH_GAPS`; provenance gaps do not select a
different image. Only the receipt's accepted `artifacts` participate, never
`rejected_artifacts`. Older receipts without `build_outcome` retain the
`SUCCEEDED` fallback.
It does not resolve a mutable compiler tag, reuse the dirty build container,
rerun build scripts, or execute the target. Missing or invalid image provenance
in an accepted build receipt is an integrity failure.

The shared native compiler image provisions the exact pinned `llvm-18` package,
including `/usr/bin/llvm-dwarfdump-18` and `/usr/bin/llvm-pdbutil-18`, and checks
both versions at image-build time. Consumer compiler images inherit those tools.
The package-owned Python export driver is staged into private run-owned
provisioning storage so sibling-container execution also works from the Dagster image.
Its bytes are compared with the installed payload before and after execution;
the launcher is not a customer evidence object or a shared content-store artifact.
Its isolated interpreter disables environment/user imports and site startup hooks.
Only the selected accepted input file and this driver are mounted read-only;
run-owned scratch is the only writable bind. Network, root filesystem writes,
capabilities and privilege escalation remain disabled.

Prebuilt artifacts use the already provisioned `tool-native-cpp` image: the
catalog declares the approved recipe, and the run's frozen host bindings supply
its immutable image ID. Planning (including repair before this job has run),
decision validation and export all use that same frozen binding, verified against
the run's resolved configuration and retained `host-pins.toml`. Missing or
mismatched bindings fail explicitly; changing the host's current pins cannot
change an existing run's reader image or reuse identity.
The same approved image is an explicit compatibility fallback when a
recorded compiler image is unavailable, cannot run on the execution platform,
or predates the readers. The attempted image, outcome and fallback reason are
retained and measured; this never changes the selected DWARF/PDB lane. Parser
failures, timeouts, output bounds and image-identity mismatches do not trigger
another-reader retries. Missing fallback infrastructure remains an explicit
failure, never a successful empty index.

Both lanes use LLVM's offline readers; native PDB parsing needs neither DIA nor
a Windows reader host. The runtime never discovers host tools on PATH, downloads
readers, follows source-server instructions, or fetches symbols. The former
`reader.tools` host-path settings are rejected rather than silently ignored.
Tool identity binds the immutable image, declared `job_debug_symbol_indexing`
release (or `platform` release), typed execution policy and accepted output
receipts. Supplied launcher, reader source and tool-manifest payloads remain
excluded from customer-evidence hashing. The format contract uses LLVM 18.1.3.
Fixtures include both Clang/LLD-produced and genuine MSVC 19.51-produced PDBs.
LLVM 18.1.3 has a known `pdb2yaml --all` crash on retained MSVC `S_REGREL32`
records; these artifacts report tool-failure coverage, not empty successful
symbol sets. See the fixture provenance for the precise tested scope.

## Inputs and bounds

Clang/DWARF accepts embedded ELF debug information or an explicitly supplied
separate debug file whose build ID/debug-link association verifies. MSVC/PDB
accepts native MSF/CodeView PDBs whose GUID and age match the PE RSDS record.
Basenames are not pairing evidence. Missing or ambiguous companions are gaps.
Mach-O/dSYM, portable .NET PDB, split/supplementary DWARF and unsupported debug
records are not silently reinterpreted as supported native evidence.

Default limits are 128 catalog candidates **including debug companions**, 512 MiB per input file, 16 MiB per
export/normalized output, 100,000 records, nesting depth 128 and 120 seconds per
reader. These live under the job's central `settings` / `settings.reader`;
invalid types and unknown settings are rejected. Raw inputs, source names and
reader records remain protected run-owned evidence. Public index rows retain
verified artifact identities and approved normalized facts.

Address indexing also caps each record at 500 ranges and 4,096 dyadic lookup
prefixes, and the shard at 2,000,000 lookup rows (bounding both prefix and interval
tables). The producer checks these before normalization: an over-limit artifact
gets a named unavailable-coverage reason; other admissible artifacts remain
queryable. It does not truncate a function's ranges or enlarge the bounds.
Verified matching companions participate in ambiguity detection even when their
records exceed an indexing bound. Two distinct matches cannot become a unique
pair by discarding the over-limit one. A sole over-limit match retains its exact
debug reference and reader/limit diagnostics with unavailable coverage. An
incomplete export supplies no complete match evidence; its limit diagnostic
remains visible even if another companion yields usable records.

Source binding reads only the declared, admitted `job_target_catalog/source_files`
shards through the observed-read boundary. Artifact catalog reads likewise produce
`artifact_catalog` receipts; a composite manifest alone grants neither read.
Receipts retain the exact producer handoff, attempt, target snapshot, path and hash.
Source inventory is capped by `reader.max_records`. A truncated inventory emits
`source_inventory_limit` and cannot prove checksum uniqueness, even for an
already encountered row. Source text and line offsets remain byte-bounded.

## Retrieval and observability

The dedicated `debug_symbols` index is queried through `query_debug_symbols`.
Its closed modes cover symbols, build-relative addresses, verified source
ranges, layouts, inline frames, compilation units, coverage and existing graph
links. The same core serves capability-scoped review cells and MCP clients.
There is no SQL, shell, arbitrary path or debugger-expression surface.

`source_ranges` by compilation unit returns line-table rows with a uniquely
verified native unit association. By function it returns existing line rows whose
half-open address ranges intersect that function, excluding known different
compilation units. Rows retain their own identities, original ranges, locations
and unit parents; the returned `source_range_relation` explicitly describes address
overlap, **not exclusive ownership**. Overlapping functions can return the same
row. Unknown/ambiguous native unit associations remain named gaps. Historical
shards without the interval lookup report a reindex-required gap and retain only
their direct-parent lookup, labelled `native_parent`.

Mixed PDBs retain public names/RVAs not already represented by the same private
name and RVA. Public-only records have no invented range or signature. Array
records retain element references and available constant DWARF dimensions;
dynamic/absent dimensions and PDB dimension counts remain explicit unknowns.
A checksum on a line-table row does not make a checksum-less function declaration
a verified source location.

Telemetry is unconditional in the default path: target decisions, reader
executions and compatibility fallbacks, artifact outcomes, index completion
and retrieval all emit structured events. Run
`appsec-review metrics --run-id <id>` and inspect `debug_symbols` for the
selected target, attempt/failure counts, reader environment/outcome counts,
fallback counts, export bytes/duration, latest index counts/duration, query
work and metric gaps. Execution receipts, bounded raw exports and diagnostics
remain protected, hash-bound evidence. Image, declared release and typed-policy
changes invalidate resume identity. Operators must bump the declared release
when changing supplied reader/launcher code; missing release identity explicitly
disables reuse. Deployment source/image byte verification is separate from
customer evidence processing. Source paths and symbol names are not metric labels.
Read coverage before interpreting an empty query.

For contracts, authority limits, routing and the unit-test matrix, see
[the design](../architecture/debug-symbol-indexing.md). Self-generated fixture
provenance and genuine LLVM export commands are documented in
[`tests/fixtures/debug_symbols/README.md`](../../tests/fixtures/debug_symbols/README.md).
