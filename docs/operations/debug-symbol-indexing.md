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

Prebuilt artifacts use the already provisioned, catalog-pinned `tool-native-cpp`
image. The same approved image is an explicit compatibility fallback when a
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

Default limits are 128 candidate binaries, 512 MiB per input file, 16 MiB per
export/normalized output, 100,000 records, nesting depth 128 and 120 seconds per
reader. These live under the job's central `settings` / `settings.reader`;
invalid types and unknown settings are rejected. Raw inputs, source names and
reader records remain protected run-owned evidence. Public index rows retain
verified artifact identities and approved normalized facts.

## Retrieval and observability

The dedicated `debug_symbols` index is queried through `query_debug_symbols`.
Its closed modes cover symbols, build-relative addresses, verified source
ranges, layouts, inline frames, compilation units, coverage and existing graph
links. The same core serves capability-scoped review cells and MCP clients.
There is no SQL, shell, arbitrary path or debugger-expression surface.

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
