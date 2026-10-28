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

## Reader prerequisites

Configure approved, host-local LLVM executables in the central TOML. Both lanes
can use LLVM's offline readers; reading native PDBs does not require executing
the target or using DIA. The runtime never discovers tools on PATH, downloads
them, follows source-server instructions, or fetches symbols.

```toml
[jobs.job_debug_symbol_indexing.settings.reader.tools.llvm_dwarfdump]
path = 'C:\ApprovedTools\LLVM\bin\llvm-dwarfdump.exe'
sha256 = '<the executable SHA-256, 64 lowercase hexadecimal characters>'

[jobs.job_debug_symbol_indexing.settings.reader.tools.llvm_pdbutil]
path = 'C:\ApprovedTools\LLVM\bin\llvm-pdbutil.exe'
sha256 = '<the executable SHA-256, 64 lowercase hexadecimal characters>'
```

Replace the placeholder pins before loading the configuration. Paths must be
absolute on the execution host. Use the approved tool environment and its
dependency/isolation policy; this feature does not provision that environment.
The checked-in configuration deliberately does not invent machine-specific tool
paths or pins. An absent, unpinned, or changed tool produces explicit unavailable
coverage rather than disabling the job silently or claiming an empty result.

The initial reader contract is exercised against LLVM 18.1.3 output. Tools are
identified by executable content, not a version string alone.
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

Telemetry is unconditional in the default path: target decisions, artifact
outcomes, index completion and retrieval all emit structured events. Run
`appsec-review metrics --run-id <id>` and inspect `debug_symbols` for the
selected target, attempt/failure counts, latest index counts/duration, query
work and metric gaps. Source paths and symbol names are not metric labels.
Read coverage before interpreting an empty query.

For contracts, authority limits, routing and the unit-test matrix, see
[the design](../architecture/debug-symbol-indexing.md). Self-generated fixture
provenance and genuine LLVM export commands are documented in
[`tests/fixtures/debug_symbols/README.md`](../../tests/fixtures/debug_symbols/README.md).
