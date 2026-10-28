# Third-party binary decompilation with Ghidra

Repository authority remains in [`../../AGENTS.md`](../../AGENTS.md). This page is a design
reference. Operator commands are in
[`../operations/binary-decompilation.md`](../operations/binary-decompilation.md).

## Purpose

Some components reach a review only as a compiled binary: a vendor `.so`, a `.dll`, or an `.exe`
with no source. This design adds a way to disassemble and decompile such a binary with Ghidra
**before a review is submitted**, and to publish the result as hash-addressed evidence that a
review can then reference.

## Status

| Part | State |
| --- | --- |
| `tool-ghidra` image, registered in `containers/catalog.toml` | Implemented, built, smoke- and security-probed |
| Ghidra export script and wrapper | Implemented, run live against the fixture |
| `[binary_decompilation]` typed configuration | Implemented |
| `appsec-review binary-decompile` pre-run command | Implemented |
| Publication store, manifest, verification, `current.json` pointer | Implemented |
| Known-binary fixture and efficacy comparison | Implemented, run live |
| Frozen record of configured binaries in each run | Implemented (existing configuration freeze) |
| `job_review_intake` resolving and recording publications (`binary_evidence.resolve_publications`, per-binary `required`) | Implemented |
| `job_binary_evidence_indexing`: bounded `binary` retrieval shards, served by the existing retrieval and MCP tools | Implemented, in the CLI graph and the Dagster wave-1 topology |
| `binary-evidence` runtime skill and binary citation rule | Implemented |
| PE fixture with and without a PDB, debug-symbol inputs, managed-code routing | Implemented, tested without Docker; the live Ghidra run of the PE and PDB path is pending ([`../TODO.md`](../TODO.md)) |
| Reviewing a binary with no source tree at all | Designed below, not implemented |
| Large-binary measurement and tuned defaults | Not done; needs a large real binary and a Docker host ([`../TODO.md`](../TODO.md)) |

A review now consumes each configured binary's publication: intake freezes it, the index job
indexes it, and review workers retrieve and cite it.

## Decisions

1. **Decompiled output is binary-derived evidence, not source.** Ghidra emits C-like pseudocode
   that does not compile. It is never fed to compilers, CodeQL, Infer, or the clangd index, and it
   is never presented to a review worker as the target's source. Every publication is labelled
   `provenance: binary-derived`.
2. **Decompilation is a pre-run step, not a review job.** It can take hours and gigabytes on a
   real binary. Running it once, ahead of time, keeps review runs fast and lets several reviews
   reuse one publication.
3. **A review references a publication by the binary's SHA-256.** The same hash appears in the
   configuration, in the store path, in the manifest, and in Ghidra's own record of the file it
   loaded.
4. **A claim anchors to an address.** The stable identity of a function is the binary hash plus
   the function's entry address. The pseudo-C file and line are a derived view of it.
5. **Missing coverage is a named gap.** A function that timed out, a truncated listing, an
   analysis timeout, and managed bytecode each produce a gap row. An empty gap table means the tool
   reported no gap. It never means the binary is free of weaknesses.
6. **The binary is never executed.** Ghidra imports and analyzes it. The container has no network.
7. **Everything recovered from the binary is target-controlled data.** Symbol names, strings, and
   decompiled text can contain text written by whoever built the binary. They are stored and
   hashed, and never treated as instructions.

## Flow

```text
 operator                                pre-run (this design, implemented)
 --------                                ----------------------------------
 1. add the binary to
    [[binary_decompilation.binaries]]
 2. appsec-review binary-decompile  -->  verify file SHA-256 and size
                                         stage a copy as the only file under /target
                                         docker run tool-ghidra (no network, read-only, non-root,
                                                                 raised memory/CPU/time)
                                           analyzeHeadless: import -> auto-analysis
                                           AppsecExportProgram.java -> raw export tables
                                         normalize, bound, hash, write manifest
                                         publish  data/binary-decompilation/<sha256>/<identity16>/
                                         point    data/binary-decompilation/<sha256>/current.json
 3. appsec-review binary-decompile
      --verify-only                 -->  re-hash the publication for the current image

 review submission (implemented)
 -------------------------------
 4. appsec-review start --target ... -->  job_review_intake
                                            freeze configuration (records the binaries)
                                            binary_evidence.resolve_publications:
                                              resolve_current(<sha256>) for each configured binary
                                              record identity + manifest hash in review-intake.json
                                          job_binary_evidence_indexing
                                            re-verify each frozen publication
                                            bounded `binary` retrieval shard per binary
                                          job_review_data_indexing composes it into the review index
                                          review workers retrieve functions by address or edge,
                                            guided by the `binary-evidence` runtime skill
```

## Inputs

### The binary

One regular file per entry. Native ELF, PE, and Mach-O are the intended formats. Ghidra detects
the format, processor, and compiler; each can be overridden per binary.

The file must match the configured SHA-256 exactly and be no larger than `max_binary_bytes`. A
symbolic link is refused. Only a staged copy, under a sanitized file name, is mounted into the
container, so the binary's directory and its neighbours are never exposed.

### Configuration

All settings live in the central `appsec-review.toml` under `[binary_decompilation]`, parsed by
`appsec_review.config.binary_decompilation`. Unknown keys are rejected.

| Setting | Default | Meaning |
| --- | --- | --- |
| `tool_id` | `tool-ghidra` | Catalog tool that performs the export. |
| `memory` | `8g` | Container memory limit. |
| `cpus` | `4` | Container CPU limit, also passed to Ghidra as its analysis thread limit. |
| `pids_limit` | `1024` | Container PID limit. |
| `max_heap` | `6g` | JVM heap. Must leave 1 GiB of `memory` for the native decompiler processes. |
| `timeout_seconds` | `7200` | Whole-container time limit. Must exceed `analysis_timeout_seconds` by 300. |
| `analysis_timeout_seconds` | `3600` | Ghidra auto-analysis limit. Reaching it is a gap, and the export still runs. |
| `decompile_timeout_seconds` | `60` | Per-function decompiler limit. Reaching it is a gap for that function. |
| `max_binary_bytes` | `536870912` | Largest accepted input. |
| `max_functions` | `50000` | Functions exported. The remainder is one `function_limit` gap. |
| `max_function_bytes` | `262144` | Pseudo-C stored per function before truncation. |
| `max_pcode_ops` | `20000` | High P-code operations stored per function before truncation. |
| `max_strings` | `100000` | Strings exported. The remainder is one `string_limit` gap. |
| `min_string_length` | `4` | Shortest string exported. |
| `output_file_bytes` | `2147483648` | Kernel file-size limit for every file the container writes. |

Each `[[binary_decompilation.binaries]]` table:

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Lowercase slug used on the command line and in reports. |
| `path` | yes | File path, absolute or relative to the configuration file. |
| `sha256` | yes | Expected SHA-256 of the file. A mismatch refuses the run. |
| `authorization` | yes | Why this binary may be reverse-engineered: a license term, contract, or ownership. Recorded in the manifest. |
| `processor` | no | Ghidra language id, for example `ARM:LE:32:v8`, when detection is wrong. |
| `compiler_spec` | no | Ghidra compiler spec id. Requires `processor`. |
| `loader` | no | Ghidra loader class name, for example `BinaryLoader` for a raw image. |
| `required` | no | Default `false`. When `true`, a binary with no verifiable publication blocks review intake instead of becoming a gap. |
| `debug_symbols_path` | no | A separate PDB for a PE binary, absolute or relative to the configuration file. Requires `debug_symbols_sha256`. |
| `debug_symbols_sha256` | no | Expected SHA-256 of the debug-symbol file. A mismatch refuses the run. |

The repository default configuration declares no binaries.

The debug-symbol file is verified, staged next to the binary under a sanitized name, and loaded by
`AppsecLoadDebugSymbols.java` before auto-analysis. Its hash enters the publication identity, so the
same binary with and without a PDB gives two publications. A PDB that Ghidra did not apply is a
`debug_symbols_not_applied` gap. DWARF embedded in an ELF needs no separate input.

### Why this command may exceed the central runtime policy

`containers/runtime-policy.toml` bounds every scanner to 1 GiB, 2 CPUs, 256 PIDs, and 600 seconds,
and the catalog loader requires each `tool.toml` to equal it. `tool-ghidra` declares those same
packaging limits, and the smoke and security probes run under them.

The pre-run command raises **only capacity** (memory, CPUs, PIDs, time) from the typed
configuration, by handing `ContainerExecutor` a copy of the catalog entry with those four fields
replaced. Network (`none`), user (`10001:10001`), read-only root, the read-only target mount, the
single writable scratch mount, dropped capabilities, and `no-new-privileges` come from the same
executor and are unchanged. The effective limits are recorded in the execution receipt and copied
into the manifest. This follows the CodeQL precedent, whose runtime also sets its own memory.

The raise is acceptable because the command runs one binary at a time, outside any review worker
pool, at a moment the operator chooses.

## The image

`appsec-review/tool-ghidra:12.1.4` is registered in `containers/catalog.toml` and described in
[`../../containers/tools/ghidra/README.md`](../../containers/tools/ghidra/README.md).

- **Pinned archive.** `ghidra_12.1.4_PUBLIC_20260921.zip` is fetched by `containers/build.py` and
  accepted only at its exact byte size and SHA-256. `safe_extract.py` re-verifies it, rejects
  unsafe members, installs only the allowlisted closure, and requires the result to equal the
  committed `inventory.json`.
- **Reviewed closure.** 2,799 files. The debugger, extensions, server, documentation, and GUI
  launchers are not installed.
- **JDK.** Ghidra's launcher refuses a JRE and compiles its scripts at run time, so Temurin 21 is
  copied from a digest-pinned stage.
- **One executable.** `/opt/appsec/bin/ghidra-export` validates every option, confines Ghidra's
  project, user settings, and temporary files to `/scratch`, and runs `analyzeHeadless` with
  `-deleteProject`.
- **Build-time API check.** The export script is compiled against the pinned Ghidra classes during
  the image build, so an incompatible Ghidra upgrade fails the build, not a decompilation run.

`analyzeHeadless` exits 0 even when its script throws. The export is therefore complete only when
`complete.json` exists, which the script writes last.

## Outputs

### Store layout

```text
<data_dir>/binary-decompilation/
  <binary-sha256>/
    current.json                  pointer to the publication a review resolves
    <identity, first 16 hex>/     one immutable publication
      manifest.json               identity, provenance, coverage, gaps, dataset hashes
      program.json                format, language, compiler, image base, memory blocks
      functions.jsonl             function table
      calls.jsonl                 call graph edges
      imports.jsonl               external symbols
      exports.jsonl               external entry points
      strings.jsonl               defined strings with cross-references
      gaps.jsonl                  every named gap
      pseudo-c/<address>.c        decompiled pseudo-C, one file per function
      pcode/<address>.jsonl       high P-code, one operation per line
      execution/execution.json    container receipt: image id, argv hash, mounts, limits, times
      execution/stdout.bin        Ghidra log (bounded)
      execution/stderr.bin
  .staging/                       in-progress work, removed on completion
  .failed/<identity16>-<id>/      receipt and logs of a failed attempt
```

`data/binary-decompilation/` is ignored by Git. The directory carries a 16-character prefix of
the identity because two full hashes in one path exceed the legacy Windows path limit; the
manifest carries the full identity, and verification checks that they agree.

### Tables

Addresses are `0x` hex in the program's default address space.

| File | One record per | Main fields |
| --- | --- | --- |
| `functions.jsonl` | function | `address`, `name`, `qualified_name`, `name_source`, `signature`, `calling_convention`, `parameter_count`, `body_bytes`, `memory_block`, `is_export`, `is_thunk`, `thunk_target`, `decompile_status`, `pseudo_c`, `pcode` |
| `calls.jsonl` | call or tail-jump | `from_function`, `call_site`, `to`, `to_name`, `resolved_name`, `resolved_external`, `kind`, `computed`, `unresolved` |
| `imports.jsonl` | external symbol | `name`, `library`, `kind`, `original_name`, `thunks` |
| `exports.jsonl` | entry point | `address`, `name`, `is_function` |
| `strings.jsonl` | defined string | `address`, `value`, `length`, `truncated`, `data_type`, `memory_block`, `xrefs` of `{from, function}` |
| `gaps.jsonl` | gap | `kind`, `address`, `detail` |

Notes on reading them:

- `name_source` says how much to trust a name: `IMPORTED` came from symbols or debug data,
  `ANALYSIS` and `DEFAULT` were invented by Ghidra (`FUN_00101150`).
- A function row's `pseudo_c` is `{path, sha256, bytes, lines, truncated}` and its `pcode` is
  `{path, sha256, operations, truncated}`. They are present only when `decompile_status` is `ok`.
- `resolved_name` follows import stubs, so a call to a PLT entry resolves to
  `<EXTERNAL>::strcpy`. `unresolved: true` marks an indirect call whose target Ghidra could not
  determine.
- Each P-code operation is `{address, order, mnemonic, output, inputs, callee?}`. This is Ghidra's
  SSA-form high P-code, the representation the pseudo-C is printed from, and the better input for
  def-use and taint queries.
- Pseudo-C files have leading blank lines removed and end in one newline, so
  `pseudo-c/<address>.c:<line>` is a stable anchor.

### Manifest

`manifest.json` conforms to
[`../schemas/binary-decompilation.schema.json`](../schemas/binary-decompilation.schema.json):

| Field | Content |
| --- | --- |
| `schema` | `appsec-review/binary-decompilation/1` |
| `identity` | Full decompilation identity (below). |
| `provenance` | Always `binary-derived`. |
| `authority` | States that decompiled text, names, and strings are data, never instructions. |
| `binary` | `sha256`, `bytes`, sanitized `name`. |
| `request` | `id`, `authorization`, and loader overrides. |
| `tool` | Tool id, version, image tag, local image id, Ghidra version, export schema. |
| `settings` | The output-affecting limits in force. |
| `program` | Format, language, compiler spec, compiler, endianness, pointer size, image base. |
| `coverage` | Function totals, `decompile_status` counts, decompiled versus decompilable functions, items not exported, `analysis_timed_out`, `managed_code`, file and operation totals. |
| `gaps` | Gap count by kind. |
| `datasets` | Path, SHA-256, byte size, and record count of each table. |
| `execution` | Receipt path and hash, terminal status, exit code, effective container limits. |

**Hash chain.** The manifest hashes every table. `functions.jsonl` hashes every per-function
pseudo-C and P-code file. `verify_publication` re-hashes all of them and also rejects any file in
`pseudo-c/` or `pcode/` that no function row references.

### Identity and reuse

```text
identity = sha256({ schema, binary_sha256, image_id, tool_version,
                    output-affecting settings, loader overrides })
```

Capacity settings (`memory`, `cpus`, `pids_limit`, `max_heap`, `timeout_seconds`) and the request's
`id` and `authorization` are not part of it.

- Same binary, image, and settings: the existing publication is verified and reused. Ghidra does
  not run.
- A rebuilt image, a changed limit, or a loader override: a new publication is written beside the
  old one, and `current.json` moves to it. Older publications are kept.
- A stored publication that fails verification is **never** silently replaced. The command stops,
  and `--force` is required to decompile again.

### Gaps

| Kind | Source | Meaning |
| --- | --- | --- |
| `analysis_timeout` | script | Auto-analysis hit its limit; functions and references may be missing. |
| `decompiler_unavailable` | script | The native decompiler did not start; no pseudo-C or P-code exists. |
| `decompile_timeout`, `decompile_failed` | script | One function has no pseudo-C or P-code. |
| `pseudo_c_truncated`, `pcode_truncated` | script | One function's listing was cut at its bound. |
| `pcode_unavailable` | script | Pseudo-C exists but no high function was produced. |
| `function_limit`, `string_limit` | script | Records beyond the configured maximum were not exported. |
| `managed_code` | normalizer | The program is .NET, JVM, or Dalvik bytecode. Native decompilation is not evidence for it. |
| `debug_symbols_not_applied` | normalizer | A configured PDB was staged but Ghidra did not apply it. |

### Failures

A failure publishes nothing. The attempt's receipt and logs move to `.failed/`, and the command
reports a status:

| Status | Cause |
| --- | --- |
| `REFUSED` | The file is missing, a symbolic link, too large, or does not match its SHA-256; or a stored publication failed verification. |
| `FAILED` | The container exited non-zero. |
| `TIMEOUT`, `OOM`, `FILE_SIZE_LIMIT` | A container limit was reached. |
| `INVALID_EXPORT` | `complete.json` is absent, Ghidra's recorded SHA-256 differs from the verified binary, or a table violates its contract. |

## Starting a decompilation

```sh
appsec-review binary-decompile                    # every configured binary
appsec-review binary-decompile --binary <id>      # one binary; repeatable
appsec-review binary-decompile --force            # decompile again despite a publication
appsec-review binary-decompile --verify-only      # re-hash existing publications; no Ghidra run
```

The command prints one JSON object per binary with `status`, `binary_sha256`, `identity`, `path`,
`manifest_sha256`, `reused`, `coverage`, and `gaps`, and exits non-zero if any binary did not end
`PUBLISHED`. See the operations page for a worked example and troubleshooting.

## Submitting a review that references a publication

Run `appsec-review binary-decompile --verify-only` first, then `appsec-review start`. The run
consumes each configured binary's publication through three stages.

### Intake: `binary_evidence.resolve_publications`

`job_review_intake` has a `binary_evidence` step with one task, `resolve_publications`:

1. Read the frozen `[binary_decompilation]` binaries.
2. For each, call `resolve_current(data_dir, sha256)`, which verifies the whole publication again
   and needs no Docker. It does not trust the pre-run command's exit code.
3. Write `binary-evidence.json` (`appsec-review/binary-evidence-intake/1`) with each binary's
   `binary_id`, `binary_sha256`, `identity`, `manifest_sha256`, publication path, `coverage`, and
   `gaps`, and reference it by hash under `binary_evidence` in `review-intake.json`. From then on
   the run uses that identity and manifest hash, so moving `current.json` later cannot change a
   run in progress or a resumed run.
4. A binary with no verifiable publication becomes a `binary_decompilation_unavailable` gap. With
   `required = true` it fails intake instead.

### Index: `job_binary_evidence_indexing`

The job depends on `job_target_catalog` (and so on the accepted intake) and runs in the CLI graph
after `job_cpg_analysis` and in the Dagster wave-1 topology. It reads only the accepted intake
handoff, re-verifies each frozen publication, and refuses one whose manifest hash, identity, or
binary hash differs from what intake recorded. For each binary it writes one current `binary`
retrieval shard:

| Entity | Located | Content |
| --- | --- | --- |
| `binary_function` | Yes, in `@binary/<sha256>/<address>.c` | Address, name, signature, flags, decompile status; retrieval text is the name and bounded pseudo-C |
| `binary_call_site` | On the one pseudo-C line that names the callee, else ambiguous or unlocated | Caller, callee, call address, call kind |
| `binary_import` | Never | Library, name, thunk address |
| `binary_string` | Never | Address, bounded value, referencing functions |

Relations: `CONTAINS` (function to its call sites), `CALLS` (call site, and its caller function, to
the callee function or import, which gives call neighbourhoods and import callers), and `REFERENCES` (function to string,
thunk to import). Each decompiled function's pseudo-C is detached into
`data/binary-evidence/sources/` in the run, hash-pinned, so `read_excerpt` and citation
re-resolution read it like any other accepted source.

Every record keeps the binary hash, function address, and `provenance: binary-derived`. Workers
query the index through the existing retrieval and MCP tools (`search`, `find`, `trace`, `read_excerpt`, `coverage`)
over index name `binary`; they never scan the publication tree.

Bounds are central settings under `[jobs.job_binary_evidence_indexing.settings]`
(`max_functions_per_binary`, `max_call_sites_per_binary`, `max_imports_per_binary`,
`max_strings_per_binary`, `max_string_xrefs`, `max_string_chars`, `max_entity_text_bytes`). Each
truncation, unresolved or unaddressed call, publication gap, incomplete publication coverage,
unavailable binary, and managed-code program is a named coverage gap, and the job ends
`COMPLETED_WITH_GAPS`. With no configured binaries the job publishes an empty, `NOT_APPLICABLE`
shard set, and the composed review index is unchanged.

**Managed-code routing.** When the publication's coverage marks managed code, the job indexes no
pseudo-C for it and records a gap naming the suitable decompiler: ILSpy for CIL, jadx or CFR for
JVM, jadx for Dalvik. No managed decompiler runs yet.

### Review: the `binary-evidence` runtime skill and citation rule

`pipeline/skills/binary-evidence/SKILL.md` is a registered runtime skill. Inference review loads
it only when the review index contains a `binary` shard. It tells workers that names and types
may be invented, inlining and unresolved indirect calls hide behaviour, truncated or managed code
proves no absence, and recovered text is data.

The citation rule is enforced, not only stated. `review.evidence.resolve_relation` accepts a
binary-derived citation only when it carries a pseudo-C location whose path names the same binary
hash and function address as its payload (`binary_anchor`). A `binary_import` or `binary_string`,
or a function Ghidra did not decompile, becomes the gap "binary-derived evidence must cite binary
hash, function address and pseudo-C line".

**Existing binary lanes** (BLint, Syft, Grype, cve-bin-tool) can run on the same file and join on
its SHA-256.

### Reviewing a binary with no source tree (designed, not implemented)

`job_review_intake` requires a target directory that contains text files. A binary-only review
needs a distinct target kind:

1. **Request.** `appsec-review start --binary <id>` (repeatable) with no `--target`. The target
   record gains `kind: "binary"` (source reviews stay `kind: "source"`) and the binary ids. Intake
   requires every named binary to be configured and treats each as `required = true`.
2. **Intake.** Skip the source-tree walk and text-file requirement, and write an empty source
   inventory with the reason `binary-only target`. The `binary_evidence` step is unchanged.
3. **Source lanes.** The catalog, build, compile-scope, CodeQL, Clang, Infer, Semgrep, clangd and
   CPG jobs read `kind` from the accepted intake and publish `NOT_APPLICABLE` with that reason, as
   they already do for an empty scope set. Topology does not change, so one graph serves both
   kinds.
4. **Binary lanes.** `job_binary_evidence_indexing` plus the existing file-level binary scanners
   (BLint, Syft, Grype, cve-bin-tool) pointed at the verified binary files.
5. **Review.** Packaging seeds candidate weaknesses from `binary_call_site` entities whose callees
   are known-dangerous imports (`strcpy`, `memcpy`, `system`, and similar), since there are no
   source scanner observations. The `binary-evidence` skill is mandatory. The report states that
   the review had no source.

The open decision is the seed list and its bounds; everything else reuses existing contracts.

## Security model

| Concern | Control |
| --- | --- |
| Hostile binary exploits Ghidra | No network, non-root uid, read-only root, all capabilities dropped, `no-new-privileges`, bounded memory, CPU, PIDs, time, and file size. Ghidra state is confined to scratch and deleted. |
| Binary executes | It is only imported and analyzed. The export script starts no process. |
| Wrong file is analyzed | The file is hashed before staging and after staging, and Ghidra's own `executable_sha256` must equal the configured hash. |
| Path or option injection | The staged file name is sanitized. The wrapper validates every option against a pattern and uses no `eval`. Function addresses are validated before they become file names. |
| Oversized or malformed output | A kernel file-size limit, per-function and per-table bounds, a per-line bound in the normalizer, and strict JSON object checks. |
| Tampering after publication | The manifest hash chain, verified on every reuse and by `resolve_current`. |
| Prompt injection through strings or symbols | Publications are labelled as data. The index job stores recovered text only as entity payload, and the `binary-evidence` runtime skill restates that it is data before a worker reads it. |
| A publication changes under a running review | Intake freezes the identity and manifest hash; the index job re-verifies the publication and each pseudo-C file against them and refuses a mismatch. |
| Unlicensed reverse engineering | `authorization` is mandatory and recorded. It is a statement by the operator; the tool does not check it. |

## Known-binary efficacy comparison

To measure what decompilation recovers, the repository holds a fixture whose answer is known:
`containers/fixtures/ghidra/case-083/main.c`, a byte-identical copy of the CWE-120 case from
`appsec-multi-vuln` (`projects/native/case-083`). `print_label` copies `argv[1]` into a 32-byte
stack buffer with `strcpy`.

No binary is committed. `python -m appsec_review.binary_decompilation.efficacy` compiles the
source offline with the pinned `tool-native-cpp` image, decompiles each variant, and scores the
publication against `containers/fixtures/ghidra/expectations.json`.

| Variant | Flags | Required checks | Result on 2026-10-12 |
| --- | --- | --- | --- |
| `symbols` | `-O0 -g -fno-inline` | Both functions by name, both imports, both call edges, both strings with their referencing function, the sink line and `[32]` buffer in pseudo-C, the `argv[1]` source, the P-code call, full decompile coverage | 12 of 12 |
| `stripped` | `-O2 -s` | Both imports, a call edge to `strcpy` from any real function, the format string referenced by that function, the sink line and `[32]` buffer in its pseudo-C, the P-code call, full decompile coverage | 7 of 7 |

The stripped variant also carries three optional checks that record what was lost. All three were
missed, as expected:

- `main` and `print_label` no longer exist by name. The compiler inlined `print_label`, and Ghidra
  names the merged function `FUN_00101150`.
- The four-character string `demo` is left as untyped data (`DAT_00102004`), below Ghidra's
  default string-length threshold.

The weakness itself survives stripping: the merged function's pseudo-C still shows
`strcpy(auStack_28,puVar1)` into `undefined1 auStack_28 [32]` with `puVar1` taken from the
argument vector.

Check kinds are `function`, `import`, `call`, `string`, `pseudo_c`, `pcode_call`, and
`decompile_coverage`. A function is selected by `{"name": ...}` or, when names are gone, by
`{"calls": ...}`. A check with `"required": false` is reported and does not affect the score.

**Iteration speed.** One variant takes about 15 seconds end to end. An unchanged image reuses the
publication and takes about 2 seconds. Changing the export script means rebuilding the image
(cached layers, under a minute), which changes the identity and reruns Ghidra automatically.

This fixture is one small C program. It shows the pipeline works and what stripping costs. It does
not measure efficacy on C++, on large binaries, or on Windows binaries.

## Tests

| File | Covers | Docker |
| --- | --- | --- |
| `tests/test_ghidra_tool.py` | Catalog registration, asset lock, Dockerfile, closure inventory, wrapper, export script contract | no |
| `tests/test_binary_decompilation.py` | Configuration, identity, runner argv and limits, publication, schema conformance, reuse, pointer resolution, tampering, failures, gaps, efficacy evaluator, CLI | no (fake runner) |
| `tests/test_live_ghidra_decompilation.py` | Fixture compile, real Ghidra run, scoring | yes; skipped when the images are absent |
| `tests/test_binary_evidence_indexing.py` | Intake resolution, `required`, mismatches; end-to-end index, retrieval, `binary_anchor`, citation gaps; not-applicable, unavailable, tampered and truncated cases; PE with and without a PDB; managed-code routing; registry, topology, matrix, runtime skill | no |

## Limitations

- **Pseudo-C is lossy.** Types are inferred, C++ becomes C with explicit vtable calls, and inlined
  functions disappear. Debug symbols improve output greatly. A separate PDB is accepted for PE
  binaries; separate DWARF (`.debug` files) is not.
- **Only an ELF fixture has run live.** The PE fixture with and without a PDB is exercised through
  the runner, normalizer and index job with a fake Ghidra; the live run needs the rebuilt image.
  Mach-O has not been run.
- **Managed code is routed, not decompiled.** The index job records which managed decompiler is
  needed; none runs.
- **No source scanners run on the output**, by decision 1.
- **Large binaries are unmeasured.** The defaults (8 GiB, 4 CPUs, 2 hours) are starting values, not
  tuned ones. All tables are loaded into memory during normalization.
- **Image id is host-local.** The catalog does not pin `image_id`, so two hosts that build the
  image produce different identities for the same binary.
- **Linux hosts:** files the container writes belong to uid 10001. Removal of the staging
  directory is best effort and may leave residue under `.staging/`.
- **Concurrency:** two simultaneous runs for the same binary are not locked against each other.
  Each publishes atomically, and the later one replaces the earlier identical publication.
- **License review is partial.** See `containers/tools/ghidra/LICENSE.md`.

## Next slices

Slices 1 to 4 of the original list (intake step, index job with retrieval and runtime skill, PE
and PDB inputs, managed-code routing) are implemented. Remaining, tracked in
[`../TODO.md`](../TODO.md):

1. Rebuild `tool-ghidra` with `AppsecLoadDebugSymbols.java` and run the PE fixture live, with and
   without its PDB.
2. Measure memory, time, and file counts on a large real binary; tune the decompilation and index
   bounds.
3. The binary-only target kind designed above.
4. A managed-code decompiler lane.
5. Advisory scan of the image, a single `base-jdk`, and a pinned catalog `image_id`.
