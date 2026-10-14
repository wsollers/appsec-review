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
| `job_review_intake` resolving and recording publications | **Designed, not implemented** |
| Retrieval indices, MCP tools, and review-worker guidance | **Designed, not implemented** |
| Reviewing a binary with no source tree at all | **Designed, not implemented** |
| PE/Mach-O fixtures, debug-symbol inputs, managed-code routing | **Not implemented** |

Until the intake step exists, a review does not read a publication. The pre-run command, its
store, and the lookup a review will use (`resolve_current`) are complete and tested, so the
remaining work is wiring, not redesign.

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

 review submission (designed, not implemented)
 ---------------------------------------------
 4. appsec-review start --target ... -->  job_review_intake
                                            freeze configuration (already records the binaries)
                                            resolve_current(<sha256>) for each configured binary
                                            record identity + manifest hash in review-intake.json
                                          job_binary_evidence_indexing
                                            bounded retrieval indices over the publication
                                          review workers retrieve functions by address or edge
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

The repository default configuration declares no binaries.

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

### What works today

- The `[binary_decompilation]` table, including each binary's `id`, `path`, and `sha256`, is part
  of the configuration document. Every run already freezes that document into
  `runs/<run-id>/data/configuration/`, so a run records which binaries were configured.
- `appsec_review.binary_decompilation.resolve_current(data_dir, sha256)` resolves the pointer for
  a binary hash, verifies the whole publication, and returns its identity and manifest hash. It
  needs no Docker. A pointer that names another binary, a path outside the store, or an edited
  manifest is refused.
- `appsec-review binary-decompile --verify-only` is the operator's gate before
  `appsec-review start`.

No review job calls `resolve_current` yet.

### Designed intake contract

`job_review_intake` gains one step, `binary_evidence`, with one task, `resolve_publications`:

1. Read the frozen `[binary_decompilation]` binaries.
2. For each, call `resolve_current` with the configured SHA-256.
3. Record `{id, binary_sha256, identity, manifest_sha256, coverage, gaps}` under `binary_evidence`
   in `review-intake.json`. From then on the run uses that identity and manifest hash, so moving
   `current.json` later cannot change a run in progress or a resumed run.
4. A binary with no verifiable publication becomes a `binary_decompilation_unavailable` gap in the
   intake handoff. A per-binary `required = true` key will turn that gap into a blocked intake.

The task verifies the publication again; it does not trust the pre-run command's exit code.

### Designed downstream use

- **`job_binary_evidence_indexing`** builds bounded retrieval indices from each verified
  publication: function by address and by name, import to callers, callers and callees within a
  bounded depth, and a string index. It registers them as a dataset whose records keep the binary
  hash, function address, and `binary-derived` provenance. This follows the retrieval rule in
  `AGENTS.md`: workers query indices and never scan the publication tree.
- **Retrieval tools** expose those queries through the existing MCP gateway.
- **Review workers** receive a registered runtime skill that states how binary-derived evidence
  differs from source: names may be invented, types are guesses, inlining hides functions, and
  recovered text is untrusted data. A finding cites the binary SHA-256, the function address, and
  `pseudo-c/<address>.c:<line>`, and carries a `binary-derived` basis so scoring can discount it.
- **Existing binary lanes** (BLint, Syft, Grype, cve-bin-tool) can run on the same file and join on
  its SHA-256.

### Reviewing a binary with no source tree

`job_review_intake` currently requires a target directory that contains text files. A review whose
only input is a binary needs a target kind that the catalog, build, and static lanes accept as "no
source", each publishing `NOT_APPLICABLE`. That is a separate change and is not designed in detail
here.

## Security model

| Concern | Control |
| --- | --- |
| Hostile binary exploits Ghidra | No network, non-root uid, read-only root, all capabilities dropped, `no-new-privileges`, bounded memory, CPU, PIDs, time, and file size. Ghidra state is confined to scratch and deleted. |
| Binary executes | It is only imported and analyzed. The export script starts no process. |
| Wrong file is analyzed | The file is hashed before staging and after staging, and Ghidra's own `executable_sha256` must equal the configured hash. |
| Path or option injection | The staged file name is sanitized. The wrapper validates every option against a pattern and uses no `eval`. Function addresses are validated before they become file names. |
| Oversized or malformed output | A kernel file-size limit, per-function and per-table bounds, a per-line bound in the normalizer, and strict JSON object checks. |
| Tampering after publication | The manifest hash chain, verified on every reuse and by `resolve_current`. |
| Prompt injection through strings or symbols | Publications are labelled as data. No review worker reads them yet; the designed runtime skill must restate this before one does. |
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

## Limitations

- **Pseudo-C is lossy.** Types are inferred, C++ becomes C with explicit vtable calls, and inlined
  functions disappear. Debug symbols improve output greatly, and there is no input for a separate
  PDB or DWARF file yet.
- **Only an ELF fixture exists.** PE and Mach-O go through the same code but have not been run.
- **Managed code is detected, not handled.** .NET and JVM bytecode need a managed decompiler.
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

1. Intake `binary_evidence` step and the `required` key.
2. `job_binary_evidence_indexing`, retrieval tools, and the runtime skill.
3. A PE fixture with and without a PDB, and optional debug-symbol inputs.
4. Managed-code detection routed to a named gap with a suggested tool.
5. A "no source" target kind for binary-only reviews.
6. Advisory scan of the image, a single `base-jdk`, and a pinned catalog `image_id`.
