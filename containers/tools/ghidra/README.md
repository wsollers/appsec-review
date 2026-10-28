# tool-ghidra: pinned Ghidra headless decompilation closure

This directory builds `appsec-review/tool-ghidra:12.1.4`: an offline, non-root image that holds the
reviewed Ghidra 12.1.4 closure, a Temurin 21 JDK, and one export script. It imports one binary,
runs Ghidra's automatic analysis, and writes bounded structured exports. The binary is never
executed.

The image is driven by `appsec-review binary-decompile`, a pre-run command, not by a review job.
Design: [`docs/architecture/binary-decompilation.md`](../../../docs/architecture/binary-decompilation.md).
Commands: [`docs/operations/binary-decompilation.md`](../../../docs/operations/binary-decompilation.md).

**Status.** Built, smoke-tested, security-probed, and run against the case-083 fixture on
2026-10-12 (see "Verification"). Its output is binary-derived evidence, not source coverage. Reviews
consume it through `job_review_intake` and `job_binary_evidence_indexing`. The debug-symbol script
and `--debug-symbols` option were added after that verification; rebuild the image before relying
on them (`docs/TODO.md`).

## Files

| File | Role |
| --- | --- |
| `assets.lock.json` | Release provenance and the exact URL, path, byte size, SHA-256, and SHA-512 of the archive, plus signature status. |
| `tool.toml` | Runtime contract (non-root, no network, read-only root and target, packaging limits, version probe) and the `[closure]` allowlist and extraction limits. |
| `Dockerfile` | Three-stage offline build: verify and unpack in digest-pinned `python:3.12-slim`, take the JDK from digest-pinned `eclipse-temurin:21-jdk-noble`, install into `appsec-review/base-jre:21-noble`. |
| `../shared/safe_extract.py` | Shared helper. Validates every archive member, installs only the closure allowlist, and requires the result to equal the committed inventory. |
| `inventory.json` | Committed inventory of the installed closure: 2,799 files with path, kind, size, and SHA-256, plus Maven coordinates and embedded native libraries for each JAR. |
| `ghidra-export` | The image's only cataloged executable. Validates every option, confines Ghidra's project, settings, and temporary files to `/scratch`, then runs `analyzeHeadless`. |
| `scripts/AppsecExportProgram.java` | Ghidra post-analysis script that writes the export tables. Compiled against the pinned Ghidra classes during the image build so an API mismatch fails the build. |
| `scripts/AppsecLoadDebugSymbols.java` | Ghidra pre-analysis script, run only with `--debug-symbols`, that loads the staged PDB before auto-analysis. Compiled during the build like the export script. |
| `ghidra-version` | Version probe: checks the launcher, native decompiler, export script, and JDK compiler, then prints the version. |
| `LICENSE.md` | License, provenance, and security review notes, including the open items. |
| `downloads/` | Ignored fetch cache (`containers/.gitignore`). The 570 MB archive is never committed. |

## Build

```sh
containers/build-all.sh --validate-only
containers/build-all.sh build tool-ghidra      # fetches and verifies the archive, builds offline
containers/build-all.sh smoke tool-ghidra
containers/build-all.sh security tool-ghidra
```

The first build downloads the 570 MB archive and pulls the two digest-pinned stage images. The
`RUN` steps have no network. The built image is about 1.8 GB.

## Wrapper contract

```text
/opt/appsec/bin/ghidra-export --input /target/<file> --output /scratch/<dir>
    [--work /scratch/<dir>] [--max-heap 768m] [--max-cpu 2]
    [--analysis-timeout 300] [--decompile-timeout 60]
    [--max-functions 50000] [--max-function-bytes 262144] [--max-pcode-ops 20000]
    [--max-strings 100000] [--min-string-length 4]
    [--processor <language id>] [--cspec <compiler spec id>] [--loader <loader class>]
    [--debug-symbols /target/<file>]
```

- `--debug-symbols` must name one regular file directly under `/target`, beside the input.
- `--input` must name one regular file directly under the read-only `/target` mount.
- `--output` and `--work` must stay under `/scratch`.
- An invalid option exits 64 before Ghidra starts.
- **Exit code 0 does not mean the export succeeded.** `analyzeHeadless` returns 0 when a script
  fails. The export is complete only when `<output>/complete.json` exists, and the Python caller
  refuses anything else.

## Export tables

The script writes these beneath `--output`. Addresses in the default address space are `0x` hex.

| File | One record per | Main fields |
| --- | --- | --- |
| `program.json` | program | format, language, compiler spec, compiler, endianness, pointer size, image base, memory blocks, `executable_sha256` |
| `functions.jsonl` | non-external function | `address`, `name`, `name_source`, `signature`, `calling_convention`, `body_bytes`, `is_thunk`, `thunk_target`, `is_export`, `decompile_status` |
| `decompiled.jsonl` | decompiled function | `address`, `c` (pseudo-C), `truncated` |
| `pcode.jsonl` | decompiled function | `address`, `operations[]` of `{address, order, mnemonic, output, inputs[], callee?}`, `truncated` |
| `calls.jsonl` | call or tail-jump edge | `from_function`, `call_site`, `to`, `to_name`, `resolved_name`, `resolved_external`, `kind`, `computed`, `unresolved?` |
| `imports.jsonl` | external symbol | `name`, `library`, `kind`, `original_name`, `thunks[]` |
| `exports.jsonl` | external entry point | `address`, `name`, `is_function` |
| `strings.jsonl` | defined string | `address`, `value`, `length`, `data_type`, `memory_block`, `xrefs[]` of `{from, function}` |
| `gaps.jsonl` | named gap | `kind`, `address`, `detail` |
| `complete.json` | export | counts, `decompile_status` totals, gap totals, effective limits |

`decompile_status` is one of `ok`, `timeout`, `failed`, `skipped_thunk`, or `unavailable`. Gap
kinds the script emits: `analysis_timeout`, `decompiler_unavailable`, `decompile_timeout`,
`decompile_failed`, `pseudo_c_truncated`, `pcode_unavailable`, `pcode_truncated`, `function_limit`,
and `string_limit`.

## Verification

Run on 2026-10-12 on Docker Desktop 29.8.1 (Windows, WSL2):

- `build.py build tool-ghidra`: passed; image id
  `sha256:55cb0b562f27c0e0a54f2bd4ea8df8e13105652abb4ac67b320a767c81b7de63`. That id is local to
  this host's build and is not pinned in the catalog.
- `build.py smoke tool-ghidra` and `build.py security tool-ghidra`: passed.
- `python -m appsec_review.binary_decompilation.efficacy`: `symbols` 12/12, `stripped` 7/7 required
  checks, with three expected losses recorded as optional checks. About 15 seconds per variant.

Not run: `smoke --functional` has no Ghidra case (the efficacy command is the functional check),
Dockerfile linting with hadolint, and the advisory match listed in `LICENSE.md`.

## Updating the pin

1. Choose an immutable release tag and download its public archive.
2. Record the exact byte size, SHA-256, and SHA-512 in `assets.lock.json`. Confirm the SHA-256
   equals the digest GitHub reports for the asset.
3. Update the version in `tool.toml`, the closure prefixes, the catalog entry, and the archive file
   name in `Dockerfile`.
4. Regenerate `inventory.json` inside the pinned Python image, never on the host (host file modes
   differ):

   ```sh
   docker run --rm --network none \
     --mount type=bind,src="$PWD/containers/tools",dst=/work,readonly \
     --mount type=bind,src="$PWD/containers/tools/ghidra",dst=/out \
     python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e \
     python -I /work/shared/safe_extract.py /work/ghidra/downloads/<archive>.zip /tmp/unpack \
       --policy /work/ghidra/tool.toml --lock /work/ghidra/assets.lock.json \
       --inventory /out/inventory.json
   ```

5. Review the inventory diff and update `LICENSE.md` and the file count in
   `tests/test_ghidra_tool.py`.
6. Build, smoke, security-test, and rerun the efficacy comparison. A new image id is a new
   decompilation identity, so existing publications are not reused.
