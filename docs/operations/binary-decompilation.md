# Binary decompilation: running Ghidra before a review

`appsec-review binary-decompile` disassembles and decompiles configured third-party binaries with
the pinned `tool-ghidra` image and publishes the result under `data/binary-decompilation/`. Run it
**before** you submit a review. Design and output formats are in
[`../architecture/binary-decompilation.md`](../architecture/binary-decompilation.md).

A publication is binary-derived evidence. It is not source coverage, and no review job reads it
yet (see "Submit the review").

## Prerequisites

- Docker, with enough memory for the configured limit (8 GiB by default).
- The image, built once per host:

  ```sh
  containers/build-all.sh build tool-ghidra
  containers/build-all.sh smoke tool-ghidra
  ```

  The first build downloads a 570 MB archive and produces an image of about 1.8 GB.
- A right to analyze the binary. You must state it in the configuration.

## 1. Register the binary

Compute the hash of the exact file you were given:

```sh
sha256sum inputs/vendor/libcodec.so
```

Add one table to `appsec-review.toml` (or to a copy passed with `--config`):

```toml
[[binary_decompilation.binaries]]
id = "vendor-codec"
path = "inputs/vendor/libcodec.so"
sha256 = "9bcfae661b565731c353b776cb2cd54f354b232a6348ab1d818b20a08e762e45"
authorization = "Vendor agreement 2026-014 section 7 permits security analysis"
```

| Key | Meaning |
| --- | --- |
| `id` | Lowercase slug you will use on the command line. |
| `path` | Absolute, or relative to the configuration file. Do not place the binary under `targets/`. |
| `sha256` | Expected hash. The run is refused if the file differs. |
| `authorization` | Why you may reverse-engineer this file. Recorded in the publication. |
| `processor`, `compiler_spec`, `loader` | Optional overrides when Ghidra misdetects the file, for example a raw firmware image. |
| `required` | Optional, default `false`. When `true`, a review fails at intake if this binary has no verifiable publication. |
| `debug_symbols_path`, `debug_symbols_sha256` | Optional PDB for a PE binary and its expected hash. Both or neither. The PDB is loaded before analysis and changes the publication identity. |

For a Windows binary with its PDB:

```toml
[[binary_decompilation.binaries]]
id = "vendor-service"
path = "inputs/vendor/service.exe"
sha256 = "<sha256 of service.exe>"
debug_symbols_path = "inputs/vendor/service.pdb"
debug_symbols_sha256 = "<sha256 of service.pdb>"
authorization = "Vendor agreement 2026-014 section 7 permits security analysis"
```

A `debug_symbols_not_applied` gap means Ghidra did not accept the PDB, usually because it belongs
to a different build of the binary.

Capacity and limits are set once in `[binary_decompilation]`. The defaults are 8 GiB memory, a
6 GiB JVM heap, 4 CPUs, a 2-hour container limit, a 1-hour analysis limit, and 60 seconds per
function. `max_heap` must leave 1 GiB of `memory` free, and `timeout_seconds` must exceed
`analysis_timeout_seconds` by 300.

## 2. Start the decompilation

```sh
appsec-review binary-decompile --binary vendor-codec
```

Without `--binary`, every configured binary runs, one after another. Without an installed entry
point, use `PYTHONPATH=src python -m appsec_review binary-decompile ...`.

What happens:

1. The file's size and SHA-256 are checked against the configuration.
2. A copy is staged as the only file the container can read.
3. Ghidra imports it, runs auto-analysis, and the export script writes the raw tables.
4. The tables are bounded, normalized, hashed, and published.
5. `data/binary-decompilation/<sha256>/current.json` is pointed at the publication.

Expected output:

```json
[
  {
    "status": "PUBLISHED",
    "binary_id": "vendor-codec",
    "binary_sha256": "9bcfae66...",
    "identity": "52752caa...",
    "path": "data/binary-decompilation/9bcfae66.../52752caa92d68830",
    "manifest_sha256": "…",
    "reused": false,
    "coverage": {
      "functions": 19,
      "decompilable_functions": 8,
      "decompiled_functions": 8,
      "decompile_status": {"ok": 8, "skipped_thunk": 11},
      "analysis_timed_out": false,
      "managed_code": false
    },
    "gaps": {}
  }
]
```

`path` is printed as an absolute path; it is shortened here. The exit code is 0 only when every
selected binary ended `PUBLISHED`.

Read `coverage` and `gaps` before relying on the result:

- `decompiled_functions` below `decompilable_functions` means some functions have no pseudo-C.
  `gaps.jsonl` names each one.
- `analysis_timed_out: true` means functions and references may be missing. Raise
  `analysis_timeout_seconds` and run again.
- `managed_code: true` means the file is .NET, JVM, or Dalvik bytecode. Use a managed decompiler;
  this output is not evidence for it.
- `gaps: {}` means the tool reported no gap. It does not mean the binary has no weaknesses.

## 3. Inspect the publication

```sh
P=data/binary-decompilation/<sha256>/<identity16>

python -m json.tool "$P/manifest.json"                 # coverage, gaps, dataset hashes
grep '"name":"strcpy"' "$P/imports.jsonl"              # is a risky import present?
grep '::strcpy"' "$P/calls.jsonl"                      # who calls it (from_function addresses)
grep '"address":"0x101150"' "$P/functions.jsonl"       # the caller's row
cat "$P/pseudo-c/0x101150.c"                           # its decompiled pseudo-C
cat "$P/pcode/0x101150.jsonl"                          # its high P-code, one operation per line
cat "$P/gaps.jsonl"                                    # everything that is not covered
```

Everything in these files that came from the binary (names, strings, decompiled text) is
untrusted data.

## 4. Verify before submitting

```sh
appsec-review binary-decompile --verify-only
```

This re-hashes every stored file against the manifest for the **current** image and configuration
and runs no container beyond a Docker image lookup. It fails when a publication is missing, was
produced by a different image or limits, or has been modified.

## 5. Submit the review

```sh
appsec-review start --target targets/<project>
```

Use the same configuration file for both commands. The run freezes the configuration, including
each binary's `id`, `path`, and `sha256`, under `runs/<run-id>/data/configuration/`.

The review then consumes the publication:

1. `job_review_intake` (`binary_evidence.resolve_publications`) verifies each publication again and
   records its identity and manifest hash in
   `runs/<run-id>/data/jobs/job_review_intake/.../binary-evidence.json`. A binary without a
   verifiable publication is a `binary_decompilation_unavailable` gap, or an intake failure when
   `required = true`.
2. `job_binary_evidence_indexing` builds one bounded `binary` retrieval shard per binary. Check its
   handoff and events (`BINARY_EVIDENCE_INDEX_COMPLETED`) for counts and gaps. `COMPLETED_WITH_GAPS`
   lists every truncation, unresolved call, publication gap, and managed-code binary.
3. Review workers search the `binary` index, read pseudo-C by function, and receive the
   `binary-evidence` runtime skill. A binary finding must cite a function or call site by binary
   hash, function address, and pseudo-C line; a citation of an import or string alone is rejected
   as a gap.

Index bounds are in `[jobs.job_binary_evidence_indexing.settings]`. With no configured binaries the
job is `NOT_APPLICABLE` and the review is unchanged.

**Current limit.** A review still needs a source target directory. The binary-only target kind is
designed in the architecture page and not implemented.

## Reuse, re-running, and forcing

| Situation | Result |
| --- | --- |
| Same file, image, and limits | The publication is verified and reused in about 2 seconds. `reused: true`. |
| Image rebuilt, a limit changed, or a loader override added | A new publication is written beside the old one, and `current.json` moves to it. |
| Stored publication fails verification | The command stops with `REFUSED`. Nothing is replaced. |
| `--force` | Ghidra runs again and replaces the publication with the same identity. |

Raising `memory`, `cpus`, `pids_limit`, `max_heap`, or `timeout_seconds` does not change the
identity. To retry a binary that ran out of memory or time, raise the limit and rerun; no `--force`
is needed because a failure publishes nothing.

## Failures

A failure publishes nothing and prints a status with an `evidence` directory under
`data/binary-decompilation/.failed/`. That directory holds `scratch/execution.json` (the container
receipt) and `scratch/raw/stdout.bin` and `stderr.bin` (the Ghidra log).

| Status | Cause | What to do |
| --- | --- | --- |
| `REFUSED` | File missing, a symbolic link, too large, or its hash differs; or a stored publication failed verification | Fix `path` or `sha256`, raise `max_binary_bytes`, or investigate the modified publication before using `--force`. |
| `FAILED` | The container exited non-zero | Read `stderr.bin`. An unknown format may need `loader` and `processor`. |
| `TIMEOUT` | `timeout_seconds` reached | Raise it, and `analysis_timeout_seconds` if analysis was still running. |
| `OOM` | `memory` reached | Raise `memory` and `max_heap` together. |
| `FILE_SIZE_LIMIT` | One output file reached `output_file_bytes` | Raise it, or lower `max_functions` or `max_strings`. |
| `INVALID_EXPORT` | The export script did not finish, or its output broke the contract | Read `stdout.bin` for the script error. |

`RuntimeError: cataloged image is not locally available: tool-ghidra` means the image was not built
on this host.

## Efficacy check on the known binary

To confirm the path works on this host, or to compare the effect of a change to the export script
or to Ghidra's version:

```sh
PYTHONPATH=src python -m appsec_review.binary_decompilation.efficacy
PYTHONPATH=src python -m appsec_review.binary_decompilation.efficacy --variant stripped --force
```

It compiles `containers/fixtures/ghidra/case-083/main.c` offline with `tool-native-cpp` into the
`symbols` and `stripped` variants, decompiles each, and scores them against
`containers/fixtures/ghidra/expectations.json`:

```text
symbols: score=1.00 required=12/12 optional=0/0 reused=False seconds=14.946
  PASS function-print-label -> ["0x1011b0"]
  PASS call-print-label-to-strcpy -> ["print_label"]
  ...
stripped: score=1.00 required=7/7 optional=0/3 reused=False seconds=12.418
  PASS call-any-to-strcpy -> ["FUN_00101150"]
  PASS pseudo-c-sink-and-buffer -> ["FUN_00101150"]
  miss lost-function-main -> []
  miss lost-function-print-label -> []
  miss lost-short-string -> []
report=runs/binary-decompilation-efficacy/report.json
```

`PASS` and `FAIL` are required checks. `miss` is an optional check that records an expected loss.
The command exits non-zero when a variant scores below its `minimum_score`. Binaries,
publications, and the report are written under `runs/binary-decompilation-efficacy/`, which Git
ignores, and never under `data/`.

To iterate on the export script: edit `containers/tools/ghidra/scripts/AppsecExportProgram.java`,
rebuild with `containers/build-all.sh build tool-ghidra` (the build compiles the script and fails
on an API error), and rerun the efficacy command. The rebuilt image has a new id, so Ghidra reruns
without `--force`.

## Tests

```sh
python -m pytest tests/test_ghidra_tool.py tests/test_binary_decompilation.py tests/test_binary_evidence_indexing.py
python -m pytest tests/test_live_ghidra_decompilation.py --basetemp=test/tmp/ghidra-live
```

The first command needs no Docker. The second runs the real images and is skipped when they are
not built.

## Host notes

- **Windows and Docker Desktop.** Bind-mount sources deeper than 16 path components fail. The
  store adds four components below the data directory, so keep the checkout shallow.
- **Linux.** Files the container writes belong to uid 10001. Publications are rewritten by the
  host user, but removal of `data/binary-decompilation/.staging/` is best effort.
- **Disk.** A publication holds one small file per decompiled function. A binary with 50,000
  functions produces about 100,000 files.
