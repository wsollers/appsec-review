# Post-build security assessment

The `post_build_security_assessment` Dagster job consumes the accepted
`job_cpp_compiled_analysis` handoff. In `wave1_review` it is ordered after compilation and compiled
analysis. Static evidence collection is a sibling branch; CodeQL and OWASP wait for the accepted
post-build handoff.

## What it retains

For every accepted native build action, the job consumes the exact protected argv set retained by
`job_language_build` under `data/build/native/units/<build-unit-id>/protected-commands/`. Legacy
fixtures without that receipt use a local protected fallback. These files are run-owned and
restricted to the creating account where the host supports file modes. Retrieval and telemetry receive only a
bounded redacted form. The record binds run, target snapshot, project, build root, configuration,
action and compile-unit identities, tool/image identity, working directory, sanitized environment
facts, inputs, outputs and hashes, timing/status when observable, and the producing job/task.

Per project, the job's task directories under the attempt hold `build-command-provenance.json`
(`appsec-review/build-command-provenance/1`) and `binary-inspections.json`
(`appsec-review/binary-inspection-set/1`, whose `records` are `appsec-review/binary-inspection/1`).

Do not copy protected command artifacts into tickets, logs, prompts, or MCP responses. They may
contain credentials passed by a target build. Central events intentionally contain identities and
counts only.

## Deterministic and inferential assessment

Produced ELF, PE/COFF, Mach-O, archive, object, LLVM bitcode, debug, and link-map candidates are
read as data; target binaries are never loaded or executed. The built-in bounded parsers extract
the facts they can prove and name gaps for facts that require unavailable pinned tooling. Rules are
selected by compiler, platform, artifact kind, configuration, and observed capability. Unknown or
irrelevant properties are respectively `UNKNOWN` or `NOT_APPLICABLE`, never `PASS`.

Inference is disabled by default. When a model client is centrally configured and injected, it
receives only structured normalized flags, topology, deterministic results, and inspected facts.
Every proposed observation must cite supplied evidence identities. The validator confirms it only
when deterministic evidence is failing, refutes it when deterministic evidence passes, and leaves
unknown evidence unvalidated. Provider failures and budget overflow complete with explicit gaps.
The model must answer with an `appsec-review/build-security-inference-proposal/1` object; the
validated outcome is written to `inference-results.json` (`appsec-review/build-security-inference/1`).

## Binaries of every build family

`load.accepted_cpp_build` loads two kinds of case:

- C/C++ cases from `job_cpp_compiled_analysis`. These are native units, plus mixed units
  (node-gyp, phpize, setuptools, clang `--target=wasm32`) whose own family build captured compiles
  of their `native_components`.
- Family cases (`family-<build-unit-id>`) from the accepted `job_language_build` receipts. These
  cover every other successful build that produced an ELF, PE/COFF or Mach-O file: Go and Rust
  executables, .NET native AOT output, and the binary members (`.so`, `.pyd`, `.dylib`, `.dll`,
  `.node`) of wheels.
  - Wheel members are extracted with a bounded archive reader into the task directory. They are
    inspected with the same `inspect_binary` parser, and each records its archive and member name.
  - WebAssembly modules are not ELF/PE/Mach-O and are not inspected here.
  - A missing language-build handoff is a named load gap.

Family cases have no captured C flags. Their checks follow the typed table in
`job_post_build_security_assessment/hardening.py` (`build-security-family-expectations/1`). Each
entry is one of three values:

- `required`: the observed value decides PASS or FAIL.
- `not_offered`: the toolchain does not provide the protection by default.
- `unknown`: no documented default is known.

Both `not_offered` and `unknown` make the check `NOT_APPLICABLE` with the documented reason and
source, never a PASS and never a finding. Each such check carries an `expectation` object with the
family, the value and the source.

Summary of the table:

| Family | Required | Not offered by default |
| --- | --- | --- |
| Go (linux/amd64) | non-executable stack | PIE (needs `-buildmode=pie`), RELRO, immediate binding, CET, stack canary, FORTIFY |
| Rust (x86_64-unknown-linux-gnu) | PIE, full RELRO, immediate binding, non-executable stack | stack protector, CET, FORTIFY |
| .NET native AOT | PE `/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA` | `/GS`, SafeSEH (64-bit) |

For .NET native AOT, ELF defaults and Control Flow Guard are `unknown`.

Native and mixed units keep the requested-versus-actual checks driven by their captured compile and
link flags. The pinned `nm`/`readelf` cross-check comes from the C/C++ lane's binary branch. Family
cases do not have it, so an ELF family artifact keeps the named gap that the pinned observation was
unavailable.

## Retrieval and resume

Each dynamically discovered build unit publishes an immutable `build_security` shard. Query through
`query_build_security` with one or more exact scopes: `project`, `build_root`, `build_action`,
`configuration`, `compile_unit`, `linked_artifact`, `producer`, or `shard`. The shard fingerprint
is local to its command and binary dependency closure, so unchanged units reuse their immutable
shards while changed units and their linked outputs are rebuilt.

Inspect `data/logs/pipeline.jsonl` for job/step/task lifecycle events,
`BUILD_COMMAND_PROVENANCE_CAPTURED`, `BUILD_ARTIFACTS_INSPECTED`,
`BUILD_SECURITY_CHECKS_COMPLETED`, model-call spans, validation counts, shard publication,
resumption, truncation, and gaps. The file is process-safe and crash-recovers a torn final record.

## Acceptance

Unit and synthetic fixture coverage validates dynamic enumeration, redaction, formats, rules,
inference validation, index scopes, fingerprints, telemetry contracts, and DAG topology. Current
live generic-build acceptance is recorded by the verification evidence named in the deployment
guide; historical fixed-case acceptance is no longer the active topology.

Exact per-command timings and linker actions remain named gaps when the build system emits only a
compile database and no link command file. Model inference was disabled in the live run as centrally
configured; deterministic inspection and checks were exercised.
