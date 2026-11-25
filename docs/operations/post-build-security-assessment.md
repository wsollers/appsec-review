---
title: "Post-build security assessment"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_cpp_compiled_analysis", "job_language_build", "job_post_build_security_assessment"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Post-build security assessment

The `post_build_security_assessment` Dagster job consumes the accepted
`job_cpp_compiled_analysis` handoff and, for the binaries of every other build family, the accepted
`job_language_build` handoff (see "Binaries of every build family" below). In `wave1_review` it is
ordered after compilation and compiled analysis. Static evidence collection is a sibling branch; CodeQL and OWASP wait for the accepted
post-build handoff.

## What it retains

For every accepted native build action, the job consumes the exact protected argv set retained by
`job_language_build` under `data/build/native/units/<build-unit-id>/protected-commands/`. Legacy
fixtures without that receipt use a local protected fallback. These files are run-owned and
restricted to the creating account where the host supports file modes. Retrieval and telemetry receive only a
bounded redacted form. The record binds run, target snapshot, project, build root, configuration,
action and compile-unit identities, tool/image identity, working directory, sanitized environment
facts, inputs, outputs and hashes, timing/status when observable, and the producing job/task.
Producing and linked-input relationships require unique full paths resolved against the captured
working directory and accepted workspace-to-case mapping. Basenames, suffix matches and a
`link.txt` file's parent directory do not establish that relationship. Missing or ambiguous
attribution stays a gap. A rejected catalog hash is excluded from subsequent discovery too.

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
Supported compiler options are evaluated in order, including disabling overrides and FORTIFY
macro undefines; unexpanded response files, including linker-forwarded `-Wl,@file` and
`-Xlinker @file` operands, leave flag posture unknown and retain a provenance gap. Compiler aliases (`cc`,
`c++`, `cl`) and direct ccache/sccache/distcc wrappers retain compile checks. Requested-versus-actual
link checks use only the uniquely resolved producing linker/driver, not flags from unrelated
artifacts or compile actions. PE32 high-entropy VA is not applicable; Mach-O magic takes priority
over an `.o` suffix; incomplete ELF tables retain partial facts and explicit unknowns. If truncated
ELF headers prevent linked-image classification, PIE/RELRO/NOW remain `UNKNOWN`, not inapplicable.

Inference is disabled by default. When a model client is centrally configured and injected, it
receives only structured normalized flags, topology, deterministic results, and inspected facts.
Every proposed observation must cite the selected deterministic check's complete resolving evidence
set (action/compile-unit and artifact/hash aliases are resolved without crossing subjects).
The selected scope is retained. The validator confirms it only
when deterministic evidence is failing, refutes it when deterministic evidence passes, and leaves
unknown evidence unvalidated. Provider failures and budget overflow complete with explicit gaps.
The model must answer with an `appsec-review/build-security-inference-proposal/1` object; the
validated outcome is written to `inference-results.json` (`appsec-review/build-security-inference/1`).
The request includes the closed response schema: `schema` and `observations` are required,
unknown/error fields are rejected, and claim/check/scope/evidence types are not coerced.
Malformed top-level replies use the existing bounded retries and exhaust to a named gap, never
successful empty coverage.

Blocked upstream cases still publish hash-bound empty stage documents. A case without build
actions or binary artifacts makes no model call and records the missing-evidence reason. Actual
model requests use the registered `post_build` worker and shared bounded execution/retry transport;
see [the canonical model and acceptance boundary](job_post_build_security_assessment.md).
Its confirmation label compares a known deterministic check; it is not independent proof of
every statement in a model claim.

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

Family selection reads the typed build outcome rather than requiring a clean receipt:
`built` / `COMPLETED_WITH_GAPS` products remain eligible after workspace-manifest and artifact
integrity validation. Original receipt gaps flow through load and family provenance; a case is
not relabeled clean, nor given exact command relationships. Failed/not-run and inconsistent
receipts remain excluded, and rejected artifacts never become inspection candidates. The
C/C++ catalog status checks remain catalog-readiness checks, not language-build outcome tests.

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
| .NET native AOT | PE `/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA` (PE32+ only) | `/GS`, SafeSEH (64-bit) |

For .NET native AOT, ELF defaults and Control Flow Guard are `unknown`. A family with no table
(`unknown_family` in `hardening.py`: Python, PHP, Node, Java or WebAssembly units that produced a
binary without captured compiles) makes every check `NOT_APPLICABLE` with the reason that no
documented default exists; Node, Python, PHP and WebAssembly units that did capture compile
actions are assessed flag-driven like native units (`_FLAG_DRIVEN_FAMILIES` in `assessment.py`).
`family_build_cases` admits artifacts with ELF, PE or Mach-O magic, except managed .NET
assemblies: a PE image with a CLR runtime header (data directory 14) carries IL, not native code,
so only native AOT output is judged by the .NET native AOT table (`_is_managed_pe`).

Native and mixed units keep the requested-versus-actual checks driven by their captured compile and
link flags. The pinned `nm`/`readelf` cross-check comes from the C/C++ lane's binary branch. Family
cases do not have it, so an ELF family artifact keeps the named gap that the pinned observation was
unavailable.

## Retrieval and resume

Each dynamically discovered build unit publishes an immutable `build_security` shard. Query through
`query_build_security` with one or more exact scopes: `project`, `build_root`, `build_action`,
`configuration`, `compile_unit`, `linked_artifact`, `producer`, or `shard`. The shard fingerprint
binds its command/binary closure, verified content hashes of all four stage documents, family
selection, model settings and target/upstream identities. Unchanged stage content can reuse an
immutable shard even from another attempt. Changed model responses, deterministic results,
provenance or inspection facts produce a new shard without changing the prior one. Indexing
rejects an in-memory stage result that differs from its referenced document. Oversized binaries
remain indexable unsupported records with a byte-bound gap.

Inspect `data/logs/pipeline.jsonl` for job/step/task lifecycle events,
`BUILD_COMMAND_PROVENANCE_CAPTURED`, `BUILD_ARTIFACTS_INSPECTED`,
`BUILD_SECURITY_CHECKS_COMPLETED`, model-call spans, validation counts, shard publication,
resumption, truncation, and gaps. The file is process-safe and crash-recovers a torn final record.

## Acceptance

Unit and synthetic fixture coverage validates dynamic enumeration, redaction, formats, rules,
inference validation, index scopes, fingerprints, telemetry contracts, and DAG topology. Current
live generic-build acceptance requires the exact verification evidence named in the deployment
guide; historical fixed-case acceptance does not establish health at the current source boundary.

Exact per-command timings and linker actions remain named gaps when the build system emits only a
compile database and no link command file. Model inference was disabled in the previously recorded live run as centrally
configured; deterministic inspection and checks were exercised.


## Tuning and whole-job recovery: `job_post_build_security_assessment`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.model.max_input_tokens` | `32000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.model.max_output_tokens` | `8000` | coverage | positive integer; exact parser/cross-field bounds? |
| `settings.model.retries` | `1` | coverage | integer >=0; exact parser/cross-field bounds? |
| `settings.model.timeout_seconds` | `120` | coverage | positive integer; exact parser/cross-field bounds? |

? The [executing job/parser](../../src/appsec_review/jobs/job_post_build_security_assessment/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.model.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `settings.model.provider` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.model.model` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `settings.model.reasoning` | Model/provider/reasoning or minimum thinking contract changes the reasoning method, not its execution ceiling. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.provenance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.inspection.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.deterministic.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.inference.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.index.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.publication.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
