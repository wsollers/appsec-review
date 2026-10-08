# Post-build security assessment

The `post_build_security_assessment` Dagster job consumes the accepted
`job_cpp_compiled_analysis` handoff. In `wave1_review` it is ordered after compilation and compiled
analysis, and before evidence collection assembles its accepted manifest.

## What it retains

For every accepted build action, the run keeps an exact argv record under
`data/cpp/cases/<case>/build-security/protected-commands/`. These files are run-owned and restricted
to the creating account where the host supports file modes. Retrieval and telemetry receive only a
bounded redacted form. The record binds run, target snapshot, project, build root, configuration,
action and compile-unit identities, tool/image identity, working directory, sanitized environment
facts, inputs, outputs and hashes, timing/status when observable, and the producing job/task.

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

## Retrieval and resume

Each case publishes an immutable `build_security` shard. Query through
`query_build_security` with one or more exact scopes: `project`, `build_root`, `build_action`,
`configuration`, `compile_unit`, `linked_artifact`, `producer`, or `shard`. The shard fingerprint
is local to its command and binary dependency closure, so unchanged cases reuse their immutable
shards while changed cases and their linked outputs are rebuilt.

Inspect `data/logs/pipeline.jsonl` for job/step/task lifecycle events,
`BUILD_COMMAND_PROVENANCE_CAPTURED`, `BUILD_ARTIFACTS_INSPECTED`,
`BUILD_SECURITY_CHECKS_COMPLETED`, model-call spans, validation counts, shard publication,
resumption, truncation, and gaps. The file is process-safe and crash-recovers a torn final record.

## Acceptance

Unit and synthetic fixture coverage validates redaction, formats, rules, inference validation,
index scopes, fingerprints, telemetry contracts, and DAG topology. Live Dagster run
`82f99ee5-cd6f-4c55-85c8-06919ee55494` (application run `2026-10-08-0037`) consumed the accepted
13-case native C++ handoff and published an accepted post-build handoff with 13 immutable
`build_security` shards. The overall Wave 1 run later failed in the separate OWASP batching job, so
that run is evidence for this job's live boundary only, not for end-to-end Wave 1 success.

Exact per-command timings and linker actions remain named gaps when the build system emits only a
compile database and no link command file. Model inference was disabled in the live run as centrally
configured; deterministic inspection and checks were exercised.
