# Continuation prompt — build configure / SAT stage 14 (2026-09-27)

Start by re-deriving ground truth: read `AGENTS.md`, the Independent work protocol in
`appsec-review-process/TODO.md`, ADR-0012, `docs/processes/build-resolution.md`, and the newest log
entry in `docs/processes/flow-bringup.md`; then fetch and inspect the current branch/worktrees and
live Dagster services. Tracked docs and immutable run evidence override this snapshot.

Stage 13 is complete. Fresh SAT `20260926T235610Z`, engagement
`20260926T235619Z-cfd753`, passed stages 1-13. Build-resolution Dagster run
`b9bfe716-b25c-4a83-a289-81981a689431` accepted attempt
`5a6496d781dc47ac8f5f034462f65f91`, image `image_build_a453dcd7c961`, and six clang compile
commands. Qualification `build-resolution-d6b412ec` proved immutable reuse, tamper rejection, a
real newer container failure, recovery without fallback, and recovered-attempt reuse. Exact grants
were apt HTTP to `archive.ubuntu.com:80` and target execution profile `build-resolution-v1` at `.`.

The next bounded task is E01 / `02-build-configure`, SAT stage 14. Replace the legacy CMake-only
`build_execution.py` path for this lifecycle node with a common-envelope worker that consumes and
validate-on-read checks the accepted stage-13 lock, container-image record, source revision and
permission binding. From a fresh writable scratch copy under B13, replay only the lock's configure
argv (`autoreconf -fi`, `./configure`) using the pinned image, read-only target mount, sole writable
`/scratch`, `--network none`, and caller-held result hash. Publish run-owned configure outputs and
provenance; never fall back to an older lock or attempt, never run tests or the built target, and do
not silently use the old `buildenv-common` wrapper.

Use the Full protocol: graph/parity, schema and output contract, registry composition, Dagster
standalone/lifecycle/sensor/launcher bindings and Docker pool, exact permission tests, immutable
reuse/tamper/newer-failure/recovery qualification, SAT stage 14, authoritative docs, Mermaid/BPMN
sources and renders where affected, generated job catalog, contract/parity checks, and a committed
isolated-worktree result. The remaining stage after E01 is E02 / `02-native-build`.
