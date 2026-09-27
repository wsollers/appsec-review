# H14 — build replay fault/recovery hardening

You are the independent coder for H14. Re-derive ground truth from the current repository and read
`AGENTS.md`, the Independent work protocol in `appsec-review-process/TODO.md`,
`docs/agent-reader.md`, `docs/dagster/run-data-and-job-execution.md`, and
`docs/processes/system-acceptance-test.md` before editing.

Own only `appsec-review-process/build_replay.py`, focused build-replay tests, and a new dedicated
build-replay qualifier under `appsec-review-process/`. Do not edit the job graph, parity manifest or
generated views, Dagster workflow/definitions, launcher, docs, output contracts, common runtime,
source-SAST files, or main. If one is required, report an integration request instead.

For both `02-build-configure` and `02-native-build`, prove immutable successful reuse, artifact and
pointer tamper rejection, no fallback after the newest failure, a controlled failure, forced
recovery, and reuse of the recovered attempt. Preserve exact accepted build-resolution and
configured-build lineage, caller-held B13 result hashes, offline/read-only execution, and exact
permission binding. Never execute a produced target binary.

Start from current main on a dedicated branch. Run focused unit tests, the qualifier where host
services permit, py_compile, contract qualification, design-parity validation and diff checks.
Commit but do not merge. Report scope, files, test counts, run/attempt/hash evidence, limitations,
integration requests, branch and commit.
