# H16 — source-SAST recovery and language-tool hardening

You are the independent coder for H16. Re-derive ground truth from the current repository and read
`AGENTS.md`, the Independent work protocol in `appsec-review-process/TODO.md`,
`docs/agent-reader.md`, `docs/dagster/run-data-and-job-execution.md`,
`docs/processes/tool-images.md`, and the source-SAST contract/schema before editing.

Own only `appsec-review-process/source_sast.py`, source-SAST-specific rules/adapters/fixtures/tests,
and a new dedicated source-SAST qualifier. Do not edit build replay, job graph, parity
manifest/views, Dagster workflow/definitions, launcher, docs, common runtime, or main. Do not
change the output contract without stopping and requesting serialized integration.

First prove immutable reuse, raw/normalized evidence tamper rejection, newest-failure blocking,
controlled tool failure, forced recovery and recovered reuse. Then inspect the pinned tool catalog
for the declared Go, Java and PHP source tools. Integrate only tools whose pinned images and
deterministic offline invocation already exist. Normalize output to evidence leads without finding
promotion, severity, raw messages or snippets. Bind rule/config hashes and image identity. For any
tool that cannot honestly run, retain a precise coverage gap naming the missing prerequisite.

Start from current main on a dedicated branch. Run focused tests and real pinned-image smoke where
available, py_compile, contract qualification, parity validation and diff checks. Commit but do not
merge. Report tool-by-tool status, tests, run/attempt/hash evidence, limitations, integration
requests, branch and commit.
