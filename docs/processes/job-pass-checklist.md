---
title: "The job-by-job pass: checklist"
kind: "process"
subsystem: "testing and operations"
status: "current"
jobs: []
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# The job-by-job pass: checklist

Applied to every job in `wave1_review` graph order (`docs/tasks/2026-11-08-job-pass-NN-*.md` is the
record for each). The pass has three parts and a job is not done until all three are.

## 1. Fix

- Start from an observed defect or a decision the walk-through named (`docs/TODO.md` ids), not from
  a redesign. A fix that spans jobs is owned by the job where the *decision* is made; the consuming
  job gets its test when the pass reaches it.
- Failures are typed (`<Job>Failed(RuntimeError)` or a more specific class), named in the task
  receipt's `error.type`, and the written evidence carries `producer-gap/1` records for what failed
  (`interchange.producer_gap`, retryable when an operator action resolves it).
- A job that cannot do its work for a wiring reason (no runner, no check) is refused at claim time
  by an input validator, never discovered inside a unit.
- `schema_identity` is bumped when the job's outputs change shape.
- **No backward compatibility during the pass** (decision 2026-11-08). A reader accepts the current
  schema only; a changed record replaces the old one, never sits beside it; no dual-read, no
  migration layer, no fallback to a previous shape. Runs started before a change are not resumed
  across it — a fresh review is started after the pass. Compatibility is reconsidered only once
  the jobs are vetted.

## 2. Audit the tests

A unit test for a job, in this repository, means:

- the real configuration (`appsec-review.toml`, copied under `tmp_path` with any profile it needs)
  and the real `JobRunner`/`GraphRunner`; run trees are produced by publishing, never by writing
  `latest.json` or `handoff.json` by hand;
- a fake only at the external boundary (provider check, Docker runner, model call, network);
  never a fake of the behaviour under test;
- no Docker engine, no model, no network, no `targets/` checkout; under a few seconds;
- assertions on what a consumer or operator sees — the handoff, the artifact, the receipt, the
  events — not on private dictionaries.

For each unit of the job the file answers: happy path; every named gap, disposition and REJECT
path by name; checkpoint/resume reuse where the job supports it; outputs validate against the
job's schema and the control-layer schema. `pytest --cov=appsec_review.jobs.<job>
--cov-report=term-missing` is recorded in the task doc with the uncovered lines explained.

## 3. Failure handling, telemetry and metrics

Every failure path the job has is driven through the runner and asserted:

- the attempt fails (or publishes `COMPLETED_WITH_GAPS` when that is the contract), the evidence
  written before the failure is kept, no `latest.json` is published for a failed attempt, and
  `resume` after the cause is removed publishes a second attempt;
- `tests/telemetry_support.assert_job_lifecycle(run_root, job_id, terminal=..., attempts=...)` on
  the success path, every failure path and the resume path: it validates every `pipeline.jsonl`
  event, checks `JOB_STARTED`/terminal pairing per attempt, the `ERROR` level and `TASK_FAILED`
  details on failure, that `status.json` agrees and carries `duration_ms`, and that the run-wide
  `data/telemetry/summary.json` (`write_run_metrics`) exists and counts the events;
- the job's own events (`<JOB>_STARTED/COMPLETED/FAILED` and the like) are asserted by
  `tests/telemetry_support.job_events` with their detail fields, on success and on failure, so a
  count or a field cannot silently disappear.

Shuffled runs (`--shuffle-seed`) of the job's file(s) and the affected neighbours are recorded;
parallel runs (`-n`) where xdist is available.

## 4. Record

- `docs/tasks/2026-11-08-job-pass-NN-<job>.md`: what the job does, what was fixed and why (including
  any earlier decision reversed), the before/after test audit as a table, coverage, commands with
  timings and results, pre-existing failures attributed to other jobs, carried-forward items.
- `docs/TODO.md`: new ids for anything deferred; state changes for anything closed.
- One commit per job on `main` (HAL5000), titled `Job pass NN: …`.
