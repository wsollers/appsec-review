# ADR-0025: Dev-mode restart by data, and one generic item executor

Status: **Proposed** (brief I, 2026-09-29, branch `dev-executor`). The rules, the guard rails and "one
generic executor until proven otherwise" come from brief I. The implementer chose the exact rewind
interpretation, the item layout, which job to port and where the mode is read; these need review.

Implementation (2026-09-29, branch `dev-executor`): `dev_restart.py`, `launch_job.py --mode/--explain/
--force <job>`, `job_executor.py`, `items/02-operations-doc-ingest/`. Unit tests only
(`tests/test_dev_restart.py`, `tests/test_job_executor.py`). Nothing has run under a live Dagster code
location. Open items: `appsec-review-process/TODO.md` section I.

## Context

Prod fingerprints (ADR-0013) hash every job's code, contract and upstream attempt. That is right
for evidence. During the edit-run loop it is a relaunch tax (TODO "Relaunch tax"): a touch to a
contract or helper reruns finished work, and a changed upstream attempt id reruns every consumer even
when the bytes it published are identical. Each new job also costs about six hand-synced files.

## Decision

1. **Two run modes.** `APPSEC_RUN_MODE=dev|prod`. The default is prod, and an unrecognised value
   fails closed. Prod behaviour and prod fingerprints do not change: no legacy lifecycle, no
   `_code_hashes` and no fingerprinted file (`execution_state.py`, `publish_job_output.py`,
   `dagster_workflow.py`, `job-graph.json`, `schemas/*`) is edited by brief I1/I2.
   `tests/test_dev_restart.py` proves this: no brief-I file is named by any fingerprint, and the mode
   never changes a code fingerprint.
2. **Dev decides from data** (`dev_restart.py`), per job, in topological order. Each input artifact
   has a content hash and a shape hash (recursive keys and JSON types; an array's shape is the set of
   its element shapes). Unchanged content: REUSE. Changed content with the same shape: RERUN. Changed
   shape: REWIND.
3. **Rewind rule, as implemented.** Before any work, the pass compares every job's recorded input
   shapes with the shapes its producers have published now. Every rewindable producer with a
   mismatch is rerun, even if its own inputs are unchanged. Because every job is checked, a producer
   whose own input shape changed rewinds its producer too, so the rule is transitive. The rewind
   point is the set of rewound jobs with no rewound ancestor. Execution then runs forward in
   topological order. A rewound producer whose output comes out byte-identical still triggers early
   cutoff. Only item-executor producers are rewindable: a legacy producer's prod fingerprint covers
   all of its code, so its published output cannot be stale relative to code. Its consumer simply
   reruns. The mismatch rewind exists because dev ignores shared runtime and other jobs' code (rule
   6), so a dev-reused producer can be stale. The shape check is the safety valve.
4. **Early cutoff.** Downstream decisions compare input content, not producer attempt ids. A rerun
   with byte-identical output therefore leaves its consumers at REUSE.
5. **Rule 6.** A job's own config, contract, schema, prompt and implementation files are inputs.
   `SHARED_RUNTIME` and other jobs' implementation files are not. For an item, "own" is the item's
   `implementation.own` list. `implementation.related` counts in prod only. `--force <job>` reruns
   one job regardless.
6. **Guard rails.** Every executor receipt carries `mode` and `evidence_grade`, and a dev receipt is
   always `mode: "dev"`, `evidence_grade: false`. The prod key includes the mode, and prod reuse also
   requires a prod receipt, so prod never reuses a dev result. `final_publication.publish` refuses a
   dev process and refuses any run with an accepted dev result. `launch_job.py` refuses a dev final
   publication. Dev never relaxes the rule that an unscanned tool is a gap.
7. **Scope of the dev rules.** They apply to jobs run by the generic item executor. Legacy
   lifecycles keep their prod fingerprint in both modes, because bringing them under dev rules would
   mean editing their fingerprinted modules. `launch_job.py --explain` predicts every job: items by
   the data rules, legacy jobs from their recorded code hashes and upstream reruns, each with "prod
   would have invalidated because ...".
8. **One generic executor until proven otherwise** (`job_executor.py`). An item is `item.json` plus
   `input.schema.json` and `output.schema.json`, run in three phases. PRE resolves inputs from
   upstream outputs, validates them, stream-filters them through the existing redaction (recording
   metadata only) and computes hashes. PROCESS runs the declared argv worker (never a shell string)
   with declared grants. POST validates the output, writes a coverage/gap record and the receipt,
   runs the optional pass-through normaliser, and publishes through `publish_job_output`. New jobs
   are written as items. A second executor needs evidence that an item cannot express the job.
   `02-operations-doc-ingest` is ported as proof, with byte-identical outputs to the legacy worker.

## Consequences

- The relaunch-tax win grows as jobs are ported. Until then `--explain` shows where the tax falls.
- Registering item ops needs a small edit to `dagster_workflow.py`. `workflow.py` hashes that file into
  the workflow-preparation branch fingerprints, so the edit changes prod fingerprints once. It is a
  separate commit, held with I3.
- Reuse between modes is one way. Dev may reuse a prod result, because prod is stricter. Prod never
  reuses a dev result, so returning to prod recomputes every item job that dev published.
