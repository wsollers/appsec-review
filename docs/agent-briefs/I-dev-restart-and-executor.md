# Brief I: dev-mode restart + generic job executor (branch `dev-executor`) - CLOUD agent

Why: throughput. Fingerprints are right for production evidence and wrong for the edit-run loop:
any code or contract touch re-executes finished jobs (relaunch tax, see `appsec-review-process/TODO.md`
"Relaunch tax"), and every new job costs ~6 hand-synced files. Two changes, in this order.

## I1. Dev-mode restart policy (do this first; it is the biggest win)
Find where a job's fingerprint and reuse/rerun decision are made (`execution_state.py`, `dagster_workflow.py`,
`launch_job.py`, `_code_hashes` / `IMPLEMENTATION_FILES` / `SHARED_RUNTIME`). Add a run mode, `APPSEC_RUN_MODE=dev|prod`
(default `prod`; prod behaviour, fingerprints and existing tests must be UNCHANGED). In `dev`, decide per job, in
topological order, from DATA only:

1. For each consumed input artifact compute a content hash and a SHAPE hash (recursive JSON keys + value types; arrays
   by the union of element shapes; independent of values and ordering of keys).
2. Input content hashes all unchanged since the job's last accepted run: REUSE.
3. Some input content changed but its shape is the same: RERUN this job.
4. An input's SHAPE changed: REWIND. Rerun the producer of that input (and, transitively, any producer whose own
   input shape changed), then continue forward. Report the rewind point.
5. EARLY CUTOFF: if a rerun publishes byte-identical output (content hash), everything downstream of it REUSEs.
6. A job's own config, contract, schema, prompt text and OWN implementation files count as its inputs. `SHARED_RUNTIME`
   and other jobs' implementation files do NOT (that is the point). `--force <job>` reruns one job regardless.

Guard rails (non-negotiable): every dev receipt carries `mode: "dev"` and `evidence_grade: false`; a prod run never
reuses a dev-published result (it recomputes or re-verifies); the report generator refuses to label a dev run as a
review deliverable. `--explain` prints one line per job: REUSE / RERUN / REWIND and the cause, including "prod would
have invalidated because <code hash of X changed>". Expose it via `launch_job.py` and the full_review launcher.
Doc: `docs/dev-mode-restart.md` (operator view, 1 page). Tests: fake-job graph covering rules 2-6, the guard rails,
and that prod fingerprints are byte-identical before and after your change.

## I2. Generic executor for new-style pipeline items (`appsec-review-process/job_executor.py`)
One generic Dagster op that runs an "item": `item.json` (config: needs, argv or worker reference, image/grants,
params) + `input.schema.json` + `output.schema.json`. Three phases:
- PRE: resolve inputs from upstream outputs, validate against `input.schema.json`, apply the existing redaction
  filter as a STREAM filter (record redaction metadata only, never values), compute input hashes/fingerprint.
- PROCESS: run the declared worker. Argv arrays only, container grants as declared, never a shell string.
- POST: validate against `output.schema.json`, write the coverage/gap record (a tool that did not run or a partial
  scan is a gap, never "no findings"), the receipt (status, `resume_from`, `rerun_command`, fingerprint, mode), and
  call an optional normalise hook (SARIF 2.1.0 for findings, CycloneDX for dependencies; PASS-THROUGH only when the
  tool already emits them; no new normalisers in this brief).
The op registers from `job-graph.json` like any job. Port exactly ONE small deterministic existing job as proof (you
choose; no model call, no container if possible). A test must prove the ported job publishes byte-identical outputs to
the old implementation on a fixture. Do not port any other job.

## I3. Fingerprint scope audit (report first, change second)
List every file in `_code_hashes` / implementation lists that is not semantics (READMEs, comment-only files, docs).
Remove those from the lists. Report the count and which jobs' prod fingerprints change once. DO NOT MERGE-SENSITIVE:
commit I3 separately so the controller can hold it until the hello-autotools baseline run finishes.

## You own
`execution_state.py` (staleness decision only), `launch_job.py`, new `job_executor.py`, new tests, the ported job,
`docs/dev-mode-restart.md`, one new ADR (next free number, currently ADR-0024) recording: dev vs prod, the rewind
rule, early cutoff, the guard rails, and "one generic executor until proven otherwise". `dagster_workflow.py` only to
register the generic op. Do NOT touch `registry/` paths, persona files or schemas beyond the two new item schemas
(brief J owns personas; brief K moves the registry later).
## Acceptance
Prod fingerprints identical before/after I1+I2 (test). Dev rules 2-6 tested. One ported job byte-identical.
Baseline failures in 00-common.md unchanged. State the exact interpretation of "rewind" you implemented.
