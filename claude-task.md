# Claude task — Batch B09 SARIF common-runtime adoption

Work only on Batch **B09** from `appsec-review-process/TODO.md`.

## Git workflow

1. Pull current `origin/main`.
2. Create branch `claude/b09-sarif-common-runtime`.
3. Do not merge to `main` and do not work on another batch.
4. When complete, commit and push the branch. Report the branch, commit SHA, tests, live run IDs,
   evidence report/hash, changed files, limitations, and blockers to the user.

## Required outcome

Migrate standalone `10-critical-findings-sarif` to the already-qualified common lifecycle,
worker-result envelope, read-only validation/publication boundary, and
`appsec-review/deterministic-child/1.0` execution contract.

Preserve its current strict fixed-input Markdown-to-SARIF behavior and standalone Dagster job.
Do not bind it to synthesis yet.

## Read first

- `AGENTS.md`
- `appsec-review-process/agent-skills/claude/process-reader.md`
- `appsec-review-process/TODO.md` — B09 and the independent-work protocol
- `docs/continuation-prompts/design-parity-worker-envelope.md`
- `docs/run-data-and-job-execution.md`
- `docs/worker-result-envelope.md`
- `docs/critical-findings-sarif-job.md`
- `appsec-review-process/critical_findings_sarif.py`
- `appsec-review-process/tests/test_critical_findings_sarif.py`

## Scope

Expected primary files:

- `appsec-review-process/critical_findings_sarif.py`
- `appsec-review-process/tests/test_critical_findings_sarif.py`
- `appsec-review-process/registry/output-contracts/critical-findings-sarif.json`
- a dedicated SARIF result schema if the common validator requires one
- `appsec-review-process/qualify_worker_adoption.py` or a narrowly separate SARIF qualification
- directly affected runtime/parity/docs files only

Use `publish_job_output.py`, `validate_job_output.py`, `worker_result.py`, and
`deterministic_child.py` as existing boundaries. Change them only for a demonstrated generic defect
covered by regression tests; do not redesign them.

## Acceptance

Prove:

- semantic parity of the existing conversion fixture;
- common-envelope success, reuse, force, tamper rejection, and contract validation;
- preflight `BLOCKED`, work `FAILED`, and cancellation `CANCELED` behavior;
- deterministic-child timeout, simultaneous stream pressure/truncation, child loss/tree cleanup,
  and log-write failure without duplicating the generic runner's tests unnecessarily;
- durable-envelope/`PENDING` publication recovery;
- interrupted-attempt recovery and no fallback after a newer failure;
- Windows and Linux focused tests;
- design-parity and registry/contract validation;
- one bounded live Dagster success, reuse, newer-failure, and recovery sequence because executable
  identities change.

Run at minimum:

```text
python -B -m py_compile <changed Python files>
python -B -m unittest discover -s appsec-review-process/tests -p test_critical_findings_sarif.py -v
python -B -m unittest discover -s appsec-review-process/tests -p test_worker_adoption.py -v
python -B -m unittest discover -s appsec-review-process/tests -p test_deterministic_child.py -v
python -B appsec-review-process/validate_design_parity.py
python -B appsec-review-process/qualify_phase1.py --check-contracts
git diff --check
```

Run the focused tests in the Linux code-server with `PYTHONDONTWRITEBYTECODE=1`. Before any live
launch, verify no Dagster run is active. Keep all qualification evidence under the owning ignored
run directory and record exact identities and hashes.

## Out of scope

Do not implement synthesis binding, developer discovery, containers, personas, pools, permissions,
standards decisions, claim-ledger work, or any other lifecycle worker. Do not rewrite historical
attempts or weaken the SARIF finding validation contract. If the migration cannot preserve current
semantics, record the gap and stop instead of broadening the batch.
