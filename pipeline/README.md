# Review pipeline

The supported engagement path is the run-owned Dagster `full_review` job. It resolves applicability,
executes only the relevant deterministic and model workers, validates immutable outputs, and carries
accepted evidence through independent verification to a draft report. This document is the short
entry point; the complete procedure is the
[`happy-path operator guide`](../docs/report-path/happy-path-operator-guide.md).

## Operator path

1. Prepare the Linux/WSL host with `orchestrator/prepare-host.sh` and stage the pinned target as the
   operator guide specifies.
2. Create/stage the run on the Linux owner of the target and run data.
3. Submit from the host:

   ```powershell
   python -B appsec-review-process/launch_job.py --run-id <run_id> --job full_review --wait
   python -B appsec-review-process/review_cli.py status --run-id <run_id>
   ```

4. Fix the first recorded breakage and submit the same run again. Reuse is accepted only when the
   worker's declared inputs, code, configuration, capabilities, and immutable output still validate.
5. Inspect the evidence-backed report and retained gaps. Final publication requires human approval
   of the exact draft hash.

Do not operate a new engagement through the retained root `engagement_job`, `pregather`, or manual
lane scripts. They remain only while the S1 inventory's field-parity and replacement gates are open;
they are not a parallel supported workflow and must not gain new callers.

## Run-owned lifecycle

The graph is generated from the registered job definitions under `appsec-review-process/pipeline/`.
At a high level it performs:

| Phase | Result |
|---|---|
| Intake and applicability | Fixed source identity, scope, permissions, language/build census, and explicit skip/gap decisions. |
| Searchable evidence | Hash-bound source, document, symbol, structural, and semantic retrieval records. |
| Deterministic collection | Applicable source, dependency, build, native, binary, mobile, deployment, test, and standards evidence in pinned workers. |
| Context assembly | Components, trust boundaries, controls, dependency reachability, tool leads, and bounded candidate records. |
| Focused review | Adversarial hypotheses, refutation, independent verification, scoring, and optional attack-chain/remediation work. |
| Report | Deterministic evidence and coverage synthesis, rendered draft artifacts, and a human-gated final package. |

Every worker terminates as `OK`, `OK_WITH_GAPS`, `SKIPPED`, `BLOCKED`, `FAILED`, or `CANCELED` with
explicit semantics. Missing tools and unsupported surfaces remain named gaps when the consumer
contract permits them. A scanner hit, similarity result, symbol edge, or model statement is not a
finding without resolving evidence and disposition.

## Data contract

Authoritative data lives under `appsec-review-process/runs/<run_id>/data/`:

```text
orchestration/launches/<launch_id>/
workflows/<workflow>/
jobs/<job>/<partition>/attempts/<attempt_id>/
imports/<import_id>/
```

Accepted pointers are the discovery boundary. Do not infer success from a directory's presence,
edit generated status, delete locks, or read shared scratch as current evidence. Explicit historical
imports are copied and hash-bound beneath `data/imports/`; they never make the source location
authoritative.

## Source and validation

- Job graph and contracts: `appsec-review-process/pipeline/`.
- Worker implementations and validators: `appsec-review-process/`.
- Dagster definitions and service integration: `orchestrator/dagster/`.
- Evidence retrieval contract: `docs/evidence/evidence-retrieval.md`.
- Run-data contract: `docs/dagster/run-data-and-job-execution.md`.
- Generated graph/readiness views: `docs/design-parity/`.

Run touched tests plus these checks after graph, registry, or catalog source changes:

```powershell
python -B appsec-review-process/validate_design_parity.py --check-generated-views
python -B docs/processes/job_catalog.py --check
```

Review logic does not move into `scripts/`. Static reference data belongs in `data/`; tools belong
in pinned images; current workers publish only inside their run-owned attempt.
