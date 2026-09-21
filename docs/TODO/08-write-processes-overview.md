# 08 -- Write the processes overview (lifecycle, failure/resume, evidence discipline, personas/roles)

Goal: `appsec-review-process/README.md` is 300+ lines mixing layout, operating model, failure
model, evidence discipline, prompt architecture and registry. Extract the durable process rules
into short component docs and leave the README as a layout map.

## Inputs
- `appsec-review-process/README.md` (all sections), `initiate.md`, `manual-orchestration-runbook.md`,
  `environment.md`, `artifacts.md`, `budget-policy.md`.
- `docs/dagster/run-data-and-job-execution.md`, `docs/adapters/worker-result-envelope.md`
  (do not duplicate; link).
- `appsec-review-process/registry/README.md`, `docs/personas-and-registry/persona-catalog.md`.

## Steps
1. `docs/processes/lifecycle.md`: run -> job -> attempt -> accepted; OK/FAILED/BLOCKED/SKIPPED/
   CANCELED; reuse and newer-failure blocking; locks. One screen, pointing at the run-data doc.
2. `docs/processes/evidence-discipline.md`: the trust rules (untrusted data, no promotion without
   citation, no inference from unscanned files, High/Critical needs lane 09, redaction before LLM).
3. `docs/personas-and-registry/roles-and-composition.md`: persona + role + domain + tooling profile
   + output contract = job template; how a persona is dispatched (B14) and pooled (C01/C02).
4. Trim `appsec-review-process/README.md` to layout + links to the above.

## Done when
`appsec-review-process/README.md` is under ~120 lines and every removed paragraph has a home.

## Touches
New files under `docs/processes/` and `docs/personas-and-registry/`; `appsec-review-process/README.md`.
