# 05 -- Bring the live trackers back in line with the code

Goal: the docs classified CURRENT that carry known drift (found during classification) get a
correction pass so an agent can trust them. No structural change.

## Inputs (each drift item, with where it was found)
- `docs/design-parity/design-parity-completion-plan.md`: B11, B13, B14, B15, C01, C02 are
  implemented per their docs/PRs (#29, #32, #33, #34, #35) but still unchecked.
- `docs/proposals/vendor-prepass/task-series.md`: V02 shown "in review" (done); V10-V13 still
  `BLOCKED(...B13)` though B13 is DONE.
- `docs/proposals/threat-workbench/task-series.md`: T02 and T06 merged (`c6acf2b`, `87707d4`;
  `schemas/integrated-threat-model.schema.json`, `threat_workbench_intercom.py`) but shown
  READY/BLOCKED; T04 still lists B14 as a blocker.
- "42 nodes" -> 51: `docs/decisions/ADR-0008-threat-workbench.md`,
  `docs/proposals/threat-workbench/input-sources.proposal.yaml` header,
  `docs/continuation-prompts/design-parity-worker-envelope.md` (42 jobs / 83 records).
- `docs/architecture/migration.md`: "audit-static Dockerfile COPY paths do not build" (fixed;
  Dockerfile line ~386) and planned change #5 "no job-graph node yet" (ADR-0010 declared them).
- `docs/personas-and-registry/persona-catalog.md`: intro cites the superseded pool proposal;
  "Persona Shape" YAML vs registry JSON; "Search And Indexing" still `scratch/` layout.
- `docs/pools/resource-pools.md`: delete the finished "After PR #30 merges" chore list.
- `docs/evidence/evidence-redaction.md`: status line "no worker calls it yet" (validator now does).
- `docs/evidence/parallel-intelligence.md`: "retain legacy scripts for compatibility" contradicts
  the AGENTS.md delete-outright rule.
- `docs/adapters/pinned-container-adapter.md`: `BOUNDARY_FLAGS` is a tuple, not a list.
- `docs/continuation-prompts/g02-owasp-workbench-decision.md`: header task text predates its own
  checkpoints ("do not edit runtime code").

## Steps
One commit per file or per tracker; verify each claim against the code/TODO.md before editing.

## Done when
Every bullet above is fixed and `appsec-review-process/TODO.md` batch statuses agree with the
three task-series files.

## Touches
Exactly the files listed. Do not run concurrently with 03 (shares nothing, but both edit
`docs/architecture/`) -- sequence them.
