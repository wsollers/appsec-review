# PR 4 Review Feedback

Review target: PR 4, `claude/t02-threat-workbench-schemas`

## Blocking Finding

The schema set does not fully enforce the ADR/T02 requirement that every canonical model record has citations, `evidence_class`, and `confidence`.

ADR-0008 says every canonical model record has a stable ID, an `evidence_class`, at least one citation, and `confidence`. `docs/proposals/threat-workbench/task-series.md` repeats this for the T02 deliverable across elements, flows, trust boundaries, data classes, deployment zones, abuse scenarios, attack trees, STRIDE hypotheses, assumptions/gaps, coverage, and dissent.

Current gaps:

- `schemas/threat-model-assumption.schema.json` requires `citations`, but has no `evidence_class` or `confidence`, and `citations` has no `minItems: 1`.
- `schemas/threat-model-gap.schema.json` has no `citations`, `evidence_class`, or `confidence`.
- `schemas/threat-model-attack-tree.schema.json` has no top-level `citations`, `evidence_class`, or `confidence`; node-level `citations` also has no `minItems: 1`.

Why this matters: T02 is supposed to make provenance and confidence structurally unavoidable before the later T08 validator exists. Letting assumptions, gaps, or attack-tree records omit those fields weakens the claim-discipline boundary this slice is meant to establish.

Requested fix:

- Add the missing `citations`, `evidence_class`, and `confidence` fields where appropriate.
- Require `minItems: 1` for citation arrays that are meant to satisfy the ADR/T02 citation requirement.
- Add focused mutation tests proving missing/empty citations and missing evidence/confidence are rejected for assumptions, gaps, and attack trees.

## Checks Run

- `python -B appsec-review-process/tests/test_threat_workbench_schemas.py` -- 38 passed
- `python -B -m unittest appsec-review-process.tests.test_design_parity appsec-review-process.tests.test_worker_result_runtime` -- 47 passed
- `python -B appsec-review-process/validate_design_parity.py` -- pass
- `python -B appsec-review-process/qualify_phase1.py --check-contracts` -- pass
- `python -B -m py_compile appsec-review-process/tests/test_threat_workbench_schemas.py` -- pass
- `git diff --check origin/main...HEAD` -- pass

## Merge Guidance

Not merge-ready yet. The fix should be small and remain inside PR 4's schema/test scope. After that, rerun the same checks.
