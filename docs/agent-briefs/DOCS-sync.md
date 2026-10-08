# Brief DOCS: documentation sync after merges (branch `docs-sync-<date>`)

Goal: after code branches merge, bring every human-facing artifact in line, without hand-editing generated files.

## Checklist per merged branch
1. Read the merge's diff (`git diff <parent>..<merge>`), its TODO section and any ADR it names.
2. Process docs under `docs/processes/` (`build-resolution.md`, `flow-bringup.md`, `host-layouts.md`, `tool-images.md`, ...): update prose that describes changed behaviour.
3. Job catalog: `python3 docs/processes/job_catalog.py` then `--check`. If a job is new, ensure `docs/processes/catalog/steps.json`, `artifacts.json`, `models.json` have its entry (that is the source of the generated catalog).
4. BPMN: `docs/processes/bpmn/*.bpmn` (and `render/`): add/adjust tasks for new or changed jobs; keep the cross-check in `job_catalog.py` green. Regenerate renders with the script that exists in `docs/processes/render/`.
5. Tunables: `docs/processes/tunables.md` is generated from job code; regenerate with the repo's generator (find it: `grep -rn tunables.md appsec-review-process/*.py docs -l`) and never hand-edit.
6. Design parity: `python3 appsec-review-process/validate_design_parity.py --write-generated-views` then `--check-generated-views`; update readiness/qualification text only from real evidence; do not raise a job to `implemented_and_qualified` without a live qualification record.
7. Job-graph diagram: keep `docs/design-parity/job-graph.mmd` and the generated top-level pipeline diagram in sync. Do not write generated views under `Claude outputs/`.
8. ADRs: update the Status/Implementation lines of the ADRs the merge implements (0016 kill chains, 0017 codeql, 0018 hunters, 0020 report, 0021 sharded reviewers, OSV feed). Do not change decisions.
9. `appsec-review-process/TODO.md`: collapse the per-agent sections into the existing structure, mark DONE with the merge commit, keep OPEN items honest. Skills: ensure `skills/README.md` lists new skills.
10. Personas: `python3 appsec-review-process/catalog_personas.py check`.
11. Final: run `job_catalog.py --check`, `validate_design_parity.py --check-generated-views`, `catalog_personas.py check` and the doc-related tests (`tests.test_job_catalog`, `tests.test_design_parity` - 5 known stale failures are being fixed by Agent B).

## You own
`docs/**`, `appsec-review-process/TODO.md`, `skills/README.md`, generated views. Do NOT change code, schemas or tests.
