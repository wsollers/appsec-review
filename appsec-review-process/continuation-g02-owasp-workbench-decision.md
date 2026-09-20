# Continuation prompt — G02 OWASP control workbench decision

Continue from branch `codex/g02-owasp-workbench-decision`.

This is a documentation/proposal-only G02 task. Do not edit runtime code, schemas, registry records,
graph/parity surfaces, generated views, tests, validators, Dockerfiles, launchers, or `TODO.md`.

## Task

Review and refine the OWASP control workbench proposal:

- `docs/decisions/ADR-0009-owasp-control-workbench.md`
- `docs/proposals/owasp-workbench/input-sources.proposal.yaml`
- `docs/proposals/owasp-workbench/workcells.proposal.yaml`
- `docs/proposals/owasp-workbench/task-series.md`

The intended pattern is: use gathered intel to decide if checks are needed, batch similar controls,
dispatch validator personas with explicit tools/evidence, and join into a validated applicability
and control-status model.

## Read first

1. `AGENTS.md`
2. `docs/agent-reader.md`
3. `appsec-review-process/TODO.md` — G02 and S03
4. `docs/design-parity-completion-plan.md` — G2
5. `docs/design-v3.md`
6. `docs/standards-checklist-validation-proposal.md`
7. `docs/persona-catalog.md`
8. `docs/intelligence-sources-and-jobs.md`
9. `appsec-review-process/04-asvs-masvs/prompt.md`
10. `appsec-review-process/04-asvs-masvs/config.md`
11. `appsec-review-process/04-asvs-masvs/subprompts.md`
12. `appsec-review-process/registry/job-templates/04-owasp-validation-worklist.json`
13. `appsec-review-process/registry/personas/owasp-validator.json`

## Exclusive file boundary

You may change only:

- `docs/decisions/ADR-0009-owasp-control-workbench.md`;
- files under `docs/proposals/owasp-workbench/`;
- this continuation prompt, only to append a final checkpoint.

## Acceptance

- Proposal remains non-runnable and proposal-only.
- OWASP standards/version/profile decisions are explicit or recorded as human gates.
- Applicability and control statuses are defined.
- Control work is batched by component/domain/evidence mode.
- Validator personas cannot publish findings/severity/compliance certification.
- Static-only evidence cannot satisfy dynamic/runtime controls.

## Verification

Run:

```text
python -c "import pathlib, yaml; [yaml.safe_load(path.read_text(encoding='utf-8')) for path in pathlib.Path('docs/proposals/owasp-workbench').glob('*.yaml')]; print('yaml ok')"
python -B appsec-review-process/validate_design_parity.py
python -B appsec-review-process/qualify_phase1.py --check-contracts
git diff --check
```

Commit on a dedicated branch and report branch, commit, files changed, validation results, and
remaining human gates.

