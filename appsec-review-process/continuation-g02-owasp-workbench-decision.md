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

## Final checkpoint — 2026-09-19

- Branch/base: `codex/g02-owasp-workbench-decision` from `90cebf1`.
- Scope remained documentation/proposal-only; no runtime, schema, registry, graph/parity, generated
  view, test, validator, Dockerfile, launcher, or `TODO.md` file was changed.
- Refined ADR-0009 and the proposal packet to define standards/profile/version selection gates,
  accepted raw-versus-derived intel lineage, evidence-backed applicability triage, deterministic
  checklist partitioning, bounded batch defaults, persona/tool/handoff boundaries, structured
  intercom, static/dynamic/manual evidence rules, the control-status taxonomy, dynamic-test request
  contents, wait-all failure accounting, and the final joined matrix/gaps/requests/report structure.
- Kept the packet proposal-only and non-runnable. A checklist gap cannot become a finding, severity,
  exploitability, runtime observation, remediation claim, or compliance certification.
- The supplied OWASP comparison location remained the literal placeholder `<OWASP_REPO_URL>`.
  Accordingly, the packet records only the user/repository-described partitioning idea and does not
  claim inspection of a specific upstream revision.
- Verification passed: proposal YAML load, design-parity validation, Phase 1 contract
  qualification, and `git diff --check`. Design-parity still reports the expected planned gaps,
  including the unapproved OWASP decision and unimplemented S03 worker surfaces.
- Remaining human gate: approve exact standard/test/crosswalk versions and storage/license policy,
  ASVS profile/level and tailoring authority, enabled optional families, applicability override and
  rescope authority, evidence/status and batch policy, dynamic/manual authorization authority, and
  report/finding-promotion policy before implementation.
