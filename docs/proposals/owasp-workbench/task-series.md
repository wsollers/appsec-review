# OWASP Control Workbench Task Series

Status: Proposal-only task packet for G02/S03. Do not mark `04-owasp-validation-worklist` or
`04-asvs-masvs` implemented from this document alone.

## T01 — Review And Approve OWASP ADR

Review `docs/decisions/ADR-0009-owasp-control-workbench.md` and confirm:

- supported OWASP families and version-pinning policy;
- profile/level selection authority;
- applicability statuses;
- control statuses;
- claim limits.

## T02 — Standards Source Records

Define source schemas and fixtures for:

- ASVS controls;
- MASVS controls;
- MASTG tests and reverse links;
- API Top 10 categories;
- OpenCRE mappings;
- optional LLM/agent guidance.

Reject records without source/version/hash/license metadata.

## T03 — Applicability Model

Define `owasp-applicability-model.json`:

- selected standards/profile/level;
- component-to-control mapping;
- evidence basis for applicability and not-applicability;
- cannot-determine gaps.

## T04 — Worklist Batching

Define `owasp-validation-worklist.json` and batching rules:

- component/domain/evidence-mode grouping;
- bounded work item size;
- required source/reference records;
- validator persona/tooling profile.

## T05 — Validator Output Contract

Define `control-assessment-result.json`:

- one status per work item/control/component;
- evidence and counterevidence citations;
- static/dynamic/human follow-up status;
- candidate verification routes.

Reject verified findings, final severity, runtime exposure, and compliance certification.

## T06 — Pool Dispatch And Wait-All

After persona/pool foundations exist, dispatch bounded validator cells and require every expected
cell to reach terminal state before join.

## T07 — Join And Reporting

Join validator outputs into:

- `owasp-control-status-matrix.json`;
- `owasp-dynamic-test-requests.json`;
- `owasp-coverage-gaps.json`;
- `owasp-workbench-summary.md`.

Preserve failed/skipped/degraded cells and unresolved applicability gaps.

## T08 — Golden Fixtures

Create small fixtures covering:

- web/API ASVS controls;
- mobile MASVS/MASTG static and dynamic-required controls;
- API Top 10 context mapping;
- documentation-only intent;
- scanner-only lead;
- not-applicable control with evidence;
- cannot-verify control.

## T09 — Lifecycle Integration

Integrator-only after T01-T08:

- registry composition;
- output contract binding;
- graph/parity manifest updates;
- generated views;
- live service qualification.

