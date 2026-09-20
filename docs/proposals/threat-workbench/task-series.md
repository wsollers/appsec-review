# Threat Workbench Task Series

Status: Proposal-only task packet for G01/S02. Do not mark `03-threat-model-dfd-stride` implemented
from this document alone.

## Review Pattern

Use paired implementation/review tasks:

- one agent drafts a bounded artifact or implementation slice;
- the other agent reviews for evidence boundaries, schema drift, claim overreach, and integration
  conflicts;
- the original agent applies fixes;
- only then does the integrator update live graph/registry/readiness surfaces.

Codex and Claude tasks must be independent and commit-ready. Shared surfaces such as
`appsec-review-process/job-graph.json`, `appsec-review-process/design-parity-manifest.json`,
runtime modules, generated views, and TODO status remain integration-only.

## T01 — Approve Threat Workbench ADR

Owner: human gate with Codex/Claude review.

Deliver:

- Review `docs/decisions/ADR-0008-threat-workbench.md`.
- Confirm the decision to make `03-threat-model-dfd-stride` a workbench subworkflow.
- Confirm that DFD remains canonical and PII/abuse/attack-tree/STRIDE are overlays.

Acceptance:

- Open questions are resolved or explicitly deferred.
- No runtime or registry implementation is claimed.

Reviewer focus:

- Does the ADR preserve static/offline boundaries?
- Does it prevent threat hypotheses from becoming findings?
- Does it define enough output for downstream OWASP/DISA/red-team/verification work?

## T02 — Schema Design For Integrated Threat Model

Owner: implementation agent after T01.

Deliver proposal first, then implementation after review:

- `schemas/integrated-threat-model.schema.json`
- `schemas/threat-workbench-intercom.schema.json`
- `schemas/threat-workbench-cell-result.schema.json`
- golden and mutation fixtures

Acceptance:

- Schema covers elements, flows, data classes, deployment zones, abuse scenarios, attack trees,
  STRIDE hypotheses, assumptions, gaps, intercom records, and workcell statuses.
- Schema rejects verified finding, final severity, runtime exposure, compliance pass/fail, and
  remediation claims.
- Schema supports Mermaid generation without embedding diagram-only state as authority.

Reviewer focus:

- Every graph edge has source, destination, data class, evidence, confidence, and boundary fields.
- Every threat has proof obligations and downstream owner.
- Intercom records are auditable and cannot be silently overwritten.

## T03 — Input Bundle And Intel Source Router

Owner: implementation agent after T02.

Deliver:

- lane-in input bundle contract;
- source freshness and attempt-hash rules;
- router mapping from accepted pregather/intel jobs to workcell-readable inputs;
- tests for stale, mixed-generation, missing, and unsupported sources.

Acceptance:

- Raw, derived, accepted-lane, persona, and reference sources are labelled.
- Secrets and raw PII cannot enter UI-safe workbench output.
- Missing optional intel creates coverage gaps, not fabricated model content.

Reviewer focus:

- Does every input source in `input-sources.proposal.yaml` have a claim limit?
- Are static-only and documented-intent sources clearly marked?

## T04 — Persona Workcell Registry Records

Owner: implementation agent after persona adapter foundation.

Deliver:

- machine-readable workcell/persona/domain/tooling-profile records;
- rendered prompts for each initial workcell;
- validation that every workcell declares inputs, outputs, proof obligations, and `must_not`.

Initial workcells:

- architecture DFD mapper;
- PII/user-data mapper;
- deployment topology mapper;
- abuse-scenario analyst;
- STRIDE enumerator;
- attack-tree builder;
- domain-specialist router;
- challenge/refutation cell;
- integrator/join cell.

Acceptance:

- Workcell prompts are short, typed, and evidence-bound.
- Personas communicate only through intercom artifacts.
- Selection is target-trait driven; no universal run-everything default.

Reviewer focus:

- Persona theater: reject vague roles without proof obligations.
- Claim discipline: reject verified/severity/compliance language.

## T05 — Pool Expansion And Wait-All For Threat Workbench

Owner: implementation agent after C01/C02 foundations.

Deliver:

- deterministic workcell instance expansion;
- private output roots;
- wait-all terminal manifest;
- interrupted/failure/cancel handling.

Acceptance:

- Join cannot run before every expected workcell is terminal.
- Failed/skipped/degraded workcells remain visible.
- Reuse and rerun honor source and prompt/composition hashes.

Reviewer focus:

- No early publication.
- No hidden fallback to older success after newer failure.

## T06 — Intercom Artifact Bus

Owner: implementation agent after T05.

Deliver:

- append-only intercom transcript writer;
- typed records for questions, assumptions, proposed edits, proposed threats, challenges, and
  responses;
- validation and merge semantics.

Acceptance:

- Workcells can address records to another cell or to the integrator.
- Resolution status is explicit.
- Unresolved records propagate to `assumptions-and-gaps.json`.

Reviewer focus:

- Intercom is durable artifact exchange, not hidden conversation.
- Contradictions are preserved until resolved.

## T07 — Join, Ranking, And Diagram Generation

Owner: implementation agent after T06.

Deliver:

- integrator merge worker;
- Mermaid DFD generator;
- Mermaid attack-tree generator;
- STRIDE radar data generator;
- ranked scenario output;
- verification worklist output.

Acceptance:

- Rankings combine impact, data sensitivity, trust boundary, preconditions, exposure, evidence
  confidence, chain support, abuse harm, and unresolved assumptions.
- Radar/spider data is labelled as visualization input, not severity.
- Every diagram node/edge traces to canonical JSON records.

Reviewer focus:

- No count-only severity.
- Mermaid output is derived from JSON, not hand-authored authority.

## T08 — Threat Workbench Validator

Owner: implementation agent after T07.

Deliver:

- validator for integrated threat model and workcell outputs;
- negative tests for overclaims, missing evidence, stale inputs, unresolved hidden assumptions,
  unredacted secrets, and malformed diagrams.

Acceptance:

- Static-only inputs cannot satisfy runtime claims.
- Scanner hits cannot become verified threats.
- Standards mappings require reference citations.
- Failed/skipped cells produce coverage gaps.

Reviewer focus:

- Validator catches the most tempting overclaims.
- Validation is read-only and fail-closed.

## T09 — Pilot Fixture And Golden Outputs

Owner: implementation agent after T08.

Deliver:

- small fixture system with known actors, PII flows, API routes, deployment config, abuse scenarios,
  and expected STRIDE hypotheses;
- golden integrated model, DFD, attack tree, radar data, and worklist;
- mutation fixtures for missing flow, wrong trust boundary, secret leakage, unsupported runtime
  claim, and overconfident attack tree.

Acceptance:

- Golden fixture passes on Windows and Linux.
- Mutations fail for the intended reason.

Reviewer focus:

- Fixture is small enough to maintain but rich enough to exercise the whole workbench.

## T10 — Lifecycle Integration

Owner: integrator only after T01-T09 and shared pool/persona foundations.

Deliver:

- registry composition;
- output contract binding;
- `03-threat-model-dfd-stride` worker binding;
- parity manifest/job graph updates;
- generated readiness/graph docs;
- live service qualification.

Acceptance:

- `full_review` reaches and blocks/passes `03-threat-model-dfd-stride` honestly.
- Downstream `04-asvs-masvs`, `07-red-team-adversarial`, `12-scoring-prioritization`,
  `13-fuzz-target-triage`, and `15-deployment-hardening` consume accepted workbench output by
  contract.
- No applicable `WORKER_NOT_IMPLEMENTED` status is hidden.

Reviewer focus:

- Integration does not invent missing worker behavior.
- Graph edges distinguish evidence production from verification and synthesis.

