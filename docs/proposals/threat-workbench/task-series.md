# Threat Workbench Task Series

Status: proposal-only task packet for G01/S02. Do not mark `03-threat-model-dfd-stride` implemented
from this document alone. Status tokens follow `TODO.md`: `READY`, `BLOCKED(<ids>)`, `HUMAN_GATE`,
`INTEGRATION`. IDs prefixed `T` are this series; bare IDs are `TODO.md` batches.

## Review Pattern

Use paired implementation/review tasks:

- one agent drafts a bounded artifact or implementation slice on a dedicated branch from
  `origin/main`;
- the other agent reviews for evidence boundaries, schema drift, claim overreach, and integration
  conflicts, and records findings in the PR;
- the original agent applies fixes;
- only the `INTEGRATION` owner touches shared surfaces: `appsec-review-process/job-graph.json`,
  `appsec-review-process/design-parity-manifest.json`, `dagster_workflow.py`, `launch_job.py`,
  `orchestrator/dagster/definitions.py`, common runtime modules, generated parity views, `TODO.md`.

Every task lists its **exclusive paths**. Two tasks never share a path. Every task's acceptance
includes the `TODO.md` minimum: focused tests, `python -B -m py_compile` on changed modules,
`python -B appsec-review-process/validate_design_parity.py`,
`python -B appsec-review-process/qualify_phase1.py --check-contracts`, `git diff --check`, and the
focused suite in the Linux code-server. A batch result states scope included/excluded, files
changed, commands and counts, evidence, limitations, and the next unblocked task. Missing
prerequisites mean `BLOCKED`, not improvised scope.

## Dependency Map

```text
T01 (HUMAN_GATE) ──┬── T02 schemas ──┬── T03 contract + claim class ── T04 registry records
                   │                 │                                   │
                   │                 └── T06 intercom bus ───────────────┤
                   │                                                     │
B14 persona adapter ──────────────────────────────────────────────────── T04
C01 pool schema ── C02 wait_all ── T05 workbench pool/wave runner ───────┤
C03 typed merge ───────────────────────────────────────────── T07 join ──┤
                                                              T08 validator
                                                              T09 fixtures
F03 component-characterization worker ──────────────────────── T10 INTEGRATION
M01 vendor-prepass decision ──(optional sources only)───────── T10
```

## T01 — Approve Threat Workbench ADR — `HUMAN_GATE`

Owner: user, with one Codex and one Claude review pass on the packet.

Deliver: answers to the seven questions in ADR-0008 "Human Gates", recorded in the ADR under a
`Decisions` section with date; ADR status moves to `Accepted` or `Rejected`.

Acceptance: every gate has an answer or an explicit deferral; no runtime or registry implementation
is claimed; `TODO.md` G01 may then be closed by the integrator (not by this task).

Reviewer focus: static/offline boundaries; hypotheses never become findings; enough output for
OWASP/DISA/red-team/verification; the `15-deployment-hardening` cycle hazard stays recorded.

## T02 — Schemas For Integrated Model, Cell Result, Intercom — `BLOCKED(T01)`

Owner: implementation agent A. Reviewer: agent B.

Exclusive paths: `schemas/integrated-threat-model.schema.json`,
`schemas/threat-workbench-cell-result.schema.json`,
`schemas/threat-workbench-intercom-record.schema.json`,
`schemas/threat-workbench-wave-manifest.schema.json`,
`appsec-review-process/tests/fixtures/threat-workbench/schema/**`,
`appsec-review-process/tests/test_threat_workbench_schemas.py`.

Deliver:

- integrated model schema with the record families in ADR-0008 "Canonical Model": elements, flows,
  trust boundaries, data classes, deployment zones, abuse scenarios, attack trees, STRIDE
  hypotheses, assumptions/gaps, coverage, dissent; every record has `id`, `citations[]` (with
  `source_class`, producer, attempt, path, sha256), `evidence_class`, `confidence`;
- closed enums: element kind, data-class category, zone kind, exposure label
  (`DECLARED_EXPOSURE`/`OBSERVED_EXPOSURE`), STRIDE category, `leaf_support`, `evidence_class`,
  `minimum_verification`, intercom `record_type` and `status`;
- `additionalProperties: false` throughout; **no** field that can carry verified status, final
  severity, compliance verdict, intent, or remediation status;
- cell-result schema: cell identity (workcell, instance, wave, persona/model hashes), terminal
  status from the seven-value set, contributed records, intercom record IDs, gaps;
- wave-manifest schema: expected instances, terminal status per instance, output-root hashes;
- golden documents and one mutation per closed enum and per forbidden concept.

Acceptance: goldens validate; every mutation fails naming the offending pointer; a document with
`OBSERVED_EXPOSURE` validates syntactically (so T08 can reject it semantically) and is covered by a
test asserting T08 must reject it.

Reviewer focus: every flow has source, destination, data class, evidence, confidence, boundary
fields; every threat has proof obligations, `minimum_verification` and downstream owner; intercom
records cannot be edited in place (no `updated_at`, only follow-up records).

## T03 — Output Contract And Claim Class — `BLOCKED(T02)`

Owner: agent B. Reviewer: agent A.

Exclusive paths: `appsec-review-process/registry/output-contracts/03-threat-model-dfd-stride.json`,
`appsec-review-process/registry/output-contracts/threat-workbench-cell-result.json`,
`appsec-review-process/tests/test_threat_workbench_contracts.py`.

Deliver:

- lifecycle contract `03-threat-model-dfd-stride`: `result_schema.artifact =
  integrated-threat-model.json`; `required_files` per ADR-0008 "Join And Report";
  `required_status_fields` in the persona/registry style (`process`, `status`, `budget`,
  `persona_id`, `role_id`, `domain_id`, `tooling_profile_id`, `artifacts_read`) plus
  `attempt_id`, `dagster_run_id`; `claim_class.claim_class_id = threat_model_candidates`,
  `allowed_assertions` per ADR, `forbidden_promotions = [finding, severity, runtime-state]`;
  `validation_rules` listing the six prohibitions in prose;
- cell-result contract with `result_schema.artifact = cell-result.json`.

Acceptance: `qualify_phase1.py --check-contracts` passes; the contract validates against
`schemas/output-contract.schema.json` **without** changing that schema; a test asserts the graph
node's `contract` string resolves once the file exists.

Reviewer focus: exactly one result artifact; no shared-surface edits; the three prohibitions the
enum cannot express are named in `validation_rules` and cross-referenced to follow-up F02.

## T04 — Persona, Role, Domain, Tooling-Profile Records And Workcell Compositions — `BLOCKED(T03, B14)`

Owner: agent A. Reviewer: agent B.

Exclusive paths: `appsec-review-process/registry/personas/<13 ids from workcells.proposal.yaml>.json`,
`appsec-review-process/registry/roles/{workcell-selector,dfd-modeler,data-flow-modeler,threat-enumerator,abuse-modeler,attack-modeler,challenger,threat-model-integrator}.json`,
`appsec-review-process/registry/domains/threat-model-graph.json`,
`appsec-review-process/registry/tooling-profiles/threat-model-static-evidence.json`,
`appsec-review-process/registry/workcells/threat-workbench/*.json` (new record type),
`schemas/workcell.schema.json`, `appsec-review-process/03-threat-model-dfd-stride/cells/*.md`
(rendered per-cell prompts), `appsec-review-process/tests/test_threat_workbench_registry.py`.

Deliver:

- persona records conforming to `appsec-review/persona/0.1`, IDs per the T01 naming decision;
- a `workcell` record type (schema + records) that composes persona/role/domain/tooling/contract
  and adds `wave`, `selection`, `intercom_reads`, `intercom_writes`, `proof_obligations`;
- rendered prompts: short, typed, evidence-bound, ending with the cell's `must_not` list and the
  prohibited-claims block B14 requires;
- registry validation: every workcell resolves all five references; every persona has
  `must_not`; the challenger's persona differs from every wave-1/2 persona; no `selection: always`
  cell lists an `m01_gated` source as required.

Acceptance: `job_graph.py`-style resolution succeeds for every workcell; a hostile-prompt fixture
(instructions embedded in a doc-intelligence fact) does not alter any rendered prompt.

Reviewer focus: persona theater (vague roles without proof obligations); claim discipline
(verified/severity/compliance language); selection is trait-driven with recorded omissions.

## T05 — Workbench Wave Runner On Pool Foundations — `BLOCKED(C01, C02, B15, T04)`

Owner: agent B. Reviewer: agent A.

Exclusive paths: `appsec-review-process/threat_workbench_runner.py`,
`appsec-review-process/tests/test_threat_workbench_runner.py`.

Deliver:

- wave expansion from workcell records + selector output into C01 pool instances with
  deterministic instance IDs and private roots under
  `data/jobs/03-threat-model-dfd-stride/whole/attempts/<attempt_id>/cells/<wave>/<instance_id>/`;
- per-wave `wait_all` via C02; the frozen wave manifest (T02 schema) is the only input to the next
  wave;
- budget-class gating of wave 4;
- interrupted/failure/cancel handling mapped to the ADR status table; a `FAILED`/`BLOCKED`
  always-selected cell fails the job; a trait cell failure degrades to `OK_WITH_GAPS`;
- cell concurrency bounded by the B15 persona/LLM pool, never by a local constant.

Acceptance: zero/one/many trait cells; duplicate instance IDs rejected; late finish, timeout,
cancel, crash, restart, duplicate terminal, missing instance; no wave starts before the previous is
fully terminal; no publication occurs before join; reuse honors source, prompt/composition and
model-identity hashes.

Reviewer focus: no early publication; no hidden fallback to an older success after a newer failure;
no cross-instance path access.

## T06 — Intercom Artifact Bus — `BLOCKED(T02)`

Owner: agent A. Reviewer: agent B. (Independent of T05; pure file semantics.)

Exclusive paths: `appsec-review-process/threat_workbench_intercom.py`,
`appsec-review-process/tests/test_threat_workbench_intercom.py`.

Deliver:

- append-only transcript writer with per-record `content_hash` and chained previous-hash;
- readers that project the previous-wave manifest into the record types a cell's
  `intercom_reads` allows, and nothing else;
- authorization checks: a `response` only from the challenged record's author; a `challenge` must
  name a `record_id` and cite counterevidence; the join authors nothing;
- injection quarantine: records whose content matches the `INJECTION_SUSPECTED` heuristics are
  flagged and excluded from the summary projection while remaining in the transcript;
- open-record sweep producing the `unresolved` set for `assumptions-and-gaps.json`.

Acceptance: order independence of readers; tamper detection on any prior record; unauthorized
author rejected; every open record appears exactly once in the unresolved set.

Reviewer focus: durable artifact exchange, not hidden conversation; contradictions preserved.

## T07 — Join, Ranking, Diagram Generation — `BLOCKED(C03, T05, T06)`

Owner: agent B. Reviewer: agent A.

Exclusive paths: `appsec-review-process/threat_workbench_join.py`,
`appsec-review-process/threat_workbench_render.py`,
`appsec-review-process/tests/test_threat_workbench_join.py`,
`appsec-review-process/tests/test_threat_workbench_render.py`.

Deliver:

- `join_controller` worker: C03 typed merge (persona claims, deterministic evidence, coverage
  receipts kept separate), deterministic dedupe key (target ID, STRIDE category, mechanism),
  dissent preservation, completeness invariant, rescope-trigger emission, status mapping;
- `prioritization_score` with visible per-factor breakdown; `OBSERVED_EXPOSURE` factor pinned to
  zero; unresolved-assumption penalty;
- deterministic Mermaid generators for `dfd.mmd` and `attack-trees.mmd` whose node IDs are model
  IDs; regenerate-and-compare check;
- `stride-radar-data.json` with `"purpose": "visualization_input"`;
- `verification-worklist.json` items carrying `minimum_verification`, downstream owner lane, and
  `contested` flag when a challenge is open.

Acceptance: order-independent merge with stable hashes; duplicate IDs and malformed cell results
fail closed; a missing expected instance yields `FAILED`, never an empty merge; every diagram node
traces to a JSON record; no count-only severity anywhere in outputs.

Reviewer focus: Mermaid is derived, never authoritative; radar is labelled; the join never resolves
a disagreement by choosing a side.

## T08 — Threat Workbench Validator — `BLOCKED(T03, T07)`

Owner: agent A. Reviewer: agent B.

Exclusive paths: `appsec-review-process/validate_threat_workbench.py`,
`appsec-review-process/tests/test_validate_threat_workbench.py`.

Deliver: read-only, fail-closed lane validator invoked after the common `validate_job_output.py`:

- projection integrity: every ID in every projection file resolves in the result artifact;
- completeness invariant; `OBSERVED_EXPOSURE` rejected; index-only citation rejected; any
  citation path outside the bundle manifest rejected;
- claim-limit negative checks for all six prohibitions (including the three the contract enum
  cannot express), plus secret-like values in any output;
- coverage: every workcell in `workcell-manifest.json` matches an expected instance from the
  selector; failed/omitted cells produce gap records;
- `.mmd` regenerate-and-compare; radar purpose label; challenger persona/model distinctness.

Acceptance: static-only inputs cannot satisfy runtime claims; scanner hits cannot become verified
threats; standards mappings require reference citations; every T09 mutation fails for its named
reason; the validator never writes to the attempt.

Reviewer focus: catches the most tempting overclaims; read-only and fail-closed.

## T09 — Golden Fixtures And Mutations — `BLOCKED(T08)`

Owner: agent B. Reviewer: agent A.

Exclusive paths: `appsec-review-process/tests/fixtures/threat-workbench/golden/<family>/**`,
`appsec-review-process/tests/fixtures/threat-workbench/mutations/**`,
`appsec-review-process/tests/test_threat_workbench_golden.py`.

Deliver: the seven golden families and eleven mutations from ADR-0008 "Golden and Mutation Fixture
Plan"; each golden pins integrated model, both `.mmd`, radar, ranked scenarios, worklist, and the
expected job status; fixtures are synthetic and contain no real personal data or secrets.

Acceptance: goldens pass on Windows and Linux with byte-identical `.mmd` output; each mutation
fails with exactly its named reason; the smallest golden runs the full wave sequence with
stubbed persona adapters in under the focused-suite budget.

Reviewer focus: small enough to maintain, rich enough to exercise every cell and both wave-4
branches.

## T10 — Lifecycle Integration — `INTEGRATION`, `BLOCKED(T01–T09, F03, B11, B14, B15, C01–C03)`

Owner: integrator only.

Shared surfaces touched: `job-graph.json` (dependencies: keep `01-component-characterization`;
decide whether to declare `02-evidence-assembly` and `02-evidence-index` edges or leave them
transitive; never add `15-deployment-hardening` or `06-cve-reachability`), `design-parity-manifest.json`
(capability `threat-model-standard`, resource pool assignment, qualification record), registry
composition for the lifecycle job, `dagster_workflow.py` binding replacing the `blocked_op`,
generated readiness/graph docs, `TODO.md` G01/S02 status, `docs/design-v3.md` §5.3 L6A placement
note (F03 below).

Acceptance: `full_review` reaches `03-threat-model-dfd-stride` and honestly blocks or passes;
consumers `04-asvs-masvs`, `07-red-team-adversarial`, `10-synthesis-report`,
`12-scoring-prioritization`, `13-fuzz-target-triage` consume accepted output by contract; no
applicable `WORKER_NOT_IMPLEMENTED` status is hidden; live service qualification recorded under a
run's `data/qualification/`.

Reviewer focus: integration does not invent missing worker behavior; graph edges distinguish
evidence production from verification and synthesis; no cycle.

## Follow-ups Outside This Series' Boundary

Recorded here because the review batch could not edit the owning files.

- **F01 — job-graph dependency declaration.** Decide (T10) whether `03`'s bundle sources beyond
  `component-map` become declared edges. Today they are transitive through `01`.
- **F02 — `forbidden_promotions` enum extension.** `schemas/output-contract.schema.json` closes the
  enum to `finding`, `severity`, `runtime-state`. Proposal: add `compliance-status`,
  `malicious-intent`, `remediation-status`. Shared surface; needs its own batch and parity
  validator update. Until then T08 enforces the three semantically.
- **F03 — design-v3 §5.3/§22.8 L6A placement.** The graph runs the threat model after full
  pregather; design-v3 says "immediately after intake". Record the graph as authoritative in
  design-v3 or open a decision to move `03` earlier (which would starve it of intelligence).
- **F04 — persona ID convention across `03/07/08/09`.** `design-v3.md` §5.5 open item; decided at
  T01 gate 4 and applied to the persona-pool proposal.
- **F05 — persona-pool proposal path drift.** `docs/persona-pool-proposal.md` names
  `appsec-review-process/personas/*.yaml`; the registry is `appsec-review-process/registry/*.json`.
- **F06 — M01 vendor-prepass decision.** The four `m01_gated` source families need graph nodes and
  contracts before they can be required inputs anywhere.
- **F07 — ADR numbering coordination.** G01 minted 0008 and G02 minted 0009 on separate branches;
  0005 and 0007 are unused. G03 should claim its number in `TODO.md` before drafting.
- **F08 — OWASP carry-over.** ADR-0009 should adopt the reusable abstractions listed in ADR-0008
  and name its persona file `workcells.proposal.yaml` (already does) with the same
  `workcell_contract` fields.
- **F09 — `component-map` contract file.** The graph declares the contract ID but no file exists;
  it is an F03-batch deliverable and T03's tests should reference it, not create it.
- **F10 — skip reasons.** No workbench skip reason is registered and none is needed while all
  consumer edges declare `allowed_skip_reasons: []`; revisit only if a consumer edge changes.
