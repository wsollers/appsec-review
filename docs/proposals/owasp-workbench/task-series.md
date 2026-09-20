# OWASP Control Workbench Task Series

Status: Proposal-only task packet for G02/S03. Do not mark `04-owasp-validation-worklist` or
`04-asvs-masvs` implemented, registered, runnable, qualified, or ready from this document alone.

The tasks are dependency ordered. T01 is a human gate; T02–T13 remain blocked until its relevant
decisions are approved. Implementation work is outside this documentation-only task.

## T01 — Approve OWASP Selection And Policy

Review `docs/decisions/ADR-0009-owasp-control-workbench.md` and record named approval for:

- exact ASVS edition and target level/profile, including component tailoring authority;
- exact MASVS and MASTG refs and platform compatibility;
- exact API Top 10 edition and its context-only role;
- exact optional LLM/agent guidance source/ref and applicability threshold;
- exact OpenCRE snapshot and context/deduplication-only role;
- source storage and license policy;
- applicability override authority and bounded rescope policy;
- evidence/status taxonomy and proposed batch limits;
- dynamic/manual test authorization authority;
- report denominators and finding-promotion boundary.

Do not infer any unanswered selection from `docs/design-v3.md`, the current registry, or model
knowledge. The ASVS 5.0.0 mention is a recommendation requiring approval.

## T02 — Standards Source And Selection Records

Define proposal-derived implementation schemas and fixtures for:

- selection record and named approval;
- ASVS controls and proof obligations;
- MASVS controls;
- MASTG tests and reverse links;
- API Top 10 context categories;
- optional LLM/agent guidance;
- OpenCRE mappings.

Reject records without source/version or immutable ref/hash/license/extraction metadata. Pin test
catalogs and crosswalks independently. Test version conflicts, retired controls, successor mappings,
duplicate IDs, changed licenses, missing control text, and offline reuse.

## T03 — Accepted Intel Lane-In

Define the input manifest that separates raw evidence from derived intelligence and records:

- accepted run-owned pointer or explicit import identity;
- producer job/attempt and source artifact hashes;
- source snapshot, freshness, redaction state, and caveats;
- permissions for static, dynamic, and manual work;
- source/artifact completeness gaps.

Reject stale indexes, unexplained derived facts, implicit legacy scratch discovery, and missing
lineage. Prove search hits are dereferenced before supporting a status.

## T04 — Applicability Model

Define `owasp-applicability-model.json` with one row per selected control/component target:

- `applicable`, `conditional`, `not_applicable`, `cannot_determine`, or `out_of_scope`;
- deterministic signals, reviewer decision, citations, and source completeness;
- profile/scope override history and authority;
- classification dependencies and rescope state.

Prove `not_applicable` cannot be derived from a single absence signal, `out_of_scope` is not
technical N/A, and ambiguous cases remain visible gaps.

## T05 — Control Partitioning And Batch Worklist

Define `owasp-validation-worklist.json` and `owasp-batch-manifest.json`:

- atomic identity is selection/family/version/profile/control/component;
- batch in order by coherent component group, domain, evidence mode/authorization, tool/persona,
  and standard/test family;
- proposed default maximum is 12 control-target rows, five components, one primary evidence mode,
  and one primary validator role;
- split composite controls into clause-level proof obligations when evidence modes differ;
- assign every selected row exactly once or account for it as N/A, out of scope, or unresolved.

Test deterministic IDs/order, boundary sizes, unrelated-domain separation, and the no-silent-skip
invariant.

## T06 — Validator Handoff And Tool Contract

Define a handoff containing selection/batch/control/component identity, proof obligations, evidence
roots, accepted inputs, tool permissions, prohibited claims, output paths, budget, timeout, and
terminal/failure semantics.

Baseline tools are read-only retrieval and inspection plus explicitly declared bounded parsing or
static analysis. Network requests, device/emulator execution, DAST, fuzzing, instrumentation, live
cloud/runtime access, and target mutation require separate authorization and are not performed by
the baseline workbench.

Test prompt-injected standard/target/intel text, undeclared tool requests, secret-bearing output,
stale source, and attempts to widen authorization.

## T07 — Validator Output And Evidence Sufficiency

Define `control-assessment-result.json` with one result per assigned control target:

- clause/proof-obligation outcomes;
- `satisfied`, `partially_satisfied`, `not_satisfied`, `cannot_verify`,
  `dynamic_test_required`, `human_decision_required`, or `not_assessed`;
- canonical citations, counterevidence, evidence modes, freshness, covered scope, and limitations;
- candidate dynamic/manual requests and candidate verification routes;
- validator/tool/batch/attempt provenance and dissent.

Reject verified findings, severity, exploitability, compliance/certification, remediation status,
or runtime claims unsupported by matching dynamic evidence. Missing evidence cannot become
`not_satisfied`; documentation proves only intent except for document/process controls.

## T08 — Structured Intercom

Define append-only workcell communication artifacts for evidence locators, applicability or
component-classification challenges, assistance request/response, duplicate/crosswalk notices,
dissent, and dynamic-test candidates.

Messages must identify sender/recipient, selection/batch/control/component, claim class, canonical
citations, requested action, response link, time, and producer. Prove messages cannot directly alter
selection, applicability, or status; recipients must issue their own cited result. Reject uncited
free-form conclusions, raw secrets, and circular message chains presented as corroboration.

## T09 — Dynamic And Manual Test Requests

Define `owasp-dynamic-test-requests.json` with:

- linked control/component/proof obligation;
- static insufficiency reason;
- test type, target environment, prerequisites, identities, and data;
- least-privilege authorization and safety constraints;
- observations and pass/fail/inconclusive criteria;
- capture/redaction requirements, owner, and reassessment/re-verification path;
- lifecycle state: proposed, authorized, executed, ingested, reassessed, canceled, or blocked.

Deduplicate compatible requests without losing linked controls. Prove static results cannot close a
dynamic obligation and proposed requests cannot imply authorization or execution.

## T10 — Dispatch, Wait-All, And Failure Accounting

After persona/pool foundations exist, dispatch bounded validator cells and require every expected
cell to reach terminal state before join. Preserve failed, canceled, timed-out, skipped, invalid,
and degraded cells. Applicable rows without a valid result become `not_assessed`.

Test partial pool failure, timeout, cancellation, invalid output, worker loss, newer failed attempt,
no fallback to an older result, and recovery/reuse only where the common lifecycle permits it.

## T11 — Deterministic Join And Reporting

Join without status upgrade into:

- `owasp-control-status-matrix.json`;
- `owasp-coverage-gaps.json`;
- `owasp-dynamic-test-requests.json`;
- `owasp-workbench-summary.md`.

The matrix must retain selection, applicability, assessment, proof obligations, evidence,
counterevidence, validator/tool/batch/attempt/intercom provenance, gaps, test requests, dissent,
crosswalk grouping, and rescope state.

The summary must report standards/profile approvals, scope/evidence cutoff/permissions, population
and batches, applicability and overrides, exact statuses, gaps and contradictions, dynamic/manual
backlog, failed/degraded cells, unassessed rows, dissent/rescope/limitations, candidate verification
routes, and artifact pointers. Report selected, applicable, assessed, and satisfied denominators
separately. Never report certification or inferred runtime behavior.

## T12 — Finding-Promotion And Crosswalk Deduplication

Route a failed/partial control to the claim lifecycle only when cited evidence supports a concrete
mechanism or impact hypothesis. Require independent verification and later scoring. Crosswalks may
deduplicate or route; they cannot provide proof, exploitability, impact, or severity.

Test one underlying gap mapped to several standards, conflicting crosswalk versions, candidate route
deduplication, and rejected promotion of a bare checklist failure.

## T13 — Golden And Mutation Fixtures

Create small approved fixtures covering:

- ASVS positive, negative, partial, N/A, cannot-determine, and out-of-scope cases;
- mobile MASVS/MASTG static, built-artifact, dynamic-required, and manual-required controls;
- API Top 10 context that does not substitute for control evidence;
- LLM/agent guidance both applicable and inapplicable;
- documentation-only intent, mocked test, passing test with mismatched environment, and scanner-only
  lead;
- missing/stale citation, contradictory evidence, dynamic evidence removed, incomplete source, and
  component reclassification/rescope;
- failed validator cell yielding `not_assessed`;
- intercom locator, challenge, assistance, dissent, and invalid self-corroboration;
- crosswalk deduplication without finding duplication;
- report denominator accounting and forbidden compliance/runtime/finding claims.

Mutations must prove no selected control is silently skipped, no status is improved by the join,
and removing required evidence lowers or invalidates the result.

## T14 — Lifecycle Integration

Integrator-only after T01–T13 are approved and qualified:

- registry/persona/role/domain/tooling/output-contract composition;
- standards source ingestion and schema binding;
- common worker lifecycle and intercom binding;
- graph/parity manifest updates and generated views;
- host/Linux contract tests and live service qualification.

This task is expressly outside the current documentation-only branch.
