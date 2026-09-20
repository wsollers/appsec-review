# OWASP Control Workbench Task Series

Status: G02/S03 task packet. The bounded T02/T02A reference-snapshot foundation and T02B NVD
publisher are implemented; do not mark `04-owasp-validation-worklist` or `04-asvs-masvs`
implemented, registered, runnable,
qualified, or ready from this document alone.

The tasks are dependency ordered. The source-version and repository-root `data/` snapshot policy
portion of T01 was approved on 2026-09-19. On 2026-09-20 the user also approved ASVS L2, justified
assigned-reviewer applicability/rescope overrides, tunable batches with the existing bounded
default, disabled dynamic execution with an inert launcher contract, and stale NVD use with an
explicit gap. T02/T02A now provide initial schemas, a pinned source
lock, immutable raw/normalized snapshots, offline verification, and the separately scheduled NVD
publisher. T03 accepted-intel lane-in and T04 applicability modeling are implemented as standalone
offline foundations. T05–T13 remain dependency ordered and later reporting/promotion work remains
gated by the narrower T01 decisions.

## T01 — Approve OWASP Selection And Policy

Recorded policy decisions:

- ASVS 5.0.0 L2 baseline;
- one assigned applicability reviewer may make justified, cited, append-only row overrides and
  bounded rescope decisions inside the approved engagement scope;
- tunable batch limits with defaults of 12 rows, five components, one primary evidence mode, and
  one primary validator role;
- dynamic request generation and an inert launcher contract are allowed, but dynamic execution is
  disabled and must fail closed;
- a structurally valid stale NVD snapshot may be used with explicit age, gap, and limitation.

Still requires named approval per ADR-0009:

- supported mobile platforms and component applicability for approved context families;
- any departure from L2 and component-specific profile tailoring authority;
- manual-observation authorization;
- the remaining evidence/status policy questions;
- report denominators and finding-promotion boundary.

Approved source set: ASVS 5.0.0, MASVS 2.1.0, MASTG 2.0.0, OWASP Top 10:2025, API
Security Top 10:2023, GenAI LLM Top 10:2026, and a dated OpenCRE export. Do not infer any remaining
profile, applicability, or authorization decision from the repository or model knowledge.

## T02 — Standards Source And Selection Records

Define proposal-derived implementation schemas and fixtures for:

- selection record and named approval;
- ASVS controls and proof obligations;
- MASVS controls;
- MASTG tests and reverse links;
- OWASP Top 10 2025 context categories;
- API Top 10 context categories;
- GenAI LLM Top 10 2026 context categories;
- OpenCRE mappings.

Reject records without source/version or immutable ref/hash/license/extraction metadata. Pin test
catalogs and crosswalks independently. Test version conflicts, retired controls, successor mappings,
duplicate IDs, changed licenses, missing control text, and offline reuse.

## T02A — Materialize Immutable Standards And OpenCRE Snapshots — IMPLEMENTED FOUNDATION

After an implementation task is explicitly authorized, populate repository-root `data/reference/`
with immutable source snapshots and manifests for the approved source set. Each snapshot must retain
raw material, normalized records, license/usage text, resolved tag/commit, retrieval time, hashes,
extractor identity, raw-to-normalized lineage, counts, and validation results.

OpenCRE has no release tag. Capture a dated public export, its exact raw/normalized hashes, API/export
format, and the approved exporter/source commit. Never use a moving OpenCRE API response directly in
an engagement. A source update creates a sibling snapshot; do not rewrite an existing snapshot.

Implemented under `data/reference/` with `source-lock.json`, raw/normalized content, manifests,
license text, and `appsec-review-process/reference_snapshots.py`. Offline verification checks schema,
hashes, counts, identities, and normalized records. Focused tests cover the committed population,
tampering, source-lock validation, and selection approval fields. Run pinning and newer-snapshot
selection remain part of T03/lifecycle integration.

## T02B — Asynchronous NVD 2.0 Snapshot Publisher — IMPLEMENTED FOUNDATION

The authorized runtime task created a separately network-enabled publisher under
`data/feeds/nvd/`:

- bootstrap from official JSON 2.0 yearly feeds;
- refresh from official recent/modified feed or bounded API 2.0 modification windows;
- run asynchronously on a proposed two-hour default schedule;
- use a scheduler singleton key and exclusive lease/heartbeat writer lock;
- write to attempt staging, validate completely, publish an immutable snapshot, then atomically
  advance `current.json` while holding the lock;
- keep the prior pointer on failure while preserving the failed newer attempt;
- pin one validated NVD snapshot into each engagement at run start;
- keep API keys in the secret provider, never beneath `data/`.

Test concurrent writers, bounded wait, timeout, worker loss, heartbeat/lease expiry, coordinator-only
stale-lock recovery, cursor gaps, partial downloads, decompression/schema/hash/count failures, atomic
pointer publication, newer failed attempts, stale-snapshot policy, and run immutability while a new
snapshot publishes. NVD output is enrichment, not affected-version, reachability, exploitability,
severity, or finding proof.

Implemented by `appsec-review-process/nvd_feed.py` and the `nvd_reference_sync` Dagster job. Focused
tests cover base/delta publication, schema and chain verification, last-good preservation after a
failed refresh, blob tamper rejection, and fresh-lease non-stealing. Engagement snapshot pinning and
the approved freshness/block policy remain lifecycle work rather than feed-publisher behavior.

## T03 — Accepted Intel Lane-In — IMPLEMENTED FOUNDATION

Define the input manifest that separates raw evidence from derived intelligence and records:

- accepted run-owned pointer or explicit import identity;
- producer job/attempt and source artifact hashes;
- source snapshot, freshness, redaction state, and caveats;
- permissions for static, dynamic, and manual work;
- source/artifact completeness gaps.

Reject stale indexes, unexplained derived facts, implicit legacy scratch discovery, and missing
lineage. Prove search hits are dereferenced before supporting a status.

Implemented by `appsec-review-process/owasp_lane_in.py` and the four `owasp-*lane-in/input*`
schemas documented in `schemas/README.md`. The worker:

- consumes an explicit `runs/<run_id>/inputs/owasp-lane-in-request.json`;
- verifies ASVS L2 selection and embeds exact approved selection/reference manifests;
- accepts only hash-checked import receipts or accepted producer attempts and rechecks them before
  publishing an immutable attempt;
- keeps derived intelligence and indexes locator-only, rejecting stale indexes and unexplained
  derivations;
- pins and verifies an optional NVD manifest/blob chain, recording stale age as a non-blocking gap;
- rejects dynamic execution, manual observation, network, and target-mutation permissions;
- publishes `owasp-input-manifest.json` and `input-gaps.json` beneath the run-owned job attempt.

CLI foundation:

```text
python -B appsec-review-process/owasp_lane_in.py --run-id <run_id>
```

This is not a registered graph job and does not make `04-owasp-validation-worklist` or
`04-asvs-masvs` runnable. T04 applicability modeling consumes this accepted manifest.

## T04 — Applicability Model — IMPLEMENTED FOUNDATION

Define `owasp-applicability-model.json` with one row per selected control/component target:

- `applicable`, `conditional`, `not_applicable`, `cannot_determine`, or `out_of_scope`;
- deterministic signals, reviewer decision, citations, and source completeness;
- profile/scope override history and authority;
- classification dependencies and rescope state.

Prove `not_applicable` cannot be derived from a single absence signal, `out_of_scope` is not
technical N/A, and ambiguous cases remain visible gaps.

Implemented by `appsec-review-process/owasp_applicability.py` and the closed T04 applicability
schemas documented in `schemas/README.md`. The worker:

- consumes an explicit `runs/<run_id>/inputs/owasp-applicability-request.json` and verifies the
  accepted T03 pointer, manifest, and selected reference snapshots again before publication;
- enumerates the full selected-control by component matrix itself, so a caller cannot silently
  omit a target;
- applies deterministic exact-control, domain, then all-controls rules; equal-specificity conflicts
  become `cannot_determine` gaps rather than an inferred decision;
- requires cited positive presence for `applicable`, an explicit unresolved expression for
  `conditional`, and cited positive exclusion plus adequate canonical evidence for technical
  `not_applicable`;
- reserves `out_of_scope` for the T03 selection approver's component-scope authority and never
  treats it as technical N/A;
- permits only the assigned applicability reviewer to add justified, cited, append-only overrides,
  with prior-status continuity and bounded rescope actions for invalidated decisions;
- publishes the complete model, applicable-control projection, visible gaps, and exact override
  chain as one immutable attempt, while making no control-satisfaction, finding, severity,
  exploitability, certification, or runtime claim.

CLI foundation:

```text
python -B appsec-review-process/owasp_applicability.py --run-id <run_id>
```

This is not a registered graph job and does not dispatch validators or launch dynamic work. T05
control partitioning and deterministic batching is next.

## T05 — Control Partitioning And Batch Worklist

Define `owasp-validation-worklist.json` and `owasp-batch-manifest.json`:

- atomic identity is selection/family/version/profile/control/component;
- batch in order by coherent component group, domain, evidence mode/authorization, tool/persona,
  and standard/test family;
- default maximum is 12 control-target rows, five components, one primary evidence mode,
  and one primary validator role;
- limits are tunable only through versioned configuration and qualification fixtures, and each
  batch records its effective limits;
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

Retain a launcher/handoff boundary, but configure it `disabled`: it may validate, deduplicate, and
persist queue artifacts only. An execute/launch request emits `dynamic_execution_disabled` and
must not contact or mutate a target. Enabling execution is a separate future policy,
implementation, and qualification task.

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

Integrator-only after T01–T13 (including T02A/T02B where required) are approved and qualified:

- registry/persona/role/domain/tooling/output-contract composition;
- standards source ingestion and schema binding;
- common worker lifecycle and intercom binding;
- graph/parity manifest updates and generated views;
- host/Linux contract tests and live service qualification.

This task is expressly outside the current documentation-only branch.
