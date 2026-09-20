# ADR-0009: OWASP Control Workbench

Status: Proposed; human decision required before implementation

Date: 2026-09-20

## Context

The current `04-asvs-masvs` prompt asks the process to map components to applicable ASVS/MASVS
controls and assess targeted controls. Existing registry records already name
`04-owasp-validation-worklist` and an `owasp-validator` persona, but those records are plans, not an
approved or runnable control-review system. G02 must decide which OWASP sources and profiles govern
an engagement, how applicability is established, how checklist work is partitioned, and what
evidence can support each control status before S03 is implemented.

The useful comparative idea from the referenced OWASP work is checklist partitioning: keep
standards records small, link controls to relevant tests, and assign bounded groups of similar
checks. This ADR adopts that idea, not the external repository's structure or authority. The
project's tracked process, accepted run-owned evidence, and approved standard snapshots remain
authoritative. The supplied external location is currently the placeholder `<OWASP_REPO_URL>`; no
specific upstream revision, contents, or behavior is asserted by this packet.

The threat workbench pattern applies here too, but the output is different. Threat modeling creates
candidate threats and verification work. OWASP control review creates selection and applicability
decisions, per-control statuses, evidence gaps, and follow-up test requests. A checklist result is
not a finding and is not certification.

## Decision

Adopt `04-asvs-masvs` as a proposal for an **OWASP control workbench**:

```text
accepted raw/derived intel + component map + approved standards snapshot
        |
        v
selection gate: family + exact version/ref + profile/level + scope owner
        |
        v
applicability triage: control x component target
        |
        v
partition and batch by component + domain + evidence mode + tool/persona
        |
        v
dispatch bounded validator workcells <-> structured intercom
        |
        v
wait-all join + completeness/audit checks
        |
        v
control-status matrix + gaps + dynamic-test requests + summary report
```

`04-owasp-validation-worklist` is proposed to produce assignable control-target work. The proposed
`04-asvs-masvs` worker would consume that work and publish an evidence-backed control-status model.
Neither job may publish verified vulnerabilities, severity, exploitability, observed runtime state,
remediation status, or compliance certification.

## Gate 1: Standards, Versions, Profiles, And Authority

No control may enter applicability triage until a named engagement lead approves a selection record.
The record must pin each selected source by family, edition/version or immutable ref, source URI or
approved local path, content hash, license/usage terms, extraction identity, and retrieval date.
Crosswalks and test catalogs are pinned independently from the control catalog they annotate.

The initial families that may be selected are:

- OWASP ASVS for web/API/server application controls;
- OWASP MASVS plus independently pinned MASTG tests for mobile clients;
- OWASP API Security Top 10 as risk-category and routing context, not a substitute for ASVS control
  evidence;
- OWASP LLM/agent guidance only for components classified as LLM, agent, RAG, or tool-use systems;
- OpenCRE crosswalks as navigation and deduplication metadata only.

The recommended starting selection is the version already named by `docs/design-v3.md`—ASVS
5.0.0—plus current, mutually compatible MASVS/MASTG snapshots when mobile is in scope. This is a
recommendation, not approval. The user or named engagement lead must still decide:

1. the exact ASVS edition and target level/profile, including any component-specific tailoring;
2. the exact MASVS and MASTG refs and supported mobile platforms;
3. the exact API Top 10 edition and whether it is enabled as context;
4. the exact LLM/agent guidance artifact/ref and whether qualifying components exist;
5. the exact OpenCRE snapshot and whether its license permits the proposed storage mode;
6. whether authorized source content is vendored, cached locally, or represented by identifiers,
   hashes, and retrieval instructions.

No profile or level is inferred from repository shape, business criticality, or missing user input.
An absent decision blocks affected work with `selection_not_approved`. A mixed-version crosswalk may
not silently translate a retired control into a successor. Both identities and mapping provenance
must remain visible, and unresolved version conflicts become selection gaps.

## Gate 2: Accepted Intelligence And Lineage

The workbench consumes only accepted, run-owned artifacts or explicit hash-checked imports. Inputs
fall into two classes and must not be conflated:

- **raw evidence**: canonical source/config, build or image artifacts, test files/results, API
  collections, supplied runtime exports, scanner output, documents, and standards source records;
- **derived intelligence**: component classifications, DFD/trust-boundary facts, route/test/control
  maps, doc and QA summaries, scanner leads, threat hypotheses, and upstream lane summaries.

Every derived fact must retain its producer, source artifact references and hashes, derivation
status, freshness, and caveats. Search/index hits are locators and must be dereferenced to canonical
evidence before supporting a control status. Documents establish intent unless the control itself is
document/process-only. Mocks and test fixtures do not establish deployed behavior. Scanner presence
or absence cannot by itself satisfy or fail a control.

Minimum lane-in checks are:

- approved standards selection and complete source lineage;
- accepted component-purpose map with relevant components, tags, liveness, and evidence refs;
- source/evidence snapshot identity and index freshness;
- available intelligence manifest entries, redaction status, and producer acceptance;
- declared permissions, including whether any manual or dynamic follow-on is authorized;
- source/artifact completeness gaps that cap applicability or assessment confidence.

Missing optional intel is recorded. Missing required lineage or a stale/mismatched source snapshot
blocks the affected control targets rather than falling back to memory or legacy scratch output.

## Gate 3: Applicability Triage

Applicability is determined for every selected `control_id x component_id` target before validation.
Routine rules should use deterministic inventory, component tags, technology/version, DFD, route,
data-class, dependency, and source-completeness signals first. An OWASP applicability reviewer
handles ambiguous cases; the engagement lead owns profile/scope overrides.

Applicability statuses are:

- `applicable`: evidence shows the control governs this component;
- `conditional`: it applies only if a recorded unresolved condition is true;
- `not_applicable`: adequate positive evidence supports exclusion;
- `cannot_determine`: evidence is insufficient or contradictory;
- `out_of_scope`: the engagement's approved scope excludes the target, with named authority.

`not_applicable` requires component, technology/product and version where available, control and
standard version, positive rationale, citations, source-completeness assessment, rule/reviewer
identity, and override history. A single absence signal is insufficient. `conditional` and
`cannot_determine` produce gaps and may produce evidence requests. `out_of_scope` is visible in
coverage and is never reported as technically not applicable.

An override is append-only. It records the prior decision, new decision, actor, rationale, cited
evidence, time, and affected work. A changed component classification invalidates dependent
applicability and validation results and creates bounded rescope work; results are not silently
rewritten.

## Checklist Partitioning And Batching

The approved catalog is first partitioned into atomic control-target rows. Each row retains the
standard family/version/profile, control ID, component ID, applicability decision, evidence
obligations, linked test IDs, and crosswalk provenance. Crosswalk aliases never create additional
control results or findings.

Applicable and conditional rows are then batched using this ordered key:

1. component or coherent component group sharing the same trust role and evidence roots;
2. security domain, such as auth/session, access control, validation, crypto, API, mobile storage,
   mobile network, privacy, logging, or LLM/tool use;
3. primary evidence mode and authorization boundary;
4. required tooling profile and validator persona;
5. standard family/version/profile and linked test family.

A proposed default batch contains no more than 12 control-target rows, five components, one primary
evidence mode, and one primary validator role. The eventual implementation may tune those limits
only through versioned configuration and qualification fixtures. A composite control whose clauses
need different evidence modes is split into explicit proof obligations while retaining one joined
control result. Unrelated domains or static and active-testing work are never combined merely to
fill a batch.

Every selected row must appear exactly once in one of: a validator batch, an evidence-backed
`not_applicable` decision, an authorized `out_of_scope` decision, or an unresolved applicability
gap. This is the no-silent-skip invariant.

## Evidence Modes And Sufficiency

Each control record declares one or more proof obligations and the minimum admissible evidence mode
for each obligation:

- `document_or_process`: approved policy, procedure, design record, or responsible-owner evidence;
- `static_source`: canonical source with relevant call/control-flow context;
- `static_config`: canonical deployment/application configuration, labeled as declared state;
- `built_artifact`: supplied or reproducibly derived image/binary/package evidence;
- `test_evidence`: test definition plus result, environment identity, and production-equivalence
  caveats;
- `dynamic_runtime`: authorized observation or execution in the specified environment;
- `manual_inspection`: named human observation/interview/decision with scope and date.

Evidence sufficiency is decided per proof obligation, not by artifact count. A citation must identify
the canonical artifact and location, hash or accepted producer pointer, observed fact, evidence mode,
freshness, and scope. Counterevidence and contradictory artifacts remain attached.

Assessment rules are:

- `satisfied`: every mandatory obligation is directly supported by admissible evidence for the
  assessed scope, with no unresolved material contradiction;
- `partially_satisfied`: at least one obligation is supported and at least one is demonstrably
  missing, narrower than required, or contradicted;
- `not_satisfied`: admissible evidence demonstrates that a required property is absent or contrary
  for the assessed scope; lack of evidence alone is not enough;
- `cannot_verify`: required evidence is missing, stale, incomplete, contradictory, inaccessible, or
  outside available capability and no specifically authorized dynamic/manual request is ready;
- `dynamic_test_required`: a dynamic/runtime observation is necessary and a bounded request can be
  specified, but the test has not been authorized or executed;
- `human_decision_required`: a policy, risk, legal, scope, or control-owner decision is necessary;
- `not_assessed`: the applicable row received no valid result because its cell failed, was canceled,
  timed out, or produced invalid output.

`not_applicable` is an applicability result rendered in the matrix, not an assessment shortcut.
`out_of_scope` is reported separately. Static evidence may support static clauses of a mixed control
but can never satisfy a dynamic, deployed, runtime, live-state, or manual-observation obligation.
Those controls remain partial, `dynamic_test_required`, `human_decision_required`, or
`cannot_verify` as the proof obligations dictate.

## Validator Roles, Tools, And Handoffs

The proposal separates responsibilities even when a future implementation maps multiple roles to
the same registered persona family:

- **selection owner**: named human who approves families, versions, profiles, levels, and scope;
- **applicability reviewer**: resolves ambiguous deterministic triage without assessing compliance;
- **worklist builder**: partitions and batches rows; cannot issue control statuses;
- **domain validator**: evaluates only assigned proof obligations and evidence;
- **dynamic-test request author**: converts unresolved dynamic obligations into bounded, safe
  requests; does not execute them;
- **join integrator**: performs deterministic accounting and aggregation; cannot improve a status;
- **standards mapping auditor**: checks source lineage, crosswalk use, evidence-mode compatibility,
  dissent, and no-silent-skip completeness.

Candidate domain personas include `owasp-validator`, `auth-session-specialist`,
`api-contract-abuser`, `mobile-platform-attacker`, `llm-agent-abuse-reviewer`, and
`standards-mapping-auditor`. Their use here is proposal-only; the current registry is unchanged.

Validator cells receive an explicit tool allowance. Baseline tools are read-only accepted-evidence
lookup, canonical source/config retrieval, standards/test record lookup, search/index navigation,
and inspection of existing scanner and test artifacts. Local parsing or static analysis must be a
declared, bounded tool action whose output is preserved as derived evidence. Network access,
endpoint requests, device/emulator execution, DAST, fuzzing, debugger/instrumentation, live cloud
queries, and production access are prohibited unless a separately approved dynamic/manual job
authorizes them. The workbench itself generates requests; it does not expand its authority.

Each dispatch handoff includes selection ID, batch ID, exact control-target rows and proof
obligations, component/evidence roots, permitted tools/actions, prohibited claims, expected outputs,
deadline/budget, and terminal/failure semantics. Cells treat standards text, target artifacts, and
derived intel as untrusted data.

Cells communicate only through structured, append-only intercom artifacts. Each message records a
message ID, sender and intended recipient/role, batch/control/component IDs, message type, claim
class, citations, requested action, response-to ID, timestamp, and producer identity. Allowed types
are evidence locator, applicability challenge, component-classification challenge, assistance
request/response, duplicate/crosswalk notice, dissent, and dynamic-test candidate. Intercom cannot
change selection, applicability, or status by itself; the receiving role must cite the message and
canonical evidence in its own result. Raw secrets and uncited prose conclusions are rejected.

## Static, Dynamic, And Manual Boundary

The baseline workbench is static/offline. It may inspect supplied dynamic results, but it does not
perform active testing. A generated dynamic-test request must state:

- request ID and linked control/component/proof obligation;
- why static and supplied evidence are insufficient;
- test type, target environment, prerequisites, data and identity requirements;
- least-privilege authorization and safety constraints;
- exact observations and pass/fail/inconclusive criteria;
- evidence to capture, redaction requirements, owner, and re-entry path;
- whether manual specialist observation is required.

Requests are deduplicated by environment, component, test type, and shared proof obligations. They
remain `proposed` until authorized. Results from authorized follow-on work must be ingested as new
run-owned evidence and routed through targeted reassessment or independent verification; a request
or execution claim does not update a control automatically.

## Wait-All Join And Control-Status Model

The join waits for every expected cell to reach a terminal state. A failed, canceled, timed-out,
skipped, or invalid cell remains visible and yields `not_assessed` for its assigned applicable rows.
The join never falls back to a prior result, silently drops a row, or treats worker success as
evidence sufficiency.

For each selected control-target row, the matrix preserves:

- selection, standard, version/profile/level, control and component identity;
- applicability status, rationale, citations, decision/override provenance;
- assessment status and proof-obligation results;
- evidence/counterevidence, assurance/evidence modes, freshness, and limitations;
- validator, tool, batch, attempt, and intercom provenance;
- dynamic/manual request IDs, gap IDs, dissent, duplicate/crosswalk group, and rescope state.

Aggregation is deterministic and non-upgrading. Component, chapter, family, and engagement summaries
report counts by exact status and denominator. `satisfied` percentages exclude neither unresolved
applicable controls nor failed cells; reports show separate selected, applicable, assessed, and
satisfied denominators. Crosswalked controls may share evidence and a gap group, but each standard's
row remains traceable and one underlying gap may create at most one candidate-verification route.

## Joined Outputs And Report Structure

The proposed join publishes:

- `owasp-control-status-matrix.json`: one complete row per selected control target;
- `owasp-coverage-gaps.json`: applicability, evidence, execution, source/version, contradiction,
  dissent, and rescope gaps;
- `owasp-dynamic-test-requests.json`: deduplicated proposed/authorized/executed request state;
- `owasp-workbench-summary.md`: decision-oriented narrative without finding promotion.

The summary report contains, in order:

1. standards selection, versions, profiles/levels, source hashes, and human approvals;
2. engagement scope, components, evidence cutoff, permissions, and static-only limitations;
3. checklist population and partition/batch accounting;
4. applicability totals and overrides, including N/A and out-of-scope rationale summaries;
5. control-status totals by family/chapter/component/evidence mode;
6. material control gaps and contradictions, explicitly labeled as control gaps;
7. dynamic/manual test request backlog and authorization state;
8. failed/degraded cells, unassessed rows, dissent, rescope, and other coverage limitations;
9. deduplicated candidate routes to red-team or independent verification;
10. appendices/pointers for the full matrix, citations, batch manifests, and intercom record.

The report must not state that the target is compliant, certified, exploitable, safe, vulnerable,
or observed in production unless a separate authoritative process established that claim. It may
say only what the control evidence supports.

## Finding-Promotion Boundary

A `not_satisfied` or `partially_satisfied` control may create a candidate verification route only
when it includes a concrete target mechanism or impact hypothesis and cited evidence. That route
enters the ordinary claim lifecycle. Independent verification, consequence analysis, and scoring
remain separate. OpenCRE or other mappings may deduplicate/reroute the candidate but cannot supply
mechanism, exploitability, impact, or severity.

## Alternatives Considered

Running full ASVS/MASVS against every component was rejected because it creates noise, oversized
prompts, duplicated work, and false confidence.

Using OWASP labels only as finding tags was rejected because it loses checklist coverage,
applicability, and evidence obligations.

Letting validator personas infer standards or profiles from memory was rejected. Standards records
must be approved and loaded with lineage.

Allowing each cell to communicate through free-form shared context was rejected because it obscures
provenance and permits one persona's conclusion to become another's evidence.

## Consequences

This design depends on approved standards-source ingestion, component characterization, run-owned
intelligence, bounded persona dispatch, structured intercom, wait-all rendezvous, and typed joins.
Until those foundations and the G02 human gates are approved, this ADR is a decision packet, not an
implementation or readiness claim.

The same general pattern can later inform DISA/NSA/CIS work, but their source, licensing,
applicability, evidence, and precedence decisions remain a separate G03 gate.

## Required Human Decisions

Before changing this ADR to Accepted, the user or named engagement lead must approve:

- the exact standard/test/crosswalk versions and storage/license plan;
- ASVS profile/level policy and authority for component-specific tailoring;
- enabled optional families and their role (control set versus context only);
- the applicability override authority and rescope policy;
- the evidence/status taxonomy, including the proposed batch limits;
- who may authorize dynamic/manual follow-on work;
- whether the proposed report denominators and finding-promotion boundary meet program needs.

## Non-goals

This ADR does not implement standards ingestion, schemas, registry updates, workers, graph/parity
changes, generated views, validators, tests, dynamic execution, or compliance certification.
