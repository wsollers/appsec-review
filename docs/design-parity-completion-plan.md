# Mythos design-parity completion plan

Status: active implementation backlog. This plan closes the gap between the architecture described
in `docs/design-v3.md` and the executable, run-owned Dagster process. A registry record, prompt,
diagram, or graph edge is not implementation. Parity requires an executable worker, a validated
output contract, recovery behavior, and service-level qualification.

## Current baseline

- The versioned parity source of truth is
  `appsec-review-process/design-parity-manifest.json` (`appsec-review/design-parity-manifest/1.0`).
  `validate_design_parity.py` reconciles it against the graph, registry, Dagster definitions,
  launcher, sensors, entrypoints, contracts, schemas, queue limits, pools, and qualification
  references. The deterministic human view is `docs/design-parity-report.md`; the lifecycle graph
  and operator table are generated as `docs/full-review-workflow.mmd` and
  `docs/design-parity-readiness.md` and are rejected when stale.
- The lifecycle graph declares 51 jobs. Only `00-intake`, `02-ossf-scorecard`, and
  `02-evidence-index` are currently marked implemented in `job-graph.json`.
- Several useful standalone Dagster jobs exist, but standalone registration does not prove that
  their corresponding lifecycle node is reachable through `full_review`.
- Planned lifecycle nodes deliberately fail with `WORKER_NOT_IMPLEMENTED`; the two discovery gates
  accept validated out-of-band work but do not dispatch analysis.
- Dagster queue limits and failure/cancellation reconciliation are implemented. Dedicated resource
  pools, persona/tool fan-out, wait-all rendezvous, quorum evaluation, and review feedback loops are
  not.

## Definition of design parity

Design parity is achieved only when all of the following are true:

1. Every enabled lifecycle node resolves a registered persona, role, domain, tooling profile,
   output contract, worker implementation, validator, and recovery policy.
2. Every applicable node is reachable through `full_review`; an inapplicable node publishes a
   contract-valid, evidence-backed skip rather than disappearing.
3. Deterministic tools and persona workers use the same run-owned attempt and acceptance envelope.
4. Pool jobs launch isolated worker instances, wait for all terminal states, merge by worker kind,
   and record degraded coverage without silently dropping failures.
5. Candidate claims flow through refutation and independent verification before promotion.
6. Rescope, remediation/retest, completeness, and resynthesis loops are bounded, durable, and
   auditable.
7. Standards work uses pinned, licensed source material and per-control evidence; a checklist miss
   is not automatically a vulnerability.
8. A clean end-to-end qualification has no `WORKER_NOT_IMPLEMENTED` result for an applicable job
   and leaves enough evidence to reproduce every acceptance decision.

## Workstream A: parity inventory and executable contracts

- [x] Create a machine-readable parity manifest mapping each design capability to lifecycle job,
  registry composition, worker, validator, schema, prompt, tool/image identity, permission set,
  resource pool, and qualification case.
- [x] Add a validator that fails when a graph node is described as implemented without all required
  executable and validation references, or when a standalone job has no declared lifecycle
  relationship.
- [x] Reconcile the design document, `job-graph.json`, Dagster definitions, launcher choices,
  diagrams, readiness tables, registry records, and operator documentation from that manifest.
  The manifest now deterministically generates and validates both the Mermaid and readiness table.
- [x] Define one common worker result envelope for deterministic tools, persona workers, pool
  coordinators, joins, and supplied human decisions.
- [x] Define explicit terminal states and allowed transitions for `OK`, `OK_WITH_GAPS`, `SKIPPED`,
  `BLOCKED`, `FAILED`, `CANCELED`, `UNRESOLVED`, and superseded attempts.
- [x] Add graph checks for cycles, unreachable nodes, invalid optional dependencies, missing skip
  semantics, namespace collisions, and a downstream contract that does not match its producer.

The versioned envelope and state machine are in `appsec-review-process/worker-result-contract.json`
and `schemas/worker-result-envelope.schema.json`. Supersession is an acceptance disposition over an
immutable terminal attempt, not a rewritten execution status. Runtime adapter migration remains
Workstream B work.

Validation:

- Generate a parity report in CI and require zero unexplained design capabilities, graph nodes,
  standalone jobs, registry templates, or output contracts.
- Mutation tests must prove that deleting or mismatching any worker, validator, contract, persona,
  dependency, permission, or qualification reference fails validation.
- The generated Mermaid graph and readiness table must reproduce the validated manifest exactly.

## Workstream B: shared dispatch and validation runtime

The first bounded validation-runtime slice is implemented in `worker_result.py`,
`validate_job_output.py`, and `worker_adapters.py`. It validates the common envelope, immutable
reuse, artifact paths/hashes, required contract files, input freshness, and dependency-edge skip
authorization. Deterministic Python and supplied-human adapters are defined; existing workers and
the remaining adapter kinds are not migrated or claimed complete.

- [x] Implement `create_job_handoff.py` from resolved registry records, with immutable prompt and
  composition hashes and bounded run-scoped inputs.
- [ ] Implement `validate_job_output.py` with contract-specific schemas, citation validation,
  source freshness, claim-class limits, status semantics, artifact hashes, and secret redaction.
- [ ] Define a worker adapter interface for Python workers, pinned container argv arrays, persona
  workers, and supplied human artifacts; reject arbitrary shell strings.

Completed subset:

- [x] Common status/acceptance, artifact hash/path, registry-required-file, input-fingerprint,
  dependency-edge skip, and immutable-reuse validation.
- [x] Contract-declared single-result schema validation for Scorecard, repository partition maps,
  and project discovery; required status values; bounded repository citation/path freshness;
  cross-record IDs; and non-mutating secret-leak rejection.
- [x] Registry-declared claim-class identity and non-mutating rejection of finding, severity, and
  observed-runtime promotion for the same three bounded result contracts.
- [x] Narrow deterministic Python and supplied-human-decision adapter protocol and implementations.
- [ ] Broader contract migration, pinned-container argv, persona invocation, pool, and controller
  adapters.
- [ ] Centralize attempt allocation, locking, timeout, cancellation, stream draining, child cleanup,
  publication, reuse, and newer-failure blocking so new workers do not reimplement the state model.
  Atomic publication, reuse validation, collision-safe allocation, interrupted-attempt recovery,
  terminal `BLOCKED`/`FAILED`/`CANCELED` recording, and newer-failure blocking are centralized and
  qualified for Scorecard and repository-partition discovery. Common success persistence and
  reusable-candidate admission also reject corrupt/stale pointers and recover a validated envelope
  left behind `PENDING` without rerunning payload work. The per-job lock and lock-scoped lifecycle
  sequence are now also common for those two workers: preflight blockers, work/validation failures,
  and cancellation route to one terminal recorder while the original exception still reaches
  Dagster. Scorecard and the standalone critical-findings SARIF transform use the versioned
  argv-only deterministic-child boundary for timeout, bounded concurrent stdout/stderr draining,
  cancellation diagnostics, and complete child-tree cleanup; SARIF adopted the common lifecycle,
  envelope and publication boundary in Batch 9 and passed its bounded live Dagster sequence in
  owner run `20260920T003602Z-41cea7`.
  Payload construction and contract-specific validation remain worker-local;
  repository-partition discovery has no child, and no broader worker was migrated.
- [ ] Add permission capabilities for target execution, network destinations, dynamic testing,
  debugger/ptrace, credentials, package restore, and target mutation.
- [ ] Add Dagster resource pools for CPU-heavy, memory-heavy, Docker, network, LLM/persona, and
  dynamic-analysis work. Preserve the global and per-engagement queue limits as outer bounds.
- [ ] Make status reporting show job, pool, worker instance, attempt, upstream generation,
  permission decision, coverage state, and actionable resume prerequisite.

Validation:

- Unit and property tests cover invalid paths, hostile prompts/evidence, malformed outputs, secret
  leakage, timeout, cancellation, output truncation, child-process loss, disk errors, and races.
- Service tests prove queue limits, per-pool concurrency, fairness between engagements, cancellation
  propagation, restart recovery, immutable reuse, forced rerun, and no fallback after newer failure.
- Cross-platform tests prove Windows-host submission and Linux worker execution retain identical
  logical contracts and path ownership.

## Workstream C: persona and tool work pools

- [ ] Finalize the pool-job schema: lane, worker kind, persona/tool identity, count, scope, inputs,
  budget, permissions, timeout, resource pool, and `wait_all` rendezvous.
- [ ] Implement deterministic expansion from worker specifications to unique immutable instance
  IDs and output roots.
- [ ] Implement persona dispatch with isolated context, exact scoped paths, fixed outer lane prompt,
  selected persona prompt, evidence-retrieval instructions, and recorded model/invocation identity.
- [ ] Implement tool dispatch as pinned-image argv arrays with no legacy-script shell-out.
- [ ] Implement a waiter that observes every expected instance to a terminal state without busy
  polling, handles cancellation, and never treats a missing worker as an empty result.
- [ ] Implement separate deterministic merges for persona findings, scanner evidence, and coverage
  receipts. Mixed pools must not flatten these into one untyped output.
- [ ] Implement evidence-qualified quorum keyed by claim and persona identity. Record when model or
  persona diversity requirements are not met; do not infer independence from worker count alone.
- [ ] Decide and configure pool concurrency separately for Docker/tool workers and model workers.
  This remains a discussion gate because machine capacity and provider rate limits are not yet
  characterized.

Validation:

- Exercise zero, one, and many workers; duplicate persona instances; mixed persona/tool pools;
  one-worker failure; timeout; cancellation; worker crash; malformed output; duplicate claim IDs;
  and late completion.
- Prove `wait_all` never publishes early, failed/degraded instances remain visible, and merge output
  is deterministic for the same accepted inputs.
- Prove workers cannot read another instance's private working context or write outside their
  run-owned scope.
- Load-test pool admission at the configured limits and record CPU, memory, Docker, and model-rate
  saturation behavior before increasing concurrency.

## Workstream D: lifecycle jobs

Implement in dependency order. Every item includes a registry composition, worker, validator,
standalone diagnostic entry where useful, lifecycle binding, documentation, and qualification.

### D1. Discovery and intelligence

- [ ] Replace the supplied-only repository-partition and developer-discovery gates with dispatchable
  persona jobs while retaining validated human-supplied results as an explicit input mode.
- [ ] Implement DevOps project discovery and SRE operations topology.
- [ ] Implement document, API collection, test, standards-source, operations-document, and binary
  intelligence ingestion with redaction and lineage.
- [ ] Implement source SAST and the separately authorized live Scorecard CLI job; keep the existing
  published-results Scorecard ingestion as a distinct evidence source.
- [ ] Publish safe derived intelligence into the evidence index without indexing raw secrets or
  confusing documented intent with observed behavior.

### D2. Build, test, IR, and binary evidence

- [ ] Qualify build configure, then implement native build with variant, compiler, dependency,
  generated-source, binary, symbol, and compile-database provenance.
- [ ] Implement native SAST, IR capture/link/facts, debug-symbol index, binary triage, and binary CFG
  as separate bounded producers.
- [ ] Implement test execution, test-result ingestion, and coverage ingestion with explicit
  provenance between source, binary, test command, result, and coverage artifact.
- [ ] Split the legacy vendor prepass into per-tool jobs for secrets, IaC, SBOM/SCA, container,
  mobile, source, and binary evidence; add missing graph nodes instead of hiding tools inside a
  generic source-SAST success.

### D3. Evidence rendezvous and analysis

- [ ] Implement `02-evidence-assembly` as the required applicability/freshness/hash/lineage barrier.
- [ ] Implement component characterization and make rescope events invalidate only affected
  downstream work.
- [ ] Implement the agreed threat-model job and standards-applicability jobs after the decision
  gates below are closed.
- [ ] Implement native-memory, CVE-reachability, fuzz-target, and deployment-hardening analysis.
- [ ] Implement red-team discovery, blue-team refutation, independent verification,
  scoring/prioritization, optional remediation/retest, completeness audit, and synthesis.
- [ ] Bind critical-findings SARIF generation to accepted synthesis/verification output while
  retaining its standalone fixed-input diagnostic mode.

Validation for every lifecycle job:

- Happy path, inapplicable path, missing/invalid input, permission denial, timeout, cancellation,
  corrupted output, source/upstream race, reuse, force, interrupted-attempt recovery, and newer
  failure must be tested.
- A real service launch must prove the worker appears in Dagster, receives the declared upstream
  generation, writes immutable evidence, passes its independent validator, and blocks descendants
  on failure.
- Negative tests must prove discovery/checklist/scanner jobs cannot publish verified findings and
  that static evidence cannot satisfy runtime claims.

## Workstream E: personas and selection

- [ ] Convert every persona used by an enabled job from catalog prose into a complete registry
  record with access level, capabilities, assumptions, prohibited assumptions, evidence inputs,
  proof obligations, output type, and eligible lanes.
- [ ] Define minimum persona sets by target characteristics—not a universal run-everything list.
- [ ] Implement a deterministic selector that consumes accepted partition/component/applicability
  evidence and records why each persona was selected, omitted, or deferred.
- [ ] Separate discoverer, refuter, verifier, standards auditor, completeness auditor, remediation,
  and stakeholder-output responsibilities. Prevent one worker result from self-verifying.
- [ ] Record prompt/template/model/tool hashes and declared diversity for every persona instance.
- [ ] Add specialized persona packs only when their required inputs and validation boundaries exist:
  web/API/auth, cloud/IaC, native, mobile, privacy, supply chain, LLM/agent, release integrity,
  operations, QA, and platform hardening.

Validation:

- Registry tests reject incomplete personas, incompatible lane/role/domain combinations, excessive
  capabilities, missing proof obligations, and outputs broader than the job contract.
- Selection fixtures cover web-only, native, mobile, IaC/cloud, API, library, and mixed monorepos,
  including shared paths and uncertain classification.
- Adversarial tests prove persona prompts and target evidence cannot override authorization,
  validation, evidence lineage, or claim-status rules.

## Workstream F: claim ledger and feedback loops

- [ ] Implement the append-only, hash-linked claim/decision ledger described by the design, with
  stable claim IDs, evidence citations, producer identity, status, confidence, affected components,
  proof obligations, dissent, supersession, and causal links.
- [ ] Route red-team candidates to independent blue-team refutation and surviving claims to
  independent verification. Refuted and unresolved claims remain auditable.
- [ ] Route verified findings to scoring and, when requested, remediation. Route patches to
  same-environment retest and then back to independent verification before any `fixed` status.
- [ ] Implement completeness audit before synthesis. Missing edges may create synthetic hypotheses
  that are assigned to targeted analysis and returned to verification before resynthesis.
- [ ] Implement rescope triggers for changed component classification, source generation, build
  semantics, applicability, and invalidated evidence.
- [ ] Bound every loop with generation IDs, maximum iterations, no-progress detection, explicit
  human gates, and an `UNRESOLVED_AND_REPORTED` terminal path.
- [ ] Recompute only affected descendants while preserving independent accepted branches and all
  earlier attempts.

Validation:

- State-machine and property tests reject illegal promotion, self-verification, missing refutation,
  unverified fixes, stale evidence, cycles without a generation advance, and silent claim deletion.
- Scenario tests cover verified, refuted, narrowed, duplicate, conflicting, unresolved, remediated,
  failed-retest, rescope, and synthetic-hypothesis paths.
- Crash/restart tests prove the controller resumes from the ledger without duplicate dispatch or
  loss of dissent, and loop limits reliably terminate.

## Workstream G: required design discussions for standards work

These are decision gates, not implementation details to infer. Record each outcome in an ADR and
update the graph/contracts before marking the corresponding worker ready.

### G1. Threat model

- [ ] Decide whether the primary artifact is DFD + STRIDE only or a composed model that also uses
  privacy/LINDDUN, abuse cases, attack trees, and deployment/runtime overlays.
- [ ] Agree the required DFD schema: actors, processes, stores, flows, trust boundaries, protocols,
  data classes, identities, tenancy, deployment zones, and evidence citations.
- [ ] Decide how documented intent, static source/IaC, test evidence, binary evidence, and observed
  runtime state are represented without conflation.
- [ ] Define applicability and completeness: which components/flows require threat enumeration,
  how unknown flows are recorded, and what triggers rescope.
- [ ] Decide who approves the model and whether threat-model disagreements create unresolved risks,
  targeted hypotheses, or both.

Required validation:

- Golden systems with known DFDs and threats; missing-flow and wrong-boundary mutations; monorepo,
  multi-tenant, queue/event, native-client, mobile, and cloud control-plane fixtures.
- Every threat must cite a modeled element and evidence; every in-scope trust-boundary crossing must
  be assessed or explicitly unresolved.

### G2. OWASP checklist and verification model

- [ ] Select and pin the authoritative OWASP sources and versions to support: ASVS level/profile,
  MASVS/MASTG, API Security Top 10, and LLM/agent guidance where applicable.
- [ ] Decide the applicability algorithm and who can override it, including web/API/mobile/library,
  client/server, authentication, tenancy, privacy, and deployment characteristics.
- [ ] Finalize per-control statuses, minimum evidence, dynamic-test requests, compensating controls,
  inherited controls, and aggregation rules.
- [ ] Define the boundary between `04-asvs-masvs`, `04-owasp-validation-worklist`, the
  `owasp-validator` persona, independent verification, and synthesis.
- [ ] Define how OpenCRE or other crosswalks are sourced and versioned without turning mappings into
  proof or duplicating one gap as multiple findings.

Required validation:

- Curated positive, negative, partial, not-applicable, and cannot-verify fixtures per supported
  family; version/hash/license lineage checks; and mutations that remove required evidence.
- Prove no selected control is silently skipped, no control is marked satisfied by scanner presence
  alone, and no checklist failure becomes a finding without exploitability/impact verification.

### G3. DISA STIG/SRG and NSA/CISA hardening

- [ ] Select supported platform families and pin authoritative STIG/SRG releases and NSA/CISA
  guidance; decide whether and where CIS benchmarks are an additional source.
- [ ] Define the applicability hierarchy for host, VM, container base image, workload, Kubernetes
  node/control plane, database, web server, SSH, and language/runtime components.
- [ ] Decide precedence and conflict handling between product STIGs, general SRGs, NSA/CISA guides,
  CIS guidance, vendor defaults, and documented compensating controls.
- [ ] Define which controls are manifest/static evaluable, built-image evaluable, runtime evaluable,
  or require authenticated/live inspection.
- [ ] Define tailoring, profile selection, severity, not-applicable evidence, inheritance, and how
  checklist gaps enter verification and synthesis.
- [ ] Define licensing/distribution rules for reference content and whether the repository stores
  control text, identifiers plus hashes, or an authorized local cache.

Required validation:

- Golden Linux/container/Kubernetes/service configurations with applicable and deliberately
  inapplicable controls; release/hash lineage; cross-source conflict fixtures; static-vs-runtime
  enforcement tests; and explicit no-reference-data failure.
- Prove a host control is not blindly applied to a minimal container, package presence is not
  configuration proof, and static manifests cannot satisfy live-state controls.

## Workstream H: full-system qualification and release gate

- [ ] Create a qualification target matrix covering at least web/API, native library/application,
  mobile, IaC/cloud, containerized service, and mixed monorepo shapes, with small deterministic
  ground-truth fixtures before expensive real repositories.
- [ ] Run schema/contract, unit, integration, property, adversarial, fault-injection, concurrency,
  performance, and cross-platform suites.
- [ ] Run a real `full_review` through every applicable job, including pool fan-out, refutation,
  verification, optional remediation/retest, completeness feedback, resynthesis, and report/SARIF
  publication.
- [ ] Inject worker, container, model, validator, storage, network, and Dagster failures and prove
  accepted state remains correct and recovery is bounded.
- [ ] Produce a signed/hash-pinned qualification manifest containing source revision, graph and
  registry hashes, prompt/model/tool/image identities, run IDs, attempts, coverage, gaps, and test
  results.
- [ ] Require an independent review of the parity report and residual limitations before declaring
  design parity.

Release criteria:

- Zero applicable `WORKER_NOT_IMPLEMENTED` nodes and zero unexplained supplied-only gates.
- Every applicable node is accepted or the full review is non-success; every inapplicable node has
  a validated reason and evidence.
- No unverified candidate is presented as a finding, no unresolved control is reported as passed,
  and no failed newer attempt falls back to older success.
- Pool, feedback, standards, recovery, authorization, and provenance tests pass against the actual
  Dagster service—not only in-process mocks.
- Remaining design deviations are explicit, approved, and represented as limitations rather than
  being labeled parity.
