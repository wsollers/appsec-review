---
title: "Job input and dispatch contracts"
kind: "architecture"
subsystem: "runtime interchange"
status: "current"
jobs: ["job_artifact_indexing", "job_binary_evidence_indexing", "job_build_environment_analysis", "job_build_iteration", "job_ci_configuration_analysis", "job_evidence_collection", "job_language_build", "job_project_build", "job_target_catalog", "job_third_party_data_sync"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Job input and dispatch contracts

`Job.contract` is the typed dispatch and input authority. It extends the existing job/dataset
contract, not a second semantic registry. `runtime.contracts` defines the closed
`appsec-review/job-contract/1` format. Per-job declarations live beside `DATASETS`.

Each input names a producer, output kind, exact schema, evidence authority, availability,
missing policy and coverage policy. Channels distinguish accepted run handoffs from imported
external evidence and internal controller transactions. A reference to external feed or acquisition
evidence does not require a maintenance job's handoff in the review run.
Resolved configuration is already a mandatory hash-bound runtime input; it is not duplicated as
an invented external producer.
Dataset declarations pin output evidence authority as well: admission refuses an authority mismatch,
including an older declaration whose authority is unknown. Historical declarations remain readable
with `authority = null`; they are not assigned a new retrospective authority. Routing/tagging and
operational receipts are distinct from source evidence, and raw review-cell proposals remain
provisional even when their producing attempt is accepted.

Required inputs reject absence; optional inputs report gaps or explicit non-applicability.
Conditional requirements apply when their producer is enabled in the frozen configuration.
An accepted producer can still have partial, unavailable or retriable coverage. Acceptance is not
completeness. A required producer envelope does not make every optional, per-scope dataset mandatory.

Scheduling edges order jobs, including transparent disabled vertices. Only semantic inputs
participate in input selection and invalidation. Dispatch classes are `review_graph`,
`internal_transaction` and `maintenance`. Target access is independently `checkout`,
`accepted_evidence` or `none`; authenticated evidence identity never grants target filesystem access.

The attempt dataset format `/3` embeds the exact hashed job contract. Readers retain `/1` and `/2`
support without inventing historic input provenance or rewriting old artifacts. A contract change
changes the attempt identity and refuses reuse under the new contract.

Consumption observations must distinguish availability, supply, reader access and explicit
citation. A handoff reader establishes access to an envelope; a shard reader establishes access to
that dataset. Neither proves that a model used it in reasoning. Undeclared reads fail at instrumented
reader boundaries; this contract is not an operating-system filesystem sandbox.

## Current dispatch and projections

All 47 registered factories attach the contract declared in their `datasets.py` module. Forty-five
are review-graph jobs (including disabled jobs); `job_build_iteration` is an internal transaction,
and `job_third_party_data_sync` is external maintenance. `Job.consumes` and module `CONSUMES` are
compatibility projections, not independent input declarations. Registry/config parity and exact
producer output/schema relationships are checked by `indexing.input_matrix.job_contract_matrix`.

The shared topology combines `schedule_after` with semantic input predecessors, projects disabled
vertices out, and removes redundant scheduling edges. Direct and Dagster dispatch use the same
projection. Input identity includes only explicitly declared producer handoffs, not arbitrary
scheduling ancestors. A fresh scheduling-only predecessor does not invalidate an independent
branch. A change to the contract definition itself, including its scheduling declaration,
conservatively invalidates the old attempt.

Reusable jobs with external or transaction inputs must supply an input-identity probe; otherwise
their contract must require fresh execution. Feed consumers re-probe verified local snapshot
selections without invoking maintenance or network operations. Intake binds acquisition and
configured binary-publication identities, and internal iterations bind the controller's pending
immutable request. These identities join the existing `input_identity` reuse check. Standalone
feed maintenance always dispatches fresh so a previous successful sync cannot suppress the next
requested update. Required non-handoff inputs also need a verified reader receipt before accepted
publication; execution without that receipt is rejected.

An `external_input_identity` callback returns the closed JSON
`appsec-review/external-input-selection/1` document, including each selector's exact identity or
named absence. `Job.bind_input_identity` invokes it once and freezes that same selection in the
claim; the reuse hash cannot describe a different probe. Actual external readers must match the
claimed identities, including if a mutable current pointer changes and is later rolled back.
Claims predating this selection cannot execute under a job that now requires it. Consumers of
already published feed pins use the accepted indexing input-summary contract, not global
current-feed selection. Copying/verifying an inherited provenance receipt is not a semantic read.
A read-contract violation remains fatal at the runtime boundary even if a handler catches it as
an optional gap. For external references, the `producer` names the declared source interface;
the original publisher's identity (including an unknown legacy origin) remains in the verified
feed-use proof and is not inferred from that name.

For an untagged single-job attempt the runtime selects current accepted inputs only from enabled
declared producers. Explicit supply rejects undeclared, stale and conflicting identities. An
explicitly supplied downstream handoff can supply its hash-pinned ancestors **only when the
consumer also declares them**. This supports package readers without promoting mere graph
ancestry into permission. Disabled PoC output is not silently selected by a standalone gate.

The launch target-access sets, internal-producer inventory exemption and downstream consumer
matrix are derived views of these contracts. Maintenance and internal jobs retain exact file
ownership, including present failed/accepted attempts, without requiring an unconditional
top-level review handoff. The source taxonomy in `INPUT_SOURCES` remains design/navigation
metadata, not dispatch authority; reconciliation uses the complete registered set, including
disabled and standalone jobs.

## Admission and read receipts

`claim.json` pins `appsec-review/input-admission/1`: each requirement's schema, authority,
availability, supply and accepted producer run/target/attempt/hash identity. Missing optional
inputs remain gaps, not empty successes. Coverage retains the producer's partial and retriable
states; requirements can refuse either. Inputs that were not supplied have unknown availability,
not an invented assertion that no artifact exists.

The runtime writes `appsec-review/input-reads/1` inside existing hash-bound unit status receipts.
It does not inject runtime fields into job-domain results. Accepted handoff decoders, indexing
and retrieval shard readers, security-tag readers, external feed proofs, intake acquisition and
binary bindings, and internal request readers report their actual verified identities. The OWASP
inventory reader requires its specialized manifest to be bound to the supplied producer.
`read_input_observations` refuses changed receipts and returns unknown for historical attempts.
The producer-consumer matrix distinguishes availability, supply and observed reads; citation is
explicitly `null` because these boundaries do not observe model reasoning.
The indexing input summary and coverage matrices now emit `/2` schemas; producer-consumer
availability is no longer serialized as evidence that consumption was complete.

This is bounded reader instrumentation, not a Python or filesystem sandbox. Direct arbitrary
filesystem reads and model citation interpretation are not inferred from these receipts. The
future shared artifact/build reader work can instrument additional private artifact readers
without changing the dispatch authority. Historical `planned_consumers` fields in review-result
schemas retain their old serialization; they do not drive current scheduling or permissions.

## Verification surfaces

Fast units live in `tests/test_job_contracts.py` and `tests/test_input_contract_admission.py`,
alongside the existing runtime, interchange, inventory and dispatch regressions. They exercise
real runner admission, exact output owners, typed target-independent authority, partial/retriable
coverage, read-versus-supplied evidence, contract reuse refusal and actual Dagster definition
edges without executing a Dagster run.

`tests/integration/test_job_input_contracts.py` is an explicit manual full indexing-to-package
scenario. It preserves a dominating accepted manifest's exact identity, rather than inventing a
new merged manifest when the supplied roots are already contained in one accepted lineage.
No live target, model, image build, deployment or review execution is implied by these units.
`tests/acceptance/test_job_input_contracts.py` is a read-only manual check of an already completed
review named by `APPSEC_F02_ACCEPTANCE_RUN`; it does not launch a review.

The [consumer read-path inventory](job-consumer-read-paths.md) enumerates all jobs and records the
downstream original-owner source view. Runner-mediated source, bound-PoC gate and actual standalone
Dagster admission regressions are in `tests/test_downstream_input_contracts.py` and
`tests/test_standalone_input_contracts.py`. A supplied review manifest never re-owns its inherited
shards or substitutes for declaring their original output kinds.
Shard ownership is resolved against the complete producer-pinned declaration set before selecting
source-view outputs or reporting availability. A more-specific coverage declaration wins over a
broad AST/symbol/observation declaration; ties and unclaimed shards are errors, never implicit input
authority. Coverage-only outputs retain their explicit requirements and gaps.

The shared `runtime.consume.accepted_upstream` reader uses these typed declarations and admitted
pins, not the available producers in `consumable_handoffs` or a scheduling ancestor closure.
It records reads through the same sticky observation scope used by shard/output readers; a caught
permission error still rejects the unit. A foreign run cannot fall back to an operator pointer
lookup. Task receipts retain the closed `input-reads/1` observation document on success and failure,
separately from admission's availability/supply metadata and unobserved citation state.

Artifact indexing requires an accepted language-build envelope and its receipt-set dataset.
Artifact security analysis additionally requires the artifact-indexing envelope and summary.
An accepted empty receipt/artifact set remains a named producer gap; a missing prerequisite is
rejected at admission rather than labelled optional and discovered by an unconditional reader.
Single-consumer test graphs must include real fixture producers or use explicit standalone supply;
an existing `latest.json` never grants an input to an explicitly empty graph projection.

A shared loader's transitive reads belong to the calling job's contract. `load_accepted_plan`
re-reads the environment publication an accepted plan is bound to (`EXPECTED_CURRENT` or
`OPTIONAL_PRIOR`), so `job_evidence_collection`, `job_language_build` and, by inheritance,
`job_build_iteration` declare `job_build_environment_analysis` as an optional input, as
`job_project_build` does. `job_binary_evidence_indexing` requires the `job_target_catalog` envelope
because it composes its shards onto that producer's pinned retrieval manifest. A job that does not
use what a loader can read asks for less instead: `job_artifact_indexing` and
`job_ci_configuration_analysis` call `load_target_catalog(..., intake_target_root=False)`.
`tests/test_plan_environment_consumers.py` and `tests/test_binary_evidence_indexing.py` run these
paths through the real runner.

The inference-review fixture pins the complete original producers' declarations and artifacts,
publishes current input-summary metadata, and supplies verified package publication where the
scanner-correlation prerequisite exists. Required but unpopulated fixture datasets publish explicit
unavailable coverage, not fabricated evidence. Fixtures deliberately omitting package prerequisites
do not manufacture an accepted package handoff. These synthetic publications do not establish live
review coverage or authorize execution of the full review test chains.
