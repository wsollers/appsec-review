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

All 46 registered factories attach the contract declared in their `datasets.py` module. Forty-four
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
