# Appsec implementation fleet

**Plan version 1.4 - 6 November 2026**

Coordinator: `02825845-7ac6-4a31-b648-999b3823ecf5` (Appsec system review).
Repository: `wsollers/appsec-review`.
Approved design: `appsec-system-review.md`, including the revised Glasswing measurement
contract. Review baseline: `967a1072bc19feeb320ce4b44d6c056616c94d7b`.
Initial implementation baseline: `f9bb376e02aaef166bc71e736eaba7ee677ce97c`.
The later baseline includes the new isolation/shuffle/parallel/timing test standards.
Version 1.2 adds the narrowly scoped inherited test-harness repair X01 to the
closeout ledger. The original 18 implementation packages are unchanged. Current
owners, ready commits, landings and blockers are in the versioned ledger rather
than inferred from this plan's initial-wave descriptions.
Version 1.3 records the APS user's narrowed deterministic-replay milestone and the
separately scoped X02 all-failed-build recovery repair. Neither change authorizes
additional runtime experiments.
Version 1.4 records incoming, separately user-directed native compiler-profile step X03
and receipt of the APS deterministic subset. Neither supplies or authorizes the later
native-admission rollout, fuzz campaigns or formal-comparison APIs.

## User authorization

> Wow. THat was simply awesome. I agree with and approve of everything there. I think
> the first step is to identify the chunks of independent work that we can spin off to
> a fleet of agents with the caveat that they work in thier own worktrees. cover
> everything with tests and upon completion notify you. The goal would be to complete
> all of these suggestions and keep a plan ledger of what is planned, in flight and
> complete. I imagine you would coordinate the fleet and dispatch work and such. and
> should control the merge to prevent issues and to merge back into local main and
> keep windows and wsl repos in lock step. so first step define and document a plan
> with ledger to track. Then start the busy bees to implement

This authorizes the approved implementation, isolated worktrees, tests, coordination
and serialized local integration. It does not turn the design's conditional choices
into mandatory rewrites. In particular: no speculative Rust wrapper, unrestricted MCP,
new stock security-agent swarm, or duplicate APS harness.

Repository test-tier rules remain in force. Run focused unit tests now; write
integration/acceptance/live coverage but record those executions as manual/pending
until explicitly authorized. Do not start customer review runs, fuzz campaigns,
network discovery, cloud provisioning, host-tool installation, production deployment,
remote pushes or PRs from this implementation instruction.

## Coordination and ledger

The coordinator owns the live SQLite tables `fleet_packages`, `fleet_dependencies`,
`fleet_events`, and `fleet_meta`. Each event receives a monotonically increasing
sequence. `fleet-ledger.json` is a published snapshot of that live record, not a second
editable source of truth.

The bootstrap worker prepares the plan, approved review, and coordinator-supplied
ledger snapshots; the landing-only owner integrates exact authorized commits under:

```text
docs/plans/appsec-system-improvements/
  README.md                 this plan
  approved-review.md        approved review and source evidence
  ledger.json               published coordinator snapshot
  integration-log.md        exact landing/parity/verification receipts
```

Workers do not edit these shared files. They return a handoff to the coordinator,
who updates the ledger and authorizes integration. Package-local architecture/operations
docs and tests belong to each worker.

### State machine

`planned -> in_flight -> ready_for_review -> merge_authorized -> integrating ->
landed_unit_verified -> complete`

`blocked`, `revision_requested`, and `validation_pending` are explicit branches.
Do not mark a package complete because an agent is idle or a branch is clean.

Track implementation and validation separately:

- `ready_for_review`: committed work plus focused unit results, not landed.
- `landed_unit_verified`: coordinator-approved code is in both local mains at the same
  commit/tree; affected post-merge units passed.
- `validation_pending`: integration/acceptance/live behavior still needs an authorized
  run, missing tooling, or an external prerequisite.
- `complete`: the package's stated exit criteria are met. Empirical-performance,
  runtime-readiness and model-quality claims require their own evidence.
- Conditional work can finish with a justified **no implementation needed** decision;
  retain its benchmark/reasoning evidence.

Each record holds owner/session URL, base and ready SHAs, owned paths, dependencies,
decisions, test commands/timings/results, remaining validation, merge approval, Windows
and WSL main SHAs, tree/parity state and blockers.

## Fleet shape and first wave

The initial wave has **four implementation sessions** (F01, F05, F08, F09), an isolated
documentation-bootstrap session, and a separate landing-only main-checkout session.
They all report here. The extra landing session is necessary because an app worktree
session cannot own canonical-main mutation; it is not another feature worker.
The coordinator dispatches dependent work only after prerequisite contracts land.

This is a staged fleet, not an unattended launch of every package at once. Initial
implementation workers should use bounded two-worker focused pytest runs (`-n 2`),
unique scratch roots, and reproducible shuffle seeds to avoid multiplying host load.
No nested fleets or independent merge loops.

| Package | Dispatched session |
|---|---|
| F00 bootstrap | Fleet integration and parity (`ghapp://sessions/053e6dce-78d3-428d-ac36-f1811056dd67`) |
| F00 landing only | Fleet main landing (`ghapp://sessions/969abd85-9a4e-42a5-a323-34843205448e`) |
| F01 | Fleet publication contract repairs (`ghapp://sessions/816be210-1d6f-4a8f-9368-3880b01cbfb1`) |
| F05 | Fleet service inventory core (`ghapp://sessions/7d50b1ec-b93e-4573-aff2-066da4f2ab6f`) |
| F08 | Fleet worker competence (`ghapp://sessions/6e6a861e-8d73-42b9-a09c-163b833fea00`) |
| F09 | Fleet Glasswing metrics (`ghapp://sessions/0bf0aaeb-d683-4fe7-a68c-ad8dec4d79a5`) |

The existing test-harness owner has released integration ownership and reports no
landing in progress or source freeze. Windows `F:\XBOX-Repositories\appsec-review`
and WSL `/home/wsollers/projects/appsec-review` are both at the implementation baseline.
WSL has untracked `data/feeds/`, which must remain untouched. A bounded `-n 8` unit gate
is running in that owner's separate disposable clone, not either main. F00 must
recheck this state and the existing lock before landing; the report is not a lasting lock.

WSL Ubuntu-22.04 is confirmed running. All four implementation workers report private
Linux-filesystem worktrees at the required base. Their app-created worktrees initially
used an older prewarm (`dc263b3`); the coordinator authorized exact-base private Linux
materialization, not resets/rebases or main changes. F00's original app-worktree scope
blocked external WSL/canonical-main access. It subsequently reported a user-granted
documentation-only Windows exception. Code implementation and candidate testing remain
WSL; the separate landing session performs only the authorized main Git operations.

## Work packages

### F00 - Integration, ledger and Windows/WSL parity

**Dependencies:** none. **Owners:** bootstrap session `053e6dce-78d3-428d-ac36-f1811056dd67`;
canonical landing executor `969abd85-9a4e-42a5-a323-34843205448e`.

- Prepare documentation in an owned isolated worktree; publish the approved plan/review
  and ledger. The narrow user-granted Windows documentation exception does not authorize
  native Windows feature development or tests.
- The landing-only session uses an owned isolated WSL worktree for candidate changes/tests.
  Canonical checkouts are only for read-only inspection and exact authorized Git landing.
- Establish the existing integration lock, canonical Windows/WSL roots, baseline
  ancestry, clean state and any active-run freeze. Coordinate with existing owners.
- Prepare landing candidates and perform exact-SHA merges only when this coordinator
  authorizes them. Never accept a worker's self-authorization to merge.
- Use existing safe local Git transfer/integration facilities. Keep host overlays,
  virtual environments, runtime state, images, secrets and targets out of synchronization.
- Record both main commit/tree IDs after each landing. No next landing until parity
  succeeds or a surfaced blocker is resolved. Never force-reset either checkout.
- Own central plan/ledger/integration log and serialized release/test-map reconciliation
  only for approved packages. Do not develop unrelated features.

**Exit:** committed plan and published ledger; every approved landing has source,
verification and two-main parity receipts. Continuous until fleet closeout.

### F01 - Publication and inventory blockers

**Dependencies:** none. **First wave.**
**Own:** `indexing/inventory.py`, job-inventory eligibility portions of
`jobs/job_review_data_indexing/job.py`, `jobs/job_build_iteration/datasets.py` if needed,
bounded build-iteration dataset wiring, `indexing/input_matrix.py`, related regression
files and docs. Coordinate edits to runtime dataset helpers; no broad job-contract redesign.

- Reproduce the review's P0 mismatches on the current baseline; fix only surviving issues.
- Account for recovery records, publication markers and unit checkpoints with explicit
  runtime ownership. Undeclared artifacts must still fail.
- Distinguish internal build iterations from unconditional graph producers; account for
  actual internal attempts without requiring them to appear as top-level publications.
- Correct the missing build-environment input-source row and immediate related
  inventory discrepancies.
- Do not weaken strict assurance, skip the publication audit, or relabel failures clean.

**Tests:** real minimal runner output through strict inventory; failed/accepted attempts,
commit/checkpoint artifacts, absent/present internal iterations, managed accounting,
unknown-file rejection, default config/registry selection and missing build environment.
Candidate selectors include `tests/test_job_runtime.py`,
`tests/test_review_data_indexing.py`, `tests/test_handoff_interchange.py` plus focused
new regressions; choose the smallest cases that cover the changed behavior.

**Exit:** regression-covered default-path contract coherence; no unrelated runtime rewrite.

### F02 - Authoritative job input and dispatch contracts

**Dependencies:** F01.
**Own:** runtime job/dataset/dependency contracts, registry/topology/config wiring,
all-job declaration reconciliation, input-source/producer-consumer matrix and contract tests.

- Define typed required/optional/conditional input requirements and dispatch class
  (review graph/internal transaction/maintenance).
- Keep scheduling-only edges separate from semantic data dependencies.
- Bind actual admitted reads to exact producer/output/schema/authority and missing policy.
- Reconcile all 46 existing jobs: tagging, OWASP, document source ownership, indexing,
  build/CodeQL cross-producers and downstream publication.
- Generate or validate matrix/docs/test/release coverage from the authoritative contract;
  do not add another competing registry.

**Exit:** all-job producer-consumer invariants, enabled/disabled topology parity,
read-contract violations, missing/partial inputs and exact identity invalidation covered.
Publish a small stable shared contract commit before dependent feature work.

### F03 - Shared artifact and accepted-build APIs

**Dependencies:** F02.
**Own:** public accepted-artifact/build readers and their call sites; storage/bound-artifact
interfaces; .NET/Rust mapping helper; focused typing and documentation.

- Unify equivalent reference/read logic without erasing sensitivity/custody differences.
- Extract exact duplicate workspace mapping.
- Replace cross-job private imports with stable accepted-build/replay interfaces.
- Extend type checking at these boundaries.
- Specify file/process-crash/power-loss durability differences; do not promise guarantees
  that were not established.

**Exit:** exact-byte/reference-policy compatibility, malformed/foreign/stale references,
path/size limits, cross-filesystem and platform cases covered. No speculative native rewrite.

### F04 - Complete recoverability

**Dependencies:** F02, F03.
**Own:** checkpoints/repair/resume, fail-fast/cleanup integration and related CLI/operator views.

- Safe immutable-reference checkpoints for expensive path-bound work.
- Precise invalidation and compatible predecessor reuse in successor runs.
- Explicit cancellation/cleanup commissioning path for supported execution modes.
- Maintain source/image identity and no implicit hot reload.
- Add failure-injection coverage around publication boundaries and visible REUSE/RUN/
  INVALIDATE reasons/costs.

**Exit:** unit-tested repair invariants and manual deployment scenarios prepared.
Real supported deployment stop/fix/resume acceptance remains a separate execution gate.

### F05 - Static deployment and service inventory core

**Dependencies:** none. **First wave.**
**Own:** new `deployment/` domain modules, versioned evidence/signature catalog, closed
schemas, inert fixtures, focused tests, deployment-inventory design/operations docs.
**Not yet owned:** central registry/TOML/topology/retrieval wiring (F06).

- Implement a bounded static extractor and evidence-backed service/listener/relationship
  model using existing source/config parsing facilities where possible.
- Cover a useful vertical slice (Compose/Kubernetes and common Nginx/Redis/PostgreSQL
  service evidence), with extensible catalog entries for the approved families.
- Identify exact supplied evidence, selected variants, authority, conflicts and unknowns.
- Separate installed/dependency/declaration/listener/reachable facts. Default ports alone
  must not establish product identity or exposure.
- Define a read-only imported-observation contract; do not connect to live environments.

**Tests:** declared vs observed, proxy/backend relationships, ambiguous versions/ports,
conflicting overlays, malformed/bounded inputs, absent configuration and excluded platform
services. Use synthetic fixtures, not network/cloud scanning.

**Exit:** a coherent tested core and stable schema/API for F06; list unsupported formats
and catalog coverage explicitly rather than claiming an exhaustive detector.

### F06 - Deployment/exposure jobs and retrieval

**Dependencies:** F02, F05.
**Own:** deployment-topology and optional imported service-observation job adapters;
config/registry/topology/datasets/indexing/retrieval wiring assigned after F02.

- Consume accepted inputs and publish queryable topology/exposure evidence.
- Reconcile source/IaC/build/service facts without conflating build and deployment graphs.
- Add bounded query routes/cards and explicit observation freshness/drift.
- Complete promised static catalog/format coverage in bounded additions.

**Exit:** coherent job registration/disable/resume/publication and consumer contract tests;
seeded multi-service integration scenarios written. Live collectors remain permission-gated.

### F07 - Threat model and document-to-review completion

**Dependencies:** F02, F06, F08.
**Own:** threat-model producer and schemas; document candidate admission into existing
review lanes; associated context/card/skill additions, configuration and tests.

- Generate evidence-backed assets/actors/boundaries/flows/threats/obligations/unknowns.
- Consume classification, applicability, deployment and build facts without dependency cycles.
- Target-owned exclusions are untrusted context, not scope authority.
- Finish neutral document-candidate routing into independent review; fill its unit mapping.
- Surface typed missing-evidence requests rather than allowing workers to self-expand.

**Exit:** end-to-end fixture contracts show relevant evidence supplied/citable and unsupported
assumptions retained; no generated model conclusion is promoted to direct evidence.

### F08 - Worker competence and stateful guidance

**Dependencies:** none. **First wave.**
**Own:** existing worker guidance/skills/cards and competence/evaluation tests; no job
topology, shared model-execution mechanics or telemetry aggregate ownership.
The coordinator also approved a pure byte-compatible remediation task-dictionary extraction
from `job_remediation_planning/job.py` into `inputs.py` for the existing request-rendering
seam, with compatibility coverage; no execution or authority change.

- Extend realistic competence cases beyond the independent verifier to discovery,
  planning and remediation through existing production request/retrieval boundaries.
- Strengthen explicit attacker capability and environment assumptions in existing dispatch.
- Add a selected reusable stateful-protocol/invariant procedure where useful.
- Test decisive retrieval on later pages, cross-file controls, denied requests, wrong
  citations, contradictory configuration, missing artifacts and justified abstention.
- Preserve blinded reasoning and exact schema/tool/citation limits.
- Prepare live efficacy/role ablation entrypoints, but do not execute model calls.

**Tests:** scripted external model boundary only; real cards/bundles/authorization and
answer validation. No blanket prompt inflation or extra always-on agent panel.

**Exit:** existing-family competence coverage plus a clear extension contract for F07/F11;
scripted protocol results never mislabeled as model effectiveness.

### F09 - Glasswing quality and reproducibility metrics

**Dependencies:** none. **First wave.**
**Own:** new quality experiment/aggregation modules under `observability/` or existing
quality seam; schemas, deterministic fixtures and tests. Do not edit broad runtime
telemetry/event dispatch or dashboards until F10.

- Separate triage/discovery and candidate/verified/reproduced populations.
- Frozen comparison groups, launch-order indices, root-cause matching versions and
  independently versioned adjudications.
- Adjacent RoR Jaccard vs MPS, retention, recurrence, new/dropped/first-seen/reappearing.
- Failed/partial/mixed-group comparisons N/A; empty/nonempty zero; both empty N/A.
- Track TP retention/FP removal/distinct yield, unresolved outcomes, observed usage and
  costs without false zero or probability/calibration claims.
- Versioned per-run/aggregate exports; out-of-order completion and label/matching rebuilds.
- Pending-label bounds are not CIs. No auto-certification from mock statistics.

**Tests:** exact numeric examples, stable FP, failed/empty/missing runs, out-of-order
completion, changing group/labels/normalizer, duplicate reports and zero denominators.

**Exit:** deterministic reusable metrics engine and exports; statistically unsupported
quality gates remain explicitly unavailable.

### F10 - Operational telemetry and useful dashboards

**Dependencies:** F02, F09.
**Own:** queue/wait accounting, evidence-use/finding-funnel operational views, offline
dashboard/rendering, optional replayable metadata export and alerts.

- Separate admission/dependency/scheduler/resource wait, launch and runtime.
- Actual supplied/retrieved/cited evidence and orphan/unfulfilled-input visibility.
- Render real run/quality records with source/label/stage identity and coverage.
- Optional bounded OTLP exporter uses canonical events and durable export position;
  remote endpoints disabled until configured/approved.
- Include cost/yield/marginal-role metrics; no source/secrets in telemetry.

**Exit:** deterministic data-driven views, bounded cardinality, restart/export failure tests,
correct failure/empty presentation and no misleading queue or independence totals.

### F11 - Experiment planning and exact-build harness contracts

**Dependencies:** F02, F03, F07.
**Own:** engine-neutral experiment schemas/planner/admission, accepted-build adapter,
bounded CLI, harness validation interfaces and selected runtime guidance.

- Eligible grounded unresolved hypotheses as well as confirmed findings.
- Exact source/build/harness/oracle/corpus/config/approval identity and resource bounds.
- Preserve current compile-only review contract; separate downstream campaign graph.
- No arbitrary shell/executable selection, environment reconstruction or self-issued consent.

**Exit:** complete dry planning/admission and fake-external-boundary tests; unsupported
builds/engines/claims return explicit outcomes.

### F12 - Downstream replay, campaign and reduction

**Dependencies:** F04, F11, EXT-APS.
**Own:** appsec campaign lifecycle/adapter and corpus/reproducer publication, not APS's SUT.

- Reuse the existing APS-owned faithful DDNet runner and its exact supported contract.
- Deterministic replay first; then bounded stateful coverage-guided campaign adapter.
- Persist exact interesting inputs, corpus snapshots, independent observations, controls,
  cleanup and partial outcomes. Seed alone is insufficient.
- Reduction preserves predicate, mode and original/minimized parentage.
- Add later language-engine adapters incrementally with explicit support inventory.

The current APS milestone supplies only deterministic replay, if successfully
implemented and handed off. It does not supply or authorize coverage-guided campaigns,
ACK-loss investigation, security-finding workflows or reduction. Do not treat delivery
of a replay executable as satisfying those additional capability and authorization gates.

**Exit:** source implementation and unit coverage; real harness/fuzz execution is a separately
authorized acceptance milestone, not implied by fake engine results.

### F13 - Lean/formal evidence bridge

**Dependencies:** F12, EXT-APS.
**Own:** restricted observed-trace projection, pinned Lean execution/result contract,
theorem-assumption applicability and model mismatch publication.

- Use the existing Lean model, not a duplicate implementation.
- Native allocator charges/results, time and Flush/lifecycle effects must be observable
  and supported; otherwise report unsupported/inconclusive.
- Separate assumption escape, logical ACK candidate, retransmission coverage, sanitizer
  failure, model equality and proved hypotheses.

**Exit:** projection/oracle controls and complete provenance; actual Lean/runtime comparison
requires corresponding acceptance evidence before verification claims.

### F14 - Re-adjudication, patch regression and final publication

**Dependencies:** F07, F12, F13.
**Own:** experiment-evidence admission into existing claims; original/fixed regression
comparison; new gate/report/dossier/OpenVEX snapshots.

- New runtime evidence creates a new publication version, never edits old certification.
- Verify original and repaired builds under the same admissible observation contract.
- Non-reproduction is not automatically refutation/not-affected; retain flaky/blocked cases.

**Exit:** publication-completeness and original/fixed controls covered; runtime success
assertions remain conditional on actual approved runs.

### F15 - Capability, skills and MCP usability

**Dependencies:** F04, F06, F07, F10, F12, F13.
**Own:** preflight/capability report, development/runtime skills in correct locations,
bounded operator/query routes and conditional async fuzz MCP wrapper.

- Report configured/installed/reachable/compatible/commissioned/permitted separately.
- Reuse one CLI/runner; MCP exists only if repeated structured job access justifies it.
- Read-only inspection without execution permission; scoped plan hash, idempotency,
  cancellation and bounded artifact reads for any execution surface.
- No blanket global agent/tool installs or unrestricted file/SQL/shell endpoint.

**Exit:** discovery/parity/permission-negative tests, honest missing-capability guidance.
Installation and live endpoints are separate operator actions.

### F16 - Measured optimization and native decision

**Dependencies:** F03, F10, F12.
**Own:** bounded representative performance fixtures/measurement and justified hot-path
changes, plus a native prototype only if evidence supports it.

- Measure hash/copy/fsync/index/lock/cache costs and useful end-to-end improvement.
- Fix repeated work without weakening custody. No speculative Rust Redis wrapper.
- If justified, test a narrow native artifact boundary against exact bytes, Unicode,
  integer/path/cross-filesystem/crash/storage constraints.
- Preserve Python orchestration and current provenance.

**Exit:** reproducible decision and measured implementation benefit, or explicit evidence
that native work is not warranted. Real heavy benchmarks remain manually gated.

### F17 - Acceptance and closeout

**Dependencies:** all F01-F16 and supplemental X01/X02; F00 owns landing mechanics.

- Reconcile directly related docs, job/input/output inventories, release closure,
  test mappings, supported-mode claims and outstanding conditional work.
- Write cross-package/manual acceptance scenarios and collect exact authorized results.
- Review known-failure and skip lists; neither may hide introduced defects.
- Final Windows/WSL source parity and artifact provenance record.

**Exit:** ledger accounts for every approved recommendation; implementation, commissioning,
live efficacy and deferred-by-evidence decisions are individually labeled. No "everything
complete" declaration while required acceptance or an external dependency remains unresolved.

### X01 - Inherited default-collection fixture regression

**Dependencies:** none. **Supplemental infrastructure repair, not another feature.**
Original owner: unit-suite session `d963e6fd-4153-401f-842f-1f6c18def977`.
**Own:** `tests/test_pytest_default_collection.py` only.

The implementation baseline introduced a `tests/time_budgets.py` dependency in
`conftest.py`; the isolated collection fixture copied only `conftest.py`. Carry both
files into each fixture project, preserving the existing collection and exclusion
assertions. No production code, harness policy, timeout or test-tier change.

**Exit:** the nine existing cases pass shuffled/in parallel in the combined candidate,
and the exact one-file fix lands through the same two-main parity gate. This repair
supports the fleet's test infrastructure; it does not authorize a full-suite run.

### X02 - All-failed build workspace recovery

**Dependencies:** none; coordinate with F02/F04 ownership before edits.
Original owner: unit-suite session `d963e6fd-4153-401f-842f-1f6c18def977`.
**Own:** `jobs/build_iterations.py` and directly necessary topology-refinement
regressions. F02 confirmed no overlap with those files or reliance on the old refusal.

Repair the bounded case where all build iterations failed and rollback left a pristine
materialized workspace with neither accepted iteration ledger nor pending request.
Exercise actual failure, rollback and resume through real workspace/controller behavior,
faking only external execution. Preserve refusal for unfinished attempts, accepted
products without admission, corrupt state and failed custody.

The original mixed eight-file handoff `ceb8ea5703d68f189ca8a41e55746f1db5ccc267`
is not approved. Prepare a separate isolated candidate; exclude its six unrelated
language-fixture migrations. Existing failed or over-ten-second cases are not passing
evidence, and cannot be hidden by skips, relaxed assertions or tier relabeling.

**Exit:** narrow positive/negative recovery regressions pass the focused unit gate,
then exact reviewed candidate and Windows/WSL parity are recorded. No production
review restart or broader language-build execution is authorized by this repair.

### EXT-APS - Existing DDNet harness work

External owner: Lean Formalization coordinator
`4c594168-d314-4336-b0b4-51aca8ae5462`.
The live ledger identifies its current implementation child. The initial child and
its replacement encountered request-service failures without source changes; WSL
availability was independently established. Do not equate either a responsive host
or a newly created session with a tested runner.

The model/design are available; the executable dependency stays gated until an exact
tested runner/schema handoff is received. This fleet does not restart that project's
work or answer its pending user decisions on the user's behalf.

**User-directed scope update, 6 November 2026:** APS's current milestone is pinned
DDNet build integration and deterministic JSON replay only, preserving the Lean models,
with reset/input validation, controlled time, zero OS network sends and ordinary
correctness tests. Coverage-guided campaigns, candidate ACK-loss investigation,
security-finding workflows and a finding reducer are excluded from that milestone.
The next possible handoff is a tested deterministic runner/schema, not a full fuzzing
API. F12/F13 remain gated on their actual required capabilities; this fleet must not
ask the APS worker to restore the excluded scope or infer authorization from a runner.

The deterministic subset was subsequently received at local commit
`4cb6ee15f572873df9dec31fa182a20de3d4e6f7` (not assumed remotely published).
The coordinator read its implemented contract and schemas, verified retained evidence
hashes and source-byte maps, and retained the producing project's test results.
This was read-only inspection, not a fleet rebuild/replay or authenticity attestation.
CLI 1.0.0 supports synchronous `build`, `inspect`, `validate`, `replay` with the
verified Linux x86_64 Clang 14 profile, native allocator and stop-on-queue-failure only.
Finding oracles are empty. No campaign, reducer, logical ACK-age ledger, async MCP or
Lean differential API is available. The live ledger records exact evidence references.

Required handoff: exact source/model/harness/schema/build commits, tested runner APIs,
observability/oracle scope, allocator/caller modes, artifact semantics and remaining
acceptance gaps. F12/F13 wait for that contract instead of implementing a competing harness.
Only implemented observations and modes belong in that handoff; planned or excluded
oracles and operations remain unavailable.

### X03 - Incoming native compiler-profile step 1

This is a separately user-directed work item reported by the existing unit-suite owner
`d963e6fd-4153-401f-842f-1f6c18def977`, not permission to implement its entire rollout.
It is tracked for serialized integration; the original fleet dependencies are unchanged.

**Own:** three new files only: `container_runtime/compiler_profiles.py`,
`tests/test_compiler_profiles.py`, `docs/plans/native-compiler-profiles.md`.
Implement the compiler-profile `/2` parser and Docker-boundary collector with bounded
unit tests. No existing topology, build job, config, image-pin or enforcement changes;
the profile is not yet a production admission input. F02 does not own these new files.
F03 should assess the reviewed interface before adding a competing accepted-build model.

**Exit:** closed, semantically checked records and bounded parsing/copy/cleanup behavior;
honest identity versus configured signature-verification claims; focused isolated tests;
exact reviewed candidate and two-main parity. Synthetic fixtures are not real image
commissioning. Live image probes, downstream enforcement and later rollout steps require
their own authorized scope. Initial review blockers and revisions remain in the ledger.

## Shared ownership and change rules

| Surface | Owner rule |
|---|---|
| Main refs, integration lock, plan ledger | F00 under exact coordinator authorization only. |
| Runtime job/data contracts, registry, central topology/input matrix | F01 bounded repair first, then F02. Later adapters receive explicit ownership windows. |
| TOML/config/profile/release/test-map registration | Assigned to the current wiring package; integrator reconciles serially. First-wave leaf packages do not edit these hotspots. |
| Existing test harness/conftest/AGENTS/known failures | Preserve the existing unit-harness owner's in-flight changes. Scope expansion needs coordinator approval. |
| Artifact/build shared interfaces | F03, then consumers import the frozen contract. |
| Guidance/cards/competence | F08 first; later F07/F11 additions wait for it. |
| Quality aggregation | F09; operational integration/rendering follows in F10. |
| APS harness/model | Existing APS project, not this fleet. |

Workers may propose necessary ownership changes, but must report conflicts before editing
another active worker's area. Shared-contract concerns come here. Do not silently copy a
helper to avoid coordination.

## Test and completion contract

- Revalidate actual baseline before edits; the review's findings are hypotheses to reproduce
  against newer code, not instructions to preserve an obsolete fix.
- Linux/WSL Linux-filesystem worktree and private virtual environment per worker.
- Unit tests use inert fixtures and fake only external boundaries. Do not run real
  Docker, models, targets, remote services or production configuration.
- Under-ten-second individual unit cases, deterministic IDs/collection, unique
  `test/tmp/<package>` basetemp, and affected shuffled parallel tests before handoff.
- Record exact command, elapsed time, failures/skips and source identity. If a case
  fails alone or only under shuffle/parallelism, fix the actual defect; no xfail/skip
  workaround or enlarged budget.
- Write relevant integration/acceptance/live tests with explicit prerequisites and budgets;
  do not execute them automatically.
- Each ready handoff names package, branch/worktree, full ready/base SHAs, changed paths,
  public contract decisions, tests/results/timings, validation not run and blockers.
- Ready means commit and notify; it does not mean merge or push.

### User-approved F02 time exceptions

The user explicitly approved these two existing offline unit-case exceptions after
the worker measured minimal fixtures exercising real durable cross-producer admission:

| Exact node ID | Maximum total case duration |
|---|---|
| `tests/test_review_data_indexing.py::test_inventory_audit_matrices_links_and_fts_validation` | 45 seconds |
| `tests/test_review_data_indexing.py::test_package_job_publishes_accepted_manifest_and_receipts` | 60 seconds |

These bounds include setup, call and teardown, not only assertions. Record per-case
declarations, the exception provenance and actual times; an overrun remains a failure
requiring resolution. The ten-second limit remains for all other unit cases. This
does not authorize a global timeout increase, weakened admission/durability checks,
full-suite runs, integration/acceptance/live execution, targets or model calls.

## Merge and parity transaction

1. Coordinator reviews ready diff, ownership, dependencies and evidence.
2. Coordinator authorizes **one package + exact ready SHA + expected main base**.
3. F00 acquires the existing OS-backed integration lock; verifies both canonical roots,
   clean state, active-run freeze and expected ancestry; rejects stale instructions.
4. Prepare the candidate in an isolated WSL integration worktree. Resolve conflicts
   explicitly; return feature conflicts to the owning worker. Run affected unit checks.
5. Transfer Git objects using the existing local method; advance each main safely.
   This is not a cross-filesystem atomic transaction: journal intermediate state.
6. Verify Windows and WSL `HEAD` and tree IDs match, ready SHA is an ancestor, and tracked
   content has no accidental line-ending changes. Do not synchronize host-specific state.
7. Report the exact receipt. If either side fails, stop further integration, preserve
   both states and report the mismatch; no force-reset or automatic conflict choice.
8. Coordinator updates ledger; only then dispatch dependent packages from landed contracts.

No timer-based merge poller, background repository updater, force push, broad cleanup,
worktree pruning or deletion of another worker's state is part of this plan.
