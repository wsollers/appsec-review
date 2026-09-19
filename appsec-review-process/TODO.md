# AppSec Review Process TODO

This list is ordered by the current Dagster/run-owned architecture. New work should preserve the
rule that accepted evidence lives under `runs/<run_id>/data/`, with immutable attempts and explicit
publication through `accepted.json`.

The cross-cutting implementation and acceptance backlog for parity with `docs/design-v3.md` is
[`docs/design-parity-completion-plan.md`](../docs/design-parity-completion-plan.md). It is the
authoritative checklist for pools, all lifecycle jobs, personas, feedback loops, standards decision
gates, and final end-to-end qualification. Start a fresh implementation task with
[`continuation-design-parity-todo.md`](continuation-design-parity-todo.md). The sections below retain
subsystem-specific detail.

## 0. Accepted foundation

- [x] Re-vet and implement Phase 1 intake: [A01-A16 PASS](../docs/phase-1-acceptance.md).
- [x] Add the persistent Dagster run queue, per-engagement serialization, parallel preparation,
  validated final join and branch recovery: [workflow documentation](../docs/dagster-workflow.md).
- [x] Enforce run-owned `runs/<run_id>/data/`, immutable attempts, validated reuse and explicit
  legacy imports.
- [x] Register lifecycle/registry jobs in the full Dagster graph with explicit missing-worker gates.
- [x] Add reference-resolution and semantic compatibility checks for composition IDs.
- [x] Validate registry JSON records locally through `qualify_phase1.py`.
- [x] Move agent-facing process guidance into docs/skills:
  [agent reader](../docs/agent-reader.md), Codex/Claude process readers, evidence retrieval
  skills, and root `AGENTS.md`.

## 1. Immediate qualification gates

- [ ] Run and record `qualify_build_execution.py` on a host with Docker and the Dagster service.
  This is the current gate for whether `build_execution` actually produces
  `build/discovery/compile_commands.json` for Freeciv21.
- [ ] Run the full host and Linux test suites after the current Dagster/build/evidence-index code
  changes are staged together. Record the tested commit, service image identities and run IDs.
- [ ] Decide whether `build_execution` should remain a standalone launched job or be wired into
  `full_review` as `02-build-configure` after qualification. (Wired in 2026-09-19 as
  `build_configure_work` in `dagster_workflow.py`, ahead of qualification, per direct request;
  its real declared upstream, `02-dev-project-discovery`, was still an unimplemented `blocked_op`
  stub at the time -- see section 4's discovery hand-off gate, added the same day, which resolves
  that chain once real data is supplied. Still not run for real inside `full_review`.)
- [ ] Confirm `review_cli.py status` clearly reports `build_discovery`, `build_execution` and
  `evidence_index` acceptance/failure locations for operators.

## 2. Build and collection graph

- [x] Implement and qualify bounded `build_discovery`: separate streams, immutable reuse,
  full-graph failure and recovery. See [build discovery](../docs/build-discovery-integration.md).
- [ ] Implement successful-build manifests with separate Debug, RelWithDebInfo and Release
  provenance, matching symbols, generated inputs, binary hashes and compile databases. Configure
  success alone is insufficient.
- [ ] Implement the `02-native-build` worker as a distinct run-owned job after configure succeeds.
- [ ] Adapt native SAST, IR capture, IR link and IR facts to bounded Dagster workers with separate
  stdout/stderr, image/version records, tool-specific exit handling and immutable outputs.
- [ ] Add source SAST as a source-only branch that can run in parallel with build-gated work.
- [ ] Implement test execution, test-result ingest and coverage ingest as separate branches.
- [ ] Implement operations-doc ingest and keep it source-only unless it needs explicit tooling.
- [ ] Implement `02-evidence-assembly` as the rendezvous barrier: validate schemas, hashes,
  producer attempt IDs, build lineage, freshness, skip receipts and coverage gaps before publishing
  `intel-manifest.json`.
- [ ] Qualify parallel Freeciv21 collection with at least one branch failure/recovery scenario.

## 3. Evidence retrieval and tooling

- [x] Implement the Dagster source evidence index, immutable snapshots, ssdeep, FTS5 retrieval,
  bounded read-only MCP tools and Codex/Claude retrieval skills:
  [retrieval guide](../docs/evidence-retrieval.md).
- [x] Add repeatable LSP and MCP filesystem/memory protocol probes with image identities and
  run-owned receipts.
- [ ] Qualify language-server semantic references against accepted compile databases/build variants;
  initialization smoke tests alone do not establish semantic coverage.
- [ ] Publish reusable Codex and Claude skill installation instructions from
  `appsec-review-process/agent-skills/`.
- [ ] Add CI coverage for evidence-index CLI/MCP query bounds, stale acceptance and corrupt
  artifact rejection when CI orchestration is introduced.

## 4. Registry, personas and handoff rendering

- [x] Wire `02-repository-partition-discovery` and `02-dev-project-discovery` into `full_review`
  as a validated hand-off gate (`appsec-review-process/discovery_gate.py`, 2026-09-19): each op
  accepts an out-of-band-supplied, schema-valid result from
  `runs/<run_id>/data/jobs/<job>/supplied/result.json` (schema validation covers map IDs, path
  scopes, overlap explanations, citations and persona routes for the partition-map contract), or
  writes an actionable `handoff.md`/`handoff.json` and fails clearly if none is supplied yet. This
  is deliberately not a worker that performs the partition analysis itself -- that requires real
  judgment about the specific target that a script cannot honestly fabricate. See
  [build discovery](../docs/build-discovery-integration.md)'s new hand-off-gate section.
- [ ] Have a human or agent actually produce and supply a schema-valid
  `02-repository-partition-discovery` / `02-dev-project-discovery` result for a real engagement,
  so `02-build-configure`'s dependency chain resolves end to end in `full_review` (currently wired
  but unexercised with real data).
- [ ] Expose the accepted partition map in the engagement evidence index once real data exists.
- [ ] Implement `create_job_handoff.py` to render registry job templates into run-scoped handoffs
  with persona, role, domain, tooling profile and output contract sections.
- [ ] Implement `validate_job_output.py` for registry output contracts, citation checks,
  static/runtime claim limits and required status fields.
- [ ] Add smoke tests for job-template rendering once `create_job_handoff.py` exists.
- [ ] Add negative tests proving discovery/persona jobs cannot emit verified findings.
- [ ] Add the registry qualification command to CI when CI orchestration is introduced.

## 5. Intelligence ingestion

- [x] Declare parallel source SAST, doc, API and test consumers; build-gated IR and binary analysis;
  separate test-result/coverage consumers; and an evidence rendezvous:
  [collection plan](../docs/parallel-intelligence.md).
- [ ] Implement doc intelligence ingestion with run-owned outputs and safe summary/search records.
- [ ] Implement API collection ingestion for Postman, Bruno, Insomnia and OpenAPI artifacts,
  including environment redaction.
- [ ] Implement test intelligence ingestion for unit, integration, acceptance, smoke and load tests.
- [ ] Build reverse indexes from standards controls to tests, components, tags and binary-intel
  leads.
- [ ] Wire component tag-cloud generation into `01-component-characterization`.
- [ ] Connect doc/API/test/binary intelligence manifests into the run-owned evidence assembly and
  downstream `ENGAGEMENT_LLM_INPUT` compatibility surface.

## 6. Binary intelligence

- [ ] Decide whether the large binary analysis image should be split into static, firmware, mobile
  and dynamic variants.
- [ ] Add version-pinning or lock metadata for external binary-tool downloads in
  `images/audit-binary-analysis/Dockerfile`.
- [ ] Implement an automated `02-binary-intelligence-ingest` runner that discovers candidate binary
  artifacts and writes run-owned binary-intel outputs.
- [ ] Define or finalize JSON contracts for `binary-artifact-inventory.json`,
  `tool-evidence-manifest.json`, `candidate-leads.json` and `verification-followups.json`.
- [ ] Add skill guidance for the `reverse-engineer` persona and binary-intelligence job.
- [ ] Add optional YARA rule bundles and document where engagement-specific rules live.
- [ ] Add a safe mechanism for network-enabled Trivy/Grype DB refreshes when explicitly authorized.
- [ ] Add dynamic-analysis job templates for debugger, QEMU and Frida workflows with stronger
  authorization gates.

## 7. Standards and validation hardening

- [ ] Complete and record the threat-model, OWASP, and DISA/NSA decision gates in the
  [design-parity plan](../docs/design-parity-completion-plan.md#workstream-g-required-design-discussions-for-standards-work)
  before implementing those workers. Do not infer versions, applicability, evidence thresholds,
  crosswalk semantics, or static/runtime claim rules from the existing prompts.
- [ ] Populate per-control standards source directories with upstream lineage, hashes and license
  metadata.
- [ ] Add checks that High/Critical findings cite independent verification outputs.
- [ ] Document when `DEBUG_CAPS=1`, `ALLOW_NETWORK=1` and dynamic analysis are allowed, including
  required status fields.
- [ ] Add checks that runtime exposure claims cannot be satisfied by static-only evidence.
- [ ] Add regression tests for cancellation, worker loss, stale producer pointers, corrupted
  `accepted.json`, mismatched build symbols and one-branch recovery after failure.

## 8. Script migration (`scripts/` -> `pipeline/` or Dagster workers)

Per the 2026-09-19 script migration rule (`AGENTS.md`, `README.md`, `docs/migration.md`): no new
review-work logic in `scripts/`; port active review scripts, qualify, update callers, delete the
old script outright (no thin wrapper). Full script-by-script survey and priority tiers:
`appsec-review-process/continuation-scripts-to-pipeline-migration.md`.

- [x] Port `scripts/summarize_evidence.py` -> `pipeline/summarize_evidence.py` (2026-09-19,
  verbatim copy -- the script had no dependency on anything else under `scripts/`). Updated both
  callers (`pipeline/engagement_job.sh` line 148, `pipeline/engagement_job.ps1`'s static-summary
  step) and `pipeline/README.md`'s script table. Qualified by running old and new against an
  identical synthetic evidence tree and diffing output (byte-identical apart from the wall-clock
  timestamp line). Old script deleted outright, no wrapper.
- [x] Port `scripts/md_to_sarif.py` to the registered, run-owned
  `critical_findings_sarif` Dagster job (2026-09-19). The replacement uses a complete registry
  composition, fixed run input, bounded child execution, immutable attempts, separate streams,
  strict finding/SARIF validation, freshness and hash checks. Semantic parity against the legacy
  converter passed on a structured fixture; focused host/Linux tests and a live service launch
  qualify the workflow registration. The old script was removed from both static images and
  deleted outright with no wrapper.
- [x] Retire the one-time `scripts/fix-binskim.ps1` Dockerfile patcher (2026-09-19). Both maintained
  static-image Dockerfiles already contain the pinned self-contained BinSkim `4.4.9.11` install,
  the existing toolbox image reports that version, and preserved EASTL evidence records a
  successful BinSkim SARIF-producing step. The patcher had no executable callers and was deleted
  without a wrapper; the future run-owned binary-hardening producer remains separate open work.
- [x] Port `scripts/Get-ComponentLocations.ps1` to
  `pipeline/extract_component_locations.py` (2026-09-19). The replacement retains the deterministic
  CycloneDX/Syft component-location CSV and path/no-location summaries, adds bounded input and
  atomic output handling, and remains explicitly outside accepted Dagster evidence. Focused fixtures
  and a Windows old/new semantic comparison qualified it; the old script had no executable callers
  and was deleted without a wrapper.
- [x] Replace retired `scripts/check_ossf_scorecard.py` with the registered run-owned
  `ossf_scorecard` published-results job (2026-09-19). The replacement requires explicit fixed-host
  network authorization, validates canonical JSON2 identity and structure, preserves raw response
  provenance, exposes missing published results as coverage gaps, and fails newer attempts closed.
  The old helper remains deleted without a wrapper. A live Scorecard CLI scan remains separate work.
- [ ] Break `scripts/Invoke-VendorAuditPrePass.ps1` / `.sh` (the big legacy audit orchestrator) apart
  into separate per-tool Dagster jobs under `appsec-review-process/` -- **corrected 2026-09-19,
  repo owner's direct instruction**: NOT a single `orchestrator/` Python replacement (superseded
  `docs/migration.md` planned-change #5). Each tool becomes a job that communicates like every
  other job in the graph (`accepted.json`/`attempts/<id>/`), orchestrated by Dagster. Source-SAST
  tools map onto the already-declared `02-source-sast` node; secrets, IaC, SBOM/SCA, BinSkim and
  mobile SAST have no declared `job-graph.json` node yet and need a decision on new nodes/contracts
  before implementation (see the tool -> job mapping in the continuation prompt doc above). Highest-
  value, highest-risk remaining Tier 1 item -- treat the PowerShell/bash as reference for step
  semantics only, not code to lift verbatim.
- [ ] Resolve `scripts/build_semantic_index.py` / `query_semantic_index.py` -- check for overlap
  with the newer Dagster evidence index (`appsec-review-process/evidence_store.py`,
  `evidence_mcp.py`) before porting; may be substantially superseded rather than needing a straight
  port.
- [ ] Tier 2-4 scripts (11 documented-but-unwired scripts, 2 apparently orphaned, build-image
  tooling, dev/ops utilities): see the continuation prompt doc above for the full breakdown and
  per-script disposition questions. Not started.

## 9. Design-parity release gate

- [ ] Complete Workstreams A-H in the
  [design-parity completion plan](../docs/design-parity-completion-plan.md).
- [ ] Generate the machine-readable parity report and prove every enabled graph node has a worker,
  validator, registry composition, output contract, recovery policy, resource-pool assignment, and
  service-level qualification.
- [ ] Qualify persona/tool pools, wait-all rendezvous, deterministic merge, quorum, claim ledger,
  refutation/verification, remediation/retest, rescope, completeness, and resynthesis loops.
- [ ] Run an actual `full_review` with zero applicable `WORKER_NOT_IMPLEMENTED` results; preserve
  explicit accepted skip/gap receipts for inapplicable or unavailable evidence.
- [ ] Obtain independent review of the qualification manifest and residual design deviations before
  claiming parity with `docs/design-v3.md`.
