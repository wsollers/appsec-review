# AppSec Review Process TODO

This list is ordered by the current Dagster/run-owned architecture. New work should preserve the
rule that accepted evidence lives under `runs/<run_id>/data/`, with immutable attempts and explicit
publication through `accepted.json`.

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
  `full_review` as `02-build-configure` after qualification.
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

- [ ] Wire `02-repository-partition-discovery` before specialist discovery. Validate map IDs, path
  scopes, overlap explanations, citations, coverage gaps and persona routes, then expose the map
  in the engagement evidence index.
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

- [ ] Populate per-control standards source directories with upstream lineage, hashes and license
  metadata.
- [ ] Add checks that High/Critical findings cite independent verification outputs.
- [ ] Document when `DEBUG_CAPS=1`, `ALLOW_NETWORK=1` and dynamic analysis are allowed, including
  required status fields.
- [ ] Add checks that runtime exposure claims cannot be satisfied by static-only evidence.
- [ ] Add regression tests for cancellation, worker loss, stale producer pointers, corrupted
  `accepted.json`, mismatched build symbols and one-branch recovery after failure.
