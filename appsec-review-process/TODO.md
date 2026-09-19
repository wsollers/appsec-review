# AppSec Review Process TODO

## Phase 1 acceptance and durable orchestration

- [x] Re-vet and implement the prompt: [A01-A16 PASS](../docs/phase-1-acceptance.md).
- [x] Extend repo-local Dagster with configured intake/validator composition, explicit dependencies, pre/post validation, separate streams and failure recovery.
- [x] Enforce new-run `runs/<run_id>/data/`, immutable attempts, validated reuse and explicit legacy imports. Unimplemented downstream dispatch is blocked.
- [x] Synchronize machine graph/Mermaid and update operational docs and registry assignments.

## Registry And Job Orchestration

- [x] Add a persistent Dagster run queue, per-engagement serialization, parallel preparation,
  a validated final join and branch recovery: [workflow documentation](../docs/dagster-workflow.md).
- Implement isolated scanner/specialist executors and resource pools before enabling heavy
  downstream work; preparation handoffs do not execute those jobs.

- Wire `02-repository-partition-discovery` before specialist discovery; validate map IDs, path scopes, overlap explanations, citations, coverage gaps, and persona routes, then expose its map in the engagement LLM index.
- Implement `create_job_handoff.py` to render registry job templates into run-scoped handoffs.
- Implement `validate_job_output.py` for registry output contracts, citation checks, and static/runtime claim limits.
- [x] Add reference-resolution and semantic compatibility checks for all five composition IDs.
- [x] Validate all registry JSON records locally through `qualify_phase1.py` (66 records qualified).
- Add the registry qualification command to CI when CI orchestration is introduced.

## Binary Intelligence

- Add an automated `02-binary-intelligence-ingest` runner that discovers candidate binary artifacts and writes `binary-intel/` outputs.
- Define a concrete JSON shape for `binary-artifact-inventory.json`, `tool-evidence-manifest.json`, `candidate-leads.json`, and `verification-followups.json`.
- Add optional YARA rule bundles and document where engagement-specific rules should live.
- Add a safe mechanism for network-enabled Trivy/Grype DB refreshes when explicitly authorized.
- Add explicit dynamic-analysis job templates for debugger, QEMU, and Frida workflows with stronger authorization gates.

## Images, MCP, And Skills

- Decide whether the large binary analysis image should be split into static, firmware, mobile, and dynamic variants.
- Add version-pinning or lock metadata for external binary-tool downloads in `images/audit-binary-analysis/Dockerfile`.
- Add MCP smoke coverage for filesystem/memory servers in each buildenv image.
- Publish reusable Codex and Claude skill install instructions from `appsec-review-process/agent-skills/`.
- Add skill guidance for the new `reverse-engineer` persona and binary-intelligence job.

## Standards And Intelligence

- Populate per-control standards source directories with upstream lineage, hashes, and license metadata.
- Build reverse indexes from standards controls to tests, components, tags, and binary-intel leads.
- Wire component tag-cloud generation into `01-component-characterization`.
- Connect doc/API/test/binary intelligence manifests into `llm/ENGAGEMENT_LLM_INPUT.md`.

## Validation And Process Hardening

- Add smoke tests for job-template rendering once `create_job_handoff.py` exists.
- Add negative tests that prove discovery jobs cannot emit verified findings.
- Add checks that High/Critical findings cite independent verification outputs.
- Document when `DEBUG_CAPS=1`, `ALLOW_NETWORK=1`, and dynamic analysis are allowed, including required status fields.
