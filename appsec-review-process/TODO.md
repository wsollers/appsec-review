# AppSec Review Process TODO

## Registry And Job Orchestration

- Implement `create_job_handoff.py` to render registry job templates into run-scoped handoffs.
- Implement `validate_job_output.py` for registry output contracts, citation checks, and static/runtime claim limits.
- Add reference-resolution checks so every job composition ID resolves to an existing persona, role, domain, tooling profile, and output contract.
- Add schema validation to CI or a local smoke command for all registry JSON records.

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
