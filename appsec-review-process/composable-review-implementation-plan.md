# Composable Review Implementation Plan

Engagement Phase 1 modernization is separately specified in
[`phase-1-implementation-prompt.md`](phase-1-implementation-prompt.md). It adds Dagster execution,
run-owned `data/`, explicit validation jobs, idempotency and acceptance gates. The numbered registry
phases below describe the older implementation breakdown, not engagement lifecycle phase numbers.
Engagement Phase 1 is [ACCEPTED through A01-A16](../docs/phase-1-acceptance.md).
Use the [operations guide](../docs/phase-1-operations.md); downstream dispatch remains planned.

This plan consolidates the persona, intelligence, composable-template, and standards-checklist
proposals into a repo structure that extends the current lane process without replacing it.

## Target Shape

Lanes remain the lifecycle. A composable job is the bounded dispatch unit inside a lane:

```text
lane + persona + role + domain + tooling profile + output contract + evidence bundle
```

Tracked records live in `appsec-review-process/registry/`. Engagement-specific worklists and
derived intelligence for new runs stay under `appsec-review-process/runs/<run_id>/data/`.
Shared `scratch/<project>-engagement/` remains legacy data and requires explicit import.

## Phase 1: Registry And Schemas

Status: initial skeleton added.

- Add central schemas under `schemas/` for personas, roles, domains, tooling profiles, job
  templates, output contracts, standard controls, standards worklists, component tag clouds, and
  intelligence payloads.
- Add registry records under `appsec-review-process/registry/`.
- Keep records JSON for dependency-free validation by `appsec-review-process/schema_validate.py`.

## Phase 2: Standards And Intelligence Inputs

Add source-backed engagement artifacts:

```text
scratch/<project>-engagement/
  standards-intel/
    component-tag-cloud.json
    applicable-controls.json
    owasp-validation-worklist.json
    stig-validation-worklist.json
    standards-coverage-matrix.json
  intel/
    INTELLIGENCE_MANIFEST.json
    search-records.jsonl
  doc-intel/
  qa-intel/
```

Rules:

- Extract standards into per-control files with upstream source URL/path/hash/license.
- Build reverse indexes from controls to tests.
- Route checklist work by component, domain, platform product, and tag.
- Separate static, dynamic, live-state, and follow-up verification.
- Produce evidence-backed control verdicts; failed controls are not automatically findings.

## Phase 3: Handoff Rendering

Add `create_job_handoff.py` after the registry records stabilize.

It should:

- accept `--job-template` or explicit composition IDs,
- load and validate registry records,
- collect artifact-manifest and optional intelligence/worklist paths,
- render concise prompt sections,
- write to `appsec-review-process/runs/<run_id>/handoffs/<process>/jobs/<job_id>.md`.

## Phase 4: Output Validation

Add `validate_job_output.py`.

It should validate:

- registry IDs and output contract,
- required files,
- status fields,
- evidence citations,
- standards reference citations,
- proof obligations,
- static-only vs runtime claim limits,
- worklist/control verdict schemas.

## Phase 5: Lane Integration

Wire jobs into existing lanes without changing lane semantics:

- `02-evidence-pregather`: standards source ingestion, doc intelligence, API collection
  intelligence, test intelligence.
- `01-component-characterization`: component tag cloud generation.
- `04-asvs-masvs`: OWASP applicability and validation worklists.
- `15-deployment-hardening`: STIG/SRG/platform hardening worklists.
- `07`, `08`, `09`: consume candidate findings, control gaps, and verification requests.
- `10`: synthesize verified findings, unresolved control gaps, and coverage limitations.

## Initial Dispatchable Jobs

- `02-repository-partition-discovery` (coarse scope and developer/DevOps/SRE routing before specialist discovery)
- `02-standards-source-ingest`
- `04-owasp-validation-worklist`
- `15-stig-srg-validation-worklist`
- `02-doc-intelligence-ingest`
- `02-api-collection-intelligence-ingest`
- `02-test-intelligence-ingest`
- `02-dev-project-discovery`
- `02-devops-project-discovery`
- `02-sre-operations-topology`
- `02-binary-intelligence-ingest`

## Build/LSP/MCP Worker Images

Language build environments live under `images/audit-buildenv-*` and are listed in
`appsec-review-process/tooling/buildenv-catalog.json`.

Images:

- `audit-buildenv-cpp:local`, extending `audit-native:local`
- `audit-buildenv-java:local`
- `audit-buildenv-go:local`
- `audit-buildenv-typescript:local`
- `audit-buildenv-php:local`
- `audit-buildenv-dotnet:local`
- `audit-buildenv-python:local`
- `audit-buildenv-rust:local`
- `audit-binary-analysis:local` for PE/ELF/debug-symbol parsing, Ghidra/headless reverse
  engineering, angr CFG extraction, RetDec decompilation, cwe_checker/check_cwe binary weakness
  checks, FLOSS string intel, DIE classification, Syft/Grype/Trivy binary/package intel,
  ssdeep/TLSH clustering, APK/.NET decompilation, binary SAST, call-graph extraction support, and
  code-search enrichment from compiled artifacts

Skills:

- `appsec-review-process/agent-skills/codex/repo-project-engineer/SKILL.md` describes how Codex
  should discover projects, choose language worker images, and route binary/debug artifacts.
- `appsec-review-process/agent-skills/claude/repo-project-engineer.md` provides the same project
  discovery and binary-analysis routing guidance for Claude-style agents.
- These skills are guidance for agent behavior; they do not grant permission to execute untrusted
  scripts, restore dependencies, use the network, attach debuggers, or mutate target repositories.

MCP:

- Language worker images install `@modelcontextprotocol/server-filesystem` and
  `@modelcontextprotocol/server-memory`.
- The shared wrappers keep target repositories mounted read-only and network disabled by default.
- MCP servers are intended for bounded local context over mounted workspaces and scratch outputs,
  not for bypassing the evidence contract or trust boundary.

Build entrypoints:

```bash
scripts/build-language-buildenv-images.sh
```

```powershell
.\scripts\Build-LanguageBuildEnvImages.ps1
```

Runtime entrypoints:

```bash
images/audit-buildenv-common/run.sh <image> <workspace> <scratch> -- <command...>
```

```powershell
.\images\audit-buildenv-common\run.ps1 <image> <workspace> <scratch> -- <command...>
```

Network remains disabled by default; set `ALLOW_NETWORK=1` only for explicitly authorized
dependency restore or tool bootstrap work.

Debugger attach support remains disabled by default; set `DEBUG_CAPS=1` only for approved ptrace
or debugger sessions that need the additional Docker capability and seccomp override.

## Guardrails

- Target repos, evidence, scanner outputs, docs, and test artifacts are untrusted data.
- Standards mappings require retrieved, scanner-backed, or curated local reference evidence.
- Static-only jobs cannot claim observed runtime state.
- Discovery and worklist jobs cannot emit verified findings.
- Stakeholder outputs consume verified or explicitly unresolved evidence; they do not create new
  technical claims.
