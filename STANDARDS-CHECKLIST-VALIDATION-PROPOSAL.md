# Proposal: Standards Checklist Ingestion And Validator Personas

## Purpose

This proposal adds a standards/checklist layer to the AppSec review process. It is inspired by the
OWASP Secure Agent Playbook pattern for consuming OWASP verification material:

- extract standard controls into small per-control files
- preserve upstream metadata and source lineage
- build reverse indexes from controls to verification tests
- assign work by component/domain/tag rather than asking one prompt to "do all of OWASP"
- distinguish static checks, dynamic checks, and follow-up checks
- keep standards mappings evidence-backed and auditable

The same pattern should support:

- OWASP ASVS
- OWASP MASVS
- OWASP MASTG
- OWASP API Security Top 10
- OWASP LLM / Agentic guidance
- OpenCRE mappings
- DISA STIGs and SRGs
- CIS Benchmarks where license/usage permits
- NSA/CISA hardening guidance
- RFC-backed protocol checks
- product- or organization-specific control catalogs

## What The OWASP Tooling Does Well

The most useful pattern in the OWASP Secure Agent Playbook is not just that it has security prompts.
It turns verification checklists into assignable review work.

Key ideas observed:

1. **Per-control files**
   - ASVS/MASVS controls are split into individual Markdown files.
   - Frontmatter stores stable metadata such as control ID, group, title, and summary.

2. **Verification-test reverse indexes**
   - MASVS controls include `mastg_tests`.
   - MASTG tests include `covers_masvs`.
   - This lets the reviewer start from a control and immediately know which tests inform it.

3. **Upstream lineage**
   - Extracted MASTG files retain upstream path/version/tag information.
   - V1 fallback and V2 successor status are tracked.

4. **Lean schema**
   - Extracted reference files avoid too much hand enrichment.
   - Enrichment lives in play rules and persona/domain logic.

5. **Static vs dynamic caveats**
   - The mobile review prompt explicitly records static-only limitations and dynamic follow-up tests.

6. **Skill assignment**
   - A skill loads the appropriate controls/tests for the detected platform and walks them in an
     ordered way.

This process should adopt the same mechanism for broader standards and infrastructure hardening.

## Proposed Architecture

Add a standards intelligence layer:

```text
appsec-review-process/standards/
  catalog/
    owasp-asvs/
    owasp-masvs/
    owasp-mastg/
    opencre/
    disa-stig/
    disa-srg/
    cis/
    nsa-cisa/
    rfcs/
  indexes/
    control-to-tests.json
    control-to-domains.json
    component-tag-to-controls.json
    platform-product-to-controls.json
    standards-crosswalk.json
  schemas/
    standard-control.schema.json
    standard-test.schema.json
    standards-crosswalk.schema.json
```

Engagement output:

```text
scratch/<project>-engagement/standards-intel/
  applicable-controls.json
  owasp-validation-worklist.json
  stig-validation-worklist.json
  standards-coverage-matrix.json
  standards-intel-summary.md
```

## Standard Control Record

Suggested canonical shape:

```json
{
  "schema": "appsec-review/standard-control/0.1",
  "standard": "OWASP ASVS",
  "standard_version": "5.0",
  "control_id": "V5.3.4",
  "title": "Parameterized queries or ORM usage",
  "summary": "Short upstream summary or extracted control text.",
  "source_url": "",
  "source_path": "",
  "source_hash": "",
  "license": "",
  "applicable_domains": ["rest-api", "database", "input-validation"],
  "applicable_component_tags": ["sql", "query-builder", "repository"],
  "evidence_modes": ["static-source", "test", "dynamic"],
  "verification_tests": [],
  "static_signals": [],
  "dynamic_followups": [],
  "cannot_verify_statically_notes": []
}
```

## Standard Test Record

```json
{
  "schema": "appsec-review/standard-test/0.1",
  "standard": "OWASP MASTG",
  "test_id": "MASTG-TEST-0337",
  "title": "",
  "covers_controls": ["MASVS-CODE-..."],
  "platform": "android",
  "test_type": ["static", "dynamic"],
  "steps_summary": "",
  "observation_criteria": "",
  "evaluation_criteria": "",
  "source_url": "",
  "source_path": "",
  "source_hash": "",
  "status_note": ""
}
```

## Checklist Ingestion Jobs

### `standards-source-ingest`

Imports upstream standards into local structured control/test files.

Inputs:

- upstream repo or downloaded bundle
- standard type
- version/ref
- output directory

Outputs:

- per-control Markdown/JSON files
- source manifest
- extraction log
- license/usage notes

Supported sources:

- OWASP ASVS
- OWASP MASVS
- OWASP MASTG
- OpenCRE
- DISA STIG/SRG
- CIS Benchmark, where permitted
- NSA/CISA hardening guides
- RFC excerpts/index records

### `standards-crosswalk-build`

Builds mappings between standards, controls, tests, domains, and component tags.

Outputs:

- `standards-crosswalk.json`
- `control-to-tests.json`
- `component-tag-to-controls.json`
- `platform-product-to-controls.json`

### `standards-applicability`

Consumes component map, doc-intel, qa-intel, scanner evidence, and source tags to identify which
controls apply to this target.

Inputs:

- component-purpose map
- component tags
- tech stack
- platform/product inventory
- DFD/trust boundaries
- doc-intel and qa-intel

Outputs:

- `applicable-controls.json`
- `standards-coverage-matrix.json`
- lane-specific worklists

### `owasp-validation-worklist`

Builds work items for an OWASP validator persona.

Inputs:

- applicable OWASP controls
- OpenCRE mappings
- component map
- API/test/doc intelligence

Outputs:

- `owasp-validation-worklist.json`
- `owasp-validation-summary.md`

Work item shape:

```json
{
  "work_item_id": "OWASP-ASVS-V5.3.4-FC12",
  "standard": "OWASP ASVS",
  "control_id": "V5.3.4",
  "component_id": "FC12",
  "domain": "database-query-construction",
  "evidence_mode": "static-source",
  "required_artifacts": [
    "component map",
    "source paths",
    "test intelligence"
  ],
  "verification_questions": [
    "Are SQL queries parameterized or ORM-generated?",
    "Can untrusted input influence raw SQL text?"
  ],
  "expected_output": "control assessment"
}
```

### `stig-validation-worklist`

Builds STIG/SRG hardening review work items.

Inputs:

- image inventory
- Dockerfile/base image inventory
- SBOM/package inventory
- OS family and version
- container runtime/deployment config
- system software inventory, such as nginx, RabbitMQ, PostgreSQL, Redis, OpenSSH
- DISA STIG/SRG references
- NSA/CISA hardening references

Outputs:

- `stig-validation-worklist.json`
- `platform-hardening-targets.json`
- `stig-applicability-matrix.json`

## Component Tag Cloud Integration

The checklist layer should guide component identification.

`01-component-characterization` should emit tags useful for standards routing:

```json
{
  "component_id": "FC12",
  "name": "User Search API",
  "component_tags": [
    "rest-api",
    "database-query",
    "pii",
    "authenticated-user",
    "tenant-scoped",
    "rate-limit-sensitive"
  ],
  "standard_domains": [
    "asvs-input-validation",
    "asvs-access-control",
    "api-security",
    "privacy"
  ],
  "platform_products": [
    "nginx",
    "postgresql"
  ]
}
```

The standards applicability job can then map:

```text
component tags -> applicable controls -> review work items -> persona assignments
```

This should improve the component cloud by making it more than a semantic summary. Components become
review targets with explicit standards worklists.

## OWASP Validator Persona

### Purpose

The `owasp-validator` persona performs standards checklist assessment using extracted OWASP controls
and tests.

It does not discover arbitrary findings. It answers whether specific OWASP controls are:

- satisfied
- partially satisfied
- not satisfied
- not applicable
- cannot verify statically
- dynamic test required

### Inputs

- `applicable-controls.json`
- `owasp-validation-worklist.json`
- component map
- source evidence
- qa-intel
- doc-intel
- scanner outputs
- OpenCRE mappings

### Output

```json
{
  "schema": "appsec-review/owasp-validation-result/0.1",
  "persona_id": "owasp-validator",
  "work_items": [
    {
      "work_item_id": "",
      "standard": "OWASP ASVS",
      "control_id": "",
      "component_id": "",
      "verdict": "satisfied | partially_satisfied | not_satisfied | not_applicable | cannot_verify | dynamic_test_required",
      "evidence_citations": [],
      "counterevidence": [],
      "gaps": [],
      "recommended_followup": ""
    }
  ]
}
```

### Rules

- Do not turn a failed control into an exploitable finding without separate claim verification.
- Do not mark `satisfied` unless the evidence actually covers the control.
- If evidence is only documentation, mark it as documented intent, not implementation proof.
- If the control requires runtime behavior, mark `dynamic_test_required`.
- Prefer `cannot_verify` over guessing.

## NSA / STIG Platform Engineer Persona

### Purpose

The `nsa-stig-platform-engineer` persona reviews operating system images, container base images,
and system software hardening against applicable STIGs, SRGs, NSA/CISA guides, and curated hardening
references.

This persona is for platform and image hardening, not application logic.

### Targets

- container base images
- Linux distribution packages
- OS configuration visible in image artifacts
- nginx
- RabbitMQ
- PostgreSQL
- Redis
- OpenSSH
- Apache HTTPD
- Tomcat
- Java runtime
- Python/Node runtime images
- Kubernetes node/workload hardening, where evidence supports it

### Inputs

- Dockerfile inventory
- image SBOM
- package inventory
- OS release files
- image filesystem scan, when available
- Trivy/Grype/Syft outputs
- Docker Bench / kube-bench outputs, when available
- nginx/RabbitMQ/system config files
- DISA STIG/SRG references
- NSA/CISA hardening references

### Output

```json
{
  "schema": "appsec-review/platform-hardening-result/0.1",
  "persona_id": "nsa-stig-platform-engineer",
  "targets": [
    {
      "target_id": "image:python:3.10.0b4",
      "target_type": "container_base_image",
      "detected_platform": "debian",
      "applicable_references": [
        "DISA Linux STIG",
        "Container Platform SRG",
        "NSA Kubernetes Hardening Guidance"
      ],
      "verdicts": []
    }
  ]
}
```

### Rules

- Do not apply a STIG to the wrong product or evidence mode.
- Container image evidence is not the same as host OS evidence.
- Dockerfile evidence is not the same as built image evidence.
- Runtime daemon configuration is not proven by package presence.
- If a STIG check requires a live host, cluster, or daemon query, mark it `live_state_required`.
- If an SRG is conceptually related but not directly evaluable, cite it only in narrative, not as a
  satisfied/failed control.

## Standards Sources To Add

### OWASP

- ASVS
- MASVS
- MASTG
- API Security Top 10
- Web Security Testing Guide
- Cheat Sheet Series, as explanatory reference
- OpenCRE mappings

### DISA

Prioritize references that map to likely evidence:

- Linux STIGs, for base image and OS-package hardening where image evidence is available
- Application Security and Development STIG, where source/process evidence exists
- Web Server STIGs, for nginx/Apache/IIS where config evidence exists
- Database STIGs, for PostgreSQL/MySQL/etc. where config evidence exists
- Kubernetes STIG, but only manifest-evaluable checks in static mode
- Container Platform SRG, but be strict about platform/runtime evidence requirements

### NSA / CISA

Potentially useful:

- Kubernetes hardening guidance
- cloud security guidance
- zero trust guidance
- container hardening guidance, when available
- identity and access management guidance

### CIS

Useful but licensing-sensitive:

- Docker Benchmark
- Kubernetes Benchmark
- Linux distribution benchmarks
- nginx/Apache benchmarks if available
- cloud provider foundations benchmarks

Use CIS IDs only when the tool output or permitted local reference supports the mapping.

### RFCs

Use for protocol-specific domains:

- HTTP semantics and caching
- OAuth 2.0 / bearer tokens
- JWT / JOSE
- TLS
- WebSocket
- SMTP/webhooks where applicable

RFC references should be tied to a concrete protocol behavior under review.

## Prompt: OWASP Validator

```text
You are the OWASP validator for this AppSec review.

You are not doing open-ended vulnerability discovery. You are assessing specific OWASP controls from
the provided worklist against the target evidence.

Inputs:
- worklist: {{OWASP_VALIDATION_WORKLIST}}
- component map: {{COMPONENT_MAP}}
- evidence package: {{EVIDENCE_PACKAGE}}
- doc intelligence: {{DOC_INTEL}}
- QA intelligence: {{QA_INTEL}}
- source paths: {{SOURCE_PATHS}}

For each work item:
1. Read the control text and any linked test/check guidance.
2. Identify what evidence would satisfy the control.
3. Inspect only the relevant artifacts and source locations.
4. Record one verdict:
   - satisfied
   - partially_satisfied
   - not_satisfied
   - not_applicable
   - cannot_verify
   - dynamic_test_required
5. Cite evidence and counterevidence.
6. State gaps and follow-up checks.

Rules:
- Do not infer compliance from absence of scanner findings.
- Do not mark satisfied from documentation alone unless the control is documentation/process-only.
- Do not invent ASVS/MASVS mappings.
- Do not report exploitable findings; emit control assessments. Candidate findings can be routed to red-team/verification.
```

## Prompt: NSA / STIG Platform Engineer

```text
You are the NSA/STIG platform hardening engineer for this AppSec review.

You review OS images, container images, and system software configuration against applicable STIG,
SRG, NSA/CISA, and curated hardening references. You are strict about applicability.

Inputs:
- platform hardening targets: {{PLATFORM_HARDENING_TARGETS}}
- image inventory/SBOM/package evidence: {{IMAGE_EVIDENCE}}
- system software config: {{SYSTEM_CONFIG_EVIDENCE}}
- STIG/SRG reference records: {{STIG_REFERENCES}}
- scanner outputs: {{SCANNER_OUTPUTS}}

For each target:
1. Identify product, version, evidence mode, and whether the target is source config, Dockerfile,
   built image, host OS, runtime daemon, Kubernetes manifest, or live system.
2. Select only applicable controls.
3. Assess each control as:
   - satisfied
   - not_satisfied
   - partially_satisfied
   - not_applicable
   - cannot_verify
   - live_state_required
4. Cite the exact evidence.
5. Separate direct control verdicts from conceptually related hardening notes.

Rules:
- Do not apply host STIG checks to a container image unless the check is actually image-evaluable.
- Do not apply a product STIG to a different product.
- Do not treat package presence as configuration proof.
- Do not treat Dockerfile instructions as proof of built-image state.
- Do not mark runtime/service hardening satisfied without runtime/config evidence.
```

## Validation Rules

The standards/checklist system should reject outputs when:

- a control verdict lacks a citation
- a standard ID has no reference source
- a static-only job claims runtime state
- a product STIG is applied to the wrong product
- `satisfied` is used where the evidence only shows intent
- dynamic-only tests are marked complete from static evidence

## Implementation Plan

1. Add standard-control and standard-test schemas.
2. Add standards source manifest and extraction log.
3. Import or reference OWASP ASVS/MASVS/MASTG using the per-control/test pattern.
4. Add OpenCRE lookup/crosswalk support.
5. Add initial DISA reference ingestion for the references already used by deployment hardening.
6. Add platform/software target inventory generation from Dockerfiles, SBOMs, package lists, and config files.
7. Add `owasp-validation-worklist` and `stig-validation-worklist` jobs.
8. Add `owasp-validator` and `nsa-stig-platform-engineer` personas to the registry.
9. Wire worklists into `04-asvs-masvs`, `15-deployment-hardening`, and synthesis.

## Bottom Line

The OWASP tool's strongest idea is turning standards into small, assignable verification units. This
process should generalize that idea beyond OWASP: component tags and platform inventory should
drive standards applicability, standards applicability should generate worklists, and validator
personas should produce evidence-backed control verdicts without overclaiming exploitability.
