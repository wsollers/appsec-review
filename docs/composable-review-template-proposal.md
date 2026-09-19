# Proposal: Composable Review Templates

## Purpose

This proposal defines a composable template system for AppSec review work. It turns personas,
roles, domains, jobs, tooling, prompts, and outputs into structured records that can be combined
repeatably.

The goal is to move from hand-written lane prompts toward reusable review building blocks:

```text
review job =
  lane
  + persona
  + role
  + domain
  + tooling profile
  + evidence bundle
  + output contract
  + validation policy
```

This model supports attacker-oriented review, defensive refutation, verification, QA intelligence,
document ingestion, stakeholder reporting, and synthesis without writing a new prompt from scratch
for each case.

## Motivation

The current process has strong lanes, evidence rules, and scanner outputs. The next layer should
make review dispatch more precise:

- Which persona is reviewing?
- Which role are they performing?
- Which technical domain are they reviewing?
- Which evidence can they use?
- Which tools or actions are allowed?
- Which claims are they permitted to make?
- Which output schema must they satisfy?
- Which validator decides whether the job is acceptable?

Without a composable model, prompts grow large and bespoke. With a composable model, the process can
dispatch targeted jobs such as:

```text
07-red-team-adversarial
  persona: opportunistic-public-web-attacker
  role: candidate-claim-generator
  domain: nginx-rest-api
  tooling: static-route-config-pack

09-independent-verification
  persona: evidence-only-verifier
  role: proof-obligation-verifier
  domain: inherited-from-claim
  tooling: cited-evidence-plus-minimal-source

02-evidence-pregather
  persona: test-coverage-indexer
  role: intelligence-extractor
  domain: qa-test-artifacts
  tooling: static-test-doc-parser
```

## Definitions

### Persona

A persona is the worldview, attacker model, or reviewer stance.

Examples:

- opportunistic public web attacker
- malicious tenant
- cloud initial-access operator
- defensive skeptic
- evidence-only verifier
- product owner
- QA lead
- executive risk briefer

The persona controls assumptions and failure modes.

### Role

A role is the work function being performed.

Examples:

- candidate claim generator
- refuter
- verifier
- intelligence extractor
- standards mapper
- test validator
- product risk summarizer
- executive briefer
- remediation planner

The role controls the job objective and output type.

### Domain

A domain is the technical or product surface.

Examples:

- nginx/rest-api
- terraform/iam
- kubernetes workload hardening
- OAuth/JWT/session management
- QA test artifacts
- functional design docs
- native parser memory
- LLM agent/MCP/RAG

The domain controls what patterns, standards, evidence, and review heuristics apply.

### Tooling Profile

A tooling profile defines allowed evidence and actions.

Examples:

- static-route-config-pack
- static-iac-cloud-network-pack
- cited-evidence-only
- postman-bruno-parser
- static-test-doc-parser
- authoritative-native-docker

The tooling profile controls what the job may read, execute, index, or claim.

### Job Template

A job template combines lane, persona, role, domain, tooling, budget, and output contract.

It is the dispatchable unit.

### Output Contract

The output contract defines required artifacts, schema, citations, confidence rules, and forbidden
claims.

## Proposed Registry Layout

```text
appsec-review-process/registry/
  README.md
  personas/
    opportunistic-public-web-attacker.yaml
    malicious-tenant.yaml
    cloud-initial-access-operator.yaml
    defensive-skeptic.yaml
    evidence-only-verifier.yaml
    product-owner.yaml
    qa-lead.yaml
    executive-risk-briefing.yaml
  roles/
    candidate-claim-generator.yaml
    refuter.yaml
    proof-obligation-verifier.yaml
    intelligence-extractor.yaml
    standards-mapping-auditor.yaml
    stakeholder-briefing-writer.yaml
    remediation-planner.yaml
  domains/
    nginx-rest-api.yaml
    rest-api-authz.yaml
    terraform-iam.yaml
    cloud-network-exposure.yaml
    kubernetes-workload-hardening.yaml
    qa-test-artifacts.yaml
    functional-design-docs.yaml
    native-parser-memory.yaml
  tooling-profiles/
    static-route-config-pack.yaml
    static-iac-cloud-network-pack.yaml
    cited-evidence-only.yaml
    cited-evidence-plus-minimal-source.yaml
    postman-bruno-parser.yaml
    static-test-doc-parser.yaml
    authoritative-native-docker.yaml
  output-contracts/
    candidate-claim.yaml
    finding.yaml
    verification-verdict.yaml
    intelligence-extract.yaml
    stakeholder-brief.yaml
  job-templates/
    07-redteam-nginx-rest-opportunist.yaml
    09-verify-candidate-claim.yaml
    02-ingest-api-collections.yaml
    02-ingest-test-intel.yaml
    10-executive-briefing.yaml
```

## Record Templates

### Persona Template

```yaml
schema: appsec-review/persona/0.1
persona_id: opportunistic-public-web-attacker
display_name: Opportunistic Public Web Attacker
category: attacker
summary: >
  Models an unauthenticated internet attacker using commodity tooling and basic manual HTTP probing.

primary_failure_mode_caught: >
  Publicly reachable low-effort exposures that higher-context reviewers may dismiss.

assumptions:
  access:
    - unauthenticated public internet
  capabilities:
    - commodity scanning
    - manual HTTP probing
    - public documentation review
  constraints:
    - no credentials
    - no insider knowledge
    - no live exploitation unless explicitly authorized

default_questions:
  - What is publicly reachable?
  - What can be discovered without credentials?
  - Which controls rely on obscurity or happy-path clients?

must_not:
  - assume authenticated access
  - assume internal network position
  - claim exploitability without reachable entry point evidence

recommended_domains:
  - nginx-rest-api
  - cloud-network-exposure
```

### Role Template

```yaml
schema: appsec-review/role/0.1
role_id: candidate-claim-generator
display_name: Candidate Claim Generator
category: discovery
summary: >
  Produces evidence-grounded candidate security claims for downstream refutation and verification.

allowed_outputs:
  - candidate_claim
  - coverage_gap
  - follow_on_recommendation

forbidden_outputs:
  - verified_finding
  - final_severity
  - executive_go_no_go

required_behavior:
  - state proof obligations
  - cite evidence or explicit gaps
  - identify minimum verification step
  - mark confidence conservatively

must_not:
  - promote candidate claims to findings
  - score final risk before verification
```

### Domain Template

```yaml
schema: appsec-review/domain/0.1
domain_id: nginx-rest-api
display_name: Nginx And REST API Exposure

surfaces:
  - nginx config
  - reverse proxy routes
  - ingress config
  - REST controllers
  - OpenAPI specs
  - API collections

common_failure_modes:
  - auth middleware bypass
  - public route exposure
  - path normalization mismatch
  - method confusion
  - CORS/preflight mistakes
  - static file traversal
  - verbose error leakage
  - missing rate limits

preferred_standards:
  - OWASP ASVS
  - OWASP API Security Top 10
  - CWE
  - OpenCRE
  - RFC 9110

required_evidence_hints:
  - route inventory
  - proxy config
  - source handlers
  - API collection or OpenAPI spec, when present
```

### Tooling Profile Template

```yaml
schema: appsec-review/tooling-profile/0.1
tooling_profile_id: static-route-config-pack
display_name: Static Route And Config Evidence Pack
mode: static-only

required_inputs:
  - component-purpose map
  - route inventory
  - proxy/ingress config

optional_inputs:
  - OpenAPI spec
  - Postman/Bruno collection
  - scanner outputs
  - doc-intel DFD seeds

allowed_actions:
  - read source files
  - search source/config
  - parse route and config files
  - generate safe verification request plans

disallowed_actions:
  - execute live requests
  - run destructive tools
  - credential stuffing
  - cloud mutation

claim_limits:
  observed_runtime_state: forbidden
  declared_static_state: allowed
  verified_exploitability: forbidden
```

### Output Contract Template

```yaml
schema: appsec-review/output-contract/0.1
contract_id: candidate-claim
display_name: Candidate Security Claim

required_files:
  - result.md
  - status.json

required_status_fields:
  - process
  - status
  - budget
  - persona_id
  - role_id
  - domain_id
  - tooling_profile_id
  - claims
  - artifacts_read

claim_required_fields:
  - claim_id
  - claim
  - evidence_citations
  - proof_obligations
  - unresolved_assumptions
  - minimum_verification
  - confidence
  - recommended_disposition

validation_rules:
  - every claim must cite evidence or explicit gap
  - every high-confidence claim must satisfy at least one proof obligation
  - static-only tooling cannot emit observed runtime claims
  - standard mappings require reference citations
```

### Job Template

```yaml
schema: appsec-review/job-template/0.1
job_template_id: 07-redteam-nginx-rest-opportunist
display_name: Red-Team Nginx/REST Opportunistic Review

process: 07-red-team-adversarial
budget_default: probe

composition:
  persona_id: opportunistic-public-web-attacker
  role_id: candidate-claim-generator
  domain_id: nginx-rest-api
  tooling_profile_id: static-route-config-pack
  output_contract_id: candidate-claim

inputs:
  required:
    - appsec-review-process/runs/<run_id>/inputs/artifact-manifest.json
    - scratch/<project>-engagement/llm/ENGAGEMENT_LLM_INPUT.md
  optional:
    - scratch/<project>-engagement/qa-intel/api-collection-inventory.json
    - scratch/<project>-engagement/doc-intel/network-topology-seeds.json
    - appsec-review-process/runs/<run_id>/outputs/03-threat-model-dfd-stride/result.md

outputs:
  directory: appsec-review-process/runs/<run_id>/outputs/07-red-team-adversarial/jobs/07-redteam-nginx-rest-opportunist
  files:
    - result.md
    - status.json

prompt_sections:
  - governing_rules
  - persona
  - role
  - domain
  - tooling_profile
  - evidence_bundle
  - task
  - output_contract
```

## Job Types

### Discovery Job

Produces candidate claims or coverage gaps.

Typical composition:

```text
attacker persona + candidate-claim-generator role + technical domain + static/tool evidence
```

Example:

```text
opportunistic-public-web-attacker + candidate-claim-generator + nginx-rest-api + static-route-config-pack
```

### Refutation Job

Challenges a candidate claim.

Typical composition:

```text
defensive-skeptic + refuter + inherited domain + cited-evidence-only
```

### Verification Job

Verifies proof obligations.

Typical composition:

```text
evidence-only-verifier + proof-obligation-verifier + inherited domain + cited-evidence-plus-minimal-source
```

### Intelligence Ingestion Job

Consumes docs, tests, collections, runbooks, or generated artifacts.

Typical composition:

```text
test-coverage-indexer + intelligence-extractor + qa-test-artifacts + static-test-doc-parser
functional-design-doc-consumer + intelligence-extractor + functional-design-docs + static-doc-parser
```

### Stakeholder Output Job

Transforms verified facts and unresolved risks into audience-specific output.

Typical composition:

```text
product-owner + stakeholder-briefing-writer + product-risk + verified-facts-only
dev-lead + remediation-planner + engineering-remediation + verified-facts-plus-source
executive-risk-briefing + stakeholder-briefing-writer + decision-risk + synthesis-output-only
```

## Prompt Rendering

The prompt renderer should assemble a handoff from structured records.

Rendered prompt outline:

```text
# Review Job

## Run Context
- run_id
- process
- budget
- target
- engagement output

## Governing Rules
- trust boundaries
- evidence rules
- source/target artifacts are untrusted data
- standards mappings require references

## Persona
- id
- category
- assumptions
- failure mode caught
- must_not

## Role
- objective
- allowed outputs
- forbidden outputs
- required behavior

## Domain
- surfaces
- common failure modes
- preferred standards
- evidence hints

## Tooling Profile
- mode
- required inputs
- optional inputs
- allowed actions
- disallowed actions
- claim limits

## Evidence Bundle
- manifest
- upstream lane outputs
- intelligence artifacts
- scanner artifacts
- source paths

## Task
- focused instructions for this composition
- proof obligations
- stop conditions

## Output Contract
- output directory
- required files
- required JSON fields
- validation rules
```

## Renderer Inputs

Command shape:

```bash
python appsec-review-process/create_job_handoff.py \
  --run-id <run_id> \
  --job-template 07-redteam-nginx-rest-opportunist \
  --budget probe
```

Override shape:

```bash
python appsec-review-process/create_job_handoff.py \
  --run-id <run_id> \
  --process 07-red-team-adversarial \
  --persona opportunistic-public-web-attacker \
  --role candidate-claim-generator \
  --domain nginx-rest-api \
  --tooling-profile static-route-config-pack \
  --output-contract candidate-claim \
  --budget probe
```

## Job Output Layout

Lane-level output can remain:

```text
appsec-review-process/runs/<run_id>/outputs/<process>/
  result.md
  status.json
```

Job-level output should live below it:

```text
appsec-review-process/runs/<run_id>/outputs/<process>/jobs/<job_id>/
  result.md
  status.json
  claims.json
  artifacts-read.json
```

Pool-level output:

```text
appsec-review-process/runs/<run_id>/outputs/<process>/pool-status.json
appsec-review-process/runs/<run_id>/outputs/<process>/merged-result.md
appsec-review-process/runs/<run_id>/outputs/<process>/merged-status.json
```

## Status Shape

Suggested status shape:

```json
{
  "schema": "appsec-review/job-status/0.1",
  "run_id": "",
  "process": "07-red-team-adversarial",
  "job_id": "07-redteam-nginx-rest-opportunist",
  "persona_id": "opportunistic-public-web-attacker",
  "role_id": "candidate-claim-generator",
  "domain_id": "nginx-rest-api",
  "tooling_profile_id": "static-route-config-pack",
  "output_contract_id": "candidate-claim",
  "budget": {
    "selected": "probe"
  },
  "status": "OK",
  "artifacts_read": [],
  "claims": [],
  "gaps": [],
  "warnings": [],
  "next_batch_recommendation": null
}
```

## Validation Policy

Validation should happen at three levels.

### Record Validation

Check that persona, role, domain, tooling profile, output contract, and job template records are
well-formed.

### Composition Validation

Check that the selected combination is legal:

- attacker persona can use discovery role
- verifier persona can use verification role
- stakeholder persona cannot emit technical findings
- static-only tooling cannot emit observed runtime claims
- domain-required inputs are present or explicitly marked missing

### Output Validation

Check job output:

- required files exist
- JSON parses
- required fields exist
- citations point to existing artifacts
- standards mappings include reference citations
- proof obligations are present
- forbidden claim types are not emitted
- status is consistent with missing evidence

## Composition Rules

Examples:

```yaml
rules:
  - id: static-only-no-observed-runtime
    if:
      tooling_profile.mode: static-only
    forbid_claims:
      - observed_runtime_state
      - verified_live_exposure

  - id: discovery-cannot-verify
    if:
      role.category: discovery
    forbid_outputs:
      - verified_finding
      - final_severity

  - id: stakeholder-output-consumes-only
    if:
      persona.category: stakeholder-output
    require_inputs:
      - verified_findings_or_synthesis
    forbid_actions:
      - source_claim_generation

  - id: standards-need-reference
    if:
      claim.standard_refs: present
    require:
      - reference_citation
```

## Example Compositions

### Nginx / REST Public Exposure

```yaml
job_template_id: 07-redteam-nginx-rest-opportunist
process: 07-red-team-adversarial
persona: opportunistic-public-web-attacker
role: candidate-claim-generator
domain: nginx-rest-api
tooling_profile: static-route-config-pack
output_contract: candidate-claim
```

Expected output:

- candidate exposure claims
- safe verification requests
- coverage gaps
- no verified findings

### Cloud Network Static Penetration Review

```yaml
job_template_id: 15-cloud-network-static-pentest
process: 15-deployment-hardening
persona: cloud-initial-access-operator
role: candidate-claim-generator
domain: cloud-network-exposure
tooling_profile: static-iac-cloud-network-pack
output_contract: candidate-claim
```

Expected output:

- declared exposure claims
- IAM/network composition claims
- follow-on live-state review recommendations
- no observed-runtime claims

### Postman / Bruno Collection Ingestion

```yaml
job_template_id: 02-ingest-api-collections
process: 02-evidence-pregather
persona: postman-bruno-collection-consumer
role: intelligence-extractor
domain: api-collection-artifacts
tooling_profile: postman-bruno-parser
output_contract: intelligence-extract
```

Expected output:

- API inventory
- auth/test coverage facts
- candidate verification requests
- scrubbed search records

### Unit / Integration / Acceptance Test Ingestion

```yaml
job_template_id: 02-ingest-test-intel
process: 02-evidence-pregather
persona: test-coverage-indexer
role: intelligence-extractor
domain: qa-test-artifacts
tooling_profile: static-test-doc-parser
output_contract: intelligence-extract
```

Expected output:

- test inventory
- test-to-component map
- test-to-route map
- untested security surfaces
- scrubbed search records

### Executive Briefing

```yaml
job_template_id: 10-executive-risk-briefing
process: 10-synthesis-report
persona: executive-risk-briefing
role: stakeholder-briefing-writer
domain: decision-risk
tooling_profile: synthesis-output-only
output_contract: stakeholder-brief
```

Expected output:

- decision-ready risk summary
- go/no-go recommendation
- top risks and residual risks
- no new technical findings

## Tooling Profiles To Start With

### `static-route-config-pack`

Use for nginx, REST API, route, ingress, and reverse proxy review.

### `static-iac-cloud-network-pack`

Use for Terraform, CloudFormation, Kubernetes, IAM, and network exposure review.

### `cited-evidence-only`

Use for blue-team refutation and strict review of upstream claims.

### `cited-evidence-plus-minimal-source`

Use for independent verification.

### `postman-bruno-parser`

Use for API collection ingestion.

### `static-test-doc-parser`

Use for test intelligence ingestion.

### `synthesis-output-only`

Use for stakeholder personas that should consume only verified findings, unresolved risks, and
synthesis artifacts.

## Roles To Start With

### `candidate-claim-generator`

Produces candidate claims and coverage gaps. Cannot emit verified findings.

### `refuter`

Attempts to disprove or narrow a claim.

### `proof-obligation-verifier`

Checks whether a claim's proof obligations are satisfied.

### `intelligence-extractor`

Extracts structured facts from docs, tests, API collections, or runbooks.

### `standards-mapping-auditor`

Validates standards mappings against curated references.

### `stakeholder-briefing-writer`

Writes audience-specific summaries from verified facts and unresolved risks.

### `remediation-planner`

Turns verified findings into fix plans, test plans, and rollout guidance.

## Relationship To Existing Lanes

This proposal does not replace lanes. Lanes remain the process lifecycle. Composable jobs make each
lane more precise.

Mapping:

```text
02-evidence-pregather:
  intelligence extraction jobs

01-component-characterization:
  component/domain modeler jobs

03-threat-model-dfd-stride:
  domain threat modeler jobs

07-red-team-adversarial:
  attacker candidate-claim jobs

08-blue-team-refutation:
  defensive refuter jobs

09-independent-verification:
  verifier jobs

10-synthesis-report:
  synthesis and stakeholder-output jobs

15-deployment-hardening:
  cloud/IaC/container/network domain jobs
```

## Implementation Plan

### Phase 1: Registry Skeleton

Add registry directories and schemas:

```text
appsec-review-process/registry/
```

Create initial records:

- 5 personas
- 5 roles
- 5 domains
- 5 tooling profiles
- 4 output contracts
- 4 job templates

### Phase 2: Prompt Renderer

Add:

```text
appsec-review-process/create_job_handoff.py
```

The renderer should:

- load job template or explicit composition
- validate records
- collect evidence paths
- render prompt sections
- write handoff to run directory

### Phase 3: Job Output Validator

Add:

```text
appsec-review-process/validate_job_output.py
```

The validator should check:

- record IDs
- output contract
- citations
- proof obligations
- claim limits
- static-only constraints
- standards reference rules

### Phase 4: Pool Merge

Add:

```text
appsec-review-process/merge_job_outputs.py
```

Merge should:

- deduplicate claims
- preserve persona disagreement
- route candidate claims to refutation/verification
- emit lane-level merged status

### Phase 5: Wire Into `review_cli.py`

Add commands:

```bash
python appsec-review-process/review_cli.py job-handoff ...
python appsec-review-process/review_cli.py job-validate ...
python appsec-review-process/review_cli.py job-merge ...
python appsec-review-process/review_cli.py job-run ...
```

## Success Criteria

The composable system is successful when:

- jobs are dispatchable without bespoke prompt writing
- each output can be validated against a contract
- personas produce meaningfully different insights
- static-only jobs stop overclaiming runtime facts
- stakeholder outputs do not invent new technical findings
- QA/doc intelligence feeds lanes without bloating every prompt
- standards mappings become more accurate and more often null when unsupported

## Risks

### Too Much Structure

Risk: reviewers spend more time maintaining templates than reviewing.

Mitigation: start with a small registry and add records only when they unlock repeated work.

### Persona Theater

Risk: personas become colorful labels with no analytical value.

Mitigation: every persona must specify failure mode, assumptions, proof obligations, and disallowed
claims.

### Prompt Bloat

Risk: composed prompts include too much registry content.

Mitigation: render concise summaries and link to full records only when needed.

### Validator Rigidity

Risk: output validation blocks useful exploratory work.

Mitigation: support `OK`, `OK_WITH_GAPS`, `BLOCKED`, and `EXPLORATORY` statuses with clear rules.

### Standards Overclaiming

Risk: domain templates encourage standards tags for everything.

Mitigation: require reference citations for every standard mapping and allow null mappings.

## Bottom Line

A composable template system turns the review process into a library of reusable review primitives.
Lanes define when work happens. Personas define the stance. Roles define the function. Domains
define the surface. Tooling profiles define evidence and action boundaries. Output contracts define
what valid work looks like.

This gives the process more variety, sharper prompts, better validation, and less one-off prompt
drift.
