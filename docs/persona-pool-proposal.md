# Proposal: Composable AppSec Persona Pools

## Purpose

This proposal defines a persona-pool model for the AppSec review process. The goal is to get the
benefit of OWASP-style security skills and specialist agents while making the roles more varied,
more testable, and more directly tied to evidence.

The central idea is that a useful review persona is not just a personality or attacker archetype.
It is a composable review unit:

```text
persona = worldview / failure model
domain = technical surface
tooling = allowed evidence and actions
contract = output schema and proof obligations
```

This gives the process more coverage without turning reviews into vague roleplay. A persona should
make the review better because it catches a specific class of failures that other personas tend to
miss.

## Problem

The current process has strong lanes and good evidence discipline, but its personas are still
mostly embedded inside lane prose. This creates several limitations:

- Personas are hard to reuse across lanes.
- Technical domain scope and attacker mindset are blended together.
- Tooling permissions are not always explicit per persona.
- It is difficult to compare persona outputs or validate that a persona did its job.
- Adding a new role requires writing another bespoke prompt rather than composing known pieces.

External projects such as OWASP Secure Agent Playbook show the value of skill and agent libraries,
but many of those roles remain broad. This process can go further by making personas structured,
composable, and evidence-bound.

## Design Principles

1. **Personas catch failure modes.**
   Every persona must state the specific review blind spot it is designed to expose.

2. **Attacker archetype is not enough.**
   "Script kiddie" or "cloud pentester" is useful shorthand, but the runnable definition must
   include access, capabilities, assumptions, evidence, and proof obligations.

3. **Domain and persona are separate axes.**
   The same attacker model can review REST APIs, nginx, Kubernetes, or cloud IAM. The same domain can
   be reviewed by an opportunistic attacker, malicious tenant, insider, or defensive skeptic.

4. **Tooling is explicit.**
   Each composed review job must state which evidence sources are required, which tools are allowed,
   and whether the job is static-only, live-safe, or authorized-active.

5. **Verification is intentionally boring.**
   Discovery personas can be creative. Verification personas should be strict, evidence-only, and
   resistant to narrative pull from the discoverer.

6. **Standards are retrieved, not remembered.**
   CWE, ASVS, MASVS, NIST, ATT&CK, RFC, CIS, DISA, and OpenCRE mappings should be cited only when
   supported by curated reference data, tool output, or retrieved standard context.

## Model

The review job should be composed from four records.

### 1. Persona

The persona defines the worldview, attacker capability, or defensive posture.

Example categories:

- attacker personas
- defender/refuter personas
- verifier personas
- completeness/audit personas
- domain modeler personas

Persona fields:

```yaml
persona_id: opportunistic-public-web-attacker
display_name: Opportunistic Public Web Attacker
category: attacker
failure_mode_caught: Publicly reachable low-effort exposures that higher-context reviewers may dismiss.
attacker_model:
  access: unauthenticated public internet
  skill: commodity tooling plus basic manual HTTP probing
  time_budget: hours, not weeks
  credentials: none
  insider_knowledge: none beyond public behavior and visible source/config evidence
review_posture:
  assume:
    - exposed routes will be probed
    - default files and verbose errors will be discovered
    - weak rate limits will be abused
  do_not_assume:
    - valid user credentials
    - source-code secrecy
    - live cloud access
```

### 2. Domain

The domain defines the technical surface under review.

Domain examples:

- nginx / reverse proxy / ingress
- REST API / OpenAPI
- Kubernetes
- Terraform / cloud IAM
- Dockerfile / container image
- CI/CD
- native C/C++
- mobile Android/iOS
- auth/session/JWT/OIDC
- data storage / queues / logs
- LLM/agent/MCP/RAG

Domain fields:

```yaml
domain_id: nginx-rest-api
display_name: Nginx and REST API Exposure
surfaces:
  - nginx config
  - ingress and reverse proxy routing
  - REST route inventory
  - OpenAPI specifications
  - static file serving
common_failure_modes:
  - public route accidentally bypasses auth middleware
  - path normalization mismatch between proxy and app
  - method confusion between proxy rules and backend handlers
  - permissive CORS or preflight behavior
  - nginx alias/root traversal
  - verbose errors expose framework or internal paths
  - missing rate limits on auth, search, export, or expensive endpoints
standards_context:
  preferred:
    - CWE
    - OWASP ASVS
    - OWASP API Security Top 10
    - OpenCRE
  optional:
    - RFC 9110 HTTP semantics
    - RFC 6750 bearer token usage
```

### 3. Tooling And Evidence Contract

The tooling contract defines what the persona may read or do.

```yaml
tooling_profile_id: static-route-config-pack
mode: static-only
required_evidence:
  - component-purpose map
  - route/API inventory
  - nginx/ingress/reverse-proxy config
  - relevant scanner outputs
optional_evidence:
  - OpenCRE lookup results
  - ASVS/API Top 10 references
  - prior red-team outputs
allowed_actions:
  - source search
  - config parsing
  - route-to-control comparison
  - safe verification request design
disallowed_actions:
  - live exploitation
  - destructive requests
  - credential stuffing
  - cloud API mutation
```

Tooling profiles should be reusable. For example, the same `static-route-config-pack` could be used
by an opportunistic attacker, defensive skeptic, or completeness auditor.

### 4. Output Contract

Every persona output should use a shared claim/finding shape, with persona-specific additions only
where needed.

Minimum output fields:

```yaml
claim_id: string
persona_id: string
domain_id: string
classification_taxonomy: string
classification: string
claim: string
attacker_capability: string
affected_component: string
attack_path: string
evidence_citations:
  - source_type: tool_output | source_file | upstream_lane | manual_diagnostic | reference_data
    path: string
    line_range: string | null
    tool_name: string | null
    tool_rule_id: string | null
    content_hash: string | null
proof_obligations:
  - string
counterevidence_checked:
  - string
unresolved_assumptions:
  - string
minimum_verification:
  type: source_review | static_check | safe_request | dynamic_test | live_state_review | human_decision
  description: string
confidence: low | medium | high
recommended_disposition: candidate | refute | verify | follow_on_required | cannot_verify
```

## Example Composition

### Opportunistic Nginx / REST API Attacker

```yaml
job_id: 07-redteam-nginx-rest-opportunist
lane: 07-red-team-adversarial
persona: opportunistic-public-web-attacker
domain: nginx-rest-api
tooling_profile: static-route-config-pack
budget: probe
focus:
  - exposed unauthenticated endpoints
  - default files or admin panels
  - CORS mistakes
  - missing rate limits
  - verbose errors
  - path traversal or alias/root mistakes
  - auth bypass by method, path, or header confusion
proof_obligations:
  - identify a public entry point
  - show why auth or another control is absent, bypassed, or uncertain
  - cite route/config/source evidence
  - state the minimum safe verification request
must_not:
  - assume authenticated access
  - claim exploitability without a reachable public route
  - use live exploit attempts unless explicitly authorized
```

### Cloud Config Network Penetration Tester

```yaml
job_id: 15-cloud-network-pentest-static
lane: 15-deployment-hardening
persona: cloud-initial-access-operator
domain: cloud-network-exposure
tooling_profile: static-iac-cloud-network-pack
budget: standard
focus:
  - public ingress
  - open security groups
  - internet-facing load balancers
  - exposed admin ports
  - permissive egress that enables callback or exfiltration
  - trust boundary mismatch between declared exposure and application role
proof_obligations:
  - identify declared exposure from IaC/config evidence
  - map exposed resource to component or workload when possible
  - cite scanner and source evidence
  - distinguish DECLARED_EXPOSURE from OBSERVED_EXPOSURE
must_not:
  - claim runtime exposure without live-state evidence
  - assume cloud resources exist just because IaC declares them
  - fill CIS/NIST/DISA mappings from memory
```

### Malicious Tenant

```yaml
job_id: 07-redteam-malicious-tenant-api
lane: 07-red-team-adversarial
persona: malicious-tenant
domain: rest-api-authz
tooling_profile: static-api-authz-pack
budget: standard
focus:
  - IDOR/BOLA
  - cross-tenant query predicates
  - object ownership checks
  - tenant-scoped caches
  - export/report endpoints
  - async job result retrieval
proof_obligations:
  - identify tenant/user-controlled object reference
  - identify missing or uncertain ownership check
  - state required authenticated role
  - provide minimum verification request pair
must_not:
  - report IDOR if object ownership is enforced in a cited shared helper
  - confuse authentication with authorization
```

### Build/Release Insider

```yaml
job_id: 07-redteam-build-insider
lane: 07-red-team-adversarial
persona: insider-developer
domain: ci-cd-build-provenance
tooling_profile: static-ci-provenance-pack
budget: standard
focus:
  - workflow permission drift
  - untrusted PR code reaching trusted deploy jobs
  - mutable action/image refs
  - artifact substitution
  - generated code not reviewed
  - build scripts that alter security controls
proof_obligations:
  - identify actor with access path
  - identify workflow/build step where trust changes
  - cite config/source evidence
  - state impact on shipped artifact or secrets
must_not:
  - assume maintainer compromise unless the scenario explicitly models insider risk
  - label a supply-chain hypothesis as verified without provenance evidence
```

### Defensive Skeptic

```yaml
job_id: 08-blue-skeptic-any-domain
lane: 08-blue-team-refutation
persona: defensive-skeptic
domain: inherited-from-claim
tooling_profile: cited-evidence-only
budget: probe
focus:
  - missing prerequisites
  - compensating controls
  - trusted vs untrusted source confusion
  - unreachable code paths
  - scanner false positives
proof_obligations:
  - address each upstream proof obligation
  - cite refuting or narrowing evidence
  - state whether the claim is refuted, narrowed, or still plausible
must_not:
  - rely on benign-vendor assumptions
  - mark a claim refuted because one source is weak if another source supports it
```

### Evidence-Only Verifier

```yaml
job_id: 09-verifier-evidence-only
lane: 09-independent-verification
persona: evidence-only-verifier
domain: inherited-from-claim
tooling_profile: cited-evidence-plus-minimal-source
budget: probe
focus:
  - proof obligations
  - source-to-sink reachability
  - control effectiveness
  - confidence and verdict
proof_obligations:
  - independently re-derive the claim from cited evidence
  - inspect source/config only as needed to confirm or refute
  - record unresolved assumptions explicitly
must_not:
  - read discoverer narrative except for IDs and cited locations
  - invent exploitability beyond evidence
  - use attacker persona framing
```

## Suggested Persona Registry Layout

Create a tracked registry under:

```text
appsec-review-process/personas/
  README.md
  persona-schema.json
  domains/
    nginx-rest-api.yaml
    cloud-network-exposure.yaml
    terraform-iam.yaml
    kubernetes-workload-hardening.yaml
    ci-cd-build-provenance.yaml
    native-parser-memory.yaml
    mobile-platform.yaml
    llm-agent-mcp.yaml
  personas/
    opportunistic-public-web-attacker.yaml
    authenticated-low-priv-user.yaml
    malicious-tenant.yaml
    cloud-initial-access-operator.yaml
    supply-chain-attacker.yaml
    insider-developer.yaml
    exploit-engineer.yaml
    privacy-abuse-reviewer.yaml
    defensive-skeptic.yaml
    completeness-auditor.yaml
    evidence-only-verifier.yaml
  tooling-profiles/
    static-route-config-pack.yaml
    static-iac-cloud-network-pack.yaml
    static-api-authz-pack.yaml
    cited-evidence-only.yaml
    cited-evidence-plus-minimal-source.yaml
  jobs/
    examples/
      07-redteam-nginx-rest-opportunist.yaml
      15-cloud-network-pentest-static.yaml
```

The registry should be data-first. Prompts should be rendered from registry records plus lane
templates, not hand-written from scratch for every new persona.

## Lane Integration

### 03 Threat Model / DFD / STRIDE

Use domain modeler personas:

- API trust-boundary modeler
- cloud/network exposure modeler
- data/privacy flow modeler
- agent/tool trust-boundary modeler
- native/parser input modeler

Outputs should include trust-boundary facts that red-team personas can consume.

### 07 Red Team / Adversarial

Use attacker personas:

- opportunistic-public-web-attacker
- authenticated-low-priv-user
- malicious-tenant
- cloud-initial-access-operator
- supply-chain-attacker
- insider-developer
- exploit-engineer
- privacy-abuse-reviewer

Outputs should be candidate claims, not final findings.

### 08 Blue Team / Refutation

Use defensive personas:

- defensive-skeptic
- control-owner
- incident-responder
- compensating-control-reviewer

Outputs should refute, narrow, or preserve candidate claims.

### 09 Independent Verification

Use strict verifier personas:

- evidence-only-verifier
- source-grounded-verifier
- executed-test-verifier, only when execution is authorized and available

The verifier should not inherit the original attacker persona. It should verify proof obligations.

### 10 Synthesis

Use synthesis and completeness personas:

- synthesis-integrator
- completeness-auditor
- standards-mapping-auditor
- decision-risk-reviewer

Outputs should preserve dissent and distinguish verified findings from unresolved risks.

### 15 Deployment Hardening

Continue the existing persona-pool pilot, but split role, domain, and tooling more explicitly:

- cloud-network-pentest-static + cloud-network-exposure + static IaC scanner pack
- terraform-iam-reviewer + terraform-iam + checkov/trivy/tfsec/semgrep pack
- k8s-workload-hardening-reviewer + kubernetes-workload-hardening + kube-linter pack
- container-source-auditor + dockerfile-base-image + hadolint/base-image pack
- exposure-composition-modeler + cross-domain exposure + sibling persona outputs

## Standards And Reference Retrieval

Personas should not rely on memory for standards IDs. Use a standards retrieval layer:

- OpenCRE for CWE to CRE/ASVS/NIST/WSTG mappings
- local curated references for DISA, CIS, EOL, and organization-specific rules
- scanner-provided standard mappings when available
- RFC references only when the reviewed code/config actually implements the relevant protocol

Rule:

```text
If a standard mapping is not supported by retrieved reference data, scanner evidence, or curated
local reference data, leave the field null and explain why.
```

## Prompt Rendering Pattern

A rendered persona handoff should have this shape:

```text
# Persona Review Job

## Run
- run_id:
- lane:
- budget:

## Persona
- persona_id:
- attacker/defender/verifier model:
- failure mode caught:

## Domain
- domain_id:
- surfaces:
- common failure modes:

## Tooling And Evidence
- mode:
- required evidence:
- optional evidence:
- allowed actions:
- disallowed actions:

## Standards Context
- retrieved references:
- mapping rules:

## Task
- focus:
- proof obligations:
- must_not:

## Output Contract
- write result.md
- write status.json
- emit findings[] / claims[] using schema
```

## Validation Requirements

The harness should reject a persona output marked `OK` when:

- required evidence was missing and no `BLOCKED` status was returned
- no artifacts were cited
- a high-confidence claim lacks proof obligations
- a standard ID is present without a reference citation
- an attacker persona reports a verified finding instead of a candidate claim
- a verifier uses discoverer narrative as evidence
- a static-only tooling profile produces runtime/observed claims

## Implementation Plan

### Phase 1: Data Model

1. Add `appsec-review-process/personas/persona-schema.json`.
2. Add schema files for domains and tooling profiles.
3. Add 5 initial personas:
   - opportunistic-public-web-attacker
   - malicious-tenant
   - cloud-initial-access-operator
   - defensive-skeptic
   - evidence-only-verifier
4. Add 3 initial domains:
   - nginx-rest-api
   - cloud-network-exposure
   - rest-api-authz

### Phase 2: Handoff Rendering

1. Extend `create_handoff.py` or add `create_persona_handoff.py`.
2. Accept:
   - `--process`
   - `--persona`
   - `--domain`
   - `--tooling-profile`
   - `--budget`
3. Render a composed handoff into:

```text
appsec-review-process/runs/<run_id>/handoffs/<process>/<persona_id>--<domain_id>.md
```

### Phase 3: Output Validation

1. Extend lane status schema with `claims[]` or reuse `findings[]` with candidate dispositions.
2. Add validation for persona/domain/tooling IDs.
3. Add static-only vs observed/runtime claim checks.
4. Add standard mapping citation checks.

### Phase 4: Pilot

Pilot two jobs:

1. `opportunistic-public-web-attacker + nginx-rest-api`
2. `cloud-initial-access-operator + cloud-network-exposure`

Use a small target with real nginx/API or IaC evidence. Compare results against the current
single-lane red-team output.

### Phase 5: Pool Merge

Add a merge step that:

- deduplicates claims by root cause and evidence path
- preserves persona-specific disagreement
- records which personas independently found the same issue
- routes candidate claims to blue-team and verification

## Success Criteria

The persona-pool model is working if it produces:

- fewer generic findings
- more explicit proof obligations
- better coverage of attacker capability differences
- fewer standards overclaims
- more useful verification tasks
- clearer distinctions between candidate, refuted, verified, and unresolved claims
- repeatable outputs from the same persona/domain/tooling composition

## Risks

### Persona Theater

Risk: Personas become colorful names without better analysis.

Mitigation: Require failure mode, attacker capability, proof obligations, and output validation.

### Prompt Bloat

Risk: Composed prompts become too large.

Mitigation: Keep personas short. Retrieve domain references and standards selectively.

### Standards Overclaiming

Risk: Personas attach ASVS/NIST/ATT&CK IDs because they sound right.

Mitigation: Require reference citations for every standards mapping.

### False Confidence From Static Evidence

Risk: Static-only personas claim runtime state.

Mitigation: Tooling profiles must declare static-only/live-safe/authorized-active mode. Validators
must reject observed/runtime claims from static-only jobs.

### Too Many Personas

Risk: The process fans out too widely and becomes expensive or hard to synthesize.

Mitigation: Start with a small registry and measure yield. Add personas only when they catch a real
missed failure mode.

## Recommended Initial Persona Set

Start with these because they cover different failure models:

1. `opportunistic-public-web-attacker`
   - catches public low-effort exposure and route/config mistakes

2. `malicious-tenant`
   - catches multi-tenant and object authorization failures

3. `cloud-initial-access-operator`
   - catches IaC/network/IAM paths that lead to initial access

4. `insider-developer`
   - catches CI/CD, build provenance, and malicious-vendor scenarios

5. `supply-chain-attacker`
   - catches dependency, package, workflow, and artifact substitution issues

6. `defensive-skeptic`
   - catches overclaims, false positives, and missing prerequisites

7. `evidence-only-verifier`
   - confirms or refutes candidate claims without inheriting red-team narrative

8. `completeness-auditor`
   - asks what important surface no persona reviewed

## Bottom Line

The persona-pool should combine the best parts of OWASP-style skills with the stronger evidence
discipline of this process. The useful abstraction is not "many personalities." It is a controlled
composition of attacker/defender worldview, technical domain, tooling permissions, and proof
obligations.

That gives the process more imagination without giving up repeatability.
