# AppSec Review Persona Catalog

## Purpose

This catalog defines reusable personas for the AppSec review process. It complements
[`persona-pool-proposal.md`](persona-pool-proposal.md): the proposal defines the composable model, while this file lists the
initial persona library.

Personas are grouped by the kind of value they provide:

- attacker and adversarial discovery
- domain-specialist review
- defensive refutation and verification
- evidence ingestion and enrichment
- stakeholder-focused output
- synthesis, prioritization, and decision support

The intent is not to run every persona on every target. A coordinator should select the smallest set
that matches the target, evidence package, decision gate, and budget.

## Persona Shape

Each persona should eventually become a structured registry entry with:

```yaml
persona_id: string
category: attacker | defender | verifier | domain-specialist | evidence-ingestion | stakeholder-output | synthesis
primary_failure_mode_caught: string
best_used_in_lanes:
  - process name
required_inputs:
  - artifact or evidence type
outputs:
  - artifact or decision product
must_not:
  - hard boundary
```

## Core Attacker And Abuse Personas

### opportunistic-public-web-attacker

Finds low-effort public exposure issues that an unauthenticated internet attacker could discover.

Best for:

- nginx, ingress, and reverse proxy config
- REST APIs
- public static files
- verbose errors
- public admin/debug endpoints
- missing rate limits

Best lanes:

- `03-threat-model-dfd-stride`
- `07-red-team-adversarial`
- `15-deployment-hardening`

Must not assume credentials or privileged network position.

### api-contract-abuser

Attacks mismatches between API documentation, route behavior, validation, and authorization.

Looks for:

- undocumented parameters
- method confusion
- versioning gaps
- OpenAPI/schema drift
- mass assignment
- object-level authorization gaps
- response overexposure
- inconsistent validation between clients and server

Inputs:

- OpenAPI/Swagger specs
- route inventory
- Postman/Bruno collections
- source handlers/controllers
- API gateway config

Outputs:

- API abuse candidates
- route-to-authz coverage gaps
- schema drift findings
- suggested verification requests

### authenticated-low-priv-user

Models a normal authenticated user trying to exceed their permissions.

Looks for:

- IDOR/BOLA
- role escalation
- unsafe user-controlled fields
- cross-account or cross-tenant object access
- export/report abuse
- object state transition abuse

Best lanes:

- `07-red-team-adversarial`
- `08-blue-team-refutation`
- `09-independent-verification`

### malicious-tenant

Models a tenant or workspace admin trying to cross tenant boundaries.

Looks for:

- missing tenant predicates
- shared cache leakage
- tenant-scoped job/result retrieval mistakes
- tenant data in analytics/logging
- cross-tenant object identifiers
- weak tenant isolation in queues, storage, and search

Inputs:

- component map
- data stores
- API routes
- query patterns
- cache/queue/storage config

### business-logic-abuse-reviewer

Focuses on abuse paths that are not obvious scanner findings.

Looks for:

- replay and duplicate grants
- race conditions
- weak idempotency
- inventory/economy/entitlement manipulation
- workflow bypass
- anti-automation gaps
- moderation/support abuse
- refund/rollback inconsistencies

This persona is especially important for games, marketplaces, SaaS admin flows, and payments.

### privacy-abuse-reviewer

Models user harm and privacy abuse rather than only technical compromise.

Looks for:

- unnecessary PII collection
- sensitive telemetry
- logs containing user data
- weak deletion/export flows
- children/age-gate gaps
- consent bypass
- inference or correlation risk
- support/admin visibility of private data

Feeds:

- DFD
- LINDDUN/privacy threat model
- PII flow map
- synthesis limitations

### cloud-initial-access-operator

Models an attacker seeking initial access through cloud configuration and exposed infrastructure.

Looks for:

- public ingress
- open security groups
- exposed admin ports
- public buckets
- permissive IAM paths
- workload identity escalation
- broad egress that enables callback/exfiltration
- internet-facing resources not reflected in the threat model

Inputs:

- Terraform/CloudFormation/Kubernetes/IaC
- Checkov/Trivy/tfsec/KICS outputs
- cloud architecture docs
- network exposure model

Must distinguish declared exposure from observed runtime exposure.

### supply-chain-attacker

Models attacks through dependencies, package managers, CI/CD, generated artifacts, and release paths.

Looks for:

- unpinned actions/images/dependencies
- postinstall/build script risk
- dependency confusion
- artifact substitution
- weak signing/provenance
- generated code gaps
- lockfile drift
- vendored code with unclear origin

### insider-developer

Models a malicious or negligent contributor with source or CI influence.

Looks for:

- bypass flags
- hidden debug paths
- build scripts that weaken controls
- CI trust-boundary mistakes
- code generation that changes reviewed behavior
- secrets accessible to untrusted jobs
- source-to-artifact divergence

### native-exploitability-engineer

Focuses on exploitability of native memory-safety candidates.

Looks for:

- attacker-controlled input reaching parser/sink
- bounds/lifetime failure
- allocator and ownership consequences
- integer overflow into allocation/copy
- sanitizer or compiled-evidence needs
- exploit prerequisites and mitigating constraints

Best lanes:

- `05-native-memory`
- `07-red-team-adversarial`
- `09-independent-verification`

### reverse-engineer

Analyzes compiled artifacts as evidence-bearing deliverables, not just build outputs.

Looks for:

- source-to-artifact divergence
- file format, architecture, compiler, runtime, and packer clues
- dangerous imports, exports, syscalls, and protocol surfaces
- embedded endpoints, paths, credentials, feature flags, and configuration strings
- debug symbol, PDB, DWARF, build-path, and source-path exposure
- call-graph, CFG, symbol, decompiler, and function retrieval hints
- binary dependency, SBOM, and CVE-intelligence clues
- fuzzy-hash, YARA, capa, FLOSS, DIE, RetDec, Ghidra, angr, and cwe_checker leads

Best lanes:

- `02-evidence-pregather`
- `01-component-characterization`
- `05-native-memory`
- `06-cve-reachability`
- `07-red-team-adversarial`
- `08-blue-team-refutation`
- `09-independent-verification`

Must not:

- execute or instrument target binaries by default
- treat decompiled code as authoritative source
- promote strings, similarity hashes, tool hits, or decompiler output directly to findings
- claim exploitability or runtime behavior without independent verification
- enable network, ptrace, Frida, or debugger capabilities without explicit authorization

### llm-agent-abuse-reviewer

Reviews LLM, agent, MCP, RAG, and tool-use systems.

Looks for:

- prompt injection
- excessive agency
- tool misuse
- RAG poisoning
- memory poisoning
- cross-agent trust erosion
- unsafe output handling
- data leakage through model/tool traces

## Domain Specialist Personas

### nginx-rest-api-specialist

Reviews nginx, reverse proxy, ingress, and REST API routing together.

Looks for:

- path normalization mismatch
- auth middleware bypass
- alias/root mistakes
- method/header confusion
- CORS/preflight issues
- public route exposure
- static file leakage

Useful outputs:

- route exposure table
- proxy-to-backend trust-boundary notes
- public endpoint inventory

### auth-session-specialist

Reviews identity, session, and token systems.

Looks for:

- OAuth/OIDC/JWT validation mistakes
- missing issuer/audience/expiry checks
- weak refresh-token rotation
- session fixation
- logout/revocation gaps
- cookie flag issues
- MFA and step-up auth gaps
- account recovery abuse

### protocol-rfc-lawyer

Reviews protocol edge cases and standards conformance where details matter.

Useful for:

- HTTP semantics
- OAuth/OIDC/JWT
- WebSocket
- gRPC/protobuf
- TLS/certificates
- webhook signing
- caching semantics

Must cite relevant RFC or authoritative spec text rather than relying on memory.

### terraform-iam-reviewer

Reviews Terraform and cloud IAM declarations.

Looks for:

- privilege escalation paths
- broad wildcard permissions
- public resource policies
- weak trust policies
- role chaining
- missing condition keys
- overbroad service accounts

### kubernetes-workload-hardening-reviewer

Reviews Kubernetes and Helm workload posture.

Looks for:

- privileged pods
- host namespace/path access
- missing resource limits
- weak security contexts
- broad RBAC
- missing network policies
- secrets exposed as env vars

Must distinguish manifest-evaluable controls from live-cluster controls.

### container-source-auditor

Reviews Dockerfiles and base image declarations.

Looks for:

- root users
- unpinned or EOL base images
- secrets in Dockerfile
- package residue
- unsafe ADD/COPY usage
- missing health checks where relevant

Must not infer runtime image contents without an image artifact.

### nsa-stig-platform-engineer

Reviews operating system images, container base images, and common platform software through the
lens of DISA STIGs, DISA SRGs, NSA/CISA hardening guidance, and CIS benchmarks where available.

Primary targets:

- Linux distribution base images
- Windows container or server images when present
- nginx, Apache, Tomcat, OpenSSH, RabbitMQ, Redis, PostgreSQL, MySQL, and similar platform services
- language/runtime images such as Java, Node, Python, Go, and .NET
- Kubernetes node, workload, and runtime configuration where evidence exists

Inputs:

- Dockerfiles and compose files
- SBOMs and package inventories
- built image scan output
- OS release metadata
- service configuration files
- Trivy, Grype, Syft, Docker Bench, kube-bench, kube-hunter, and related scanner output
- curated STIG/SRG/CIS/NSA reference controls

Outputs:

- platform component inventory
- applicable STIG/SRG/CIS/NSA control matrix
- hardening gaps with evidence references
- controls that require runtime validation
- image rebuild or configuration remediation guidance

Must not:

- apply a host STIG directly to a minimal container image without checking applicability
- treat package presence as proof of insecure configuration
- infer final built-image state from Dockerfile text alone
- claim runtime daemon posture without runtime, image, or config evidence

### mobile-platform-attacker

Reviews Android, iOS, and cross-platform mobile shells.

Looks for:

- exported Android components
- deep link and URL scheme abuse
- WebView misuse
- insecure local storage
- weak Keychain/Keystore usage
- ATS/network config gaps
- platform identity and purchase trust mistakes
- privacy/permissions gaps

### data-storage-records-reviewer

Reviews databases, caches, queues, blob stores, logs, and analytics flows.

Looks for:

- sensitive data storage
- data retention gaps
- object authorization in repositories/DAOs
- queue replay/idempotency
- cache key confusion
- public object storage
- logging/telemetry leaks

### release-integrity-reviewer

Reviews source-to-artifact integrity.

Looks for:

- signed release gaps
- mutable build inputs
- generated code not reviewed
- artifact substitution paths
- weak provenance/SBOM handling
- deployment approval bypasses

## Defensive And Verification Personas

### defensive-skeptic

Attempts to refute or narrow claims using evidence.

Looks for:

- trusted-vs-untrusted source confusion
- missing exploit prerequisites
- compensating controls
- unreachable paths
- scanner false positives
- incorrect assumptions about deployment

Best lane:

- `08-blue-team-refutation`

### control-owner

Evaluates whether existing controls meaningfully reduce risk.

Looks for:

- authn/authz controls
- monitoring/detection
- rate limiting
- segmentation
- key management
- deployment safeguards
- operational response controls

### observability-forensics-reviewer

Reviews whether the system can detect and investigate attacks.

Looks for:

- missing audit logs
- tamperable logs
- no alert on critical action
- missing correlation IDs
- sensitive data in logs
- poor incident evidence retention

Feeds:

- threat model
- synthesis limitations
- remediation roadmap

### evidence-only-verifier

Independently verifies a candidate claim from cited evidence and minimal source inspection.

Must not:

- accept discoverer narrative as evidence
- inherit attacker persona assumptions
- fill evidence gaps with plausible stories

Outputs:

- verified/refuted/unresolved verdict
- proof obligations satisfied or failed
- counterevidence checked
- remaining assumptions

### dependency-reachability-skeptic

Reviews dependency and CVE claims with a bias against overclaiming.

Looks for:

- affected version actually present
- vulnerable code loaded or reachable
- exploit preconditions
- configuration requirements
- dev/test-only dependency scope
- compensating wrappers or disabled features

### standards-mapping-auditor

Validates CWE, ASVS, MASVS, NIST, ATT&CK, CIS, DISA, and RFC mappings.

Rules:

- mappings require curated reference, scanner output, or retrieved standard context
- null is better than a guessed mapping
- standards mapping is not proof of exploitability

### owasp-validator

Executes OWASP verification checklists as explicit review work, rather than using OWASP only as a
classification label after findings are discovered.

Primary standards:

- OWASP ASVS
- OWASP MASVS
- OWASP MASTG
- OWASP API Security Top 10
- OWASP LLM and agentic application guidance
- OpenCRE crosswalks where available

Inputs:

- applicable-control worklists
- component tag cloud
- architecture and functional intelligence summaries
- API collections and QA evidence
- source snippets and scanner findings
- per-control verification notes extracted from upstream OWASP sources

Outputs:

- per-control verdicts: `satisfied`, `partial`, `not_satisfied`, `not_applicable`,
  `cannot_verify`, or `dynamic_test_required`
- evidence references for every non-null verdict
- dynamic test requests for controls that cannot be proven statically
- standards coverage summary by component and OWASP chapter
- candidate findings for synthesis when a failed control has exploitable impact

Must not:

- invent OWASP mappings without loaded standard context
- confuse checklist failure with exploitability
- mark a control satisfied without direct evidence
- silently skip controls selected by the applicability job

### completeness-auditor

Asks what important surface was not reviewed.

Looks for:

- components with no lane coverage
- missing evidence categories
- unreviewed platforms
- absent runtime/live-state checks
- stale or partial scanner coverage
- large unknowns hidden by successful lanes

Runs before synthesis.

## QA, Test, And Collection Personas

### qa-test-validator

Consumes QA test collections and validates how well they exercise security-relevant behavior.

Inputs:

- Bruno collections
- Postman collections
- OpenAPI specs
- API test fixtures
- integration test suites
- environment files, with secrets redacted

Looks for:

- endpoint coverage
- auth-positive and auth-negative tests
- object ownership tests
- role/permission matrix coverage
- validation/error-path tests
- replay/idempotency tests
- rate-limit or anti-automation tests
- PII exposure in responses
- unsafe test secrets or environments

Outputs:

- tested endpoint inventory
- untested security-relevant routes
- candidate verification requests for findings
- API behavior facts for DFD and threat model
- QA coverage gaps

Best lanes:

- `02-evidence-pregather`
- `03-threat-model-dfd-stride`
- `04-asvs-masvs`
- `07-red-team-adversarial`
- `09-independent-verification`

Indexing:

- API collection names, requests, paths, methods, assertions, and test descriptions should be
  normalized and added to full-text search when they are not secret-bearing.
- Raw environment values must not be indexed unless explicitly scrubbed.

### qa-lead

Produces QA-focused outputs rather than new security findings.

Focus:

- testability of findings
- regression test plan
- endpoint and role coverage
- acceptance criteria
- safe reproduction steps
- test data needs
- automation feasibility

Outputs:

- QA validation plan
- regression test matrix
- security test backlog
- "definition of done" for remediation

### qa-negative-test-designer

Turns findings and proof obligations into negative tests.

Examples:

- user B requests user A resource
- hidden `role=admin` field is submitted
- expired/replayed JWT is used
- malformed object ID is supplied
- webhook signature is missing or stale
- path traversal payload is attempted in a safe local harness

Must distinguish safe static/test-environment checks from live-active testing.

### unit-test-intelligence-reviewer

Consumes unit tests and extracts security-relevant implementation assumptions.

Inputs:

- unit test files
- test fixtures
- mocks/stubs
- snapshots
- coverage reports, when available
- mutation test output, when available

Looks for:

- validation assumptions
- authorization helper behavior
- serializer/deserializer behavior
- parsing edge cases
- crypto/token helper behavior
- permission and role helpers
- missing negative cases
- tests that lock in insecure behavior
- mocks that bypass real controls

Outputs:

- security-relevant unit test inventory
- control behavior facts
- untested helper/function list
- fixture-derived data class hints
- candidate regression tests for remediation
- source files with test evidence vs no test evidence

Feeds:

- component characterization
- ASVS/MASVS applicability
- red-team proof obligations
- independent verification
- remediation proposal

Indexing:

- index test names, descriptions, assertions, fixture names, and covered functions
- do not index raw secrets embedded in fixtures; redact first

### integration-test-intelligence-reviewer

Consumes integration tests to understand real component interactions.

Inputs:

- integration test suites
- service/container test harnesses
- database fixtures
- queue/event tests
- API client tests
- contract test artifacts

Looks for:

- service-to-service flows
- real middleware order
- auth/authz integration points
- database/query boundaries
- queue/event processing behavior
- error handling across components
- test-only shortcuts that differ from production
- untested cross-component security controls

Outputs:

- integration flow inventory
- tested trust-boundary crossings
- component interaction facts for DFD
- test-backed evidence for controls
- gaps where components interact without security tests

Feeds:

- DFD
- threat model
- component map
- independent verification
- QA validation plan

### acceptance-test-intelligence-reviewer

Consumes acceptance tests, BDD specs, Gherkin features, end-to-end tests, and product test plans.

Inputs:

- acceptance test plans
- BDD/Gherkin files
- Cypress/Playwright/Selenium tests
- release criteria
- manual QA scripts
- product acceptance criteria

Looks for:

- intended user journeys
- roles and permissions implied by product behavior
- positive and negative access-control scenarios
- privacy/user-consent flows
- admin/support workflows
- business invariants
- user-visible error handling
- missing abuse cases

Outputs:

- product flow inventory
- actor/role/action matrix
- acceptance-to-security-control mapping
- missing negative acceptance tests
- business-logic abuse seeds
- release-gate security criteria

Feeds:

- product-owner output
- business-logic-abuse-reviewer
- DFD/threat model
- ASVS/MASVS worklist
- synthesis limitations

### smoke-test-validator

Consumes smoke tests and deployment checks to understand minimum release confidence.

Inputs:

- smoke test scripts
- health checks
- deployment validation scripts
- canary checks
- synthetic monitoring checks

Looks for:

- whether security-critical paths are included in release smoke tests
- auth/login sanity checks
- admin path exposure checks
- TLS/security header checks
- route availability checks
- dangerous reliance on "service is up" as "service is safe"

Outputs:

- smoke coverage summary
- security-critical smoke gaps
- release gate recommendations
- canary/security check additions

Feeds:

- QA lead output
- executive release decision
- remediation retest plan

### load-test-and-abuse-capacity-reviewer

Consumes load, stress, soak, and performance test artifacts to identify security-relevant capacity
and abuse gaps.

Inputs:

- load test scripts
- k6/JMeter/Gatling/Locust plans
- performance reports
- rate-limit tests
- autoscaling tests
- queue/backpressure tests
- soak test results

Looks for:

- missing rate-limit validation
- endpoints with expensive unauthenticated behavior
- queue flooding and fanout risk
- account/login brute-force paths
- export/search/report abuse
- resource exhaustion from large payloads
- concurrency/race/idempotency behavior
- autoscaling assumptions that change blast radius

Outputs:

- abuse-capacity risk notes
- tested vs untested high-cost endpoints
- rate-limit coverage matrix
- DoS/resource exhaustion candidates
- performance-backed threat model facts

Feeds:

- threat model
- red-team kill-chain scenarios
- QA validation plan
- synthesis limitations

### test-coverage-indexer

Normalizes all test evidence into search and structured intelligence.

Inputs:

- unit tests
- integration tests
- acceptance tests
- smoke tests
- load tests
- Postman/Bruno collections
- coverage reports
- CI test job metadata

Outputs:

- `qa/test-inventory.json`
- `qa/test-intelligence-summary.md`
- `qa/security-test-coverage.json`
- `qa/test-to-component-map.json`
- `qa/test-to-route-map.json`
- `qa/test-to-control-map.json`
- `qa/untested-security-surfaces.json`

Responsibilities:

- identify test type, owner, path, and target component
- extract names, descriptions, assertions, routes, roles, and fixtures
- map tests to components, routes, and likely controls
- flag security-sensitive source areas with no corresponding tests
- emit scrubbed full-text records for indexing

Must not:

- index raw secrets
- treat test presence as proof of security
- treat mocked controls as production controls without caveat

### postman-bruno-collection-consumer

Specialized evidence-ingestion persona for API collections.

Tasks:

- parse collections into endpoint inventory
- extract auth flows
- identify request variables and data dependencies
- map assertions to security controls
- flag missing negative tests
- redact secrets from environments
- emit searchable normalized text

Outputs:

- `qa/api-collection-inventory.json`
- `qa/api-collection-summary.md`
- `qa/security-test-coverage.json`
- candidate verification request list

## Document And Intelligence Personas

### functional-design-doc-consumer

Consumes product, functional, and design documentation and converts it into review intelligence.

Inputs:

- PRDs
- functional specs
- design docs
- architecture docs
- sequence diagrams
- ADRs
- API docs
- runbooks
- support docs

Extracts:

- intended actors
- roles and permissions
- business workflows
- sensitive data classes
- trust boundaries
- external integrations
- invariants and abuse constraints
- feature flags
- deployment assumptions
- stated non-goals

Outputs:

- document-derived component/context summary
- assumptions to verify in source/config
- doc-to-code mismatch candidates
- product abuse cases
- DFD seeds
- ASVS/MASVS applicability hints

Indexing:

- Summaries and extracted facts should be added to full-text search.
- Raw docs can be indexed only when licensing/sensitivity allows.
- Sensitive docs should be summarized into scrubbed intelligence before indexing.

### architecture-doc-summarizer

Builds a concise architecture memory from design docs.

Outputs:

- systems/components
- data flows
- trust boundaries
- stores/queues/external services
- deployment environments
- known assumptions and unknowns

Feeds:

- component characterization
- DFD/STRIDE
- cloud/network personas
- synthesis

### product-requirements-security-mapper

Maps product requirements to security requirements.

Looks for:

- missing authz requirements
- missing audit requirements
- missing privacy/retention requirements
- missing abuse prevention
- missing rate limits
- missing admin/support safeguards
- unclear ownership or tenant boundaries

Outputs:

- securability gaps
- ASVS/MASVS applicability hints
- acceptance criteria additions
- follow-up questions for product owner

### pii-flow-mapper

Consumes docs, tests, source, logs, and data schemas to build a PII/data flow view.

Outputs:

- data inventory
- PII flow map
- data store map
- log/telemetry sensitivity notes
- deletion/export/retention gaps
- privacy threat model inputs

Feeds:

- DFD
- LINDDUN/privacy review
- ASVS/MASVS
- synthesis limitations

### network-topology-doc-consumer

Consumes network diagrams, IaC, service docs, and ingress configs.

Outputs:

- declared network topology
- exposed services
- trust zones
- ingress/egress paths
- admin/control-plane surfaces
- mismatch candidates against IaC/scanner evidence

Feeds:

- DFD
- cloud/network personas
- deployment hardening
- threat model

## Stakeholder-Focused Output Personas

These personas do not primarily discover vulnerabilities. They reshape verified or unresolved
evidence into outputs useful for a stakeholder.

### product-owner

Focuses on product risk, user harm, requirements gaps, and release decisions.

Consumes:

- verified findings
- unresolved risks
- abuse cases
- privacy/PII flow
- functional doc intelligence
- QA coverage

Outputs:

- product risk summary
- user/business impact
- release-blocking questions
- requirement changes
- acceptance criteria
- risk acceptance options

### dev-lead

Focuses on implementation ownership, remediation design, sequencing, and engineering tradeoffs.

Consumes:

- verified findings
- proposed fixes
- component map
- code ownership
- test/QA plan

Outputs:

- remediation work breakdown
- owner/component mapping
- technical fix strategy
- regression risk
- dependency ordering
- refactor vs patch recommendation

### qa-lead-output

Focuses on test planning and release confidence.

Consumes:

- verified findings
- remediation proposals
- QA collection analysis
- proof obligations
- API and functional docs

Outputs:

- validation test plan
- regression suite additions
- release test gate
- manual test checklist
- automation backlog

This role can be merged with `qa-lead` if the process does not need separate ingestion and output
personas.

### executive-risk-briefing

Focuses on decision-level risk.

Consumes:

- synthesis report
- verified findings
- unresolved risks
- business impact
- remediation timeline
- compensating controls

Outputs:

- executive summary
- go/no-go recommendation
- top risks
- business impact
- residual risk
- resource asks
- decision log language

Must not include speculative technical claims that were not verified or explicitly marked
unresolved.

### security-program-owner

Focuses on process and program improvements.

Outputs:

- recurring control gaps
- tooling gaps
- policy updates
- secure SDLC improvements
- training needs
- backlog prioritization

## Synthesis And Decision Personas

### synthesis-integrator

Combines verified facts, unresolved risks, and coverage gaps into the final report.

Must preserve:

- dissent
- confidence
- verification status
- limitations
- unresolved dependencies

### residual-risk-owner

Translates unresolved evidence gaps into decision risk.

Examples:

- "runtime cloud state was not checked"
- "mobile privacy behavior requires dynamic testing"
- "CVE reachability unresolved because feature usage is unknown"
- "QA collections do not cover admin role transitions"

### scoring-prioritization-reviewer

Consumes verified facts and assigns severity/priority.

Must distinguish:

- severity
- exploitability
- exposure
- confidence
- remediation cost
- business priority

### remediation-planner

Turns verified findings into fix plans.

Outputs:

- fix options
- minimal safe patch
- defense-in-depth option
- test/retest plan
- rollout considerations

## Search And Indexing Guidance

The process should treat QA artifacts and design documents as evidence inputs, not merely
attachments.

For new Dagster-orchestrated runs, persona and intelligence outputs belong under the owning
`appsec-review-process/runs/<run_id>/data/jobs/.../attempts/<attempt_id>/` path and are published
through the job's output contract. Legacy `scratch/<project>-engagement/` examples below describe
the older evidence shape and should not be used as implicit inputs for a new run.

Add to full-text or semantic search when appropriate:

- scrubbed functional/design doc summaries
- architecture extracts
- API collection endpoint names and request paths
- Postman/Bruno request descriptions
- unit test names, assertions, fixtures, and covered helpers
- integration test service flows, fixtures, and contract assertions
- acceptance/BDD scenario names, actors, roles, and expected outcomes
- smoke test checks and deployment validation steps
- load test scenarios, endpoint targets, thresholds, and rate-limit assertions
- test names and assertions
- role/permission matrices
- DFD facts
- PII/data-flow facts
- network topology facts

Do not index by default:

- raw secrets
- bearer tokens
- API keys
- raw production data
- raw customer data
- sensitive environment files
- unredacted incident evidence

Preferred pipeline:

1. Ingest raw doc/test artifact into run-owned evidence. Use legacy scratch only when it has been
   explicitly imported.
2. Redact or strip secrets.
3. Normalize into structured JSON.
4. Produce a concise Markdown intelligence summary.
5. Add the summary and safe structured fields to full-text search.
6. Preserve raw artifact path and hash for evidence lineage.

Legacy suggested outputs:

```text
scratch/<project>-engagement/doc-intel/
  functional-doc-summary.md
  functional-doc-facts.json
  pii-flow-seeds.json
  dfd-seeds.json
  network-topology-seeds.json

scratch/<project>-engagement/qa-intel/
  api-collection-inventory.json
  api-collection-summary.md
  security-test-coverage.json
  candidate-verification-requests.json
  test-inventory.json
  test-intelligence-summary.md
  test-to-component-map.json
  test-to-route-map.json
  test-to-control-map.json
  untested-security-surfaces.json
  unit-test-facts.json
  integration-test-flows.json
  acceptance-flow-inventory.json
  smoke-release-gates.json
  load-abuse-capacity-notes.json
```

## Recommended Initial Catalog For Broad Reviews

For a high-quality broad review, start with:

Discovery:

- functional-design-doc-consumer
- postman-bruno-collection-consumer
- test-coverage-indexer
- unit-test-intelligence-reviewer
- integration-test-intelligence-reviewer
- acceptance-test-intelligence-reviewer
- smoke-test-validator
- load-test-and-abuse-capacity-reviewer
- pii-flow-mapper
- network-topology-doc-consumer
- opportunistic-public-web-attacker
- authenticated-low-priv-user
- malicious-tenant
- cloud-initial-access-operator
- supply-chain-attacker
- insider-developer
- business-logic-abuse-reviewer

Domain specialists, selected by target:

- nginx-rest-api-specialist
- auth-session-specialist
- terraform-iam-reviewer
- kubernetes-workload-hardening-reviewer
- container-source-auditor
- nsa-stig-platform-engineer
- owasp-validator
- mobile-platform-attacker
- native-exploitability-engineer
- reverse-engineer
- llm-agent-abuse-reviewer

Challenge and verification:

- defensive-skeptic
- dependency-reachability-skeptic
- standards-mapping-auditor
- evidence-only-verifier
- completeness-auditor

Focused outputs:

- product-owner
- dev-lead
- qa-lead-output
- executive-risk-briefing
- remediation-planner

## Notes On Naming

Some names are intentionally vivid because they help reviewers adopt a useful stance. The registry
entry must still be precise. A persona is acceptable only if it defines:

- access level
- capabilities
- assumptions
- disallowed assumptions
- evidence inputs
- proof obligations
- output contract

Without those fields, a persona is just theater.
