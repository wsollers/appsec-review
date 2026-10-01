# Parked personas (not loadable by any job)

These catalog sections were moved out of [`persona-catalog.md`](persona-catalog.md) on 2026-10-01 together with their
records, which now live under `appsec-review-process/personas-unused/personas/<id>/`. No job template, worker, config
or test named them (see `docs/prompt-persona-role-alignment-plan-2026-10-01.md`, section 3). `catalog_personas.py`
reads only `persona-catalog.md`, so nothing here is generated or checked. To restore one, follow
`appsec-review-process/personas-unused/README.md`.

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

## Defensive And Verification Personas

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
- lane-14 attack-chain composition (ADR-0016)
- QA validation plan
- synthesis limitations

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
