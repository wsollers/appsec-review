# Persona and role assignment of model-calling jobs

Audit of 2026-09-28 (branch `ws-personas`, [ADR-0021](../decisions/ADR-0021-sharded-claim-review-personas.md)),
updated 2026-09-29 for the personas folder and per-stage review roles (brief J,
[ADR-0024](../decisions/ADR-0024-per-stage-review-roles.md)).
Every model call goes through `claude_cli_invoker` with a persona request whose composition
(persona, role, domain, tooling profile, output contract) comes from a registry job template; the
registry decides, the request only repeats it. A template may also list `persona_variants`
(ADR-0021) and `role_variants` (ADR-0024) that one instance can run as instead of its composed
persona or role.

## Registry records

All 54 personas in [persona-catalog.md](persona-catalog.md) now have a record under
`appsec-review-process/personas/personas/<id>/persona.json` (one folder per persona and per role; see
[README](README.md)). 48 were generated from the catalog text by
`appsec-review-process/catalog_personas.py generate` and carry
`provenance: {generated_by: catalog_personas.py, reviewed: false}`; six (reverse-engineer,
nsa-stig-platform-engineer, owasp-validator, qa-test-validator, test-coverage-indexer,
functional-design-doc-consumer) were already hand-authored (a hand-authored record now carries
`provenance: {}`). `catalog_personas.py check` fails when a
catalog persona has no record or a generated record is stale. Persona records reference no role,
domain or tooling profile; those are bound by job templates, so no new role/domain/tooling records
were needed for the generated personas.

## Claim review (07/08/09/12): one persona per reviewer instance

`claim_reviewer_pool.py` shards each stage's claims across `claim_review_pool_instances` instances
(default 3) and gives each instance its own persona from `claim-review-pool-cell.stage_personas`
(see [the pool doc](../pools/pool-specification.md#claim-review-sharding-adr-0021)). Each instance runs
as the stage's registry role from `claim-review-pool-cell.stage_roles` (ADR-0024): `red-team-adversary`
(07), `blue-team-refuter` (08), `independent-verifier` (09), `scorer` (12), each allowing only the
stage's claim class. Domain, tooling profile and output contract stay `claim-review-lifecycle` /
`claim-review-static` / `claim-review-pool-candidates`; the template's composed role stays the generic
`claim-reviewer`. The 07/08/09 role is also the decision actor, as before.

| Stage | Persona pool (in rotation order) |
|---|---|
| 07 red team | opportunistic-public-web-attacker, api-contract-abuser, authenticated-low-priv-user, malicious-tenant, business-logic-abuse-reviewer, privacy-abuse-reviewer, cloud-initial-access-operator, supply-chain-attacker, insider-developer, native-exploitability-engineer, reverse-engineer, llm-agent-abuse-reviewer, mobile-platform-attacker |
| 08 blue team | defensive-skeptic, control-owner, dependency-reachability-skeptic, observability-forensics-reviewer, release-integrity-reviewer, auth-session-specialist, container-source-auditor, kubernetes-workload-hardening-reviewer, data-storage-records-reviewer |
| 09 verification | evidence-only-verifier, standards-mapping-auditor, protocol-rfc-lawyer, claim-reviewer |
| 12 scoring | scoring-prioritization-reviewer, residual-risk-owner, remediation-planner, product-owner |

On the appsec-multi-vuln 60-claim STRIDE ledger (run `20260928T034921Z-be3585`) the 07 plan is three
shards of 18/18/24 claims reviewed as reverse-engineer (vendored zlib/httplib flows),
supply-chain-attacker (CI automation) and insider-developer (build scripts).

## Other model-calling jobs (as of this audit)

| Job / module | Template | Persona | Role | Assessment |
|---|---|---|---|---|
| `01-component-characterization` (`component_characterization.py`) | same | component-security-auditor | component-characterizer | Dedicated persona since 2026-10-01 (alignment plan R01, decision D3); was developer-engineer, a build-discovery persona on a security-routing job |
| `02-evidence-producer-binding` (`evidence_assembly_runtime.py`) | same | evidence-custodian | evidence-assembler | Fits (bookkeeping-heavy binding call) |
| `02-build-classify` (`build_classify.py`) | same | developer-engineer | build-unit-classifier | Fits |
| `02-build-plan` (`build_plan.py`) | same | developer-engineer | build-planner | Fits |
| D01 `02-repository-partition-discovery` | same | developer-engineer | repository-partition-mapper | Fits; routes partitions to developer/devops/SRE personas |
| D02 `02-dev-project-discovery` (`discovery_gate.py`) | same | developer-engineer | repo-project-discoverer | Fits |
| D03 `02-devops-project-discovery` | same | devops-engineer | repo-project-discoverer | Fits |
| D04 `02-sre-operations-topology` | same | sre-engineer | operations-topology-mapper | Fits |
| OWASP validator cells (`owasp_workbench_lifecycle.py`) | `04-owasp-validator-cell` | owasp-validator | standards-control-validator | Fits; every cell uses the same persona (candidate for variants: api-contract-abuser, auth-session-specialist, mobile-platform-attacker by chapter) |
| Intake review pool (`persona_tool_pool_lifecycle.py`) | `intake-review-pool-cell`, `intake-review-pool-independent-cell` | claim-reviewer, reverse-engineer | claim-reviewer | Two distinct personas already; claim-reviewer is generic for an intake check (candidate: completeness-auditor, parked in `personas-unused/`) |
| `persona-tool-pool-dispatch` (`control_lane_orchestration.py`) | caller-supplied spec | per spec | per spec | Persona comes from the supplied pool spec |

Not changed here (listed for William): the `07/08/09/12` lifecycle templates themselves name
evidence-custodian/evidence-assembler, but those jobs are deterministic Python and make no model
call; the OWASP cell and intake-pool suggestions above are design choices rather than
mis-assignments. No other model-calling job had a trivially wrong persona.
