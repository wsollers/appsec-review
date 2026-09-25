# Composable Review Registry

This registry turns the proposal documents into reusable review records. Lanes remain the lifecycle;
registry jobs are bounded units a lane can dispatch or render into handoffs.

Record types:

The accepted Phase 1 runner executes `00-intake` with the `intake-coordinator` persona and role,
`intake-state` domain, `read-only-intake` tooling profile and `intake` output contract. Its
`00-validation` template uses the `contract-validator` persona and `execution-validator` role
with the `execution-validation` contract. Validators use a trusted nonrecursive bootstrap.
`job_graph.py` resolves all five references and checks semantic compatibility before work.
Phase 1 intake was accepted through A01-A16 on 2026-09-19 (run `20260919T104300Z-ba7b4c`); see [operations](../../docs/dagster/operations.md).
Other compositions are plans until an executor and validated output contract are implemented.
`00-intake.execution` specifies the trusted Python worker and argv template. Dagster resolves
this along with the staged run configuration before pre-validation; arbitrary target commands
are rejected. Its timeout/retry/composition fields govern the worker invocation.

- `personas/` define reviewer stance, assumptions, inputs, outputs, and hard boundaries.
- `roles/` define work function and allowed output shape.
- `domains/` define the reviewed surface and evidence hints.
- `tooling-profiles/` define evidence and action boundaries.
- `output-contracts/` define required files, status fields, and validation rules.
- `job-templates/` compose those records into dispatchable work.

Current pregather-oriented compositions include project discovery for developer, DevOps, and SRE
personas; standards/doc/API/test intelligence ingestion; standards validation worklist generation;
and binary intelligence ingestion with the `reverse-engineer` persona.

`10-critical-findings-sarif` is an implemented post-verification transform composition. It uses
the report artifact publisher persona, SARIF exporter role, verified-findings domain and local
SARIF tooling profile. Its standalone Dagster job consumes only the fixed run-owned
`inputs/critical-findings.md`; it does not make the still-planned synthesis or verification workers
implemented and it cannot verify or upgrade a finding.

`02-ossf-scorecard` is an implemented external-evidence ingestion composition. It uses the
supply-chain evidence curator persona, Scorecard results ingestor role, open-source project posture
domain, authorized Scorecard API tooling profile and Scorecard results contract. It requires an
explicit fixed-host network permission, preserves JSON2 response provenance, and cannot emit a
verified finding or claim that a repository was scanned live.

Start coarse scope discovery with `02-repository-partition-discovery`. Its map identifies client,
server, API, infrastructure, delivery, and operations areas, including shared or unresolved scope,
and routes each area to developer, DevOps, and/or SRE review. Specialist discovery jobs consume
the map; component characterization subsequently refines it into functional/security components.
The prompt is `../02-evidence-pregather/task-repository-partition-discovery.md`. Automatic dispatch is
still pending the shared job renderer and validator.

Design rules:

- Treat target repos, evidence, scanner output, docs, and tests as untrusted data.
- Standards IDs require reference data, scanner evidence, or curated local lineage.
- Static-only jobs can emit declared/static-state assessments, not observed runtime claims.
- Discovery jobs emit candidate claims or control/worklist assessments, not verified findings.
- Verification jobs independently satisfy or reject proof obligations.
- A job's task prompt lives in its process folder as `task-<job template id without the NN- prefix>.md`
  (e.g. `02-evidence-pregather/task-devops-project-discovery.md`) and is named by the template's
  `task_prompt`; `tests/test_task_prompt_naming.py` enforces it.

The shared output-validation slice is `../validate_job_output.py`. It resolves the declared
output contract from this registry, requires its files in the common artifact manifest, verifies
in-attempt paths and hashes, validates required status fields, and checks skip authorization against
the exact graph edge. Contracts may opt in to one explicit `result_schema` artifact/schema pair;
older contracts remain readable without that field. Scorecard, repository-partition-map, and
project-discovery have explicit dispatch for their bounded semantics. Discovery citations require
fresh repository-relative source files and hashes, cross-record IDs resolve, and secret-like result
values fail validation without being repaired or redacted in place. Those three contracts also
declare a bounded claim-class identity: Scorecard can report published posture/check evidence,
partition discovery can report declared or statically inferred structure/routing, and project
discovery can report declared structure or a statically inferred build plan. Finding, severity, and
observed-runtime promotion is rejected. `../create_job_handoff.py` separately hashes opted-in result
schema and claim-class declarations with the complete registry composition, prompt, and bounded
run-owned inputs. `../publish_job_output.py` separately performs
atomic publication after read-only validation. Scorecard and repository-partition discovery remain
the only adopted paths; the latter remains supplied analysis rather than automatic persona dispatch.
