# Composable Review Registry

This registry turns the proposal documents into reusable review records. Lanes remain the lifecycle;
registry jobs are bounded units a lane can dispatch or render into handoffs.

Record types:

The accepted Phase 1 runner executes `00-intake` with the `intake-coordinator` persona and role,
`intake-state` domain, `read-only-intake` tooling profile and `intake` output contract. Its
`00-validation` template uses the `contract-validator` persona and `execution-validator` role
with the `execution-validation` contract. Validators use a trusted nonrecursive bootstrap.
`job_graph.py` resolves all five references and checks semantic compatibility before work.
See [acceptance](../../docs/phase-1-acceptance.md) and [operations](../../docs/phase-1-operations.md).
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

Start coarse scope discovery with `02-repository-partition-discovery`. Its map identifies client,
server, API, infrastructure, delivery, and operations areas, including shared or unresolved scope,
and routes each area to developer, DevOps, and/or SRE review. Specialist discovery jobs consume
the map; component characterization subsequently refines it into functional/security components.
The prompt is `../02-evidence-pregather/repository-partition-discovery.md`. Automatic dispatch is
still pending the shared job renderer and validator.

Design rules:

- Treat target repos, evidence, scanner output, docs, and tests as untrusted data.
- Standards IDs require reference data, scanner evidence, or curated local lineage.
- Static-only jobs can emit declared/static-state assessments, not observed runtime claims.
- Discovery jobs emit candidate claims or control/worklist assessments, not verified findings.
- Verification jobs independently satisfy or reject proof obligations.
