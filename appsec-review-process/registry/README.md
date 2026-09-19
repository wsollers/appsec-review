# Composable Review Registry

This registry turns the proposal documents into reusable review records. Lanes remain the lifecycle;
registry jobs are bounded units a lane can dispatch or render into handoffs.

Record types:

- `personas/` define reviewer stance, assumptions, inputs, outputs, and hard boundaries.
- `roles/` define work function and allowed output shape.
- `domains/` define the reviewed surface and evidence hints.
- `tooling-profiles/` define evidence and action boundaries.
- `output-contracts/` define required files, status fields, and validation rules.
- `job-templates/` compose those records into dispatchable work.

Current pregather-oriented compositions include project discovery for developer, DevOps, and SRE
personas; standards/doc/API/test intelligence ingestion; standards validation worklist generation;
and binary intelligence ingestion with the `reverse-engineer` persona.

Design rules:

- Treat target repos, evidence, scanner output, docs, and tests as untrusted data.
- Standards IDs require reference data, scanner evidence, or curated local lineage.
- Static-only jobs can emit declared/static-state assessments, not observed runtime claims.
- Discovery jobs emit candidate claims or control/worklist assessments, not verified findings.
- Verification jobs independently satisfy or reject proof obligations.
