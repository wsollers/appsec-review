# Component and module routing for OWASP

`01-component-characterization` publishes stable functional component IDs, path patterns,
relationships, parallel review groups, tags, unknowns, and rescope triggers. The evidence index can
filter accepted derived records by `component_id` and `partition_id`.

`04-owasp-applicability` produces exactly one row for every selected ASVS or MASVS control x
component. Each row retains target, control/domain, component, classification inputs,
applicability, proof obligations, signals, citations and rationale. It fails if its row count is not
exactly controls x components.

`04-owasp-control-batcher` accounts for every row. Applicable and conditional rows become bounded
validator fragments; not-applicable, out-of-scope and unresolved rows remain explicit accounting
or gaps. Batches are partitioned by component/group, domain, evidence mode, tooling profile,
authorization boundary and validator role.

## Assembly and validation

The full-review assembler must derive `owasp-applicability-request.json` from the newest accepted
component map and approved OWASP selection/reference inputs. Until its current lifecycle binding is
qualified, explicit run-owned requests may still appear. Always verify:

- component classification hashes and input IDs bind to the accepted map;
- `counts.control_targets == selected_controls x components`;
- unknown or conflicting classification becomes `cannot_determine` with a rescope gap;
- every row is represented in batching, dispatch accounting, validator results and the joined
  control matrix exactly once;
- a component map alone is not evidence that OWASP validation ran.

Implementation authorities are `appsec-review-process/owasp_applicability.py`,
`owasp_batching.py`, `owasp_validator_handoff.py`, `owasp_dispatch.py`, and
`owasp_join_report.py`. Principal schemas include `owasp-applicability-model.schema.json`,
`owasp-applicability-row.schema.json`, `owasp-batch-request.schema.json`, and
`owasp-control-status-matrix.schema.json`.
