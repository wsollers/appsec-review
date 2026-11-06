# Job input and dispatch contracts

`Job.contract` is the typed dispatch and input authority. It extends the existing job/dataset
contract, not a second semantic registry. `runtime.contracts` defines the closed
`appsec-review/job-contract/1` format. Per-job declarations live beside `DATASETS`.

Each input names a producer, output kind, exact schema, evidence authority, availability,
missing policy and coverage policy. Channels distinguish accepted run handoffs from imported
external evidence and internal controller transactions. A reference to external feed or acquisition
evidence does not require a maintenance job's handoff in the review run.

Required inputs reject absence; optional inputs report gaps or explicit non-applicability.
Conditional requirements apply when their producer is enabled in the frozen configuration.
An accepted producer can still have partial, unavailable or retriable coverage. Acceptance is not
completeness. A required producer envelope does not make every optional, per-scope dataset mandatory.

Scheduling edges order jobs, including transparent disabled vertices. Only semantic inputs
participate in input selection and invalidation. Dispatch classes are `review_graph`,
`internal_transaction` and `maintenance`. Target access is independently `checkout`,
`accepted_evidence` or `none`; authenticated evidence identity never grants target filesystem access.

The attempt dataset format `/3` embeds the exact hashed job contract. Readers retain `/1` and `/2`
support without inventing historic input provenance or rewriting old artifacts. A contract change
changes the attempt identity and refuses reuse under the new contract.

Consumption observations must distinguish availability, supply, reader access and explicit
citation. A handoff reader establishes access to an envelope; a shard reader establishes access to
that dataset. Neither proves that a model used it in reasoning. Undeclared reads fail at instrumented
reader boundaries; this contract is not an operating-system filesystem sandbox.
