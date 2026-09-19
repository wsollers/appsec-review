# orchestrator

Python. Ledger writer + hash chain, contract validator, artifact registry, run-state regeneration. See ADR-0002.

The [local Dagster runner](dagster/README.md) provides persistent containers, a run queue and
`engagement_workflow`, the default submission job. It wraps atomic intake, three parallel
preparation branches and a validated join. The smaller `phase1_intake` and original smoke job
remain available. Start with [how to submit jobs](../docs/dagster-launching.md); see
[workflow internals](../docs/dagster-workflow.md) and [Phase 1 acceptance](../docs/phase-1-acceptance.md).
Downstream scanners and specialist execution remain planned.
