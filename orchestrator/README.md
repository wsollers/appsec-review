# orchestrator

Python. Ledger writer + hash chain, contract validator, artifact registry, run-state regeneration. See ADR-0002.

The [local Dagster runner](dagster/README.md) provides persistent containers, a run queue and
`engagement_workflow`, the default submission job. It wraps atomic intake, three parallel
preparation branches and a validated join. The smaller `phase1_intake` and original smoke job
remain available. Start with [how to submit jobs](../docs/dagster/dagster-launching.md); see
[workflow internals](../docs/dagster/dagster-workflow.md). Phase 1 intake was accepted through A01-A16 on 2026-09-19 (run `20260919T104300Z-ba7b4c`).
Downstream scanners and specialist execution remain planned.
