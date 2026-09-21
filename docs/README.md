# docs

The information base for the current architecture, partitioned by component. Start with
[`agent-reader.md`](agent-reader.md); it is the entry point and read order for every agent.

| Folder | What lives here | Read it when |
|---|---|---|
| `architecture/` | The design authority (`design-v3.md`), the migration rule and the script-migration ledger. | You need the intended shape of the system or are moving code out of `scripts/`. |
| `dagster/` | Submitting, queueing, monitoring and recovering jobs; the run-owned data contract; operations (limits, imports, locks). | Before touching a run. |
| `evidence/` | Evidence retrieval and indexing, redaction, Scorecard ingest, intelligence collection, SBOM/SCA/NVD binding. | Before reading or producing evidence. |
| `build-discovery/` | Build discovery and execution gates. | Build jobs or compile databases are involved. |
| `pools/` | Resource pools (B15) and pool specification / deterministic expansion (C01). | Dispatching more than one worker. |
| `rendezvous/` | Wait-all rendezvous and the terminal-instance manifest (C02). | Waiting on a pool. |
| `adapters/` | The worker-result envelope, pinned-container (B13) and persona-invocation (B14) adapters, permission capabilities (B11). | Writing or validating a worker. |
| `personas-and-registry/` | The human-readable persona catalog (machine records: `appsec-review-process/registry/`). | Selecting or interpreting persona work. |
| `contracts/` | Validator dispatch rules for output contracts. | Validating an attempt. |
| `design-parity/` | The completion plan and four **generated** views (`design-parity-readiness.md`, `design-parity-report.md`, `full-review-workflow.mmd`, `job-graph.mmd`). Never hand-edit the generated ones; run `validate_design_parity.py --write-generated-views --write-report docs/design-parity/design-parity-report.md` and `phase1.py graph`. | Asking "is X built and qualified?". |
| `decisions/` | Architecture decision records. | A decision's rationale matters. |
| `proposals/` | Per-workbench task series and proposal fixtures (some are test-pinned; do not move them). | Working a workbench batch. |
| `continuation-prompts/` | Session handoffs. Start from the newest dated one. | Continuing earlier work. |
| `TODO/` | Independent task chunks that finish this reorganization and fill the missing buckets. | Picking up docs work. |

Not yet written (see `TODO/`): `review-lanes/`, `images-and-tools/`, `processes/`.

Rules: a dated status log or engagement record belongs in `continuation-prompts/` or nowhere; a
spec that a test ties to code says so in its first paragraph; every relative link must resolve.

Changelog: 2026-09-21 chunk 01 -- keep-set moved into buckets, links rewritten, generators and
tests repointed (`docs/REORG-2026-09-21.md` is the classification this executed).
2026-09-21 chunks 02 + 04 -- 24 disposed docs removed (git history keeps them), their inbound
references redirected, the six open 2026-09-11 design-review items ported into the completion plan.
2026-09-21 chunks 03 + 05 -- design-v3 dated appendices moved to its §24 decision log, ADR-0004 rewritten
(repo copy canonical), stale trackers (completion plan, task series, migration, catalog) corrected.
