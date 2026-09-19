# Evidence collection, similarity and full-text retrieval

The `evidence_index` Dagster job is implemented. It runs configuration → accepted intake →
accepted build discovery → evidence collection/pre/post validation. It is also a required
source branch in `full_review`; evidence assembly cannot pass without it. Native build, IR,
binary CFG and scanner adapters retain their existing explicit missing-worker gates.

Its registry composition uses the `evidence-custodian` persona, `evidence-indexer` role,
`local-evidence-retrieval` tooling profile and `evidence-index` contract, with intake coordination.
The worker reads configured timeouts and validates this composition before launching Python.
The immutable input record captures the complete composition, producer pointers, bounds,
worker hash, Python/SQLite identities and libfuzzy library hash.

Storage is entirely under `runs/<run_id>/data/jobs/02-evidence-index/whole/attempts/<attempt_id>/`.
SHA-256 objects retain exact bytes; ssdeep fingerprints cover collected binary and text files;
SQLite FTS5 stores text chunks with line ranges. The manifest and file table record coverage gaps.
Failed or interrupted attempts remain available. New attempts supersede acceptance; failed work
never falls back to an older success. Reuse and every query validate producer freshness and all
artifact hashes. An interrupted attempt receives a separate recovery record on retry.

Full commands and tooling limits are in the
[LLM addendum](../appsec-review-process/tooling/llm-retrieval-addendum.md). Both Codex and Claude
receive an `evidence-retrieval` repository skill; intake handoffs point to it and the addendum.
MCP configuration is an explicit client operation. The same retrieval functions remain available
through the CLI when the client has no connected MCP endpoint.

## Repeat qualification

```sh
python -B appsec-review-process/qualify_evidence_index.py --run-id OWNER_RUN_ID
python -B appsec-review-process/qualify_tooling.py --run-id OWNER_RUN_ID
```

The evidence qualifier creates a Linux-staged Freeciv21 engagement, submits real Dagster runs,
checks immutable reuse, separate logs, full-text citations, snapshot reads, similarity lookup,
and an actual MCP initialize/tools/list/tools/call exchange. Its report records a resume command
that preserves the engagement. Tests cover forced failure, recovery, stale inputs, corrupt
artifacts, source races, scope exclusions, query bounds and MCP error responses.

The tooling qualifier uses pinned installed image IDs, no network, read-only source mounts,
dropped capabilities and run-owned writable scratch. Eight primary language servers and each
image's filesystem/memory MCP services are probed. Receipts distinguish protocol availability
from semantic build qualification; auxiliary servers in the catalog are not automatically
qualified by a primary-server test.

Qualification evidence for this extension belongs to owner run `20260919T135727Z-105605`.
Historical Phase 1 A01–A16 acceptance remains scoped to its recorded implementation and hashes;
it does not certify the new downstream build/RE pipeline.
