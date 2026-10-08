# Telemetry and derived metrics

`runs/<run-id>/data/logs/pipeline.jsonl` is the canonical append-only event stream. Every record uses
`appsec-review/telemetry-event/1`, a contiguous sequence, stable event identity, UTC timestamp, and
run/job/attempt/step/task correlation. Details may add Dagster run/node, producer/tool invocation,
index shard, MCP session/invocation, future model invocation, or finding-package identities.

The writer is process-safe and crash-recovering. It bounds depth, collection size, strings, and total
record bytes. Credentials, secret-like values, prompts, responses, raw model output, source text,
and query text are redacted. Telemetry uses request, guidance, reason, evidence, and artifact hashes.

Lifecycle families are:

- `RUN_*`, `GRAPH_*`, `JOB_*`, `STEP_*`, and `TASK_*` start and terminal events, including duration,
  reuse, disposition, and `COMPLETED_WITH_GAPS` where applicable.
- `TOOL_INVOCATION_STARTED/COMPLETED` for scanners and external tools, with immutable tool identity,
  retry, duration, result/gap counts, truncation, disposition, and error class.
- `MCP_TOOL_STARTED/COMPLETED` for transport calls and `RETRIEVAL_SUBOP_COMPLETED` for child spans.
- `MODEL_CALL_STARTED/COMPLETED`, ready for later inference, with provider/model/reasoning identities,
  guidance and request hashes, token/cache counts, duration, retry, status, and error class.
- `FINDING_TRANSITION` for `NONE -> CANDIDATE -> CONFIRMED|REFUTED`. It carries the immutable finding
  package, evidence identities/count, actor class, and reason/evidence hash. Scanner observations are
  evidence records; they are never counted as confirmed findings without a valid transition.

`appsec-review metrics --run-id <id>` deterministically rebuilds bounded counts and duration/token
sums from events. This view is operational convenience; mutable counters are never authoritative.
