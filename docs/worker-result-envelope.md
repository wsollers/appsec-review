# Common worker-result envelope

`appsec-review-process/worker-result-contract.json` and
`schemas/worker-result-envelope.schema.json` define the versioned result boundary shared by
deterministic Python workers, pinned-container workers, persona workers, pool coordinators,
join/controllers, and supplied human decisions. This is the Workstream A contract; Workstream B
still has to migrate adapters and validators to emit and enforce it at runtime.

Every terminal result identifies its run, lifecycle job, immutable attempt, worker kind, input
fingerprint, output contract, timestamps, artifacts and hashes, limitations, failure/skip cause,
and recovery instruction. `OK_WITH_GAPS` and `UNRESOLVED` preserve useful bounded work without
claiming full completion. `SKIPPED` requires an edge-authorized reason and evidence; a missing
worker, crash, failed build, or unavailable required input is never a skip.

Execution state and acceptance state are deliberately separate. An attempt moves through
`PENDING`, `READY`, and `RUNNING` to exactly one immutable execution terminal state: `OK`,
`OK_WITH_GAPS`, `SKIPPED`, `BLOCKED`, `FAILED`, `CANCELED`, or `UNRESOLVED`. Terminal execution
states have no outgoing transitions. Acceptance may move from `NOT_ACCEPTED` to `CURRENT`, and a
current or rejected older attempt may later become `SUPERSEDED`. Supersession names the replacement
attempt in the acceptance view; it never rewrites the older attempt's execution result.

Only `OK`, `OK_WITH_GAPS`, and an evidence-backed `SKIPPED` result are candidates for publication.
Consumers still apply their own contract and dependency-edge rules. `BLOCKED`, `FAILED`,
`CANCELED`, and `UNRESOLVED` remain visible terminal outcomes and cannot silently satisfy an edge.

`worker_result.py` owns reusable envelope, transition, and immutable-reuse validation.
`validate_job_output.py` additionally checks the owning attempt directory, staged input
fingerprint, normalized in-root artifact paths, artifact hashes, registry-required files, and the
exact consumer dependency edge authorizing a skip. An output contract may optionally identify one
result artifact and schema; the declaration is absent from and nonbreaking for older contracts.
For opted-in contracts, validation checks required status fields and only that declared result as
the structured result. Explicit Scorecard and discovery dispatch adds payload semantics,
repository-relative citation freshness, cross-record identity, and bounded secret-leak rejection.
The same contracts declare a separately hashed claim-class identity. Their accepted surfaces are
published Scorecard posture/check evidence, supplied repository structure/routing, and supplied
project/build discovery; they cannot promote those records to findings, severities, or observed
runtime state. It is read-only: validation does not publish, redact, or repair an attempt.

`worker_adapters.py` defines the narrow adapter protocol. This batch implements only callable
deterministic Python and read-only supplied-human-decision adapters. Pinned-container, persona,
pool-coordinator, and join/controller adapters remain explicit unsupported kinds until their
isolation, provenance, rendezvous, and recovery contracts are implemented and qualified.

`create_job_handoff.py` resolves registry compositions and records immutable template, record,
prompt, contract, and bounded run-owned input hashes. `publish_job_output.py` is the separate
atomic publication boundary: it consumes the read-only validator, requires the candidate to remain
the newest attempt, and never exposes an older success after a newer attempt starts or fails. For
the three adopted workers it also owns bounded collision-safe attempt allocation and durable
non-current completion. Inputs and transient status are persisted before the fail-closed `PENDING`
and `latest.json` transition; a later allocation converts abandoned pending work into an immutable
`FAILED` envelope before replacement. `BLOCKED`, `FAILED`, and `CANCELED` recording rechecks the
newest attempt and preserves any already-durable candidate envelope. A common coordinator owns the
per-job lock and the reuse/recovery/allocation/terminal-exception sequence for those same three
workers. It maps preflight, work, and cancellation outcomes without swallowing the original
exception or double-writing an already-terminal attempt. Worker execution, timeout, process
cleanup, streams, payload construction, and contract-specific validation otherwise remain local to
each worker.

`deterministic_child.py` is the first bounded execution sub-contract. `02-ossf-scorecard` and
`10-critical-findings-sarif` adopt `appsec-review/deterministic-child/1.0`: an absolute executable
and fixed argv prefix, no shell executable or shell string, an explicit environment, an in-attempt
log root, a timeout, and per-stream retained-byte limits. It drains stdout and stderr concurrently after a process gate,
records observed/written/dropped byte counts, and always closes the Windows Job Object or POSIX
process session so descendants cannot escape on normal exit, timeout, cancellation, stream failure,
or child loss. `KeyboardInterrupt` and `SystemExit` retain their type after cleanup. This is not a
pinned-container, persona, pool, or general worker-controller adapter. Supplied
repository-partition discovery has no child process and is deliberately not routed through it, and
no other worker has been migrated to it.

For those adopted paths, reusable-candidate admission is also common. The accepted pointer must
match the run, job, fingerprint, status and newest attempt; its immutable tree and envelope hashes
and the complete output contract are revalidated before reuse. A matching but corrupt pointer is a
failure, not a cache miss. Successful terminal persistence writes final status, runs the explicit
worker payload check, hashes declared artifacts, and persists the `CURRENT` envelope before the
publication pointer moves. A durable envelope left behind a `PENDING` pointer is recoverable: the
next invocation validates and publishes the same attempt without executing payload work again.

The design-parity validator checks the state sets, transition closure, terminal immutability,
schema enums, skip-reason registry, graph reachability/cycles, dependency skip semantics,
namespace uniqueness, and producer/consumer contract agreement. Live publication, immutable
reuse, lock contention, one-allocation ownership, callback failure and cancellation routing,
post-envelope publication recovery, interrupted-attempt failure, newer-failure blocking, and
recovery are qualified for
`02-ossf-scorecard` and
`02-repository-partition-discovery`. Scorecard's deterministic-child behavior is additionally
fault-qualified on Windows and Linux for timeout, cancellation, simultaneous stream pressure,
retained-log truncation, child loss, and log-write failure, plus one live successful API ingest.
`10-critical-findings-sarif` adopted the same boundary in Batch 9 and is focus-qualified for
semantic parity, common publication/reuse/recovery, contract-declared result validation, and
deterministic-child fault mapping; its bounded live Dagster sequence
(`qualify_sarif_adoption.py`) is still outstanding and it is therefore not yet live-qualified.
Migration of all other workers remains later Workstream B work; historical attempts are not
rewritten.
