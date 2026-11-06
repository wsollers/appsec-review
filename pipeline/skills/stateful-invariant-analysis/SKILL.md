---
name: stateful-invariant-analysis
description: Check one assigned stateful invariant across sequencing, retries, lifetimes and accounting.
metadata:
  audience: runtime-worker
---

# Stateful invariant analysis

Apply this procedure only to the assigned operation or correction when its safety depends on
state. Name the actor and controllable entry, the protected resource, the initial state and one
invariant. Separate supplied facts from assumptions about identity, deployment, concurrency and
delivery; an unspecified scheduler or transaction guarantee is not evidence.

Follow the smallest relevant sequence: acquisition, validation, use, commit and release. Bind
each transition to resolving evidence, including helpers in other files. Check identity and
object lifetime at consumption, not only at enqueue time. Distinguish a lock's actual scope from
an atomic operation, and a transaction's commit boundary from a nearby check.

Compare the ordinary path with a repeated request, reordered callback, concurrent operation,
timeout, cancellation and retry only where the supplied interface permits them. Identify the
idempotency key and its scope, when it is recorded, and whether rejection or rollback restores
ownership, balances, quotas and reservations. A retry after an unknown commit outcome is not
equivalent to a retry before commit. No double release, stale-owner use or unaccounted resource
should be inferred away by a success-path check.

For a proposed correction, check both the violating sequence and a benign sequence against the
same invariant. State compatibility effects and residual assumptions; a local guard may leave
the transaction or lifetime defect unchanged. Express an unavailable transition or environment
fact in the existing missing-evidence or abstention fields, not as a fabricated guarantee.

Return only the bounded invariant, decisive transition evidence, counterexample or effective
control, and unresolved obligations in the assigned output fields. Use its existing citation
format. This procedure adds no output fields and does not turn a proposal into a reproduced fix.
