---
name: predicate-verification
description: Independently verify each assigned predicate against direct resolving evidence.
metadata:
  audience: runtime-worker
---

# Predicate verification

Translate the neutral claim or assigned obligation into independently testable predicates before
evaluating the cited evidence. Resolve the affected construct, input origin, reachability, guard,
effective configuration and consequence separately. A scanner label or another conclusion is not
direct evidence that any predicate holds.

For each predicate, compare the strongest supporting fact with the strongest counter-fact.
Distinguish a complete accepted dataflow path from call adjacency and analyst inference. Check
the path's actual guard, range, alias and mutation facts, not just its endpoint names. For a
destination write, calculate source availability and destination capacity separately, accounting
for arithmetic width, termination bytes and every relevant path.

Across an asynchronous boundary, verify which principal and object state survive serialization
and which checks occur again at consumption. A producer-side check may not protect a later
operation on changed state. For configuration, separate documented defaults from observed
runtime selection.

Return concise per-predicate evidence summaries using the assigned contract's evidence references
(cell-local labels for compact review), with explicit missing facts. Do not treat unresolved
predicates as supporting evidence. Distinguish generated code,
successful compilation and an actual reproduced observation with a run-owned result artifact.
