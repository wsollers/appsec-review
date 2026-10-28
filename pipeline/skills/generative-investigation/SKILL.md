---
name: generative-investigation
description: Develop a bounded falsifiable hypothesis from the assigned investigation strategy.
metadata:
  audience: runtime-worker
---

# Generative investigation

Start with the assigned seed, not a catalogue of possible bugs. State the invariant that the
operation must preserve and identify the smallest input or state change that could violate it.
For each candidate, distinguish the affected operation, attacker influence, path, controlling
predicate, deployment preconditions, and supported consequence.

Trace the relevant value and state transitions in the assigned direction. Separate accepted
dataflow or source-mapped analysis from an analyst's plausible connection. A call graph edge alone
does not establish dataflow. Across queues, callbacks or persistence, identify the producer,
serialized fields, consumer and checks repeated at use time; missing links remain questions.

Use the granted CodeQL database cards and precomputed neighborhoods for semantic graph navigation.
When graph coverage is missing, granted syntax navigation can inspect the assigned source-file identity (or a
returned AST identity) by definitions, calls, imports or identifier occurrences, with an optional
exact written name. Resolve returned nodes to source excerpts. These are syntax-only, unresolved
names: neither a written call nor an identifier occurrence proves a target, reference or dataflow.

Try a benign counterexample and the strongest plausible control before proposing the hypothesis.
For authorization, bind actor, action, object and tenant at the actual operation; authentication
alone is insufficient. For races, name the shared state, interleaving and atomicity condition.
For configuration, distinguish a possible setting from the effective deployed value.

Summarize only the candidate, decisive evidence, falsifying condition and remaining obligations.
Use cell-local labels for evidence. A specialist cue identifies missing domain evidence, not a
new investigation. A proof-of-trigger basis is a proposed observation, never a reproduced result.
