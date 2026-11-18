---
name: generative-investigation
description: Develop a bounded falsifiable hypothesis from the assigned investigation strategy.
metadata:
  audience: runtime-worker
---

# Generative investigation

Start with the assigned seed or unit, not a catalogue of possible bugs. State the invariant that
the operation must preserve and identify the smallest input or state change that could violate it.
In each candidate's entry/trigger and obligation fields, name the attacker (anonymous caller,
authenticated tenant, uploaded file, adjacent process, plugin, dependency or operator), controlled
inputs and required privileges. Bind the entry to cited evidence; do not assume a browser or
remote service. Separate supplied environment/build facts from unresolved deployment assumptions.

Discover unseeded paths systematically using the granted catalog tools: prioritize high-complexity
or unguarded CFG functions, trace bounded entry-to-sink call paths, compute backward or forward
Alternate CPG slices around candidate sinks or carriers, and correlate threat-boundary crossings,
OWASP control gaps, specification-versus-handler drift, engineering hotspots and dependency
reachability. Separate accepted dataflow from a call graph edge alone. Across queues, callbacks or
persistence, identify producer, serialized fields, consumer and use-time checks; missing links
remain questions.

Use the granted CodeQL database cards, precomputed neighborhoods and semantic graph queries first.
When semantic graph coverage is missing, granted syntax navigation can inspect the assigned
source-file identity (or a returned AST identity) by definitions, calls, imports or identifier
occurrences, then resolve returned nodes to source excerpts; syntax names alone do not prove target
dispatch or dataflow.

Try a benign counterexample and inspect dominating branch guards before proposing the hypothesis.
For authorization, bind actor, action, object and tenant at the actual operation; authentication
alone is insufficient. For races, name shared state, interleaving and atomicity. For configuration,
distinguish a possible setting from the effective deployed value.

Summarize only the candidate, decisive cell-local labels, falsifying condition and remaining
obligations. A proof-of-trigger basis is a proposed observation, never a reproduced result.
