---
name: appsec-evidence-search
description: Use AppSec Review lexical, semantic, similarity, and structural search without mistaking retrieval results for evidence. Applies when locating source, accepted evidence, components, symbols, AST/CPG records, IR facts, or citations in a review run.
---

# AppSec evidence search

Select the facility by question type:

- Use SQLite FTS5 for exact terms, identifiers, strings, paths, and nearby source text.
- Use LanceDB only for semantic recall when wording is unknown. Vector distance is never evidence.
- Use ssdeep only to locate similar bytes. Similarity is never identity or proof.
- Use Joern/AST/CPG or IR structural queries for calls, symbols, types, flows, and memory operations.
- Filter accepted derived records by `component_id` or `partition_id` when the question is scoped to
  a characterized part of the target.

Every result is a locator. Before using it in analysis, dereference the immutable source/evidence
artifact, verify its accepted pointer and generation bindings, and cite the resolved file/tool
output and location. Report unavailable, stale, mixed-generation, redacted, truncated, or
unindexed material as a coverage gap.

Read [references/search-facilities.md](references/search-facilities.md) before operating or changing
the search system. It records the authority boundaries and current lifecycle status of each mode.
