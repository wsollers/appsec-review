---
id: adjudicate_claim
version: 2
roles: ["adjudication_judge"]
requests_tools: ["find", "query_call_paths", "query_cfg_function", "query_code_graph", "query_cpg_slice", "query_guard_dominators", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 450
---
## Question
For the claim in the task input, decide which side, A or B, is correct on each predicate it ruled on
and overall. Re-verify cited rows against source lines and CPG/CFG graph facts: compare concrete
`source -> transform -> sink` continuity (`codeql_semantic`, `hybrid_fused`, or source-verified
`syntactic_fallback` hops) against dominating guard facts covering all incoming paths on the tainted
value. Unverified assertions, dead guards, or checks on unrelated variables do not carry a predicate.

## Expected result
A choice of A, B, both, neither or unresolved, with the cell-local labels that support it per
predicate and a concise reason. Name a side only when cited resolvable rows prove its position;
otherwise answer unresolved.
