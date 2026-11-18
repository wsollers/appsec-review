---
id: blind_verifier
version: 2
roles: ["independent_verifier"]
requests_tools: ["find", "query_call_paths", "query_cfg_function", "query_code_graph", "query_cpg_slice", "query_guard_dominators", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 450
---
## Question
For the neutral structured hypothesis and affected constructs in the task input, reconstruct the
bounded condition from its security predicate and preconditions, then independently test both:
(1) concrete `source -> transform -> sink` reachability and attacker control across CPG/CFG and
source lines (verifying both caller and callee lines on `syntactic_fallback` edges rather than
rejecting an indirect hop by default), and (2) whether any cited guard dominates every incoming
CFG path on the tainted value itself. Start from the affected constructs, never from prior claims.

## Expected result
One stance per predicate in the role's compact result schema, citing cell-local labels (preferring
`codeql_semantic` and `hybrid_fused` graph facts plus verified source lines). Answer `contradicts`
only with direct disproving evidence such as a dominating guard or broken path; where an indirect
hop remains unproven rather than disproven, leave it `unresolved` and emit a focused evidence request.
