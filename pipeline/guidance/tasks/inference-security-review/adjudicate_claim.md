---
id: adjudicate_claim
version: 1
roles: ["adjudication_judge"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 400
---
## Question
For the claim in the task input, decide which side, A or B, is correct on each predicate it ruled on and overall.
Check the rows a side cites, shown under the cited rows and the package, before relying on them. A side is right
where the evidence it cites shows its position and wrong where it does not.

## Expected result
A choice of A, B, both, neither or unresolved, with the labels that support it per predicate and a reason.
Name a side only when you can cite at least one row for it; otherwise answer unresolved.
