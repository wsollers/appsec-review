---
id: chain_weakest_link_verifier
version: 1
roles: ["independent_verifier"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 650
---
## Question
Reconstruct the weakest link of this neutral ordered path independently from accepted native
evidence. Check all five continuity dimensions on every edge, starting with the least-supported
ones. The component findings do not establish that their connection exists. Explicitly identify
missing deployment, privilege or temporal facts.

## Expected result
The chain-challenge-result object: chain_id, checks and gaps. Each check names edge_index,
dimension, stance (holds, defeated or unresolved) and cites (accepted native relation IDs).
Give exactly one check for every edge and dimension; a plausible narrative is not proof.
