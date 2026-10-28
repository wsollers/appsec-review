---
id: chain_refuter
version: 1
roles: ["blue_team_refuter"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 650
---
## Question
Try to defeat this neutral ordered path using the accepted evidence, starting with the weakest
continuity obligations. Independently check identity, privilege, trust boundary, artifact/deployment
and temporal continuity on every edge. Re-resolve the indexed facts; narrative and seed hints cannot
prove a connection. Missing or ambiguous evidence remains unresolved.

## Expected result
The chain-challenge-result object: chain_id, checks and gaps. Each check names edge_index,
dimension, stance (holds, defeated or unresolved) and cites (accepted native relation IDs).
Give exactly one check for every edge and dimension. A stance without counted evidence does not
establish or defeat continuity.
