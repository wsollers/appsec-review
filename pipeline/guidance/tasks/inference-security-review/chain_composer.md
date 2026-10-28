---
id: chain_composer
version: 1
roles: ["attack_chain_analyst"]
requests_tools: ["find", "read_excerpt", "resolve_evidence", "trace"]
max_tokens: 700
---
## Question
Which simple ordered paths through the supplied component claims could achieve one concrete
objective in this observed environment? Consider only the admitted frontier pairs. Seed hints are
search suggestions, not evidence. Name the exact output and input entities on each edge. Use
accepted resolving evidence rather than inferring a connection from two individually valid claims.

## Expected result
The chain-composer-result object: candidates with objective, component_claim_ids, edges
(output_entity and input_entity), prerequisites and rationale, plus named gaps.
Do not treat rationale as continuity proof. Empty candidates with explicit missing evidence are
appropriate when no meaningful path can be proposed. Identity, privilege, trust boundary,
artifact/deployment and temporal continuity are separate obligations.
